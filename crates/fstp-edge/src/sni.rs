//! The ClientHello SNI parser (M3 design section 9.4, ADR-009 "Edge and
//! tunnel", TH-26, H-05, I-19 and boundary rule B5).
//!
//! The parser reads the first bytes of a connection and names the host of
//! the `server_name` extension (RFC 6066 section 3). It takes a shared
//! slice, so it never changes a byte, and its verdict never depends on any
//! byte after the ClientHello. The edge forwards every byte it read, the
//! ClientHello included, unchanged.
//!
//! Strict readings (design section 17.2 and the W2i lane report):
//!
//! - The whole ClientHello, record headers included, fits in
//!   [`MAX_HELLO_BUF`] bytes. A hello that claims more is refused at once,
//!   so the parser never asks for more bytes beyond that bound.
//! - A ClientHello may span several handshake records. Any other record
//!   type before its end, a zero-length record, and handshake bytes after
//!   it in its last record are refused.
//! - Every length must match exactly. Duplicate extensions, a server name
//!   list with more than one entry and an unknown name type are refused.
//! - A hello that carries `encrypted_client_hello` is read like any other
//!   hello, and its outer SNI decides the route (ADR-009, Daniel's
//!   decisions of 2026-10-29 and 2026-11-13). Chromium-family browsers
//!   send that extension as GREASE, so refusing it would close them. The
//!   parser never tries to tell GREASE from real ECH.
//! - The host name is an LDH DNS name, folded to lowercase.

use crate::host::{HostError, HostName};

/// The most bytes the edge reads before it decides (design section 9.4).
pub const MAX_HELLO_BUF: usize = 16 * 1024;

/// TLS record content type `handshake`.
const CONTENT_HANDSHAKE: u8 = 0x16;
/// The major version byte of every TLS record version.
const TLS_MAJOR: u8 = 0x03;
/// The length of a TLS record header.
const RECORD_HEADER_LEN: usize = 5;
/// The largest TLS plaintext record body (RFC 8446 section 5.1).
const MAX_RECORD_BODY: usize = 1 << 14;
/// The length of a handshake message header.
const HANDSHAKE_HEADER_LEN: usize = 4;
/// Handshake message type `client_hello`.
const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
/// The length of `ClientHello.random`.
const RANDOM_LEN: usize = 32;
/// The longest `legacy_session_id` (RFC 8446 section 4.1.2).
const MAX_SESSION_ID: usize = 32;
/// Extension `server_name` (RFC 6066).
const EXT_SERVER_NAME: u16 = 0x0000;
/// Server name type `host_name`, the only type RFC 6066 defines.
const NAME_TYPE_HOST: u8 = 0;

/// What the parser found in the first bytes of a connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SniOutcome {
    /// More bytes are needed.
    NeedMore,
    /// The ClientHello names this host.
    Host(HostName),
    /// The ClientHello has no SNI.
    NoSni,
    /// The bytes are not TLS.
    NotTls,
}

/// The part of a ClientHello that is malformed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HelloPart {
    /// A record header after the first one.
    RecordVersion,
    /// `legacy_version`.
    LegacyVersion,
    /// `random`.
    Random,
    /// `legacy_session_id`.
    SessionId,
    /// `cipher_suites`.
    CipherSuites,
    /// `legacy_compression_methods`.
    Compression,
    /// The extensions block.
    Extensions,
    /// One extension's type or body.
    Extension,
    /// The `server_name` list.
    ServerNameList,
    /// One entry of the `server_name` list.
    ServerName,
}

/// Why the ClientHello parser refused. Every refusal closes the
/// connection (design section 9.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SniError {
    /// A record body is empty or longer than TLS allows.
    RecordLength,
    /// The ClientHello needs more than [`MAX_HELLO_BUF`] bytes.
    HelloTooLong,
    /// A record that is not a handshake record came before the end of the
    /// ClientHello.
    UnexpectedRecord,
    /// The first handshake message is not a ClientHello.
    NotClientHello,
    /// The last record of the ClientHello holds bytes after it.
    TrailingHandshakeBytes,
    /// A part of the ClientHello is malformed.
    Malformed(HelloPart),
    /// Two extensions share a type.
    DuplicateExtension,
    /// The server name list holds more than one name.
    MultipleServerNames,
    /// The server name is of a type other than `host_name`.
    UnknownNameType,
    /// The host name is not an LDH DNS name.
    InvalidHost(HostError),
}

/// Parses the SNI from the first bytes of a connection, at most
/// [`MAX_HELLO_BUF`] bytes. Fuzzed (`client_hello_sni`).
///
/// # Errors
///
/// Returns an [`SniError`] for a hello the edge refuses. Every refusal,
/// [`SniOutcome::NoSni`] and [`SniOutcome::NotTls`] close the connection.
pub fn parse_client_hello_sni(buf: &[u8]) -> Result<SniOutcome, SniError> {
    let Some(&first) = buf.first() else {
        return Ok(SniOutcome::NeedMore);
    };
    if first != CONTENT_HANDSHAKE {
        return Ok(SniOutcome::NotTls);
    }
    if buf.get(1).is_some_and(|major| *major != TLS_MAJOR) {
        return Ok(SniOutcome::NotTls);
    }
    match assemble(buf)? {
        None => Ok(SniOutcome::NeedMore),
        Some(body) => parse_body(&body),
    }
}

/// Collects the ClientHello body from the handshake records at the start
/// of `buf`. `None` means more bytes are needed.
///
/// Each check runs as soon as the bytes it reads have arrived, and every
/// later check reads only later bytes. So a refusal on a buffer is also
/// the verdict on every longer buffer, and the parser asks for more bytes
/// only when the hello can still fit in [`MAX_HELLO_BUF`].
fn assemble(buf: &[u8]) -> Result<Option<Vec<u8>>, SniError> {
    let mut hs: Vec<u8> = Vec::new();
    let mut at = 0usize;
    loop {
        let Some(&ty) = buf.get(at) else {
            return Ok(None);
        };
        if ty != CONTENT_HANDSHAKE {
            return Err(SniError::UnexpectedRecord);
        }
        let Some(&major) = buf.get(add(at, 1)?) else {
            return Ok(None);
        };
        if major != TLS_MAJOR {
            return Err(SniError::Malformed(HelloPart::RecordVersion));
        }
        let (Some(&hi), Some(&lo)) = (buf.get(add(at, 3)?), buf.get(add(at, 4)?)) else {
            return Ok(None);
        };
        let len = usize::from(u16::from_be_bytes([hi, lo]));
        if len == 0 || len > MAX_RECORD_BODY {
            return Err(SniError::RecordLength);
        }
        let start = add(at, RECORD_HEADER_LEN)?;
        let end = add(start, len)?;
        if end > MAX_HELLO_BUF {
            return Err(SniError::HelloTooLong);
        }
        let before = hs.len();
        let avail = buf.get(start..end.min(buf.len())).unwrap_or_default();
        hs.extend_from_slice(avail);
        if hs.first().is_some_and(|t| *t != HANDSHAKE_CLIENT_HELLO) {
            return Err(SniError::NotClientHello);
        }
        let total = match handshake_total(&hs)? {
            Some(total) => total,
            None if buf.len() < end => return Ok(None),
            None => {
                at = end;
                continue;
            }
        };
        // The bytes this hello still needs after this record's header.
        let rest = total.checked_sub(before).ok_or(SniError::HelloTooLong)?;
        if add(start, rest)? > MAX_HELLO_BUF {
            return Err(SniError::HelloTooLong);
        }
        if add(before, len)? > total {
            return Err(SniError::TrailingHandshakeBytes);
        }
        if buf.len() < end {
            return Ok(None);
        }
        if hs.len() == total {
            return Ok(hs.get(HANDSHAKE_HEADER_LEN..).map(<[u8]>::to_vec));
        }
        at = end;
    }
}

/// The total length of the handshake message, header included, once its
/// header has arrived.
fn handshake_total(hs: &[u8]) -> Result<Option<usize>, SniError> {
    let (Some(&a), Some(&b), Some(&c)) = (hs.get(1), hs.get(2), hs.get(3)) else {
        return Ok(None);
    };
    let len =
        usize::try_from(u32::from_be_bytes([0, a, b, c])).map_err(|_| SniError::HelloTooLong)?;
    add(len, HANDSHAKE_HEADER_LEN).map(Some)
}

/// Checked addition. An overflow can only come from a length past every
/// bound, so it refuses as too long.
fn add(a: usize, b: usize) -> Result<usize, SniError> {
    a.checked_add(b).ok_or(SniError::HelloTooLong)
}

/// Tells the edge's read loop when [`parse_client_hello_sni`] can decide,
/// so the loop parses a hello once and not after every read.
///
/// It reads each record header once and copies no record body, so its
/// work over a whole hello is linear in the bytes read. It says "parse
/// now" when the record that completes the hello has arrived, which is
/// the first point at which the parser can name a host or find no SNI.
/// It also says so when it sees a byte the parser refuses. It may miss
/// some refusals until the hello ends. That only delays the close: a
/// refusal on a buffer is also the verdict on every longer buffer.
/// Fuzzed (`client_hello_sni`): it never says "wait" on a prefix that the
/// parser routes or closes as `NoSni` or `NotTls`.
#[derive(Debug, Default)]
pub struct HelloScan {
    /// The offset of the next record header.
    at: usize,
    /// The handshake bytes in the complete records before `at`.
    hs_len: usize,
    /// The first bytes of the handshake message.
    head: [u8; HANDSHAKE_HEADER_LEN],
    /// Whether an earlier call said "parse now". The answer then stays.
    done: bool,
}

impl HelloScan {
    /// Whether the parser should run on `buf`. Each call continues from
    /// the record the last call stopped at, so `buf` must extend the
    /// buffer of the last call. Once it says yes, it says yes on every
    /// longer buffer.
    pub fn ready(&mut self, buf: &[u8]) -> bool {
        if !self.done {
            self.done = self.scan(buf);
        }
        self.done
    }

    /// Scans the records that arrived since the last call.
    fn scan(&mut self, buf: &[u8]) -> bool {
        loop {
            let Some(&ty) = buf.get(self.at) else {
                return false;
            };
            if ty != CONTENT_HANDSHAKE {
                return true;
            }
            let Some(&major) = buf.get(self.at.saturating_add(1)) else {
                return false;
            };
            if major != TLS_MAJOR {
                return true;
            }
            let (Some(&hi), Some(&lo)) = (
                buf.get(self.at.saturating_add(3)),
                buf.get(self.at.saturating_add(4)),
            ) else {
                return false;
            };
            let len = usize::from(u16::from_be_bytes([hi, lo]));
            let start = self.at.saturating_add(RECORD_HEADER_LEN);
            let end = start.saturating_add(len);
            if len == 0 || len > MAX_RECORD_BODY || end > MAX_HELLO_BUF {
                return true;
            }
            let Some(body) = buf.get(start..end) else {
                // A first handshake byte other than `client_hello` is
                // refused at once.
                return self.hs_len == 0
                    && buf.get(start).is_some_and(|t| *t != HANDSHAKE_CLIENT_HELLO);
            };
            let missing = HANDSHAKE_HEADER_LEN.saturating_sub(self.hs_len);
            let slots = self.head.iter_mut().skip(self.hs_len);
            for (slot, b) in slots.zip(body.iter().take(missing)) {
                *slot = *b;
            }
            self.hs_len = self.hs_len.saturating_add(len);
            self.at = end;
            if self.hs_len >= HANDSHAKE_HEADER_LEN {
                let [kind, a, b, c] = self.head;
                if kind != HANDSHAKE_CLIENT_HELLO {
                    return true;
                }
                let total = usize::try_from(u32::from_be_bytes([0, a, b, c]))
                    .unwrap_or(usize::MAX)
                    .saturating_add(HANDSHAKE_HEADER_LEN);
                if self.hs_len >= total {
                    return true;
                }
                // The rest of the hello needs at least one more header.
                let rest = total.saturating_sub(self.hs_len);
                if end.saturating_add(RECORD_HEADER_LEN).saturating_add(rest) > MAX_HELLO_BUF {
                    return true;
                }
            }
        }
    }
}

/// A cursor over a byte slice that refuses to read past its end.
struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Reader { rest: bytes }
    }

    fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    fn take(&mut self, n: usize, part: HelloPart) -> Result<&'a [u8], SniError> {
        let (head, tail) = self
            .rest
            .split_at_checked(n)
            .ok_or(SniError::Malformed(part))?;
        self.rest = tail;
        Ok(head)
    }

    fn u8(&mut self, part: HelloPart) -> Result<u8, SniError> {
        let (&b, tail) = self.rest.split_first().ok_or(SniError::Malformed(part))?;
        self.rest = tail;
        Ok(b)
    }

    fn u16(&mut self, part: HelloPart) -> Result<u16, SniError> {
        let (&b, tail) = self
            .rest
            .split_first_chunk::<2>()
            .ok_or(SniError::Malformed(part))?;
        self.rest = tail;
        Ok(u16::from_be_bytes(b))
    }

    /// A vector with a one-byte length.
    fn vec8(&mut self, part: HelloPart) -> Result<&'a [u8], SniError> {
        let n = self.u8(part)?;
        self.take(usize::from(n), part)
    }

    /// A vector with a two-byte length.
    fn vec16(&mut self, part: HelloPart) -> Result<&'a [u8], SniError> {
        let n = self.u16(part)?;
        self.take(usize::from(n), part)
    }
}

/// Parses a complete ClientHello body (RFC 8446 section 4.1.2).
fn parse_body(body: &[u8]) -> Result<SniOutcome, SniError> {
    let mut r = Reader::new(body);
    let version = r.take(2, HelloPart::LegacyVersion)?;
    if version.first() != Some(&TLS_MAJOR) {
        return Err(SniError::Malformed(HelloPart::LegacyVersion));
    }
    r.take(RANDOM_LEN, HelloPart::Random)?;
    if r.vec8(HelloPart::SessionId)?.len() > MAX_SESSION_ID {
        return Err(SniError::Malformed(HelloPart::SessionId));
    }
    let suites = r.vec16(HelloPart::CipherSuites)?;
    if suites.is_empty() || suites.len() % 2 != 0 {
        return Err(SniError::Malformed(HelloPart::CipherSuites));
    }
    if r.vec8(HelloPart::Compression)?.is_empty() {
        return Err(SniError::Malformed(HelloPart::Compression));
    }
    if r.is_empty() {
        // A hello without extensions names no host.
        return Ok(SniOutcome::NoSni);
    }
    let block = r.vec16(HelloPart::Extensions)?;
    if !r.is_empty() {
        return Err(SniError::Malformed(HelloPart::Extensions));
    }
    parse_extensions(block)
}

/// Parses the extensions block and returns the verdict.
fn parse_extensions(block: &[u8]) -> Result<SniOutcome, SniError> {
    let mut r = Reader::new(block);
    let mut seen: Vec<u16> = Vec::new();
    let mut host: Option<HostName> = None;
    while !r.is_empty() {
        let ty = r.u16(HelloPart::Extension)?;
        let body = r.vec16(HelloPart::Extension)?;
        match seen.binary_search(&ty) {
            Ok(_) => return Err(SniError::DuplicateExtension),
            Err(pos) => seen.insert(pos, ty),
        }
        // Every other extension, `encrypted_client_hello` included, is
        // skipped unread (ADR-009, Daniel 2026-10-29 and 2026-11-13).
        if ty == EXT_SERVER_NAME {
            host = Some(parse_server_name(body)?);
        }
    }
    Ok(host.map_or(SniOutcome::NoSni, SniOutcome::Host))
}

/// Parses the body of a `server_name` extension: a list of exactly one
/// `host_name` entry.
fn parse_server_name(body: &[u8]) -> Result<HostName, SniError> {
    let mut r = Reader::new(body);
    let list = r.vec16(HelloPart::ServerNameList)?;
    if !r.is_empty() || list.is_empty() {
        return Err(SniError::Malformed(HelloPart::ServerNameList));
    }
    let mut entries = Reader::new(list);
    let mut first: Option<(u8, &[u8])> = None;
    while !entries.is_empty() {
        let ty = entries.u8(HelloPart::ServerName)?;
        let name = entries.vec16(HelloPart::ServerName)?;
        if first.is_some() {
            return Err(SniError::MultipleServerNames);
        }
        first = Some((ty, name));
    }
    let Some((ty, name)) = first else {
        return Err(SniError::Malformed(HelloPart::ServerNameList));
    };
    if ty != NAME_TYPE_HOST {
        return Err(SniError::UnknownNameType);
    }
    HostName::parse(name).map_err(SniError::InvalidHost)
}
