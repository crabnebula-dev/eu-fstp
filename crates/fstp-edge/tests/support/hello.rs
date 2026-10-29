//! A reference ClientHello writer for the `fstp-edge` tests and fuzz
//! targets (TH-26, M3 design section 9.4).
//!
//! It follows RFC 8446 section 4.1.2 for the ClientHello and RFC 6066
//! section 3 for the `server_name` extension. It shares no code with the
//! parser under test. The fuzz project includes this file too, so it
//! depends on nothing but `std`.

#![allow(dead_code)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

/// TLS record content type `handshake`.
pub(crate) const CONTENT_HANDSHAKE: u8 = 0x16;
/// Handshake message type `client_hello`.
pub(crate) const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
/// Handshake message type `server_hello`.
pub(crate) const HANDSHAKE_SERVER_HELLO: u8 = 0x02;
/// Extension `server_name` (RFC 6066).
pub(crate) const EXT_SERVER_NAME: u16 = 0x0000;
/// Extension `supported_groups`.
pub(crate) const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
/// Extension `signature_algorithms`.
pub(crate) const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
/// Extension `padding` (RFC 7685).
pub(crate) const EXT_PADDING: u16 = 0x0015;
/// Extension `extended_master_secret` (RFC 7627), empty body.
pub(crate) const EXT_EXTENDED_MASTER_SECRET: u16 = 0x0017;
/// Extension `supported_versions`.
pub(crate) const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
/// Extension `key_share`.
pub(crate) const EXT_KEY_SHARE: u16 = 0x0033;
/// Extension `encrypted_client_hello` (ECH).
pub(crate) const EXT_ECH: u16 = 0xfe0d;
/// Server name type `host_name`, the only type RFC 6066 defines.
pub(crate) const NAME_TYPE_HOST: u8 = 0;
/// The most bytes the edge reads before it decides (design section 9.4).
pub(crate) const MAX_SNI_BUF: usize = 16 * 1024;
/// The largest TLS plaintext record body (RFC 8446 section 5.1).
pub(crate) const MAX_RECORD_BODY: usize = 1 << 14;

/// GREASE extension types (RFC 8701). A parser must skip them.
pub(crate) const GREASE: [u16; 8] = [
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
];

/// The fields of one ClientHello, written in wire order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Hello {
    /// `TLSPlaintext.legacy_record_version`.
    pub(crate) record_version: [u8; 2],
    /// `ClientHello.legacy_version`.
    pub(crate) legacy_version: [u8; 2],
    /// `ClientHello.random`.
    pub(crate) random: [u8; 32],
    /// `legacy_session_id`, at most 32 bytes on a valid hello.
    pub(crate) session_id: Vec<u8>,
    /// `cipher_suites`.
    pub(crate) cipher_suites: Vec<u16>,
    /// `legacy_compression_methods`.
    pub(crate) compression: Vec<u8>,
    /// Extensions in wire order: type and body.
    pub(crate) extensions: Vec<(u16, Vec<u8>)>,
}

impl Hello {
    /// A typical TLS 1.3 hello. With `host`, it carries one `server_name`
    /// extension that names it as a `host_name`.
    pub(crate) fn tls13(host: Option<&[u8]>) -> Hello {
        let mut extensions = vec![
            (EXT_SUPPORTED_VERSIONS, vec![2, 0x03, 0x04]),
            (EXT_SUPPORTED_GROUPS, vec![0, 4, 0x11, 0xec, 0x00, 0x1d]),
            (EXT_SIGNATURE_ALGORITHMS, vec![0, 4, 0x04, 0x03, 0x08, 0x07]),
            (EXT_KEY_SHARE, key_share_x25519(&[0x42; 32])),
        ];
        if let Some(h) = host {
            extensions.insert(0, (EXT_SERVER_NAME, server_name(&[(NAME_TYPE_HOST, h)])));
        }
        Hello {
            record_version: [0x03, 0x01],
            legacy_version: [0x03, 0x03],
            random: [0x5a; 32],
            session_id: vec![0x11; 32],
            cipher_suites: vec![0x1301, 0x1302, 0x1303],
            compression: vec![0],
            extensions,
        }
    }

    /// The extensions block: a two-byte length and the extensions.
    pub(crate) fn extensions_block(&self) -> Vec<u8> {
        let mut exts = Vec::new();
        for (ty, body) in &self.extensions {
            exts.extend_from_slice(&ty.to_be_bytes());
            put_len16(&mut exts, body);
        }
        let mut out = Vec::new();
        put_len16(&mut out, &exts);
        out
    }

    /// The ClientHello body up to and including the compression methods.
    pub(crate) fn fixed_part(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.legacy_version);
        out.extend_from_slice(&self.random);
        put_len8(&mut out, &self.session_id);
        let mut suites = Vec::new();
        for s in &self.cipher_suites {
            suites.extend_from_slice(&s.to_be_bytes());
        }
        put_len16(&mut out, &suites);
        put_len8(&mut out, &self.compression);
        out
    }

    /// The ClientHello body.
    pub(crate) fn body(&self) -> Vec<u8> {
        let mut out = self.fixed_part();
        out.extend_from_slice(&self.extensions_block());
        out
    }

    /// The handshake message: type, three-byte length, body.
    pub(crate) fn handshake(&self) -> Vec<u8> {
        handshake_message(HANDSHAKE_CLIENT_HELLO, &self.body())
    }

    /// One TLS record holding the handshake message.
    pub(crate) fn record(&self) -> Vec<u8> {
        record(self.record_version, &self.handshake())
    }
}

/// A handshake message of type `ty` around `body`.
pub(crate) fn handshake_message(ty: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![ty];
    put_u24(&mut out, body.len());
    out.extend_from_slice(body);
    out
}

/// A handshake record around `fragment`.
pub(crate) fn record(version: [u8; 2], fragment: &[u8]) -> Vec<u8> {
    let mut out = vec![CONTENT_HANDSHAKE, version[0], version[1]];
    put_len16(&mut out, fragment);
    out
}

/// The body of a `server_name` extension holding `names` in order, each a
/// name type and the name bytes.
pub(crate) fn server_name(names: &[(u8, &[u8])]) -> Vec<u8> {
    let mut list = Vec::new();
    for (ty, name) in names {
        list.push(*ty);
        put_len16(&mut list, name);
    }
    let mut out = Vec::new();
    put_len16(&mut out, &list);
    out
}

/// The body of a `key_share` extension with one X25519 share.
pub(crate) fn key_share_x25519(public: &[u8; 32]) -> Vec<u8> {
    let mut entry = 0x001du16.to_be_bytes().to_vec();
    put_len16(&mut entry, public);
    let mut out = Vec::new();
    put_len16(&mut out, &entry);
    out
}

/// The total length of the first TLS record in `bytes`, header included,
/// read from its length field. `None` when the header is incomplete.
pub(crate) fn first_record_len(bytes: &[u8]) -> Option<usize> {
    let hi = *bytes.get(3)?;
    let lo = *bytes.get(4)?;
    Some(5 + usize::from(u16::from_be_bytes([hi, lo])))
}

/// Appends a one-byte length and `data`. A longer `data` writes a wrong
/// length rather than panic, so callers keep their inputs in bounds.
pub(crate) fn put_len8(out: &mut Vec<u8>, data: &[u8]) {
    out.push(u8::try_from(data.len()).unwrap_or(u8::MAX));
    out.extend_from_slice(data);
}

/// Appends a two-byte length and `data`, as [`put_len8`] does.
pub(crate) fn put_len16(out: &mut Vec<u8>, data: &[u8]) {
    let n = u16::try_from(data.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(data);
}

/// Appends a three-byte length.
pub(crate) fn put_u24(out: &mut Vec<u8>, n: usize) {
    let n = u32::try_from(n).unwrap_or(u32::MAX).min(0x00ff_ffff);
    out.extend_from_slice(&n.to_be_bytes()[1..]);
}

/// The lowercase form of a host name, the form `HostName` holds.
pub(crate) fn lowercase(host: &[u8]) -> String {
    host.iter()
        .map(|b| char::from(b.to_ascii_lowercase()))
        .collect()
}
