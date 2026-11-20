//! An in-house DNS client for TXT records (ADR-027), used by the sending
//! domain probe only.
//!
//! - [`txt_query`] encodes one question of type TXT, class IN, with
//!   recursion desired (RFC 1035 section 4.1).
//! - [`decode_txt_response`] reads the answer to it. It checks the id and
//!   the response bit, refuses a truncated answer, reads NXDOMAIN as no
//!   record, and gives the TXT records of the answer section, each as its
//!   character strings joined (RFC 7208 section 3.3). It follows no
//!   compression pointer: owner names are skipped, never read, so a
//!   CNAME chain still yields the TXT records at its end.
//! - [`TcpResolver`] asks the configured resolver over TCP (RFC 7766),
//!   through [`crate::egress::Destination::DnsResolver`].
//!
//! The decoder is fuzzed (`dns_txt_decode`). It never panics, and it
//! bounds what it keeps by [`MAX_RECORDS`] and the message length.
//! No DNSSEC validation is done (ADR-027).

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Duration;

use fstp_rt::{IoExt, Runtime, timeout};

/// The TXT record type (RFC 1035 section 3.2.2).
pub const TYPE_TXT: u16 = 16;
/// The IN class.
pub const CLASS_IN: u16 = 1;
/// The most TXT records one answer may hold. More fails the lookup.
pub const MAX_RECORDS: usize = 64;
/// The longest DNS name in its text form, without the final dot.
pub const MAX_NAME_LEN: usize = 253;
/// The DNS port. [`TcpResolver`] reaches no other.
pub const DNS_PORT: u16 = 53;
/// How long one lookup may take, connection included.
pub const LOOKUP_TIMEOUT: Duration = Duration::from_secs(10);

/// Why a lookup gave no records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsError {
    /// The name is not a host name of letters, digits, hyphens and
    /// underscores in dot-separated labels.
    Name,
    /// The answer does not parse, or holds more than [`MAX_RECORDS`].
    Malformed,
    /// The answer is for another question id, or is not a response.
    NotOurs,
    /// The server set the truncation bit, even over TCP.
    Truncated,
    /// The server answered with this error code, NXDOMAIN aside.
    Server(u8),
    /// The connector refused the resolver, or the transport failed.
    Unreachable,
}

/// The wire form of `name` (RFC 1035 section 3.1), lowercased.
fn encode_name(name: &str, out: &mut Vec<u8>) -> Result<(), DnsError> {
    let n = name.strip_suffix('.').unwrap_or(name);
    if n.is_empty() || n.len() > MAX_NAME_LEN {
        return Err(DnsError::Name);
    }
    for label in n.split('.') {
        let ok = (1..=63).contains(&label.len())
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if !ok {
            return Err(DnsError::Name);
        }
        out.push(u8::try_from(label.len()).map_err(|_| DnsError::Name)?);
        out.extend(label.bytes().map(|b| b.to_ascii_lowercase()));
    }
    out.push(0);
    Ok(())
}

/// One TXT question for `name` with id `id`: a 12-byte header with
/// recursion desired and one question, of type TXT and class IN.
///
/// # Errors
///
/// [`DnsError::Name`] for a name that is not a host name.
pub fn txt_query(id: u16, name: &str) -> Result<Vec<u8>, DnsError> {
    let mut out = Vec::with_capacity(32);
    out.extend_from_slice(&id.to_be_bytes());
    // QR 0, opcode 0, RD 1.
    out.extend_from_slice(&0x0100u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    encode_name(name, &mut out)?;
    out.extend_from_slice(&TYPE_TXT.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(out)
}

/// A reader over one message.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], DnsError> {
        let end = self.at.checked_add(n).ok_or(DnsError::Malformed)?;
        let s = self.bytes.get(self.at..end).ok_or(DnsError::Malformed)?;
        self.at = end;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, DnsError> {
        self.take(1)?.first().copied().ok_or(DnsError::Malformed)
    }

    fn u16(&mut self) -> Result<u16, DnsError> {
        match self.take(2)? {
            [a, b] => Ok(u16::from_be_bytes([*a, *b])),
            _ => Err(DnsError::Malformed),
        }
    }

    /// Skips one name: labels up to a zero byte, or up to a compression
    /// pointer, which ends the name in place.
    fn skip_name(&mut self) -> Result<(), DnsError> {
        for _ in 0..128 {
            let len = self.u8()?;
            match len & 0xC0 {
                0x00 if len == 0 => return Ok(()),
                0x00 => {
                    self.take(usize::from(len))?;
                }
                0xC0 => {
                    self.u8()?;
                    return Ok(());
                }
                _ => return Err(DnsError::Malformed),
            }
        }
        Err(DnsError::Malformed)
    }
}

/// The TXT records of the answer `bytes` to the question with id `id`
/// (module documentation). Each record is its character strings joined.
///
/// # Errors
///
/// [`DnsError::NotOurs`], [`DnsError::Truncated`], [`DnsError::Server`]
/// or [`DnsError::Malformed`].
pub fn decode_txt_response(bytes: &[u8], id: u16) -> Result<Vec<Vec<u8>>, DnsError> {
    let mut r = Reader { bytes, at: 0 };
    if r.u16()? != id {
        return Err(DnsError::NotOurs);
    }
    let flags = r.u16()?;
    if flags & 0x8000 == 0 || flags & 0x7800 != 0 {
        return Err(DnsError::NotOurs);
    }
    if flags & 0x0200 != 0 {
        return Err(DnsError::Truncated);
    }
    let qd = r.u16()?;
    let an = r.u16()?;
    // The authority and additional sections are never read.
    r.u16()?;
    r.u16()?;
    match u8::try_from(flags & 0x000F).map_err(|_| DnsError::Malformed)? {
        0 => {}
        3 => return Ok(Vec::new()),
        code => return Err(DnsError::Server(code)),
    }
    for _ in 0..qd {
        r.skip_name()?;
        r.take(4)?;
    }
    let mut out = Vec::new();
    for _ in 0..an {
        r.skip_name()?;
        let kind = r.u16()?;
        let class = r.u16()?;
        r.take(4)?;
        let len = r.u16()?;
        let data = r.take(usize::from(len))?;
        if kind != TYPE_TXT || class != CLASS_IN {
            continue;
        }
        if out.len() >= MAX_RECORDS {
            return Err(DnsError::Malformed);
        }
        let mut d = Reader { bytes: data, at: 0 };
        let mut text = Vec::with_capacity(data.len());
        while d.at < data.len() {
            let n = d.u8()?;
            text.extend_from_slice(d.take(usize::from(n))?);
        }
        out.push(text);
    }
    Ok(out)
}

/// The TCP frame of `message`: a two-byte length, then the message
/// (RFC 1035 section 4.2.2).
///
/// # Errors
///
/// [`DnsError::Name`] for a message longer than 65535 bytes, which no
/// question of a valid name reaches.
pub fn tcp_frame(message: &[u8]) -> Result<Vec<u8>, DnsError> {
    let len = u16::try_from(message.len()).map_err(|_| DnsError::Name)?;
    let mut out = Vec::with_capacity(message.len().saturating_add(2));
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(message);
    Ok(out)
}

/// One boxed lookup.
pub type LookupFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Vec<Vec<u8>>, DnsError>> + Send + 'a>>;

/// Where the probes look up TXT records. Tests use a fake one.
pub trait TxtResolver: Send + Sync + 'static {
    /// The TXT records at `name`.
    fn txt<'a>(&'a self, name: &'a str) -> LookupFuture<'a>;
}

/// The resolver at a configured address, over TCP (module
/// documentation). It reaches port 53 only.
#[derive(Clone, Debug)]
pub struct TcpResolver<R> {
    rt: R,
    addr: SocketAddr,
}

impl<R: Runtime> TcpResolver<R> {
    /// The resolver at `addr`.
    ///
    /// # Errors
    ///
    /// The connector's refusal of an address that is not on port 53.
    pub fn new(rt: R, addr: SocketAddr) -> Result<TcpResolver<R>, crate::egress::EgressRefusal> {
        crate::egress::check_port(
            &crate::egress::Destination::DnsResolver { addr },
            addr.port(),
        )?;
        Ok(TcpResolver { rt, addr })
    }

    async fn lookup(&self, name: &str) -> Result<Vec<Vec<u8>>, DnsError> {
        let id = fstp_crypto::random_array::<2>()
            .map(u16::from_be_bytes)
            .map_err(|_| DnsError::Unreachable)?;
        let frame = tcp_frame(&txt_query(id, name)?)?;
        let rt = self.rt.clone();
        let addr = self.addr;
        let run = async move {
            let mut tcp = rt
                .connect_tcp(addr)
                .await
                .map_err(|_| DnsError::Unreachable)?;
            tcp.write_all(&frame)
                .await
                .map_err(|_| DnsError::Unreachable)?;
            tcp.flush().await.map_err(|_| DnsError::Unreachable)?;
            let mut len = [0u8; 2];
            tcp.read_exact(&mut len)
                .await
                .map_err(|_| DnsError::Unreachable)?;
            let mut answer = vec![0u8; usize::from(u16::from_be_bytes(len))];
            tcp.read_exact(&mut answer)
                .await
                .map_err(|_| DnsError::Unreachable)?;
            decode_txt_response(&answer, id)
        };
        timeout(&self.rt, LOOKUP_TIMEOUT, run)
            .await
            .map_err(|_| DnsError::Unreachable)?
    }
}

impl<R: Runtime> TxtResolver for TcpResolver<R> {
    fn txt<'a>(&'a self, name: &'a str) -> LookupFuture<'a> {
        Box::pin(self.lookup(name))
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        reason = "test code"
    )]

    use super::*;

    /// An answer to `id` with `records`, each a TXT record of the given
    /// character strings, after one CNAME record, with compressed names.
    fn answer(id: u16, rcode: u16, records: &[&[&[u8]]]) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&id.to_be_bytes());
        m.extend_from_slice(&(0x8180u16 | rcode).to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        let an = u16::try_from(records.len() + 1).unwrap();
        m.extend_from_slice(&an.to_be_bytes());
        m.extend_from_slice(&[0, 0, 0, 0]);
        encode_name("example.org", &mut m).unwrap();
        m.extend_from_slice(&[0, 16, 0, 1]);
        // A CNAME record, skipped.
        m.extend_from_slice(&[0xC0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 2, 0xC0, 12]);
        for strings in records {
            m.extend_from_slice(&[0xC0, 12, 0, 16, 0, 1, 0, 0, 0, 60]);
            let data: Vec<u8> = strings
                .iter()
                .flat_map(|s| {
                    let mut v = vec![u8::try_from(s.len()).unwrap()];
                    v.extend_from_slice(s);
                    v
                })
                .collect();
            m.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
            m.extend_from_slice(&data);
        }
        m
    }

    /// ADR-027: the question is one TXT question with recursion desired.
    #[test]
    fn adr027_txt_query_encodes_one_question() {
        let q = txt_query(0x1234, "_dmarc.Example.org.").unwrap();
        assert_eq!(&q[..4], &[0x12, 0x34, 0x01, 0x00]);
        assert_eq!(&q[4..12], &[0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            &q[12..],
            b"\x06_dmarc\x07example\x03org\x00\x00\x10\x00\x01"
        );
        assert_eq!(txt_query(1, "bad name"), Err(DnsError::Name));
        assert_eq!(txt_query(1, ""), Err(DnsError::Name));
        assert_eq!(txt_query(1, "a..b"), Err(DnsError::Name));
    }

    /// ADR-027, RFC 7208 section 3.3: each record is its strings joined,
    /// and other record types are skipped.
    #[test]
    fn adr027_txt_answer_joins_strings_and_skips_other_types() {
        let m = answer(7, 0, &[&[b"v=spf1 ", b"-all"], &[b"other"]]);
        assert_eq!(
            decode_txt_response(&m, 7).unwrap(),
            vec![b"v=spf1 -all".to_vec(), b"other".to_vec()]
        );
    }

    /// ADR-027: NXDOMAIN is no record, another error code fails, and so do
    /// another id, a truncated answer and a cut message.
    #[test]
    fn adr027_txt_answer_fails_closed() {
        assert_eq!(decode_txt_response(&answer(7, 3, &[]), 7), Ok(Vec::new()));
        assert_eq!(
            decode_txt_response(&answer(7, 2, &[]), 7),
            Err(DnsError::Server(2))
        );
        assert_eq!(
            decode_txt_response(&answer(7, 0, &[]), 8),
            Err(DnsError::NotOurs)
        );
        let mut t = answer(7, 0, &[&[b"x"]]);
        t[2] |= 0x02;
        assert_eq!(decode_txt_response(&t, 7), Err(DnsError::Truncated));
        let m = answer(7, 0, &[&[b"abc"]]);
        for cut in 0..m.len() {
            assert!(decode_txt_response(&m[..cut], 7).is_err(), "cut at {cut}");
        }
    }

    /// ADR-027: an answer with more than [`MAX_RECORDS`] TXT records fails.
    #[test]
    fn adr027_txt_answer_bounds_its_records() {
        let one: &[&[u8]] = &[b"x"];
        let many = vec![one; MAX_RECORDS + 1];
        assert_eq!(
            decode_txt_response(&answer(7, 0, &many), 7),
            Err(DnsError::Malformed)
        );
    }
}
