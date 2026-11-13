//! Shared generators and verdict helpers for the `fstp-edge` tests.
//!
//! The helpers tell a real refusal from the W0 stub's `NotImplemented`
//! refusal by the error's `Debug` form. So a test that expects a refusal
//! stays red while the stub refuses everything, and still compiles once
//! lane W2i replaces the error variants.

#![allow(dead_code)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::fmt::Debug;

use fstp_edge::{HostName, SniError, SniOutcome, TUNNEL_HEADER_LEN};
use fstp_prop::Gen;

use crate::hello::{
    EXT_EXTENDED_MASTER_SECRET, EXT_KEY_SHARE, EXT_PADDING, EXT_SERVER_NAME,
    EXT_SIGNATURE_ALGORITHMS, EXT_SUPPORTED_GROUPS, EXT_SUPPORTED_VERSIONS, GREASE, Hello,
    NAME_TYPE_HOST, key_share_x25519, server_name,
};

/// Whether an error is the W0 stub's refusal.
pub(crate) fn is_stub<E: Debug>(e: &E) -> bool {
    format!("{e:?}").starts_with("NotImplemented")
}

/// The parser's verdict, as text for a property message.
pub(crate) type Verdict = Result<SniOutcome, SniError>;

/// A real refusal: an error that is not the stub's.
pub(crate) fn refused(v: &Verdict) -> bool {
    matches!(v, Err(e) if !is_stub(e))
}

/// The edge closes the connection: a real refusal, no SNI or not TLS
/// (design section 9.4: "No SNI, an unknown host or a malformed hello
/// closes the connection").
pub(crate) fn closes(v: &Verdict) -> bool {
    refused(v) || matches!(v, Ok(SniOutcome::NoSni | SniOutcome::NotTls))
}

/// The host of a `Host` verdict.
pub(crate) fn host_of(v: &Verdict) -> Option<&HostName> {
    match v {
        Ok(SniOutcome::Host(h)) => Some(h),
        _ => None,
    }
}

/// Parses `bytes` and returns the host, or a message naming the verdict.
pub(crate) fn parse_host(bytes: &[u8]) -> Result<HostName, String> {
    match fstp_edge::parse_client_hello_sni(bytes) {
        Ok(SniOutcome::Host(h)) => Ok(h),
        other => Err(format!("a valid hello did not name its host: {other:?}")),
    }
}

/// Bytes allowed in a host label (LDH, RFC 1123), lowercase.
pub(crate) const LDH: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789-";
/// Letters and digits, for the first and last byte of a label.
pub(crate) const ALNUM: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
/// Letters, for the first byte of the last label, so a generated name is
/// never an address literal.
pub(crate) const LETTERS: &[u8] = b"abcdefghijklmnopqrstuvwxyz";

/// A valid host name of 1 to 253 bytes in random case. Labels hold 1 to
/// 63 LDH bytes, start and end with a letter or digit, and the last label
/// starts with a letter.
pub(crate) fn gen_host(g: &mut Gen) -> Vec<u8> {
    let count = g.usize_in(1..=6);
    let mut labels: Vec<Vec<u8>> = Vec::new();
    let mut total = 0usize;
    for _ in 0..count {
        let len = g.usize_in(1..=63);
        let mut label = Vec::with_capacity(len);
        for j in 0..len {
            let edge = j == 0 || j + 1 == len;
            label.push(*g.pick(if edge { ALNUM } else { LDH }));
        }
        let extra = if labels.is_empty() { len } else { len + 1 };
        if total + extra > 253 {
            break;
        }
        total += extra;
        labels.push(label);
    }
    if labels.is_empty() {
        labels.push(vec![b'a']);
    }
    if let Some(last) = labels.last_mut() {
        last[0] = *g.pick(LETTERS);
    }
    let mut host = labels.join(&b'.');
    for b in &mut host {
        if g.bool() {
            *b = b.to_ascii_uppercase();
        }
    }
    host
}

/// Extensions that a parser must skip without reading: GREASE values with
/// random bodies, padding and `extended_master_secret`.
fn gen_other_extension(g: &mut Gen) -> (u16, Vec<u8>) {
    match g.u8_in(0..=2) {
        0 => (*g.pick(&GREASE), g.bytes(0..=24)),
        1 => (EXT_PADDING, vec![0; g.usize_in(0..=64)]),
        _ => (EXT_EXTENDED_MASTER_SECRET, Vec::new()),
    }
}

/// A random valid TLS 1.3 ClientHello with `sni` as its `server_name`
/// extension body, if any, at a random position.
pub(crate) fn gen_hello_with(g: &mut Gen, sni: Option<Vec<u8>>) -> Hello {
    let mut random = [0u8; 32];
    for b in &mut random {
        *b = g.u8();
    }
    let session_id = g.bytes(0..=32);
    let cipher_suites = g.vec(1..=12, |g| {
        *g.pick(&[0x1301u16, 0x1302, 0x1303, 0x0a0a, 0xc02b])
    });
    let mut extensions: Vec<(u16, Vec<u8>)> = vec![
        (EXT_SUPPORTED_VERSIONS, vec![2, 0x03, 0x04]),
        (EXT_SUPPORTED_GROUPS, vec![0, 4, 0x11, 0xec, 0x00, 0x1d]),
        (EXT_SIGNATURE_ALGORITHMS, vec![0, 4, 0x04, 0x03, 0x08, 0x07]),
    ];
    let mut share = [0u8; 32];
    for b in &mut share {
        *b = g.u8();
    }
    extensions.push((EXT_KEY_SHARE, key_share_x25519(&share)));
    for (ty, body) in g.vec(0..=5, gen_other_extension) {
        if extensions.iter().all(|(t, _)| *t != ty) {
            extensions.push((ty, body));
        }
    }
    g.shuffle(&mut extensions);
    if let Some(body) = sni {
        let at = g.usize_in(0..=extensions.len());
        extensions.insert(at, (EXT_SERVER_NAME, body));
    }
    Hello {
        record_version: *g.pick(&[[0x03, 0x01], [0x03, 0x03]]),
        legacy_version: [0x03, 0x03],
        random,
        session_id,
        cipher_suites,
        compression: vec![0],
        extensions,
    }
}

/// A random valid hello that names `host` in one `server_name` extension.
pub(crate) fn gen_hello_naming(g: &mut Gen, host: &[u8]) -> Hello {
    gen_hello_with(g, Some(server_name(&[(NAME_TYPE_HOST, host)])))
}

/// A host name known to the edge, parsed from a valid hello. `HostName`
/// has no public constructor in the W0 stub, so the parser is the only
/// source (gap recorded in the lane report).
pub(crate) fn host_via_parser(g: &mut Gen) -> Result<HostName, String> {
    let host = gen_host(g);
    let hello = gen_hello_naming(g, &host);
    parse_host(&hello.record())
}

/// Turns what `encode_tunnel_header` returns into bytes. The design gives
/// an infallible encoder (`[u8; TUNNEL_HEADER_LEN]`), and the W0 stub
/// returns a `Result`. Both forms implement this trait, so the tests
/// compile against either.
pub(crate) trait Encoded {
    /// The encoded header, or a message naming the refusal.
    fn into_bytes(self) -> Result<[u8; TUNNEL_HEADER_LEN], String>;
}

impl Encoded for [u8; TUNNEL_HEADER_LEN] {
    fn into_bytes(self) -> Result<[u8; TUNNEL_HEADER_LEN], String> {
        Ok(self)
    }
}

impl<E: Debug> Encoded for Result<[u8; TUNNEL_HEADER_LEN], E> {
    fn into_bytes(self) -> Result<[u8; TUNNEL_HEADER_LEN], String> {
        self.map_err(|e| format!("encode_tunnel_header refused: {e:?}"))
    }
}

/// Encodes a tunnel header through [`Encoded`].
pub(crate) fn encode(h: &fstp_edge::TunnelHeader) -> Result<[u8; TUNNEL_HEADER_LEN], String> {
    fstp_edge::encode_tunnel_header(h).into_bytes()
}
