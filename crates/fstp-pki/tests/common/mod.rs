//! References, oracles and generators shared by the `fstp-pki` tests.
//!
//! Written by the W1i test agent from design sections 1.2, 1.3, 4.1, 9.1
//! and 15, ADR-005 "Role certificates", ADR-009 "Certificate authorities"
//! and RFC 5280. Nothing here calls `fstp-pki` except [`profile::to_spec`],
//! [`profile::pki_tbs`] and [`profile::pki_issue`], so every reference is
//! independent of the code it checks.
//!
//! The reference profile fixes these choices, which the design leaves open:
//!
//! - Names are UTF8String values, one attribute per RDN, the OU before the
//!   CN. The CN holds 1 to 64 characters (RFC 5280 `ub-common-name`).
//! - The serial is a big-endian magnitude. Leading zero bytes are dropped,
//!   zero is refused, and the INTEGER holds at most 20 octets.
//! - Validity is UTCTime through 2049 and GeneralizedTime from 2050, in
//!   1950 ..= 9999. `not_before` after `not_after` is refused.
//! - A CA has critical basicConstraints `cA TRUE, pathLen 0` and critical
//!   keyUsage `keyCertSign`. A leaf has critical basicConstraints with `cA`
//!   false, critical keyUsage `digitalSignature` and one extKeyUsage
//!   purpose, serverAuth or clientAuth.
//! - A client certificate lives at most 7 days (design section 1.3).

#![allow(
    dead_code,
    unreachable_pub,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    reason = "test references compute on known-small values; each test binary uses a subset"
)]

pub(crate) mod der;
pub(crate) mod keys;
pub(crate) mod oracle;
pub(crate) mod pem;
pub(crate) mod pg;
pub(crate) mod pop;
pub(crate) mod profile;
pub(crate) mod time;

use fstp_prop::Gen;

/// A common name of 1 to 64 characters, edge-biased by `fstp-prop`.
pub(crate) fn gen_cn(g: &mut Gen) -> String {
    let s = g.string(1..=64);
    if s.is_empty() { "x".to_owned() } else { s }
}

/// A serial magnitude of 0 to 22 bytes, so both limits and zero occur.
pub(crate) fn gen_serial(g: &mut Gen) -> Vec<u8> {
    g.bytes(0..=22)
}

/// A valid serial magnitude: 1 to 19 bytes with a nonzero first byte.
pub(crate) fn gen_valid_serial(g: &mut Gen) -> Vec<u8> {
    let mut s = g.bytes(1..=19);
    if s[0] == 0 {
        s[0] = 1;
    }
    s
}

/// An instant inside the encodable range, biased to the range ends and the
/// UTCTime to GeneralizedTime switch.
pub(crate) fn gen_time(g: &mut Gen) -> i64 {
    match g.weighted(&[3, 1, 1, 1]) {
        0 => g.i64_in(time::MIN_TIME..=time::MAX_TIME),
        1 => g.i64_in(time::GENERALIZED_FROM - 2..=time::GENERALIZED_FROM + 1),
        2 => g.i64_in(time::MIN_TIME..=time::MIN_TIME + 1),
        _ => g.i64_in(time::MAX_TIME - 1..=time::MAX_TIME),
    }
}

/// An instant that may fall outside the encodable range by a little.
pub(crate) fn gen_any_time(g: &mut Gen) -> i64 {
    match g.weighted(&[2, 1, 1]) {
        0 => gen_time(g),
        1 => g.i64_in(time::MIN_TIME - 2..=time::MIN_TIME + 1),
        _ => g.i64_in(time::MAX_TIME - 1..=time::MAX_TIME + 2),
    }
}

/// The content of `bytes` when `bytes` is exactly one TLV with tag `tag`.
///
/// This reads no length: it asks the reference writer which length octets
/// each candidate content length would get, and compares. So it holds no
/// in-house DER parser.
pub(crate) fn tlv_content(tag: u8, bytes: &[u8]) -> Result<&[u8], String> {
    if bytes.first() != Some(&tag) {
        return Err(format!(
            "expected tag {tag:#04x}, found {:02x?}",
            bytes.first()
        ));
    }
    for h in 1..=5 {
        if bytes.len() < 1 + h {
            break;
        }
        let content_len = bytes.len() - 1 - h;
        if der::len(content_len) == bytes[1..1 + h] {
            return Ok(&bytes[1 + h..]);
        }
    }
    Err(format!(
        "{} bytes are not one DER TLV with tag {tag:#04x}",
        bytes.len()
    ))
}

/// The content of `bytes` when `bytes` is exactly one SEQUENCE.
pub(crate) fn split_sequence(bytes: &[u8]) -> Result<&[u8], String> {
    tlv_content(0x30, bytes)
}

/// Checks that `bytes` is exactly one TLV with tag `tag`.
pub(crate) fn single_tlv(tag: u8, bytes: &[u8]) -> Result<(), String> {
    tlv_content(tag, bytes).map(|_| ())
}

/// The cluster kind markers of design section 4.1, the only OU values a
/// server certificate may carry (I-83).
pub(crate) const CLUSTER_KINDS: [&str; 4] = ["application", "vault", "control", "witness"];

/// An optional OU for a name. A server subject gets a cluster kind marker
/// or none. Any other name gets none, a marker, or free text of 1 to 64
/// characters.
pub(crate) fn gen_ou(g: &mut Gen, server_subject: bool) -> Option<String> {
    match g.weighted(&[1, 1, if server_subject { 0 } else { 1 }]) {
        0 => None,
        1 => Some((*g.pick(&CLUSTER_KINDS)).to_owned()),
        _ => Some(gen_cn(g)),
    }
}

/// One lowercase LDH label of `len` bytes. It neither starts nor ends with
/// a hyphen. With `last`, it starts with a letter, so the name's last
/// label is never all digits (RFC 1123 section 2.1).
fn gen_label(g: &mut Gen, len: usize, last: bool) -> String {
    const ALNUM: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    const LETTERS: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
    const INNER: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789-";
    (0..len)
        .map(|i| {
            let set = if i == 0 && last {
                LETTERS
            } else if i == 0 || i + 1 == len {
                ALNUM
            } else {
                INNER
            };
            char::from(*g.pick(set))
        })
        .collect()
}

/// A valid `dNSName`: lowercase LDH labels. It is biased to the limits: a
/// 63-byte label, and a 253-byte name of four labels.
pub(crate) fn gen_dns_name(g: &mut Gen) -> String {
    let lens: Vec<usize> = match g.weighted(&[3, 1, 1]) {
        0 => {
            let n = g.usize_in(1..=4);
            (0..n).map(|_| g.usize_in(1..=12)).collect()
        }
        1 => vec![g.usize_in(1..=8), 63],
        _ => vec![63, 63, 63, 61],
    };
    let last = lens.len() - 1;
    let labels: Vec<String> = lens
        .iter()
        .enumerate()
        .map(|(i, len)| gen_label(g, *len, i == last))
        .collect();
    labels.join(".")
}

/// An IPv4 or IPv6 address with arbitrary octets.
pub(crate) fn gen_ip(g: &mut Gen) -> std::net::IpAddr {
    if g.bool() {
        let b = g.bytes(4..=4);
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]))
    } else {
        let b = g.bytes(16..=16);
        let mut o = [0u8; 16];
        o.copy_from_slice(&b);
        std::net::IpAddr::V6(std::net::Ipv6Addr::from(o))
    }
}
