//! The closed grammars behind the byte-carrying field types (I-19, design
//! section 9.1, ADR-010, ADR-011).
//!
//! Each check accepts one spelling per value, so no byte of an accepted
//! field is left free to carry data:
//!
//! - `ScramVerifier`: `SCRAM-SHA-256$<iterations>:<salt>$<StoredKey>:
//!   <ServerKey>` with canonical padded base64 fields (ADR-011);
//! - `PopSig`: an ASN.1 DER `ECDSA-Sig-Value` for P-256, with `r`
//!   and `s` in 1 to n - 1 (the fstp-pki `pop` module);
//! - `CertDer`: a DER `Certificate`, a SEQUENCE of exactly a
//!   SEQUENCE, a SEQUENCE and a BIT STRING, every length in its shortest
//!   form;
//! - `CompositeSig`: `mldsaSig || tradSig`, exactly
//!   [`COMPOSITE_SIG_LEN`] bytes (ADR-010).

use crate::ProtoError;

/// The length of a composite ML-DSA-65 and Ed25519 signature, `mldsaSig
/// || tradSig`: 3309 and 64 bytes (ADR-010 "Composite encoding"). The
/// test `i19_composite_sig_accepts_exactly_the_composite_layout` ties it
/// to `fstp_crypto::composite::SIGNATURE_LEN`.
pub const COMPOSITE_SIG_LEN: usize = 3373;

/// The fewest SCRAM iterations a verifier may name. ADR-011 records the
/// minimum at first use. This is that first use: 4096, the floor that
/// `fstp-pgwire` already enforces as a client (HANDOFF, decisions of
/// 2026-10-25).
pub const MIN_SCRAM_ITERATIONS: u32 = 4096;

/// The most SCRAM iterations a verifier may name: PostgreSQL keeps the
/// count in a signed 32-bit integer.
pub const MAX_SCRAM_ITERATIONS: u32 = 2_147_483_647;

/// The shortest SCRAM salt, in bytes. PostgreSQL draws 16.
pub const MIN_SCRAM_SALT_LEN: usize = 16;

/// The longest SCRAM salt, in bytes.
pub const MAX_SCRAM_SALT_LEN: usize = 64;

/// The length of a SCRAM-SHA-256 StoredKey or ServerKey: one SHA-256
/// output.
pub const SCRAM_KEY_LEN: usize = 32;

/// The longest certificate the protocol carries, in bytes.
pub const MAX_CERT_LEN: usize = 8192;

/// The deepest nesting of constructed DER values inside a certificate.
const MAX_DER_DEPTH: usize = 16;

/// The shortest DER P-256 signature: two one-byte INTEGERs.
pub const MIN_POP_SIG_LEN: usize = 8;

/// The longest DER P-256 signature: two 33-byte INTEGERs.
pub const MAX_POP_SIG_LEN: usize = 72;

/// The order `n` of the P-256 group, big-endian (SEC 2 section 2.4.2).
const P256_N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

fn refuse(what: &'static str) -> ProtoError {
    ProtoError::Grammar(what)
}

// ---------------------------------------------------------------------------
// Base64 (RFC 4648 section 4, padded, canonical).

fn b64_digit(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => c.checked_sub(b'A'),
        b'a'..=b'z' => c.checked_sub(b'a').and_then(|v| v.checked_add(26)),
        b'0'..=b'9' => c.checked_sub(b'0').and_then(|v| v.checked_add(52)),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// The length of the bytes that canonical padded base64 `text` spells, or
/// `None` when `text` is not canonical: a length that is a multiple of 4,
/// padding only at the end and only as needed, and zero unused bits.
fn canonical_b64_len(text: &[u8]) -> Option<usize> {
    if text.is_empty() || !text.len().is_multiple_of(4) {
        return None;
    }
    let pad = text.iter().rev().take_while(|c| **c == b'=').count();
    if pad > 2 {
        return None;
    }
    let digits = text.get(..text.len().checked_sub(pad)?)?;
    let mut last = 0u8;
    for c in digits {
        last = b64_digit(*c)?;
    }
    // One padding byte leaves 2 unused bits in the last digit, two leave 4.
    let unused_mask = match pad {
        0 => 0,
        1 => 0b11,
        _ => 0b1111,
    };
    if last & unused_mask != 0 {
        return None;
    }
    (text.len() / 4).checked_mul(3)?.checked_sub(pad)
}

// ---------------------------------------------------------------------------
// ScramVerifier (ADR-011).

/// Whether `text` is a decimal count without sign or leading zero, within
/// the iteration bounds.
fn iterations_fit(text: &[u8]) -> bool {
    if text.is_empty() || text.len() > 10 || text.first() == Some(&b'0') {
        return false;
    }
    let mut n: u64 = 0;
    for c in text {
        if !c.is_ascii_digit() {
            return false;
        }
        let Some(next) = n
            .checked_mul(10)
            .and_then(|v| v.checked_add(u64::from(c.wrapping_sub(b'0'))))
        else {
            return false;
        };
        n = next;
    }
    (u64::from(MIN_SCRAM_ITERATIONS)..=u64::from(MAX_SCRAM_ITERATIONS)).contains(&n)
}

/// Checks the SCRAM-SHA-256 verifier grammar of ADR-011.
pub(crate) fn scram_verifier(bytes: &[u8]) -> Result<(), ProtoError> {
    const PREFIX: &[u8] = b"SCRAM-SHA-256$";
    let what = "ScramVerifier";
    let rest = bytes.strip_prefix(PREFIX).ok_or(refuse(what))?;
    let mut parts = rest.split(|c| *c == b'$');
    let (Some(params), Some(keys), None) = (parts.next(), parts.next(), parts.next()) else {
        return Err(refuse(what));
    };
    let mut params = params.split(|c| *c == b':');
    let (Some(iterations), Some(salt), None) = (params.next(), params.next(), params.next()) else {
        return Err(refuse(what));
    };
    let mut keys = keys.split(|c| *c == b':');
    let (Some(stored), Some(server), None) = (keys.next(), keys.next(), keys.next()) else {
        return Err(refuse(what));
    };
    if !iterations_fit(iterations) {
        return Err(refuse(what));
    }
    let salt_ok = canonical_b64_len(salt)
        .is_some_and(|n| (MIN_SCRAM_SALT_LEN..=MAX_SCRAM_SALT_LEN).contains(&n));
    let keys_ok = [stored, server]
        .iter()
        .all(|k| canonical_b64_len(k) == Some(SCRAM_KEY_LEN));
    if salt_ok && keys_ok {
        Ok(())
    } else {
        Err(refuse(what))
    }
}

// ---------------------------------------------------------------------------
// DER.

/// One DER value at the start of `b`: its tag, its content and the rest.
/// Refuses the high tag number form, the indefinite length, long forms
/// that a shorter form could spell, and lengths beyond `b`.
fn der_tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = b.split_first()?;
    if tag & 0x1f == 0x1f {
        return None;
    }
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = match first {
        0x00..=0x7f => (usize::from(first), rest),
        0x81 => {
            let (&l, rest) = rest.split_first()?;
            if l < 0x80 {
                return None;
            }
            (usize::from(l), rest)
        }
        0x82 => {
            let (&hi, rest) = rest.split_first()?;
            let (&lo, rest) = rest.split_first()?;
            if hi == 0 {
                return None;
            }
            (usize::from(u16::from_be_bytes([hi, lo])), rest)
        }
        _ => return None,
    };
    if rest.len() < len {
        return None;
    }
    let (content, rest) = rest.split_at(len);
    Some((tag, content, rest))
}

/// Whether `b` is a sequence of well-formed DER values, each constructed
/// value well-formed inside, at most `depth` levels deep.
fn der_values_fit(mut b: &[u8], depth: usize) -> bool {
    let Some(inner) = depth.checked_sub(1) else {
        return false;
    };
    while !b.is_empty() {
        let Some((tag, content, rest)) = der_tlv(b) else {
            return false;
        };
        if tag & 0x20 != 0 && !der_values_fit(content, inner) {
            return false;
        }
        b = rest;
    }
    true
}

/// Checks the DER `Certificate` grammar: a SEQUENCE of exactly a
/// SEQUENCE (the TBS certificate), a SEQUENCE (the signature algorithm)
/// and a BIT STRING with no unused bits (the signature), nothing after it.
pub(crate) fn certificate(bytes: &[u8]) -> Result<(), ProtoError> {
    let what = "CertDer";
    if bytes.len() > MAX_CERT_LEN {
        return Err(refuse(what));
    }
    let (tag, body, rest) = der_tlv(bytes).ok_or(refuse(what))?;
    if tag != 0x30 || !rest.is_empty() {
        return Err(refuse(what));
    }
    let (tbs_tag, tbs, body) = der_tlv(body).ok_or(refuse(what))?;
    let (alg_tag, alg, body) = der_tlv(body).ok_or(refuse(what))?;
    let (sig_tag, sig, body) = der_tlv(body).ok_or(refuse(what))?;
    let shape = tbs_tag == 0x30
        && alg_tag == 0x30
        && sig_tag == 0x03
        && body.is_empty()
        && sig.first() == Some(&0x00)
        && sig.len() > 1
        && !tbs.is_empty()
        && !alg.is_empty();
    if shape && der_values_fit(tbs, MAX_DER_DEPTH) && der_values_fit(alg, MAX_DER_DEPTH) {
        Ok(())
    } else {
        Err(refuse(what))
    }
}

/// One minimal positive DER INTEGER at the start of `b`, of a value in 1
/// to n - 1: its magnitude and the rest.
fn p256_scalar(b: &[u8]) -> Option<&[u8]> {
    let (&tag, rest) = b.split_first()?;
    let (&len, rest) = rest.split_first()?;
    let len = usize::from(len);
    if tag != 0x02 || !(1..=33).contains(&len) || rest.len() < len {
        return None;
    }
    let (content, rest) = rest.split_at(len);
    let (&first, tail) = content.split_first()?;
    if first & 0x80 != 0 {
        return None;
    }
    let magnitude = if first == 0 {
        // A leading zero is allowed only to keep a high bit positive.
        match tail.first() {
            Some(next) if next & 0x80 != 0 => tail,
            _ => return None,
        }
    } else {
        content
    };
    if magnitude.len() > 32 {
        return None;
    }
    let mut padded = [0u8; 32];
    let start = 32usize.checked_sub(magnitude.len())?;
    padded.get_mut(start..)?.copy_from_slice(magnitude);
    if padded.iter().all(|b| *b == 0) || padded >= P256_N {
        return None;
    }
    Some(rest)
}

/// Checks the proof-of-possession signature grammar: `SEQUENCE { INTEGER
/// r, INTEGER s }` in DER, short-form lengths, each INTEGER minimal,
/// positive and below n.
pub(crate) fn pop_signature(bytes: &[u8]) -> Result<(), ProtoError> {
    let what = "PopSig";
    if !(MIN_POP_SIG_LEN..=MAX_POP_SIG_LEN).contains(&bytes.len()) {
        return Err(refuse(what));
    }
    let ok = (|| {
        let (&tag, rest) = bytes.split_first()?;
        let (&len, body) = rest.split_first()?;
        if tag != 0x30 || len >= 0x80 || usize::from(len) != body.len() {
            return None;
        }
        let rest = p256_scalar(body)?;
        let rest = p256_scalar(rest)?;
        rest.is_empty().then_some(())
    })();
    ok.ok_or(refuse(what))
}

/// Checks the composite signature layout of ADR-010: exactly
/// [`COMPOSITE_SIG_LEN`] bytes. Validity is the verifier's.
pub(crate) fn composite_signature(bytes: &[u8]) -> Result<(), ProtoError> {
    if bytes.len() == COMPOSITE_SIG_LEN {
        Ok(())
    } else {
        Err(refuse("CompositeSig"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// I-19: canonical base64 spells each byte string once.
    #[test]
    fn i19_canonical_base64_refuses_other_spellings() {
        assert_eq!(canonical_b64_len(b"AAAA"), Some(3));
        assert_eq!(canonical_b64_len(b"AA=="), Some(1));
        assert_eq!(canonical_b64_len(b"AAA="), Some(2));
        for bad in [
            &b""[..],
            b"AAA",
            b"AB==",
            b"AAB=",
            b"A===",
            b"AA=A",
            b"AA*=",
        ] {
            assert_eq!(canonical_b64_len(bad), None, "{bad:?}");
        }
    }

    /// I-19: DER lengths take their shortest form.
    #[test]
    fn i19_der_lengths_take_their_shortest_form() {
        assert!(der_tlv(&[0x04, 0x01, 0xaa]).is_some());
        assert!(der_tlv(&[0x04, 0x81, 0x01, 0xaa]).is_none());
        assert!(der_tlv(&[0x04, 0x82, 0x00, 0x01, 0xaa]).is_none());
        assert!(der_tlv(&[0x04, 0x80]).is_none());
        assert!(der_tlv(&[0x1f, 0x01, 0x00]).is_none());
    }
}
