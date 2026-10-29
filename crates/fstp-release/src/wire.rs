//! Byte helpers shared by the formats of this crate.
//!
//! Every helper is total. Reads return `None` past the end of the input,
//! and no helper panics or wraps.

use fstp_crypto::sig::{self, ED25519_PUBLIC_KEY_LEN, Ed25519SigningKey};

use crate::ReleaseError;

/// The message an Ed25519 format signature covers:
/// `context || 0x00 || body`.
pub(crate) fn signed_message(context: &[u8], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(context.len().saturating_add(body.len()).saturating_add(1));
    out.extend_from_slice(context);
    out.push(0);
    out.extend_from_slice(body);
    out
}

/// Whether `signature` is a valid Ed25519 signature by `key` over
/// `context || 0x00 || body`.
pub(crate) fn signed_by(
    key: &[u8; ED25519_PUBLIC_KEY_LEN],
    context: &[u8],
    body: &[u8],
    signature: &[u8],
) -> bool {
    sig::ed25519_verify(key, &signed_message(context, body), signature).is_ok()
}

/// `body` followed by an Ed25519 signature by `key` over
/// `context || 0x00 || body`.
pub(crate) fn sign(
    key: &Ed25519SigningKey,
    context: &[u8],
    body: Vec<u8>,
) -> Result<Vec<u8>, ReleaseError> {
    let signature = key
        .sign(&signed_message(context, &body))
        .map_err(|_| ReleaseError::Signing)?;
    let mut out = body;
    out.extend_from_slice(&signature);
    Ok(out)
}

/// The fixed-size array at `at` in `bytes`.
pub(crate) fn array<const N: usize>(bytes: &[u8], at: usize) -> Option<[u8; N]> {
    let end = at.checked_add(N)?;
    bytes.get(at..end)?.try_into().ok()
}

/// The big-endian `i64` at `at`.
pub(crate) fn be_i64(bytes: &[u8], at: usize) -> Option<i64> {
    array::<8>(bytes, at).map(i64::from_be_bytes)
}

/// The big-endian `u64` at `at`.
pub(crate) fn be_u64(bytes: &[u8], at: usize) -> Option<u64> {
    array::<8>(bytes, at).map(u64::from_be_bytes)
}

/// The big-endian `u16` at `at`.
pub(crate) fn be_u16(bytes: &[u8], at: usize) -> Option<u16> {
    array::<2>(bytes, at).map(u16::from_be_bytes)
}

/// The lowercase hex digits.
const HEX: &[u8; 16] = b"0123456789abcdef";

/// The lowercase hex of `bytes`, two digits per byte.
pub(crate) fn lower_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        for nibble in [b >> 4, b & 0x0f] {
            if let Some(c) = HEX.get(usize::from(nibble)) {
                out.push(char::from(*c));
            }
        }
    }
    out
}

/// The value of one lowercase hex digit. Upper case is refused, so each
/// byte string has one spelling.
const fn hex_value(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(c.wrapping_sub(b'a').wrapping_add(10)),
        _ => None,
    }
}

/// The `N` bytes of exactly `2 * N` lowercase hex digits.
pub(crate) fn parse_lower_hex<const N: usize>(text: &[u8]) -> Option<[u8; N]> {
    if text.len() != N.checked_mul(2)? {
        return None;
    }
    let mut out = [0u8; N];
    for (slot, pair) in out.iter_mut().zip(text.chunks_exact(2)) {
        let hi = hex_value(*pair.first()?)?;
        let lo = hex_value(*pair.get(1)?)?;
        *slot = (hi << 4) | lo;
    }
    Some(out)
}

/// The base64 alphabet of RFC 4648 section 4.
const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard padded base64 (RFC 4648 section 4).
pub(crate) fn base64(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3).saturating_mul(4));
    for chunk in bytes.chunks(3) {
        let b0 = chunk.first().copied().unwrap_or(0);
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let n = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        let sextets = [n >> 18, n >> 12, n >> 6, n];
        for (i, s) in sextets.iter().enumerate() {
            if i <= chunk.len() {
                if let Some(c) = B64.get((s & 0x3f) as usize) {
                    out.push(char::from(*c));
                }
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// The value of one base64 character, or `None` outside the alphabet.
fn b64_value(c: u8) -> Option<u32> {
    let v = match c {
        b'A'..=b'Z' => c.wrapping_sub(b'A'),
        b'a'..=b'z' => c.wrapping_sub(b'a').wrapping_add(26),
        b'0'..=b'9' => c.wrapping_sub(b'0').wrapping_add(52),
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    };
    Some(u32::from(v))
}

/// Decodes standard padded base64 in its one canonical spelling. Missing
/// padding, padding inside the text, set unused bits and characters
/// outside the alphabet are refused, so `base64(unbase64(t)) == t`.
pub(crate) fn unbase64(text: &[u8]) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(4) {
        return None;
    }
    let quads = text.len() / 4;
    let mut out = Vec::with_capacity(quads.saturating_mul(3));
    for (index, quad) in text.chunks_exact(4).enumerate() {
        let last = index.checked_add(1)? == quads;
        let mut n = 0u32;
        let mut pad = 0usize;
        for c in quad {
            n <<= 6;
            if *c == b'=' {
                pad = pad.saturating_add(1);
            } else if pad > 0 {
                return None;
            } else {
                n |= b64_value(*c)?;
            }
        }
        if pad > 2 || (pad > 0 && !last) {
            return None;
        }
        let [_, a, b, c] = n.to_be_bytes();
        let take = 3usize.checked_sub(pad)?;
        let unused = match pad {
            0 => 0,
            1 => u32::from(c),
            _ => (u32::from(b) << 8) | u32::from(c),
        };
        if unused != 0 {
            return None;
        }
        out.extend_from_slice([a, b, c].get(..take)?);
    }
    Some(out)
}

/// Renders `n` in decimal without leading zeros.
pub(crate) fn push_decimal(out: &mut String, n: u64) {
    let mut digits = [0u8; 20];
    let mut len = 0usize;
    let mut rest = n;
    loop {
        if let Some(slot) = digits.get_mut(len) {
            *slot = b'0'.wrapping_add((rest % 10) as u8);
        }
        len = len.saturating_add(1);
        rest /= 10;
        if rest == 0 {
            break;
        }
    }
    for d in digits.get(..len).unwrap_or_default().iter().rev() {
        out.push(char::from(*d));
    }
}

/// A plain decimal of at most `max_digits` digits without a sign or a
/// leading zero ("0" itself is allowed).
pub(crate) fn parse_plain_decimal(text: &[u8], max_digits: usize) -> Option<u64> {
    if text.is_empty() || text.len() > max_digits {
        return None;
    }
    if text.len() > 1 && text.first() == Some(&b'0') {
        return None;
    }
    let mut n = 0u64;
    for c in text {
        if !c.is_ascii_digit() {
            return None;
        }
        n = n
            .checked_mul(10)?
            .checked_add(u64::from(c.wrapping_sub(b'0')))?;
    }
    Some(n)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    /// RFC 4648 section 10 test vectors, both ways.
    #[test]
    fn i38_base64_rfc4648_vectors_round_trip() {
        let vectors: [(&[u8], &str); 7] = [
            (b"", ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
        ];
        for (bytes, text) in vectors {
            assert_eq!(base64(bytes), text);
            assert_eq!(unbase64(text.as_bytes()).unwrap(), bytes);
        }
    }

    /// Non-canonical spellings are refused.
    #[test]
    fn i38_unbase64_refuses_other_spellings() {
        for bad in [
            "Zg", "Zh==", "Zm9=", "Z===", "Zg==Zg==", "Zm-v", "Zm_v", " Zg=",
        ] {
            assert_eq!(unbase64(bad.as_bytes()), None, "{bad}");
        }
    }

    #[test]
    fn i38_decimal_and_hex_have_one_spelling() {
        let mut s = String::new();
        push_decimal(&mut s, 0);
        push_decimal(&mut s, 65_535);
        assert_eq!(s, "065535");
        assert_eq!(parse_plain_decimal(b"0", 5), Some(0));
        assert_eq!(parse_plain_decimal(b"01", 5), None);
        assert_eq!(parse_plain_decimal(b"+1", 5), None);
        assert_eq!(parse_plain_decimal(b"123456", 5), None);
        assert_eq!(lower_hex(&[0x0a, 0xff]), "0aff");
        assert_eq!(parse_lower_hex::<2>(b"0aff"), Some([0x0a, 0xff]));
        assert_eq!(parse_lower_hex::<2>(b"0AFF"), None);
        assert_eq!(parse_lower_hex::<2>(b"0af"), None);
    }
}
