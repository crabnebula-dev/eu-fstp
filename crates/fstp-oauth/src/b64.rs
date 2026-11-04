//! Unpadded base64url (RFC 4648 section 5), the spelling of every token.

use crate::OauthError;

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// The longest text [`decode_base64url`] reads, in bytes.
pub const MAX_BASE64URL_LEN: usize = 4096;

/// Decoded base64url bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct Base64Url(Vec<u8>);

impl Base64Url {
    /// The decoded bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The decoded bytes, owned.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl std::fmt::Debug for Base64Url {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Base64Url({} bytes)", self.0.len())
    }
}

/// Unpadded base64url of `bytes`.
pub fn encode_base64url(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(4).saturating_add(2) / 3);
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk.first().copied().unwrap_or(0));
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        let chars = chunk.len().saturating_add(1);
        for (i, shift) in [18u32, 12, 6, 0].into_iter().enumerate() {
            if i >= chars {
                break;
            }
            let idx = usize::try_from((n >> shift) & 0x3f).unwrap_or(0);
            out.push(char::from(ALPHABET.get(idx).copied().unwrap_or(b'A')));
        }
    }
    out
}

fn sextet(c: u8) -> Option<u32> {
    let v = match c {
        b'A'..=b'Z' => c.checked_sub(b'A')?,
        b'a'..=b'z' => c.checked_sub(b'a')?.checked_add(26)?,
        b'0'..=b'9' => c.checked_sub(b'0')?.checked_add(52)?,
        b'-' => 62,
        b'_' => 63,
        _ => return None,
    };
    Some(u32::from(v))
}

/// Decodes unpadded base64url text. Fuzzed (`base64url_decode`).
///
/// Padding, the standard alphabet's `+` and `/`, a length of one modulo
/// four and non-zero trailing bits are refused, so each byte string has
/// exactly one accepted spelling.
pub fn decode_base64url(bytes: &[u8]) -> Result<Base64Url, OauthError> {
    if bytes.len() > MAX_BASE64URL_LEN || bytes.len() % 4 == 1 {
        return Err(OauthError::InvalidBase64);
    }
    let mut out = Vec::with_capacity(bytes.len().saturating_mul(3) / 4);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &c in bytes {
        let v = sextet(c).ok_or(OauthError::InvalidBase64)?;
        acc = ((acc << 6) | v) & 0x00ff_ffff;
        bits = bits.saturating_add(6);
        if bits >= 8 {
            bits = bits.saturating_sub(8);
            out.push(u8::try_from((acc >> bits) & 0xff).map_err(|_| OauthError::InvalidBase64)?);
        }
    }
    let mask = (1u32 << bits).saturating_sub(1);
    if acc & mask != 0 {
        return Err(OauthError::InvalidBase64);
    }
    Ok(Base64Url(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ADR-013: every byte string round-trips, and its spelling is unique.
    #[test]
    fn adr013_base64url_round_trips() {
        fstp_prop::check("adr013_base64url_round_trips", |g| {
            let bytes = g.bytes(0..=80);
            let text = encode_base64url(&bytes);
            let back = decode_base64url(text.as_bytes()).map_err(|e| e.to_string())?;
            fstp_prop::prop_assert_eq!(back.as_bytes(), bytes.as_slice());
            Ok(())
        });
    }

    /// ADR-013: non-zero trailing bits are refused.
    #[test]
    fn adr013_base64url_refuses_trailing_bits() {
        assert!(decode_base64url(b"AA").is_ok());
        assert!(decode_base64url(b"AB").is_err());
        assert!(decode_base64url(b"AAB").is_err());
        assert!(decode_base64url(b"AA==").is_err());
    }
}
