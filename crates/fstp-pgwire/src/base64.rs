//! Strict standard base64 (RFC 4648 section 4, with padding), as SCRAM
//! uses it. This is an encoding, not a cryptographic primitive.
//!
//! Decoding accepts only the canonical form: the length is a multiple of
//! four, padding appears only at the end, and unused trailing bits are
//! zero. So `encode(decode(s)?) == s` for every accepted `s`.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Why a base64 string was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Base64Error {
    /// The length is not a multiple of four.
    Length,
    /// A byte outside the alphabet, or padding in the wrong place.
    InvalidByte,
    /// Unused bits in the last group are not zero.
    NonCanonical,
}

impl std::fmt::Display for Base64Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Base64Error::Length => "base64 length is not a multiple of four",
            Base64Error::InvalidByte => "invalid base64 character or padding",
            Base64Error::NonCanonical => "non-canonical base64 encoding",
        })
    }
}

impl std::error::Error for Base64Error {}

fn sextet(b: u8) -> Option<u32> {
    let v = match b {
        b'A'..=b'Z' => b.wrapping_sub(b'A'),
        b'a'..=b'z' => b.wrapping_sub(b'a').wrapping_add(26),
        b'0'..=b'9' => b.wrapping_sub(b'0').wrapping_add(52),
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    };
    Some(u32::from(v))
}

fn symbol(v: u32) -> char {
    let i = usize::try_from(v & 63).unwrap_or(0);
    char::from(ALPHABET.get(i).copied().unwrap_or(b'A'))
}

/// Encodes `data` with padding.
#[must_use]
pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3).saturating_mul(4));
    for chunk in data.chunks(3) {
        let b0 = u32::from(chunk.first().copied().unwrap_or(0));
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(symbol(n >> 18));
        out.push(symbol(n >> 12));
        if chunk.len() > 1 {
            out.push(symbol(n >> 6));
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(symbol(n));
        } else {
            out.push('=');
        }
    }
    out
}

/// Decodes canonical padded base64.
///
/// # Errors
///
/// Returns a [`Base64Error`] for any non-canonical or invalid input.
pub fn decode(input: &[u8]) -> Result<Vec<u8>, Base64Error> {
    if !input.len().is_multiple_of(4) {
        return Err(Base64Error::Length);
    }
    let groups = input.len() / 4;
    let mut out = Vec::with_capacity(groups.saturating_mul(3));
    for (i, group) in input.chunks_exact(4).enumerate() {
        let last = i.saturating_add(1) == groups;
        let mut vals = [0u32; 4];
        let mut pad = 0usize;
        for (j, b) in group.iter().enumerate() {
            if *b == b'=' {
                // Padding only in the last group, only in positions 2 and 3,
                // and nothing but padding after it.
                if !last || j < 2 {
                    return Err(Base64Error::InvalidByte);
                }
                pad = pad.saturating_add(1);
                continue;
            }
            if pad > 0 {
                return Err(Base64Error::InvalidByte);
            }
            let v = sextet(*b).ok_or(Base64Error::InvalidByte)?;
            if let Some(slot) = vals.get_mut(j) {
                *slot = v;
            }
        }
        let [a, b, c, d] = vals;
        let n = (a << 18) | (b << 12) | (c << 6) | d;
        let bytes = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        match pad {
            0 => out.extend_from_slice(&bytes),
            1 => {
                if n & 0xff != 0 {
                    return Err(Base64Error::NonCanonical);
                }
                out.extend_from_slice(bytes.get(..2).unwrap_or_default());
            }
            _ => {
                if n & 0xffff != 0 {
                    return Err(Base64Error::NonCanonical);
                }
                out.extend_from_slice(bytes.get(..1).unwrap_or_default());
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    #[test]
    fn rfc4648_vectors() {
        let cases: &[(&[u8], &str)] = &[
            (b"", ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
        ];
        for (raw, enc) in cases {
            assert_eq!(encode(raw), *enc);
            assert_eq!(decode(enc.as_bytes()).unwrap(), *raw);
        }
    }

    #[test]
    fn th26_rejects_non_canonical_input() {
        assert_eq!(decode(b"Zg="), Err(Base64Error::Length));
        assert_eq!(decode(b"Zh=="), Err(Base64Error::NonCanonical));
        assert_eq!(decode(b"Zm9="), Err(Base64Error::NonCanonical));
        assert_eq!(decode(b"Z==="), Err(Base64Error::InvalidByte));
        assert_eq!(decode(b"Zg==Zg=="), Err(Base64Error::InvalidByte));
        assert_eq!(decode(b"Zm=v"), Err(Base64Error::InvalidByte));
        assert_eq!(decode(b"Zm9v\n"), Err(Base64Error::Length));
        assert_eq!(decode(b"Zm-v"), Err(Base64Error::InvalidByte));
    }

    #[test]
    fn round_trip_property() {
        fstp_prop::check("base64_round_trip", |g| {
            let data = g.bytes(0..=64);
            let enc = encode(&data);
            fstp_prop::prop_assert_eq!(decode(enc.as_bytes()), Ok(data));
            Ok(())
        });
    }
}
