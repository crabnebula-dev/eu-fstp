//! Strict standard base64 (RFC 4648 section 4) for AUTH PLAIN.
//!
//! Decoding accepts only the canonical form: padded to a multiple of four,
//! with zero unused bits. So decoding and encoding round-trip exactly.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn sym(v: u32) -> char {
    ALPHABET
        .get(usize::try_from(v & 0x3f).unwrap_or(0))
        .map_or('A', |&b| char::from(b))
}

pub(crate) fn encode(input: &[u8]) -> String {
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b0 = u32::from(chunk.first().copied().unwrap_or(0));
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(sym(n >> 18));
        out.push(sym(n >> 12));
        out.push(if chunk.len() > 1 { sym(n >> 6) } else { '=' });
        out.push(if chunk.len() > 2 { sym(n) } else { '=' });
    }
    out
}

fn value(b: u8) -> Option<u32> {
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

/// Decodes canonical base64, or `None`.
pub(crate) fn decode(input: &[u8]) -> Option<Vec<u8>> {
    if !input.len().is_multiple_of(4) {
        return None;
    }
    let groups = input.len() / 4;
    let mut out = Vec::new();
    for (g, quad) in input.chunks(4).enumerate() {
        let last = g.saturating_add(1) == groups;
        let [a, b, c, d] = *quad else { return None };
        let pad = match (c, d) {
            (b'=', b'=') if last => 2,
            (_, b'=') if last => 1,
            _ => 0,
        };
        let va = value(a)?;
        let vb = value(b)?;
        let vc = if pad == 2 { 0 } else { value(c)? };
        let vd = if pad >= 1 { 0 } else { value(d)? };
        let n = (va << 18) | (vb << 12) | (vc << 6) | vd;
        let bytes = n.to_be_bytes();
        let [_, x, y, z] = bytes;
        match pad {
            2 => {
                if n & 0xffff != 0 {
                    return None;
                }
                out.push(x);
            }
            1 => {
                if n & 0xff != 0 {
                    return None;
                }
                out.extend([x, y]);
            }
            _ => out.extend([x, y, z]),
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::{decode, encode};

    /// TH-26: RFC 4648 section 10 test vectors round-trip.
    #[test]
    fn th26_base64_rfc4648_vectors() {
        for (raw, b64) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(encode(raw.as_bytes()), b64);
            assert_eq!(decode(b64.as_bytes()).unwrap(), raw.as_bytes());
        }
        for bad in ["Zg", "Zh==", "Zm9=", "Z===", "====", "Zg==Zg==", "Zm 9"] {
            assert_eq!(decode(bad.as_bytes()), None, "{bad}");
        }
    }
}
