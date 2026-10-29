//! Base64 writers (RFC 4648 sections 4 and 5), for client data challenges.

const URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn encode(alphabet: &[u8; 64], bytes: &[u8], pad: bool) -> String {
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        let chars = chunk.len() + 1;
        for (i, shift) in [18u32, 12, 6, 0].into_iter().enumerate() {
            if i < chars {
                out.push(char::from(alphabet[((n >> shift) & 0x3f) as usize]));
            } else if pad {
                out.push('=');
            }
        }
    }
    out
}

/// Base64url without padding, as WebAuthn client data carries the challenge.
pub(crate) fn url(bytes: &[u8]) -> String {
    encode(URL, bytes, false)
}

/// Base64url with `=` padding. Not the WebAuthn spelling.
pub(crate) fn url_padded(bytes: &[u8]) -> String {
    encode(URL, bytes, true)
}

/// Standard base64 with padding. Not the WebAuthn spelling.
pub(crate) fn standard(bytes: &[u8]) -> String {
    encode(STD, bytes, true)
}
