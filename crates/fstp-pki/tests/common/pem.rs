//! Reference base64 (RFC 4648 section 4, padded) and PEM (RFC 7468
//! section 2, strict form) writers. Encoders only, written apart from
//! `fstp_pki::pem` and from `fstp_pgwire::base64`.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Padded standard base64 of `data`.
pub(crate) fn base64(data: &[u8]) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let mut buf = [0u8; 3];
        buf[..chunk.len()].copy_from_slice(chunk);
        let n = (u32::from(buf[0]) << 16) | (u32::from(buf[1]) << 8) | u32::from(buf[2]);
        let symbols = chunk.len() + 1;
        for i in 0..4 {
            if i < symbols {
                let v = (n >> (18 - 6 * i)) & 63;
                out.push(char::from(ALPHABET[v as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// One strict PEM block: the label lines, then the base64 text in lines of
/// 64 characters, the last one shorter or equal, each ending in LF.
pub(crate) fn pem(label: &str, der: &[u8]) -> String {
    let body = base64(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in body.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}
