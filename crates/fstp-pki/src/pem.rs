//! The in-house PEM writer (M3 design section 1.3).
//!
//! PostgreSQL reads certificates as PEM. This module writes the strict
//! form of RFC 7468 section 2: the label lines, then padded standard
//! base64 (RFC 4648 section 4) in lines of 64 characters, each line ending
//! in LF. The base64 here encodes only, so `fstp-pki` still parses
//! nothing.

use crate::PkiError;

/// The PEM labels the writer emits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PemLabel {
    /// `CERTIFICATE`.
    Certificate,
    /// `CERTIFICATE REQUEST`.
    CertificateRequest,
}

impl PemLabel {
    fn text(self) -> &'static str {
        match self {
            PemLabel::Certificate => "CERTIFICATE",
            PemLabel::CertificateRequest => "CERTIFICATE REQUEST",
        }
    }
}

/// The standard base64 alphabet (RFC 4648 table 1).
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Base64 characters per PEM line (RFC 7468 section 2).
const LINE_CHARS: usize = 64;

/// The base64 symbol for the low six bits of `v`.
fn symbol(v: u32) -> char {
    let index = usize::try_from(v & 0x3f).unwrap_or_default();
    ALPHABET.get(index).map_or('A', |b| char::from(*b))
}

/// Padded standard base64 of `data`.
fn base64(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3).saturating_mul(4));
    for chunk in data.chunks(3) {
        let b0 = chunk.first().copied().unwrap_or_default();
        let b1 = chunk.get(1).copied();
        let b2 = chunk.get(2).copied();
        let n = (u32::from(b0) << 16)
            | (u32::from(b1.unwrap_or_default()) << 8)
            | u32::from(b2.unwrap_or_default());
        out.push(symbol(n >> 18));
        out.push(symbol(n >> 12));
        out.push(if b1.is_some() { symbol(n >> 6) } else { '=' });
        out.push(if b2.is_some() { symbol(n) } else { '=' });
    }
    out
}

/// Writes `der` as one PEM block with `label`.
///
/// # Errors
///
/// [`PkiError::EmptyDer`] when `der` is empty, since a PEM block of no
/// bytes carries nothing.
pub fn encode(label: PemLabel, der: &[u8]) -> Result<String, PkiError> {
    if der.is_empty() {
        return Err(PkiError::EmptyDer);
    }
    let body = base64(der);
    let label = label.text();
    let mut out = String::with_capacity(body.len().saturating_mul(2).saturating_add(64));
    out.push_str("-----BEGIN ");
    out.push_str(label);
    out.push_str("-----\n");
    let mut rest = body.as_str();
    while !rest.is_empty() {
        // Base64 text is ASCII, so every index is a character boundary.
        let (line, tail) = rest.split_at(rest.len().min(LINE_CHARS));
        out.push_str(line);
        out.push('\n');
        rest = tail;
    }
    out.push_str("-----END ");
    out.push_str(label);
    out.push_str("-----\n");
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_rfc4648_section_10_vectors() {
        for (input, expected) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(input.as_bytes()), expected);
        }
        assert_eq!(base64(&[0xff, 0xff, 0xfe]), "///+");
    }

    #[test]
    fn empty_der_is_refused() {
        assert_eq!(encode(PemLabel::Certificate, &[]), Err(PkiError::EmptyDer));
    }
}
