//! The companion signature record of a contractual notice and its stored
//! form (R-CR-04, `SPEC/02-domain/contractual-notices.md`, M9 design D6,
//! decision CD3 completed by lane M9 finish).
//!
//! A notice "carries a composite Ed25519 plus ML-DSA-65 companion
//! signature over its hash", which "is stored with the notice and
//! included in exports". [`NoticeCompanionSigned`] is that record.
//! `fstp-contract` signs and verifies it (`notice_companion`). This crate
//! does no cryptography: it holds the typed record and its stored form.
//!
//! The stored form is one canonical I-JSON object (RFC 8785) with exactly
//! these members, each a string:
//!
//! | Member | Value |
//! | --- | --- |
//! | `form` | [`STORED_FORM`], the format version |
//! | `notice` | the notice id as 32 lowercase hex digits, big-endian |
//! | `notice_digest` | the SHA-256 of the sealed notice PDF, 64 lowercase hex digits |
//! | `key` | the SHA-256 of the composite public key that signed, 64 lowercase hex digits |
//! | `signature` | the composite signature `mldsaSig \|\| tradSig`, [`SIGNATURE_LEN`] bytes as lowercase hex |
//!
//! [`decode_notice_companion`] refuses any other member, a missing one,
//! a number, upper-case hex, a signature of another length and any text
//! that is not the canonical form. It is fuzzed as
//! `notice_companion_decode`. Errors name no input content (R-NF-02).

use fstp_json::{Object, ParseLimits, Value, parse_with, to_canonical};

use crate::digest::Digest;

/// The format version of the stored form.
pub const STORED_FORM: &str = "fstp-notice-companion-v1";

/// The length of a composite Ed25519 plus ML-DSA-65 signature (draft 19):
/// 3309 bytes of ML-DSA-65, then 64 of Ed25519. `fstp-contract` checks it
/// equals `fstp_crypto::composite::SIGNATURE_LEN`.
pub const SIGNATURE_LEN: usize = 3373;

/// The longest stored form the decoder reads, in bytes.
pub const MAX_STORED_BYTES: usize = 8192;

/// A contractual notice, as its store names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NoticeId(pub u128);

/// The companion signature of one notice, kept with the notice.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NoticeCompanionSigned {
    /// The notice.
    pub notice: NoticeId,
    /// The SHA-256 of the sealed notice PDF.
    pub notice_digest: Digest,
    /// The SHA-256 of the composite public key that signed.
    pub key: Digest,
    /// The composite signature, `mldsaSig || tradSig`.
    pub signature: Vec<u8>,
}

/// Why a stored form was refused. The text never quotes the input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoredFormError(pub &'static str);

impl std::fmt::Display for StoredFormError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "notice companion stored form: {}", self.0)
    }
}

impl std::error::Error for StoredFormError {}

const MEMBERS: [&str; 5] = ["form", "key", "notice", "notice_digest", "signature"];

fn limits() -> ParseLimits {
    ParseLimits::default()
        .with_max_input_bytes(MAX_STORED_BYTES)
        .with_max_depth(2)
        .with_max_string_bytes(SIGNATURE_LEN.saturating_mul(2))
        .with_max_container_len(MEMBERS.len())
        .with_max_nodes(8)
        .with_max_memory_bytes(1 << 16)
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        for n in [b >> 4, b & 0x0f] {
            s.push(char::from_digit(u32::from(n), 16).unwrap_or('0'));
        }
    }
    s
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => c.checked_sub(b'0'),
        b'a'..=b'f' => c.checked_sub(b'a').and_then(|x| x.checked_add(10)),
        _ => None,
    }
}

/// The bytes of exactly `len` bytes of lowercase hex.
fn unhex(s: &str, len: usize) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if b.len() != len.checked_mul(2)? {
        return None;
    }
    b.chunks_exact(2)
        .map(|p| match p {
            [hi, lo] => nibble(*hi)?.checked_mul(16)?.checked_add(nibble(*lo)?),
            _ => None,
        })
        .collect()
}

/// The stored form of `rec`: canonical I-JSON bytes (module documentation).
///
/// # Errors
///
/// A signature of another length than [`SIGNATURE_LEN`] has no stored form.
pub fn encode_notice_companion(rec: &NoticeCompanionSigned) -> Result<Vec<u8>, StoredFormError> {
    if rec.signature.len() != SIGNATURE_LEN {
        return Err(StoredFormError("the signature has another length"));
    }
    let mut o = Object::with_capacity(MEMBERS.len());
    let _ = o.insert("form", Value::String(STORED_FORM.to_owned()));
    let _ = o.insert("key", Value::String(rec.key.hex()));
    let _ = o.insert("notice", Value::String(hex(&rec.notice.0.to_be_bytes())));
    let _ = o.insert("notice_digest", Value::String(rec.notice_digest.hex()));
    let _ = o.insert("signature", Value::String(hex(&rec.signature)));
    to_canonical(&Value::Object(o))
        .map(String::into_bytes)
        .map_err(|_| StoredFormError("the form does not serialise"))
}

fn text<'a>(o: &'a Object, key: &str) -> Result<&'a str, StoredFormError> {
    o.get(key)
        .and_then(Value::as_str)
        .ok_or(StoredFormError("a member is not a string"))
}

/// The record of a stored form, by the strict rules of the module
/// documentation. Fuzzed as `notice_companion_decode`.
///
/// # Errors
///
/// [`StoredFormError`] for anything but a canonical stored form.
pub fn decode_notice_companion(bytes: &[u8]) -> Result<NoticeCompanionSigned, StoredFormError> {
    let v = parse_with(bytes, &limits()).map_err(|_| StoredFormError("not I-JSON in bounds"))?;
    let o = v.as_object().ok_or(StoredFormError("expected an object"))?;
    if o.len() != MEMBERS.len() || !MEMBERS.iter().all(|k| o.contains_key(k)) {
        return Err(StoredFormError("unknown or missing member"));
    }
    if text(o, "form")? != STORED_FORM {
        return Err(StoredFormError("unknown form"));
    }
    let notice = unhex(text(o, "notice")?, 16)
        .and_then(|b| <[u8; 16]>::try_from(b).ok())
        .map(|b| NoticeId(u128::from_be_bytes(b)))
        .ok_or(StoredFormError("the notice is not 32 hex digits"))?;
    let notice_digest = Digest::from_hex(text(o, "notice_digest")?)
        .ok_or(StoredFormError("the notice digest is not 64 hex digits"))?;
    let key = Digest::from_hex(text(o, "key")?)
        .ok_or(StoredFormError("the key digest is not 64 hex digits"))?;
    let signature = unhex(text(o, "signature")?, SIGNATURE_LEN)
        .ok_or(StoredFormError("the signature is not hex of its length"))?;
    let rec = NoticeCompanionSigned {
        notice,
        notice_digest,
        key,
        signature,
    };
    // Only the canonical spelling is a stored form, so one record has one form.
    if encode_notice_companion(&rec)? != bytes {
        return Err(StoredFormError("not the canonical form"));
    }
    Ok(rec)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;

    fn sample() -> NoticeCompanionSigned {
        NoticeCompanionSigned {
            notice: NoticeId(0x0102_0304_0506_0708_090a_0b0c_0d0e_0f10),
            notice_digest: Digest::from_bytes([0xab; 32]),
            key: Digest::from_bytes([0xcd; 32]),
            signature: vec![0x5a; SIGNATURE_LEN],
        }
    }

    /// R-CR-04: the stored form round-trips, and only its canonical text decodes.
    #[test]
    fn r_cr_04_stored_form_round_trips_and_is_canonical() {
        let rec = sample();
        let bytes = encode_notice_companion(&rec).unwrap();
        assert_eq!(decode_notice_companion(&bytes).unwrap(), rec);
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert!(text.starts_with("{\"form\":\"fstp-notice-companion-v1\",\"key\":\""));
        let spaced = text.replacen(',', ", ", 1);
        assert!(decode_notice_companion(spaced.as_bytes()).is_err());
        let upper = text.replace("abab", "ABAB");
        assert!(decode_notice_companion(upper.as_bytes()).is_err());
    }

    /// R-CR-04: a member too many or too few, another form, or a short
    /// signature is refused, and no signature of another length encodes.
    #[test]
    fn r_cr_04_stored_form_refuses_other_shapes() {
        let text = String::from_utf8(encode_notice_companion(&sample()).unwrap()).unwrap();
        let extra = text.replacen('{', "{\"a\":\"b\",", 1);
        assert!(decode_notice_companion(extra.as_bytes()).is_err());
        let other = text.replace("fstp-notice-companion-v1", "fstp-notice-companion-v2");
        assert!(decode_notice_companion(other.as_bytes()).is_err());
        let short = text.replacen("5a5a\"", "\"", 1);
        assert!(decode_notice_companion(short.as_bytes()).is_err());
        let mut rec = sample();
        rec.signature.pop();
        assert!(encode_notice_companion(&rec).is_err());
        assert!(decode_notice_companion(b"{}").is_err());
        assert!(decode_notice_companion(b"").is_err());
    }
}
