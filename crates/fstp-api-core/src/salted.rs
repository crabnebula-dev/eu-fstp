//! Salted free text, as the text and blob stores keep it (ADR-007; lane
//! m4wire).
//!
//! ADR-007 keys the digest of a `TextRef` "with a random salt stored with
//! the text and destroyed with it, so after erasure the digest cannot
//! confirm a guessed text". It also says "Free-text salts sit inside the
//! sealed text, never in a clear column". So the bytes this core stores
//! are the salt followed by the text, and the digest a ledger body holds
//! is HMAC-SHA256 of the text under the salt, through `fstp-crypto`.
//!
//! A reader of the stored bytes splits them with [`split`]. Anyone who
//! holds the stored bytes can check a ledger digest with [`verify`].
//! Once the stored bytes are erased, the salt is gone with them.
//!
//! Interim, pending the lead: the text and blob ports take plain bytes,
//! so the salt travels inside them. A port that seals the salt with the
//! text under the text's data key would make this module its encoder.

use crate::{ApiError, ErrorCode};

/// The length of a text salt, in bytes.
pub const SALT_LEN: usize = 32;

/// A freshly drawn text salt. A draw that fails refuses the call
/// (fail closed).
pub(crate) fn draw() -> Result<[u8; SALT_LEN], ApiError> {
    fstp_crypto::random_array::<SALT_LEN>()
        .map_err(|_| ApiError::refused(ErrorCode::Unavailable, "ids"))
}

/// The stored bytes of `text` under `salt`: the salt, then the text.
pub fn stored(salt: &[u8; SALT_LEN], text: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(SALT_LEN.saturating_add(text.len()));
    out.extend_from_slice(salt);
    out.extend_from_slice(text);
    out
}

/// The salt and the text of stored bytes, or `None` for bytes shorter
/// than a salt.
pub fn split(bytes: &[u8]) -> Option<([u8; SALT_LEN], &[u8])> {
    let (salt, text) = bytes.split_at_checked(SALT_LEN)?;
    let salt: [u8; SALT_LEN] = salt.try_into().ok()?;
    Some((salt, text))
}

/// The keyed digest of `text` under `salt`: HMAC-SHA256.
pub fn digest(salt: &[u8; SALT_LEN], text: &[u8]) -> [u8; 32] {
    fstp_crypto::hmac_sha256(salt, text)
}

/// Whether `tag` is the keyed digest of `text` under `salt`, compared in
/// constant time.
pub fn verify(salt: &[u8; SALT_LEN], text: &[u8], tag: &[u8; 32]) -> bool {
    fstp_crypto::hmac_sha256_verify(salt, text, tag)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    /// ADR-007, I-81: the stored bytes split back into the salt and the
    /// text, and the keyed digest verifies under that salt only. It is
    /// never the unkeyed SHA-256 of the text.
    #[test]
    fn adr007_salted_text_round_trips_and_is_keyed() {
        let salt = draw().unwrap();
        let text = b"r1@e2e.invalid";
        let bytes = stored(&salt, text);
        let (s, t) = split(&bytes).unwrap();
        assert_eq!((s, t), (salt, &text[..]));
        let tag = digest(&salt, text);
        assert!(verify(&salt, text, &tag));
        assert_ne!(tag, fstp_crypto::sha256(text));
        let other = draw().unwrap();
        assert_ne!(other, salt);
        assert!(!verify(&other, text, &tag));
        assert!(split(&bytes[..SALT_LEN - 1]).is_none());
        assert_eq!(split(&salt).map(|(_, t)| t.len()), Some(0));
    }
}
