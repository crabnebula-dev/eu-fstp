//! The composite companion signature on contractual notices (R-CR-04,
//! `SPEC/02-domain/contractual-notices.md`, ADR-001 "Post-quantum
//! signatures", M9 design D6, lane C2).
//!
//! Each notice carries an eIDAS seal, which is the legally relevant
//! signature, and a composite Ed25519 plus ML-DSA-65 companion signature
//! over its hash. The companion signature is evidence that stays
//! verifiable if classical signatures weaken.
//!
//! - The key is the App chain level 2 key with purpose
//!   [`Purpose::NoticeCompanion`], separate from the anchor key (D6,
//!   ADR-004 record line of 2026-11-13). Custody hands it out as a
//!   [`NoticeCompanionKey`], which refuses a key of any other purpose.
//! - The signature is `CompositeSigningKey::sign_with_context` under
//!   [`NOTICE_COMPANION_CONTEXT`] over [`companion_message`]: the notice
//!   id and the SHA-256 of the sealed PDF. This crate never generates the
//!   key and never touches a primitive (I-75).
//! - [`verify_notice_companion`] accepts only when both halves verify
//!   (I-90). It is a row of the I-90 sweep in `fstp-celltest`.
//!
//! [`NoticeCompanionSigned`] is the record kept with the notice. Its type
//! and stored form live in `fstp_contract_core::notice` (fuzz target
//! `notice_companion_decode`). [`store_notice_companion`] writes the
//! stored form to the write-once document store under its digest, beside
//! the sealed PDF, and [`load_notice_companion`] reads it back. The cell
//! keystore holds the key (`fstp_cell::tasks::erasure`).

use fstp_crypto::composite::{self, CompositeSigningKey, PUBLIC_KEY_LEN, SIGNATURE_LEN};
use fstp_keys::Purpose;

use crate::blob::{BlobError, BlobKind, BlobStore};
use crate::digest::{Digest, sha256};

pub use fstp_contract_core::notice::{
    NoticeCompanionSigned, NoticeId, STORED_FORM, StoredFormError, decode_notice_companion,
    encode_notice_companion,
};

/// The composite context of the companion signature (M9 design D6).
pub const NOTICE_COMPANION_CONTEXT: &[u8] = b"fstp-notice-companion-v1";

/// Why a companion signature was not made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompanionError {
    /// Custody handed out a key of another purpose (D6).
    WrongPurpose(Purpose),
    /// The composite signer gave no signature.
    Signing,
}

impl std::fmt::Display for CompanionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompanionError::WrongPurpose(p) => {
                write!(f, "a {p:?} key cannot sign a notice companion")
            }
            CompanionError::Signing => f.write_str("the composite signer gave no signature"),
        }
    }
}

impl std::error::Error for CompanionError {}

/// The `NoticeCompanion` level 2 key, as custody hands it out.
pub struct NoticeCompanionKey {
    key: CompositeSigningKey,
}

impl NoticeCompanionKey {
    /// The key custody holds under `purpose`. Any purpose but
    /// [`Purpose::NoticeCompanion`] is refused, so an anchor key never
    /// signs a notice (D6).
    ///
    /// # Errors
    ///
    /// [`CompanionError::WrongPurpose`] for any other purpose.
    pub fn from_custody(
        purpose: Purpose,
        key: CompositeSigningKey,
    ) -> Result<NoticeCompanionKey, CompanionError> {
        if purpose == Purpose::NoticeCompanion {
            Ok(NoticeCompanionKey { key })
        } else {
            Err(CompanionError::WrongPurpose(purpose))
        }
    }

    /// The composite public key bytes, `mldsaPK || tradPK`.
    pub fn public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.key.public_key().to_bytes()
    }
}

/// The signed message: the notice id as 16 big-endian bytes, then the
/// 32 bytes of the notice digest.
pub fn companion_message(notice: NoticeId, notice_digest: Digest) -> [u8; 48] {
    let mut m = [0_u8; 48];
    let (id, d) = m.split_at_mut(16);
    id.copy_from_slice(&notice.0.to_be_bytes());
    d.copy_from_slice(&notice_digest.bytes());
    m
}

/// Signs the companion signature of `notice` over `notice_digest` with
/// the custody key (module documentation).
///
/// # Errors
///
/// [`CompanionError::Signing`] when the composite signer gives no
/// signature.
pub fn sign_notice_companion(
    key: &NoticeCompanionKey,
    notice: NoticeId,
    notice_digest: Digest,
) -> Result<NoticeCompanionSigned, CompanionError> {
    let signature = key
        .key
        .sign_with_context(
            &companion_message(notice, notice_digest),
            NOTICE_COMPANION_CONTEXT,
        )
        .map_err(|_| CompanionError::Signing)?;
    Ok(NoticeCompanionSigned {
        notice,
        notice_digest,
        key: sha256(&key.public_key()),
        signature: signature.to_bytes().to_vec(),
    })
}

/// Whether `rec` is a companion signature by `public_key` over its notice
/// and digest. The record must name that key's digest, and both halves
/// must verify (I-90). A key or signature of another length never
/// verifies, and nothing panics on one.
pub fn verify_notice_companion(rec: &NoticeCompanionSigned, public_key: &[u8]) -> bool {
    public_key.len() == PUBLIC_KEY_LEN
        && rec.signature.len() == SIGNATURE_LEN
        && rec.key == sha256(public_key)
        && composite::verify_with_context(
            public_key,
            &companion_message(rec.notice, rec.notice_digest),
            NOTICE_COMPANION_CONTEXT,
            &rec.signature,
        )
        .is_ok()
}

/// Why a companion signature was not stored or loaded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompanionStoreError {
    /// The record has no stored form, or the stored bytes are not one.
    Form(StoredFormError),
    /// The document store refused.
    Store(BlobError),
}

impl std::fmt::Display for CompanionStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompanionStoreError::Form(e) => write!(f, "{e}"),
            CompanionStoreError::Store(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for CompanionStoreError {}

/// Stores the stored form of `rec` in the write-once document store and
/// returns its digest, which the notice keeps beside its PDF digest. The
/// same record stored again returns the same digest (I-30).
///
/// # Errors
///
/// [`CompanionStoreError::Form`] for a record with no stored form, and
/// [`CompanionStoreError::Store`] when the store refuses.
pub fn store_notice_companion<S: BlobStore>(
    store: &mut S,
    rec: &NoticeCompanionSigned,
) -> Result<Digest, CompanionStoreError> {
    let bytes = encode_notice_companion(rec).map_err(CompanionStoreError::Form)?;
    store
        .put(BlobKind::NoticeCompanion, &bytes)
        .map_err(CompanionStoreError::Store)
}

/// The companion signature stored under `digest`, decoded strictly.
///
/// # Errors
///
/// [`CompanionStoreError::Store`] when nothing is stored there, and
/// [`CompanionStoreError::Form`] when the bytes are no stored form.
pub fn load_notice_companion<S: BlobStore>(
    store: &S,
    digest: &Digest,
) -> Result<NoticeCompanionSigned, CompanionStoreError> {
    let bytes = store.get(digest).map_err(CompanionStoreError::Store)?;
    decode_notice_companion(&bytes).map_err(CompanionStoreError::Form)
}

#[cfg(test)]
mod tests {
    /// R-CR-04: the stored form's signature length is the composite one.
    #[test]
    fn r_cr_04_stored_signature_length_is_the_composite_length() {
        assert_eq!(
            fstp_contract_core::notice::SIGNATURE_LEN,
            super::SIGNATURE_LEN
        );
    }
}
