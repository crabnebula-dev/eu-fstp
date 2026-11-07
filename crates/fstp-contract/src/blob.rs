//! Write-once storage of PDF revisions and other documents by SHA-256
//! (M5 design section 4.3, I-30).
//!
//! The cell database holds them in `doc.blob`, sealed under a data key,
//! keyed by the digest of the clear bytes. The `app` role has INSERT and
//! SELECT only, and a second insert of a digest fails. [`MemBlobStore`]
//! is the in-memory form for tests and the demo, with the same rule.

use std::collections::BTreeMap;

use crate::digest::Digest;

/// What a stored document is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BlobKind {
    /// A contract PDF revision.
    ContractRevision = 1,
    /// A sealed draft of a contract terminated before any signature.
    SealedDraft = 2,
    /// A report or payment record file.
    Report = 3,
}

/// Why a store operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlobError {
    /// The digest is already stored with other bytes or another kind (I-30).
    Conflict,
    /// The bytes do not hash to the digest.
    DigestMismatch,
    /// No document with that digest.
    Missing,
    /// The backing store failed.
    Unavailable,
}

impl std::fmt::Display for BlobError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "document store: {self:?}")
    }
}

impl std::error::Error for BlobError {}

/// A write-once document store keyed by SHA-256.
pub trait BlobStore {
    /// Stores `bytes` under their digest and returns it. Storing the same
    /// bytes again returns the same digest and changes nothing.
    ///
    /// # Errors
    ///
    /// [`BlobError::Conflict`] when the digest is held by other bytes.
    fn put(&mut self, kind: BlobKind, bytes: &[u8]) -> Result<Digest, BlobError>;

    /// The bytes stored under `digest`.
    ///
    /// # Errors
    ///
    /// [`BlobError::Missing`] when none are stored.
    fn get(&self, digest: &Digest) -> Result<Vec<u8>, BlobError>;
}

/// The in-memory store.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MemBlobStore {
    docs: BTreeMap<Digest, (BlobKind, Vec<u8>)>,
}

impl MemBlobStore {
    /// Inserts `bytes` under `digest` as the database row would be
    /// written, without hashing first. A second insert of a digest fails
    /// unless kind and bytes are the same; bytes that do not hash to the
    /// digest are refused.
    ///
    /// # Errors
    ///
    /// [`BlobError::Conflict`] or [`BlobError::DigestMismatch`].
    pub fn insert_raw(
        &mut self,
        digest: Digest,
        kind: BlobKind,
        bytes: &[u8],
    ) -> Result<(), BlobError> {
        if let Some((k, b)) = self.docs.get(&digest) {
            return if *k == kind && b == bytes {
                Ok(())
            } else {
                Err(BlobError::Conflict)
            };
        }
        if crate::digest::sha256(bytes) != digest {
            return Err(BlobError::DigestMismatch);
        }
        self.docs.insert(digest, (kind, bytes.to_vec()));
        Ok(())
    }

    /// The number of stored documents.
    #[must_use]
    pub fn len(&self) -> usize {
        self.docs.len()
    }

    /// Whether the store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.docs.is_empty()
    }
}

impl BlobStore for MemBlobStore {
    fn put(&mut self, kind: BlobKind, bytes: &[u8]) -> Result<Digest, BlobError> {
        let d = crate::digest::sha256(bytes);
        self.insert_raw(d, kind, bytes)?;
        Ok(d)
    }

    fn get(&self, digest: &Digest) -> Result<Vec<u8>, BlobError> {
        self.docs
            .get(digest)
            .map(|(_, b)| b.clone())
            .ok_or(BlobError::Missing)
    }
}
