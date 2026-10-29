//! Identifiers and digests of the import store (M4 design section 3.3).
//!
//! The shell draws every id and computes every digest, as the M2 core
//! does. This crate is pure: it never hashes and never reads a clock.
//!
//! Free text stays out of ledger bodies (ADR-007, design 4.2). A recorded
//! proposal names its value by a [`ValueTextRef`]. The digests of a text
//! that an import body holds are keyed with a salt that erasure destroys.
//!
//! Interim, pending the lead: the design names `ProgrammeId` and
//! `AccountId` of `fstp-domain` in import documents and records. This
//! crate has no direct edge to `fstp-domain`, and adding one changes the
//! shared `Cargo.lock`. So the store names a programme and an account by
//! [`ProgrammeRef`] and [`AccountRef`], which hold the raw value of the
//! domain id. The engine bridge maps them one to one with `from_raw` and
//! `raw`.

macro_rules! id {
    ($($(#[$doc:meta])* $n:ident),* $(,)?) => { $(
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $n(u128);

        impl $n {
            /// The id with raw value `r`, as drawn by the shell.
            pub const fn from_raw(r: u128) -> Self {
                Self(r)
            }

            /// The raw value.
            pub const fn raw(self) -> u128 {
                self.0
            }
        }
    )* };
}

id!(
    /// An uploaded import document.
    ImportDocumentId,
    /// One proposed value of an import.
    ImportProposalId,
    /// The proposer configuration that proposed a value (M7 pins its
    /// prompt and model).
    ImportConfigId,
    /// A programme, by the raw value of its `fstp_domain::id::ProgrammeId`.
    ProgrammeRef,
    /// An account, by the raw value of its `fstp_domain::id::AccountId`.
    AccountRef,
    /// A stored value text, by the raw value of its
    /// `fstp_domain::id::TextId` in the text store.
    ValueTextId,
);

macro_rules! digest {
    ($($(#[$doc:meta])* $n:ident),* $(,)?) => { $(
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $n([u8; 32]);

        impl $n {
            /// The digest with these bytes, as the shell computed them.
            pub const fn from_bytes(b: [u8; 32]) -> Self {
                Self(b)
            }

            /// The raw bytes.
            pub const fn bytes(self) -> [u8; 32] {
                self.0
            }
        }
    )* };
}

digest!(
    /// The reference `BlobStore::put` returns for the uploaded bytes.
    ///
    /// Interim, pending the lead: the W0 port calls it a content address.
    /// If that is an unkeyed hash, it can confirm a guessed document after
    /// erasure, which ADR-007 rules out for `TextRef` digests. The blob
    /// store owns that choice. This crate only carries the bytes.
    BlobAddress,
    /// The digest of the normalised text, keyed with the random salt that
    /// is stored with the document and destroyed with it (ADR-007). So
    /// after erasure it cannot confirm a guessed text. Evidence spans are
    /// byte offsets into exactly that text.
    TextDigest,
    /// The SHA-256 of the normal text of an [`crate::UntrustedValue`]
    /// (`UntrustedValue::as_data`), for the creator's save. The API core
    /// computes it for a confirmed or edited value. No import record body
    /// holds it.
    ValueDigest,
    /// The digest of a stored value text, keyed with the random salt that
    /// is stored inside the sealed text and destroyed with it (ADR-007).
    /// So after erasure it cannot confirm a guessed value. The review page
    /// shows it, and the client names it as `shown`.
    SaltedDigest,
);

/// Where the shell stored a proposed value's normal text: the text's id
/// in the text store and its salted digest (ADR-007 `TextRef`).
///
/// A ledger body holds this reference and never the value. Erasure then
/// destroys the text's data key and leaves the body unchanged (I-23,
/// I-81).
///
/// Interim, pending the lead: it mirrors `fstp_domain::id::TextRef`, since
/// this crate has no edge to `fstp-domain`. The engine maps it one to one
/// with `TextId::from_raw` and `ContentDigest::from_bytes`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ValueTextRef {
    id: ValueTextId,
    digest: SaltedDigest,
}

impl ValueTextRef {
    /// The reference to text `id` with salted digest `digest`.
    pub const fn new(id: ValueTextId, digest: SaltedDigest) -> ValueTextRef {
        ValueTextRef { id, digest }
    }

    /// The text's id.
    pub const fn id(self) -> ValueTextId {
        self.id
    }

    /// The text's salted digest.
    pub const fn digest(self) -> SaltedDigest {
        self.digest
    }
}
