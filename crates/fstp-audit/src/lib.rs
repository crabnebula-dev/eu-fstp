//! The audit chain: row format, link function, verifier, anchors,
//! receipts and the anchorer core (I-24, M3 design section 7, ADR-010).
//! Pure: no I/O, no runtime (layering rule 1).
//!
//! # The composite encoding hard limit
//!
//! ADR-010 "Composite encoding" says no production code in `fstp-audit`
//! or `fstp-witness` signs or verifies before Daniel accepts the composite
//! encoding table. The table is transcribed but not yet accepted. So
//! [`anchor::sign_anchor`] and every signature check inside
//! [`verify::verify`] refuse with [`AuditError::AwaitsAcceptance`], which
//! names [`COMPOSITE_ENCODING_ACCEPTANCE`]. The verifier still fails
//! closed. While signatures are unchecked it never answers `Ok` for a
//! chain that holds any row, anchor or witness record.
//!
//! # Readings
//!
//! - The byte layouts of genesis, row bytes and the anchor message are the
//!   ADR-010 proposals (open point 2). The receipt message order and the
//!   witness chain link are the W1e readings, since ADR-010 gives only
//!   their labels and fields.
//! - A prepare carries the head it extends and the stored hashes of its
//!   rows, so the witness can recompute the link (open point 3).
//! - The verifier reports a committed row that no receipted prepare
//!   covers as [`Tamper::Unwitnessed`]. ADR-010 lists no variant for it.

pub mod anchor;
pub mod anchorer;
pub mod chain;
pub mod codec;
pub mod verify;
pub mod witness;

pub use anchor::{Anchor, AnchorRow, Receipt, ReceiptFields};
pub use chain::{ChainId, ChainRow, ChainWriter, Link, RowKind, StoredEntry, StoredRow};
pub use fstp_crypto::composite::{CompositePublicKey, CompositeSigningKey};
pub use verify::{ChainView, Tamper, Verified};
pub use witness::{Prepare, WitnessRecord};

/// What every signing and signature check waits on (ADR-010 "Composite
/// encoding", lane W2g hard limit).
pub const COMPOSITE_ENCODING_ACCEPTANCE: &str = "ADR-010 composite encoding acceptance (Daniel)";

/// The composite signature length of draft 19: ML-DSA-65 then Ed25519
/// (ADR-010 "Composite encoding", row "Signature").
pub const SIGNATURE_LEN: usize = fstp_crypto::composite::SIGNATURE_LEN;

/// The composite public key length of draft 19 (ADR-010, row "Public
/// key").
pub const PUBLIC_KEY_LEN: usize = fstp_crypto::composite::PUBLIC_KEY_LEN;

/// A cell identifier, 16 random bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CellId(pub [u8; 16]);

/// Why an audit operation failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuditError {
    /// The verifier found a change to the chain.
    Tamper(Tamper),
    /// Bytes did not decode.
    Decode(DecodeError),
    /// An input the operation refuses to build or encode.
    Invalid(Invalid),
    /// The operation signs or checks a signature, and waits on the named
    /// acceptance ([`COMPOSITE_ENCODING_ACCEPTANCE`]).
    AwaitsAcceptance(&'static str),
    /// The operation waits for another lane. It names the operation. No
    /// operation of this crate answers it today; it stays for the callers
    /// that tell a stub from a real refusal.
    NotImplemented(&'static str),
}

impl std::fmt::Display for AuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditError::Tamper(t) => write!(f, "audit chain tampered: {t:?}"),
            AuditError::Decode(e) => write!(f, "audit bytes do not decode: {e:?}"),
            AuditError::Invalid(e) => write!(f, "audit input refused: {e:?}"),
            AuditError::AwaitsAcceptance(what) => write!(f, "refused until {what}"),
            AuditError::NotImplemented(op) => write!(f, "{op} is not implemented yet"),
        }
    }
}

impl std::error::Error for AuditError {}

impl From<DecodeError> for AuditError {
    fn from(e: DecodeError) -> AuditError {
        AuditError::Decode(e)
    }
}

impl From<Invalid> for AuditError {
    fn from(e: Invalid) -> AuditError {
        AuditError::Invalid(e)
    }
}

/// Why bytes did not decode (TH-26).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The input ended inside a value.
    Truncated,
    /// Bytes follow the value.
    TrailingBytes,
    /// The format version byte is not known.
    UnknownVersion(u8),
    /// A tag or kind code is not known.
    UnknownTag(u16),
    /// A length is above its limit.
    TooLong,
    /// The value decodes but is not valid.
    Invalid(Invalid),
}

impl From<Invalid> for DecodeError {
    fn from(e: Invalid) -> DecodeError {
        DecodeError::Invalid(e)
    }
}

/// An input refused by a builder, an encoder or a decoder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Invalid {
    /// A kind 1 row needs its ledger entry.
    MissingEntry,
    /// The entry's `seq` is not the one the kind 1 row names.
    EntryOfAnotherSeq,
    /// A kind 2 row names no ledger entry.
    EntryForEventRow,
    /// A body is longer than its limit.
    BodyTooLong,
    /// Row numbers start at 1 (ADR-010).
    RowNumberZero,
    /// The chain is at row `u64::MAX` and cannot grow.
    RowNumberExhausted,
    /// Witness sequences start at 1.
    WitnessSeqZero,
    /// A signature is not of the composite length.
    SignatureLength,
    /// A prepare has no rows, too many rows, or an `n` that is not its
    /// previous head plus its row count.
    PrepareShape,
    /// File store sequences must strictly rise.
    SequenceNotRising,
    /// A whole file store must hold sequences 1, 2, 3 with no gap.
    SequenceGap,
}
