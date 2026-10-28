//! Anchors and witness receipts (design section 7.2).

use crate::chain::{ChainId, Link};
use crate::{AuditError, CellId};

/// A signed statement of a chain head, sent to the witness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Anchor {
    /// The cell.
    pub cell: CellId,
    /// The chain.
    pub chain: ChainId,
    /// The row number of the head.
    pub n: u64,
    /// The head link.
    pub link: Link,
    /// UTC microseconds.
    pub at: i64,
    /// The composite signature bytes.
    pub signature: Vec<u8>,
}

/// The witness's receipt for an anchor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    /// The witness sequence.
    pub witness_seq: u64,
    /// The witness chain link.
    pub witness_link: Link,
    /// The witness signature bytes.
    pub signature: Vec<u8>,
}

/// Decodes an anchor. Fuzzed (`anchor_decode`).
pub fn decode_anchor(bytes: &[u8]) -> Result<Anchor, AuditError> {
    let _ = bytes;
    Err(AuditError::NotImplemented(
        "fstp_audit::anchor::decode_anchor",
    ))
}

/// Decodes a receipt. Fuzzed (`receipt_decode`).
pub fn decode_receipt(bytes: &[u8]) -> Result<Receipt, AuditError> {
    let _ = bytes;
    Err(AuditError::NotImplemented(
        "fstp_audit::anchor::decode_receipt",
    ))
}
