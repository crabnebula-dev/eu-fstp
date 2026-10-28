//! The chain verifier (I-24, design section 7.1).

use crate::AuditError;
use crate::anchor::{Anchor, Receipt};
use crate::chain::ChainRow;

/// A change the verifier found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Tamper {
    /// A row changed.
    Changed {
        /// The row number.
        n: u64,
    },
    /// A row is missing.
    Gap {
        /// The row number.
        n: u64,
    },
    /// Rows are out of order.
    Reordered {
        /// The row number.
        n: u64,
    },
    /// The chain is shorter than the witness saw.
    Truncated {
        /// The witnessed length.
        witnessed: u64,
        /// The stored length.
        have: u64,
    },
    /// An anchor does not match its row.
    AnchorMismatch {
        /// The row number.
        n: u64,
    },
    /// An anchor signature does not verify.
    BadSignature {
        /// The row number.
        n: u64,
    },
    /// A ledger entry has no chain row.
    LedgerWithoutRow {
        /// The ledger sequence.
        seq: u64,
    },
    /// A chain row has no ledger entry.
    RowWithoutLedger {
        /// The row number.
        n: u64,
    },
    /// A ledger entry's stored hash differs from its row.
    StoredHashMismatch {
        /// The ledger sequence.
        seq: u64,
    },
    /// A witnessed row was deleted.
    Deleted {
        /// The row number.
        n: u64,
    },
    /// An aborted prepare has a stored row.
    AbortedButPresent {
        /// The row number.
        n: u64,
    },
}

/// A verified chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Verified {
    /// The number of verified rows.
    pub rows: u64,
}

/// Verifies rows, stored ledger hashes, anchors and receipts.
pub fn verify(
    rows: &[ChainRow],
    stored_hashes: &[(u64, [u8; 32])],
    anchors: &[Anchor],
    receipts: &[Receipt],
) -> Result<Verified, AuditError> {
    let _ = (rows, stored_hashes, anchors, receipts);
    Err(AuditError::NotImplemented("fstp_audit::verify::verify"))
}
