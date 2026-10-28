//! Chain rows and links (design section 7.1).

use crate::{AuditError, CellId};

/// The two chains of a cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ChainId {
    /// The application chain.
    App,
    /// The vault chain.
    Vault,
}

/// A SHA-256 link.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Link(pub [u8; 32]);

/// What a chain row records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RowKind {
    /// A ledger entry, by sequence.
    Ledger {
        /// The ledger sequence.
        seq: u64,
    },
    /// An audit event with a sealed body.
    Event {
        /// The sealed body bytes.
        body: Vec<u8>,
    },
}

/// One row of a chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainRow {
    /// The row number.
    pub n: u64,
    /// UTC microseconds.
    pub at: i64,
    /// What the row records.
    pub kind: RowKind,
    /// SHA-256 of the stored row bytes.
    pub stored_hash: [u8; 32],
}

/// The link before the first row of a chain.
pub fn genesis(cell: CellId, chain: ChainId) -> Result<Link, AuditError> {
    let _ = (cell, chain);
    Err(AuditError::NotImplemented("fstp_audit::chain::genesis"))
}

/// The link after `row`.
pub fn link(prev: &Link, cell: CellId, chain: ChainId, row: &ChainRow) -> Result<Link, AuditError> {
    let _ = (prev, cell, chain, row);
    Err(AuditError::NotImplemented("fstp_audit::chain::link"))
}

/// The only code that computes links for new rows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainWriter {
    head: (u64, Link),
}

impl ChainWriter {
    /// A writer that continues after `head`.
    pub fn resume(n: u64, link: Link) -> ChainWriter {
        ChainWriter { head: (n, link) }
    }

    /// The row number and link of the head.
    pub fn head(&self) -> (u64, Link) {
        self.head
    }
}

/// Decodes a stored chain row. Fuzzed (`chain_row_decode`).
pub fn decode_chain_row(bytes: &[u8]) -> Result<ChainRow, AuditError> {
    let _ = bytes;
    Err(AuditError::NotImplemented(
        "fstp_audit::chain::decode_chain_row",
    ))
}
