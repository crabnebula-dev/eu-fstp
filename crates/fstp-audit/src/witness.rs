//! What the anchorer sends the witness and what the witness logs
//! (ADR-010 "Prepare, receipt, commit").
//!
//! The witness keeps its own chain per cell and chain. Each prepare, abort
//! and in-doubt record advances it:
//!
//! ```text
//! witness genesis = SHA-256("fstp-witness-v1" || cell || chain)
//! witness link    = SHA-256("fstp-witness-v1" || cell || chain || kind
//!                           || be64(witness_seq) || previous witness link
//!                           || be64(n) || link)
//! ```
//!
//! ADR-010 fixes no layout for it. This is the W1e reading, so the
//! witness core and the reference witness agree state for state. It lives
//! here, beside the other audit hashes, so that the verifier can
//! recompute it once the witness log carries its own links.

use crate::anchor::{Anchor, AnchorRow};
use crate::chain::{ChainId, Link, link_of};
use crate::codec::sha256;
use crate::{CellId, Invalid};

/// The witness chain label (W1e reading).
pub const WITNESS_LABEL: &[u8] = b"fstp-witness-v1";
/// The most rows one prepare covers. A batch of entries shares one
/// prepare (design section 7.2).
pub const MAX_PREPARE_ROWS: usize = 65_536;

/// A prepare: the head it extends, the stored hashes of its rows, and the
/// anchor of the prospective head (ADR-010 "Prepare", reading of open
/// point 3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prepare {
    /// The head this prepare extends: its row number and link.
    pub prev: (u64, Link),
    /// The stored hashes of the rows after `prev`, in order.
    pub stored_hashes: Vec<[u8; 32]>,
    /// The anchor of the prospective head.
    pub anchor: Anchor,
}

impl Prepare {
    /// Whether the prepare has a shape a witness can check: one to
    /// [`MAX_PREPARE_ROWS`] rows, and an anchor `n` that is `prev` plus
    /// the row count.
    ///
    /// # Errors
    ///
    /// [`Invalid::PrepareShape`] otherwise.
    pub fn check_shape(&self) -> Result<(), Invalid> {
        let count = self.stored_hashes.len();
        if count == 0 || count > MAX_PREPARE_ROWS {
            return Err(Invalid::PrepareShape);
        }
        let count = u64::try_from(count).map_err(|_| Invalid::PrepareShape)?;
        match self.prev.0.checked_add(count) {
            Some(n) if n == self.anchor.n => Ok(()),
            _ => Err(Invalid::PrepareShape),
        }
    }

    /// The head the stored hashes recompute to after `prev`, for the
    /// anchor's cell and chain. `None` when the row number overflows.
    pub fn recomputed_head(&self) -> Option<(u64, Link)> {
        let (mut n, mut l) = self.prev;
        for sh in &self.stored_hashes {
            n = n.checked_add(1)?;
            l = link_of(&l, self.anchor.cell, self.anchor.chain, n, sh);
        }
        Some((n, l))
    }
}

/// The kind of a witness log record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RecordKind {
    /// A receipted prepare. Code 1.
    Prepare,
    /// An abort of the outstanding prepare. Code 2.
    Abort,
    /// An in-doubt prepare whose row was missing. Code 3.
    InDoubtAbsent,
}

impl RecordKind {
    /// The record code in the witness link.
    pub const fn code(self) -> u8 {
        match self {
            RecordKind::Prepare => 1,
            RecordKind::Abort => 2,
            RecordKind::InDoubtAbsent => 3,
        }
    }
}

/// One record of the witness log for one cell and chain, as the verifier
/// reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WitnessRecord {
    /// A receipted prepare: the anchor and the receipt the witness gave.
    Prepare(AnchorRow),
    /// An abort of a prepare.
    Abort {
        /// The row number.
        n: u64,
        /// The prepared link.
        link: Link,
    },
    /// A prepare whose commit outcome was unknown and whose row was
    /// missing at reconnect.
    InDoubtAbsent {
        /// The row number.
        n: u64,
        /// The prepared link.
        link: Link,
    },
}

/// The witness chain head before any record of `cell`'s `chain`.
pub fn witness_genesis(cell: CellId, chain: ChainId) -> Link {
    Link(sha256(&[WITNESS_LABEL, &cell.0, &[chain.byte()]]))
}

/// The witness chain link after a record of `kind` for `(n, link)` at
/// witness sequence `seq`, after `prev`.
pub fn witness_link(
    prev: &Link,
    cell: CellId,
    chain: ChainId,
    kind: RecordKind,
    seq: u64,
    n: u64,
    link: &Link,
) -> Link {
    Link(sha256(&[
        WITNESS_LABEL,
        &cell.0,
        &[chain.byte(), kind.code()],
        &seq.to_be_bytes(),
        &prev.0,
        &n.to_be_bytes(),
        &link.0,
    ]))
}
