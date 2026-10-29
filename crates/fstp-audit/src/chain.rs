//! Chain rows, stored hashes and links (design section 7.1, ADR-010
//! "Link function").
//!
//! ```text
//! genesis       = SHA-256("fstp-audit-genesis-v1" || cell || chain)
//! row bytes     = "fstp-audit-row-v1" || be16(kind) || be64(at) || payload
//!   kind 1:       payload = be64(seq) || be64(entry_at) || command (16 bytes)
//!                           || be16(schema) || be32(key_ix) || be32(len(body)) || body
//!   kind 2:       payload = be32(len(body)) || body
//! stored_hash_n = SHA-256(row bytes)
//! link_n        = SHA-256("fstp-audit-v1" || cell || chain || be64(n) || link_{n-1}
//!                         || stored_hash_n)
//! ```
//!
//! The stored hash binds every column of the row and, for kind 1, every
//! column of its ledger entry. The link binds the stored hash, so it binds
//! them all (I-24, `i24_teeth_link_omitting_a_field_is_caught`).

use crate::codec::{Reader, Sink, len32, sha256};
use crate::{AuditError, CellId, DecodeError, Invalid};

/// The link label (design section 7.1).
pub const LINK_LABEL: &[u8] = b"fstp-audit-v1";
/// The genesis label (ADR-010 proposal).
pub const GENESIS_LABEL: &[u8] = b"fstp-audit-genesis-v1";
/// The row bytes label (ADR-010 proposal).
pub const ROW_LABEL: &[u8] = b"fstp-audit-row-v1";
/// The kind code of a ledger entry row.
pub const KIND_LEDGER: u16 = 1;
/// The kind code of an event row.
pub const KIND_EVENT: u16 = 2;
/// The longest event body a chain row holds. Event bodies hold ids,
/// enums and digests only (ADR-010 "Chains").
pub const MAX_EVENT_BODY_LEN: usize = 65_536;
/// The format version of an encoded chain row.
pub const ROW_FORMAT: u8 = 1;

/// The two chains of a cell (ADR-010 "Chains").
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ChainId {
    /// The application chain, written by `fstp-cell`. Byte value 1.
    App,
    /// The vault chain, written by `fstp-vault`. Byte value 2.
    Vault,
}

impl ChainId {
    /// Both chains.
    pub const ALL: [ChainId; 2] = [ChainId::App, ChainId::Vault];

    /// The ADR-010 byte value: `App` is 1, `Vault` is 2.
    pub const fn byte(self) -> u8 {
        match self {
            ChainId::App => 1,
            ChainId::Vault => 2,
        }
    }

    /// The chain of an ADR-010 byte value.
    pub const fn from_byte(b: u8) -> Option<ChainId> {
        match b {
            1 => Some(ChainId::App),
            2 => Some(ChainId::Vault),
            _ => None,
        }
    }
}

/// A SHA-256 link.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Link(pub [u8; 32]);

/// What a chain row records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RowKind {
    /// Kind 1: a ledger entry, by sequence.
    Ledger {
        /// The ledger sequence.
        seq: u64,
    },
    /// Kind 2: an audit event with a sealed body.
    Event {
        /// The sealed body bytes.
        body: Vec<u8>,
    },
}

impl RowKind {
    /// The ADR-010 kind code.
    pub const fn code(&self) -> u16 {
        match self {
            RowKind::Ledger { .. } => KIND_LEDGER,
            RowKind::Event { .. } => KIND_EVENT,
        }
    }
}

/// One row of a chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainRow {
    /// The row number, from 1.
    pub n: u64,
    /// UTC microseconds.
    pub at: i64,
    /// What the row records.
    pub kind: RowKind,
    /// SHA-256 of the stored row bytes.
    pub stored_hash: [u8; 32],
}

/// A stored chain row with its link column.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredRow {
    /// The row's columns.
    pub row: ChainRow,
    /// The stored link column.
    pub link: Link,
}

/// A stored ledger entry, sealed body included. The chain hashes it
/// without a content key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredEntry {
    /// The ledger sequence.
    pub seq: u64,
    /// UTC microseconds.
    pub at: i64,
    /// The command id.
    pub command: [u8; 16],
    /// The schema version.
    pub schema: u16,
    /// The ledger key index.
    pub key_ix: u32,
    /// The sealed canonical text.
    pub body: Vec<u8>,
}

/// The link before the first row of `cell`'s `chain`. It binds the cell
/// and the chain.
pub fn genesis(cell: CellId, chain: ChainId) -> Link {
    Link(sha256(&[GENESIS_LABEL, &cell.0, &[chain.byte()]]))
}

/// The link of row `n` with `stored_hash` after `prev`.
pub fn link_of(prev: &Link, cell: CellId, chain: ChainId, n: u64, stored_hash: &[u8; 32]) -> Link {
    Link(sha256(&[
        LINK_LABEL,
        &cell.0,
        &[chain.byte()],
        &n.to_be_bytes(),
        &prev.0,
        stored_hash,
    ]))
}

/// The link after `row`. It reads the row's number and stored hash
/// column; the stored hash binds the other columns.
pub fn link(prev: &Link, cell: CellId, chain: ChainId, row: &ChainRow) -> Link {
    link_of(prev, cell, chain, row.n, &row.stored_hash)
}

/// Writes the ADR-010 row bytes to `out`. `entry` is the ledger entry of a
/// kind 1 row and must be `None` for a kind 2 row.
fn write_row<S: Sink>(
    out: &mut S,
    at: i64,
    kind: &RowKind,
    entry: Option<&StoredEntry>,
) -> Result<(), Invalid> {
    match (kind, entry) {
        (RowKind::Ledger { .. }, None) => return Err(Invalid::MissingEntry),
        (RowKind::Ledger { seq }, Some(e)) if e.seq != *seq => {
            return Err(Invalid::EntryOfAnotherSeq);
        }
        (RowKind::Event { .. }, Some(_)) => return Err(Invalid::EntryForEventRow),
        _ => {}
    }
    let body_len = match (kind, entry) {
        (RowKind::Event { body }, _) => len32(body.len(), MAX_EVENT_BODY_LEN),
        // A sealed ledger body is bounded by its `be32` length only.
        (RowKind::Ledger { .. }, Some(e)) => len32(e.body.len(), usize::MAX),
        (RowKind::Ledger { .. }, None) => None,
    }
    .ok_or(Invalid::BodyTooLong)?;
    out.put(ROW_LABEL);
    out.put(&kind.code().to_be_bytes());
    out.put(&at.to_be_bytes());
    match (kind, entry) {
        (RowKind::Ledger { seq }, Some(e)) => {
            out.put(&seq.to_be_bytes());
            out.put(&e.at.to_be_bytes());
            out.put(&e.command);
            out.put(&e.schema.to_be_bytes());
            out.put(&e.key_ix.to_be_bytes());
            out.put(&body_len);
            out.put(&e.body);
        }
        (RowKind::Event { body }, _) => {
            out.put(&body_len);
            out.put(body);
        }
        (RowKind::Ledger { .. }, None) => return Err(Invalid::MissingEntry),
    }
    Ok(())
}

/// The ADR-010 row bytes of a row at `at` of `kind`. A kind 1 row needs
/// its ledger entry, whose `seq` is the one the row names.
///
/// # Errors
///
/// [`AuditError::Invalid`] for a missing, mismatched or extra entry, or a
/// body over its limit.
pub fn row_bytes(
    at: i64,
    kind: &RowKind,
    entry: Option<&StoredEntry>,
) -> Result<Vec<u8>, AuditError> {
    let mut out = Vec::new();
    write_row(&mut out, at, kind, entry)?;
    Ok(out)
}

/// `stored_hash = SHA-256(row bytes)`, hashed as the bytes are written.
///
/// # Errors
///
/// As [`row_bytes`].
pub fn stored_hash(
    at: i64,
    kind: &RowKind,
    entry: Option<&StoredEntry>,
) -> Result<[u8; 32], AuditError> {
    let mut h = fstp_crypto::Sha256::new();
    write_row(&mut h, at, kind, entry)?;
    Ok(h.finish())
}

/// The only code that computes links for new rows (design section 7.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainWriter {
    head: (u64, Link),
}

impl ChainWriter {
    /// A writer at the genesis of `cell`'s `chain`.
    pub fn genesis(cell: CellId, chain: ChainId) -> ChainWriter {
        ChainWriter {
            head: (0, genesis(cell, chain)),
        }
    }

    /// A writer that continues after `head`.
    pub fn resume(n: u64, link: Link) -> ChainWriter {
        ChainWriter { head: (n, link) }
    }

    /// The row number and link of the head.
    pub fn head(&self) -> (u64, Link) {
        self.head
    }

    /// Appends one row of `kind` at `at` and returns it with its link. A
    /// kind 1 row needs its ledger entry. On a refusal the head is
    /// unchanged.
    ///
    /// # Errors
    ///
    /// [`Invalid::RowNumberExhausted`] after row `u64::MAX`, and the
    /// refusals of [`row_bytes`].
    pub fn append(
        &mut self,
        cell: CellId,
        chain: ChainId,
        at: i64,
        kind: RowKind,
        entry: Option<&StoredEntry>,
    ) -> Result<StoredRow, AuditError> {
        let (n, prev) = self.head;
        let n = n.checked_add(1).ok_or(Invalid::RowNumberExhausted)?;
        let stored_hash = stored_hash(at, &kind, entry)?;
        let link = link_of(&prev, cell, chain, n, &stored_hash);
        self.head = (n, link);
        Ok(StoredRow {
            row: ChainRow {
                n,
                at,
                kind,
                stored_hash,
            },
            link,
        })
    }
}

/// Encodes a chain row's columns:
///
/// ```text
/// version (1) || be64(n) || be64(at) || be16(kind)
///   || kind 1: be64(seq) | kind 2: be32(len) || body
///   || stored_hash (32)
/// ```
///
/// # Errors
///
/// [`Invalid::RowNumberZero`] for row 0, [`Invalid::BodyTooLong`] for an
/// event body over [`MAX_EVENT_BODY_LEN`].
pub fn encode_chain_row(row: &ChainRow) -> Result<Vec<u8>, AuditError> {
    if row.n == 0 {
        return Err(Invalid::RowNumberZero.into());
    }
    let mut out = Vec::new();
    out.push(ROW_FORMAT);
    out.extend_from_slice(&row.n.to_be_bytes());
    out.extend_from_slice(&row.at.to_be_bytes());
    out.extend_from_slice(&row.kind.code().to_be_bytes());
    match &row.kind {
        RowKind::Ledger { seq } => out.extend_from_slice(&seq.to_be_bytes()),
        RowKind::Event { body } => {
            let len = len32(body.len(), MAX_EVENT_BODY_LEN).ok_or(Invalid::BodyTooLong)?;
            out.extend_from_slice(&len);
            out.extend_from_slice(body);
        }
    }
    out.extend_from_slice(&row.stored_hash);
    Ok(out)
}

/// Decodes a stored chain row. One spelling: the input is exactly
/// [`encode_chain_row`] of the result. Fuzzed (`chain_row_decode`).
///
/// # Errors
///
/// [`AuditError::Decode`] for any other input.
pub fn decode_chain_row(bytes: &[u8]) -> Result<ChainRow, AuditError> {
    let mut r = Reader::new(bytes);
    let version = r.u8()?;
    if version != ROW_FORMAT {
        return Err(DecodeError::UnknownVersion(version).into());
    }
    let n = r.be64()?;
    if n == 0 {
        return Err(DecodeError::Invalid(Invalid::RowNumberZero).into());
    }
    let at = r.bei64()?;
    let kind = match r.be16()? {
        KIND_LEDGER => RowKind::Ledger { seq: r.be64()? },
        KIND_EVENT => RowKind::Event {
            body: r.bytes32(MAX_EVENT_BODY_LEN)?,
        },
        other => return Err(DecodeError::UnknownTag(other).into()),
    };
    let stored_hash = r.array::<32>()?;
    r.finish()?;
    Ok(ChainRow {
        n,
        at,
        kind,
        stored_hash,
    })
}
