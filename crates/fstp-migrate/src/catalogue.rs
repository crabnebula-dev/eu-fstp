//! The schema catalogue types (M3 design section 4.5, R-NF-08, I-16, I-19).
//!
//! Each migration set's owner lists its own tables next to its migrations:
//! `fstp_pgstore::CATALOGUE` (app), `fstp_vault::CATALOGUE`,
//! `fstp_control::CATALOGUE` (cp), `fstp_witness::CATALOGUE` and
//! `fstp_release_svc::CATALOGUE` (licence). A test in `fstp-celltest` takes
//! their union, so no lane edits another lane's list.
//!
//! Status: W0 stub. Lane W2e owns this file. It adds the shared SQL of
//! `fstp_meta.apply_grant` (design section 4.1) and the catalogue tests.
//!
//! [`TableClass`] is closed. It has no class for a balance or a held amount
//! (I-16). A column whose class the design has not settled carries `None`
//! in [`ColumnSpec::class`]. The R-NF-08 catalogue test must refuse such a
//! column until the class is decided.

/// What a table holds. Closed: there is no class for a balance or a held
/// amount (I-16).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TableClass {
    /// Sealed ledger records (ADR-007).
    LedgerRecord,
    /// Audit chain rows, anchors and receipts (I-24).
    AuditEvent,
    /// Sealed content such as texts.
    SealedContent,
    /// Wrapped keys and key records.
    KeyMaterial,
    /// Operational records that carry no tenant content.
    Operational,
    /// Migration ledger rows.
    Migration,
    /// Placement of cells on clusters (I-83).
    Placement,
}

/// What a clear column may hold (R-NF-08).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ColumnClass {
    /// Ciphertext under a cell key.
    Sealed,
    /// A random identifier.
    RandomId,
    /// A sequence number.
    Sequence,
    /// A timestamp.
    Time,
    /// A value of a closed enum.
    Enum,
    /// A hash of a random secret.
    SecretDigest,
    /// An HMAC under a key that erasure rotates.
    KeyedDigest,
    /// A count.
    Count,
}

/// One column of a catalogued table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ColumnSpec {
    /// The column name.
    pub name: &'static str,
    /// The column class, or `None` while the design has not settled it.
    pub class: Option<ColumnClass>,
}

/// One catalogued table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TableSpec {
    /// The schema name.
    pub schema: &'static str,
    /// The table name.
    pub name: &'static str,
    /// What the table holds.
    pub class: TableClass,
    /// Every column, in declaration order.
    pub columns: &'static [ColumnSpec],
}
