//! The anchor witness: anchor intake, per-cell anchor chains and receipts
//! (I-24, M3 design section 7.2, ADR-010). A PostgreSQL store serves SaaS
//! and an append-only file store serves self-hosted installs.
//!
//! Status: W0 stub. Lane W2g fills the crate. [`CATALOGUE`] holds the
//! `witness.anchor` column map of design section 4.4, reviewed in W0.
//! ADR-010 adds prepare, abort, in-doubt and restore records; design
//! section 4.4 does not list their tables yet, so they are not here. Every
//! operation refuses with [`WitnessError::NotImplemented`].

use fstp_migrate::catalogue::{ColumnClass, ColumnSpec, TableClass, TableSpec};

/// Why a witness operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WitnessError {
    /// The operation is a W0 stub. It names the operation.
    NotImplemented(&'static str),
}

impl std::fmt::Display for WitnessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WitnessError::NotImplemented(op) => write!(f, "{op} is not implemented yet"),
        }
    }
}

impl std::error::Error for WitnessError {}

const fn col(name: &'static str, class: ColumnClass) -> ColumnSpec {
    ColumnSpec {
        name,
        class: Some(class),
    }
}

/// A column whose class the closed list of design section 4.5 does not
/// cover. Open for Daniel; the R-NF-08 test refuses it until decided.
const fn open(name: &'static str) -> ColumnSpec {
    ColumnSpec { name, class: None }
}

/// The tables of the witness database (design section 4.4).
pub const CATALOGUE: &[TableSpec] = &[TableSpec {
    schema: "witness",
    name: "anchor",
    class: TableClass::AuditEvent,
    columns: &[
        col("cell_id", ColumnClass::RandomId),
        col("chain", ColumnClass::Enum),
        col("n", ColumnClass::Sequence),
        open("link"),
        col("at", ColumnClass::Time),
        open("signature"),
        col("received_at", ColumnClass::Time),
        col("witness_seq", ColumnClass::Sequence),
        open("witness_link"),
    ],
}];

/// A message to the witness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WitnessMessage {
    /// Prepare an anchor and ask for its receipt.
    Prepare {
        /// The anchor bytes.
        anchor: Vec<u8>,
    },
    /// Abort a prepare whose commit failed.
    Abort {
        /// The row number.
        n: u64,
    },
    /// Report a prepare whose commit outcome is unknown.
    InDoubt {
        /// The row number.
        n: u64,
    },
}

/// One record of the append-only file store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileRecord {
    /// The witness sequence.
    pub witness_seq: u64,
    /// The record bytes.
    pub bytes: Vec<u8>,
}

/// Decodes a message. Fuzzed (`witness_message_decode`).
pub fn decode_witness_message(bytes: &[u8]) -> Result<WitnessMessage, WitnessError> {
    let _ = bytes;
    Err(WitnessError::NotImplemented(
        "fstp_witness::decode_witness_message",
    ))
}

/// Decodes the file store. A truncated file is detected. Fuzzed
/// (`file_store_decode`).
pub fn decode_file_store(bytes: &[u8]) -> Result<Vec<FileRecord>, WitnessError> {
    let _ = bytes;
    Err(WitnessError::NotImplemented(
        "fstp_witness::decode_file_store",
    ))
}

/// Runs the witness until shutdown.
pub fn run() -> Result<(), WitnessError> {
    Err(WitnessError::NotImplemented("fstp_witness::run"))
}
