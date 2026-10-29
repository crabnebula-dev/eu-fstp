//! The anchor witness: anchor intake, per-cell witness chains and
//! receipts (I-24, M3 design section 7.2, ADR-010). A PostgreSQL store
//! serves SaaS and an append-only file store serves self-hosted installs.
//!
//! - [`chain_witness`] is the pure witness core for one cell and chain: the sender
//!   rule, prepare, receipt, abort and in-doubt records, and the
//!   one-outstanding-prepare rule.
//! - [`message`] encodes and decodes what cells and vaults send.
//! - [`file_store`] is the append-only store of a self-hosted witness.
//! - [`receipt`] signs receipts and checks anchor signatures. Both refuse
//!   until Daniel accepts the ADR-010 composite encoding table (lane W2g
//!   hard limit), so no receipt leaves the witness today.
//!
//! [`CATALOGUE`] holds the `witness.anchor` column map of design section
//! 4.4, reviewed in W0. ADR-010 adds prepare, abort, in-doubt and restore
//! records; design section 4.4 does not list their tables yet, so they
//! are not here (ADR-010 open point 4).
//!
//! Open design conflict, raised for Daniel and the lead before any lane
//! writes the witness database store. The core numbers `witness_seq` per
//! cell and chain from 1, as W1e does. It also lets a cell prepare the
//! same `n` again with another link once the abort is recorded (ADR-010
//! "Abort"). Design section 4.4 declares `witness_seq` UNIQUE across the
//! whole table and `PRIMARY KEY (cell_id, chain, n)`. A second cell's
//! first prepare then breaks the UNIQUE constraint, and a re-prepare of
//! an aborted `n` breaks the key. [`CATALOGUE`] keeps the design's
//! columns unchanged until the decision lands in ADR-010 open point 4.
//!
//! [`run`], the service over TLS and
//! PostgreSQL, is not written: without receipt signing it could only
//! refuse every prepare.

pub mod chain_witness;
pub mod file_store;
pub mod message;
pub mod receipt;

use fstp_audit::{DecodeError, Invalid};
use fstp_migrate::catalogue::{ColumnClass, ColumnSpec, TableClass, TableSpec};

pub use crate::chain_witness::{
    ChainWitness, Refusal, Sender, Withdrawal, WitnessState, accepts_sender,
};
pub use crate::file_store::{FileRecord, decode_file_store, encode_file_store, load_file_store};
pub use crate::message::{WitnessMessage, decode_witness_message, encode_witness_message};
pub use crate::receipt::sign_receipt;

/// Why a witness operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WitnessError {
    /// Bytes did not decode.
    Decode(DecodeError),
    /// An input the operation refuses to encode.
    Invalid(Invalid),
    /// The operation signs or checks a signature, and waits on the named
    /// acceptance ([`fstp_audit::COMPOSITE_ENCODING_ACCEPTANCE`]).
    AwaitsAcceptance(&'static str),
    /// The operation is not written yet. It names the operation.
    NotImplemented(&'static str),
}

impl std::fmt::Display for WitnessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WitnessError::Decode(e) => write!(f, "witness bytes do not decode: {e:?}"),
            WitnessError::Invalid(e) => write!(f, "witness input refused: {e:?}"),
            WitnessError::AwaitsAcceptance(what) => write!(f, "refused until {what}"),
            WitnessError::NotImplemented(op) => write!(f, "{op} is not implemented yet"),
        }
    }
}

impl std::error::Error for WitnessError {}

impl From<DecodeError> for WitnessError {
    fn from(e: DecodeError) -> WitnessError {
        match e {
            DecodeError::Invalid(i) => WitnessError::Invalid(i),
            other => WitnessError::Decode(other),
        }
    }
}

impl From<Invalid> for WitnessError {
    fn from(e: Invalid) -> WitnessError {
        WitnessError::Invalid(e)
    }
}

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

/// Runs the witness until shutdown. Not written yet: the service needs
/// receipt signing, which waits on the ADR-010 composite encoding
/// acceptance, and its TLS and database wiring.
///
/// # Errors
///
/// [`WitnessError::NotImplemented`].
pub fn run() -> Result<(), WitnessError> {
    Err(WitnessError::NotImplemented("fstp_witness::run"))
}
