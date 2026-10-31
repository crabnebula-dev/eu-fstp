//! The anchor witness: anchor intake, per-cell witness chains and
//! receipts (I-24, M3 design section 7.2, ADR-010). A PostgreSQL store
//! serves SaaS and an append-only file store serves self-hosted installs.
//!
//! - [`chain_witness`] is the pure witness core for one cell and chain: the sender
//!   rule, prepare, receipt, abort and in-doubt records, and the
//!   one-outstanding-prepare rule.
//! - [`message`] encodes and decodes what cells and vaults send.
//! - [`file_store`] is the append-only store of a self-hosted witness.
//! - [`receipt`] signs receipts under the witness key and checks anchor
//!   signatures under the chain's anchor key history (ADR-010 "Receipt"
//!   and "Keys"). The service runs the anchor check before
//!   [`ChainWitness::prepare`] and signs the receipt fields it returns.
//!
//! - [`wire`] frames the requests and replies of a witness connection.
//! - [`peer`] tells the sender of a connection from its client
//!   certificate, among the pinned cell CAs.
//! - [`store`] is the PostgreSQL store of a SaaS witness, and
//!   [`MIGRATIONS`] its migration set.
//! - [`service`] is the run loop: the mutual TLS listener, the store and
//!   the receipts, on one runtime through `fstp-rt` ([`serve`]).
//! - [`lock`] is the async mutex the service and the cell's link use.
//!
//! [`CATALOGUE`] holds the column maps of the witness database (design
//! section 4.4): `witness.anchor`, and the receipt, withdrawal, CA and
//! anchor key records of ADR-010 open point 4. The core numbers
//! `witness_seq` per cell and chain from 1, and lets a cell prepare the
//! same `n` again with another link once the abort is recorded (ADR-010
//! "Abort"). So `witness.anchor` and `witness.withdrawal` are keyed by
//! `(cell_id, chain, witness_seq)`, with `(cell_id, chain, n, link)`
//! unique. Daniel accepted that key and the three extra tables on
//! 2026-10-30 (design sections 4.4 and 21.0).
//!
//! Every column has a class of design section 4.5. Links are
//! `PublicDigest`, composite signatures `Signature`, and pinned CA
//! certificates and anchor public keys `PublicKeyMaterial` (Daniel,
//! 2026-10-30).
//!
//! [`run`], the binary's entry, still refuses: the process configuration
//! and the receipt key's custody entry are not designed yet (ADR-010
//! "Keys", open point 6). [`serve`] is the run loop a world starts.

pub mod chain_witness;
pub mod file_store;
pub mod lock;
pub mod message;
pub mod peer;
pub mod receipt;
pub mod service;
pub mod store;
pub mod wire;

use fstp_audit::{CryptoError, DecodeError, Invalid};
use fstp_migrate::catalogue::{ColumnClass, ColumnSpec, TableClass, TableSpec};

pub use crate::chain_witness::{
    ChainWitness, Refusal, Sender, Withdrawal, WitnessState, accepts_sender,
};
pub use crate::file_store::{FileRecord, decode_file_store, encode_file_store, load_file_store};
pub use crate::message::{WitnessMessage, decode_witness_message, encode_witness_message};
pub use crate::receipt::sign_receipt;
pub use crate::service::{WitnessHandle, WitnessParts, serve};

/// The witness migrations, in order (design sections 4.4 and 4.6):
///
/// 1. `meta`: `fstp_meta.placement` with kind 4 only, and the shared
///    trigger function.
/// 2. `apply_grant`: `fstp_migrate::catalogue::APPLY_GRANT_SQL` and
///    `APPLY_GRANT_REVOKE_SQL`, the shared text of the application and
///    vault sets, byte for byte.
/// 3. `witness`: the witness tables of [`CATALOGUE`].
pub const MIGRATIONS: &[fstp_migrate::Migration] = &[
    fstp_migrate::Migration::new(
        1,
        "meta",
        include_str!("../migrations/witness/0001_meta.sql"),
    ),
    fstp_migrate::Migration::new(
        2,
        "apply_grant",
        include_str!("../migrations/witness/0002_apply_grant.sql"),
    ),
    fstp_migrate::Migration::new(
        3,
        "witness",
        include_str!("../migrations/witness/0003_witness.sql"),
    ),
];

/// Why a witness operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WitnessError {
    /// Bytes did not decode.
    Decode(DecodeError),
    /// An input the operation refuses to encode.
    Invalid(Invalid),
    /// An anchor signature did not verify under any key of the chain's
    /// anchor key history, in both halves (I-90).
    BadSignature,
    /// The composite signer gave no signature, for example when the
    /// system random number generator failed. Nothing was signed.
    Signing(CryptoError),
    /// The operation is not written yet. It names the operation.
    NotImplemented(&'static str),
    /// The witness database failed or refused.
    Store(store::StoreError),
    /// The TLS configuration did not build.
    Tls,
    /// A registered CA certificate does not read, or has no
    /// subjectKeyIdentifier.
    BadCa,
    /// A listener failed.
    Io(std::io::ErrorKind),
}

impl std::fmt::Display for WitnessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WitnessError::Decode(e) => write!(f, "witness bytes do not decode: {e:?}"),
            WitnessError::Invalid(e) => write!(f, "witness input refused: {e:?}"),
            WitnessError::BadSignature => f.write_str("anchor signature does not verify"),
            WitnessError::Signing(e) => write!(f, "receipt signing failed: {e}"),
            WitnessError::NotImplemented(op) => write!(f, "{op} is not implemented yet"),
            WitnessError::Store(e) => write!(f, "witness store: {e:?}"),
            WitnessError::Tls => f.write_str("witness TLS configuration refused"),
            WitnessError::BadCa => f.write_str("a registered CA certificate does not read"),
            WitnessError::Io(k) => write!(f, "witness listener: {k:?}"),
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

/// The tables of the witness database (design section 4.4, ADR-010 open
/// point 4), in the order the migrations create them.
pub const CATALOGUE: &[TableSpec] = &[
    TableSpec {
        schema: "fstp_meta",
        name: "placement",
        class: TableClass::Placement,
        columns: &[
            col("cluster_id", ColumnClass::RandomId),
            col("kind", ColumnClass::Enum),
        ],
    },
    TableSpec {
        schema: "witness",
        name: "anchor",
        class: TableClass::AuditEvent,
        columns: &[
            col("cell_id", ColumnClass::RandomId),
            col("chain", ColumnClass::Enum),
            col("n", ColumnClass::Sequence),
            col("link", ColumnClass::PublicDigest),
            col("at", ColumnClass::Time),
            col("signature", ColumnClass::Signature),
            col("received_at", ColumnClass::Time),
            col("witness_seq", ColumnClass::Sequence),
            col("witness_link", ColumnClass::PublicDigest),
        ],
    },
    TableSpec {
        schema: "witness",
        name: "receipt",
        class: TableClass::AuditEvent,
        columns: &[
            col("cell_id", ColumnClass::RandomId),
            col("chain", ColumnClass::Enum),
            col("witness_seq", ColumnClass::Sequence),
            col("signature", ColumnClass::Signature),
        ],
    },
    TableSpec {
        schema: "witness",
        name: "withdrawal",
        class: TableClass::AuditEvent,
        columns: &[
            col("cell_id", ColumnClass::RandomId),
            col("chain", ColumnClass::Enum),
            col("witness_seq", ColumnClass::Sequence),
            col("kind", ColumnClass::Enum),
            col("n", ColumnClass::Sequence),
            col("link", ColumnClass::PublicDigest),
            col("received_at", ColumnClass::Time),
            col("witness_link", ColumnClass::PublicDigest),
        ],
    },
    TableSpec {
        schema: "witness",
        name: "cell_ca",
        class: TableClass::Operational,
        columns: &[
            col("cell_id", ColumnClass::RandomId),
            col("ca_cert", ColumnClass::PublicKeyMaterial),
            col("registered_at", ColumnClass::Time),
        ],
    },
    TableSpec {
        schema: "witness",
        name: "anchor_key",
        class: TableClass::Operational,
        columns: &[
            col("cell_id", ColumnClass::RandomId),
            col("chain", ColumnClass::Enum),
            col("public_key", ColumnClass::PublicKeyMaterial),
            col("registered_at", ColumnClass::Time),
        ],
    },
];

/// The binary's entry. It refuses: the process configuration and the
/// receipt key's custody entry are not designed (ADR-010 "Keys", open
/// point 6). [`serve`] is the run loop, which a world starts with the
/// parts it holds.
///
/// # Errors
///
/// [`WitnessError::NotImplemented`].
pub fn run() -> Result<(), WitnessError> {
    Err(WitnessError::NotImplemented(
        "fstp_witness::run: the process configuration and the receipt key's custody entry (ADR-010 Keys, open point 6); fstp_witness::serve is the run loop",
    ))
}
