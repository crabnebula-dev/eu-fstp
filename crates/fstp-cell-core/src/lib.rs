//! Cell commands, records and state, the gate, the sans-IO driver, the
//! release rule and tenant records (M3 design section 5). Pure.
//!
//! `CellCommand` and `CellRecord` extend the M2 engine envelope. The M2
//! members `core` and `finding` decode through `fstp_engine::Record`
//! unchanged, so every M2 record keeps its exact bytes.
//!
//! Status: W0 stub. Lane W2c fills the crate. The gate's high-risk table
//! is data reviewed in W0 against `SPEC/03-architecture/authentication.md`
//! and the M2 base (I-78). Every operation refuses with a typed
//! `NotImplemented` error.

pub mod codec;
pub mod driver;
pub mod gate;
pub mod ops;
pub mod release;
pub mod tenant;
pub mod text;

use fstp_domain::id::AccountId;
use fstp_domain::oracle::{Answers, Query};
use fstp_ledger::Entry;

pub use codec::{decode_cell_command, decode_cell_record, record_from_canonical_at};

/// A command of a cell.
#[allow(
    clippy::large_enum_variant,
    reason = "the envelope keeps the M2 member unboxed, as fstp_engine::Command does"
)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CellCommand {
    /// An M2 engine command.
    Engine(fstp_engine::Command),
    /// Credentials, step-ups and recovery steps.
    Auth(fstp_auth::AuthCommand),
    /// Tenant admin grants, self-grant approval and the login policy.
    Tenant(tenant::TenantCommand),
    /// Text store writes and erasure requests.
    Text(text::TextCommand),
    /// Key operations from the erasure runner.
    Key(KeyCommand),
    /// Release and write tickets, and relationship records.
    Release(release::ReleaseCommand),
    /// Break-glass, operator tickets and scheduled session ends.
    Ops(ops::OpsCommand),
}

/// A record of a cell.
#[allow(
    clippy::large_enum_variant,
    reason = "the envelope keeps the M2 member unboxed, as fstp_engine::Record does"
)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CellRecord {
    /// An M2 engine record.
    Engine(fstp_engine::Record),
    /// An auth record.
    Auth(fstp_auth::AuthRecord),
    /// A tenant record.
    Tenant(tenant::TenantRecord),
    /// A text record.
    Text(text::TextRecord),
    /// A key record.
    Key(KeyRecord),
    /// A release record.
    Release(release::ReleaseRecord),
    /// An ops record.
    Ops(ops::OpsRecord),
}

/// A key operation from the erasure runner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyCommand {
    /// Record a key operation.
    RecordKeyOp {
        /// The operation, canonical.
        op: Vec<u8>,
    },
    /// Record a destroyed root epoch with its custody receipt digest.
    RecordEpochDestroyed {
        /// The epoch.
        epoch: u64,
        /// The receipt digest.
        receipt: [u8; 32],
    },
}

/// A key record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyRecord {
    /// A key operation was recorded.
    KeyOpRecorded {
        /// The operation, canonical.
        op: Vec<u8>,
    },
    /// A root epoch was destroyed.
    EpochDestroyed {
        /// The epoch.
        epoch: u64,
        /// The receipt digest.
        receipt: [u8; 32],
    },
}

/// The state of a cell, folded from its ledger.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CellState {
    engine: fstp_engine::EngineState,
}

impl CellState {
    /// The M2 engine state.
    pub fn engine(&self) -> &fstp_engine::EngineState {
        &self.engine
    }
}

/// The context a cell command runs in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CellCtx {
    /// The acting account.
    pub actor: AccountId,
    /// UTC microseconds.
    pub at: i64,
}

/// Why a cell command was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CellRefusal {
    /// The M2 domain refused.
    Domain(fstp_domain::Refusal),
    /// The operation is a W0 stub. It names the operation.
    NotImplemented(&'static str),
}

/// Why the fold refused a record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FoldError {
    /// The M2 fold refused.
    Engine(fstp_domain::FoldError),
    /// The fold is a W0 stub. It names the operation.
    NotImplemented(&'static str),
}

/// The attestations of `Ctx` for an M2 command, read only from the tenant
/// fold.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Attestation {
    /// Whether the actor is a current tenant admin.
    pub tenant_admin: bool,
    /// Whether a second tenant admin approved this grant.
    pub second_tenant_admin: bool,
    /// Whether the grant binds a tenant admin.
    pub binds_tenant_admin: bool,
}

/// The vault queries a command needs.
pub fn queries(s: &CellState, c: &CellCommand, x: &CellCtx) -> Result<Vec<Query>, CellRefusal> {
    let _ = (s, c, x);
    Err(CellRefusal::NotImplemented("fstp_cell_core::queries"))
}

/// Decides a command into records.
pub fn decide(
    s: &CellState,
    c: &CellCommand,
    x: &CellCtx,
    a: &Answers,
) -> Result<Vec<CellRecord>, CellRefusal> {
    let _ = (s, c, x, a);
    Err(CellRefusal::NotImplemented("fstp_cell_core::decide"))
}

/// Folds one entry.
pub fn apply(s: &mut CellState, e: &Entry<CellRecord>) -> Result<(), FoldError> {
    let _ = (s, e);
    Err(FoldError::NotImplemented("fstp_cell_core::apply"))
}

/// Folds a ledger from genesis.
pub fn replay(entries: &[Entry<CellRecord>]) -> Result<CellState, FoldError> {
    let _ = entries;
    Err(FoldError::NotImplemented("fstp_cell_core::replay"))
}

/// The `Ctx` attestations for an M2 command. The designed function is
/// infallible; the stub returns a `Result` until lane W2c lands it.
pub fn attest(
    s: &CellState,
    actor: AccountId,
    cmd: &fstp_engine::Command,
) -> Result<Attestation, CellRefusal> {
    let _ = (s, actor, cmd);
    Err(CellRefusal::NotImplemented("fstp_cell_core::attest"))
}
