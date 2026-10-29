//! Cell commands, records and state, the gate, the sans-IO driver, the
//! release rule and tenant records (M3 design section 5). Pure.
//!
//! `CellCommand` and `CellRecord` extend the M2 engine envelope. The M2
//! members `core` and `finding` decode through `fstp_engine::Record`
//! unchanged, so every M2 record keeps its exact bytes ([`codec`]).
//!
//! - [`queries`] and [`decide`] run a command. An M2 command goes to the
//!   M2 decider with the `Ctx` attestations read from the tenant fold
//!   ([`attest`]), never from request fields. The cell commands are
//!   decided in [`decide`] itself (design section 5.1).
//! - [`apply`] and [`replay`] fold the ledger ([`state`]).
//! - [`gate`] admits an action, and [`driver`] runs one admitted command.
//!
//! The auth member is encoded and decoded by `fstp_auth::codec`, so each
//! auth record and command has one spelling. The gate's session checks
//! call `fstp_auth` (lanes W2b and W2c, integrated). An auth command whose
//! batch needs an input that only a route holds is refused with
//! [`CellRefusal::NotImplemented`], naming lane W3a.

#![deny(
    clippy::float_arithmetic,
    clippy::float_cmp,
    clippy::cast_precision_loss,
    clippy::arithmetic_side_effects
)]

pub mod codec;
mod decide;
pub mod driver;
pub mod gate;
pub mod ops;
pub mod release;
pub mod state;
pub mod tenant;
pub mod text;

use fstp_domain::id::AccountId;
use fstp_domain::oracle::{Answers, Query};
use fstp_domain::time::Timestamp;
use fstp_ledger::{Entry, Seq};

pub use codec::{
    decode_cell_command, decode_cell_record, encode_cell_command, encode_cell_record,
    record_from_canonical_at, try_encode_cell_command,
};
pub use decide::{
    ACCOUNT_ERASURE_CAUSES, ERASURE_CAUSES, RELEASE_STATES, RouteInput,
    WRITE_KIND_GUARDIAN_CONSENT, action_digest, attest_at, decide_reaction, reaction_queries,
    route_inputs, self_grant_digest, try_action_digest, vault_changed, without_vault_outcomes,
};
pub use state::CellState;
pub use state::{
    SYSTEM_PREFIX, is_system_command_id, reaction_command_id, reaction_epoch, system_command_id,
};

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

/// The context a cell command runs in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CellCtx {
    /// The acting account.
    pub actor: AccountId,
    /// UTC microseconds.
    pub at: i64,
}

/// A system task of the cell: a caller that holds no session and acts
/// for no account (design sections 3.5 and 5.1).
///
/// Key records, scheduled session ends and the M2 commands that
/// `fstp_domain::due` lists come from system tasks only. An account
/// command never decides them, so no session can forge erasure evidence
/// or end a binding (I-24, I-81, ADR-007). A task's command runs under an
/// id in the namespace [`state::SYSTEM_PREFIX`], which no account may use.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SystemTask {
    /// The erasure runner (design section 3.5): `KeyCommand`.
    ErasureRunner,
    /// The timeline (design section 5.1, `fstp_domain::due`): the M2
    /// System commands due at an instant, with the actor
    /// `System(Timeline)`, and `EndSessionsAtBindingEnd`.
    Timeline,
}

/// The context a system task's command runs in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemCtx {
    /// The task.
    pub task: SystemTask,
    /// UTC microseconds.
    pub at: i64,
}

/// Why a cell command was refused.
///
/// Every refusal of the cell is a domain refusal, with the rule and the
/// reason of `fstp_domain::refusal`, so a caller handles one kind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CellRefusal {
    /// The M2 domain or the cell refused.
    Domain(fstp_domain::Refusal),
    /// The command needs a record or an input that the sources do not
    /// define yet. It names what is missing and the lane that owns it.
    NotImplemented(&'static str),
}

/// Why the fold refused a record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FoldError {
    /// The M2 fold or the cell fold refused, with the M2 error kinds.
    Engine(fstp_domain::FoldError),
    /// The fold met a record it cannot fold yet. It names the operation.
    NotImplemented(&'static str),
}

/// The attestations of `Ctx` for an M2 command, read only from the tenant
/// fold (design section 5.1).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Attestation {
    /// Whether the actor is a current tenant admin.
    pub tenant_admin: bool,
    /// Whether a second tenant admin approved this grant (SoD-07).
    pub second_tenant_admin: bool,
    /// Whether the grant binds a tenant admin.
    pub binds_tenant_admin: bool,
}

/// The vault queries a command needs.
pub fn queries(s: &CellState, c: &CellCommand, x: &CellCtx) -> Result<Vec<Query>, CellRefusal> {
    decide::queries_with(s, c, decide::Who::Account(x.actor), x.at, None)
}

/// Decides a command into records.
///
/// `CellCtx` carries no command id, so a self-grant decided here is never
/// approved under SoD-07. The driver decides with the caller's command id
/// ([`decide_with_id`]).
pub fn decide(
    s: &CellState,
    c: &CellCommand,
    x: &CellCtx,
    a: &Answers,
) -> Result<Vec<CellRecord>, CellRefusal> {
    decide::decide_with(s, c, decide::Who::Account(x.actor), x.at, None, None, a)
}

/// [`decide`] under the caller's command id, which the SoD-07 grant
/// digest names (design section 5.1).
pub fn decide_with_id(
    s: &CellState,
    c: &CellCommand,
    x: &CellCtx,
    command: [u8; 16],
    a: &Answers,
) -> Result<Vec<CellRecord>, CellRefusal> {
    decide::decide_with(
        s,
        c,
        decide::Who::Account(x.actor),
        x.at,
        Some(command),
        None,
        a,
    )
}

/// [`queries`] under the caller's command id.
pub fn queries_with_id(
    s: &CellState,
    c: &CellCommand,
    x: &CellCtx,
    command: [u8; 16],
) -> Result<Vec<Query>, CellRefusal> {
    decide::queries_with(s, c, decide::Who::Account(x.actor), x.at, Some(command))
}

/// The vault queries of a system task's command ([`SystemTask`]).
pub fn queries_system(
    s: &CellState,
    c: &CellCommand,
    x: &SystemCtx,
    command: [u8; 16],
) -> Result<Vec<Query>, CellRefusal> {
    decide::queries_with(s, c, decide::Who::System(x.task), x.at, Some(command))
}

/// Decides a system task's command under its command id. Each task
/// decides its own commands only, and refuses every other with
/// `WrongActor` ([`SystemTask`]).
pub fn decide_system(
    s: &CellState,
    c: &CellCommand,
    x: &SystemCtx,
    command: [u8; 16],
    a: &Answers,
) -> Result<Vec<CellRecord>, CellRefusal> {
    decide::decide_with(
        s,
        c,
        decide::Who::System(x.task),
        x.at,
        Some(command),
        None,
        a,
    )
}

/// Folds one entry. The entry must follow the state's head, and its time
/// must not be earlier than the latest recorded time of any member.
pub fn apply(s: &mut CellState, e: &Entry<CellRecord>) -> Result<(), FoldError> {
    state::fold(s, e.seq, Timestamp::from_micros(e.at), e.command, &e.record)
}

/// Folds a ledger from genesis (I-23). Sequence numbers must run from 1
/// without gaps.
pub fn replay(entries: &[Entry<CellRecord>]) -> Result<CellState, FoldError> {
    let mut s = CellState::genesis();
    for e in entries {
        apply(&mut s, e)?;
    }
    Ok(s)
}

/// The `Ctx` attestations for an M2 command, read only from the tenant
/// fold. Without a command id and an instant, no SoD-07 approval can be
/// matched, so `second_tenant_admin` is false here ([`attest_at`]).
///
/// Design section 5.1 gives an infallible function. The `Result` is kept
/// because the W1 suites call it so. It never refuses.
pub fn attest(
    s: &CellState,
    actor: AccountId,
    cmd: &fstp_engine::Command,
) -> Result<Attestation, CellRefusal> {
    Ok(decide::attestation(s, actor, cmd, None).public())
}

/// The sequence number one past `head`, or `None` at the end of the range.
pub(crate) fn next_seq(head: Seq) -> Option<Seq> {
    head.raw().checked_add(1).map(Seq::from_raw)
}
