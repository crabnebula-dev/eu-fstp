//! `queries` and `decide` for every cell command, the `Ctx` attestations
//! and the digests (design sections 5.1, 6.5, 6.6 and 8.4).
//!
//! - An M2 command goes to `fstp_engine::DomainDecider` with a `Ctx` whose
//!   attestations come from the tenant fold. A self-grant counts as
//!   approved only for an unused, unexpired approval by another current
//!   tenant admin of its digest, and the grant batch records the use
//!   (SoD-07, TH-05, Q40).
//! - Every command is refused when its time is earlier than the latest
//!   recorded time of any member (design section 2.2).
//! - The cell commands are decided here. Each refusal is a domain refusal
//!   with a rule and a reason.
//!
//! - While a scheduled binding end is overdue, every cell command of an
//!   account is refused as M2 refuses its commands (SoD-05, Cooling-off
//!   NOTE), except the auth commands and the two commands that only end
//!   access (`EndBreakGlass`, `EndTenantAdmin`). A holder check also
//!   counts a binding only until its scheduled end instant (design
//!   section 8.2).
//!
//! Readings taken, for Daniel's review:
//! - Interim: the first `GrantTenantAdmin` of a cell that never had a
//!   tenant admin is taken by the account it names. It stands in for the
//!   first-admin enrolment ceremony (design section 8.3, Q14, Q35) until
//!   that exists. Once the cell had a tenant admin, an empty admin set
//!   never reopens it.
//! - Erasures, break-glass approvals and the login policy are tenant admin
//!   commands. A text write is open to every account the gate admits.
//! - Interim: a tenant admin records an erasure only with the cause
//!   erasure request or cell erasure, and is its authoriser (ADR-007
//!   "Erasure-log entries"). Retention expiry (P-41) and a completed
//!   verification (R-ID-03) are refused to every account (`WrongActor`).
//!   Their authoriser is the system or the vault, and no record names
//!   one yet. So no task records them either, until a record form with
//!   the P-41 rule reference exists (fail closed).
//! - Every decided batch must read back from its stored bytes, so no
//!   record beyond a codec bound is ever appended (I-23, design 5.3).
//! - Key records come from the erasure runner, and scheduled session ends
//!   and the M2 commands of `fstp_domain::due` from the timeline, both
//!   system tasks ([`crate::SystemTask`]). Relationship records and
//!   operator tickets come from system paths too. An account never
//!   decides any of them (`WrongActor`). No relationship form and no
//!   operator ticket form is defined yet, so a system task is refused them
//!   as well.
//! - A guardian consent write ticket goes to the actor, which must hold a
//!   current Guardian binding on a proposal whose consent collection is
//!   open and must not be its lead. The cell asks
//!   `IsVerifiedAdultAtDeadline` for the lead at the deadline of the call
//!   the proposal was submitted to, and `SameIdentityAsAny` for the actor
//!   and the lead. It issues the ticket only on a no to both (I-18, design
//!   section 6.6 step 3).
//! - A release ticket goes to a tenant admin or an Operations holder of
//!   the programme, for a proposal in NEGOTIATION, GRANTED,
//!   IN_EXECUTION, COMPLETED or TERMINATED (I-17, design section 6.5).
//! - Interim: the `SessionEnded` reactions of design section 5.1 are
//!   recorded when the route or task gives the live session rows
//!   ([`RouteInputs`]). Without rows a grant or an end commits without
//!   them. The gate refuses those sessions either way (design section 5.4
//!   step 2), so the rows carry visibility, not the guarantee. The
//!   commands whose batch is a session end (`EndSession`,
//!   `RevokeCredential`, `CompleteRecovery`, `EndSessionsAtBindingEnd`)
//!   are refused without rows. After `CompleteRecovery` the gate also
//!   refuses every session of the account that started by its entry
//!   instant (I-79). `RevokeCredential` has no such backstop: the gate's
//!   `SessionView` does not name the credential a session logged in with.
//! - A digest holds every approval its admins recorded, and a grant uses
//!   the first that admits it. Only a used digest refuses a new approval
//!   (SoD-07, Q40, as the W1b reference rule reads it).

use std::collections::BTreeSet;

use fstp_domain::command::{Actor, Ctx, SystemCause, Via};
use fstp_domain::id::{AccountId, BindingId, CommandId, ProposalId, VaultEpoch};
use fstp_domain::oracle::{Answers, Query};
use fstp_domain::refusal::{Refusal, RefusalReason, RuleRef};
use fstp_domain::roles::{Group, Role};
use fstp_domain::rules::StateTag;
use fstp_domain::time::Timestamp;
use fstp_engine::Decider;

use crate::codec::{
    MAX_CREDENTIAL, MAX_OPAQUE, MAX_TEXT_IDS, decode_cell_record, encode_cell_command,
    encode_cell_record, grant_without_second_admin,
};
use crate::inputs::{RouteInputs, SessionRows};
use crate::ops::OpsCommand;
use crate::release::{ReleaseCommand, ReleaseRecord};
use crate::state::TextStatus;
use crate::tenant::{TenantCommand, TenantLoginPolicy, TenantRecord};
use crate::text::{TextCommand, TextRecord};
use crate::timeline::{EventStatus, TimelineCommand, TimelineRecord};
use crate::{
    Attestation, CellCommand, CellRecord, CellRefusal, CellState, KeyCommand, KeyRecord, SystemTask,
};

/// Who issues a command: an account the gate admitted, or a system task.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Who {
    /// An account.
    Account(AccountId),
    /// A system task.
    System(SystemTask),
}

/// The write kind of a guardian consent (ADR-009 "Write kinds").
pub const WRITE_KIND_GUARDIAN_CONSENT: u16 = 4;

/// The erasure causes of design section 5.6, as closed codes: retention
/// expiry (P-41), an erasure request, a cell erasure, and a completed
/// identity verification of a document (R-ID-03).
pub const ERASURE_CAUSES: [u16; 4] = [1, 2, 3, 4];

/// The erasure causes an account may record as their authoriser: an
/// erasure request and a cell erasure (ADR-007 "Erasure-log entries",
/// design section 5.6). A retention expiry is authorised by the system
/// under the P-41 rule, and a completed verification by the vault.
pub const ACCOUNT_ERASURE_CAUSES: [u16; 2] = [2, 3];

/// The proposal states in which a release ticket may be issued (I-17).
pub const RELEASE_STATES: [StateTag; 5] = [
    StateTag::Negotiation,
    StateTag::Granted,
    StateTag::InExecution,
    StateTag::Completed,
    StateTag::Terminated,
];

fn refuse(rule: RuleRef, reason: RefusalReason) -> CellRefusal {
    CellRefusal::Domain(Refusal::new(rule, reason))
}

fn wrong_actor() -> CellRefusal {
    refuse(RuleRef::Actor, RefusalReason::WrongActor)
}

fn reused() -> CellRefusal {
    refuse(RuleRef::Input, RefusalReason::IdReused)
}

fn unknown() -> CellRefusal {
    refuse(RuleRef::Input, RefusalReason::UnknownEntity)
}

fn invalid() -> CellRefusal {
    refuse(RuleRef::Input, RefusalReason::InvalidValue)
}

fn i18() -> CellRefusal {
    refuse(RuleRef::I18, RefusalReason::GuardFailed)
}

fn answer_missing() -> CellRefusal {
    refuse(RuleRef::FactsIncomplete, RefusalReason::AnswerMissing)
}

// ---------------------------------------------------------------------------
// Digests.

/// `SHA-256(canonical(command) || command_id)`: the action digest a
/// step-up authorises (design section 8.4).
///
/// It hashes [`encode_cell_command`] as it is. The gate checks a step-up
/// only through [`try_action_digest`], which refuses a command whose
/// encoding does not name it alone, so a digest from here never admits
/// such a command.
pub fn action_digest(cmd: &CellCommand, command_id: [u8; 16]) -> [u8; 32] {
    digest_of(&encode_cell_command(cmd), command_id)
}

/// [`action_digest`], or `None` when the canonical encoding of `cmd` does
/// not decode back to `cmd` alone (`try_encode_cell_command`). The gate
/// refuses the step-up then, so it fails closed (I-78).
pub fn try_action_digest(cmd: &CellCommand, command_id: [u8; 16]) -> Option<[u8; 32]> {
    crate::codec::try_encode_cell_command(cmd).map(|bytes| digest_of(&bytes, command_id))
}

fn digest_of(bytes: &[u8], command_id: [u8; 16]) -> [u8; 32] {
    let mut h = fstp_crypto::Sha256::new();
    h.update(bytes);
    h.update(&command_id);
    h.finish()
}

/// `SHA-256(canonical(GrantRole without second_admin) || command_id)`:
/// the SoD-07 grant digest (design section 5.1). `None` for a command
/// that is not a `GrantRole`.
pub fn self_grant_digest(grant: &fstp_engine::Command, command_id: [u8; 16]) -> Option<[u8; 32]> {
    let fstp_engine::Command::Core(core) = grant else {
        return None;
    };
    let bytes = grant_without_second_admin(core)?;
    let mut h = fstp_crypto::Sha256::new();
    h.update(&bytes);
    h.update(&command_id);
    Some(h.finish())
}

/// A 16-byte id that the cell derives for a record it creates, from what
/// the command names. The same command at the same instant under the same
/// id gives the same record id.
fn derive_id(
    tag: &[u8],
    command: Option<[u8; 16]>,
    actor: AccountId,
    at: i64,
    payload: &[u8],
) -> [u8; 16] {
    let mut h = fstp_crypto::Sha256::new();
    h.update(b"fstp-cell-id-v1");
    h.update(tag);
    h.update(&command.unwrap_or([0; 16]));
    h.update(&actor.raw().to_be_bytes());
    h.update(&at.to_be_bytes());
    h.update(payload);
    let d = h.finish();
    let mut out = [0u8; 16];
    out.copy_from_slice(d.get(..16).unwrap_or(&[0; 16]));
    out
}

/// The records of `batch` that an account may be shown: every record but
/// the vault outcomes. A vault outcome is an identity answer, which no
/// Judging role may see (R-NG-01, overview NOTE 7, I-18).
pub fn without_vault_outcomes(batch: &[CellRecord]) -> Vec<CellRecord> {
    batch
        .iter()
        .filter(|r| {
            !matches!(
                r,
                CellRecord::Engine(fstp_engine::Record::Core(
                    fstp_domain::Record::VaultOutcome { .. }
                ))
            )
        })
        .cloned()
        .collect()
}

// ---------------------------------------------------------------------------
// Attestations.

/// The attestations of one M2 command, with the approval it uses.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Attest {
    tenant_admin: bool,
    second: Option<AccountId>,
    binds: bool,
    approval: Option<[u8; 32]>,
}

impl Attest {
    pub(crate) fn public(&self) -> Attestation {
        Attestation {
            tenant_admin: self.tenant_admin,
            second_tenant_admin: self.second.is_some(),
            binds_tenant_admin: self.binds,
        }
    }
}

/// The account an M2 command binds: `GrantRole::account`,
/// `AddTeamMember::account` or `AddGuardian::account`, and the actor for
/// `CreateDraft` (`fstp_domain::Ctx::binds_tenant_admin`).
fn bound_account(actor: AccountId, cmd: &fstp_engine::Command) -> Option<AccountId> {
    use fstp_domain::Command as C;
    match cmd {
        fstp_engine::Command::Core(C::GrantRole { account, .. })
        | fstp_engine::Command::Core(C::AddTeamMember { account, .. })
        | fstp_engine::Command::Core(C::AddGuardian { account, .. }) => Some(*account),
        fstp_engine::Command::Core(C::CreateDraft { .. }) => Some(actor),
        _ => None,
    }
}

/// The attestations of `cmd` by `actor`, with the SoD-07 approval matched
/// under `id_at`, the command id and the instant.
pub(crate) fn attestation(
    s: &CellState,
    actor: AccountId,
    cmd: &fstp_engine::Command,
    id_at: Option<([u8; 16], Timestamp)>,
) -> Attest {
    let tenant = s.tenant();
    let mut a = Attest {
        tenant_admin: tenant.is_admin(actor),
        second: None,
        binds: bound_account(actor, cmd).is_some_and(|b| tenant.is_admin(b)),
        approval: None,
    };
    if let (
        fstp_engine::Command::Core(fstp_domain::Command::GrantRole {
            account,
            second_admin: Some(named),
            ..
        }),
        Some((id, now)),
    ) = (cmd, id_at)
        && *account == actor
        && let Some(digest) = self_grant_digest(cmd, id)
        && let Some(approval) = tenant.approvals(&digest).iter().find(|a| {
            // The first approval that admits the grant, as the W1b
            // reference rule takes it. An approval that cannot admit it,
            // such as the grantor's own, never hides a later one.
            !a.used
                && a.approver == *named
                && a.approver != actor
                && tenant.is_admin(a.approver)
                && now.micros() <= a.expires_at
        })
    {
        a.second = Some(approval.approver);
        a.approval = Some(digest);
    }
    a
}

/// The `Ctx` attestations for an M2 command under the caller's command id
/// at `now`. The SoD-07 approval matches the grant's digest, which holds
/// the command id, and lapses after its `expires_at` (design section 5.1,
/// Q40).
pub fn attest_at(
    s: &CellState,
    actor: AccountId,
    cmd: &fstp_engine::Command,
    command_id: [u8; 16],
    now: Timestamp,
) -> Attestation {
    attestation(s, actor, cmd, Some((command_id, now))).public()
}

/// The M2 context of an account's command.
fn engine_ctx(actor: AccountId, now: Timestamp, command: Option<[u8; 16]>, a: &Attest) -> Ctx {
    Ctx {
        now,
        actor: Actor::Account(actor),
        command: CommandId::from_bytes(command.unwrap_or([0; 16])),
        via: Via::Web,
        tenant_admin: a.tenant_admin,
        second_tenant_admin: a.second,
        binds_tenant_admin: a.binds,
    }
}

/// The M2 context of a system task's command: `System(Timeline)`, with
/// no attestation (`fstp_domain::due`).
fn system_ctx(now: Timestamp, command: Option<[u8; 16]>) -> Ctx {
    Ctx {
        now,
        actor: Actor::System(SystemCause::Timeline),
        command: CommandId::from_bytes(command.unwrap_or([0; 16])),
        via: Via::Web,
        tenant_admin: false,
        second_tenant_admin: None,
        binds_tenant_admin: false,
    }
}

// ---------------------------------------------------------------------------
// queries and decide.

/// Refuses a command earlier than the latest recorded time of any member,
/// as M2 does (design section 2.2).
fn clock(s: &CellState, now: Timestamp) -> Result<(), CellRefusal> {
    if now < s.now_floor() {
        return Err(refuse(RuleRef::Ledger, RefusalReason::ClockBackwards));
    }
    Ok(())
}

/// Whether `c` comes from a system task only, so an account never decides
/// it ([`SystemTask`], design sections 3.5 and 5.1).
fn system_only(c: &CellCommand) -> bool {
    matches!(
        c,
        CellCommand::Key(_)
            | CellCommand::Release(ReleaseCommand::RecordRelationship { .. })
            | CellCommand::Timeline(_)
            | CellCommand::Ops(
                OpsCommand::ApplyOperatorTicket { .. } | OpsCommand::EndSessionsAtBindingEnd { .. }
            )
            | CellCommand::Tenant(TenantCommand::IssueFirstAdminInvitation { .. })
    )
}

/// Refuses an account's cell command while a scheduled binding end is
/// overdue, as M2 `shared_checks` refuses its own commands (SoD-05, the
/// Cooling-off NOTE). No decision then reads a binding as held after its
/// end instant. The auth commands are left open. Credentials and step-ups
/// read no binding, and the gate ends the sessions the end would have
/// ended (design section 5.4 step 2). A recovery approval reads the
/// holdings at its instant, which count a binding only until its
/// scheduled end (design section 8.2).
///
/// Reading: `EndBreakGlass` and `EndTenantAdmin` are left open too. They
/// read no binding and only reduce access, so refusing them would only
/// delay a safety action until the timeline records the end.
fn overdue(s: &CellState, c: &CellCommand, now: Timestamp) -> Result<(), CellRefusal> {
    if matches!(
        c,
        // M2 checks its own commands.
        CellCommand::Engine(_)
            | CellCommand::Auth(_)
            | CellCommand::Ops(OpsCommand::EndBreakGlass { .. })
            | CellCommand::Tenant(
                TenantCommand::EndTenantAdmin { .. } | TenantCommand::EnrolByInvitation { .. }
            )
    ) {
        return Ok(());
    }
    let due = fstp_domain::due(&s.engine().core, now);
    if due
        .iter()
        .any(|d| matches!(d, fstp_domain::Command::EndScheduledRole { .. }))
    {
        return Err(refuse(RuleRef::Sod05, RefusalReason::WrongState));
    }
    Ok(())
}

/// The M2 command of a system task, which must be one that
/// `fstp_domain::due` lists at `now`. The timeline issues those and no
/// other, so a task never runs `VaultChanged` or an account's command.
fn due_engine_command<'a>(
    s: &CellState,
    task: SystemTask,
    cmd: &'a fstp_engine::Command,
    now: Timestamp,
) -> Result<&'a fstp_engine::Command, CellRefusal> {
    match (task, cmd) {
        (SystemTask::Timeline, fstp_engine::Command::Core(core))
            if fstp_domain::due(&s.engine().core, now).contains(core) =>
        {
            Ok(cmd)
        }
        _ => Err(wrong_actor()),
    }
}

pub(crate) fn queries_with(
    s: &CellState,
    c: &CellCommand,
    who: Who,
    at: i64,
    command: Option<[u8; 16]>,
) -> Result<Vec<Query>, CellRefusal> {
    let now = Timestamp::from_micros(at);
    clock(s, now)?;
    let actor = match who {
        Who::Account(actor) => actor,
        Who::System(task) => {
            return match c {
                CellCommand::Engine(cmd) => {
                    let cmd = due_engine_command(s, task, cmd, now)?;
                    fstp_engine::DomainDecider
                        .queries(s.engine(), cmd, &system_ctx(now, command))
                        .map_err(CellRefusal::Domain)
                }
                CellCommand::Timeline(TimelineCommand::Fire {
                    then: Some(core), ..
                }) => {
                    let wrapped = fstp_engine::Command::Core((**core).clone());
                    let cmd = due_engine_command(s, task, &wrapped, now)?;
                    fstp_engine::DomainDecider
                        .queries(s.engine(), cmd, &system_ctx(now, command))
                        .map_err(CellRefusal::Domain)
                }
                _ => Ok(Vec::new()),
            };
        }
    };
    if system_only(c) {
        return Err(wrong_actor());
    }
    overdue(s, c, now)?;
    match c {
        CellCommand::Engine(cmd) => {
            let a = attestation(s, actor, cmd, command.map(|id| (id, now)));
            let ctx = engine_ctx(actor, now, command, &a);
            fstp_engine::DomainDecider
                .queries(s.engine(), cmd, &ctx)
                .map_err(CellRefusal::Domain)
        }
        CellCommand::Release(ReleaseCommand::IssueWriteTicket {
            kind: WRITE_KIND_GUARDIAN_CONSENT,
        }) => guardian_plan(s, actor, now).map(|p| p.queries()),
        CellCommand::Auth(fstp_auth::AuthCommand::ApproveRecovery { case }) => {
            approval_plan(s, *case, actor, now).map(|p| p.queries())
        }
        _ => Ok(Vec::new()),
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the command, who issues it, its instant and id, its step-up instant, its route inputs and its answers"
)]
pub(crate) fn decide_with(
    s: &CellState,
    c: &CellCommand,
    who: Who,
    at: i64,
    command: Option<[u8; 16]>,
    stepup_at: Option<Timestamp>,
    inputs: &RouteInputs,
    answers: &Answers,
) -> Result<Vec<CellRecord>, CellRefusal> {
    let mut batch = decide_unchecked(s, c, who, at, command, stepup_at, inputs, answers)?;
    if let Some(rows) = inputs.sessions() {
        let reactions = session_reactions(s, &batch, rows, Timestamp::from_micros(at));
        batch.extend(reactions);
    }
    storable(&batch)?;
    Ok(batch)
}

/// The `SessionEnded` reactions of `batch` over the live session rows
/// `rows` (design section 5.1 "Reactions", Q16 A, interim, pending
/// Daniel):
///
/// - A grant of a Drafting, Judging, Operations or tenant admin role ends
///   that account's weak sessions (`fstp_auth::session::ended_by_grant`).
/// - An ended, suspended or voided binding of those groups, and an ended
///   tenant admin grant, end every session of the account that started at
///   or before the instant (`fstp_auth::session::ended_by_binding_end`).
///   A recorded end takes the instant it names, and a suspension or a
///   voiding the batch instant.
///
/// A session the batch ends already, or the ledger ended, is never named
/// again. The gate refuses these sessions whether or not the reaction is
/// recorded (design section 5.4 step 2), so the guarantee never rests on
/// the rows. The record makes the end visible and writes its
/// `auth_log.session_end` row.
fn session_reactions(
    s: &CellState,
    batch: &[CellRecord],
    rows: &SessionRows,
    now: Timestamp,
) -> Vec<CellRecord> {
    use fstp_auth::session::{ended_by_binding_end, ended_by_grant};
    use fstp_domain::Record as R;
    let management = |b: BindingId| {
        s.engine()
            .core
            .roster()
            .binding(b)
            .filter(|b| b.group() != Group::Receiving)
            .map(|b| b.account)
    };
    let mut ended: Vec<[u8; 16]> = Vec::new();
    for r in batch {
        match r {
            CellRecord::Engine(fstp_engine::Record::Core(R::BindingGranted(g)))
                if g.role.group() != Group::Receiving =>
            {
                ended.extend(ended_by_grant(&rows.of(s, g.account), g.account));
            }
            CellRecord::Engine(fstp_engine::Record::Core(R::BindingEnded(e))) => {
                if let Some(a) = management(e.binding) {
                    ended.extend(ended_by_binding_end(&rows.of(s, a), a, e.at));
                }
            }
            CellRecord::Engine(fstp_engine::Record::Core(
                R::BindingSuspended(fstp_domain::record::BindingSuspended { binding, .. })
                | R::BindingVoided(fstp_domain::record::BindingVoided { binding, .. }),
            )) => {
                if let Some(a) = management(*binding) {
                    ended.extend(ended_by_binding_end(&rows.of(s, a), a, now));
                }
            }
            CellRecord::Tenant(TenantRecord::TenantAdminGranted { account }) => {
                ended.extend(ended_by_grant(&rows.of(s, *account), *account));
            }
            CellRecord::Tenant(TenantRecord::TenantAdminEnded { account }) => {
                ended.extend(ended_by_binding_end(&rows.of(s, *account), *account, now));
            }
            _ => {}
        }
    }
    let mut seen: BTreeSet<[u8; 16]> = batch
        .iter()
        .filter_map(|r| match r {
            CellRecord::Auth(fstp_auth::AuthRecord::SessionEnded { session }) => Some(*session),
            _ => None,
        })
        .collect();
    ended
        .into_iter()
        .filter(|id| seen.insert(*id))
        .map(|session| CellRecord::Auth(fstp_auth::AuthRecord::SessionEnded { session }))
        .collect()
}

/// Refuses a batch that holds a record the store cannot read back: one
/// whose stored bytes do not decode to it, for example a list beyond a
/// codec bound. `PgRecordStore` keeps canonical text and decodes it on
/// read (design section 5.3), so such a record would stop the replay of
/// the ledger (I-23). The refusal comes before any append.
fn storable(batch: &[CellRecord]) -> Result<(), CellRefusal> {
    for r in batch {
        match decode_cell_record(&encode_cell_record(r)) {
            Ok(back) if back == *r => {}
            _ => return Err(invalid()),
        }
    }
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "the command, who issues it, its instant and id, its step-up instant, its route inputs and its answers"
)]
fn decide_unchecked(
    s: &CellState,
    c: &CellCommand,
    who: Who,
    at: i64,
    command: Option<[u8; 16]>,
    stepup_at: Option<Timestamp>,
    inputs: &RouteInputs,
    answers: &Answers,
) -> Result<Vec<CellRecord>, CellRefusal> {
    let now = Timestamp::from_micros(at);
    clock(s, now)?;
    let actor = match who {
        Who::Account(actor) => actor,
        Who::System(task) => return decide_system(s, c, task, now, command, inputs, answers),
    };
    if system_only(c) {
        return Err(wrong_actor());
    }
    overdue(s, c, now)?;
    match c {
        CellCommand::Engine(cmd) => decide_engine(s, cmd, actor, now, command, answers),
        CellCommand::Auth(cmd) => {
            let call = AuthCall {
                actor,
                now,
                command,
                stepup_at,
                inputs,
            };
            decide_auth(s, cmd, &call, answers)
        }
        CellCommand::Tenant(TenantCommand::EnrolByInvitation {
            invitation,
            credential,
        }) => decide_enrolment(s, *invitation, credential, actor, now, inputs),
        CellCommand::Tenant(cmd) => decide_tenant(s, cmd, actor, now, stepup_at),
        CellCommand::Text(cmd) => decide_text(s, cmd, actor),
        CellCommand::Release(cmd) => decide_release(s, cmd, actor, now, command, answers),
        CellCommand::Ops(cmd) => decide_ops(s, cmd, actor),
        // `system_only` refused these above.
        CellCommand::Key(_) | CellCommand::Timeline(_) => Err(wrong_actor()),
    }
}

/// Decides a system task's command: each task its own commands, every
/// other `WrongActor` ([`SystemTask`]).
fn decide_system(
    s: &CellState,
    c: &CellCommand,
    task: SystemTask,
    now: Timestamp,
    command: Option<[u8; 16]>,
    inputs: &RouteInputs,
    answers: &Answers,
) -> Result<Vec<CellRecord>, CellRefusal> {
    match (task, c) {
        (_, CellCommand::Engine(cmd)) => {
            let cmd = due_engine_command(s, task, cmd, now)?;
            let records = fstp_engine::DomainDecider
                .decide(s.engine(), cmd, &system_ctx(now, command), answers)
                .map_err(CellRefusal::Domain)?;
            Ok(records.into_iter().map(CellRecord::Engine).collect())
        }
        (SystemTask::ErasureRunner, CellCommand::Key(cmd)) => decide_key(s, cmd),
        (
            SystemTask::Provisioning,
            CellCommand::Tenant(TenantCommand::IssueFirstAdminInvitation {
                invitation,
                account,
                token_digest,
            }),
        ) => issue_first_admin_invitation(s, *invitation, *account, *token_digest, now, inputs),
        (
            SystemTask::Timeline,
            CellCommand::Ops(OpsCommand::EndSessionsAtBindingEnd { account }),
        ) => end_sessions_at_binding_end(s, *account, now, inputs),
        (SystemTask::Timeline, CellCommand::Timeline(cmd)) => {
            decide_timeline(s, cmd, now, command, inputs, answers)
        }
        // No relationship form and no operator ticket form is defined yet,
        // so both are refused (fail closed).
        (
            _,
            CellCommand::Release(ReleaseCommand::RecordRelationship { .. })
            | CellCommand::Ops(OpsCommand::ApplyOperatorTicket { .. }),
        ) => Err(invalid()),
        _ => Err(wrong_actor()),
    }
}

/// Decides a timeline command (M6 design section 4).
///
/// - `Plan` carries `EventScheduled` and `EventCancelled` records only,
///   at most [`crate::timeline::MAX_MESSAGES`], and no bodies.
/// - `Fire` names a scheduled event that is due at `now`. Its templates
///   are `TemplateVersionRecorded` records, and the task's bodies name
///   exactly its messages, in order. Its System command, if any, must be
///   due, and its records join the same batch as `EventFired`, so the
///   command and the messages commit together or not at all.
///
/// The fold checks the rest: a second firing, a cancelled event, an
/// unrecorded template version and a repeated key are all refused.
fn decide_timeline(
    s: &CellState,
    cmd: &TimelineCommand,
    now: Timestamp,
    command: Option<[u8; 16]>,
    inputs: &RouteInputs,
    answers: &Answers,
) -> Result<Vec<CellRecord>, CellRefusal> {
    let bodies = inputs.outbox().unwrap_or(&[]);
    match cmd {
        TimelineCommand::Plan { records } => {
            let only_plan = records.iter().all(|r| {
                matches!(
                    r,
                    TimelineRecord::EventScheduled { .. } | TimelineRecord::EventCancelled { .. }
                )
            });
            if records.is_empty()
                || records.len() > crate::timeline::MAX_MESSAGES
                || !only_plan
                || !bodies.is_empty()
            {
                return Err(invalid());
            }
            Ok(records.iter().cloned().map(CellRecord::Timeline).collect())
        }
        TimelineCommand::Fire {
            event,
            templates,
            messages,
            then,
        } => {
            let e = s.timeline().event(event).ok_or_else(unknown)?;
            if e.status != EventStatus::Scheduled || e.due > now.micros() {
                return Err(refuse(RuleRef::Ledger, RefusalReason::WrongState));
            }
            let only_templates = templates
                .iter()
                .all(|r| matches!(r, TimelineRecord::TemplateVersionRecorded { .. }));
            let same = bodies.len() == messages.len()
                && bodies
                    .iter()
                    .zip(messages)
                    .all(|(b, m)| b.outbox == m.outbox);
            if !only_templates || !same {
                return Err(invalid());
            }
            let mut batch: Vec<CellRecord> = templates
                .iter()
                .cloned()
                .map(CellRecord::Timeline)
                .collect();
            if let Some(core) = then {
                let wrapped = fstp_engine::Command::Core((**core).clone());
                let cmd = due_engine_command(s, SystemTask::Timeline, &wrapped, now)?;
                let records = fstp_engine::DomainDecider
                    .decide(s.engine(), cmd, &system_ctx(now, command), answers)
                    .map_err(CellRefusal::Domain)?;
                batch.extend(records.into_iter().map(CellRecord::Engine));
            }
            batch.push(CellRecord::Timeline(TimelineRecord::EventFired {
                event: *event,
                messages: messages.clone(),
            }));
            Ok(batch)
        }
    }
}

fn decide_engine(
    s: &CellState,
    cmd: &fstp_engine::Command,
    actor: AccountId,
    now: Timestamp,
    command: Option<[u8; 16]>,
    answers: &Answers,
) -> Result<Vec<CellRecord>, CellRefusal> {
    let a = attestation(s, actor, cmd, command.map(|id| (id, now)));
    let ctx = engine_ctx(actor, now, command, &a);
    let records = fstp_engine::DomainDecider
        .decide(s.engine(), cmd, &ctx, answers)
        .map_err(CellRefusal::Domain)?;
    let mut out: Vec<CellRecord> = records.into_iter().map(CellRecord::Engine).collect();
    if let Some(grant_digest) = a.approval {
        // One approval admits one grant (TH-05).
        out.push(CellRecord::Tenant(TenantRecord::SelfGrantApprovalUsed {
            grant_digest,
        }));
    }
    Ok(out)
}

/// An input that a command's batch needs beyond the ledger and the vault
/// answers, which only its route or task holds. [`RouteInputs`] carries
/// them into `decide`, and the gate's route admissions set them
/// (`crate::gate::admit_add_passkey` and the functions beside it).
///
/// An auth command whose batch needs one that it was not given is refused
/// with the closed domain refusal [`ROUTE_INPUT_MISSING`]: rule `Input`,
/// reason `AnswerMissing`. No other path pairs those two, so a caller
/// tells it apart from a vault that did not answer (`FactsIncomplete`).
/// It is not the stub refusal `NotImplemented`, which I-23 forbids from
/// `decide`. [`route_inputs`] lists what each auth command needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RouteInput {
    /// The new passkey that the gate verified through
    /// `fstp_auth::ceremony::verify_new_passkey` (design section 8.3).
    VerifiedCredential,
    /// The live session rows of the account, an operational table
    /// (design section 4.2). A batch that ends sessions names them.
    SessionRows,
    /// Whether the cell is SaaS or self-hosted, which picks the recovery
    /// path of a sole tenant admin (design section 8.5).
    DeploymentMode,
}

impl RouteInput {
    /// The lane that owns the routes holding these inputs.
    pub const OWNER: &'static str = "W3a";
}

/// The route inputs the batch of `c` needs beyond the ledger and the
/// vault answers. Empty for a command that `decide` decides alone.
pub fn route_inputs(c: &fstp_auth::AuthCommand) -> &'static [RouteInput] {
    use fstp_auth::AuthCommand as C;
    match c {
        C::RegisterCredential { .. } => &[RouteInput::VerifiedCredential],
        C::RevokeCredential { .. } | C::EndSession { .. } => &[RouteInput::SessionRows],
        C::RequestRecovery { .. } => &[RouteInput::DeploymentMode],
        C::CompleteRecovery { .. } => &[
            RouteInput::VerifiedCredential,
            RouteInput::SessionRows,
            RouteInput::DeploymentMode,
        ],
        C::GrantStepUp { .. } | C::ProveRecoveryEmail { .. } | C::ApproveRecovery { .. } => &[],
    }
}

/// The refusal of an auth command whose batch needs a [`RouteInput`] it
/// was not given.
///
/// `fstp_domain::refusal` is closed and holds no reason for a route
/// input. So this pairs rule `Input` with reason `AnswerMissing`, which
/// no other path of the cell or of M2 returns. A reason of its own needs
/// a change to `fstp-domain`, which is the lead's.
pub const ROUTE_INPUT_MISSING: Refusal = Refusal::new(RuleRef::Input, RefusalReason::AnswerMissing);

/// The refusal of a command whose batch needs `input` ([`RouteInput`]).
/// The input itself is in [`route_inputs`] for the command, and its
/// owner is [`RouteInput::OWNER`].
fn needs(input: RouteInput) -> CellRefusal {
    let _ = input;
    CellRefusal::Domain(ROUTE_INPUT_MISSING)
}

/// What an auth command is decided under.
struct AuthCall<'a> {
    actor: AccountId,
    now: Timestamp,
    command: Option<[u8; 16]>,
    stepup_at: Option<Timestamp>,
    inputs: &'a RouteInputs,
}

/// The step-up id of a `GrantStepUp` under `command` (design section 8.4).
///
/// The route issues `GrantStepUp` under the step-up challenge id as its
/// command id (`POST /auth/stepup`). So the step-up id is that challenge
/// id, and it keys `StepUpGranted`, `StepUpConsumed` and the
/// `auth_log.stepup_consumed.challenge_id` row alike, end to end. It is
/// also the id `fstp_auth::stepup::verify_step_up` names. A decision
/// without a command id appends nothing (the driver refuses it with
/// `NoCommandId`), so its id is derived from the payload instead.
pub fn stepup_id(
    command: Option<[u8; 16]>,
    actor: AccountId,
    at: i64,
    session: [u8; 16],
    action_digest: [u8; 32],
) -> [u8; 16] {
    match command {
        Some(id) => id,
        None => {
            let mut payload = Vec::with_capacity(48);
            payload.extend_from_slice(&session);
            payload.extend_from_slice(&action_digest);
            derive_id(b"stepup", None, actor, at, &payload)
        }
    }
}

/// Decides an auth command (design section 8).
///
/// Each command first passes the checks `decide` can make from the
/// ledger. A command whose batch needs a route input it was not given is
/// then refused ([`RouteInput`], [`route_inputs`]):
/// - `RegisterCredential` needs the credential that the gate verified
///   ([`crate::gate::admit_add_passkey`]). It adds a further passkey to an
///   account that holds one (`AddPasskey`, design section 8.3).
/// - `RevokeCredential` and `EndSession` need the live session rows.
///   Revoking a device ends the sessions it logged in, and only a
///   session's own account ends it (`fstp_auth::session`, R-LG-04).
/// - `RequestRecovery` needs the cell's deployment mode for the path
///   (`fstp_auth::recovery::request`).
/// - `CompleteRecovery` needs the verified new passkey, the session rows
///   it ends and the deployment mode (`fstp_auth::recovery::complete`).
///   No gate admission sets them yet (`crate::gate::ROUTE_ADMISSION_SEAM`).
///
/// `GrantStepUp`, `ProveRecoveryEmail` and `ApproveRecovery` need no
/// route input. No gate admission admits the first two yet
/// (`crate::gate::ROUTE_ADMISSION_SEAM`), so they run only from tests.
fn decide_auth(
    s: &CellState,
    cmd: &fstp_auth::AuthCommand,
    call: &AuthCall<'_>,
    answers: &Answers,
) -> Result<Vec<CellRecord>, CellRefusal> {
    use fstp_auth::{AuthCommand as C, AuthRecord as R};
    let auth = s.auth();
    let actor = call.actor;
    let now = call.now;
    match cmd {
        C::RegisterCredential {
            account,
            credential,
        } => {
            if *account != actor {
                return Err(wrong_actor());
            }
            if credential.is_empty() || credential.len() > MAX_CREDENTIAL {
                return Err(invalid());
            }
            if auth.is_registered(credential) {
                return Err(reused());
            }
            let Some(cred) = call.inputs.credential() else {
                return Err(needs(RouteInput::VerifiedCredential));
            };
            if cred.id != *credential {
                return Err(invalid());
            }
            // A first passkey comes only from a ceremony (design section
            // 8.3), which has no command form yet. So this is `AddPasskey`:
            // the account holds a live passkey already.
            if !auth.has_any_credential(*account) {
                return Err(refuse(RuleRef::Input, RefusalReason::WrongState));
            }
            // ADR-008 "User verification": a holder's passkey gives UV. The
            // gate verified it so, and the batch checks it again.
            if holds_management_at(s, *account, now) && !cred.user_verified {
                return Err(invalid());
            }
            Ok(vec![CellRecord::Auth(R::registration(*account, cred))])
        }
        C::RevokeCredential {
            account,
            credential,
        } => {
            // Only the credential's own account revokes it, and only a live
            // credential (R-LG-04).
            if *account != actor {
                return Err(wrong_actor());
            }
            let live: Vec<fstp_auth::session::CredentialOwner> = auth
                .live_credentials(*account)
                .into_iter()
                .map(|c| fstp_auth::session::CredentialOwner {
                    account: *account,
                    credential: c,
                })
                .collect();
            if !fstp_auth::session::may_revoke_credential(&live, actor, *account, credential) {
                return Err(unknown());
            }
            let Some(rows) = call.inputs.sessions() else {
                return Err(needs(RouteInput::SessionRows));
            };
            let ended = fstp_auth::session::ended_by_credential_revocation(
                &rows.of(s, *account),
                rows.logins(),
                *account,
                credential,
            );
            let mut out = vec![CellRecord::Auth(R::CredentialRevoked {
                account: *account,
                credential: credential.clone(),
            })];
            out.extend(session_ends(&ended));
            Ok(out)
        }
        C::GrantStepUp {
            session,
            action_digest,
        } => {
            let id = stepup_id(call.command, actor, now.micros(), *session, *action_digest);
            if auth.stepup(id).is_some() {
                return Err(reused());
            }
            Ok(vec![CellRecord::Auth(R::StepUpGranted {
                id,
                action_digest: *action_digest,
                session: *session,
            })])
        }
        C::EndSession { session } => {
            if auth.session_ended(*session) {
                return Err(unknown());
            }
            let Some(rows) = call.inputs.sessions() else {
                return Err(needs(RouteInput::SessionRows));
            };
            // Only the session's own account ends it, and only a live one.
            // Another account's session reads as unknown, so the refusal
            // tells nothing of it (R-LG-04).
            if !fstp_auth::session::may_end_session(&rows.of(s, actor), actor, *session) {
                return Err(unknown());
            }
            Ok(session_ends(&[*session]))
        }
        C::RequestRecovery { case, account } => {
            if auth.recovery(*case).is_some() {
                return Err(reused());
            }
            let Some(mode) = call.inputs.mode() else {
                return Err(needs(RouteInput::DeploymentMode));
            };
            let roster = fstp_auth::RosterView::from_roster(s.engine().core.roster(), now);
            Ok(vec![CellRecord::Auth(fstp_auth::recovery::request(
                *case,
                *account,
                &roster,
                &tenant_view(s),
                mode,
            ))])
        }
        C::ProveRecoveryEmail { case } => {
            let c = open_case(s, *case)?;
            // The email proof is the holder's own.
            if c.account != actor {
                return Err(wrong_actor());
            }
            if c.email_proven {
                return Err(reused());
            }
            Ok(vec![CellRecord::Auth(R::RecoveryEmailProven {
                case: *case,
            })])
        }
        C::ApproveRecovery { case } => {
            let plan = approval_plan(s, *case, actor, now)?;
            let verified = |q: &Query| answers.get(q).map(|a| a.holds);
            let identity = match (
                verified(&plan.approver_verified()),
                verified(&plan.holder_verified()),
                verified(&plan.same_identity()),
            ) {
                (Some(a), Some(h), Some(same)) => Ok(fstp_auth::recovery::IdentityFacts {
                    both_verified: a && h,
                    same_identity: same,
                }),
                // A missing answer is a vault that did not answer (fail
                // closed, design section 8.5).
                _ => Err(fstp_auth::recovery::VaultDown),
            };
            // The approval is the high-risk action `ApproveRecovery`. The
            // gate checked its step-up, and the driver passes the step-up's
            // assertion instant. Without one the approval is refused.
            let stepup = match call.stepup_at {
                Some(_) => Ok(()),
                None => Err(fstp_auth::stepup::StepUpDeny::Required),
            };
            let tenant = tenant_view(s);
            let approval = fstp_auth::recovery::Approval::new(actor, &tenant, stepup, identity);
            fstp_auth::recovery::approve(plan.holder, &approval).map_err(approval_refusal)?;
            Ok(vec![CellRecord::Auth(R::RecoveryApproved {
                case: *case,
                approver: actor,
            })])
        }
        C::CompleteRecovery { case, credential } => {
            let c = open_case(s, *case)?;
            // The ceremony completes the holder's own case.
            if c.account != actor {
                return Err(wrong_actor());
            }
            if auth.is_registered(credential) {
                return Err(reused());
            }
            let Some(cred) = call.inputs.credential() else {
                return Err(needs(RouteInput::VerifiedCredential));
            };
            if cred.id != *credential {
                return Err(invalid());
            }
            let Some(rows) = call.inputs.sessions() else {
                return Err(needs(RouteInput::SessionRows));
            };
            let Some(mode) = call.inputs.mode() else {
                return Err(needs(RouteInput::DeploymentMode));
            };
            let case_view = recovery_case(s, *case, call.inputs.ticket().copied())?;
            let roster = fstp_auth::RosterView::from_roster(s.engine().core.roster(), now);
            let tenant = tenant_view(s);
            let credentials = auth.live_credentials(c.account);
            let sessions: Vec<[u8; 16]> = rows.of(s, c.account).iter().map(|r| r.id).collect();
            let revocation = fstp_auth::recovery::Revocation {
                credentials: &credentials,
                sessions: &sessions,
                new_credential: cred,
            };
            let records =
                fstp_auth::recovery::complete(&case_view, &roster, &tenant, mode, &revocation)
                    .map_err(recovery_refusal)?;
            Ok(records.into_iter().map(CellRecord::Auth).collect())
        }
    }
}

/// One `SessionEnded` record per session id, in order.
fn session_ends(sessions: &[[u8; 16]]) -> Vec<CellRecord> {
    fstp_auth::session::session_end_records(sessions)
        .into_iter()
        .map(CellRecord::Auth)
        .collect()
}

/// Whether `a` holds a management role at `now`: a Drafting, Judging or
/// Operations binding by the gate's holdings rule, or tenant admin
/// (design section 8.2).
fn holds_management_at(s: &CellState, a: AccountId, now: Timestamp) -> bool {
    s.tenant().is_admin(a) || crate::gate::management_holders(s, now).contains(&a)
}

/// Case `case` as `fstp_auth::recovery` reads it, with the evidence its
/// records state and the operator ticket `ticket` (I-79, design section
/// 8.5).
///
/// Reading, for Daniel's review: a recorded `RecoveryApproved` passed the
/// step-up and the identity check when it was decided, so the evidence
/// carries it as a passed approval. The completion checks again that its
/// approver is still a tenant admin. No record holds a host console
/// command, so the `HostConsole` path never completes here (fail closed).
pub(crate) fn recovery_case(
    s: &CellState,
    case: [u8; 16],
    ticket: Option<fstp_auth::recovery::VerifiedTicket>,
) -> Result<fstp_auth::recovery::Case, CellRefusal> {
    let c = open_case(s, case)?;
    let tenant = tenant_view(s);
    let approval = c.approver.map(|a| {
        fstp_auth::recovery::Approval::new(
            a,
            &tenant,
            Ok(()),
            Ok(fstp_auth::recovery::IdentityFacts {
                both_verified: false,
                same_identity: false,
            }),
        )
    });
    Ok(fstp_auth::recovery::Case {
        case,
        holder: c.account,
        requested: c.requested,
        evidence: fstp_auth::recovery::Evidence {
            email: c.email_proven,
            approval,
            ticket,
            host_console: false,
        },
    })
}

/// The cell refusal of a refused recovery completion.
fn recovery_refusal(d: fstp_auth::recovery::RecoveryDeny) -> CellRefusal {
    use fstp_auth::recovery::RecoveryDeny as D;
    match d {
        D::PathNotSatisfied(_) => refuse(RuleRef::Input, RefusalReason::WrongState),
        D::NoUserVerification(_) | D::Passkey(_) => invalid(),
    }
}

/// The open recovery case `case`: requested and not completed.
fn open_case(s: &CellState, case: [u8; 16]) -> Result<crate::state::RecoveryCase, CellRefusal> {
    let c = s.auth().recovery(case).ok_or_else(unknown)?;
    if c.completed.is_some() {
        return Err(refuse(RuleRef::Input, RefusalReason::WrongState));
    }
    Ok(c)
}

/// The tenant admins of the tenant fold, as `fstp-auth` reads them.
fn tenant_view(s: &CellState) -> fstp_auth::TenantView {
    fstp_auth::TenantView {
        admins: s.tenant().admins(),
    }
}

/// What a recovery approval asks the vault about.
struct ApprovalPlan {
    approver: AccountId,
    holder: AccountId,
}

impl ApprovalPlan {
    fn approver_verified(&self) -> Query {
        Query::IsVerified {
            account: self.approver,
        }
    }

    fn holder_verified(&self) -> Query {
        Query::IsVerified {
            account: self.holder,
        }
    }

    fn same_identity(&self) -> Query {
        Query::SameIdentityAsAny {
            subject: self.approver,
            others: BTreeSet::from([self.holder]),
        }
    }

    fn queries(&self) -> Vec<Query> {
        vec![
            self.approver_verified(),
            self.holder_verified(),
            self.same_identity(),
        ]
    }
}

/// The approval of case `case` by `approver` at `now`, before the vault
/// is asked (I-79, design section 8.5). The case is open, its email proof
/// was given and no approval was recorded. The path recomputed from the
/// holdings at `now` must be `SecondAdmin`: no other path takes an
/// approval. That path does not depend on the deployment mode.
fn approval_plan(
    s: &CellState,
    case: [u8; 16],
    approver: AccountId,
    now: Timestamp,
) -> Result<ApprovalPlan, CellRefusal> {
    let c = open_case(s, case)?;
    if !c.email_proven {
        return Err(refuse(RuleRef::Input, RefusalReason::WrongState));
    }
    if c.approver.is_some() {
        return Err(reused());
    }
    let roster = fstp_auth::RosterView::from_roster(s.engine().core.roster(), now);
    let tenant = tenant_view(s);
    let holdings = fstp_auth::recovery::Holdings::of(&roster, &tenant, c.account);
    let path = fstp_auth::recovery::path_of(
        holdings,
        tenant.others(c.account),
        fstp_auth::recovery::Deployment::Saas,
    );
    if path != fstp_auth::RecoveryPath::SecondAdmin {
        return Err(refuse(RuleRef::Input, RefusalReason::WrongState));
    }
    Ok(ApprovalPlan {
        approver,
        holder: c.account,
    })
}

/// The cell refusal of a refused recovery approval.
fn approval_refusal(d: fstp_auth::recovery::ApprovalDeny) -> CellRefusal {
    use fstp_auth::recovery::ApprovalDeny as D;
    match d {
        D::SelfApproval | D::NotAdmin => wrong_actor(),
        D::StepUp(_) => refuse(RuleRef::I78, RefusalReason::GuardFailed),
        D::SameIdentity => refuse(RuleRef::Actor, RefusalReason::GuardFailed),
        D::VaultDown => answer_missing(),
    }
}

fn decide_tenant(
    s: &CellState,
    cmd: &TenantCommand,
    actor: AccountId,
    now: Timestamp,
    stepup_at: Option<Timestamp>,
) -> Result<Vec<CellRecord>, CellRefusal> {
    let tenant = s.tenant();
    match cmd {
        TenantCommand::GrantTenantAdmin { account } => {
            // Interim bootstrap: only a cell that never had a tenant admin
            // (design section 8.3, Q14). Ending the last admin never
            // reopens it.
            let first = !tenant.ever_had_admin() && *account == actor;
            if !first && !tenant.is_admin(actor) {
                return Err(wrong_actor());
            }
            if tenant.is_admin(*account) {
                return Err(reused());
            }
            Ok(vec![CellRecord::Tenant(TenantRecord::TenantAdminGranted {
                account: *account,
            })])
        }
        TenantCommand::EndTenantAdmin { account } => {
            if !tenant.is_admin(actor) {
                return Err(wrong_actor());
            }
            if !tenant.is_admin(*account) {
                return Err(unknown());
            }
            Ok(vec![CellRecord::Tenant(TenantRecord::TenantAdminEnded {
                account: *account,
            })])
        }
        TenantCommand::ApproveSelfGrant { grant_digest } => {
            if !tenant.is_admin(actor) {
                return Err(wrong_actor());
            }
            // SoD-07, Q40: only a used digest refuses a new approval. An
            // earlier approval of the same digest, by the grantor or by an
            // admin whose approval expired, must not stop a second admin
            // from approving it (sod_07_self_grant_matches_the_reference_rule).
            if tenant.digest_used(grant_digest) {
                return Err(reused());
            }
            // Interim: P-71 from the approval's step-up (Q40, ADR-008). The
            // driver passes the step-up's assertion instant. Without one, the
            // command instant stands in, and a step-up is never later.
            let from = stepup_at.map_or(now, |t| t.min(now));
            let expires_at = from
                .micros()
                .checked_add(tenant.policy().p71_us())
                .filter(|e| *e <= fstp_ledger::MAX_AT)
                .ok_or_else(invalid)?;
            Ok(vec![CellRecord::Tenant(TenantRecord::SelfGrantApproved {
                approver: actor,
                grant_digest: *grant_digest,
                expires_at,
            })])
        }
        TenantCommand::SetLoginPolicy { policy } => {
            if !tenant.is_admin(actor) {
                return Err(wrong_actor());
            }
            TenantLoginPolicy::decode(policy).map_err(|_| invalid())?;
            Ok(vec![CellRecord::Tenant(TenantRecord::LoginPolicySet {
                policy: policy.clone(),
            })])
        }
        TenantCommand::IssueInvitation {
            invitation,
            account,
            token_digest,
        } => issue_invitation(s, *invitation, *account, *token_digest, actor, stepup_at),
        // Provisioning issues the first one as a system task, and only a
        // ceremony admission enrols. Neither reaches this point.
        TenantCommand::IssueFirstAdminInvitation { .. }
        | TenantCommand::EnrolByInvitation { .. } => Err(wrong_actor()),
    }
}

/// Whether any record of the cell names `account`: a tenant admin grant,
/// a binding or an auth record. An invitation creates its account, so it
/// names an account no record names yet (ADR-008 "Ceremonies and the
/// first passkey"). Invitations that no enrolment used do not count
/// (`fstp_cell_core::state::AuthState::names_account`).
fn account_known(s: &CellState, account: AccountId) -> bool {
    s.tenant().is_admin(account)
        || s.auth().names_account(account)
        || s.engine()
            .core
            .roster()
            .bindings()
            .any(|(_, b)| b.account == account)
}

/// `IssueFirstAdminInvitation` of the system task `Provisioning` (design
/// sections 8.3 and 9.2 step 10, Q35). The rule is
/// `fstp_auth::ceremony::issue_invitation` with the provisioning issuer:
/// no first admin enrolled, no first-admin invitation open at `now`, and an
/// account no record names. The invitation id must be new. The cell's
/// deployment mode is a task input: a SaaS cell records a split token.
fn issue_first_admin_invitation(
    s: &CellState,
    invitation: [u8; 16],
    account: AccountId,
    token_digest: [u8; 32],
    now: Timestamp,
    inputs: &RouteInputs,
) -> Result<Vec<CellRecord>, CellRefusal> {
    let Some(mode) = inputs.mode() else {
        return Err(needs(RouteInput::DeploymentMode));
    };
    if s.auth().invitation(invitation).is_some() {
        return Err(reused());
    }
    let issuer = fstp_auth::ceremony::Issuer::Provisioning {
        first_admin_enrolled: s.auth().any_first_admin(),
        invitation_open: s.auth().first_admin_invitation_open(now),
    };
    let record = fstp_auth::ceremony::issue_invitation(
        issuer,
        mode,
        invitation,
        account,
        token_digest,
        !account_known(s, account),
    )
    .map_err(|e| match e {
        fstp_auth::ceremony::EnrolDeny::InviteeNotNew => reused(),
        _ => refuse(RuleRef::Input, RefusalReason::WrongState),
    })?;
    Ok(vec![CellRecord::Auth(record)])
}

/// `IssueInvitation` by a tenant admin (design section 8.3 ceremony 1,
/// `authentication.md` "First passkey"). The rule is
/// `fstp_auth::ceremony::issue_invitation` with the tenant admin issuer:
/// the actor is a current tenant admin, the batch consumes a step-up, and
/// no record names the account. The invitation id must be new.
///
/// The gate admitted the step-up (`ManagementRoleChange`), and the driver
/// passes its assertion instant as `stepup_at`. A decision without one is
/// refused here too, so no path issues an invitation without a step-up.
/// The deployment mode only splits a first admin's token, which this
/// issuer never draws, so the SaaS mode stands in for it.
fn issue_invitation(
    s: &CellState,
    invitation: [u8; 16],
    account: AccountId,
    token_digest: [u8; 32],
    actor: AccountId,
    stepup_at: Option<Timestamp>,
) -> Result<Vec<CellRecord>, CellRefusal> {
    let admin = s.tenant().is_admin(actor);
    if !admin {
        return Err(wrong_actor());
    }
    if s.auth().invitation(invitation).is_some() {
        return Err(reused());
    }
    let stepup = stepup_at
        .map(|_| ())
        .ok_or(fstp_auth::stepup::StepUpDeny::Required);
    let issuer = fstp_auth::ceremony::Issuer::TenantAdmin { admin, stepup };
    let record = fstp_auth::ceremony::issue_invitation(
        issuer,
        fstp_auth::recovery::Deployment::Saas,
        invitation,
        account,
        token_digest,
        !account_known(s, account),
    )
    .map_err(|e| match e {
        fstp_auth::ceremony::EnrolDeny::InviteeNotNew => reused(),
        _ => refuse(RuleRef::I78, RefusalReason::GuardFailed),
    })?;
    Ok(vec![CellRecord::Auth(record)])
}

/// `EnrolByInvitation`, the first passkey of an invited account (design
/// section 8.3, ceremony 1, G10, Q35).
///
/// The admission `crate::gate::admit_invitation_enrolment` matched the
/// proof to the invitation and verified the registration. The batch checks
/// again what the ledger can tell at the commit instant: the invitation
/// exists and names the actor, it is unused and at most 72 hours old, the
/// invitee holds no passkey, and the credential the gate verified is the
/// one the command names and is new to the cell. A first admin's or a
/// holder's passkey gives UV (ADR-008 "User verification").
///
/// The records are those of `fstp_auth::ceremony::invitation_records`:
/// `InvitationConsumed`, `CredentialRegistered` and, for the first admin,
/// `FirstAdminEnrolled`. The first admin's batch also grants the tenant
/// admin role, which every later tenant admin sees in the admin list.
fn decide_enrolment(
    s: &CellState,
    invitation: [u8; 16],
    credential: &[u8],
    actor: AccountId,
    now: Timestamp,
    inputs: &RouteInputs,
) -> Result<Vec<CellRecord>, CellRefusal> {
    let auth = s.auth();
    let Some(inv) = auth.invitation(invitation) else {
        return Err(unknown());
    };
    if inv.account != actor {
        return Err(wrong_actor());
    }
    if inv.consumed {
        return Err(reused());
    }
    let age = now.micros().checked_sub(inv.issued_at.micros());
    if !age.is_some_and(|a| (0..=fstp_auth::ceremony::INVITATION_US).contains(&a)) {
        return Err(refuse(RuleRef::Input, RefusalReason::WrongState));
    }
    if auth.has_any_credential(actor) {
        return Err(refuse(RuleRef::Input, RefusalReason::WrongState));
    }
    if credential.is_empty() || credential.len() > MAX_CREDENTIAL {
        return Err(invalid());
    }
    if auth.is_registered(credential) {
        return Err(reused());
    }
    let Some(cred) = inputs.credential() else {
        return Err(needs(RouteInput::VerifiedCredential));
    };
    if cred.id != credential {
        return Err(invalid());
    }
    if (inv.first_admin || holds_management_at(s, actor, now)) && !cred.user_verified {
        return Err(invalid());
    }
    let mut batch: Vec<CellRecord> =
        fstp_auth::ceremony::invitation_records(&inv.ceremony_view(invitation), cred)
            .into_iter()
            .map(CellRecord::Auth)
            .collect();
    if inv.first_admin && !s.tenant().is_admin(actor) {
        batch.push(CellRecord::Tenant(TenantRecord::TenantAdminGranted {
            account: actor,
        }));
    }
    Ok(batch)
}

fn decide_text(
    s: &CellState,
    cmd: &TextCommand,
    actor: AccountId,
) -> Result<Vec<CellRecord>, CellRefusal> {
    match cmd {
        TextCommand::PutText { id } => {
            if s.text(*id).is_some() {
                return Err(reused());
            }
            Ok(vec![CellRecord::Text(TextRecord::TextPut { id: *id })])
        }
        TextCommand::EraseTexts { ids, cause } => {
            if !s.tenant().is_admin(actor) {
                return Err(wrong_actor());
            }
            if !ERASURE_CAUSES.contains(cause) || ids.is_empty() || ids.len() > MAX_TEXT_IDS {
                return Err(invalid());
            }
            if !ACCOUNT_ERASURE_CAUSES.contains(cause) {
                // Retention expiry is the system's, with the P-41 rule as
                // its authoriser, and a completed verification is the
                // vault's (ADR-007 "Erasure-log entries").
                return Err(wrong_actor());
            }
            let mut seen = BTreeSet::new();
            for id in ids {
                if !seen.insert(*id) {
                    return Err(invalid());
                }
                if s.text(*id) != Some(TextStatus::Live) {
                    return Err(unknown());
                }
            }
            // The request is the erasure-log entry. In M3 the erasure completes
            // in the same batch. The erasure runner of design section 3.5
            // moves completion after the key destruction once it lands.
            Ok(vec![
                CellRecord::Text(TextRecord::ErasureRequested {
                    ids: ids.clone(),
                    cause: *cause,
                    by: actor,
                }),
                CellRecord::Text(TextRecord::TextsErased { ids: ids.clone() }),
            ])
        }
    }
}

/// Whether `bytes` are the RFC 8785 text of a JSON object of at most
/// [`MAX_OPAQUE`] bytes.
fn canonical_object(bytes: &[u8]) -> bool {
    bytes.len() <= MAX_OPAQUE
        && fstp_json::parse(bytes).is_ok_and(|v| {
            v.as_object().is_some()
                && fstp_json::to_canonical(&v).is_ok_and(|t| t.as_bytes() == bytes)
        })
}

fn decide_key(s: &CellState, cmd: &KeyCommand) -> Result<Vec<CellRecord>, CellRefusal> {
    match cmd {
        KeyCommand::RecordKeyOp { op } => {
            if !canonical_object(op) {
                return Err(invalid());
            }
            Ok(vec![CellRecord::Key(KeyRecord::KeyOpRecorded {
                op: op.clone(),
            })])
        }
        KeyCommand::RecordEpochDestroyed { epoch, receipt } => {
            if s.epoch_destroyed(*epoch) {
                return Err(reused());
            }
            Ok(vec![CellRecord::Key(KeyRecord::EpochDestroyed {
                epoch: *epoch,
                receipt: *receipt,
            })])
        }
    }
}

/// What a guardian consent ticket is for.
struct GuardianPlan {
    lead: AccountId,
    actor: AccountId,
    deadline: Timestamp,
    proposal: ProposalId,
}

impl GuardianPlan {
    fn adult(&self) -> Query {
        Query::IsVerifiedAdultAtDeadline {
            account: self.lead,
            deadline: self.deadline,
        }
    }

    fn same_identity(&self) -> Query {
        Query::SameIdentityAsAny {
            subject: self.actor,
            others: BTreeSet::from([self.lead]),
        }
    }

    fn queries(&self) -> Vec<Query> {
        vec![self.adult(), self.same_identity()]
    }
}

/// The proposal a guardian consent ticket for `actor` is for: the first,
/// in id order, on which `actor` holds an active Guardian binding and
/// whose consent collection is open (design section 6.6 step 3).
fn guardian_plan(
    s: &CellState,
    actor: AccountId,
    now: Timestamp,
) -> Result<GuardianPlan, CellRefusal> {
    let core = &s.engine().core;
    let proposal = core
        .roster()
        .bindings()
        .filter(|(_, b)| b.account == actor && b.role == Role::Guardian && counts_at(b, now))
        .filter_map(|(_, b)| b.proposal())
        .find(|p| fstp_domain::decision::awaiting_guardian_consent(core, *p))
        .ok_or_else(i18)?;
    let (call, lead) = s.proposal(proposal).ok_or_else(unknown)?;
    if lead == actor {
        return Err(i18());
    }
    let deadline = fstp_domain::programme::call(core, call)
        .map(|c| c.deadline())
        .ok_or_else(unknown)?;
    Ok(GuardianPlan {
        lead,
        actor,
        deadline,
        proposal,
    })
}

/// Whether binding `b` counts at `now`: active, and before its scheduled
/// end instant if it has one (design section 8.2, Cooling-off NOTE).
fn counts_at(b: &fstp_domain::roles::Binding, now: Timestamp) -> bool {
    b.active_at(now) && b.scheduled_end.is_none_or(|e| now < e)
}

fn decide_release(
    s: &CellState,
    cmd: &ReleaseCommand,
    actor: AccountId,
    now: Timestamp,
    command: Option<[u8; 16]>,
    answers: &Answers,
) -> Result<Vec<CellRecord>, CellRefusal> {
    let at = now.micros();
    match cmd {
        ReleaseCommand::IssueReleaseTicket { proposal } => {
            let p = ProposalId::from_raw(*proposal);
            let core = &s.engine().core;
            let (call, _) = s.proposal(p).ok_or_else(unknown)?;
            let programme = fstp_domain::programme::call(core, call)
                .map(|c| c.programme())
                .ok_or_else(unknown)?;
            let holder = s.tenant().is_admin(actor)
                || core.roster().bindings().any(|(_, b)| {
                    b.account == actor
                        && b.group() == Group::Operations
                        && b.programme == programme
                        && counts_at(b, now)
                });
            if !holder {
                return Err(wrong_actor());
            }
            let state = fstp_domain::view::proposal_state(core, p).ok_or_else(unknown)?;
            if !RELEASE_STATES.contains(&state) {
                return Err(refuse(RuleRef::Input, RefusalReason::WrongState));
            }
            let id = derive_id(b"release", command, actor, at, &proposal.to_be_bytes());
            if s.ticket_issued(id) {
                return Err(reused());
            }
            // The record names the proposal and the account, so the read of
            // identity attributes is logged (R-AU-01, design section 6.5).
            Ok(vec![CellRecord::Release(
                ReleaseRecord::IdentityReleaseIssued {
                    id,
                    proposal: *proposal,
                    by: actor,
                },
            )])
        }
        ReleaseCommand::IssueWriteTicket { kind } => match *kind {
            WRITE_KIND_GUARDIAN_CONSENT => {
                let plan = guardian_plan(s, actor, now)?;
                let adult = answers.get(&plan.adult()).ok_or_else(answer_missing)?;
                let same = answers
                    .get(&plan.same_identity())
                    .ok_or_else(answer_missing)?;
                if adult.holds || same.holds {
                    return Err(i18());
                }
                let mut payload = Vec::with_capacity(18);
                payload.extend_from_slice(&kind.to_be_bytes());
                payload.extend_from_slice(&plan.proposal.raw().to_be_bytes());
                let id = derive_id(b"write", command, actor, at, &payload);
                if s.ticket_issued(id) {
                    return Err(reused());
                }
                Ok(vec![CellRecord::Release(ReleaseRecord::TicketIssued {
                    id,
                    kind: *kind,
                    proposal: plan.proposal.raw(),
                    holder: actor,
                })])
            }
            // The other kinds of ADR-009 need a writer rule each, and the
            // command names no proposal or scope yet. Until then they are
            // refused (fail closed), as is any code outside the list.
            _ => Err(invalid()),
        },
        // No relationship form is defined yet, so every relationship is
        // refused (fail closed).
        ReleaseCommand::RecordRelationship { .. } => Err(invalid()),
    }
}

fn decide_ops(
    s: &CellState,
    cmd: &OpsCommand,
    actor: AccountId,
) -> Result<Vec<CellRecord>, CellRefusal> {
    use crate::ops::OpsRecord;
    match cmd {
        OpsCommand::ApproveBreakGlass { request } => {
            if !s.tenant().is_admin(actor) {
                return Err(wrong_actor());
            }
            if s.break_glass_known(*request) {
                return Err(reused());
            }
            Ok(vec![CellRecord::Ops(OpsRecord::BreakGlassApproved {
                grant: *request,
            })])
        }
        OpsCommand::EndBreakGlass { grant } => {
            if !s.tenant().is_admin(actor) {
                return Err(wrong_actor());
            }
            if !s.break_glass_active(*grant) {
                return Err(unknown());
            }
            Ok(vec![CellRecord::Ops(OpsRecord::BreakGlassEnded {
                grant: *grant,
            })])
        }
        // System paths only: `decide_with` refuses them for an account.
        OpsCommand::ApplyOperatorTicket { .. } | OpsCommand::EndSessionsAtBindingEnd { .. } => {
            Err(wrong_actor())
        }
    }
}

/// `EndSessionsAtBindingEnd` from the timeline, for an account whose
/// scheduled binding end is due (design sections 5.1 and 8.2, Q16 A).
///
/// The timeline gives the live session rows as its task input. The batch
/// ends every live session of the account that started before a due end
/// instant, which is the set the gate refuses from that instant on
/// (`CellState::binding_ended_between`). Without rows it is refused with
/// [`ROUTE_INPUT_MISSING`]. With no such session there is nothing to
/// record, so it is refused as unknown and appends nothing.
fn end_sessions_at_binding_end(
    s: &CellState,
    account: AccountId,
    now: Timestamp,
    inputs: &RouteInputs,
) -> Result<Vec<CellRecord>, CellRefusal> {
    let ends = s.due_binding_ends(account, now);
    if ends.is_empty() {
        return Err(unknown());
    }
    let Some(rows) = inputs.sessions() else {
        return Err(needs(RouteInput::SessionRows));
    };
    let ended: Vec<[u8; 16]> = rows
        .of(s, account)
        .iter()
        .filter(|r| ends.iter().any(|e| r.started < *e))
        .map(|r| r.id)
        .collect();
    if ended.is_empty() {
        return Err(unknown());
    }
    Ok(session_ends(&ended))
}

// ---------------------------------------------------------------------------
// The vault reaction (NOTE 3, NOTE 4).

/// The `VaultChanged` command of the reaction to vault epoch `epoch`, for
/// the accounts the vault reported as changed.
pub fn vault_changed(epoch: VaultEpoch, changed: BTreeSet<AccountId>) -> fstp_engine::Command {
    fstp_engine::Command::Core(fstp_domain::Command::VaultChanged { epoch, changed })
}

/// The context of a reaction: a `System(Vault)` actor at `now`, under the
/// reaction's reserved command id, as `fstp_engine::Engine` runs it.
pub(crate) fn reaction_ctx(epoch: VaultEpoch, now: Timestamp) -> Ctx {
    Ctx {
        now,
        actor: Actor::System(SystemCause::Vault),
        command: CommandId::from_bytes(crate::state::reaction_command_id(epoch.raw())),
        via: Via::Web,
        tenant_admin: false,
        second_tenant_admin: None,
        binds_tenant_admin: false,
    }
}

/// The vault queries of the reaction `cmd` at `now`. They include the
/// change query itself. The vault answers them with `reaction_for` set to
/// the reaction's epoch, so they see the provisional fact (NOTE 4).
pub fn reaction_queries(
    s: &CellState,
    cmd: &fstp_engine::Command,
    now: Timestamp,
) -> Result<Vec<Query>, CellRefusal> {
    let epoch = reaction_epoch_of(cmd)?;
    clock(s, now)?;
    fstp_engine::DomainDecider
        .queries(s.engine(), cmd, &reaction_ctx(epoch, now))
        .map_err(CellRefusal::Domain)
}

/// The records of the reaction `cmd` at `now` under `answers`, as the M2
/// engine decides `VaultChanged` with a `System(Vault)` actor. Lane W2c
/// gives this to the shells that run a reaction outside `DriverCore`.
pub fn decide_reaction(
    s: &CellState,
    cmd: &fstp_engine::Command,
    now: Timestamp,
    answers: &Answers,
) -> Result<Vec<CellRecord>, CellRefusal> {
    decide_reaction_with_inputs(s, cmd, now, &RouteInputs::none(), answers)
}

/// [`decide_reaction`] with the live session rows of `inputs`. A
/// suspension or a voiding in the reaction then ends every live session
/// of its account in the same batch (design section 5.1, "Reactions",
/// and [`session_reactions`]). Without rows the batch is the M2 engine's
/// alone, as for any other command.
pub fn decide_reaction_with_inputs(
    s: &CellState,
    cmd: &fstp_engine::Command,
    now: Timestamp,
    inputs: &RouteInputs,
    answers: &Answers,
) -> Result<Vec<CellRecord>, CellRefusal> {
    let epoch = reaction_epoch_of(cmd)?;
    clock(s, now)?;
    let records = fstp_engine::DomainDecider
        .decide(s.engine(), cmd, &reaction_ctx(epoch, now), answers)
        .map_err(CellRefusal::Domain)?;
    let mut batch: Vec<CellRecord> = records.into_iter().map(CellRecord::Engine).collect();
    if let Some(rows) = inputs.sessions() {
        let reactions = session_reactions(s, &batch, rows, now);
        batch.extend(reactions);
    }
    storable(&batch)?;
    Ok(batch)
}

/// The epoch of a `VaultChanged` command, or a refusal for any other.
fn reaction_epoch_of(cmd: &fstp_engine::Command) -> Result<VaultEpoch, CellRefusal> {
    match cmd {
        fstp_engine::Command::Core(fstp_domain::Command::VaultChanged { epoch, .. }) => Ok(*epoch),
        _ => Err(invalid()),
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]
mod route_input_tests {
    //! The batches that only a gate-verified passkey unlocks (lane int3).
    //! `RouteInputs::with_credential` is crate-private, so these run here.

    use super::*;
    use fstp_auth::{
        AuthCommand as C, AuthRecord as R, CoseKey, Method, NewCredential, RecoveryPath,
    };
    use fstp_ledger::{MemStore, RecordStore, Seq};

    const NOW: i64 = 1_000_000 + 3_600_000_000;
    const HOLDER: AccountId = AccountId::from_raw(101);
    const ADMIN: AccountId = AccountId::from_raw(1);
    const CASE: [u8; 16] = [0xCA; 16];

    fn key() -> CoseKey {
        CoseKey::Ed25519 { x: [0x0D; 32] }
    }

    fn state(records: &[CellRecord]) -> CellState {
        let mut store: MemStore<CellRecord> = MemStore::new();
        for (i, r) in records.iter().enumerate() {
            let id = [u8::try_from(i + 1).unwrap(); 16];
            store
                .append(store.head(), 1_000_000, id, vec![r.clone()])
                .unwrap();
        }
        let mut out = Vec::new();
        store.read(Seq::ZERO, usize::MAX, &mut out).unwrap();
        crate::replay(&out).unwrap()
    }

    fn registered(account: AccountId, credential: &[u8]) -> CellRecord {
        CellRecord::Auth(R::CredentialRegistered {
            account,
            credential: credential.to_vec(),
            key: key(),
            user_verified: true,
        })
    }

    fn new_passkey(id: &[u8], uv: bool) -> NewCredential {
        NewCredential {
            id: id.to_vec(),
            key: key(),
            sign_count: 0,
            user_verified: uv,
        }
    }

    fn view(id: u8, account: AccountId) -> fstp_auth::SessionView {
        fstp_auth::SessionView {
            id: [id; 16],
            account,
            method: Method::Passkey,
            started: Timestamp::from_micros(NOW - 60_000_000),
            last_used: Timestamp::from_micros(NOW),
        }
    }

    fn decide_as(
        s: &CellState,
        actor: AccountId,
        cmd: C,
        inputs: &RouteInputs,
    ) -> Result<Vec<CellRecord>, CellRefusal> {
        decide_with(
            s,
            &CellCommand::Auth(cmd),
            Who::Account(actor),
            NOW,
            Some([0x99; 16]),
            None,
            inputs,
            &Answers::new(),
        )
    }

    /// I-78, design section 8.3 (`AddPasskey`): `decide` alone, with the
    /// passkey its inputs carry. `RegisterCredential` records that key for
    /// an account that holds a passkey already. A first passkey, an id
    /// other than the command's, and a holder's passkey without UV are
    /// refused. The gate's own checks are tested in
    /// `fstp-celltest/tests/int3_route_admissions.rs`.
    #[test]
    fn i78_add_passkey_batch_records_the_key_its_inputs_carry() {
        let s = state(&[registered(HOLDER, &[0x5E, 0])]);
        let cmd = || C::RegisterCredential {
            account: HOLDER,
            credential: vec![0x5E, 1],
        };
        let with = |c: NewCredential| RouteInputs::none().with_credential(c);
        let batch = decide_as(&s, HOLDER, cmd(), &with(new_passkey(&[0x5E, 1], false))).unwrap();
        assert_eq!(
            batch,
            vec![CellRecord::Auth(R::CredentialRegistered {
                account: HOLDER,
                credential: vec![0x5E, 1],
                key: key(),
                user_verified: false,
            })]
        );
        assert_eq!(
            decide_as(&s, HOLDER, cmd(), &with(new_passkey(&[0x5E, 2], true))),
            Err(invalid())
        );
        assert_eq!(
            decide_as(&s, HOLDER, cmd(), &RouteInputs::none()),
            Err(CellRefusal::Domain(ROUTE_INPUT_MISSING))
        );
        let first = state(&[]);
        assert_eq!(
            decide_as(&first, HOLDER, cmd(), &with(new_passkey(&[0x5E, 1], true))),
            Err(refuse(RuleRef::Input, RefusalReason::WrongState))
        );
        let admin = state(&[
            CellRecord::Tenant(TenantRecord::TenantAdminGranted { account: HOLDER }),
            registered(HOLDER, &[0x5E, 0]),
        ]);
        assert_eq!(
            decide_as(&admin, HOLDER, cmd(), &with(new_passkey(&[0x5E, 1], false))),
            Err(invalid())
        );
    }

    /// I-79, design section 8.5 (Q15): a completion with the gate-verified
    /// passkey, the session rows and the mode revokes every live credential
    /// of the holder, ends every live session of the holder, registers the
    /// new passkey and records the path recomputed at completion. The
    /// batch folds. Without each input it is refused as missing.
    #[test]
    fn i79_completion_revokes_every_credential_and_ends_every_session() {
        let s = state(&[
            CellRecord::Tenant(TenantRecord::TenantAdminGranted { account: ADMIN }),
            registered(HOLDER, &[0x5E, 0]),
            CellRecord::Auth(R::RecoveryRequested {
                case: CASE,
                account: HOLDER,
                path: RecoveryPath::EmailThenPasskey,
            }),
            CellRecord::Auth(R::RecoveryEmailProven { case: CASE }),
        ]);
        let cmd = || C::CompleteRecovery {
            case: CASE,
            credential: vec![0x5E, 7],
        };
        let rows = SessionRows::new(vec![view(0x51, HOLDER), view(0x52, ADMIN)], Vec::new());
        let inputs = RouteInputs::none()
            .with_credential(new_passkey(&[0x5E, 7], false))
            .with_sessions(rows.clone())
            .with_mode(fstp_auth::recovery::Deployment::Saas);
        let batch = decide_as(&s, HOLDER, cmd(), &inputs).unwrap();
        assert_eq!(
            batch,
            vec![
                CellRecord::Auth(R::CredentialRevoked {
                    account: HOLDER,
                    credential: vec![0x5E, 0],
                }),
                CellRecord::Auth(R::SessionEnded {
                    session: [0x51; 16],
                }),
                CellRecord::Auth(R::CredentialRegistered {
                    account: HOLDER,
                    credential: vec![0x5E, 7],
                    key: key(),
                    user_verified: false,
                }),
                CellRecord::Auth(R::RecoveryCompleted {
                    case: CASE,
                    account: HOLDER,
                    path: RecoveryPath::EmailThenPasskey,
                    shown_to_tenant: false,
                }),
            ]
        );
        let mut next = s.clone();
        for (i, r) in batch.iter().enumerate() {
            let seq = Seq::from_raw(s.head().raw() + u64::try_from(i).unwrap() + 1);
            crate::state::fold(&mut next, seq, Timestamp::from_micros(NOW), [0x99; 16], r).unwrap();
        }
        assert_eq!(
            decide_as(&s, ADMIN, cmd(), &inputs),
            Err(wrong_actor()),
            "another account completed the holder's case"
        );
        let missing = RouteInputs::none()
            .with_credential(new_passkey(&[0x5E, 7], false))
            .with_sessions(rows);
        assert_eq!(
            decide_as(&s, HOLDER, cmd(), &missing),
            Err(CellRefusal::Domain(ROUTE_INPUT_MISSING))
        );
    }

    /// I-79, design section 8.5: the path is recomputed at completion. A
    /// management role held at completion makes an email-only case fail,
    /// so no completion records it.
    #[test]
    fn i79_non_receiving_never_completes_by_email_alone() {
        let s = state(&[
            CellRecord::Tenant(TenantRecord::TenantAdminGranted { account: ADMIN }),
            CellRecord::Tenant(TenantRecord::TenantAdminGranted { account: HOLDER }),
            CellRecord::Auth(R::RecoveryRequested {
                case: CASE,
                account: HOLDER,
                path: RecoveryPath::EmailThenPasskey,
            }),
            CellRecord::Auth(R::RecoveryEmailProven { case: CASE }),
        ]);
        let inputs = RouteInputs::none()
            .with_credential(new_passkey(&[0x5E, 7], true))
            .with_sessions(SessionRows::default())
            .with_mode(fstp_auth::recovery::Deployment::Saas);
        assert_eq!(
            decide_as(
                &s,
                HOLDER,
                C::CompleteRecovery {
                    case: CASE,
                    credential: vec![0x5E, 7],
                },
                &inputs
            ),
            Err(refuse(RuleRef::Input, RefusalReason::WrongState))
        );
    }
}
