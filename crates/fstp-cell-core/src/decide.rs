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
//!   NOTE), except the credential and step-up records and the two
//!   commands that only end access (`EndBreakGlass`, `EndTenantAdmin`).
//!   A holder check
//!   also counts a binding only until its scheduled end instant (design
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

use std::collections::BTreeSet;

use fstp_domain::command::{Actor, Ctx, SystemCause, Via};
use fstp_domain::id::{AccountId, CommandId, ProposalId, VaultEpoch};
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
use crate::ops::OpsCommand;
use crate::release::{ReleaseCommand, ReleaseRecord};
use crate::state::TextStatus;
use crate::tenant::{TenantCommand, TenantLoginPolicy, TenantRecord};
use crate::text::{TextCommand, TextRecord};
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
        && let Some(approval) = tenant.approval(&digest)
        && !approval.used
        && approval.approver == *named
        && approval.approver != actor
        && tenant.is_admin(approval.approver)
        && now.micros() <= approval.expires_at
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
            | CellCommand::Ops(
                OpsCommand::ApplyOperatorTicket { .. } | OpsCommand::EndSessionsAtBindingEnd { .. }
            )
    )
}

/// Refuses an account's cell command while a scheduled binding end is
/// overdue, as M2 `shared_checks` refuses its own commands (SoD-05, the
/// Cooling-off NOTE). No decision then reads a binding as held after its
/// end instant. The credential and step-up records are left open: they
/// read no binding, and the gate ends the sessions the end would have
/// ended (design section 5.4 step 2).
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
            | CellCommand::Tenant(TenantCommand::EndTenantAdmin { .. })
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
        _ => Ok(Vec::new()),
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the command, who issues it, its instant and id, its step-up instant and its answers"
)]
pub(crate) fn decide_with(
    s: &CellState,
    c: &CellCommand,
    who: Who,
    at: i64,
    command: Option<[u8; 16]>,
    stepup_at: Option<Timestamp>,
    answers: &Answers,
) -> Result<Vec<CellRecord>, CellRefusal> {
    let batch = decide_unchecked(s, c, who, at, command, stepup_at, answers)?;
    storable(&batch)?;
    Ok(batch)
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
    reason = "the command, who issues it, its instant and id, its step-up instant and its answers"
)]
fn decide_unchecked(
    s: &CellState,
    c: &CellCommand,
    who: Who,
    at: i64,
    command: Option<[u8; 16]>,
    stepup_at: Option<Timestamp>,
    answers: &Answers,
) -> Result<Vec<CellRecord>, CellRefusal> {
    let now = Timestamp::from_micros(at);
    clock(s, now)?;
    let actor = match who {
        Who::Account(actor) => actor,
        Who::System(task) => return decide_system(s, c, task, now, command, answers),
    };
    if system_only(c) {
        return Err(wrong_actor());
    }
    overdue(s, c, now)?;
    match c {
        CellCommand::Engine(cmd) => decide_engine(s, cmd, actor, now, command, answers),
        CellCommand::Auth(cmd) => decide_auth(s, cmd, actor, at, command),
        CellCommand::Tenant(cmd) => decide_tenant(s, cmd, actor, now, stepup_at),
        CellCommand::Text(cmd) => decide_text(s, cmd, actor),
        CellCommand::Release(cmd) => decide_release(s, cmd, actor, now, command, answers),
        CellCommand::Ops(cmd) => decide_ops(s, cmd, actor),
        // `system_only` refused these above.
        CellCommand::Key(_) => Err(wrong_actor()),
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
            SystemTask::Timeline,
            CellCommand::Ops(OpsCommand::EndSessionsAtBindingEnd { account }),
        ) => end_sessions_at_binding_end(s, *account, now),
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

fn decide_auth(
    s: &CellState,
    cmd: &fstp_auth::AuthCommand,
    actor: AccountId,
    at: i64,
    command: Option<[u8; 16]>,
) -> Result<Vec<CellRecord>, CellRefusal> {
    use fstp_auth::{AuthCommand as C, AuthRecord as R};
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
            if s.auth().has_credential(*account, credential) {
                return Err(reused());
            }
            Ok(vec![CellRecord::Auth(R::CredentialRegistered {
                account: *account,
                credential: credential.clone(),
            })])
        }
        C::RevokeCredential {
            account,
            credential,
        } => {
            if *account != actor && !s.tenant().is_admin(actor) {
                return Err(wrong_actor());
            }
            if !s.auth().has_credential(*account, credential) {
                return Err(unknown());
            }
            Err(CellRefusal::NotImplemented(
                "RevokeCredential: fstp_auth::AuthRecord has no revocation record (lane W2b)",
            ))
        }
        C::GrantStepUp {
            session,
            action_digest,
        } => {
            let mut payload = Vec::with_capacity(48);
            payload.extend_from_slice(session);
            payload.extend_from_slice(action_digest);
            let id = derive_id(b"stepup", command, actor, at, &payload);
            if s.auth().stepup(id).is_some() {
                return Err(reused());
            }
            Ok(vec![CellRecord::Auth(R::StepUpGranted {
                id,
                action_digest: *action_digest,
            })])
        }
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
            if tenant.approval(grant_digest).is_some() {
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
    }
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
/// scheduled binding end is due.
fn end_sessions_at_binding_end(
    s: &CellState,
    account: AccountId,
    now: Timestamp,
) -> Result<Vec<CellRecord>, CellRefusal> {
    if !s.binding_end_due(account, now) {
        return Err(unknown());
    }
    Err(CellRefusal::NotImplemented(
        "EndSessionsAtBindingEnd: decide sees no session rows, so the batch cannot name the sessions it ends (design sections 4.2 and 5.1)",
    ))
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
    let epoch = reaction_epoch_of(cmd)?;
    clock(s, now)?;
    let records = fstp_engine::DomainDecider
        .decide(s.engine(), cmd, &reaction_ctx(epoch, now), answers)
        .map_err(CellRefusal::Domain)?;
    let batch: Vec<CellRecord> = records.into_iter().map(CellRecord::Engine).collect();
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
