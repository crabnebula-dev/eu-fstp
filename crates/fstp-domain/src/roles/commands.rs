//! Engine entry points of lane L-SOD (design sections 2.6, 3.4 and 4.1 to 4.3).
//!
//! Commands this lane owns:
//!
//! - `GrantRole` of a Drafting, Judging or Operations role by a tenant
//!   admin. Receiving roles are never granted, because they arise from
//!   proposals. Drafting and Judging grants need accepted confidentiality
//!   terms, `IsVerified` true and `SameIdentityAsAny` false over the
//!   candidate set (SoD-09, I-06). A self-grant needs the second tenant
//!   admin that the shell attested (SoD-07). A committee member grant
//!   needs the reviewer's organisation, since SoD-10 and I-34 count
//!   organisations from it (decided 2026-10-25). For other roles the
//!   field is data only.
//!   A committee member grant whose organisation differs from a held
//!   committee binding of the account in the programme, whatever its
//!   period, is refused, since a reviewer has one organisation per
//!   programme (SoD-10, decided 2026-10-28). A grant may schedule its
//!   end with `end`, after `start`.
//! - `EndRole` of a Drafting, Judging or Operations binding that is not
//!   voided. At `ctx.now` it ends the binding and pins the cooling-off
//!   bar, which never counts for a conflict-of-interest suspension. At a
//!   later instant, after the binding's start, it schedules the end, or
//!   brings a scheduled end forward. Moving a scheduled end later, or
//!   before `ctx.now`, is refused (Cooling-off NOTE, decided 2026-10-25).
//! - `EndScheduledRole`, by the System, which [`due`] lists from the
//!   scheduled instant on. It records the end at that instant, with the
//!   bar of that instant. Until it is recorded, the engine decides no
//!   other command but `VaultChanged` ([`end_overdue`]).
//! - `ReinstateBinding` of a suspended binding. A committee binding is
//!   refused under SoD-10 when another held committee binding of the
//!   account in the programme records another organisation. A conflict-of-interest
//!   suspension is reinstated only once the identity clash is over: no
//!   I-01 or I-02 clash on its own account, and `SameIdentityAsAny` false
//!   over the other accounts it would break I-01 with (I-06). Its record
//!   falls back to an ordinary suspension kept beneath the marker, if any.
//! - `VaultChanged`, the same-step reaction to a newer vault epoch
//!   (enforcement point 3). It voids every held Receiving binding of a
//!   changed account in an excluded class (I-04). It also voids every held
//!   or ended Receiving binding whose account shares a verified identity
//!   with a candidate set that touches a changed account (I-06). It
//!   suspends, as a conflict of interest, every held or ended Judging
//!   binding found to share a verified identity with a Drafting binding it
//!   breaks I-01 with. The Drafting binding stays. Its queries are answered at
//!   the new epoch, so under the commit protocol they see the provisional
//!   fact the reaction reacts to (overview NOTE 4).
//!
//! Contributions to other lanes' batches:
//!
//! - `CreateDraft`, `AddTeamMember` and `AddGuardian`: the Receiving
//!   binding, after the account rules, SoD-03, SoD-06 over the call's
//!   effective P-13 and I-06 (enforcement point 1).
//! - `EditPolicy` that adds a P-13 class: the voids of every held
//!   Receiving binding of the programme now in an excluded class (P-13
//!   NOTE 7, Identity discovery).
//! - Any batch that takes a proposal to a terminal state: the end of its
//!   held Receiving bindings (Q11 A). A binding the batch already ends or
//!   voids gets no end.
//!
//! The engine asks for contributions in `LANES` order, and Roles comes
//! before Assignment, Proposal, Decision, Grant, Payment and Amendment.
//! So this lane sees a terminal `Transitioned` only when the owning lane's
//! decide, or the Policy or Programme contribution, records it. A lane
//! that moves a proposal to a terminal state must record the `Transitioned`
//! from its own decide, never from a contribution to another lane's batch.
//! Otherwise the proposal's Receiving bindings stay held and pin no bar.
//!
//! Every vault answer a decision uses is recorded as a `VaultOutcome`
//! with the query digest and the bit, never the query (overview NOTE 5).
//! A batch records each answer once, even when several rechecks share it.

use std::collections::BTreeSet;

use crate::command::{Command, Ctx};
use crate::engine::{FoldError, PolicyScope};
use crate::id::{AccountId, BindingId, CallId, OrganisationId, ProgrammeId, VaultEpoch};
use crate::oracle::{Answer, Answers, Query};
use crate::programme::DraftGate;
use crate::record::{
    BindingEnded, BindingGranted, BindingReinstated, BindingSuspended, BindingVoided, OutboxEvent,
    Record,
};
use crate::refusal::{Refusal, RefusalReason, RuleRef};
use crate::roles::guards::{
    Target, account_rule, breaking_accounts, breaking_candidates, identity_candidates, latest,
    other_separated, published_call, unknown,
};
use crate::roles::{
    Binding, BindingScope, BindingStatus, EndedBinding, Group, IdentityDiscovery, Role,
};
use crate::state::{State, UsedId};
use crate::time::Timestamp;

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// The refusal of a shell-supplied id that is already taken.
const fn reused() -> Refusal {
    Refusal::new(RuleRef::Ledger, RefusalReason::IdReused)
}

/// The refusal of a command that does not apply to the entity's state.
const fn wrong_state() -> Refusal {
    Refusal::new(RuleRef::Input, RefusalReason::WrongState)
}

/// The answer to `q`, or the refusal for a missing one.
fn answer<'a>(answers: &'a Answers, q: &Query) -> Result<&'a Answer, Refusal> {
    answers.get(q).ok_or(Refusal::new(
        RuleRef::FactsIncomplete,
        RefusalReason::AnswerMissing,
    ))
}

/// The record of a vault answer a decision used (overview NOTE 5).
fn outcome(q: &Query, a: &Answer) -> Record {
    Record::VaultOutcome {
        kind: q.kind(),
        digest: a.digest,
        holds: a.holds,
        epoch: a.epoch,
    }
}

/// Appends the record of answer `a` to `q` unless `prior` or `out` holds
/// it already. Two rechecks can ask the same question, and a batch records
/// each answer it uses once (overview NOTE 5, design 4.4). The digest
/// covers the query's canonical encoding, so equal records mean one answer.
fn record_outcome(out: &mut Vec<Record>, prior: &[Record], q: &Query, a: &Answer) {
    let r = outcome(q, a);
    if !prior.contains(&r) && !out.contains(&r) {
        out.push(r);
    }
}

/// The records that end binding `id` at `at`: the end with its pinned
/// bar, then the group membership removal (I-29 seam).
///
/// The bar is the latest call sequence published in the programme plus
/// the head's P-12, both read now, before the end record in ledger order.
fn end_records(
    state: &State,
    id: BindingId,
    b: &Binding,
    at: Timestamp,
) -> Result<[Record; 2], Refusal> {
    let p12 = crate::policy::live_values(state, b.programme)
        .ok_or_else(unknown)?
        .p12;
    let bar = latest(state, b.programme).saturating_add(u32::from(p12.0));
    Ok([
        Record::BindingEnded(BindingEnded {
            binding: id,
            at,
            barred_through: bar,
            p12,
        }),
        Record::OutboxEnqueued(OutboxEvent::BindingEnded { binding: id }),
    ])
}

// ---------------------------------------------------------------------------
// GrantRole
// ---------------------------------------------------------------------------

/// A checked `GrantRole`: the binding to record and its vault questions.
struct GrantPlan {
    /// The binding, with no SoD-09 epoch yet.
    record: BindingGranted,
    /// The scheduled end, if the grant sets one.
    end: Option<Timestamp>,
    /// `IsVerified` for a Drafting or Judging grant (SoD-09).
    verified: Option<Query>,
    /// `SameIdentityAsAny` over a non-empty candidate set (I-06, SoD-09).
    identity: Option<Query>,
}

impl GrantPlan {
    /// The vault questions, in a stable order.
    fn queries(&self) -> Vec<Query> {
        self.verified
            .iter()
            .chain(self.identity.iter())
            .cloned()
            .collect()
    }
}

/// Checks a `GrantRole` against the state and returns its plan.
///
/// The check is a status gate, then the SoD guards (M4 change D3). Under
/// `DraftGate::Enforce` a draft programme admits only a programme manager
/// grant, so its builders hold the binding that I-65 names. Every other
/// grant on a draft is refused with `RuleRef::I66` and `WrongState`. A
/// preview skips the gate and runs the SoD guards alone.
fn plan_grant(
    state: &State,
    cmd: &Command,
    ctx: &Ctx,
    gate: DraftGate,
) -> Result<GrantPlan, Refusal> {
    let Command::GrantRole {
        binding,
        account,
        programme,
        role,
        start,
        second_admin,
        confidentiality,
        organisation,
        end,
    } = cmd
    else {
        return Err(wrong_state());
    };
    let actor = crate::policy::actor_account(ctx)?;
    if crate::policy::head(state, *programme).is_none() {
        return Err(unknown());
    }
    if *role != Role::ProgrammeManager {
        crate::programme::draft_gate(state, *programme, gate)?;
    }
    if state.used_ids.contains(UsedId::Binding(*binding)) {
        return Err(reused());
    }
    let group = role.group();
    if group == Group::Receiving {
        // Receiving bindings arise from proposals, never from a grant.
        return Err(Refusal::new(RuleRef::Input, RefusalReason::InvalidValue));
    }
    if *role == Role::CommitteeMember && organisation.is_none() {
        // Each committee binding records the reviewer's organisation, and
        // SoD-10 and I-34 count organisations from it (decided 2026-10-25).
        return Err(Refusal::new(RuleRef::Sod10, RefusalReason::InvalidValue));
    }
    if *role == Role::CommitteeMember
        && let Some(o) = organisation
        && other_organisation(state, *account, *programme, *o, None)
    {
        // A reviewer has one organisation per programme (SoD-10, decided
        // 2026-10-28), so the count of organisations never depends on
        // which of its committee bindings is read.
        return Err(Refusal::new(RuleRef::Sod10, RefusalReason::GuardFailed));
    }
    if *start < ctx.now {
        // No backdating (design 2.6).
        return Err(Refusal::new(RuleRef::Input, RefusalReason::InvalidValue));
    }
    if end.is_some_and(|e| e <= *start) {
        // A scheduled end lies at a later instant than the start
        // (Cooling-off NOTE, decided 2026-10-25).
        return Err(Refusal::new(RuleRef::Input, RefusalReason::InvalidValue));
    }
    if group.needs_verification() && confidentiality.is_none() {
        // Confidentiality on binding. The terms' wording is TODO(legal).
        return Err(Refusal::new(RuleRef::Input, RefusalReason::GuardFailed));
    }
    if *account == actor {
        let approved = matches!(
            (*second_admin, ctx.second_tenant_admin),
            (Some(s), Some(t)) if s == t && s != actor
        );
        if !approved {
            return Err(Refusal::new(RuleRef::Sod07, RefusalReason::GuardFailed));
        }
    }
    let target = Target::Programme {
        latest: latest(state, *programme),
    };
    if let Some(rule) = account_rule(state, *account, *programme, *role, target) {
        return Err(Refusal::new(rule, RefusalReason::GuardFailed));
    }
    let (verified, identity) = if group.needs_verification() {
        let others = identity_candidates(state, *account, *programme, group, target);
        (
            Some(Query::IsVerified { account: *account }),
            (!others.is_empty()).then_some(Query::SameIdentityAsAny {
                subject: *account,
                others,
            }),
        )
    } else {
        (None, None)
    };
    Ok(GrantPlan {
        record: BindingGranted {
            binding: *binding,
            account: *account,
            programme: *programme,
            role: *role,
            scope: BindingScope::Programme,
            start: *start,
            granted_by: actor,
            second_admin: *second_admin,
            confidentiality: *confidentiality,
            organisation: *organisation,
            verified_epoch: None,
        },
        end: *end,
        verified,
        identity,
    })
}

/// The records of a checked `GrantRole` under `answers`.
fn decide_grant(plan: GrantPlan, answers: &Answers) -> Result<Vec<Record>, Refusal> {
    let mut out = Vec::new();
    let mut record = plan.record;
    if let Some(q) = &plan.verified {
        let a = answer(answers, q)?;
        if !a.holds {
            return Err(Refusal::new(RuleRef::Sod09, RefusalReason::VaultRefused));
        }
        out.push(outcome(q, a));
        record.verified_epoch = Some(a.epoch);
    }
    if let Some(q) = &plan.identity {
        let a = answer(answers, q)?;
        if a.holds {
            return Err(Refusal::new(RuleRef::I06, RefusalReason::VaultRefused));
        }
        out.push(outcome(q, a));
    }
    let binding = record.binding;
    out.push(Record::BindingGranted(record));
    if let Some(at) = plan.end {
        out.push(Record::BindingEndScheduled { binding, at });
    }
    Ok(out)
}

/// Whether `account` holds a committee member binding in `programme`, other
/// than `except`, that records an organisation other than `organisation`
/// (SoD-10, decided 2026-10-28).
///
/// A reviewer has one organisation per programme. Every held binding
/// counts, whatever its period: one with a scheduled end that is not yet
/// recorded, one that starts later, and an ordinarily suspended one,
/// since it can be reinstated. A voided binding or a conflict-of-interest
/// suspension is not held. So the organisation that `binding_releases`
/// and I-35 read for kept assignments never changes (W7 fix round 2).
fn other_organisation(
    state: &State,
    account: AccountId,
    programme: ProgrammeId,
    organisation: OrganisationId,
    except: Option<BindingId>,
) -> bool {
    state.roster.bindings().any(|(id, b)| {
        Some(id) != except
            && b.account == account
            && b.programme == programme
            && b.role == Role::CommitteeMember
            && b.held()
            && b.organisation.is_some_and(|o| o != organisation)
    })
}

// ---------------------------------------------------------------------------
// EndRole and ReinstateBinding
// ---------------------------------------------------------------------------

/// Checks an `EndRole` and returns its records.
///
/// A binding under a conflict-of-interest suspension can end too. The bar
/// its end pins never counts (Identity discovery, decided 2026-10-25).
///
/// An end at `ctx.now` ends the binding at once, a scheduled one too. A
/// later instant schedules the end (Cooling-off NOTE, decided 2026-10-25):
/// the binding stays held until then, and [`due`] lists its
/// `EndScheduledRole` from that instant on. A scheduled end can be
/// brought forward, never moved later. An earlier end than `ctx.now` is
/// backdating. Scheduling the same instant again is refused, since it
/// changes nothing. A scheduled end lies after the binding's start, as
/// at the grant.
///
/// Once a scheduled instant is reached, the engine refuses every command
/// but the System end and `VaultChanged` until the end is recorded
/// ([`end_overdue`]). So an `EndRole` never moves an overdue end later.
fn plan_end(
    state: &State,
    binding: BindingId,
    at: Timestamp,
    ctx: &Ctx,
) -> Result<Vec<Record>, Refusal> {
    let b = state.roster.binding(binding).ok_or_else(unknown)?;
    if b.voided() || b.group() == Group::Receiving {
        // Voided bindings are no longer held. Receiving bindings end with
        // the proposal's terminal state (Q11 A).
        return Err(wrong_state());
    }
    if at < ctx.now {
        // An earlier end is backdating.
        return Err(Refusal::new(RuleRef::Input, RefusalReason::InvalidValue));
    }
    if b.scheduled_end.is_some_and(|s| s <= ctx.now) {
        // The engine refuses this before any lane runs. Kept so the rule
        // holds here on its own.
        return Err(Refusal::new(RuleRef::Sod05, RefusalReason::WrongState));
    }
    if at == ctx.now {
        return Ok(end_records(state, binding, b, at)?.to_vec());
    }
    if b.scheduled_end.is_some_and(|s| at >= s) {
        // A scheduled end is brought forward, never moved later.
        return Err(Refusal::new(RuleRef::Input, RefusalReason::InvalidValue));
    }
    if at <= b.start {
        // A scheduled end lies at a later instant than the start, as the
        // grant requires.
        return Err(Refusal::new(RuleRef::Input, RefusalReason::InvalidValue));
    }
    Ok(vec![Record::BindingEndScheduled { binding, at }])
}

/// Checks an `EndScheduledRole` and returns its records: the end at the
/// scheduled instant, once `ctx.now` has reached it (Cooling-off NOTE,
/// decided 2026-10-25).
///
/// The bar is the latest call sequence published in the programme plus
/// P-12, both read when the System records the end. From the instant on,
/// the engine refuses every other command but `VaultChanged` until this
/// end is recorded ([`end_overdue`]). No call is published and no P-12 is
/// edited in between, so these are the calls published by the instant and
/// the P-12 value in force at it.
fn plan_scheduled_end(
    state: &State,
    binding: BindingId,
    ctx: &Ctx,
) -> Result<Vec<Record>, Refusal> {
    let b = state.roster.binding(binding).ok_or_else(unknown)?;
    let at = b.scheduled_end.ok_or_else(wrong_state)?;
    if b.voided() || at > ctx.now {
        return Err(wrong_state());
    }
    Ok(end_records(state, binding, b, at)?.to_vec())
}

/// Whether the binding `b` has a scheduled end at or before `now` that the
/// System has not yet recorded.
fn overdue(b: &Binding, now: Timestamp) -> bool {
    !b.voided() && b.scheduled_end.is_some_and(|s| s <= now)
}

/// Whether some binding has a scheduled end at or before `now` that the
/// System has not yet recorded (Cooling-off NOTE, decided 2026-10-25).
///
/// The binding stays held until its instant, and its bar is pinned then.
/// The engine refuses every command but `EndScheduledRole` and
/// `VaultChanged` while this holds. So no decision reads the binding as
/// held after its instant, and the end reads the state of the instant.
/// `VaultChanged` stays open because every command first processes a
/// newer vault epoch, the System end included (overview NOTE 3). A
/// reaction only voids and suspends, so it never grants through the
/// binding.
pub(crate) fn end_overdue(state: &State, now: Timestamp) -> bool {
    state.roster.bindings().any(|(_, b)| overdue(b, now))
}

/// The System commands due at `now`: the end of every open binding whose
/// scheduled end instant is at or before `now` (Cooling-off NOTE, decided
/// 2026-10-25).
pub(crate) fn due(state: &State, now: Timestamp) -> Vec<Command> {
    state
        .roster
        .bindings()
        .filter(|(_, b)| overdue(b, now))
        .map(|(binding, _)| Command::EndScheduledRole { binding })
        .collect()
}

/// A checked `ReinstateBinding`: the record and its vault question.
struct ReinstatePlan {
    /// The reinstatement.
    record: BindingReinstated,
    /// For a conflict-of-interest suspension, `SameIdentityAsAny` over the
    /// other accounts whose bindings the reinstated binding would break
    /// I-01 with (I-06). None for every other suspension, or when the set
    /// is empty.
    identity: Option<Query>,
}

/// Checks a `ReinstateBinding` and returns its plan.
///
/// A conflict-of-interest suspension is reinstated only once the identity
/// clash is over (Identity discovery, decided 2026-10-25). Counted again,
/// the binding must not break the I-01 pair rule with a binding of its own
/// account. Nor may it break I-02 with a binding of its own account that
/// was held beside it, held now or ended since its grant. The vault
/// question covers the other accounts of its verified identity (I-06).
///
/// A committee binding is refused under SoD-10 when another held committee
/// binding of the account in the programme records another
/// organisation, whatever its period (decided 2026-10-28).
fn plan_reinstate(
    state: &State,
    binding: BindingId,
    reason: crate::id::TextRef,
    ctx: &Ctx,
) -> Result<ReinstatePlan, Refusal> {
    let by = crate::policy::actor_account(ctx)?;
    let b = state.roster.binding(binding).ok_or_else(unknown)?;
    if !matches!(b.status, BindingStatus::Suspended(_)) {
        return Err(wrong_state());
    }
    if b.role == Role::CommitteeMember
        && let Some(o) = b.organisation
        && other_organisation(state, b.account, b.programme, o, Some(binding))
    {
        // A committee binding granted while this one was not held may
        // record another organisation. Counted again, this one would give
        // the reviewer two organisations in the programme (SoD-10, decided
        // 2026-10-28).
        return Err(Refusal::new(RuleRef::Sod10, RefusalReason::GuardFailed));
    }
    let mut identity = None;
    if b.conflict_of_interest() {
        let groups = other_separated(b.group());
        let breaking = breaking_accounts(state, b.programme, &groups, b.opened, None);
        if breaking.contains(&b.account) {
            return Err(Refusal::new(RuleRef::I01, RefusalReason::GuardFailed));
        }
        if irc_clash(state, b) {
            return Err(Refusal::new(RuleRef::I02, RefusalReason::GuardFailed));
        }
        let others = breaking_candidates(state, b.account, b.programme, &groups, b.opened, None);
        identity = (!others.is_empty()).then_some(Query::SameIdentityAsAny {
            subject: b.account,
            others,
        });
    }
    Ok(ReinstatePlan {
        record: BindingReinstated {
            binding,
            by,
            reason,
        },
        identity,
    })
}

/// Whether the open binding `b`, counted again, would have been held at the
/// same time as a binding of its own account and programme that I-02
/// separates from it.
///
/// A counted binding held now was open beside `b`. So was a counted
/// binding that ended after the grant of `b` in fold order, because `b`
/// has been open since its grant. Counted again, `b` counts over its
/// conflict-of-interest suspension too, so an IRC binding granted and
/// ended during it still clashes. Otherwise the history would show both
/// held at the same time.
fn irc_clash(state: &State, b: &Binding) -> bool {
    let separated = |y: &Binding| {
        y.account == b.account
            && y.programme == b.programme
            && y.held()
            && ((b.role == Role::IrcMember && y.role.other_judging())
                || (b.role.other_judging() && y.role == Role::IrcMember))
    };
    state.roster.bindings().any(|(_, y)| separated(y))
        || state
            .roster
            .ended()
            .any(|(_, e)| separated(&e.binding) && e.ended > b.granted)
}

/// The records of a checked `ReinstateBinding` under `answers`. A shared
/// verified identity means the clash lasts, so the reinstatement is refused.
fn decide_reinstate(plan: ReinstatePlan, answers: &Answers) -> Result<Vec<Record>, Refusal> {
    let mut out = Vec::new();
    if let Some(q) = &plan.identity {
        let a = answer(answers, q)?;
        if a.holds {
            return Err(Refusal::new(RuleRef::I06, RefusalReason::VaultRefused));
        }
        out.push(outcome(q, a));
    }
    out.push(Record::BindingReinstated(plan.record));
    Ok(out)
}

// ---------------------------------------------------------------------------
// VaultChanged
// ---------------------------------------------------------------------------

/// What a positive identity answer does to the binding a recheck covers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Remedy {
    /// A Receiving binding, held or ended, is voided (Identity discovery).
    Void,
    /// A Judging binding, held or ended, is suspended as a conflict of
    /// interest under I-06 (Identity discovery, decided 2026-10-25).
    Suspend,
}

/// The vault questions about one binding in a reaction.
struct Recheck {
    /// The binding.
    binding: BindingId,
    /// What a positive answer does.
    remedy: Remedy,
    /// `InExcludedClass` over the call's effective P-13, when a held
    /// Receiving binding's account changed (I-04).
    excluded: Option<Query>,
    /// `SameIdentityAsAny` over the candidate set, when it or the account changed (I-06).
    identity: Option<Query>,
}

/// A checked `VaultChanged`: the change question and the rechecks.
struct ReactionPlan {
    /// `ChangedSince` the state's epoch.
    changed: Query,
    /// One recheck per binding that the change may affect.
    rechecks: Vec<Recheck>,
}

impl ReactionPlan {
    /// The vault questions, in a stable order.
    fn queries(&self) -> Vec<Query> {
        let mut out = vec![self.changed.clone()];
        for r in &self.rechecks {
            out.extend(r.excluded.iter().cloned());
            out.extend(r.identity.iter().cloned());
        }
        out
    }
}

/// The sequence number of `call` for the cooling-off comparison. An
/// unpublished call has none, and every bar covers it.
fn call_seq(state: &State, call: CallId) -> u32 {
    crate::programme::call(state, call)
        .and_then(crate::programme::CallView::seq)
        .map_or(0, |s| s.get())
}

/// The `SameIdentityAsAny` question for a binding of `b.account` opened at
/// `b.opened` and barred through `bar`, against the other accounts with a
/// binding in `groups` that breaks I-01 with it. None when the set is
/// empty, or when neither the account nor a candidate changed.
fn identity_recheck(
    state: &State,
    b: &Binding,
    groups: &[Group],
    bar: Option<u32>,
    changed: &BTreeSet<AccountId>,
) -> Option<Query> {
    let others = breaking_candidates(state, b.account, b.programme, groups, b.opened, bar);
    let touched = changed.contains(&b.account) || others.iter().any(|a| changed.contains(a));
    (touched && !others.is_empty()).then_some(Query::SameIdentityAsAny {
        subject: b.account,
        others,
    })
}

/// Checks a `VaultChanged` and returns its plan.
///
/// - Every held Receiving binding of a changed account is rechecked for
///   I-04, over its call's effective P-13. A policy read that fails
///   refuses the reaction, so nothing is recorded (fail closed).
/// - Every held or ended Receiving binding is rechecked for I-06 when its
///   account or a candidate changed. An ended binding counts through its
///   bar, so voiding it drops a past binding inside the cooling-off period.
/// - Every Judging binding that counts, held or ended inside its bar, is
///   rechecked against the Drafting bindings in the same way. A positive
///   answer is a conflict of interest, and the reaction suspends the
///   Judging binding under I-06 (Identity discovery, decided 2026-10-25).
///   Only a later identity merge reaches this, since SoD-09 refuses it at
///   binding time. The Drafting binding stays. The pair rule is
///   symmetric, so the Judging side alone covers each pair.
///
/// Every recheck reads the bindings that count before the reaction, so the
/// voids and suspensions of one reaction do not depend on each other.
/// Exclusions are facts about identities, so the vault lists every account
/// of an identity whose exclusion changed. Bars and bindings do not change
/// with the vault, so no other binding can start to break I-04 or I-06.
fn plan_reaction(
    state: &State,
    epoch: VaultEpoch,
    changed: &BTreeSet<AccountId>,
) -> Result<ReactionPlan, Refusal> {
    if epoch <= state.epoch {
        return Err(wrong_state());
    }
    let mut rechecks = Vec::new();
    for (id, b) in state.roster.bindings() {
        if !b.held() {
            continue;
        }
        let recheck = match b.group() {
            Group::Receiving => {
                let Some(call) = b.call() else { continue };
                let excluded = if changed.contains(&b.account) {
                    Some(Query::InExcludedClass {
                        account: b.account,
                        programme: b.programme,
                        classes: crate::policy::effective_p13(state, call)?,
                    })
                } else {
                    None
                };
                Recheck {
                    binding: id,
                    remedy: Remedy::Void,
                    excluded,
                    identity: identity_recheck(
                        state,
                        b,
                        &[Group::Drafting, Group::Judging],
                        None,
                        changed,
                    ),
                }
            }
            Group::Judging => Recheck {
                binding: id,
                remedy: Remedy::Suspend,
                excluded: None,
                identity: identity_recheck(state, b, &[Group::Drafting], None, changed),
            },
            Group::Drafting | Group::Operations => continue,
        };
        if recheck.excluded.is_some() || recheck.identity.is_some() {
            rechecks.push(recheck);
        }
    }
    for (id, e) in state.roster.ended() {
        let Some(bar) = e.live_bar() else { continue };
        let (remedy, groups): (Remedy, &[Group]) = match e.binding.group() {
            Group::Receiving => (Remedy::Void, &[Group::Drafting, Group::Judging]),
            Group::Judging => (Remedy::Suspend, &[Group::Drafting]),
            Group::Drafting | Group::Operations => continue,
        };
        let identity = identity_recheck(state, &e.binding, groups, Some(bar), changed);
        if identity.is_some() {
            rechecks.push(Recheck {
                binding: id,
                remedy,
                excluded: None,
                identity,
            });
        }
    }
    Ok(ReactionPlan {
        changed: Query::ChangedSince { epoch: state.epoch },
        rechecks,
    })
}

/// The records of a checked `VaultChanged` under `answers`: the answers
/// used, the voids and suspensions, and the new epoch.
///
/// A binding that breaks both I-04 and I-06 is voided under I-06, so the
/// identity discovery stays a fact for R-CF-04.
fn decide_reaction(
    plan: &ReactionPlan,
    epoch: VaultEpoch,
    changed: &BTreeSet<AccountId>,
    answers: &Answers,
) -> Result<Vec<Record>, Refusal> {
    let a = answer(answers, &plan.changed)?;
    if a.accounts.as_ref() != Some(changed) {
        return Err(Refusal::new(
            RuleRef::StaleFacts,
            RefusalReason::AnswerStale,
        ));
    }
    let mut out = vec![outcome(&plan.changed, a)];
    let mut remedies = Vec::new();
    for r in &plan.rechecks {
        let mut excluded = false;
        if let Some(q) = &r.excluded {
            let a = answer(answers, q)?;
            record_outcome(&mut out, &[], q, a);
            excluded = a.holds;
        }
        let mut shared = false;
        if let Some(q) = &r.identity {
            let a = answer(answers, q)?;
            record_outcome(&mut out, &[], q, a);
            shared = a.holds;
        }
        let rule = if shared {
            RuleRef::I06
        } else if excluded {
            RuleRef::I04
        } else {
            continue;
        };
        remedies.push(match r.remedy {
            Remedy::Void => Record::BindingVoided(BindingVoided {
                binding: r.binding,
                rule,
                epoch,
            }),
            Remedy::Suspend => Record::BindingSuspended(BindingSuspended {
                binding: r.binding,
                rule,
                epoch,
            }),
        });
    }
    out.extend(remedies);
    out.push(Record::VaultEpochProcessed { epoch });
    Ok(out)
}

// ---------------------------------------------------------------------------
// Receiving bindings of other lanes' commands
// ---------------------------------------------------------------------------

/// A checked Receiving binding of `CreateDraft`, `AddTeamMember` or
/// `AddGuardian`: the binding and its vault questions.
struct ReceivingPlan {
    /// The binding.
    record: BindingGranted,
    /// `InExcludedClass` over the call's effective P-13 (SoD-06, I-04).
    excluded: Query,
    /// `SameIdentityAsAny` over a non-empty candidate set (I-06).
    identity: Option<Query>,
}

impl ReceivingPlan {
    /// The vault questions, in a stable order.
    fn queries(&self) -> Vec<Query> {
        let mut out = vec![self.excluded.clone()];
        out.extend(self.identity.iter().cloned());
        out
    }
}

/// Checks the Receiving binding that `cmd` creates, if it creates one.
///
/// The account is the actor for `CreateDraft` and the added account
/// otherwise. A tenant admin at tenant scope counts as holding an
/// Operations role (SoD-03, `Ctx::binds_tenant_admin`).
fn plan_receiving(
    state: &State,
    cmd: &Command,
    ctx: &Ctx,
) -> Result<Option<ReceivingPlan>, Refusal> {
    let (proposal, call, account, role, binding, admin) = match cmd {
        Command::CreateDraft {
            proposal,
            call,
            binding,
            ..
        } => (
            *proposal,
            *call,
            crate::policy::actor_account(ctx)?,
            Role::Applicant,
            *binding,
            ctx.binds_tenant_admin || ctx.tenant_admin,
        ),
        Command::AddTeamMember {
            proposal,
            account,
            binding,
        }
        | Command::AddGuardian {
            proposal,
            account,
            binding,
        } => {
            let call =
                crate::proposal::draft::proposal_call(state, *proposal).ok_or_else(unknown)?;
            let role = if matches!(cmd, Command::AddGuardian { .. }) {
                Role::Guardian
            } else {
                Role::ApplicantTeamMember
            };
            (
                *proposal,
                call,
                *account,
                role,
                *binding,
                ctx.binds_tenant_admin,
            )
        }
        _ => return Ok(None),
    };
    let granted_by = crate::policy::actor_account(ctx)?;
    if state.used_ids.contains(UsedId::Binding(binding)) {
        return Err(reused());
    }
    let (programme, seq) = published_call(state, call)?;
    let target = Target::Call { seq };
    if let Some(rule) = account_rule(state, account, programme, role, target) {
        return Err(Refusal::new(rule, RefusalReason::GuardFailed));
    }
    if admin {
        return Err(Refusal::new(RuleRef::Sod03, RefusalReason::GuardFailed));
    }
    let classes = crate::policy::effective_p13(state, call)?;
    let others = identity_candidates(state, account, programme, Group::Receiving, target);
    Ok(Some(ReceivingPlan {
        record: BindingGranted {
            binding,
            account,
            programme,
            role,
            scope: BindingScope::Proposal { proposal, call },
            start: ctx.now,
            granted_by,
            second_admin: None,
            confidentiality: None,
            organisation: None,
            verified_epoch: None,
        },
        excluded: Query::InExcludedClass {
            account,
            programme,
            classes,
        },
        identity: (!others.is_empty()).then_some(Query::SameIdentityAsAny {
            subject: account,
            others,
        }),
    }))
}

/// The records of a checked Receiving binding under `answers`.
fn decide_receiving(plan: ReceivingPlan, answers: &Answers) -> Result<Vec<Record>, Refusal> {
    let mut out = Vec::new();
    let a = answer(answers, &plan.excluded)?;
    if a.holds {
        return Err(Refusal::new(RuleRef::Sod06, RefusalReason::VaultRefused));
    }
    out.push(outcome(&plan.excluded, a));
    if let Some(q) = &plan.identity {
        let a = answer(answers, q)?;
        if a.holds {
            return Err(Refusal::new(RuleRef::I06, RefusalReason::VaultRefused));
        }
        out.push(outcome(q, a));
    }
    out.push(Record::BindingGranted(plan.record));
    Ok(out)
}

/// The `InExcludedClass` question for each held Receiving binding of the
/// programme when `cmd` is an `EditPolicy` on the head that adds a P-13
/// class (P-13 NOTE 7). The classes are the binding's call snapshot and
/// the new live value.
fn p13_rechecks(state: &State, cmd: &Command) -> Vec<(BindingId, Query)> {
    let Some(change) = crate::policy::live_change(state, cmd) else {
        return Vec::new();
    };
    if change.added_p13().0.is_empty() {
        return Vec::new();
    }
    let programme: ProgrammeId = change.programme;
    let mut out = Vec::new();
    for (id, b) in state.roster.bindings() {
        if !b.held() || b.group() != Group::Receiving || b.programme != programme {
            continue;
        }
        let Some(call) = b.call() else { continue };
        let mut classes = change.after.p13.clone();
        if let Some(policy) = crate::policy::frozen_policy(state, call) {
            classes.0.extend(policy.snapshot().p13.0.iter().copied());
        }
        out.push((
            id,
            Query::InExcludedClass {
                account: b.account,
                programme,
                classes,
            },
        ));
    }
    out
}

/// The end of the held Receiving bindings of every proposal that `batch`
/// takes to a terminal state (Q11 A).
///
/// `own` holds the records this lane already contributes to the batch. A
/// binding that `batch` or `own` already ends or voids gets no end: a
/// voided binding pins no bar, and the fold refuses to end it.
fn terminal_ends(
    state: &State,
    now: Timestamp,
    batch: &[Record],
    own: &[Record],
) -> Result<Vec<Record>, Refusal> {
    let mut out = Vec::new();
    let mut ended: BTreeSet<BindingId> = batch
        .iter()
        .chain(own)
        .filter_map(|r| match r {
            Record::BindingEnded(e) => Some(e.binding),
            Record::BindingVoided(v) => Some(v.binding),
            _ => None,
        })
        .collect();
    for r in batch {
        let Record::Transitioned(t) = r else { continue };
        if !t.to.is_terminal() {
            continue;
        }
        for (id, b) in state.roster.bindings() {
            if b.held() && b.proposal() == Some(t.proposal) && ended.insert(id) {
                out.extend(end_records(state, id, b, now)?);
            }
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Engine entry points
// ---------------------------------------------------------------------------

/// The vault questions of a `GrantRole` preview on `state` (M4 change D3,
/// Q13 A interim reading, pending Daniel). They are the questions that
/// `crate::queries` asks for the grant on a copy of `state` in which the
/// programme is active: the shared engine checks, the SoD guards and the
/// contributing lanes, without the draft gate. Any other command is
/// refused with `Input` and `WrongState`.
///
/// The creator's live SoD check (creator step 9) asks these questions,
/// records each answer as a query digest and the bit, and rate-limits the
/// previews (overview NOTE 5, H-07). A refusal is shown by its rule only,
/// never with an account (R-CF-03).
pub fn preview_grant_queries(
    state: &State,
    cmd: &Command,
    ctx: &Ctx,
) -> Result<Vec<Query>, Refusal> {
    if !matches!(cmd, Command::GrantRole { .. }) {
        return Err(wrong_state());
    }
    crate::engine::queries_gated(state, cmd, ctx, DraftGate::Skip)
}

/// The outcome of a `GrantRole` preview on `state` under `answers` (M4
/// change D3, Q13 A): `Ok` exactly when `crate::decide` would accept the
/// grant on a copy of `state` in which the programme is active, and its
/// refusal otherwise. It appends no record, and nothing is folded.
pub fn preview_grant(
    state: &State,
    cmd: &Command,
    ctx: &Ctx,
    answers: &Answers,
) -> Result<(), Refusal> {
    if !matches!(cmd, Command::GrantRole { .. }) {
        return Err(wrong_state());
    }
    crate::engine::decide_gated(state, cmd, ctx, answers, DraftGate::Skip).map(|_| ())
}

/// The vault questions of the role and vault change commands. `gate` is
/// `DraftGate::Skip` only for a `GrantRole` preview.
pub(crate) fn queries(
    state: &State,
    cmd: &Command,
    ctx: &Ctx,
    gate: DraftGate,
) -> Result<Vec<Query>, Refusal> {
    match cmd {
        Command::GrantRole { .. } => Ok(plan_grant(state, cmd, ctx, gate)?.queries()),
        Command::EndRole { binding, at } => {
            plan_end(state, *binding, *at, ctx)?;
            Ok(Vec::new())
        }
        Command::EndScheduledRole { binding } => {
            plan_scheduled_end(state, *binding, ctx)?;
            Ok(Vec::new())
        }
        Command::ReinstateBinding { binding, reason } => {
            Ok(plan_reinstate(state, *binding, *reason, ctx)?
                .identity
                .into_iter()
                .collect())
        }
        Command::VaultChanged { epoch, changed } => {
            Ok(plan_reaction(state, *epoch, changed)?.queries())
        }
        _ => Err(wrong_state()),
    }
}

/// The records of the role and vault change commands. `gate` is
/// `DraftGate::Skip` only for a `GrantRole` preview.
pub(crate) fn decide(
    state: &State,
    cmd: &Command,
    ctx: &Ctx,
    answers: &Answers,
    gate: DraftGate,
) -> Result<Vec<Record>, Refusal> {
    match cmd {
        Command::GrantRole { .. } => decide_grant(plan_grant(state, cmd, ctx, gate)?, answers),
        Command::EndRole { binding, at } => plan_end(state, *binding, *at, ctx),
        Command::EndScheduledRole { binding } => plan_scheduled_end(state, *binding, ctx),
        Command::ReinstateBinding { binding, reason } => {
            decide_reinstate(plan_reinstate(state, *binding, *reason, ctx)?, answers)
        }
        Command::VaultChanged { epoch, changed } => {
            let plan = plan_reaction(state, *epoch, changed)?;
            decide_reaction(&plan, *epoch, changed, answers)
        }
        _ => Err(wrong_state()),
    }
}

/// Folds a role and vault change record. The fold checks structure only
/// and never re-runs a guard.
pub(crate) fn apply(
    state: &mut State,
    seq: fstp_ledger::Seq,
    at: Timestamp,
    record: &Record,
) -> Result<(), FoldError> {
    let _ = (seq, at);
    match record {
        Record::BindingGranted(g) => fold_grant(state, g),
        Record::BindingEnded(e) => {
            let b = *state
                .roster
                .bindings
                .get(&e.binding)
                .ok_or(FoldError::UnknownEntity)?;
            // A conflict-of-interest suspension can end. Its bar never counts.
            if b.voided() {
                return Err(FoldError::Inconsistent);
            }
            state.roster.bindings.remove(&e.binding);
            let ended = judging_tick(state, b.group());
            if b.group().separated() {
                state.roster.ended.insert(
                    e.binding,
                    EndedBinding {
                        binding: b,
                        bar: e.barred_through,
                        ended,
                    },
                );
            }
            Ok(())
        }
        Record::BindingSuspended(s) => fold_suspension(state, s),
        Record::BindingVoided(v) => fold_void(state, v),
        Record::BindingReinstated(r) => fold_reinstatement(state, r),
        Record::BindingEndScheduled { binding, at } => {
            let b = state
                .roster
                .bindings
                .get_mut(binding)
                .ok_or(FoldError::UnknownEntity)?;
            if b.voided() || b.group() == Group::Receiving {
                return Err(FoldError::Inconsistent);
            }
            b.scheduled_end = Some(*at);
            Ok(())
        }
        Record::VaultEpochProcessed { epoch } => {
            if *epoch <= state.epoch {
                return Err(FoldError::Inconsistent);
            }
            state.epoch = *epoch;
            Ok(())
        }
        _ => Err(FoldError::Inconsistent),
    }
}

/// The next fold position for the grant or end of a binding of `group`:
/// a fresh one for Judging, and 0 for every other group (I-02 reads it).
fn judging_tick(state: &mut State, group: Group) -> u64 {
    if group == Group::Judging {
        state.roster.tick()
    } else {
        0
    }
}

/// Folds one `BindingSuspended`.
///
/// - The conflict-of-interest marker (rule I-06 on a Judging binding)
///   applies to a binding not voided, held or ended, that is not under the
///   marker already (Identity discovery, decided 2026-10-25). An ordinary
///   suspension it lands on is kept beneath the marker.
/// - An ordinary suspension applies to any binding not voided, held or
///   ended. On a binding under the marker it is kept beneath the marker.
///   On a binding already under an ordinary suspension it replaces the
///   rule. The reference keeps one pending ordinary suspension, so one
///   reinstatement lifts it, however many records led to it.
///
/// Reinstating the marker falls back to the suspension beneath it, which
/// stays pending resolution (enforcement point 3). A voided binding takes
/// no suspension, and the marker never lands twice. Each marker is
/// recorded as an identity discovery.
fn fold_suspension(state: &mut State, s: &BindingSuspended) -> Result<(), FoldError> {
    let b = match state.roster.bindings.get_mut(&s.binding) {
        Some(b) => b,
        None => {
            &mut state
                .roster
                .ended
                .get_mut(&s.binding)
                .ok_or(FoldError::UnknownEntity)?
                .binding
        }
    };
    let marker = s.rule == RuleRef::I06 && b.group() == Group::Judging;
    match (b.status, marker) {
        (BindingStatus::Voided(_), _) => return Err(FoldError::Inconsistent),
        (BindingStatus::Suspended(_), true) if b.conflict_of_interest() => {
            return Err(FoldError::Inconsistent);
        }
        (BindingStatus::Suspended(prior), true) => {
            b.suspended_beneath = Some(prior);
            b.status = BindingStatus::Suspended(s.rule);
        }
        (BindingStatus::Suspended(_), false) if b.conflict_of_interest() => {
            b.suspended_beneath = Some(s.rule);
        }
        (BindingStatus::Active | BindingStatus::Suspended(_), _) => {
            b.status = BindingStatus::Suspended(s.rule);
        }
    }
    if marker {
        let d = IdentityDiscovery::ConflictOfInterest {
            binding: s.binding,
            account: b.account,
            programme: b.programme,
            role: b.role,
            epoch: s.epoch,
        };
        state.roster.discovered(d);
    }
    Ok(())
}

/// Folds one `BindingReinstated`. It lifts one suspension: the conflict of
/// interest first, which falls back to the ordinary suspension beneath it.
fn fold_reinstatement(state: &mut State, r: &BindingReinstated) -> Result<(), FoldError> {
    let b = state
        .roster
        .bindings
        .get_mut(&r.binding)
        .ok_or(FoldError::UnknownEntity)?;
    if !matches!(b.status, BindingStatus::Suspended(_)) {
        return Err(FoldError::Inconsistent);
    }
    b.status = match b.suspended_beneath.take() {
        Some(prior) => BindingStatus::Suspended(prior),
        None => BindingStatus::Active,
    };
    Ok(())
}

/// Folds one `BindingVoided`: a held Receiving binding, or an ended one
/// whose bar still counts (Identity discovery: voided bindings pin no
/// bar). A void under I-06 is recorded as an identity discovery.
fn fold_void(state: &mut State, v: &BindingVoided) -> Result<(), FoldError> {
    let b = match state.roster.bindings.get_mut(&v.binding) {
        Some(b) => b,
        None => {
            &mut state
                .roster
                .ended
                .get_mut(&v.binding)
                .ok_or(FoldError::UnknownEntity)?
                .binding
        }
    };
    if !b.held() || b.group() != Group::Receiving {
        return Err(FoldError::Inconsistent);
    }
    b.status = BindingStatus::Voided(v.rule);
    let discovery = match (v.rule, b.proposal()) {
        (RuleRef::I06, Some(proposal)) => Some(IdentityDiscovery::ReceivingVoided {
            binding: v.binding,
            account: b.account,
            proposal,
            epoch: v.epoch,
        }),
        _ => None,
    };
    if let Some(d) = discovery {
        state.roster.discovered(d);
    }
    Ok(())
}

/// Folds one `BindingGranted`. A Receiving role must be scoped to a
/// created proposal of its call, and every other role to the programme.
fn fold_grant(state: &mut State, g: &BindingGranted) -> Result<(), FoldError> {
    if state.used_ids.contains(UsedId::Binding(g.binding))
        || state.roster.bindings.contains_key(&g.binding)
    {
        return Err(FoldError::DuplicateId);
    }
    if state.policy.programme(g.programme).is_none() {
        return Err(FoldError::UnknownEntity);
    }
    match (g.role.group(), g.scope) {
        (Group::Receiving, BindingScope::Proposal { proposal, call }) => {
            let created = crate::proposal::draft::proposal_call(state, proposal)
                .ok_or(FoldError::UnknownEntity)?;
            let programme = crate::programme::call(state, call)
                .map(crate::programme::CallView::programme)
                .ok_or(FoldError::UnknownEntity)?;
            if created != call || programme != g.programme {
                return Err(FoldError::Inconsistent);
            }
        }
        (Group::Receiving, BindingScope::Programme) | (_, BindingScope::Proposal { .. }) => {
            return Err(FoldError::Inconsistent);
        }
        (_, BindingScope::Programme) => {}
    }
    // The opening, read before the grant record in ledger order.
    let opened = match g.scope {
        BindingScope::Proposal { call, .. } => call_seq(state, call),
        BindingScope::Programme => latest(state, g.programme),
    };
    state.used_ids.insert(UsedId::Binding(g.binding));
    let granted = judging_tick(state, g.role.group());
    state.roster.bindings.insert(
        g.binding,
        Binding {
            account: g.account,
            programme: g.programme,
            role: g.role,
            scope: g.scope,
            start: g.start,
            opened,
            status: BindingStatus::Active,
            suspended_beneath: None,
            granted,
            organisation: g.organisation,
            scheduled_end: None,
        },
    );
    // I-67, Q1 A: a grantor on a draft programme is one of its builders.
    crate::programme::note_builder(&mut state.calls, g.programme, g.granted_by);
    Ok(())
}

/// The vault questions this lane needs for its contribution to the batch of
/// a command that another lane owns. It reads only the state and the command.
pub(crate) fn contribute_queries(
    state: &State,
    cmd: &Command,
    ctx: &Ctx,
) -> Result<Vec<Query>, Refusal> {
    let mut out = match plan_receiving(state, cmd, ctx)? {
        Some(plan) => plan.queries(),
        None => Vec::new(),
    };
    out.extend(p13_rechecks(state, cmd).into_iter().map(|(_, q)| q));
    Ok(out)
}

/// The records this lane adds to the batch of a command that another lane
/// owns, given the records so far (`crate::engine` module docs): the
/// Receiving binding of a draft command, the voids of a P-13 edit, and the
/// end of Receiving bindings at a terminal state.
pub(crate) fn contribute(
    state: &State,
    cmd: &Command,
    ctx: &Ctx,
    answers: &Answers,
    batch: &[Record],
) -> Result<Vec<Record>, Refusal> {
    let mut out = match plan_receiving(state, cmd, ctx)? {
        Some(plan) => decide_receiving(plan, answers)?,
        None => Vec::new(),
    };
    let mut voids = Vec::new();
    for (binding, q) in p13_rechecks(state, cmd) {
        let a = answer(answers, &q)?;
        record_outcome(&mut out, batch, &q, a);
        if a.holds {
            voids.push(Record::BindingVoided(BindingVoided {
                binding,
                rule: RuleRef::I04,
                epoch: a.epoch,
            }));
        }
    }
    out.extend(voids);
    let ends = terminal_ends(state, ctx.now, batch, &out)?;
    out.extend(ends);
    Ok(out)
}

/// The policy whose P-77 governs a binding action of this lane through MCP
/// (R-MC-05). None does: the role commands are high risk and never
/// complete through MCP (I-85), and `VaultChanged` has a System actor.
pub(crate) fn governing_policy(state: &State, cmd: &Command) -> Result<PolicyScope, Refusal> {
    let _ = state;
    match cmd {
        Command::GrantRole { .. } | Command::EndRole { .. } | Command::ReinstateBinding { .. } => {
            Err(Refusal::new(RuleRef::I85, RefusalReason::NotThroughMcp))
        }
        Command::VaultChanged { .. } | Command::EndScheduledRole { .. } => {
            Err(Refusal::new(RuleRef::Actor, RefusalReason::WrongActor))
        }
        _ => Err(wrong_state()),
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code"
)]
mod tests {
    //! These tests reach the private terminal end rule directly. No lane
    //! records a terminal `Transitioned` yet, so the testkit cannot drive
    //! this path through the engine.

    use super::*;
    use crate::command::Actor;
    use crate::id::ProposalId;
    use crate::record::Transitioned;
    use crate::rules::{Row, StateTag};

    const P: ProposalId = ProposalId::from_raw(10);
    const CALL: CallId = CallId::from_raw(20);
    const ID: BindingId = BindingId::from_raw(30);
    const LEAD: AccountId = AccountId::from_raw(40);

    /// A state whose roster holds one active Applicant binding of `P`.
    fn state_with_applicant() -> State {
        let mut state = State::genesis();
        state.roster.bindings.insert(
            ID,
            Binding {
                account: LEAD,
                programme: ProgrammeId::from_raw(1),
                role: Role::Applicant,
                scope: BindingScope::Proposal {
                    proposal: P,
                    call: CALL,
                },
                start: Timestamp::from_micros(1),
                opened: 1,
                status: BindingStatus::Active,
                suspended_beneath: None,
                granted: 0,
                scheduled_end: None,
                organisation: None,
            },
        );
        state
    }

    /// The move of `P` from NEGOTIATION to DECLINED.
    fn declined() -> Record {
        Record::Transitioned(Transitioned {
            proposal: P,
            from: StateTag::Negotiation,
            to: StateTag::Declined,
            row: Row::NegotiationToDeclined,
            actor: Actor::Account(LEAD),
            decision: None,
        })
    }

    /// I-01, Identity discovery: a Receiving binding that the same batch
    /// voids gets no end when its proposal reaches a terminal state. A
    /// voided binding pins no bar, and the fold refuses to end it.
    #[test]
    fn i01_terminal_end_skips_a_binding_voided_in_the_batch() {
        let state = state_with_applicant();
        let void = Record::BindingVoided(BindingVoided {
            binding: ID,
            rule: RuleRef::I06,
            epoch: VaultEpoch::from_raw(2),
        });
        let now = Timestamp::from_micros(5);
        let from_batch = terminal_ends(&state, now, &[void.clone(), declined()], &[]);
        assert_eq!(from_batch, Ok(Vec::new()), "void earlier in the batch");
        let from_own = terminal_ends(&state, now, &[declined()], &[void]);
        assert_eq!(from_own, Ok(Vec::new()), "void in this lane's records");
    }
}
