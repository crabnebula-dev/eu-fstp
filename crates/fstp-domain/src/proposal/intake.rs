//! Proposal intake: `RecordPlanVersion`, `Submit` and `Withdraw` (design sections 2.8 and 3.2).
//!
//! Written by lane L-REV in step W4a. Lane L-LIFE extends the lifecycle
//! around it and reuses the shared fold of `Transitioned` kept here.
//!
//! - [`Intake`] keeps the proposal states that differ from DRAFT, the call
//!   each proposal is evaluated in, the plan versions and the submissions.
//!   A created proposal with no transition yet is in DRAFT.
//! - `RecordPlanVersion` of origin "submitted" is the lead's, in DRAFT. It
//!   needs fresh plan and milestone ids, at least one task, a milestone in
//!   every task, start dates no later than due dates and amounts in the
//!   programme currency (ADR-006). The plans of a proposal form one chain:
//!   a new plan supersedes the live plan when one exists, and nothing
//!   otherwise. The plan text lives outside the domain, which keeps
//!   amounts, structure and a digest only (R-SB-01). The other origins
//!   belong to lane L-LIFE and lane L-MONEY. Here they are refused in DRAFT,
//!   SUBMITTED and terminal states, and refused as not implemented elsewhere.
//! - `Submit` takes the DRAFT to SUBMITTED row. It needs the lead with an
//!   active Applicant binding, a call open at `now`, and a plan of the
//!   proposal with origin "submitted" that no later plan supersedes and that
//!   has its required fields. It needs no guardian record (R-SB-02) and asks
//!   the vault nothing. It records the ethics declaration and the notice
//!   version (R-SB-05, R-NG-06) and the transition.
//! - `Withdraw` takes row 15 from the eight withdrawable states (NOTE 10).
//!   It records the transition to WITHDRAWN from this lane's own decide, so
//!   lane L-SOD's contribution ends the Receiving bindings in the same batch
//!   (Q11 A). Lane L-MONEY's contribution releases any reservation.
//! - The fold of `Transitioned` checks the row against
//!   [`crate::rules::TRANSITIONS`] and the state it leaves. It never re-runs
//!   a guard.
//!
//! Readings of this lane, reported to Daniel:
//!
//! - "Required fields present" means at least one task, each with at least
//!   one milestone. A plan without them is refused when it is recorded.
//! - A superseded plan cannot be submitted. Only the latest version of the
//!   submission counts, and the chain rule keeps one latest version.
//! - Assignments on a withdrawn proposal stay as they are. No release cause
//!   names a closed proposal, and `crate::assignment` builds no reviewer
//!   act on a terminal proposal.

use std::collections::{BTreeMap, BTreeSet};

use crate::command::{Command, Ctx};
use crate::engine::{FoldError, PolicyScope};
use crate::id::{CallId, ContentDigest, MilestoneId, PlanVersionId, ProposalId};
use crate::oracle::{Answers, Query};
use crate::proposal::{EthicsDeclaration, NoticeVersion, PlanOrigin, Task};
use crate::record::{PlanVersionRecorded, Record, Transitioned};
use crate::refusal::{Refusal, RefusalReason, RuleRef};
use crate::roles::Role;
use crate::rules::{Row, StateTag, TRANSITIONS};
use crate::state::{State, UsedId};

/// Where one proposal stands after its first transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Life {
    /// The proposal state.
    pub(crate) state: StateTag,
    /// The call the proposal is evaluated in: its creation call, or the
    /// call of its latest re-entry, which lane L-LIFE sets (NOTE 8).
    pub(crate) current_call: CallId,
}

/// One plan version.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Plan {
    /// The proposal.
    pub(crate) proposal: ProposalId,
    /// Where it comes from.
    pub(crate) origin: PlanOrigin,
    /// Whether a later plan supersedes it.
    pub(crate) superseded: bool,
    /// Tasks with their milestones. Totals are derived, never stored.
    pub(crate) tasks: Vec<Task>,
    /// Digest of the plan text held outside the domain.
    pub(crate) content: ContentDigest,
}

/// What a submission recorded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Submission {
    /// The submitted plan.
    pub(crate) plan: PlanVersionId,
    /// The ethics self-declaration (R-SB-05).
    pub(crate) ethics: EthicsDeclaration,
    /// The data protection notice version shown (R-NG-06).
    pub(crate) notice: NoticeVersion,
}

/// Intake part of the proposal store.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Intake {
    /// Proposals that left DRAFT at least once, with their state and call.
    lives: BTreeMap<ProposalId, Life>,
    /// Plan versions.
    plans: BTreeMap<PlanVersionId, Plan>,
    /// Submissions.
    submissions: BTreeMap<ProposalId, Submission>,
}

impl Intake {
    /// No plan, no submission and no transition yet.
    pub(crate) const fn genesis() -> Intake {
        Intake {
            lives: BTreeMap::new(),
            plans: BTreeMap::new(),
            submissions: BTreeMap::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// The read API for other lanes
// ---------------------------------------------------------------------------

/// The state of the created proposal `proposal`, or `None` for an unknown one.
pub(crate) fn proposal_state(state: &State, proposal: ProposalId) -> Option<StateTag> {
    crate::proposal::draft::draft(state, proposal)?;
    Some(
        state
            .proposals
            .intake
            .lives
            .get(&proposal)
            .map_or(StateTag::Draft, |l| l.state),
    )
}

/// The call `proposal` is evaluated in now: its creation call, or the call
/// of its latest re-entry (NOTE 8). `None` for an unknown proposal.
pub(crate) fn current_call(state: &State, proposal: ProposalId) -> Option<CallId> {
    let created = crate::proposal::draft::proposal_call(state, proposal)?;
    Some(
        state
            .proposals
            .intake
            .lives
            .get(&proposal)
            .map_or(created, |l| l.current_call),
    )
}

/// The plan version `plan`.
#[allow(dead_code, reason = "lanes L-LIFE and L-MONEY read plans")]
pub(crate) fn plan(state: &State, plan: PlanVersionId) -> Option<&Plan> {
    state.proposals.intake.plans.get(&plan)
}

/// The submission of `proposal`, once submitted.
#[allow(dead_code, reason = "lanes L-LIFE and L-MONEY read submissions")]
pub(crate) fn submission(state: &State, proposal: ProposalId) -> Option<&Submission> {
    state.proposals.intake.submissions.get(&proposal)
}

/// Every proposal that left DRAFT, with its state and current call.
/// Proposals still in DRAFT are not listed.
pub(crate) fn submitted_proposals(
    state: &State,
) -> impl Iterator<Item = (ProposalId, StateTag, CallId)> + '_ {
    state
        .proposals
        .intake
        .lives
        .iter()
        .map(|(p, l)| (*p, l.state, l.current_call))
}

/// The total of the plan's milestone amounts, or `None` when the plan has
/// no milestone or the sum fails (ADR-006).
pub(crate) fn plan_total(plan: &Plan) -> Option<fstp_money::NonNegAmount> {
    tasks_total(&plan.tasks)
}

/// The total of the milestone amounts in `tasks`, or `None` when there is
/// no milestone or the sum leaves the money range (ADR-006).
fn tasks_total(tasks: &[Task]) -> Option<fstp_money::NonNegAmount> {
    let mut total: Option<fstp_money::Amount> = None;
    for m in tasks.iter().flat_map(|t| t.milestones.iter()) {
        let a = m.amount.amount();
        total = Some(match total {
            None => a,
            Some(t) => t.checked_add(a).ok()?,
        });
    }
    fstp_money::NonNegAmount::new(total?).ok()
}

// ---------------------------------------------------------------------------
// Guards
// ---------------------------------------------------------------------------

/// The refusal of an unknown entity.
const fn unknown() -> Refusal {
    Refusal::new(RuleRef::Input, RefusalReason::UnknownEntity)
}

/// The refusal of a shell-supplied id that is already taken.
const fn reused() -> Refusal {
    Refusal::new(RuleRef::Ledger, RefusalReason::IdReused)
}

/// The refusal of a command the proposal's state does not admit.
const fn wrong_row() -> Refusal {
    Refusal::new(RuleRef::Row, RefusalReason::WrongState)
}

/// The refusal of a value the command may not carry.
const fn invalid() -> Refusal {
    Refusal::new(RuleRef::Input, RefusalReason::InvalidValue)
}

/// Refuses unless the actor is the lead of `proposal` with an active
/// Applicant binding on it (enforcement point 2).
fn require_lead(state: &State, proposal: ProposalId, ctx: &Ctx) -> Result<(), Refusal> {
    let actor = crate::policy::actor_account(ctx)?;
    let d = crate::proposal::draft::draft(state, proposal).ok_or_else(unknown)?;
    let active = state
        .roster
        .active_receiving(actor, Role::Applicant, proposal, ctx.now)
        .is_some();
    if d.lead != actor || !active {
        return Err(Refusal::new(RuleRef::Actor, RefusalReason::BindingInactive));
    }
    Ok(())
}

/// Whether the plan has its required fields: at least one task, and at
/// least one milestone in every task.
fn complete(tasks: &[Task]) -> bool {
    !tasks.is_empty() && tasks.iter().all(|t| !t.milestones.is_empty())
}

/// Checks the structure of a submitted plan: required fields, fresh and
/// distinct milestone ids, start no later than due, amounts in the
/// programme currency of `proposal`, and a total inside the money range
/// (ADR-006).
fn check_tasks(state: &State, proposal: ProposalId, tasks: &[Task]) -> Result<(), Refusal> {
    if !complete(tasks) {
        return Err(invalid());
    }
    let call = crate::proposal::draft::proposal_call(state, proposal).ok_or_else(unknown)?;
    let programme = crate::programme::call(state, call)
        .map(crate::programme::CallView::programme)
        .ok_or_else(unknown)?;
    let currency = crate::policy::programme_currency(state, programme).ok_or_else(unknown)?;
    let mut seen: BTreeSet<MilestoneId> = BTreeSet::new();
    for m in tasks.iter().flat_map(|t| t.milestones.iter()) {
        if state.used_ids.contains(UsedId::Milestone(m.id)) || !seen.insert(m.id) {
            return Err(reused());
        }
        if m.start > m.due || m.amount.amount().currency() != currency {
            return Err(invalid());
        }
    }
    if tasks_total(tasks).is_none() {
        return Err(invalid());
    }
    Ok(())
}

/// The plan of `proposal` that no later plan supersedes, if any.
fn live_plan(state: &State, proposal: ProposalId) -> Option<PlanVersionId> {
    state
        .proposals
        .intake
        .plans
        .iter()
        .find(|(_, p)| p.proposal == proposal && !p.superseded)
        .map(|(id, _)| *id)
}

/// Checks that a new plan of `proposal` keeps one chain of versions: it
/// supersedes the live plan when one exists, and nothing otherwise. So at
/// most one plan of a proposal is live, and only the latest version counts.
fn check_chain(
    state: &State,
    proposal: ProposalId,
    supersedes: Option<PlanVersionId>,
) -> Result<(), Refusal> {
    if supersedes == live_plan(state, proposal) {
        Ok(())
    } else {
        Err(invalid())
    }
}

/// Checks a `RecordPlanVersion` and returns its record.
fn check_plan(state: &State, cmd: &Command, ctx: &Ctx) -> Result<Vec<Record>, Refusal> {
    let Command::RecordPlanVersion {
        plan,
        proposal,
        origin,
        supersedes,
        tasks,
        content,
    } = cmd
    else {
        return Err(wrong_row());
    };
    let current = proposal_state(state, *proposal).ok_or_else(unknown)?;
    require_lead(state, *proposal, ctx)?;
    if state.used_ids.contains(UsedId::PlanVersion(*plan)) {
        return Err(reused());
    }
    check_chain(state, *proposal, *supersedes)?;
    match origin {
        PlanOrigin::Submitted if current != StateTag::Draft => return Err(wrong_row()),
        PlanOrigin::Submitted => {}
        _ if matches!(current, StateTag::Draft | StateTag::Submitted) || current.is_terminal() => {
            return Err(wrong_row());
        }
        // Stage 2 revisions, negotiated plans and amendments are lanes
        // L-LIFE and L-MONEY.
        _ => return Err(Refusal::not_implemented()),
    }
    check_tasks(state, *proposal, tasks)?;
    Ok(vec![Record::PlanVersionRecorded(PlanVersionRecorded {
        plan: *plan,
        proposal: *proposal,
        origin: *origin,
        supersedes: *supersedes,
        tasks: tasks.clone(),
        content: *content,
    })])
}

/// Checks a `Submit` and returns its records (DRAFT to SUBMITTED).
fn check_submit(state: &State, cmd: &Command, ctx: &Ctx) -> Result<Vec<Record>, Refusal> {
    let Command::Submit {
        proposal,
        plan,
        ethics,
        notice,
    } = cmd
    else {
        return Err(wrong_row());
    };
    let current = proposal_state(state, *proposal).ok_or_else(unknown)?;
    require_lead(state, *proposal, ctx)?;
    if current != StateTag::Draft {
        return Err(wrong_row());
    }
    let call = crate::proposal::draft::proposal_call(state, *proposal).ok_or_else(unknown)?;
    if !crate::programme::is_open_at(state, call, ctx.now) {
        return Err(Refusal::new(RuleRef::Row, RefusalReason::GuardFailed));
    }
    let p = state.proposals.intake.plans.get(plan).ok_or_else(unknown)?;
    if p.proposal != *proposal || p.origin != PlanOrigin::Submitted || p.superseded {
        return Err(invalid());
    }
    if !complete(&p.tasks) {
        return Err(Refusal::new(RuleRef::Row, RefusalReason::GuardFailed));
    }
    Ok(vec![
        Record::Submitted {
            proposal: *proposal,
            plan: *plan,
            ethics: *ethics,
            notice: *notice,
        },
        Record::Transitioned(Transitioned {
            proposal: *proposal,
            from: StateTag::Draft,
            to: StateTag::Submitted,
            row: Row::DraftToSubmitted,
            actor: ctx.actor,
            decision: None,
        }),
    ])
}

/// Checks a `Withdraw` and returns its transition (row 15, NOTE 10).
fn check_withdraw(state: &State, cmd: &Command, ctx: &Ctx) -> Result<Vec<Record>, Refusal> {
    let Command::Withdraw { proposal } = cmd else {
        return Err(wrong_row());
    };
    let current = proposal_state(state, *proposal).ok_or_else(unknown)?;
    require_lead(state, *proposal, ctx)?;
    if !current.is_withdrawable() {
        return Err(wrong_row());
    }
    Ok(vec![Record::Transitioned(Transitioned {
        proposal: *proposal,
        from: current,
        to: StateTag::Withdrawn,
        row: Row::Withdraw,
        actor: ctx.actor,
        decision: None,
    })])
}

/// Checks one of the three commands and returns its records.
fn check(state: &State, cmd: &Command, ctx: &Ctx) -> Result<Vec<Record>, Refusal> {
    match cmd {
        Command::RecordPlanVersion { .. } => check_plan(state, cmd, ctx),
        Command::Submit { .. } => check_submit(state, cmd, ctx),
        Command::Withdraw { .. } => check_withdraw(state, cmd, ctx),
        _ => Err(wrong_row()),
    }
}

// ---------------------------------------------------------------------------
// Engine entry points, called by `crate::proposal`
// ---------------------------------------------------------------------------

/// Whether `cmd` is one of the commands this module decides.
pub(crate) const fn is_intake_command(cmd: &Command) -> bool {
    matches!(
        cmd,
        Command::RecordPlanVersion { .. } | Command::Submit { .. } | Command::Withdraw { .. }
    )
}

/// Whether `record` is one of the records this module folds.
pub(crate) const fn is_intake_record(record: &Record) -> bool {
    matches!(
        record,
        Record::PlanVersionRecorded(_) | Record::Submitted { .. } | Record::Transitioned(_)
    )
}

/// The vault questions of the three commands. They ask none (R-SB-01:
/// no identity data is needed before negotiation).
pub(crate) fn queries(state: &State, cmd: &Command, ctx: &Ctx) -> Result<Vec<Query>, Refusal> {
    check(state, cmd, ctx)?;
    Ok(Vec::new())
}

/// The records of the three commands.
pub(crate) fn decide(
    state: &State,
    cmd: &Command,
    ctx: &Ctx,
    answers: &Answers,
) -> Result<Vec<Record>, Refusal> {
    let _ = answers;
    check(state, cmd, ctx)
}

/// Folds `PlanVersionRecorded`, `Submitted` and `Transitioned`. The fold
/// checks structure only.
pub(crate) fn apply(state: &mut State, record: &Record) -> Result<(), FoldError> {
    match record {
        Record::PlanVersionRecorded(p) => fold_plan(state, p),
        Record::Submitted {
            proposal,
            plan,
            ethics,
            notice,
        } => {
            proposal_state(state, *proposal).ok_or(FoldError::UnknownEntity)?;
            let p = state
                .proposals
                .intake
                .plans
                .get(plan)
                .ok_or(FoldError::UnknownEntity)?;
            if p.proposal != *proposal || state.proposals.intake.submissions.contains_key(proposal)
            {
                return Err(FoldError::Inconsistent);
            }
            state.proposals.intake.submissions.insert(
                *proposal,
                Submission {
                    plan: *plan,
                    ethics: *ethics,
                    notice: *notice,
                },
            );
            Ok(())
        }
        Record::Transitioned(t) => fold_transition(state, t),
        _ => Err(FoldError::Inconsistent),
    }
}

/// Folds one plan version.
fn fold_plan(state: &mut State, p: &PlanVersionRecorded) -> Result<(), FoldError> {
    proposal_state(state, p.proposal).ok_or(FoldError::UnknownEntity)?;
    if state.used_ids.contains(UsedId::PlanVersion(p.plan))
        || state.proposals.intake.plans.contains_key(&p.plan)
    {
        return Err(FoldError::DuplicateId);
    }
    let mut seen = BTreeSet::new();
    for m in p.tasks.iter().flat_map(|t| t.milestones.iter()) {
        if state.used_ids.contains(UsedId::Milestone(m.id)) || !seen.insert(m.id) {
            return Err(FoldError::DuplicateId);
        }
    }
    if let Some(s) = p.supersedes {
        let old = state
            .proposals
            .intake
            .plans
            .get_mut(&s)
            .ok_or(FoldError::UnknownEntity)?;
        if old.proposal != p.proposal || old.superseded {
            return Err(FoldError::Inconsistent);
        }
        old.superseded = true;
    }
    state.used_ids.insert(UsedId::PlanVersion(p.plan));
    for m in seen {
        state.used_ids.insert(UsedId::Milestone(m));
    }
    state.proposals.intake.plans.insert(
        p.plan,
        Plan {
            proposal: p.proposal,
            origin: p.origin,
            superseded: false,
            tasks: p.tasks.clone(),
            content: p.content,
        },
    );
    Ok(())
}

/// Folds one transition: the row must exist in the transitions table with
/// these endpoints, and the proposal must be in the state it leaves.
/// Lane L-LIFE uses this fold for every row it records.
pub(crate) fn fold_transition(state: &mut State, t: &Transitioned) -> Result<(), FoldError> {
    let current = proposal_state(state, t.proposal).ok_or(FoldError::UnknownEntity)?;
    let call = current_call(state, t.proposal).ok_or(FoldError::UnknownEntity)?;
    let known = TRANSITIONS
        .iter()
        .any(|r| r.row == t.row && r.to == t.to && r.from.contains(&t.from));
    if !known || current != t.from {
        return Err(FoldError::Inconsistent);
    }
    state.proposals.intake.lives.insert(
        t.proposal,
        Life {
            state: t.to,
            current_call: call,
        },
    );
    Ok(())
}

/// The policy whose P-77 governs `Submit` and `Withdraw` through MCP: the
/// frozen policy of the proposal's call (R-MC-05). `RecordPlanVersion`
/// prepares a plan and is not a binding action.
pub(crate) fn governing_policy(state: &State, cmd: &Command) -> Result<PolicyScope, Refusal> {
    match cmd {
        Command::RecordPlanVersion { proposal, .. }
        | Command::Submit { proposal, .. }
        | Command::Withdraw { proposal } => crate::proposal::draft::proposal_call(state, *proposal)
            .map(PolicyScope::Call)
            .ok_or_else(unknown),
        _ => Err(wrong_row()),
    }
}
