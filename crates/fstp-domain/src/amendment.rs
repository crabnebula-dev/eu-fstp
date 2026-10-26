//! Amendments (design section 2.11, I-13, I-14, I-15).
//!
//! Owned by lane L-MONEY (docs/handoff/m2-design.md section 10). The rules
//! come from `SPEC/02-domain/state-machine.md` Amendments and
//! `SPEC/02-domain/contracts.md` (Rules, Repeat grants and amendments),
//! decided 2026-10-25.
//!
//! An amendment is a separate workflow on a GRANTED or IN_EXECUTION
//! proposal, and the proposal state never changes:
//!
//! - `ProposeAmendment`, by the lead or an assigned reviewer of the grant
//!   with a [`crate::assignment::ReviewerAct`], names a plan of origin
//!   "amendment" of the grant. The plan is the live version of the chain,
//!   and no other amendment names it.
//! - `RouteAmendment`, by the programme manager, who decides whether a
//!   P-14 exemption applies.
//! - `ActivateAmendment`, by the System on the M5 contract-version fact.
//!   It needs the I-15 record of the identity's earlier grants and of this
//!   grant itself, the amended total within P-04 (I-13), and the vault's
//!   answer that the amended total keeps the recipient within the cap
//!   (I-14). The plan must still be the live version. Every milestone with
//!   a paid or pending amount stays in the amended plan under its id, at
//!   no less than that amount (I-31, I-58, I-61). The amended total then
//!   counts against P-05.
//!
//! An IRC route needs the IRC review of the amendment first (R-IR-04, step
//! W5 integration):
//!
//! - The FSTP coordinator assigns IRC members with `Assign` of kind
//!   `AssignmentKind::Amendment`. It names an amendment of the same grant
//!   that is routed to IRC review, not activated and without a concern, on
//!   a GRANTED or IN_EXECUTION grant. The rules of an IRC assignment apply
//!   (`crate::assignment`).
//! - Each assignee declares on the assignment, then records one
//!   `RecordIrcReview` on it with a [`crate::assignment::ReviewerAct`]
//!   (`crate::decision`). The batch holds no transition and no deferral,
//!   since the proposal state never changes (Q18).
//! - Activation needs at least P-15 active amendment assignments, every
//!   one validated, none awaiting its declaration, and no concern (R-IR-01
//!   read for amendments).
//!
//! Readings of this step, reported to Daniel:
//!
//! - A concern ends the IRC review of the amendment for good. No later
//!   review or assignment is taken, and the amendment cannot be activated.
//!   The grant keeps its state and its counted amount.
//! - A concern on an amendment enqueues no notification. The outbox event
//!   of an IRC concern names a proposal in IRC_REVIEW, and M6 owns a
//!   notification of its own for amendments.

use std::collections::BTreeMap;

use crate::assignment::AssignmentKind;
use crate::command::{Command, Ctx};
use crate::engine::{FoldError, PolicyScope};
use fstp_money::PosAmount;

use crate::grant::{
    at_most, cap_query, clear_repeat, guard, inactive, invalid, plan_total, record_answer,
    record_complete, repeat_check, reused, subject, unknown, vault, wrong_state,
};
use crate::id::{
    AccountId, AmendmentId, AssignmentId, ContractId, MilestoneId, PlanVersionId, ProposalId,
};
use crate::oracle::{Answers, Query};
use crate::proposal::PlanOrigin;
use crate::record::Record;
use crate::refusal::{Refusal, RuleRef};
use crate::roles::Role;
use crate::rules::StateTag;
use crate::state::{State, UsedId};

/// How an amendment is reviewed. The programme manager decides whether a
/// P-14 exemption applies (`SPEC/02-domain/state-machine.md` Amendments).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AmendmentRoute {
    /// A P-14 exemption applies, so IRC review is skipped (R-IR-04).
    Exempt,
    /// IRC review applies.
    Irc,
}

/// One amendment of the projection.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Amendment {
    /// The grant.
    pub(crate) grant: ProposalId,
    /// The amended plan.
    pub(crate) plan: PlanVersionId,
    /// The route, once routed.
    pub(crate) route: Option<AmendmentRoute>,
    /// Whether it was activated.
    pub(crate) activated: bool,
    /// The IRC reviews recorded on its amendment assignments: `true` for a
    /// validation, `false` for a concern (R-IR-04).
    pub(crate) reviews: BTreeMap<AssignmentId, bool>,
}

impl Amendment {
    /// Whether a concern was recorded on the amendment.
    fn concern(&self) -> bool {
        self.reviews.values().any(|ok| !*ok)
    }
}

/// The amendment `id`.
fn amendment_of(state: &State, id: AmendmentId) -> Result<&Amendment, Refusal> {
    state.money.amendments.get(&id).ok_or_else(unknown)
}

/// Whether the proposal is in GRANTED or IN_EXECUTION.
const fn amendable(s: StateTag) -> bool {
    matches!(s, StateTag::Granted | StateTag::InExecution)
}

// ---------------------------------------------------------------------------
// IRC review of an amendment (R-IR-04)
// ---------------------------------------------------------------------------

/// Refuses unless the amendment `id` of `grant` is under IRC review: it is
/// routed to IRC review, not activated and without a concern, and the
/// grant is in GRANTED or IN_EXECUTION.
fn under_irc_review(state: &State, id: AmendmentId, grant: ProposalId) -> Result<(), Refusal> {
    let a = amendment_of(state, id)?;
    if a.grant != grant {
        return Err(invalid());
    }
    if a.route != Some(AmendmentRoute::Irc) || a.activated || a.concern() {
        return Err(guard(RuleRef::Rir04));
    }
    if !amendable(subject(state, grant)?.state) {
        return Err(wrong_state());
    }
    Ok(())
}

/// Refuses an `Assign` of kind `AssignmentKind::Amendment(id)` on `grant`
/// unless the amendment is under IRC review. `crate::assignment` checks
/// every other rule of an IRC assignment.
pub(crate) fn check_irc_assignment(
    state: &State,
    id: AmendmentId,
    grant: ProposalId,
) -> Result<(), Refusal> {
    under_irc_review(state, id, grant)
}

/// Refuses a `RecordIrcReview` on the amendment assignment `assignment` of
/// amendment `id` on `grant` unless the amendment is under IRC review and
/// the assignment has no review yet (R-IR-01, R-IR-04). The caller checks
/// the assignee and builds the reviewer act.
pub(crate) fn check_irc_review(
    state: &State,
    id: AmendmentId,
    grant: ProposalId,
    assignment: AssignmentId,
) -> Result<(), Refusal> {
    under_irc_review(state, id, grant)?;
    if amendment_of(state, id)?.reviews.contains_key(&assignment) {
        return Err(guard(RuleRef::Rir01));
    }
    Ok(())
}

/// Folds the IRC review of amendment `id` on `assignment`. The fold checks
/// structure only: the amendment exists and the assignment has no review yet.
pub(crate) fn fold_irc_review(
    state: &mut State,
    id: AmendmentId,
    assignment: AssignmentId,
    validated: bool,
) -> Result<(), FoldError> {
    let a = state
        .money
        .amendments
        .get_mut(&id)
        .ok_or(FoldError::UnknownEntity)?;
    if a.reviews.contains_key(&assignment) {
        return Err(FoldError::Inconsistent);
    }
    a.reviews.insert(assignment, validated);
    Ok(())
}

/// Whether the IRC review of the amendment `id` on `grant` is complete
/// (R-IR-01 read for amendments, R-IR-04): no concern, at least P-15 active
/// amendment assignments, every one validated, and none awaiting its
/// declaration. Assignments whose assignee holds a conflict fact on the
/// grant count in neither.
fn irc_review_complete(state: &State, id: AmendmentId, a: &Amendment) -> Result<bool, Refusal> {
    if a.concern() {
        return Ok(false);
    }
    let p15 = crate::assignment::governing_values(state, a.grant)?.p15;
    let kind = AssignmentKind::Amendment(id);
    let mut active = 0_usize;
    for (assignment, x) in state.review.assignments() {
        if x.proposal != a.grant
            || x.kind != kind
            || !x.unreleased()
            || state.review.conflict_fact(x.reviewer, a.grant)
        {
            continue;
        }
        if !x.active() || a.reviews.get(&assignment) != Some(&true) {
            return Ok(false);
        }
        active = active.saturating_add(1);
    }
    Ok(active >= usize::from(p15.get()))
}

/// A checked `ProposeAmendment`: the proposer, and the reviewer's
/// `HasConflict` question when the proposer is not the lead.
struct ProposePlan {
    record: Record,
    grant: ProposalId,
    by: AccountId,
    conflict: Option<Query>,
}

fn check_propose(
    state: &State,
    id: AmendmentId,
    grant: ProposalId,
    plan: PlanVersionId,
    ctx: &Ctx,
) -> Result<ProposePlan, Refusal> {
    let by = crate::policy::actor_account(ctx)?;
    let s = subject(state, grant)?;
    let lead = s.lead == by
        && state
            .roster
            .active_receiving(by, Role::Applicant, grant, ctx.now)
            .is_some();
    let conflict = if lead {
        None
    } else {
        crate::assignment::qualifying_assignment(
            state,
            by,
            grant,
            AssignmentKind::Reviewer,
            ctx.now,
        )
        .ok_or_else(inactive)?;
        Some(crate::assignment::conflict_query(state, by, grant))
    };
    if !amendable(s.state) {
        return Err(wrong_state());
    }
    if state.money.amendments.contains_key(&id) || state.used_ids.contains(UsedId::Amendment(id)) {
        return Err(reused());
    }
    let ok = crate::proposal::intake::plan(state, plan)
        .is_some_and(|p| p.proposal == grant && p.origin == PlanOrigin::Amendment && !p.superseded);
    let named = state.money.amendments.values().any(|a| a.plan == plan);
    if !ok || named {
        return Err(invalid());
    }
    Ok(ProposePlan {
        record: Record::AmendmentProposed {
            amendment: id,
            grant,
            plan,
            by,
        },
        grant,
        by,
        conflict,
    })
}

/// Refuses an amended plan that drops a claimed milestone or sets its
/// amount below its paid plus pending amount (I-61). So the claims of the
/// grant stay on milestones of the effective contract version (I-59), no
/// milestone is claimed twice (I-58) and released payments never exceed
/// the contract amount (I-31). It is refused as an invalid value, as
/// I-58 is. Plan intake lets an amendment plan keep a milestone of the
/// effective contract version under its id.
fn keeps_claims(state: &State, grant: ProposalId, plan: PlanVersionId) -> Result<(), Refusal> {
    let amended: BTreeMap<MilestoneId, PosAmount> = crate::grant::plan_milestones(state, plan)
        .ok_or_else(unknown)?
        .into_iter()
        .map(|(m, amount, _)| (m, amount))
        .collect();
    for (m, claimed) in crate::payment::claimed(state, grant) {
        let Some(amount) = amended.get(&m) else {
            return Err(invalid());
        };
        if !at_most(claimed.amount(), amount.amount())? {
            return Err(invalid());
        }
    }
    Ok(())
}

/// A checked `ActivateAmendment` and its questions.
struct ActivatePlan {
    record: Record,
    grant: ProposalId,
    lead: AccountId,
    cap: Query,
    own_complete: bool,
}

fn check_activate(
    state: &State,
    id: AmendmentId,
    contract: ContractId,
) -> Result<ActivatePlan, Refusal> {
    let a = amendment_of(state, id)?;
    let route = a.route.ok_or_else(wrong_state)?;
    if a.activated {
        return Err(wrong_state());
    }
    let s = subject(state, a.grant)?;
    if !amendable(s.state) {
        return Err(wrong_state());
    }
    if route == AmendmentRoute::Irc && !irc_review_complete(state, id, a)? {
        return Err(guard(RuleRef::Rir04));
    }
    // Only the latest plan version counts, so a later plan of the grant
    // makes this amendment stale.
    let live = crate::proposal::intake::plan(state, a.plan).is_some_and(|p| !p.superseded);
    if !live {
        return Err(invalid());
    }
    let total = plan_total(state, a.plan).ok_or_else(unknown)?;
    let p04 = crate::assignment::governing_values(state, a.grant)?.p04;
    if !p04.contains(total).map_err(|_| invalid())? {
        return Err(guard(RuleRef::I13));
    }
    keeps_claims(state, a.grant, a.plan)?;
    Ok(ActivatePlan {
        record: Record::AmendmentActivated {
            amendment: id,
            plan: a.plan,
            route,
            contract,
        },
        grant: a.grant,
        lead: s.lead,
        cap: cap_query(state, a.grant, total)?,
        own_complete: record_complete(state, a.grant),
    })
}

// ---------------------------------------------------------------------------
// Engine entry points of this lane, called by `crate::engine`.
// ---------------------------------------------------------------------------

/// The vault questions of the amendment commands.
pub(crate) fn queries(state: &State, cmd: &Command, ctx: &Ctx) -> Result<Vec<Query>, Refusal> {
    match cmd {
        Command::ProposeAmendment {
            amendment,
            grant,
            plan,
        } => Ok(check_propose(state, *amendment, *grant, *plan, ctx)?
            .conflict
            .into_iter()
            .collect()),
        Command::RouteAmendment { amendment, .. } => {
            check_route(state, *amendment, ctx)?;
            Ok(Vec::new())
        }
        Command::ActivateAmendment {
            amendment,
            contract,
        } => {
            let plan = check_activate(state, *amendment, *contract)?;
            let (_, repeat) = repeat_check(state, plan.lead, plan.grant);
            let mut out: Vec<Query> = repeat.into_iter().collect();
            out.push(plan.cap);
            Ok(out)
        }
        _ => Err(wrong_state()),
    }
}

/// Checks a `RouteAmendment` and returns the programme manager.
fn check_route(state: &State, id: AmendmentId, ctx: &Ctx) -> Result<AccountId, Refusal> {
    let by = crate::policy::actor_account(ctx)?;
    let a = amendment_of(state, id)?;
    let s = subject(state, a.grant)?;
    crate::policy::require_holder(state, by, s.programme, &[Role::ProgrammeManager], ctx.now)?;
    if a.route.is_some() || a.activated {
        return Err(wrong_state());
    }
    Ok(by)
}

/// The records of the amendment commands.
pub(crate) fn decide(
    state: &State,
    cmd: &Command,
    ctx: &Ctx,
    answers: &Answers,
) -> Result<Vec<Record>, Refusal> {
    match cmd {
        Command::ProposeAmendment {
            amendment,
            grant,
            plan,
        } => {
            let p = check_propose(state, *amendment, *grant, *plan, ctx)?;
            let mut out = vec![p.record];
            if let Some(q) = &p.conflict {
                let act = crate::assignment::reviewer_act_on(
                    state,
                    p.by,
                    p.grant,
                    AssignmentKind::Reviewer,
                    ctx.now,
                    answers,
                )?;
                act.require_proposal(p.grant)?;
                record_answer(&mut out, q, answers)?;
            }
            Ok(out)
        }
        Command::RouteAmendment { amendment, route } => {
            let by = check_route(state, *amendment, ctx)?;
            Ok(vec![Record::AmendmentRouted {
                amendment: *amendment,
                route: *route,
                by,
            }])
        }
        Command::ActivateAmendment {
            amendment,
            contract,
        } => {
            let plan = check_activate(state, *amendment, *contract)?;
            let mut out = vec![plan.record];
            let repeat = clear_repeat(state, plan.lead, plan.grant, answers, &mut out)?;
            if repeat.is_none() || !plan.own_complete {
                return Err(guard(RuleRef::I15));
            }
            if !record_answer(&mut out, &plan.cap, answers)? {
                return Err(vault(RuleRef::I14));
            }
            Ok(out)
        }
        _ => Err(wrong_state()),
    }
}

/// Folds an amendment record. The fold checks structure only.
pub(crate) fn apply(
    state: &mut State,
    seq: fstp_ledger::Seq,
    at: crate::time::Timestamp,
    record: &Record,
) -> Result<(), FoldError> {
    let _ = (seq, at);
    match record {
        Record::AmendmentProposed {
            amendment,
            grant,
            plan,
            ..
        } => {
            crate::proposal::draft::draft(state, *grant).ok_or(FoldError::UnknownEntity)?;
            if state.money.amendments.contains_key(amendment)
                || !state.used_ids.insert(UsedId::Amendment(*amendment))
            {
                return Err(FoldError::DuplicateId);
            }
            state.money.amendments.insert(
                *amendment,
                Amendment {
                    grant: *grant,
                    plan: *plan,
                    route: None,
                    activated: false,
                    reviews: BTreeMap::new(),
                },
            );
            Ok(())
        }
        Record::AmendmentRouted {
            amendment, route, ..
        } => {
            let a = state
                .money
                .amendments
                .get_mut(amendment)
                .ok_or(FoldError::UnknownEntity)?;
            if a.route.is_some() {
                return Err(FoldError::Inconsistent);
            }
            a.route = Some(*route);
            Ok(())
        }
        Record::AmendmentActivated {
            amendment, plan, ..
        } => {
            let a = state
                .money
                .amendments
                .get(amendment)
                .ok_or(FoldError::UnknownEntity)?;
            if a.activated || a.plan != *plan {
                return Err(FoldError::Inconsistent);
            }
            let grant = a.grant;
            let total = plan_total(state, *plan).ok_or(FoldError::UnknownEntity)?;
            crate::grant::amend(state, grant, *plan, total)?;
            if let Some(x) = state.money.amendments.get_mut(amendment) {
                x.activated = true;
            }
            Ok(())
        }
        _ => Err(FoldError::Inconsistent),
    }
}

/// The vault questions this lane needs for its contribution to the batch of
/// a command that another lane owns. It asks none.
pub(crate) fn contribute_queries(
    state: &State,
    cmd: &Command,
    ctx: &Ctx,
) -> Result<Vec<Query>, Refusal> {
    let _ = (state, cmd, ctx);
    Ok(Vec::new())
}

/// The records this lane adds to the batch of a command that another lane
/// owns (`crate::engine` module docs). The amendment lane adds none in M2.
pub(crate) fn contribute(
    state: &State,
    cmd: &Command,
    ctx: &Ctx,
    answers: &Answers,
    batch: &[Record],
) -> Result<Vec<Record>, Refusal> {
    let _ = (state, cmd, ctx, answers, batch);
    Ok(Vec::new())
}

/// The policy whose P-77 governs a binding action of this lane through MCP
/// (R-MC-05, `crate::engine::PolicyScope`): the frozen policy of the
/// grant's creation call.
pub(crate) fn governing_policy(state: &State, cmd: &Command) -> Result<PolicyScope, Refusal> {
    let grant = match cmd {
        Command::ProposeAmendment { grant, .. } => *grant,
        Command::RouteAmendment { amendment, .. }
        | Command::ActivateAmendment { amendment, .. } => amendment_of(state, *amendment)?.grant,
        _ => return Err(wrong_state()),
    };
    crate::grant::call_scope(state, grant)
}
