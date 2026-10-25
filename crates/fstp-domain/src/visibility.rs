//! Visibility and the ranking view (design section 3.7, R-AC-01, P-10).
//!
//! Owned by lane L-REV (docs/handoff/m2-design.md section 10).
//!
//! - [`can_read_content`] says whether an account may read a proposal's
//!   full content now, before the fresh vault check. `ReadContent` also
//!   needs a [`crate::assignment::ReviewerAct`], which re-checks
//!   `HasConflict` at the current epoch, for every reader outside the
//!   applicant team.
//! - [`ranking_view`] is what committee members who are not assigned to a
//!   proposal see under P-10 "assigned reviewers only". It has no field
//!   for LLM findings, so none can reach it (`SPEC/02-domain/roles-and-sod.md`
//!   Committee ranking view).
//!
//! Who reads, in this lane's reading of R-AC-01, P-10 and the Conflict
//! declarations section:
//!
//! - The proposal's applicant team reads its own proposal through an
//!   active Receiving binding.
//! - Nobody else reads while a conflict fact exists for them on the
//!   proposal, or while the vault answers `HasConflict` true (I-03).
//! - In SUBMITTED only the FSTP coordinator reads, for the knock-out
//!   check, after declaring no conflict on the proposal.
//! - In STAGE1 and STAGE2, P-10 decides. "Assigned reviewers only" admits
//!   an active committee member through an active reviewer assignment in
//!   the current call. "All committee members" also admits an active
//!   committee member who declared no conflict on the proposal. "Operator
//!   staff only" admits nobody in M2, because its reading role is open (O-43).
//! - In IRC_REVIEW an IRC member reads through an active IRC assignment,
//!   and in NEGOTIATION an assigned reviewer reads to determine the amount.
//! - Every other read is M4 visibility and refused here.

use fstp_money::{Amount, NonNegAmount, Ratio};

use crate::assignment::{AssignmentKind, governing_values, programme_of};
use crate::id::{AccountId, AssignmentId, CallId, CriterionId, ProposalId, TextRef};
use crate::policy::ReadAccess;
use crate::proposal::intake::{current_call, plan_total, proposal_state, submission};
use crate::refusal::{Refusal, RefusalReason, RuleRef};
use crate::roles::Role;
use crate::rules::StateTag;
use crate::state::State;
use crate::time::Timestamp;

/// What a read rests on, before the fresh vault check.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum ReadBasis {
    /// An active Receiving binding on the proposal: the applicant team.
    Team,
    /// An active assignment of the reader on the proposal.
    Assignment(AssignmentId),
    /// A proposal-level no-conflict declaration by a holder of this role.
    Declared(Role),
}

/// The refusal of a read that R-AC-01 and P-10 do not open.
const fn closed() -> Refusal {
    Refusal::new(RuleRef::Rac01, RefusalReason::GuardFailed)
}

/// The active assignment of `kind` that `account` holds on `proposal` in
/// its current call, over an active binding of the kind's role.
fn active_assignment(
    state: &State,
    account: AccountId,
    proposal: ProposalId,
    kind: AssignmentKind,
    now: Timestamp,
) -> Option<AssignmentId> {
    crate::assignment::qualifying_assignment(state, account, proposal, kind, now)
}

/// What a read of `proposal` by `account` at `now` rests on, or the refusal.
/// The fresh `HasConflict` check comes after it, in the `ReviewerAct`.
pub(crate) fn read_basis(
    state: &State,
    account: AccountId,
    proposal: ProposalId,
    now: Timestamp,
) -> Result<ReadBasis, Refusal> {
    let unknown = Refusal::new(RuleRef::Input, RefusalReason::UnknownEntity);
    let current = proposal_state(state, proposal).ok_or(unknown)?;
    let team = [Role::Applicant, Role::ApplicantTeamMember, Role::Guardian]
        .iter()
        .any(|r| {
            state
                .roster
                .active_receiving(account, *r, proposal, now)
                .is_some()
        });
    if team {
        return Ok(ReadBasis::Team);
    }
    if state.review().conflict_fact(account, proposal) {
        return Err(Refusal::new(RuleRef::I03, RefusalReason::GuardFailed));
    }
    let programme = programme_of(state, proposal)?;
    let holds = |role: Role| {
        state
            .roster
            .active_binding(account, role, programme, now)
            .is_some()
    };
    let cleared = state.review().cleared(account, proposal);
    let reviewer = || active_assignment(state, account, proposal, AssignmentKind::Reviewer, now);
    match current {
        StateTag::Submitted => {
            if holds(Role::FstpCoordinator) && cleared {
                Ok(ReadBasis::Declared(Role::FstpCoordinator))
            } else {
                Err(Refusal::new(RuleRef::Rcf02, RefusalReason::GuardFailed))
            }
        }
        StateTag::Stage1 | StateTag::Stage2 => {
            let p10 = governing_values(state, proposal)?.p10;
            if p10 == ReadAccess::OperatorStaffOnly {
                return Err(closed());
            }
            if let Some(id) = reviewer() {
                return Ok(ReadBasis::Assignment(id));
            }
            if p10 == ReadAccess::AllCommitteeMembers && holds(Role::CommitteeMember) && cleared {
                return Ok(ReadBasis::Declared(Role::CommitteeMember));
            }
            Err(closed())
        }
        StateTag::IrcReview => {
            active_assignment(state, account, proposal, AssignmentKind::Irc, now)
                .map(ReadBasis::Assignment)
                .ok_or_else(closed)
        }
        StateTag::Negotiation => reviewer().map(ReadBasis::Assignment).ok_or_else(closed),
        _ => Err(closed()),
    }
}

/// Whether `account` may read the full content of `proposal` at `now`
/// (R-AC-01, P-10), before the fresh vault check that `ReadContent`
/// makes for every reader outside the applicant team.
pub fn can_read_content(
    state: &State,
    account: AccountId,
    proposal: ProposalId,
    now: Timestamp,
) -> bool {
    read_basis(state, account, proposal, now).is_ok()
}

/// One row of the committee ranking view (`SPEC/02-domain/roles-and-sod.md`
/// Committee ranking view). It holds no findings field, and none can be added
/// without changing this type.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RankingRow {
    /// The proposal.
    pub proposal: ProposalId,
    /// The title the assigned reviewers wrote, once recorded.
    pub title: Option<TextRef>,
    /// The neutral summary the assigned reviewers wrote, once recorded.
    pub neutral_summary: Option<TextRef>,
    /// The weighted score per criterion. Lane L-LIFE fills it from the
    /// score sheet, which this lane cannot read yet.
    pub criterion_scores: Vec<(CriterionId, Ratio)>,
    /// The requested amount: the total of the submitted plan.
    pub requested: NonNegAmount,
    /// The remaining call budget, signed because a call can be over-nominated.
    pub remaining_budget: Amount,
    /// The assigned reviewers' rationale, once recorded.
    pub rationale: Option<TextRef>,
}

/// The requested amount of `proposal`: the total of its submitted plan,
/// or zero in `currency` when it has no submission.
///
/// A submitted plan whose total cannot be computed refuses, so a wrong
/// value never stands in for it (ADR-006). Stage 2 revisions and
/// negotiated plans cannot be recorded yet, so the submitted plan is the
/// effective plan (I-09) in every reachable state. Once lane L-LIFE
/// exposes the effective plan and the negotiated amount, this totals
/// those instead.
fn requested(
    state: &State,
    proposal: ProposalId,
    currency: fstp_money::Currency,
) -> Result<NonNegAmount, Refusal> {
    let invalid = Refusal::new(RuleRef::Input, RefusalReason::InvalidValue);
    match submission(state, proposal) {
        Some(s) => crate::proposal::intake::plan(state, s.plan)
            .and_then(plan_total)
            .ok_or(invalid),
        None => NonNegAmount::new(Amount::zero(currency)).map_err(|_| invalid),
    }
}

/// The committee ranking view of `call`: one row per RANKED proposal whose
/// current call is `call`, in proposal order.
///
/// The remaining budget is the call budget minus the requested totals of
/// the call's proposals in IRC_REVIEW, NEGOTIATION and later states
/// (interim reading Q14). Withdrawn, declined and deferred proposals do
/// not count. An unknown call, or a sum outside the money range, refuses.
pub fn ranking_view(state: &State, call: CallId) -> Result<Vec<RankingRow>, Refusal> {
    let unknown = Refusal::new(RuleRef::Input, RefusalReason::UnknownEntity);
    let overflow = Refusal::new(RuleRef::Input, RefusalReason::InvalidValue);
    let view = crate::programme::call(state, call).ok_or(unknown)?;
    let budget = view.budget().amount();
    let currency = budget.currency();
    let mut remaining = budget;
    let mut ranked = Vec::new();
    for (p, s, c) in crate::proposal::intake::submitted_proposals(state) {
        if c != call {
            continue;
        }
        let committed = matches!(
            s,
            StateTag::IrcReview
                | StateTag::Negotiation
                | StateTag::Granted
                | StateTag::InExecution
                | StateTag::Completed
                | StateTag::Terminated
        );
        if committed {
            let r = requested(state, p, currency)?;
            remaining = remaining.checked_sub(r.amount()).map_err(|_| overflow)?;
        }
        if s == StateTag::Ranked {
            ranked.push(p);
        }
    }
    let mut rows = Vec::new();
    for p in ranked {
        if current_call(state, p) != Some(call) {
            continue;
        }
        let summary = state.review().summary(p);
        rows.push(RankingRow {
            proposal: p,
            title: summary.map(|s| s.title),
            neutral_summary: summary.map(|s| s.neutral_summary),
            criterion_scores: Vec::new(),
            requested: requested(state, p, currency)?,
            remaining_budget: remaining,
            rationale: summary.map(|s| s.rationale),
        });
    }
    Ok(rows)
}
