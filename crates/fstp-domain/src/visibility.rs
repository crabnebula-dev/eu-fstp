//! Visibility and the ranking view (design section 3.7, R-AC-01, P-10).
//!
//! Owned by lane L-REV (docs/handoff/m2-design.md section 10), with the M4
//! changes D4, D6 and D9 to D11 of lane L-DOM (M4 design section 3.4).
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
//! declarations section. Every one of the 16 states has a rule (D11):
//!
//! - The proposal's applicant team reads its own proposal through an
//!   active Receiving binding, in every state.
//! - Nobody else reads while a conflict fact exists for them on the
//!   proposal, or while the vault answers `HasConflict` true (I-03).
//! - In DRAFT nobody else reads. The draft is private to the team.
//! - In SUBMITTED only the FSTP coordinator reads, for the knock-out
//!   check, after declaring no conflict on the proposal.
//! - In STAGE1 and STAGE2, P-10 decides. "Assigned reviewers only" admits
//!   an active committee member through an active reviewer assignment in
//!   the current call. "All committee members" also admits an active
//!   committee member who declared no conflict on the proposal. "Operator
//!   staff only" admits only the FSTP coordinator, after a proposal-level
//!   declaration of no conflict (O-43, policy-parameters NOTE 1, decided
//!   2026-10-25, D4). Under the two other options the coordinator does
//!   not read in these stages.
//! - In IRC_REVIEW an IRC member reads through an active IRC assignment,
//!   and in NEGOTIATION an assigned reviewer reads to determine the amount.
//! - RANKED, DEFERRED, GRANTED, IN_EXECUTION and the terminal states admit
//!   the applicant team only. In RANKED the committee reads the ranking
//!   view, never the content (Q39, interim, pending Daniel).
//! - Through MCP, P-75 governs reviewers' agents: a read whose basis is not
//!   the applicant team is refused unless the frozen P-75 of the
//!   proposal's original call is on (D6, TH-62). The applicant team reads
//!   its own proposal through MCP as through the web (I-84).

use fstp_money::{Amount, NonNegAmount, Ratio};

use crate::assignment::{AssignmentKind, governing_values, programme_of};
use crate::command::Ctx;
use crate::id::{AccountId, AssignmentId, CallId, CriterionId, ProposalId, TextRef};
use crate::policy::{AgentContentAccess, ReadAccess};
use crate::proposal::intake::{current_call, plan_total, proposal_state};
use crate::refusal::{Refusal, RefusalReason, RuleRef};
use crate::roles::Role;
use crate::rules::{ParamId, StateTag};
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
        // The draft is private to the applicant team.
        StateTag::Draft => Err(closed()),
        StateTag::Submitted => {
            if holds(Role::FstpCoordinator) && cleared {
                Ok(ReadBasis::Declared(Role::FstpCoordinator))
            } else {
                Err(Refusal::new(RuleRef::Rcf02, RefusalReason::GuardFailed))
            }
        }
        StateTag::Stage1 | StateTag::Stage2 => {
            let p10 = governing_values(state, proposal)?.p10;
            match p10 {
                // O-43, policy-parameters NOTE 1, D4: the FSTP coordinator
                // reads after declaring no conflict on the proposal.
                ReadAccess::OperatorStaffOnly => {
                    if holds(Role::FstpCoordinator) && cleared {
                        Ok(ReadBasis::Declared(Role::FstpCoordinator))
                    } else {
                        Err(closed())
                    }
                }
                ReadAccess::AssignedReviewersOnly => {
                    reviewer().map(ReadBasis::Assignment).ok_or_else(closed)
                }
                ReadAccess::AllCommitteeMembers => {
                    if let Some(id) = reviewer() {
                        Ok(ReadBasis::Assignment(id))
                    } else if holds(Role::CommitteeMember) && cleared {
                        Ok(ReadBasis::Declared(Role::CommitteeMember))
                    } else {
                        Err(closed())
                    }
                }
            }
        }
        StateTag::IrcReview => {
            active_assignment(state, account, proposal, AssignmentKind::Irc, now)
                .map(ReadBasis::Assignment)
                .ok_or_else(closed)
        }
        StateTag::Negotiation => reviewer().map(ReadBasis::Assignment).ok_or_else(closed),
        // Q39 interim reading, D11: the applicant team only. In RANKED the
        // committee reads the ranking view, never the content.
        StateTag::Ranked
        | StateTag::Deferred
        | StateTag::Granted
        | StateTag::InExecution
        | StateTag::Ineligible
        | StateTag::NotSelected
        | StateTag::Declined
        | StateTag::Withdrawn
        | StateTag::Completed
        | StateTag::Terminated => Err(closed()),
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

/// The P-75 check of a `ReadContent` through MCP (D6, TH-62). The engine
/// runs it with the shared checks, for `Via::Mcp` only.
///
/// A read whose basis is the applicant team passes, so the team reads its
/// own proposal through MCP as through the web (I-84). Any other read is
/// refused with `Param(P75)` and `NotThroughMcp` unless the frozen P-75 of
/// the proposal's original call is on (I-12). A read with no basis passes
/// here, and the owning lane refuses it as it does through the web.
pub(crate) fn mcp_read_allowed(
    state: &State,
    proposal: ProposalId,
    ctx: &Ctx,
) -> Result<(), Refusal> {
    let Ok(actor) = crate::policy::actor_account(ctx) else {
        return Ok(());
    };
    match read_basis(state, actor, proposal, ctx.now) {
        Err(_) | Ok(ReadBasis::Team) => Ok(()),
        Ok(ReadBasis::Assignment(_) | ReadBasis::Declared(_)) => {
            if governing_values(state, proposal)?.p75 == AgentContentAccess::On {
                Ok(())
            } else {
                Err(Refusal::new(
                    RuleRef::Param(ParamId::P75),
                    RefusalReason::NotThroughMcp,
                ))
            }
        }
    }
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
    /// The weighted score per criterion, in P-01 order: the mean over the
    /// reviewers whose scores count of weight times score, as an exact
    /// ratio, from the effective score set after stage 2 (R-EV-08, I-09,
    /// D9).
    pub criterion_scores: Vec<(CriterionId, Ratio)>,
    /// The requested amount: the total of the effective plan (I-09, D10).
    pub requested: NonNegAmount,
    /// The remaining call budget, signed because a call can be over-nominated.
    pub remaining_budget: Amount,
    /// The assigned reviewers' rationale, once recorded.
    pub rationale: Option<TextRef>,
}

/// The requested amount of `proposal`: the total of its effective plan
/// (I-09, D10), or zero in `currency` when it has no submission.
///
/// The effective plan is the plan the effective score after stage 2 names.
/// Before that score is set it is the last submitted stage 2 revision,
/// else the submitted plan (`crate::proposal::intake::effective_plan`). A
/// plan whose total cannot be computed refuses, so a wrong value never
/// stands in for it (ADR-006).
fn requested(
    state: &State,
    proposal: ProposalId,
    currency: fstp_money::Currency,
) -> Result<NonNegAmount, Refusal> {
    let invalid = Refusal::new(RuleRef::Input, RefusalReason::InvalidValue);
    match crate::proposal::intake::effective_plan(state, proposal) {
        Some(plan) => crate::proposal::intake::plan(state, plan)
            .and_then(plan_total)
            .ok_or(invalid),
        None => NonNegAmount::new(Amount::zero(currency)).map_err(|_| invalid),
    }
}

/// The weighted score of each P-01 criterion of `proposal` (R-EV-08, D9):
/// per criterion, the mean over the score keys that the effective score
/// set counts of the criterion's weight times the score, as an exact
/// ratio, in P-01 order. A proposal without an effective score has none.
///
/// A counted key without a current value refuses under I-09, since the
/// effective score set names only valid scores.
fn criterion_scores(
    state: &State,
    proposal: ProposalId,
) -> Result<Vec<(CriterionId, Ratio)>, Refusal> {
    let Some(effective) = crate::decision::effective_score(state, proposal) else {
        return Ok(Vec::new());
    };
    let overflow = Refusal::new(RuleRef::Input, RefusalReason::InvalidValue);
    let missing = Refusal::new(RuleRef::I09, RefusalReason::GuardFailed);
    let sheet = crate::proposal::life::facts(state, proposal)
        .map(|f| &f.sheet)
        .ok_or(missing)?;
    let mut vectors = Vec::new();
    for key in effective.counted() {
        vectors.push(sheet.current(*key).ok_or(missing)?);
    }
    let Some(den) = u64::try_from(vectors.len())
        .ok()
        .and_then(core::num::NonZeroU64::new)
    else {
        return Ok(Vec::new());
    };
    let criteria = governing_values(state, proposal)?.p01.items();
    let mut out = Vec::new();
    for (i, c) in criteria.iter().enumerate() {
        let mut sum: u64 = 0;
        for v in &vectors {
            let score = v.0.get(i).ok_or(missing)?;
            sum = u64::from(c.weight.get())
                .checked_mul(u64::from(*score))
                .and_then(|w| sum.checked_add(w))
                .ok_or(overflow)?;
        }
        out.push((c.id, Ratio::new(sum, den)));
    }
    Ok(out)
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
            criterion_scores: criterion_scores(state, p)?,
            requested: requested(state, p, currency)?,
            remaining_budget: remaining,
            rationale: summary.map(|s| s.rationale),
        });
    }
    Ok(rows)
}
