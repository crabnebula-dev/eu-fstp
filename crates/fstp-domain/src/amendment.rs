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
//!   "amendment" of the grant.
//! - `RouteAmendment`, by the programme manager, who decides whether a
//!   P-14 exemption applies.
//! - `ActivateAmendment`, by the System on the M5 contract-version fact.
//!   It needs the I-15 record of the identity's earlier grants and of this
//!   grant itself, the amended total within P-04 (I-13), and the vault's
//!   answer that the amended total keeps the recipient within the cap
//!   (I-14). The amended total is at least the paid plus pending amount of
//!   the grant (I-31, I-61). The amended total then counts against P-05.
//!
//! An IRC route needs the IRC review of the amendment first. M2 records no
//! such review, so its activation is refused under R-IR-04 until one exists.

use crate::assignment::AssignmentKind;
use crate::command::{Command, Ctx};
use crate::engine::{FoldError, PolicyScope};
use fstp_money::NonNegAmount;

use crate::grant::{
    add_opt, at_most, cap_query, clear_repeat, guard, inactive, invalid, plan_total, record_answer,
    record_complete, repeat_check, reused, subject, unknown, vault, wrong_state,
};
use crate::id::{AccountId, AmendmentId, ContractId, PlanVersionId, ProposalId};
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Amendment {
    /// The grant.
    pub(crate) grant: ProposalId,
    /// The amended plan.
    pub(crate) plan: PlanVersionId,
    /// The route, once routed.
    pub(crate) route: Option<AmendmentRoute>,
    /// Whether it was activated.
    pub(crate) activated: bool,
}

/// The amendment `id`.
fn amendment_of(state: &State, id: AmendmentId) -> Result<&Amendment, Refusal> {
    state.money.amendments.get(&id).ok_or_else(unknown)
}

/// Whether the proposal is in GRANTED or IN_EXECUTION.
const fn amendable(s: StateTag) -> bool {
    matches!(s, StateTag::Granted | StateTag::InExecution)
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
        .is_some_and(|p| p.proposal == grant && p.origin == PlanOrigin::Amendment);
    if !ok {
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

/// Refuses an amended total below the paid plus pending amount of the
/// grant, so released payments never exceed the contract amount (I-31)
/// and the amendment never sets the contract below what is claimed
/// (I-61). It is refused as an invalid value, as I-58 is.
///
/// TODO(M5): I-59 and I-61 per milestone. An amended plan must keep every
/// milestone that carries paid or pending lines, at no less than that
/// amount. This needs a rule for milestone identity across contract
/// versions, which plan intake (lane L-LIFE) does not have yet.
fn keeps_claims(state: &State, grant: ProposalId, total: NonNegAmount) -> Result<(), Refusal> {
    let claimed = crate::payment::claimed(state, grant)
        .into_values()
        .fold(None, |acc, a| add_opt(acc, Some(a)));
    match claimed {
        Some(c) if !at_most(c.amount(), total.amount())? => Err(invalid()),
        _ => Ok(()),
    }
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
    if route == AmendmentRoute::Irc {
        return Err(guard(RuleRef::Rir04));
    }
    let total = plan_total(state, a.plan).ok_or_else(unknown)?;
    let p04 = crate::assignment::governing_values(state, a.grant)?.p04;
    if !p04.contains(total).map_err(|_| invalid())? {
        return Err(guard(RuleRef::I13));
    }
    keeps_claims(state, a.grant, total)?;
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
            let a = *state
                .money
                .amendments
                .get(amendment)
                .ok_or(FoldError::UnknownEntity)?;
            if a.activated || a.plan != *plan {
                return Err(FoldError::Inconsistent);
            }
            let total = plan_total(state, *plan).ok_or(FoldError::UnknownEntity)?;
            crate::grant::amend(state, a.grant, *plan, total)?;
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
