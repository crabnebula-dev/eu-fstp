//! Deferral, re-entry and the settlement after a concern (R-EV-07, R-IR-02, NOTE 5, NOTE 7, NOTE 8, NOTE 13).
//!
//! Written by lane L-LIFE in step W4b.
//!
//! - `ExpireStage2` is the System's. It takes STAGE2 to DEFERRED once the
//!   P-07 window has elapsed without answers and without a "no questions"
//!   record (NOTE 4). It needs no future call, so a proposal deferred
//!   while no next call exists waits (NOTE 5). Stage 2 has also concluded,
//!   so the expiry is refused, when a submitted revision has at least P-03
//!   valid stage 2 scores, or when every active assigned reviewer recorded
//!   "no questions" (NOTE 4, O-50).
//! - `ReEnter` is the System's. It takes DEFERRED back to the stage left,
//!   in the next published call of the programme after the call left, once
//!   that call has opened (NOTE 8). The original call's frozen policy keeps
//!   governing. Assignments and handles are made afresh in the new call,
//!   and findings stay with the call that produced them. The re-entry is
//!   refused under I-36 while a former reviewer of the proposal holds a
//!   Receiving binding in the new call.
//! - `DeclineAfterConcern` settles a recorded concern under NOTE 7, read
//!   when the command is recorded. With no later call of the programme
//!   published, it takes IRC_REVIEW to DECLINED. That is a decision, so the
//!   programme manager records it (NOTE 13, O-49), and P-77 governs it
//!   through MCP (R-MC-05). Once a later call is published, it takes
//!   IRC_REVIEW to DEFERRED instead. That outcome is computed from the
//!   concern and the publication, so the System records it.
//! - [`due`] lists the expiries, the deferrals after a concern and the
//!   re-entries enabled at an instant. The decline is not among them,
//!   because a System actor cannot record it.
//!
//! None of these rows records a decision id: the timer rows and the
//! deferral are not decisions, and the decline command carries none.
//!
//! Readings of this lane, reported to Daniel: the IRC_REVIEW to DEFERRED
//! row names an IRC member. A concern raised while no later call exists
//! is deferred by the System once one is published, so the proposal never
//! waits in IRC_REVIEW with no row it can take.

use crate::command::{Actor, Command, Ctx, Via};
use crate::engine::FoldError;
use crate::id::{CallId, ProposalId};
use crate::proposal::ReentryStage;
use crate::proposal::life::{
    current_call, facts, facts_mut, invalid, no_questions_complete, revision_scored_without_vault,
    state_of, unknown, window_end, wrong_state,
};
use crate::record::{Record, Transitioned};
use crate::refusal::{Refusal, RefusalReason, RuleRef};
use crate::roles::Role;
use crate::rules::{ParamId, Row, StateTag};
use crate::state::State;
use crate::time::Timestamp;

/// Whether `cmd` is one of the commands this module decides.
pub(crate) const fn is_deferral_command(cmd: &Command) -> bool {
    matches!(
        cmd,
        Command::ExpireStage2 { .. }
            | Command::ReEnter { .. }
            | Command::DeclineAfterConcern { .. }
    )
}

/// Whether `record` is one of the records this module folds.
pub(crate) const fn is_deferral_record(record: &Record) -> bool {
    matches!(
        record,
        Record::DeferralRecorded { .. } | Record::ReEntered { .. }
    )
}

/// Whether the P-07 window of `proposal` elapsed at `now` without answers
/// and without a "no questions" record, and stage 2 has not concluded by a
/// scored revision (R-EV-07, NOTE 4, O-50).
fn expirable(state: &State, proposal: ProposalId, now: Timestamp) -> Result<(), Refusal> {
    if state_of(state, proposal)? != StateTag::Stage2 {
        return Err(wrong_state());
    }
    let end = window_end(state, proposal).ok_or_else(wrong_state)?;
    let answered = facts(state, proposal)
        .and_then(|f| f.round.as_ref())
        .is_some_and(|r| r.answered);
    if now < end || answered {
        return Err(Refusal::new(RuleRef::Rev07, RefusalReason::GuardFailed));
    }
    if no_questions_complete(state, proposal) || revision_scored_without_vault(state, proposal) {
        return Err(Refusal::new(RuleRef::Rev05, RefusalReason::GuardFailed));
    }
    Ok(())
}

/// The stage `proposal` re-enters and the call it enters at `now`, when the
/// row applies to `call` (NOTE 8, I-36).
fn reentry(
    state: &State,
    proposal: ProposalId,
    call: CallId,
    now: Timestamp,
) -> Result<(CallId, ReentryStage), Refusal> {
    if state_of(state, proposal)? != StateTag::Deferred {
        return Err(wrong_state());
    }
    let (from, left) = facts(state, proposal)
        .and_then(|f| f.deferral)
        .ok_or_else(wrong_state)?;
    if crate::programme::next_published_call(state, from) != Some(call) {
        return Err(Refusal::new(RuleRef::Row, RefusalReason::GuardFailed));
    }
    let opens = crate::programme::call(state, call)
        .map(crate::programme::CallView::opens)
        .ok_or_else(unknown)?;
    if now < opens {
        return Err(Refusal::new(RuleRef::Row, RefusalReason::GuardFailed));
    }
    if crate::assignment::former_reviewer_receiving_in(state, proposal, call) {
        return Err(Refusal::new(RuleRef::I36, RefusalReason::GuardFailed));
    }
    Ok((from, left))
}

/// Whether a later call of the programme of `call` is published (NOTE 7).
pub(crate) fn future_call_exists(state: &State, call: CallId) -> bool {
    crate::programme::next_published_call(state, call).is_some()
}

/// The records of one of the three commands.
fn check(state: &State, cmd: &Command, ctx: &Ctx) -> Result<Vec<Record>, Refusal> {
    match cmd {
        Command::ExpireStage2 { proposal } => {
            expirable(state, *proposal, ctx.now)?;
            Ok(vec![
                Record::DeferralRecorded {
                    proposal: *proposal,
                    from_call: current_call(state, *proposal)?,
                    left: ReentryStage::Stage2,
                },
                Record::Transitioned(Transitioned {
                    proposal: *proposal,
                    from: StateTag::Stage2,
                    to: StateTag::Deferred,
                    row: Row::Stage2ToDeferred,
                    actor: ctx.actor,
                    decision: None,
                }),
            ])
        }
        Command::ReEnter { proposal, call } => {
            let (from, left) = reentry(state, *proposal, *call, ctx.now)?;
            let (to, row) = match left {
                ReentryStage::Stage2 => (StateTag::Stage2, Row::DeferredToStage2),
                ReentryStage::IrcReview => (StateTag::IrcReview, Row::DeferredToIrcReview),
            };
            Ok(vec![
                Record::ReEntered {
                    proposal: *proposal,
                    from_call: from,
                    to_call: *call,
                    stage: left,
                },
                Record::Transitioned(Transitioned {
                    proposal: *proposal,
                    from: StateTag::Deferred,
                    to,
                    row,
                    actor: ctx.actor,
                    decision: None,
                }),
            ])
        }
        Command::DeclineAfterConcern { proposal } => settle_concern(state, *proposal, ctx),
        _ => Err(invalid()),
    }
}

/// Refuses unless `proposal` is in IRC_REVIEW with a concern recorded in
/// the current IRC round (R-IR-02).
fn concern_raised(state: &State, proposal: ProposalId) -> Result<(), Refusal> {
    if state_of(state, proposal)? != StateTag::IrcReview {
        return Err(wrong_state());
    }
    if facts(state, proposal).and_then(|f| f.concern).is_none() {
        return Err(Refusal::new(RuleRef::Rir02, RefusalReason::GuardFailed));
    }
    Ok(())
}

/// The records of `DeclineAfterConcern` (NOTE 7, NOTE 13, O-49, R-MC-05).
///
/// - The programme manager records the decline while no later call of
///   the programme is published. Through MCP, P-77 of the governing
///   frozen policy must allow it, as for every other decision.
/// - The System records the deferral once a later call is published.
/// - Any other pairing of actor and NOTE 7 answer is refused.
fn settle_concern(state: &State, proposal: ProposalId, ctx: &Ctx) -> Result<Vec<Record>, Refusal> {
    if let Actor::Account(actor) = ctx.actor {
        let programme = crate::assignment::programme_of(state, proposal)?;
        crate::policy::require_holder(state, actor, programme, &[Role::ProgrammeManager], ctx.now)?;
        if ctx.via == Via::Mcp {
            let call =
                crate::proposal::draft::proposal_call(state, proposal).ok_or_else(unknown)?;
            if !crate::policy::mcp_binding_allowed(state, crate::engine::PolicyScope::Call(call))? {
                return Err(Refusal::new(
                    RuleRef::Param(ParamId::P77),
                    RefusalReason::NotThroughMcp,
                ));
            }
        }
    }
    concern_raised(state, proposal)?;
    let call = current_call(state, proposal)?;
    let later = future_call_exists(state, call);
    match (ctx.actor, later) {
        (Actor::Account(_), false) => Ok(vec![Record::Transitioned(Transitioned {
            proposal,
            from: StateTag::IrcReview,
            to: StateTag::Declined,
            row: Row::IrcReviewToDeclined,
            actor: ctx.actor,
            decision: None,
        })]),
        (Actor::System(_), true) => Ok(vec![
            Record::DeferralRecorded {
                proposal,
                from_call: call,
                left: ReentryStage::IrcReview,
            },
            Record::Transitioned(Transitioned {
                proposal,
                from: StateTag::IrcReview,
                to: StateTag::Deferred,
                row: Row::IrcReviewToDeferred,
                actor: ctx.actor,
                decision: None,
            }),
        ]),
        (Actor::Account(_), true) => Err(Refusal::new(RuleRef::Row, RefusalReason::GuardFailed)),
        (Actor::System(_), false) => Err(Refusal::new(RuleRef::Actor, RefusalReason::WrongActor)),
    }
}

/// Whether the System's deferral after a concern applies to `proposal`:
/// IRC_REVIEW with a concern, and a later call of the programme published
/// (NOTE 7).
fn deferrable_after_concern(state: &State, proposal: ProposalId) -> bool {
    concern_raised(state, proposal).is_ok()
        && current_call(state, proposal).is_ok_and(|c| future_call_exists(state, c))
}

/// The vault questions of the three commands. They ask none.
pub(crate) fn queries(
    state: &State,
    cmd: &Command,
    ctx: &Ctx,
) -> Result<Vec<crate::oracle::Query>, Refusal> {
    check(state, cmd, ctx)?;
    Ok(Vec::new())
}

/// The records of the three commands.
pub(crate) fn decide(state: &State, cmd: &Command, ctx: &Ctx) -> Result<Vec<Record>, Refusal> {
    check(state, cmd, ctx)
}

/// Folds a deferral or a re-entry. A re-entry moves the proposal to the
/// new call, which the next transition keeps (NOTE 8).
pub(crate) fn apply(state: &mut State, record: &Record) -> Result<(), FoldError> {
    match record {
        Record::DeferralRecorded {
            proposal,
            from_call,
            left,
        } => {
            crate::programme::call(state, *from_call).ok_or(FoldError::UnknownEntity)?;
            facts_mut(state, *proposal)?.deferral = Some((*from_call, *left));
            Ok(())
        }
        Record::ReEntered {
            proposal,
            from_call,
            to_call,
            stage,
        } => {
            crate::programme::call(state, *to_call).ok_or(FoldError::UnknownEntity)?;
            if crate::proposal::intake::proposal_state(state, *proposal) != Some(StateTag::Deferred)
            {
                return Err(FoldError::Inconsistent);
            }
            let f = facts_mut(state, *proposal)?;
            if f.deferral != Some((*from_call, *stage)) {
                return Err(FoldError::Inconsistent);
            }
            f.deferral = None;
            crate::proposal::intake::set_current_call(state, *proposal, *to_call)
        }
        _ => Err(FoldError::Inconsistent),
    }
}

/// The System commands of this lane enabled at `now` (design section 3.6):
/// the expiry of every elapsed stage 2 window without answers, the
/// deferral of every concern once a later call is published, and the
/// re-entry of every deferred proposal whose next call has opened.
pub(crate) fn due(state: &State, now: Timestamp) -> Vec<Command> {
    let mut out = Vec::new();
    for (proposal, s, _) in crate::proposal::intake::submitted_proposals(state) {
        match s {
            StateTag::Stage2 if expirable(state, proposal, now).is_ok() => {
                out.push(Command::ExpireStage2 { proposal });
            }
            StateTag::IrcReview if deferrable_after_concern(state, proposal) => {
                out.push(Command::DeclineAfterConcern { proposal });
            }
            StateTag::Deferred => {
                let next = facts(state, proposal)
                    .and_then(|f| f.deferral)
                    .and_then(|(from, _)| crate::programme::next_published_call(state, from));
                if let Some(call) = next
                    && reentry(state, proposal, call, now).is_ok()
                {
                    out.push(Command::ReEnter { proposal, call });
                }
            }
            _ => {}
        }
    }
    out
}
