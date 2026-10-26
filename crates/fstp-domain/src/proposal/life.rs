//! The lifecycle facts of each proposal after submission (design sections 2.8 to 2.10 and 2.14).
//!
//! Written by lane L-LIFE in step W4b. The projection keeps current,
//! decision-relevant facts only, so two histories that reach the same
//! situation give equal projections.
//!
//! - [`Facts`] holds, per proposal, the current scores with the entry of
//!   each current value and the assignments that ever gave a score. It
//!   also holds the knock-out result, the recorded stage 1 close, the open
//!   stage 2 round and the submitted revisions. The effective score, the
//!   last deferral and the current IRC round complete it.
//! - [`on_transition`] keeps the rounds in step with the proposal state.
//!   Entering STAGE2 opens a round at the entry time, also on re-entry.
//!   Leaving STAGE2 closes it. Entering IRC_REVIEW starts a fresh IRC round.
//! - The read helpers here are what the stage 2, deferral and decision code
//!   share: the governing frozen values, the stage 2 window and the active
//!   assignments of a call.

use std::collections::{BTreeMap, BTreeSet};

use fstp_ledger::Seq;

use crate::assignment::AssignmentKind;
use crate::decision::{EffectiveScoreSet, Stage1Closed};
use crate::engine::FoldError;
use crate::id::{AccountId, AssignmentId, CallId, PlanVersionId, ProposalId, TextRef};
use crate::policy::FrozenValues;
use crate::proposal::ReentryStage;
use crate::record::Transitioned;
use crate::refusal::{Refusal, RefusalReason, RuleRef};
use crate::rules::StateTag;
use crate::scoring::{ScoreKey, ScoreSheet};
use crate::state::State;
use crate::time::Timestamp;

/// One stage 2 round, from an entry into STAGE2 to the exit (NOTE 4).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Round {
    /// The entry into STAGE2. The P-07 window runs from here.
    pub(crate) opened: Timestamp,
    /// The assignments that asked a question in this round.
    pub(crate) questions: BTreeSet<AssignmentId>,
    /// The assignments that recorded "no questions" in this round.
    pub(crate) no_questions: BTreeSet<AssignmentId>,
    /// Whether the applicant answered in this round.
    pub(crate) answered: bool,
}

/// The lifecycle facts of one proposal.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Facts {
    /// The current score values, one per key (NOTE 3).
    pub(crate) sheet: ScoreSheet,
    /// The ledger entry of each current value, which a correction supersedes.
    pub(crate) entries: BTreeMap<ScoreKey, Seq>,
    /// The assignments that ever recorded a score, for R-CF-04.
    pub(crate) given: BTreeSet<AssignmentId>,
    /// Whether the knock-out check passed, once recorded (R-EV-01).
    pub(crate) knock_out: Option<bool>,
    /// The recorded stage 1 close. Its score is sealed (NOTE 3).
    pub(crate) closed: Option<Stage1Closed>,
    /// The open stage 2 round, while the proposal is in STAGE2.
    pub(crate) round: Option<Round>,
    /// The submitted stage 2 revisions, in submission order (NOTE 4).
    pub(crate) revisions: Vec<PlanVersionId>,
    /// The effective score, once set. It is never cleared (I-09).
    pub(crate) effective: Option<EffectiveScoreSet>,
    /// The last deferral: the call left and the stage left (NOTE 8).
    pub(crate) deferral: Option<(CallId, ReentryStage)>,
    /// The IRC reviews of the current IRC round: `true` for a validation.
    pub(crate) irc: BTreeMap<AssignmentId, bool>,
    /// The concern of the current IRC round (R-IR-02).
    pub(crate) concern: Option<TextRef>,
}

impl Facts {
    /// The facts of a proposal with no lifecycle record yet.
    fn new() -> Facts {
        Facts {
            sheet: ScoreSheet::empty(),
            entries: BTreeMap::new(),
            given: BTreeSet::new(),
            knock_out: None,
            closed: None,
            round: None,
            revisions: Vec::new(),
            effective: None,
            deferral: None,
            irc: BTreeMap::new(),
            concern: None,
        }
    }
}

/// The lifecycle facts of every proposal that has one.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Lives {
    facts: BTreeMap<ProposalId, Facts>,
}

impl Lives {
    /// No lifecycle fact yet.
    pub(crate) const fn genesis() -> Lives {
        Lives {
            facts: BTreeMap::new(),
        }
    }

    /// The facts of `proposal`, if it has any.
    pub(crate) fn get(&self, proposal: ProposalId) -> Option<&Facts> {
        self.facts.get(&proposal)
    }
}

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------

/// The lifecycle facts of `proposal`, if it has any.
pub(crate) fn facts(state: &State, proposal: ProposalId) -> Option<&Facts> {
    state.proposals.life.get(proposal)
}

/// The facts of `proposal` for a fold, created on first use. The proposal
/// must exist.
pub(crate) fn facts_mut(state: &mut State, proposal: ProposalId) -> Result<&mut Facts, FoldError> {
    crate::proposal::draft::draft(state, proposal).ok_or(FoldError::UnknownEntity)?;
    Ok(state
        .proposals
        .life
        .facts
        .entry(proposal)
        .or_insert_with(Facts::new))
}

/// The refusal of an unknown entity.
pub(crate) const fn unknown() -> Refusal {
    Refusal::new(RuleRef::Input, RefusalReason::UnknownEntity)
}

/// The refusal of a command the proposal's state does not admit.
pub(crate) const fn wrong_state() -> Refusal {
    Refusal::new(RuleRef::Row, RefusalReason::WrongState)
}

/// The refusal of a value the command may not carry.
pub(crate) const fn invalid() -> Refusal {
    Refusal::new(RuleRef::Input, RefusalReason::InvalidValue)
}

/// The state of `proposal`, or the refusal of an unknown one.
pub(crate) fn state_of(state: &State, proposal: ProposalId) -> Result<StateTag, Refusal> {
    crate::proposal::intake::proposal_state(state, proposal).ok_or_else(unknown)
}

/// The call `proposal` is evaluated in now (NOTE 8).
pub(crate) fn current_call(state: &State, proposal: ProposalId) -> Result<CallId, Refusal> {
    crate::proposal::intake::current_call(state, proposal).ok_or_else(unknown)
}

/// The frozen values of the call that governs `proposal`: its creation
/// call, also after re-entry (NOTE 8).
pub(crate) fn governing(state: &State, proposal: ProposalId) -> Result<&FrozenValues, Refusal> {
    crate::assignment::governing_values(state, proposal)
}

/// The close of the stage 2 window of `proposal`: the opening of its round
/// plus P-07 whole days of 86 400 seconds. `None` outside a round.
pub(crate) fn window_end(state: &State, proposal: ProposalId) -> Option<Timestamp> {
    let round = facts(state, proposal)?.round.as_ref()?;
    let days = governing(state, proposal).ok()?.p07;
    round.opened.checked_add_days(days)
}

/// The open stage 2 round of `proposal` at `now`: the proposal is in
/// STAGE2 and the P-07 window has not elapsed (R-EV-05, R-EV-07).
pub(crate) fn open_round(
    state: &State,
    proposal: ProposalId,
    now: Timestamp,
) -> Result<&Round, Refusal> {
    if state_of(state, proposal)? != StateTag::Stage2 {
        return Err(wrong_state());
    }
    let round = facts(state, proposal)
        .and_then(|f| f.round.as_ref())
        .ok_or_else(wrong_state)?;
    let end = window_end(state, proposal).ok_or_else(wrong_state)?;
    if now >= end {
        return Err(Refusal::new(RuleRef::Rev07, RefusalReason::GuardFailed));
    }
    Ok(round)
}

/// Refuses unless the actor is the lead of `proposal` with an active
/// Applicant binding on it (enforcement point 2).
pub(crate) fn require_lead(
    state: &State,
    proposal: ProposalId,
    ctx: &crate::command::Ctx,
) -> Result<AccountId, Refusal> {
    let actor = crate::policy::actor_account(ctx)?;
    let d = crate::proposal::draft::draft(state, proposal).ok_or_else(unknown)?;
    let active = state
        .roster
        .active_receiving(actor, crate::roles::Role::Applicant, proposal, ctx.now)
        .is_some();
    if d.lead != actor || !active {
        return Err(Refusal::new(RuleRef::Actor, RefusalReason::BindingInactive));
    }
    Ok(actor)
}

/// The active assignments of `kind` on `proposal` made in `call` whose
/// assignee has no conflict fact on the proposal (NOTE 3, R-IR-01).
pub(crate) fn active_assignments(
    state: &State,
    proposal: ProposalId,
    call: CallId,
    kind: AssignmentKind,
) -> BTreeSet<AssignmentId> {
    state
        .review
        .assignments()
        .filter(|(_, a)| {
            a.proposal == proposal
                && a.call == call
                && a.kind == kind
                && a.active()
                && !state.review.conflict_fact(a.reviewer, proposal)
        })
        .map(|(id, _)| id)
        .collect()
}

/// Whether every active reviewer assignment of the current call of
/// `proposal` recorded "no questions" in the open round, with at least one
/// such assignment (NOTE 4, O-50). The window has then closed with answers
/// deemed complete, also when the last outstanding assignee was released.
pub(crate) fn no_questions_complete(state: &State, proposal: ProposalId) -> bool {
    let Ok(call) = current_call(state, proposal) else {
        return false;
    };
    let Some(round) = facts(state, proposal).and_then(|f| f.round.as_ref()) else {
        return false;
    };
    let active = active_assignments(state, proposal, call, AssignmentKind::Reviewer);
    !active.is_empty() && active.is_subset(&round.no_questions)
}

/// Whether a submitted revision of `proposal` has at least P-03 valid
/// stage 2 scores from distinct reviewers, read without the vault
/// (NOTE 4). The ranking itself rechecks the reviewers with the vault.
pub(crate) fn revision_scored_without_vault(state: &State, proposal: ProposalId) -> bool {
    let (Ok(values), Ok(call)) = (governing(state, proposal), current_call(state, proposal)) else {
        return false;
    };
    let p03 = usize::from(values.p03.get());
    facts(state, proposal).is_some_and(|f| {
        f.revisions.iter().any(|plan| {
            let keys = crate::proposal::score::valid_keys(
                state,
                proposal,
                call,
                crate::scoring::Stage::Two,
                *plan,
            );
            let scored: BTreeSet<AssignmentId> = keys.iter().map(|k| k.assignment).collect();
            assignees(state, &scored).len() >= p03
        })
    })
}

/// The assignees of `ids`.
pub(crate) fn assignees(state: &State, ids: &BTreeSet<AssignmentId>) -> BTreeSet<AccountId> {
    ids.iter()
        .filter_map(|id| state.review.get(*id).map(|a| a.reviewer))
        .collect()
}

/// The proposals of the assignments of `account` that recorded a score
/// (R-CF-04: the scores a Judging account already gave).
pub(crate) fn scored_by(state: &State, account: AccountId) -> BTreeSet<ProposalId> {
    state
        .review
        .assignments()
        .filter(|(id, a)| {
            a.reviewer == account && facts(state, a.proposal).is_some_and(|f| f.given.contains(id))
        })
        .map(|(_, a)| a.proposal)
        .collect()
}

// ---------------------------------------------------------------------------
// Folds
// ---------------------------------------------------------------------------

/// Keeps the rounds in step with a transition folded at `at`. The
/// transition itself is folded by `crate::proposal::intake`.
pub(crate) fn on_transition(
    state: &mut State,
    t: &Transitioned,
    at: Timestamp,
) -> Result<(), FoldError> {
    let entering_stage2 = t.to == StateTag::Stage2;
    let leaving_stage2 = t.from == StateTag::Stage2;
    let entering_irc = t.to == StateTag::IrcReview;
    if !(entering_stage2 || leaving_stage2 || entering_irc) {
        return Ok(());
    }
    let f = facts_mut(state, t.proposal)?;
    if leaving_stage2 {
        f.round = None;
    }
    if entering_stage2 {
        f.round = Some(Round {
            opened: at,
            questions: BTreeSet::new(),
            no_questions: BTreeSet::new(),
            answered: false,
        });
    }
    if entering_irc {
        f.irc = BTreeMap::new();
        f.concern = None;
    }
    Ok(())
}
