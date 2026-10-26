//! Scores and corrections: `RecordScore` and `CorrectScore` (design section 2.9, NOTE 3, NOTE 4).
//!
//! Written by lane L-LIFE in step W4b.
//!
//! - A score is a reviewer act. It needs a [`crate::assignment::ReviewerAct`]
//!   over a reviewer assignment of the stage's call: the creation call for
//!   stage 1, which is the current call in STAGE1, and the current call for
//!   stage 2 (NOTE 8).
//! - Stage 1 scores the submitted plan in STAGE1. Stage 2 scores a
//!   submitted revision in STAGE2. Scores seal when the proposal leaves the
//!   stage, so no score is taken outside it (NOTE 3).
//! - Every value lies in 0 to N, one per P-01 criterion (NOTE 6).
//! - `RecordScore` needs a key with no current value. `CorrectScore` needs
//!   one with a current value, and supersedes its entry with a reason.
//! - The fold replaces the current value of a key, so a corrected value
//!   never counts twice. A void removes it.
//! - The fold refuses a correction or a void once the key's stage
//!   sealed, with `FoldError::SealedStage` (design 5.1, NOTE 3, step W5
//!   integration). `decide` never writes one, so every ledger the engine
//!   writes still replays.
//! - [`ScoreFacts`] is the quorum's view of the proposal store.

use std::collections::BTreeSet;

use fstp_ledger::Seq;

use crate::assignment::{AssignmentKind, conflict_query, reviewer_act};
use crate::command::{Command, Ctx};
use crate::engine::FoldError;
use crate::id::{AccountId, CallId, PlanVersionId, ProposalId};
use crate::oracle::{Answers, Query};
use crate::proposal::PlanOrigin;
use crate::proposal::ProposalStore;
use crate::proposal::life::{facts, facts_mut, invalid, state_of, unknown, wrong_state};
use crate::record::{Record, ScoreRecorded};
use crate::refusal::{Refusal, RefusalReason, RuleRef};
use crate::rules::{ParamId, StateTag};
use crate::scoring::{ScoreFacts, ScoreKey, ScoreSheet, Stage};
use crate::state::State;

/// Whether `cmd` is a score command.
pub(crate) const fn is_score_command(cmd: &Command) -> bool {
    matches!(
        cmd,
        Command::RecordScore { .. } | Command::CorrectScore { .. }
    )
}

/// A checked score command: the assignee and proposal, and the record.
struct Planned {
    account: AccountId,
    proposal: ProposalId,
    record: ScoreRecorded,
}

/// Checks a score command against the state, without the vault answer.
fn plan(state: &State, cmd: &Command, ctx: &Ctx) -> Result<Planned, Refusal> {
    let (key, values, reason) = match cmd {
        Command::RecordScore { key, values } => (*key, values, None),
        Command::CorrectScore {
            key,
            values,
            reason,
        } => (*key, values, Some(*reason)),
        _ => return Err(wrong_state()),
    };
    let account = crate::policy::actor_account(ctx)?;
    let a = crate::assignment::reviewer_basis(state, account, key.assignment, ctx.now)?;
    if a.kind != AssignmentKind::Reviewer {
        return Err(Refusal::new(RuleRef::Actor, RefusalReason::WrongActor));
    }
    let proposal = a.proposal;
    let current = state_of(state, proposal)?;
    let f = facts(state, proposal);
    match key.stage {
        Stage::One => {
            if current != StateTag::Stage1 {
                return Err(wrong_state());
            }
            let submitted = crate::proposal::intake::submission(state, proposal).map(|s| s.plan);
            if submitted != Some(key.plan) {
                return Err(invalid());
            }
        }
        Stage::Two => {
            if current != StateTag::Stage2 {
                return Err(wrong_state());
            }
            if !f.is_some_and(|x| x.revisions.contains(&key.plan)) {
                return Err(invalid());
            }
        }
    }
    let p01 = &crate::proposal::life::governing(state, proposal)?.p01;
    p01.check_vector(values)
        .map_err(|_| Refusal::new(RuleRef::Param(ParamId::P01), RefusalReason::InvalidValue))?;
    let entry = f.and_then(|x| x.entries.get(&key)).copied();
    let supersedes = match (reason, entry) {
        (None, None) => None,
        (Some(_), Some(seq)) => Some(seq),
        (None, Some(_)) | (Some(_), None) => return Err(invalid()),
    };
    Ok(Planned {
        account,
        proposal,
        record: ScoreRecorded {
            key,
            values: values.clone(),
            supersedes,
            reason,
        },
    })
}

/// The vault question of a score command: `HasConflict` for the assignee (I-03).
pub(crate) fn queries(state: &State, cmd: &Command, ctx: &Ctx) -> Result<Vec<Query>, Refusal> {
    let p = plan(state, cmd, ctx)?;
    Ok(vec![conflict_query(state, p.account, p.proposal)])
}

/// The records of a score command: the vault answer used and the score.
pub(crate) fn decide(
    state: &State,
    cmd: &Command,
    ctx: &Ctx,
    answers: &Answers,
) -> Result<Vec<Record>, Refusal> {
    let p = plan(state, cmd, ctx)?;
    let act = reviewer_act(state, p.account, p.record.key.assignment, ctx.now, answers)?;
    act.require_proposal(p.proposal)?;
    let mut out = Vec::new();
    crate::decision::record_answer(
        &mut out,
        &conflict_query(state, p.account, p.proposal),
        answers,
    )?;
    out.push(Record::ScoreRecorded(p.record));
    Ok(out)
}

/// The proposal of `key`, and whether its stage has sealed (NOTE 3).
///
/// A key is open while the proposal is in the key's stage, unless the key
/// held a current value when the proposal last left that stage. So the
/// stage 2 keys of the call a proposal was deferred from stay sealed after
/// its re-entry (NOTE 8). Only a recorded complaint remedy reopens a
/// sealed stage. M2 records none, so no record reopens one here.
fn score_stage(state: &State, key: ScoreKey) -> Result<(ProposalId, bool), FoldError> {
    let proposal = state
        .review
        .get(key.assignment)
        .map(|a| a.proposal)
        .ok_or(FoldError::UnknownEntity)?;
    let current =
        crate::proposal::intake::proposal_state(state, proposal).ok_or(FoldError::UnknownEntity)?;
    let in_stage = match key.stage {
        Stage::One => current == StateTag::Stage1,
        Stage::Two => current == StateTag::Stage2,
    };
    let left = facts(state, proposal).is_some_and(|f| f.sealed.contains(&key));
    Ok((proposal, !in_stage || left))
}

/// Folds a score or a correction at entry `seq`. A correction must name the
/// entry of the key's current value, and a first score finds none (I-23).
/// A correction on a sealed stage is refused (design 5.1, NOTE 3). A first
/// score on a sealed stage still folds, since `decide` takes one only in
/// its stage. Whether the fold should refuse it too is open for Daniel.
pub(crate) fn apply_score(state: &mut State, seq: Seq, s: &ScoreRecorded) -> Result<(), FoldError> {
    let (proposal, sealed) = score_stage(state, s.key)?;
    let entry = facts(state, proposal).and_then(|f| f.entries.get(&s.key).copied());
    if s.supersedes != entry {
        return Err(FoldError::CorrectionTarget);
    }
    if s.supersedes.is_some() && sealed {
        return Err(FoldError::SealedStage);
    }
    let f = facts_mut(state, proposal)?;
    f.sheet.record(s.key, s.values.clone());
    f.entries.insert(s.key, seq);
    f.given.insert(s.key.assignment);
    Ok(())
}

/// Folds a void: the key's current value stops counting. A void on a
/// sealed stage is refused (design 5.1, NOTE 3).
pub(crate) fn apply_void(state: &mut State, key: ScoreKey) -> Result<(), FoldError> {
    let (proposal, sealed) = score_stage(state, key)?;
    if !facts(state, proposal).is_some_and(|f| f.entries.contains_key(&key)) {
        return Err(FoldError::Inconsistent);
    }
    if sealed {
        return Err(FoldError::SealedStage);
    }
    let f = facts_mut(state, proposal)?;
    if f.sheet.void(key).is_none() {
        return Err(FoldError::Inconsistent);
    }
    f.entries.remove(&key);
    Ok(())
}

/// The valid stage 1 keys of `proposal` on its submitted plan, without the
/// vault: current values from active reviewer assignments of the creation
/// call whose assignee has no conflict fact (NOTE 3).
pub(crate) fn valid_stage1_keys(state: &State, proposal: ProposalId) -> BTreeSet<ScoreKey> {
    let Some(plan) = crate::proposal::intake::submission(state, proposal).map(|s| s.plan) else {
        return BTreeSet::new();
    };
    let Some(call) = crate::proposal::draft::proposal_call(state, proposal) else {
        return BTreeSet::new();
    };
    valid_keys(state, proposal, call, Stage::One, plan)
}

/// The current keys on `stage` and `plan` of `proposal` from active
/// reviewer assignments of `call` with no conflict fact.
pub(crate) fn valid_keys(
    state: &State,
    proposal: ProposalId,
    call: CallId,
    stage: Stage,
    plan: PlanVersionId,
) -> BTreeSet<ScoreKey> {
    let active =
        crate::proposal::life::active_assignments(state, proposal, call, AssignmentKind::Reviewer);
    facts(state, proposal)
        .map(|f| {
            f.sheet
                .on(stage, plan)
                .map(|(k, _)| *k)
                .filter(|k| active.contains(&k.assignment))
                .collect()
        })
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// The quorum's view of the proposal store
// ---------------------------------------------------------------------------

impl ScoreFacts for ProposalStore {
    fn governing_call(&self, proposal: ProposalId) -> Result<Option<CallId>, Refusal> {
        Ok(self.drafts.get(proposal).map(|d| d.call))
    }

    fn current_call(&self, proposal: ProposalId) -> Result<Option<CallId>, Refusal> {
        let Some(d) = self.drafts.get(proposal) else {
            return Ok(None);
        };
        Ok(Some(
            self.intake.current_call_of(proposal).unwrap_or(d.call),
        ))
    }

    fn plan_origin(
        &self,
        proposal: ProposalId,
        plan: PlanVersionId,
    ) -> Result<Option<PlanOrigin>, Refusal> {
        Ok(self
            .intake
            .plan_of(plan)
            .filter(|p| p.proposal == proposal)
            .map(|p| p.origin))
    }

    fn submitted_plan(&self, proposal: ProposalId) -> Result<Option<PlanVersionId>, Refusal> {
        Ok(self.intake.submission_of(proposal).map(|s| s.plan))
    }

    /// The lead of the proposal. Team members are bindings of lane L-SOD,
    /// which the proposal store does not hold. Every reviewer act also asks
    /// `HasConflict` against the full team through
    /// [`crate::assignment::conflict_query`], so this narrower question
    /// never decides alone.
    fn applicant_team(&self, proposal: ProposalId) -> Result<BTreeSet<AccountId>, Refusal> {
        self.drafts
            .get(proposal)
            .map(|d| [d.lead].into_iter().collect())
            .ok_or_else(unknown)
    }

    fn score_sheet(&self, proposal: ProposalId) -> Result<Option<&ScoreSheet>, Refusal> {
        Ok(self.life.get(proposal).map(|f| &f.sheet))
    }
}

/// The `HasConflict` question that the quorum asks for `reviewer` on
/// `proposal`, against [`ScoreFacts::applicant_team`].
pub(crate) fn quorum_conflict_query(
    state: &State,
    reviewer: AccountId,
    proposal: ProposalId,
) -> Result<Query, Refusal> {
    Ok(Query::HasConflict {
        reviewer,
        team: state.proposals.applicant_team(proposal)?,
    })
}
