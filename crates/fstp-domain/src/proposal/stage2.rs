//! Stage 2: questions, "no questions", answers and revisions (R-EV-05, NOTE 1, NOTE 4).
//!
//! Written by lane L-LIFE in step W4b.
//!
//! - The stage 2 window opens when the proposal enters STAGE2, also on
//!   re-entry, and closes P-07 whole days later. Every act here needs the
//!   window open: `now` before the close.
//! - `AskQuestion` and `RecordNoQuestions` are reviewer acts through a
//!   reviewer assignment of the current call. A reviewer who recorded "no
//!   questions" asks nothing more, and each assignment records "no
//!   questions" once and only without a question of its own.
//! - When every active assigned reviewer of the current call recorded "no
//!   questions", the window closes at once with answers deemed complete.
//!   The last record then takes STAGE2 to RANKED in the same batch, with
//!   the effective score of P-24 (NOTE 4, O-50, I-09).
//! - `AnswerQuestions` is the lead's and needs a question in the round.
//!   `SubmitRevision` is the lead's and submits a live stage 2 revision
//!   that was not submitted before. The plan itself is recorded with
//!   `RecordPlanVersion` of origin "stage 2 revision" (`intake`).
//!
//! Readings of this lane, reported to Daniel: answers are the
//! `AnswersRecorded` records only, so a submitted revision alone is not an
//! answer. A question may be asked more than once through one assignment.

use crate::assignment::{AssignmentKind, conflict_query, reviewer_act};
use crate::command::{Command, Ctx};
use crate::engine::FoldError;
use crate::id::{AccountId, AssignmentId, PlanVersionId, ProposalId};
use crate::oracle::{Answers, Query};
use crate::proposal::PlanOrigin;
use crate::proposal::life::{
    active_assignments, current_call, facts, facts_mut, invalid, open_round, require_lead,
    wrong_state,
};
use crate::record::Record;
use crate::refusal::{Refusal, RefusalReason, RuleRef};
use crate::state::State;

/// Whether `cmd` is a stage 2 act of this module.
pub(crate) const fn is_stage2_command(cmd: &Command) -> bool {
    matches!(
        cmd,
        Command::AskQuestion { .. }
            | Command::RecordNoQuestions { .. }
            | Command::AnswerQuestions { .. }
            | Command::SubmitRevision { .. }
    )
}

/// Whether `record` is a stage 2 record of this module.
pub(crate) const fn is_stage2_record(record: &Record) -> bool {
    matches!(
        record,
        Record::QuestionAsked { .. }
            | Record::NoQuestionsRecorded { .. }
            | Record::AnswersRecorded { .. }
            | Record::RevisionSubmitted { .. }
    )
}

/// The reviewer of a reviewer act through `assignment` on `proposal`, checked
/// against the state without the vault answer.
fn reviewer_basis(
    state: &State,
    proposal: ProposalId,
    assignment: AssignmentId,
    ctx: &Ctx,
) -> Result<AccountId, Refusal> {
    let account = crate::policy::actor_account(ctx)?;
    let a = crate::assignment::reviewer_basis(state, account, assignment, ctx.now)?;
    if a.kind != AssignmentKind::Reviewer || a.proposal != proposal {
        return Err(invalid());
    }
    Ok(account)
}

/// Whether `assignment` recording "no questions" completes the round: every
/// active reviewer assignment of the current call recorded it (O-50).
fn completes_round(
    state: &State,
    proposal: ProposalId,
    assignment: AssignmentId,
) -> Result<bool, Refusal> {
    let call = current_call(state, proposal)?;
    let active = active_assignments(state, proposal, call, AssignmentKind::Reviewer);
    let recorded = facts(state, proposal)
        .and_then(|f| f.round.as_ref())
        .map(|r| r.no_questions.clone())
        .unwrap_or_default();
    Ok(active
        .iter()
        .all(|id| *id == assignment || recorded.contains(id)))
}

/// What a checked stage 2 act needs from the vault and records.
enum Planned {
    /// A reviewer act: its account and the record. `ranks` is set when the
    /// act is the last "no questions" of the round.
    Reviewer {
        account: AccountId,
        proposal: ProposalId,
        assignment: AssignmentId,
        record: Record,
        ranks: bool,
    },
    /// An act of the lead.
    Lead(Record),
}

/// Checks a stage 2 act against the state.
fn plan(state: &State, cmd: &Command, ctx: &Ctx) -> Result<Planned, Refusal> {
    match cmd {
        Command::AskQuestion {
            proposal,
            assignment,
            text,
        } => {
            let account = reviewer_basis(state, *proposal, *assignment, ctx)?;
            let round = open_round(state, *proposal, ctx.now)?;
            if round.no_questions.contains(assignment) {
                return Err(Refusal::new(RuleRef::Rev05, RefusalReason::GuardFailed));
            }
            Ok(Planned::Reviewer {
                account,
                proposal: *proposal,
                assignment: *assignment,
                record: Record::QuestionAsked {
                    proposal: *proposal,
                    assignment: *assignment,
                    text: *text,
                },
                ranks: false,
            })
        }
        Command::RecordNoQuestions {
            proposal,
            assignment,
        } => {
            let account = reviewer_basis(state, *proposal, *assignment, ctx)?;
            let round = open_round(state, *proposal, ctx.now)?;
            if round.no_questions.contains(assignment) || round.questions.contains(assignment) {
                return Err(Refusal::new(RuleRef::Rev05, RefusalReason::GuardFailed));
            }
            Ok(Planned::Reviewer {
                account,
                proposal: *proposal,
                assignment: *assignment,
                record: Record::NoQuestionsRecorded {
                    proposal: *proposal,
                    assignment: *assignment,
                },
                // The last "no questions" ranks only while the active
                // reviewers span P-39 organisations (I-34). Otherwise it is
                // recorded alone, and a reassignment completes the round.
                ranks: completes_round(state, *proposal, *assignment)?
                    && crate::decision::require_stage2_organisations(state, *proposal, ctx.now)
                        .is_ok(),
            })
        }
        Command::AnswerQuestions { proposal, text } => {
            require_lead(state, *proposal, ctx)?;
            let round = open_round(state, *proposal, ctx.now)?;
            if round.questions.is_empty() {
                return Err(Refusal::new(RuleRef::Rev05, RefusalReason::GuardFailed));
            }
            Ok(Planned::Lead(Record::AnswersRecorded {
                proposal: *proposal,
                text: *text,
            }))
        }
        Command::SubmitRevision { proposal, plan } => {
            require_lead(state, *proposal, ctx)?;
            open_round(state, *proposal, ctx.now)?;
            check_revision(state, *proposal, *plan)?;
            Ok(Planned::Lead(Record::RevisionSubmitted {
                proposal: *proposal,
                plan: *plan,
            }))
        }
        _ => Err(wrong_state()),
    }
}

/// Refuses unless `plan` is a live stage 2 revision of `proposal` that was
/// not submitted before (R-EV-05, NOTE 1).
fn check_revision(state: &State, proposal: ProposalId, plan: PlanVersionId) -> Result<(), Refusal> {
    let p = crate::proposal::intake::plan(state, plan).ok_or_else(invalid)?;
    let submitted = facts(state, proposal).is_some_and(|f| f.revisions.contains(&plan));
    if p.proposal != proposal || p.origin != PlanOrigin::Stage2Revision || p.superseded || submitted
    {
        return Err(invalid());
    }
    Ok(())
}

/// The vault questions of a stage 2 act: `HasConflict` for a reviewer, and
/// the questions of the ranking when the act completes the round.
pub(crate) fn queries(state: &State, cmd: &Command, ctx: &Ctx) -> Result<Vec<Query>, Refusal> {
    match plan(state, cmd, ctx)? {
        Planned::Reviewer {
            account,
            proposal,
            ranks,
            ..
        } => {
            let mut out = vec![conflict_query(state, account, proposal)];
            if ranks {
                out.extend(crate::decision::ranking_queries(state, proposal)?);
            }
            Ok(out)
        }
        Planned::Lead(_) => Ok(Vec::new()),
    }
}

/// The records of a stage 2 act.
pub(crate) fn decide(
    state: &State,
    cmd: &Command,
    ctx: &Ctx,
    answers: &Answers,
) -> Result<Vec<Record>, Refusal> {
    match plan(state, cmd, ctx)? {
        Planned::Reviewer {
            account,
            proposal,
            assignment,
            record,
            ranks,
        } => {
            reviewer_act(state, account, assignment, ctx.now, answers)?
                .require_proposal(proposal)?;
            let mut out = Vec::new();
            crate::decision::record_answer(
                &mut out,
                &conflict_query(state, account, proposal),
                answers,
            )?;
            out.push(record);
            if ranks {
                out.extend(crate::decision::ranking_records(
                    state, proposal, ctx, answers, &out,
                )?);
            }
            Ok(out)
        }
        Planned::Lead(record) => Ok(vec![record]),
    }
}

/// Folds a stage 2 record. Questions, "no questions" and answers need an
/// open round. A revision must be a plan of the proposal, submitted once.
pub(crate) fn apply(state: &mut State, record: &Record) -> Result<(), FoldError> {
    match record {
        Record::QuestionAsked {
            proposal,
            assignment,
            ..
        } => {
            let round = facts_mut(state, *proposal)?
                .round
                .as_mut()
                .ok_or(FoldError::Inconsistent)?;
            round.questions.insert(*assignment);
            Ok(())
        }
        Record::NoQuestionsRecorded {
            proposal,
            assignment,
        } => {
            let round = facts_mut(state, *proposal)?
                .round
                .as_mut()
                .ok_or(FoldError::Inconsistent)?;
            if !round.no_questions.insert(*assignment) {
                return Err(FoldError::Inconsistent);
            }
            Ok(())
        }
        Record::AnswersRecorded { proposal, .. } => {
            let round = facts_mut(state, *proposal)?
                .round
                .as_mut()
                .ok_or(FoldError::Inconsistent)?;
            round.answered = true;
            Ok(())
        }
        Record::RevisionSubmitted { proposal, plan } => {
            let p = crate::proposal::intake::plan(state, *plan).ok_or(FoldError::UnknownEntity)?;
            if p.proposal != *proposal {
                return Err(FoldError::Inconsistent);
            }
            let f = facts_mut(state, *proposal)?;
            if f.revisions.contains(plan) {
                return Err(FoldError::Inconsistent);
            }
            f.revisions.push(*plan);
            Ok(())
        }
        _ => Err(FoldError::Inconsistent),
    }
}
