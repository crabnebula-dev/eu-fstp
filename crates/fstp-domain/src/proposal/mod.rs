//! Proposals and plan versions (design section 2.8).
//!
//! Owned by lane L-LIFE (docs/handoff/m2-design.md section 10). Step W1c
//! declared only the vocabulary the interface names and the empty
//! [`ProposalStore`]. The proposal states themselves are the tags in
//! [`crate::rules::StateTag`].
//!
//! Lane L-LIFE (step W4b) completes the lifecycle from SUBMITTED to the
//! entry into NEGOTIATION, with deferral and re-entry:
//!
//! - `life` keeps the lifecycle facts of each proposal.
//! - `score` takes scores and corrections and is the quorum's view of the store.
//! - `stage2` takes questions, "no questions", answers and revisions.
//! - `deferral` takes the expiry of stage 2, the re-entry and the decline
//!   after a concern, and lists the System commands that are due.
//! - The decisions of the lifecycle are in [`crate::decision`].

pub(crate) mod deferral;
pub(crate) mod draft;
pub(crate) mod intake;
pub(crate) mod life;
pub(crate) mod score;
pub(crate) mod stage2;

use fstp_money::PosAmount;

use crate::id::{ActivityTypeId, DeliverableId, MilestoneId, TextRef};
use crate::time::Timestamp;

/// Where a plan version comes from.
///
/// Declared by W1c for the interface. Lane L-LIFE completes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PlanOrigin {
    /// The plan of the submission.
    Submitted,
    /// A revised plan in stage 2 (R-EV-05).
    Stage2Revision,
    /// The plan agreed in negotiation (R-NG-03).
    Negotiated,
    /// The plan of an amendment.
    Amendment,
}

/// One milestone of a task. Each milestone carries a start date as well as
/// a due date (`SPEC/02-domain/contracts.md`, decided 2026-10-25).
///
/// Declared by W1c for the interface. Lane L-LIFE completes it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Milestone {
    /// The milestone.
    pub id: MilestoneId,
    /// Its amount, above zero.
    pub amount: PosAmount,
    /// Its start date. GRANTED to IN_EXECUTION uses the earliest (NOTE 11).
    pub start: Timestamp,
    /// Its due date.
    pub due: Timestamp,
    /// Its activity type from the closed list of P-55 (I-47), when set.
    pub activity: Option<ActivityTypeId>,
    /// Its deliverables.
    pub deliverables: Vec<DeliverableId>,
}

/// One task of a plan. Task and plan totals are derived, never stored.
///
/// Declared by W1c for the interface. Lane L-LIFE completes it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Task {
    /// The task's milestones.
    pub milestones: Vec<Milestone>,
}

/// The ethics self-declaration of a submission (R-SB-05).
///
/// Declared by W1c for the interface. Lane L-LIFE completes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EthicsDeclaration {
    /// Whether the applicant declared ethics issues, which are flagged to the assigned reviewers.
    pub issues_declared: bool,
    /// The declaration text.
    pub text: TextRef,
}

/// The stage a deferred proposal left, where it re-enters (NOTE 8).
///
/// Declared by W1c for the interface. Lane L-LIFE completes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReentryStage {
    /// Deferred from STAGE2.
    Stage2,
    /// Deferred from IRC_REVIEW.
    IrcReview,
}

/// The version of the data protection notice M4 showed (R-NG-06).
///
/// Declared by W1c for the interface. Lane L-LIFE completes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NoticeVersion(pub u32);

/// Proposal part of the projection: state, call history, plans, current
/// scores, stage results and negotiation per proposal.
///
/// Declared empty by W1c so that `State` can hold it. Lane L-SOD added the
/// drafts, lane L-REV the intake and lane L-LIFE the lifecycle facts.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProposalStore {
    /// The created proposals, from `draft` (lane L-SOD, step W3b).
    drafts: draft::Drafts,
    /// States, plans and submissions, from `intake` (lane L-REV, step W4a).
    intake: intake::Intake,
    /// Scores, stage results, rounds and deferrals, from `life` (lane L-LIFE, step W4b).
    life: life::Lives,
}

impl ProposalStore {
    /// The proposal store before any record.
    pub(crate) const fn genesis() -> ProposalStore {
        ProposalStore {
            drafts: draft::Drafts::genesis(),
            intake: intake::Intake::genesis(),
            life: life::Lives::genesis(),
        }
    }
}

// ---------------------------------------------------------------------------
// Engine entry points of this lane, called by `crate::engine`.
// ---------------------------------------------------------------------------

/// The vault questions of the proposal lifecycle commands.
pub(crate) fn queries(
    state: &crate::state::State,
    cmd: &crate::command::Command,
    ctx: &crate::command::Ctx,
) -> Result<Vec<crate::oracle::Query>, crate::refusal::Refusal> {
    if is_draft_command(cmd) {
        return draft::queries(state, cmd, ctx);
    }
    if intake::is_intake_command(cmd) {
        return intake::queries(state, cmd, ctx);
    }
    if score::is_score_command(cmd) {
        return score::queries(state, cmd, ctx);
    }
    if stage2::is_stage2_command(cmd) {
        return stage2::queries(state, cmd, ctx);
    }
    if deferral::is_deferral_command(cmd) {
        return deferral::queries(state, cmd, ctx);
    }
    Err(crate::refusal::Refusal::not_implemented())
}

/// Whether `cmd` is one of the commands that `draft` decides.
const fn is_draft_command(cmd: &crate::command::Command) -> bool {
    matches!(
        cmd,
        crate::command::Command::CreateDraft { .. }
            | crate::command::Command::AddTeamMember { .. }
            | crate::command::Command::AddGuardian { .. }
    )
}

/// The records of the proposal lifecycle commands.
pub(crate) fn decide(
    state: &crate::state::State,
    cmd: &crate::command::Command,
    ctx: &crate::command::Ctx,
    answers: &crate::oracle::Answers,
) -> Result<Vec<crate::record::Record>, crate::refusal::Refusal> {
    if is_draft_command(cmd) {
        return draft::decide(state, cmd, ctx, answers);
    }
    if intake::is_intake_command(cmd) {
        return intake::decide(state, cmd, ctx, answers);
    }
    if score::is_score_command(cmd) {
        return score::decide(state, cmd, ctx, answers);
    }
    if stage2::is_stage2_command(cmd) {
        return stage2::decide(state, cmd, ctx, answers);
    }
    if deferral::is_deferral_command(cmd) {
        return deferral::decide(state, cmd, ctx);
    }
    Err(crate::refusal::Refusal::not_implemented())
}

/// Folds a proposal lifecycle record. A transition is folded by `intake`,
/// then `life` keeps the stage rounds in step with it.
pub(crate) fn apply(
    state: &mut crate::state::State,
    seq: fstp_ledger::Seq,
    at: crate::time::Timestamp,
    record: &crate::record::Record,
) -> Result<(), crate::engine::FoldError> {
    use crate::record::Record;
    match record {
        Record::ProposalCreated { .. } => draft::apply(state, record),
        Record::Transitioned(t) => {
            intake::apply(state, record)?;
            life::on_transition(state, t, at)
        }
        Record::ScoreRecorded(s) => score::apply_score(state, seq, s),
        Record::ScoreVoided(v) => score::apply_void(state, v.key),
        _ if intake::is_intake_record(record) => intake::apply(state, record),
        _ if stage2::is_stage2_record(record) => stage2::apply(state, record),
        _ if deferral::is_deferral_record(record) => deferral::apply(state, record),
        _ => Err(crate::engine::FoldError::Inconsistent),
    }
}

/// The System commands of this lane that are enabled at `now` (design
/// section 3.6): `ExpireStage2` and `ReEnter`.
pub(crate) fn due(
    state: &crate::state::State,
    now: crate::time::Timestamp,
) -> Vec<crate::command::Command> {
    deferral::due(state, now)
}

/// The vault questions this lane needs for its contribution to the batch of
/// a command that another lane owns. It reads only the state and the command.
/// The lifecycle contributes to no other lane's batch in M2.
pub(crate) fn contribute_queries(
    state: &crate::state::State,
    cmd: &crate::command::Command,
    ctx: &crate::command::Ctx,
) -> Result<Vec<crate::oracle::Query>, crate::refusal::Refusal> {
    let _ = (state, cmd, ctx);
    Ok(Vec::new())
}

/// The records this lane adds to the batch of a command that another lane
/// owns, given the records so far (`crate::engine` module docs). It adds
/// none: a released assignment's scores stop counting because the quorum
/// counts active assignments only, so no void is recorded (NOTE 3).
pub(crate) fn contribute(
    state: &crate::state::State,
    cmd: &crate::command::Command,
    ctx: &crate::command::Ctx,
    answers: &crate::oracle::Answers,
    batch: &[crate::record::Record],
) -> Result<Vec<crate::record::Record>, crate::refusal::Refusal> {
    let _ = (state, cmd, ctx, answers, batch);
    Ok(Vec::new())
}

/// The policy whose P-77 governs a binding action of this lane through MCP
/// (R-MC-05, `crate::engine::PolicyScope`): the frozen policy of the
/// proposal's original call.
pub(crate) fn governing_policy(
    state: &crate::state::State,
    cmd: &crate::command::Command,
) -> Result<crate::engine::PolicyScope, crate::refusal::Refusal> {
    use crate::command::Command;
    if is_draft_command(cmd) {
        return draft::governing_policy(state, cmd);
    }
    if intake::is_intake_command(cmd) {
        return intake::governing_policy(state, cmd);
    }
    let proposal = match cmd {
        Command::RecordScore { key, .. } | Command::CorrectScore { key, .. } => state
            .review
            .get(key.assignment)
            .map(|a| a.proposal)
            .ok_or_else(life::unknown)?,
        Command::AskQuestion { proposal, .. }
        | Command::RecordNoQuestions { proposal, .. }
        | Command::AnswerQuestions { proposal, .. }
        | Command::SubmitRevision { proposal, .. }
        | Command::ExpireStage2 { proposal }
        | Command::ReEnter { proposal, .. }
        | Command::DeclineAfterConcern { proposal } => *proposal,
        _ => return Err(crate::refusal::Refusal::not_implemented()),
    };
    draft::proposal_call(state, proposal)
        .map(crate::engine::PolicyScope::Call)
        .ok_or_else(life::unknown)
}
