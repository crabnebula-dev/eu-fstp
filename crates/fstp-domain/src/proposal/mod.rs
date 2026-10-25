//! Proposals and plan versions (design section 2.8).
//!
//! Owned by lane L-LIFE (docs/handoff/m2-design.md section 10). Step W1c
//! declared only the vocabulary the interface names and the empty
//! [`ProposalStore`]. The proposal states themselves are the tags in
//! [`crate::rules::StateTag`]. Lane L-LIFE completes the lifecycle.

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
/// Declared empty by W1c so that `State` can hold it. Lane L-LIFE fills it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProposalStore {
    _pending: (),
}

impl ProposalStore {
    /// The proposal store before any record.
    pub(crate) const fn genesis() -> ProposalStore {
        ProposalStore { _pending: () }
    }
}

// ---------------------------------------------------------------------------
// Engine entry points of this lane, called by `crate::engine`.
// ---------------------------------------------------------------------------

/// The vault questions of the proposal lifecycle commands.
///
/// Declared by W1c as a stub. Lane L-LIFE completes it.
pub(crate) fn queries(
    state: &crate::state::State,
    cmd: &crate::command::Command,
    ctx: &crate::command::Ctx,
) -> Result<Vec<crate::oracle::Query>, crate::refusal::Refusal> {
    let _ = (state, cmd, ctx);
    Err(crate::refusal::Refusal::not_implemented())
}

/// The records of the proposal lifecycle commands.
///
/// Declared by W1c as a stub. Lane L-LIFE completes it.
pub(crate) fn decide(
    state: &crate::state::State,
    cmd: &crate::command::Command,
    ctx: &crate::command::Ctx,
    answers: &crate::oracle::Answers,
) -> Result<Vec<crate::record::Record>, crate::refusal::Refusal> {
    let _ = (state, cmd, ctx, answers);
    Err(crate::refusal::Refusal::not_implemented())
}

/// Folds a proposal lifecycle record.
///
/// Declared by W1c as a stub. Lane L-LIFE completes it.
pub(crate) fn apply(
    state: &mut crate::state::State,
    seq: fstp_ledger::Seq,
    at: crate::time::Timestamp,
    record: &crate::record::Record,
) -> Result<(), crate::engine::FoldError> {
    let _ = (state, seq, at, record);
    Err(crate::engine::FoldError::NotImplemented)
}

/// The System commands of this lane that are enabled at `now` (design section 3.6).
///
/// Declared by W1c as a stub. Lane L-LIFE completes it.
pub(crate) fn due(
    state: &crate::state::State,
    now: crate::time::Timestamp,
) -> Vec<crate::command::Command> {
    let _ = (state, now);
    Vec::new()
}

/// The vault questions this lane needs for its contribution to the batch of
/// a command that another lane owns. It reads only the state and the command.
///
/// Declared by W1c as a stub that asks nothing. Lane L-LIFE completes it.
pub(crate) fn contribute_queries(
    state: &crate::state::State,
    cmd: &crate::command::Command,
    ctx: &crate::command::Ctx,
) -> Result<Vec<crate::oracle::Query>, crate::refusal::Refusal> {
    let _ = (state, cmd, ctx);
    Ok(Vec::new())
}

/// The records this lane adds to the batch of a command that another lane
/// owns, given the records so far (`crate::engine` module docs).
/// Example: voiding the scores of assignments that the batch released (enforcement point 3).
///
/// Declared by W1c as a stub that adds nothing. Lane L-LIFE completes it.
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
/// (R-MC-05, `crate::engine::PolicyScope`).
///
/// Declared by W1c as a stub. Lane L-LIFE completes it.
pub(crate) fn governing_policy(
    state: &crate::state::State,
    cmd: &crate::command::Command,
) -> Result<crate::engine::PolicyScope, crate::refusal::Refusal> {
    let _ = (state, cmd);
    Err(crate::refusal::Refusal::not_implemented())
}
