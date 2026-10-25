//! Assignments, conflicts, handles and reads (design section 2.7, I-03).
//!
//! Owned by lane L-REV (docs/handoff/m2-design.md section 10). Step W1c
//! declared only the vocabulary the interface names and the empty
//! [`ReviewState`]. Lane L-REV completes the `ReviewerAct` witness and the
//! assignment rules.

use crate::id::AmendmentId;

/// What an assignment is for.
///
/// Declared by W1c for the interface. Lane L-REV completes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AssignmentKind {
    /// An assigned reviewer over a committee member binding.
    Reviewer,
    /// An IRC review over an IRC member binding.
    Irc,
    /// An IRC review of an amendment.
    Amendment(AmendmentId),
}

/// Why an assignment was released.
///
/// Declared by W1c for the interface. Lane L-REV completes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReleaseCause {
    /// The assignee declared a conflict (R-CF-02).
    DeclaredConflict,
    /// The vault detected a conflict (I-03).
    DetectedConflict,
    /// The FSTP coordinator unassigned the reviewer.
    Unassigned,
    /// The underlying binding ended.
    BindingEnded,
    /// The underlying binding was suspended.
    BindingSuspended,
    /// The underlying binding was voided.
    BindingVoided,
}

/// Review part of the projection: assignments, conflict facts, issued
/// handles and reviewed-by facts (I-36).
///
/// Declared empty by W1c so that `State` can hold it. Lane L-REV fills it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ReviewState {
    _pending: (),
}

impl ReviewState {
    /// The review state before any record.
    pub(crate) const fn genesis() -> ReviewState {
        ReviewState { _pending: () }
    }
}

// ---------------------------------------------------------------------------
// Engine entry points of this lane, called by `crate::engine`.
// ---------------------------------------------------------------------------

/// The vault questions of the assignment, conflict, read and ranking summary commands.
///
/// Declared by W1c as a stub. Lane L-REV completes it.
pub(crate) fn queries(
    state: &crate::state::State,
    cmd: &crate::command::Command,
    ctx: &crate::command::Ctx,
) -> Result<Vec<crate::oracle::Query>, crate::refusal::Refusal> {
    let _ = (state, cmd, ctx);
    Err(crate::refusal::Refusal::not_implemented())
}

/// The records of the assignment, conflict, read and ranking summary commands.
///
/// Declared by W1c as a stub. Lane L-REV completes it.
pub(crate) fn decide(
    state: &crate::state::State,
    cmd: &crate::command::Command,
    ctx: &crate::command::Ctx,
    answers: &crate::oracle::Answers,
) -> Result<Vec<crate::record::Record>, crate::refusal::Refusal> {
    let _ = (state, cmd, ctx, answers);
    Err(crate::refusal::Refusal::not_implemented())
}

/// Folds a assignment, conflict, read and ranking summary record.
///
/// Declared by W1c as a stub. Lane L-REV completes it.
pub(crate) fn apply(
    state: &mut crate::state::State,
    seq: fstp_ledger::Seq,
    at: crate::time::Timestamp,
    record: &crate::record::Record,
) -> Result<(), crate::engine::FoldError> {
    let _ = (state, seq, at, record);
    Err(crate::engine::FoldError::NotImplemented)
}

/// The vault questions this lane needs for its contribution to the batch of
/// a command that another lane owns. It reads only the state and the command.
///
/// Declared by W1c as a stub that asks nothing. Lane L-REV completes it.
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
/// Example: the `ConflictDetected` and `AssignmentReleased` records of a vault change or of a voided binding (enforcement point 3).
///
/// Declared by W1c as a stub that adds nothing. Lane L-REV completes it.
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
/// Declared by W1c as a stub. Lane L-REV completes it.
pub(crate) fn governing_policy(
    state: &crate::state::State,
    cmd: &crate::command::Command,
) -> Result<crate::engine::PolicyScope, crate::refusal::Refusal> {
    let _ = (state, cmd);
    Err(crate::refusal::Refusal::not_implemented())
}
