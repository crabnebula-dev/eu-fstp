//! Programmes and calls (design section 2.5).
//!
//! Owned by lane L-POL (docs/handoff/m2-design.md section 10). Step W1c
//! declared only the empty [`CallState`] that `State` holds. Lane L-POL
//! completes the call views, R-PC-03 drafter sets and publication.

use crate::id::{CallSeq, ProgrammeId};

/// Call part of the projection: call status, sequence, budget, authors,
/// approval, frozen policy and pinned configuration per call.
///
/// Declared empty by W1c so that `State` can hold it. Lane L-POL fills it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CallState {
    _pending: (),
}

impl CallState {
    /// The call state before any record.
    pub(crate) const fn genesis() -> CallState {
        CallState { _pending: () }
    }

    /// The sequence number of the latest call published in `programme`, if any.
    /// Lane L-SOD reads it to pin cooling-off bars (P-12 NOTE 4).
    ///
    /// Declared by W1c as a stub that finds no call. Lane L-POL completes it.
    #[allow(dead_code, reason = "lane L-SOD calls it")]
    pub(crate) fn latest_published_seq(&self, programme: ProgrammeId) -> Option<CallSeq> {
        let _ = programme;
        None
    }
}

// ---------------------------------------------------------------------------
// Engine entry points of this lane, called by `crate::engine`.
// ---------------------------------------------------------------------------

/// The vault questions of the call commands.
///
/// Declared by W1c as a stub. Lane L-POL completes it.
pub(crate) fn queries(
    state: &crate::state::State,
    cmd: &crate::command::Command,
    ctx: &crate::command::Ctx,
) -> Result<Vec<crate::oracle::Query>, crate::refusal::Refusal> {
    let _ = (state, cmd, ctx);
    Err(crate::refusal::Refusal::not_implemented())
}

/// The records of the call commands.
///
/// Declared by W1c as a stub. Lane L-POL completes it.
pub(crate) fn decide(
    state: &crate::state::State,
    cmd: &crate::command::Command,
    ctx: &crate::command::Ctx,
    answers: &crate::oracle::Answers,
) -> Result<Vec<crate::record::Record>, crate::refusal::Refusal> {
    let _ = (state, cmd, ctx, answers);
    Err(crate::refusal::Refusal::not_implemented())
}

/// Folds a call record.
///
/// Declared by W1c as a stub. Lane L-POL completes it.
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
/// Declared by W1c as a stub that asks nothing. Lane L-POL completes it.
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
/// The call lane is not expected to contribute in M2.
///
/// Declared by W1c as a stub that adds nothing. Lane L-POL completes it.
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
/// Declared by W1c as a stub. Lane L-POL completes it.
pub(crate) fn governing_policy(
    state: &crate::state::State,
    cmd: &crate::command::Command,
) -> Result<crate::engine::PolicyScope, crate::refusal::Refusal> {
    let _ = (state, cmd);
    Err(crate::refusal::Refusal::not_implemented())
}
