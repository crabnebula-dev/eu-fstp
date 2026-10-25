//! The payments seam (design section 2.12, I-05).
//!
//! Owned by lane L-MONEY (docs/handoff/m2-design.md section 10). Step W1c
//! declared only the vocabulary the interface names, the empty
//! [`PaymentState`] and the [`PaymentReleased`] payload that only a
//! `PaymentChain<Released>` may build. Lane L-MONEY completes the chain.

use std::collections::BTreeSet;

use fstp_money::PosAmount;

use crate::id::{AccountId, LineId, MilestoneId, ProposalId, RequestId};

/// One line of a payment request.
///
/// Declared by W1c for the interface. Lane L-MONEY completes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PaymentLine {
    /// The line.
    pub line: LineId,
    /// The milestone of the same grant it claims against (I-59).
    pub milestone: MilestoneId,
    /// The requested amount.
    pub amount: PosAmount,
}

/// The release record. Only a builder taking a `PaymentChain<Released>` may
/// construct it, so the releaser is never an acceptor or the approver (I-05).
///
/// Declared by W1c for the interface. Lane L-MONEY adds that builder.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PaymentReleased {
    request: RequestId,
    grant: ProposalId,
    acceptors: BTreeSet<AccountId>,
    approver: AccountId,
    releaser: AccountId,
}

impl PaymentReleased {
    /// Every field, for the record decoder in `codec/` only (design section 3.5).
    /// Lane L-CODEC calls it. Every other path builds the record from a
    /// `PaymentChain<Released>`.
    #[allow(dead_code, reason = "reserved for the record decoder of lane L-CODEC")]
    pub(crate) fn from_decoded(
        request: RequestId,
        grant: ProposalId,
        acceptors: BTreeSet<AccountId>,
        approver: AccountId,
        releaser: AccountId,
    ) -> Self {
        PaymentReleased {
            request,
            grant,
            acceptors,
            approver,
            releaser,
        }
    }

    /// The payment request.
    pub fn request(&self) -> RequestId {
        self.request
    }

    /// The grant.
    pub fn grant(&self) -> ProposalId {
        self.grant
    }

    /// The accounts that accepted lines.
    pub fn acceptors(&self) -> &BTreeSet<AccountId> {
        &self.acceptors
    }

    /// The finance approver.
    pub fn approver(&self) -> AccountId {
        self.approver
    }

    /// The payment releaser.
    pub fn releaser(&self) -> AccountId {
        self.releaser
    }
}

/// Payment part of the projection.
///
/// Declared empty by W1c so that `State` can hold it. Lane L-MONEY fills it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PaymentState {
    _pending: (),
}

impl PaymentState {
    /// The payment state before any record.
    pub(crate) const fn genesis() -> PaymentState {
        PaymentState { _pending: () }
    }
}

// ---------------------------------------------------------------------------
// Engine entry points of this lane, called by `crate::engine`.
// ---------------------------------------------------------------------------

/// The vault questions of the payment request commands.
///
/// Declared by W1c as a stub. Lane L-MONEY completes it.
pub(crate) fn queries(
    state: &crate::state::State,
    cmd: &crate::command::Command,
    ctx: &crate::command::Ctx,
) -> Result<Vec<crate::oracle::Query>, crate::refusal::Refusal> {
    let _ = (state, cmd, ctx);
    Err(crate::refusal::Refusal::not_implemented())
}

/// The records of the payment request commands.
///
/// Declared by W1c as a stub. Lane L-MONEY completes it.
pub(crate) fn decide(
    state: &crate::state::State,
    cmd: &crate::command::Command,
    ctx: &crate::command::Ctx,
    answers: &crate::oracle::Answers,
) -> Result<Vec<crate::record::Record>, crate::refusal::Refusal> {
    let _ = (state, cmd, ctx, answers);
    Err(crate::refusal::Refusal::not_implemented())
}

/// Folds a payment request record.
///
/// Declared by W1c as a stub. Lane L-MONEY completes it.
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
/// Declared by W1c as a stub that asks nothing. Lane L-MONEY completes it.
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
/// The payment lane is not expected to contribute in M2.
///
/// Declared by W1c as a stub that adds nothing. Lane L-MONEY completes it.
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
/// Declared by W1c as a stub. Lane L-MONEY completes it.
pub(crate) fn governing_policy(
    state: &crate::state::State,
    cmd: &crate::command::Command,
) -> Result<crate::engine::PolicyScope, crate::refusal::Refusal> {
    let _ = (state, cmd);
    Err(crate::refusal::Refusal::not_implemented())
}
