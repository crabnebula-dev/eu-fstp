//! Grants, reservations and deliverables (design section 2.11, I-13, I-14, I-15).
//!
//! Owned by lane L-MONEY (docs/handoff/m2-design.md section 10). Step W1c
//! declared only the vocabulary the interface names, the empty
//! [`MoneyState`] and the [`GrantDecided`] payload that only a
//! `GrantClearance` may build. Lane L-MONEY completes the witnesses.

use fstp_money::{NonNegAmount, PosAmount};

use crate::id::{ContractId, DecisionId, PlanVersionId, ProposalId, TextRef, VaultEpoch};
use crate::record::RulesVersion;

/// One recorded deduction for ineligible costs, with its reason (I-13).
///
/// Declared by W1c for the interface. Lane L-MONEY completes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IneligibleCost {
    /// The amount deducted.
    pub amount: PosAmount,
    /// The recorded reason.
    pub reason: TextRef,
}

/// The NEGOTIATION to GRANTED record. Only a builder taking a
/// `GrantClearance` may construct it (I-13, I-14, I-15).
///
/// Declared by W1c for the interface. Lane L-MONEY adds that builder.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GrantDecided {
    proposal: ProposalId,
    granted: NonNegAmount,
    agreed_plan: PlanVersionId,
    acceptance: DecisionId,
    approval: DecisionId,
    contract: ContractId,
    epoch: VaultEpoch,
    rules: RulesVersion,
}

impl GrantDecided {
    /// Every field, for the record decoder in `codec/` only (design section 3.5).
    /// Lane L-CODEC calls it. Every other path builds the record from a `GrantClearance`.
    #[allow(dead_code, reason = "reserved for the record decoder of lane L-CODEC")]
    #[expect(
        clippy::too_many_arguments,
        reason = "one argument per field of the decoded record"
    )]
    pub(crate) fn from_decoded(
        proposal: ProposalId,
        granted: NonNegAmount,
        agreed_plan: PlanVersionId,
        acceptance: DecisionId,
        approval: DecisionId,
        contract: ContractId,
        epoch: VaultEpoch,
        rules: RulesVersion,
    ) -> Self {
        GrantDecided {
            proposal,
            granted,
            agreed_plan,
            acceptance,
            approval,
            contract,
            epoch,
            rules,
        }
    }

    /// The proposal.
    pub fn proposal(&self) -> ProposalId {
        self.proposal
    }

    /// The granted amount.
    pub fn granted(&self) -> NonNegAmount {
        self.granted
    }

    /// The agreed plan version, whose total equals the granted amount.
    pub fn agreed_plan(&self) -> PlanVersionId {
        self.agreed_plan
    }

    /// The applicant's acceptance decision.
    pub fn acceptance(&self) -> DecisionId {
        self.acceptance
    }

    /// The programme manager's approval decision.
    pub fn approval(&self) -> DecisionId {
        self.approval
    }

    /// The effective contract.
    pub fn contract(&self) -> ContractId {
        self.contract
    }

    /// The vault epoch of the clearance answers.
    pub fn epoch(&self) -> VaultEpoch {
        self.epoch
    }

    /// The rules version that produced the decision.
    pub fn rules(&self) -> RulesVersion {
        self.rules
    }
}

/// Money part of the projection: granted and reserved sums per programme
/// and account, and deliverable completeness.
///
/// Declared empty by W1c so that `State` can hold it. Lane L-MONEY fills it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MoneyState {
    _pending: (),
}

impl MoneyState {
    /// The money state before any record.
    pub(crate) const fn genesis() -> MoneyState {
        MoneyState { _pending: () }
    }
}

// ---------------------------------------------------------------------------
// Engine entry points of this lane, called by `crate::engine`.
// ---------------------------------------------------------------------------

/// The vault questions of the grant, negotiation and execution commands.
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

/// The records of the grant, negotiation and execution commands.
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

/// Folds a grant, negotiation and execution record.
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

/// The System commands of this lane that are enabled at `now` (design section 3.6).
///
/// Declared by W1c as a stub. Lane L-MONEY completes it.
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
/// Example: releasing the open reservation of a proposal that the batch withdraws (row 15).
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
