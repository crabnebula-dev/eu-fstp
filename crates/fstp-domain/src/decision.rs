//! Decisions and decision records (design section 2.10).
//!
//! Owned by lane L-LIFE (docs/handoff/m2-design.md section 10). Step W1c
//! declared only the vocabulary the interface names, and the two record
//! payloads that only a witness may build. Their fields are private. Lane
//! L-LIFE adds their builders, which take the `Stage1Verdict` and
//! `EffectiveScore` witnesses (design section 3.5).

use std::collections::BTreeSet;

use fstp_money::{Percent, Ratio};

use crate::command::{Command, Ctx};
use crate::engine::FoldError;
use crate::id::{AccountId, PlanVersionId, ProposalId, TextRef};
use crate::oracle::{Answers, Query};
use crate::record::Record;
use crate::record::RulesVersion;
use crate::refusal::Refusal;
use crate::scoring::ScoreKey;
use crate::state::State;
use crate::time::Timestamp;
use fstp_ledger::Seq;

/// One committee ballot on a cut-off (R-EV-09). The P-16 details are open (O-44).
///
/// Declared by W1c for the interface. Lane L-LIFE completes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Ballot {
    /// The committee member who cast the ballot.
    pub voter: AccountId,
    /// The vote.
    pub vote: Vote,
    /// The member who delegated this vote to the voter, if any.
    pub delegated_by: Option<AccountId>,
}

/// A committee vote.
///
/// Declared by W1c for the interface. Lane L-LIFE completes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Vote {
    /// For the proposed cut-off.
    For,
    /// Against it.
    Against,
    /// Abstaining.
    Abstain,
}

/// The outcome of one IRC review.
///
/// Declared by W1c for the interface. Lane L-LIFE completes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IrcVerdict {
    /// The IRC member validates the nomination.
    Validate,
    /// The IRC member raises a concern, sent to the applicant (R-IR-02).
    Concern(TextRef),
}

/// Why a negotiation cannot reach GRANTED, as the NEGOTIATION to DECLINED
/// row lists it (`SPEC/02-domain/state-machine.md`, NOTE 9). Each variant
/// names one rule, and `crate::rules::Guard::rule` maps it. Under Q7 A the
/// granted amount is the plan total minus recorded deductions, so the I-13
/// and I-14 failures are told apart by the rule the amount breaks.
///
/// Declared by W1c for the interface. Lane L-LIFE completes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NegotiationFailure {
    /// Identity verification fails (SoD-09).
    IdentityNotVerified,
    /// SoD-09 refuses the applicant.
    Sod09Refused,
    /// The applicant's Receiving bindings were voided under I-04.
    ReceivingVoidedUnderI04,
    /// The applicant's Receiving bindings were voided under I-06.
    ReceivingVoidedUnderI06,
    /// No grant amount can keep I-13: the determined amount lies outside P-04.
    NoAmountWithinRange,
    /// No grant amount can keep I-14: the determined amount exceeds the cap headroom.
    NoAmountWithinCap,
    /// The I-15 deliverable record is incomplete.
    RepeatRecordIncomplete,
    /// Guardian consent (I-18) is missing.
    GuardianConsentMissing,
}

/// Which plan version an effective score names (I-09).
///
/// Declared by W1c for the interface. Lane L-LIFE completes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Basis {
    /// The original plan carries forward.
    Original,
    /// The revised plan carries forward.
    Revised,
}

/// The stage 1 exit record. Its outcome is computed, never chosen (I-07, I-08).
/// Only a builder taking a `Stage1Verdict` may construct it. A computed
/// outcome carries no `DecisionId`, as `Transitioned::decision` is `None`
/// for it. The ledger entry identifies the record, and the recorder names
/// the human (R-LA-03).
///
/// Declared by W1c for the interface. Lane L-LIFE adds that builder.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Stage1Closed {
    proposal: ProposalId,
    recorder: AccountId,
    score: Ratio,
    threshold: Percent,
    counted: BTreeSet<ScoreKey>,
    passed: bool,
    rules: RulesVersion,
}

impl Stage1Closed {
    /// Every field, for the record decoder in `codec/` only (design section 3.5).
    /// Lane L-CODEC calls it. Every other path builds the record from a `Stage1Verdict`.
    #[allow(dead_code, reason = "reserved for the record decoder of lane L-CODEC")]
    pub(crate) fn from_decoded(
        proposal: ProposalId,
        recorder: AccountId,
        score: Ratio,
        threshold: Percent,
        counted: BTreeSet<ScoreKey>,
        passed: bool,
        rules: RulesVersion,
    ) -> Self {
        Stage1Closed {
            proposal,
            recorder,
            score,
            threshold,
            counted,
            passed,
            rules,
        }
    }

    /// The proposal.
    pub fn proposal(&self) -> ProposalId {
        self.proposal
    }

    /// The named human who recorded the close (R-LA-03, NOTE 3).
    pub fn recorder(&self) -> AccountId {
        self.recorder
    }

    /// The weighted score as an exact fraction of the maximum.
    pub fn score(&self) -> Ratio {
        self.score
    }

    /// The P-02 threshold compared against.
    pub fn threshold(&self) -> Percent {
        self.threshold
    }

    /// The score keys counted in the quorum.
    pub fn counted(&self) -> &BTreeSet<ScoreKey> {
        &self.counted
    }

    /// Whether the score is strictly above the threshold.
    pub fn passed(&self) -> bool {
        self.passed
    }

    /// The rules version that produced the decision.
    pub fn rules(&self) -> RulesVersion {
        self.rules
    }
}

/// The effective score after stage 2, naming exactly one plan version (I-09).
/// Only a builder taking an `EffectiveScore` may construct it. Like
/// [`Stage1Closed`], a computed outcome carries no `DecisionId`.
///
/// Declared by W1c for the interface. Lane L-LIFE adds that builder.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EffectiveScoreSet {
    proposal: ProposalId,
    plan: PlanVersionId,
    value: Ratio,
    basis: Basis,
    counted: BTreeSet<ScoreKey>,
    rules: RulesVersion,
}

impl EffectiveScoreSet {
    /// Every field, for the record decoder in `codec/` only (design section 3.5).
    /// Lane L-CODEC calls it. Every other path builds the record from an `EffectiveScore`.
    #[allow(dead_code, reason = "reserved for the record decoder of lane L-CODEC")]
    pub(crate) fn from_decoded(
        proposal: ProposalId,
        plan: PlanVersionId,
        value: Ratio,
        basis: Basis,
        counted: BTreeSet<ScoreKey>,
        rules: RulesVersion,
    ) -> Self {
        EffectiveScoreSet {
            proposal,
            plan,
            value,
            basis,
            counted,
            rules,
        }
    }

    /// The proposal.
    pub fn proposal(&self) -> ProposalId {
        self.proposal
    }

    /// The one plan version the score names.
    pub fn plan(&self) -> PlanVersionId {
        self.plan
    }

    /// The effective score.
    pub fn value(&self) -> Ratio {
        self.value
    }

    /// Whether the original or the revised plan carries forward.
    pub fn basis(&self) -> Basis {
        self.basis
    }

    /// The score keys counted.
    pub fn counted(&self) -> &BTreeSet<ScoreKey> {
        &self.counted
    }

    /// The rules version that produced the decision.
    pub fn rules(&self) -> RulesVersion {
        self.rules
    }
}

// ---------------------------------------------------------------------------
// Engine entry points of this lane, called by `crate::engine`.
// ---------------------------------------------------------------------------

/// The vault questions of the decision commands: knock-out, admission, stage 1
/// close, ranking after stage 2, cut-off and IRC review.
///
/// Declared by W1c as a stub. Lane L-LIFE completes it.
pub(crate) fn queries(state: &State, cmd: &Command, ctx: &Ctx) -> Result<Vec<Query>, Refusal> {
    let _ = (state, cmd, ctx);
    Err(Refusal::not_implemented())
}

/// The records of the decision commands.
///
/// Declared by W1c as a stub. Lane L-LIFE completes it.
pub(crate) fn decide(
    state: &State,
    cmd: &Command,
    ctx: &Ctx,
    answers: &Answers,
) -> Result<Vec<Record>, Refusal> {
    let _ = (state, cmd, ctx, answers);
    Err(Refusal::not_implemented())
}

/// Folds a decision record.
///
/// Declared by W1c as a stub. Lane L-LIFE completes it.
pub(crate) fn apply(
    state: &mut State,
    seq: Seq,
    at: Timestamp,
    record: &Record,
) -> Result<(), FoldError> {
    let _ = (state, seq, at, record);
    Err(FoldError::NotImplemented)
}

/// The proposals whose stage 1 close trigger holds at `now` (NOTE 3).
///
/// Declared by W1c as a stub. Lane L-LIFE completes it.
pub(crate) fn stage1_ready(state: &State, now: Timestamp) -> Vec<ProposalId> {
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
/// The decision lane is not expected to contribute in M2.
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
