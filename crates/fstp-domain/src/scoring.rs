//! Scores, quorum and the I-08 comparison (design section 2.9, I-07, I-08, I-09).
//!
//! Owned by lane L-SCORE (docs/handoff/m2-design.md section 10).
//!
//! - [`Criteria`] is the P-01 value. [`Criteria::check_vector`] applies
//!   NOTE 6: every reviewer scores every criterion, each from 0 to N.
//! - [`ScoreSheet`] holds the current value of each score key of one
//!   proposal. A correction replaces the value and a void removes it, so a
//!   value never counts twice (NOTE 3).
//! - [`establish_quorum`] builds the I-07 witness [`Quorum`]. It counts the
//!   valid scores on one stage and plan, and refuses below P-03. A stage 1
//!   quorum is always on the submitted plan and counts the assignments of
//!   the call stage 1 ran in, which is the governing call. A stage 2
//!   quorum is always on a stage 2 revision and counts the assignments of
//!   the proposal's current call (NOTE 4, NOTE 8).
//! - A quorum reads the assignments that are active now. Scores seal when
//!   the proposal leaves the stage (NOTE 3), and a later release does not
//!   unseal them. So after a stage closes, lane L-LIFE reads its outcome
//!   from the recorded close, for example `Stage1Closed`, and never from
//!   a recomputed quorum.
//! - [`weighted_score`] and [`judge_stage1`] give the exact NOTE 6 score
//!   and the I-08 witness [`Stage1Verdict`], which passes only strictly
//!   above P-02. [`judge_stage1`] refuses a stage 2 quorum. It also refuses
//!   while an active assignee has no valid score (NOTE 3).
//! - [`effective_score`] gives the I-09 witness [`EffectiveScore`] under
//!   P-24, which names exactly one plan version.
//!   [`effective_score_of_revisions`] picks the latest scored revision.
//!
//! The witness fields are private and only this module builds witnesses.
//! The score arithmetic is exact integer arithmetic in `u64`. It uses no
//! float and no rounding.
//!
//! Departures from the design section 2.9 text, for the lead to record
//! there:
//!
//! - [`judge_stage1`] returns a `Result`. It refuses a quorum that is not
//!   on stage 1 with I-08, and a quorum with an unscored active assignee
//!   with I-07. So a [`Stage1Verdict`] always witnesses a NOTE 3 close on
//!   the submitted plan, and lane L-LIFE need not repeat these checks.
//! - The quorum has no cap on the number of valid scores. Nothing bounds
//!   the number of assignments, and checked `u64` arithmetic holds the
//!   score for about 1e13 reviewers.
//! - Two valid scores from one account refuse with I-07 and
//!   `InvalidValue`. Too few valid scores refuse with I-07 and
//!   `GuardFailed`.
//!
//! State seam. The quorum reads assignments from lane L-REV and scores
//! from lane L-LIFE through two crate-private traits, `AssignmentFacts`
//! and `ScoreFacts`. It reads the frozen policy of a call from lane L-POL
//! through `CallState::frozen`. Lane L-LIFE implements `ScoreFacts` in
//! `proposal/score.rs`. In step W4b it also replaced the two other stub
//! blocks at the end of this file with reads of the owning lanes'
//! accessors, since the quorum cannot run without them.

use std::collections::{BTreeMap, BTreeSet};
use std::num::{NonZeroU8, NonZeroU16, NonZeroU64};

use fstp_money::{Percent, Ratio};

use crate::assignment::{AssignmentKind, ReviewState};
use crate::decision::Basis;
use crate::id::{AccountId, AssignmentId, CallId, CriterionId, PlanVersionId, ProposalId};
use crate::oracle::{Answers, Query};
use crate::policy::{EffectiveScoreRule, FrozenPolicy};
use crate::programme::CallState;
use crate::proposal::PlanOrigin;
use crate::refusal::{Refusal, RefusalReason, RuleRef};
use crate::rules::ParamId;
use crate::state::State;

/// One scoring criterion of P-01 with its positive integer weight.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Criterion {
    /// The criterion.
    pub id: CriterionId,
    /// Its weight. Weights need no particular total (P-01 NOTE 6).
    pub weight: NonZeroU16,
}

/// The P-01 value: the criteria, their weights and the scale maximum N.
/// Each criterion is scored on the integer scale 0 to N (P-01 NOTE 6).
///
/// Fields are private so that only the checked [`Criteria::new`] builds one.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Criteria {
    scale_max: NonZeroU8,
    items: Vec<Criterion>,
}

impl Criteria {
    /// Checked P-01 criteria with the design section 2.4 bounds: 1 to 16
    /// criteria with unique ids, each weight at most 1000, and a scale maximum
    /// of at most 100. These keep the exact score arithmetic within `u64`.
    pub fn new(scale_max: NonZeroU8, items: Vec<Criterion>) -> Result<Criteria, CriteriaError> {
        if items.is_empty() {
            return Err(CriteriaError::Empty);
        }
        if items.len() > usize::from(Criteria::MAX_CRITERIA) {
            return Err(CriteriaError::TooMany);
        }
        if scale_max.get() > Criteria::MAX_SCALE {
            return Err(CriteriaError::ScaleTooLarge);
        }
        if items.iter().any(|c| c.weight.get() > Criteria::MAX_WEIGHT) {
            return Err(CriteriaError::WeightTooLarge);
        }
        let ids: BTreeSet<CriterionId> = items.iter().map(|c| c.id).collect();
        if ids.len() != items.len() {
            return Err(CriteriaError::DuplicateCriterion);
        }
        Ok(Criteria { scale_max, items })
    }

    /// The most criteria P-01 may hold.
    pub const MAX_CRITERIA: u8 = 16;
    /// The largest weight of one criterion.
    pub const MAX_WEIGHT: u16 = 1000;
    /// The largest scale maximum N.
    pub const MAX_SCALE: u8 = 100;

    /// The scale maximum N.
    pub fn scale_max(&self) -> NonZeroU8 {
        self.scale_max
    }

    /// The criteria in their P-01 order.
    pub fn items(&self) -> &[Criterion] {
        &self.items
    }

    /// The sum of the weights. The bounds keep it at most 16 000.
    pub fn weight_sum(&self) -> u32 {
        self.items.iter().fold(0_u32, |sum, c| {
            sum.saturating_add(u32::from(c.weight.get()))
        })
    }

    /// Whether `values` is a complete score under this P-01 (NOTE 6): one
    /// value per criterion, in P-01 order, each from 0 to N.
    pub fn check_vector(&self, values: &ScoreVector) -> Result<(), ScoreVectorError> {
        if values.0.len() != self.items.len() {
            return Err(ScoreVectorError::WrongLength);
        }
        if values.0.iter().any(|v| *v > self.scale_max.get()) {
            return Err(ScoreVectorError::AboveScale);
        }
        Ok(())
    }
}

/// Why [`Criteria::new`] refused a P-01 value (design section 2.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CriteriaError {
    /// No criterion.
    Empty,
    /// More than 16 criteria.
    TooMany,
    /// A weight above 1000.
    WeightTooLarge,
    /// A scale maximum above 100.
    ScaleTooLarge,
    /// Two criteria share an id.
    DuplicateCriterion,
}

impl core::fmt::Display for CriteriaError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid P-01 criteria: {self:?}")
    }
}

impl std::error::Error for CriteriaError {}

/// Why [`Criteria::check_vector`] refused a score vector (NOTE 6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ScoreVectorError {
    /// The vector does not hold exactly one value per criterion. A score
    /// that leaves out a criterion is incomplete.
    WrongLength,
    /// A value is above the scale maximum N.
    AboveScale,
}

impl core::fmt::Display for ScoreVectorError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid score vector under P-01: {self:?}")
    }
}

impl std::error::Error for ScoreVectorError {}

/// Evaluation stage of a score.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Stage {
    /// Stage 1 scoring.
    One,
    /// Stage 2 rescoring of a revised plan.
    Two,
}

/// The key of one current score: one assignment, one stage, one plan version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScoreKey {
    /// The assignment that scored.
    pub assignment: AssignmentId,
    /// The stage.
    pub stage: Stage,
    /// The plan version scored.
    pub plan: PlanVersionId,
}

/// One value per P-01 criterion, in P-01 order, each from 0 to N.
/// [`Criteria::check_vector`] checks it against P-01.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ScoreVector(pub Vec<u8>);

/// Why a score stopped counting.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VoidCause {
    /// The assignment was released before the stage closed (NOTE 3).
    AssignmentReleased,
    /// A conflict on the proposal was declared or detected (I-03).
    Conflict,
    /// A recorded complaint remedy reopened the stage (`SPEC/02-domain/complaints.md`).
    ComplaintRemedy,
}

// ---------------------------------------------------------------------------
// Current scores
// ---------------------------------------------------------------------------

/// The current scores of one proposal: at most one value per score key.
///
/// Superseded values leave the projection (design section 2.14). A
/// correction replaces the current value of its key and a void removes it,
/// so one key never holds two values and a corrected score never counts
/// twice (NOTE 3). Lane L-LIFE holds one sheet per proposal and folds
/// `ScoreRecorded` and `ScoreVoided` into it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ScoreSheet {
    current: BTreeMap<ScoreKey, ScoreVector>,
}

impl ScoreSheet {
    /// A sheet with no score.
    #[allow(dead_code, reason = "lane L-LIFE builds one per proposal")]
    pub(crate) const fn empty() -> ScoreSheet {
        ScoreSheet {
            current: BTreeMap::new(),
        }
    }

    /// Records `values` as the current value of `key`, for a score or a
    /// correction. Returns the value it replaces, if any.
    #[allow(dead_code, reason = "lane L-LIFE folds ScoreRecorded through it")]
    pub(crate) fn record(&mut self, key: ScoreKey, values: ScoreVector) -> Option<ScoreVector> {
        self.current.insert(key, values)
    }

    /// Removes the current value of `key`. Returns it, if any.
    #[allow(dead_code, reason = "lane L-LIFE folds ScoreVoided through it")]
    pub(crate) fn void(&mut self, key: ScoreKey) -> Option<ScoreVector> {
        self.current.remove(&key)
    }

    /// The current value of `key`, if any.
    pub fn current(&self, key: ScoreKey) -> Option<&ScoreVector> {
        self.current.get(&key)
    }

    /// The current values on `stage` and `plan`, in key order.
    pub fn on(
        &self,
        stage: Stage,
        plan: PlanVersionId,
    ) -> impl Iterator<Item = (&ScoreKey, &ScoreVector)> {
        self.current
            .iter()
            .filter(move |(k, _)| k.stage == stage && k.plan == plan)
    }

    /// The number of current values.
    pub fn len(&self) -> usize {
        self.current.len()
    }

    /// Whether the sheet holds no current value.
    pub fn is_empty(&self) -> bool {
        self.current.is_empty()
    }
}

// ---------------------------------------------------------------------------
// The facts the quorum reads from other lanes
// ---------------------------------------------------------------------------

/// What the quorum reads about one assignment (design section 2.7).
#[allow(dead_code, reason = "lane L-REV builds it from its assignments")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct AssignmentFact {
    /// The proposal assigned.
    pub(crate) proposal: ProposalId,
    /// The call the assignment was made in. After a re-entry only the
    /// assignments of the new call count (NOTE 8).
    pub(crate) call: CallId,
    /// The assignee.
    pub(crate) reviewer: AccountId,
    /// The kind of assignment.
    pub(crate) kind: AssignmentKind,
    /// Whether the assignment is active now: declared without conflict and
    /// not released (design section 2.7).
    pub(crate) active: bool,
}

/// The assignment facts the quorum reads. Lane L-REV implements it on
/// `ReviewState` in its own module.
pub(crate) trait AssignmentFacts {
    /// The assignment `id`, or `None` when no such assignment exists.
    fn assignment(&self, id: AssignmentId) -> Result<Option<AssignmentFact>, Refusal>;

    /// The reviewer assignments to `proposal` made in `call` that are
    /// active now, scored or not. The stage 1 close needs a valid score
    /// from each of them (NOTE 3).
    fn active_reviewer_assignments(
        &self,
        proposal: ProposalId,
        call: CallId,
    ) -> Result<BTreeSet<AssignmentId>, Refusal>;

    /// Whether a conflict fact exists for `account` on `proposal`: a
    /// conflicted declaration on any of its assignments to the proposal or
    /// on the proposal itself, or a detected conflict. Conflict facts are
    /// permanent for the proposal across calls (design section 2.7).
    fn has_conflict_fact(&self, account: AccountId, proposal: ProposalId) -> Result<bool, Refusal>;
}

/// The proposal and score facts the quorum reads. Lane L-LIFE implements
/// it on `ProposalStore` in its own module.
pub(crate) trait ScoreFacts {
    /// The call whose frozen policy governs `proposal`, or `None` for an
    /// unknown proposal. After a re-entry it is still the original call (NOTE 8).
    fn governing_call(&self, proposal: ProposalId) -> Result<Option<CallId>, Refusal>;

    /// The call `proposal` is in now: the call it was created in, or the
    /// call it last re-entered (NOTE 8). `None` for an unknown proposal.
    fn current_call(&self, proposal: ProposalId) -> Result<Option<CallId>, Refusal>;

    /// The origin of `plan` when it is a plan version of `proposal`, else
    /// `None`. A stage 2 quorum needs a stage 2 revision (NOTE 4).
    fn plan_origin(
        &self,
        proposal: ProposalId,
        plan: PlanVersionId,
    ) -> Result<Option<PlanOrigin>, Refusal>;

    /// The plan version `proposal` was submitted with, which stage 1
    /// scores. `None` before submission or for an unknown proposal.
    fn submitted_plan(&self, proposal: ProposalId) -> Result<Option<PlanVersionId>, Refusal>;

    /// The lead and team accounts of `proposal`, the team of `HasConflict`.
    fn applicant_team(&self, proposal: ProposalId) -> Result<BTreeSet<AccountId>, Refusal>;

    /// The current scores of `proposal`, or `None` when it has none yet.
    fn score_sheet(&self, proposal: ProposalId) -> Result<Option<&ScoreSheet>, Refusal>;
}

// ---------------------------------------------------------------------------
// I-07: the quorum
// ---------------------------------------------------------------------------

/// The I-07 witness: at least P-03 valid scores on one stage and plan of
/// one proposal, from distinct reviewers, each counted once.
///
/// A valid score is the current value of its key, from a reviewer
/// assignment to the proposal that is active now and was made in the
/// stage's call, with no conflict fact for its account on the proposal
/// (NOTE 3, NOTE 4, NOTE 8). The stage's call is the governing call for
/// stage 1 and the proposal's current call for stage 2. Built only by
/// [`establish_quorum`].
///
/// The quorum keeps the frozen policy it was established under and the
/// exact score of its counted values. So a later state or another policy
/// cannot change what it witnesses. It also keeps the active assignees of
/// the stage's call that have no valid score, which the stage 1 close
/// reads (NOTE 3).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Quorum {
    proposal: ProposalId,
    stage: Stage,
    plan: PlanVersionId,
    call: CallId,
    keys: BTreeSet<ScoreKey>,
    unscored: BTreeSet<AssignmentId>,
    required: NonZeroU8,
    policy: FrozenPolicy,
    score: Ratio,
}

impl Quorum {
    /// The proposal.
    pub fn proposal(&self) -> ProposalId {
        self.proposal
    }

    /// The stage scored.
    pub fn stage(&self) -> Stage {
        self.stage
    }

    /// The plan version scored. On stage 1 it is the submitted plan.
    pub fn plan(&self) -> PlanVersionId {
        self.plan
    }

    /// The call whose assignments were counted. On stage 1 it is the call
    /// stage 1 ran in, which is the governing call. On stage 2 it is the
    /// proposal's current call (NOTE 8).
    pub fn call(&self) -> CallId {
        self.call
    }

    /// The valid score keys counted, one per reviewer.
    pub fn keys(&self) -> &BTreeSet<ScoreKey> {
        &self.keys
    }

    /// The active reviewer assignments of the stage's call that have no
    /// valid score on this stage and plan.
    pub fn unscored(&self) -> &BTreeSet<AssignmentId> {
        &self.unscored
    }

    /// Whether every active assignee of the stage's call has a valid score
    /// on this stage and plan (NOTE 3).
    pub fn every_active_assignee_scored(&self) -> bool {
        self.unscored.is_empty()
    }

    /// The P-03 value the count met.
    pub fn required(&self) -> NonZeroU8 {
        self.required
    }

    /// The frozen policy the quorum was established under.
    pub fn policy(&self) -> &FrozenPolicy {
        &self.policy
    }
}

/// The I-07 quorum of `proposal` on `stage` and `plan` under `policy`, or
/// the refusal.
///
/// - `policy` must be the frozen policy of the proposal's governing call,
///   or the refusal names I-12.
/// - An unknown proposal or plan refuses with `Input` and `UnknownEntity`.
///   A stage 1 quorum on a plan other than the submitted plan refuses
///   with `Input` and `InvalidValue`. So does a stage 2 quorum on a plan
///   that is not a stage 2 revision (NOTE 4).
/// - Stage 1 counts the assignments of the governing call, where stage 1
///   ran. Re-entry never returns to STAGE1 (NOTE 8). Stage 2 counts the
///   assignments of the proposal's current call.
/// - Each counted reviewer needs a fresh `HasConflict` answer of false at
///   the state's epoch. A missing answer refuses with `FactsIncomplete`, a
///   stale one with `StaleFacts`, and a conflict with I-03.
/// - Two valid scores from one account refuse with I-07 and
///   `InvalidValue`. Fewer than P-03 valid scores refuse with I-07 and
///   `GuardFailed`.
/// - A counted value that is not a complete P-01 score refuses with P-01.
///
/// In stage 2 this is the NOTE 4 rule: at least P-03 valid stage 2 scores
/// on the revised plan. Which revision counts is the caller's choice.
pub fn establish_quorum(
    state: &State,
    proposal: ProposalId,
    stage: Stage,
    plan: PlanVersionId,
    policy: &FrozenPolicy,
    answers: &Answers,
) -> Result<Quorum, Refusal> {
    establish_over(
        &state.review,
        &state.proposals,
        state.epoch(),
        Target {
            proposal,
            stage,
            plan,
        },
        policy,
        answers,
    )
}

/// What a quorum is asked for.
#[derive(Clone, Copy, Debug)]
struct Target {
    proposal: ProposalId,
    stage: Stage,
    plan: PlanVersionId,
}

/// [`establish_quorum`] over the two fact sources, so the rule reads no
/// other part of the state.
fn establish_over(
    review: &impl AssignmentFacts,
    proposals: &impl ScoreFacts,
    epoch: crate::id::VaultEpoch,
    target: Target,
    policy: &FrozenPolicy,
    answers: &Answers,
) -> Result<Quorum, Refusal> {
    let required = policy.values().p03;
    let counted = collect_quorum(
        review,
        proposals,
        epoch,
        target,
        Limits {
            governing: policy.call(),
            required,
        },
        answers,
    )?;
    let score = weighted_ratio(&policy.values().p01, &counted.vectors)?;
    Ok(Quorum {
        proposal: target.proposal,
        stage: target.stage,
        plan: target.plan,
        call: counted.call,
        keys: counted.keys,
        unscored: counted.unscored,
        required,
        policy: policy.clone(),
        score,
    })
}

/// The policy values [`collect_quorum`] checks against.
#[derive(Clone, Copy, Debug)]
struct Limits {
    /// The call of the frozen policy the caller passed.
    governing: CallId,
    /// P-03.
    required: NonZeroU8,
}

/// The valid scores of a target, before the score is computed.
#[derive(Debug)]
struct Counted<'a> {
    call: CallId,
    keys: BTreeSet<ScoreKey>,
    vectors: Vec<&'a ScoreVector>,
    unscored: BTreeSet<AssignmentId>,
}

/// The valid scores of `target`, with every refusal of
/// [`establish_quorum`] except the P-01 check of the values.
fn collect_quorum<'a>(
    review: &impl AssignmentFacts,
    proposals: &'a impl ScoreFacts,
    epoch: crate::id::VaultEpoch,
    target: Target,
    limits: Limits,
    answers: &Answers,
) -> Result<Counted<'a>, Refusal> {
    let unknown = Refusal::new(RuleRef::Input, RefusalReason::UnknownEntity);
    let Target {
        proposal,
        stage,
        plan,
    } = target;
    let governing = proposals.governing_call(proposal)?.ok_or(unknown)?;
    if governing != limits.governing {
        return Err(Refusal::new(RuleRef::I12, RefusalReason::InvalidValue));
    }
    let origin = proposals.plan_origin(proposal, plan)?.ok_or(unknown)?;
    let wrong_plan = Refusal::new(RuleRef::Input, RefusalReason::InvalidValue);
    let call = match stage {
        Stage::One => {
            if proposals.submitted_plan(proposal)? != Some(plan) {
                return Err(wrong_plan);
            }
            governing
        }
        Stage::Two => {
            if origin != PlanOrigin::Stage2Revision {
                return Err(wrong_plan);
            }
            proposals.current_call(proposal)?.ok_or(unknown)?
        }
    };
    let team = proposals.applicant_team(proposal)?;
    let mut keys: BTreeSet<ScoreKey> = BTreeSet::new();
    let mut reviewers: BTreeSet<AccountId> = BTreeSet::new();
    let mut vectors: Vec<&'a ScoreVector> = Vec::new();
    if let Some(sheet) = proposals.score_sheet(proposal)? {
        for (key, values) in sheet.on(stage, plan) {
            let Some(reviewer) = valid_reviewer(review, proposal, call, *key)? else {
                continue;
            };
            fresh_no_conflict(answers, epoch, reviewer, &team)?;
            if !reviewers.insert(reviewer) {
                return Err(Refusal::new(RuleRef::I07, RefusalReason::InvalidValue));
            }
            keys.insert(*key);
            vectors.push(values);
        }
    }
    if keys.len() < usize::from(limits.required.get()) {
        return Err(Refusal::new(RuleRef::I07, RefusalReason::GuardFailed));
    }
    let mut unscored = review.active_reviewer_assignments(proposal, call)?;
    for key in &keys {
        unscored.remove(&key.assignment);
    }
    Ok(Counted {
        call,
        keys,
        vectors,
        unscored,
    })
}

/// The account behind `key` when its score is valid, else `None`: the key's
/// assignment is a reviewer assignment to `proposal`, made in `call`, the
/// stage's call, active now, and its account has no conflict fact on the
/// proposal (NOTE 3, NOTE 8).
fn valid_reviewer(
    review: &impl AssignmentFacts,
    proposal: ProposalId,
    call: CallId,
    key: ScoreKey,
) -> Result<Option<AccountId>, Refusal> {
    let Some(a) = review.assignment(key.assignment)? else {
        return Ok(None);
    };
    if a.proposal != proposal || a.call != call || a.kind != AssignmentKind::Reviewer || !a.active {
        return Ok(None);
    }
    if review.has_conflict_fact(a.reviewer, proposal)? {
        return Ok(None);
    }
    Ok(Some(a.reviewer))
}

/// Checks the fresh vault answer that `reviewer` has no conflict with `team`
/// at `epoch` (I-03, design section 3.3).
fn fresh_no_conflict(
    answers: &Answers,
    epoch: crate::id::VaultEpoch,
    reviewer: AccountId,
    team: &BTreeSet<AccountId>,
) -> Result<(), Refusal> {
    let query = Query::HasConflict {
        reviewer,
        team: team.clone(),
    };
    match answers.get(&query) {
        None => Err(Refusal::new(
            RuleRef::FactsIncomplete,
            RefusalReason::AnswerMissing,
        )),
        Some(a) if a.epoch != epoch => Err(Refusal::new(
            RuleRef::StaleFacts,
            RefusalReason::AnswerStale,
        )),
        Some(a) if a.holds => Err(Refusal::new(RuleRef::I03, RefusalReason::VaultRefused)),
        Some(_) => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// I-08: the weighted score and the strict comparison
// ---------------------------------------------------------------------------

/// The NOTE 6 score of complete reviewer vectors as an exact fraction of
/// the maximum: `num = sum_r sum_i w_i * s_ri` over
/// `den = R * N * sum_i w_i`.
///
/// The P-01 bounds let one reviewer add at most `16 * 1000 * 100` to `num`
/// and to `den`. So `u64` holds both for about 1e13 reviewers, and the
/// number of valid scores needs no cap. Checked arithmetic refuses beyond
/// that rather than wrap.
fn weighted_ratio(criteria: &Criteria, vectors: &[&ScoreVector]) -> Result<Ratio, Refusal> {
    let unsafe_value = Refusal::new(RuleRef::I08, RefusalReason::InvalidValue);
    let mut num: u64 = 0;
    for v in vectors {
        criteria
            .check_vector(v)
            .map_err(|_| Refusal::new(RuleRef::Param(ParamId::P01), RefusalReason::InvalidValue))?;
        for (c, s) in criteria.items.iter().zip(&v.0) {
            num = u64::from(c.weight.get())
                .checked_mul(u64::from(*s))
                .and_then(|p| num.checked_add(p))
                .ok_or(unsafe_value)?;
        }
    }
    let reviewers = u64::try_from(vectors.len()).map_err(|_| unsafe_value)?;
    let den = reviewers
        .checked_mul(u64::from(criteria.scale_max.get()))
        .and_then(|d| d.checked_mul(u64::from(criteria.weight_sum())))
        .and_then(NonZeroU64::new)
        .ok_or(unsafe_value)?;
    Ok(Ratio::new(num, den))
}

/// The weighted score of the quorum's counted values as an exact fraction
/// of the maximum (NOTE 6): the mean over reviewers of their weighted sums.
///
/// The quorum computed it when it was established, under its own frozen
/// policy. `state` and `policy` are the design signature's. They are not
/// read, so a caller cannot score a witness under another state or policy.
pub fn weighted_score(q: &Quorum, _state: &State, _policy: &FrozenPolicy) -> Ratio {
    q.score
}

/// The I-08 witness: the stage 1 score of a quorum against P-02.
/// `passed` is exactly `score.exceeds(threshold)`, so equality never passes.
/// Built only by [`judge_stage1`], so its quorum is always a stage 1
/// quorum on the submitted plan in which every active assignee of the
/// stage 1 call has a valid score (NOTE 3).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Stage1Verdict {
    quorum: Quorum,
    score: Ratio,
    threshold: Percent,
    passed: bool,
}

impl Stage1Verdict {
    /// The stage 1 quorum judged.
    pub fn quorum(&self) -> &Quorum {
        &self.quorum
    }

    /// The weighted score as an exact fraction of the maximum.
    pub fn score(&self) -> Ratio {
        self.score
    }

    /// The P-02 threshold of the quorum's frozen policy.
    pub fn threshold(&self) -> Percent {
        self.threshold
    }

    /// Whether the score is strictly above the threshold (I-08).
    pub fn passed(&self) -> bool {
        self.passed
    }
}

/// The I-08 verdict of `q`: its weighted score against the P-02 of the
/// quorum's frozen policy, compared exactly and strictly (NOTE 6).
///
/// It refuses a quorum on stage 2 with I-08 and `InvalidValue`. It refuses
/// with I-07 and `GuardFailed` while an active assignee of the stage 1
/// call has no valid score, because stage 1 closes only then (NOTE 3).
///
/// As for [`weighted_score`], `state` and `policy` are not read.
pub fn judge_stage1(
    q: Quorum,
    _state: &State,
    _policy: &FrozenPolicy,
) -> Result<Stage1Verdict, Refusal> {
    stage1_ready(q.stage, &q.unscored)?;
    let threshold = q.policy.values().p02;
    let score = q.score;
    Ok(Stage1Verdict {
        passed: score.exceeds(threshold),
        quorum: q,
        score,
        threshold,
    })
}

/// Whether a quorum on `stage` with these unscored active assignees may
/// close stage 1 (NOTE 3).
fn stage1_ready(stage: Stage, unscored: &BTreeSet<AssignmentId>) -> Result<(), Refusal> {
    if stage != Stage::One {
        return Err(Refusal::new(RuleRef::I08, RefusalReason::InvalidValue));
    }
    if !unscored.is_empty() {
        return Err(Refusal::new(RuleRef::I07, RefusalReason::GuardFailed));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// I-09: the effective score after stage 2
// ---------------------------------------------------------------------------

/// The I-09 witness: the effective score after stage 2, naming exactly one
/// plan version. Built only by [`effective_score`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EffectiveScore {
    plan: PlanVersionId,
    value: Ratio,
    basis: Basis,
}

impl EffectiveScore {
    /// The one plan version that carries forward.
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
}

/// The effective score under P-24 of the original plan's score and the
/// score of the latest scored revision, if any (NOTE 4).
///
/// Under "higher of original and revised" the revision carries forward
/// only when its score is strictly higher. On a tie, and without a scored
/// revision, the original carries forward. A revision that names the
/// original plan itself counts as the original.
pub fn effective_score(
    rule: EffectiveScoreRule,
    original: (PlanVersionId, Ratio),
    revised: Option<(PlanVersionId, Ratio)>,
) -> EffectiveScore {
    let (o_plan, o_value) = original;
    let keep_original = EffectiveScore {
        plan: o_plan,
        value: o_value,
        basis: Basis::Original,
    };
    match rule {
        EffectiveScoreRule::HigherOfOriginalAndRevised => match revised {
            Some((plan, value)) if plan != o_plan && value > o_value => EffectiveScore {
                plan,
                value,
                basis: Basis::Revised,
            },
            _ => keep_original,
        },
    }
}

/// The effective score under P-24 of the original plan's score and the
/// revisions in submission order (NOTE 4). Each revision carries its stage
/// 2 score when it has a stage 2 quorum, else `None`.
///
/// The latest scored revision is the one compared with the original. A
/// later revision without a score never hides an earlier scored one.
pub fn effective_score_of_revisions(
    rule: EffectiveScoreRule,
    original: (PlanVersionId, Ratio),
    revisions: &[(PlanVersionId, Option<Ratio>)],
) -> EffectiveScore {
    let latest = revisions
        .iter()
        .rev()
        .find_map(|(plan, score)| score.map(|s| (*plan, s)));
    effective_score(rule, original, latest)
}

// ---------------------------------------------------------------------------
// The fact sources of the lanes that own the state the quorum reads
// ---------------------------------------------------------------------------

/// The assignment facts of lane L-REV, read through the accessors that
/// `crate::assignment` keeps for the quorum. Lane L-LIFE replaced the stub
/// block here in step W4b, since the quorum cannot run without it.
impl AssignmentFacts for ReviewState {
    fn assignment(&self, id: AssignmentId) -> Result<Option<AssignmentFact>, Refusal> {
        Ok(self.quorum_fact(id))
    }

    fn active_reviewer_assignments(
        &self,
        proposal: ProposalId,
        call: CallId,
    ) -> Result<BTreeSet<AssignmentId>, Refusal> {
        Ok(self.active_reviewers_in(proposal, call))
    }

    fn has_conflict_fact(&self, account: AccountId, proposal: ProposalId) -> Result<bool, Refusal> {
        Ok(self.conflict_fact(account, proposal))
    }
}

// Lane L-LIFE implements `ScoreFacts` on `ProposalStore` in `proposal/score.rs`.

/// The read of lane L-POL over its call views. Lane L-LIFE replaced the
/// stub block here in step W4b, since the quorum cannot run without it.
impl CallState {
    /// The frozen policy of `call` once it is published (I-12, design
    /// section 2.5).
    pub fn frozen(&self, call: CallId) -> Option<&FrozenPolicy> {
        self.get(call).and_then(crate::programme::CallView::frozen)
    }
}

// ---------------------------------------------------------------------------
// Regression tests of the quorum rule over test fact sources
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code"
)]
mod tests {
    //! These tests reach the private quorum rule through fact sources
    //! built here, because the owning lanes have not landed the real ones.
    //! The testkit property tests cover the same rule through the fold.

    use super::*;
    use crate::id::{ContentDigest, VaultEpoch};
    use crate::oracle::Answer;
    use core::cmp::Ordering;

    const P: ProposalId = ProposalId::from_raw(10);
    const OTHER: ProposalId = ProposalId::from_raw(11);
    const FIRST_CALL: CallId = CallId::from_raw(20);
    const NEXT_CALL: CallId = CallId::from_raw(21);
    const SUBMITTED: PlanVersionId = PlanVersionId::from_raw(30);
    const REVISED: PlanVersionId = PlanVersionId::from_raw(31);
    const NEGOTIATED: PlanVersionId = PlanVersionId::from_raw(32);
    const LEAD: AccountId = AccountId::from_raw(40);

    /// Assignment facts held in memory.
    #[derive(Default)]
    struct Review {
        facts: BTreeMap<AssignmentId, AssignmentFact>,
        conflicts: BTreeSet<(AccountId, ProposalId)>,
    }

    impl AssignmentFacts for Review {
        fn assignment(&self, id: AssignmentId) -> Result<Option<AssignmentFact>, Refusal> {
            Ok(self.facts.get(&id).copied())
        }

        fn active_reviewer_assignments(
            &self,
            proposal: ProposalId,
            call: CallId,
        ) -> Result<BTreeSet<AssignmentId>, Refusal> {
            Ok(self
                .facts
                .iter()
                .filter(|(_, f)| {
                    f.proposal == proposal
                        && f.call == call
                        && f.kind == AssignmentKind::Reviewer
                        && f.active
                })
                .map(|(id, _)| *id)
                .collect())
        }

        fn has_conflict_fact(
            &self,
            account: AccountId,
            proposal: ProposalId,
        ) -> Result<bool, Refusal> {
            Ok(self.conflicts.contains(&(account, proposal)))
        }
    }

    /// Proposal `P`, governed by the first call, with its score sheet.
    struct Proposals {
        current: CallId,
        sheet: ScoreSheet,
    }

    impl ScoreFacts for Proposals {
        fn governing_call(&self, proposal: ProposalId) -> Result<Option<CallId>, Refusal> {
            Ok((proposal == P).then_some(FIRST_CALL))
        }

        fn current_call(&self, proposal: ProposalId) -> Result<Option<CallId>, Refusal> {
            Ok((proposal == P).then_some(self.current))
        }

        fn plan_origin(
            &self,
            proposal: ProposalId,
            plan: PlanVersionId,
        ) -> Result<Option<PlanOrigin>, Refusal> {
            if proposal != P {
                return Ok(None);
            }
            Ok(match plan {
                SUBMITTED => Some(PlanOrigin::Submitted),
                REVISED => Some(PlanOrigin::Stage2Revision),
                NEGOTIATED => Some(PlanOrigin::Negotiated),
                _ => None,
            })
        }

        fn submitted_plan(&self, proposal: ProposalId) -> Result<Option<PlanVersionId>, Refusal> {
            Ok((proposal == P).then_some(SUBMITTED))
        }

        fn applicant_team(&self, proposal: ProposalId) -> Result<BTreeSet<AccountId>, Refusal> {
            let _ = proposal;
            Ok([LEAD].into_iter().collect())
        }

        fn score_sheet(&self, proposal: ProposalId) -> Result<Option<&ScoreSheet>, Refusal> {
            Ok((proposal == P).then_some(&self.sheet))
        }
    }

    /// A small world of assignments and scores on proposal `P`.
    struct World {
        review: Review,
        proposals: Proposals,
        answers: Answers,
    }

    impl World {
        fn new() -> World {
            World {
                review: Review::default(),
                proposals: Proposals {
                    current: FIRST_CALL,
                    sheet: ScoreSheet::empty(),
                },
                answers: Answers::new(),
            }
        }

        /// Assignment `n` of account `account` to `P` in `call`, with a
        /// fresh no-conflict vault answer for the account.
        fn assign(
            &mut self,
            n: u128,
            account: u128,
            call: CallId,
            kind: AssignmentKind,
            active: bool,
        ) -> AssignmentId {
            let id = AssignmentId::from_raw(n);
            let reviewer = AccountId::from_raw(account);
            self.review.facts.insert(
                id,
                AssignmentFact {
                    proposal: P,
                    call,
                    reviewer,
                    kind,
                    active,
                },
            );
            self.answers.insert(
                Query::HasConflict {
                    reviewer,
                    team: [LEAD].into_iter().collect(),
                },
                Answer {
                    holds: false,
                    accounts: None,
                    epoch: VaultEpoch::GENESIS,
                    digest: ContentDigest::from_bytes([0; 32]),
                },
            );
            id
        }

        /// An active reviewer assignment in the first call.
        fn reviewer(&mut self, n: u128, account: u128) -> AssignmentId {
            self.assign(n, account, FIRST_CALL, AssignmentKind::Reviewer, true)
        }

        fn score(&mut self, assignment: AssignmentId, stage: Stage, plan: PlanVersionId) {
            let key = ScoreKey {
                assignment,
                stage,
                plan,
            };
            self.proposals.sheet.record(key, ScoreVector(vec![3, 3, 3]));
        }

        fn collect(
            &self,
            stage: Stage,
            plan: PlanVersionId,
            required: u8,
        ) -> Result<Counted<'_>, Refusal> {
            collect_quorum(
                &self.review,
                &self.proposals,
                VaultEpoch::GENESIS,
                Target {
                    proposal: P,
                    stage,
                    plan,
                },
                Limits {
                    governing: FIRST_CALL,
                    required: NonZeroU8::new(required).unwrap(),
                },
                &self.answers,
            )
        }
    }

    fn assignments(counted: &Counted<'_>) -> BTreeSet<AssignmentId> {
        counted.keys.iter().map(|k| k.assignment).collect()
    }

    fn ids(raw: &[u128]) -> BTreeSet<AssignmentId> {
        raw.iter().map(|n| AssignmentId::from_raw(*n)).collect()
    }

    fn criteria(scale: u8, weights: &[u16]) -> Criteria {
        let items = weights
            .iter()
            .enumerate()
            .map(|(i, w)| Criterion {
                id: CriterionId::from_raw(u128::try_from(i).unwrap()),
                weight: NonZeroU16::new(*w).unwrap(),
            })
            .collect();
        Criteria::new(NonZeroU8::new(scale).unwrap(), items).unwrap()
    }

    fn ratio(num: u64, den: u64) -> Ratio {
        Ratio::new(num, NonZeroU64::new(den).unwrap())
    }

    /// I-08, NOTE 6 regression: more than 64 valid scores still give the
    /// exact score. The old cap refused 65 scores, so such a proposal could
    /// never leave STAGE1. The largest P-01 values do not overflow either.
    #[test]
    fn i08_weighted_ratio_has_no_cap_on_the_number_of_scores() {
        let c = criteria(4, &[30, 40, 30]);
        let v = ScoreVector(vec![3, 3, 3]);
        for n in [1_usize, 64, 65, 1_000] {
            let vectors: Vec<&ScoreVector> = (0..n).map(|_| &v).collect();
            let got = weighted_ratio(&c, &vectors).unwrap();
            assert_eq!(got, ratio(3, 4), "{n} reviewers");
        }
        let big = criteria(100, &[1000; 16]);
        let full = ScoreVector(vec![100; 16]);
        let vectors: Vec<&ScoreVector> = (0..100_000).map(|_| &full).collect();
        assert_eq!(weighted_ratio(&big, &vectors).unwrap(), ratio(1, 1));
    }

    /// I-07, NOTE 3 regression: a conflict fact on the proposal excludes
    /// the score of an assignment that is still active. A conflict fact on
    /// another proposal does not.
    #[test]
    fn i07_conflict_fact_on_an_active_assignment_excludes_its_score() {
        let mut w = World::new();
        let a = w.reviewer(1, 101);
        let b = w.reviewer(2, 102);
        w.score(a, Stage::One, SUBMITTED);
        w.score(b, Stage::One, SUBMITTED);
        w.review.conflicts.insert((AccountId::from_raw(101), P));
        w.review.conflicts.insert((AccountId::from_raw(102), OTHER));
        let counted = w.collect(Stage::One, SUBMITTED, 1).unwrap();
        assert_eq!(assignments(&counted), ids(&[2]));
        assert_eq!(
            w.collect(Stage::One, SUBMITTED, 2).unwrap_err(),
            Refusal::new(RuleRef::I07, RefusalReason::GuardFailed)
        );
    }

    /// I-07, NOTE 8 regression: after a re-entry only the assignments of
    /// the new call count. An account assigned in both calls is counted
    /// once, from the new call, and causes no duplicate refusal.
    #[test]
    fn i07_assignments_of_an_earlier_call_never_count_after_reentry() {
        let mut w = World::new();
        let old_same = w.reviewer(1, 101);
        let old_other = w.reviewer(2, 102);
        let new_same = w.assign(3, 101, NEXT_CALL, AssignmentKind::Reviewer, true);
        let new_third = w.assign(4, 103, NEXT_CALL, AssignmentKind::Reviewer, true);
        w.proposals.current = NEXT_CALL;
        for a in [old_same, old_other, new_same, new_third] {
            w.score(a, Stage::Two, REVISED);
        }
        let counted = w.collect(Stage::Two, REVISED, 2).unwrap();
        assert_eq!(counted.call, NEXT_CALL);
        assert_eq!(assignments(&counted), ids(&[3, 4]));
        assert!(counted.unscored.is_empty());
        assert_eq!(
            w.collect(Stage::Two, REVISED, 3).unwrap_err(),
            Refusal::new(RuleRef::I07, RefusalReason::GuardFailed)
        );
    }

    /// I-07 regression: two valid scores from one account refuse with a
    /// reason other than too few scores.
    #[test]
    fn i07_two_valid_scores_from_one_account_refuse_apart_from_too_few() {
        let mut w = World::new();
        let a = w.reviewer(1, 101);
        let b = w.reviewer(2, 101);
        w.score(a, Stage::One, SUBMITTED);
        w.score(b, Stage::One, SUBMITTED);
        assert_eq!(
            w.collect(Stage::One, SUBMITTED, 1).unwrap_err(),
            Refusal::new(RuleRef::I07, RefusalReason::InvalidValue)
        );
    }

    /// I-07, NOTE 3 regression: the quorum lists every active reviewer
    /// assignment of the current call without a valid score. IRC
    /// assignments, released assignments and earlier calls are not listed.
    /// Stage 1 closes only once the list is empty.
    #[test]
    fn i07_stage1_close_needs_every_active_assignee_scored() {
        let mut w = World::new();
        let a = w.reviewer(1, 101);
        let b = w.reviewer(2, 102);
        let c = w.reviewer(3, 103);
        let conflicted = w.reviewer(4, 104);
        w.assign(5, 105, FIRST_CALL, AssignmentKind::Irc, true);
        w.assign(6, 106, FIRST_CALL, AssignmentKind::Reviewer, false);
        w.assign(7, 107, NEXT_CALL, AssignmentKind::Reviewer, true);
        w.review.conflicts.insert((AccountId::from_raw(104), P));
        for x in [a, b, conflicted] {
            w.score(x, Stage::One, SUBMITTED);
        }
        let counted = w.collect(Stage::One, SUBMITTED, 2).unwrap();
        assert_eq!(assignments(&counted), ids(&[1, 2]));
        assert_eq!(counted.unscored, ids(&[3, 4]));
        assert_eq!(
            stage1_ready(Stage::One, &counted.unscored).unwrap_err(),
            Refusal::new(RuleRef::I07, RefusalReason::GuardFailed)
        );
        w.score(c, Stage::One, SUBMITTED);
        w.review.facts.get_mut(&conflicted).unwrap().active = false;
        let counted = w.collect(Stage::One, SUBMITTED, 2).unwrap();
        assert!(counted.unscored.is_empty());
        stage1_ready(Stage::One, &counted.unscored).unwrap();
    }

    /// I-08 regression: a stage 2 quorum never yields a stage 1 verdict.
    #[test]
    fn i08_stage1_verdict_refuses_a_stage2_quorum() {
        assert_eq!(
            stage1_ready(Stage::Two, &BTreeSet::new()).unwrap_err(),
            Refusal::new(RuleRef::I08, RefusalReason::InvalidValue)
        );
        stage1_ready(Stage::One, &BTreeSet::new()).unwrap();
    }

    /// I-08 regression: a stage 1 quorum is only on the submitted plan.
    #[test]
    fn i08_stage1_quorum_is_only_on_the_submitted_plan() {
        let mut w = World::new();
        let a = w.reviewer(1, 101);
        w.score(a, Stage::One, REVISED);
        assert_eq!(
            w.collect(Stage::One, REVISED, 1).unwrap_err(),
            Refusal::new(RuleRef::Input, RefusalReason::InvalidValue)
        );
        w.score(a, Stage::Two, REVISED);
        assert_eq!(
            assignments(&w.collect(Stage::Two, REVISED, 1).unwrap()),
            ids(&[1])
        );
    }

    /// I-07, NOTE 4 regression: a stage 2 quorum is only on a stage 2
    /// revision. Stage 2 keys on the submitted plan or on a negotiated plan
    /// never form one, however many exist.
    #[test]
    fn i07_stage2_quorum_is_only_on_a_stage2_revision() {
        let mut w = World::new();
        let a = w.reviewer(1, 101);
        let b = w.reviewer(2, 102);
        for x in [a, b] {
            for plan in [SUBMITTED, REVISED, NEGOTIATED] {
                w.score(x, Stage::Two, plan);
            }
        }
        for plan in [SUBMITTED, NEGOTIATED] {
            assert_eq!(
                w.collect(Stage::Two, plan, 1).unwrap_err(),
                Refusal::new(RuleRef::Input, RefusalReason::InvalidValue),
                "{plan:?}"
            );
        }
        assert_eq!(
            assignments(&w.collect(Stage::Two, REVISED, 2).unwrap()),
            ids(&[1, 2])
        );
        assert_eq!(
            w.collect(Stage::One, NEGOTIATED, 1).unwrap_err(),
            Refusal::new(RuleRef::Input, RefusalReason::InvalidValue)
        );
    }

    /// I-07, I-08, NOTE 8 regression: stage 1 ran in the governing call,
    /// so after a re-entry a stage 1 quorum still counts that call's
    /// assignments. The new call's assignments have no stage 1 score and
    /// are neither counted nor listed as unscored.
    #[test]
    fn i07_stage1_quorum_stays_in_the_call_stage1_ran_in() {
        let mut w = World::new();
        let a = w.reviewer(1, 101);
        let b = w.reviewer(2, 102);
        w.score(a, Stage::One, SUBMITTED);
        w.score(b, Stage::One, SUBMITTED);
        let fresh = w.assign(3, 103, NEXT_CALL, AssignmentKind::Reviewer, true);
        w.score(fresh, Stage::Two, REVISED);
        w.proposals.current = NEXT_CALL;
        let counted = w.collect(Stage::One, SUBMITTED, 2).unwrap();
        assert_eq!(counted.call, FIRST_CALL);
        assert_eq!(assignments(&counted), ids(&[1, 2]));
        assert!(counted.unscored.is_empty());
        stage1_ready(Stage::One, &counted.unscored).unwrap();
        let counted = w.collect(Stage::Two, REVISED, 1).unwrap();
        assert_eq!(counted.call, NEXT_CALL);
        assert_eq!(assignments(&counted), ids(&[3]));
    }

    /// I-09, NOTE 4 regression: the latest scored revision is compared with
    /// the original. An unscored later revision does not hide it, and a
    /// tie keeps the original.
    #[test]
    fn i09_effective_score_of_revisions_compares_the_latest_scored() {
        let rule = EffectiveScoreRule::HigherOfOriginalAndRevised;
        let r1 = PlanVersionId::from_raw(41);
        let r2 = PlanVersionId::from_raw(42);
        let original = (SUBMITTED, ratio(1, 2));
        let e =
            effective_score_of_revisions(rule, original, &[(r1, Some(ratio(3, 4))), (r2, None)]);
        assert_eq!((e.plan(), e.basis()), (r1, Basis::Revised));
        let e = effective_score_of_revisions(
            rule,
            original,
            &[(r1, Some(ratio(3, 4))), (r2, Some(ratio(1, 4)))],
        );
        assert_eq!((e.plan(), e.basis()), (SUBMITTED, Basis::Original));
        let e = effective_score_of_revisions(rule, original, &[(r1, Some(ratio(2, 4)))]);
        assert_eq!((e.plan(), e.basis()), (SUBMITTED, Basis::Original));
        assert_eq!(e.value().cmp(&ratio(1, 2)), Ordering::Equal);
        let e = effective_score_of_revisions(rule, original, &[]);
        assert_eq!((e.plan(), e.basis()), (SUBMITTED, Basis::Original));
    }
}
