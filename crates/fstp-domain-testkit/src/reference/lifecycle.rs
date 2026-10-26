//! Independent reference for the proposal lifecycle, written from the spec text (design sections 2.8 to 2.10, 3.2 to 3.7 and 6.1).
//!
//! Owned by lane L-LIFE (docs/handoff/m2-design.md section 10).
//!
//! Sources: `SPEC/02-domain/state-machine.md` with NOTES 1 to 13,
//! `SPEC/02-domain/policy-parameters.md` NOTE 6 and NOTE 8,
//! `SPEC/02-domain/roles-and-sod.md` (Conflict declarations, Identity
//! discovery), `SPEC/02-domain/invariants.md` (I-07, I-08, I-09, I-18) and
//! `SPEC/01-requirements/functional.md` (R-EV-01 to R-EV-09, R-IR-01,
//! R-IR-02, R-LA-03, R-AU-01, R-NG-02). The reference shares only id,
//! command and record types with production. It reads roles through the
//! L-SOD reference view, recusal through the L-REV reference, and
//! assignments, conflicts and scores through its own fold.
//!
//! - [`LifeView`] folds core records into the facts the lifecycle needs.
//!   When a proposal leaves STAGE1 or enters RANKED, the fold computes the
//!   reference outcome from the facts before the batch and keeps it as
//!   ghost state ([`StageOneExit`], [`LifeProposal::expected_effective`]).
//! - [`life_verdict`] says whether a lifecycle command must be accepted
//!   or refused, and what an accepted one must record ([`Expect`]).
//!   [`check_batch`] compares a production batch with that expectation,
//!   and [`synthesize`] builds the records for a run on the reference alone.
//! - [`check_i07`], [`check_i08`], [`check_i09`], [`check_sealed`] and
//!   [`check_recorded_by_human`] are the invariant predicates. They read
//!   the view only.
//! - [`p16_outcome`] is the P-16 ballot rule of NOTE 8.
//!
//! # Readings
//!
//! Each reading is the strictest one the spec text allows. Readings marked
//! as test-author choices fill a gap. The implementer can match them or
//! raise them with Daniel.
//!
//! - The governing policy of a proposal is the frozen policy of the call
//!   it was created in, also after re-entry (NOTE 8).
//! - `RecordKnockOut` is the FSTP coordinator's, in SUBMITTED, once per
//!   proposal. The coordinator first declared no conflict on the proposal,
//!   and the vault finds none (I-03). The outcomes name each P-09 criterion
//!   exactly once. A failed criterion needs a reason and makes the proposal
//!   INELIGIBLE. A passed check leaves it in SUBMITTED.
//! - `AdmitToStage1` is the coordinator's, under the same I-03 condition.
//!   It needs a passed knock-out check and at least P-03 active assignments
//!   in the current call: declared without conflict, not released and with
//!   no conflict fact. Every such assignee must be free of a vault
//!   conflict, or the admission is refused, since stage 1 could not close.
//!   I-34: when every such assignee's committee binding records an
//!   organisation, they span at least P-39 organisations. When a P-38
//!   list applies, the verdict is left open.
//! - A score is the assignee's, through an active assignment and an active
//!   committee member binding, with no conflict fact and no vault conflict.
//!   Stage 1 scores the submitted plan in STAGE1 with assignments of the
//!   creation call. Stage 2 scores a submitted revision in STAGE2 with
//!   assignments of the current call. `RecordScore` needs a key with no
//!   current value, and `CorrectScore` one with a current value. Every
//!   value lies in 0 to N and every P-01 criterion has one (NOTE 6).
//! - Scores seal when the proposal leaves the stage (NOTE 3). Any score
//!   recorded on a stage the proposal is not in is a breach.
//! - `CloseStage1` is recorded by an active FSTP coordinator, never by the
//!   System (R-LA-03, NOTE 13). It needs every active reviewer assignment
//!   of the creation call to hold a valid score, and at least P-03 valid
//!   scores (NOTE 3). The outcome is STAGE2 exactly when the weighted score
//!   is strictly above P-02 (I-08).
//! - The stage 2 window opens when the proposal enters STAGE2, also on
//!   re-entry. It closes at the opening plus P-07 whole days of 86 400
//!   seconds. Test-author choice: "elapsed" means `now >= close`, and
//!   questions, "no questions", answers and revisions need `now < close`.
//! - Questions and "no questions" are the assignee's, once per assignment
//!   and round, and exclusive. The window closes at once when every active
//!   reviewer assignment of the current call recorded "no questions"
//!   (NOTE 4, O-50). The last such record then takes STAGE2 to RANKED.
//! - `AnswerQuestions` is the lead's and needs a question in the round.
//!   Test-author choice: answers are the `AnswersRecorded` records only.
//!   A submitted revision alone is not an answer.
//! - A revision is a plan of origin "stage 2 revision" recorded by the
//!   lead in STAGE2, superseding the live plan, then submitted with
//!   `SubmitRevision`. A scored revision has at least P-03 valid stage 2
//!   scores. The latest submitted scored revision is the revised plan.
//! - `RankAfterStage2` is an assignee's. It needs a scored revision, the
//!   window elapsed with answers, or every active reviewer assignment of
//!   the current call with a "no questions" record (O-50), which a release
//!   of the last one without it can bring about. The effective score is
//!   the stage 1 score on the submitted plan, or the revised plan's score
//!   when it is strictly higher (P-24, I-09). A tie keeps the original
//!   plan (Q3).
//! - `ExpireStage2` is the System's. It needs the window elapsed without
//!   answers, and no future call (R-EV-07, NOTE 5). Stage 2 must not have
//!   concluded: no scored revision, and not every active reviewer with a
//!   "no questions" record (NOTE 4, O-50).
//! - `ReEnter` is the System's. It needs DEFERRED and the next published
//!   call of the programme after the call the proposal left, opened. It
//!   re-enters at the stage left (NOTE 8). It is refused while a former
//!   reviewer of the proposal holds a Receiving binding in that call (I-36).
//! - `RecordCutOff` is recorded by a committee member or chair who is not
//!   recused. The order lists exactly the call's RANKED proposals, with
//!   effective scores that never increase along it. A tie across the
//!   cut-off position needs a recorded P-17 tie-break (R-EV-08 AC). The
//!   ballots follow [`p16_outcome`]. The first `nominated` go to
//!   IRC_REVIEW and the rest become NOT_SELECTED (NOTE 6).
//! - `RecordIrcReview` is the IRC assignee's, once per assignment and
//!   round, while no concern is raised. The proposal enters NEGOTIATION
//!   when every active IRC assignment of the current call validated, there
//!   are at least P-15, and no IRC assignment of the call awaits its
//!   declaration (test-author choice, design 3.2). A validated member may
//!   repeat the validation only to record that entry, for example after
//!   a release by the System, which records no decision (R-LA-03, NOTE
//!   13). Any decision row with the System as actor is a breach that
//!   [`check_recorded_by_human`] reports. For a minor's proposal without a verified
//!   guardian consent, the last validation may be refused or recorded
//!   without the transition (I-18, R-NG-02). A concern goes to the
//!   applicant through the outbox (R-IR-02). With a later published call
//!   of the programme it defers the proposal (NOTE 7). Otherwise the
//!   proposal stays in IRC_REVIEW until the programme manager records
//!   `DeclineAfterConcern` (NOTE 13, O-49). Test-author choice: once a
//!   later call is published, the System's `DeclineAfterConcern` defers it
//!   instead, and the programme manager's is refused.
//! - Every transition records `Transitioned` with its row, the command's
//!   actor and the command's decision id, `None` for a computed outcome
//!   (R-AU-01, design 3.5).

use core::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use fstp_domain::assignment::AssignmentKind;
use fstp_domain::command::{Actor, Command, KnockOutResult};
use fstp_domain::decision::{Ballot, Basis, IrcVerdict, Vote};
use fstp_domain::id::{
    AccountId, AssignmentId, CallId, DecisionId, KnockOutCriterionId, MilestoneId, PlanVersionId,
    PolicyVersionId, ProgrammeId, ProposalId, TextRef,
};
use fstp_domain::proposal::{PlanOrigin, ReentryStage};
use fstp_domain::record::{
    CutOffRecorded, Declared, OutboxEvent, PlanVersionRecorded, Record, RulesVersion,
    ScoreRecorded, Transitioned,
};
use fstp_domain::roles::Role;
use fstp_domain::rules::{Row, StateTag};
use fstp_domain::scoring::{ScoreKey, ScoreVector, Stage, VoidCause};
use fstp_domain::time::{Days, Timestamp};
use fstp_json::{Object, ToJson, Value};
use fstp_ledger::Seq;
use fstp_money::{Amount, Currency, NonNegAmount, Percent, Ratio};

use crate::r#gen::review::WorldFacts;
use crate::reference::review::{
    ConflictFacts, RevView, committee_organisation, holds_active, receiving_ends, recused, team_of,
};
use crate::reference::scoring::{Exact, passes_reference, weighted_reference};
use crate::reference::sod;
use crate::vault::GroundTruth;

// ---------------------------------------------------------------------------
// Vault facts
// ---------------------------------------------------------------------------

/// The vault facts the lifecycle reference reads: the review questions and
/// the guardian consent record (I-18).
pub trait LifeFacts: ConflictFacts {
    /// "Does this proposal have a verified guardian consent record?"
    fn has_consent(&self, proposal: ProposalId) -> bool;
}

impl LifeFacts for GroundTruth {
    fn has_consent(&self, proposal: ProposalId) -> bool {
        GroundTruth::has_consent(self, proposal)
    }
}

impl LifeFacts for WorldFacts<'_> {
    fn has_consent(&self, proposal: ProposalId) -> bool {
        self.truth.has_consent(proposal)
    }
}

// ---------------------------------------------------------------------------
// Exact fractions
// ---------------------------------------------------------------------------

/// An exact non-negative fraction with a denominator above zero, as model state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Frac {
    /// The numerator.
    pub num: u128,
    /// The denominator.
    pub den: u128,
}

impl Frac {
    /// The fraction as the scoring reference's [`Exact`].
    pub fn exact(self) -> Exact {
        Exact {
            num: self.num,
            den: self.den,
        }
    }

    /// The fraction of an [`Exact`].
    pub fn of_exact(e: Exact) -> Frac {
        Frac {
            num: e.num,
            den: e.den,
        }
    }

    /// The fraction of a production [`Ratio`].
    pub fn of_ratio(r: Ratio) -> Frac {
        Frac {
            num: u128::from(r.num()),
            den: u128::from(r.den().get()),
        }
    }

    /// Compares by cross-multiplication. `None` on overflow.
    pub fn compare(self, other: Frac) -> Option<Ordering> {
        self.exact().compare(other.exact())
    }

    /// Whether the two fractions have the same value.
    pub fn same(self, other: Frac) -> bool {
        self.compare(other) == Some(Ordering::Equal)
    }

    /// Whether the fraction is strictly above P-02 in basis points (I-08).
    pub fn above(self, p02_bp: u16) -> Option<bool> {
        passes_reference(self.exact(), p02_bp).ok()
    }
}

impl core::fmt::Display for Frac {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}/{}", self.num, self.den)
    }
}

// ---------------------------------------------------------------------------
// The view
// ---------------------------------------------------------------------------

/// The lifecycle parameters of one policy version.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LifePolicy {
    /// The programme.
    pub programme: ProgrammeId,
    /// The P-01 scale maximum N.
    pub scale_max: u8,
    /// The P-01 weights, in criterion order.
    pub weights: Vec<u16>,
    /// P-02 in basis points.
    pub p02_bp: u16,
    /// P-03.
    pub p03: u8,
    /// P-07 in days.
    pub p07_days: u16,
    /// The P-09 criteria.
    pub p09: BTreeSet<KnockOutCriterionId>,
    /// P-15.
    pub p15: u8,
    /// P-39.
    pub p39: u8,
}

/// A call as the lifecycle reference sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LifeCall {
    /// The programme.
    pub programme: ProgrammeId,
    /// The opening.
    pub opens: Timestamp,
    /// The deadline.
    pub deadline: Timestamp,
    /// The call budget.
    pub budget: NonNegAmount,
    /// The publication sequence number, once published.
    pub seq: Option<u32>,
    /// The frozen policy version, once published.
    pub policy: Option<PolicyVersionId>,
}

/// An assignment as the lifecycle reference sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LifeAssignment {
    /// The proposal.
    pub proposal: ProposalId,
    /// The call it was made in.
    pub call: CallId,
    /// The assignee.
    pub reviewer: AccountId,
    /// The kind.
    pub kind: AssignmentKind,
    /// Whether the assignee declared no conflict on it.
    pub declared: bool,
    /// Whether it was released.
    pub released: bool,
}

impl LifeAssignment {
    /// Whether the assignment is active: declared without conflict and not released.
    pub fn active(&self) -> bool {
        self.declared && !self.released
    }
}

/// A plan version of a proposal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LifePlan {
    /// Where it comes from.
    pub origin: PlanOrigin,
    /// Whether a later plan supersedes it.
    pub superseded: bool,
    /// The total of its milestone amounts.
    pub total: Option<NonNegAmount>,
}

/// The ghost of a stage 1 exit by score: the reference facts just before
/// the proposal left STAGE1 (I-07, I-08, NOTE 3).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct StageOneExit {
    /// The state reached.
    pub to: StateTag,
    /// The valid stage 1 scores on the submitted plan.
    pub valid: BTreeSet<ScoreKey>,
    /// The distinct reviewers behind them.
    pub reviewers: usize,
    /// Whether every active reviewer assignment of the creation call had one.
    pub all_active_scored: bool,
    /// The weighted score of the valid scores, when there is one.
    pub score: Option<Frac>,
    /// Whether that score is strictly above P-02.
    pub passed: Option<bool>,
    /// P-03 of the governing policy.
    pub p03: u8,
    /// P-02 of the governing policy, in basis points.
    pub p02_bp: u16,
}

/// What a `Stage1Closed` record says.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ClosedRecord {
    /// The recorder (R-LA-03).
    pub recorder: AccountId,
    /// The score.
    pub score: Frac,
    /// The threshold, in basis points.
    pub threshold_bp: u16,
    /// The counted keys.
    pub counted: BTreeSet<ScoreKey>,
    /// Whether it passed.
    pub passed: bool,
}

/// An effective score, recorded or expected (I-09).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Effective {
    /// The one plan version it names.
    pub plan: PlanVersionId,
    /// Its value.
    pub value: Frac,
    /// Which plan carries forward.
    pub basis: Basis,
}

/// One stage 2 round: from an entry into STAGE2 to the exit.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Round {
    /// The opening.
    pub opened: Timestamp,
    /// The assignments that asked a question.
    pub questions: BTreeSet<AssignmentId>,
    /// The assignments that recorded "no questions".
    pub no_questions: BTreeSet<AssignmentId>,
    /// Whether the applicant answered.
    pub answered: bool,
}

/// One proposal as the lifecycle reference sees it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LifeProposal {
    /// The call it was created in. Its frozen policy governs (NOTE 8).
    pub created_call: CallId,
    /// The call it is evaluated in now.
    pub current_call: CallId,
    /// The lead.
    pub lead: AccountId,
    /// The minor flag.
    pub minor: bool,
    /// The state.
    pub state: StateTag,
    /// The submitted plan.
    pub submitted: Option<PlanVersionId>,
    /// Every plan version of the proposal.
    pub plans: BTreeMap<PlanVersionId, LifePlan>,
    /// The submitted revisions, in order.
    pub revisions: Vec<PlanVersionId>,
    /// Whether the knock-out check passed, once recorded.
    pub knock_out: Option<bool>,
    /// The `Stage1Closed` record, once recorded.
    pub closed: Option<ClosedRecord>,
    /// The ghost of the stage 1 exit by score.
    pub exit: Option<StageOneExit>,
    /// Whether the proposal ever entered STAGE2.
    pub reached_stage2: bool,
    /// The current or last stage 2 round.
    pub round: Option<Round>,
    /// Every `EffectiveScoreSet` recorded for it.
    pub effective: Vec<Effective>,
    /// The ghost of the effective score the reference expects at RANKED.
    pub expected_effective: Option<Effective>,
    /// Whether a STAGE2 to RANKED transition was recorded.
    pub ranked: bool,
    /// The last deferral: the call left and the stage left.
    pub deferral: Option<(CallId, ReentryStage)>,
    /// The IRC reviews of the current IRC round: validation or concern.
    pub irc: BTreeMap<AssignmentId, bool>,
    /// The concern of the current IRC round.
    pub concern: Option<TextRef>,
    /// Every state the proposal was in.
    pub visited: BTreeSet<StateTag>,
    /// Every row it took.
    pub rows: BTreeSet<Row>,
}

/// The lifecycle reference's fold of core records.
///
/// It holds sets and maps only, so two histories that reach the same
/// situation give equal views, apart from the ghost computed at exits.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LifeView {
    /// Policy versions.
    pub policies: BTreeMap<PolicyVersionId, LifePolicy>,
    /// Calls.
    pub calls: BTreeMap<CallId, LifeCall>,
    /// Proposals.
    pub proposals: BTreeMap<ProposalId, LifeProposal>,
    /// Assignments.
    pub assignments: BTreeMap<AssignmentId, LifeAssignment>,
    /// Conflict facts, declared or detected, by account and proposal.
    pub facts: BTreeSet<(AccountId, ProposalId)>,
    /// Proposal-level no-conflict declarations.
    pub cleared: BTreeSet<(AccountId, ProposalId)>,
    /// Notifiable conflicts (R-CF-04), by account and proposal.
    pub notifiable: BTreeSet<(AccountId, ProposalId)>,
    /// Proposals with a notifiable-conflict draft in the outbox (R-CF-04).
    pub notifiable_outbox: BTreeSet<ProposalId>,
    /// IRC concerns enqueued for the applicant (R-IR-02).
    pub concern_outbox: BTreeSet<(ProposalId, TextRef)>,
    /// The current value of every score key.
    pub scores: BTreeMap<ScoreKey, Vec<u8>>,
    /// Decision ids already used.
    pub decisions: BTreeSet<DecisionId>,
    /// Plan ids already used.
    pub plan_ids: BTreeSet<PlanVersionId>,
    /// Milestone ids already used.
    pub milestones: BTreeSet<MilestoneId>,
    /// Breaches found at fold time, each starting with its rule id.
    pub breaches: BTreeSet<String>,
    /// Decision rows recorded with the System as actor (R-LA-03, NOTE 13).
    pub unrecorded: BTreeSet<String>,
}

impl Default for LifeView {
    fn default() -> LifeView {
        LifeView::new()
    }
}

/// The states after stage 2 in which I-09 must hold (NOTE 1).
pub const AFTER_STAGE2: [StateTag; 11] = [
    StateTag::Ranked,
    StateTag::IrcReview,
    StateTag::Deferred,
    StateTag::Declined,
    StateTag::Negotiation,
    StateTag::Withdrawn,
    StateTag::NotSelected,
    StateTag::Granted,
    StateTag::InExecution,
    StateTag::Completed,
    StateTag::Terminated,
];

/// The states that count against the remaining call budget (design 3.7,
/// Q14): IRC_REVIEW, NEGOTIATION and every later state, TERMINATED included.
pub const BUDGET_STATES: [StateTag; 6] = [
    StateTag::IrcReview,
    StateTag::Negotiation,
    StateTag::Granted,
    StateTag::InExecution,
    StateTag::Completed,
    StateTag::Terminated,
];

fn total_of(tasks: &[fstp_domain::proposal::Task]) -> Option<NonNegAmount> {
    let mut total: Option<Amount> = None;
    for m in tasks.iter().flat_map(|t| t.milestones.iter()) {
        let a = m.amount.amount();
        total = Some(match total {
            None => a,
            Some(t) => t.checked_add(a).ok()?,
        });
    }
    NonNegAmount::new(total?).ok()
}

impl LifeView {
    /// The view of an empty ledger.
    pub fn new() -> LifeView {
        LifeView {
            policies: BTreeMap::new(),
            calls: BTreeMap::new(),
            proposals: BTreeMap::new(),
            assignments: BTreeMap::new(),
            facts: BTreeSet::new(),
            cleared: BTreeSet::new(),
            notifiable: BTreeSet::new(),
            notifiable_outbox: BTreeSet::new(),
            concern_outbox: BTreeSet::new(),
            scores: BTreeMap::new(),
            decisions: BTreeSet::new(),
            plan_ids: BTreeSet::new(),
            milestones: BTreeSet::new(),
            breaches: BTreeSet::new(),
            unrecorded: BTreeSet::new(),
        }
    }

    /// The view of `records`, each folded at its time.
    pub fn of<'a>(
        records: impl IntoIterator<Item = (&'a Record, Timestamp)>,
    ) -> Result<LifeView, String> {
        let mut v = LifeView::new();
        for (r, at) in records {
            v.fold(r, at)?;
        }
        Ok(v)
    }

    /// The governing policy of `proposal`: that of its creation call (NOTE 8).
    pub fn governing(&self, proposal: ProposalId) -> Option<&LifePolicy> {
        let p = self.proposals.get(&proposal)?;
        let v = self.calls.get(&p.created_call)?.policy?;
        self.policies.get(&v)
    }

    /// The programme of `proposal`.
    pub fn programme_of(&self, proposal: ProposalId) -> Option<ProgrammeId> {
        let p = self.proposals.get(&proposal)?;
        self.calls.get(&p.created_call).map(|c| c.programme)
    }

    /// The state of `proposal`.
    pub fn state_of(&self, proposal: ProposalId) -> Option<StateTag> {
        self.proposals.get(&proposal).map(|p| p.state)
    }

    /// The call whose assignments act in `stage`: the creation call for
    /// stage 1 and the current call for stage 2 (NOTE 8).
    pub fn stage_call(&self, proposal: ProposalId, stage: Stage) -> Option<CallId> {
        let p = self.proposals.get(&proposal)?;
        Some(match stage {
            Stage::One => p.created_call,
            Stage::Two => p.current_call,
        })
    }

    /// The active assignments of `kind` on `proposal` in `call` whose assignee has no conflict fact.
    pub fn active_assignments(
        &self,
        proposal: ProposalId,
        call: CallId,
        kind: AssignmentKind,
    ) -> BTreeSet<AssignmentId> {
        self.assignments
            .iter()
            .filter(|(_, a)| {
                a.proposal == proposal
                    && a.call == call
                    && a.kind == kind
                    && a.active()
                    && !self.facts.contains(&(a.reviewer, proposal))
            })
            .map(|(id, _)| *id)
            .collect()
    }

    /// The assignments of `kind` to `proposal` made in `call` that await
    /// their declaration: not declared, not released and without a
    /// conflict fact. Test-author choice: such an IRC assignment is
    /// outstanding, so it keeps the IRC review open (design 3.2).
    pub fn awaiting_declaration(
        &self,
        proposal: ProposalId,
        call: CallId,
        kind: AssignmentKind,
    ) -> BTreeSet<AssignmentId> {
        self.assignments
            .iter()
            .filter(|(_, a)| {
                a.proposal == proposal
                    && a.call == call
                    && a.kind == kind
                    && !a.declared
                    && !a.released
                    && !self.facts.contains(&(a.reviewer, proposal))
            })
            .map(|(id, _)| *id)
            .collect()
    }

    /// The valid scores of `proposal` on `(stage, plan)` (NOTE 3, design 2.9):
    /// current values from active reviewer assignments of the stage's call,
    /// whose assignee has no conflict fact on the proposal.
    pub fn valid_keys(
        &self,
        proposal: ProposalId,
        stage: Stage,
        plan: PlanVersionId,
    ) -> BTreeSet<ScoreKey> {
        let Some(call) = self.stage_call(proposal, stage) else {
            return BTreeSet::new();
        };
        let active = self.active_assignments(proposal, call, AssignmentKind::Reviewer);
        self.scores
            .keys()
            .filter(|k| k.stage == stage && k.plan == plan && active.contains(&k.assignment))
            .copied()
            .collect()
    }

    /// The distinct reviewers behind `keys`.
    pub fn reviewers_of(&self, keys: &BTreeSet<ScoreKey>) -> usize {
        keys.iter()
            .filter_map(|k| self.assignments.get(&k.assignment).map(|a| a.reviewer))
            .collect::<BTreeSet<_>>()
            .len()
    }

    /// The weighted score of the current values of `keys` under the
    /// governing P-01 of `proposal` (NOTE 6), or `None` without keys.
    pub fn score_of(&self, proposal: ProposalId, keys: &BTreeSet<ScoreKey>) -> Option<Frac> {
        let policy = self.governing(proposal)?;
        let vectors: Vec<Vec<u8>> = keys
            .iter()
            .filter_map(|k| self.scores.get(k).cloned())
            .collect();
        if vectors.is_empty() {
            return None;
        }
        weighted_reference(policy.scale_max, &policy.weights, &vectors)
            .ok()
            .map(Frac::of_exact)
    }

    /// The stage 1 facts of `proposal` now, as the ghost of an exit to `to`.
    pub fn stage_one_facts(&self, proposal: ProposalId, to: StateTag) -> Option<StageOneExit> {
        let p = self.proposals.get(&proposal)?;
        let policy = self.governing(proposal)?;
        let plan = p.submitted?;
        let valid = self.valid_keys(proposal, Stage::One, plan);
        let scored: BTreeSet<AssignmentId> = valid.iter().map(|k| k.assignment).collect();
        let active = self.active_assignments(proposal, p.created_call, AssignmentKind::Reviewer);
        let score = self.score_of(proposal, &valid);
        Some(StageOneExit {
            to,
            reviewers: self.reviewers_of(&valid),
            all_active_scored: active.is_subset(&scored),
            passed: score.and_then(|s| s.above(policy.p02_bp)),
            score,
            valid,
            p03: policy.p03,
            p02_bp: policy.p02_bp,
        })
    }

    /// Whether stage 1 of `proposal` may close now (NOTE 3).
    pub fn stage1_closable(&self, proposal: ProposalId) -> bool {
        self.stage_one_facts(proposal, StateTag::Stage2)
            .is_some_and(|e| e.all_active_scored && e.reviewers >= usize::from(e.p03))
    }

    /// The close of the stage 2 window of `proposal`, when it is in a round.
    pub fn window_end(&self, proposal: ProposalId) -> Option<Timestamp> {
        let p = self.proposals.get(&proposal)?;
        let days = self.governing(proposal)?.p07_days;
        p.round.as_ref()?.opened.checked_add_days(Days::new(days))
    }

    /// The score of revision `plan` when it has at least P-03 valid stage 2 scores.
    pub fn revision_score(&self, proposal: ProposalId, plan: PlanVersionId) -> Option<Frac> {
        let p03 = self.governing(proposal)?.p03;
        let keys = self.valid_keys(proposal, Stage::Two, plan);
        if self.reviewers_of(&keys) < usize::from(p03) {
            return None;
        }
        self.score_of(proposal, &keys)
    }

    /// The latest submitted revision with at least P-03 valid stage 2 scores, and its score (NOTE 4).
    pub fn latest_scored_revision(&self, proposal: ProposalId) -> Option<(PlanVersionId, Frac)> {
        let p = self.proposals.get(&proposal)?;
        p.revisions
            .iter()
            .rev()
            .find_map(|plan| self.revision_score(proposal, *plan).map(|s| (*plan, s)))
    }

    /// The effective score the reference computes now (P-24, I-09, Q3):
    /// the revised plan only when its score is strictly higher.
    pub fn effective_now(&self, proposal: ProposalId) -> Option<Effective> {
        let p = self.proposals.get(&proposal)?;
        let original_plan = p.submitted?;
        let original = p.exit.as_ref()?.score?;
        match self.latest_scored_revision(proposal) {
            Some((plan, value)) if value.compare(original) == Some(Ordering::Greater) => {
                Some(Effective {
                    plan,
                    value,
                    basis: Basis::Revised,
                })
            }
            _ => Some(Effective {
                plan: original_plan,
                value: original,
                basis: Basis::Original,
            }),
        }
    }

    /// Whether every active reviewer assignment of the current call recorded
    /// "no questions" in the open round, with at least one such assignment
    /// (NOTE 4, O-50). This also holds once the last assignee who had not
    /// recorded it is released.
    pub fn no_questions_complete(&self, proposal: ProposalId) -> bool {
        let Some(p) = self.proposals.get(&proposal) else {
            return false;
        };
        let Some(round) = p.round.as_ref() else {
            return false;
        };
        let active = self.active_assignments(proposal, p.current_call, AssignmentKind::Reviewer);
        !active.is_empty() && active.is_subset(&round.no_questions)
    }

    /// The sequence number of `call`, once published.
    pub fn seq_of(&self, call: CallId) -> Option<u32> {
        self.calls.get(&call).and_then(|c| c.seq)
    }

    /// Whether a later call of the programme of `call` is published (NOTE 7).
    pub fn later_call_published(&self, call: CallId) -> bool {
        let Some(c) = self.calls.get(&call) else {
            return false;
        };
        let Some(seq) = c.seq else {
            return false;
        };
        self.calls
            .values()
            .any(|d| d.programme == c.programme && d.seq.is_some_and(|s| s > seq))
    }

    /// The next published call of the programme after `call`, by sequence number.
    pub fn next_call_after(&self, call: CallId) -> Option<CallId> {
        let c = self.calls.get(&call)?;
        let seq = c.seq?;
        self.calls
            .iter()
            .filter(|(_, d)| d.programme == c.programme && d.seq.is_some_and(|s| s > seq))
            .min_by_key(|(_, d)| d.seq)
            .map(|(id, _)| *id)
    }

    /// The remaining budget of `call` (R-EV-08, design 3.7, Q14): the
    /// budget minus the requested totals of the call's proposals in
    /// IRC_REVIEW, NEGOTIATION and later states. The requested total is the
    /// submitted plan's, as the committee ranking view shows it, so the
    /// recorded value is the value the committee saw.
    pub fn remaining_budget(&self, call: CallId) -> Option<Amount> {
        let c = self.calls.get(&call)?;
        let mut left = c.budget.amount();
        for p in self.proposals.values() {
            if p.current_call != call || !BUDGET_STATES.contains(&p.state) {
                continue;
            }
            let plan = p
                .submitted
                .and_then(|id| p.plans.get(&id))
                .and_then(|pl| pl.total)?;
            left = left.checked_sub(plan.amount()).ok()?;
        }
        Some(left)
    }

    fn proposal_mut(&mut self, proposal: ProposalId) -> Result<&mut LifeProposal, String> {
        self.proposals
            .get_mut(&proposal)
            .ok_or_else(|| format!("record for unknown proposal {proposal:?}"))
    }

    /// Folds one core record entered at `at`. Records outside the
    /// lifecycle leave the view unchanged. An error names a record the
    /// reference cannot follow, which no engine may emit.
    pub fn fold(&mut self, record: &Record, at: Timestamp) -> Result<(), String> {
        match record {
            Record::PolicyVersionRecorded { version, .. } => {
                let f = &version.frozen;
                self.policies.insert(
                    version.id,
                    LifePolicy {
                        programme: version.programme,
                        scale_max: f.p01.scale_max().get(),
                        weights: f.p01.items().iter().map(|c| c.weight.get()).collect(),
                        p02_bp: f.p02.bp(),
                        p03: f.p03.get(),
                        p07_days: f.p07.get(),
                        p09: f.p09.0.iter().map(|c| c.id).collect(),
                        p15: f.p15.get(),
                        p39: f.p39.get(),
                    },
                );
            }
            Record::CallDrafted {
                call,
                programme,
                opens,
                deadline,
                budget,
                ..
            } => {
                self.calls.insert(
                    *call,
                    LifeCall {
                        programme: *programme,
                        opens: *opens,
                        deadline: *deadline,
                        budget: *budget,
                        seq: None,
                        policy: None,
                    },
                );
            }
            Record::CallEdited {
                call,
                opens,
                deadline,
                budget,
                ..
            } => {
                let c = self
                    .calls
                    .get_mut(call)
                    .ok_or_else(|| format!("unknown call {call:?} edited"))?;
                c.opens = *opens;
                c.deadline = *deadline;
                c.budget = *budget;
            }
            Record::CallApproved { decision, .. } => {
                self.decisions.insert(*decision);
            }
            Record::CallPublished {
                call, policy, seq, ..
            } => {
                let c = self
                    .calls
                    .get_mut(call)
                    .ok_or_else(|| format!("unknown call {call:?} published"))?;
                c.seq = Some(seq.get());
                c.policy = Some(*policy);
            }
            Record::ProposalCreated {
                proposal,
                call,
                lead,
                minor,
            } => {
                if self.proposals.contains_key(proposal) {
                    return Err(format!("proposal {proposal:?} created twice"));
                }
                self.proposals.insert(
                    *proposal,
                    LifeProposal {
                        created_call: *call,
                        current_call: *call,
                        lead: *lead,
                        minor: *minor,
                        state: StateTag::Draft,
                        submitted: None,
                        plans: BTreeMap::new(),
                        revisions: Vec::new(),
                        knock_out: None,
                        closed: None,
                        exit: None,
                        reached_stage2: false,
                        round: None,
                        effective: Vec::new(),
                        expected_effective: None,
                        ranked: false,
                        deferral: None,
                        irc: BTreeMap::new(),
                        concern: None,
                        visited: [StateTag::Draft].into_iter().collect(),
                        rows: BTreeSet::new(),
                    },
                );
            }
            Record::PlanVersionRecorded(p) => self.fold_plan(p)?,
            Record::Submitted { proposal, plan, .. } => {
                self.proposal_mut(*proposal)?.submitted = Some(*plan);
            }
            Record::Assigned(a) => {
                self.assignments.insert(
                    a.assignment,
                    LifeAssignment {
                        proposal: a.proposal,
                        call: a.call,
                        reviewer: a.reviewer,
                        kind: a.kind,
                        declared: false,
                        released: false,
                    },
                );
            }
            Record::ConflictDeclared(d) => match d.subject {
                Declared::Assignment(id) => {
                    let a = self
                        .assignments
                        .get_mut(&id)
                        .ok_or_else(|| format!("declaration on unknown assignment {id:?}"))?;
                    if d.conflicted {
                        let pair = (a.reviewer, a.proposal);
                        self.facts.insert(pair);
                        if d.notifiable {
                            self.notifiable.insert(pair);
                        }
                    } else {
                        a.declared = true;
                    }
                }
                Declared::Proposal { proposal, account } => {
                    if d.conflicted {
                        self.facts.insert((account, proposal));
                        if d.notifiable {
                            self.notifiable.insert((account, proposal));
                        }
                    } else {
                        self.cleared.insert((account, proposal));
                    }
                }
            },
            Record::ConflictDetected(d) => {
                self.facts.insert((d.account, d.proposal));
                if d.notifiable {
                    self.notifiable.insert((d.account, d.proposal));
                }
            }
            Record::AssignmentReleased(r) => {
                let a = self
                    .assignments
                    .get_mut(&r.assignment)
                    .ok_or_else(|| format!("unknown assignment {:?} released", r.assignment))?;
                a.released = true;
            }
            Record::KnockOutRecorded {
                decision,
                proposal,
                outcomes,
                ..
            } => {
                self.decisions.insert(*decision);
                let passed = outcomes.iter().all(|o| o.passed);
                self.proposal_mut(*proposal)?.knock_out = Some(passed);
            }
            Record::ScoreRecorded(s) => self.fold_score(s)?,
            Record::ScoreVoided(v) => {
                self.scores.remove(&v.key);
            }
            Record::Stage1Closed(c) => {
                let closed = ClosedRecord {
                    recorder: c.recorder(),
                    score: Frac::of_ratio(c.score()),
                    threshold_bp: c.threshold().bp(),
                    counted: c.counted().clone(),
                    passed: c.passed(),
                };
                self.proposal_mut(c.proposal())?.closed = Some(closed);
            }
            Record::QuestionAsked {
                proposal,
                assignment,
                ..
            } => {
                let p = self.proposal_mut(*proposal)?;
                let round = p
                    .round
                    .as_mut()
                    .ok_or("I-07: a stage 2 question outside a stage 2 round")?;
                round.questions.insert(*assignment);
            }
            Record::NoQuestionsRecorded {
                proposal,
                assignment,
            } => {
                let p = self.proposal_mut(*proposal)?;
                let round = p
                    .round
                    .as_mut()
                    .ok_or("NOTE 4: \"no questions\" outside a stage 2 round")?;
                round.no_questions.insert(*assignment);
            }
            Record::AnswersRecorded { proposal, .. } => {
                let p = self.proposal_mut(*proposal)?;
                let round = p
                    .round
                    .as_mut()
                    .ok_or("NOTE 4: answers outside a stage 2 round")?;
                round.answered = true;
            }
            Record::RevisionSubmitted { proposal, plan } => {
                self.proposal_mut(*proposal)?.revisions.push(*plan);
            }
            Record::EffectiveScoreSet(e) => {
                let eff = Effective {
                    plan: e.plan(),
                    value: Frac::of_ratio(e.value()),
                    basis: e.basis(),
                };
                self.proposal_mut(e.proposal())?.effective.push(eff);
            }
            Record::CutOffRecorded(c) => {
                self.decisions.insert(c.decision);
            }
            Record::IrcReviewRecorded {
                assignment,
                verdict,
            } => {
                let a = *self
                    .assignments
                    .get(assignment)
                    .ok_or_else(|| format!("IRC review on unknown assignment {assignment:?}"))?;
                let p = self.proposal_mut(a.proposal)?;
                match verdict {
                    IrcVerdict::Validate => {
                        p.irc.insert(*assignment, true);
                    }
                    IrcVerdict::Concern(t) => {
                        p.irc.insert(*assignment, false);
                        p.concern = Some(*t);
                    }
                }
            }
            Record::DeferralRecorded {
                proposal,
                from_call,
                left,
            } => {
                self.proposal_mut(*proposal)?.deferral = Some((*from_call, *left));
            }
            Record::ReEntered {
                proposal, to_call, ..
            } => {
                self.proposal_mut(*proposal)?.current_call = *to_call;
            }
            Record::Transitioned(t) => self.fold_transition(t, at)?,
            Record::OutboxEnqueued(OutboxEvent::NotifiableConflict { proposal }) => {
                self.notifiable_outbox.insert(*proposal);
            }
            Record::OutboxEnqueued(OutboxEvent::IrcConcern { proposal, concern }) => {
                self.concern_outbox.insert((*proposal, *concern));
            }
            _ => {}
        }
        Ok(())
    }

    fn fold_plan(&mut self, p: &PlanVersionRecorded) -> Result<(), String> {
        self.plan_ids.insert(p.plan);
        for m in p.tasks.iter().flat_map(|t| t.milestones.iter()) {
            self.milestones.insert(m.id);
        }
        let life = self.proposal_mut(p.proposal)?;
        if let Some(s) = p.supersedes
            && let Some(old) = life.plans.get_mut(&s)
        {
            old.superseded = true;
        }
        life.plans.insert(
            p.plan,
            LifePlan {
                origin: p.origin,
                superseded: false,
                total: total_of(&p.tasks),
            },
        );
        Ok(())
    }

    fn fold_score(&mut self, s: &ScoreRecorded) -> Result<(), String> {
        let a = *self
            .assignments
            .get(&s.key.assignment)
            .ok_or_else(|| format!("score on unknown assignment {:?}", s.key.assignment))?;
        let state = self
            .state_of(a.proposal)
            .ok_or("score on an unknown proposal")?;
        let open = match s.key.stage {
            Stage::One => StateTag::Stage1,
            Stage::Two => StateTag::Stage2,
        };
        if state != open {
            self.breaches.insert(format!(
                "NOTE 3: a {:?} score on {:?} was recorded in {state:?}, after the stage sealed",
                s.key.stage, a.proposal
            ));
        }
        self.scores.insert(s.key, s.values.0.clone());
        Ok(())
    }

    fn fold_transition(&mut self, t: &Transitioned, at: Timestamp) -> Result<(), String> {
        let from = self
            .state_of(t.proposal)
            .ok_or_else(|| format!("unknown proposal {:?} transitioned", t.proposal))?;
        if from != t.from {
            return Err(format!(
                "{:?} transitioned from {:?}, but it is in {from:?}",
                t.proposal, t.from
            ));
        }
        // R-AU-01: the decision id of a transition is taken from then on.
        // An admission records its id on the transition alone.
        if let Some(d) = t.decision {
            self.decisions.insert(d);
        }
        if matches!(t.actor, Actor::System(_)) && !system_recorded(t.row) {
            self.unrecorded.insert(format!(
                "R-LA-03, NOTE 13: {:?} took {:?} with the System as actor, \
                 but the row is a decision that a named human records",
                t.proposal, t.row
            ));
        }
        let exit = if from == StateTag::Stage1
            && matches!(t.to, StateTag::Stage2 | StateTag::NotSelected)
        {
            self.stage_one_facts(t.proposal, t.to)
        } else {
            None
        };
        let effective = if from == StateTag::Stage2 && t.to == StateTag::Ranked {
            self.effective_now(t.proposal)
        } else {
            None
        };
        let p = self.proposal_mut(t.proposal)?;
        if let Some(e) = exit {
            p.exit = Some(e);
        }
        if effective.is_some() {
            p.expected_effective = effective;
        }
        if t.to == StateTag::Ranked && from == StateTag::Stage2 {
            p.ranked = true;
        }
        if t.to == StateTag::Stage2 {
            p.reached_stage2 = true;
            p.round = Some(Round {
                opened: at,
                questions: BTreeSet::new(),
                no_questions: BTreeSet::new(),
                answered: false,
            });
        }
        if t.to == StateTag::IrcReview {
            p.irc = BTreeMap::new();
            p.concern = None;
        }
        p.state = t.to;
        p.visited.insert(t.to);
        p.rows.insert(t.row);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Invariant predicates
// ---------------------------------------------------------------------------

/// I-07: every exit from STAGE1 by score had at least P-03 valid scores,
/// and every active assigned reviewer had one (NOTE 3).
pub fn check_i07(view: &LifeView) -> Result<(), String> {
    for (id, p) in &view.proposals {
        if let Some(e) = &p.exit
            && (e.reviewers < usize::from(e.p03) || !e.all_active_scored)
        {
            return Err(format!(
                "I-07: {id:?} left STAGE1 for {:?} with {} valid scores ({} reviewers, P-03 {}), every active assignee scored: {}",
                e.to,
                e.valid.len(),
                e.reviewers,
                e.p03,
                e.all_active_scored
            ));
        }
    }
    Ok(())
}

/// I-08: a proposal reached STAGE2 only with a weighted score strictly
/// above P-02, and NOT_SELECTED from STAGE1 only without one. A recorded
/// `Stage1Closed` agrees with the reference score and outcome.
pub fn check_i08(view: &LifeView) -> Result<(), String> {
    for (id, p) in &view.proposals {
        if p.reached_stage2 {
            let passed = p.exit.as_ref().and_then(|e| e.passed);
            if passed != Some(true) {
                return Err(format!(
                    "I-08: {id:?} reached STAGE2, but its stage 1 score {:?} is not strictly above P-02",
                    p.exit.as_ref().map(|e| (e.score, e.p02_bp))
                ));
            }
        }
        let Some(e) = &p.exit else {
            continue;
        };
        if e.to == StateTag::NotSelected && e.passed == Some(true) {
            return Err(format!(
                "I-08: {id:?} became NOT_SELECTED at stage 1 with a score {:?} strictly above P-02 {}",
                e.score, e.p02_bp
            ));
        }
        if let Some(c) = &p.closed {
            let same = e.score.is_some_and(|s| s.same(c.score));
            if !same || Some(c.passed) != e.passed || c.threshold_bp != e.p02_bp {
                return Err(format!(
                    "I-08: Stage1Closed of {id:?} says {} against {} passed {}, the reference computes {:?} against {} passed {:?}",
                    c.score, c.threshold_bp, c.passed, e.score, e.p02_bp, e.passed
                ));
            }
        }
    }
    Ok(())
}

/// I-09: every proposal that took STAGE2 to RANKED has exactly one
/// effective score in every later state. It names one plan of the proposal
/// and follows P-24 with the original plan on a tie (NOTE 1, NOTE 4).
pub fn check_i09(view: &LifeView) -> Result<(), String> {
    for (id, p) in &view.proposals {
        if !p.ranked {
            if !p.effective.is_empty() {
                return Err(format!(
                    "I-09: {id:?} has an effective score but never took STAGE2 to RANKED"
                ));
            }
            continue;
        }
        let [e] = p.effective.as_slice() else {
            return Err(format!(
                "I-09: {id:?} in {:?} has {} effective scores, not exactly one",
                p.state,
                p.effective.len()
            ));
        };
        if !p.plans.contains_key(&e.plan) {
            return Err(format!(
                "I-09: the effective score of {id:?} names {:?}, which is not one of its plans",
                e.plan
            ));
        }
        match &p.expected_effective {
            Some(x) if x.plan == e.plan && x.basis == e.basis && x.value.same(e.value) => {}
            other => {
                return Err(format!(
                    "I-09: the effective score of {id:?} is {e:?}, P-24 gives {other:?}"
                ));
            }
        }
    }
    Ok(())
}

/// NOTE 3: no score was recorded on a stage after it sealed.
pub fn check_sealed(view: &LifeView) -> Result<(), String> {
    match view.breaches.iter().next() {
        Some(b) => Err(b.clone()),
        None => Ok(()),
    }
}

/// The rows the System may record (NOTE 13, O-49): those driven by a timer
/// or a date, which are not decisions. Test-author choice: the System's
/// deferral after a concern once a later call is published (NOTE 7) is
/// one too. Every other row is a decision that a named human records.
pub fn system_recorded(row: Row) -> bool {
    matches!(
        row,
        Row::Stage2ToDeferred
            | Row::DeferredToStage2
            | Row::DeferredToIrcReview
            | Row::IrcReviewToDeferred
            | Row::GrantedToInExecution
            | Row::InExecutionToCompleted
    )
}

/// R-LA-03, NOTE 13: no decision row was recorded with the System as actor.
pub fn check_recorded_by_human(view: &LifeView) -> Result<(), String> {
    match view.unrecorded.iter().next() {
        Some(b) => Err(b.clone()),
        None => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// P-16
// ---------------------------------------------------------------------------

/// The outcome of a cut-off ballot under P-16 (NOTE 8, R-EV-09, Conflict
/// declarations): `Ok(true)` adopted, `Ok(false)` not adopted, `Err` an
/// invalid ballot set.
///
/// - Every voter and every delegating member is a committee member who is
///   not recused. Nobody delegates to themselves.
/// - Each member is represented once, voting or delegating, and a voter
///   holds at most one delegated vote.
/// - The quorum is more than half of the members who are not recused,
///   delegated votes included.
/// - Abstentions are not votes cast (test-author choice). The decision is
///   adopted with more votes for than against. On a tie, the chair's own
///   vote decides as the casting vote.
pub fn p16_outcome(
    members: &BTreeSet<AccountId>,
    recused: &BTreeSet<AccountId>,
    chairs: &BTreeSet<AccountId>,
    ballots: &[Ballot],
) -> Result<bool, String> {
    let eligible: BTreeSet<AccountId> = members.difference(recused).copied().collect();
    let mut represented: BTreeSet<AccountId> = BTreeSet::new();
    let mut delegations: BTreeMap<AccountId, u8> = BTreeMap::new();
    let mut votes_for: usize = 0;
    let mut votes_against: usize = 0;
    let mut chair_for = false;
    for b in ballots {
        if !eligible.contains(&b.voter) {
            return Err(format!(
                "P-16: {:?} votes but is not a committee member who may vote",
                b.voter
            ));
        }
        let member = match b.delegated_by {
            Some(d) if d == b.voter => {
                return Err(format!("P-16: {d:?} delegates to themselves"));
            }
            Some(d) if !eligible.contains(&d) => {
                return Err(format!(
                    "P-16: {d:?} delegates but is not a committee member who may vote"
                ));
            }
            Some(d) => {
                let n = delegations.entry(b.voter).or_insert(0);
                *n = n.saturating_add(1);
                if *n > 1 {
                    return Err(format!(
                        "P-16: {:?} holds more than one delegated vote",
                        b.voter
                    ));
                }
                d
            }
            None => b.voter,
        };
        if !represented.insert(member) {
            return Err(format!("P-16: {member:?} votes twice"));
        }
        match b.vote {
            Vote::For => votes_for = votes_for.saturating_add(1),
            Vote::Against => votes_against = votes_against.saturating_add(1),
            Vote::Abstain => {}
        }
        if b.delegated_by.is_none() && chairs.contains(&b.voter) && b.vote == Vote::For {
            chair_for = true;
        }
    }
    if represented.len().saturating_mul(2) <= eligible.len() {
        return Err(format!(
            "P-16: {} of {} members who may vote take part, no quorum",
            represented.len(),
            eligible.len()
        ));
    }
    Ok(votes_for > votes_against || (votes_for == votes_against && chair_for))
}

/// The accounts with an active binding of `role` in `programme` at `now`.
pub fn holders(
    view: &sod::View,
    role: Role,
    programme: ProgrammeId,
    now: Timestamp,
) -> BTreeSet<AccountId> {
    view.bindings
        .values()
        .filter(|b| b.role == role && b.programme == programme && b.active() && b.start <= now)
        .map(|b| b.account)
        .collect()
}

/// The committee of `programme` at `now`: committee members and chairs.
pub fn committee(view: &sod::View, programme: ProgrammeId, now: Timestamp) -> BTreeSet<AccountId> {
    let mut out = holders(view, Role::CommitteeMember, programme, now);
    out.extend(holders(view, Role::CommitteeChair, programme, now));
    out
}

// ---------------------------------------------------------------------------
// Expectations
// ---------------------------------------------------------------------------

/// One record an accepted batch must hold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Want {
    /// The knock-out record.
    KnockOut {
        /// The decision.
        decision: DecisionId,
        /// The proposal.
        proposal: ProposalId,
        /// The coordinator.
        coordinator: AccountId,
        /// The outcomes.
        outcomes: Vec<KnockOutResult>,
        /// The reason.
        reason: Option<TextRef>,
    },
    /// A score or a correction.
    Score {
        /// The key.
        key: ScoreKey,
        /// The values.
        values: Vec<u8>,
        /// The reason of a correction.
        correction: Option<TextRef>,
    },
    /// The stage 1 close.
    Stage1Closed {
        /// The proposal.
        proposal: ProposalId,
        /// The recorder.
        recorder: AccountId,
        /// The score.
        score: Frac,
        /// The threshold in basis points.
        threshold_bp: u16,
        /// The counted keys.
        counted: BTreeSet<ScoreKey>,
        /// Whether it passed.
        passed: bool,
    },
    /// A record that must appear exactly as given.
    Exact(Record),
    /// The effective score.
    Effective {
        /// The proposal.
        proposal: ProposalId,
        /// The expected score.
        effective: Effective,
        /// The keys behind it.
        counted: BTreeSet<ScoreKey>,
    },
    /// The cut-off record.
    CutOff(Box<CutOffRecorded>),
}

impl Want {
    /// Whether `r` is the wanted record. The cut-off's remaining budget and
    /// a correction's superseded entry are not compared here.
    pub fn matches(&self, r: &Record) -> bool {
        match (self, r) {
            (
                Want::KnockOut {
                    decision,
                    proposal,
                    coordinator,
                    outcomes,
                    reason,
                },
                Record::KnockOutRecorded {
                    decision: d,
                    proposal: p,
                    coordinator: c,
                    outcomes: o,
                    reason: why,
                    ..
                },
            ) => {
                d == decision && p == proposal && c == coordinator && o == outcomes && why == reason
            }
            (
                Want::Score {
                    key,
                    values,
                    correction,
                },
                Record::ScoreRecorded(s),
            ) => {
                s.key == *key
                    && s.values.0 == *values
                    && s.reason == *correction
                    && s.supersedes.is_some() == correction.is_some()
            }
            (
                Want::Stage1Closed {
                    proposal,
                    recorder,
                    score,
                    threshold_bp,
                    counted,
                    passed,
                },
                Record::Stage1Closed(c),
            ) => {
                c.proposal() == *proposal
                    && c.recorder() == *recorder
                    && Frac::of_ratio(c.score()).same(*score)
                    && c.threshold().bp() == *threshold_bp
                    && c.counted() == counted
                    && c.passed() == *passed
            }
            (Want::Exact(want), got) => want == got,
            (
                Want::Effective {
                    proposal,
                    effective,
                    ..
                },
                Record::EffectiveScoreSet(e),
            ) => {
                e.proposal() == *proposal
                    && e.plan() == effective.plan
                    && e.basis() == effective.basis
                    && Frac::of_ratio(e.value()).same(effective.value)
            }
            (Want::CutOff(want), Record::CutOffRecorded(c)) => {
                c.decision == want.decision
                    && c.call == want.call
                    && c.order == want.order
                    && c.nominated == want.nominated
                    && c.rationale == want.rationale
                    && c.tie_breaks == want.tie_breaks
                    && c.ballots == want.ballots
                    && c.recused == want.recused
                    && c.recorder == want.recorder
            }
            _ => false,
        }
    }

    /// The record a run on the reference alone appends for this want.
    pub fn record(&self) -> Result<Record, String> {
        Ok(match self {
            Want::KnockOut {
                decision,
                proposal,
                coordinator,
                outcomes,
                reason,
            } => Record::KnockOutRecorded {
                decision: *decision,
                proposal: *proposal,
                coordinator: *coordinator,
                outcomes: outcomes.clone(),
                reason: *reason,
                rules: RulesVersion::M2,
            },
            Want::Score {
                key,
                values,
                correction,
            } => Record::ScoreRecorded(ScoreRecorded {
                key: *key,
                values: ScoreVector(values.clone()),
                supersedes: correction.map(|_| Seq::from_raw(1)),
                reason: *correction,
            }),
            Want::Stage1Closed {
                proposal,
                recorder,
                score,
                threshold_bp,
                counted,
                passed,
            } => forge_stage1_closed(
                *proposal,
                *recorder,
                *score,
                *threshold_bp,
                counted,
                *passed,
            )?,
            Want::Exact(r) => r.clone(),
            Want::Effective {
                proposal,
                effective,
                counted,
            } => forge_effective(*proposal, *effective, counted)?,
            Want::CutOff(c) => Record::CutOffRecorded((**c).clone()),
        })
    }
}

/// What an accepted lifecycle command must record.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Expect {
    /// The records the batch must hold.
    pub wants: Vec<Want>,
    /// Exactly the transitions the batch must hold (R-AU-01).
    pub transitions: Vec<Transitioned>,
    /// The proposals that reach a terminal state, whose Receiving bindings
    /// end in the same batch (Q11 A). A run on the reference alone
    /// appends those ends.
    pub terminal: Vec<ProposalId>,
}

/// The lifecycle verdict on one command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LifeVerdict {
    /// The command must be accepted and record what [`Expect`] says.
    Accept(Expect),
    /// The command may be refused. When accepted, it must record what
    /// [`Expect`] says.
    Either(Expect),
    /// The command must be refused, for the reason named.
    Refuse(String),
    /// The command is not a lifecycle command of this reference.
    NotMine,
}

impl LifeVerdict {
    /// Whether the command must be accepted.
    pub fn accepts(&self) -> bool {
        matches!(self, LifeVerdict::Accept(_))
    }
}

/// Checks an accepted batch against `exp`: every wanted record is in the
/// batch, and the batch's transitions are exactly the expected ones.
pub fn check_batch(context: &str, exp: &Expect, batch: &[Record]) -> Result<(), String> {
    for w in &exp.wants {
        if !batch.iter().any(|r| w.matches(r)) {
            return Err(format!(
                "{context}: the batch lacks {w:?}\n  batch: {batch:?}"
            ));
        }
    }
    let mut got: Vec<Transitioned> = batch
        .iter()
        .filter_map(|r| match r {
            Record::Transitioned(t) => Some(*t),
            _ => None,
        })
        .collect();
    let mut want = exp.transitions.clone();
    let key = |t: &Transitioned| (t.proposal, t.from, t.to, t.row);
    got.sort_by_key(key);
    want.sort_by_key(key);
    if got != want {
        return Err(format!(
            "{context}: R-AU-01, the transitions are {got:?}, the reference expects {want:?}"
        ));
    }
    Ok(())
}

/// The records of an accepted command on the reference alone: the wanted
/// records, the transitions, and the ends of the Receiving bindings of
/// proposals that reach a terminal state (Q11 A).
pub fn synthesize(exp: &Expect, view: &sod::View, now: Timestamp) -> Result<Vec<Record>, String> {
    let mut out = Vec::new();
    for w in &exp.wants {
        out.push(w.record()?);
    }
    out.extend(exp.transitions.iter().map(|t| Record::Transitioned(*t)));
    for p in &exp.terminal {
        out.extend(receiving_ends(view, *p, now));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Forged witness records, for runs on the reference alone and teeth faults
// ---------------------------------------------------------------------------

fn member_of(record: &Record, name: &str) -> Result<Value, String> {
    record
        .to_json()
        .get(name)
        .cloned()
        .ok_or_else(|| format!("the codec writes no {name} member"))
}

fn template(proposal: ProposalId, recorder: AccountId) -> Record {
    Record::KnockOutRecorded {
        decision: DecisionId::from_raw(0),
        proposal,
        coordinator: recorder,
        outcomes: Vec::new(),
        reason: None,
        rules: RulesVersion::M2,
    }
}

fn key_json(key: ScoreKey) -> Result<Value, String> {
    member_of(
        &Record::ScoreVoided(fstp_domain::record::ScoreVoided {
            key,
            cause: VoidCause::Conflict,
        }),
        "key",
    )
}

fn ratio_json(f: Frac) -> Result<Value, String> {
    let num = u64::try_from(f.num).map_err(|_| "numerator above u64")?;
    let den = u64::try_from(f.den)
        .ok()
        .and_then(core::num::NonZeroU64::new)
        .ok_or("denominator 0 or above u64")?;
    let r = Ratio::new(num, den);
    let mut o = Object::new();
    o.insert("num", Value::String(r.num().to_string()));
    o.insert("den", Value::String(r.den().get().to_string()));
    Ok(Value::Object(o))
}

fn keys_json(keys: &BTreeSet<ScoreKey>) -> Result<Value, String> {
    let mut items = Vec::new();
    for k in keys {
        items.push(key_json(*k)?);
    }
    Ok(Value::Array(fstp_json::Array::from(items)))
}

fn decode(o: Object) -> Result<Record, String> {
    fstp_domain::codec::record_from_json_at(fstp_domain::codec::CURRENT_SCHEMA, &Value::Object(o))
        .map_err(|e| format!("the codec refused a forged record: {e:?}"))
}

/// A `Stage1Closed` record with these fields, built through the record
/// decoder. Only runs on the reference alone and teeth faults use it.
pub fn forge_stage1_closed(
    proposal: ProposalId,
    recorder: AccountId,
    score: Frac,
    threshold_bp: u16,
    counted: &BTreeSet<ScoreKey>,
    passed: bool,
) -> Result<Record, String> {
    let t = template(proposal, recorder);
    let threshold = Percent::from_bp(threshold_bp).ok_or("P-02 out of range")?;
    let mut o = Object::new();
    o.insert("type", Value::String("Stage1Closed".to_owned()));
    o.insert("proposal", member_of(&t, "proposal")?);
    o.insert("recorder", member_of(&t, "coordinator")?);
    o.insert("score", ratio_json(score)?);
    o.insert("threshold", threshold.to_json());
    o.insert("counted", keys_json(counted)?);
    o.insert("passed", Value::Bool(passed));
    o.insert("rules", member_of(&t, "rules")?);
    decode(o)
}

/// An `EffectiveScoreSet` record with these fields, built through the
/// record decoder. Only runs on the reference alone and teeth faults use it.
pub fn forge_effective(
    proposal: ProposalId,
    effective: Effective,
    counted: &BTreeSet<ScoreKey>,
) -> Result<Record, String> {
    let t = template(proposal, AccountId::from_raw(0));
    let plan = member_of(
        &Record::RevisionSubmitted {
            proposal,
            plan: effective.plan,
        },
        "plan",
    )?;
    let basis = match effective.basis {
        Basis::Original => "Original",
        Basis::Revised => "Revised",
    };
    let mut o = Object::new();
    o.insert("type", Value::String("EffectiveScoreSet".to_owned()));
    o.insert("proposal", member_of(&t, "proposal")?);
    o.insert("plan", plan);
    o.insert("value", ratio_json(effective.value)?);
    o.insert("basis", Value::String(basis.to_owned()));
    o.insert("counted", keys_json(counted)?);
    o.insert("rules", member_of(&t, "rules")?);
    decode(o)
}

// ---------------------------------------------------------------------------
// Verdicts
// ---------------------------------------------------------------------------

/// The reference's view of one command.
#[derive(Clone, Copy, Debug)]
pub struct LifeAsk<'a> {
    /// The actor.
    pub actor: Actor,
    /// The command time.
    pub now: Timestamp,
    /// The command.
    pub cmd: &'a Command,
}

/// Everything a verdict reads.
#[derive(Clone, Copy)]
pub struct LifeCx<'a> {
    /// The L-SOD reference view.
    pub sod: &'a sod::View,
    /// The L-REV reference view.
    pub rev: &'a RevView,
    /// The lifecycle view.
    pub life: &'a LifeView,
    /// The vault facts.
    pub facts: &'a dyn LifeFacts,
}

fn refuse(why: impl Into<String>) -> LifeVerdict {
    LifeVerdict::Refuse(why.into())
}

fn account(ask: &LifeAsk<'_>) -> Option<AccountId> {
    match ask.actor {
        Actor::Account(a) => Some(a),
        Actor::System(_) => None,
    }
}

impl LifeCx<'_> {
    fn holds(&self, a: AccountId, role: Role, programme: ProgrammeId, now: Timestamp) -> bool {
        holds_active(self.sod, a, role, programme, now)
    }

    /// No conflict fact and no vault conflict for `a` on `p` (I-03).
    fn clear(&self, a: AccountId, p: ProposalId) -> bool {
        !self.life.facts.contains(&(a, p)) && !self.facts.has_conflict(a, &team_of(self.sod, p))
    }

    fn lead(&self, a: AccountId, p: ProposalId, now: Timestamp) -> bool {
        self.life.proposals.get(&p).is_some_and(|l| l.lead == a)
            && self.sod.bindings.values().any(|b| {
                b.account == a
                    && b.role == Role::Applicant
                    && b.proposal == Some(p)
                    && b.active()
                    && b.start <= now
            })
    }

    /// The assignee basis of a reviewer act through `assignment` of `kind`
    /// in the call of `stage` (I-03, design 2.7): the actor's active
    /// assignment, an active binding of its role, and no conflict.
    fn act_basis(
        &self,
        ask: &LifeAsk<'_>,
        assignment: AssignmentId,
        kind: AssignmentKind,
        call_of: impl Fn(&LifeProposal) -> CallId,
    ) -> Result<(AccountId, ProposalId), String> {
        let a = account(ask).ok_or("R-LA-03: a reviewer act needs a named account")?;
        let asg = self
            .life
            .assignments
            .get(&assignment)
            .ok_or("unknown assignment")?;
        let p = self
            .life
            .proposals
            .get(&asg.proposal)
            .ok_or("unknown proposal")?;
        let programme = self
            .life
            .programme_of(asg.proposal)
            .ok_or("unknown programme")?;
        if asg.reviewer != a || asg.kind != kind {
            return Err("I-03: the actor does not hold this assignment".to_owned());
        }
        if !asg.active() || asg.call != call_of(p) {
            return Err("I-03: the assignment is not active in this call".to_owned());
        }
        if !self.holds(a, kind.role(), programme, ask.now) {
            return Err("enforcement point 2: the assignee's binding is not active".to_owned());
        }
        if !self.clear(a, asg.proposal) {
            return Err("I-03: the assignee has a conflict on the proposal".to_owned());
        }
        Ok((a, asg.proposal))
    }

    fn coordinator(&self, ask: &LifeAsk<'_>, p: ProposalId) -> Result<AccountId, String> {
        let a = account(ask).ok_or("R-LA-03: the System records no decision")?;
        let programme = self.life.programme_of(p).ok_or("unknown proposal")?;
        if !self.holds(a, Role::FstpCoordinator, programme, ask.now) {
            return Err("the actor is not an active FSTP coordinator".to_owned());
        }
        Ok(a)
    }

    fn coordinator_cleared(&self, a: AccountId, p: ProposalId) -> Result<(), String> {
        if !self.life.cleared.contains(&(a, p)) {
            return Err("I-03: the coordinator has not declared on the proposal".to_owned());
        }
        if !self.clear(a, p) {
            return Err("I-03: the coordinator has a conflict on the proposal".to_owned());
        }
        Ok(())
    }
}

fn transition(
    proposal: ProposalId,
    from: StateTag,
    to: StateTag,
    row: Row,
    actor: Actor,
    decision: Option<DecisionId>,
) -> Transitioned {
    Transitioned {
        proposal,
        from,
        to,
        row,
        actor,
        decision,
    }
}

fn verdict_of(r: Result<Expect, String>) -> LifeVerdict {
    match r {
        Ok(e) => LifeVerdict::Accept(e),
        Err(why) => LifeVerdict::Refuse(why),
    }
}

/// The reference verdict on `ask`, or [`LifeVerdict::NotMine`] for a
/// command outside the lifecycle.
pub fn life_verdict(cx: &LifeCx<'_>, ask: &LifeAsk<'_>) -> LifeVerdict {
    match ask.cmd {
        Command::RecordKnockOut { .. } => verdict_of(knock_out(cx, ask)),
        Command::AdmitToStage1 { .. } => admit(cx, ask),
        Command::RecordScore { .. } | Command::CorrectScore { .. } => verdict_of(score(cx, ask)),
        Command::CloseStage1 { .. } => verdict_of(close(cx, ask)),
        Command::AskQuestion { .. }
        | Command::RecordNoQuestions { .. }
        | Command::AnswerQuestions { .. }
        | Command::SubmitRevision { .. } => verdict_of(stage2_act(cx, ask)),
        Command::RecordPlanVersion {
            origin: PlanOrigin::Stage2Revision,
            ..
        } => verdict_of(revision_plan(cx, ask)),
        Command::RankAfterStage2 { .. } => verdict_of(rank(cx, ask)),
        Command::ExpireStage2 { .. } => verdict_of(expire(cx, ask)),
        Command::ReEnter { .. } => verdict_of(reenter(cx, ask)),
        Command::RecordCutOff { .. } => verdict_of(cut_off(cx, ask)),
        Command::RecordIrcReview { .. } => irc_review(cx, ask),
        Command::DeclineAfterConcern { .. } => verdict_of(decline(cx, ask)),
        _ => LifeVerdict::NotMine,
    }
}

fn knock_out(cx: &LifeCx<'_>, ask: &LifeAsk<'_>) -> Result<Expect, String> {
    let Command::RecordKnockOut {
        decision,
        proposal,
        outcomes,
        reason,
    } = ask.cmd
    else {
        return Err("not a knock-out".to_owned());
    };
    let p = cx.life.proposals.get(proposal).ok_or("unknown proposal")?;
    let a = cx.coordinator(ask, *proposal)?;
    if p.state != StateTag::Submitted {
        return Err("the knock-out check needs SUBMITTED".to_owned());
    }
    if p.knock_out.is_some() {
        return Err("the knock-out check is already recorded".to_owned());
    }
    cx.coordinator_cleared(a, *proposal)?;
    if cx.life.decisions.contains(decision) {
        return Err("the decision id is taken".to_owned());
    }
    let policy = cx.life.governing(*proposal).ok_or("no governing policy")?;
    let named: BTreeSet<KnockOutCriterionId> = outcomes.iter().map(|o| o.criterion).collect();
    if named.len() != outcomes.len() || named != policy.p09 {
        return Err("R-EV-01: the outcomes must name each P-09 criterion exactly once".to_owned());
    }
    let failed = outcomes.iter().any(|o| !o.passed);
    if failed && reason.is_none() {
        return Err("a failed knock-out needs a recorded reason".to_owned());
    }
    let mut exp = Expect {
        wants: vec![Want::KnockOut {
            decision: *decision,
            proposal: *proposal,
            coordinator: a,
            outcomes: outcomes.clone(),
            reason: *reason,
        }],
        ..Expect::default()
    };
    if failed {
        exp.transitions.push(transition(
            *proposal,
            StateTag::Submitted,
            StateTag::Ineligible,
            Row::SubmittedToIneligible,
            ask.actor,
            Some(*decision),
        ));
        exp.terminal.push(*proposal);
    }
    Ok(exp)
}

fn admit(cx: &LifeCx<'_>, ask: &LifeAsk<'_>) -> LifeVerdict {
    let Command::AdmitToStage1 { decision, proposal } = ask.cmd else {
        return refuse("not an admission");
    };
    let Some(p) = cx.life.proposals.get(proposal) else {
        return refuse("unknown proposal");
    };
    let a = match cx.coordinator(ask, *proposal) {
        Ok(a) => a,
        Err(e) => return refuse(e),
    };
    if p.state != StateTag::Submitted {
        return refuse("admission needs SUBMITTED");
    }
    if p.knock_out != Some(true) {
        return refuse("R-EV-01: admission needs a passed knock-out check");
    }
    if let Err(e) = cx.coordinator_cleared(a, *proposal) {
        return refuse(e);
    }
    if cx.life.decisions.contains(decision) {
        return refuse("the decision id is taken");
    }
    let (Some(policy), Some(programme)) = (
        cx.life.governing(*proposal),
        cx.life.programme_of(*proposal),
    ) else {
        return refuse("no governing policy");
    };
    let active: Vec<AccountId> = cx
        .life
        .active_assignments(*proposal, p.current_call, AssignmentKind::Reviewer)
        .iter()
        .filter_map(|id| cx.life.assignments.get(id).map(|x| x.reviewer))
        .collect();
    if active.iter().any(|r| !cx.clear(*r, *proposal)) {
        return refuse("I-03, R-EV-02: an active assignee has a vault conflict");
    }
    if active.len() < usize::from(policy.p03) {
        return refuse("R-EV-02: fewer than P-03 active assignments without conflict");
    }
    let orgs: Vec<Option<_>> = active
        .iter()
        .map(|r| committee_organisation(cx.sod, cx.rev, *r, programme, ask.now))
        .collect();
    if orgs.iter().all(Option::is_some) {
        let distinct: BTreeSet<_> = orgs.iter().flatten().collect();
        if distinct.len() < usize::from(policy.p39) {
            return refuse("I-34: the active reviewers span fewer than P-39 organisations");
        }
        let lists = orgs
            .iter()
            .flatten()
            .any(|o| cx.rev.proximity_list(programme, *o).is_some());
        if lists {
            return LifeVerdict::Either(admitted(*proposal, ask.actor, *decision));
        }
    }
    LifeVerdict::Accept(admitted(*proposal, ask.actor, *decision))
}

fn admitted(proposal: ProposalId, actor: Actor, decision: DecisionId) -> Expect {
    Expect {
        transitions: vec![transition(
            proposal,
            StateTag::Submitted,
            StateTag::Stage1,
            Row::SubmittedToStage1,
            actor,
            Some(decision),
        )],
        ..Expect::default()
    }
}

fn score(cx: &LifeCx<'_>, ask: &LifeAsk<'_>) -> Result<Expect, String> {
    let (key, values, correction) = match ask.cmd {
        Command::RecordScore { key, values } => (*key, values, None),
        Command::CorrectScore {
            key,
            values,
            reason,
        } => (*key, values, Some(*reason)),
        _ => return Err("not a score".to_owned()),
    };
    let stage = key.stage;
    let (_, proposal) = cx.act_basis(
        ask,
        key.assignment,
        AssignmentKind::Reviewer,
        |p| match stage {
            Stage::One => p.created_call,
            Stage::Two => p.current_call,
        },
    )?;
    let p = cx.life.proposals.get(&proposal).ok_or("unknown proposal")?;
    match stage {
        Stage::One => {
            if p.state != StateTag::Stage1 {
                return Err("NOTE 3: stage 1 scores need STAGE1, and seal at exit".to_owned());
            }
            if p.submitted != Some(key.plan) {
                return Err("stage 1 scores the submitted plan".to_owned());
            }
        }
        Stage::Two => {
            if p.state != StateTag::Stage2 {
                return Err("NOTE 4: stage 2 scores need STAGE2, and seal at exit".to_owned());
            }
            if !p.revisions.contains(&key.plan) {
                return Err("NOTE 4: stage 2 scores a submitted revision".to_owned());
            }
        }
    }
    let policy = cx.life.governing(proposal).ok_or("no governing policy")?;
    if values.0.len() != policy.weights.len() || values.0.iter().any(|v| *v > policy.scale_max) {
        return Err("NOTE 6: one value from 0 to N per P-01 criterion".to_owned());
    }
    let current = cx.life.scores.contains_key(&key);
    if correction.is_none() && current {
        return Err("the key has a value: a change is a correction".to_owned());
    }
    if correction.is_some() && !current {
        return Err("a correction needs a current value".to_owned());
    }
    Ok(Expect {
        wants: vec![Want::Score {
            key,
            values: values.0.clone(),
            correction,
        }],
        ..Expect::default()
    })
}

fn close(cx: &LifeCx<'_>, ask: &LifeAsk<'_>) -> Result<Expect, String> {
    let Command::CloseStage1 { proposal } = ask.cmd else {
        return Err("not a close".to_owned());
    };
    let p = cx.life.proposals.get(proposal).ok_or("unknown proposal")?;
    let a = cx.coordinator(ask, *proposal)?;
    if p.state != StateTag::Stage1 {
        return Err("the close needs STAGE1".to_owned());
    }
    let facts = cx
        .life
        .stage_one_facts(*proposal, StateTag::Stage2)
        .ok_or("no stage 1 facts")?;
    if !facts.all_active_scored {
        return Err("NOTE 3: an active assigned reviewer has no valid score".to_owned());
    }
    if facts.reviewers < usize::from(facts.p03) {
        return Err("I-07: fewer than P-03 valid scores".to_owned());
    }
    let (Some(score), Some(passed)) = (facts.score, facts.passed) else {
        return Err("no score".to_owned());
    };
    let (to, row) = if passed {
        (StateTag::Stage2, Row::Stage1ToStage2)
    } else {
        (StateTag::NotSelected, Row::Stage1ToNotSelected)
    };
    Ok(Expect {
        wants: vec![Want::Stage1Closed {
            proposal: *proposal,
            recorder: a,
            score,
            threshold_bp: facts.p02_bp,
            counted: facts.valid.clone(),
            passed,
        }],
        transitions: vec![transition(
            *proposal,
            StateTag::Stage1,
            to,
            row,
            ask.actor,
            None,
        )],
        terminal: if passed { Vec::new() } else { vec![*proposal] },
    })
}

/// The effective score record and the STAGE2 to RANKED transition, as the
/// reference expects them now.
fn ranked(
    cx: &LifeCx<'_>,
    proposal: ProposalId,
    actor: Actor,
    extra: Vec<Want>,
) -> Result<Expect, String> {
    let effective = cx
        .life
        .effective_now(proposal)
        .ok_or("no effective score can be computed")?;
    let p = cx.life.proposals.get(&proposal).ok_or("unknown proposal")?;
    let counted = match effective.basis {
        Basis::Original => p.exit.as_ref().map(|e| e.valid.clone()).unwrap_or_default(),
        Basis::Revised => cx.life.valid_keys(proposal, Stage::Two, effective.plan),
    };
    let mut wants = extra;
    wants.push(Want::Effective {
        proposal,
        effective,
        counted,
    });
    Ok(Expect {
        wants,
        transitions: vec![transition(
            proposal,
            StateTag::Stage2,
            StateTag::Ranked,
            Row::Stage2ToRanked,
            actor,
            None,
        )],
        terminal: Vec::new(),
    })
}

fn open_round<'a>(
    cx: &LifeCx<'a>,
    proposal: ProposalId,
    now: Timestamp,
) -> Result<&'a Round, String> {
    let p = cx.life.proposals.get(&proposal).ok_or("unknown proposal")?;
    if p.state != StateTag::Stage2 {
        return Err("NOTE 4: the act needs STAGE2".to_owned());
    }
    let round = p.round.as_ref().ok_or("no stage 2 round")?;
    let end = cx.life.window_end(proposal).ok_or("no window")?;
    if now >= end {
        return Err("R-EV-07: the P-07 window has elapsed".to_owned());
    }
    Ok(round)
}

fn stage2_act(cx: &LifeCx<'_>, ask: &LifeAsk<'_>) -> Result<Expect, String> {
    let current = |p: &LifeProposal| p.current_call;
    match ask.cmd {
        Command::AskQuestion {
            proposal,
            assignment,
            text,
        } => {
            let (_, p) = cx.act_basis(ask, *assignment, AssignmentKind::Reviewer, current)?;
            if p != *proposal {
                return Err("the assignment is on another proposal".to_owned());
            }
            let round = open_round(cx, p, ask.now)?;
            if round.no_questions.contains(assignment) {
                return Err("NOTE 4: the reviewer recorded \"no questions\"".to_owned());
            }
            Ok(Expect {
                wants: vec![Want::Exact(Record::QuestionAsked {
                    proposal: p,
                    assignment: *assignment,
                    text: *text,
                })],
                ..Expect::default()
            })
        }
        Command::RecordNoQuestions {
            proposal,
            assignment,
        } => {
            let (_, p) = cx.act_basis(ask, *assignment, AssignmentKind::Reviewer, current)?;
            if p != *proposal {
                return Err("the assignment is on another proposal".to_owned());
            }
            let round = open_round(cx, p, ask.now)?;
            if round.no_questions.contains(assignment) || round.questions.contains(assignment) {
                return Err("NOTE 4: the reviewer already asked or recorded".to_owned());
            }
            let record = Want::Exact(Record::NoQuestionsRecorded {
                proposal: p,
                assignment: *assignment,
            });
            let call = cx.life.stage_call(p, Stage::Two).ok_or("no call")?;
            let active = cx
                .life
                .active_assignments(p, call, AssignmentKind::Reviewer);
            let mut recorded = round.no_questions.clone();
            recorded.insert(*assignment);
            if active.is_subset(&recorded) {
                ranked(cx, p, ask.actor, vec![record])
            } else {
                Ok(Expect {
                    wants: vec![record],
                    ..Expect::default()
                })
            }
        }
        Command::AnswerQuestions { proposal, text } => {
            let a = account(ask).ok_or("answers come from the lead")?;
            if !cx.lead(a, *proposal, ask.now) {
                return Err(
                    "answers come from the lead with an active Applicant binding".to_owned(),
                );
            }
            let round = open_round(cx, *proposal, ask.now)?;
            if round.questions.is_empty() {
                return Err("NOTE 4: no question to answer".to_owned());
            }
            Ok(Expect {
                wants: vec![Want::Exact(Record::AnswersRecorded {
                    proposal: *proposal,
                    text: *text,
                })],
                ..Expect::default()
            })
        }
        Command::SubmitRevision { proposal, plan } => {
            let a = account(ask).ok_or("a revision comes from the lead")?;
            if !cx.lead(a, *proposal, ask.now) {
                return Err(
                    "a revision comes from the lead with an active Applicant binding".to_owned(),
                );
            }
            open_round(cx, *proposal, ask.now)?;
            let p = cx.life.proposals.get(proposal).ok_or("unknown proposal")?;
            let ok = p
                .plans
                .get(plan)
                .is_some_and(|pl| pl.origin == PlanOrigin::Stage2Revision && !pl.superseded)
                && !p.revisions.contains(plan);
            if !ok {
                return Err(
                    "R-EV-05: the plan is not a live, unsubmitted stage 2 revision".to_owned(),
                );
            }
            Ok(Expect {
                wants: vec![Want::Exact(Record::RevisionSubmitted {
                    proposal: *proposal,
                    plan: *plan,
                })],
                ..Expect::default()
            })
        }
        _ => Err("not a stage 2 act".to_owned()),
    }
}

fn revision_plan(cx: &LifeCx<'_>, ask: &LifeAsk<'_>) -> Result<Expect, String> {
    let Command::RecordPlanVersion {
        plan,
        proposal,
        origin,
        supersedes,
        tasks,
        content,
    } = ask.cmd
    else {
        return Err("not a plan".to_owned());
    };
    let a = account(ask).ok_or("a plan comes from the lead")?;
    if !cx.lead(a, *proposal, ask.now) {
        return Err("a plan comes from the lead with an active Applicant binding".to_owned());
    }
    open_round(cx, *proposal, ask.now)?;
    let p = cx.life.proposals.get(proposal).ok_or("unknown proposal")?;
    if cx.life.plan_ids.contains(plan) {
        return Err("the plan id is taken".to_owned());
    }
    let live = p
        .plans
        .iter()
        .find(|(_, pl)| !pl.superseded)
        .map(|(id, _)| *id);
    if *supersedes != live {
        return Err("a new plan supersedes the live plan".to_owned());
    }
    let mut seen = BTreeSet::new();
    let currency_ok = |m: &fstp_domain::proposal::Milestone| {
        m.amount.amount().currency() == Currency::Eur && m.start <= m.due
    };
    if tasks.is_empty() || tasks.iter().any(|t| t.milestones.is_empty()) {
        return Err("required fields: a task, each with a milestone".to_owned());
    }
    for m in tasks.iter().flat_map(|t| t.milestones.iter()) {
        if cx.life.milestones.contains(&m.id) || !seen.insert(m.id) || !currency_ok(m) {
            return Err("a milestone id is taken, or its dates or currency are wrong".to_owned());
        }
    }
    if total_of(tasks).is_none() {
        return Err("the plan total leaves the money range".to_owned());
    }
    Ok(Expect {
        wants: vec![Want::Exact(Record::PlanVersionRecorded(
            PlanVersionRecorded {
                plan: *plan,
                proposal: *proposal,
                origin: *origin,
                supersedes: *supersedes,
                tasks: tasks.clone(),
                content: *content,
            },
        ))],
        ..Expect::default()
    })
}

fn rank(cx: &LifeCx<'_>, ask: &LifeAsk<'_>) -> Result<Expect, String> {
    let Command::RankAfterStage2 { proposal } = ask.cmd else {
        return Err("not a ranking".to_owned());
    };
    let p = cx.life.proposals.get(proposal).ok_or("unknown proposal")?;
    if p.state != StateTag::Stage2 {
        return Err("ranking needs STAGE2".to_owned());
    }
    let a = account(ask).ok_or("ranking is recorded by an assigned reviewer")?;
    let mine = cx
        .life
        .active_assignments(*proposal, p.current_call, AssignmentKind::Reviewer)
        .into_iter()
        .filter(|id| cx.life.assignments.get(id).is_some_and(|x| x.reviewer == a))
        .collect::<Vec<_>>();
    let Some(asg) = mine.first() else {
        return Err("ranking is recorded by an assigned reviewer".to_owned());
    };
    cx.act_basis(ask, *asg, AssignmentKind::Reviewer, |q| q.current_call)?;
    let round = p.round.as_ref().ok_or("no stage 2 round")?;
    let end = cx.life.window_end(*proposal).ok_or("no window")?;
    let scored = cx.life.latest_scored_revision(*proposal).is_some();
    let closed_with_answers = ask.now >= end && round.answered;
    let no_questions = cx.life.no_questions_complete(*proposal);
    if !scored && !closed_with_answers && !no_questions {
        return Err(
            "NOTE 4: no revised plan scored by P-03 reviewers, no window closed with answers, \
             and not every active reviewer recorded \"no questions\""
                .to_owned(),
        );
    }
    ranked(cx, *proposal, ask.actor, Vec::new())
}

fn expire(cx: &LifeCx<'_>, ask: &LifeAsk<'_>) -> Result<Expect, String> {
    let Command::ExpireStage2 { proposal } = ask.cmd else {
        return Err("not an expiry".to_owned());
    };
    if account(ask).is_some() {
        return Err("NOTE 13: the System records the expiry".to_owned());
    }
    let p = cx.life.proposals.get(proposal).ok_or("unknown proposal")?;
    if p.state != StateTag::Stage2 {
        return Err("the expiry needs STAGE2".to_owned());
    }
    let round = p.round.as_ref().ok_or("no stage 2 round")?;
    let end = cx.life.window_end(*proposal).ok_or("no window")?;
    if ask.now < end {
        return Err("R-EV-07: P-07 has not elapsed".to_owned());
    }
    if round.answered {
        return Err("R-EV-07: the applicant answered".to_owned());
    }
    if cx.life.no_questions_complete(*proposal) {
        return Err("NOTE 4, O-50: every active reviewer recorded \"no questions\"".to_owned());
    }
    if cx.life.latest_scored_revision(*proposal).is_some() {
        return Err("NOTE 4: a revised plan has P-03 valid stage 2 scores".to_owned());
    }
    Ok(Expect {
        wants: vec![Want::Exact(Record::DeferralRecorded {
            proposal: *proposal,
            from_call: p.current_call,
            left: ReentryStage::Stage2,
        })],
        transitions: vec![transition(
            *proposal,
            StateTag::Stage2,
            StateTag::Deferred,
            Row::Stage2ToDeferred,
            ask.actor,
            None,
        )],
        terminal: Vec::new(),
    })
}

fn reenter(cx: &LifeCx<'_>, ask: &LifeAsk<'_>) -> Result<Expect, String> {
    let Command::ReEnter { proposal, call } = ask.cmd else {
        return Err("not a re-entry".to_owned());
    };
    if account(ask).is_some() {
        return Err("NOTE 13: the System records the re-entry".to_owned());
    }
    let p = cx.life.proposals.get(proposal).ok_or("unknown proposal")?;
    if p.state != StateTag::Deferred {
        return Err("re-entry needs DEFERRED".to_owned());
    }
    let (from, left) = p.deferral.ok_or("no deferral")?;
    if cx.life.next_call_after(from) != Some(*call) {
        return Err("NOTE 8: re-entry is into the next published call".to_owned());
    }
    let opens = cx.life.calls.get(call).map(|c| c.opens).ok_or("no call")?;
    if ask.now < opens {
        return Err("NOTE 8: the next call has not opened".to_owned());
    }
    let former_reviewer_receiving = cx.sod.bindings.values().any(|b| {
        b.held()
            && b.group == sod::RefGroup::Receiving
            && b.call == Some(*call)
            && cx.rev.reviewed.contains(&(b.account, *proposal))
    });
    if former_reviewer_receiving {
        return Err(
            "I-36: a former reviewer of the proposal holds a Receiving binding in the new call"
                .to_owned(),
        );
    }
    let (to, row) = match left {
        ReentryStage::Stage2 => (StateTag::Stage2, Row::DeferredToStage2),
        ReentryStage::IrcReview => (StateTag::IrcReview, Row::DeferredToIrcReview),
    };
    Ok(Expect {
        wants: vec![Want::Exact(Record::ReEntered {
            proposal: *proposal,
            from_call: from,
            to_call: *call,
            stage: left,
        })],
        transitions: vec![transition(
            *proposal,
            StateTag::Deferred,
            to,
            row,
            ask.actor,
            None,
        )],
        terminal: Vec::new(),
    })
}

fn cut_off(cx: &LifeCx<'_>, ask: &LifeAsk<'_>) -> Result<Expect, String> {
    let Command::RecordCutOff {
        decision,
        call,
        order,
        nominated,
        rationale,
        tie_breaks,
        ballots,
    } = ask.cmd
    else {
        return Err("not a cut-off".to_owned());
    };
    let a = account(ask).ok_or("R-LA-03: a committee member records the cut-off")?;
    let c = cx.life.calls.get(call).ok_or("unknown call")?;
    if c.seq.is_none() {
        return Err("the call is not published".to_owned());
    }
    let members = committee(cx.sod, c.programme, ask.now);
    let facts: &dyn ConflictFacts = cx.facts;
    let recused_set: BTreeSet<AccountId> = members
        .iter()
        .copied()
        .filter(|m| recused(cx.sod, cx.rev, facts, *m, *call))
        .collect();
    if !members.contains(&a) || recused_set.contains(&a) {
        return Err("the recorder is not a committee member who may vote".to_owned());
    }
    if cx.life.decisions.contains(decision) {
        return Err("the decision id is taken".to_owned());
    }
    let ranked_now: BTreeSet<ProposalId> = cx
        .life
        .proposals
        .iter()
        .filter(|(_, p)| p.state == StateTag::Ranked && p.current_call == *call)
        .map(|(id, _)| *id)
        .collect();
    let listed: BTreeSet<ProposalId> = order.iter().copied().collect();
    if order.is_empty() || listed.len() != order.len() || listed != ranked_now {
        return Err("NOTE 6: the order lists exactly the call's RANKED proposals".to_owned());
    }
    let n = usize::try_from(*nominated).map_err(|_| "nominated too large")?;
    if n > order.len() {
        return Err("NOTE 6: the cut-off lies beyond the order".to_owned());
    }
    let mut values = Vec::new();
    for p in order {
        let v = cx
            .life
            .proposals
            .get(p)
            .and_then(|x| x.effective.last())
            .map(|e| e.value)
            .ok_or("a ranked proposal has no effective score")?;
        values.push(v);
    }
    if values
        .windows(2)
        .any(|w| matches!(w, [x, y] if x.compare(*y) == Some(Ordering::Less)))
    {
        return Err("NOTE 6: the order is not by effective score".to_owned());
    }
    let tie = n > 0
        && n < values.len()
        && matches!(
            (values.get(n.saturating_sub(1)), values.get(n)),
            (Some(x), Some(y)) if x.same(*y)
        );
    if tie && tie_breaks.is_none() {
        return Err("R-EV-08: a tie at the cut-off needs a recorded P-17 tie-break".to_owned());
    }
    let chairs = holders(cx.sod, Role::CommitteeChair, c.programme, ask.now);
    if !p16_outcome(&members, &recused_set, &chairs, ballots)? {
        return Err("P-16: the cut-off is not adopted".to_owned());
    }
    let remaining = cx
        .life
        .remaining_budget(*call)
        .ok_or("no remaining budget")?;
    let mut exp = Expect {
        wants: vec![Want::CutOff(Box::new(CutOffRecorded {
            decision: *decision,
            call: *call,
            order: order.clone(),
            nominated: *nominated,
            rationale: *rationale,
            tie_breaks: *tie_breaks,
            ballots: ballots.clone(),
            recused: recused_set,
            remaining_budget: remaining,
            recorder: a,
            rules: RulesVersion::M2,
        }))],
        ..Expect::default()
    };
    for (i, p) in order.iter().enumerate() {
        let (to, row) = if i < n {
            (StateTag::IrcReview, Row::RankedToIrcReview)
        } else {
            exp.terminal.push(*p);
            (StateTag::NotSelected, Row::RankedToNotSelected)
        };
        exp.transitions.push(transition(
            *p,
            StateTag::Ranked,
            to,
            row,
            ask.actor,
            Some(*decision),
        ));
    }
    Ok(exp)
}

fn irc_review(cx: &LifeCx<'_>, ask: &LifeAsk<'_>) -> LifeVerdict {
    let Command::RecordIrcReview {
        assignment,
        verdict,
    } = ask.cmd
    else {
        return refuse("not an IRC review");
    };
    let (_, proposal) =
        match cx.act_basis(ask, *assignment, AssignmentKind::Irc, |p| p.current_call) {
            Ok(x) => x,
            Err(e) => return refuse(e),
        };
    let Some(p) = cx.life.proposals.get(&proposal) else {
        return refuse("unknown proposal");
    };
    if p.state != StateTag::IrcReview {
        return refuse("an IRC review needs IRC_REVIEW");
    }
    if p.concern.is_some() {
        return refuse("R-IR-01: a concern is raised in this round");
    }
    // A validated IRC member may repeat the validation to complete the
    // review once its condition holds, for example after a vault release
    // or a guardian consent (R-IR-01, R-LA-03, I-18). Any other repeat is
    // refused.
    let rerun = match (p.irc.get(assignment), verdict) {
        (None, _) => false,
        (Some(true), IrcVerdict::Validate) => true,
        (Some(_), _) => return refuse("R-IR-01: the review is recorded"),
    };
    let Some(policy) = cx.life.governing(proposal) else {
        return refuse("no governing policy");
    };
    let review = Want::Exact(Record::IrcReviewRecorded {
        assignment: *assignment,
        verdict: *verdict,
    });
    match verdict {
        IrcVerdict::Validate => {
            let active = cx
                .life
                .active_assignments(proposal, p.current_call, AssignmentKind::Irc);
            let mut validated: BTreeSet<AssignmentId> = p
                .irc
                .iter()
                .filter(|(_, ok)| **ok)
                .map(|(id, _)| *id)
                .collect();
            validated.insert(*assignment);
            let awaiting =
                cx.life
                    .awaiting_declaration(proposal, p.current_call, AssignmentKind::Irc);
            let complete = active.len() >= usize::from(policy.p15)
                && active.is_subset(&validated)
                && awaiting.is_empty();
            if !complete && rerun {
                return refuse("R-IR-01: a repeated validation only completes the review");
            }
            if !complete {
                return LifeVerdict::Accept(Expect {
                    wants: vec![review],
                    ..Expect::default()
                });
            }
            let wants = if rerun { Vec::new() } else { vec![review] };
            if p.minor && !cx.facts.has_consent(proposal) {
                if rerun {
                    return refuse("I-18: no verified guardian consent");
                }
                return LifeVerdict::Either(Expect {
                    wants,
                    ..Expect::default()
                });
            }
            LifeVerdict::Accept(Expect {
                wants,
                transitions: vec![transition(
                    proposal,
                    StateTag::IrcReview,
                    StateTag::Negotiation,
                    Row::IrcReviewToNegotiation,
                    ask.actor,
                    None,
                )],
                terminal: Vec::new(),
            })
        }
        IrcVerdict::Concern(t) => {
            let outbox = Want::Exact(Record::OutboxEnqueued(OutboxEvent::IrcConcern {
                proposal,
                concern: *t,
            }));
            if cx.life.later_call_published(p.current_call) {
                LifeVerdict::Accept(Expect {
                    wants: vec![
                        review,
                        outbox,
                        Want::Exact(Record::DeferralRecorded {
                            proposal,
                            from_call: p.current_call,
                            left: ReentryStage::IrcReview,
                        }),
                    ],
                    transitions: vec![transition(
                        proposal,
                        StateTag::IrcReview,
                        StateTag::Deferred,
                        Row::IrcReviewToDeferred,
                        ask.actor,
                        None,
                    )],
                    terminal: Vec::new(),
                })
            } else {
                LifeVerdict::Accept(Expect {
                    wants: vec![review, outbox],
                    ..Expect::default()
                })
            }
        }
    }
}

fn decline(cx: &LifeCx<'_>, ask: &LifeAsk<'_>) -> Result<Expect, String> {
    let Command::DeclineAfterConcern { proposal } = ask.cmd else {
        return Err("not a decline".to_owned());
    };
    let p = cx.life.proposals.get(proposal).ok_or("unknown proposal")?;
    let programme = cx.life.programme_of(*proposal).ok_or("unknown programme")?;
    let named = account(ask);
    if let Some(a) = named
        && !cx.holds(a, Role::ProgrammeManager, programme, ask.now)
    {
        return Err("NOTE 13: the programme manager records the decline".to_owned());
    }
    if p.state != StateTag::IrcReview || p.concern.is_none() {
        return Err("the decline needs IRC_REVIEW with a concern".to_owned());
    }
    let later = cx.life.later_call_published(p.current_call);
    if named.is_none() {
        // NOTE 7: once a later call is published, the concern defers the
        // proposal. The outcome is computed, so the System records it.
        if !later {
            return Err("NOTE 13: the programme manager records the decline".to_owned());
        }
        return Ok(Expect {
            wants: vec![Want::Exact(Record::DeferralRecorded {
                proposal: *proposal,
                from_call: p.current_call,
                left: ReentryStage::IrcReview,
            })],
            transitions: vec![transition(
                *proposal,
                StateTag::IrcReview,
                StateTag::Deferred,
                Row::IrcReviewToDeferred,
                ask.actor,
                None,
            )],
            terminal: Vec::new(),
        });
    }
    if later {
        return Err("NOTE 7: a future call exists".to_owned());
    }
    Ok(Expect {
        transitions: vec![transition(
            *proposal,
            StateTag::IrcReview,
            StateTag::Declined,
            Row::IrcReviewToDeclined,
            ask.actor,
            None,
        )],
        terminal: vec![*proposal],
        ..Expect::default()
    })
}
