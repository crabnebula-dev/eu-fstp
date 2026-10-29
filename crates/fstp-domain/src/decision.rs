//! Decisions and decision records (design section 2.10).
//!
//! Owned by lane L-LIFE (docs/handoff/m2-design.md section 10). Step W1c
//! declared the vocabulary the interface names, and the two record
//! payloads that only a witness may build. Their fields are private. Lane
//! L-LIFE added their builders in step W4b, which take the `Stage1Verdict`
//! and `EffectiveScore` witnesses (design section 3.5), and the decision
//! commands of the lifecycle:
//!
//! - `RecordKnockOut` (row 2): the FSTP coordinator, after a no-conflict
//!   declaration on the proposal that the vault confirms (I-03), records
//!   one outcome per P-09 criterion once. A failed criterion needs a reason
//!   and makes the proposal INELIGIBLE, which is terminal (R-EV-01).
//! - `AdmitToStage1` (row 3): the coordinator, under the same I-03
//!   condition, after a passed knock-out check. It needs at least P-03
//!   active reviewer assignments, and every active assignee free of
//!   conflict, so stage 1 can close later (R-EV-02, I-03). They span at
//!   least P-39 organisations (I-34), and an unknown organisation fails
//!   the check. They are clear of the P-38 proximity lists (I-35).
//! - `CloseStage1` (rows 4 and 5): the FSTP coordinator records it and
//!   cannot choose its outcome (R-LA-03, NOTE 3, NOTE 13). The close needs
//!   the I-07 quorum with every active assignee scored, and passes strictly
//!   above P-02 (I-08). The active assignees still span P-39 organisations
//!   (I-34), since a release after admission can lower the count.
//! - `RankAfterStage2` (row 6): an assigned reviewer, once a revision has
//!   at least P-03 valid stage 2 scores, the window closed with answers,
//!   or every active assigned reviewer recorded "no questions" (NOTE 4,
//!   O-50). The last case also covers a round whose last outstanding
//!   assignee was released. The effective score follows P-24 and names one
//!   plan (I-09). The last "no questions" of a round ranks through
//!   [`ranking_records`] too. Both need the active assignees to span P-39
//!   organisations (I-34). Otherwise the last "no questions" is recorded
//!   alone, and a reassignment completes the round.
//! - The cut-off round (rows 8 and 9, M4 change D5, Q4 A interim reading,
//!   pending Daniel). A committee member or chair who is not recused
//!   opens a round with `OpenCutOffRound`: a rank position over the call's
//!   RANKED proposals, the rationale and any P-17 tie-break. One round is
//!   open per call. Each member who is not recused casts their own ballot
//!   with `CastBallot`, or delegates their own vote with `DelegateVote`.
//!   No command names another member's vote (R-EV-09). A member who is
//!   not recused then records the cut-off with `RecordCutOff`, which
//!   counts only the ballots cast under P-16 (NOTE 8). The record names
//!   the round as its decision, the recused members and the remaining
//!   budget (NOTE 6, R-EV-08). A round whose order stops matching the
//!   call's RANKED proposals, after a withdrawal or a new ranking, is
//!   stale: nothing more acts in it, and a new round supersedes it. A
//!   round whose vote has failed is superseded the same way (interim,
//!   pending Daniel). Its vote has failed when the cut-off would not be
//!   adopted even if every member who may vote and has not yet voted
//!   cast For. That is asked with the recusal answers of every member,
//!   so the new round's opening records them.
//! - `RecordIrcReview` (rows 10 and 11): an IRC assignee validates or
//!   raises a concern (R-IR-01, R-IR-02, NOTE 7, I-18). A validated IRC
//!   member may repeat the validation once the review would complete, and
//!   the repeat records only the entry into NEGOTIATION.
//! - `RecordIrcReview` on an amendment assignment (R-IR-04, step W5
//!   integration): the assignee validates or raises a concern on an
//!   amendment under IRC review (`crate::amendment`). The batch holds the
//!   review only, with no transition, deferral or outbox event (Q18).
//! - A batch of a named human in another lane that releases the last IRC
//!   assignment not yet validated completes the IRC review through
//!   [`contribute`] (R-IR-01). A release by the System does not, since the
//!   entry is a decision (R-LA-03, NOTE 13).
//!
//! Every transition records `Transitioned` with its row, the command's
//! actor and its decision id, which is `None` for a computed outcome
//! (R-AU-01). Each vault answer used is recorded as a `VaultOutcome`.
//!
//! Readings of this lane, reported to Daniel:
//!
//! - The cut-off order is non-increasing in effective score. A tie across
//!   the rank position needs a recorded P-17 tie-break, and the vault's
//!   P-17 country answer for the tied leads is recorded with it.
//! - Abstentions are not votes cast, and the chair's casting vote is the
//!   chair's own direct vote.
//! - The remaining budget is the one the ranking view shows before the
//!   round (`crate::visibility::ranking_view`): the requested totals of the
//!   call's proposals in IRC_REVIEW, NEGOTIATION and later states, with
//!   TERMINATED included (design 3.7, Q14).
//! - The minor flag at the NEGOTIATION gate is derived from the vault and
//!   never from the actor (R-ID-04, state-machine NOTE 14). A validation
//!   that would complete the review asks whether the lead has an effective
//!   verified over-18 attestation at the deadline of the call in which the
//!   proposal passes IRC review, its current call. For a proposal that
//!   re-entered under a later call (NOTE 8) that is the later call
//!   (ADR-008, "Which deadline", decided 2026-10-29). It also asks
//!   whether the proposal has a verified guardian consent. With neither,
//!   the proposal is minor-flagged. The validation is recorded and the
//!   proposal stays in IRC_REVIEW until the consent is effective (I-18,
//!   R-NG-01, R-NG-02). A validated member then repeats the validation to
//!   record the entry, and the repeat is refused before that. A missing
//!   answer refuses the validation (overview NOTE 2).
//! - [`awaiting_guardian_consent`] tells the cell when consent collection
//!   is open, so it can issue the guardian's write ticket (R-NG-01, design
//!   6.6 step 3). [`awaiting_guardian_consent_in_negotiation`] does the
//!   same in NEGOTIATION, where the guard into GRANTED derives the flag
//!   again (ADR-008 "Second derivation", decided 2026-10-29).
//! - Open point for Daniel, next to the GRANTED re-derivation: the batch of
//!   the last validation holds `VaultOutcome` records for the attestation
//!   and the consent. The cell must never show them to the IRC actor
//!   (R-NG-01, overview NOTE 7). The gate outcome itself still lets the
//!   last validating IRC member infer the attestation bit. NOTE 14 sets
//!   that outcome, so this module does not hide it.
//! - An IRC assignment still awaiting its declaration is outstanding, so
//!   it keeps the IRC review open (design 3.2, "none outstanding").

use std::collections::{BTreeMap, BTreeSet};

use fstp_money::{Amount, Percent, Ratio};

use crate::assignment::{
    AssignmentKind, cleared_act, committee_organisation, conflict_query, cut_off_recusal_queries,
    qualifying_assignment, recused_from_cut_off, reviewer_act,
};
use crate::command::{Actor, Command, Ctx};
use crate::engine::FoldError;
use crate::id::{
    AccountId, AmendmentId, AssignmentId, CallId, DecisionId, PlanVersionId, ProgrammeId,
    ProposalId, TextRef,
};
use crate::oracle::{Answer, Answers, Query};
use crate::policy::FrozenPolicy;
use crate::proposal::ReentryStage;
use crate::proposal::life::{self, unknown};
use crate::record::{CutOffRecorded, OutboxEvent, Record, RulesVersion, Transitioned};
use crate::refusal::{Refusal, RefusalReason, RuleRef};
use crate::roles::Role;
use crate::rules::{ParamId, Row, StateTag};
use crate::scoring::{
    EffectiveScore, ScoreKey, Stage, Stage1Verdict, effective_score_of_revisions, establish_quorum,
    judge_stage1, weighted_score,
};
use crate::state::{State, UsedId};
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

/// The effective score the projection holds for `proposal`, once set. It
/// names exactly one plan and is never cleared, in every later state and
/// across deferral and re-entry (I-09). Later lanes read it, so the models
/// compare it with the reference after every step.
pub fn effective_score(state: &State, proposal: ProposalId) -> Option<&EffectiveScoreSet> {
    life::facts(state, proposal).and_then(|f| f.effective.as_ref())
}

/// Whether guardian consent collection is open for `proposal` (R-NG-01,
/// guardian exception; design section 6.6 step 3).
///
/// It holds while the proposal is in IRC_REVIEW, every reviewing IRC member
/// has validated it, and it is minor-flagged (R-ID-04). The cell reads it
/// to issue the guardian's write ticket. The domain learns the lead's
/// attestation only from the gate's vault answer. So before a gate has
/// asked, for example after a release completed the review, this read
/// counts the proposal as minor-flagged. The cell then asks the vault
/// `IsVerifiedAdultAtDeadline` before it issues the ticket. Neither this
/// read nor that answer is shown to a Judging role (R-NG-01, overview
/// NOTE 7).
pub fn awaiting_guardian_consent(state: &State, proposal: ProposalId) -> bool {
    crate::proposal::draft::minor_flagged(state, proposal)
        && irc_completes(state, proposal, None, &BTreeSet::new())
}

/// Whether guardian consent collection may be needed for `proposal` in
/// NEGOTIATION (ADR-008 "Second derivation", decided 2026-10-29).
///
/// It holds while the proposal is in NEGOTIATION. The guard into GRANTED
/// derives the minor flag again, so a lead the vault no longer shows 18 or
/// older needs a verified guardian consent first. The domain cannot know
/// the vault's answer before it asks. So the cell asks
/// [`minor_flag_query`] before it issues the guardian's write ticket, and
/// issues it only on a no, as it does after the IRC review. Reading for
/// Daniel to confirm, together with `AddGuardian` in NEGOTIATION.
pub fn awaiting_guardian_consent_in_negotiation(state: &State, proposal: ProposalId) -> bool {
    crate::proposal::intake::proposal_state(state, proposal) == Some(StateTag::Negotiation)
}

/// The question that derives the minor flag of `proposal` (R-ID-04,
/// state-machine NOTE 14): `IsVerifiedAdultAtDeadline` for its lead at the
/// deadline of the call in which it passes IRC review. Both gates ask it,
/// and the cell asks it before it issues a guardian's write ticket. `None`
/// for an unknown proposal.
pub fn minor_flag_query(state: &State, proposal: ProposalId) -> Option<Query> {
    crate::proposal::draft::adult_query(state, proposal)
}

// ---------------------------------------------------------------------------
// Builders from the witnesses (design section 3.5)
// ---------------------------------------------------------------------------

impl Stage1Closed {
    /// The stage 1 exit record of `verdict`, recorded by `recorder`. The
    /// outcome is the verdict's, so no caller can choose it (I-08, R-LA-03).
    pub(crate) fn from_verdict(verdict: &Stage1Verdict, recorder: AccountId) -> Stage1Closed {
        Stage1Closed {
            proposal: verdict.quorum().proposal(),
            recorder,
            score: verdict.score(),
            threshold: verdict.threshold(),
            counted: verdict.quorum().keys().clone(),
            passed: verdict.passed(),
            rules: RulesVersion::M2,
        }
    }
}

impl EffectiveScoreSet {
    /// The effective score record of `effective` for `proposal`, with the
    /// keys behind its value (I-09).
    pub(crate) fn from_effective(
        proposal: ProposalId,
        effective: EffectiveScore,
        counted: BTreeSet<ScoreKey>,
    ) -> EffectiveScoreSet {
        EffectiveScoreSet {
            proposal,
            plan: effective.plan(),
            value: effective.value(),
            basis: effective.basis(),
            counted,
            rules: RulesVersion::M2,
        }
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// The refusal of a missing vault answer.
const fn missing() -> Refusal {
    Refusal::new(RuleRef::FactsIncomplete, RefusalReason::AnswerMissing)
}

/// The refusal of a decision id that is already taken.
const fn reused() -> Refusal {
    Refusal::new(RuleRef::Ledger, RefusalReason::IdReused)
}

/// The answer to `q`, or the refusal of a missing one.
fn answer<'a>(answers: &'a Answers, q: &Query) -> Result<&'a Answer, Refusal> {
    answers.get(q).ok_or_else(missing)
}

/// Appends the record of the vault answer to `q`, unless `out` holds it
/// already (overview NOTE 5).
pub(crate) fn record_answer(
    out: &mut Vec<Record>,
    q: &Query,
    answers: &Answers,
) -> Result<(), Refusal> {
    let a = answer(answers, q)?;
    let r = Record::VaultOutcome {
        kind: q.kind(),
        digest: a.digest,
        holds: a.holds,
        epoch: a.epoch,
    };
    if !out.contains(&r) {
        out.push(r);
    }
    Ok(())
}

/// The frozen policy of the call that governs `proposal`: its creation
/// call, also after re-entry (NOTE 8).
fn frozen_of(state: &State, proposal: ProposalId) -> Result<&FrozenPolicy, Refusal> {
    let call = crate::proposal::draft::proposal_call(state, proposal).ok_or_else(unknown)?;
    crate::policy::frozen_policy(state, call).ok_or_else(unknown)
}

/// A transition record of `proposal` with the command's actor (R-AU-01).
const fn transition(
    proposal: ProposalId,
    from: StateTag,
    to: StateTag,
    row: Row,
    actor: Actor,
    decision: Option<DecisionId>,
) -> Record {
    Record::Transitioned(Transitioned {
        proposal,
        from,
        to,
        row,
        actor,
        decision,
    })
}

/// Refuses unless the actor is an account holding `role` in the programme
/// of `proposal` now. Returns the account.
fn holder(
    state: &State,
    proposal: ProposalId,
    role: Role,
    ctx: &Ctx,
) -> Result<AccountId, Refusal> {
    let actor = crate::policy::actor_account(ctx)?;
    let programme = crate::assignment::programme_of(state, proposal)?;
    crate::policy::require_holder(state, actor, programme, &[role], ctx.now)?;
    Ok(actor)
}

/// The two `HasConflict` questions for `reviewer` on `proposal`: against
/// the full team, which every reviewer act asks, and against the team the
/// quorum asks about.
fn reviewer_questions(
    state: &State,
    reviewer: AccountId,
    proposal: ProposalId,
) -> Result<Vec<Query>, Refusal> {
    Ok(vec![
        conflict_query(state, reviewer, proposal),
        crate::proposal::score::quorum_conflict_query(state, reviewer, proposal)?,
    ])
}

/// Records the answers to the questions of `reviewers` on `proposal`, and
/// refuses with I-03 when the vault answers a conflict with the full team.
fn counted_reviewers(
    out: &mut Vec<Record>,
    state: &State,
    proposal: ProposalId,
    reviewers: &BTreeSet<AccountId>,
    answers: &Answers,
) -> Result<(), Refusal> {
    for r in reviewers {
        for q in reviewer_questions(state, *r, proposal)? {
            record_answer(out, &q, answers)?;
        }
        if answer(answers, &conflict_query(state, *r, proposal))?.holds {
            return Err(Refusal::new(RuleRef::I03, RefusalReason::VaultRefused));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Knock-out and admission (rows 2 and 3, R-EV-01, R-EV-02, I-03, I-34, I-35)
// ---------------------------------------------------------------------------

/// The coordinator of a knock-out check or an admission: an active FSTP
/// coordinator, on a SUBMITTED proposal, with a decision id not taken.
fn intake_basis(
    state: &State,
    proposal: ProposalId,
    decision: DecisionId,
    ctx: &Ctx,
) -> Result<AccountId, Refusal> {
    let actor = holder(state, proposal, Role::FstpCoordinator, ctx)?;
    if life::state_of(state, proposal)? != StateTag::Submitted {
        return Err(life::wrong_state());
    }
    if state.used_ids.contains(UsedId::Decision(decision)) {
        return Err(reused());
    }
    Ok(actor)
}

/// Checks a knock-out check against the state: one outcome per P-09
/// criterion, a reason for a failed one, and no earlier check (R-EV-01).
fn plan_knock_out(state: &State, cmd: &Command, ctx: &Ctx) -> Result<AccountId, Refusal> {
    let Command::RecordKnockOut {
        decision,
        proposal,
        outcomes,
        reason,
    } = cmd
    else {
        return Err(life::wrong_state());
    };
    let actor = intake_basis(state, *proposal, *decision, ctx)?;
    if life::facts(state, *proposal).is_some_and(|f| f.knock_out.is_some()) {
        return Err(life::wrong_state());
    }
    let p09: BTreeSet<_> = life::governing(state, *proposal)?
        .p09
        .0
        .iter()
        .map(|c| c.id)
        .collect();
    let named: BTreeSet<_> = outcomes.iter().map(|o| o.criterion).collect();
    if named.len() != outcomes.len() || named != p09 {
        return Err(Refusal::new(RuleRef::Rev01, RefusalReason::InvalidValue));
    }
    if outcomes.iter().any(|o| !o.passed) && reason.is_none() {
        return Err(Refusal::new(RuleRef::Rev01, RefusalReason::GuardFailed));
    }
    Ok(actor)
}

/// The records of a knock-out check: the check, and INELIGIBLE when a
/// criterion failed. The coordinator declared no conflict on the proposal
/// before the read, and the vault confirms it (I-03).
fn decide_knock_out(
    state: &State,
    cmd: &Command,
    ctx: &Ctx,
    answers: &Answers,
) -> Result<Vec<Record>, Refusal> {
    let actor = plan_knock_out(state, cmd, ctx)?;
    let Command::RecordKnockOut {
        decision,
        proposal,
        outcomes,
        reason,
    } = cmd
    else {
        return Err(life::wrong_state());
    };
    cleared_act(
        state,
        actor,
        *proposal,
        Role::FstpCoordinator,
        ctx.now,
        answers,
    )?;
    let mut out = Vec::new();
    record_answer(&mut out, &conflict_query(state, actor, *proposal), answers)?;
    out.push(Record::KnockOutRecorded {
        decision: *decision,
        proposal: *proposal,
        coordinator: actor,
        outcomes: outcomes.clone(),
        reason: *reason,
        rules: RulesVersion::M2,
    });
    if outcomes.iter().any(|o| !o.passed) {
        out.push(transition(
            *proposal,
            StateTag::Submitted,
            StateTag::Ineligible,
            Row::SubmittedToIneligible,
            ctx.actor,
            Some(*decision),
        ));
    }
    Ok(out)
}

/// A checked admission: the coordinator and the candidate reviewers, the
/// active reviewer assignments of the current call without a conflict fact.
struct Admission {
    actor: AccountId,
    proposal: ProposalId,
    decision: DecisionId,
    candidates: Vec<(AssignmentId, AccountId)>,
    /// The I-35 questions per candidate assignment, from the live P-38 lists.
    proximity: Vec<(AssignmentId, Query)>,
}

/// Checks an admission against the state (row 3).
fn plan_admit(state: &State, cmd: &Command, ctx: &Ctx) -> Result<Admission, Refusal> {
    let Command::AdmitToStage1 { decision, proposal } = cmd else {
        return Err(life::wrong_state());
    };
    let actor = intake_basis(state, *proposal, *decision, ctx)?;
    if life::facts(state, *proposal).and_then(|f| f.knock_out) != Some(true) {
        return Err(Refusal::new(RuleRef::Rev01, RefusalReason::GuardFailed));
    }
    let call = life::current_call(state, *proposal)?;
    let candidates: Vec<(AssignmentId, AccountId)> =
        life::active_assignments(state, *proposal, call, AssignmentKind::Reviewer)
            .into_iter()
            .filter_map(|id| state.review.get(id).map(|a| (id, a.reviewer)))
            .collect();
    let programme = crate::assignment::programme_of(state, *proposal)?;
    let team = state.roster.receiving_accounts(*proposal);
    let lists = crate::policy::live_values(state, programme).map(|l| &l.p38.0);
    let proximity = candidates
        .iter()
        .filter_map(|(id, r)| {
            let org = committee_organisation(state, *r, programme, ctx.now)?;
            let list = lists?.get(&org)?;
            Some((
                *id,
                Query::DeclaresAffiliationOnList {
                    team: team.clone(),
                    list: *list,
                },
            ))
        })
        .collect();
    Ok(Admission {
        actor,
        proposal: *proposal,
        decision: *decision,
        candidates,
        proximity,
    })
}

/// The vault questions of an admission.
fn admit_queries(state: &State, a: &Admission) -> Vec<Query> {
    let mut out = vec![conflict_query(state, a.actor, a.proposal)];
    out.extend(
        a.candidates
            .iter()
            .map(|(_, r)| conflict_query(state, *r, a.proposal)),
    );
    out.extend(a.proximity.iter().map(|(_, q)| q.clone()));
    out
}

/// The records of an admission: SUBMITTED to STAGE1 once the knock-out
/// check passed and at least P-03 active assignments are free of conflict
/// (R-EV-02, I-03), across at least P-39 known organisations (I-34), and
/// clear of the proximity lists (I-35).
fn decide_admit(
    state: &State,
    a: &Admission,
    ctx: &Ctx,
    answers: &Answers,
) -> Result<Vec<Record>, Refusal> {
    cleared_act(
        state,
        a.actor,
        a.proposal,
        Role::FstpCoordinator,
        ctx.now,
        answers,
    )?;
    let mut out = Vec::new();
    for q in admit_queries(state, a) {
        record_answer(&mut out, &q, answers)?;
    }
    // Row 3 admits with reviewers assigned without conflict. An active
    // assignee the vault finds conflicted would block the stage 1 close,
    // so the admission is refused until that assignment is released.
    let mut free = Vec::new();
    for (id, r) in &a.candidates {
        if answer(answers, &conflict_query(state, *r, a.proposal))?.holds {
            return Err(Refusal::new(RuleRef::I03, RefusalReason::VaultRefused));
        }
        free.push((*id, *r));
    }
    let values = life::governing(state, a.proposal)?;
    if free.len() < usize::from(values.p03.get()) {
        return Err(Refusal::new(RuleRef::Rev02, RefusalReason::GuardFailed));
    }
    let programme = crate::assignment::programme_of(state, a.proposal)?;
    // An unknown organisation fails closed (SoD-10, decided 2026-10-25).
    let distinct: Option<BTreeSet<_>> = free
        .iter()
        .map(|(_, r)| committee_organisation(state, *r, programme, ctx.now))
        .collect();
    if distinct.is_none_or(|d| d.len() < usize::from(values.p39.get())) {
        return Err(Refusal::new(RuleRef::I34, RefusalReason::GuardFailed));
    }
    for (id, q) in &a.proximity {
        if free.iter().any(|(f, _)| f == id) && answer(answers, q)?.holds {
            return Err(Refusal::new(RuleRef::I35, RefusalReason::VaultRefused));
        }
    }
    out.push(transition(
        a.proposal,
        StateTag::Submitted,
        StateTag::Stage1,
        Row::SubmittedToStage1,
        ctx.actor,
        Some(a.decision),
    ));
    Ok(out)
}

// ---------------------------------------------------------------------------
// The stage 1 close (rows 4 and 5, I-07, I-08, NOTE 3, R-LA-03)
// ---------------------------------------------------------------------------

/// A checked close: the recording coordinator, the proposal, its submitted
/// plan and the reviewers whose scores may count.
struct Close {
    actor: AccountId,
    proposal: ProposalId,
    plan: PlanVersionId,
    reviewers: BTreeSet<AccountId>,
}

/// Checks a close against the state. The FSTP coordinator records it.
fn plan_close(state: &State, cmd: &Command, ctx: &Ctx) -> Result<Close, Refusal> {
    let Command::CloseStage1 { proposal } = cmd else {
        return Err(life::wrong_state());
    };
    let actor = holder(state, *proposal, Role::FstpCoordinator, ctx)?;
    if life::state_of(state, *proposal)? != StateTag::Stage1 {
        return Err(life::wrong_state());
    }
    let plan = crate::proposal::intake::submission(state, *proposal)
        .map(|s| s.plan)
        .ok_or_else(life::wrong_state)?;
    let call = crate::proposal::draft::proposal_call(state, *proposal).ok_or_else(unknown)?;
    let reviewers = life::assignees(
        state,
        &life::active_assignments(state, *proposal, call, AssignmentKind::Reviewer),
    );
    // I-34 holds at the close too: a release after admission can leave
    // the scores to fewer than P-39 organisations (SoD-10).
    crate::assignment::require_reviewers_span_p39(state, *proposal, &reviewers, ctx.now)?;
    Ok(Close {
        actor,
        proposal: *proposal,
        plan,
        reviewers,
    })
}

/// The vault questions of a close: `HasConflict` per reviewer who may count.
fn close_queries(state: &State, c: &Close) -> Result<Vec<Query>, Refusal> {
    let mut out = Vec::new();
    for r in &c.reviewers {
        out.extend(reviewer_questions(state, *r, c.proposal)?);
    }
    Ok(out)
}

/// The records of a close: the computed `Stage1Closed` and the transition
/// to STAGE2 when the score is strictly above P-02, or to NOT_SELECTED.
/// The transition carries no decision id, as its outcome is computed.
fn decide_close(
    state: &State,
    c: &Close,
    ctx: &Ctx,
    answers: &Answers,
) -> Result<Vec<Record>, Refusal> {
    let mut out = Vec::new();
    counted_reviewers(&mut out, state, c.proposal, &c.reviewers, answers)?;
    let frozen = frozen_of(state, c.proposal)?;
    let quorum = establish_quorum(state, c.proposal, Stage::One, c.plan, frozen, answers)?;
    let verdict = judge_stage1(quorum, state, frozen)?;
    let (to, row) = if verdict.passed() {
        (StateTag::Stage2, Row::Stage1ToStage2)
    } else {
        (StateTag::NotSelected, Row::Stage1ToNotSelected)
    };
    out.push(Record::Stage1Closed(Stage1Closed::from_verdict(
        &verdict, c.actor,
    )));
    out.push(transition(
        c.proposal,
        StateTag::Stage1,
        to,
        row,
        ctx.actor,
        None,
    ));
    Ok(out)
}

/// The proposals whose stage 1 close trigger holds (NOTE 3): in STAGE1,
/// every active reviewer assignment of the stage 1 call has a valid score,
/// at least P-03 valid scores from distinct reviewers exist, and the
/// active reviewers span at least P-39 organisations (I-34).
pub(crate) fn stage1_ready(state: &State, now: Timestamp) -> Vec<ProposalId> {
    crate::proposal::intake::submitted_proposals(state)
        .filter(|(_, s, _)| *s == StateTag::Stage1)
        .map(|(p, _, _)| p)
        .filter(|p| stage1_closable(state, *p, now))
        .collect()
}

/// Whether the stage 1 close trigger of `proposal` holds, without the vault.
fn stage1_closable(state: &State, proposal: ProposalId, now: Timestamp) -> bool {
    let (Ok(values), Some(call)) = (
        life::governing(state, proposal),
        crate::proposal::draft::proposal_call(state, proposal),
    ) else {
        return false;
    };
    let valid = crate::proposal::score::valid_stage1_keys(state, proposal);
    let scored: BTreeSet<AssignmentId> = valid.iter().map(|k| k.assignment).collect();
    let reviewers = life::assignees(state, &scored);
    let active = state.review.active_reviewers_in(proposal, call);
    let active_reviewers = life::assignees(state, &active);
    reviewers.len() >= usize::from(values.p03.get())
        && active.is_subset(&scored)
        && crate::assignment::reviewers_span_p39(state, proposal, &active_reviewers, now)
            .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Ranking after stage 2 (row 6, I-09, NOTE 4)
// ---------------------------------------------------------------------------

/// The vault questions of a ranking of `proposal`: `HasConflict` for every
/// reviewer whose stage 2 score may count.
pub(crate) fn ranking_queries(state: &State, proposal: ProposalId) -> Result<Vec<Query>, Refusal> {
    let mut out = Vec::new();
    for r in stage2_reviewers(state, proposal)? {
        out.extend(reviewer_questions(state, r, proposal)?);
    }
    Ok(out)
}

/// The assignees of the active reviewer assignments of the current call.
fn stage2_reviewers(state: &State, proposal: ProposalId) -> Result<BTreeSet<AccountId>, Refusal> {
    let call = life::current_call(state, proposal)?;
    Ok(life::assignees(
        state,
        &life::active_assignments(state, proposal, call, AssignmentKind::Reviewer),
    ))
}

/// The refusal of a ranking whose active reviewers in the current call
/// span fewer than P-39 known organisations (I-34, SoD-10). A release in
/// STAGE2 can take the count below P-39, and a reassignment restores it.
pub(crate) fn require_stage2_organisations(
    state: &State,
    proposal: ProposalId,
    now: Timestamp,
) -> Result<(), Refusal> {
    let reviewers = stage2_reviewers(state, proposal)?;
    crate::assignment::require_reviewers_span_p39(state, proposal, &reviewers, now)
}

/// One revision with its stage 2 score and counted keys, when it has a quorum.
type RevisionQuorum = (PlanVersionId, Option<(Ratio, BTreeSet<ScoreKey>)>);

/// The stage 2 quorum of each submitted revision, in submission order:
/// its score and keys when at least P-03 valid stage 2 scores exist.
fn revision_quorums(
    state: &State,
    proposal: ProposalId,
    policy: &FrozenPolicy,
    answers: &Answers,
) -> Result<Vec<RevisionQuorum>, Refusal> {
    let revisions = life::facts(state, proposal)
        .map(|f| f.revisions.clone())
        .unwrap_or_default();
    let mut out = Vec::new();
    for plan in revisions {
        let scored = match establish_quorum(state, proposal, Stage::Two, plan, policy, answers) {
            Ok(q) => Some((weighted_score(&q, state, policy), q.keys().clone())),
            Err(r) if r.rule == RuleRef::I07 => None,
            Err(r) => return Err(r),
        };
        out.push((plan, scored));
    }
    Ok(out)
}

/// Whether a revision of `proposal` has at least P-03 valid stage 2 scores.
fn revision_scored(
    state: &State,
    proposal: ProposalId,
    answers: &Answers,
) -> Result<bool, Refusal> {
    let frozen = frozen_of(state, proposal)?;
    Ok(revision_quorums(state, proposal, frozen, answers)?
        .iter()
        .any(|(_, s)| s.is_some()))
}

/// The records that take `proposal` from STAGE2 to RANKED: the answers
/// used, the effective score under P-24 and the transition (I-09). The
/// original plan's score is the sealed stage 1 close. The latest scored
/// revision counts, and a tie keeps the original plan (NOTE 4). `prior`
/// holds the batch so far, so an answer is recorded once.
pub(crate) fn ranking_records(
    state: &State,
    proposal: ProposalId,
    ctx: &Ctx,
    answers: &Answers,
    prior: &[Record],
) -> Result<Vec<Record>, Refusal> {
    let mut out = prior.to_vec();
    let reviewers = stage2_reviewers(state, proposal)?;
    counted_reviewers(&mut out, state, proposal, &reviewers, answers)?;
    let mut out: Vec<Record> = out.split_off(prior.len());
    let facts = life::facts(state, proposal).ok_or_else(life::wrong_state)?;
    let closed = facts
        .closed
        .as_ref()
        .ok_or(Refusal::new(RuleRef::I09, RefusalReason::GuardFailed))?;
    let original = crate::proposal::intake::submission(state, proposal)
        .map(|s| s.plan)
        .ok_or_else(life::wrong_state)?;
    let frozen = frozen_of(state, proposal)?;
    let quorums = revision_quorums(state, proposal, frozen, answers)?;
    let scores: Vec<(PlanVersionId, Option<Ratio>)> = quorums
        .iter()
        .map(|(p, s)| (*p, s.as_ref().map(|(r, _)| *r)))
        .collect();
    let effective =
        effective_score_of_revisions(frozen.values().p24, (original, closed.score()), &scores);
    let counted = match effective.basis() {
        Basis::Original => closed.counted().clone(),
        Basis::Revised => quorums
            .iter()
            .find(|(p, _)| *p == effective.plan())
            .and_then(|(_, s)| s.as_ref().map(|(_, k)| k.clone()))
            .unwrap_or_default(),
    };
    out.push(Record::EffectiveScoreSet(
        EffectiveScoreSet::from_effective(proposal, effective, counted),
    ));
    out.push(transition(
        proposal,
        StateTag::Stage2,
        StateTag::Ranked,
        Row::Stage2ToRanked,
        ctx.actor,
        None,
    ));
    Ok(out)
}

/// The assignee and assignment of a ranking: an active reviewer assignment
/// of the actor in the current call, in STAGE2.
fn plan_rank(
    state: &State,
    cmd: &Command,
    ctx: &Ctx,
) -> Result<(AccountId, ProposalId, AssignmentId), Refusal> {
    let Command::RankAfterStage2 { proposal } = cmd else {
        return Err(life::wrong_state());
    };
    if life::state_of(state, *proposal)? != StateTag::Stage2 {
        return Err(life::wrong_state());
    }
    let actor = crate::policy::actor_account(ctx)?;
    let assignment =
        qualifying_assignment(state, actor, *proposal, AssignmentKind::Reviewer, ctx.now)
            .ok_or(Refusal::new(RuleRef::Actor, RefusalReason::BindingInactive))?;
    require_stage2_organisations(state, *proposal, ctx.now)?;
    Ok((actor, *proposal, assignment))
}

/// The records of a ranking by an assigned reviewer. Stage 2 has
/// concluded when a revision has at least P-03 valid stage 2 scores, when
/// the window closed with answers, or when every active assigned reviewer
/// recorded "no questions" (NOTE 4, O-50).
fn decide_rank(
    state: &State,
    cmd: &Command,
    ctx: &Ctx,
    answers: &Answers,
) -> Result<Vec<Record>, Refusal> {
    let (actor, proposal, assignment) = plan_rank(state, cmd, ctx)?;
    reviewer_act(state, actor, assignment, ctx.now, answers)?.require_proposal(proposal)?;
    let mut out = Vec::new();
    record_answer(&mut out, &conflict_query(state, actor, proposal), answers)?;
    let answered = life::facts(state, proposal)
        .and_then(|f| f.round.as_ref())
        .is_some_and(|r| r.answered);
    let closed_window = life::window_end(state, proposal).is_some_and(|end| ctx.now >= end);
    let no_questions = life::no_questions_complete(state, proposal);
    if !(no_questions || revision_scored(state, proposal, answers)? || (closed_window && answered))
    {
        return Err(Refusal::new(RuleRef::Rev05, RefusalReason::GuardFailed));
    }
    let more = ranking_records(state, proposal, ctx, answers, &out)?;
    out.extend(more);
    Ok(out)
}

// ---------------------------------------------------------------------------
// The cut-off (rows 8 and 9, NOTE 6, R-EV-08, R-EV-09, P-16 NOTE 8)
// ---------------------------------------------------------------------------
/// The state of one cut-off round (M4 change D5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum RoundStatus {
    /// Members cast and delegate, and a member may record the cut-off.
    Open,
    /// The cut-off was recorded. Nothing acts in the round any more.
    Recorded,
    /// A later round of the call replaced it, after its order went stale
    /// or its vote failed (interim, pending Daniel).
    Superseded,
}

/// One cut-off round as the projection holds it: what was opened, and
/// what each member did for themselves in it (R-EV-09, P-16 NOTE 8).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct CutOffRound {
    call: CallId,
    order: Vec<ProposalId>,
    nominated: u32,
    rationale: TextRef,
    tie_breaks: Option<TextRef>,
    status: RoundStatus,
    /// The ballot each member cast, by member.
    cast: BTreeMap<AccountId, Vote>,
    /// Each delegation, from the delegating member to the holder.
    delegated: BTreeMap<AccountId, AccountId>,
}

/// The cut-off rounds of every call (D5). The projection keeps the facts
/// of each round, so two histories that reach the same ballots give equal
/// rounds whatever the order of the casts.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Rounds {
    rounds: BTreeMap<DecisionId, CutOffRound>,
    /// The open round of each call, at most one.
    open: BTreeMap<CallId, DecisionId>,
}

impl Rounds {
    /// No round.
    pub(crate) const fn genesis() -> Rounds {
        Rounds {
            rounds: BTreeMap::new(),
            open: BTreeMap::new(),
        }
    }
}

/// The committee of `programme` at `now`: active committee members and chairs.
fn committee(state: &State, programme: ProgrammeId, now: Timestamp) -> BTreeSet<AccountId> {
    holders(
        state,
        programme,
        &[Role::CommitteeMember, Role::CommitteeChair],
        now,
    )
}

/// The accounts with an active binding of one of `roles` in `programme` at `now`.
fn holders(
    state: &State,
    programme: ProgrammeId,
    roles: &[Role],
    now: Timestamp,
) -> BTreeSet<AccountId> {
    state
        .roster
        .bindings()
        .filter(|(_, b)| b.programme == programme && roles.contains(&b.role) && b.active_at(now))
        .map(|(_, b)| b.account)
        .collect()
}

/// The effective score of a RANKED proposal.
fn effective_value(state: &State, proposal: ProposalId) -> Result<Ratio, Refusal> {
    life::facts(state, proposal)
        .and_then(|f| f.effective.as_ref())
        .map(EffectiveScoreSet::value)
        .ok_or(Refusal::new(RuleRef::I09, RefusalReason::GuardFailed))
}

/// The RANKED proposals whose current call is `call`.
fn ranked_in(state: &State, call: CallId) -> BTreeSet<ProposalId> {
    crate::proposal::intake::submitted_proposals(state)
        .filter(|(_, s, c)| *s == StateTag::Ranked && *c == call)
        .map(|(p, _, _)| p)
        .collect()
}

/// Checks a round's order against the state (NOTE 6, R-EV-08): exactly
/// the call's RANKED proposals, by non-increasing effective score, a rank
/// position inside it, and a recorded P-17 tie-break for a tie across that
/// position. Returns the proposals tied across the position, for the P-17
/// question.
fn check_order(
    state: &State,
    call: CallId,
    order: &[ProposalId],
    nominated: u32,
    tie_breaks: Option<TextRef>,
) -> Result<Vec<ProposalId>, Refusal> {
    let listed: BTreeSet<ProposalId> = order.iter().copied().collect();
    if order.is_empty() || listed.len() != order.len() || listed != ranked_in(state, call) {
        return Err(Refusal::new(RuleRef::Rev08, RefusalReason::InvalidValue));
    }
    let n = usize::try_from(nominated).map_err(|_| life::invalid())?;
    if n > order.len() {
        return Err(Refusal::new(RuleRef::Rev08, RefusalReason::InvalidValue));
    }
    let mut values = Vec::new();
    for p in order {
        values.push(effective_value(state, *p)?);
    }
    if values.windows(2).any(|w| matches!(w, [x, y] if x < y)) {
        return Err(Refusal::new(RuleRef::Rev08, RefusalReason::InvalidValue));
    }
    let boundary = n
        .checked_sub(1)
        .and_then(|i| values.get(i).copied().zip(values.get(n).copied()));
    match boundary {
        Some((last_in, first_out)) if last_in == first_out => {
            if tie_breaks.is_none() {
                return Err(Refusal::new(
                    RuleRef::Param(ParamId::P17),
                    RefusalReason::GuardFailed,
                ));
            }
            Ok(order
                .iter()
                .zip(&values)
                .filter(|(_, v)| **v == last_in)
                .map(|(p, _)| *p)
                .collect())
        }
        _ => Ok(Vec::new()),
    }
}

/// The published call `call` and its programme, or the refusal.
fn published_programme(state: &State, call: CallId) -> Result<ProgrammeId, Refusal> {
    let view = crate::programme::call(state, call).ok_or_else(unknown)?;
    if view.seq().is_none() {
        return Err(life::wrong_state());
    }
    Ok(view.programme())
}

/// The refusal of an act in a round that is not open.
const fn round_closed() -> Refusal {
    Refusal::new(RuleRef::Rev09, RefusalReason::WrongState)
}

/// The refusal of a ballot or delegation that P-16 NOTE 8 forbids.
const fn ballot_refused() -> Refusal {
    Refusal::new(RuleRef::Rev09, RefusalReason::InvalidValue)
}

/// Whether the open round `r` still matches its call: its order lists
/// exactly the call's RANKED proposals. A withdrawal or a newly ranked
/// proposal makes it stale. Then nothing more acts in it, and a member
/// may open a new round of the call, which supersedes it. A live round is
/// superseded only once its vote has failed ([`could_adopt`]).
fn is_live(state: &State, r: &CutOffRound) -> bool {
    r.status == RoundStatus::Open
        && r.order.iter().copied().collect::<BTreeSet<_>>() == ranked_in(state, r.call)
}

/// The live round `round`, or the refusal.
fn live_round(state: &State, round: DecisionId) -> Result<&CutOffRound, Refusal> {
    let r = state.calls.rounds.rounds.get(&round).ok_or_else(unknown)?;
    if r.status != RoundStatus::Open {
        return Err(round_closed());
    }
    if !is_live(state, r) {
        return Err(Refusal::new(RuleRef::Rev08, RefusalReason::WrongState));
    }
    Ok(r)
}

/// The call of round `round`, for the P-77 scope.
fn round_call(state: &State, round: DecisionId) -> Result<CallId, Refusal> {
    state
        .calls
        .rounds
        .rounds
        .get(&round)
        .map(|r| r.call)
        .ok_or_else(unknown)
}

/// A checked round command, before the vault answers.
struct RoundPlan {
    /// The acting committee member.
    actor: AccountId,
    /// The round's call.
    call: CallId,
    /// The round's programme.
    programme: ProgrammeId,
    /// The members whose recusal the command asks about.
    asked: BTreeSet<AccountId>,
    /// The proposals tied across the position, for a cut-off's P-17 question.
    tied: Vec<ProposalId>,
    /// For an `OpenCutOffRound`, the live open round of the call that the
    /// new round would supersede. The opening needs that round's vote to
    /// have failed, which the recusal answers of every member decide.
    supersedes: Option<DecisionId>,
}

/// The committee member behind `ctx` in `programme` at `ctx.now`, or the refusal.
fn member(
    state: &State,
    programme: ProgrammeId,
    ctx: &Ctx,
) -> Result<(AccountId, BTreeSet<AccountId>), Refusal> {
    let actor = crate::policy::actor_account(ctx)?;
    let members = committee(state, programme, ctx.now);
    if !members.contains(&actor) {
        return Err(Refusal::new(RuleRef::Actor, RefusalReason::BindingInactive));
    }
    Ok((actor, members))
}

/// Checks a round command against the state (D5):
///
/// - `OpenCutOffRound`: a committee member, a fresh round id, a published
///   call, and an order that [`check_order`] admits. Only one round is
///   open per call. A live open round of the call is superseded only when
///   its vote has failed, which the decision checks with the recusal
///   answers of every member (interim, pending Daniel).
/// - `CastBallot`: a committee member of the live round's call who has
///   neither cast nor delegated.
/// - `DelegateVote`: as a cast, to another committee member who has
///   neither delegated nor holds a delegated vote, by a member who holds
///   none (P-16 NOTE 8).
/// - `RecordCutOff`: a committee member, a live round whose order still
///   passes [`check_order`].
///
/// Recusal comes from the vault answers in the decision, not here.
fn plan_round(state: &State, cmd: &Command, ctx: &Ctx) -> Result<RoundPlan, Refusal> {
    match cmd {
        Command::OpenCutOffRound {
            round,
            call,
            order,
            nominated,
            tie_breaks,
            ..
        } => {
            let programme = published_programme(state, *call)?;
            let (actor, members) = member(state, programme, ctx)?;
            if state.used_ids.contains(UsedId::Decision(*round)) {
                return Err(reused());
            }
            let supersedes = state.calls.rounds.open.get(call).copied().filter(|id| {
                state
                    .calls
                    .rounds
                    .rounds
                    .get(id)
                    .is_some_and(|r| is_live(state, r))
            });
            check_order(state, *call, order, *nominated, *tie_breaks)?;
            let asked = match supersedes {
                Some(_) => members,
                None => [actor].into_iter().collect(),
            };
            Ok(RoundPlan {
                actor,
                call: *call,
                programme,
                asked,
                tied: Vec::new(),
                supersedes,
            })
        }
        Command::CastBallot { round, .. } => {
            let r = live_round(state, *round)?;
            let programme = published_programme(state, r.call)?;
            let (actor, _) = member(state, programme, ctx)?;
            if r.cast.contains_key(&actor) || r.delegated.contains_key(&actor) {
                return Err(ballot_refused());
            }
            Ok(RoundPlan {
                actor,
                call: r.call,
                programme,
                asked: [actor].into_iter().collect(),
                tied: Vec::new(),
                supersedes: None,
            })
        }
        Command::DelegateVote { round, to } => {
            let r = live_round(state, *round)?;
            let programme = published_programme(state, r.call)?;
            let (actor, members) = member(state, programme, ctx)?;
            let holds_vote = |m: &AccountId| r.delegated.values().any(|t| t == m);
            if !members.contains(to)
                || *to == actor
                || r.cast.contains_key(&actor)
                || r.delegated.contains_key(&actor)
                || holds_vote(&actor)
                || r.delegated.contains_key(to)
                || holds_vote(to)
            {
                return Err(ballot_refused());
            }
            Ok(RoundPlan {
                actor,
                call: r.call,
                programme,
                asked: [actor, *to].into_iter().collect(),
                tied: Vec::new(),
                supersedes: None,
            })
        }
        Command::RecordCutOff { round } => {
            let r = live_round(state, *round)?;
            let programme = published_programme(state, r.call)?;
            let (actor, members) = member(state, programme, ctx)?;
            let tied = check_order(state, r.call, &r.order, r.nominated, r.tie_breaks)?;
            Ok(RoundPlan {
                actor,
                call: r.call,
                programme,
                asked: members,
                tied,
                supersedes: None,
            })
        }
        _ => Err(life::wrong_state()),
    }
}

/// The vault questions of a round command: the recusal questions of each
/// member it asks about (Conflict declarations), and for a cut-off the
/// P-17 country question for the leads of tied proposals
/// (policy-parameters NOTE 9).
fn round_queries(state: &State, p: &RoundPlan) -> Vec<Query> {
    let mut out = Vec::new();
    for m in &p.asked {
        out.extend(cut_off_recusal_queries(state, *m, p.call));
    }
    out.extend(p.tied.iter().filter_map(|t| {
        crate::proposal::draft::draft(state, *t).map(|d| Query::MeetsTieBreakCountry {
            account: d.lead,
            programme: p.programme,
        })
    }));
    out
}

/// The remaining budget of `call` (R-EV-08, design 3.7, Q14): the one the
/// committee ranking view shows, so the recorded value is the value the
/// committee saw. The ranking view lists a row per RANKED proposal of the
/// call, and a cut-off orders at least one, so a row exists. It is signed,
/// since a call can be over-nominated.
fn remaining_budget(state: &State, call: CallId) -> Result<Amount, Refusal> {
    crate::visibility::ranking_view(state, call)?
        .first()
        .map(|row| row.remaining_budget)
        .ok_or_else(life::wrong_state)
}

/// The ballots that count in `r` under P-16 NOTE 8 (R-EV-09, D5): each
/// ballot that a member who may vote cast for themselves, and each
/// delegated vote of such a member to such a member, with the vote its
/// holder cast, once the holder cast. Recused members neither vote nor
/// count, and neither does a member no longer on the committee. A vote
/// that was never cast counts for nobody.
fn counted_ballots(r: &CutOffRound, eligible: &BTreeSet<AccountId>) -> Vec<Ballot> {
    let mut out: Vec<Ballot> = r
        .cast
        .iter()
        .filter(|(m, _)| eligible.contains(*m))
        .map(|(m, v)| Ballot {
            voter: *m,
            vote: *v,
            delegated_by: None,
        })
        .collect();
    for (from, to) in &r.delegated {
        if let Some(v) = r.cast.get(to)
            && eligible.contains(from)
            && eligible.contains(to)
        {
            out.push(Ballot {
                voter: *to,
                vote: *v,
                delegated_by: Some(*from),
            });
        }
    }
    out
}

/// The P-16 outcome of `ballots` (policy-parameters NOTE 8), counted over
/// the members in `eligible`: a refusal without a quorum, and otherwise
/// whether the cut-off is adopted.
///
/// - The quorum is more than half of the members who may vote, delegated
///   votes included.
/// - The cut-off needs a majority of the votes cast. Abstentions are not
///   votes cast. On a tie, the chair's own vote is the casting vote: the
///   tie is broken for the cut-off when a chair voted for it and no chair
///   voted against it.
fn p16_adopted(
    eligible: &BTreeSet<AccountId>,
    chairs: &BTreeSet<AccountId>,
    ballots: &[Ballot],
) -> Result<bool, Refusal> {
    let represented: BTreeSet<AccountId> = ballots
        .iter()
        .map(|b| b.delegated_by.unwrap_or(b.voter))
        .collect();
    if represented.len().saturating_mul(2) <= eligible.len() {
        return Err(Refusal::new(RuleRef::Rev09, RefusalReason::GuardFailed));
    }
    let count = |v: Vote| ballots.iter().filter(|b| b.vote == v).count();
    let (yes, no) = (count(Vote::For), count(Vote::Against));
    let casting = |v: Vote| {
        ballots
            .iter()
            .any(|b| b.delegated_by.is_none() && chairs.contains(&b.voter) && b.vote == v)
    };
    Ok(yes > no || (yes == no && casting(Vote::For) && !casting(Vote::Against)))
}

/// Whether the vote of round `r` can still adopt its cut-off under P-16
/// NOTE 8, counted over `eligible`: whether it would be adopted if every
/// member of `eligible` who has neither cast nor delegated cast For. A
/// vote For never lowers the outcome, so a `false` here means the vote
/// has failed whatever the remaining members do (interim, pending
/// Daniel). A round with no possible quorum cannot adopt either.
fn could_adopt(
    r: &CutOffRound,
    eligible: &BTreeSet<AccountId>,
    chairs: &BTreeSet<AccountId>,
) -> bool {
    let mut best = r.clone();
    for m in eligible {
        if !best.cast.contains_key(m) && !best.delegated.contains_key(m) {
            best.cast.insert(*m, Vote::For);
        }
    }
    p16_adopted(eligible, chairs, &counted_ballots(&best, eligible)).unwrap_or(false)
}

/// The records of a round command (D5).
///
/// - `OpenCutOffRound`: the opener's recusal answers and the opened round.
///   When a live round of the call is open, the recusal answers of every
///   member too, and the opening is refused under R-EV-09 unless that
///   round's vote has failed ([`could_adopt`]). The fold then supersedes
///   the failed round.
/// - `CastBallot` and `DelegateVote`: the recusal answers and the actor's
///   own ballot or delegation. A recused member, as actor or as holder of
///   a delegation, is refused under I-03.
/// - `RecordCutOff`: the recusal answers of every member and the P-17
///   answers, the cut-off with the round as its decision, the ballots
///   counted, the recused members and the remaining budget, then per
///   proposal of the order IRC_REVIEW within the rank position or
///   NOT_SELECTED below it, each with the round as its decision.
fn decide_round(
    state: &State,
    cmd: &Command,
    ctx: &Ctx,
    answers: &Answers,
) -> Result<Vec<Record>, Refusal> {
    let p = plan_round(state, cmd, ctx)?;
    let mut out = Vec::new();
    for q in round_queries(state, &p) {
        record_answer(&mut out, &q, answers)?;
    }
    let mut recused = BTreeSet::new();
    for m in &p.asked {
        if recused_from_cut_off(state, *m, p.call, answers)? {
            recused.insert(*m);
        }
    }
    let refused = match cmd {
        // The recorder's own recusal is checked with the outcome below.
        Command::RecordCutOff { .. } => false,
        // An opening asks about every member only to supersede a round.
        Command::OpenCutOffRound { .. } => recused.contains(&p.actor),
        _ => !recused.is_empty(),
    };
    if refused {
        // Conflict declarations: a recused member neither votes nor
        // delegates, and nobody votes for them.
        return Err(Refusal::new(RuleRef::I03, RefusalReason::GuardFailed));
    }
    if let Some(old) = p.supersedes {
        let r = live_round(state, old)?;
        let eligible: BTreeSet<AccountId> = p.asked.difference(&recused).copied().collect();
        let chairs = holders(state, p.programme, &[Role::CommitteeChair], ctx.now);
        if could_adopt(r, &eligible, &chairs) {
            // R-EV-09: a round whose vote can still pass stays the open one.
            return Err(round_closed());
        }
    }
    match cmd {
        Command::OpenCutOffRound {
            round,
            call,
            order,
            nominated,
            rationale,
            tie_breaks,
        } => out.push(Record::CutOffRoundOpened {
            round: *round,
            call: *call,
            order: order.clone(),
            nominated: *nominated,
            rationale: *rationale,
            tie_breaks: *tie_breaks,
            by: p.actor,
        }),
        Command::CastBallot { round, vote } => out.push(Record::BallotCast {
            round: *round,
            voter: p.actor,
            vote: *vote,
        }),
        Command::DelegateVote { round, to } => out.push(Record::VoteDelegated {
            round: *round,
            from: p.actor,
            to: *to,
        }),
        Command::RecordCutOff { round } => {
            if recused.contains(&p.actor) {
                return Err(Refusal::new(RuleRef::I03, RefusalReason::GuardFailed));
            }
            let r = live_round(state, *round)?;
            let eligible: BTreeSet<AccountId> = p.asked.difference(&recused).copied().collect();
            let ballots = counted_ballots(r, &eligible);
            let chairs = holders(state, p.programme, &[Role::CommitteeChair], ctx.now);
            if !p16_adopted(&eligible, &chairs, &ballots)? {
                return Err(Refusal::new(RuleRef::Rev09, RefusalReason::GuardFailed));
            }
            out.push(Record::CutOffRecorded(CutOffRecorded {
                decision: *round,
                call: r.call,
                order: r.order.clone(),
                nominated: r.nominated,
                rationale: r.rationale,
                tie_breaks: r.tie_breaks,
                ballots,
                recused,
                remaining_budget: remaining_budget(state, r.call)?,
                recorder: p.actor,
                rules: RulesVersion::M4,
            }));
            let n = usize::try_from(r.nominated).map_err(|_| life::invalid())?;
            for (i, proposal) in r.order.iter().enumerate() {
                let (to, row) = if i < n {
                    (StateTag::IrcReview, Row::RankedToIrcReview)
                } else {
                    (StateTag::NotSelected, Row::RankedToNotSelected)
                };
                out.push(transition(
                    *proposal,
                    StateTag::Ranked,
                    to,
                    row,
                    ctx.actor,
                    Some(*round),
                ));
            }
        }
        _ => return Err(life::wrong_state()),
    }
    Ok(out)
}

/// Folds a round record: the opening, a member's ballot or delegation.
/// The fold checks structure only: the call exists, the round id is used
/// once, the round is open, and each member casts or delegates once.
fn fold_round(state: &mut State, record: &Record) -> Result<(), FoldError> {
    match record {
        Record::CutOffRoundOpened {
            round,
            call,
            order,
            nominated,
            rationale,
            tie_breaks,
            ..
        } => {
            crate::programme::call(state, *call).ok_or(FoldError::UnknownEntity)?;
            if !state.used_ids.insert(UsedId::Decision(*round)) {
                return Err(FoldError::DuplicateId);
            }
            let rounds = &mut state.calls.rounds;
            if let Some(old) = rounds.open.insert(*call, *round)
                && let Some(r) = rounds.rounds.get_mut(&old)
            {
                r.status = RoundStatus::Superseded;
            }
            rounds.rounds.insert(
                *round,
                CutOffRound {
                    call: *call,
                    order: order.clone(),
                    nominated: *nominated,
                    rationale: *rationale,
                    tie_breaks: *tie_breaks,
                    status: RoundStatus::Open,
                    cast: BTreeMap::new(),
                    delegated: BTreeMap::new(),
                },
            );
            Ok(())
        }
        Record::BallotCast { round, voter, vote } => {
            let r = open_round_mut(state, *round)?;
            if r.cast.contains_key(voter) || r.delegated.contains_key(voter) {
                return Err(FoldError::Inconsistent);
            }
            r.cast.insert(*voter, *vote);
            Ok(())
        }
        Record::VoteDelegated { round, from, to } => {
            let r = open_round_mut(state, *round)?;
            if from == to || r.cast.contains_key(from) || r.delegated.contains_key(from) {
                return Err(FoldError::Inconsistent);
            }
            r.delegated.insert(*from, *to);
            Ok(())
        }
        _ => Err(FoldError::Inconsistent),
    }
}

/// The open round `round` for a fold.
fn open_round_mut(state: &mut State, round: DecisionId) -> Result<&mut CutOffRound, FoldError> {
    let r = state
        .calls
        .rounds
        .rounds
        .get_mut(&round)
        .ok_or(FoldError::UnknownEntity)?;
    if r.status != RoundStatus::Open {
        return Err(FoldError::Inconsistent);
    }
    Ok(r)
}

/// Folds a `CutOffRecorded`. Under [`RulesVersion::M4`] its decision is
/// the open round of its call, which it closes (D5). Under an earlier
/// version it took a fresh decision id of its own.
fn fold_cut_off(state: &mut State, c: &CutOffRecorded) -> Result<(), FoldError> {
    crate::programme::call(state, c.call).ok_or(FoldError::UnknownEntity)?;
    if c.rules < RulesVersion::M4 {
        if !state.used_ids.insert(UsedId::Decision(c.decision)) {
            return Err(FoldError::DuplicateId);
        }
        return Ok(());
    }
    let rounds = &mut state.calls.rounds;
    if rounds.open.get(&c.call) != Some(&c.decision) {
        return Err(FoldError::Inconsistent);
    }
    let r = rounds
        .rounds
        .get_mut(&c.decision)
        .ok_or(FoldError::UnknownEntity)?;
    if r.status != RoundStatus::Open {
        return Err(FoldError::Inconsistent);
    }
    r.status = RoundStatus::Recorded;
    rounds.open.remove(&c.call);
    Ok(())
}

// ---------------------------------------------------------------------------
// IRC review (rows 10 and 11, R-IR-01, R-IR-02, I-18, R-NG-02, NOTE 7)
// ---------------------------------------------------------------------------

/// A checked IRC review.
struct Review {
    actor: AccountId,
    proposal: ProposalId,
    assignment: AssignmentId,
    verdict: IrcVerdict,
    /// Whether a validation completes the review: at least P-15 active IRC
    /// assignments of the current call, every one validated, and none
    /// awaiting its declaration (R-IR-01).
    completes: bool,
    /// Whether the IRC member repeats an earlier validation of the round to
    /// complete the review, so no new review is recorded.
    rerun: bool,
    /// The gate's questions, asked when a validation completes the review
    /// of the proposal itself (state-machine NOTE 14).
    gate: Option<Gate>,
    /// The amendment under review, for a review on an amendment
    /// assignment (R-IR-04). Such a review never moves the proposal.
    amendment: Option<AmendmentId>,
}

/// The questions of the IRC_REVIEW to NEGOTIATION gate (state-machine
/// NOTE 14, R-ID-04, I-18). The gate admits the proposal when either holds.
struct Gate {
    /// Does the lead have an effective verified over-18 attestation at the
    /// deadline? A yes clears the minor flag.
    adult: Query,
    /// Does the proposal have a verified guardian consent record?
    consent: Query,
}

/// The gate's questions for `proposal`. The deadline is that of the call
/// in which the proposal passes IRC review, which is the later call after
/// a re-entry (NOTE 8, NOTE 14, ADR-008 "Which deadline", decided
/// 2026-10-29).
fn gate_questions(state: &State, proposal: ProposalId) -> Result<Gate, Refusal> {
    Ok(Gate {
        adult: crate::proposal::draft::adult_query(state, proposal).ok_or_else(unknown)?,
        consent: Query::HasGuardianConsent { proposal },
    })
}

/// Checks an IRC review against the state: the IRC assignee's own active
/// assignment in the current call, IRC_REVIEW, no concern raised in the
/// round, and no review of this assignment yet.
///
/// A validated IRC member may repeat the validation once the review would
/// complete, for example after a vault release or once a guardian consent
/// exists. The repeat records the entry into NEGOTIATION only, so a named
/// human records the decision (R-IR-01, R-LA-03, NOTE 13). Any other repeat
/// is refused.
fn plan_review(state: &State, cmd: &Command, ctx: &Ctx) -> Result<Review, Refusal> {
    let Command::RecordIrcReview {
        assignment,
        verdict,
    } = cmd
    else {
        return Err(life::wrong_state());
    };
    let actor = crate::policy::actor_account(ctx)?;
    let a = crate::assignment::reviewer_basis(state, actor, *assignment, ctx.now)?;
    if let AssignmentKind::Amendment(id) = a.kind {
        crate::amendment::check_irc_review(state, id, a.proposal, *assignment)?;
        return Ok(Review {
            actor,
            proposal: a.proposal,
            assignment: *assignment,
            verdict: *verdict,
            completes: false,
            rerun: false,
            gate: None,
            amendment: Some(id),
        });
    }
    if a.kind != AssignmentKind::Irc {
        return Err(Refusal::new(RuleRef::Actor, RefusalReason::WrongActor));
    }
    let proposal = a.proposal;
    if life::state_of(state, proposal)? != StateTag::IrcReview {
        return Err(life::wrong_state());
    }
    let facts = life::facts(state, proposal);
    let guard = Refusal::new(RuleRef::Rir01, RefusalReason::GuardFailed);
    if facts.is_some_and(|f| f.concern.is_some()) {
        return Err(guard);
    }
    let rerun = match (facts.and_then(|f| f.irc.get(assignment)), verdict) {
        (None, _) => false,
        (Some(true), IrcVerdict::Validate) => true,
        (Some(_), _) => return Err(guard),
    };
    let completes = match verdict {
        IrcVerdict::Validate => irc_completes(state, proposal, Some(*assignment), &BTreeSet::new()),
        IrcVerdict::Concern(_) => false,
    };
    if rerun && !completes {
        return Err(guard);
    }
    let gate = if completes {
        Some(gate_questions(state, proposal)?)
    } else {
        None
    };
    Ok(Review {
        actor,
        proposal,
        assignment: *assignment,
        verdict: *verdict,
        completes,
        rerun,
        gate,
        amendment: None,
    })
}

/// The vault questions of an IRC review: `HasConflict` for the IRC member,
/// and the gate's questions when the validation would take the proposal
/// into NEGOTIATION (state-machine NOTE 14).
fn review_queries(state: &State, r: &Review) -> Vec<Query> {
    let mut out = vec![conflict_query(state, r.actor, r.proposal)];
    if let Some(g) = &r.gate {
        out.push(g.adult.clone());
        out.push(g.consent.clone());
    }
    out
}

/// The records of an IRC review.
///
/// - A validation that completes the review takes the proposal into
///   NEGOTIATION, unless the proposal is minor-flagged and has no verified
///   guardian consent (state-machine NOTE 14). The flag is set unless the
///   lead has an effective verified over-18 attestation at the deadline.
///   A minor-flagged proposal stays in IRC_REVIEW with the validation
///   recorded. A validated member repeats the validation to record the
///   entry once the consent is effective. Until then the repeat is refused.
/// - A concern goes to the applicant through the outbox. With a later call
///   of the programme published it defers the proposal, and otherwise the
///   proposal waits in IRC_REVIEW for the programme manager's decline.
fn decide_review(
    state: &State,
    r: &Review,
    ctx: &Ctx,
    answers: &Answers,
) -> Result<Vec<Record>, Refusal> {
    reviewer_act(state, r.actor, r.assignment, ctx.now, answers)?.require_proposal(r.proposal)?;
    let mut out = Vec::new();
    for q in review_queries(state, r) {
        record_answer(&mut out, &q, answers)?;
    }
    // State-machine NOTE 14: the gate admits the proposal on the lead's
    // attestation or on its guardian consent. A missing answer refuses the
    // command (overview NOTE 2).
    let admitted = match &r.gate {
        Some(g) => answer(answers, &g.adult)?.holds || answer(answers, &g.consent)?.holds,
        None => true,
    };
    if !admitted && r.rerun {
        return Err(Refusal::new(RuleRef::I18, RefusalReason::VaultRefused));
    }
    if !r.rerun {
        out.push(Record::IrcReviewRecorded {
            assignment: r.assignment,
            verdict: r.verdict,
        });
    }
    // The review of an amendment leaves the proposal state unchanged (Q18).
    if r.amendment.is_some() {
        return Ok(out);
    }
    match r.verdict {
        IrcVerdict::Validate if r.completes && admitted => out.push(transition(
            r.proposal,
            StateTag::IrcReview,
            StateTag::Negotiation,
            Row::IrcReviewToNegotiation,
            ctx.actor,
            None,
        )),
        IrcVerdict::Validate => {}
        IrcVerdict::Concern(concern) => {
            out.push(Record::OutboxEnqueued(OutboxEvent::IrcConcern {
                proposal: r.proposal,
                concern,
            }));
            let call = life::current_call(state, r.proposal)?;
            if crate::proposal::deferral::future_call_exists(state, call) {
                out.push(Record::DeferralRecorded {
                    proposal: r.proposal,
                    from_call: call,
                    left: ReentryStage::IrcReview,
                });
                out.push(transition(
                    r.proposal,
                    StateTag::IrcReview,
                    StateTag::Deferred,
                    Row::IrcReviewToDeferred,
                    ctx.actor,
                    None,
                ));
            }
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Engine entry points of this lane, called by `crate::engine`.
// ---------------------------------------------------------------------------

/// The vault questions of the decision commands: knock-out, admission, stage 1
/// close, ranking after stage 2, cut-off and IRC review.
pub(crate) fn queries(state: &State, cmd: &Command, ctx: &Ctx) -> Result<Vec<Query>, Refusal> {
    match cmd {
        Command::RecordKnockOut { proposal, .. } => {
            let actor = plan_knock_out(state, cmd, ctx)?;
            Ok(vec![conflict_query(state, actor, *proposal)])
        }
        Command::AdmitToStage1 { .. } => Ok(admit_queries(state, &plan_admit(state, cmd, ctx)?)),
        Command::CloseStage1 { .. } => close_queries(state, &plan_close(state, cmd, ctx)?),
        Command::RankAfterStage2 { .. } => {
            let (actor, proposal, _) = plan_rank(state, cmd, ctx)?;
            let mut out = vec![conflict_query(state, actor, proposal)];
            out.extend(ranking_queries(state, proposal)?);
            Ok(out)
        }
        Command::OpenCutOffRound { .. }
        | Command::CastBallot { .. }
        | Command::DelegateVote { .. }
        | Command::RecordCutOff { .. } => Ok(round_queries(state, &plan_round(state, cmd, ctx)?)),
        Command::RecordIrcReview { .. } => {
            Ok(review_queries(state, &plan_review(state, cmd, ctx)?))
        }
        // The dispatcher sends no other command here.
        _ => Err(life::wrong_state()),
    }
}

/// The records of the decision commands.
pub(crate) fn decide(
    state: &State,
    cmd: &Command,
    ctx: &Ctx,
    answers: &Answers,
) -> Result<Vec<Record>, Refusal> {
    match cmd {
        Command::RecordKnockOut { .. } => decide_knock_out(state, cmd, ctx, answers),
        Command::AdmitToStage1 { .. } => {
            decide_admit(state, &plan_admit(state, cmd, ctx)?, ctx, answers)
        }
        Command::CloseStage1 { .. } => {
            decide_close(state, &plan_close(state, cmd, ctx)?, ctx, answers)
        }
        Command::RankAfterStage2 { .. } => decide_rank(state, cmd, ctx, answers),
        Command::OpenCutOffRound { .. }
        | Command::CastBallot { .. }
        | Command::DelegateVote { .. }
        | Command::RecordCutOff { .. } => decide_round(state, cmd, ctx, answers),
        Command::RecordIrcReview { .. } => {
            decide_review(state, &plan_review(state, cmd, ctx)?, ctx, answers)
        }
        // The dispatcher sends no other command here.
        _ => Err(life::wrong_state()),
    }
}

/// Folds a decision record. The fold checks structure only: the entities
/// exist, a decision id is used once, and each stage result is recorded
/// once in the state it belongs to. It never re-runs a guard.
pub(crate) fn apply(
    state: &mut State,
    seq: Seq,
    at: Timestamp,
    record: &Record,
) -> Result<(), FoldError> {
    let _ = (seq, at);
    let in_state =
        |state: &State, p: ProposalId, s: StateTag| match crate::proposal::intake::proposal_state(
            state, p,
        ) {
            None => Err(FoldError::UnknownEntity),
            Some(x) if x == s => Ok(()),
            Some(_) => Err(FoldError::Inconsistent),
        };
    match record {
        Record::KnockOutRecorded {
            decision,
            proposal,
            outcomes,
            ..
        } => {
            let passed = outcomes.iter().all(|o| o.passed);
            in_state(state, *proposal, StateTag::Submitted)?;
            if life::facts(state, *proposal).is_some_and(|f| f.knock_out.is_some()) {
                return Err(FoldError::Inconsistent);
            }
            if !state.used_ids.insert(UsedId::Decision(*decision)) {
                return Err(FoldError::DuplicateId);
            }
            life::facts_mut(state, *proposal)?.knock_out = Some(passed);
            Ok(())
        }
        Record::Stage1Closed(c) => {
            in_state(state, c.proposal, StateTag::Stage1)?;
            let f = life::facts_mut(state, c.proposal)?;
            if f.closed.is_some() {
                return Err(FoldError::Inconsistent);
            }
            f.closed = Some(c.clone());
            Ok(())
        }
        Record::EffectiveScoreSet(e) => {
            in_state(state, e.proposal, StateTag::Stage2)?;
            let plan =
                crate::proposal::intake::plan(state, e.plan).ok_or(FoldError::UnknownEntity)?;
            if plan.proposal != e.proposal {
                return Err(FoldError::Inconsistent);
            }
            let f = life::facts_mut(state, e.proposal)?;
            if f.effective.is_some() {
                return Err(FoldError::Inconsistent);
            }
            f.effective = Some(e.clone());
            Ok(())
        }
        Record::CutOffRecorded(c) => fold_cut_off(state, c),
        Record::CutOffRoundOpened { .. }
        | Record::BallotCast { .. }
        | Record::VoteDelegated { .. } => fold_round(state, record),
        Record::IrcReviewRecorded {
            assignment,
            verdict,
        } => {
            let a = state
                .review
                .get(*assignment)
                .ok_or(FoldError::UnknownEntity)?;
            let proposal = a.proposal;
            // The review of an amendment is the amendment's, and never
            // touches the proposal's own IRC round (R-IR-04).
            if let AssignmentKind::Amendment(id) = a.kind {
                let validated = matches!(verdict, IrcVerdict::Validate);
                return crate::amendment::fold_irc_review(state, id, *assignment, validated);
            }
            in_state(state, proposal, StateTag::IrcReview)?;
            let f = life::facts_mut(state, proposal)?;
            if f.irc.contains_key(assignment) {
                return Err(FoldError::Inconsistent);
            }
            f.irc
                .insert(*assignment, matches!(verdict, IrcVerdict::Validate));
            if let IrcVerdict::Concern(t) = verdict {
                f.concern = Some(*t);
            }
            Ok(())
        }
        _ => Err(FoldError::Inconsistent),
    }
}

/// Whether the IRC review of `proposal` completes once `validating`
/// validates and the IRC assignments in `released` are released (R-IR-01).
///
/// - The proposal is in IRC_REVIEW with no concern raised in the round.
/// - At least P-15 active IRC assignments of the current call remain, and
///   every one validated.
/// - No other IRC assignment of the current call awaits its declaration.
///   Such an assignment is outstanding (design 3.2), which is the strict
///   reading reported to Daniel.
fn irc_completes(
    state: &State,
    proposal: ProposalId,
    validating: Option<AssignmentId>,
    released: &BTreeSet<AssignmentId>,
) -> bool {
    if life::state_of(state, proposal).ok() != Some(StateTag::IrcReview) {
        return false;
    }
    let (Ok(call), Ok(values)) = (
        life::current_call(state, proposal),
        life::governing(state, proposal),
    ) else {
        return false;
    };
    let facts = life::facts(state, proposal);
    if facts.is_some_and(|f| f.concern.is_some()) {
        return false;
    }
    let validated = |id: &AssignmentId| {
        validating == Some(*id) || facts.is_some_and(|f| f.irc.get(id) == Some(&true))
    };
    let remaining: BTreeSet<AssignmentId> =
        life::active_assignments(state, proposal, call, AssignmentKind::Irc)
            .difference(released)
            .copied()
            .collect();
    let awaiting = state.review.assignments().any(|(id, a)| {
        a.proposal == proposal
            && a.call == call
            && a.kind == AssignmentKind::Irc
            && a.status == crate::assignment::AssignmentStatus::AwaitingDeclaration
            && !released.contains(&id)
            && !state.review.conflict_fact(a.reviewer, proposal)
    });
    !awaiting && remaining.len() >= usize::from(values.p15.get()) && remaining.iter().all(validated)
}

/// The vault questions this lane needs for its contribution to the batch of
/// a command that another lane owns. This lane contributes nothing, so it
/// asks none.
pub(crate) fn contribute_queries(
    state: &crate::state::State,
    cmd: &crate::command::Command,
    ctx: &crate::command::Ctx,
) -> Result<Vec<crate::oracle::Query>, crate::refusal::Refusal> {
    let _ = (state, cmd, ctx);
    Ok(Vec::new())
}

/// The records this lane adds to the batch of a command that another lane
/// owns (`crate::engine` module docs). It adds none.
///
/// IRC_REVIEW to NEGOTIATION is the IRC members' row, computed only by
/// `RecordIrcReview` with a conflict-free actor (R-IR-01, R-LA-03, I-03).
/// So a batch that releases an IRC assignment never records the entry,
/// whoever sends it: an `Unassign` by the coordinator, an `EndRole` by a
/// tenant admin, or a conflicted declaration by the IRC member itself. The
/// proposal stays in IRC_REVIEW, and a validated IRC member records the
/// entry by repeating the validation once the review would complete.
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
/// proposal's original call, and for a round command that of the round's call.
pub(crate) fn governing_policy(
    state: &crate::state::State,
    cmd: &crate::command::Command,
) -> Result<crate::engine::PolicyScope, crate::refusal::Refusal> {
    let proposal = match cmd {
        Command::RecordKnockOut { proposal, .. }
        | Command::AdmitToStage1 { proposal, .. }
        | Command::CloseStage1 { proposal }
        | Command::RankAfterStage2 { proposal } => *proposal,
        Command::RecordIrcReview { assignment, .. } => state
            .review
            .get(*assignment)
            .map(|a| a.proposal)
            .ok_or_else(unknown)?,
        Command::OpenCutOffRound { call, .. } => {
            return Ok(crate::engine::PolicyScope::Call(*call));
        }
        Command::CastBallot { round, .. }
        | Command::DelegateVote { round, .. }
        | Command::RecordCutOff { round } => {
            return round_call(state, *round).map(crate::engine::PolicyScope::Call);
        }
        // The dispatcher sends no other command here.
        _ => return Err(life::wrong_state()),
    };
    crate::proposal::draft::proposal_call(state, proposal)
        .map(crate::engine::PolicyScope::Call)
        .ok_or_else(unknown)
}
