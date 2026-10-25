//! Assignments, conflicts, handles and reads (design section 2.7, I-02, I-03, I-34, I-35, I-36).
//!
//! Owned by lane L-REV (docs/handoff/m2-design.md section 10). The rules
//! come from `SPEC/02-domain/roles-and-sod.md` (Conflict declarations,
//! Reviewer assignment, Anonymous reviewer handles),
//! `SPEC/02-domain/invariants.md` and `SPEC/01-requirements/functional.md`
//! (R-CF-01 to R-CF-04, R-AN-01, R-AC-01).
//!
//! - [`ReviewState`] keeps every assignment ever made with its status,
//!   the conflict facts, the proposal-level no-conflict declarations, every
//!   handle ever issued in the cell and the ranking summaries.
//! - A conflict fact for an account and a proposal is a conflicted
//!   declaration, on an assignment or at proposal level, or a detected
//!   conflict. It is permanent for that proposal across calls.
//! - [`ReviewerAct`] is the only proof that a read or a reviewer act may
//!   proceed (I-03). Only `reviewer_act`, `reviewer_act_on` and
//!   `cleared_act` build one. Each re-checks a fresh `HasConflict` answer
//!   at the state's epoch, and none builds one on a terminal proposal.
//!
//! Commands this lane owns:
//!
//! - `Assign`, by an active FSTP coordinator (interim actor, design 2.7).
//!   A reviewer assignment needs an active committee member binding and
//!   SUBMITTED, STAGE1 or STAGE2. An IRC assignment needs an active IRC
//!   member binding and IRC_REVIEW. Amendment assignments are lane
//!   L-MONEY's. The assignee holds no unreleased assignment of the other
//!   side of I-02 in the same programme, no conflict fact on the proposal,
//!   and the vault answers `HasConflict` false for the assignee. Under
//!   P-11 anonymous the handle was never issued in the cell (R-AN-01).
//!   Under P-11 named no handle is given. A reviewer assignment keeps I-34
//!   and I-35 when the committee binding records an organisation.
//! - `Unassign`, by an active FSTP coordinator, of an unreleased assignment.
//! - `DeclareConflict` on an assignment by its assignee while it awaits
//!   the declaration. A conflict found later is declared on the active
//!   assignment too. A declaration may also be on a proposal, by the FSTP
//!   coordinator or, under P-10 "all committee members", by a committee
//!   member (R-CF-02). A conflicted declaration releases the declarer's
//!   assignments on the proposal in the same batch. A notifiable one also
//!   enqueues the coordinator's notification draft (R-CF-04).
//! - `ReadContent` through [`crate::visibility`]: the applicant team
//!   reads its own proposal, and everyone else needs a [`ReviewerAct`].
//! - `RecordRankingSummary` by an assigned reviewer with a [`ReviewerAct`],
//!   in STAGE1, STAGE2 or RANKED.
//!
//! Contributions to other lanes' batches:
//!
//! - `VaultChanged`: every unreleased assignment and every proposal-level
//!   clearance without a conflict fact is rechecked with `HasConflict`.
//!   A positive answer records a `ConflictDetected` and releases the
//!   account's assignments on that proposal (I-03, R-CF-02). The recheck
//!   covers every tracked pair, not only the accounts the change query
//!   lists, so a silent vault change cannot leave an assignment active.
//! - `VaultChanged` also asks `DeclaresAffiliationOnList` for every
//!   unreleased reviewer assignment whose organisation has a P-38 list. A
//!   positive answer releases the assignment (I-35, enforcement point 3).
//!   An `EditPolicy` that changes P-38 asks the same over the new lists.
//! - `VaultChanged` records a notifiable conflict for every account that
//!   held an assignment or a clearance on a proposal, when the batch voids
//!   a Receiving binding of that proposal under I-06 and the vault answers
//!   that the two accounts share a verified identity (R-CF-04, Identity
//!   discovery). Released assignments count, since their scores stay.
//! - `AddTeamMember` and `AddGuardian` recheck every tracked pair of the
//!   proposal against the team with the new account, and I-35 against the
//!   new team. A positive answer records the detection and the releases
//!   in the same batch (enforcement point 1).
//! - A batch that ends, suspends or voids a committee member or IRC member
//!   binding releases the assignments that rest on it, unless the account
//!   holds another binding of that role in the programme (I-02).
//! - `CreateDraft`, `AddTeamMember` and `AddGuardian` are refused under
//!   I-36 when the account reviewed a proposal that is under evaluation in
//!   the binding's call. A DEFERRED proposal is under evaluation in the
//!   next published call too. P-12 does not matter.
//!
//! Readings of this lane, reported to Daniel:
//!
//! - "Reviewed" for I-36 means any reviewer or IRC assignment on the
//!   proposal, released or not.
//! - P-03, P-10, P-11 and P-39 come from the frozen policy of the
//!   proposal's original call, which keeps governing it after re-entry.
//! - A conflicted FSTP coordinator may still assign on that proposal.
//!   Assignment is not among the acts that the Conflict declarations
//!   section bars, and barring it would block every reassignment by the
//!   only coordinator. To be confirmed by Daniel.
//! - An I-35 release has the cause `DetectedConflict` and records no
//!   conflict fact, since the proximity rule bars the assignment only.
//!   The codec enumerates the release causes, so a cause of its own needs
//!   a change outside this lane.
//!
//! Gap reported to the lead: the roster keeps no organisation per binding,
//! so `committee_organisation` finds none, and I-34 and I-35 cannot be
//! checked until lane L-SOD keeps the field (`SPEC/02-domain/roles-and-sod.md`
//! Reviewer assignment NOTE). With the field, `committee_organisation`
//! returns `state.roster.binding(binding)?.organisation`.

use std::collections::{BTreeMap, BTreeSet};

use crate::command::{Command, Ctx, DeclarationSubject};
use crate::engine::{FoldError, PolicyScope};
use crate::id::{
    AccountId, AmendmentId, AssignmentId, CallId, Handle, OrganisationId, ProgrammeId, ProposalId,
    TextRef, VaultEpoch,
};
use crate::oracle::{Answer, Answers, Query};
use crate::policy::{FrozenValues, ReadAccess, ReviewerAnonymity};
use crate::proposal::intake::{current_call, proposal_state};
use crate::record::{
    Assigned, AssignmentReleased, ConflictDeclared, ConflictDetected, ContentRead, Declared,
    OutboxEvent, Record,
};
use crate::refusal::{Refusal, RefusalReason, RuleRef};
use crate::roles::{BindingStatus, Group, Role};
use crate::rules::StateTag;
use crate::state::{State, UsedId};
use crate::time::Timestamp;

/// What an assignment is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AssignmentKind {
    /// An assigned reviewer over a committee member binding.
    Reviewer,
    /// An IRC review over an IRC member binding.
    Irc,
    /// An IRC review of an amendment.
    Amendment(AmendmentId),
}

impl AssignmentKind {
    /// The role whose binding the assignment rests on.
    pub const fn role(self) -> Role {
        match self {
            AssignmentKind::Reviewer => Role::CommitteeMember,
            AssignmentKind::Irc | AssignmentKind::Amendment(_) => Role::IrcMember,
        }
    }

    /// Whether the assignment is on the IRC side of I-02.
    pub const fn irc_side(self) -> bool {
        !matches!(self, AssignmentKind::Reviewer)
    }

    /// Whether the assignment counts as having reviewed the proposal (I-36).
    pub const fn reviews_proposal(self) -> bool {
        matches!(self, AssignmentKind::Reviewer | AssignmentKind::Irc)
    }
}

/// Why an assignment was released.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReleaseCause {
    /// The assignee declared a conflict (R-CF-02).
    DeclaredConflict,
    /// The vault detected a conflict (I-03), or a team affiliation on the
    /// proximity list of the reviewer's organisation (I-35).
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

/// Where an assignment stands (design section 2.7).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AssignmentStatus {
    /// Made, and awaiting the assignee's declaration (R-CF-02).
    AwaitingDeclaration,
    /// The assignee declared no conflict.
    Active,
    /// Released, for good.
    Released(ReleaseCause),
}

/// One assignment of the projection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Assignment {
    /// The proposal.
    pub proposal: ProposalId,
    /// The call the assignment was made in (NOTE 8).
    pub call: CallId,
    /// The assignee.
    pub reviewer: AccountId,
    /// The kind.
    pub kind: AssignmentKind,
    /// The handle under P-11 anonymous.
    pub handle: Option<Handle>,
    /// The status.
    pub status: AssignmentStatus,
}

impl Assignment {
    /// Whether the assignment is not released.
    pub const fn unreleased(&self) -> bool {
        !matches!(self.status, AssignmentStatus::Released(_))
    }

    /// Whether the assignee declared no conflict and the assignment is not released.
    pub const fn active(&self) -> bool {
        matches!(self.status, AssignmentStatus::Active)
    }
}

/// The title, neutral summary and rationale that the committee ranking
/// view shows, as the assigned reviewers last recorded them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RankingSummary {
    /// The writing reviewer's assignment.
    pub assignment: AssignmentId,
    /// The title.
    pub title: TextRef,
    /// The neutral summary.
    pub neutral_summary: TextRef,
    /// The reviewers' rationale.
    pub rationale: TextRef,
}

/// Review part of the projection: assignments, conflict facts, issued
/// handles and ranking summaries. Reviewed-by facts (I-36) are the
/// assignments themselves, which are never removed.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ReviewState {
    /// Every assignment ever made.
    assignments: BTreeMap<AssignmentId, Assignment>,
    /// Conflict facts, declared or detected, by account and proposal.
    facts: BTreeSet<(AccountId, ProposalId)>,
    /// Proposal-level no-conflict declarations.
    cleared: BTreeSet<(AccountId, ProposalId)>,
    /// Every handle ever issued in the cell (R-AN-01).
    handles: BTreeSet<Handle>,
    /// The latest ranking summary per proposal.
    summaries: BTreeMap<ProposalId, RankingSummary>,
}

impl ReviewState {
    /// The review state before any record.
    pub(crate) const fn genesis() -> ReviewState {
        ReviewState {
            assignments: BTreeMap::new(),
            facts: BTreeSet::new(),
            cleared: BTreeSet::new(),
            handles: BTreeSet::new(),
            summaries: BTreeMap::new(),
        }
    }

    /// The assignment `id`.
    pub fn get(&self, id: AssignmentId) -> Option<&Assignment> {
        self.assignments.get(&id)
    }

    /// Every assignment ever made, by id.
    pub fn assignments(&self) -> impl Iterator<Item = (AssignmentId, &Assignment)> {
        self.assignments.iter().map(|(id, a)| (*id, a))
    }

    /// Whether a conflict fact exists for `account` on `proposal`.
    pub fn conflict_fact(&self, account: AccountId, proposal: ProposalId) -> bool {
        self.facts.contains(&(account, proposal))
    }

    /// Whether `account` declared no conflict on `proposal` at proposal level.
    pub fn cleared(&self, account: AccountId, proposal: ProposalId) -> bool {
        self.cleared.contains(&(account, proposal))
    }

    /// Whether `handle` was ever issued in the cell.
    pub fn handle_issued(&self, handle: Handle) -> bool {
        self.handles.contains(&handle)
    }

    /// The latest ranking summary of `proposal`.
    pub fn summary(&self, proposal: ProposalId) -> Option<&RankingSummary> {
        self.summaries.get(&proposal)
    }

    /// Whether `account` ever held a reviewer or IRC assignment on `proposal` (I-36).
    pub fn reviewed(&self, account: AccountId, proposal: ProposalId) -> bool {
        self.assignments
            .values()
            .any(|a| a.reviewer == account && a.proposal == proposal && a.kind.reviews_proposal())
    }

    /// The unreleased assignments of `account`.
    fn unreleased_of(
        &self,
        account: AccountId,
    ) -> impl Iterator<Item = (AssignmentId, &Assignment)> {
        self.assignments
            .iter()
            .filter(move |(_, a)| a.reviewer == account && a.unreleased())
            .map(|(id, a)| (*id, a))
    }

    /// The quorum's view of the assignment `id` (`crate::scoring`).
    ///
    /// The stub `AssignmentFacts` implementation in `scoring.rs` can
    /// delegate to this and the next method once its owner removes the stub.
    #[allow(
        dead_code,
        reason = "the AssignmentFacts stub in scoring.rs is replaced later"
    )]
    pub(crate) fn quorum_fact(&self, id: AssignmentId) -> Option<crate::scoring::AssignmentFact> {
        self.assignments
            .get(&id)
            .map(|a| crate::scoring::AssignmentFact {
                proposal: a.proposal,
                call: a.call,
                reviewer: a.reviewer,
                kind: a.kind,
                active: a.active(),
            })
    }

    /// The active reviewer assignments to `proposal` made in `call` (NOTE 3).
    #[allow(
        dead_code,
        reason = "the AssignmentFacts stub in scoring.rs is replaced later"
    )]
    pub(crate) fn active_reviewers_in(
        &self,
        proposal: ProposalId,
        call: CallId,
    ) -> BTreeSet<AssignmentId> {
        self.assignments
            .iter()
            .filter(|(_, a)| {
                a.proposal == proposal
                    && a.call == call
                    && a.kind == AssignmentKind::Reviewer
                    && a.active()
            })
            .map(|(id, _)| *id)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// The ReviewerAct witness
// ---------------------------------------------------------------------------

/// The only proof a read or reviewer act may proceed (I-03, design section 2.7).
///
/// Built only by `reviewer_act`, over an active assignment, and by
/// `cleared_act`, over a proposal-level no-conflict declaration. Both
/// check that no conflict fact exists and that the vault answered
/// `HasConflict` false at the state's epoch. Its fields are private, so
/// code outside the crate cannot build one:
///
/// ```compile_fail
/// use fstp_domain::assignment::ReviewerAct;
/// use fstp_domain::id::{AccountId, ProposalId, VaultEpoch};
/// let _forged = ReviewerAct {
///     account: AccountId::from_raw(1),
///     proposal: ProposalId::from_raw(1),
///     assignment: None,
///     epoch: VaultEpoch::GENESIS,
/// };
/// ```
///
/// The twin below differs only in the forbidden line, so the pair cannot
/// pass because of a typo in the shared text:
///
/// ```no_run
/// use fstp_domain::assignment::ReviewerAct;
/// use fstp_domain::id::{AccountId, ProposalId, VaultEpoch};
/// let _read = |act: &ReviewerAct| (act.account(), act.proposal(), act.assignment(), act.epoch());
/// let _ = (AccountId::from_raw(1), ProposalId::from_raw(1), VaultEpoch::GENESIS);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ReviewerAct {
    account: AccountId,
    proposal: ProposalId,
    assignment: Option<AssignmentId>,
    epoch: VaultEpoch,
}

impl ReviewerAct {
    /// The acting account.
    pub fn account(&self) -> AccountId {
        self.account
    }

    /// The proposal acted on.
    pub fn proposal(&self) -> ProposalId {
        self.proposal
    }

    /// The assignment the act rests on, or `None` for an act under a
    /// proposal-level declaration.
    pub fn assignment(&self) -> Option<AssignmentId> {
        self.assignment
    }

    /// The vault epoch of the fresh `HasConflict` answer.
    pub fn epoch(&self) -> VaultEpoch {
        self.epoch
    }

    /// Refuses unless the act is on `proposal`. A command that names both a
    /// proposal and an assignment calls it after [`reviewer_act`].
    #[allow(dead_code, reason = "lanes L-LIFE and L-MONEY call it")]
    pub(crate) fn require_proposal(&self, proposal: ProposalId) -> Result<(), Refusal> {
        if self.proposal == proposal {
            Ok(())
        } else {
            Err(invalid())
        }
    }
}

/// The `HasConflict` question for `account` and the team of `proposal`:
/// every account with a held Receiving binding on it (design 4.2).
pub(crate) fn conflict_query(state: &State, account: AccountId, proposal: ProposalId) -> Query {
    Query::HasConflict {
        reviewer: account,
        team: state.roster.receiving_accounts(proposal),
    }
}

/// Checks the fresh vault answer that `account` has no conflict with the
/// team of `proposal`, at the state's epoch. Returns that epoch.
fn fresh_no_conflict(
    state: &State,
    account: AccountId,
    proposal: ProposalId,
    answers: &Answers,
) -> Result<VaultEpoch, Refusal> {
    match answers.get(&conflict_query(state, account, proposal)) {
        None => Err(Refusal::new(
            RuleRef::FactsIncomplete,
            RefusalReason::AnswerMissing,
        )),
        Some(a) if a.epoch != state.epoch => Err(Refusal::new(
            RuleRef::StaleFacts,
            RefusalReason::AnswerStale,
        )),
        Some(a) if a.holds => Err(Refusal::new(RuleRef::I03, RefusalReason::VaultRefused)),
        Some(a) => Ok(a.epoch),
    }
}

/// The structural part of [`reviewer_act`]: the assignment is the
/// account's, active, made in the proposal's current call, over an active
/// binding of its role, and no conflict fact exists. The proposal is not
/// in a terminal state. Returns the assignment.
pub(crate) fn reviewer_basis(
    state: &State,
    account: AccountId,
    assignment: AssignmentId,
    now: Timestamp,
) -> Result<&Assignment, Refusal> {
    let a = state.review.get(assignment).ok_or_else(unknown)?;
    if a.reviewer != account {
        return Err(Refusal::new(RuleRef::Actor, RefusalReason::WrongActor));
    }
    if proposal_state(state, a.proposal).is_none_or(StateTag::is_terminal) {
        return Err(wrong_state());
    }
    if !a.active() || current_call(state, a.proposal) != Some(a.call) {
        return Err(Refusal::new(RuleRef::Actor, RefusalReason::BindingInactive));
    }
    let programme = programme_of(state, a.proposal)?;
    if state
        .roster
        .active_binding(account, a.kind.role(), programme, now)
        .is_none()
    {
        return Err(Refusal::new(RuleRef::Actor, RefusalReason::BindingInactive));
    }
    if state.review.conflict_fact(account, a.proposal) {
        return Err(Refusal::new(RuleRef::I03, RefusalReason::GuardFailed));
    }
    Ok(a)
}

/// The [`ReviewerAct`] of `account` over `assignment` at `now`: an active
/// assignment of the account, in the proposal's current call, over an
/// active binding of its role, with no conflict fact and a fresh
/// `HasConflict` answer of false (I-03). Later lanes build their reviewer
/// acts here: scores, corrections, questions, amounts, line acceptance and
/// IRC reviews. They ask [`conflict_query`] in their `queries`.
pub(crate) fn reviewer_act(
    state: &State,
    account: AccountId,
    assignment: AssignmentId,
    now: Timestamp,
    answers: &Answers,
) -> Result<ReviewerAct, Refusal> {
    let a = reviewer_basis(state, account, assignment, now)?;
    let epoch = fresh_no_conflict(state, account, a.proposal, answers)?;
    Ok(ReviewerAct {
        account,
        proposal: a.proposal,
        assignment: Some(assignment),
        epoch,
    })
}

/// The assignment of `kind` that `account` holds on `proposal` and that
/// passes [`reviewer_basis`] at `now`, if any.
pub(crate) fn qualifying_assignment(
    state: &State,
    account: AccountId,
    proposal: ProposalId,
    kind: AssignmentKind,
    now: Timestamp,
) -> Option<AssignmentId> {
    state
        .review
        .assignments
        .iter()
        .filter(|(_, a)| a.reviewer == account && a.proposal == proposal && a.kind == kind)
        .find(|(id, _)| reviewer_basis(state, account, **id, now).is_ok())
        .map(|(id, _)| *id)
}

/// The [`ReviewerAct`] of `account` on `proposal` through its qualifying
/// assignment of `kind` (see [`reviewer_act`]). It refuses when the
/// account holds no such assignment on that proposal. A command that names
/// a proposal but no assignment, such as `DetermineAmount`, builds its act here.
#[allow(dead_code, reason = "lanes L-LIFE and L-MONEY call it")]
pub(crate) fn reviewer_act_on(
    state: &State,
    account: AccountId,
    proposal: ProposalId,
    kind: AssignmentKind,
    now: Timestamp,
    answers: &Answers,
) -> Result<ReviewerAct, Refusal> {
    let id = qualifying_assignment(state, account, proposal, kind, now)
        .ok_or(Refusal::new(RuleRef::Actor, RefusalReason::BindingInactive))?;
    reviewer_act(state, account, id, now, answers)
}

/// The [`ReviewerAct`] of `account` on `proposal` under a proposal-level
/// no-conflict declaration: the account holds an active binding of `role`,
/// declared no conflict on the proposal, has no conflict fact on it, and
/// the vault answers `HasConflict` false now (I-03). The proposal is not
/// in a terminal state. The FSTP coordinator's knock-out read and check
/// use it, and so do committee reads under P-10 "all committee members".
pub(crate) fn cleared_act(
    state: &State,
    account: AccountId,
    proposal: ProposalId,
    role: Role,
    now: Timestamp,
    answers: &Answers,
) -> Result<ReviewerAct, Refusal> {
    if proposal_state(state, proposal).is_none_or(StateTag::is_terminal) {
        return Err(wrong_state());
    }
    let programme = programme_of(state, proposal)?;
    if state
        .roster
        .active_binding(account, role, programme, now)
        .is_none()
    {
        return Err(Refusal::new(RuleRef::Actor, RefusalReason::BindingInactive));
    }
    if state.review.conflict_fact(account, proposal) {
        return Err(Refusal::new(RuleRef::I03, RefusalReason::GuardFailed));
    }
    if !state.review.cleared(account, proposal) {
        return Err(Refusal::new(RuleRef::Rcf02, RefusalReason::GuardFailed));
    }
    let epoch = fresh_no_conflict(state, account, proposal, answers)?;
    Ok(ReviewerAct {
        account,
        proposal,
        assignment: None,
        epoch,
    })
}

// ---------------------------------------------------------------------------
// Read API for other lanes
// ---------------------------------------------------------------------------

/// The organisation recorded on the active committee member binding of
/// `account` in `programme` (I-34, SoD-10).
///
/// The roster of lane L-SOD keeps no organisation per binding yet, so this
/// finds none, and I-34 and I-35 stay unchecked. Once `Binding` keeps the
/// `BindingGranted::organisation` field, this reads it.
pub(crate) fn committee_organisation(
    state: &State,
    account: AccountId,
    programme: ProgrammeId,
    now: Timestamp,
) -> Option<OrganisationId> {
    let binding = state
        .roster
        .active_binding(account, Role::CommitteeMember, programme, now)?;
    state.roster.binding(binding)?.organisation
}

/// Whether `proposal` is under evaluation in `call` now (I-36): it is in
/// SUBMITTED, STAGE1, STAGE2, RANKED, IRC_REVIEW, DEFERRED or NEGOTIATION
/// with `call` as its current call, or it is DEFERRED and `call` is the
/// next published call of the programme (Q12).
pub(crate) fn under_evaluation_in(state: &State, proposal: ProposalId, call: CallId) -> bool {
    let Some(s) = proposal_state(state, proposal) else {
        return false;
    };
    let evaluating = matches!(
        s,
        StateTag::Submitted
            | StateTag::Stage1
            | StateTag::Stage2
            | StateTag::Ranked
            | StateTag::IrcReview
            | StateTag::Deferred
            | StateTag::Negotiation
    );
    let Some(current) = current_call(state, proposal) else {
        return false;
    };
    evaluating
        && (current == call
            || (s == StateTag::Deferred
                && crate::programme::next_published_call(state, current) == Some(call)))
}

/// Whether a Receiving binding of `account` in `call` would break I-36:
/// the account reviewed a proposal under evaluation in that call.
pub fn i36_bars(state: &State, account: AccountId, call: CallId) -> bool {
    state.review.assignments.values().any(|a| {
        a.reviewer == account
            && a.kind.reviews_proposal()
            && under_evaluation_in(state, a.proposal, call)
    })
}

/// Whether someone who reviewed `proposal` holds a Receiving binding in
/// `call` (I-36). Lane L-LIFE reads it at `ReEnter`, where a deferred
/// proposal enters a call that a former reviewer joined first.
pub fn former_reviewer_receiving_in(state: &State, proposal: ProposalId, call: CallId) -> bool {
    state.roster.bindings().any(|(_, b)| {
        b.held()
            && b.group() == Group::Receiving
            && b.call() == Some(call)
            && state.review.reviewed(b.account, proposal)
    })
}

/// The `HasConflict` questions of `member` for the cut-off of `call`: one
/// per RANKED proposal of the call (Q10, Conflict declarations).
pub fn cut_off_recusal_queries(state: &State, member: AccountId, call: CallId) -> Vec<Query> {
    ranked_in(state, call)
        .into_iter()
        .map(|p| conflict_query(state, member, p))
        .collect()
}

/// Whether committee member `member` recuses from the cut-off vote of
/// `call`: a conflict fact, or a `HasConflict` answer of true at the
/// state's epoch, on any RANKED proposal of the call. A recused member
/// neither votes nor delegates, and nobody votes for them (Q10). A missing
/// or stale answer refuses.
pub fn recused_from_cut_off(
    state: &State,
    member: AccountId,
    call: CallId,
    answers: &Answers,
) -> Result<bool, Refusal> {
    let mut recused = false;
    for p in ranked_in(state, call) {
        if state.review.conflict_fact(member, p) {
            recused = true;
        }
        match fresh_no_conflict(state, member, p, answers) {
            Ok(_) => {}
            Err(r) if r.rule == RuleRef::I03 => recused = true,
            Err(r) => return Err(r),
        }
    }
    Ok(recused)
}

/// The RANKED proposals whose current call is `call`.
fn ranked_in(state: &State, call: CallId) -> Vec<ProposalId> {
    crate::proposal::intake::submitted_proposals(state)
        .filter(|(_, s, c)| *s == StateTag::Ranked && *c == call)
        .map(|(p, _, _)| p)
        .collect()
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// The refusal of an unknown entity.
const fn unknown() -> Refusal {
    Refusal::new(RuleRef::Input, RefusalReason::UnknownEntity)
}

/// The refusal of a shell-supplied id that is already taken.
const fn reused() -> Refusal {
    Refusal::new(RuleRef::Ledger, RefusalReason::IdReused)
}

/// The refusal of a command the proposal's or assignment's state does not admit.
const fn wrong_state() -> Refusal {
    Refusal::new(RuleRef::Row, RefusalReason::WrongState)
}

/// The refusal of a value the command may not carry.
const fn invalid() -> Refusal {
    Refusal::new(RuleRef::Input, RefusalReason::InvalidValue)
}

/// The programme of `proposal`, through its call.
pub(crate) fn programme_of(state: &State, proposal: ProposalId) -> Result<ProgrammeId, Refusal> {
    let call = crate::proposal::draft::proposal_call(state, proposal).ok_or_else(unknown)?;
    crate::programme::call(state, call)
        .map(crate::programme::CallView::programme)
        .ok_or_else(unknown)
}

/// The frozen values of the call that governs `proposal`: its original
/// call, also after re-entry (NOTE 8).
pub(crate) fn governing_values(
    state: &State,
    proposal: ProposalId,
) -> Result<&FrozenValues, Refusal> {
    let call = crate::proposal::draft::proposal_call(state, proposal).ok_or_else(unknown)?;
    crate::policy::frozen_policy(state, call)
        .map(crate::policy::FrozenPolicy::values)
        .ok_or_else(unknown)
}

/// The answer to `q`, or the refusal for a missing one.
fn answer<'a>(answers: &'a Answers, q: &Query) -> Result<&'a Answer, Refusal> {
    answers.get(q).ok_or(Refusal::new(
        RuleRef::FactsIncomplete,
        RefusalReason::AnswerMissing,
    ))
}

/// Appends the record of the answer to `q` unless `prior` or `out` holds
/// it already (overview NOTE 5).
fn record_outcome(out: &mut Vec<Record>, prior: &[Record], q: &Query, a: &Answer) {
    let r = Record::VaultOutcome {
        kind: q.kind(),
        digest: a.digest,
        holds: a.holds,
        epoch: a.epoch,
    };
    if !prior.contains(&r) && !out.contains(&r) {
        out.push(r);
    }
}

/// The proposal of the command, for the commands that name one through an assignment.
fn assignment_proposal(state: &State, id: AssignmentId) -> Result<ProposalId, Refusal> {
    state.review.get(id).map(|a| a.proposal).ok_or_else(unknown)
}

// ---------------------------------------------------------------------------
// Assign
// ---------------------------------------------------------------------------

/// A checked `Assign`: the record and the vault questions it needs.
struct AssignPlan {
    /// The assignment, with the state's epoch.
    record: Assigned,
    /// `HasConflict` for the assignee.
    reviewer: Query,
    /// `DeclaresAffiliationOnList` for the reviewer's organisation (I-35).
    proximity: Option<Query>,
}

impl AssignPlan {
    /// The vault questions, in a stable order.
    fn queries(&self) -> Vec<Query> {
        let mut out = vec![self.reviewer.clone()];
        out.extend(self.proximity.iter().cloned());
        out
    }
}

/// Checks an `Assign` against the state and returns its plan.
fn plan_assign(state: &State, cmd: &Command, ctx: &Ctx) -> Result<AssignPlan, Refusal> {
    let Command::Assign {
        assignment,
        proposal,
        reviewer,
        kind,
        handle,
    } = cmd
    else {
        return Err(wrong_state());
    };
    let actor = crate::policy::actor_account(ctx)?;
    let current = proposal_state(state, *proposal).ok_or_else(unknown)?;
    let call = current_call(state, *proposal).ok_or_else(unknown)?;
    let programme = programme_of(state, *proposal)?;
    crate::policy::require_holder(state, actor, programme, &[Role::FstpCoordinator], ctx.now)?;
    if state.used_ids.contains(UsedId::Assignment(*assignment))
        || state.review.get(*assignment).is_some()
    {
        return Err(reused());
    }
    let open = match kind {
        AssignmentKind::Reviewer => matches!(
            current,
            StateTag::Submitted | StateTag::Stage1 | StateTag::Stage2
        ),
        AssignmentKind::Irc => current == StateTag::IrcReview,
        // IRC review of amendments is lane L-MONEY's.
        AssignmentKind::Amendment(_) => return Err(Refusal::not_implemented()),
    };
    if !open {
        return Err(wrong_state());
    }
    if state
        .roster
        .active_binding(*reviewer, kind.role(), programme, ctx.now)
        .is_none()
    {
        return Err(Refusal::new(RuleRef::Input, RefusalReason::BindingInactive));
    }
    let duplicate = state.review.assignments.values().any(|a| {
        a.reviewer == *reviewer
            && a.proposal == *proposal
            && a.kind == *kind
            && a.call == call
            && a.unreleased()
    });
    if duplicate {
        return Err(invalid());
    }
    // I-02 and SoD-02 hold within one programme (NOTE 3).
    let other_side = state.review.unreleased_of(*reviewer).any(|(_, a)| {
        a.kind.irc_side() != kind.irc_side()
            && programme_of(state, a.proposal).ok() == Some(programme)
    });
    if other_side {
        return Err(Refusal::new(RuleRef::I02, RefusalReason::GuardFailed));
    }
    if state.review.conflict_fact(*reviewer, *proposal) {
        return Err(Refusal::new(RuleRef::I03, RefusalReason::GuardFailed));
    }
    let values = governing_values(state, *proposal)?;
    match (values.p11, handle) {
        (ReviewerAnonymity::Anonymous, None) => {
            return Err(Refusal::new(RuleRef::Ran01, RefusalReason::InvalidValue));
        }
        (ReviewerAnonymity::Anonymous, Some(h)) if state.review.handle_issued(*h) => {
            return Err(Refusal::new(RuleRef::Ran01, RefusalReason::IdReused));
        }
        (ReviewerAnonymity::Named, Some(_)) => return Err(invalid()),
        _ => {}
    }
    let mut proximity = None;
    if *kind == AssignmentKind::Reviewer
        && let Some(org) = committee_organisation(state, *reviewer, programme, ctx.now)
    {
        let orgs = assigned_organisations(state, *proposal, call, ctx.now);
        if orgs.len() < usize::from(values.p39.get()) && orgs.contains(&org) {
            return Err(Refusal::new(RuleRef::I34, RefusalReason::GuardFailed));
        }
        let list =
            crate::policy::live_values(state, programme).and_then(|l| l.p38.0.get(&org).copied());
        proximity = list.map(|list| Query::DeclaresAffiliationOnList {
            team: state.roster.receiving_accounts(*proposal),
            list,
        });
    }
    Ok(AssignPlan {
        record: Assigned {
            assignment: *assignment,
            proposal: *proposal,
            call,
            reviewer: *reviewer,
            kind: *kind,
            handle: *handle,
            by: actor,
            epoch: state.epoch,
        },
        reviewer: conflict_query(state, *reviewer, *proposal),
        proximity,
    })
}

/// The organisations of the unreleased reviewer assignments of `proposal`
/// in `call`, from each assignee's committee binding (I-34).
fn assigned_organisations(
    state: &State,
    proposal: ProposalId,
    call: CallId,
    now: Timestamp,
) -> BTreeSet<OrganisationId> {
    let Ok(programme) = programme_of(state, proposal) else {
        return BTreeSet::new();
    };
    state
        .review
        .assignments
        .values()
        .filter(|a| {
            a.proposal == proposal
                && a.call == call
                && a.kind == AssignmentKind::Reviewer
                && a.unreleased()
        })
        .filter_map(|a| committee_organisation(state, a.reviewer, programme, now))
        .collect()
}

/// The records of a checked `Assign` under `answers`.
fn decide_assign(plan: AssignPlan, answers: &Answers) -> Result<Vec<Record>, Refusal> {
    let mut out = Vec::new();
    let a = answer(answers, &plan.reviewer)?;
    if a.holds {
        return Err(Refusal::new(RuleRef::I03, RefusalReason::VaultRefused));
    }
    record_outcome(&mut out, &[], &plan.reviewer, a);
    if let Some(q) = &plan.proximity {
        let a = answer(answers, q)?;
        if a.holds {
            return Err(Refusal::new(RuleRef::I35, RefusalReason::VaultRefused));
        }
        record_outcome(&mut out, &[], q, a);
    }
    out.push(Record::Assigned(plan.record));
    Ok(out)
}

// ---------------------------------------------------------------------------
// Unassign and DeclareConflict
// ---------------------------------------------------------------------------

/// Checks an `Unassign` and returns its record.
fn check_unassign(
    state: &State,
    assignment: AssignmentId,
    ctx: &Ctx,
) -> Result<Vec<Record>, Refusal> {
    let actor = crate::policy::actor_account(ctx)?;
    let a = state.review.get(assignment).ok_or_else(unknown)?;
    let programme = programme_of(state, a.proposal)?;
    crate::policy::require_holder(state, actor, programme, &[Role::FstpCoordinator], ctx.now)?;
    if !a.unreleased() {
        return Err(wrong_state());
    }
    Ok(vec![Record::AssignmentReleased(AssignmentReleased {
        assignment,
        cause: ReleaseCause::Unassigned,
    })])
}

/// Whether an assignment in `status` takes a declaration. The first
/// declaration comes while it awaits one. A conflict found after a
/// no-conflict declaration is declared on the active assignment, and
/// releases it in the same batch (R-CF-02, design 2.7).
const fn declaration_open(status: AssignmentStatus, conflicted: bool) -> bool {
    match status {
        AssignmentStatus::AwaitingDeclaration => true,
        AssignmentStatus::Active => conflicted,
        AssignmentStatus::Released(_) => false,
    }
}

/// Checks a `DeclareConflict` and returns its records (R-CF-02, R-CF-04).
fn check_declare(
    state: &State,
    subject: DeclarationSubject,
    conflicted: bool,
    notifiable: bool,
    ctx: &Ctx,
) -> Result<Vec<Record>, Refusal> {
    let actor = crate::policy::actor_account(ctx)?;
    if notifiable && !conflicted {
        return Err(invalid());
    }
    let (declared, proposal, released): (Declared, ProposalId, Vec<AssignmentId>) = match subject {
        DeclarationSubject::Assignment(id) => {
            let a = state.review.get(id).ok_or_else(unknown)?;
            if a.reviewer != actor {
                return Err(Refusal::new(RuleRef::Actor, RefusalReason::WrongActor));
            }
            let programme = programme_of(state, a.proposal)?;
            crate::policy::require_holder(state, actor, programme, &[a.kind.role()], ctx.now)?;
            if !declaration_open(a.status, conflicted) {
                return Err(wrong_state());
            }
            let released = if conflicted { vec![id] } else { Vec::new() };
            (Declared::Assignment(id), a.proposal, released)
        }
        DeclarationSubject::Proposal(proposal) => {
            let current = proposal_state(state, proposal).ok_or_else(unknown)?;
            let programme = programme_of(state, proposal)?;
            let coordinator = crate::policy::holds_any(
                state,
                actor,
                programme,
                &[Role::FstpCoordinator],
                ctx.now,
            );
            let all_committee =
                governing_values(state, proposal)?.p10 == ReadAccess::AllCommitteeMembers;
            let member = all_committee
                && crate::policy::holds_any(
                    state,
                    actor,
                    programme,
                    &[Role::CommitteeMember],
                    ctx.now,
                );
            if !coordinator && !member {
                return Err(Refusal::new(RuleRef::Actor, RefusalReason::WrongActor));
            }
            if current == StateTag::Draft || current.is_terminal() {
                return Err(wrong_state());
            }
            if state.review.conflict_fact(actor, proposal) {
                // The fact is permanent for the proposal (design 2.7).
                return Err(Refusal::new(RuleRef::I03, RefusalReason::GuardFailed));
            }
            if state.review.cleared(actor, proposal) && !conflicted {
                return Err(invalid());
            }
            let released = if conflicted {
                state
                    .review
                    .unreleased_of(actor)
                    .filter(|(_, a)| a.proposal == proposal)
                    .map(|(id, _)| id)
                    .collect()
            } else {
                Vec::new()
            };
            (
                Declared::Proposal {
                    proposal,
                    account: actor,
                },
                proposal,
                released,
            )
        }
    };
    let mut out = vec![Record::ConflictDeclared(ConflictDeclared {
        subject: declared,
        conflicted,
        notifiable,
    })];
    out.extend(released.into_iter().map(|assignment| {
        Record::AssignmentReleased(AssignmentReleased {
            assignment,
            cause: ReleaseCause::DeclaredConflict,
        })
    }));
    if notifiable {
        out.push(Record::OutboxEnqueued(OutboxEvent::NotifiableConflict {
            proposal,
        }));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// ReadContent and RecordRankingSummary
// ---------------------------------------------------------------------------

/// Checks a `ReadContent` and returns the vault questions it needs: none
/// for the applicant team, and `HasConflict` for everyone else.
fn read_queries(state: &State, proposal: ProposalId, ctx: &Ctx) -> Result<Vec<Query>, Refusal> {
    let actor = crate::policy::actor_account(ctx)?;
    match crate::visibility::read_basis(state, actor, proposal, ctx.now)? {
        crate::visibility::ReadBasis::Team => Ok(Vec::new()),
        _ => Ok(vec![conflict_query(state, actor, proposal)]),
    }
}

/// The records of a `ReadContent`: the read, after the [`ReviewerAct`]
/// for every reader outside the applicant team (I-03, R-AU-01).
fn decide_read(
    state: &State,
    proposal: ProposalId,
    ctx: &Ctx,
    answers: &Answers,
) -> Result<Vec<Record>, Refusal> {
    let actor = crate::policy::actor_account(ctx)?;
    let mut out = Vec::new();
    let basis = crate::visibility::read_basis(state, actor, proposal, ctx.now)?;
    let act = match basis {
        crate::visibility::ReadBasis::Team => None,
        crate::visibility::ReadBasis::Assignment(id) => {
            Some(reviewer_act(state, actor, id, ctx.now, answers)?)
        }
        crate::visibility::ReadBasis::Declared(role) => {
            Some(cleared_act(state, actor, proposal, role, ctx.now, answers)?)
        }
    };
    if let Some(act) = act {
        let q = conflict_query(state, act.account(), act.proposal());
        record_outcome(&mut out, &[], &q, answer(answers, &q)?);
    }
    out.push(Record::ContentRead(ContentRead {
        account: actor,
        proposal,
    }));
    Ok(out)
}

/// The fields of a `RecordRankingSummary`.
struct SummaryInput {
    /// The proposal.
    proposal: ProposalId,
    /// The writing reviewer's assignment.
    assignment: AssignmentId,
    /// The title.
    title: TextRef,
    /// The neutral summary.
    neutral_summary: TextRef,
    /// The reviewers' rationale.
    rationale: TextRef,
}

/// Checks a `RecordRankingSummary` against the state: the actor's own
/// reviewer assignment on the proposal, in STAGE1, STAGE2 or RANKED.
fn check_summary(state: &State, s: &SummaryInput, ctx: &Ctx) -> Result<(), Refusal> {
    let actor = crate::policy::actor_account(ctx)?;
    let current = proposal_state(state, s.proposal).ok_or_else(unknown)?;
    let a = reviewer_basis(state, actor, s.assignment, ctx.now)?;
    if a.proposal != s.proposal || a.kind != AssignmentKind::Reviewer {
        return Err(invalid());
    }
    if !matches!(
        current,
        StateTag::Stage1 | StateTag::Stage2 | StateTag::Ranked
    ) {
        return Err(wrong_state());
    }
    Ok(())
}

/// The records of a checked `RecordRankingSummary` under `answers`.
fn decide_summary(
    state: &State,
    s: &SummaryInput,
    ctx: &Ctx,
    answers: &Answers,
) -> Result<Vec<Record>, Refusal> {
    check_summary(state, s, ctx)?;
    let actor = crate::policy::actor_account(ctx)?;
    let act = reviewer_act(state, actor, s.assignment, ctx.now, answers)?;
    let mut out = Vec::new();
    let q = conflict_query(state, act.account(), act.proposal());
    record_outcome(&mut out, &[], &q, answer(answers, &q)?);
    out.push(Record::RankingSummaryRecorded {
        proposal: s.proposal,
        assignment: s.assignment,
        title: s.title,
        neutral_summary: s.neutral_summary,
        rationale: s.rationale,
    });
    Ok(out)
}

/// The fields of `cmd` when it is a `RecordRankingSummary`.
fn summary_input(cmd: &Command) -> Option<SummaryInput> {
    match cmd {
        Command::RecordRankingSummary {
            proposal,
            assignment,
            title,
            neutral_summary,
            rationale,
        } => Some(SummaryInput {
            proposal: *proposal,
            assignment: *assignment,
            title: *title,
            neutral_summary: *neutral_summary,
            rationale: *rationale,
        }),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Engine entry points of this lane, called by `crate::engine`.
// ---------------------------------------------------------------------------

/// The vault questions of the assignment, conflict, read and ranking summary commands.
pub(crate) fn queries(state: &State, cmd: &Command, ctx: &Ctx) -> Result<Vec<Query>, Refusal> {
    match cmd {
        Command::Assign { .. } => Ok(plan_assign(state, cmd, ctx)?.queries()),
        Command::Unassign { assignment } => {
            check_unassign(state, *assignment, ctx)?;
            Ok(Vec::new())
        }
        Command::DeclareConflict {
            subject,
            conflicted,
            notifiable,
        } => {
            check_declare(state, *subject, *conflicted, *notifiable, ctx)?;
            Ok(Vec::new())
        }
        Command::ReadContent { proposal } => read_queries(state, *proposal, ctx),
        Command::RecordRankingSummary { .. } => {
            let s = summary_input(cmd).ok_or_else(wrong_state)?;
            check_summary(state, &s, ctx)?;
            let actor = crate::policy::actor_account(ctx)?;
            Ok(vec![conflict_query(state, actor, s.proposal)])
        }
        _ => Err(wrong_state()),
    }
}

/// The records of the assignment, conflict, read and ranking summary commands.
pub(crate) fn decide(
    state: &State,
    cmd: &Command,
    ctx: &Ctx,
    answers: &Answers,
) -> Result<Vec<Record>, Refusal> {
    match cmd {
        Command::Assign { .. } => decide_assign(plan_assign(state, cmd, ctx)?, answers),
        Command::Unassign { assignment } => check_unassign(state, *assignment, ctx),
        Command::DeclareConflict {
            subject,
            conflicted,
            notifiable,
        } => check_declare(state, *subject, *conflicted, *notifiable, ctx),
        Command::ReadContent { proposal } => decide_read(state, *proposal, ctx, answers),
        Command::RecordRankingSummary { .. } => {
            let s = summary_input(cmd).ok_or_else(wrong_state)?;
            decide_summary(state, &s, ctx, answers)
        }
        _ => Err(wrong_state()),
    }
}

/// Folds an assignment, conflict, read or ranking summary record. The
/// fold checks structure only and never re-runs a guard, so a read after
/// a conflict fact still folds, and the I-03 checks see it.
pub(crate) fn apply(
    state: &mut State,
    seq: fstp_ledger::Seq,
    at: Timestamp,
    record: &Record,
) -> Result<(), FoldError> {
    let _ = (seq, at);
    match record {
        Record::Assigned(a) => {
            if state.used_ids.contains(UsedId::Assignment(a.assignment))
                || state.review.assignments.contains_key(&a.assignment)
            {
                return Err(FoldError::DuplicateId);
            }
            proposal_state(state, a.proposal).ok_or(FoldError::UnknownEntity)?;
            if let Some(h) = a.handle
                && state.review.handles.contains(&h)
            {
                return Err(FoldError::DuplicateId);
            }
            state.used_ids.insert(UsedId::Assignment(a.assignment));
            if let Some(h) = a.handle {
                state.review.handles.insert(h);
            }
            state.review.assignments.insert(
                a.assignment,
                Assignment {
                    proposal: a.proposal,
                    call: a.call,
                    reviewer: a.reviewer,
                    kind: a.kind,
                    handle: a.handle,
                    status: AssignmentStatus::AwaitingDeclaration,
                },
            );
            Ok(())
        }
        Record::ConflictDeclared(d) => match d.subject {
            Declared::Assignment(id) => {
                let a = state
                    .review
                    .assignments
                    .get_mut(&id)
                    .ok_or(FoldError::UnknownEntity)?;
                if !declaration_open(a.status, d.conflicted) {
                    return Err(FoldError::Inconsistent);
                }
                let pair = (a.reviewer, a.proposal);
                if d.conflicted {
                    state.review.facts.insert(pair);
                } else {
                    a.status = AssignmentStatus::Active;
                }
                Ok(())
            }
            Declared::Proposal { proposal, account } => {
                proposal_state(state, proposal).ok_or(FoldError::UnknownEntity)?;
                if d.conflicted {
                    state.review.facts.insert((account, proposal));
                } else {
                    state.review.cleared.insert((account, proposal));
                }
                Ok(())
            }
        },
        Record::ConflictDetected(d) => {
            proposal_state(state, d.proposal).ok_or(FoldError::UnknownEntity)?;
            state.review.facts.insert((d.account, d.proposal));
            Ok(())
        }
        Record::AssignmentReleased(r) => {
            let a = state
                .review
                .assignments
                .get_mut(&r.assignment)
                .ok_or(FoldError::UnknownEntity)?;
            if !a.unreleased() {
                return Err(FoldError::Inconsistent);
            }
            a.status = AssignmentStatus::Released(r.cause);
            Ok(())
        }
        Record::ContentRead(c) => {
            proposal_state(state, c.proposal).ok_or(FoldError::UnknownEntity)?;
            Ok(())
        }
        Record::RankingSummaryRecorded {
            proposal,
            assignment,
            title,
            neutral_summary,
            rationale,
        } => {
            let a = state
                .review
                .assignments
                .get(assignment)
                .ok_or(FoldError::UnknownEntity)?;
            if a.proposal != *proposal {
                return Err(FoldError::Inconsistent);
            }
            state.review.summaries.insert(
                *proposal,
                RankingSummary {
                    assignment: *assignment,
                    title: *title,
                    neutral_summary: *neutral_summary,
                    rationale: *rationale,
                },
            );
            Ok(())
        }
        _ => Err(FoldError::Inconsistent),
    }
}

// ---------------------------------------------------------------------------
// Contributions to other lanes' batches
// ---------------------------------------------------------------------------

/// The account and call of the Receiving binding that `cmd` creates, for
/// the I-36 bar. `None` for every other command.
fn receiving_target(state: &State, cmd: &Command, ctx: &Ctx) -> Option<(AccountId, CallId)> {
    match cmd {
        Command::CreateDraft { call, .. } => {
            crate::policy::actor_account(ctx).ok().map(|a| (a, *call))
        }
        Command::AddTeamMember {
            proposal, account, ..
        }
        | Command::AddGuardian {
            proposal, account, ..
        } => crate::proposal::draft::proposal_call(state, *proposal).map(|c| (*account, c)),
        _ => None,
    }
}

/// Refuses the Receiving binding of `cmd` under I-36.
fn check_i36(state: &State, cmd: &Command, ctx: &Ctx) -> Result<(), Refusal> {
    match receiving_target(state, cmd, ctx) {
        Some((account, call)) if i36_bars(state, account, call) => {
            Err(Refusal::new(RuleRef::I36, RefusalReason::GuardFailed))
        }
        _ => Ok(()),
    }
}

/// The pairs a vault reaction rechecks: the assignee of every unreleased
/// assignment, and every proposal-level clearance without a conflict fact.
fn tracked_pairs(state: &State) -> BTreeSet<(AccountId, ProposalId)> {
    let mut out: BTreeSet<(AccountId, ProposalId)> = state
        .review
        .assignments
        .values()
        .filter(|a| a.unreleased())
        .map(|a| (a.reviewer, a.proposal))
        .collect();
    out.extend(
        state
            .review
            .cleared
            .iter()
            .filter(|pair| !state.review.facts.contains(pair))
            .copied(),
    );
    out
}

/// The account and proposal of a Receiving binding that the roster holds,
/// held or ended.
fn receiving_of(state: &State, binding: crate::id::BindingId) -> Option<(AccountId, ProposalId)> {
    let b = state.roster.binding(binding).or_else(|| {
        state
            .roster
            .ended()
            .find(|(id, _)| *id == binding)
            .map(|(_, e)| &e.binding)
    })?;
    b.proposal().map(|p| (b.account, p))
}

/// The accounts that judged `proposal`: every assignee, released or not,
/// and every account with a proposal-level clearance, without a conflict
/// fact on it. Their acts stay on the ledger, so an identity discovery
/// reaches them all (R-CF-04).
fn judged_by(state: &State, proposal: ProposalId) -> BTreeSet<AccountId> {
    let mut out: BTreeSet<AccountId> = state
        .review
        .assignments
        .values()
        .filter(|a| a.proposal == proposal)
        .map(|a| a.reviewer)
        .collect();
    out.extend(
        state
            .review
            .cleared
            .iter()
            .filter(|(_, p)| *p == proposal)
            .map(|(a, _)| *a),
    );
    out.retain(|a| !state.review.conflict_fact(*a, proposal));
    out
}

/// One identity question of a vault reaction (R-CF-04).
struct IdentityCheck {
    /// The account of a Receiving binding of the proposal.
    subject: AccountId,
    /// The proposal.
    proposal: ProposalId,
    /// An account that judged the proposal.
    judge: AccountId,
    /// `SameIdentityAsAny` of the subject against the judge alone.
    query: Query,
}

/// The identity questions of a `VaultChanged` that lists `changed`: one
/// per Receiving account that is not voided and per account that judged
/// its proposal, when either changed. Lane L-SOD voids a Receiving binding
/// under I-06 only when its account or a candidate changed, so the
/// questions cover every discovery the batch can record.
fn identity_checks(state: &State, changed: &BTreeSet<AccountId>) -> Vec<IdentityCheck> {
    let subjects: BTreeSet<(AccountId, ProposalId)> = state
        .roster
        .bindings()
        .map(|(_, b)| b)
        .chain(state.roster.ended().map(|(_, e)| &e.binding))
        .filter(|b| b.group() == Group::Receiving && !matches!(b.status, BindingStatus::Voided(_)))
        .filter_map(|b| b.proposal().map(|p| (b.account, p)))
        .collect();
    let mut out = Vec::new();
    for (subject, proposal) in subjects {
        for judge in judged_by(state, proposal) {
            if judge == subject || !(changed.contains(&subject) || changed.contains(&judge)) {
                continue;
            }
            out.push(IdentityCheck {
                subject,
                proposal,
                judge,
                query: Query::SameIdentityAsAny {
                    subject,
                    others: [judge].into_iter().collect(),
                },
            });
        }
    }
    out
}

/// The I-35 questions for the unreleased reviewer assignments of
/// `proposal` against `team`: one per assignee whose committee binding
/// records an organisation with a list in `lists` (P-38).
fn proximity_checks(
    state: &State,
    proposal: ProposalId,
    team: &BTreeSet<AccountId>,
    lists: &BTreeMap<OrganisationId, crate::id::ProximityListId>,
    now: Timestamp,
) -> Vec<(AssignmentId, Query)> {
    let Ok(programme) = programme_of(state, proposal) else {
        return Vec::new();
    };
    state
        .review
        .assignments
        .iter()
        .filter(|(_, a)| {
            a.proposal == proposal && a.kind == AssignmentKind::Reviewer && a.unreleased()
        })
        .filter_map(|(id, a)| {
            let org = committee_organisation(state, a.reviewer, programme, now)?;
            let list = lists.get(&org)?;
            Some((
                *id,
                Query::DeclaresAffiliationOnList {
                    team: team.clone(),
                    list: *list,
                },
            ))
        })
        .collect()
}

/// The proposals with an unreleased reviewer assignment.
fn proposals_with_reviewers(state: &State) -> BTreeSet<ProposalId> {
    state
        .review
        .assignments
        .values()
        .filter(|a| a.kind == AssignmentKind::Reviewer && a.unreleased())
        .map(|a| a.proposal)
        .collect()
}

/// The I-35 questions for every proposal with an unreleased reviewer
/// assignment, against its team and the live P-38 lists of its programme.
fn live_proximity_checks(
    state: &State,
    team: impl Fn(ProposalId) -> BTreeSet<AccountId>,
    only: Option<ProposalId>,
    now: Timestamp,
) -> Vec<(AssignmentId, Query)> {
    let mut out = Vec::new();
    for p in proposals_with_reviewers(state) {
        if only.is_some_and(|o| o != p) {
            continue;
        }
        let Some(live) = programme_of(state, p)
            .ok()
            .and_then(|programme| crate::policy::live_values(state, programme))
        else {
            continue;
        };
        out.extend(proximity_checks(state, p, &team(p), &live.p38.0, now));
    }
    out
}

/// The vault questions of this lane's contribution to one batch, with
/// what a positive answer does.
struct Rechecks {
    /// `HasConflict` per tracked pair: a positive answer records a
    /// detection and releases the account's assignments on the proposal.
    conflicts: Vec<(AccountId, ProposalId, Query)>,
    /// `DeclaresAffiliationOnList` per unreleased reviewer assignment: a
    /// positive answer releases it (I-35).
    proximity: Vec<(AssignmentId, Query)>,
    /// Identity questions: a positive answer, when the batch voids the
    /// subject's binding under I-06, records a notifiable detection (R-CF-04).
    identity: Vec<IdentityCheck>,
}

impl Rechecks {
    /// No question.
    const fn none() -> Rechecks {
        Rechecks {
            conflicts: Vec::new(),
            proximity: Vec::new(),
            identity: Vec::new(),
        }
    }

    /// The vault questions, in a stable order.
    fn queries(&self) -> Vec<Query> {
        let mut out: Vec<Query> = self.conflicts.iter().map(|(_, _, q)| q.clone()).collect();
        out.extend(self.proximity.iter().map(|(_, q)| q.clone()));
        out.extend(self.identity.iter().map(|c| c.query.clone()));
        out
    }
}

/// The rechecks of this lane's contribution to the batch of `cmd`.
///
/// - `VaultChanged`: every tracked pair against its team, every
///   unreleased reviewer assignment against the live P-38 lists, and the
///   identity questions of [`identity_checks`].
/// - `AddTeamMember` and `AddGuardian`: the tracked pairs and reviewer
///   assignments of the proposal against the team with the new account.
/// - `EditPolicy` that changes P-38: every unreleased reviewer assignment
///   of the programme against the new lists.
fn plan_rechecks(state: &State, cmd: &Command, ctx: &Ctx) -> Rechecks {
    let mut plan = Rechecks::none();
    match cmd {
        Command::VaultChanged { changed, .. } => {
            plan.conflicts = tracked_pairs(state)
                .into_iter()
                .map(|(a, p)| (a, p, conflict_query(state, a, p)))
                .collect();
            plan.proximity =
                live_proximity_checks(state, |p| state.roster.receiving_accounts(p), None, ctx.now);
            plan.identity = identity_checks(state, changed);
        }
        Command::AddTeamMember {
            proposal, account, ..
        }
        | Command::AddGuardian {
            proposal, account, ..
        } => {
            let mut team = state.roster.receiving_accounts(*proposal);
            team.insert(*account);
            plan.conflicts = tracked_pairs(state)
                .into_iter()
                .filter(|(_, p)| p == proposal)
                .map(|(a, p)| {
                    let q = Query::HasConflict {
                        reviewer: a,
                        team: team.clone(),
                    };
                    (a, p, q)
                })
                .collect();
            plan.proximity =
                live_proximity_checks(state, |_| team.clone(), Some(*proposal), ctx.now);
        }
        Command::EditPolicy { .. } => {
            if let Some(change) = crate::policy::live_change(state, cmd)
                && change.p38_changed()
            {
                for p in proposals_with_reviewers(state) {
                    if programme_of(state, p).ok() == Some(change.programme) {
                        let team = state.roster.receiving_accounts(p);
                        plan.proximity.extend(proximity_checks(
                            state,
                            p,
                            &team,
                            &change.after.p38.0,
                            ctx.now,
                        ));
                    }
                }
            }
        }
        _ => {}
    }
    plan
}

/// The account and proposal of every Receiving binding that `batch` voids under I-06.
fn voided_under_i06(state: &State, batch: &[Record]) -> BTreeSet<(AccountId, ProposalId)> {
    batch
        .iter()
        .filter_map(|r| match r {
            Record::BindingVoided(v) if v.rule == RuleRef::I06 => receiving_of(state, v.binding),
            _ => None,
        })
        .collect()
}

/// The records of the rechecks in `plan` under `answers`, at `epoch`
/// (I-03, I-35, R-CF-02, R-CF-04): the answers used, one detection per
/// conflicted pair, the releases, and one notification draft per proposal
/// with a notifiable detection.
fn react(
    state: &State,
    plan: &Rechecks,
    epoch: VaultEpoch,
    answers: &Answers,
    batch: &[Record],
) -> Result<Vec<Record>, Refusal> {
    let voided = voided_under_i06(state, batch);
    let mut outcomes = Vec::new();
    let mut matched: BTreeSet<(AccountId, ProposalId)> = BTreeSet::new();
    for c in &plan.identity {
        if !voided.contains(&(c.subject, c.proposal)) {
            continue;
        }
        let a = answer(answers, &c.query)?;
        record_outcome(&mut outcomes, batch, &c.query, a);
        if a.holds {
            matched.insert((c.judge, c.proposal));
        }
    }
    let mut detected = matched.clone();
    for (account, proposal, q) in &plan.conflicts {
        let a = answer(answers, q)?;
        record_outcome(&mut outcomes, batch, q, a);
        if a.holds {
            detected.insert((*account, *proposal));
        }
    }
    let mut records = Vec::new();
    let mut released: BTreeSet<AssignmentId> = BTreeSet::new();
    let mut notify: BTreeSet<ProposalId> = BTreeSet::new();
    for (account, proposal) in detected {
        let notifiable = matched.contains(&(account, proposal));
        records.push(Record::ConflictDetected(ConflictDetected {
            account,
            proposal,
            notifiable,
            epoch,
        }));
        for (id, x) in state.review.unreleased_of(account) {
            if x.proposal == proposal && released.insert(id) {
                records.push(Record::AssignmentReleased(AssignmentReleased {
                    assignment: id,
                    cause: ReleaseCause::DetectedConflict,
                }));
            }
        }
        if notifiable {
            notify.insert(proposal);
        }
    }
    for (id, q) in &plan.proximity {
        let a = answer(answers, q)?;
        record_outcome(&mut outcomes, batch, q, a);
        if a.holds && released.insert(*id) {
            records.push(Record::AssignmentReleased(AssignmentReleased {
                assignment: *id,
                cause: ReleaseCause::DetectedConflict,
            }));
        }
    }
    records.extend(
        notify
            .into_iter()
            .map(|proposal| Record::OutboxEnqueued(OutboxEvent::NotifiableConflict { proposal })),
    );
    outcomes.extend(records);
    Ok(outcomes)
}

/// The releases of the assignments that rest on a committee member or IRC
/// member binding that `batch` ends, suspends or voids (I-02). An
/// assignment that `batch` or `own` already releases is skipped, and so is
/// one whose account keeps another binding of the role in the programme.
fn binding_releases(state: &State, batch: &[Record], own: &[Record]) -> Vec<Record> {
    let mut released: BTreeSet<AssignmentId> = batch
        .iter()
        .chain(own)
        .filter_map(|r| match r {
            Record::AssignmentReleased(x) => Some(x.assignment),
            _ => None,
        })
        .collect();
    let lost: BTreeSet<crate::id::BindingId> = batch
        .iter()
        .filter_map(|r| match r {
            Record::BindingEnded(e) => Some(e.binding),
            Record::BindingSuspended(s) => Some(s.binding),
            Record::BindingVoided(v) => Some(v.binding),
            _ => None,
        })
        .collect();
    let mut out = Vec::new();
    for r in batch {
        let (binding, cause) = match r {
            Record::BindingEnded(e) => (e.binding, ReleaseCause::BindingEnded),
            Record::BindingSuspended(s) => (s.binding, ReleaseCause::BindingSuspended),
            Record::BindingVoided(v) => (v.binding, ReleaseCause::BindingVoided),
            _ => continue,
        };
        let Some(b) = state.roster.binding(binding) else {
            continue;
        };
        if !matches!(b.role, Role::CommitteeMember | Role::IrcMember) {
            continue;
        }
        let other = state.roster.bindings().any(|(id, x)| {
            id != binding
                && !lost.contains(&id)
                && x.account == b.account
                && x.role == b.role
                && x.programme == b.programme
                && match cause {
                    ReleaseCause::BindingEnded => x.held(),
                    _ => x.status == BindingStatus::Active,
                }
        });
        if other {
            continue;
        }
        let rest: Vec<AssignmentId> = state
            .review
            .unreleased_of(b.account)
            .filter(|(_, a)| {
                a.kind.role() == b.role && programme_of(state, a.proposal).ok() == Some(b.programme)
            })
            .map(|(id, _)| id)
            .collect();
        for id in rest {
            if released.insert(id) {
                out.push(Record::AssignmentReleased(AssignmentReleased {
                    assignment: id,
                    cause,
                }));
            }
        }
    }
    out
}

/// The vault questions this lane needs for its contribution to the batch of
/// a command that another lane owns. It reads only the state and the command.
pub(crate) fn contribute_queries(
    state: &State,
    cmd: &Command,
    ctx: &Ctx,
) -> Result<Vec<Query>, Refusal> {
    check_i36(state, cmd, ctx)?;
    Ok(plan_rechecks(state, cmd, ctx).queries())
}

/// The records this lane adds to the batch of a command that another lane
/// owns, given the records so far (`crate::engine` module docs): the
/// detections, releases and notification drafts of [`plan_rechecks`], the
/// releases of assignments whose binding ends, is suspended or is voided,
/// and the I-36 refusal of a Receiving binding.
pub(crate) fn contribute(
    state: &State,
    cmd: &Command,
    ctx: &Ctx,
    answers: &Answers,
    batch: &[Record],
) -> Result<Vec<Record>, Refusal> {
    check_i36(state, cmd, ctx)?;
    let epoch = match cmd {
        Command::VaultChanged { epoch, .. } => *epoch,
        _ => state.epoch,
    };
    let mut out = react(
        state,
        &plan_rechecks(state, cmd, ctx),
        epoch,
        answers,
        batch,
    )?;
    let releases = binding_releases(state, batch, &out);
    out.extend(releases);
    Ok(out)
}

/// The policy whose P-77 governs a binding action of this lane through MCP
/// (R-MC-05): the frozen policy of the proposal's original call.
pub(crate) fn governing_policy(state: &State, cmd: &Command) -> Result<PolicyScope, Refusal> {
    let proposal = match cmd {
        Command::Assign { proposal, .. }
        | Command::ReadContent { proposal }
        | Command::RecordRankingSummary { proposal, .. }
        | Command::DeclareConflict {
            subject: DeclarationSubject::Proposal(proposal),
            ..
        } => *proposal,
        Command::Unassign { assignment }
        | Command::DeclareConflict {
            subject: DeclarationSubject::Assignment(assignment),
            ..
        } => assignment_proposal(state, *assignment)?,
        _ => return Err(wrong_state()),
    };
    crate::proposal::draft::proposal_call(state, proposal)
        .map(PolicyScope::Call)
        .ok_or_else(unknown)
}
