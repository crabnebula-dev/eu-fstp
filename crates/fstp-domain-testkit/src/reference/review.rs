//! Independent reference for review and proposal intake, written from the spec text (design sections 2.7, 2.8, 3.2, 3.7 and 6.1).
//!
//! Written from `SPEC/02-domain/invariants.md` (I-02, I-03, I-34, I-35,
//! I-36), `SPEC/02-domain/roles-and-sod.md` (Conflict declarations,
//! Reviewer assignment, Anonymous reviewer handles),
//! `SPEC/02-domain/state-machine.md` (DRAFT to SUBMITTED, NOTE 10) and
//! `SPEC/01-requirements/functional.md` (R-CF-01 to R-CF-04, R-SB-01 to
//! R-SB-05, R-AN-01, R-AC-01, R-NG-06). It shares only id, command and
//! record types with production, and reads roles through the L-SOD
//! reference view, never through a production guard.
//!
//! - [`RevView`] is the reference's own fold of core records: proposals
//!   and their states, plans, assignments, conflict facts, clearances,
//!   handles, reads and reviewed-by facts.
//! - [`verdict`] says whether a command must be accepted or refused, or
//!   leaves it to production. [`expected`] says what an accepted command
//!   must record, and [`check_reaction`] checks a vault reaction.
//! - [`check_i03`], [`check_rcf02`], [`check_handles`],
//!   [`check_i02_assignments`], [`check_i36`], [`check_i36_held`] and
//!   [`check_i36_grants`] are the invariant predicates. They read the
//!   views only.
//!
//! # Readings
//!
//! Each reading is the strictest one the spec text allows. Readings marked
//! as test-author choices fill a gap, so the implementer can match them or
//! raise them with Daniel.
//!
//! - A conflict fact for an account and a proposal is a declaration with
//!   `conflicted` set, on an assignment or at proposal level, or a detected
//!   conflict. It is permanent for that proposal across calls. After it,
//!   no content read and no act by that account on that proposal follows
//!   (I-03). Acts recorded today are scores, questions, "no questions",
//!   ranking summaries, IRC reviews, knock-out checks and amount
//!   determinations. Later lanes add cut-off votes and line acceptance.
//! - The `HasConflict` team of a proposal is every account with a held
//!   Receiving binding on it: the lead, team members and guardians.
//! - Reads follow P-10 in stages 1 and 2 (R-AC-01). In SUBMITTED only the
//!   FSTP coordinator reads, for the knock-out check, after declaring no
//!   conflict on the proposal (R-CF-02 AC). DRAFT is private to the
//!   applicant team, so any other reader is refused. Reads by the
//!   proposal's own Receiving accounts, reads outside stages 1 and 2, and
//!   coordinator reads in stages 1 and 2 are M4 visibility and unjudged.
//!   Every read, judged or not, is refused while a conflict fact exists or
//!   the vault answers `HasConflict` true at the current epoch. Every
//!   read by someone outside the applicant team, in any state, is refused
//!   before that reader declared no conflict, through an active assignment
//!   or at proposal level (R-CF-02).
//! - An assigned reviewer reads only through an active assignment: one
//!   whose assignee declared no conflict, in the proposal's current call,
//!   over an active committee member binding. Test-author choice: an
//!   assignee does not read in SUBMITTED, because P-10 opens reads in
//!   stages 1 and 2 only.
//! - `Assign` is the FSTP coordinator's (interim, design 2.7). A reviewer
//!   assignment needs an active committee member binding, and is made in
//!   SUBMITTED, STAGE1 or STAGE2. An IRC assignment needs an active IRC
//!   member binding and is made in IRC_REVIEW (test-author choice).
//!   DRAFT and terminal states refuse both. Each assignment starts
//!   awaiting its declaration.
//! - `Assign` is refused when the reviewer has a conflict fact on the
//!   proposal, or the vault answers `HasConflict` true. It is refused when
//!   the reviewer already holds an unreleased assignment of that kind on
//!   the proposal in its current call. A conflicted coordinator may assign,
//!   since assignment is not among the acts that the Conflict declarations
//!   section bars.
//! - P-03, P-10, P-11 and P-39 come from the frozen policy of the
//!   proposal's original call, also after re-entry (Q15 A).
//! - P-11 anonymous needs a handle never issued before in the cell, on any
//!   proposal, call or programme (R-AN-01). A missing handle is refused.
//!   A handle under P-11 named is unjudged.
//! - I-34 at assignment (test-author choice): while the proposal's
//!   unreleased reviewer assignments span fewer than P-39 organisations,
//!   a new reviewer must bring a new organisation. So every run of
//!   assignments keeps `distinct >= min(count, P-39)` after each accepted
//!   `Assign`. The organisation is the committee binding's field. A
//!   reviewer without one is unjudged.
//! - I-35: a reviewer whose organisation has a P-38 proximity list is
//!   refused when the vault answers that a team member declares an
//!   affiliation on that list. P-38 is live, so the head version counts. A
//!   vault reaction releases every unreleased reviewer assignment that the
//!   facts now put in breach of I-35 (enforcement point 3).
//! - I-02, assignment half: an account with an unreleased IRC assignment
//!   gets no reviewer assignment in the same programme, and the reverse. An unreleased
//!   assignment rests on a held binding of its role. When that binding
//!   ends, the same batch releases the assignment, unless another held
//!   binding of the role remains.
//! - A declaration on an assignment is the assignee's, while the
//!   assignment awaits it. A declaration with `conflicted` set releases
//!   the assignment in the same batch (R-CF-02). A conflicted declaration on
//!   an active assignment is accepted the same way, and a no-conflict one
//!   is unjudged. A proposal-level declaration is the
//!   FSTP coordinator's, or a committee member's under P-10 "all committee
//!   members". A `conflicted` declaration at proposal level releases the
//!   declarer's unreleased assignments on that proposal. A no-conflict
//!   declaration after a conflict fact is refused, because the fact is
//!   permanent. A declaration with `notifiable` set and `conflicted` clear
//!   is unjudged.
//! - A vault reaction records a detected conflict and releases the
//!   assignment, in the same batch, for every unreleased assignment whose
//!   assignee the vault now finds conflicted. It also records a detected
//!   conflict for every account with a proposal-level clearance that the
//!   vault now finds conflicted, so the fact stays when the relation ends.
//!   When the batch voids a Receiving binding under I-06, every account
//!   that judged the proposal and shares the voided account's verified
//!   identity gets a notifiable detection and a notification draft
//!   (R-CF-04). Released assignments count. No other detection is
//!   notifiable.
//! - `AddTeamMember` and `AddGuardian` record a detection and the
//!   releases for every tracked pair of the proposal that the vault finds
//!   conflicted with the new team, and the I-35 releases for it
//!   (enforcement point 1).
//! - I-36: "reviewed" means held a reviewer or IRC assignment on the
//!   proposal, released or not (test-author choice, the strictest). A
//!   proposal is under evaluation in its current call in SUBMITTED,
//!   STAGE1, STAGE2, RANKED, IRC_REVIEW and NEGOTIATION. A DEFERRED
//!   proposal is under evaluation in its current call and in the next
//!   published call of the programme (Q12). A Receiving binding of a
//!   former reviewer in such a call is refused, whatever P-12 says.
//! - I-36, decided 2026-10-25 (Reviewer assignment, data placement NOTE):
//!   a former reviewer takes no Receiving role in a call of a programme
//!   where they reviewed a proposal, until every proposal they reviewed is
//!   decided. Decided means terminal, or GRANTED or later. This closes the
//!   race in which a proposal is deferred into a call after its former
//!   reviewer drafted there. Two test-author choices, the strictest the
//!   text allows: "later call" covers every call of that programme, and
//!   "every proposal they reviewed" counts proposals of any programme.
//! - I-36 also holds as a state predicate: no held Receiving binding sits
//!   in a call where a proposal its account reviewed is under evaluation
//!   ([`check_i36_held`]). It catches a deferral that lands after a grant.
//! - Intake: `Submit` and `RecordPlanVersion` are the lead's, with an
//!   active Applicant binding on the proposal. `Submit` needs DRAFT, a
//!   published call with `opens <= now < deadline`, and a plan of the
//!   proposal with origin "submitted" that has at least one task, each with
//!   at least one milestone ("required fields present", test-author
//!   choice). It needs no guardian record (R-SB-02). It records the ethics
//!   declaration and the notice version (R-SB-05, R-NG-06) and the DRAFT
//!   to SUBMITTED transition. Submitting a superseded plan is refused.
//! - `RecordPlanVersion` with origin "submitted" needs DRAFT, a fresh plan
//!   id, fresh and distinct milestone ids, and it supersedes the live plan
//!   of the proposal when one exists, and nothing otherwise. Other origins are refused in DRAFT, SUBMITTED and
//!   terminal states, and unjudged elsewhere. An incomplete plan is
//!   unjudged at recording and refused at `Submit`.
//! - `Withdraw` is the lead's, with an active Applicant binding, in DRAFT,
//!   SUBMITTED, STAGE1, STAGE2, RANKED, IRC_REVIEW, DEFERRED and
//!   NEGOTIATION (NOTE 10). It records the transition to WITHDRAWN and
//!   ends the proposal's held Receiving bindings in the same batch (Q11).

use std::collections::{BTreeMap, BTreeSet};

use fstp_domain::assignment::{AssignmentKind, ReleaseCause};
use fstp_domain::command::{Actor, Command, DeclarationSubject};
use fstp_domain::id::{
    AccountId, AssignmentId, BindingId, CallId, Handle, MilestoneId, OrganisationId, PlanVersionId,
    PolicyVersionId, ProgrammeId, ProposalId, ProximityListId, VaultEpoch,
};
use fstp_domain::oracle::Query;
use fstp_domain::policy::{ReadAccess, ReviewerAnonymity};
use fstp_domain::proposal::{EthicsDeclaration, NoticeVersion, PlanOrigin};
use fstp_domain::record::{
    AssignmentReleased, BindingEnded, ConflictDeclared, ConflictDetected, ContentRead, Declared,
    Record, Transitioned,
};
use fstp_domain::roles::{BindingScope, CoolingOff, Role};
use fstp_domain::rules::{Row, StateTag};
use fstp_domain::time::Timestamp;

use crate::reference::sod::{self, Ask, RefBinding, RefGroup, Verdict};
use crate::vault::GroundTruth;

// ---------------------------------------------------------------------------
// Vault facts
// ---------------------------------------------------------------------------

/// The vault facts the review reference reads: the two review questions
/// of `SPEC/03-architecture/overview.md`.
pub trait ConflictFacts {
    /// "Does this reviewer have a conflict with this proposal's applicant team?"
    fn has_conflict(&self, reviewer: AccountId, team: &BTreeSet<AccountId>) -> bool;
    /// "Does any team member declare an affiliation on this proximity list?"
    fn declares_on_list(&self, team: &BTreeSet<AccountId>, list: ProximityListId) -> bool;
    /// "Do these two accounts share a verified identity?" (Identity discovery, R-CF-04)
    fn same_identity(&self, subject: AccountId, other: AccountId) -> bool;
}

impl ConflictFacts for GroundTruth {
    fn has_conflict(&self, reviewer: AccountId, team: &BTreeSet<AccountId>) -> bool {
        self.holds(&Query::HasConflict {
            reviewer,
            team: team.clone(),
        })
    }

    fn declares_on_list(&self, team: &BTreeSet<AccountId>, list: ProximityListId) -> bool {
        self.holds(&Query::DeclaresAffiliationOnList {
            team: team.clone(),
            list,
        })
    }

    fn same_identity(&self, subject: AccountId, other: AccountId) -> bool {
        self.holds(&Query::SameIdentityAsAny {
            subject,
            others: [other].into_iter().collect(),
        })
    }
}

// ---------------------------------------------------------------------------
// The view
// ---------------------------------------------------------------------------

/// The review parameters of one policy version.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RefPolicy {
    /// The programme.
    pub programme: ProgrammeId,
    /// P-03.
    pub p03: u8,
    /// P-10.
    pub p10: ReadAccess,
    /// P-11.
    pub p11: ReviewerAnonymity,
    /// P-39.
    pub p39: u8,
    /// P-38, live.
    pub p38: BTreeMap<OrganisationId, ProximityListId>,
}

/// A call's dates and publication, as the review reference sees them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RefCallDates {
    /// The programme.
    pub programme: ProgrammeId,
    /// The opening, inclusive.
    pub opens: Timestamp,
    /// The deadline, exclusive.
    pub deadline: Timestamp,
    /// The sequence number, once published.
    pub seq: Option<u32>,
    /// The policy version frozen at publication.
    pub policy: Option<PolicyVersionId>,
}

/// One proposal's life as the review reference sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RefLife {
    /// The call it was created in.
    pub call: CallId,
    /// The call it is evaluated in now: the creation call, or the call of its latest re-entry.
    pub current_call: CallId,
    /// The lead.
    pub lead: AccountId,
    /// The minor flag.
    pub minor: bool,
    /// The state.
    pub state: StateTag,
}

/// One plan version.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RefPlan {
    /// The proposal.
    pub proposal: ProposalId,
    /// Where it comes from.
    pub origin: PlanOrigin,
    /// Whether it has at least one task and every task has a milestone.
    pub complete: bool,
    /// Whether a later plan supersedes it.
    pub superseded: bool,
}

/// What a submission recorded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RefSubmission {
    /// The submitted plan.
    pub plan: PlanVersionId,
    /// The ethics declaration (R-SB-05).
    pub ethics: EthicsDeclaration,
    /// The notice version (R-NG-06).
    pub notice: NoticeVersion,
}

/// Where an assignment stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RefStatus {
    /// Awaiting the assignee's declaration (R-CF-02).
    Awaiting,
    /// The assignee declared no conflict.
    Active,
    /// Released.
    Released(ReleaseCause),
}

/// One assignment as the reference sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RefAssignment {
    /// The assignment.
    pub id: AssignmentId,
    /// The proposal.
    pub proposal: ProposalId,
    /// The call it was made in.
    pub call: CallId,
    /// The assignee.
    pub reviewer: AccountId,
    /// The kind.
    pub kind: AssignmentKind,
    /// The handle, under P-11 anonymous.
    pub handle: Option<Handle>,
    /// The status.
    pub status: RefStatus,
}

impl RefAssignment {
    /// Whether the assignment is not released.
    pub fn unreleased(&self) -> bool {
        !matches!(self.status, RefStatus::Released(_))
    }

    /// The role the assignment rests on.
    pub fn role(&self) -> Option<Role> {
        match self.kind {
            AssignmentKind::Reviewer => Some(Role::CommitteeMember),
            AssignmentKind::Irc | AssignmentKind::Amendment(_) => Some(Role::IrcMember),
        }
    }
}

/// The review reference's fold of core records.
///
/// It holds sets and maps only, so two histories that reach the same
/// situation give equal views. Breaches are recorded at fold time, in
/// ledger order, because a read is a breach only when it follows a fact.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RevView {
    /// Policy versions.
    pub policies: BTreeMap<PolicyVersionId, RefPolicy>,
    /// The head version of each programme.
    pub heads: BTreeMap<ProgrammeId, PolicyVersionId>,
    /// Calls.
    pub calls: BTreeMap<CallId, RefCallDates>,
    /// The organisation each binding records.
    pub organisations: BTreeMap<BindingId, OrganisationId>,
    /// Proposals.
    pub proposals: BTreeMap<ProposalId, RefLife>,
    /// Plan versions.
    pub plans: BTreeMap<PlanVersionId, RefPlan>,
    /// Milestone ids recorded in any plan.
    pub milestones: BTreeSet<MilestoneId>,
    /// Submissions.
    pub submissions: BTreeMap<ProposalId, RefSubmission>,
    /// Assignments.
    pub assignments: BTreeMap<AssignmentId, RefAssignment>,
    /// Conflict facts, declared or detected, by account and proposal.
    pub facts: BTreeSet<(AccountId, ProposalId)>,
    /// Proposal-level no-conflict declarations.
    pub cleared: BTreeSet<(AccountId, ProposalId)>,
    /// Every handle issued, with the first assignment that carried it.
    pub handles: BTreeMap<Handle, AssignmentId>,
    /// Handles issued more than once.
    pub handle_repeats: BTreeSet<Handle>,
    /// Accounts that held a reviewer or IRC assignment on a proposal (I-36).
    pub reviewed: BTreeSet<(AccountId, ProposalId)>,
    /// Content reads, by account and proposal.
    pub reads: BTreeSet<(AccountId, ProposalId)>,
    /// Reads and acts that followed a conflict fact for the same account and proposal.
    pub breaches: BTreeSet<(AccountId, ProposalId)>,
    /// Accounts ever bound to a proposal by a Receiving binding: its applicant team.
    pub receiving: BTreeSet<(AccountId, ProposalId)>,
    /// Reads by an account outside the applicant team with neither an active
    /// assignment nor a clearance on the proposal.
    pub undeclared_reads: BTreeSet<(AccountId, ProposalId)>,
    /// Receiving bindings granted to a former reviewer while I-36 barred
    /// them: in a call where a reviewed proposal was under evaluation, or
    /// in a call of a programme where they reviewed, while a reviewed
    /// proposal was undecided.
    pub i36_breaches: BTreeSet<(AccountId, CallId)>,
    /// The last vault epoch processed.
    pub epoch: VaultEpoch,
}

impl Default for RevView {
    fn default() -> RevView {
        RevView::new()
    }
}

/// The states in which a proposal is under evaluation in its current call (I-36).
pub const UNDER_EVALUATION: [StateTag; 7] = [
    StateTag::Submitted,
    StateTag::Stage1,
    StateTag::Stage2,
    StateTag::Ranked,
    StateTag::IrcReview,
    StateTag::Deferred,
    StateTag::Negotiation,
];

/// The states withdrawal is open in (NOTE 10).
pub const WITHDRAWABLE: [StateTag; 8] = [
    StateTag::Draft,
    StateTag::Submitted,
    StateTag::Stage1,
    StateTag::Stage2,
    StateTag::Ranked,
    StateTag::IrcReview,
    StateTag::Deferred,
    StateTag::Negotiation,
];

/// The terminal states of the states table.
pub const TERMINAL: [StateTag; 6] = [
    StateTag::Ineligible,
    StateTag::NotSelected,
    StateTag::Declined,
    StateTag::Withdrawn,
    StateTag::Completed,
    StateTag::Terminated,
];

/// Whether `s` is terminal, from the states table.
pub fn terminal(s: StateTag) -> bool {
    TERMINAL.contains(&s)
}

/// The states in which a reviewed proposal is decided for I-36: terminal,
/// or GRANTED or later (decided 2026-10-25).
pub const DECIDED: [StateTag; 8] = [
    StateTag::Ineligible,
    StateTag::NotSelected,
    StateTag::Declined,
    StateTag::Withdrawn,
    StateTag::Granted,
    StateTag::InExecution,
    StateTag::Completed,
    StateTag::Terminated,
];

/// Whether `s` is decided for I-36.
pub fn decided(s: StateTag) -> bool {
    DECIDED.contains(&s)
}

impl RevView {
    /// The view of an empty ledger.
    pub fn new() -> RevView {
        RevView {
            policies: BTreeMap::new(),
            heads: BTreeMap::new(),
            calls: BTreeMap::new(),
            organisations: BTreeMap::new(),
            proposals: BTreeMap::new(),
            plans: BTreeMap::new(),
            milestones: BTreeSet::new(),
            submissions: BTreeMap::new(),
            assignments: BTreeMap::new(),
            facts: BTreeSet::new(),
            cleared: BTreeSet::new(),
            handles: BTreeMap::new(),
            handle_repeats: BTreeSet::new(),
            reviewed: BTreeSet::new(),
            reads: BTreeSet::new(),
            breaches: BTreeSet::new(),
            receiving: BTreeSet::new(),
            undeclared_reads: BTreeSet::new(),
            i36_breaches: BTreeSet::new(),
            epoch: VaultEpoch::GENESIS,
        }
    }

    /// The view of `records`, folded in order.
    pub fn of<'a>(records: impl IntoIterator<Item = &'a Record>) -> Result<RevView, String> {
        let mut v = RevView::new();
        for r in records {
            v.fold(r)?;
        }
        Ok(v)
    }

    /// The frozen review parameters of `call`, once published.
    pub fn call_policy(&self, call: CallId) -> Option<&RefPolicy> {
        self.calls
            .get(&call)
            .and_then(|c| c.policy)
            .and_then(|v| self.policies.get(&v))
    }

    /// The frozen review parameters that govern `proposal`: those of its
    /// original call, also after re-entry (Q15 A, NOTE 8).
    pub fn governing_policy(&self, proposal: ProposalId) -> Option<&RefPolicy> {
        self.proposals
            .get(&proposal)
            .and_then(|l| self.call_policy(l.call))
    }

    /// The plan of `proposal` that no later plan supersedes, if any.
    pub fn live_plan(&self, proposal: ProposalId) -> Option<PlanVersionId> {
        self.plans
            .iter()
            .find(|(_, p)| p.proposal == proposal && !p.superseded)
            .map(|(id, _)| *id)
    }

    /// The accounts that judged `proposal`: every assignee, released or
    /// not, and every proposal-level clearance, without a conflict fact.
    pub fn judges_of(&self, proposal: ProposalId) -> BTreeSet<AccountId> {
        self.assignments
            .values()
            .filter(|a| a.proposal == proposal)
            .map(|a| a.reviewer)
            .chain(
                self.cleared
                    .iter()
                    .filter(|(_, p)| *p == proposal)
                    .map(|(a, _)| *a),
            )
            .filter(|a| !self.facts.contains(&(*a, proposal)))
            .collect()
    }

    /// The live P-38 list of `organisation` in `programme`.
    pub fn proximity_list(
        &self,
        programme: ProgrammeId,
        organisation: OrganisationId,
    ) -> Option<ProximityListId> {
        self.heads
            .get(&programme)
            .and_then(|v| self.policies.get(v))
            .and_then(|p| p.p38.get(&organisation).copied())
    }

    /// The programme of `proposal`.
    pub fn programme_of(&self, proposal: ProposalId) -> Option<ProgrammeId> {
        let life = self.proposals.get(&proposal)?;
        self.calls.get(&life.call).map(|c| c.programme)
    }

    /// The unreleased assignments of `account`.
    pub fn unreleased_of(&self, account: AccountId) -> impl Iterator<Item = &RefAssignment> {
        self.assignments
            .values()
            .filter(move |a| a.reviewer == account && a.unreleased())
    }

    /// Whether `account` holds an active assignment of `kind` on `proposal` in its current call.
    pub fn active_assignment(
        &self,
        account: AccountId,
        proposal: ProposalId,
        kind: AssignmentKind,
    ) -> bool {
        let Some(life) = self.proposals.get(&proposal) else {
            return false;
        };
        self.assignments.values().any(|a| {
            a.reviewer == account
                && a.proposal == proposal
                && a.kind == kind
                && a.call == life.current_call
                && a.status == RefStatus::Active
        })
    }

    /// The next published call of the programme of `call`, by sequence number.
    pub fn next_call(&self, call: CallId) -> Option<CallId> {
        let c = self.calls.get(&call)?;
        let seq = c.seq?;
        let target = seq.checked_add(1)?;
        self.calls
            .iter()
            .find(|(_, d)| d.programme == c.programme && d.seq == Some(target))
            .map(|(id, _)| *id)
    }

    /// Whether `proposal` is under evaluation in `call` now (I-36, Q12).
    pub fn under_evaluation_in(&self, proposal: ProposalId, call: CallId) -> bool {
        let Some(life) = self.proposals.get(&proposal) else {
            return false;
        };
        if !UNDER_EVALUATION.contains(&life.state) {
            return false;
        }
        if life.current_call == call {
            return true;
        }
        life.state == StateTag::Deferred && self.next_call(life.current_call) == Some(call)
    }

    /// The proposals `account` reviewed: any reviewer or IRC assignment,
    /// released or not (I-36).
    pub fn reviewed_by(&self, account: AccountId) -> impl Iterator<Item = ProposalId> + '_ {
        self.reviewed
            .iter()
            .filter(move |(a, _)| *a == account)
            .map(|(_, p)| *p)
    }

    /// Whether `proposal` is decided for I-36: terminal, or GRANTED or
    /// later. An unknown proposal is not decided.
    pub fn decided(&self, proposal: ProposalId) -> bool {
        self.proposals
            .get(&proposal)
            .is_some_and(|l| decided(l.state))
    }

    /// The narrower check that I-36 had before the decision of 2026-10-25:
    /// a reviewed proposal is under evaluation in `call` now. It is kept
    /// for the teeth tests, which inject it as the faulty engine.
    pub fn i36_bars_current_call_only(&self, account: AccountId, call: CallId) -> bool {
        self.reviewed_by(account)
            .any(|p| self.under_evaluation_in(p, call))
    }

    /// Whether a Receiving binding of `account` in `call` breaks I-36 now.
    ///
    /// It does when a proposal the account reviewed is under evaluation in
    /// `call`. It also does when the account reviewed a proposal of the
    /// programme of `call`, and any proposal it reviewed is undecided
    /// (decided 2026-10-25).
    pub fn i36_bars(&self, account: AccountId, call: CallId) -> bool {
        if self.i36_bars_current_call_only(account, call) {
            return true;
        }
        let Some(programme) = self.calls.get(&call).map(|c| c.programme) else {
            return false;
        };
        let reviewed_here = self
            .reviewed_by(account)
            .any(|p| self.programme_of(p) == Some(programme));
        reviewed_here && self.reviewed_by(account).any(|p| !self.decided(p))
    }

    fn act(&mut self, account: AccountId, proposal: ProposalId) {
        if self.facts.contains(&(account, proposal)) {
            self.breaches.insert((account, proposal));
        }
    }

    fn act_by_assignment(&mut self, assignment: AssignmentId) -> Result<(), String> {
        let a = self
            .assignments
            .get(&assignment)
            .ok_or_else(|| format!("act on unknown assignment {assignment:?}"))?;
        let (r, p) = (a.reviewer, a.proposal);
        self.act(r, p);
        Ok(())
    }

    /// Folds one core record. Records outside review, intake and their
    /// policy and call inputs leave the view unchanged. An error names a
    /// record the reference cannot follow, which no engine may emit.
    pub fn fold(&mut self, record: &Record) -> Result<(), String> {
        match record {
            Record::PolicyVersionRecorded { version, .. } => {
                let f = &version.frozen;
                self.policies.insert(
                    version.id,
                    RefPolicy {
                        programme: version.programme,
                        p03: f.p03.get(),
                        p10: f.p10,
                        p11: f.p11,
                        p39: f.p39.get(),
                        p38: version.live.p38.0.clone(),
                    },
                );
                self.heads.insert(version.programme, version.id);
            }
            Record::CallDrafted {
                call,
                programme,
                opens,
                deadline,
                ..
            } => {
                self.calls.insert(
                    *call,
                    RefCallDates {
                        programme: *programme,
                        opens: *opens,
                        deadline: *deadline,
                        seq: None,
                        policy: None,
                    },
                );
            }
            Record::CallEdited {
                call,
                opens,
                deadline,
                ..
            } => {
                let c = self
                    .calls
                    .get_mut(call)
                    .ok_or_else(|| format!("unknown call {call:?} edited"))?;
                c.opens = *opens;
                c.deadline = *deadline;
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
            Record::BindingGranted(g) => {
                if let Some(o) = g.organisation {
                    self.organisations.insert(g.binding, o);
                }
                if let BindingScope::Proposal { proposal, call } = g.scope {
                    self.receiving.insert((g.account, proposal));
                    if self.i36_bars(g.account, call) {
                        self.i36_breaches.insert((g.account, call));
                    }
                }
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
                    RefLife {
                        call: *call,
                        current_call: *call,
                        lead: *lead,
                        minor: *minor,
                        state: StateTag::Draft,
                    },
                );
            }
            Record::PlanVersionRecorded(p) => {
                if self.plans.contains_key(&p.plan) {
                    return Err(format!("plan {:?} recorded twice", p.plan));
                }
                if !self.proposals.contains_key(&p.proposal) {
                    return Err(format!("plan for unknown proposal {:?}", p.proposal));
                }
                if let Some(s) = p.supersedes
                    && let Some(old) = self.plans.get_mut(&s)
                {
                    old.superseded = true;
                }
                for t in &p.tasks {
                    for m in &t.milestones {
                        self.milestones.insert(m.id);
                    }
                }
                self.plans.insert(
                    p.plan,
                    RefPlan {
                        proposal: p.proposal,
                        origin: p.origin,
                        complete: !p.tasks.is_empty()
                            && p.tasks.iter().all(|t| !t.milestones.is_empty()),
                        superseded: false,
                    },
                );
            }
            Record::Submitted {
                proposal,
                plan,
                ethics,
                notice,
            } => {
                if !self.proposals.contains_key(proposal) {
                    return Err(format!("unknown proposal {proposal:?} submitted"));
                }
                self.submissions.insert(
                    *proposal,
                    RefSubmission {
                        plan: *plan,
                        ethics: *ethics,
                        notice: *notice,
                    },
                );
            }
            Record::Transitioned(t) => {
                let life = self
                    .proposals
                    .get_mut(&t.proposal)
                    .ok_or_else(|| format!("unknown proposal {:?} transitioned", t.proposal))?;
                if life.state != t.from {
                    return Err(format!(
                        "{:?} transitioned from {:?}, but it is in {:?}",
                        t.proposal, t.from, life.state
                    ));
                }
                life.state = t.to;
            }
            Record::ReEntered {
                proposal, to_call, ..
            } => {
                let life = self
                    .proposals
                    .get_mut(proposal)
                    .ok_or_else(|| format!("unknown proposal {proposal:?} re-entered"))?;
                life.current_call = *to_call;
            }
            Record::Assigned(a) => {
                if self.assignments.contains_key(&a.assignment) {
                    return Err(format!("assignment {:?} recorded twice", a.assignment));
                }
                if !self.proposals.contains_key(&a.proposal) {
                    return Err(format!("assignment to unknown proposal {:?}", a.proposal));
                }
                if let Some(h) = a.handle
                    && self.handles.insert(h, a.assignment).is_some()
                {
                    self.handle_repeats.insert(h);
                }
                if matches!(a.kind, AssignmentKind::Reviewer | AssignmentKind::Irc) {
                    self.reviewed.insert((a.reviewer, a.proposal));
                }
                self.assignments.insert(
                    a.assignment,
                    RefAssignment {
                        id: a.assignment,
                        proposal: a.proposal,
                        call: a.call,
                        reviewer: a.reviewer,
                        kind: a.kind,
                        handle: a.handle,
                        status: RefStatus::Awaiting,
                    },
                );
            }
            Record::ConflictDeclared(d) => self.fold_declared(d)?,
            Record::ConflictDetected(d) => {
                self.facts.insert((d.account, d.proposal));
            }
            Record::AssignmentReleased(r) => {
                let a = self
                    .assignments
                    .get_mut(&r.assignment)
                    .ok_or_else(|| format!("unknown assignment {:?} released", r.assignment))?;
                if !a.unreleased() {
                    return Err(format!("assignment {:?} released twice", r.assignment));
                }
                a.status = RefStatus::Released(r.cause);
            }
            Record::ContentRead(c) => {
                self.reads.insert((c.account, c.proposal));
                let declared = self.receiving.contains(&(c.account, c.proposal))
                    || self.cleared.contains(&(c.account, c.proposal))
                    || self.assignments.values().any(|a| {
                        a.reviewer == c.account
                            && a.proposal == c.proposal
                            && a.status == RefStatus::Active
                    });
                if !declared {
                    self.undeclared_reads.insert((c.account, c.proposal));
                }
                self.act(c.account, c.proposal);
            }
            Record::KnockOutRecorded {
                proposal,
                coordinator,
                ..
            } => self.act(*coordinator, *proposal),
            Record::AmountDetermined { proposal, by, .. } => self.act(*by, *proposal),
            Record::ScoreRecorded(s) => self.act_by_assignment(s.key.assignment)?,
            Record::QuestionAsked { assignment, .. }
            | Record::NoQuestionsRecorded { assignment, .. }
            | Record::RankingSummaryRecorded { assignment, .. }
            | Record::IrcReviewRecorded { assignment, .. } => {
                self.act_by_assignment(*assignment)?;
            }
            Record::VaultEpochProcessed { epoch } => self.epoch = *epoch,
            _ => {}
        }
        Ok(())
    }

    fn fold_declared(&mut self, d: &ConflictDeclared) -> Result<(), String> {
        match d.subject {
            Declared::Assignment(id) => {
                let a = self
                    .assignments
                    .get_mut(&id)
                    .ok_or_else(|| format!("declaration on unknown assignment {id:?}"))?;
                if d.conflicted {
                    let pair = (a.reviewer, a.proposal);
                    self.facts.insert(pair);
                } else if a.status == RefStatus::Awaiting {
                    a.status = RefStatus::Active;
                }
            }
            Declared::Proposal { proposal, account } => {
                if !self.proposals.contains_key(&proposal) {
                    return Err(format!("declaration on unknown proposal {proposal:?}"));
                }
                if d.conflicted {
                    self.facts.insert((account, proposal));
                } else {
                    self.cleared.insert((account, proposal));
                }
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Roles through the L-SOD reference view
// ---------------------------------------------------------------------------

/// Whether `account` holds a binding of `role` in `programme` that is
/// active at `now`: held, not suspended and started.
pub fn holds_active(
    view: &sod::View,
    account: AccountId,
    role: Role,
    programme: ProgrammeId,
    now: Timestamp,
) -> bool {
    view.bindings_of(account, programme)
        .any(|b| b.role == role && b.active() && b.start <= now)
}

/// The organisation of `account`'s active committee member binding in `programme`.
pub fn committee_organisation(
    view: &sod::View,
    rev: &RevView,
    account: AccountId,
    programme: ProgrammeId,
    now: Timestamp,
) -> Option<OrganisationId> {
    view.bindings_of(account, programme)
        .filter(|b| b.role == Role::CommitteeMember && b.active() && b.start <= now)
        .find_map(|b| rev.organisations.get(&b.binding).copied())
}

/// Whether `account` holds a held Receiving binding on `proposal`.
pub fn receiving_holder(view: &sod::View, account: AccountId, proposal: ProposalId) -> bool {
    view.bindings.values().any(|b| {
        b.account == account
            && b.proposal == Some(proposal)
            && b.group == RefGroup::Receiving
            && b.held()
    })
}

/// The `HasConflict` team of `proposal`: every held Receiving account on it.
pub fn team_of(view: &sod::View, proposal: ProposalId) -> BTreeSet<AccountId> {
    view.bindings
        .values()
        .filter(|b| b.proposal == Some(proposal) && b.group == RefGroup::Receiving && b.held())
        .map(|b| b.account)
        .collect()
}

/// Whether `account` is the lead of `proposal` with an active Applicant binding on it.
pub fn active_lead(
    view: &sod::View,
    rev: &RevView,
    account: AccountId,
    proposal: ProposalId,
    now: Timestamp,
) -> bool {
    rev.proposals
        .get(&proposal)
        .is_some_and(|l| l.lead == account)
        && view.bindings.values().any(|b| {
            b.account == account
                && b.role == Role::Applicant
                && b.proposal == Some(proposal)
                && b.active()
                && b.start <= now
        })
}

// ---------------------------------------------------------------------------
// Verdicts
// ---------------------------------------------------------------------------

fn refuse(why: &str) -> Verdict {
    Verdict::Refuse(why.to_owned())
}

/// The reference verdict on `ask`.
///
/// It judges `Assign`, `Unassign`, `DeclareConflict`, `ReadContent`,
/// `RecordRankingSummary`, `RecordPlanVersion`, `Submit` and `Withdraw`.
/// It adds I-36 to the L-SOD verdict on `CreateDraft`, `AddTeamMember`
/// and `AddGuardian`, and passes
/// every other command to the L-SOD verdict over `truth`. `facts` answers
/// the review questions: the ground truth itself for a truthful vault, or
/// a havoc oracle's bits.
pub fn verdict(
    view: &sod::View,
    rev: &RevView,
    truth: &GroundTruth,
    facts: &dyn ConflictFacts,
    ask: &Ask<'_>,
) -> Verdict {
    let Actor::Account(actor) = ask.actor else {
        return match ask.cmd {
            Command::Assign { .. }
            | Command::Unassign { .. }
            | Command::DeclareConflict { .. }
            | Command::ReadContent { .. }
            | Command::RecordPlanVersion { .. }
            | Command::Submit { .. }
            | Command::RecordRankingSummary { .. }
            | Command::Withdraw { .. } => refuse("actor"),
            _ => sod::verdict(view, truth, ask),
        };
    };
    let now = ask.now;
    match ask.cmd {
        Command::Assign {
            assignment,
            proposal,
            reviewer,
            kind,
            handle,
        } => assign_verdict(
            view,
            rev,
            facts,
            actor,
            now,
            *assignment,
            *proposal,
            *reviewer,
            *kind,
            *handle,
        ),
        Command::Unassign { assignment } => {
            let Some(a) = rev.assignments.get(assignment) else {
                return refuse("unknown assignment");
            };
            let Some(programme) = rev.programme_of(a.proposal) else {
                return refuse("unknown programme");
            };
            if !holds_active(view, actor, Role::FstpCoordinator, programme, now) {
                return refuse("actor");
            }
            if !a.unreleased() {
                return refuse("assignment already released");
            }
            Verdict::Accept
        }
        Command::DeclareConflict {
            subject,
            conflicted,
            notifiable,
        } => declare_verdict(view, rev, actor, now, *subject, *conflicted, *notifiable),
        Command::ReadContent { proposal } => read_verdict(view, rev, facts, actor, now, *proposal),
        Command::RecordRankingSummary {
            proposal,
            assignment,
            ..
        } => summary_verdict(view, rev, facts, actor, now, *proposal, *assignment),
        Command::RecordPlanVersion {
            plan,
            proposal,
            origin,
            supersedes,
            tasks,
            ..
        } => {
            let Some(life) = rev.proposals.get(proposal) else {
                return refuse("unknown proposal");
            };
            if !active_lead(view, rev, actor, *proposal, now) {
                return refuse("actor");
            }
            if rev.plans.contains_key(plan) {
                return refuse("plan id reused");
            }
            let mut seen = BTreeSet::new();
            for t in tasks {
                for m in &t.milestones {
                    if rev.milestones.contains(&m.id) || !seen.insert(m.id) {
                        return refuse("milestone id reused");
                    }
                }
            }
            if let Some(s) = supersedes
                && rev.plans.get(s).is_none_or(|p| p.proposal != *proposal)
            {
                return refuse("superseded plan of another proposal");
            }
            if *supersedes != rev.live_plan(*proposal) {
                return refuse("a new plan supersedes the live plan, and only it");
            }
            let early =
                matches!(life.state, StateTag::Draft | StateTag::Submitted) || terminal(life.state);
            match origin {
                PlanOrigin::Submitted if life.state != StateTag::Draft => {
                    return refuse("a submitted plan is recorded in DRAFT");
                }
                PlanOrigin::Submitted => {}
                _ if early => return refuse("origin not open in this state"),
                _ => return Verdict::Unjudged,
            }
            let complete = !tasks.is_empty() && tasks.iter().all(|t| !t.milestones.is_empty());
            let dated = tasks
                .iter()
                .flat_map(|t| t.milestones.iter())
                .all(|m| m.start <= m.due);
            if complete && dated {
                Verdict::Accept
            } else {
                Verdict::Unjudged
            }
        }
        Command::Submit { proposal, plan, .. } => {
            let Some(life) = rev.proposals.get(proposal) else {
                return refuse("unknown proposal");
            };
            if !active_lead(view, rev, actor, *proposal, now) {
                return refuse("actor");
            }
            if life.state != StateTag::Draft {
                return refuse("Submit needs DRAFT");
            }
            let Some(c) = rev.calls.get(&life.call) else {
                return refuse("unknown call");
            };
            if c.seq.is_none() || now < c.opens || now >= c.deadline {
                return refuse("call not open");
            }
            let Some(p) = rev.plans.get(plan) else {
                return refuse("unknown plan");
            };
            if p.proposal != *proposal || p.origin != PlanOrigin::Submitted {
                return refuse("plan of another proposal or origin");
            }
            if !p.complete {
                return refuse("required fields missing");
            }
            if p.superseded {
                return refuse("only the latest plan version counts");
            }
            Verdict::Accept
        }
        Command::Withdraw { proposal } => {
            let Some(life) = rev.proposals.get(proposal) else {
                return refuse("unknown proposal");
            };
            if !active_lead(view, rev, actor, *proposal, now) {
                return refuse("actor");
            }
            if !WITHDRAWABLE.contains(&life.state) {
                return refuse("not withdrawable (NOTE 10)");
            }
            Verdict::Accept
        }
        Command::CreateDraft { call, .. } => {
            with_i36(sod::verdict(view, truth, ask), rev, actor, *call)
        }
        Command::AddTeamMember {
            proposal, account, ..
        }
        | Command::AddGuardian {
            proposal, account, ..
        } => {
            let v = sod::verdict(view, truth, ask);
            match rev.proposals.get(proposal) {
                Some(life) => with_i36(v, rev, *account, life.call),
                None => v,
            }
        }
        _ => sod::verdict(view, truth, ask),
    }
}

fn with_i36(v: Verdict, rev: &RevView, account: AccountId, call: CallId) -> Verdict {
    if v.accepts() && rev.i36_bars(account, call) {
        refuse("I-36")
    } else {
        v
    }
}

#[allow(clippy::too_many_arguments)]
fn assign_verdict(
    view: &sod::View,
    rev: &RevView,
    facts: &dyn ConflictFacts,
    actor: AccountId,
    now: Timestamp,
    assignment: AssignmentId,
    proposal: ProposalId,
    reviewer: AccountId,
    kind: AssignmentKind,
    handle: Option<Handle>,
) -> Verdict {
    let Some(life) = rev.proposals.get(&proposal) else {
        return refuse("unknown proposal");
    };
    let Some(programme) = rev.programme_of(proposal) else {
        return refuse("unknown programme");
    };
    if !holds_active(view, actor, Role::FstpCoordinator, programme, now) {
        return refuse("actor");
    }
    if rev.assignments.contains_key(&assignment) {
        return refuse("assignment id reused");
    }
    if life.state == StateTag::Draft || terminal(life.state) {
        return refuse("no assignment in DRAFT or a terminal state");
    }
    let mut unjudged = false;
    let role = match kind {
        AssignmentKind::Reviewer => {
            match life.state {
                StateTag::Submitted | StateTag::Stage1 | StateTag::Stage2 => {}
                _ => unjudged = true,
            }
            Role::CommitteeMember
        }
        AssignmentKind::Irc => {
            match life.state {
                StateTag::IrcReview => {}
                StateTag::Deferred => unjudged = true,
                _ => return refuse("IRC assignments are made in IRC_REVIEW"),
            }
            Role::IrcMember
        }
        AssignmentKind::Amendment(_) => return Verdict::Unjudged,
    };
    if !holds_active(view, reviewer, role, programme, now) {
        return refuse("the assignee holds no active binding of the role");
    }
    let duplicate = rev.assignments.values().any(|a| {
        a.reviewer == reviewer
            && a.proposal == proposal
            && a.kind == kind
            && a.call == life.current_call
            && a.unreleased()
    });
    if duplicate {
        return refuse("already assigned");
    }
    let other = match kind {
        AssignmentKind::Reviewer => AssignmentKind::Irc,
        _ => AssignmentKind::Reviewer,
    };
    // I-02 and SoD-02 hold within one programme (NOTE 3).
    if rev
        .unreleased_of(reviewer)
        .any(|a| a.kind == other && rev.programme_of(a.proposal) == Some(programme))
    {
        return refuse("I-02");
    }
    if rev.facts.contains(&(reviewer, proposal)) {
        return refuse("I-03: conflict fact");
    }
    let team = team_of(view, proposal);
    if facts.has_conflict(reviewer, &team) {
        return refuse("I-03: the vault finds a conflict");
    }
    match rev.governing_policy(proposal).map(|p| p.p11) {
        Some(ReviewerAnonymity::Anonymous) => match handle {
            None => return refuse("R-AN-01: no handle under P-11 anonymous"),
            Some(h) if rev.handles.contains_key(&h) => {
                return refuse("R-AN-01: handle issued before");
            }
            Some(_) => {}
        },
        Some(ReviewerAnonymity::Named) => {
            if handle.is_some() {
                unjudged = true;
            }
        }
        None => return refuse("call not published"),
    }
    if kind == AssignmentKind::Reviewer {
        match committee_organisation(view, rev, reviewer, programme, now) {
            None => unjudged = true,
            Some(org) => {
                let p39 = rev.governing_policy(proposal).map_or(0, |p| p.p39);
                let orgs = assigned_organisations(view, rev, proposal, now);
                if orgs.len() < usize::from(p39) && orgs.contains(&org) {
                    return refuse("I-34");
                }
                if let Some(list) = rev.proximity_list(programme, org)
                    && facts.declares_on_list(&team, list)
                {
                    return refuse("I-35");
                }
            }
        }
    }
    // A conflicted coordinator may assign: assignment is not among the
    // barred acts of the Conflict declarations section.
    if unjudged {
        Verdict::Unjudged
    } else {
        Verdict::Accept
    }
}

/// The organisations of the unreleased reviewer assignments of `proposal`
/// in its current call, from each assignee's committee binding.
pub fn assigned_organisations(
    view: &sod::View,
    rev: &RevView,
    proposal: ProposalId,
    now: Timestamp,
) -> BTreeSet<OrganisationId> {
    let (Some(life), Some(programme)) = (rev.proposals.get(&proposal), rev.programme_of(proposal))
    else {
        return BTreeSet::new();
    };
    rev.assignments
        .values()
        .filter(|a| {
            a.proposal == proposal
                && a.kind == AssignmentKind::Reviewer
                && a.call == life.current_call
                && a.unreleased()
        })
        .filter_map(|a| committee_organisation(view, rev, a.reviewer, programme, now))
        .collect()
}

/// The number of unreleased reviewer assignments of `proposal` in its current call.
pub fn assigned_count(rev: &RevView, proposal: ProposalId) -> usize {
    let Some(life) = rev.proposals.get(&proposal) else {
        return 0;
    };
    rev.assignments
        .values()
        .filter(|a| {
            a.proposal == proposal
                && a.kind == AssignmentKind::Reviewer
                && a.call == life.current_call
                && a.unreleased()
        })
        .count()
}

fn declare_verdict(
    view: &sod::View,
    rev: &RevView,
    actor: AccountId,
    now: Timestamp,
    subject: DeclarationSubject,
    conflicted: bool,
    notifiable: bool,
) -> Verdict {
    match subject {
        DeclarationSubject::Assignment(id) => {
            let Some(a) = rev.assignments.get(&id) else {
                return refuse("unknown assignment");
            };
            if a.reviewer != actor {
                return refuse("only the assignee declares on an assignment");
            }
            let Some(programme) = rev.programme_of(a.proposal) else {
                return refuse("unknown programme");
            };
            let Some(role) = a.role() else {
                return refuse("unknown role");
            };
            if !holds_active(view, actor, role, programme, now) {
                return refuse("the assignee's binding is not active");
            }
            match a.status {
                RefStatus::Released(_) => refuse("assignment released"),
                // A conflict found after a no-conflict declaration (R-CF-02).
                RefStatus::Active if conflicted => Verdict::Accept,
                RefStatus::Active => Verdict::Unjudged,
                RefStatus::Awaiting if notifiable && !conflicted => Verdict::Unjudged,
                RefStatus::Awaiting => Verdict::Accept,
            }
        }
        DeclarationSubject::Proposal(proposal) => {
            let Some(life) = rev.proposals.get(&proposal) else {
                return refuse("unknown proposal");
            };
            let Some(programme) = rev.programme_of(proposal) else {
                return refuse("unknown programme");
            };
            let coordinator = holds_active(view, actor, Role::FstpCoordinator, programme, now);
            let all_committee = rev
                .governing_policy(proposal)
                .is_some_and(|p| p.p10 == ReadAccess::AllCommitteeMembers);
            let member = holds_active(view, actor, Role::CommitteeMember, programme, now);
            if !coordinator && !(member && all_committee) {
                return if member {
                    Verdict::Unjudged
                } else {
                    refuse("actor")
                };
            }
            if life.state == StateTag::Draft || terminal(life.state) {
                return refuse("nothing to declare on in DRAFT or a terminal state");
            }
            if rev.facts.contains(&(actor, proposal)) && !conflicted {
                return refuse("the conflict fact is permanent");
            }
            if rev.facts.contains(&(actor, proposal)) || rev.cleared.contains(&(actor, proposal)) {
                return Verdict::Unjudged;
            }
            if notifiable && !conflicted {
                return Verdict::Unjudged;
            }
            if life.state == StateTag::Submitted {
                Verdict::Accept
            } else {
                Verdict::Unjudged
            }
        }
    }
}

fn read_verdict(
    view: &sod::View,
    rev: &RevView,
    facts: &dyn ConflictFacts,
    actor: AccountId,
    now: Timestamp,
    proposal: ProposalId,
) -> Verdict {
    let Some(life) = rev.proposals.get(&proposal) else {
        return refuse("unknown proposal");
    };
    let Some(programme) = rev.programme_of(proposal) else {
        return refuse("unknown programme");
    };
    if receiving_holder(view, actor, proposal) {
        return Verdict::Unjudged;
    }
    if rev.facts.contains(&(actor, proposal)) {
        return refuse("I-03: conflict fact");
    }
    if facts.has_conflict(actor, &team_of(view, proposal)) {
        return refuse("I-03: the vault finds a conflict");
    }
    let coordinator = holds_active(view, actor, Role::FstpCoordinator, programme, now);
    let cleared = rev.cleared.contains(&(actor, proposal));
    let assigned = rev
        .assignments
        .values()
        .any(|a| a.reviewer == actor && a.proposal == proposal && a.status == RefStatus::Active);
    if !cleared && !assigned {
        return refuse("R-CF-02: no declaration before the read");
    }
    let p10 = rev.governing_policy(proposal).map(|p| p.p10);
    match life.state {
        StateTag::Draft => refuse("DRAFT is private to the applicant team"),
        StateTag::Submitted => {
            if coordinator && cleared {
                Verdict::Accept
            } else {
                refuse("R-CF-02: only the declared FSTP coordinator reads in SUBMITTED")
            }
        }
        StateTag::Stage1 | StateTag::Stage2 => {
            let member = holds_active(view, actor, Role::CommitteeMember, programme, now);
            if p10 == Some(ReadAccess::OperatorStaffOnly) {
                return Verdict::Unjudged;
            }
            if member && rev.active_assignment(actor, proposal, AssignmentKind::Reviewer) {
                return Verdict::Accept;
            }
            if member && cleared && p10 == Some(ReadAccess::AllCommitteeMembers) {
                return Verdict::Accept;
            }
            if coordinator {
                return Verdict::Unjudged;
            }
            refuse("P-10")
        }
        _ => Verdict::Unjudged,
    }
}

/// The verdict on a `RecordRankingSummary` of `assignment` on `proposal`
/// by `actor`: an assigned-reviewer act (Conflict declarations). It needs
/// the actor's active reviewer assignment on the proposal in its current
/// call, over an active committee member binding, in STAGE1, STAGE2 or
/// RANKED, with no conflict fact and no conflict the vault finds (I-03).
fn summary_verdict(
    view: &sod::View,
    rev: &RevView,
    facts: &dyn ConflictFacts,
    actor: AccountId,
    now: Timestamp,
    proposal: ProposalId,
    assignment: AssignmentId,
) -> Verdict {
    let (Some(life), Some(programme)) = (rev.proposals.get(&proposal), rev.programme_of(proposal))
    else {
        return refuse("unknown proposal");
    };
    let Some(a) = rev.assignments.get(&assignment) else {
        return refuse("unknown assignment");
    };
    if a.reviewer != actor || a.proposal != proposal || a.kind != AssignmentKind::Reviewer {
        return refuse("only the assigned reviewer writes the summary of its proposal");
    }
    if !matches!(
        life.state,
        StateTag::Stage1 | StateTag::Stage2 | StateTag::Ranked
    ) {
        return refuse("summaries are written in STAGE1, STAGE2 and RANKED");
    }
    if a.status != RefStatus::Active || a.call != life.current_call {
        return refuse("R-CF-02: no active assignment in the current call");
    }
    if !holds_active(view, actor, Role::CommitteeMember, programme, now) {
        return refuse("the committee member binding is not active");
    }
    if rev.facts.contains(&(actor, proposal)) {
        return refuse("I-03: conflict fact");
    }
    if facts.has_conflict(actor, &team_of(view, proposal)) {
        return refuse("I-03: the vault finds a conflict");
    }
    Verdict::Accept
}

/// Whether committee member `member` recuses from the cut-off vote of
/// `call` (Conflict declarations): a conflict fact, or a conflict the
/// vault finds, on any RANKED proposal whose current call is `call`.
pub fn recused(
    view: &sod::View,
    rev: &RevView,
    facts: &dyn ConflictFacts,
    member: AccountId,
    call: CallId,
) -> bool {
    rev.proposals.iter().any(|(p, life)| {
        life.state == StateTag::Ranked
            && life.current_call == call
            && (rev.facts.contains(&(member, *p)) || facts.has_conflict(member, &team_of(view, *p)))
    })
}

// ---------------------------------------------------------------------------
// Expected records
// ---------------------------------------------------------------------------

/// Which records an accepted batch may hold beside the required ones.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Allow {
    /// Only `VaultOutcome` and `OutboxEnqueued`.
    Audit,
    /// Also releases of assignments on the proposal and reservation releases (withdrawal).
    Withdrawal(ProposalId),
    /// Anything: another lane's command, whose records that lane's reference checks.
    Any,
}

/// What an accepted command must record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Expected {
    /// Records the batch must hold, each exactly.
    pub required: Vec<Record>,
    /// What else it may hold.
    pub allow: Allow,
}

/// What `ask` must record when accepted, at vault epoch `epoch`, under
/// the review facts `facts`.
pub fn expected(
    view: &sod::View,
    rev: &RevView,
    facts: &dyn ConflictFacts,
    ask: &Ask<'_>,
    epoch: VaultEpoch,
) -> Option<Expected> {
    let Actor::Account(actor) = ask.actor else {
        return None;
    };
    let audit = |required| {
        Some(Expected {
            required,
            allow: Allow::Audit,
        })
    };
    match ask.cmd {
        Command::Assign {
            assignment,
            proposal,
            reviewer,
            kind,
            handle,
        } => {
            let life = rev.proposals.get(proposal)?;
            audit(vec![Record::Assigned(fstp_domain::record::Assigned {
                assignment: *assignment,
                proposal: *proposal,
                call: life.current_call,
                reviewer: *reviewer,
                kind: *kind,
                handle: *handle,
                by: actor,
                epoch,
            })])
        }
        Command::Unassign { assignment } => {
            audit(vec![Record::AssignmentReleased(AssignmentReleased {
                assignment: *assignment,
                cause: ReleaseCause::Unassigned,
            })])
        }
        Command::DeclareConflict {
            subject,
            conflicted,
            notifiable,
        } => {
            let (declared, released): (Declared, Vec<AssignmentId>) = match subject {
                DeclarationSubject::Assignment(id) => (
                    Declared::Assignment(*id),
                    if *conflicted { vec![*id] } else { Vec::new() },
                ),
                DeclarationSubject::Proposal(p) => (
                    Declared::Proposal {
                        proposal: *p,
                        account: actor,
                    },
                    if *conflicted {
                        rev.unreleased_of(actor)
                            .filter(|a| a.proposal == *p)
                            .map(|a| a.id)
                            .collect()
                    } else {
                        Vec::new()
                    },
                ),
            };
            let mut required = vec![Record::ConflictDeclared(ConflictDeclared {
                subject: declared,
                conflicted: *conflicted,
                notifiable: *notifiable,
            })];
            required.extend(released.into_iter().map(|assignment| {
                Record::AssignmentReleased(AssignmentReleased {
                    assignment,
                    cause: ReleaseCause::DeclaredConflict,
                })
            }));
            audit(required)
        }
        Command::ReadContent { proposal } => audit(vec![Record::ContentRead(ContentRead {
            account: actor,
            proposal: *proposal,
        })]),
        Command::RecordRankingSummary {
            proposal,
            assignment,
            title,
            neutral_summary,
            rationale,
        } => audit(vec![Record::RankingSummaryRecorded {
            proposal: *proposal,
            assignment: *assignment,
            title: *title,
            neutral_summary: *neutral_summary,
            rationale: *rationale,
        }]),
        Command::RecordPlanVersion {
            plan,
            proposal,
            origin,
            supersedes,
            tasks,
            content,
        } => audit(vec![Record::PlanVersionRecorded(
            fstp_domain::record::PlanVersionRecorded {
                plan: *plan,
                proposal: *proposal,
                origin: *origin,
                supersedes: *supersedes,
                tasks: tasks.clone(),
                content: *content,
            },
        )]),
        Command::Submit {
            proposal,
            plan,
            ethics,
            notice,
        } => audit(vec![
            Record::Submitted {
                proposal: *proposal,
                plan: *plan,
                ethics: *ethics,
                notice: *notice,
            },
            Record::Transitioned(Transitioned {
                proposal: *proposal,
                from: StateTag::Draft,
                to: StateTag::Submitted,
                row: Row::DraftToSubmitted,
                actor: ask.actor,
                decision: None,
            }),
        ]),
        Command::Withdraw { proposal } => {
            let life = rev.proposals.get(proposal)?;
            let mut required = vec![Record::Transitioned(Transitioned {
                proposal: *proposal,
                from: life.state,
                to: StateTag::Withdrawn,
                row: Row::Withdraw,
                actor: ask.actor,
                decision: None,
            })];
            required.extend(receiving_ends(view, *proposal, ask.now));
            Some(Expected {
                required,
                allow: Allow::Withdrawal(*proposal),
            })
        }
        Command::EndRole { binding, .. } => Some(Expected {
            required: end_releases(view, rev, *binding),
            allow: Allow::Any,
        }),
        Command::AddTeamMember {
            proposal, account, ..
        }
        | Command::AddGuardian {
            proposal, account, ..
        } => Some(Expected {
            required: team_change_records(view, rev, facts, *proposal, *account, epoch, ask.now),
            allow: Allow::Any,
        }),
        _ => None,
    }
}

/// The ends of the held Receiving bindings of `proposal` at `now`, each
/// pinning the L-SOD reference bar (Q11, Cooling-off).
pub fn receiving_ends(view: &sod::View, proposal: ProposalId, now: Timestamp) -> Vec<Record> {
    view.bindings
        .values()
        .filter(|b| b.proposal == Some(proposal) && b.group == RefGroup::Receiving && b.held())
        .filter_map(|b| {
            sod::expected_end(view, b.binding).map(|(bar, p12)| {
                Record::BindingEnded(BindingEnded {
                    binding: b.binding,
                    at: now,
                    barred_through: bar,
                    p12: CoolingOff(p12),
                })
            })
        })
        .collect()
}

/// The releases an `EndRole` of `binding` must record: every unreleased
/// assignment resting on it, unless the account holds another held binding
/// of the role in the programme.
pub fn end_releases(view: &sod::View, rev: &RevView, binding: BindingId) -> Vec<Record> {
    let Some(b) = view.bindings.get(&binding) else {
        return Vec::new();
    };
    let other = view
        .bindings_of(b.account, b.programme)
        .any(|x: &RefBinding| x.binding != binding && x.role == b.role && x.held());
    if other || !b.held() {
        return Vec::new();
    }
    rev.unreleased_of(b.account)
        .filter(|a| a.role() == Some(b.role) && rev.programme_of(a.proposal) == Some(b.programme))
        .map(|a| {
            Record::AssignmentReleased(AssignmentReleased {
                assignment: a.id,
                cause: ReleaseCause::BindingEnded,
            })
        })
        .collect()
}

/// Checks an accepted batch against `exp`: every required record is in
/// the batch, and every other record is one `exp.allow` admits.
pub fn check_expected(
    context: &str,
    rev: &RevView,
    exp: &Expected,
    batch: &[Record],
) -> Result<(), String> {
    for r in &exp.required {
        if !batch.contains(r) {
            return Err(format!(
                "{context}: the batch lacks {r:?}\n  batch: {batch:?}"
            ));
        }
    }
    for r in batch {
        if exp.required.contains(r) {
            continue;
        }
        let ok = match (exp.allow, r) {
            (_, Record::VaultOutcome { .. } | Record::OutboxEnqueued(_)) => true,
            (Allow::Any, _) => true,
            (Allow::Withdrawal(p), Record::AssignmentReleased(x)) => rev
                .assignments
                .get(&x.assignment)
                .is_some_and(|a| a.proposal == p),
            (Allow::Withdrawal(p), Record::CapReleased { proposal, .. }) => *proposal == p,
            _ => false,
        };
        if !ok {
            return Err(format!(
                "{context}: the batch holds the unexpected record {r:?}"
            ));
        }
    }
    Ok(())
}

/// The pairs a batch must flag as notifiable (R-CF-04, Identity
/// discovery): for every Receiving binding of account `a` on proposal `p`
/// that `batch` voids under I-06, every account that judged `p` and
/// shares a verified identity with `a`.
pub fn discovery_matches(
    view: &sod::View,
    rev: &RevView,
    facts: &dyn ConflictFacts,
    batch: &[Record],
) -> BTreeSet<(AccountId, ProposalId)> {
    let mut out = BTreeSet::new();
    for r in batch {
        let Record::BindingVoided(v) = r else {
            continue;
        };
        if v.rule != fstp_domain::refusal::RuleRef::I06 {
            continue;
        }
        let Some(b) = view.bindings.get(&v.binding) else {
            continue;
        };
        let (RefGroup::Receiving, Some(p)) = (b.group, b.proposal) else {
            continue;
        };
        for judge in rev.judges_of(p) {
            if judge != b.account && facts.same_identity(b.account, judge) {
                out.insert((judge, p));
            }
        }
    }
    out
}

/// The unreleased reviewer assignments, on `only` or on every proposal,
/// whose assignee's organisation has a live P-38 list on which a member
/// of `team(proposal)` declares an affiliation (I-35, SoD-11).
pub fn proximity_hits(
    view: &sod::View,
    rev: &RevView,
    facts: &dyn ConflictFacts,
    team: &dyn Fn(ProposalId) -> BTreeSet<AccountId>,
    only: Option<ProposalId>,
    now: Timestamp,
) -> BTreeSet<AssignmentId> {
    rev.assignments
        .values()
        .filter(|a| a.kind == AssignmentKind::Reviewer && a.unreleased())
        .filter(|a| only.is_none_or(|p| p == a.proposal))
        .filter(|a| {
            let Some(programme) = rev.programme_of(a.proposal) else {
                return false;
            };
            committee_organisation(view, rev, a.reviewer, programme, now)
                .and_then(|org| rev.proximity_list(programme, org))
                .is_some_and(|list| facts.declares_on_list(&team(a.proposal), list))
        })
        .map(|a| a.id)
        .collect()
}

/// The detections and releases for `detected` and `proximity`, with one
/// notification draft per proposal that has a notifiable detection.
fn detection_records(
    rev: &RevView,
    detected: &BTreeSet<(AccountId, ProposalId)>,
    notifiable: &BTreeSet<(AccountId, ProposalId)>,
    proximity: &BTreeSet<AssignmentId>,
    epoch: VaultEpoch,
) -> Vec<Record> {
    let mut out = Vec::new();
    let mut released = BTreeSet::new();
    let mut notify = BTreeSet::new();
    for (account, proposal) in detected {
        let flag = notifiable.contains(&(*account, *proposal));
        out.push(Record::ConflictDetected(ConflictDetected {
            account: *account,
            proposal: *proposal,
            notifiable: flag,
            epoch,
        }));
        for a in rev.unreleased_of(*account) {
            if a.proposal == *proposal && released.insert(a.id) {
                out.push(Record::AssignmentReleased(AssignmentReleased {
                    assignment: a.id,
                    cause: ReleaseCause::DetectedConflict,
                }));
            }
        }
        if flag {
            notify.insert(*proposal);
        }
    }
    for id in proximity {
        if released.insert(*id) {
            out.push(Record::AssignmentReleased(AssignmentReleased {
                assignment: *id,
                cause: ReleaseCause::DetectedConflict,
            }));
        }
    }
    out.extend(notify.into_iter().map(|proposal| {
        Record::OutboxEnqueued(fstp_domain::record::OutboxEvent::NotifiableConflict { proposal })
    }));
    out
}

/// The tracked pairs of `proposal`, or of every proposal: the assignee of
/// every unreleased assignment, and every clearance without a conflict fact.
fn tracked(rev: &RevView, only: Option<ProposalId>) -> BTreeSet<(AccountId, ProposalId)> {
    rev.assignments
        .values()
        .filter(|a| a.unreleased())
        .map(|a| (a.reviewer, a.proposal))
        .chain(
            rev.cleared
                .iter()
                .filter(|pair| !rev.facts.contains(pair))
                .copied(),
        )
        .filter(|(_, p)| only.is_none_or(|o| o == *p))
        .collect()
}

/// The review records a reaction at `epoch` must hold, given the L-SOD
/// records `voids` of the same batch: a detection for every tracked pair
/// the vault finds conflicted, a notifiable one for every discovery match,
/// the releases of [`detection_records`], and the I-35 releases.
pub fn reaction_records(
    view: &sod::View,
    rev: &RevView,
    facts: &dyn ConflictFacts,
    voids: &[Record],
    epoch: VaultEpoch,
    now: Timestamp,
) -> Vec<Record> {
    let matched = discovery_matches(view, rev, facts, voids);
    let mut detected: BTreeSet<(AccountId, ProposalId)> = tracked(rev, None)
        .into_iter()
        .filter(|(a, p)| facts.has_conflict(*a, &team_of(view, *p)))
        .collect();
    detected.extend(matched.iter().copied());
    let proximity = proximity_hits(view, rev, facts, &|p| team_of(view, p), None, now);
    detection_records(rev, &detected, &matched, &proximity, epoch)
}

/// The review records an accepted `AddTeamMember` or `AddGuardian` of
/// `account` on `proposal` must hold (enforcement point 1): a detection
/// and the releases for every tracked pair of the proposal that the vault
/// finds conflicted with the new team, and the I-35 releases for it.
pub fn team_change_records(
    view: &sod::View,
    rev: &RevView,
    facts: &dyn ConflictFacts,
    proposal: ProposalId,
    account: AccountId,
    epoch: VaultEpoch,
    now: Timestamp,
) -> Vec<Record> {
    let mut team = team_of(view, proposal);
    team.insert(account);
    let detected: BTreeSet<(AccountId, ProposalId)> = tracked(rev, Some(proposal))
        .into_iter()
        .filter(|(a, _)| facts.has_conflict(*a, &team))
        .collect();
    let proximity = proximity_hits(view, rev, facts, &|_| team.clone(), Some(proposal), now);
    detection_records(rev, &detected, &BTreeSet::new(), &proximity, epoch)
}

/// Checks the review part of a vault reaction batch at `now`.
///
/// - Required: a `ConflictDetected` and an `AssignmentReleased` with cause
///   `DetectedConflict`, for every unreleased assignment whose assignee
///   `facts` finds conflicted, when `must(assignee, team)` says the
///   reaction had to recheck it. The same for a `ConflictDetected` of every
///   proposal-level clearance without a conflict fact.
/// - Required: a notifiable `ConflictDetected`, the releases of the
///   account's unreleased assignments and a notification draft for every
///   discovery match of the batch (R-CF-04). A detection is notifiable
///   exactly when it is such a match.
/// - Required: the release of every unreleased reviewer assignment that
///   breaks I-35 under the vault facts.
/// - Allowed: detections only for discovery matches and for pairs `facts`
///   finds conflicted, among assignees and proposal-level clearances, and
///   releases only of assignments detected in the batch or breaking I-35.
pub fn check_reaction(
    context: &str,
    view: &sod::View,
    rev: &RevView,
    facts: &dyn ConflictFacts,
    must: &dyn Fn(AccountId, &BTreeSet<AccountId>) -> bool,
    batch: &[Record],
    now: Timestamp,
) -> Result<(), String> {
    let detected: BTreeMap<(AccountId, ProposalId), bool> = batch
        .iter()
        .filter_map(|r| match r {
            Record::ConflictDetected(ConflictDetected {
                account,
                proposal,
                notifiable,
                ..
            }) => Some(((*account, *proposal), *notifiable)),
            _ => None,
        })
        .collect();
    let released: BTreeMap<AssignmentId, ReleaseCause> = batch
        .iter()
        .filter_map(|r| match r {
            Record::AssignmentReleased(x) => Some((x.assignment, x.cause)),
            _ => None,
        })
        .collect();
    let matched = discovery_matches(view, rev, facts, batch);
    let proximity = proximity_hits(view, rev, facts, &|p| team_of(view, p), None, now);
    for a in rev.assignments.values().filter(|a| a.unreleased()) {
        let team = team_of(view, a.proposal);
        let conflicted = facts.has_conflict(a.reviewer, &team) && must(a.reviewer, &team);
        if conflicted || matched.contains(&(a.reviewer, a.proposal)) {
            if !detected.contains_key(&(a.reviewer, a.proposal)) {
                return Err(format!(
                    "I-03: {context}: the vault finds {:?} conflicted on {:?}, and no ConflictDetected is recorded",
                    a.reviewer, a.proposal
                ));
            }
            if released.get(&a.id) != Some(&ReleaseCause::DetectedConflict) {
                return Err(format!(
                    "R-CF-02: {context}: {:?} is not released with DetectedConflict in the same batch",
                    a.id
                ));
            }
        }
    }
    for (account, proposal) in &rev.cleared {
        let team = team_of(view, *proposal);
        let open = !rev.facts.contains(&(*account, *proposal));
        if open
            && facts.has_conflict(*account, &team)
            && must(*account, &team)
            && !detected.contains_key(&(*account, *proposal))
        {
            return Err(format!(
                "I-03: {context}: the vault finds the cleared {account:?} conflicted on {proposal:?}, and no ConflictDetected is recorded"
            ));
        }
    }
    for (account, proposal) in &matched {
        if detected.get(&(*account, *proposal)) != Some(&true) {
            return Err(format!(
                "R-CF-04: {context}: {account:?} judged {proposal:?} and shares a verified identity with a discovered applicant, and no notifiable ConflictDetected is recorded"
            ));
        }
        let draft = Record::OutboxEnqueued(fstp_domain::record::OutboxEvent::NotifiableConflict {
            proposal: *proposal,
        });
        if !batch.contains(&draft) {
            return Err(format!(
                "R-CF-04: {context}: no notification draft for the notifiable conflict on {proposal:?}"
            ));
        }
    }
    for id in &proximity {
        if !released.contains_key(id) {
            return Err(format!(
                "I-35: {context}: {id:?} stays assigned to a proposal whose team declares an affiliation on its organisation's list"
            ));
        }
    }
    for ((account, proposal), notifiable) in &detected {
        let pair = (*account, *proposal);
        let is_match = matched.contains(&pair);
        let tracked = rev
            .assignments
            .values()
            .any(|a| a.reviewer == *account && a.proposal == *proposal && a.unreleased())
            || rev.cleared.contains(&pair);
        let backed = tracked && facts.has_conflict(*account, &team_of(view, *proposal));
        if !backed && !is_match {
            return Err(format!(
                "{context}: a ConflictDetected for {account:?} on {proposal:?} that the vault does not back"
            ));
        }
        if *notifiable != is_match {
            return Err(format!(
                "R-CF-04: {context}: the ConflictDetected for {account:?} on {proposal:?} has notifiable {notifiable}, but the batch's discoveries say {is_match}"
            ));
        }
    }
    for (assignment, cause) in &released {
        let Some(a) = rev.assignments.get(assignment) else {
            return Err(format!("{context}: release of unknown {assignment:?}"));
        };
        let ok = match cause {
            ReleaseCause::DetectedConflict => {
                detected.contains_key(&(a.reviewer, a.proposal)) || proximity.contains(assignment)
            }
            ReleaseCause::BindingVoided | ReleaseCause::BindingSuspended => true,
            _ => false,
        };
        if !ok {
            return Err(format!(
                "{context}: {assignment:?} released with {cause:?} by a vault reaction"
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Invariant predicates
// ---------------------------------------------------------------------------

/// I-03: no content read and no act by an account on a proposal follows
/// a conflict fact for that account and proposal, in ledger order.
pub fn check_i03(rev: &RevView) -> Result<(), String> {
    match rev.breaches.iter().next() {
        None => Ok(()),
        Some((a, p)) => Err(format!(
            "I-03: {a:?} read or acted on {p:?} after a declared or detected conflict"
        )),
    }
}

/// R-CF-02: every read by someone outside the proposal's Receiving
/// accounts followed that reader's no-conflict declaration, and every
/// assignment with a conflicted declaration is released.
pub fn check_rcf02(view: &sod::View, rev: &RevView) -> Result<(), String> {
    for (a, p) in &rev.undeclared_reads {
        if !receiving_holder(view, *a, *p) {
            return Err(format!(
                "R-CF-02: {a:?} read {p:?} before declaring no conflict on it"
            ));
        }
    }
    for x in rev.assignments.values() {
        if rev.facts.contains(&(x.reviewer, x.proposal)) && x.unreleased() {
            return Err(format!(
                "R-CF-02: {:?} holds {:?} on {:?} beside a conflict fact",
                x.reviewer, x.id, x.proposal
            ));
        }
    }
    Ok(())
}

/// R-AN-01 and P-11: no handle was issued on two assignments in the cell.
pub fn check_handles(rev: &RevView) -> Result<(), String> {
    match rev.handle_repeats.iter().next() {
        None => Ok(()),
        Some(h) => Err(format!("R-AN-01: handle {h:?} issued on two assignments")),
    }
}

/// I-02, assignment half: no account holds an IRC binding or an unreleased
/// IRC assignment together with another held Judging binding or an
/// unreleased reviewer assignment in one programme. Every unreleased
/// assignment rests on a held binding of its role.
pub fn check_i02_assignments(view: &sod::View, rev: &RevView) -> Result<(), String> {
    for a in rev.assignments.values().filter(|a| a.unreleased()) {
        let Some(programme) = rev.programme_of(a.proposal) else {
            continue;
        };
        let Some(role) = a.role() else {
            continue;
        };
        let rests = view
            .bindings_of(a.reviewer, programme)
            .any(|b| b.role == role && b.held());
        if !rests {
            return Err(format!(
                "I-02: {:?} of {:?} rests on no held {role:?} binding",
                a.id, a.reviewer
            ));
        }
        let irc_side = role == Role::IrcMember;
        let clash_binding = view.bindings_of(a.reviewer, programme).any(|b| {
            b.held()
                && if irc_side {
                    sod::other_judging(b.role)
                } else {
                    b.role == Role::IrcMember
                }
        });
        let clash_assignment = rev.unreleased_of(a.reviewer).any(|x| {
            x.id != a.id
                && x.role() != Some(role)
                && rev.programme_of(x.proposal) == Some(programme)
        });
        if clash_binding || clash_assignment {
            return Err(format!(
                "I-02: {:?} holds {:?} beside an IRC role and another Judging role",
                a.reviewer, a.id
            ));
        }
    }
    Ok(())
}

/// I-36: no Receiving binding was granted to a former reviewer while
/// [`RevView::i36_bars`] barred it. That is a call where a reviewed
/// proposal was under evaluation, or a call of a programme where the
/// account reviewed while a proposal it reviewed was undecided.
pub fn check_i36(rev: &RevView) -> Result<(), String> {
    match rev.i36_breaches.iter().next() {
        None => Ok(()),
        Some((a, c)) => Err(format!(
            "I-36: former reviewer {a:?} took a Receiving role in {c:?} while a proposal it reviewed was undecided"
        )),
    }
}

/// I-36 as a state predicate: no held Receiving binding sits in a call
/// where a proposal its account reviewed is under evaluation now. The call
/// is the binding's own call and the current call of its proposal. A
/// DEFERRED proposal is under evaluation in the next published call too
/// (Q12), so a deferral that lands after the grant is caught here.
pub fn check_i36_held(view: &sod::View, rev: &RevView) -> Result<(), String> {
    for b in view
        .bindings
        .values()
        .filter(|b| b.group == RefGroup::Receiving && b.held())
    {
        let current = b
            .proposal
            .and_then(|p| rev.proposals.get(&p))
            .map(|l| l.current_call);
        for call in b.call.into_iter().chain(current) {
            if let Some(p) = rev
                .reviewed_by(b.account)
                .find(|p| rev.under_evaluation_in(*p, call))
            {
                return Err(format!(
                    "I-36: {:?} holds Receiving binding {:?} in {call:?}, where {p:?}, which it reviewed, is under evaluation",
                    b.account, b.binding
                ));
            }
        }
    }
    Ok(())
}

/// I-36 on one step: no Receiving binding that `records` grant was barred
/// by [`RevView::i36_bars`] in `before`, the view before the step.
pub fn check_i36_grants(before: &RevView, records: &[Record]) -> Result<(), String> {
    for r in records {
        if let Record::BindingGranted(g) = r
            && let BindingScope::Proposal { call, .. } = g.scope
            && before.i36_bars(g.account, call)
        {
            return Err(format!(
                "I-36: former reviewer {:?} was granted Receiving binding {:?} in {call:?} while a proposal it reviewed was undecided",
                g.account, g.binding
            ));
        }
    }
    Ok(())
}

/// I-34 after an accepted `Assign` (test-author reading): when the
/// proposal's assignments spanned fewer than P-39 organisations before,
/// the new reviewer brought a new one. `before` is the view before the
/// step, and `reviewer` the new assignee. A reviewer whose committee
/// binding records no organisation is outside the reading.
pub fn check_i34_assign(
    view: &sod::View,
    before: &RevView,
    proposal: ProposalId,
    reviewer: AccountId,
    now: Timestamp,
) -> Result<(), String> {
    let Some(programme) = before.programme_of(proposal) else {
        return Ok(());
    };
    let Some(org) = committee_organisation(view, before, reviewer, programme, now) else {
        return Ok(());
    };
    let p39 = usize::from(before.governing_policy(proposal).map_or(0, |p| p.p39));
    let orgs_before = assigned_organisations(view, before, proposal, now);
    if orgs_before.len() < p39 && orgs_before.contains(&org) {
        return Err(format!(
            "I-34: {proposal:?} spans {} organisations below P-39 = {p39}, and the new reviewer adds none",
            orgs_before.len()
        ));
    }
    Ok(())
}
