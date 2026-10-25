//! The M-CONFLICT model for fstp-mc, its properties and its fault (design sections 6.2 and 6.3).
//!
//! - [`ConflictModel`] is M-CONFLICT: committee members of distinct
//!   organisations, the FSTP coordinator and submitted proposals, with
//!   P-03 = 2 and P-39 = 2. The start state is built from genesis by
//!   production commands ([`ReviewWorld::from_setup`]). Actions assign,
//!   declare on an assignment, declare a later conflict on an active
//!   assignment, declare at proposal level, read, unassign, and flip one
//!   vault bit. Each bit flips at most once, and each reviewer is
//!   assigned to each proposal at most once.
//! - The truthful instance flips relations in the ground truth: co-workers,
//!   mentoring and relatives, added mid-run, and one relation removed.
//!   The havoc instance flips scripted `HasConflict` bits, with change
//!   queries that list the reviewer or nobody. Under havoc the domain must
//!   obey the bits it is given, and a silent flip must still bar a read
//!   through the fresh check at the current epoch.
//! - The two-proposal instance (design 6.3) checks that a conflict fact and
//!   a declaration on one proposal never open or bar an act on the other.
//! - The staged instance also folds the SUBMITTED to STAGE1 to STAGE2 to
//!   RANKED rows, as the teeth tests do, until lane L-LIFE records them.
//!   Assigned reviewers read and write ranking summaries there, and every
//!   step compares the production cut-off recusal predicate with the
//!   reference (Conflict declarations).
//! - The property builders read only the reference views and the vault
//!   facts, never production structures. The recusal comparison is part
//!   of the two-way check and runs on the production backend only.
//!
//! A run in [`Backend::Reference`] mode checks the model itself: every
//! property passes and every witness is reached on the references.

use std::collections::{BTreeMap, BTreeSet};

use fstp_domain::assignment::{AssignmentKind, ReleaseCause};
use fstp_domain::command::{Actor, Command, DeclarationSubject};
use fstp_domain::id::{AccountId, AssignmentId, CallId, ProposalId};
use fstp_domain::oracle::Answers;
use fstp_domain::record::{ContentRead, Record, Transitioned};
use fstp_domain::roles::Role;
use fstp_domain::rules::{Row, StateTag};
use fstp_mc::{Model, Property};

use crate::r#gen::policy::text;
use crate::r#gen::review::{
    COORDINATOR, DraftSpec, Havoc, L1, L2, O1, O2, O3, PR1, PR2, R1, R2, R3, ReviewSetup,
    ReviewWorld, assign, declare, handle, reacted, read, review_truth, tag, unassign,
};
use crate::r#gen::roster::{Backend, Flags, SodSetup, Step, call};
use crate::reference::review::{
    ConflictFacts, RefStatus, assigned_count, check_i03, check_rcf02, recused, team_of,
};
use crate::vault::{GroundTruth, Relation};

/// One vault bit an action may flip once.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Flip {
    /// The account becomes related to the proposal's lead.
    Relate {
        /// The account.
        who: AccountId,
        /// The proposal.
        proposal: ProposalId,
        /// How.
        relation: Relation,
    },
    /// The account's relation to the proposal's lead ends.
    Unrelate {
        /// The account.
        who: AccountId,
        /// The proposal.
        proposal: ProposalId,
        /// How.
        relation: Relation,
    },
    /// The havoc oracle answers `bit` to `HasConflict(who, team)`. The
    /// change query lists `who` when `listed`, and nobody otherwise.
    Havoc {
        /// The account.
        who: AccountId,
        /// The proposal.
        proposal: ProposalId,
        /// The new bit.
        bit: bool,
        /// Whether the change query lists the account.
        listed: bool,
    },
}

impl Flip {
    /// The account and proposal the flip is about.
    pub const fn pair(self) -> (AccountId, ProposalId) {
        match self {
            Flip::Relate { who, proposal, .. }
            | Flip::Unrelate { who, proposal, .. }
            | Flip::Havoc { who, proposal, .. } => (who, proposal),
        }
    }
}

/// One M-CONFLICT instance.
#[derive(Clone, Debug)]
pub struct ConflictConfig {
    /// The setup from genesis.
    pub setup: ReviewSetup,
    /// The vault facts at genesis.
    pub truth: GroundTruth,
    /// The havoc script after the setup, if any.
    pub havoc: Option<Havoc>,
    /// The committee members who may be assigned.
    pub reviewers: Vec<AccountId>,
    /// The proposals.
    pub proposals: Vec<ProposalId>,
    /// The most assignments per reviewer and proposal.
    pub max_assignments: u8,
    /// The bits that may flip, each once.
    pub flips: Vec<Flip>,
    /// Whether the run folds the stage rows and offers ranking summaries.
    pub staged: bool,
}

/// One M-CONFLICT state.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ConflictState {
    /// Production, the vault and the reference views.
    pub world: ReviewWorld,
    /// Assignments made per reviewer and proposal.
    pub made: BTreeMap<(AccountId, ProposalId), u8>,
    /// The flips taken, by index.
    pub flipped: BTreeSet<usize>,
    /// The read or reviewer act the last step recorded, if any.
    pub last: Option<(AccountId, ProposalId)>,
    /// Ghost: pairs for which the vault answered a conflict and later no
    /// longer did.
    pub conflict_ended: BTreeSet<(AccountId, ProposalId)>,
    /// Ghost: a reviewer was assigned to a proposal after its conflict ended.
    pub assigned_after_end: bool,
    /// Ghost: a committee member read content through an assignment.
    pub reviewer_read: bool,
    /// Ghost: an assigned reviewer recorded a ranking summary.
    pub summary_written: bool,
    /// Set when production and the reference disagree. The `two-way`
    /// property fails on it, and the state is terminal.
    pub divergence: Option<String>,
}

/// An M-CONFLICT action.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ConflictAction {
    /// The coordinator assigns the reviewer to the proposal.
    Assign {
        /// The reviewer.
        reviewer: AccountId,
        /// The proposal.
        proposal: ProposalId,
    },
    /// The assignee declares on the assignment.
    Declare {
        /// The assignment.
        assignment: AssignmentId,
        /// Whether conflicted.
        conflicted: bool,
    },
    /// The coordinator declares on the proposal before the knock-out read.
    CoordinatorDeclare {
        /// The proposal.
        proposal: ProposalId,
        /// Whether conflicted.
        conflicted: bool,
    },
    /// The reader reads the proposal's content.
    Read {
        /// The reader.
        reader: AccountId,
        /// The proposal.
        proposal: ProposalId,
    },
    /// The coordinator releases the assignment.
    Unassign(AssignmentId),
    /// The flip with this index, and the reaction in the same step.
    Flip(usize),
    /// The proposal takes its next stage row, folded structurally.
    Advance(ProposalId),
    /// The assignee records the ranking summary of the assignment's proposal.
    Summary(AssignmentId),
}

/// The id of the `n`-th assignment of the reviewer at `i` to the proposal at `j`.
pub fn assignment_id(i: usize, j: usize, n: u8) -> AssignmentId {
    let i = u128::try_from(i).unwrap_or(0);
    let j = u128::try_from(j).unwrap_or(0);
    AssignmentId::from_raw(
        7_000u128
            .saturating_add(i.saturating_mul(100))
            .saturating_add(j.saturating_mul(10))
            .saturating_add(u128::from(n)),
    )
}

/// The M-CONFLICT model (design 6.3).
pub struct ConflictModel {
    /// The instance.
    pub config: ConflictConfig,
    /// The start state.
    pub start: ConflictState,
}

impl ConflictModel {
    /// The model of `config` over `backend`, with its start state built from genesis.
    pub fn new(config: ConflictConfig, backend: Backend) -> Result<ConflictModel, String> {
        let world = ReviewWorld::from_setup(
            backend,
            config.truth.clone(),
            &config.setup,
            config.havoc.clone(),
        )?;
        Ok(ConflictModel {
            start: ConflictState {
                world,
                made: BTreeMap::new(),
                flipped: BTreeSet::new(),
                last: None,
                conflict_ended: BTreeSet::new(),
                assigned_after_end: false,
                reviewer_read: false,
                summary_written: false,
                divergence: None,
            },
            config,
        })
    }

    fn lead(&self, s: &ConflictState, proposal: ProposalId) -> Option<AccountId> {
        s.world.view.proposals.get(&proposal).map(|l| l.lead)
    }
}

fn diverged(s: &ConflictState, why: String) -> ConflictState {
    let mut next = s.clone();
    next.divergence = Some(why);
    next.last = None;
    next
}

/// The next stage row of a proposal in `state`, if the staged run takes one.
const fn next_row(state: StateTag) -> Option<(StateTag, Row)> {
    match state {
        StateTag::Submitted => Some((StateTag::Stage1, Row::SubmittedToStage1)),
        StateTag::Stage1 => Some((StateTag::Stage2, Row::Stage1ToStage2)),
        StateTag::Stage2 => Some((StateTag::Ranked, Row::Stage2ToRanked)),
        _ => None,
    }
}

/// The `RecordRankingSummary` of `assignment` by `reviewer` on `proposal`.
fn summary(reviewer: AccountId, proposal: ProposalId, assignment: AssignmentId) -> Step {
    Step::by(
        reviewer,
        Flags::NONE,
        Command::RecordRankingSummary {
            proposal,
            assignment,
            title: text(9_001),
            neutral_summary: text(9_002),
            rationale: text(9_003),
        },
    )
}

/// The call every M-CONFLICT proposal belongs to.
fn model_call() -> CallId {
    call(1)
}

/// Compares the production cut-off recusal predicate with the reference
/// for every committee member of `members`, on the production backend.
fn recusal_divergence(world: &ReviewWorld, members: &[AccountId]) -> Option<String> {
    if world.sod.backend != Backend::Production {
        return None;
    }
    let state = &world.sod.state;
    let facts = world.facts();
    for member in members {
        let mut answers = Answers::new();
        for q in fstp_domain::assignment::cut_off_recusal_queries(state, *member, model_call()) {
            let a = world.answer(&q);
            answers.insert(q, a);
        }
        let expected = recused(&world.sod.view, &world.view, &facts, *member, model_call());
        match fstp_domain::assignment::recused_from_cut_off(state, *member, model_call(), &answers)
        {
            Ok(got) if got == expected => {}
            other => {
                return Some(format!(
                    "cut-off recusal of {member:?}: production {other:?}, reference {expected}"
                ));
            }
        }
    }
    None
}

impl Model for ConflictModel {
    type State = ConflictState;
    type Action = ConflictAction;

    fn init(&self) -> Vec<ConflictState> {
        vec![self.start.clone()]
    }

    fn actions(&self, s: &ConflictState, actions: &mut Vec<ConflictAction>) {
        for proposal in &self.config.proposals {
            for reviewer in &self.config.reviewers {
                if s.made.get(&(*reviewer, *proposal)).copied().unwrap_or(0)
                    < self.config.max_assignments
                {
                    actions.push(ConflictAction::Assign {
                        reviewer: *reviewer,
                        proposal: *proposal,
                    });
                }
            }
            let pair = (COORDINATOR, *proposal);
            if !s.world.view.cleared.contains(&pair) && !s.world.view.facts.contains(&pair) {
                for conflicted in [false, true] {
                    actions.push(ConflictAction::CoordinatorDeclare {
                        proposal: *proposal,
                        conflicted,
                    });
                }
            }
            for reader in self.config.reviewers.iter().chain([COORDINATOR].iter()) {
                actions.push(ConflictAction::Read {
                    reader: *reader,
                    proposal: *proposal,
                });
            }
            if self.config.staged
                && s.world
                    .view
                    .proposals
                    .get(proposal)
                    .is_some_and(|l| next_row(l.state).is_some())
            {
                actions.push(ConflictAction::Advance(*proposal));
            }
        }
        for a in s.world.view.assignments.values() {
            match a.status {
                RefStatus::Awaiting => {
                    for conflicted in [false, true] {
                        actions.push(ConflictAction::Declare {
                            assignment: a.id,
                            conflicted,
                        });
                    }
                }
                RefStatus::Active => actions.push(ConflictAction::Declare {
                    assignment: a.id,
                    conflicted: true,
                }),
                RefStatus::Released(_) => {}
            }
            if a.unreleased() {
                actions.push(ConflictAction::Unassign(a.id));
            }
            if self.config.staged && a.status == RefStatus::Active {
                actions.push(ConflictAction::Summary(a.id));
            }
        }
        for i in 0..self.config.flips.len() {
            if !s.flipped.contains(&i) {
                actions.push(ConflictAction::Flip(i));
            }
        }
    }

    fn step(&self, s: &ConflictState, a: &ConflictAction) -> Option<ConflictState> {
        if s.divergence.is_some() {
            return None;
        }
        let step = match a {
            ConflictAction::Assign { reviewer, proposal } => {
                let i = self.config.reviewers.iter().position(|r| r == reviewer)?;
                let j = self.config.proposals.iter().position(|p| p == proposal)?;
                let n = s
                    .made
                    .get(&(*reviewer, *proposal))
                    .copied()
                    .unwrap_or(0)
                    .saturating_add(1);
                let id = assignment_id(i, j, n);
                assign(
                    COORDINATOR,
                    id,
                    *proposal,
                    *reviewer,
                    AssignmentKind::Reviewer,
                    Some(handle(id.raw())),
                )
            }
            ConflictAction::Declare {
                assignment,
                conflicted,
            } => {
                let reviewer = s.world.view.assignments.get(assignment)?.reviewer;
                declare(
                    reviewer,
                    DeclarationSubject::Assignment(*assignment),
                    *conflicted,
                    *conflicted,
                )
            }
            ConflictAction::CoordinatorDeclare {
                proposal,
                conflicted,
            } => declare(
                COORDINATOR,
                DeclarationSubject::Proposal(*proposal),
                *conflicted,
                false,
            ),
            ConflictAction::Read { reader, proposal } => read(*reader, *proposal),
            ConflictAction::Unassign(id) => unassign(COORDINATOR, *id),
            ConflictAction::Flip(i) => return self.flip(s, *i),
            ConflictAction::Advance(p) => return self.advance(s, *p),
            ConflictAction::Summary(id) => {
                let x = s.world.view.assignments.get(id)?;
                summary(x.reviewer, x.proposal, *id)
            }
        };
        match crate::r#gen::review::judged(&s.world, &step)? {
            Err(why) => Some(diverged(s, why)),
            Ok((world, records)) => {
                if let Some(why) = recusal_divergence(&world, &self.config.reviewers) {
                    return Some(diverged(s, why));
                }
                let mut next = s.clone();
                next.last = records.iter().find_map(|r| match r {
                    Record::ContentRead(ContentRead { account, proposal }) => {
                        Some((*account, *proposal))
                    }
                    Record::RankingSummaryRecorded { assignment, .. } => s
                        .world
                        .view
                        .assignments
                        .get(assignment)
                        .map(|x| (x.reviewer, x.proposal)),
                    _ => None,
                });
                next.world = world;
                for r in &records {
                    match r {
                        Record::ContentRead(c) if self.config.reviewers.contains(&c.account) => {
                            next.reviewer_read = true;
                        }
                        Record::RankingSummaryRecorded { .. } => next.summary_written = true,
                        Record::Assigned(x)
                            if s.conflict_ended.contains(&(x.reviewer, x.proposal)) =>
                        {
                            next.assigned_after_end = true;
                        }
                        _ => {}
                    }
                }
                if let ConflictAction::Assign { reviewer, proposal } = a
                    && records.iter().any(|r| matches!(r, Record::Assigned(_)))
                {
                    let n = next.made.entry((*reviewer, *proposal)).or_insert(0);
                    *n = n.saturating_add(1);
                }
                Some(next)
            }
        }
    }

    fn is_terminal(&self, s: &ConflictState) -> bool {
        s.divergence.is_some()
    }
}

impl ConflictModel {
    fn flip(&self, s: &ConflictState, i: usize) -> Option<ConflictState> {
        if s.flipped.contains(&i) {
            return None;
        }
        let flip = *self.config.flips.get(i)?;
        let (who, proposal) = flip.pair();
        let team = team_of(&s.world.sod.view, proposal);
        let before = s.world.facts().has_conflict(who, &team);
        let mut world = s.world.clone();
        let listed: BTreeSet<AccountId> = match flip {
            Flip::Relate {
                who,
                proposal,
                relation,
            } => {
                let lead = self.lead(s, proposal)?;
                world.sod.truth.relate(tag(who), tag(lead), relation);
                world.changed_since(world.processed())
            }
            Flip::Unrelate {
                who,
                proposal,
                relation,
            } => {
                let lead = self.lead(s, proposal)?;
                world.sod.truth.unrelate(tag(who), tag(lead), relation);
                world.changed_since(world.processed())
            }
            Flip::Havoc {
                who,
                proposal,
                bit,
                listed,
            } => {
                let team = team_of(&world.sod.view, proposal);
                world.flip(who, team, bit, listed);
                world.changed_since(world.processed())
            }
        };
        let after = world.facts().has_conflict(who, &team);
        let must = move |r: AccountId, team: &BTreeSet<AccountId>| {
            listed.contains(&r) || team.iter().any(|t| listed.contains(t))
        };
        let mut next = s.clone();
        next.flipped.insert(i);
        next.last = None;
        if before && !after {
            next.conflict_ended.insert((who, proposal));
        }
        match reacted(&world, &must) {
            Ok((w, _)) => {
                next.world = w;
                Some(next)
            }
            Err(why) => {
                next.world = world;
                next.divergence = Some(why);
                Some(next)
            }
        }
    }

    /// Folds the next stage row of `proposal` into production and both
    /// views, as the teeth tests do until lane L-LIFE records the rows.
    fn advance(&self, s: &ConflictState, proposal: ProposalId) -> Option<ConflictState> {
        let life = s.world.view.proposals.get(&proposal)?;
        let (to, row) = next_row(life.state)?;
        let mut next = s.clone();
        next.last = None;
        let record = Record::Transitioned(Transitioned {
            proposal,
            from: life.state,
            to,
            row,
            actor: Actor::Account(COORDINATOR),
            decision: None,
        });
        if let Err(why) = next.world.commit(&[record]) {
            return Some(diverged(s, why));
        }
        if let Some(why) = recusal_divergence(&next.world, &self.config.reviewers) {
            return Some(diverged(s, why));
        }
        Some(next)
    }
}

// ---------------------------------------------------------------------------
// Instances
// ---------------------------------------------------------------------------

/// The state counts of the M-CONFLICT instances, measured in step W4a. Each
/// run stops at twice its count, so growth fails visibly. The counts are
/// the larger of the two backends. They differ only for the staged
/// instance, whose production projection also keeps the ranking summaries.
pub const M_CONFLICT_TRUTHFUL_STATES: usize = 23_364;
/// See [`M_CONFLICT_TRUTHFUL_STATES`].
pub const M_CONFLICT_HAVOC_STATES: usize = 16_724;
/// See [`M_CONFLICT_TRUTHFUL_STATES`].
pub const M_CONFLICT_TWO_PROPOSAL_STATES: usize = 2_702;
/// See [`M_CONFLICT_TRUTHFUL_STATES`].
pub const M_CONFLICT_STAGED_STATES: usize = 10_230;

/// The setup of M-CONFLICT: one programme with one published call, the
/// coordinator and R1 to R3 of organisations O1 to O3, and PR1 of L1, submitted.
pub fn conflict_setup() -> ReviewSetup {
    let mut base = SodSetup::one(1, &[1]);
    base.published = vec![call(1)];
    ReviewSetup {
        base,
        p38: BTreeMap::new(),
        p10: fstp_domain::policy::ReadAccess::AssignedReviewersOnly,
        judges: vec![
            (COORDINATOR, Role::FstpCoordinator, None),
            (R1, Role::CommitteeMember, Some(O1)),
            (R2, Role::CommitteeMember, Some(O2)),
            (R3, Role::CommitteeMember, Some(O3)),
        ],
        drafts: vec![DraftSpec {
            lead: L1,
            proposal: PR1,
            call: call(1),
            team: Vec::new(),
            minor: false,
            submit: true,
        }],
    }
}

/// The truthful instance: R3 is a relative of L1 at genesis, and the run
/// may make R1 a co-worker, R2 a mentor and the coordinator a relative of
/// L1, and may end R3's relation.
pub fn truthful_config() -> ConflictConfig {
    let setup = conflict_setup();
    let mut truth = review_truth(setup.accounts());
    truth.relate(tag(R3), tag(L1), Relation::Relative);
    ConflictConfig {
        setup,
        truth,
        havoc: None,
        reviewers: vec![R1, R2, R3],
        proposals: vec![PR1],
        max_assignments: 1,
        flips: vec![
            Flip::Relate {
                who: R1,
                proposal: PR1,
                relation: Relation::CoWorker,
            },
            Flip::Relate {
                who: R2,
                proposal: PR1,
                relation: Relation::Mentoring,
            },
            Flip::Relate {
                who: COORDINATOR,
                proposal: PR1,
                relation: Relation::Relative,
            },
            Flip::Unrelate {
                who: R3,
                proposal: PR1,
                relation: Relation::Relative,
            },
        ],
        staged: false,
    }
}

/// The havoc instance: the oracle answers `HasConflict(R3, {L1})` true
/// after the setup. The run may flip R1 to true with R1 listed, R2 and
/// the coordinator to true with nobody listed, and R3 to false.
pub fn havoc_config() -> ConflictConfig {
    let setup = conflict_setup();
    let truth = review_truth(setup.accounts());
    let team: BTreeSet<AccountId> = [L1].into_iter().collect();
    ConflictConfig {
        setup,
        truth,
        havoc: Some(Havoc::new([((R3, team), true)].into_iter().collect())),
        reviewers: vec![R1, R2, R3],
        proposals: vec![PR1],
        max_assignments: 1,
        flips: vec![
            Flip::Havoc {
                who: R1,
                proposal: PR1,
                bit: true,
                listed: true,
            },
            Flip::Havoc {
                who: R2,
                proposal: PR1,
                bit: true,
                listed: false,
            },
            Flip::Havoc {
                who: COORDINATOR,
                proposal: PR1,
                bit: true,
                listed: false,
            },
            Flip::Havoc {
                who: R3,
                proposal: PR1,
                bit: false,
                listed: true,
            },
        ],
        staged: false,
    }
}

/// The two-proposal instance (design 6.3): R1, and PR1 of L1 and PR2 of
/// L2, both submitted in one call. The run may make R1 a co-worker of L1
/// and the coordinator a co-worker of L2. A conflict on one proposal must
/// leave every act on the other as it was.
pub fn two_proposal_config() -> ConflictConfig {
    let mut setup = conflict_setup();
    setup.judges.retain(|(a, _, _)| *a != R2 && *a != R3);
    setup.drafts.push(DraftSpec {
        lead: L2,
        proposal: PR2,
        call: call(1),
        team: Vec::new(),
        minor: false,
        submit: true,
    });
    let truth = review_truth(setup.accounts());
    ConflictConfig {
        setup,
        truth,
        havoc: None,
        reviewers: vec![R1],
        proposals: vec![PR1, PR2],
        max_assignments: 1,
        flips: vec![
            Flip::Relate {
                who: R1,
                proposal: PR1,
                relation: Relation::CoWorker,
            },
            Flip::Relate {
                who: COORDINATOR,
                proposal: PR2,
                relation: Relation::CoWorker,
            },
        ],
        staged: false,
    }
}

/// The staged instance: R1 and R2 on PR1, which the run may take through
/// STAGE1 and STAGE2 to RANKED. The run may make R1 a co-worker of L1
/// with R1 listed, and R2 a mentor of L1 through a silent havoc bit.
pub fn staged_config() -> ConflictConfig {
    let mut setup = conflict_setup();
    setup.judges.retain(|(a, _, _)| *a != R3);
    let truth = review_truth(setup.accounts());
    ConflictConfig {
        setup,
        truth,
        havoc: Some(Havoc::new(BTreeMap::new())),
        reviewers: vec![R1, R2],
        proposals: vec![PR1],
        max_assignments: 1,
        flips: vec![
            Flip::Relate {
                who: R1,
                proposal: PR1,
                relation: Relation::CoWorker,
            },
            Flip::Havoc {
                who: R2,
                proposal: PR1,
                bit: true,
                listed: false,
            },
        ],
        staged: true,
    }
}

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------

/// `always("two-way")`: production and the references agree on every step,
/// in both directions, including the records of accepted steps and of
/// every vault reaction.
pub fn two_way<'a, M: Model<State = ConflictState>>() -> Property<'a, M> {
    Property::<M>::always_with("two-way", |s| match &s.divergence {
        None => Ok(()),
        Some(d) => Err(format!("two-way: {d}")),
    })
}

/// `always("I-03")`: no read or act by an account on a proposal follows a
/// conflict fact for that account and proposal, in ledger order.
pub fn always_i03<'a, M: Model<State = ConflictState>>() -> Property<'a, M> {
    Property::<M>::always_with("I-03", |s| check_i03(&s.world.view))
}

/// `transition("I-03 act")`: a step that records a read or a ranking
/// summary by `a` on `p` starts from a state with no conflict fact for
/// them, where the vault answers `HasConflict` false for `a` and the team
/// of `p`.
pub fn transition_i03<'a, M: Model<State = ConflictState>>() -> Property<'a, M> {
    Property::<M>::transition_with("I-03 act", |before, _, after| {
        let Some((a, p)) = after.last else {
            return Ok(());
        };
        if before.world.view.facts.contains(&(a, p)) {
            return Err(format!("I-03: {a:?} acted on {p:?} after a conflict fact"));
        }
        let team = team_of(&before.world.sod.view, p);
        if before.world.facts().has_conflict(a, &team) {
            return Err(format!(
                "I-03: {a:?} acted on {p:?} while the vault answers a conflict"
            ));
        }
        Ok(())
    })
}

/// `transition("R-CF-02")`: a step that records a read or act by `a` on
/// `p` starts from a state where `a` declared no conflict on `p`, through
/// an active assignment or at proposal level. After every step, an
/// assignment with a conflicted declaration is released.
pub fn transition_rcf02<'a, M: Model<State = ConflictState>>() -> Property<'a, M> {
    Property::<M>::transition_with("R-CF-02", |before, _, after| {
        if let Some((a, p)) = after.last {
            let v = &before.world.view;
            let declared = v.cleared.contains(&(a, p))
                || v.assignments
                    .values()
                    .any(|x| x.reviewer == a && x.proposal == p && x.status == RefStatus::Active);
            if !declared {
                return Err(format!(
                    "R-CF-02: {a:?} read or acted on {p:?} before declaring no conflict"
                ));
            }
        }
        check_rcf02(&after.world.sod.view, &after.world.view)
    })
}

/// Witness: content was read after a no-conflict declaration.
pub fn read_after_clearance(s: &ConflictState) -> bool {
    s.world
        .view
        .reads
        .iter()
        .any(|pair| s.world.view.cleared.contains(pair) || s.world.view.reviewed.contains(pair))
}

/// Witness: a proposal with an assignment released by a declared conflict
/// again holds at least P-03 active reviewer assignments. P-03 comes from
/// the proposal's original call (Q15 A).
pub fn reassignment_restores_p03(s: &ConflictState) -> bool {
    let v = &s.world.view;
    v.proposals.keys().any(|p| {
        let p03 = v.governing_policy(*p).map_or(u8::MAX, |x| x.p03);
        let declared = v.assignments.values().any(|a| {
            a.proposal == *p && a.status == RefStatus::Released(ReleaseCause::DeclaredConflict)
        });
        let active = v
            .assignments
            .values()
            .filter(|a| {
                a.proposal == *p
                    && a.kind == AssignmentKind::Reviewer
                    && a.status == RefStatus::Active
            })
            .count();
        declared && active >= usize::from(p03) && assigned_count(v, *p) >= usize::from(p03)
    })
}

/// Witness: a vault reaction detected a conflict and released the assignment.
pub fn detected_release(s: &ConflictState) -> bool {
    s.world
        .view
        .assignments
        .values()
        .any(|a| a.status == RefStatus::Released(ReleaseCause::DetectedConflict))
}

/// Witness: a cleared coordinator whom the vault now finds conflicted, so
/// only a fresh answer at the current epoch bars the next read.
pub fn cleared_reader_now_conflicted(s: &ConflictState) -> bool {
    let facts = s.world.facts();
    s.world
        .view
        .cleared
        .iter()
        .any(|(a, p)| facts.has_conflict(*a, &team_of(&s.world.sod.view, *p)))
}

/// Witness: a reviewer was assigned to a proposal after the vault, which
/// first found a conflict for that pair, no longer did.
pub fn assigned_after_conflict_ended(s: &ConflictState) -> bool {
    s.assigned_after_end
}

/// Witness: a conflict declared on an active assignment, after a
/// no-conflict declaration, released it (R-CF-02).
pub fn later_declaration_released(s: &ConflictState) -> bool {
    s.world
        .view
        .reads
        .iter()
        .any(|(a, p)| s.world.view.facts.contains(&(*a, *p)))
        && s.world
            .view
            .assignments
            .values()
            .any(|a| a.status == RefStatus::Released(ReleaseCause::DeclaredConflict))
}

/// Witness: an account with a conflict fact on one proposal read another.
pub fn conflict_stays_on_its_proposal(s: &ConflictState) -> bool {
    let v = &s.world.view;
    v.facts
        .iter()
        .any(|(a, p)| v.reads.iter().any(|(b, q)| a == b && p != q))
}

/// Witness: a detected conflict released a reviewer's assignment on one
/// proposal, and the reviewer's assignment on the other stays active.
pub fn detection_spares_the_other_proposal(s: &ConflictState) -> bool {
    let v = &s.world.view;
    v.assignments.values().any(|x| {
        x.status == RefStatus::Released(ReleaseCause::DetectedConflict)
            && v.assignments.values().any(|y| {
                y.reviewer == x.reviewer
                    && y.proposal != x.proposal
                    && y.status == RefStatus::Active
            })
    })
}

/// Witness: a committee member read content through an assignment.
pub fn reviewer_read(s: &ConflictState) -> bool {
    s.reviewer_read
}

/// Witness: an assigned reviewer recorded a ranking summary.
pub fn summary_written(s: &ConflictState) -> bool {
    s.summary_written
}

/// Witness: a committee member recuses from the cut-off vote of the call.
pub fn member_recused(s: &ConflictState) -> bool {
    let facts = s.world.facts();
    [R1, R2, R3]
        .iter()
        .any(|m| recused(&s.world.sod.view, &s.world.view, &facts, *m, model_call()))
}

/// The safety properties every instance checks.
fn safety<'a, M: Model<State = ConflictState>>() -> Vec<Property<'a, M>> {
    vec![
        two_way::<M>(),
        always_i03::<M>(),
        transition_i03::<M>(),
        transition_rcf02::<M>(),
    ]
}

/// The properties of the truthful instance, with their witnesses.
pub fn truthful_properties<'a, M: Model<State = ConflictState>>() -> Vec<Property<'a, M>> {
    let mut out = safety::<M>();
    out.extend([
        Property::<M>::reachable(
            "I-03 witness: content read after a no-conflict declaration",
            read_after_clearance,
        ),
        Property::<M>::reachable(
            "R-CF-02 witness: reassignment restores P-03 after a declared conflict",
            reassignment_restores_p03,
        ),
        Property::<M>::reachable(
            "I-03 witness: a detected conflict releases the assignment",
            detected_release,
        ),
        Property::<M>::reachable(
            "I-03 witness: a reviewer is assigned once the vault no longer finds a conflict",
            assigned_after_conflict_ended,
        ),
    ]);
    out
}

/// The properties of the havoc instance, with their witnesses.
pub fn havoc_properties<'a, M: Model<State = ConflictState>>() -> Vec<Property<'a, M>> {
    let mut out = safety::<M>();
    out.extend([
        Property::<M>::reachable(
            "I-03 witness: content read after a no-conflict declaration",
            read_after_clearance,
        ),
        Property::<M>::reachable(
            "R-CF-02 witness: reassignment restores P-03 after a declared conflict",
            reassignment_restores_p03,
        ),
        Property::<M>::reachable(
            "I-03 witness: a listed havoc conflict releases the assignment",
            detected_release,
        ),
        Property::<M>::reachable(
            "I-03 witness: a silent havoc conflict on a cleared reader",
            cleared_reader_now_conflicted,
        ),
        Property::<M>::reachable(
            "I-03 witness: a reviewer is assigned once the oracle no longer answers a conflict",
            assigned_after_conflict_ended,
        ),
    ]);
    out
}

/// The properties of the two-proposal instance, with their witnesses.
pub fn two_proposal_properties<'a, M: Model<State = ConflictState>>() -> Vec<Property<'a, M>> {
    let mut out = safety::<M>();
    out.extend([
        Property::<M>::reachable(
            "I-03 witness: an account conflicted on one proposal reads the other",
            conflict_stays_on_its_proposal,
        ),
        Property::<M>::reachable(
            "I-03 witness: a detection on one proposal leaves the other assignment active",
            detection_spares_the_other_proposal,
        ),
    ]);
    out
}

/// The properties of the staged instance, with their witnesses.
pub fn staged_properties<'a, M: Model<State = ConflictState>>() -> Vec<Property<'a, M>> {
    let mut out = safety::<M>();
    out.extend([
        Property::<M>::reachable(
            "R-AC-01 witness: an assigned reviewer reads in a stage",
            reviewer_read,
        ),
        Property::<M>::reachable(
            "I-03 witness: an assigned reviewer records a ranking summary",
            summary_written,
        ),
        Property::<M>::reachable(
            "R-CF-02 witness: a conflict declared after reading releases the assignment",
            later_declaration_released,
        ),
        Property::<M>::reachable(
            "I-03 witness: a committee member recuses from the cut-off vote",
            member_recused,
        ),
        Property::<M>::reachable(
            "I-03 witness: a detected conflict releases the assignment",
            detected_release,
        ),
    ]);
    out
}

// ---------------------------------------------------------------------------
// The fault of the teeth test
// ---------------------------------------------------------------------------

/// The fault of `i03_teeth_read_after_conflict_is_caught`: a broken engine
/// records a content read by an account that has a conflict fact on the
/// proposal. It folds through the public structural `apply` and the
/// reference folds, as a broken engine's batch would.
pub fn fault_read_after_conflict(s: &ConflictState) -> Option<ConflictState> {
    let (account, proposal) = s
        .world
        .view
        .facts
        .iter()
        .find(|pair| !s.world.view.breaches.contains(pair))
        .copied()?;
    let mut next = s.clone();
    next.world
        .commit(&[Record::ContentRead(ContentRead { account, proposal })])
        .ok()?;
    next.last = Some((account, proposal));
    Some(next)
}
