//! Generators, fixtures, the model driver and the fstp-prop machine for review and intake (design sections 2.7, 2.8, 4.5 and 6.1).
//!
//! Synthetic data only: numeric ids, synthetic identity numbers and
//! organisation numbers. No real personal data.
//!
//! - [`ReviewSetup`] lists the production commands that reach a start
//!   state from genesis: a programme with its review parameters, staff,
//!   calls drafted, approved and published, Judging bindings with
//!   organisations, and proposals created, planned and submitted.
//! - [`ReviewWorld`] is the driver of the models. It runs production
//!   `queries`, `decide` and `apply` without a store, over the vault facts
//!   and an optional [`Havoc`] script of `HasConflict` bits. Its
//!   [`Backend::Reference`] mode runs the same steps on the references
//!   alone, which checks the model before production lands.
//! - [`ReviewMachine`] is the fstp-prop machine over `Assign`,
//!   `DeclareConflict`, `ReadContent`, `Unassign`, `Withdraw`, Judging
//!   grants and ends, and vault relations and affiliations added mid-run.
//!   It runs through a [`Scenario`], so every step also checks the ledger
//!   (I-23). Each [`RevFocus`] weights it for one invariant.
//!
//! Reading for the models: no review guard compares wall-clock times
//! except the call window at `Submit`. So model commands run at [`T0`],
//! inside every call window, and the reduced clock has nothing to move.

use core::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use fstp_domain::assignment::AssignmentKind;
use fstp_domain::command::{Actor, Command, DeclarationSubject, SystemCause};
use fstp_domain::id::{
    AccountId, AssignmentId, BindingId, CallId, CommandId, ContentDigest, Handle, MilestoneId,
    OrganisationId, PlanVersionId, ProposalId, ProximityListId, VaultEpoch,
};
use fstp_domain::oracle::{Answer, Answers, Query};
use fstp_domain::policy::{ProximityLists, ReadAccess};
use fstp_domain::proposal::{
    EthicsDeclaration, Milestone, NoticeVersion, PlanOrigin, ReentryStage, Task,
};
use fstp_domain::record::{BindingVoided, Record, Transitioned};
use fstp_domain::refusal::{Refusal, RefusalReason, RuleRef};
use fstp_domain::roles::Role;
use fstp_domain::rules::{Row, StateTag};
use fstp_domain::time::Timestamp;
use fstp_engine::{ExecError, Record as EngineRecord};
use fstp_ledger::{Entry, Seq};
use fstp_money::{Amount, Currency, PosAmount};
use fstp_prop::{Gen, StateMachine};

use crate::r#gen::policy::{core_records, text};
use crate::r#gen::roster::{
    Backend, Facts, Flags, P1, P2, SodSetup, SodWorld, Step, T0, add_member, add_staff, call,
    draft, end, grant,
};
use crate::harness::prop::{ledger_step, two_way_exec};
use crate::reference::review::{
    ConflictFacts, RevView, check_expected, check_handles, check_i02_assignments, check_i03,
    check_i34_assign, check_i36, check_i36_grants, check_i36_held, check_rcf02, check_reaction,
    committee_organisation, end_releases, expected, reaction_records, receiving_holder,
    team_change_records, team_of, verdict,
};
use crate::reference::sod::{self, Verdict};
use crate::scenario::Scenario;
use crate::vault::{GroundTruth, IdentityTag, PLACEHOLDER_DIGEST, Relation};

// ---------------------------------------------------------------------------
// Synthetic accounts, organisations and ids
// ---------------------------------------------------------------------------

/// The FSTP coordinator.
pub const COORDINATOR: AccountId = AccountId::from_raw(201);
/// Committee member 1, of organisation [`O1`].
pub const R1: AccountId = AccountId::from_raw(211);
/// Committee member 2, of organisation [`O1`] in the machine and [`O2`] in M-CONFLICT.
pub const R2: AccountId = AccountId::from_raw(212);
/// Committee member 3.
pub const R3: AccountId = AccountId::from_raw(213);
/// Committee member 4.
pub const R4: AccountId = AccountId::from_raw(214);
/// The IRC member.
pub const IRC: AccountId = AccountId::from_raw(221);
/// An account that switches between committee member and IRC member (I-02).
pub const SWITCHER: AccountId = AccountId::from_raw(231);
/// Lead 1.
pub const L1: AccountId = AccountId::from_raw(301);
/// Lead 2.
pub const L2: AccountId = AccountId::from_raw(302);
/// Lead 3.
pub const L3: AccountId = AccountId::from_raw(303);
/// Lead 4.
pub const L4: AccountId = AccountId::from_raw(304);
/// A team member of the first proposal.
pub const MEMBER: AccountId = AccountId::from_raw(311);
/// An account with no binding.
pub const STRANGER: AccountId = AccountId::from_raw(399);

/// Partner organisation 1, with proximity list [`LIST_1`].
pub const O1: OrganisationId = OrganisationId::from_raw(1);
/// Partner organisation 2.
pub const O2: OrganisationId = OrganisationId::from_raw(2);
/// Partner organisation 3.
pub const O3: OrganisationId = OrganisationId::from_raw(3);
/// The P-38 proximity list of [`O1`].
pub const LIST_1: ProximityListId = ProximityListId::from_raw(1);

/// Proposal 1.
pub const PR1: ProposalId = ProposalId::from_raw(1);
/// Proposal 2.
pub const PR2: ProposalId = ProposalId::from_raw(2);
/// Proposal 3.
pub const PR3: ProposalId = ProposalId::from_raw(3);
/// Proposal 4.
pub const PR4: ProposalId = ProposalId::from_raw(4);

/// The synthetic identity of `account`: its number plus 5000.
pub fn tag(account: AccountId) -> IdentityTag {
    IdentityTag::new(u64::try_from(account.raw()).map_or(0, |n| n.saturating_add(5_000)))
}

/// The handle with synthetic number `n`.
pub fn handle(n: u128) -> Handle {
    let mut b = [0u8; 16];
    b.copy_from_slice(&n.to_be_bytes());
    Handle::from_bytes(b)
}

/// The plan id of the submitted plan of `proposal`.
pub fn plan_of(proposal: ProposalId) -> PlanVersionId {
    PlanVersionId::from_raw(proposal.raw().saturating_add(400))
}

/// The milestone id of the submitted plan of `proposal`.
pub fn milestone_of(proposal: ProposalId) -> MilestoneId {
    MilestoneId::from_raw(proposal.raw().saturating_add(600))
}

/// One microsecond after `t`, saturating.
pub fn after(t: Timestamp, micros: i64) -> Timestamp {
    Timestamp::from_micros(t.micros().saturating_add(micros))
}

// ---------------------------------------------------------------------------
// Steps
// ---------------------------------------------------------------------------

/// An `Assign` by `coordinator`.
pub fn assign(
    coordinator: AccountId,
    assignment: AssignmentId,
    proposal: ProposalId,
    reviewer: AccountId,
    kind: AssignmentKind,
    handle: Option<Handle>,
) -> Step {
    Step::by(
        coordinator,
        Flags::NONE,
        Command::Assign {
            assignment,
            proposal,
            reviewer,
            kind,
            handle,
        },
    )
}

/// A `DeclareConflict` by `actor`.
pub fn declare(
    actor: AccountId,
    subject: DeclarationSubject,
    conflicted: bool,
    notifiable: bool,
) -> Step {
    Step::by(
        actor,
        Flags::NONE,
        Command::DeclareConflict {
            subject,
            conflicted,
            notifiable,
        },
    )
}

/// A `ReadContent` by `actor`.
pub fn read(actor: AccountId, proposal: ProposalId) -> Step {
    Step::by(actor, Flags::NONE, Command::ReadContent { proposal })
}

/// An `Unassign` by `coordinator`.
pub fn unassign(coordinator: AccountId, assignment: AssignmentId) -> Step {
    Step::by(coordinator, Flags::NONE, Command::Unassign { assignment })
}

/// One milestone of 1000.00 EUR from `T0` to a year later.
pub fn milestone(id: MilestoneId) -> Result<Milestone, String> {
    let a = Amount::from_minor(100_000, Currency::Eur).map_err(|e| format!("amount: {e:?}"))?;
    Ok(Milestone {
        id,
        amount: PosAmount::new(a).map_err(|e| format!("amount: {e:?}"))?,
        start: T0,
        due: after(T0, 31_536_000_000_000),
        activity: None,
        deliverables: Vec::new(),
    })
}

/// A plan of one task per milestone id.
pub fn tasks(milestones: &[MilestoneId]) -> Result<Vec<Task>, String> {
    milestones
        .iter()
        .map(|m| {
            Ok(Task {
                milestones: vec![milestone(*m)?],
            })
        })
        .collect()
}

/// A `RecordPlanVersion` of a submitted plan by `lead`, one task per milestone.
pub fn record_plan(
    lead: AccountId,
    plan: PlanVersionId,
    proposal: ProposalId,
    milestones: &[MilestoneId],
) -> Result<Step, String> {
    let mut digest = [0u8; 32];
    let (head, _) = digest.split_at_mut(16);
    head.copy_from_slice(&plan.raw().to_be_bytes());
    Ok(Step::by(
        lead,
        Flags::NONE,
        Command::RecordPlanVersion {
            plan,
            proposal,
            origin: PlanOrigin::Submitted,
            supersedes: None,
            tasks: tasks(milestones)?,
            content: ContentDigest::from_bytes(digest),
        },
    ))
}

/// The ethics declaration of `proposal` (R-SB-05).
pub fn ethics(proposal: ProposalId, issues_declared: bool) -> EthicsDeclaration {
    EthicsDeclaration {
        issues_declared,
        text: text(proposal.raw().saturating_add(70_000)),
    }
}

/// The data protection notice version every submission shows (R-NG-06).
pub const NOTICE: NoticeVersion = NoticeVersion(1);

/// A `Submit` by `lead`.
pub fn submit(lead: AccountId, proposal: ProposalId, plan: PlanVersionId, issues: bool) -> Step {
    Step::by(
        lead,
        Flags::NONE,
        Command::Submit {
            proposal,
            plan,
            ethics: ethics(proposal, issues),
            notice: NOTICE,
        },
    )
}

/// A `Withdraw` by `actor`.
pub fn withdraw(actor: AccountId, proposal: ProposalId) -> Step {
    Step::by(actor, Flags::NONE, Command::Withdraw { proposal })
}

// ---------------------------------------------------------------------------
// Setup from genesis
// ---------------------------------------------------------------------------

/// One proposal of a setup.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DraftSpec {
    /// The lead.
    pub lead: AccountId,
    /// The proposal.
    pub proposal: ProposalId,
    /// The call.
    pub call: CallId,
    /// The team members.
    pub team: Vec<AccountId>,
    /// Whether the lead is flagged as a minor.
    pub minor: bool,
    /// Whether the setup submits it.
    pub submit: bool,
}

/// A start state from genesis: what [`ReviewSetup::steps`] runs.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ReviewSetup {
    /// The programme and its calls, with the calls to publish.
    pub base: SodSetup,
    /// P-38 of the programme.
    pub p38: BTreeMap<OrganisationId, ProximityListId>,
    /// P-10 of the programme.
    pub p10: ReadAccess,
    /// Judging bindings: account, role and organisation.
    pub judges: Vec<(AccountId, Role, Option<OrganisationId>)>,
    /// The proposals.
    pub drafts: Vec<DraftSpec>,
}

/// The binding id of the `i`-th Judging grant of a setup.
pub fn judge_binding(i: usize) -> BindingId {
    BindingId::from_raw(200u128.saturating_add(u128::try_from(i).unwrap_or(0)))
}

/// The binding id of the `j`-th Receiving binding of the `i`-th draft of a setup.
pub fn draft_binding(i: usize, j: usize) -> BindingId {
    let i = u128::try_from(i).unwrap_or(0);
    let j = u128::try_from(j).unwrap_or(0);
    BindingId::from_raw(
        300u128
            .saturating_add(i.saturating_mul(10))
            .saturating_add(j),
    )
}

impl ReviewSetup {
    /// The production commands of the setup, in order.
    pub fn steps(&self) -> Result<Vec<Step>, String> {
        let mut out = self.base.steps()?;
        for s in &mut out {
            if let Command::CreateProgramme { policy } = &mut s.cmd {
                policy.live.p38 = ProximityLists(self.p38.clone());
                policy.frozen.p10 = self.p10;
            }
        }
        for (i, (account, role, org)) in self.judges.iter().enumerate() {
            let mut step = grant(judge_binding(i), *account, P1, *role, T0);
            if let Command::GrantRole { organisation, .. } = &mut step.cmd {
                *organisation = *org;
            }
            out.push(step);
        }
        for (i, d) in self.drafts.iter().enumerate() {
            out.push(draft(
                d.lead,
                d.proposal,
                d.call,
                draft_binding(i, 0),
                d.minor,
            ));
            for (j, m) in d.team.iter().enumerate() {
                out.push(add_member(
                    d.lead,
                    d.proposal,
                    *m,
                    draft_binding(i, j.saturating_add(1)),
                    false,
                ));
            }
            out.push(record_plan(
                d.lead,
                plan_of(d.proposal),
                d.proposal,
                &[milestone_of(d.proposal)],
            )?);
            if d.submit {
                out.push(submit(d.lead, d.proposal, plan_of(d.proposal), false));
            }
        }
        Ok(out)
    }

    /// Every account of the setup beside staff.
    pub fn accounts(&self) -> BTreeSet<AccountId> {
        let mut out: BTreeSet<AccountId> = self.judges.iter().map(|(a, _, _)| *a).collect();
        for d in &self.drafts {
            out.insert(d.lead);
            out.extend(d.team.iter().copied());
        }
        out
    }
}

/// The vault of a setup: staff, and every account of `accounts` with its
/// own synthetic identity, verified. No relation and no affiliation.
pub fn review_truth(accounts: impl IntoIterator<Item = AccountId>) -> GroundTruth {
    let mut truth = GroundTruth::new();
    add_staff(&mut truth);
    for a in accounts {
        truth.set_identity(a, tag(a));
        truth.verify(a);
    }
    truth
}

// ---------------------------------------------------------------------------
// The model driver
// ---------------------------------------------------------------------------

/// A havoc script of `HasConflict` bits (design section 4.5): the vault
/// answers them whatever its facts, and the domain must obey.
///
/// Each flip advances the vault epoch by one beyond the ground truth's,
/// and lists the accounts the change query reports, possibly none.
/// Queries outside the script are answered from the ground truth.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Havoc {
    /// The scripted bits, by reviewer and team.
    pub bits: BTreeMap<(AccountId, BTreeSet<AccountId>), bool>,
    /// The flips so far.
    pub flips: u64,
    /// The epoch of each flip and the accounts its change query lists.
    pub log: Vec<(VaultEpoch, BTreeSet<AccountId>)>,
}

impl Havoc {
    /// A script with `bits` and no flip yet.
    pub fn new(bits: BTreeMap<(AccountId, BTreeSet<AccountId>), bool>) -> Havoc {
        Havoc {
            bits,
            flips: 0,
            log: Vec::new(),
        }
    }
}

/// The review facts of a world: the ground truth, overridden by a havoc script.
#[derive(Clone, Copy, Debug)]
pub struct WorldFacts<'a> {
    /// The ground truth.
    pub truth: &'a GroundTruth,
    /// The havoc script, if any.
    pub havoc: Option<&'a Havoc>,
}

impl ConflictFacts for WorldFacts<'_> {
    fn has_conflict(&self, reviewer: AccountId, team: &BTreeSet<AccountId>) -> bool {
        if let Some(b) = self
            .havoc
            .and_then(|h| h.bits.get(&(reviewer, team.clone())))
        {
            return *b;
        }
        self.truth.has_conflict(reviewer, team)
    }

    fn declares_on_list(&self, team: &BTreeSet<AccountId>, list: ProximityListId) -> bool {
        self.truth.declares_on_list(team, list)
    }

    fn same_identity(&self, subject: AccountId, other: AccountId) -> bool {
        self.truth.same_identity(subject, other)
    }
}

/// The command id every model command uses. The pure functions never read it.
const MODEL_COMMAND: CommandId = CommandId::from_bytes(*b"model:rev:steps!");

/// The model refusal of a step the reference refuses, in reference mode.
const REFERENCE_REFUSAL: Refusal = Refusal::new(RuleRef::Input, RefusalReason::GuardFailed);

/// What a step did: the records it committed, or the refusal. The outer
/// error is a harness failure, such as a batch the fold refused.
pub type StepResult = Result<Result<Vec<Record>, Refusal>, String>;

/// A model world for review: the L-SOD world (production projection,
/// vault facts and roles view), the review view and the havoc script.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ReviewWorld {
    /// Production, the vault facts and the L-SOD reference view.
    pub sod: SodWorld,
    /// The review reference view of every record committed.
    pub view: RevView,
    /// The havoc script, after the setup.
    pub havoc: Option<Havoc>,
}

impl ReviewWorld {
    /// A world after running `setup` from genesis over `truth`. Every step
    /// must succeed. The havoc script, if any, starts after the setup.
    pub fn from_setup(
        backend: Backend,
        truth: GroundTruth,
        setup: &ReviewSetup,
        havoc: Option<Havoc>,
    ) -> Result<ReviewWorld, String> {
        let mut w = ReviewWorld {
            sod: SodWorld::new(backend, truth),
            view: RevView::new(),
            havoc: None,
        };
        for step in setup.steps()? {
            let kind = step.cmd.kind();
            if let Err(r) = w.exec(&step)? {
                return Err(format!("setup step {kind:?} refused: {r}"));
            }
        }
        w.havoc = havoc;
        Ok(w)
    }

    /// The review facts.
    pub fn facts(&self) -> WorldFacts<'_> {
        WorldFacts {
            truth: &self.sod.truth,
            havoc: self.havoc.as_ref(),
        }
    }

    /// The vault epoch: the ground truth's, plus one per havoc flip.
    pub fn vault_epoch(&self) -> VaultEpoch {
        let flips = self.havoc.as_ref().map_or(0, |h| h.flips);
        VaultEpoch::from_raw(self.sod.truth.epoch().raw().saturating_add(flips))
    }

    /// The accounts the change query lists after `epoch`.
    pub fn changed_since(&self, epoch: VaultEpoch) -> BTreeSet<AccountId> {
        let mut out = self.sod.truth.changed_since(epoch);
        if let Some(h) = &self.havoc {
            for (e, accounts) in &h.log {
                if *e > epoch {
                    out.extend(accounts.iter().copied());
                }
            }
        }
        out
    }

    /// The vault epoch the world has processed.
    pub fn processed(&self) -> VaultEpoch {
        match self.sod.backend {
            Backend::Production => self.sod.state.epoch(),
            Backend::Reference => self.sod.view.epoch,
        }
    }

    /// The answer to `q` at the vault epoch.
    pub fn answer(&self, q: &Query) -> Answer {
        let epoch = self.vault_epoch();
        let (holds, accounts) = match q {
            Query::ChangedSince { epoch: e } => {
                let a = self.changed_since(*e);
                (!a.is_empty(), Some(a))
            }
            Query::HasConflict { reviewer, team } => {
                (self.facts().has_conflict(*reviewer, team), None)
            }
            _ => (self.sod.truth.holds(q), None),
        };
        Answer {
            holds,
            accounts,
            epoch,
            digest: PLACEHOLDER_DIGEST,
        }
    }

    /// Flips the havoc bit of `reviewer` and `team` to `bit`. The change
    /// query lists the reviewer when `listed`, and nobody otherwise.
    pub fn flip(
        &mut self,
        reviewer: AccountId,
        team: BTreeSet<AccountId>,
        bit: bool,
        listed: bool,
    ) {
        let epoch = VaultEpoch::from_raw(self.vault_epoch().raw().saturating_add(1));
        let h = self
            .havoc
            .get_or_insert_with(|| Havoc::new(BTreeMap::new()));
        h.bits.insert((reviewer, team), bit);
        h.flips = h.flips.saturating_add(1);
        let accounts = if listed {
            [reviewer].into_iter().collect()
        } else {
            BTreeSet::new()
        };
        h.log.push((epoch, accounts));
    }

    /// The reference verdict on `step` now.
    pub fn verdict(&self, step: &Step) -> Verdict {
        let facts = self.facts();
        verdict(
            &self.sod.view,
            &self.view,
            &self.sod.truth,
            &facts,
            &step.ask(self.sod.now),
        )
    }

    /// Folds `records` into the production projection and both views, as
    /// one batch. Nothing changes when a fold refuses.
    pub fn commit(&mut self, records: &[Record]) -> Result<(), String> {
        let mut view = self.view.clone();
        for r in records {
            view.fold(r)
                .map_err(|e| format!("the review reference cannot follow {r:?}: {e}"))?;
        }
        self.sod.commit(records)?;
        self.view = view;
        Ok(())
    }

    /// Runs `step` on production: queries, answers at the vault epoch, decide.
    fn production(&self, step: &Step) -> Result<Vec<Record>, Refusal> {
        let ctx = step.ctx(self.sod.now, MODEL_COMMAND);
        let mut answers = Answers::new();
        for q in fstp_domain::queries(&self.sod.state, &step.cmd, &ctx)? {
            let a = self.answer(&q);
            answers.insert(q, a);
        }
        fstp_domain::decide(&self.sod.state, &step.cmd, &ctx, &answers)
    }

    /// The `VaultChanged` step that processes the vault epoch now.
    pub fn vault_step(&self) -> Step {
        Step {
            actor: Actor::System(SystemCause::Vault),
            flags: Flags::NONE,
            cmd: Command::VaultChanged {
                epoch: self.vault_epoch(),
                changed: self.changed_since(self.processed()),
            },
        }
    }

    /// Processes a newer vault epoch with `VaultChanged`. Returns the
    /// records, empty when the epoch is current, or the refusal.
    pub fn sync(&mut self) -> StepResult {
        let target = self.vault_epoch();
        if target <= self.processed() {
            return Ok(Ok(Vec::new()));
        }
        let records = match self.sod.backend {
            Backend::Production => match self.production(&self.vault_step()) {
                Ok(r) => r,
                Err(r) => return Ok(Err(r)),
            },
            Backend::Reference => self.reference_reaction(target),
        };
        self.commit(&records)?;
        Ok(Ok(records))
    }

    /// The records the references expect of a reaction at `target`.
    fn reference_reaction(&self, target: VaultEpoch) -> Vec<Record> {
        let mut out: Vec<Record> = sod::expected_voids(&self.sod.view, &self.sod.truth)
            .into_iter()
            .filter_map(|(binding, rules)| {
                let rule = if rules.contains(&RuleRef::I06) {
                    Some(RuleRef::I06)
                } else {
                    rules.first().copied()
                };
                rule.map(|rule| {
                    Record::BindingVoided(BindingVoided {
                        binding,
                        rule,
                        epoch: target,
                    })
                })
            })
            .collect();
        let facts = self.facts();
        let review = reaction_records(
            &self.sod.view,
            &self.view,
            &facts,
            &out,
            target,
            self.sod.now,
        );
        out.extend(review);
        out.push(Record::VaultEpochProcessed { epoch: target });
        out
    }

    /// Runs `step`: first the reaction to a newer vault epoch, as the
    /// driver does (overview NOTE 3), then the step. Returns its records.
    pub fn exec(&mut self, step: &Step) -> StepResult {
        if let Err(r) = self.sync()? {
            return Ok(Err(r));
        }
        let records = match self.sod.backend {
            Backend::Production => match self.production(step) {
                Ok(r) => r,
                Err(r) => return Ok(Err(r)),
            },
            Backend::Reference => match self.synthesize(step)? {
                Some(r) => r,
                None => return Ok(Err(REFERENCE_REFUSAL)),
            },
        };
        self.commit(&records)?;
        Ok(Ok(records))
    }

    /// The records the references expect of `step`, or `None` when they
    /// refuse. An unjudged command is taken as accepted.
    fn synthesize(&self, step: &Step) -> Result<Option<Vec<Record>>, String> {
        if let Verdict::Refuse(_) = self.verdict(step) {
            return Ok(None);
        }
        let ask = step.ask(self.sod.now);
        let mine = matches!(
            step.cmd,
            Command::Assign { .. }
                | Command::Unassign { .. }
                | Command::DeclareConflict { .. }
                | Command::ReadContent { .. }
                | Command::RecordPlanVersion { .. }
                | Command::Submit { .. }
                | Command::RecordRankingSummary { .. }
                | Command::Withdraw { .. }
        );
        if mine {
            return Ok(expected(
                &self.sod.view,
                &self.view,
                &self.facts(),
                &ask,
                self.processed(),
            )
            .map(|e| e.required));
        }
        let mut probe = self.sod.clone();
        let mut records = match probe.exec(step, Facts::Effective)? {
            Ok(r) => r,
            Err(_) => return Ok(None),
        };
        if let Command::EndRole { binding, .. } = &step.cmd {
            records.extend(end_releases(&self.sod.view, &self.view, *binding));
        }
        if let Command::AddTeamMember {
            proposal, account, ..
        }
        | Command::AddGuardian {
            proposal, account, ..
        } = &step.cmd
        {
            records.extend(team_change_records(
                &self.sod.view,
                &self.view,
                &self.facts(),
                *proposal,
                *account,
                self.processed(),
                self.sod.now,
            ));
        }
        Ok(Some(records))
    }
}

/// Runs `step` on `world` and compares the outcome with the reference in
/// both directions, including the records an accepted step must hold.
/// Returns the world after the step and its records, `None` when both
/// refuse, or the divergence.
pub fn judged(
    world: &ReviewWorld,
    step: &Step,
) -> Option<Result<(ReviewWorld, Vec<Record>), String>> {
    let v = world.verdict(step);
    let ask = step.ask(world.sod.now);
    let exp = expected(
        &world.sod.view,
        &world.view,
        &world.facts(),
        &ask,
        world.processed(),
    );
    let exp_binding = sod::expected_binding(&world.sod.view, &ask);
    let context = format!("{:?} by {:?}", step.cmd, step.actor);
    let mut next = world.clone();
    match next.exec(step) {
        Err(e) => Some(Err(format!("{context}: {e}"))),
        Ok(Err(r)) => match v {
            Verdict::Accept => Some(Err(format!(
                "{context}: over-denial, the reference accepts, production refuses with {r}"
            ))),
            _ => None,
        },
        Ok(Ok(records)) => {
            if let Verdict::Refuse(why) = &v {
                return Some(Err(format!(
                    "{context}: over-permission, the reference refuses ({why}), production accepts"
                )));
            }
            if v.accepts() {
                if let Some(e) = &exp
                    && let Err(e) = check_expected(&context, &world.view, e, &records)
                {
                    return Some(Err(e));
                }
                if let Some(e) = &exp_binding
                    && let Err(e) = sod::check_granted(&context, e, &records)
                {
                    return Some(Err(e));
                }
                if let Command::EndRole { binding, at } = &step.cmd
                    && let Err(e) =
                        sod::check_ended(&context, &world.sod.view, *binding, *at, &records)
                {
                    return Some(Err(e));
                }
            }
            Some(Ok((next, records)))
        }
    }
}

/// Runs the reaction to a newer vault epoch on `world` and checks it:
/// accepted, with the voids of the L-SOD reference and the detections and
/// releases of [`check_reaction`]. `must` says which assignees the
/// reaction had to recheck.
pub fn reacted(
    world: &ReviewWorld,
    must: &dyn Fn(AccountId, &BTreeSet<AccountId>) -> bool,
) -> Result<(ReviewWorld, Vec<Record>), String> {
    let mut next = world.clone();
    let records = match next.sync()? {
        Ok(r) => r,
        Err(r) => {
            return Err(format!(
                "vault reaction: over-denial, production refused VaultChanged with {r}"
            ));
        }
    };
    let voids = sod::expected_voids(&world.sod.view, &world.sod.truth);
    sod::check_voids("vault reaction", &voids, &records)?;
    let facts = next.facts();
    check_reaction(
        "vault reaction",
        &world.sod.view,
        &world.view,
        &facts,
        must,
        &records,
        world.sod.now,
    )?;
    Ok((next, records))
}

// ---------------------------------------------------------------------------
// The fstp-prop machine
// ---------------------------------------------------------------------------

/// What a machine draws most, and how big its cases are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RevFocus {
    /// Draw weights in the order assign, declare on an assignment, declare
    /// on a proposal, read, unassign, relate, unrelate, affiliate,
    /// withdraw, Judging grant, Judging end.
    pub weights: [u32; 11],
    /// The share in 16 of assignments that reuse an issued handle.
    pub handle_reuse: u32,
    /// Commands per case.
    pub max_commands: usize,
    /// Cases per run.
    pub cases: u32,
}

impl RevFocus {
    /// I-03 and R-CF-02: assignments, declarations, reads and relations
    /// and mentoring added and removed mid-run.
    pub const I03: RevFocus = RevFocus {
        weights: [6, 5, 3, 8, 2, 4, 2, 0, 1, 0, 0],
        handle_reuse: 1,
        max_commands: 40,
        cases: 128,
    };
    /// I-34 and I-35: assignment runs over organisations and proximity lists.
    pub const I34_I35: RevFocus = RevFocus {
        weights: [10, 3, 0, 1, 4, 0, 0, 3, 0, 0, 0],
        handle_reuse: 1,
        max_commands: 40,
        cases: 128,
    };
    /// I-02: Judging grants and ends of one account, with its assignments.
    pub const I02: RevFocus = RevFocus {
        weights: [6, 2, 0, 0, 2, 0, 0, 0, 0, 5, 4],
        handle_reuse: 0,
        max_commands: 40,
        cases: 128,
    };
    /// R-AN-01 and P-11: assignment runs across proposals and calls, with
    /// issued handles drawn again.
    pub const R_AN_01: RevFocus = RevFocus {
        weights: [10, 2, 0, 0, 3, 0, 0, 0, 1, 0, 0],
        handle_reuse: 6,
        max_commands: 40,
        cases: 128,
    };
}

/// A vault change of the machine, processed in the same step (design 6.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RevOp {
    /// The two identities become related.
    Relate(IdentityTag, IdentityTag, Relation),
    /// The relation ends.
    Unrelate(IdentityTag, IdentityTag, Relation),
    /// The account declares an affiliation on the list.
    Affiliate(AccountId, ProximityListId),
}

impl RevOp {
    /// Applies the change to `truth`.
    pub fn apply(self, truth: &mut GroundTruth) {
        match self {
            RevOp::Relate(a, b, r) => truth.relate(a, b, r),
            RevOp::Unrelate(a, b, r) => truth.unrelate(a, b, r),
            RevOp::Affiliate(a, l) => truth.declare_affiliation(a, l),
        }
    }
}

/// One machine command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RevCmd {
    /// Builds the start state from genesis over these vault facts.
    Setup {
        /// The vault facts.
        truth: Box<GroundTruth>,
    },
    /// A core command at `now`.
    Core {
        /// The instant, in microseconds.
        now: i64,
        /// The command.
        step: Box<Step>,
    },
    /// A vault change at `now`, with its reaction.
    Vault {
        /// The instant, in microseconds.
        now: i64,
        /// The change.
        op: RevOp,
    },
}

/// The reference side of the machine, used to draw commands.
#[derive(Clone, Debug)]
pub struct RevModel {
    /// Whether the setup ran.
    pub ready: bool,
    /// The roles view of the records production appended.
    pub sod: sod::View,
    /// The review view of the records production appended.
    pub rev: RevView,
    /// The vault facts.
    pub truth: GroundTruth,
    /// The latest instant, in microseconds.
    pub now: i64,
    /// The next fresh id.
    pub next_id: u128,
}

/// What the machine drives.
#[derive(Debug)]
pub enum RevDriver {
    /// The production engine through the reference driver over a store.
    Engine(Box<Scenario>),
    /// The references alone, with the records they accepted.
    Reference(Box<ReviewWorld>, Vec<Record>),
}

impl RevDriver {
    /// The vault facts.
    pub fn truth(&self) -> &GroundTruth {
        match self {
            RevDriver::Engine(s) => s.truth(),
            RevDriver::Reference(w, _) => &w.sod.truth,
        }
    }

    fn execute(&mut self, step: &Step, now: Timestamp) -> Result<Seq, ExecError> {
        match self {
            RevDriver::Engine(s) => {
                let mut ctx = s.ctx(now, step.actor);
                ctx.tenant_admin = step.flags.tenant_admin;
                ctx.second_tenant_admin = step.flags.second_admin;
                ctx.binds_tenant_admin = step.flags.binds_tenant_admin;
                s.execute(fstp_engine::Command::Core(step.cmd.clone()), ctx)
            }
            RevDriver::Reference(w, records) => {
                w.sod.now = now;
                match w.sync() {
                    Ok(Ok(batch)) => {
                        records.extend(batch);
                    }
                    Ok(Err(r)) => return Err(ExecError::Refused(r)),
                    Err(_) => return Err(ExecError::Contended),
                }
                match w.exec(step) {
                    Ok(Ok(batch)) => Ok(append(records, batch)),
                    Ok(Err(r)) => Err(ExecError::Refused(r)),
                    Err(_) => Err(ExecError::Contended),
                }
            }
        }
    }

    fn change_vault(&mut self, op: RevOp, now: Timestamp) -> Result<Seq, ExecError> {
        let processed = match self {
            RevDriver::Engine(s) => {
                let ctx = s.ctx(now, Actor::System(SystemCause::Vault));
                s.change_vault(|t| op.apply(t), ctx)?
            }
            RevDriver::Reference(w, records) => {
                w.sod.now = now;
                op.apply(&mut w.sod.truth);
                match w.sync() {
                    Ok(Ok(batch)) if batch.is_empty() => None,
                    Ok(Ok(batch)) => Some(append(records, batch)),
                    Ok(Err(r)) => return Err(ExecError::Refused(r)),
                    Err(_) => return Err(ExecError::Contended),
                }
            }
        };
        processed.ok_or(ExecError::Refused(Refusal::new(
            RuleRef::StaleFacts,
            RefusalReason::AnswerStale,
        )))
    }
}

fn append(records: &mut Vec<Record>, batch: Vec<Record>) -> Seq {
    records.extend(batch);
    Seq::from_raw(u64::try_from(records.len()).unwrap_or(u64::MAX))
}

/// The production side of the machine.
#[derive(Debug)]
pub struct RevSut {
    /// The driver, once the setup ran.
    pub driver: Option<RevDriver>,
    /// The ledger before the latest step, under the engine driver.
    pub previous: Vec<Entry<EngineRecord>>,
    /// The ledger after the latest step, under the engine driver.
    pub current: Vec<Entry<EngineRecord>>,
    /// The core records after the latest step.
    pub records: Vec<Record>,
}

impl RevSut {
    fn advance(&mut self) -> Vec<Record> {
        let before = self.records.len();
        match &self.driver {
            Some(RevDriver::Engine(s)) => {
                self.previous = core::mem::take(&mut self.current);
                self.current = s.entries().unwrap_or_default();
                self.records = core_records(&self.current);
            }
            Some(RevDriver::Reference(_, records)) => self.records.clone_from(records),
            None => self.records.clear(),
        }
        self.records.get(before..).unwrap_or_default().to_vec()
    }
}

/// What one machine step returned, with the views taken before the step.
#[derive(Debug)]
pub struct RevOutput {
    /// What the step is.
    pub context: String,
    /// The reference verdict.
    pub verdict: Verdict,
    /// The driver result.
    pub result: Result<Seq, ExecError>,
    /// The core records the step appended.
    pub appended: Vec<Record>,
    /// The roles view before the step.
    pub sod: sod::View,
    /// The review view before the step.
    pub rev: RevView,
    /// The vault facts after the step.
    pub truth: GroundTruth,
    /// The instant.
    pub now: Timestamp,
}

/// The fstp-prop machine over the review commands (I-02, I-03, I-34,
/// I-35, R-CF-02, R-AN-01). Postconditions compare accept and refuse with
/// [`verdict`] in both directions and check the records of every accepted
/// step. The invariant checks I-03, R-CF-02, the handles, I-02, I-36 and
/// I-23 after every step.
#[derive(Debug)]
pub struct ReviewMachine {
    /// What the machine draws most.
    pub focus: RevFocus,
    /// What decides.
    pub backend: Backend,
    last: RefCell<Vec<Record>>,
}

/// The Judging bindings of the machine setup.
pub fn machine_judges() -> Vec<(AccountId, Role, Option<OrganisationId>)> {
    vec![
        (COORDINATOR, Role::FstpCoordinator, None),
        (R1, Role::CommitteeMember, Some(O1)),
        (R2, Role::CommitteeMember, Some(O1)),
        (R3, Role::CommitteeMember, Some(O2)),
        (R4, Role::CommitteeMember, Some(O3)),
        (IRC, Role::IrcMember, None),
    ]
}

/// The setup of the machine: one programme with P-12 = 1, P-38 giving
/// [`O1`] the list [`LIST_1`], two published calls, the Judging bindings
/// of [`machine_judges`], and four proposals. PR1 has a team member, PR1
/// to PR3 are submitted and PR4 stays in DRAFT.
pub fn machine_setup() -> ReviewSetup {
    let mut base = SodSetup::one(1, &[1, 2]);
    base.published = vec![call(1), call(2)];
    ReviewSetup {
        base,
        p38: [(O1, LIST_1)].into_iter().collect(),
        p10: ReadAccess::AssignedReviewersOnly,
        judges: machine_judges(),
        drafts: vec![
            DraftSpec {
                lead: L1,
                proposal: PR1,
                call: call(1),
                team: vec![MEMBER],
                minor: false,
                submit: true,
            },
            DraftSpec {
                lead: L2,
                proposal: PR2,
                call: call(1),
                team: Vec::new(),
                minor: true,
                submit: true,
            },
            DraftSpec {
                lead: L3,
                proposal: PR3,
                call: call(2),
                team: Vec::new(),
                minor: false,
                submit: true,
            },
            DraftSpec {
                lead: L4,
                proposal: PR4,
                call: call(2),
                team: Vec::new(),
                minor: false,
                submit: false,
            },
        ],
    }
}

/// Every account the machine names beside staff.
pub fn machine_accounts() -> Vec<AccountId> {
    vec![
        COORDINATOR,
        R1,
        R2,
        R3,
        R4,
        IRC,
        SWITCHER,
        L1,
        L2,
        L3,
        L4,
        MEMBER,
        STRANGER,
    ]
}

impl ReviewMachine {
    /// A machine with `focus` over production.
    pub fn new(focus: RevFocus) -> ReviewMachine {
        ReviewMachine::with_backend(focus, Backend::Production)
    }

    /// A machine with `focus` over `backend`.
    pub fn with_backend(focus: RevFocus, backend: Backend) -> ReviewMachine {
        ReviewMachine {
            focus,
            backend,
            last: RefCell::new(Vec::new()),
        }
    }

    fn fresh(&self, g: &mut Gen, model: &RevModel, existing: u128) -> u128 {
        if existing > 0 && g.weighted(&[19, 1]) == 1 {
            existing
        } else {
            model.next_id
        }
    }

    fn proposal(&self, g: &mut Gen, model: &RevModel) -> ProposalId {
        let all: Vec<ProposalId> = model.rev.proposals.keys().copied().collect();
        if all.is_empty() { PR1 } else { *g.pick(&all) }
    }

    fn judge(&self, g: &mut Gen) -> AccountId {
        match g.weighted(&[10, 1, 1, 1]) {
            0 => *g.pick(&[R1, R2, R3, R4]),
            1 => IRC,
            2 => SWITCHER,
            _ => *g.pick(&[COORDINATOR, L2, STRANGER]),
        }
    }

    fn coordinator(&self, g: &mut Gen) -> AccountId {
        if g.weighted(&[12, 1]) == 1 {
            *g.pick(&[R1, L1, STRANGER])
        } else {
            COORDINATOR
        }
    }

    fn gen_assign(&self, g: &mut Gen, model: &RevModel, now: i64) -> RevCmd {
        let proposal = self.proposal(g, model);
        let reviewer = self.judge(g);
        let kind = if g.weighted(&[8, 1]) == 1 {
            AssignmentKind::Irc
        } else {
            AssignmentKind::Reviewer
        };
        let max = model
            .rev
            .assignments
            .keys()
            .next_back()
            .map_or(0, |a| a.raw());
        let id = self.fresh(g, model, max);
        let issued: Vec<Handle> = model.rev.handles.keys().copied().collect();
        let h = match g.weighted(&[
            16u32.saturating_sub(self.focus.handle_reuse),
            self.focus.handle_reuse,
            1,
        ]) {
            1 if !issued.is_empty() => Some(*g.pick(&issued)),
            2 => None,
            _ => Some(handle(model.next_id.saturating_add(90_000))),
        };
        RevCmd::Core {
            now,
            step: Box::new(assign(
                self.coordinator(g),
                AssignmentId::from_raw(id),
                proposal,
                reviewer,
                kind,
                h,
            )),
        }
    }

    fn gen_declare_assignment(&self, g: &mut Gen, model: &RevModel, now: i64) -> RevCmd {
        let all: Vec<(AssignmentId, AccountId)> = model
            .rev
            .assignments
            .values()
            .map(|a| (a.id, a.reviewer))
            .collect();
        if all.is_empty() {
            return self.gen_assign(g, model, now);
        }
        let (id, reviewer) = *g.pick(&all);
        let actor = if g.weighted(&[12, 1]) == 1 {
            self.judge(g)
        } else {
            reviewer
        };
        let conflicted = g.weighted(&[3, 1]) == 1;
        let notifiable = conflicted && g.bool();
        RevCmd::Core {
            now,
            step: Box::new(declare(
                actor,
                DeclarationSubject::Assignment(id),
                conflicted,
                notifiable,
            )),
        }
    }

    fn gen_declare_proposal(&self, g: &mut Gen, model: &RevModel, now: i64) -> RevCmd {
        let proposal = self.proposal(g, model);
        let actor = self.coordinator(g);
        let conflicted = g.weighted(&[3, 1]) == 1;
        RevCmd::Core {
            now,
            step: Box::new(declare(
                actor,
                DeclarationSubject::Proposal(proposal),
                conflicted,
                false,
            )),
        }
    }

    fn gen_read(&self, g: &mut Gen, model: &RevModel, now: i64) -> RevCmd {
        let proposal = self.proposal(g, model);
        let lead = model.rev.proposals.get(&proposal).map_or(L1, |l| l.lead);
        let actor = match g.weighted(&[6, 4, 1, 1]) {
            0 => COORDINATOR,
            1 => self.judge(g),
            2 => lead,
            _ => MEMBER,
        };
        RevCmd::Core {
            now,
            step: Box::new(read(actor, proposal)),
        }
    }

    fn gen_unassign(&self, g: &mut Gen, model: &RevModel, now: i64) -> RevCmd {
        let all: Vec<AssignmentId> = model.rev.assignments.keys().copied().collect();
        if all.is_empty() {
            return self.gen_assign(g, model, now);
        }
        RevCmd::Core {
            now,
            step: Box::new(unassign(self.coordinator(g), *g.pick(&all))),
        }
    }

    fn gen_relation(&self, g: &mut Gen, model: &RevModel, now: i64, add: bool) -> RevCmd {
        // Mostly a pair the platform tracks: an assignee or a cleared reader
        // and the lead of that proposal, so detections happen.
        let tracked: Vec<(AccountId, ProposalId)> = model
            .rev
            .assignments
            .values()
            .filter(|a| a.unreleased())
            .map(|a| (a.reviewer, a.proposal))
            .chain(model.rev.cleared.iter().copied())
            .collect();
        let (judge, applicant) = if !tracked.is_empty() && g.weighted(&[1, 3]) == 1 {
            let (j, p) = *g.pick(&tracked);
            let lead = model.rev.proposals.get(&p).map_or(L1, |l| l.lead);
            (j, if p == PR1 && g.bool() { MEMBER } else { lead })
        } else {
            (
                *g.pick(&[COORDINATOR, R1, R2, R3, R4, IRC]),
                *g.pick(&[L1, L2, L3, L4, MEMBER]),
            )
        };
        let relation = *g.pick(&[Relation::CoWorker, Relation::Relative, Relation::Mentoring]);
        let (a, b) = if g.bool() {
            (tag(judge), tag(applicant))
        } else {
            (tag(applicant), tag(judge))
        };
        RevCmd::Vault {
            now,
            op: if add {
                RevOp::Relate(a, b, relation)
            } else {
                RevOp::Unrelate(a, b, relation)
            },
        }
    }

    fn gen_affiliate(&self, g: &mut Gen, now: i64) -> RevCmd {
        let account = *g.pick(&[L1, L2, L3, L4, MEMBER]);
        RevCmd::Vault {
            now,
            op: RevOp::Affiliate(account, LIST_1),
        }
    }

    fn gen_withdraw(&self, g: &mut Gen, model: &RevModel, now: i64) -> RevCmd {
        let proposal = self.proposal(g, model);
        let lead = model.rev.proposals.get(&proposal).map_or(L1, |l| l.lead);
        let actor = if g.weighted(&[8, 1]) == 1 {
            MEMBER
        } else {
            lead
        };
        RevCmd::Core {
            now,
            step: Box::new(withdraw(actor, proposal)),
        }
    }

    fn gen_grant(&self, g: &mut Gen, model: &RevModel, now: i64) -> RevCmd {
        let role = *g.pick(&[Role::CommitteeMember, Role::IrcMember]);
        let max = model.sod.max_binding();
        let binding = BindingId::from_raw(self.fresh(g, model, max).max(1_000));
        let mut step = grant(binding, SWITCHER, P1, role, Timestamp::from_micros(now));
        if let Command::GrantRole { organisation, .. } = &mut step.cmd {
            *organisation = (role == Role::CommitteeMember).then_some(O3);
        }
        RevCmd::Core {
            now,
            step: Box::new(step),
        }
    }

    fn gen_end(&self, g: &mut Gen, model: &RevModel, now: i64) -> RevCmd {
        let held: Vec<BindingId> = model
            .sod
            .bindings
            .values()
            .filter(|b| b.held() && matches!(b.role, Role::CommitteeMember | Role::IrcMember))
            .filter(|b| b.account == SWITCHER || g.weighted(&[6, 1]) == 1)
            .map(|b| b.binding)
            .collect();
        if held.is_empty() {
            return self.gen_grant(g, model, now);
        }
        RevCmd::Core {
            now,
            step: Box::new(end(*g.pick(&held), Timestamp::from_micros(now))),
        }
    }
}

impl StateMachine for ReviewMachine {
    type Model = RevModel;
    type Sut = RevSut;
    type Command = RevCmd;
    type Output = RevOutput;

    fn init_model(&self) -> RevModel {
        RevModel {
            ready: false,
            sod: sod::View::new(),
            rev: RevView::new(),
            truth: GroundTruth::new(),
            now: T0.micros(),
            next_id: 10_000,
        }
    }

    fn init_sut(&self) -> RevSut {
        RevSut {
            driver: None,
            previous: Vec::new(),
            current: Vec::new(),
            records: Vec::new(),
        }
    }

    fn command(&self, g: &mut Gen, model: &RevModel) -> RevCmd {
        if !model.ready {
            return RevCmd::Setup {
                truth: Box::new(review_truth(machine_accounts())),
            };
        }
        let now = model
            .now
            .saturating_add(i64::try_from(g.weighted(&[1, 2])).unwrap_or(0));
        match g.weighted(&self.focus.weights) {
            0 => self.gen_assign(g, model, now),
            1 => self.gen_declare_assignment(g, model, now),
            2 => self.gen_declare_proposal(g, model, now),
            3 => self.gen_read(g, model, now),
            4 => self.gen_unassign(g, model, now),
            5 => self.gen_relation(g, model, now, true),
            6 => self.gen_relation(g, model, now, false),
            7 => self.gen_affiliate(g, now),
            8 => self.gen_withdraw(g, model, now),
            9 => self.gen_grant(g, model, now),
            _ => self.gen_end(g, model, now),
        }
    }

    fn precondition(&self, model: &RevModel, cmd: &RevCmd) -> bool {
        match cmd {
            RevCmd::Setup { .. } => !model.ready,
            RevCmd::Core { now, .. } | RevCmd::Vault { now, .. } => {
                model.ready && *now >= model.now
            }
        }
    }

    fn run(&self, sut: &mut RevSut, cmd: &RevCmd) -> RevOutput {
        self.last.borrow_mut().clear();
        let sod_before = sod::View::of(sut.records.iter()).unwrap_or_default();
        let rev_before = RevView::of(sut.records.iter()).unwrap_or_default();
        let mut out = RevOutput {
            context: String::new(),
            verdict: Verdict::Unjudged,
            result: Err(ExecError::Refused(Refusal::not_implemented())),
            appended: Vec::new(),
            sod: sod::View::new(),
            rev: RevView::new(),
            truth: GroundTruth::new(),
            now: T0,
        };
        match cmd {
            RevCmd::Setup { truth } => {
                out.context = "setup".to_owned();
                out.verdict = Verdict::Accept;
                out.result = run_setup(sut, truth, self.backend);
            }
            RevCmd::Core { now, step } => {
                let Some(driver) = sut.driver.as_mut() else {
                    out.context = "no driver".to_owned();
                    return out;
                };
                let at = Timestamp::from_micros(*now);
                out.now = at;
                out.context = format!("{:?} by {:?}", step.cmd, step.actor);
                out.verdict = verdict(
                    &sod_before,
                    &rev_before,
                    driver.truth(),
                    driver.truth(),
                    &step.ask(at),
                );
                out.result = driver.execute(step, at);
            }
            RevCmd::Vault { now, op } => {
                let Some(driver) = sut.driver.as_mut() else {
                    out.context = "no driver".to_owned();
                    return out;
                };
                out.now = Timestamp::from_micros(*now);
                out.context = format!("vault change {op:?}");
                out.verdict = Verdict::Accept;
                out.result = driver.change_vault(*op, out.now);
            }
        }
        if let Some(d) = &sut.driver {
            out.truth = d.truth().clone();
        }
        out.sod = sod_before;
        out.rev = rev_before;
        out.appended = sut.advance();
        self.last.borrow_mut().clone_from(&out.appended);
        out
    }

    fn postcondition(
        &self,
        _model: &RevModel,
        cmd: &RevCmd,
        out: &RevOutput,
    ) -> Result<(), String> {
        let context = &out.context;
        let step = match cmd {
            RevCmd::Setup { .. } => {
                return match &out.result {
                    Ok(_) => Ok(()),
                    Err(e) => Err(format!("the setup from genesis failed: {e:?}")),
                };
            }
            RevCmd::Vault { .. } => {
                if let Err(e) = &out.result {
                    return Err(format!(
                        "{context}: the reaction must be accepted, the driver returned {e:?}"
                    ));
                }
                let voids = sod::expected_voids(&out.sod, &out.truth);
                sod::check_voids(context, &voids, &out.appended)?;
                return check_reaction(
                    context,
                    &out.sod,
                    &out.rev,
                    &out.truth,
                    &|_, _| true,
                    &out.appended,
                    out.now,
                );
            }
            RevCmd::Core { step, .. } => step,
        };
        match &out.verdict {
            Verdict::Accept => two_way_exec(context, true, &out.result)?,
            Verdict::Refuse(why) => {
                two_way_exec(&format!("{context} (reference: {why})"), false, &out.result)?
            }
            Verdict::Unjudged => {}
        }
        if out.result.is_err() {
            return Ok(());
        }
        let ask = step.ask(out.now);
        if out.verdict.accepts() {
            if let Some(e) = expected(&out.sod, &out.rev, &out.truth, &ask, out.rev.epoch) {
                check_expected(context, &out.rev, &e, &out.appended)?;
            }
            if let Some(e) = sod::expected_binding(&out.sod, &ask) {
                sod::check_granted(context, &e, &out.appended)?;
            }
            if let Command::EndRole { binding, at } = &step.cmd {
                sod::check_ended(context, &out.sod, *binding, *at, &out.appended)?;
            }
        }
        for r in &out.appended {
            if let Record::ContentRead(c) = r
                && !receiving_holder(&out.sod, c.account, c.proposal)
                && out
                    .truth
                    .has_conflict(c.account, &team_of(&out.sod, c.proposal))
            {
                return Err(format!(
                    "I-03: {context}: {:?} read {:?} while the vault finds a conflict",
                    c.account, c.proposal
                ));
            }
            if let Record::Assigned(a) = r {
                if a.kind == AssignmentKind::Reviewer {
                    check_i34_assign(&out.sod, &out.rev, a.proposal, a.reviewer, out.now)?;
                }
                let programme = out.rev.programme_of(a.proposal);
                let org = programme.and_then(|p| {
                    committee_organisation(&out.sod, &out.rev, a.reviewer, p, out.now)
                });
                if let (Some(p), Some(o)) = (programme, org)
                    && let Some(list) = out.rev.proximity_list(p, o)
                    && out
                        .truth
                        .declares_on_list(&team_of(&out.sod, a.proposal), list)
                {
                    return Err(format!(
                        "I-35: {context}: {:?} assigned to {:?}, whose team declares an affiliation on the list of {o:?}",
                        a.reviewer, a.proposal
                    ));
                }
            }
        }
        Ok(())
    }

    fn next_state(&self, model: &mut RevModel, cmd: &RevCmd) {
        let records = self.last.borrow().clone();
        match cmd {
            RevCmd::Setup { truth } => {
                model.ready = true;
                model.truth = (**truth).clone();
            }
            RevCmd::Core { now, .. } => model.now = *now,
            RevCmd::Vault { now, op } => {
                model.now = *now;
                op.apply(&mut model.truth);
            }
        }
        for r in &records {
            // A record the references cannot follow fails the invariant,
            // which re-folds the whole ledger.
            let _ = model.sod.fold(r);
            let _ = model.rev.fold(r);
        }
        model.next_id = model.next_id.saturating_add(1);
    }

    fn invariant(&self, _model: &RevModel, sut: &RevSut) -> Result<(), String> {
        let Some(driver) = sut.driver.as_ref() else {
            return Ok(());
        };
        if let RevDriver::Engine(scenario) = driver {
            ledger_step(&sut.previous, &sut.current, scenario.state())?;
        }
        let view = sod::View::of(sut.records.iter())
            .map_err(|e| format!("the roles reference cannot follow the ledger: {e}"))?;
        let rev = RevView::of(sut.records.iter())
            .map_err(|e| format!("the review reference cannot follow the ledger: {e}"))?;
        check_i03(&rev)?;
        check_rcf02(&view, &rev)?;
        check_handles(&rev)?;
        check_i02_assignments(&view, &rev)?;
        sod::check_i02(&view)?;
        check_i36_held(&view, &rev)?;
        check_i36(&rev)
    }

    fn max_commands(&self) -> usize {
        self.focus.max_commands
    }
}

/// Builds the driver of the machine from genesis over `truth`.
fn run_setup(sut: &mut RevSut, truth: &GroundTruth, backend: Backend) -> Result<Seq, ExecError> {
    let failed = Err(ExecError::Refused(Refusal::not_implemented()));
    let mut driver = match backend {
        Backend::Production => match Scenario::new(truth.clone()) {
            Ok(s) => RevDriver::Engine(Box::new(s)),
            Err(_) => return failed,
        },
        Backend::Reference => RevDriver::Reference(
            Box::new(ReviewWorld {
                sod: SodWorld::new(Backend::Reference, truth.clone()),
                view: RevView::new(),
                havoc: None,
            }),
            Vec::new(),
        ),
    };
    let Ok(steps) = machine_setup().steps() else {
        return failed;
    };
    let mut last = failed;
    for step in steps {
        last = driver.execute(&step, T0);
        if last.is_err() {
            break;
        }
    }
    sut.driver = Some(driver);
    last
}

// ---------------------------------------------------------------------------
// Scenario helpers for the example tests
// ---------------------------------------------------------------------------

/// Runs `step` at `now` on `s`, with the step's attestations.
pub fn run_on(s: &mut Scenario, step: &Step, now: Timestamp) -> Result<Seq, ExecError> {
    let mut ctx = s.ctx(now, step.actor);
    ctx.tenant_admin = step.flags.tenant_admin;
    ctx.second_tenant_admin = step.flags.second_admin;
    ctx.binds_tenant_admin = step.flags.binds_tenant_admin;
    s.execute(fstp_engine::Command::Core(step.cmd.clone()), ctx)
}

/// Every core record of `s`, in ledger order.
pub fn records_of(s: &Scenario) -> Result<Vec<Record>, String> {
    s.entries()
        .map(|e| core_records(&e))
        .map_err(|e| format!("store read: {e:?}"))
}

/// Runs `step` at `now` on `s` and returns the core records it appended,
/// or the refusal. Any other driver error is a harness failure.
pub fn run_records(s: &mut Scenario, step: &Step, now: Timestamp) -> StepResult {
    let before = records_of(s)?.len();
    match run_on(s, step, now) {
        Ok(_) => Ok(Ok(records_of(s)?
            .get(before..)
            .unwrap_or_default()
            .to_vec())),
        Err(ExecError::Refused(r)) => Ok(Err(r)),
        Err(e) => Err(format!(
            "{:?}: the driver failed with {e:?}",
            step.cmd.kind()
        )),
    }
}

/// A scenario from genesis through `setup` over `truth`, every step at `T0`.
/// Every step must be accepted.
pub fn scenario_from(setup: &ReviewSetup, truth: GroundTruth) -> Result<Scenario, String> {
    let mut s = Scenario::new(truth).map_err(|e| format!("open: {e:?}"))?;
    for step in setup.steps()? {
        if let Err(r) = run_records(&mut s, &step, T0)? {
            return Err(format!("setup step {:?} refused: {r}", step.cmd.kind()));
        }
    }
    Ok(s)
}

// ---------------------------------------------------------------------------
// I-36: former reviewers and later calls
// ---------------------------------------------------------------------------

/// The call of the second programme [`P2`] in the I-36 setup.
pub const I36_OTHER_CALL: CallId = call(11);

/// The calls the I-36 property drafts in: the three calls of [`P1`] and
/// the call of [`P2`]. SoD-05 bars call 1 to every former committee
/// member, so the I-36 cases sit in calls 2, 3 and 11.
pub const I36_TARGET_CALLS: [CallId; 4] = [call(1), call(2), call(3), I36_OTHER_CALL];

/// The committee members of the I-36 setup. Their bindings end before
/// the later calls are published.
pub const I36_REVIEWERS: [AccountId; 4] = [R1, R2, R3, R4];

/// The proposals of the I-36 setup, all submitted in call 1.
pub const I36_PROPOSALS: [ProposalId; 3] = [PR1, PR2, PR3];

/// The former judges of the I-36 setup: the committee members and the IRC
/// member. Every binding of theirs ends before the later calls are published.
pub const I36_FORMER_JUDGES: [AccountId; 5] = [R1, R2, R3, R4, IRC];

/// The accounts the I-36 property drafts with: the former judges and two
/// accounts that never review.
pub const I36_APPLICANTS: [AccountId; 7] = [R1, R2, R3, R4, IRC, L4, STRANGER];

/// Steps per case of the I-36 property, after the setup.
pub const I36_MAX_STEPS: usize = 24;

/// The lifecycle rows the I-36 property folds, from the transitions table.
/// `Withdraw` is left out, since the property runs the command instead.
pub const I36_ROWS: [(StateTag, StateTag, Row); 19] = [
    (
        StateTag::Submitted,
        StateTag::Ineligible,
        Row::SubmittedToIneligible,
    ),
    (
        StateTag::Submitted,
        StateTag::Stage1,
        Row::SubmittedToStage1,
    ),
    (
        StateTag::Stage1,
        StateTag::NotSelected,
        Row::Stage1ToNotSelected,
    ),
    (StateTag::Stage1, StateTag::Stage2, Row::Stage1ToStage2),
    (StateTag::Stage2, StateTag::Ranked, Row::Stage2ToRanked),
    (StateTag::Stage2, StateTag::Deferred, Row::Stage2ToDeferred),
    (
        StateTag::Ranked,
        StateTag::NotSelected,
        Row::RankedToNotSelected,
    ),
    (
        StateTag::Ranked,
        StateTag::IrcReview,
        Row::RankedToIrcReview,
    ),
    (
        StateTag::IrcReview,
        StateTag::Negotiation,
        Row::IrcReviewToNegotiation,
    ),
    (
        StateTag::IrcReview,
        StateTag::Deferred,
        Row::IrcReviewToDeferred,
    ),
    (
        StateTag::IrcReview,
        StateTag::Declined,
        Row::IrcReviewToDeclined,
    ),
    (StateTag::Deferred, StateTag::Stage2, Row::DeferredToStage2),
    (
        StateTag::Deferred,
        StateTag::IrcReview,
        Row::DeferredToIrcReview,
    ),
    (
        StateTag::Negotiation,
        StateTag::Granted,
        Row::NegotiationToGranted,
    ),
    (
        StateTag::Negotiation,
        StateTag::Declined,
        Row::NegotiationToDeclined,
    ),
    (
        StateTag::Granted,
        StateTag::InExecution,
        Row::GrantedToInExecution,
    ),
    (
        StateTag::Granted,
        StateTag::Terminated,
        Row::GrantedToTerminated,
    ),
    (
        StateTag::InExecution,
        StateTag::Completed,
        Row::InExecutionToCompleted,
    ),
    (
        StateTag::InExecution,
        StateTag::Terminated,
        Row::InExecutionToTerminated,
    ),
];

/// The setup of the I-36 tests.
///
/// Programmes [`P1`] and [`P2`] have P-12 = 0, so SoD-05 alone lets a
/// former committee member apply to every call published after its
/// binding ended. Calls 1 to 3 of P1 and [`I36_OTHER_CALL`] of P2 are
/// drafted and approved, and call 1 is published. The Judging bindings
/// are those of [`machine_judges`], all in P1. PR1 to PR3 are submitted
/// in call 1 by L1 to L3.
pub fn i36_setup() -> ReviewSetup {
    let mut base = SodSetup::one(0, &[1, 2, 3]);
    base.programmes.push(P2);
    base.calls.push((P2, I36_OTHER_CALL));
    base.published = vec![call(1)];
    let drafts = [(L1, PR1), (L2, PR2), (L3, PR3)]
        .into_iter()
        .map(|(lead, proposal)| DraftSpec {
            lead,
            proposal,
            call: call(1),
            team: Vec::new(),
            minor: false,
            submit: true,
        })
        .collect();
    ReviewSetup {
        base,
        p38: BTreeMap::new(),
        p10: ReadAccess::AssignedReviewersOnly,
        judges: machine_judges(),
        drafts,
    }
}

/// The assignment id of the `n`-th review of [`i36_world`].
pub fn i36_assignment(n: usize) -> AssignmentId {
    AssignmentId::from_raw(8_000u128.saturating_add(u128::try_from(n).unwrap_or(0)))
}

/// The rows that bring a SUBMITTED proposal to IRC_REVIEW, where IRC
/// assignments open.
pub const I36_TO_IRC_REVIEW: [(StateTag, StateTag, Row); 4] = [
    (
        StateTag::Submitted,
        StateTag::Stage1,
        Row::SubmittedToStage1,
    ),
    (StateTag::Stage1, StateTag::Stage2, Row::Stage1ToStage2),
    (StateTag::Stage2, StateTag::Ranked, Row::Stage2ToRanked),
    (
        StateTag::Ranked,
        StateTag::IrcReview,
        Row::RankedToIrcReview,
    ),
];

/// A world after [`i36_setup`], then the assignments `reviews`, then the
/// end of every committee member binding and of the IRC binding, then the
/// publication of calls 2, 3 and [`I36_OTHER_CALL`].
///
/// A pair with [`IRC`] is an IRC assignment, and every other pair is a
/// reviewer assignment. The reviewer assignments come first. An IRC
/// assignment then folds its proposal from SUBMITTED to IRC_REVIEW with
/// [`I36_TO_IRC_REVIEW`], since only IRC_REVIEW opens it. An assignment
/// that the backend refuses, such as one that I-34 bars, is no review and
/// is skipped. The ends release the assignments, which stay reviews for
/// I-36.
pub fn i36_world(
    backend: Backend,
    reviews: &[(AccountId, ProposalId)],
) -> Result<ReviewWorld, String> {
    let setup = i36_setup();
    let mut w = ReviewWorld::from_setup(backend, review_truth(machine_accounts()), &setup, None)?;
    let (irc, committee): (Vec<_>, Vec<_>) = reviews
        .iter()
        .enumerate()
        .partition(|(_, (r, _))| *r == IRC);
    for (n, (reviewer, proposal)) in committee.into_iter().chain(irc) {
        let kind = if *reviewer == IRC {
            let submitted = w
                .view
                .proposals
                .get(proposal)
                .is_some_and(|l| l.state == StateTag::Submitted);
            if submitted {
                i36_fold_path(&mut w, *proposal, &I36_TO_IRC_REVIEW)?;
            }
            AssignmentKind::Irc
        } else {
            AssignmentKind::Reviewer
        };
        let id = i36_assignment(n);
        let step = assign(
            COORDINATOR,
            id,
            *proposal,
            *reviewer,
            kind,
            Some(handle(id.raw())),
        );
        // A refusal leaves the world unchanged, and the pair is no review.
        let _refused = w.exec(&step)?;
    }
    // Judges 1 to 4 are the committee members, and judge 5 is the IRC member.
    let mut fixed: Vec<Step> = (1..=5).map(|i| end(judge_binding(i), T0)).collect();
    fixed.extend([call(2), call(3), I36_OTHER_CALL].map(crate::r#gen::roster::publish));
    for step in fixed {
        if let Err(r) = w.exec(&step)? {
            return Err(format!(
                "I-36 setup step {:?} refused: {r}",
                step.cmd.kind()
            ));
        }
    }
    Ok(w)
}

/// Folds the lifecycle row `from` to `to` of `proposal` through the public
/// structural fold, as the teeth helpers do, since lane L-LIFE does not
/// record these rows yet. A row that leaves DEFERRED also folds the
/// `ReEntered` record into the next published call first.
///
/// Returns whether the row was folded. It is not when the proposal is not
/// in `from`, when no next call exists, or when the production fold does
/// not take `ReEntered` yet.
pub fn i36_advance(
    w: &mut ReviewWorld,
    proposal: ProposalId,
    from: StateTag,
    to: StateTag,
    row: Row,
) -> Result<bool, String> {
    let Some(life) = w.view.proposals.get(&proposal) else {
        return Ok(false);
    };
    if life.state != from {
        return Ok(false);
    }
    let stage = match row {
        Row::DeferredToStage2 => Some(ReentryStage::Stage2),
        Row::DeferredToIrcReview => Some(ReentryStage::IrcReview),
        _ => None,
    };
    let mut records = Vec::new();
    if let Some(stage) = stage {
        let Some(next) = w.view.next_call(life.current_call) else {
            return Ok(false);
        };
        records.push(Record::ReEntered {
            proposal,
            from_call: life.current_call,
            to_call: next,
            stage,
        });
    }
    records.push(Record::Transitioned(Transitioned {
        proposal,
        from,
        to,
        row,
        actor: Actor::System(SystemCause::Timeline),
        decision: None,
    }));
    match w.commit(&records) {
        Ok(()) => Ok(true),
        // Until lane L-LIFE lands, production refuses to fold `ReEntered`.
        Err(_) if stage.is_some() => Ok(false),
        Err(e) => Err(e),
    }
}

/// Folds `rows` of `proposal` in order with [`i36_advance`]. Every row must fold.
pub fn i36_fold_path(
    w: &mut ReviewWorld,
    proposal: ProposalId,
    rows: &[(StateTag, StateTag, Row)],
) -> Result<(), String> {
    for (from, to, row) in rows {
        if !i36_advance(w, proposal, *from, *to, *row)? {
            return Err(format!("{proposal:?}: the row {row:?} did not fold"));
        }
    }
    Ok(())
}

/// The account and call of the Receiving binding that `step` asks for,
/// read from the review view. `None` for every other command.
pub fn i36_target(rev: &RevView, step: &Step) -> Option<(AccountId, CallId)> {
    match &step.cmd {
        Command::CreateDraft { call, .. } => match step.actor {
            Actor::Account(a) => Some((a, *call)),
            Actor::System(_) => None,
        },
        Command::AddTeamMember {
            proposal, account, ..
        }
        | Command::AddGuardian {
            proposal, account, ..
        } => rev.proposals.get(proposal).map(|l| (*account, l.call)),
        _ => None,
    }
}

/// The faulty engine of the I-36 teeth tests: the references with the
/// check that I-36 had before the decision of 2026-10-25. It refuses a
/// former reviewer only in a call where a proposal it reviewed is under
/// evaluation now, and grants everything else that the other rules allow.
/// It runs on [`Backend::Reference`] only.
pub fn i36_exec_current_call_only(w: &mut ReviewWorld, step: &Step) -> StepResult {
    if w.sod.backend != Backend::Reference {
        return Err("the faulty I-36 engine runs on the references only".to_owned());
    }
    if let Err(r) = w.sync()? {
        return Ok(Err(r));
    }
    let narrow_allows =
        i36_target(&w.view, step).is_some_and(|(a, c)| !w.view.i36_bars_current_call_only(a, c));
    if !narrow_allows {
        return w.exec(step);
    }
    // The faulty engine forgets every review beyond the current-call check.
    let mut blind = w.clone();
    blind.view.reviewed.clear();
    let result = blind.exec(step)?;
    if let Ok(records) = &result {
        w.commit(records)?;
    }
    Ok(result)
}

/// Runs one command of the I-36 property on `w` and checks it.
///
/// The I-36 check of the grants comes first, so a counterexample names
/// I-36. Then the outcome is compared with the reference verdict in both
/// directions. A refusal that the reference gives for I-36 alone must
/// carry `RuleRef::I36` in production. `faulty` runs the step on
/// [`i36_exec_current_call_only`].
pub fn i36_core(w: &mut ReviewWorld, step: &Step, faulty: bool) -> Result<(), String> {
    let context = format!("{:?} by {:?}", step.cmd, step.actor);
    let before = w.view.clone();
    let v = w.verdict(step);
    let result = if faulty {
        i36_exec_current_call_only(w, step)?
    } else {
        w.exec(step)?
    };
    match (result, &v) {
        (Ok(records), _) => {
            check_i36_grants(&before, &records).map_err(|e| format!("{e} ({context})"))?;
            if let Verdict::Refuse(why) = &v {
                return Err(format!(
                    "{context}: over-permission, the reference refuses ({why}), the engine accepts"
                ));
            }
            Ok(())
        }
        (Err(r), Verdict::Accept) => Err(format!(
            "{context}: over-denial, the reference accepts, the engine refuses with {r}"
        )),
        (Err(r), Verdict::Refuse(why))
            if why == "I-36" && w.sod.backend == Backend::Production && r.rule != RuleRef::I36 =>
        {
            Err(format!(
                "I-36: {context}: refused with {r}, but the refusal must name RuleRef::I36"
            ))
        }
        (Err(_), _) => Ok(()),
    }
}

/// One step of the I-36 property.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum I36Act {
    /// Folds a lifecycle row of a proposal with [`i36_advance`].
    Advance {
        /// The proposal.
        proposal: ProposalId,
        /// The state left.
        from: StateTag,
        /// The state reached.
        to: StateTag,
        /// The row.
        row: Row,
    },
    /// A core command, run with [`i36_core`].
    Core(Box<Step>),
}

/// Draws one step of the I-36 property over `w`. `next` is a fresh id for
/// a new proposal or binding.
pub fn i36_act(g: &mut Gen, w: &ReviewWorld, next: u128) -> I36Act {
    let drafts: Vec<(ProposalId, AccountId)> = w
        .view
        .proposals
        .iter()
        .filter(|(p, l)| !I36_PROPOSALS.contains(p) && l.state == StateTag::Draft)
        .map(|(p, l)| (*p, l.lead))
        .collect();
    match g.weighted(&[6, 5, 2, 1]) {
        0 => {
            let proposal = *g.pick(&I36_PROPOSALS);
            let state = w.view.proposals.get(&proposal).map(|l| l.state);
            let rows: Vec<(StateTag, StateTag, Row)> = I36_ROWS
                .iter()
                .filter(|(from, _, _)| Some(*from) == state)
                .copied()
                .collect();
            if rows.is_empty() {
                return i36_draw_draft(g, next);
            }
            let (from, to, row) = *g.pick(&rows);
            I36Act::Advance {
                proposal,
                from,
                to,
                row,
            }
        }
        1 => i36_draw_draft(g, next),
        2 if !drafts.is_empty() => {
            let (proposal, lead) = *g.pick(&drafts);
            let account = *g.pick(&I36_FORMER_JUDGES);
            let guardian = g.weighted(&[3, 1]) == 1;
            I36Act::Core(Box::new(add_member(
                lead,
                proposal,
                account,
                BindingId::from_raw(next),
                guardian,
            )))
        }
        2 => i36_draw_draft(g, next),
        _ => {
            let proposal = *g.pick(&I36_PROPOSALS);
            let lead = w.view.proposals.get(&proposal).map_or(L1, |l| l.lead);
            I36Act::Core(Box::new(withdraw(lead, proposal)))
        }
    }
}

/// Draws a draft by an account of [`I36_APPLICANTS`]. One draft in three
/// is a minor's, so that `AddGuardian` on it reaches the I-36 bar.
fn i36_draw_draft(g: &mut Gen, next: u128) -> I36Act {
    let account = *g.pick(&I36_APPLICANTS);
    let target = I36_TARGET_CALLS
        .get(g.weighted(&[1, 4, 3, 2]))
        .copied()
        .unwrap_or(I36_OTHER_CALL);
    let minor = g.weighted(&[2, 1]) == 1;
    I36Act::Core(Box::new(draft(
        account,
        ProposalId::from_raw(next),
        target,
        BindingId::from_raw(next),
        minor,
    )))
}

/// The I-36 property (decided 2026-10-25, test plan row I-36).
///
/// It draws reviews of PR1 to PR3 by the committee members, always with
/// R1 on PR1. In half the cases, the IRC member also reviews one of them.
/// It then builds [`i36_world`] on `backend`. It then runs up to
/// [`I36_MAX_STEPS`] steps: lifecycle rows of the reviewed proposals,
/// withdrawals, drafts and team roles in calls 1 to 3 and the call of the
/// other programme. Each command is checked with [`i36_core`]. After every
/// step, [`check_i36_held`] and [`check_i36`] must hold. `faulty` runs the
/// commands on [`i36_exec_current_call_only`] instead, for the teeth.
pub fn i36_property(g: &mut Gen, backend: Backend, faulty: bool) -> Result<(), String> {
    let mut reviews = vec![(R1, PR1)];
    for r in I36_REVIEWERS {
        for p in I36_PROPOSALS {
            if (r, p) != (R1, PR1) && g.weighted(&[2, 1]) == 1 {
                reviews.push((r, p));
            }
        }
    }
    if g.weighted(&[1, 1]) == 1 {
        reviews.push((IRC, *g.pick(&I36_PROPOSALS)));
    }
    g.note("reviews", &reviews);
    let mut w = i36_world(backend, &reviews)?;
    let steps = g.usize_in(1..=I36_MAX_STEPS);
    let mut next: u128 = 7_000;
    for _ in 0..steps {
        next = next.saturating_add(1);
        let act = i36_act(g, &w, next);
        g.note("step", &act);
        match &act {
            I36Act::Advance {
                proposal,
                from,
                to,
                row,
            } => {
                i36_advance(&mut w, *proposal, *from, *to, *row)?;
            }
            I36Act::Core(step) => i36_core(&mut w, step, faulty)?,
        }
        check_i36_held(&w.sod.view, &w.view)?;
        check_i36(&w.view)?;
    }
    Ok(())
}
