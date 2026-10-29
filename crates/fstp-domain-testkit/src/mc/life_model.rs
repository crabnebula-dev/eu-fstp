//! The life models for fstp-mc: the world driver, M-LIFE-S1 and M-LIFE-S2, their properties and faults (design sections 6.2 and 6.3).
//!
//! Owned by lane L-LIFE (docs/handoff/m2-design.md section 10).
//!
//! - [`LifeWorld`] is the model driver. It wraps the L-REV world, which
//!   runs production `queries`, `decide` and `apply` without a store, and
//!   adds the lifecycle reference view. [`LifeWorld::step`] compares each
//!   command with the references in both directions and checks the
//!   records an accepted lifecycle command must hold. Its
//!   [`Backend::Reference`] mode runs the same steps on the references
//!   alone, which checks the models before production lands.
//! - [`LifeSetup`] builds start states from genesis by production
//!   commands: the programme with its P-01, P-02, P-03, P-07 and P-15
//!   values, calls, Judging bindings and a proposal, then intake, stage 1
//!   or stage 2 as [`Start`] asks.
//! - [`LifeModel`] is one model over one proposal. [`Phases`] selects the
//!   actions an instance offers. [`s1_config`] is M-LIFE-S1, [`s2_config`]
//!   is M-LIFE-S2, and `lifecycle_model` builds M-LIFECYCLE on the same model.
//! - The property builders read only the reference views, the ghost in
//!   them and the vault facts, never production structures.
//! - The faults inject records a broken engine would emit through the
//!   public structural `apply` (design 6.1 "Teeth").
//!
//! Reduced clock (design 6.1): [`LifeAction::Tick`] moves `now` to the next
//! instant of the current stage 2 window: one microsecond before its close,
//! then its close. Later instants give the same guard outcomes as the close.
//! No other lifecycle guard compares times, because every call opens
//! before the evaluation starts.

use std::collections::BTreeSet;
use std::num::{NonZeroU8, NonZeroU16};

use fstp_domain::assignment::AssignmentKind;
use fstp_domain::command::{Actor, Command, DeclarationSubject, KnockOutResult, SystemCause};
use fstp_domain::decision::{Ballot, Basis, IrcVerdict, Vote};
use fstp_domain::id::{
    AccountId, AssignmentId, CallId, ContentDigest, CriterionId, DecisionId, KnockOutCriterionId,
    MilestoneId, OrganisationId, PlanVersionId, ProposalId,
};
use fstp_domain::policy::ReadAccess;
use fstp_domain::proposal::PlanOrigin;
use fstp_domain::record::{Record, Transitioned};
use fstp_domain::roles::Role;
use fstp_domain::rules::{Row, StateTag};
use fstp_domain::scoring::{Criteria, Criterion, ScoreKey, ScoreVector, Stage};
use fstp_domain::time::{Days, Timestamp};
use fstp_findings::Finding;
use fstp_mc::{Model, Property};
use fstp_money::Percent;

use crate::clock::ReducedClock;
use crate::r#gen::policy::text;
use crate::r#gen::review::{
    COORDINATOR, DraftSpec, IRC, L1, O1, O2, O3, PR1, R1, R2, R3, ReviewSetup, ReviewWorld, assign,
    attest_adult_leads, declare, handle, judged, milestone, plan_of, review_truth, submit, tag,
    withdraw,
};
use crate::r#gen::roster::{Backend, Flags, STAFF_PM, SodSetup, SodWorld, Step, call, publish};
use crate::mc::findings_model::FindingSide;
use crate::reference::lifecycle::{
    Effective, Frac, LifeAsk, LifeCx, LifeVerdict, LifeView, check_batch, check_i07, check_i08,
    check_i09, check_recorded_by_human, check_sealed, forge_effective, forge_stage1_closed,
    life_verdict, synthesize,
};
use crate::reference::review::RevView;
use crate::vault::{GroundTruth, Relation};

// ---------------------------------------------------------------------------
// Accounts, ids and instants
// ---------------------------------------------------------------------------

/// The second IRC member, so that P-15 = 2 can be met.
pub const IRC2: AccountId = AccountId::from_raw(222);
/// The committee chair.
pub const CHAIR: AccountId = AccountId::from_raw(241);
/// A fourth committee member, of organisation [`O3`].
pub const R5: AccountId = AccountId::from_raw(215);

/// The instant the evaluation starts: one second after every call deadline.
pub const T_EVAL: Timestamp = Timestamp::from_micros(4_000_001_000_000);

/// The id of the assignment of `reviewer` of `kind` to `proposal` in `call`.
pub fn assignment_of(
    reviewer: AccountId,
    proposal: ProposalId,
    call: CallId,
    kind: AssignmentKind,
) -> AssignmentId {
    let k = u128::from(kind != AssignmentKind::Reviewer);
    AssignmentId::from_raw(
        80_000_000u128
            .saturating_add(proposal.raw().saturating_mul(100_000))
            .saturating_add(reviewer.raw().saturating_mul(100))
            .saturating_add(call.raw().saturating_mul(10))
            .saturating_add(k),
    )
}

/// The id of the `n`-th stage 2 revision of `proposal`.
pub fn revision_of(proposal: ProposalId, n: usize) -> PlanVersionId {
    let n = u128::try_from(n).unwrap_or(0);
    PlanVersionId::from_raw(proposal.raw().saturating_add(500).saturating_add(n))
}

/// The milestone id of the `n`-th stage 2 revision of `proposal`.
pub fn revision_milestone(proposal: ProposalId, n: usize) -> MilestoneId {
    let n = u128::try_from(n).unwrap_or(0);
    MilestoneId::from_raw(proposal.raw().saturating_add(700).saturating_add(n))
}

/// The knock-out decision of `proposal`.
pub fn knock_out_decision(proposal: ProposalId) -> DecisionId {
    DecisionId::from_raw(proposal.raw().saturating_add(9_100))
}

/// The admission decision of `proposal`.
pub fn admit_decision(proposal: ProposalId) -> DecisionId {
    DecisionId::from_raw(proposal.raw().saturating_add(9_200))
}

/// The `n`-th cut-off decision.
pub fn cut_off_decision(n: u128) -> DecisionId {
    DecisionId::from_raw(9_300u128.saturating_add(n))
}

// ---------------------------------------------------------------------------
// Steps
// ---------------------------------------------------------------------------

/// A command by `account` with no attestation.
pub fn by(account: AccountId, cmd: Command) -> Step {
    Step::by(account, Flags::NONE, cmd)
}

/// A System command from the timeline (NOTE 13).
pub fn system(cmd: Command) -> Step {
    Step {
        actor: Actor::System(SystemCause::Timeline),
        flags: Flags::NONE,
        cmd,
    }
}

/// The coordinator's knock-out check of `proposal`: every P-09 criterion
/// passed, or the first one failed with a reason.
pub fn knock_out(proposal: ProposalId, pass: bool) -> Step {
    let outcomes = (1u128..=3)
        .map(|c| KnockOutResult {
            criterion: KnockOutCriterionId::from_raw(c),
            passed: pass || c != 1,
        })
        .collect();
    by(
        COORDINATOR,
        Command::RecordKnockOut {
            decision: knock_out_decision(proposal),
            proposal,
            outcomes,
            reason: (!pass).then(|| text(proposal.raw().saturating_add(81_000))),
        },
    )
}

/// The coordinator's admission of `proposal` to stage 1.
pub fn admit(proposal: ProposalId) -> Step {
    by(
        COORDINATOR,
        Command::AdmitToStage1 {
            decision: admit_decision(proposal),
            proposal,
        },
    )
}

/// A `RecordScore` by `reviewer` on `key`.
pub fn score(reviewer: AccountId, key: ScoreKey, values: &[u8]) -> Step {
    by(
        reviewer,
        Command::RecordScore {
            key,
            values: ScoreVector(values.to_vec()),
        },
    )
}

/// A `CorrectScore` by `reviewer` on `key` with a synthetic reason.
pub fn correct(reviewer: AccountId, key: ScoreKey, values: &[u8]) -> Step {
    by(
        reviewer,
        Command::CorrectScore {
            key,
            values: ScoreVector(values.to_vec()),
            reason: text(82_000),
        },
    )
}

/// A `CloseStage1` of `proposal` by `actor`.
pub fn close(actor: Actor, proposal: ProposalId) -> Step {
    Step {
        actor,
        flags: Flags::NONE,
        cmd: Command::CloseStage1 { proposal },
    }
}

/// A stage 2 question by `reviewer` through `assignment`.
pub fn ask(reviewer: AccountId, proposal: ProposalId, assignment: AssignmentId) -> Step {
    by(
        reviewer,
        Command::AskQuestion {
            proposal,
            assignment,
            text: text(83_000),
        },
    )
}

/// A "no questions" record by `reviewer` through `assignment`.
pub fn no_questions(reviewer: AccountId, proposal: ProposalId, assignment: AssignmentId) -> Step {
    by(
        reviewer,
        Command::RecordNoQuestions {
            proposal,
            assignment,
        },
    )
}

/// The lead's answers.
pub fn answer(lead: AccountId, proposal: ProposalId) -> Step {
    by(
        lead,
        Command::AnswerQuestions {
            proposal,
            text: text(84_000),
        },
    )
}

/// The lead's stage 2 revision `plan`, superseding `supersedes`, with one
/// milestone of 1000.00 EUR.
pub fn revision_plan(
    lead: AccountId,
    proposal: ProposalId,
    plan: PlanVersionId,
    supersedes: Option<PlanVersionId>,
    milestone_id: MilestoneId,
) -> Result<Step, String> {
    let mut digest = [7u8; 32];
    let (head, _) = digest.split_at_mut(16);
    head.copy_from_slice(&plan.raw().to_be_bytes());
    Ok(by(
        lead,
        Command::RecordPlanVersion {
            plan,
            proposal,
            origin: PlanOrigin::Stage2Revision,
            supersedes,
            tasks: vec![fstp_domain::proposal::Task {
                milestones: vec![milestone(milestone_id)?],
            }],
            content: ContentDigest::from_bytes(digest),
        },
    ))
}

/// The lead's submission of the revision `plan`.
pub fn submit_revision(lead: AccountId, proposal: ProposalId, plan: PlanVersionId) -> Step {
    by(lead, Command::SubmitRevision { proposal, plan })
}

/// `RankAfterStage2` by `reviewer`.
pub fn rank(reviewer: AccountId, proposal: ProposalId) -> Step {
    by(reviewer, Command::RankAfterStage2 { proposal })
}

/// The System's `ExpireStage2`.
pub fn expire(proposal: ProposalId) -> Step {
    system(Command::ExpireStage2 { proposal })
}

/// The System's `ReEnter` into `into`.
pub fn reenter(proposal: ProposalId, into: CallId) -> Step {
    system(Command::ReEnter {
        proposal,
        call: into,
    })
}

/// Ballots for the cut-off: each of `voters` votes `vote` directly.
pub fn ballots(voters: &[AccountId], vote: Vote) -> Vec<Ballot> {
    voters
        .iter()
        .map(|v| Ballot {
            voter: *v,
            vote,
            delegated_by: None,
        })
        .collect()
}

/// A `RecordCutOff` by `recorder`.
pub fn cut_off(
    recorder: AccountId,
    decision: DecisionId,
    in_call: CallId,
    order: Vec<ProposalId>,
    nominated: u32,
    tie_break: bool,
    ballots: Vec<Ballot>,
) -> Step {
    by(
        recorder,
        Command::RecordCutOff {
            decision,
            call: in_call,
            order,
            nominated,
            rationale: text(85_000),
            tie_breaks: tie_break.then(|| text(85_001)),
            ballots,
        },
    )
}

/// An IRC review by `member` through `assignment`: a validation, or a concern.
pub fn irc_review(member: AccountId, assignment: AssignmentId, validate: bool) -> Step {
    let verdict = if validate {
        IrcVerdict::Validate
    } else {
        IrcVerdict::Concern(text(86_000))
    };
    by(
        member,
        Command::RecordIrcReview {
            assignment,
            verdict,
        },
    )
}

/// `DeclineAfterConcern` by `actor`.
pub fn decline(actor: Actor, proposal: ProposalId) -> Step {
    Step {
        actor,
        flags: Flags::NONE,
        cmd: Command::DeclineAfterConcern { proposal },
    }
}

/// The assignment of `reviewer` of `kind` in `in_call`, with its no-conflict declaration.
pub fn assign_declared(
    reviewer: AccountId,
    proposal: ProposalId,
    in_call: CallId,
    kind: AssignmentKind,
) -> Vec<Step> {
    let id = assignment_of(reviewer, proposal, in_call, kind);
    vec![
        assign(
            COORDINATOR,
            id,
            proposal,
            reviewer,
            kind,
            Some(handle(id.raw())),
        ),
        declare(reviewer, DeclarationSubject::Assignment(id), false, false),
    ]
}

// ---------------------------------------------------------------------------
// The world
// ---------------------------------------------------------------------------

/// A model world for the lifecycle: the L-REV world and the lifecycle view.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LifeWorld {
    /// Production, the vault, and the L-SOD and L-REV reference views.
    pub rev: ReviewWorld,
    /// The lifecycle reference view of every record committed.
    pub life: LifeView,
}

impl LifeWorld {
    /// A world at genesis over `truth`.
    pub fn new(backend: Backend, truth: GroundTruth) -> LifeWorld {
        LifeWorld {
            rev: ReviewWorld {
                sod: SodWorld::new(backend, truth),
                view: RevView::new(),
                havoc: None,
            },
            life: LifeView::new(),
        }
    }

    /// A world after `steps` from genesis. Every step must be accepted by
    /// production and the references alike.
    pub fn from_steps(
        backend: Backend,
        truth: GroundTruth,
        steps: &[Step],
    ) -> Result<LifeWorld, String> {
        let mut w = LifeWorld::new(backend, truth);
        for s in steps {
            w = w.must(s)?;
        }
        Ok(w)
    }

    /// The world after `step`, which must be accepted.
    pub fn must(&self, step: &Step) -> Result<LifeWorld, String> {
        match self.step(step)? {
            Some((w, _)) => Ok(w),
            None => Err(format!(
                "{:?} by {:?} was refused by production and the references",
                step.cmd.kind(),
                step.actor
            )),
        }
    }

    /// What decides the steps.
    pub fn backend(&self) -> Backend {
        self.rev.sod.backend
    }

    /// The instant of every command.
    pub fn now(&self) -> Timestamp {
        self.rev.sod.now
    }

    /// Moves `now` to `t`. Time never runs backwards.
    pub fn set_now(&mut self, t: Timestamp) {
        if t > self.rev.sod.now {
            self.rev.sod.now = t;
        }
    }

    /// The lifecycle verdict on `step` now.
    pub fn life_verdict(&self, step: &Step) -> LifeVerdict {
        let facts = self.rev.facts();
        let cx = LifeCx {
            sod: &self.rev.sod.view,
            rev: &self.rev.view,
            life: &self.life,
            facts: &facts,
        };
        life_verdict(
            &cx,
            &LifeAsk {
                actor: step.actor,
                now: self.now(),
                cmd: &step.cmd,
            },
        )
    }

    fn fold(&mut self, records: &[Record]) -> Result<(), String> {
        let now = self.now();
        for r in records {
            self.life
                .fold(r, now)
                .map_err(|e| format!("the lifecycle reference cannot follow {r:?}: {e}"))?;
        }
        Ok(())
    }

    /// Processes a newer vault epoch and folds its records. A refusal of
    /// the reaction is an error, since every reaction must be accepted.
    pub fn sync(&mut self) -> Result<Vec<Record>, String> {
        match self.rev.sync()? {
            Ok(records) => {
                self.fold(&records)?;
                Ok(records)
            }
            Err(r) => Err(format!("the vault reaction was refused: {r}")),
        }
    }

    /// Runs `step` after any pending vault reaction and compares it with
    /// the references in both directions. `Ok(Some)` is the world after an
    /// accepted step with its records, `Ok(None)` a step both refuse, and
    /// `Err` a divergence or a harness failure.
    ///
    /// After every accepted step, the effective score in the production
    /// projection must equal the last one the reference folded, for every
    /// proposal (I-09). Later lanes read the projection, so a production
    /// fold that clears or changes it is a divergence even when the
    /// records agree.
    pub fn step(&self, step: &Step) -> Result<Option<(LifeWorld, Vec<Record>)>, String> {
        let out = self.step_unchecked(step)?;
        if let Some((w, _)) = &out {
            w.effective_agrees()
                .map_err(|e| format!("{:?} by {:?}: {e}", step.cmd, step.actor))?;
        }
        Ok(out)
    }

    /// I-09 on the production projection: for every proposal, the
    /// effective score that `fstp_domain::decision::effective_score` reads
    /// names the plan, value and basis of the reference's last recorded
    /// one, and exists exactly when the reference has one. On the
    /// references alone production keeps no projection, so nothing is
    /// compared there.
    pub fn effective_agrees(&self) -> Result<(), String> {
        if self.backend() == Backend::Reference {
            return Ok(());
        }
        for (id, p) in &self.life.proposals {
            let prod = fstp_domain::decision::effective_score(&self.rev.sod.state, *id)
                .map(|e| (e.plan(), Frac::of_ratio(e.value()), e.basis()));
            let refr = p.effective.last().map(|e| (e.plan, e.value, e.basis));
            let same = match (prod, refr) {
                (None, None) => true,
                (Some((pp, pv, pb)), Some((rp, rv, rb))) => pp == rp && pb == rb && pv.same(rv),
                _ => false,
            };
            if !same {
                return Err(format!(
                    "I-09: the production projection holds the effective score {prod:?} \
                     for {id:?}, the reference recorded {refr:?}"
                ));
            }
        }
        Ok(())
    }

    fn step_unchecked(&self, step: &Step) -> Result<Option<(LifeWorld, Vec<Record>)>, String> {
        let mut w = self.clone();
        w.sync()?;
        let context = format!("{:?} by {:?}", step.cmd, step.actor);
        let verdict = w.life_verdict(step);
        if verdict == LifeVerdict::NotMine {
            return match judged(&w.rev, step) {
                None => Ok(None),
                Some(Err(e)) => Err(e),
                Some(Ok((rev, records))) => {
                    w.rev = rev;
                    w.fold(&records)?;
                    Ok(Some((w, records)))
                }
            };
        }
        let outcome: Result<Vec<Record>, String> = match w.backend() {
            Backend::Production => match w.rev.exec(step)? {
                Ok(r) => Ok(r),
                Err(r) => Err(r.to_string()),
            },
            Backend::Reference => match &verdict {
                LifeVerdict::Accept(e) | LifeVerdict::Either(e) => {
                    let records = synthesize(e, &w.rev.sod.view, w.now())?;
                    w.rev.commit(&records)?;
                    Ok(records)
                }
                LifeVerdict::Refuse(why) => Err(why.clone()),
                LifeVerdict::NotMine => Err("unreachable".to_owned()),
            },
        };
        match (verdict, outcome) {
            (LifeVerdict::Refuse(_) | LifeVerdict::Either(_), Err(_)) => Ok(None),
            (LifeVerdict::Accept(_), Err(r)) => Err(format!(
                "{context}: over-denial, the reference accepts, production refuses with {r}"
            )),
            (LifeVerdict::Refuse(why), Ok(records)) => Err(format!(
                "{context}: over-permission, the reference refuses ({why}), production accepts with {records:?}"
            )),
            (LifeVerdict::Accept(e) | LifeVerdict::Either(e), Ok(records)) => {
                check_batch(&context, &e, &records)?;
                w.fold(&records)?;
                Ok(Some((w, records)))
            }
            (LifeVerdict::NotMine, _) => Err("unreachable".to_owned()),
        }
    }

    /// Folds `records` that a broken engine would emit into production
    /// through the public structural `apply`, and into the views. Nothing
    /// changes when a fold refuses.
    pub fn inject(&self, records: &[Record]) -> Result<LifeWorld, String> {
        let mut w = self.clone();
        w.rev.commit(records)?;
        w.fold(records)?;
        Ok(w)
    }

    /// The assignment of `reviewer` of `kind` on `proposal` in its current
    /// call, or in its creation call for stage 1.
    pub fn assignment(
        &self,
        reviewer: AccountId,
        proposal: ProposalId,
        stage: Stage,
        kind: AssignmentKind,
    ) -> Option<AssignmentId> {
        let in_call = self.life.stage_call(proposal, stage)?;
        Some(assignment_of(reviewer, proposal, in_call, kind))
            .filter(|id| self.life.assignments.contains_key(id))
    }
}

// ---------------------------------------------------------------------------
// Setups from genesis
// ---------------------------------------------------------------------------

/// Where a model starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Start {
    /// The proposal in DRAFT, with its plan recorded.
    Draft,
    /// The proposal in STAGE1, with the reviewers assigned and declared.
    Stage1,
    /// The proposal in STAGE2 after the start scores.
    Stage2,
    /// The proposal in RANKED. On the revised plan, the lead submits a
    /// revision that every reviewer scores with the revision scores, and R1
    /// ranks it. On the original plan, every reviewer records "no questions".
    Ranked {
        /// Whether the revised plan carries forward.
        revised: bool,
    },
}

/// The parameters and population of one start state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LifeSetup {
    /// The P-01 scale maximum.
    pub scale_max: u8,
    /// The P-01 weights.
    pub weights: Vec<u16>,
    /// P-02 in basis points.
    pub p02_bp: u16,
    /// P-03.
    pub p03: u8,
    /// P-07 in days.
    pub p07_days: u16,
    /// P-15.
    pub p15: u8,
    /// The Judging bindings: account, role and organisation.
    pub judges: Vec<(AccountId, Role, Option<OrganisationId>)>,
    /// The proposals in call 1: lead, proposal and minor flag. The models act on the first, PR1.
    pub proposals: Vec<(AccountId, ProposalId, bool)>,
    /// The reviewers assigned in stage 1.
    pub reviewers: Vec<AccountId>,
    /// The stage 1 vectors of [`Start::Stage2`], one per reviewer.
    pub start_scores: Vec<Vec<u8>>,
    /// The stage 2 vectors of [`Start::Ranked`] on the revised plan, one per reviewer.
    pub revision_scores: Vec<Vec<u8>>,
    /// Where the model starts.
    pub start: Start,
}

/// The Judging bindings of the life models: the coordinator, three
/// committee members of three organisations and two IRC members.
pub fn life_judges() -> Vec<(AccountId, Role, Option<OrganisationId>)> {
    vec![
        (COORDINATOR, Role::FstpCoordinator, None),
        (R1, Role::CommitteeMember, Some(O1)),
        (R2, Role::CommitteeMember, Some(O2)),
        (R3, Role::CommitteeMember, Some(O3)),
        (IRC, Role::IrcMember, None),
        (IRC2, Role::IrcMember, None),
    ]
}

impl LifeSetup {
    /// The P-01 value of the setup.
    pub fn criteria(&self) -> Result<Criteria, String> {
        let scale = NonZeroU8::new(self.scale_max).ok_or("scale maximum zero")?;
        let mut items = Vec::new();
        for (i, w) in (1u128..).zip(&self.weights) {
            items.push(Criterion {
                id: CriterionId::from_raw(i),
                weight: NonZeroU16::new(*w).ok_or("weight zero")?,
            });
        }
        Criteria::new(scale, items).map_err(|e| format!("criteria: {e}"))
    }

    /// The review setup: one programme with P-12 = 0, calls 1 and 2 drafted
    /// and approved, call 1 published, the judges and the proposals in DRAFT in call 1.
    pub fn review(&self) -> ReviewSetup {
        let mut base = SodSetup::one(0, &[1, 2]);
        base.published = vec![call(1)];
        ReviewSetup {
            base,
            p38: std::collections::BTreeMap::new(),
            p10: ReadAccess::AssignedReviewersOnly,
            judges: self.judges.clone(),
            drafts: self
                .proposals
                .iter()
                .map(|(lead, proposal, minor)| DraftSpec {
                    lead: *lead,
                    proposal: *proposal,
                    call: call(1),
                    team: Vec::new(),
                    minor: *minor,
                    submit: false,
                })
                .collect(),
        }
    }

    /// Every account of the setup beside staff.
    pub fn accounts(&self) -> BTreeSet<AccountId> {
        self.review().accounts()
    }

    /// The vault of the setup: every account verified with its own identity,
    /// and every lead of a proposal not flagged as a minor's attested 18 or
    /// older from [`crate::r#gen::roster::LEAD_ADULT_FROM`] on.
    ///
    /// The minor bit of [`LifeSetup::proposals`] is the vault fact the
    /// lifecycle derives the flag from (R-ID-04, state-machine NOTE 14). It
    /// is also sent as the `CreateDraft` field, which no guard may read. A
    /// test that separates the two changes the truth, for example through
    /// [`Story::new`].
    pub fn truth(&self) -> GroundTruth {
        let mut truth = review_truth(self.accounts());
        attest_adult_leads(&mut truth, self.proposals.iter().map(|(l, _, m)| (*l, *m)));
        truth
    }

    /// The production commands from genesis to the proposal in DRAFT, with
    /// the setup's policy values.
    pub fn draft_steps(&self) -> Result<Vec<Step>, String> {
        let mut steps = self.review().steps()?;
        let p01 = self.criteria()?;
        for s in &mut steps {
            if let Command::CreateProgramme { policy } = &mut s.cmd {
                policy.frozen.p01 = p01.clone();
                policy.frozen.p02 = Percent::from_bp(self.p02_bp).ok_or("P-02")?;
                policy.frozen.p03 = NonZeroU8::new(self.p03).ok_or("P-03")?;
                policy.frozen.p07 = Days::new(self.p07_days);
                policy.frozen.p15 = NonZeroU8::new(self.p15).ok_or("P-15")?;
            }
        }
        Ok(steps)
    }

    /// The world at the setup's start state, built from genesis.
    pub fn world(&self, backend: Backend, truth: GroundTruth) -> Result<LifeWorld, String> {
        let mut w = LifeWorld::from_steps(backend, truth, &self.draft_steps()?)?;
        if self.start == Start::Draft {
            return Ok(w);
        }
        w = w.must(&submit(L1, PR1, plan_of(PR1), false))?;
        w.set_now(T_EVAL);
        for r in &self.reviewers {
            for s in assign_declared(*r, PR1, call(1), AssignmentKind::Reviewer) {
                w = w.must(&s)?;
            }
        }
        w = w.must(&declare(
            COORDINATOR,
            DeclarationSubject::Proposal(PR1),
            false,
            false,
        ))?;
        w = w.must(&knock_out(PR1, true))?;
        w = w.must(&admit(PR1))?;
        if self.start == Start::Stage1 {
            return Ok(w);
        }
        for (r, v) in self.reviewers.iter().zip(&self.start_scores) {
            let key = ScoreKey {
                assignment: assignment_of(*r, PR1, call(1), AssignmentKind::Reviewer),
                stage: Stage::One,
                plan: plan_of(PR1),
            };
            w = w.must(&score(*r, key, v))?;
        }
        w = w.must(&close(Actor::Account(COORDINATOR), PR1))?;
        let Start::Ranked { revised } = self.start else {
            return Ok(w);
        };
        if !revised {
            for r in &self.reviewers {
                let id = assignment_of(*r, PR1, call(1), AssignmentKind::Reviewer);
                w = w.must(&no_questions(*r, PR1, id))?;
            }
            return Ok(w);
        }
        let plan = revision_of(PR1, 1);
        w = w.must(&revision_plan(
            L1,
            PR1,
            plan,
            Some(plan_of(PR1)),
            revision_milestone(PR1, 1),
        )?)?;
        w = w.must(&submit_revision(L1, PR1, plan))?;
        for (r, v) in self.reviewers.iter().zip(&self.revision_scores) {
            let key = ScoreKey {
                assignment: assignment_of(*r, PR1, call(1), AssignmentKind::Reviewer),
                stage: Stage::Two,
                plan,
            };
            w = w.must(&score(*r, key, v))?;
        }
        w.must(&rank(R1, PR1))
    }
}

// ---------------------------------------------------------------------------
// The model
// ---------------------------------------------------------------------------

/// Who issues a `CloseStage1` or a `DeclineAfterConcern` probe.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Who {
    /// The named human the row names: the coordinator or the programme manager.
    Named,
    /// Another account: committee member R1.
    Other,
    /// The System, which records no decision (R-LA-03).
    System,
}

/// One action of a life model on PR1.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum LifeAction {
    /// The lead submits.
    Submit,
    /// The coordinator declares no conflict on the proposal.
    CoordinatorDeclare,
    /// The coordinator assigns a reviewer in the current call, who declares no conflict.
    Assign(AccountId),
    /// The coordinator records the knock-out check.
    KnockOut(bool),
    /// The coordinator admits the proposal to stage 1.
    Admit,
    /// A stage 1 score.
    Score(AccountId, Vec<u8>),
    /// A stage 1 correction.
    Correct(AccountId, Vec<u8>),
    /// A `CloseStage1` probe.
    Close(Who),
    /// The vault relates the reviewer to the lead, and the reaction runs in the same step.
    Conflict(AccountId),
    /// The havoc vault answers a conflict for the reviewer, and the reaction runs.
    Havoc(AccountId),
    /// A stage 2 question.
    Ask(AccountId),
    /// A "no questions" record.
    NoQuestions(AccountId),
    /// The lead answers.
    Answer,
    /// The lead records and submits a stage 2 revision.
    Revise,
    /// A stage 2 score on the latest submitted revision.
    Score2(AccountId, Vec<u8>),
    /// `RankAfterStage2` by the reviewer.
    Rank(AccountId),
    /// The reduced clock moves to the next instant.
    Tick,
    /// The System's `ExpireStage2`.
    Expire,
    /// The programme manager publishes call 2.
    Publish2,
    /// The System's `ReEnter` into call 2.
    ReEnter,
    /// The cut-off of the current call, nominating PR1 or not.
    CutOff(bool),
    /// The coordinator assigns an IRC member, who declares no conflict.
    AssignIrc(AccountId),
    /// An IRC review: validation or concern.
    Irc(AccountId, bool),
    /// A `DeclineAfterConcern` probe.
    Decline(Who),
    /// The lead withdraws.
    Withdraw,
    /// The assessor stores the model's finding offer at this index (I-10).
    /// Lane L-FIND-B, see `mc::findings_model`.
    AddFinding(usize),
}

/// The action families a model offers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Phases {
    /// Submission, assignment, knock-out and admission.
    pub intake: bool,
    /// Stage 1 scores, corrections, conflicts and the close.
    pub stage1: bool,
    /// Stage 2 questions, answers and rankings.
    pub stage2: bool,
    /// Stage 2 revisions and their scores.
    pub revisions: bool,
    /// The clock, expiry, publication of call 2, re-entry and fresh assignments.
    pub deferral: bool,
    /// The cut-off, IRC review and the decline.
    pub after: bool,
    /// Withdrawal.
    pub withdraw: bool,
}

/// One life model instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LifeConfig {
    /// The start state from genesis.
    pub setup: LifeSetup,
    /// The reviewers the model's actions name.
    pub reviewers: Vec<AccountId>,
    /// The stage 1 vectors offered.
    pub vectors: Vec<Vec<u8>>,
    /// The stage 2 vectors offered, by reviewer.
    pub vectors2: Vec<(AccountId, Vec<u8>)>,
    /// The corrections allowed.
    pub corrections: u8,
    /// The reviewers who may get a conflict, at most one in a run.
    pub conflicts: Vec<AccountId>,
    /// The reviewers the havoc vault may flip, at most one in a run.
    pub havoc: Vec<AccountId>,
    /// The revisions allowed.
    pub revisions: u8,
    /// The reviewers the coordinator may assign in STAGE2 once a stage 2
    /// reviewer was released. A release can leave fewer than P-39
    /// organisations, and a new reviewer restores them (I-34, O-50).
    pub spares: Vec<AccountId>,
    /// The action families.
    pub phases: Phases,
}

/// One life model state.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LifeState {
    /// Production, the vault and the reference views.
    pub world: LifeWorld,
    /// Corrections left.
    pub corrections: u8,
    /// Conflicts and havoc flips left.
    pub flips: u8,
    /// Revisions left.
    pub revisions: u8,
    /// Set when production and the references disagree. The `two-way`
    /// property fails on it, and the state is terminal.
    pub divergence: Option<String>,
    /// The findings beside the core: the production and reference stores
    /// and the offer budget (I-10, I-11, lane L-FIND-B).
    pub findings: FindingSide,
}

impl LifeState {
    /// The reference state of PR1.
    pub fn state(&self) -> Option<StateTag> {
        self.world.life.state_of(PR1)
    }
}

/// A life model.
pub struct LifeModel {
    /// The instance.
    pub config: LifeConfig,
    /// The start state.
    pub start: LifeState,
    /// The findings `LifeAction::AddFinding` offers, by index. Empty
    /// unless the model was built by [`LifeModel::with_findings`].
    pub offers: Vec<Finding>,
}

impl LifeModel {
    /// The model of `config` over `backend`, with its start built from genesis.
    pub fn new(config: LifeConfig, backend: Backend) -> Result<LifeModel, String> {
        LifeModel::with_findings(config, backend, Vec::new(), 0)
    }

    /// The model of `config` over `backend` that also offers each finding
    /// of `offers` while its call is its proposal's current call, at most
    /// `budget` times in a run (I-10, lane L-FIND-B).
    pub fn with_findings(
        config: LifeConfig,
        backend: Backend,
        offers: Vec<Finding>,
        budget: u8,
    ) -> Result<LifeModel, String> {
        let world = config.setup.world(backend, config.setup.truth())?;
        let findings = FindingSide::new(&config.setup.draft_steps()?, budget);
        Ok(LifeModel {
            start: LifeState {
                world,
                corrections: config.corrections,
                flips: 1,
                revisions: config.revisions,
                divergence: None,
                findings,
            },
            config,
            offers,
        })
    }

    /// The steps of `action` in `s`, or `None` where it does not apply.
    fn steps(&self, s: &LifeState, action: &LifeAction) -> Option<Vec<Step>> {
        let w = &s.world;
        let p = w.life.proposals.get(&PR1)?;
        let current = p.current_call;
        let reviewer_in =
            |r: AccountId, stage: Stage| w.assignment(r, PR1, stage, AssignmentKind::Reviewer);
        Some(match action {
            LifeAction::Submit => vec![submit(L1, PR1, plan_of(PR1), false)],
            LifeAction::CoordinatorDeclare => vec![declare(
                COORDINATOR,
                DeclarationSubject::Proposal(PR1),
                false,
                false,
            )],
            LifeAction::Assign(r) => {
                if w.life.assignments.contains_key(&assignment_of(
                    *r,
                    PR1,
                    current,
                    AssignmentKind::Reviewer,
                )) {
                    return None;
                }
                assign_declared(*r, PR1, current, AssignmentKind::Reviewer)
            }
            LifeAction::KnockOut(pass) => vec![knock_out(PR1, *pass)],
            LifeAction::Admit => vec![admit(PR1)],
            LifeAction::Score(r, v) => {
                let key = ScoreKey {
                    assignment: reviewer_in(*r, Stage::One)?,
                    stage: Stage::One,
                    plan: p.submitted?,
                };
                vec![score(*r, key, v)]
            }
            LifeAction::Correct(r, v) => {
                if s.corrections == 0 {
                    return None;
                }
                let key = ScoreKey {
                    assignment: reviewer_in(*r, Stage::One)?,
                    stage: Stage::One,
                    plan: p.submitted?,
                };
                if w.life.scores.get(&key) == Some(v) {
                    return None;
                }
                vec![correct(*r, key, v)]
            }
            LifeAction::Close(who) => {
                let actor = match who {
                    Who::Named => Actor::Account(COORDINATOR),
                    Who::Other => Actor::Account(R1),
                    Who::System => Actor::System(SystemCause::Timeline),
                };
                vec![close(actor, PR1)]
            }
            LifeAction::Conflict(_)
            | LifeAction::Havoc(_)
            | LifeAction::Tick
            | LifeAction::AddFinding(_) => Vec::new(),
            LifeAction::Ask(r) => vec![ask(*r, PR1, reviewer_in(*r, Stage::Two)?)],
            LifeAction::NoQuestions(r) => vec![no_questions(*r, PR1, reviewer_in(*r, Stage::Two)?)],
            LifeAction::Answer => vec![answer(L1, PR1)],
            LifeAction::Revise => {
                if s.revisions == 0 {
                    return None;
                }
                let n = p.plans.len();
                let live = p
                    .plans
                    .iter()
                    .find(|(_, pl)| !pl.superseded)
                    .map(|(id, _)| *id);
                let plan = revision_of(PR1, n);
                vec![
                    revision_plan(L1, PR1, plan, live, revision_milestone(PR1, n)).ok()?,
                    submit_revision(L1, PR1, plan),
                ]
            }
            LifeAction::Score2(r, v) => {
                let plan = *p.revisions.last()?;
                let key = ScoreKey {
                    assignment: reviewer_in(*r, Stage::Two)?,
                    stage: Stage::Two,
                    plan,
                };
                vec![score(*r, key, v)]
            }
            LifeAction::Rank(r) => vec![rank(*r, PR1)],
            LifeAction::Expire => vec![expire(PR1)],
            LifeAction::Publish2 => {
                if w.life.seq_of(call(2)).is_some() {
                    return None;
                }
                vec![publish(call(2))]
            }
            LifeAction::ReEnter => vec![reenter(PR1, call(2))],
            LifeAction::CutOff(nominate) => {
                let c = w.life.calls.get(&current)?;
                let facts = w.rev.facts();
                let voters: Vec<AccountId> =
                    crate::reference::lifecycle::committee(&w.rev.sod.view, c.programme, w.now())
                        .into_iter()
                        .filter(|m| {
                            !crate::reference::review::recused(
                                &w.rev.sod.view,
                                &w.rev.view,
                                &facts,
                                *m,
                                current,
                            )
                        })
                        .collect();
                vec![cut_off(
                    R1,
                    cut_off_decision(current.raw()),
                    current,
                    vec![PR1],
                    u32::from(*nominate),
                    false,
                    ballots(&voters, Vote::For),
                )]
            }
            LifeAction::AssignIrc(i) => {
                if w.life.assignments.contains_key(&assignment_of(
                    *i,
                    PR1,
                    current,
                    AssignmentKind::Irc,
                )) {
                    return None;
                }
                assign_declared(*i, PR1, current, AssignmentKind::Irc)
            }
            LifeAction::Irc(i, validate) => {
                let id = w.assignment(*i, PR1, Stage::Two, AssignmentKind::Irc)?;
                vec![irc_review(*i, id, *validate)]
            }
            LifeAction::Decline(who) => {
                let actor = match who {
                    Who::Named => Actor::Account(STAFF_PM),
                    Who::Other => Actor::Account(R1),
                    Who::System => Actor::System(SystemCause::Timeline),
                };
                vec![decline(actor, PR1)]
            }
            LifeAction::Withdraw => vec![withdraw(L1, PR1)],
        })
    }

    fn vault(&self, s: &LifeState, action: &LifeAction) -> Option<LifeState> {
        if s.flips == 0 {
            return None;
        }
        let mut next = s.clone();
        next.flips = 0;
        match action {
            LifeAction::Conflict(r) => {
                next.world
                    .rev
                    .sod
                    .truth
                    .relate(tag(*r), tag(L1), Relation::CoWorker);
            }
            LifeAction::Havoc(r) => {
                let team = crate::reference::review::team_of(&next.world.rev.sod.view, PR1);
                next.world.rev.flip(*r, team, true, true);
            }
            _ => return None,
        }
        if let Err(e) = next.world.sync() {
            next.divergence = Some(e);
        }
        Some(next)
    }

    fn tick(&self, s: &LifeState) -> Option<LifeState> {
        let end = s.world.life.window_end(PR1)?;
        let now = s.world.now();
        let t = ReducedClock::new([end])
            .instants()
            .iter()
            .copied()
            .filter(|t| *t > now && *t <= end)
            .min()?;
        let mut next = s.clone();
        next.world.set_now(t);
        Some(next)
    }
}

fn diverged(s: &LifeState, why: String) -> LifeState {
    let mut next = s.clone();
    next.divergence = Some(why);
    next
}

impl Model for LifeModel {
    type State = LifeState;
    type Action = LifeAction;

    fn init(&self) -> Vec<LifeState> {
        vec![self.start.clone()]
    }

    fn actions(&self, s: &LifeState, actions: &mut Vec<LifeAction>) {
        if s.divergence.is_some() {
            return;
        }
        let Some(state) = s.state() else {
            return;
        };
        let ph = self.config.phases;
        let rs = &self.config.reviewers;
        if ph.intake {
            match state {
                StateTag::Draft => actions.push(LifeAction::Submit),
                StateTag::Submitted => {
                    actions.push(LifeAction::CoordinatorDeclare);
                    actions.extend(rs.iter().map(|r| LifeAction::Assign(*r)));
                    actions.push(LifeAction::KnockOut(true));
                    actions.push(LifeAction::KnockOut(false));
                    actions.push(LifeAction::Admit);
                }
                StateTag::Ineligible => {
                    actions.extend(rs.iter().map(|r| LifeAction::Assign(*r)));
                    actions.push(LifeAction::Admit);
                }
                _ => {}
            }
        }
        if ph.stage1 && matches!(state, StateTag::Stage1 | StateTag::Stage2) {
            for r in rs {
                for v in &self.config.vectors {
                    actions.push(LifeAction::Score(*r, v.clone()));
                    if s.corrections > 0 {
                        actions.push(LifeAction::Correct(*r, v.clone()));
                    }
                }
            }
            actions.push(LifeAction::Close(Who::Named));
            if state == StateTag::Stage1 {
                actions.push(LifeAction::Close(Who::Other));
                actions.push(LifeAction::Close(Who::System));
                if s.flips > 0 {
                    actions.extend(
                        self.config
                            .conflicts
                            .iter()
                            .map(|r| LifeAction::Conflict(*r)),
                    );
                }
            }
        }
        if s.flips > 0 && !matches!(state, StateTag::Draft) && !state.is_terminal() {
            actions.extend(self.config.havoc.iter().map(|r| LifeAction::Havoc(*r)));
        }
        if ph.stage2 && state == StateTag::Stage2 {
            for r in rs {
                actions.push(LifeAction::Ask(*r));
                actions.push(LifeAction::NoQuestions(*r));
                actions.push(LifeAction::Rank(*r));
            }
            actions.push(LifeAction::Answer);
            // A vault conflict releases a stage 2 reviewer, so the round
            // can complete with the remaining reviewers (O-50).
            if s.flips > 0 {
                actions.extend(
                    self.config
                        .conflicts
                        .iter()
                        .map(|r| LifeAction::Conflict(*r)),
                );
            }
            // I-34: after a release the remaining reviewers may span fewer
            // than P-39 organisations. The coordinator then assigns a
            // spare reviewer, who completes the round (O-50).
            let released = s.world.life.proposals.get(&PR1).is_some_and(|p| {
                s.world.life.assignments.values().any(|a| {
                    a.proposal == PR1
                        && a.call == p.current_call
                        && a.kind == AssignmentKind::Reviewer
                        && a.released
                })
            });
            if released {
                for r in &self.config.spares {
                    actions.push(LifeAction::Assign(*r));
                    actions.push(LifeAction::NoQuestions(*r));
                }
            }
        }
        if ph.revisions && state == StateTag::Stage2 {
            if s.revisions > 0 {
                actions.push(LifeAction::Revise);
            }
            for (r, v) in &self.config.vectors2 {
                actions.push(LifeAction::Score2(*r, v.clone()));
            }
        }
        if ph.deferral {
            match state {
                StateTag::Stage2 => {
                    actions.push(LifeAction::Tick);
                    actions.push(LifeAction::Expire);
                }
                StateTag::Deferred => actions.push(LifeAction::ReEnter),
                _ => {}
            }
            let publishable = match state {
                StateTag::Deferred => true,
                StateTag::Stage2 | StateTag::Ranked | StateTag::IrcReview => ph.after,
                _ => false,
            };
            if publishable {
                actions.push(LifeAction::Publish2);
            }
            let reentered = s
                .world
                .life
                .proposals
                .get(&PR1)
                .is_some_and(|p| p.current_call != p.created_call);
            if reentered && state == StateTag::Stage2 {
                actions.extend(rs.iter().map(|r| LifeAction::Assign(*r)));
            }
        }
        if ph.after {
            match state {
                StateTag::Ranked => {
                    actions.push(LifeAction::CutOff(true));
                    actions.push(LifeAction::CutOff(false));
                }
                StateTag::IrcReview => {
                    for i in [IRC, IRC2] {
                        actions.push(LifeAction::AssignIrc(i));
                        actions.push(LifeAction::Irc(i, true));
                        actions.push(LifeAction::Irc(i, false));
                    }
                    actions.push(LifeAction::Decline(Who::Named));
                    actions.push(LifeAction::Decline(Who::System));
                }
                _ => {}
            }
        }
        if ph.withdraw && state.is_withdrawable() {
            actions.push(LifeAction::Withdraw);
        }
        crate::mc::findings_model::offer_findings(self, s, actions);
    }

    fn step(&self, s: &LifeState, action: &LifeAction) -> Option<LifeState> {
        if s.divergence.is_some() {
            return None;
        }
        match action {
            LifeAction::Conflict(_) | LifeAction::Havoc(_) => return self.vault(s, action),
            LifeAction::Tick => return self.tick(s),
            LifeAction::AddFinding(i) => {
                return crate::mc::findings_model::add_finding(self, s, *i);
            }
            _ => {}
        }
        let steps = self.steps(s, action)?;
        let mut w = s.world.clone();
        for (i, st) in steps.iter().enumerate() {
            match w.step(st) {
                Ok(Some((nw, _))) => w = nw,
                Ok(None) if i == 0 => return None,
                Ok(None) => {
                    return Some(diverged(
                        s,
                        format!("{action:?}: step {i} of a composite action was refused"),
                    ));
                }
                Err(e) => return Some(diverged(s, format!("{action:?}: {e}"))),
            }
        }
        let mut next = s.clone();
        next.world = w;
        for st in &steps {
            next.findings.observe(st);
        }
        match action {
            LifeAction::Correct(..) => next.corrections = next.corrections.saturating_sub(1),
            LifeAction::Revise => next.revisions = next.revisions.saturating_sub(1),
            _ => {}
        }
        Some(next)
    }

    fn is_terminal(&self, s: &LifeState) -> bool {
        s.divergence.is_some() || s.state().is_some_and(StateTag::is_terminal)
    }
}

// ---------------------------------------------------------------------------
// Instances
// ---------------------------------------------------------------------------

/// The stage 1 vectors of M-LIFE-S1: with weights (1, 1) they score 0,
/// 50.00 and 100.00; with weights (3, 1) they score 0, 75.00 and 100.00.
pub fn s1_vectors() -> Vec<Vec<u8>> {
    vec![vec![0, 0], vec![2, 0], vec![2, 2]]
}

/// M-LIFE-S1 (design 6.3): one proposal in STAGE1 from genesis, three
/// reviewers, two criteria on a scale of 0 to 2, P-03 = 2, one
/// correction and one conflict. The tail expires stage 2, publishes the
/// next call and re-enters, so I-08 is checked after re-entry too.
pub fn s1_config(weights: [u16; 2], p02_bp: u16) -> LifeConfig {
    LifeConfig {
        setup: LifeSetup {
            scale_max: 2,
            weights: weights.to_vec(),
            p02_bp,
            p03: 2,
            p07_days: 28,
            p15: 2,
            judges: life_judges(),
            proposals: vec![(L1, PR1, false)],
            reviewers: vec![R1, R2, R3],
            start_scores: Vec::new(),
            revision_scores: Vec::new(),
            start: Start::Stage1,
        },
        reviewers: vec![R1, R2, R3],
        vectors: s1_vectors(),
        vectors2: Vec::new(),
        corrections: 1,
        conflicts: vec![R1, R2, R3],
        havoc: Vec::new(),
        revisions: 0,
        spares: Vec::new(),
        phases: Phases {
            intake: false,
            stage1: true,
            stage2: false,
            revisions: false,
            deferral: true,
            after: false,
            withdraw: true,
        },
    }
}

/// M-LIFE-S1 with weights (1, 1) at P-02 50.00.
pub fn s1_even() -> LifeConfig {
    s1_config([1, 1], 5_000)
}

/// M-LIFE-S1 with weights (3, 1) at P-02 75.00.
pub fn s1_weighted() -> LifeConfig {
    s1_config([3, 1], 7_500)
}

/// M-LIFE-S2, stage 2 part (design 6.3): one proposal in STAGE2 from
/// genesis with a stage 1 score of 75.00 under weights (1, 1) and P-02
/// 50.00, two reviewers, two calls, one revision, one deferral and one
/// re-entry. Stage 2 vectors score 50.00, 75.00 and 100.00, so a revision
/// can score lower than, equal to and above the original. One vault
/// conflict releases R2 in STAGE2, so the round can complete with the
/// remaining reviewer (O-50). RANKED ends the run apart from withdrawal.
/// [`s2_after_config`] covers the later rows.
pub fn s2_config() -> LifeConfig {
    LifeConfig {
        setup: LifeSetup {
            scale_max: 2,
            weights: vec![1, 1],
            p02_bp: 5_000,
            p03: 2,
            p07_days: 28,
            p15: 2,
            judges: life_judges(),
            proposals: vec![(L1, PR1, false)],
            reviewers: vec![R1, R2],
            start_scores: vec![vec![2, 1], vec![2, 1]],
            revision_scores: Vec::new(),
            start: Start::Stage2,
        },
        reviewers: vec![R1, R2],
        vectors: Vec::new(),
        vectors2: vec![
            (R1, vec![1, 1]),
            (R1, vec![2, 1]),
            (R1, vec![2, 2]),
            (R2, vec![2, 1]),
        ],
        corrections: 0,
        conflicts: vec![R2],
        havoc: Vec::new(),
        revisions: 1,
        spares: vec![R3],
        phases: Phases {
            intake: false,
            stage1: false,
            stage2: true,
            revisions: true,
            deferral: true,
            after: false,
            withdraw: true,
        },
    }
}

/// M-LIFE-S2, after-ranking part (design 6.3): the same proposal ranked
/// from genesis on the revised plan, or on the original plan, then the
/// cut-off, IRC review, deferral from IRC_REVIEW, re-entry, decline and
/// withdrawal. I-09 must hold in every state it reaches.
pub fn s2_after_config(revised: bool) -> LifeConfig {
    let mut c = s2_config();
    c.setup.start = Start::Ranked { revised };
    c.setup.revision_scores = vec![vec![2, 2], vec![2, 2]];
    c.revisions = 0;
    c.vectors2 = Vec::new();
    c.conflicts = Vec::new();
    c.phases = Phases {
        intake: false,
        stage1: false,
        stage2: false,
        revisions: false,
        deferral: true,
        after: true,
        withdraw: true,
    };
    c
}

/// The state count of M-LIFE-S1 with weights (1, 1), measured on production
/// in step W6. The references store 5_698.
pub const M_LIFE_S1_EVEN_STATES: usize = 6_766;
/// The state count of M-LIFE-S1 with weights (3, 1), measured on production
/// in step W6. The references store 5_260.
pub const M_LIFE_S1_WEIGHTED_STATES: usize = 6_202;
/// The state count of M-LIFE-S2, measured on production in the W7 review,
/// after I-34 was checked again at the ranking and a spare reviewer was
/// added after a release. The references store 25_870.
pub const M_LIFE_S2_STATES: usize = 34_824;
/// The reference counts of M-LIFE-S1 (1, 1), M-LIFE-S1 (3, 1) and M-LIFE-S2,
/// the tripwires of their `_reference` twins (design 6.1).
pub const M_LIFE_S1_EVEN_REFERENCE_STATES: usize = 5_698;
/// See [`M_LIFE_S1_EVEN_REFERENCE_STATES`].
pub const M_LIFE_S1_WEIGHTED_REFERENCE_STATES: usize = 5_260;
/// See [`M_LIFE_S1_EVEN_REFERENCE_STATES`].
pub const M_LIFE_S2_REFERENCE_STATES: usize = 25_870;
/// The state count of M-LIFE-S2 after ranking on the revised plan, measured
/// on production in step W6. The references store the same count.
pub const M_LIFE_S2_AFTER_STATES: usize = 192;

// ---------------------------------------------------------------------------
// Predicates
// ---------------------------------------------------------------------------

/// Whether the model and production agree: no divergence was recorded.
pub fn agree(s: &LifeState) -> Result<(), String> {
    match &s.divergence {
        Some(d) => Err(format!("two-way: {d}")),
        None => Ok(()),
    }
}

/// Whether PR1 left STAGE1 by score between `before` and `after`.
pub fn left_stage1_by_score(before: &LifeState, after: &LifeState) -> bool {
    before.state() == Some(StateTag::Stage1)
        && matches!(
            after.state(),
            Some(StateTag::Stage2 | StateTag::NotSelected)
        )
}

/// transition("I-07"): an exit from STAGE1 by score needs, in `before`, at
/// least P-03 valid scores and a valid score from every active assignee.
pub fn transition_i07(before: &LifeState, after: &LifeState) -> Result<(), String> {
    if !left_stage1_by_score(before, after) {
        return Ok(());
    }
    if before.world.life.stage1_closable(PR1) {
        Ok(())
    } else {
        Err(format!(
            "I-07: PR1 left STAGE1 for {:?}, but before it {:?}",
            after.state(),
            before.world.life.stage_one_facts(PR1, StateTag::Stage2)
        ))
    }
}

/// transition("I-08"): an exit to STAGE2 needs a weighted score strictly
/// above P-02 in `before`, and an exit to NOT_SELECTED needs one not above.
pub fn transition_i08(before: &LifeState, after: &LifeState) -> Result<(), String> {
    if !left_stage1_by_score(before, after) {
        return Ok(());
    }
    let facts = before.world.life.stage_one_facts(PR1, StateTag::Stage2);
    let passed = facts.as_ref().and_then(|f| f.passed);
    let to_stage2 = after.state() == Some(StateTag::Stage2);
    if passed == Some(to_stage2) {
        Ok(())
    } else {
        Err(format!(
            "I-08: PR1 went to {:?}, but its score before was {:?} against P-02 {:?}",
            after.state(),
            facts.as_ref().and_then(|f| f.score),
            facts.as_ref().map(|f| f.p02_bp)
        ))
    }
}

/// transition("I-08 close"): only the coordinator's `CloseStage1` takes
/// PR1 out of STAGE1 by score.
pub fn transition_only_close(
    before: &LifeState,
    action: &LifeAction,
    after: &LifeState,
) -> Result<(), String> {
    if !left_stage1_by_score(before, after) || *action == LifeAction::Close(Who::Named) {
        return Ok(());
    }
    Err(format!(
        "I-08: {action:?} took PR1 out of STAGE1 by score, only CloseStage1 may"
    ))
}

/// transition("I-09"): entering RANKED sets exactly one effective score per
/// P-24, computed from `before`.
pub fn transition_i09(before: &LifeState, after: &LifeState) -> Result<(), String> {
    if !(before.state() == Some(StateTag::Stage2) && after.state() == Some(StateTag::Ranked)) {
        return Ok(());
    }
    let expected = before.world.life.effective_now(PR1);
    let got = after
        .world
        .life
        .proposals
        .get(&PR1)
        .map(|p| p.effective.clone())
        .unwrap_or_default();
    match (expected, got.as_slice()) {
        (Some(x), [e]) if x.plan == e.plan && x.basis == e.basis && x.value.same(e.value) => Ok(()),
        (x, g) => Err(format!(
            "I-09: entering RANKED recorded {g:?}, P-24 gives {x:?}"
        )),
    }
}

/// Whether the stage 1 exit of PR1 went to `to` with a score exactly at P-02.
pub fn exit_at_equality(s: &LifeState, to: StateTag) -> bool {
    s.world
        .life
        .proposals
        .get(&PR1)
        .and_then(|p| p.exit.as_ref())
        .is_some_and(|e| {
            e.to == to
                && e.score.is_some_and(|f| {
                    let lhs = f.num.checked_mul(10_000);
                    let rhs = u128::from(e.p02_bp).checked_mul(f.den);
                    lhs.is_some() && lhs == rhs
                })
        })
}

/// Whether PR1 is in `state`.
pub fn in_state(s: &LifeState, state: StateTag) -> bool {
    s.state() == Some(state)
}

/// Whether PR1 is in STAGE2 after a re-entry.
pub fn stage2_after_reentry(s: &LifeState) -> bool {
    s.world
        .life
        .proposals
        .get(&PR1)
        .is_some_and(|p| p.state == StateTag::Stage2 && p.current_call != p.created_call)
}

/// Whether PR1 was ranked with an effective score of `basis` and is now in `state`.
pub fn ranked_with(s: &LifeState, basis: Basis, state: StateTag) -> bool {
    s.world.life.proposals.get(&PR1).is_some_and(|p| {
        p.state == state && p.ranked && p.effective.first().is_some_and(|e| e.basis == basis)
    })
}

/// Whether PR1 was ranked on the original plan although a revision scored
/// exactly as much (Q3, R-EV-06 AC).
pub fn tie_kept_original(s: &LifeState) -> bool {
    let life = &s.world.life;
    life.proposals.get(&PR1).is_some_and(|p| {
        p.ranked
            && p.effective
                .first()
                .is_some_and(|e| e.basis == Basis::Original)
            && p.exit.as_ref().and_then(|x| x.score).is_some_and(|orig| {
                p.revisions
                    .iter()
                    .any(|r| life.revision_score(PR1, *r).is_some_and(|v| v.same(orig)))
            })
    })
}

/// The M-LIFE-S1 properties: two-way, always and transition I-07 and
/// I-08, the close-only rule, sealing, and the witnesses.
pub fn s1_properties<'a, M>() -> Vec<Property<'a, M>>
where
    M: Model<State = LifeState, Action = LifeAction> + 'a,
{
    vec![
        Property::always_with("two-way", agree),
        Property::always_with("I-07", |s: &LifeState| check_i07(&s.world.life)),
        Property::always_with("I-08", |s: &LifeState| check_i08(&s.world.life)),
        Property::always_with("NOTE 3", |s: &LifeState| check_sealed(&s.world.life)),
        Property::always_with("R-LA-03", |s: &LifeState| {
            check_recorded_by_human(&s.world.life)
        }),
        Property::transition_with("I-07", |b: &LifeState, _: &LifeAction, a: &LifeState| {
            transition_i07(b, a)
        }),
        Property::transition_with("I-08", |b: &LifeState, _: &LifeAction, a: &LifeState| {
            transition_i08(b, a)
        }),
        Property::transition_with("I-08 close", transition_only_close),
        Property::reachable(
            "I-08 witness: a score exactly at P-02 ends NOT_SELECTED",
            |s: &LifeState| exit_at_equality(s, StateTag::NotSelected),
        ),
        Property::reachable("I-07 witness: STAGE1 to STAGE2", |s: &LifeState| {
            in_state(s, StateTag::Stage2)
        }),
        Property::reachable("I-07 witness: STAGE1 to NOT_SELECTED", |s: &LifeState| {
            in_state(s, StateTag::NotSelected)
        }),
        Property::reachable("I-08 witness: STAGE2 after re-entry", stage2_after_reentry),
    ]
}

/// Whether PR1 took STAGE2 to RANKED and is now in `state`.
pub fn ranked_and_in(s: &LifeState, state: StateTag) -> bool {
    s.world
        .life
        .proposals
        .get(&PR1)
        .is_some_and(|p| p.ranked && p.state == state)
}

/// The I-09 properties every life model shares: two-way, always I-09, I-08,
/// I-07 and sealing, and transition I-09.
fn i09_core<'a, M>() -> Vec<Property<'a, M>>
where
    M: Model<State = LifeState, Action = LifeAction> + 'a,
{
    vec![
        Property::always_with("two-way", agree),
        Property::always_with("I-09", |s: &LifeState| check_i09(&s.world.life)),
        Property::always_with("I-08", |s: &LifeState| check_i08(&s.world.life)),
        Property::always_with("I-07", |s: &LifeState| check_i07(&s.world.life)),
        Property::always_with("NOTE 3", |s: &LifeState| check_sealed(&s.world.life)),
        Property::always_with("R-LA-03", |s: &LifeState| {
            check_recorded_by_human(&s.world.life)
        }),
        Property::transition_with("I-09", |b: &LifeState, _: &LifeAction, a: &LifeState| {
            transition_i09(b, a)
        }),
    ]
}

/// The M-LIFE-S2 stage 2 properties: [`i09_core`], and the witnesses of
/// both bases, of a tie, of a deferral from STAGE2, of RANKED after
/// re-entry and of withdrawal after ranking.
pub fn s2_properties<'a, M>() -> Vec<Property<'a, M>>
where
    M: Model<State = LifeState, Action = LifeAction> + 'a,
{
    let mut out = i09_core();
    out.extend([
        Property::reachable(
            "I-09 witness: RANKED on the original plan",
            |s: &LifeState| ranked_with(s, Basis::Original, StateTag::Ranked),
        ),
        Property::reachable(
            "I-09 witness: RANKED on the revised plan",
            |s: &LifeState| ranked_with(s, Basis::Revised, StateTag::Ranked),
        ),
        Property::reachable(
            "I-09 witness: a tie keeps the original plan",
            tie_kept_original,
        ),
        Property::reachable("R-EV-07 witness: STAGE2 to DEFERRED", |s: &LifeState| {
            in_state(s, StateTag::Deferred)
        }),
        Property::reachable("I-09 witness: RANKED after re-entry", |s: &LifeState| {
            s.world
                .life
                .proposals
                .get(&PR1)
                .is_some_and(|p| p.state == StateTag::Ranked && p.current_call != p.created_call)
        }),
        Property::reachable("I-09 witness: WITHDRAWN after ranking", |s: &LifeState| {
            ranked_and_in(s, StateTag::Withdrawn)
        }),
        Property::reachable(
            "O-50 witness: RANKED by \"no questions\" after a stage 2 release",
            ranked_by_no_questions_after_release,
        ),
    ]);
    out
}

/// Whether PR1 is RANKED with a stage 2 reviewer assignment released and
/// every remaining active one with a "no questions" record (O-50).
pub fn ranked_by_no_questions_after_release(s: &LifeState) -> bool {
    let life = &s.world.life;
    let Some(p) = life.proposals.get(&PR1) else {
        return false;
    };
    let call = p.current_call;
    let released = life.assignments.values().any(|a| {
        a.proposal == PR1 && a.call == call && a.kind == AssignmentKind::Reviewer && a.released
    });
    let active = life.active_assignments(PR1, call, AssignmentKind::Reviewer);
    let quiet = p
        .round
        .as_ref()
        .is_some_and(|r| !active.is_empty() && active.is_subset(&r.no_questions));
    p.state == StateTag::Ranked && released && quiet
}

/// The M-LIFE-S2 after-ranking properties: [`i09_core`], and the
/// witnesses of I-09 in NOT_SELECTED, IRC_REVIEW after re-entry, DEFERRED,
/// DECLINED, WITHDRAWN and NEGOTIATION.
pub fn s2_after_properties<'a, M>() -> Vec<Property<'a, M>>
where
    M: Model<State = LifeState, Action = LifeAction> + 'a,
{
    let mut out = i09_core();
    for state in [
        StateTag::NotSelected,
        StateTag::Deferred,
        StateTag::Declined,
        StateTag::Withdrawn,
        StateTag::Negotiation,
    ] {
        out.push(Property::reachable(
            format!("I-09 witness: {} after ranking", state.spec_name()),
            move |s: &LifeState| ranked_and_in(s, state),
        ));
    }
    out.push(Property::reachable(
        "I-09 witness: IRC_REVIEW after re-entry",
        |s: &LifeState| {
            s.world
                .life
                .proposals
                .get(&PR1)
                .is_some_and(|p| p.state == StateTag::IrcReview && p.current_call != p.created_call)
        },
    ));
    out
}

// ---------------------------------------------------------------------------
// Faults (design 6.1 "Teeth")
// ---------------------------------------------------------------------------

/// The first of `alternatives` that the structural fold accepts.
fn inject_first(s: &LifeState, alternatives: &[Vec<Record>]) -> Option<LifeState> {
    for records in alternatives {
        if let Ok(w) = s.world.inject(records) {
            let mut next = s.clone();
            next.world = w;
            return Some(next);
        }
    }
    None
}

fn stage1_exit_records(
    s: &LifeState,
    passed: bool,
    counted: &BTreeSet<ScoreKey>,
    score: Frac,
) -> Option<Vec<Vec<Record>>> {
    let p02 = s.world.life.governing(PR1)?.p02_bp;
    let closed = forge_stage1_closed(PR1, COORDINATOR, score, p02, counted, passed).ok()?;
    let (to, row) = if passed {
        (StateTag::Stage2, Row::Stage1ToStage2)
    } else {
        (StateTag::NotSelected, Row::Stage1ToNotSelected)
    };
    let t = Record::Transitioned(Transitioned {
        proposal: PR1,
        from: StateTag::Stage1,
        to,
        row,
        actor: Actor::Account(COORDINATOR),
        decision: None,
    });
    Some(vec![vec![closed.clone(), t.clone()], vec![t], vec![closed]])
}

/// The I-07 fault: an engine that counts a superseded score as a second
/// score. Once a correction left one valid score, it closes stage 1 as if
/// P-03 scores existed.
pub fn fault_superseded_counted(s: &LifeState) -> Option<LifeState> {
    if s.state() != Some(StateTag::Stage1) || s.corrections > 0 || s.divergence.is_some() {
        return None;
    }
    let facts = s.world.life.stage_one_facts(PR1, StateTag::Stage2)?;
    if facts.reviewers != 1 {
        return None;
    }
    let score = facts.score?;
    let passed = facts.passed?;
    inject_first(s, &stage1_exit_records(s, passed, &facts.valid, score)?)
}

/// The I-08 fault: an engine that compares with `>=` and passes a score
/// exactly at P-02.
pub fn fault_ge_instead_of_gt(s: &LifeState) -> Option<LifeState> {
    if s.state() != Some(StateTag::Stage1) || s.divergence.is_some() {
        return None;
    }
    if !s.world.life.stage1_closable(PR1) {
        return None;
    }
    let facts = s.world.life.stage_one_facts(PR1, StateTag::Stage2)?;
    let score = facts.score?;
    let at = score.num.checked_mul(10_000)? == u128::from(facts.p02_bp).checked_mul(score.den)?;
    if !at {
        return None;
    }
    inject_first(s, &stage1_exit_records(s, true, &facts.valid, score)?)
}

/// The I-09 fault: an engine that clears the effective score. It ranks
/// PR1 and leaves no effective score behind, or, where the fold needs
/// one, an effective score that names the original plan with the value 0.
pub fn fault_effective_cleared(s: &LifeState) -> Option<LifeState> {
    if s.state() != Some(StateTag::Stage2) || s.divergence.is_some() {
        return None;
    }
    let plan = s.world.life.proposals.get(&PR1)?.submitted?;
    let t = Record::Transitioned(Transitioned {
        proposal: PR1,
        from: StateTag::Stage2,
        to: StateTag::Ranked,
        row: Row::Stage2ToRanked,
        actor: Actor::Account(R1),
        decision: None,
    });
    let zero = forge_effective(
        PR1,
        Effective {
            plan,
            value: Frac { num: 0, den: 1 },
            basis: Basis::Revised,
        },
        &BTreeSet::new(),
    )
    .ok()?;
    inject_first(s, &[vec![t.clone()], vec![zero, t]])
}

// ---------------------------------------------------------------------------
// Stories for the example tests
// ---------------------------------------------------------------------------

/// The setup of an example story: weights (1, 1) on a scale of 0 to 2,
/// P-02 50.00, P-03 = 2, P-07 = 28 days, P-15 = 2, `judges`, and
/// `proposals` in DRAFT in call 1.
pub fn story_setup(
    proposals: Vec<(AccountId, ProposalId, bool)>,
    judges: Vec<(AccountId, Role, Option<OrganisationId>)>,
) -> LifeSetup {
    LifeSetup {
        scale_max: 2,
        weights: vec![1, 1],
        p02_bp: 5_000,
        p03: 2,
        p07_days: 28,
        p15: 2,
        judges,
        proposals,
        reviewers: Vec::new(),
        start_scores: Vec::new(),
        revision_scores: Vec::new(),
        start: Start::Draft,
    }
}

/// A world for an example test, with helpers that drive a proposal along
/// its rows. Every step is compared with the references in both directions.
#[derive(Clone, Debug)]
pub struct Story {
    /// The world.
    pub world: LifeWorld,
}

impl Story {
    /// The story of `setup` from genesis to every proposal in DRAFT, over
    /// the setup's vault after `change`.
    pub fn new(
        setup: &LifeSetup,
        backend: Backend,
        change: impl FnOnce(&mut GroundTruth),
    ) -> Result<Story, String> {
        let mut truth = setup.truth();
        change(&mut truth);
        Ok(Story {
            world: LifeWorld::from_steps(backend, truth, &setup.draft_steps()?)?,
        })
    }

    /// Runs `step`, which production and the references must both accept.
    pub fn run(&mut self, step: &Step) -> Result<Vec<Record>, String> {
        match self.attempt(step)? {
            Some(records) => Ok(records),
            None => Err(format!(
                "{:?} by {:?} was refused by production and the references",
                step.cmd, step.actor
            )),
        }
    }

    /// Runs `step`. `Ok(None)` when production and the references both refuse it.
    pub fn attempt(&mut self, step: &Step) -> Result<Option<Vec<Record>>, String> {
        match self.world.step(step)? {
            Some((w, records)) => {
                self.world = w;
                Ok(Some(records))
            }
            None => Ok(None),
        }
    }

    /// Processes the vault after `change`, in the same step, and returns the reaction's records.
    pub fn vault(&mut self, change: impl FnOnce(&mut GroundTruth)) -> Result<Vec<Record>, String> {
        change(&mut self.world.rev.sod.truth);
        self.world.sync()
    }

    /// The reference state of `proposal`.
    pub fn state(&self, proposal: ProposalId) -> Option<StateTag> {
        self.world.life.state_of(proposal)
    }

    /// Moves `now` to `t`.
    pub fn at(&mut self, t: Timestamp) {
        self.world.set_now(t);
    }

    /// Submits `proposal` before the call deadline.
    pub fn submit(&mut self, lead: AccountId, proposal: ProposalId) -> Result<(), String> {
        self.run(&submit(lead, proposal, plan_of(proposal), false))?;
        Ok(())
    }

    /// Submits `proposal` unless it already is, then assigns `reviewers`, who declare no
    /// conflict, declares the coordinator clear and records a passed
    /// knock-out check, from [`T_EVAL`] on.
    pub fn checked(
        &mut self,
        lead: AccountId,
        proposal: ProposalId,
        reviewers: &[AccountId],
    ) -> Result<(), String> {
        if self.state(proposal) == Some(StateTag::Draft) {
            self.submit(lead, proposal)?;
        }
        self.at(T_EVAL);
        for r in reviewers {
            for s in assign_declared(*r, proposal, call(1), AssignmentKind::Reviewer) {
                self.run(&s)?;
            }
        }
        self.run(&declare(
            COORDINATOR,
            DeclarationSubject::Proposal(proposal),
            false,
            false,
        ))?;
        self.run(&knock_out(proposal, true))?;
        Ok(())
    }

    /// [`Story::checked`], then the admission to STAGE1.
    pub fn to_stage1(
        &mut self,
        lead: AccountId,
        proposal: ProposalId,
        reviewers: &[AccountId],
    ) -> Result<(), String> {
        self.checked(lead, proposal, reviewers)?;
        self.run(&admit(proposal))?;
        Ok(())
    }

    /// Stage 1 scores of `vectors` by `reviewers` on the submitted plan of `proposal`.
    pub fn score_stage1(
        &mut self,
        proposal: ProposalId,
        reviewers: &[AccountId],
        vectors: &[Vec<u8>],
    ) -> Result<(), String> {
        for (r, v) in reviewers.iter().zip(vectors) {
            let key = ScoreKey {
                assignment: assignment_of(*r, proposal, call(1), AssignmentKind::Reviewer),
                stage: Stage::One,
                plan: plan_of(proposal),
            };
            self.run(&score(*r, key, v))?;
        }
        Ok(())
    }

    /// [`Story::to_stage1`], the stage 1 scores and the coordinator's close.
    /// Returns the close's records.
    pub fn closed(
        &mut self,
        lead: AccountId,
        proposal: ProposalId,
        reviewers: &[AccountId],
        vectors: &[Vec<u8>],
    ) -> Result<Vec<Record>, String> {
        self.to_stage1(lead, proposal, reviewers)?;
        self.score_stage1(proposal, reviewers, vectors)?;
        self.run(&close(Actor::Account(COORDINATOR), proposal))
    }

    /// Every reviewer of `reviewers` records "no questions" on `proposal`
    /// through its assignment in the current call.
    pub fn no_questions(
        &mut self,
        proposal: ProposalId,
        reviewers: &[AccountId],
    ) -> Result<Vec<Record>, String> {
        let mut out = Vec::new();
        for r in reviewers {
            let id = self
                .world
                .assignment(*r, proposal, Stage::Two, AssignmentKind::Reviewer)
                .ok_or("no stage 2 assignment")?;
            out.extend(self.run(&no_questions(*r, proposal, id))?);
        }
        Ok(out)
    }

    /// [`Story::closed`] and "no questions" by every reviewer, which ranks the proposal.
    pub fn ranked(
        &mut self,
        lead: AccountId,
        proposal: ProposalId,
        reviewers: &[AccountId],
        vectors: &[Vec<u8>],
    ) -> Result<(), String> {
        self.closed(lead, proposal, reviewers, vectors)?;
        self.no_questions(proposal, reviewers)?;
        Ok(())
    }
}
