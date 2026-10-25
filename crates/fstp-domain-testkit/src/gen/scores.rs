//! Generators for scores, with synthetic data only (design section 6.1).
//!
//! Owned by lane L-SCORE (docs/handoff/m2-design.md section 10).
//!
//! - [`Script`] is a list of raw ledger records with their sequence numbers
//!   and times. The I-07 reference reads these records directly. A
//!   production adapter folds them into a state through the public
//!   structural `apply` ([`Script::fold`]), never through commands.
//! - [`stage1_case`] draws P-01 criteria, reviewer score vectors and a P-02
//!   threshold. It favours cases whose score equals P-02 exactly (I-08).
//! - [`two_programme_case`] draws two P-01 weight vectors and one set of
//!   reviewer inputs that the weights must tell apart (R-PC-01).
//! - [`quorum_case`] draws assignments, scores, corrections, voids,
//!   conflicts and releases around the P-03 boundary (I-07).
//! - [`effective_case`] draws an original plan score and zero to three
//!   revisions, and favours ties (I-09, P-24).
//!
//! Every id and account is a small synthetic number. No record holds text,
//! only [`TextRef`] values with synthetic digests.

use std::collections::{BTreeMap, BTreeSet};
use std::num::{NonZeroU8, NonZeroU16, NonZeroU64};

use fstp_domain::assignment::{AssignmentKind, ReleaseCause};
use fstp_domain::command::{Actor, KnockOutResult, SystemCause};
use fstp_domain::id::{
    AccountId, AmendmentId, AssignmentId, CallId, CallSeq, ContentDigest, CriterionId, DecisionId,
    KnockOutCriterionId, LlmConfigId, MilestoneId, OrganisationId, PlanVersionId, PolicyVersionId,
    ProgrammeId, ProposalId, TextId, TextRef, VaultEpoch,
};
use fstp_domain::oracle::{Answer, Answers, Query};
use fstp_domain::policy::{
    EffectiveScoreRule, ExclusionClasses, FrozenValues, FunderProfileRef, InferenceBinding,
    IrcExemptions, KnockOutCriteria, KnockOutCriterion, LicenceSet, LiveValues, McpBindingActions,
    ModelRef, OpaqueValue, PolicyVersion, ProximityLists, ReadAccess, ReviewerAnonymity, SpdxId,
    TieBreakRule, VotingRules,
};
use fstp_domain::proposal::{
    EthicsDeclaration, Milestone, NoticeVersion, PlanOrigin, ReentryStage, Task,
};
use fstp_domain::record::{
    Assigned, AssignmentReleased, BindingGranted, ConflictDeclared, ConflictDetected, Declared,
    PlanVersionRecorded, Record, RulesVersion, ScoreRecorded, ScoreVoided, Transitioned,
};
use fstp_domain::roles::{BindingScope, CoolingOff, Role};
use fstp_domain::rules::{Row, StateTag};
use fstp_domain::scoring::{Criteria, Criterion, ScoreKey, ScoreVector, Stage, VoidCause};
use fstp_domain::state::State;
use fstp_domain::time::{Days, Timestamp, ZoneName};
use fstp_ledger::Seq;
use fstp_money::{Amount, AmountRange, Currency, NonNegAmount, Percent, PosAmount, Ratio};
use fstp_prop::Gen;

use crate::harness::teeth::inject;

// ---------------------------------------------------------------------------
// Fixed synthetic accounts
// ---------------------------------------------------------------------------

/// The tenant admin who creates programmes and grants Judging roles.
pub const ADMIN: AccountId = AccountId::from_raw(1);
/// The programme manager who approves publication (R-PC-03).
pub const MANAGER: AccountId = AccountId::from_raw(2);
/// The call drafter, distinct from the approving manager.
pub const DRAFTER: AccountId = AccountId::from_raw(3);
/// The FSTP coordinator who records the knock-out check and assigns.
pub const COORDINATOR: AccountId = AccountId::from_raw(4);

/// The account of reviewer number `n`, from 1000 upwards.
pub fn reviewer(n: u8) -> AccountId {
    AccountId::from_raw(1000_u128.saturating_add(u128::from(n)))
}

// ---------------------------------------------------------------------------
// Fixtures and scripts
// ---------------------------------------------------------------------------

/// The ids and P-01, P-02 and P-03 values of one programme, call and proposal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fixture {
    /// The programme.
    pub programme: ProgrammeId,
    /// The policy version frozen at publication.
    pub policy: PolicyVersionId,
    /// The call.
    pub call: CallId,
    /// The scored proposal.
    pub proposal: ProposalId,
    /// Its submitted, original plan.
    pub plan: PlanVersionId,
    /// Its lead.
    pub lead: AccountId,
    /// The P-01 scale maximum N.
    pub scale_max: u8,
    /// The P-01 weights, in criterion order.
    pub weights: Vec<u16>,
    /// The P-02 threshold in basis points.
    pub p02_bp: u16,
    /// The P-03 minimum.
    pub p03: u8,
}

impl Fixture {
    /// Fixture number `n`: every id is derived from `n`, so two fixtures
    /// with different numbers never share an id.
    pub fn numbered(n: u8, scale_max: u8, weights: Vec<u16>, p02_bp: u16, p03: u8) -> Fixture {
        let base = u128::from(n).saturating_mul(1_000_000);
        Fixture {
            programme: ProgrammeId::from_raw(base.saturating_add(1)),
            policy: PolicyVersionId::from_raw(base.saturating_add(2)),
            call: CallId::from_raw(base.saturating_add(3)),
            proposal: ProposalId::from_raw(base.saturating_add(4)),
            plan: PlanVersionId::from_raw(base.saturating_add(5)),
            lead: AccountId::from_raw(base.saturating_add(6)),
            scale_max,
            weights,
            p02_bp,
            p03,
        }
    }

    /// The checked P-01 value of this fixture.
    pub fn criteria(&self) -> Result<Criteria, String> {
        let scale = NonZeroU8::new(self.scale_max).ok_or("P-01 scale maximum 0")?;
        let mut items = Vec::new();
        for (i, w) in self.weights.iter().enumerate() {
            let weight = NonZeroU16::new(*w).ok_or("P-01 weight 0")?;
            let id = CriterionId::from_raw(u128::try_from(i).map_err(|e| e.to_string())?);
            items.push(Criterion { id, weight });
        }
        Criteria::new(scale, items).map_err(|e| e.to_string())
    }
}

/// One entry of a [`Script`]: sequence number, time and record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScriptEntry {
    /// The sequence number, from 1 without gaps.
    pub seq: Seq,
    /// The entry time.
    pub at: Timestamp,
    /// The record.
    pub record: Record,
}

/// Raw ledger records that a scenario needs, built without commands.
///
/// The I-07 reference reads [`Script::records`]. A production adapter folds
/// the same records with [`Script::fold`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Script {
    entries: Vec<ScriptEntry>,
    epoch: VaultEpoch,
    next_id: u128,
    leads: BTreeMap<ProposalId, AccountId>,
    assigned: Vec<(AssignmentId, ProposalId, AccountId)>,
}

impl Default for Script {
    fn default() -> Script {
        Script::new()
    }
}

/// The time of the first script entry, in microseconds.
const SCRIPT_START: i64 = 1_000_000;
/// The time between two script entries, in microseconds.
const SCRIPT_STEP: i64 = 1_000;
/// The call deadline: far after every script entry.
const DEADLINE: i64 = 1_000_000_000_000_000;

impl Script {
    /// An empty script at vault epoch 0.
    pub fn new() -> Script {
        Script {
            entries: Vec::new(),
            epoch: VaultEpoch::GENESIS,
            next_id: 900_000_000,
            leads: BTreeMap::new(),
            assigned: Vec::new(),
        }
    }

    /// The entries, in order.
    pub fn entries(&self) -> &[ScriptEntry] {
        &self.entries
    }

    /// The records, in order.
    pub fn records(&self) -> Vec<Record> {
        self.entries.iter().map(|e| e.record.clone()).collect()
    }

    /// The last vault epoch processed by the script.
    pub fn epoch(&self) -> VaultEpoch {
        self.epoch
    }

    /// The time of the last entry, or the start time when there is none.
    pub fn now(&self) -> Timestamp {
        self.entries
            .last()
            .map_or(Timestamp::from_micros(SCRIPT_START), |e| e.at)
    }

    /// Appends `record` as the next entry and returns its sequence number.
    pub fn push(&mut self, record: Record) -> Result<Seq, String> {
        let n = u64::try_from(self.entries.len())
            .ok()
            .and_then(|n| n.checked_add(1))
            .ok_or("script too long")?;
        let offset = i64::try_from(n)
            .ok()
            .and_then(|n| n.checked_mul(SCRIPT_STEP))
            .and_then(|d| d.checked_add(SCRIPT_START))
            .ok_or("script time overflow")?;
        let seq = Seq::from_raw(n);
        if let Record::VaultEpochProcessed { epoch } = &record {
            self.epoch = *epoch;
        }
        self.entries.push(ScriptEntry {
            seq,
            at: Timestamp::from_micros(offset),
            record,
        });
        Ok(seq)
    }

    /// A fresh synthetic id value, never used by a fixture.
    pub fn fresh(&mut self) -> u128 {
        self.next_id = self.next_id.saturating_add(1);
        self.next_id
    }

    /// A text reference with a synthetic digest.
    pub fn text(&mut self) -> TextRef {
        let id = self.fresh();
        let byte = u8::try_from(id.checked_rem(251).unwrap_or(0)).unwrap_or(0);
        TextRef::new(TextId::from_raw(id), ContentDigest::from_bytes([byte; 32]))
    }

    /// Folds every entry into a state from genesis through the public
    /// structural `apply`, with the teeth `inject` helper. The error names
    /// the first entry the fold refused.
    pub fn fold(&self) -> Result<State, String> {
        let mut state = State::genesis();
        for e in &self.entries {
            inject(&mut state, e.seq, e.at, &e.record).map_err(|err| {
                format!(
                    "the fold refused entry {} ({}): {err}",
                    e.seq.raw(),
                    record_name(&e.record)
                )
            })?;
        }
        Ok(state)
    }

    /// Vault answers that every account assigned to `proposal` has no
    /// conflict with its team, at the script's epoch. Conflicts in these
    /// scenarios are recorded facts, never vault answers.
    pub fn no_conflict_answers(&self, proposal: ProposalId) -> Answers {
        let mut answers = Answers::new();
        let Some(lead) = self.leads.get(&proposal) else {
            return answers;
        };
        let team: BTreeSet<AccountId> = [*lead].into_iter().collect();
        for (_, p, account) in &self.assigned {
            if *p == proposal {
                answers.insert(
                    Query::HasConflict {
                        reviewer: *account,
                        team: team.clone(),
                    },
                    Answer {
                        holds: false,
                        accounts: None,
                        epoch: self.epoch,
                        digest: ContentDigest::from_bytes([0; 32]),
                    },
                );
            }
        }
        answers
    }

    /// The programme, its policy version, a call, its approval and its
    /// publication, with the manager, drafter and coordinator bindings.
    pub fn open_programme(&mut self, fx: &Fixture) -> Result<(), String> {
        self.push(Record::ProgrammeCreated {
            programme: fx.programme,
            currency: Currency::Eur,
            by: ADMIN,
        })?;
        let version = policy_version(self, fx)?;
        self.push(Record::PolicyVersionRecorded {
            version: Box::new(version),
            author: MANAGER,
        })?;
        for (account, role) in [
            (MANAGER, Role::ProgrammeManager),
            (DRAFTER, Role::CallDrafter),
            (COORDINATOR, Role::FstpCoordinator),
        ] {
            self.bind(fx, account, role, BindingScope::Programme)?;
        }
        self.publish_call(fx, fx.call, CallSeq::FIRST)
    }

    /// Call `call` of the programme of `fx`, drafted, approved and
    /// published as number `seq` under the policy version of `fx`.
    pub fn publish_call(&mut self, fx: &Fixture, call: CallId, seq: CallSeq) -> Result<(), String> {
        let text = self.text();
        let budget = eur(100_000_000)?;
        self.push(Record::CallDrafted {
            call,
            programme: fx.programme,
            opens: Timestamp::from_micros(0),
            deadline: Timestamp::from_micros(DEADLINE),
            deadline_zone: ZoneName::new("Europe/Brussels").ok_or("zone name")?,
            budget,
            text,
            author: DRAFTER,
        })?;
        let decision = DecisionId::from_raw(self.fresh());
        self.push(Record::CallApproved {
            call,
            decision,
            approver: MANAGER,
        })?;
        let config = LlmConfigId::from_raw(self.fresh());
        self.push(Record::CallPublished {
            call,
            policy: fx.policy,
            seq,
            config,
            by: MANAGER,
        })?;
        Ok(())
    }

    /// A programme-scoped or proposal-scoped binding of `account`.
    pub fn bind(
        &mut self,
        fx: &Fixture,
        account: AccountId,
        role: Role,
        scope: BindingScope,
    ) -> Result<(), String> {
        let binding = fstp_domain::id::BindingId::from_raw(self.fresh());
        let confidentiality = Some(self.text());
        let organisation = match role {
            Role::CommitteeMember => Some(OrganisationId::from_raw(account.raw())),
            _ => None,
        };
        let start = self.now();
        self.push(Record::BindingGranted(BindingGranted {
            binding,
            account,
            programme: fx.programme,
            role,
            scope,
            start,
            granted_by: if role == Role::Applicant {
                account
            } else {
                ADMIN
            },
            second_admin: None,
            confidentiality,
            organisation,
            verified_epoch: Some(self.epoch),
        }))?;
        Ok(())
    }

    /// A committee member binding for each account in `reviewers`.
    pub fn bind_reviewers(&mut self, fx: &Fixture, reviewers: &[AccountId]) -> Result<(), String> {
        for r in reviewers {
            self.bind(fx, *r, Role::CommitteeMember, BindingScope::Programme)?;
        }
        Ok(())
    }

    /// The proposal of `fx` with its lead binding, original plan,
    /// submission, knock-out check and admission to STAGE1.
    pub fn submit_proposal(&mut self, fx: &Fixture) -> Result<(), String> {
        self.submit(fx, fx.proposal, fx.plan, fx.lead)
    }

    /// A proposal of the call of `fx` taken to STAGE1, with these ids.
    pub fn submit(
        &mut self,
        fx: &Fixture,
        proposal: ProposalId,
        plan: PlanVersionId,
        lead: AccountId,
    ) -> Result<(), String> {
        self.push(Record::ProposalCreated {
            proposal,
            call: fx.call,
            lead,
            minor: false,
        })?;
        self.leads.insert(proposal, lead);
        self.bind(
            fx,
            lead,
            Role::Applicant,
            BindingScope::Proposal {
                proposal,
                call: fx.call,
            },
        )?;
        self.plan(proposal, plan, PlanOrigin::Submitted, None)?;
        let text = self.text();
        self.push(Record::Submitted {
            proposal,
            plan,
            ethics: EthicsDeclaration {
                issues_declared: false,
                text,
            },
            notice: NoticeVersion(1),
        })?;
        self.transition(
            proposal,
            StateTag::Draft,
            StateTag::Submitted,
            Row::DraftToSubmitted,
            Actor::Account(lead),
            None,
        )?;
        let decision = DecisionId::from_raw(self.fresh());
        self.push(Record::KnockOutRecorded {
            decision,
            proposal,
            coordinator: COORDINATOR,
            outcomes: vec![KnockOutResult {
                criterion: KnockOutCriterionId::from_raw(1),
                passed: true,
            }],
            reason: None,
            rules: RulesVersion::M2,
        })?;
        self.transition(
            proposal,
            StateTag::Submitted,
            StateTag::Stage1,
            Row::SubmittedToStage1,
            Actor::Account(COORDINATOR),
            Some(decision),
        )?;
        Ok(())
    }

    /// A plan version of `proposal` with one task and one milestone.
    pub fn plan(
        &mut self,
        proposal: ProposalId,
        plan: PlanVersionId,
        origin: PlanOrigin,
        supersedes: Option<PlanVersionId>,
    ) -> Result<(), String> {
        let milestone = Milestone {
            id: MilestoneId::from_raw(self.fresh()),
            amount: PosAmount::new(eur(1_000_000)?.amount()).map_err(|e| e.to_string())?,
            start: Timestamp::from_micros(DEADLINE),
            due: Timestamp::from_micros(DEADLINE.saturating_mul(2)),
            activity: None,
            deliverables: Vec::new(),
        };
        let digest = ContentDigest::from_bytes([7; 32]);
        self.push(Record::PlanVersionRecorded(PlanVersionRecorded {
            plan,
            proposal,
            origin,
            supersedes,
            tasks: vec![Task {
                milestones: vec![milestone],
            }],
            content: digest,
        }))?;
        Ok(())
    }

    /// A proposal state transition record.
    pub fn transition(
        &mut self,
        proposal: ProposalId,
        from: StateTag,
        to: StateTag,
        row: Row,
        actor: Actor,
        decision: Option<DecisionId>,
    ) -> Result<(), String> {
        self.push(Record::Transitioned(Transitioned {
            proposal,
            from,
            to,
            row,
            actor,
            decision,
        }))?;
        Ok(())
    }

    /// A reviewer assignment of `account` to `proposal` in the call of
    /// `fx`, followed by the reviewer's no-conflict declaration (R-CF-02).
    pub fn assign(
        &mut self,
        fx: &Fixture,
        proposal: ProposalId,
        assignment: AssignmentId,
        account: AccountId,
    ) -> Result<(), String> {
        self.assign_as(
            fx.call,
            proposal,
            assignment,
            account,
            AssignmentKind::Reviewer,
            true,
        )
    }

    /// An assignment of `kind` of `account` to `proposal` in `call`. With
    /// `declare`, the assignee's no-conflict declaration follows at once.
    /// Without it, the assignment awaits its declaration and is not
    /// active yet (design section 2.7).
    pub fn assign_as(
        &mut self,
        call: CallId,
        proposal: ProposalId,
        assignment: AssignmentId,
        account: AccountId,
        kind: AssignmentKind,
        declare: bool,
    ) -> Result<(), String> {
        let epoch = self.epoch;
        self.push(Record::Assigned(Assigned {
            assignment,
            proposal,
            call,
            reviewer: account,
            kind,
            handle: None,
            by: COORDINATOR,
            epoch,
        }))?;
        self.assigned.push((assignment, proposal, account));
        if declare {
            self.declare(assignment)?;
        }
        Ok(())
    }

    /// The assignee's no-conflict declaration on `assignment` (R-CF-02).
    pub fn declare(&mut self, assignment: AssignmentId) -> Result<(), String> {
        self.push(Record::ConflictDeclared(ConflictDeclared {
            subject: Declared::Assignment(assignment),
            conflicted: false,
            notifiable: false,
        }))?;
        Ok(())
    }

    /// A score, or a correction of the entry `supersedes`.
    pub fn score(
        &mut self,
        key: ScoreKey,
        values: Vec<u8>,
        supersedes: Option<Seq>,
    ) -> Result<Seq, String> {
        let reason = supersedes.map(|_| self.text());
        self.push(Record::ScoreRecorded(ScoreRecorded {
            key,
            values: ScoreVector(values),
            supersedes,
            reason,
        }))
    }
}

/// A short name of a record's kind, for messages.
pub fn record_name(record: &Record) -> String {
    let full = format!("{record:?}");
    full.split(['(', ' ', '{'])
        .next()
        .unwrap_or("record")
        .to_owned()
}

/// `minor` euro cents as a non-negative amount.
fn eur(minor: i64) -> Result<NonNegAmount, String> {
    let a = Amount::from_minor(minor, Currency::Eur).map_err(|e| e.to_string())?;
    NonNegAmount::new(a).map_err(|e| e.to_string())
}

/// An opaque frozen value with synthetic content.
fn opaque(label: &str) -> Result<OpaqueValue, String> {
    OpaqueValue::from_value(&fstp_json::Value::String(label.to_owned()))
        .map_err(|e| format!("{e:?}"))
}

/// A complete policy version for `fx`, with the SuperSAFE defaults where
/// the scoring tests do not vary a value.
fn policy_version(script: &mut Script, fx: &Fixture) -> Result<PolicyVersion, String> {
    let p02 = Percent::from_bp(fx.p02_bp).ok_or("P-02 above 100.00")?;
    let p03 = NonZeroU8::new(fx.p03).ok_or("P-03 of 0")?;
    let knock_out_text = script.text();
    let frozen = FrozenValues {
        p01: fx.criteria()?,
        p02,
        p03,
        p04: AmountRange::new(eur(500_000)?, eur(10_000_000)?).map_err(|e| e.to_string())?,
        p07: Days::new(28),
        p09: KnockOutCriteria(vec![KnockOutCriterion {
            id: KnockOutCriterionId::from_raw(1),
            text: knock_out_text,
        }]),
        p10: ReadAccess::AssignedReviewersOnly,
        p11: ReviewerAnonymity::Named,
        p14: IrcExemptions(opaque("p14")?),
        p15: NonZeroU8::MIN,
        p16: VotingRules(opaque("p16")?),
        p17: TieBreakRule(opaque("p17")?),
        p21: InferenceBinding {
            provider: opaque("synthetic-provider")?,
            primary: ModelRef("synthetic-model".to_owned()),
            fallbacks: Vec::new(),
        },
        p24: EffectiveScoreRule::HigherOfOriginalAndRevised,
        p26: LicenceSet([SpdxId("MIT".to_owned())].into_iter().collect()),
        p39: NonZeroU8::MIN,
        p53: FunderProfileRef(opaque("p53")?),
        p77: McpBindingActions::DraftOnly,
        opaque: BTreeMap::new(),
    };
    let live = LiveValues {
        p05: eur(40_000_000)?,
        p12: CoolingOff(1),
        p13: ExclusionClasses(BTreeSet::new()),
        p38: ProximityLists(BTreeMap::new()),
        p56: None,
        p58: None,
        opaque: BTreeMap::new(),
    };
    Ok(PolicyVersion {
        id: fx.policy,
        programme: fx.programme,
        parent: None,
        currency: Currency::Eur,
        frozen,
        live,
    })
}

// ---------------------------------------------------------------------------
// I-08: stage 1 cases
// ---------------------------------------------------------------------------

/// P-01 criteria, every reviewer's complete score vector and P-02 (NOTE 6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stage1Case {
    /// The scale maximum N, from 1 to 100.
    pub scale_max: u8,
    /// One weight per criterion, from 1 to 1000, 1 to 16 criteria.
    pub weights: Vec<u16>,
    /// One vector per reviewer, one value per criterion, each 0 to N. It
    /// is the reviewer's current value.
    pub vectors: Vec<Vec<u8>>,
    /// Per reviewer, an earlier complete vector that the reviewer recorded
    /// first and then corrected to its entry in `vectors`, or `None`. A
    /// missing entry is `None`. Only the current value counts (NOTE 3).
    pub earlier: Vec<Option<Vec<u8>>>,
    /// P-02 in basis points.
    pub p02_bp: u16,
}

/// Scale maxima that divide 10 000, so a uniform score can equal P-02 exactly.
const EXACT_SCALES: [u8; 9] = [1, 2, 4, 5, 10, 20, 25, 50, 100];

/// A stage 1 case. About half the cases have a score exactly equal to
/// P-02, and most others lie one basis point either side of it.
pub fn stage1_case(g: &mut Gen) -> Stage1Case {
    let shape = g.weighted(&[3, 2, 4]);
    let scale_max = match shape {
        0 => *g.pick(&EXACT_SCALES),
        1 => 4,
        _ => g.u8_in(1..=100),
    };
    let weights = match shape {
        1 => vec![30, 40, 30],
        _ => g.vec(1..=16, |g| g.u16_in(1..=1000)),
    };
    let reviewers = if g.weighted(&[15, 1]) == 0 {
        g.usize_in(1..=6)
    } else {
        g.usize_in(1..=64)
    };
    let uniform = g.bool();
    let vectors = if uniform {
        let v = g.u8_in(0..=scale_max);
        vec![vec![v; weights.len()]; reviewers]
    } else {
        let n = weights.len();
        (0..reviewers)
            .map(|_| (0..n).map(|_| g.u8_in(0..=scale_max)).collect())
            .collect()
    };
    let p02_bp = near_threshold(g, scale_max, &weights, &vectors);
    let earlier = if g.bool() {
        vectors
            .iter()
            .map(|v| g.bool().then(|| other_vector(g, v, scale_max)))
            .collect()
    } else {
        Vec::new()
    };
    Stage1Case {
        scale_max,
        weights,
        vectors,
        earlier,
        p02_bp,
    }
}

/// A complete vector on the scale 0 to `scale_max` that differs from `v`.
/// At least one value differs, so a correction always changes the vector.
fn other_vector(g: &mut Gen, v: &[u8], scale_max: u8) -> Vec<u8> {
    let mut out: Vec<u8> = v.iter().map(|_| g.u8_in(0..=scale_max)).collect();
    if out.as_slice() == v {
        let i = g.usize_in(0..=v.len().saturating_sub(1));
        if let Some(s) = out.get_mut(i) {
            *s = if *s < scale_max {
                s.saturating_add(1)
            } else {
                s.saturating_sub(1)
            };
        }
    }
    out
}

/// A P-02 value near the exact score: equal to it when the score is a
/// whole number of basis points, else just below or just above. Some
/// cases draw any value, so the far ranges stay covered.
fn near_threshold(g: &mut Gen, scale_max: u8, weights: &[u16], vectors: &[Vec<u8>]) -> u16 {
    let any = g.u16_in(0..=Percent::MAX_BP);
    let Some((num, den)) = raw_score(scale_max, weights, vectors) else {
        return any;
    };
    // floor(score * 10 000) and whether the product is a whole number.
    let scaled = num.saturating_mul(u128::from(Percent::MAX_BP));
    let floor = scaled.checked_div(den).unwrap_or(0);
    let exact = scaled.checked_rem(den) == Some(0);
    let floor = u16::try_from(floor).unwrap_or(Percent::MAX_BP);
    match g.weighted(&[6, 2, 2, 1]) {
        0 if exact => floor,
        0 | 1 => floor.saturating_sub(1),
        2 => floor.saturating_add(1).min(Percent::MAX_BP),
        _ => any,
    }
}

/// The unreduced score fraction, computed reviewer by reviewer. Used only
/// to steer P-02 towards equality, never as the reference.
fn raw_score(scale_max: u8, weights: &[u16], vectors: &[Vec<u8>]) -> Option<(u128, u128)> {
    let mut num: u128 = 0;
    for v in vectors {
        for (w, s) in weights.iter().zip(v) {
            num = num.checked_add(u128::from(*w).checked_mul(u128::from(*s))?)?;
        }
    }
    let wsum = weights
        .iter()
        .try_fold(0_u128, |a, w| a.checked_add(u128::from(*w)))?;
    let r = u128::try_from(vectors.len()).ok()?;
    let den = r.checked_mul(u128::from(scale_max))?.checked_mul(wsum)?;
    (den > 0).then_some((num, den))
}

/// The records of a stage 1 case: one programme, a proposal in STAGE1,
/// one assignment per vector, and one current score per assignment on the
/// original plan. A reviewer with an earlier vector records it first and
/// then corrects it, with `supersedes` set. The corrections follow every
/// first score. A fold that keeps the first value of a key then scores the
/// earlier vectors. P-03 is 1, so every case has a quorum.
pub fn stage1_script(case: &Stage1Case) -> Result<(Fixture, Script), String> {
    let fx = Fixture::numbered(1, case.scale_max, case.weights.clone(), case.p02_bp, 1);
    let mut script = Script::new();
    script.open_programme(&fx)?;
    let reviewers = reviewers_for(case.vectors.len())?;
    script.bind_reviewers(&fx, &reviewers)?;
    script.submit_proposal(&fx)?;
    let mut corrections: Vec<(ScoreKey, Seq, Vec<u8>)> = Vec::new();
    for (i, (r, v)) in reviewers.iter().zip(&case.vectors).enumerate() {
        let assignment = AssignmentId::from_raw(script.fresh());
        script.assign(&fx, fx.proposal, assignment, *r)?;
        let key = ScoreKey {
            assignment,
            stage: Stage::One,
            plan: fx.plan,
        };
        match case.earlier.get(i).cloned().flatten() {
            Some(e) => {
                let first = script.score(key, e, None)?;
                corrections.push((key, first, v.clone()));
            }
            None => {
                script.score(key, v.clone(), None)?;
            }
        }
    }
    for (key, first, v) in corrections {
        script.score(key, v, Some(first))?;
    }
    Ok((fx, script))
}

/// Reviewer accounts 0 to `n - 1`.
fn reviewers_for(n: usize) -> Result<Vec<AccountId>, String> {
    let n = u8::try_from(n).map_err(|_| "more than 255 reviewers".to_owned())?;
    Ok((0..n).map(reviewer).collect())
}

// ---------------------------------------------------------------------------
// R-PC-01: two programmes
// ---------------------------------------------------------------------------

/// Two programmes with different P-01 weights and identical reviewer inputs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TwoProgrammeCase {
    /// The scale maximum N of both programmes.
    pub scale_max: u8,
    /// The weights of programme A.
    pub weights_a: Vec<u16>,
    /// The weights of programme B.
    pub weights_b: Vec<u16>,
    /// The reviewer inputs, identical in both programmes.
    pub vectors: Vec<Vec<u8>>,
    /// P-02 of both programmes, in basis points.
    pub p02_bp: u16,
}

/// A two-programme case whose inputs discriminate the two weightings.
///
/// Programme B swaps the weights of two criteria `i` and `j` with unequal
/// weights, and the reviewers' score totals on `i` and `j` differ. Both
/// programmes then have the same denominator, and the numerators differ
/// by `(w_i - w_j) * (S_i - S_j)`, which is not zero. The R-PC-01 AC is
/// false for inputs whose criterion scores are all equal, so the
/// generator never draws them (design section 6.2).
pub fn two_programme_case(g: &mut Gen) -> TwoProgrammeCase {
    let scale_max = if g.bool() { 4 } else { g.u8_in(1..=100) };
    let n = g.usize_in(2..=16);
    let mut weights_a: Vec<u16> = (0..n).map(|_| g.u16_in(1..=1000)).collect();
    let i = g.usize_in(0..=n.saturating_sub(1));
    let j = loop_other(g, i, n);
    if weights_a.get(i) == weights_a.get(j) {
        let wi = weights_a.get(i).copied().unwrap_or(1);
        if let Some(w) = weights_a.get_mut(j) {
            *w = if wi < 1000 {
                wi.saturating_add(1)
            } else {
                wi.saturating_sub(1)
            };
        }
    }
    let reviewers = g.usize_in(1..=6);
    let mut vectors: Vec<Vec<u8>> = (0..reviewers)
        .map(|_| (0..n).map(|_| g.u8_in(0..=scale_max)).collect())
        .collect();
    let total = |vs: &[Vec<u8>], c: usize| -> u32 {
        vs.iter()
            .map(|v| u32::from(v.get(c).copied().unwrap_or(0)))
            .fold(0_u32, u32::saturating_add)
    };
    if total(&vectors, i) == total(&vectors, j) {
        let r = g.usize_in(0..=reviewers.saturating_sub(1));
        if let Some(s) = vectors.get_mut(r).and_then(|v| v.get_mut(i)) {
            *s = if *s < scale_max {
                s.saturating_add(1)
            } else {
                s.saturating_sub(1)
            };
        }
    }
    let mut weights_b = weights_a.clone();
    weights_b.swap(i, j);
    let p02_bp = g.u16_in(0..=Percent::MAX_BP);
    TwoProgrammeCase {
        scale_max,
        weights_a,
        weights_b,
        vectors,
        p02_bp,
    }
}

/// An index in `0..n` other than `i`, for `n >= 2`.
fn loop_other(g: &mut Gen, i: usize, n: usize) -> usize {
    let k = g.usize_in(1..=n.saturating_sub(1));
    i.saturating_add(k).checked_rem(n).unwrap_or(0)
}

/// The records of a two-programme case in one tenant ledger: programme A
/// is fixture 1 and programme B fixture 2. The same reviewer accounts
/// score one proposal in each, with identical vectors.
pub fn two_programme_script(case: &TwoProgrammeCase) -> Result<(Fixture, Fixture, Script), String> {
    let a = Fixture::numbered(1, case.scale_max, case.weights_a.clone(), case.p02_bp, 1);
    let b = Fixture::numbered(2, case.scale_max, case.weights_b.clone(), case.p02_bp, 1);
    let mut script = Script::new();
    let reviewers = reviewers_for(case.vectors.len())?;
    for fx in [&a, &b] {
        script.open_programme(fx)?;
        script.bind_reviewers(fx, &reviewers)?;
        script.submit_proposal(fx)?;
        for (r, v) in reviewers.iter().zip(&case.vectors) {
            let assignment = AssignmentId::from_raw(script.fresh());
            script.assign(fx, fx.proposal, assignment, *r)?;
            let key = ScoreKey {
                assignment,
                stage: Stage::One,
                plan: fx.plan,
            };
            script.score(key, v.clone(), None)?;
        }
    }
    Ok((a, b, script))
}

// ---------------------------------------------------------------------------
// I-07: quorum cases
// ---------------------------------------------------------------------------

/// A scenario of assignments and score records, and the quorum asked for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuorumCase {
    /// The programme, call and proposal, with P-03.
    pub fixture: Fixture,
    /// The raw records.
    pub script: Script,
    /// The stage asked for.
    pub stage: Stage,
    /// The plan version asked for.
    pub plan: PlanVersionId,
}

/// One assignment to the scored proposal that the generator tracks.
#[derive(Clone, Debug)]
struct Live {
    assignment: AssignmentId,
    account: AccountId,
    call: CallId,
    kind: AssignmentKind,
    declared: bool,
    active: bool,
}

/// What the quorum generator knows about its own records.
struct Track {
    live: Vec<Live>,
    current: BTreeMap<ScoreKey, Seq>,
    conflicted: BTreeSet<AccountId>,
    pool: Vec<AccountId>,
    call: CallId,
    criteria: usize,
    scale_max: u8,
}

impl Track {
    /// A complete random score vector.
    fn vector(&self, g: &mut Gen) -> Vec<u8> {
        (0..self.criteria)
            .map(|_| g.u8_in(0..=self.scale_max))
            .collect()
    }

    /// The assignments not released, of every kind, call and declaration.
    fn active(&self) -> Vec<Live> {
        self.live.iter().filter(|l| l.active).cloned().collect()
    }

    /// Accounts of the pool with no conflict fact and no unreleased
    /// reviewer assignment in the current call.
    fn free(&self) -> Vec<AccountId> {
        self.pool
            .iter()
            .copied()
            .filter(|a| !self.conflicted.contains(a))
            .filter(|a| {
                !self.live.iter().any(|l| {
                    l.active
                        && l.account == *a
                        && l.call == self.call
                        && l.kind == AssignmentKind::Reviewer
                })
            })
            .collect()
    }

    /// The accounts behind the tracked assignments, each once.
    fn accounts(&self) -> Vec<AccountId> {
        self.live
            .iter()
            .map(|l| l.account)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }
}

/// A quorum case around the P-03 boundary.
///
/// - P-03 is drawn from 1 to 4. The initial assignments number P-03 minus
///   one to P-03 plus two.
/// - Operations: scores, corrections (which must never count twice),
///   unassignments, declared and detected conflicts, proposal-level
///   conflict declarations, reassignments, and noise scores on a second
///   proposal. Releases emit voids for the current stage only sometimes,
///   so a quorum that relies on voids alone is caught.
/// - Complaint remedy voids on an active, declared reviewer assignment,
///   sometimes followed by a fresh score on the same key. Only the void
///   excludes such a key, so a quorum that ignores voids is caught.
/// - Operations that commands never produce but the structural fold
///   accepts, so that each clause of a valid score is tested alone:
///   conflict facts that leave the assignment active, conflicts on
///   released assignments and on the noise proposal, reassignment of a
///   conflicted account, IRC and amendment assignments, assignments
///   awaiting their declaration, keys whose assignment belongs to the
///   noise proposal, and keys on the other stage.
/// - Half the cases enter stage 2 and rescore up to three revisions. Half
///   of those then defer, re-enter a second call with fresh assignments
///   and rescore once more. The first call's assignments stay unreleased,
///   so a stage 2 quorum that ignores the call counts them. A stage 1
///   quorum still counts them, since stage 1 ran in that call (NOTE 8).
/// - Stage 2 cases sometimes ask for a stage 2 quorum on the submitted
///   plan, with stage 2 scores on it. NOTE 4 scores only a revision, so
///   the expected outcome is a refusal.
pub fn quorum_case(g: &mut Gen) -> Result<QuorumCase, String> {
    let p03 = g.u8_in(1..=4);
    let scale_max = if g.bool() { 4 } else { g.u8_in(1..=10) };
    let weights = if g.bool() {
        vec![30, 40, 30]
    } else {
        g.vec(1..=4, |g| g.u16_in(1..=1000))
    };
    let fx = Fixture::numbered(1, scale_max, weights.clone(), 7_500, p03);
    let mut script = Script::new();
    script.open_programme(&fx)?;
    let pool = reviewers_for(7)?;
    script.bind_reviewers(&fx, &pool)?;
    script.submit_proposal(&fx)?;
    let noise = g.bool().then(|| {
        (
            ProposalId::from_raw(fx.proposal.raw().saturating_add(500)),
            PlanVersionId::from_raw(fx.plan.raw().saturating_add(500)),
            AccountId::from_raw(fx.lead.raw().saturating_add(500)),
        )
    });
    if let Some((p, plan, lead)) = noise {
        script.submit(&fx, p, plan, lead)?;
    }
    let mut t = Track {
        live: Vec::new(),
        current: BTreeMap::new(),
        conflicted: BTreeSet::new(),
        pool: pool.clone(),
        call: fx.call,
        criteria: weights.len(),
        scale_max,
    };
    let offset = g.usize_in(0..=3);
    let initial = usize::from(p03)
        .saturating_add(offset)
        .saturating_sub(1)
        .clamp(1, pool.len());
    for account in pool.iter().take(initial) {
        assign_live(
            &mut script,
            &mut t,
            &fx,
            *account,
            AssignmentKind::Reviewer,
            true,
        )?;
    }
    // Stage 1.
    let mut plan = fx.plan;
    run_ops(g, &mut script, &mut t, &fx, Stage::One, plan, noise)?;
    let mut revisions: Vec<PlanVersionId> = Vec::new();
    let stage2 = g.bool();
    if stage2 {
        script.transition(
            fx.proposal,
            StateTag::Stage1,
            StateTag::Stage2,
            Row::Stage1ToStage2,
            Actor::Account(COORDINATOR),
            None,
        )?;
        let count = g.usize_in(1..=3);
        for _ in 0..count {
            plan = revise(&mut script, &fx, plan)?;
            revisions.push(plan);
            run_ops(g, &mut script, &mut t, &fx, Stage::Two, plan, noise)?;
        }
        if g.bool() {
            reenter(g, &mut script, &mut t, &fx)?;
            plan = revise(&mut script, &fx, plan)?;
            revisions.push(plan);
            run_ops(g, &mut script, &mut t, &fx, Stage::Two, plan, noise)?;
        }
    }
    let (stage, target) = if stage2 {
        match g.weighted(&[3, 2, 1, 2]) {
            0 => (Stage::Two, plan),
            1 => (Stage::Two, *g.pick(&revisions)),
            2 => (Stage::Two, fx.plan),
            _ => (Stage::One, fx.plan),
        }
    } else {
        (Stage::One, fx.plan)
    };
    if (stage, target) == (Stage::Two, fx.plan) {
        // Stage 2 scores on the submitted plan from every unreleased
        // assignee, so a quorum that does not check the plan finds enough.
        for l in t.active() {
            let key = ScoreKey {
                assignment: l.assignment,
                stage: Stage::Two,
                plan: fx.plan,
            };
            score_key(g, &mut script, &mut t, key)?;
        }
    }
    Ok(QuorumCase {
        fixture: fx,
        script,
        stage,
        plan: target,
    })
}

/// A stage 2 revision of the scored proposal that supersedes `plan`.
fn revise(script: &mut Script, fx: &Fixture, plan: PlanVersionId) -> Result<PlanVersionId, String> {
    let next = PlanVersionId::from_raw(script.fresh());
    script.plan(fx.proposal, next, PlanOrigin::Stage2Revision, Some(plan))?;
    script.push(Record::RevisionSubmitted {
        proposal: fx.proposal,
        plan: next,
    })?;
    Ok(next)
}

/// A deferral from STAGE2 and a re-entry into a second call of the
/// programme, with one to four fresh reviewer assignments there (NOTE 8).
/// Fresh assignments often go to accounts that still hold an unreleased
/// assignment of the first call.
fn reenter(g: &mut Gen, script: &mut Script, t: &mut Track, fx: &Fixture) -> Result<(), String> {
    let next = CallId::from_raw(fx.call.raw().saturating_add(100));
    let seq = CallSeq::FIRST.next().ok_or("no second call number")?;
    script.publish_call(fx, next, seq)?;
    let system = Actor::System(SystemCause::Timeline);
    script.transition(
        fx.proposal,
        StateTag::Stage2,
        StateTag::Deferred,
        Row::Stage2ToDeferred,
        system,
        None,
    )?;
    script.push(Record::DeferralRecorded {
        proposal: fx.proposal,
        from_call: fx.call,
        left: ReentryStage::Stage2,
    })?;
    script.push(Record::ReEntered {
        proposal: fx.proposal,
        from_call: fx.call,
        to_call: next,
        stage: ReentryStage::Stage2,
    })?;
    script.transition(
        fx.proposal,
        StateTag::Deferred,
        StateTag::Stage2,
        Row::DeferredToStage2,
        system,
        None,
    )?;
    t.call = next;
    let count = g.usize_in(1..=4);
    for _ in 0..count {
        let free = t.free();
        if free.is_empty() {
            break;
        }
        let account = *g.pick(&free);
        assign_live(script, t, fx, account, AssignmentKind::Reviewer, true)?;
    }
    Ok(())
}

/// A new assignment of `account` to the scored proposal in the current
/// call, tracked as live.
fn assign_live(
    script: &mut Script,
    t: &mut Track,
    fx: &Fixture,
    account: AccountId,
    kind: AssignmentKind,
    declare: bool,
) -> Result<AssignmentId, String> {
    let assignment = AssignmentId::from_raw(script.fresh());
    script.assign_as(t.call, fx.proposal, assignment, account, kind, declare)?;
    t.live.push(Live {
        assignment,
        account,
        call: t.call,
        kind,
        declared: declare,
        active: true,
    });
    Ok(assignment)
}

/// One phase of quorum operations on `(stage, plan)`.
fn run_ops(
    g: &mut Gen,
    script: &mut Script,
    t: &mut Track,
    fx: &Fixture,
    stage: Stage,
    plan: PlanVersionId,
    noise: Option<(ProposalId, PlanVersionId, AccountId)>,
) -> Result<(), String> {
    // Often every unreleased assignee scores first, so the boundary is reached.
    if g.bool() {
        for l in t.active() {
            let key = ScoreKey {
                assignment: l.assignment,
                stage,
                plan,
            };
            score_key(g, script, t, key)?;
        }
    }
    let ops = g.usize_in(0..=12);
    for _ in 0..ops {
        match g.weighted(&[6, 4, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 1]) {
            0 => op_score(g, script, t, stage, plan)?,
            1 => op_correct(g, script, t, stage, plan)?,
            2 => op_release(g, script, t, stage, Release::Unassign)?,
            3 => op_release(g, script, t, stage, Release::Declare)?,
            4 => op_detect(g, script, t, fx, stage)?,
            5 => op_release(g, script, t, stage, Release::ProposalLevel)?,
            6 => op_reassign(g, script, t, fx)?,
            7 => op_noise(g, script, t, fx, noise)?,
            8 => op_conflict_kept(g, script, t, fx)?,
            9 => op_conflict_on_released(g, script, t)?,
            10 => op_noise_conflict(g, script, t, noise)?,
            11 => op_reassign_conflicted(g, script, t, fx)?,
            12 => op_other_kind(g, script, t, fx, stage, plan)?,
            13 => op_undeclared(g, script, t, fx, stage, plan)?,
            14 => op_declare_pending(g, script, t)?,
            15 => op_cross_proposal(g, script, t, fx, (stage, plan), noise)?,
            16 => op_void_kept(g, script, t, stage, plan)?,
            _ => op_off_stage(g, script, t, fx, stage, plan)?,
        }
    }
    Ok(())
}

/// A score on `key`, or a correction when the key has a current value.
fn score_key(g: &mut Gen, script: &mut Script, t: &mut Track, key: ScoreKey) -> Result<(), String> {
    let values = t.vector(g);
    let supersedes = t.current.get(&key).copied();
    let seq = script.score(key, values, supersedes)?;
    t.current.insert(key, seq);
    Ok(())
}

/// A first score by an unreleased assignee without a current value for the key.
fn op_score(
    g: &mut Gen,
    script: &mut Script,
    t: &mut Track,
    stage: Stage,
    plan: PlanVersionId,
) -> Result<(), String> {
    let candidates: Vec<Live> = t
        .active()
        .into_iter()
        .filter(|l| {
            !t.current.contains_key(&ScoreKey {
                assignment: l.assignment,
                stage,
                plan,
            })
        })
        .collect();
    if candidates.is_empty() {
        return Ok(());
    }
    let l = g.pick(&candidates).clone();
    let key = ScoreKey {
        assignment: l.assignment,
        stage,
        plan,
    };
    score_key(g, script, t, key)
}

/// A correction of a current score of an unreleased assignee on this stage and plan.
fn op_correct(
    g: &mut Gen,
    script: &mut Script,
    t: &mut Track,
    stage: Stage,
    plan: PlanVersionId,
) -> Result<(), String> {
    let candidates: Vec<ScoreKey> = t
        .current
        .keys()
        .filter(|k| k.stage == stage && k.plan == plan)
        .filter(|k| {
            t.live
                .iter()
                .any(|l| l.active && l.assignment == k.assignment)
        })
        .copied()
        .collect();
    if candidates.is_empty() {
        return Ok(());
    }
    let key = *g.pick(&candidates);
    score_key(g, script, t, key)
}

/// How an assignment is released.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Release {
    /// The coordinator unassigns the reviewer.
    Unassign,
    /// The reviewer declares a conflict on the assignment (R-CF-02).
    Declare,
    /// The reviewer's account declares a conflict on the proposal.
    ProposalLevel,
}

/// The release of one unreleased assignment, with its conflict record when
/// there is one, and voids of its current scores on this stage when the
/// generator draws them.
fn op_release(
    g: &mut Gen,
    script: &mut Script,
    t: &mut Track,
    stage: Stage,
    how: Release,
) -> Result<(), String> {
    let candidates = t.active();
    if candidates.is_empty() {
        return Ok(());
    }
    let l = g.pick(&candidates).clone();
    let (cause, void) = match how {
        Release::Unassign => (ReleaseCause::Unassigned, VoidCause::AssignmentReleased),
        Release::Declare => {
            script.push(Record::ConflictDeclared(ConflictDeclared {
                subject: Declared::Assignment(l.assignment),
                conflicted: true,
                notifiable: g.bool(),
            }))?;
            t.conflicted.insert(l.account);
            (ReleaseCause::DeclaredConflict, VoidCause::Conflict)
        }
        Release::ProposalLevel => {
            let proposal =
                proposal_of(script, l.assignment).ok_or("assignment without proposal")?;
            script.push(Record::ConflictDeclared(ConflictDeclared {
                subject: Declared::Proposal {
                    proposal,
                    account: l.account,
                },
                conflicted: true,
                notifiable: false,
            }))?;
            t.conflicted.insert(l.account);
            (ReleaseCause::DeclaredConflict, VoidCause::Conflict)
        }
    };
    release(g, script, t, &l, cause, void, stage)
}

/// A vault epoch and a detected conflict of `account` on `proposal` at it.
fn detect(
    g: &mut Gen,
    script: &mut Script,
    account: AccountId,
    proposal: ProposalId,
) -> Result<(), String> {
    let epoch = VaultEpoch::from_raw(script.epoch().raw().saturating_add(1));
    script.push(Record::VaultEpochProcessed { epoch })?;
    script.push(Record::ConflictDetected(ConflictDetected {
        account,
        proposal,
        notifiable: g.bool(),
        epoch,
    }))?;
    Ok(())
}

/// A detected conflict of one account that holds an assignment, past or
/// present, with the releases of its unreleased assignments.
fn op_detect(
    g: &mut Gen,
    script: &mut Script,
    t: &mut Track,
    fx: &Fixture,
    stage: Stage,
) -> Result<(), String> {
    let accounts: Vec<AccountId> = t
        .accounts()
        .into_iter()
        .filter(|a| !t.conflicted.contains(a))
        .collect();
    if accounts.is_empty() {
        return Ok(());
    }
    let account = *g.pick(&accounts);
    detect(g, script, account, fx.proposal)?;
    t.conflicted.insert(account);
    let affected: Vec<Live> = t
        .active()
        .into_iter()
        .filter(|l| l.account == account)
        .collect();
    for l in affected {
        release(
            g,
            script,
            t,
            &l,
            ReleaseCause::DetectedConflict,
            VoidCause::Conflict,
            stage,
        )?;
    }
    Ok(())
}

/// The release record of `l`, and voids of its current scores on `stage`
/// when the generator draws them.
fn release(
    g: &mut Gen,
    script: &mut Script,
    t: &mut Track,
    l: &Live,
    cause: ReleaseCause,
    void: VoidCause,
    stage: Stage,
) -> Result<(), String> {
    script.push(Record::AssignmentReleased(AssignmentReleased {
        assignment: l.assignment,
        cause,
    }))?;
    if let Some(x) = t.live.iter_mut().find(|x| x.assignment == l.assignment) {
        x.active = false;
    }
    if g.bool() {
        let keys: Vec<ScoreKey> = t
            .current
            .keys()
            .filter(|k| k.assignment == l.assignment && k.stage == stage)
            .copied()
            .collect();
        for key in keys {
            script.push(Record::ScoreVoided(ScoreVoided { key, cause: void }))?;
            t.current.remove(&key);
        }
    }
    Ok(())
}

/// A void of a current score on this stage and plan that leaves its
/// assignment active, as a complaint remedy that reopens the stage does
/// (`VoidCause::ComplaintRemedy`, `SPEC/02-domain/complaints.md`). The key
/// belongs to a declared reviewer assignment of the current call, so only
/// the void excludes it. Half the time the reviewer scores the key afresh,
/// and that new value counts once.
fn op_void_kept(
    g: &mut Gen,
    script: &mut Script,
    t: &mut Track,
    stage: Stage,
    plan: PlanVersionId,
) -> Result<(), String> {
    let candidates: Vec<ScoreKey> = t
        .current
        .keys()
        .filter(|k| k.stage == stage && k.plan == plan)
        .filter(|k| {
            t.live.iter().any(|l| {
                l.assignment == k.assignment
                    && l.active
                    && l.declared
                    && l.kind == AssignmentKind::Reviewer
                    && l.call == t.call
            })
        })
        .copied()
        .collect();
    if candidates.is_empty() {
        return Ok(());
    }
    let key = *g.pick(&candidates);
    script.push(Record::ScoreVoided(ScoreVoided {
        key,
        cause: VoidCause::ComplaintRemedy,
    }))?;
    t.current.remove(&key);
    if g.bool() {
        score_key(g, script, t, key)?;
    }
    Ok(())
}

/// A new reviewer assignment of a free account in the current call.
fn op_reassign(
    g: &mut Gen,
    script: &mut Script,
    t: &mut Track,
    fx: &Fixture,
) -> Result<(), String> {
    let free = t.free();
    if free.is_empty() {
        return Ok(());
    }
    let account = *g.pick(&free);
    assign_live(script, t, fx, account, AssignmentKind::Reviewer, true)?;
    Ok(())
}

/// An assignment and a score on the noise proposal, which never count.
fn op_noise(
    g: &mut Gen,
    script: &mut Script,
    t: &mut Track,
    fx: &Fixture,
    noise: Option<(ProposalId, PlanVersionId, AccountId)>,
) -> Result<(), String> {
    let Some((proposal, plan, _)) = noise else {
        return Ok(());
    };
    let account = *g.pick(&t.pool);
    let assignment = AssignmentId::from_raw(script.fresh());
    script.assign(fx, proposal, assignment, account)?;
    let key = ScoreKey {
        assignment,
        stage: Stage::One,
        plan,
    };
    let values = t.vector(g);
    script.score(key, values, None)?;
    Ok(())
}

/// A conflict fact on the scored proposal for the account of an
/// unreleased assignment, with no release: a detected conflict or a
/// proposal-level declaration. Commands release the assignment in the
/// same batch (design section 2.7). The structural fold accepts the record
/// alone, and the quorum must still exclude the account's scores.
fn op_conflict_kept(
    g: &mut Gen,
    script: &mut Script,
    t: &mut Track,
    fx: &Fixture,
) -> Result<(), String> {
    let accounts: Vec<AccountId> = t
        .active()
        .into_iter()
        .map(|l| l.account)
        .filter(|a| !t.conflicted.contains(a))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if accounts.is_empty() {
        return Ok(());
    }
    let account = *g.pick(&accounts);
    if g.bool() {
        detect(g, script, account, fx.proposal)?;
    } else {
        script.push(Record::ConflictDeclared(ConflictDeclared {
            subject: Declared::Proposal {
                proposal: fx.proposal,
                account,
            },
            conflicted: true,
            notifiable: false,
        }))?;
    }
    t.conflicted.insert(account);
    Ok(())
}

/// A conflicted declaration on an assignment already released. It is a
/// conflict fact for the account on the proposal, so it excludes every
/// other assignment of the account, which the generator prefers to pick.
fn op_conflict_on_released(g: &mut Gen, script: &mut Script, t: &mut Track) -> Result<(), String> {
    let released: Vec<Live> = t.live.iter().filter(|l| !l.active).cloned().collect();
    if released.is_empty() {
        return Ok(());
    }
    let preferred: Vec<Live> = released
        .iter()
        .filter(|r| t.live.iter().any(|l| l.active && l.account == r.account))
        .cloned()
        .collect();
    let l = if !preferred.is_empty() && g.weighted(&[3, 1]) == 0 {
        g.pick(&preferred).clone()
    } else {
        g.pick(&released).clone()
    };
    script.push(Record::ConflictDeclared(ConflictDeclared {
        subject: Declared::Assignment(l.assignment),
        conflicted: true,
        notifiable: false,
    }))?;
    t.conflicted.insert(l.account);
    Ok(())
}

/// A conflict fact on the noise proposal for an account assigned to the
/// scored proposal. It never excludes a score of the scored proposal.
fn op_noise_conflict(
    g: &mut Gen,
    script: &mut Script,
    t: &mut Track,
    noise: Option<(ProposalId, PlanVersionId, AccountId)>,
) -> Result<(), String> {
    let Some((proposal, _, _)) = noise else {
        return Ok(());
    };
    let accounts = t.accounts();
    if accounts.is_empty() {
        return Ok(());
    }
    let account = *g.pick(&accounts);
    if g.bool() {
        detect(g, script, account, proposal)?;
    } else {
        script.push(Record::ConflictDeclared(ConflictDeclared {
            subject: Declared::Proposal { proposal, account },
            conflicted: true,
            notifiable: false,
        }))?;
    }
    Ok(())
}

/// A new reviewer assignment of an account with a conflict fact on the
/// proposal. `Assign` refuses it (design section 2.7), but the structural
/// fold accepts it, and its scores must never count.
fn op_reassign_conflicted(
    g: &mut Gen,
    script: &mut Script,
    t: &mut Track,
    fx: &Fixture,
) -> Result<(), String> {
    let accounts: Vec<AccountId> = t.conflicted.iter().copied().collect();
    if accounts.is_empty() {
        return Ok(());
    }
    let account = *g.pick(&accounts);
    assign_live(script, t, fx, account, AssignmentKind::Reviewer, true)?;
    Ok(())
}

/// A declared IRC or amendment assignment to the scored proposal, with a
/// score on this stage and plan. Only reviewer assignments count.
fn op_other_kind(
    g: &mut Gen,
    script: &mut Script,
    t: &mut Track,
    fx: &Fixture,
    stage: Stage,
    plan: PlanVersionId,
) -> Result<(), String> {
    let account = *g.pick(&t.pool);
    let kind = if g.bool() {
        AssignmentKind::Irc
    } else {
        AssignmentKind::Amendment(AmendmentId::from_raw(script.fresh()))
    };
    let assignment = assign_live(script, t, fx, account, kind, true)?;
    let key = ScoreKey {
        assignment,
        stage,
        plan,
    };
    score_key(g, script, t, key)
}

/// A reviewer assignment that awaits its declaration, scored at once half
/// the time. It is not active until the declaration (design section 2.7).
fn op_undeclared(
    g: &mut Gen,
    script: &mut Script,
    t: &mut Track,
    fx: &Fixture,
    stage: Stage,
    plan: PlanVersionId,
) -> Result<(), String> {
    let free = t.free();
    if free.is_empty() {
        return Ok(());
    }
    let account = *g.pick(&free);
    let assignment = assign_live(script, t, fx, account, AssignmentKind::Reviewer, false)?;
    if g.bool() {
        let key = ScoreKey {
            assignment,
            stage,
            plan,
        };
        score_key(g, script, t, key)?;
    }
    Ok(())
}

/// The no-conflict declaration of an unreleased assignment that awaits it.
fn op_declare_pending(g: &mut Gen, script: &mut Script, t: &mut Track) -> Result<(), String> {
    let pending: Vec<AssignmentId> = t
        .live
        .iter()
        .filter(|l| l.active && !l.declared)
        .map(|l| l.assignment)
        .collect();
    if pending.is_empty() {
        return Ok(());
    }
    let assignment = *g.pick(&pending);
    script.declare(assignment)?;
    if let Some(l) = t.live.iter_mut().find(|l| l.assignment == assignment) {
        l.declared = true;
    }
    Ok(())
}

/// A score whose key names this stage and the scored plan, but whose
/// assignment is a declared reviewer assignment to the noise proposal.
/// The assignment's proposal decides, so it never counts.
fn op_cross_proposal(
    g: &mut Gen,
    script: &mut Script,
    t: &mut Track,
    fx: &Fixture,
    (stage, plan): (Stage, PlanVersionId),
    noise: Option<(ProposalId, PlanVersionId, AccountId)>,
) -> Result<(), String> {
    let Some((proposal, _, _)) = noise else {
        return Ok(());
    };
    let account = *g.pick(&t.pool);
    let assignment = AssignmentId::from_raw(script.fresh());
    script.assign(fx, proposal, assignment, account)?;
    let key = ScoreKey {
        assignment,
        stage,
        plan,
    };
    let values = t.vector(g);
    script.score(key, values, None)?;
    Ok(())
}

/// A score of an unreleased assignment on the other stage: a stage 2 key
/// on the submitted plan, or a stage 1 key on a revision. It never counts
/// for the stage asked for.
fn op_off_stage(
    g: &mut Gen,
    script: &mut Script,
    t: &mut Track,
    fx: &Fixture,
    stage: Stage,
    plan: PlanVersionId,
) -> Result<(), String> {
    let candidates = t.active();
    if candidates.is_empty() {
        return Ok(());
    }
    let assignment = g.pick(&candidates).assignment;
    let key = match stage {
        Stage::One => ScoreKey {
            assignment,
            stage: Stage::Two,
            plan: fx.plan,
        },
        Stage::Two if g.bool() => ScoreKey {
            assignment,
            stage: Stage::One,
            plan,
        },
        Stage::Two => ScoreKey {
            assignment,
            stage: Stage::Two,
            plan: fx.plan,
        },
    };
    score_key(g, script, t, key)
}

/// The proposal of an assignment in `script`.
fn proposal_of(script: &Script, assignment: AssignmentId) -> Option<ProposalId> {
    script
        .assigned
        .iter()
        .find(|(a, _, _)| *a == assignment)
        .map(|(_, p, _)| *p)
}

// ---------------------------------------------------------------------------
// I-09: effective score cases
// ---------------------------------------------------------------------------

/// An original plan score and zero to three revisions, each scored or not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EffectiveCase {
    /// The original plan and its stage 1 score.
    pub original: (PlanVersionId, Ratio),
    /// The revisions in submission order, with their stage 2 score when scored.
    pub revisions: Vec<(PlanVersionId, Option<Ratio>)>,
}

/// An effective score case. Revision scores often tie the original, or lie
/// one step either side of it.
pub fn effective_case(g: &mut Gen) -> EffectiveCase {
    let den = g.u64_in(1..=10_000);
    let num = g.u64_in(0..=den);
    let original = (PlanVersionId::from_raw(1), ratio(num, den));
    let count = g.usize_in(0..=3);
    let mut revisions = Vec::new();
    for k in 0..count {
        let id = PlanVersionId::from_raw(u128::try_from(k).unwrap_or(0).saturating_add(2));
        let score = match g.weighted(&[2, 4, 2, 2, 2]) {
            0 => None,
            1 => Some(ratio(num, den)),
            2 => Some(ratio(num.saturating_add(1).min(den), den)),
            3 => Some(ratio(num.saturating_sub(1), den)),
            _ => {
                let d = g.u64_in(1..=10_000);
                Some(ratio(g.u64_in(0..=d), d))
            }
        };
        revisions.push((id, score));
    }
    EffectiveCase {
        original,
        revisions,
    }
}

/// `num / den` as a ratio, with a denominator of at least 1.
fn ratio(num: u64, den: u64) -> Ratio {
    Ratio::new(num, NonZeroU64::new(den).unwrap_or(NonZeroU64::MIN))
}
