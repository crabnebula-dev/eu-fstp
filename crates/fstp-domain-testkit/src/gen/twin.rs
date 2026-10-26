//! The I-12 twin machine over the full engine (design sections 6.1 and 6.2, row I-12).
//!
//! Owned by lane W6 twin (docs/handoff/m2-design.md section 10, step W6).
//!
//! I-12: frozen parameters lock when a call publishes and apply unchanged
//! to that call (`SPEC/02-domain/invariants.md`). Changes apply to the
//! next call (`SPEC/02-domain/policy-parameters.md`).
//!
//! - Twins A and B are two reference drivers over a `MemStore` and the
//!   synthetic vault, each built from genesis by the same production
//!   commands. Genesis publishes call 1 and submits three proposals.
//! - Both twins run the same evaluation commands: knock-out, stage 1,
//!   stage 2 with questions, revisions, expiry and re-entry, ranking, the
//!   cut-off, IRC review, negotiation, the NOTE 9 decline, the grant,
//!   deliverables and amendments. Both also run the same live edits of
//!   P-05, P-12, P-13 and P-38, the same binding ends and the publication
//!   of call 2.
//! - Some evaluation acts make the frozen guards bite: R4 shares R1's
//!   organisation (P-39), R3 declares on a proposal and committee members
//!   read content (P-10), a deliverable carries a licence that some P-26
//!   candidate lacks before a later grant (P-26), an amendment has one or
//!   two IRC members and a total inside or outside call 1's range (P-15,
//!   P-04), and some acts arrive through MCP (P-77). The knock-out and
//!   the admission can also run apart, so an edit can fall between them.
//! - Composite acts run a whole stage at once, and the machine picks the
//!   most advanced proposals most often. So short cases still reach
//!   negotiation, where frozen edits can fall before the decline.
//! - Twin B alone also receives random edits of frozen parameters by a
//!   second programme manager, interleaved anywhere after publication.
//!   Every frozen programme parameter of the spec can be edited, typed or
//!   opaque, except P-24, whose type has one value only.
//!
//! The checks after every command:
//! - an evaluation command gives identical records, or identical
//!   refusals, on both twins: transitions, scores, effective scores and
//!   decisions;
//! - an evaluation command asks identical vault questions on both twins,
//!   or meets identical refusals before asking;
//! - a frozen edit appends exactly one policy version, the one sent;
//! - every published call's frozen policy equals the copy taken at its
//!   publication, and call 1's is identical on both twins;
//! - call 2, published after the edits, freezes twin B's edited values;
//! - a live value a decision used equals the head at decision time: the
//!   P-12 a binding end pins, the P-05 cap a cap question carries, which
//!   is the lower of the call snapshot and the head, the P-13 classes an
//!   exclusion question carries, which are the union of both (NOTE 7),
//!   and the P-38 list a proximity question carries, which is the head's.
//!
//! The teeth: [`TwinMachine::faulty`] makes twin B emit a stage 1 close
//! built from the head P-02 instead of the snapshot, folded through the
//! public structural `fstp_engine::apply`. The twin comparison must fail.
//!
//! The model of the machine is a ghost folded from twin A's records, so
//! every command is generated for the proposals' real states. Each
//! command names the state it expects, so a shrunk sequence skips the
//! commands whose prerequisites were deleted.

use core::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::num::{NonZeroU8, NonZeroU16};

use fstp_domain::amendment::AmendmentRoute;
use fstp_domain::assignment::AssignmentKind;
use fstp_domain::command::{Actor, Command, DeclarationSubject, Via};
use fstp_domain::decision::{EffectiveScoreSet, Vote};
use fstp_domain::id::{
    AccountId, AmendmentId, BindingId, CallId, ClassId, CommandId, ContractId, CriterionId,
    DeliverableId, KnockOutCriterionId, MilestoneId, OrganisationId, PlanVersionId,
    PolicyVersionId, ProposalId, ProximityListId,
};
use fstp_domain::oracle::Query;
use fstp_domain::policy::{
    ExclusionClasses, FrozenPolicy, FrozenValues, FunderProfileRef, InferenceBinding,
    IrcExemptions, KnockOutCriteria, KnockOutCriterion, LicenceSet, McpBindingActions, OpaqueValue,
    PolicyVersion, ProximityLists, ReadAccess, ReviewerAnonymity, SpdxId, TieBreakRule,
    VotingRules, is_frozen_opaque,
};
use fstp_domain::proposal::PlanOrigin;
use fstp_domain::record::{Record, Transitioned};
use fstp_domain::refusal::Refusal;
use fstp_domain::roles::{CoolingOff, Role};
use fstp_domain::rules::{Freeze, Level, ParamId, Row, StateTag};
use fstp_domain::scoring::{Criteria, Criterion, ScoreKey, Stage};
use fstp_domain::time::{Days, MICROS_PER_DAY, Timestamp};
use fstp_engine::EngineState;
use fstp_ledger::Seq;
use fstp_money::{AmountRange, Percent};
use fstp_prop::{Gen, StateMachine};

use crate::r#gen::money::{
    FINREL, LA, LB, LC, MoneySetup, PA, PB, PC, REL, accept_grant, activate_amendment,
    amendment_assignment, amount_decision, approve_grant, assign_amendment_declared,
    contract_effective, decline_negotiation, determine, milestone_n, money_plan, nonneg,
    propose_amendment, record_deliverable, route_amendment, start_execution, terminate,
};
use crate::r#gen::policy::{knock_outs, model, next_version, opaque, text};
use crate::r#gen::review::{
    COORDINATOR, IRC, O1, O2, O3, R1, R2, R3, R4, declare, judge_binding, plan_of, read,
    records_of, run_records, submit, withdraw,
};
use crate::r#gen::roster::{Flags, P1, STAFF_PM, Step, call, end};
use crate::mc::life_model::{
    IRC2, T_EVAL, admit, answer, ask, assign_declared, assignment_of, ballots, close, correct,
    cut_off, cut_off_decision, decline, expire, irc_review, knock_out, no_questions, rank, reenter,
    revision_milestone, revision_of, score, submit_revision,
};
use crate::reference::lifecycle::{Frac, forge_stage1_closed};
use crate::reference::scoring::{Exact, passes_reference};
use crate::scenario::Scenario;

// ---------------------------------------------------------------------------
// Accounts, proposals and setup
// ---------------------------------------------------------------------------

/// The second programme manager, who authors twin B's frozen edits. The
/// staff programme manager approves call 2 again after a P-01 or P-09
/// edit, which an author of those values may not do (R-PC-03).
pub const PM2: AccountId = AccountId::from_raw(601);

/// The proposals of the twins and their leads, all in call 1.
pub const TWIN_PROPOSALS: [(AccountId, ProposalId); 3] = [(LA, PA), (LB, PB), (LC, PC)];

/// The submitted plan total of every proposal, cents.
pub const TWIN_PLAN_CENTS: i64 = 300;

/// The base id of twin B's frozen edit versions.
pub const FROZEN_VERSION_BASE: u128 = 5_000;

/// The base id of the live edit versions both twins record.
pub const LIVE_VERSION_BASE: u128 = 900;

/// The base id of twin B's renewed approvals of call 2.
pub const APPROVAL_BASE: u128 = 9_600;

/// The lead of `proposal`.
pub fn lead_of(proposal: ProposalId) -> AccountId {
    TWIN_PROPOSALS
        .iter()
        .find(|(_, p)| *p == proposal)
        .map_or(LA, |(l, _)| *l)
}

/// The bindings both twins may end: the finance approver's and the
/// payment releaser's. They are the eighth and ninth Judging and
/// Operations grants of [`twin_setup`].
pub fn spare_bindings() -> [BindingId; 2] {
    [judge_binding(7), judge_binding(8)]
}

/// The base id of the deliverables both twins record.
pub const DELIVERABLE_BASE: u128 = 7_700;

/// The organisation of each committee member of the twins: the life
/// judges' organisations, and [`R4`] in [`O1`] beside R1 (P-39).
pub fn organisation_of(r: AccountId) -> Option<OrganisationId> {
    match r {
        x if x == R1 || x == R4 => Some(O1),
        x if x == R2 => Some(O2),
        x if x == R3 => Some(O3),
        _ => None,
    }
}

/// The setup from genesis: the life judges, [`PM2`], a finance approver,
/// a payment releaser and a fourth committee member [`R4`], three leads
/// of distinct identities with plans of 3.00 EUR, P-04 = [2.00, 4.00]
/// and P-05 = 10.00. [`twin_genesis`] places R4 in R1's organisation.
pub fn twin_setup() -> MoneySetup {
    let mut s = MoneySetup::sybil([TWIN_PLAN_CENTS; 3]);
    s.shared = Vec::new();
    s.p04 = (200, 400);
    s.p05 = 1_000;
    for d in &mut s.drafts {
        d.negotiate = false;
    }
    s.staff = vec![
        (PM2, Role::ProgrammeManager),
        (FINREL, Role::FinanceApprover),
        (REL, Role::PaymentReleaser),
        (R4, Role::CommitteeMember),
    ];
    s
}

/// The commands from genesis: the setup with [`R4`] in R1's organisation,
/// then the submission of every proposal. Call 1 is published inside the setup.
pub fn twin_genesis() -> Result<Vec<Step>, String> {
    let mut steps = twin_setup().draft_steps()?;
    for s in &mut steps {
        if let Command::GrantRole {
            account,
            organisation,
            ..
        } = &mut s.cmd
            && *account == R4
        {
            *organisation = organisation_of(R4);
        }
    }
    for (lead, p) in TWIN_PROPOSALS {
        steps.push(submit(lead, p, plan_of(p), false));
    }
    Ok(steps)
}

// ---------------------------------------------------------------------------
// Frozen edits
// ---------------------------------------------------------------------------

/// The frozen programme parameters whose value an edit can change: every
/// one of the catalogue except P-24. `EffectiveScoreRule` has one value
/// only, so P-24 cannot change at all.
pub fn editable_frozen() -> Vec<ParamId> {
    ParamId::ALL
        .into_iter()
        .filter(|p| {
            p.spec()
                .is_some_and(|s| s.freeze == Freeze::Frozen && s.level == Level::Programme)
        })
        .filter(|p| *p != ParamId::P24)
        .collect()
}

/// Whether `param` is typed and interpreted by M2, rather than opaque.
pub fn is_interpreted(param: ParamId) -> bool {
    !is_frozen_opaque(param)
}

/// One edit of twin B: each pair changes one frozen parameter to the
/// candidate value its number picks.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FrozenEdit {
    /// The parameters changed, with the candidate picks.
    pub changes: Vec<(ParamId, u8)>,
}

/// Sets `slot` to the first candidate from position `pick` on that
/// differs from it. Fails when every candidate equals it.
fn choose<T: PartialEq + Clone>(slot: &mut T, candidates: &[T], pick: u8) -> Result<(), String> {
    let n = candidates.len();
    let found = candidates
        .iter()
        .cycle()
        .skip(usize::from(pick).checked_rem(n).unwrap_or(0))
        .take(n)
        .find(|c| *c != slot)
        .cloned();
    match found {
        Some(c) => {
            *slot = c;
            Ok(())
        }
        None => Err("no candidate differs from the current value".to_owned()),
    }
}

/// P-01 with `weights` on criteria 1, 2 and so on, and scale maximum `n`.
fn criteria_of(n: u8, weights: &[u16]) -> Result<Criteria, String> {
    let scale = NonZeroU8::new(n).ok_or("scale maximum zero")?;
    let mut items = Vec::new();
    for (i, w) in (1u128..).zip(weights) {
        items.push(Criterion {
            id: CriterionId::from_raw(i),
            weight: NonZeroU16::new(*w).ok_or("weight zero")?,
        });
    }
    Criteria::new(scale, items).map_err(|e| format!("criteria: {e}"))
}

fn range(min: i64, max: i64) -> Result<AmountRange, String> {
    AmountRange::new(nonneg(min)?, nonneg(max)?).map_err(|e| format!("P-04: {e:?}"))
}

fn small(n: u8) -> Result<NonZeroU8, String> {
    NonZeroU8::new(n).ok_or_else(|| "zero".to_owned())
}

fn opaque_candidates(label: &str) -> Result<Vec<OpaqueValue>, String> {
    (0..3)
        .map(|k| opaque(&format!("synthetic {label} edit {k}")))
        .collect()
}

/// P-09 with the criterion `ids`, their texts numbered from `first_text`.
fn knock_out_ids(ids: &[u128], first_text: u128) -> KnockOutCriteria {
    KnockOutCriteria(
        (0u128..)
            .zip(ids)
            .map(|(i, id)| KnockOutCriterion {
                id: KnockOutCriterionId::from_raw(*id),
                text: text(first_text.saturating_add(i)),
            })
            .collect(),
    )
}

fn licences(ids: &[&str]) -> LicenceSet {
    LicenceSet(ids.iter().map(|s| SpdxId((*s).to_owned())).collect())
}

/// Changes the frozen parameter `param` of `v` to the candidate that
/// `pick` names, always to a value other than the current one. Fails for
/// P-24, which has one value, and for a parameter that is not frozen.
pub fn apply_frozen(v: &mut PolicyVersion, param: ParamId, pick: u8) -> Result<(), String> {
    let f = &mut v.frozen;
    match param {
        ParamId::P01 => choose(
            &mut f.p01,
            &[
                criteria_of(2, &[1, 1])?,
                criteria_of(2, &[3, 1])?,
                criteria_of(4, &[30, 40, 30])?,
                criteria_of(5, &[1, 2, 3])?,
            ],
            pick,
        ),
        ParamId::P02 => {
            let mut c = Vec::new();
            for bp in [0, 2_500, 5_000, 7_500, 10_000] {
                c.push(Percent::from_bp(bp).ok_or("P-02")?);
            }
            choose(&mut f.p02, &c, pick)
        }
        ParamId::P03 => choose(&mut f.p03, &[small(1)?, small(2)?, small(3)?], pick),
        // Most candidates exclude the plan total of 3.00 EUR, so a guard
        // that read the head P-04 would decide otherwise on twin B.
        ParamId::P04 => choose(
            &mut f.p04,
            &[
                range(200, 400)?,
                range(0, 100)?,
                range(350, 500)?,
                range(0, 1_000)?,
                range(0, 250)?,
                range(310, 900)?,
            ],
            pick,
        ),
        ParamId::P07 => choose(
            &mut f.p07,
            &[Days::new(28), Days::new(7), Days::new(60)],
            pick,
        ),
        // Three candidates change the criterion id set, so a knock-out
        // guard that read the head would refuse call 1's outcomes on twin B.
        ParamId::P09 => choose(
            &mut f.p09,
            &[
                knock_outs(1_000),
                knock_out_ids(&[1, 2], 2_000),
                knock_out_ids(&[1, 2, 3, 4], 3_000),
                knock_out_ids(&[2, 3, 4], 4_000),
                knock_outs(5_000),
            ],
            pick,
        ),
        ParamId::P10 => choose(
            &mut f.p10,
            &[
                ReadAccess::AssignedReviewersOnly,
                ReadAccess::AllCommitteeMembers,
                ReadAccess::OperatorStaffOnly,
            ],
            pick,
        ),
        ParamId::P11 => choose(
            &mut f.p11,
            &[ReviewerAnonymity::Anonymous, ReviewerAnonymity::Named],
            pick,
        ),
        ParamId::P14 => {
            let c: Vec<IrcExemptions> = opaque_candidates("P-14")?
                .into_iter()
                .map(IrcExemptions)
                .collect();
            choose(&mut f.p14, &c, pick)
        }
        ParamId::P15 => choose(&mut f.p15, &[small(1)?, small(2)?, small(3)?], pick),
        ParamId::P16 => {
            let c: Vec<VotingRules> = opaque_candidates("P-16")?
                .into_iter()
                .map(VotingRules)
                .collect();
            choose(&mut f.p16, &c, pick)
        }
        ParamId::P17 => {
            let c: Vec<TieBreakRule> = opaque_candidates("P-17")?
                .into_iter()
                .map(TieBreakRule)
                .collect();
            choose(&mut f.p17, &c, pick)
        }
        ParamId::P21 => {
            let provider = f.p21.provider.clone();
            let c: Vec<InferenceBinding> = (0u8..3)
                .map(|i| InferenceBinding {
                    provider: provider.clone(),
                    primary: model(i),
                    fallbacks: vec![model(i.saturating_add(1))],
                })
                .collect();
            choose(&mut f.p21, &c, pick)
        }
        ParamId::P26 => choose(
            &mut f.p26,
            &[
                licences(&["Apache-2.0", "MIT"]),
                licences(&["MIT"]),
                licences(&["GPL-3.0-only", "MIT"]),
            ],
            pick,
        ),
        ParamId::P39 => choose(&mut f.p39, &[small(1)?, small(2)?, small(3)?], pick),
        ParamId::P53 => {
            let c: Vec<FunderProfileRef> = opaque_candidates("P-53")?
                .into_iter()
                .map(FunderProfileRef)
                .collect();
            choose(&mut f.p53, &c, pick)
        }
        ParamId::P77 => choose(
            &mut f.p77,
            &[McpBindingActions::DraftOnly, McpBindingActions::Allowed],
            pick,
        ),
        ParamId::P24 => Err("P-24 has one value only, so no edit can change it".to_owned()),
        p if is_frozen_opaque(p) => {
            let c = opaque_candidates(p.spec_id())?;
            let slot = f
                .opaque
                .get_mut(&p)
                .ok_or_else(|| format!("{} is not in the frozen opaque map", p.spec_id()))?;
            choose(slot, &c, pick)
        }
        p => Err(format!(
            "{} is not a frozen programme parameter",
            p.spec_id()
        )),
    }
}

/// The frozen parameters whose values differ between `a` and `b`.
pub fn frozen_diff(a: &FrozenValues, b: &FrozenValues) -> BTreeSet<ParamId> {
    let typed = [
        (ParamId::P01, a.p01 != b.p01),
        (ParamId::P02, a.p02 != b.p02),
        (ParamId::P03, a.p03 != b.p03),
        (ParamId::P04, a.p04 != b.p04),
        (ParamId::P07, a.p07 != b.p07),
        (ParamId::P09, a.p09 != b.p09),
        (ParamId::P10, a.p10 != b.p10),
        (ParamId::P11, a.p11 != b.p11),
        (ParamId::P14, a.p14 != b.p14),
        (ParamId::P15, a.p15 != b.p15),
        (ParamId::P16, a.p16 != b.p16),
        (ParamId::P17, a.p17 != b.p17),
        (ParamId::P21, a.p21 != b.p21),
        (ParamId::P24, a.p24 != b.p24),
        (ParamId::P26, a.p26 != b.p26),
        (ParamId::P39, a.p39 != b.p39),
        (ParamId::P53, a.p53 != b.p53),
        (ParamId::P77, a.p77 != b.p77),
    ];
    let mut out: BTreeSet<ParamId> = typed
        .into_iter()
        .filter(|(_, d)| *d)
        .map(|(p, _)| p)
        .collect();
    let keys: BTreeSet<ParamId> = a.opaque.keys().chain(b.opaque.keys()).copied().collect();
    out.extend(
        keys.into_iter()
            .filter(|k| a.opaque.get(k) != b.opaque.get(k)),
    );
    out
}

/// Draws a frozen edit of one to three parameters. Interpreted
/// parameters, which guards read, come up three times as often as opaque ones.
pub fn gen_frozen_edit(g: &mut Gen) -> FrozenEdit {
    let params = editable_frozen();
    let weights: Vec<u32> = params
        .iter()
        .map(|p| if is_interpreted(*p) { 3 } else { 1 })
        .collect();
    let n = g.u8_in(1..=3);
    let mut changes = Vec::new();
    for _ in 0..n {
        let i = g.weighted(&weights);
        if let Some(p) = params.get(i) {
            changes.push((*p, g.u8_in(0..=5)));
        }
    }
    FrozenEdit { changes }
}

/// One live edit both twins record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LiveEdit {
    /// P-05 to these cents.
    P05(i64),
    /// P-12 to this many calls.
    P12(u8),
    /// P-13 to the class set this number picks, see [`p13_candidate`].
    P13(u8),
    /// P-38 to the proximity lists this number picks, see [`p38_candidate`].
    P38(u8),
}

/// The P-13 class set `pick` names: {1}, {1, 2} or {3}.
pub fn p13_candidate(pick: u8) -> ExclusionClasses {
    let ids: &[u128] = match pick % 3 {
        0 => &[1],
        1 => &[1, 2],
        _ => &[3],
    };
    ExclusionClasses(ids.iter().map(|c| ClassId::from_raw(*c)).collect())
}

/// The P-38 lists `pick` names: none, O1's, O1's and O2's, or O2's alone.
pub fn p38_candidate(pick: u8) -> ProximityLists {
    let pairs: &[(OrganisationId, u128)] = match pick % 4 {
        0 => &[],
        1 => &[(O1, 1)],
        2 => &[(O1, 1), (O2, 2)],
        _ => &[(O2, 3)],
    };
    ProximityLists(
        pairs
            .iter()
            .map(|(o, l)| (*o, ProximityListId::from_raw(*l)))
            .collect(),
    )
}

/// Applies `edit` to the live values of `v`.
pub fn apply_live(v: &mut PolicyVersion, edit: LiveEdit) -> Result<(), String> {
    match edit {
        LiveEdit::P05(c) => v.live.p05 = nonneg(c)?,
        LiveEdit::P12(n) => v.live.p12 = CoolingOff(n),
        LiveEdit::P13(n) => v.live.p13 = p13_candidate(n),
        LiveEdit::P38(n) => v.live.p38 = p38_candidate(n),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The ghost
// ---------------------------------------------------------------------------

/// What the machine knows, folded from twin A's records.
#[derive(Clone, Debug)]
pub struct TwinGhost {
    /// The latest command instant.
    pub now: Timestamp,
    /// The state of each proposal.
    pub states: BTreeMap<ProposalId, StateTag>,
    /// The current call of each proposal.
    pub calls: BTreeMap<ProposalId, CallId>,
    /// When each proposal last entered STAGE2.
    pub stage2_at: BTreeMap<ProposalId, Timestamp>,
    /// The plans each proposal recorded during the machine run.
    pub plans: BTreeMap<ProposalId, Vec<PlanVersionId>>,
    /// The latest submitted stage 2 revision of each proposal.
    pub revisions: BTreeMap<ProposalId, PlanVersionId>,
    /// The effective score of each proposal.
    pub effective: BTreeMap<ProposalId, EffectiveScoreSet>,
    /// The amount determinations of each proposal.
    pub determinations: BTreeMap<ProposalId, u128>,
    /// The cut-offs recorded.
    pub cut_offs: u128,
    /// The deliverables recorded, accepted or not.
    pub deliverables: u128,
    /// The amendments activated.
    pub activated: u128,
    /// Whether call 2 is published.
    pub published2: bool,
    /// The bindings ended.
    pub ended: BTreeSet<BindingId>,
    /// The frozen edits sent.
    pub frozen_edits: u128,
    /// The live edits sent.
    pub live_edits: u128,
    /// The frozen parameters edited, accepted or not.
    pub edited: BTreeSet<ParamId>,
}

impl TwinGhost {
    /// The ghost after genesis: every proposal SUBMITTED in call 1, at [`T_EVAL`].
    pub fn new() -> TwinGhost {
        TwinGhost {
            now: T_EVAL,
            states: TWIN_PROPOSALS
                .iter()
                .map(|(_, p)| (*p, StateTag::Submitted))
                .collect(),
            calls: TWIN_PROPOSALS.iter().map(|(_, p)| (*p, call(1))).collect(),
            stage2_at: BTreeMap::new(),
            plans: BTreeMap::new(),
            revisions: BTreeMap::new(),
            effective: BTreeMap::new(),
            determinations: BTreeMap::new(),
            cut_offs: 0,
            deliverables: 0,
            activated: 0,
            published2: false,
            ended: BTreeSet::new(),
            frozen_edits: 0,
            live_edits: 0,
            edited: BTreeSet::new(),
        }
    }

    /// The state of `p`.
    pub fn state(&self, p: ProposalId) -> StateTag {
        self.states.get(&p).copied().unwrap_or(StateTag::Submitted)
    }

    /// The current call of `p`.
    pub fn call_of(&self, p: ProposalId) -> CallId {
        self.calls.get(&p).copied().unwrap_or(call(1))
    }

    /// The latest plan of `p`: its latest recorded plan, or the submitted one.
    pub fn latest_plan(&self, p: ProposalId) -> PlanVersionId {
        self.plans
            .get(&p)
            .and_then(|v| v.last().copied())
            .unwrap_or_else(|| plan_of(p))
    }

    /// Folds twin A's records of one command at `now`.
    pub fn fold(&mut self, records: &[Record], now: Timestamp) {
        for r in records {
            match r {
                Record::Transitioned(t) => {
                    self.states.insert(t.proposal, t.to);
                    if t.to == StateTag::Stage2 {
                        self.stage2_at.insert(t.proposal, now);
                    }
                }
                Record::ReEntered {
                    proposal, to_call, ..
                } => {
                    self.calls.insert(*proposal, *to_call);
                }
                Record::PlanVersionRecorded(p) => {
                    self.plans.entry(p.proposal).or_default().push(p.plan);
                }
                Record::RevisionSubmitted { proposal, plan } => {
                    self.revisions.insert(*proposal, *plan);
                }
                Record::EffectiveScoreSet(e) => {
                    self.effective.insert(e.proposal(), e.clone());
                }
                Record::AmountDetermined { proposal, .. } => {
                    let n = self.determinations.entry(*proposal).or_insert(0);
                    *n = n.saturating_add(1);
                }
                Record::CutOffRecorded(_) => self.cut_offs = self.cut_offs.saturating_add(1),
                Record::AmendmentActivated { .. } => {
                    self.activated = self.activated.saturating_add(1);
                }
                Record::DeliverableRecorded(_) => {
                    self.deliverables = self.deliverables.saturating_add(1);
                }
                Record::CallPublished { call: c, .. } if *c == call(2) => self.published2 = true,
                Record::BindingEnded(b) => {
                    self.ended.insert(b.binding);
                }
                _ => {}
            }
        }
    }

    /// The milestone of the plan `p` was determined on: the submitted
    /// plan's first milestone, or the milestone of its revision.
    pub fn effective_milestone(&self, p: ProposalId) -> MilestoneId {
        let plan = self
            .effective
            .get(&p)
            .map_or_else(|| plan_of(p), EffectiveScoreSet::plan);
        (1usize..=self.plans.get(&p).map_or(0, Vec::len))
            .find(|n| revision_of(p, *n) == plan)
            .map_or_else(|| milestone_n(p, 0), |n| revision_milestone(p, n))
    }

    /// The RANKED proposals of `in_call`, by non-increasing effective
    /// score, ties by proposal id, and whether two of them tie.
    pub fn ranked_order(&self, in_call: CallId) -> (Vec<ProposalId>, bool) {
        let mut ranked: Vec<(ProposalId, Option<fstp_money::Ratio>)> = self
            .states
            .iter()
            .filter(|(p, s)| **s == StateTag::Ranked && self.call_of(**p) == in_call)
            .map(|(p, _)| (*p, self.effective.get(p).map(EffectiveScoreSet::value)))
            .collect();
        ranked.sort_by(|x, y| y.1.partial_cmp(&x.1).unwrap_or(core::cmp::Ordering::Equal));
        let tie = ranked.windows(2).any(|w| matches!(w, [x, y] if x.1 == y.1));
        (ranked.into_iter().map(|(p, _)| p).collect(), tie)
    }
}

impl Default for TwinGhost {
    fn default() -> Self {
        TwinGhost::new()
    }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/// One evaluation act on a proposal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Act {
    /// Two reviewers assigned and declared, the coordinator's declaration,
    /// a passed knock-out check and the admission.
    Admit,
    /// [`Act::Admit`] without the admission, so a frozen edit can fall
    /// between the knock-out check and [`Act::AdmitOnly`].
    Prepare,
    /// The coordinator's admission alone.
    AdmitOnly,
    /// The coordinator's declaration and a failed knock-out check.
    Ineligible,
    /// A committee member's declaration on the proposal, which P-10 "all
    /// committee members" allows and the other values refuse.
    MemberDeclare(AccountId),
    /// The M5 checks' accepted deliverable on the effective milestone, under
    /// the licence this number picks, see [`DELIVERABLE_LICENCES`].
    Deliverable(u8),
    /// The lead withdraws.
    Withdraw,
    /// A stage 1 score.
    Score(AccountId, [u8; 2]),
    /// A stage 1 correction.
    Correct(AccountId, [u8; 2]),
    /// The coordinator records the stage 1 close.
    Close,
    /// A stage 2 question.
    Ask(AccountId),
    /// A "no questions" record.
    NoQuestions(AccountId),
    /// The lead answers.
    Answer,
    /// The lead records and submits a revision with one milestone of these cents.
    Revise(i64),
    /// A stage 2 score on the latest revision.
    Score2(AccountId, [u8; 2]),
    /// R1 ranks after stage 2.
    Rank,
    /// The System expires the window, 29 days after stage 2 began.
    Expire,
    /// A reviewer assigned and declared in the current call, after re-entry.
    Assign(AccountId),
    /// The System re-enters the proposal into call 2.
    ReEnter,
    /// The cut-off of a call: its RANKED proposals with this rank position.
    CutOff(CallId, u32),
    /// An IRC member assigned and declared in the current call.
    AssignIrc(AccountId),
    /// An IRC review: a validation or a concern.
    Irc(AccountId, bool),
    /// The programme manager records IRC_REVIEW to DECLINED.
    DeclineConcern,
    /// R1 determines the amount on the effective plan.
    Determine,
    /// The lead accepts the grant.
    Accept,
    /// The programme manager approves the grant.
    Approve,
    /// The contract port's EFFECTIVE fact.
    Contract,
    /// The programme manager records NEGOTIATION to DECLINED.
    DeclineNegotiation,
    /// The System starts execution.
    Start,
    /// The programme manager terminates the grant.
    Terminate,
    /// R1's and R2's stage 1 scores, then the coordinator's close.
    Stage1All([u8; 2], [u8; 2]),
    /// R1's and R2's "no questions" records, which close the window at once.
    Stage2All,
    /// Both IRC members assigned, declared and validating.
    IrcAll,
    /// The amount determination, the acceptance, the approval and the
    /// contract port's EFFECTIVE fact.
    GrantAll,
    /// A `ReadContent` by this account, which P-10 governs in STAGE1 and STAGE2.
    Read(AccountId),
    /// An amendment of the grant with one milestone of these cents. With
    /// zero IRC members it is routed through a P-14 exemption. Otherwise
    /// that many IRC members validate it, which P-15 counts. Then the
    /// contract port activates it, which P-04 bounds (I-13).
    Amend(i64, u8),
}

/// The deliverable licences: one in every P-26 candidate, one in the
/// call 1 value but not in every candidate, and one outside the call 1 value.
pub const DELIVERABLE_LICENCES: [&str; 3] = ["MIT", "Apache-2.0", "GPL-3.0-only"];

/// One command of the twin machine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TwinCmd {
    /// Both twins run `steps` at `now`, step by step.
    Eval {
        /// The instant.
        now: Timestamp,
        /// The act.
        act: Act,
        /// The proposal and the state the act expects, or `None` for a cut-off.
        on: Option<(ProposalId, StateTag)>,
        /// Whether the commands arrive through MCP, which P-77 governs.
        mcp: bool,
        /// The commands.
        steps: Vec<Step>,
    },
    /// Twin B alone: [`PM2`] records a frozen edit on the head as version `id`.
    Frozen {
        /// The instant.
        now: Timestamp,
        /// The new version id.
        id: PolicyVersionId,
        /// The changes.
        edit: FrozenEdit,
    },
    /// Both twins: the staff programme manager records a live edit as version `id`.
    Live {
        /// The instant.
        now: Timestamp,
        /// The new version id.
        id: PolicyVersionId,
        /// The change.
        edit: LiveEdit,
    },
    /// Both twins publish call 2. Twin B approves it again first when an
    /// edit of P-01 or P-09 revoked the approval (R-PC-03).
    Publish2 {
        /// The instant.
        now: Timestamp,
    },
    /// Both twins end a spare binding, which pins the live P-12.
    EndSpare {
        /// The instant.
        now: Timestamp,
        /// The binding.
        binding: BindingId,
    },
}

impl TwinCmd {
    /// The instant of the command.
    pub fn now(&self) -> Timestamp {
        match self {
            TwinCmd::Eval { now, .. }
            | TwinCmd::Frozen { now, .. }
            | TwinCmd::Live { now, .. }
            | TwinCmd::Publish2 { now }
            | TwinCmd::EndSpare { now, .. } => *now,
        }
    }
}

fn reviewer_key(
    r: AccountId,
    p: ProposalId,
    in_call: CallId,
    stage: Stage,
    plan: PlanVersionId,
) -> ScoreKey {
    ScoreKey {
        assignment: assignment_of(r, p, in_call, AssignmentKind::Reviewer),
        stage,
        plan,
    }
}

/// The commands of `act` on `p` in `m`, or `None` where the act cannot be built.
pub fn act_steps(m: &TwinGhost, p: Option<ProposalId>, act: Act) -> Option<Vec<Step>> {
    let p = p.unwrap_or(PA);
    let c = m.call_of(p);
    let lead = lead_of(p);
    Some(match act {
        Act::Admit => {
            let mut out = assign_declared(R1, p, c, AssignmentKind::Reviewer);
            out.extend(assign_declared(R2, p, c, AssignmentKind::Reviewer));
            out.push(declare(
                COORDINATOR,
                DeclarationSubject::Proposal(p),
                false,
                false,
            ));
            out.push(knock_out(p, true));
            out.push(admit(p));
            out
        }
        Act::Prepare => {
            let mut out = act_steps(m, Some(p), Act::Admit)?;
            out.pop();
            out
        }
        Act::AdmitOnly => vec![admit(p)],
        Act::Ineligible => vec![
            declare(COORDINATOR, DeclarationSubject::Proposal(p), false, false),
            knock_out(p, false),
        ],
        Act::MemberDeclare(r) => vec![declare(r, DeclarationSubject::Proposal(p), false, false)],
        Act::Deliverable(pick) => {
            let licence = DELIVERABLE_LICENCES
                .get(usize::from(pick).checked_rem(DELIVERABLE_LICENCES.len())?)
                .copied()?;
            vec![record_deliverable(
                p,
                DeliverableId::from_raw(DELIVERABLE_BASE.saturating_add(m.deliverables)),
                m.effective_milestone(p),
                licence,
                true,
            )]
        }
        Act::Withdraw => vec![withdraw(lead, p)],
        Act::Score(r, v) => vec![score(
            r,
            reviewer_key(r, p, call(1), Stage::One, plan_of(p)),
            &v,
        )],
        Act::Correct(r, v) => vec![correct(
            r,
            reviewer_key(r, p, call(1), Stage::One, plan_of(p)),
            &v,
        )],
        Act::Close => vec![close(Actor::Account(COORDINATOR), p)],
        Act::Ask(r) => vec![ask(r, p, assignment_of(r, p, c, AssignmentKind::Reviewer))],
        Act::NoQuestions(r) => vec![no_questions(
            r,
            p,
            assignment_of(r, p, c, AssignmentKind::Reviewer),
        )],
        Act::Answer => vec![answer(lead, p)],
        Act::Revise(cents) => {
            let n = m.plans.get(&p).map_or(0, Vec::len).saturating_add(1);
            let plan = revision_of(p, n);
            vec![
                money_plan(
                    lead,
                    p,
                    plan,
                    PlanOrigin::Stage2Revision,
                    Some(m.latest_plan(p)),
                    &[(revision_milestone(p, n), cents, crate::r#gen::roster::T0)],
                )
                .ok()?,
                submit_revision(lead, p, plan),
            ]
        }
        Act::Score2(r, v) => vec![score(
            r,
            reviewer_key(r, p, c, Stage::Two, *m.revisions.get(&p)?),
            &v,
        )],
        Act::Rank => vec![rank(R1, p)],
        Act::Expire => vec![expire(p)],
        Act::Assign(r) => assign_declared(r, p, c, AssignmentKind::Reviewer),
        Act::ReEnter => vec![reenter(p, call(2))],
        Act::CutOff(in_call, nominated) => {
            let (order, tie) = m.ranked_order(in_call);
            if order.is_empty() {
                return None;
            }
            vec![cut_off(
                R1,
                cut_off_decision(100u128.saturating_add(m.cut_offs)),
                in_call,
                order,
                nominated,
                tie,
                ballots(&[R1, R2, R3], Vote::For),
            )]
        }
        Act::AssignIrc(i) => assign_declared(i, p, c, AssignmentKind::Irc),
        Act::Irc(i, validate) => vec![irc_review(
            i,
            assignment_of(i, p, c, AssignmentKind::Irc),
            validate,
        )],
        Act::DeclineConcern => vec![decline(Actor::Account(STAFF_PM), p)],
        Act::Determine => {
            let n = m
                .determinations
                .get(&p)
                .copied()
                .unwrap_or(0)
                .saturating_add(1);
            let agreed = m
                .effective
                .get(&p)
                .map_or_else(|| plan_of(p), EffectiveScoreSet::plan);
            vec![determine(R1, p, amount_decision(p, n), agreed, &[]).ok()?]
        }
        Act::Accept => vec![accept_grant(lead, p)],
        Act::Approve => vec![approve_grant(STAFF_PM, p)],
        Act::Contract => vec![contract_effective(p)],
        Act::DeclineNegotiation => vec![decline_negotiation(Actor::Account(STAFF_PM), p)],
        Act::Start => vec![start_execution(p)],
        Act::Terminate => vec![terminate(STAFF_PM, p)],
        Act::Stage1All(v1, v2) => [Act::Score(R1, v1), Act::Score(R2, v2), Act::Close]
            .into_iter()
            .map(|a| act_steps(m, Some(p), a))
            .collect::<Option<Vec<_>>>()?
            .concat(),
        Act::Stage2All => vec![
            no_questions(R1, p, assignment_of(R1, p, c, AssignmentKind::Reviewer)),
            no_questions(R2, p, assignment_of(R2, p, c, AssignmentKind::Reviewer)),
        ],
        Act::IrcAll => [
            Act::AssignIrc(IRC),
            Act::AssignIrc(IRC2),
            Act::Irc(IRC, true),
            Act::Irc(IRC2, true),
        ]
        .into_iter()
        .map(|a| act_steps(m, Some(p), a))
        .collect::<Option<Vec<_>>>()?
        .concat(),
        Act::GrantAll => [Act::Determine, Act::Accept, Act::Approve, Act::Contract]
            .into_iter()
            .map(|a| act_steps(m, Some(p), a))
            .collect::<Option<Vec<_>>>()?
            .concat(),
        Act::Read(r) => vec![read(r, p)],
        Act::Amend(cents, members) => amend_steps(m, p, cents, members)?,
    })
}

/// The id of the `n`-th amendment of `p`.
pub fn twin_amendment(p: ProposalId, n: usize) -> AmendmentId {
    let n = u128::try_from(n).unwrap_or(0);
    AmendmentId::from_raw(
        70_000u128
            .saturating_add(p.raw().saturating_mul(100))
            .saturating_add(n),
    )
}

/// The commands of [`Act::Amend`] on `p`: the lead's amendment plan, which
/// supersedes the latest plan, its proposal, the programme manager's
/// route, the IRC review by `members` members, and the activation.
fn amend_steps(m: &TwinGhost, p: ProposalId, cents: i64, members: u8) -> Option<Vec<Step>> {
    let lead = lead_of(p);
    let n = m.plans.get(&p).map_or(0, Vec::len).saturating_add(1);
    let plan = revision_of(p, n);
    let id = twin_amendment(p, n);
    let route = if members == 0 {
        AmendmentRoute::Exempt
    } else {
        AmendmentRoute::Irc
    };
    let mut out = vec![
        money_plan(
            lead,
            p,
            plan,
            PlanOrigin::Amendment,
            Some(m.latest_plan(p)),
            &[(revision_milestone(p, n), cents, crate::r#gen::roster::T0)],
        )
        .ok()?,
        propose_amendment(lead, id, p, plan),
        route_amendment(STAFF_PM, id, route),
    ];
    let irc = [IRC, IRC2];
    let chosen = irc.get(..usize::from(members).min(irc.len()))?;
    for i in chosen {
        out.extend(assign_amendment_declared(*i, p, id));
    }
    for i in chosen {
        out.push(irc_review(*i, amendment_assignment(*i, id), true));
    }
    out.push(activate_amendment(
        id,
        ContractId::from_raw(55_000u128.saturating_add(id.raw())),
    ));
    Some(out)
}

/// A stage 1 or stage 2 score vector: mostly above P-02 50.00, sometimes at or below it.
fn vector(g: &mut Gen) -> [u8; 2] {
    if g.weighted(&[1, 3]) == 0 {
        [g.u8_in(0..=1), g.u8_in(0..=1)]
    } else {
        [2, g.u8_in(1..=2)]
    }
}

fn reviewer(g: &mut Gen) -> AccountId {
    *g.pick(&[R1, R2])
}

/// An amendment act: a total inside or outside the call 1 P-04 of
/// [2.00, 4.00], and zero, one or two IRC members against the call 1 P-15 of two.
fn amend_act(g: &mut Gen) -> Act {
    Act::Amend(*g.pick(&[150, 250, 300, 450]), g.u8_in(0..=2))
}

/// The weight of a proposal in `state` when the machine picks the one to
/// act on. The further a proposal has come, the likelier it is picked, so
/// short cases still reach IRC review, negotiation and the grant.
fn progress_weight(state: StateTag) -> u32 {
    match state {
        StateTag::Stage1 | StateTag::Deferred => 3,
        StateTag::Stage2 | StateTag::Granted => 5,
        StateTag::Ranked => 6,
        StateTag::IrcReview => 8,
        StateTag::Negotiation => 10,
        StateTag::InExecution => 4,
        _ => 1,
    }
}

/// The acts open to `p` in state `s`, with their weights.
fn acts_for(g: &mut Gen, m: &TwinGhost, p: ProposalId, s: StateTag) -> Vec<(u32, Act)> {
    let mut out: Vec<(u32, Act)> = Vec::new();
    match s {
        StateTag::Submitted => {
            out.push((6, Act::Admit));
            out.push((2, Act::Prepare));
            out.push((2, Act::AdmitOnly));
            out.push((1, Act::Ineligible));
            out.push((1, Act::Assign(R4)));
            out.push((1, Act::MemberDeclare(R3)));
        }
        StateTag::Stage1 => {
            out.push((4, Act::Score(reviewer(g), vector(g))));
            out.push((1, Act::Correct(reviewer(g), vector(g))));
            out.push((2, Act::Close));
            out.push((4, Act::Stage1All(vector(g), vector(g))));
            out.push((1, Act::Assign(R4)));
            out.push((1, Act::Score(R4, vector(g))));
            out.push((1, Act::MemberDeclare(R3)));
            out.push((2, Act::Read(*g.pick(&[R1, R2, R3, R4]))));
        }
        StateTag::Stage2 => {
            let reentered = m.call_of(p) != call(1);
            if reentered {
                out.push((4, Act::Assign(reviewer(g))));
            }
            out.push((1, Act::MemberDeclare(R3)));
            out.push((2, Act::Read(*g.pick(&[R1, R2, R3, R4]))));
            out.push((4, Act::Stage2All));
            out.push((3, Act::NoQuestions(reviewer(g))));
            out.push((2, Act::Ask(reviewer(g))));
            out.push((1, Act::Answer));
            out.push((1, Act::Revise(*g.pick(&[250, 300, 450]))));
            if m.revisions.contains_key(&p) {
                out.push((3, Act::Score2(reviewer(g), vector(g))));
            }
            out.push((2, Act::Rank));
            out.push((1, Act::Expire));
        }
        StateTag::Deferred => out.push((4, Act::ReEnter)),
        StateTag::Ranked => {
            let c = m.call_of(p);
            let (order, _) = m.ranked_order(c);
            let n = u8::try_from(order.len()).unwrap_or(u8::MAX);
            let nominated = if g.weighted(&[1, 3]) == 0 {
                g.u8_in(0..=n)
            } else {
                n
            };
            out.push((5, Act::CutOff(c, u32::from(nominated))));
        }
        StateTag::IrcReview => {
            let i = *g.pick(&[IRC, IRC2]);
            out.push((3, Act::AssignIrc(i)));
            out.push((4, Act::Irc(i, true)));
            out.push((4, Act::IrcAll));
            out.push((1, Act::Irc(i, false)));
            out.push((1, Act::DeclineConcern));
        }
        StateTag::Negotiation => {
            // Determine and the NOTE 9 decline read P-04, so they come up most often.
            out.push((6, Act::Determine));
            out.push((3, Act::Accept));
            out.push((3, Act::Approve));
            out.push((3, Act::Contract));
            out.push((2, Act::GrantAll));
            out.push((5, Act::DeclineNegotiation));
        }
        StateTag::Granted => {
            out.push((2, Act::Start));
            out.push((3, Act::Deliverable(g.u8_in(0..=2))));
            out.push((3, amend_act(g)));
            out.push((1, Act::Terminate));
        }
        StateTag::InExecution => {
            out.push((3, Act::Deliverable(g.u8_in(0..=2))));
            out.push((3, amend_act(g)));
            out.push((1, Act::Terminate));
        }
        _ => {}
    }
    for (w, _) in &mut out {
        *w = w.saturating_mul(6);
    }
    if s.is_withdrawable() {
        out.push((1, Act::Withdraw));
    }
    out
}

/// The instant of `act` on `p`: 29 days after stage 2 began for an
/// expiry, so the P-07 window of 28 days has elapsed, and `now` otherwise.
fn act_time(m: &TwinGhost, p: ProposalId, act: Act) -> Timestamp {
    match act {
        Act::Expire => {
            let began = m.stage2_at.get(&p).copied().unwrap_or(m.now);
            let due = began
                .micros()
                .saturating_add(MICROS_PER_DAY.saturating_mul(29));
            Timestamp::from_micros(due.max(m.now.micros()))
        }
        _ => m.now,
    }
}

// ---------------------------------------------------------------------------
// The system under test
// ---------------------------------------------------------------------------

/// One twin: the reference driver, and the state the checks read.
#[derive(Clone, Debug)]
pub struct Twin {
    /// The driver over its store and vault.
    pub scenario: Scenario,
    /// The state the checks read: the driver's state, or the state with a
    /// teeth fault folded in through the public structural apply.
    pub observed: EngineState,
    /// The frozen policy of each published call, as read at its publication.
    pub snapshots: BTreeMap<CallId, FrozenPolicy>,
    /// The ledger positions of the entries that only this twin recorded:
    /// twin B's frozen edits and its renewed approvals of call 2.
    pub own: BTreeSet<u64>,
}

/// What one step did on one twin: its core records, or its refusal.
pub type Outcome = Result<Vec<Record>, Refusal>;

impl Twin {
    /// A twin after [`twin_genesis`], every step at the setup instant.
    pub fn genesis() -> Result<Twin, String> {
        let mut scenario =
            Scenario::new(twin_setup().truth()).map_err(|e| format!("open: {e:?}"))?;
        for step in twin_genesis()? {
            if let Err(r) = run_records(&mut scenario, &step, crate::r#gen::roster::T0)? {
                return Err(format!("genesis step {:?} refused: {r}", step.cmd.kind()));
            }
        }
        let observed = scenario.state().clone();
        let mut twin = Twin {
            scenario,
            observed,
            snapshots: BTreeMap::new(),
            own: BTreeSet::new(),
        };
        let f = twin
            .frozen(call(1))
            .cloned()
            .ok_or("genesis did not publish call 1")?;
        twin.snapshots.insert(call(1), f);
        Ok(twin)
    }

    /// Runs `step` at `now`. A harness failure is an error.
    pub fn run(&mut self, step: &Step, now: Timestamp) -> Result<Outcome, String> {
        let out = run_records(&mut self.scenario, step, now)?;
        self.observed = self.scenario.state().clone();
        Ok(out)
    }

    /// Runs `step` at `now` through `via`. A harness failure is an error.
    pub fn run_via(&mut self, step: &Step, now: Timestamp, via: Via) -> Result<Outcome, String> {
        if via == Via::Web {
            return self.run(step, now);
        }
        let before = records_of(&self.scenario)?.len();
        let mut ctx = self.scenario.ctx(now, step.actor);
        ctx.via = via;
        ctx.tenant_admin = step.flags.tenant_admin;
        ctx.second_tenant_admin = step.flags.second_admin;
        ctx.binds_tenant_admin = step.flags.binds_tenant_admin;
        let out = match self
            .scenario
            .execute(fstp_engine::Command::Core(step.cmd.clone()), ctx)
        {
            Ok(_) => Ok(records_of(&self.scenario)?
                .get(before..)
                .unwrap_or_default()
                .to_vec()),
            Err(fstp_engine::ExecError::Refused(r)) => Err(r),
            Err(e) => {
                return Err(format!(
                    "{:?} through {via:?}: the driver failed with {e:?}",
                    step.cmd.kind()
                ));
            }
        };
        self.observed = self.scenario.state().clone();
        Ok(out)
    }

    /// The vault questions `step` would ask at `now` through `via`, or
    /// the refusal met before asking.
    pub fn queries(&self, step: &Step, now: Timestamp, via: Via) -> Result<Vec<Query>, Refusal> {
        let mut ctx = step.ctx(now, CommandId::from_bytes(*b"twin:queries:000"));
        ctx.via = via;
        fstp_domain::queries(&self.observed.core, &step.cmd, &ctx)
    }

    /// Runs `step` at `now` as a command of this twin alone, so its entries
    /// do not count as positions of the shared ledger.
    pub fn run_own(&mut self, step: &Step, now: Timestamp) -> Result<Outcome, String> {
        let before = self.scenario.engine().head().raw();
        let out = self.run(step, now)?;
        let after = self.scenario.engine().head().raw();
        self.own.extend(before.saturating_add(1)..=after);
        Ok(out)
    }

    /// An outcome with its records normalised, see [`Twin::normalise`].
    pub fn norm(&self, out: &Outcome) -> Outcome {
        out.as_ref().map(|r| self.normalise(r)).map_err(|e| *e)
    }

    /// `records` with every ledger position they name counted among the
    /// shared entries only. Score corrections name the entry they
    /// supersede, and twin B's own entries shift its positions.
    pub fn normalise(&self, records: &[Record]) -> Vec<Record> {
        records
            .iter()
            .map(|r| match r {
                Record::ScoreRecorded(s) => {
                    let mut s = s.clone();
                    s.supersedes = s.supersedes.map(|q| {
                        let shift = self.own.range(..q.raw()).count();
                        Seq::from_raw(
                            q.raw()
                                .saturating_sub(u64::try_from(shift).unwrap_or(u64::MAX)),
                        )
                    });
                    Record::ScoreRecorded(s)
                }
                other => other.clone(),
            })
            .collect()
    }

    /// The head policy version of the programme.
    pub fn head(&self) -> Result<PolicyVersion, String> {
        fstp_domain::policy::head(&self.observed.core, P1)
            .cloned()
            .ok_or_else(|| "harness: no policy head".to_owned())
    }

    /// The frozen policy of `c`, through the one public read.
    pub fn frozen(&self, c: CallId) -> Option<&FrozenPolicy> {
        fstp_domain::policy::frozen_policy(&self.observed.core, c)
    }
}

/// Both twins, with what twin B's head should hold.
#[derive(Clone, Debug)]
pub struct TwinPair {
    /// Twin A, without frozen edits.
    pub a: Twin,
    /// Twin B, with frozen edits.
    pub b: Twin,
    /// The frozen values of the genesis head, which twin A keeps.
    pub initial: FrozenValues,
    /// The frozen values twin B's head should hold after its edits.
    pub expected_b: FrozenValues,
    /// Twin B's renewed approvals of call 2.
    pub approvals: u128,
}

/// The system under test: both twins, or why genesis failed.
#[derive(Debug)]
pub struct TwinSut {
    /// The twins.
    pub pair: Result<TwinPair, String>,
}

impl TwinSut {
    /// Both twins from genesis.
    pub fn new() -> TwinSut {
        let pair = Twin::genesis().and_then(|a| {
            let b = Twin::genesis()?;
            let initial = a.head()?.frozen;
            Ok(TwinPair {
                a,
                b,
                expected_b: initial.clone(),
                initial,
                approvals: 0,
            })
        });
        TwinSut { pair }
    }
}

impl Default for TwinSut {
    fn default() -> Self {
        TwinSut::new()
    }
}

/// What one command of the machine did.
#[derive(Debug)]
pub struct TwinOutput {
    /// What the command is.
    pub context: String,
    /// The twin comparison: `Ok` when every check of the command held.
    pub verdict: Result<(), String>,
}

// ---------------------------------------------------------------------------
// Checks
// ---------------------------------------------------------------------------

/// The live P-05 a cap question must carry: the lower of call 1's
/// publication snapshot and the head at decision time (P-05 NOTE 7, Q9).
fn expected_cap(t: &Twin) -> Result<i64, String> {
    let snapshot = t
        .snapshots
        .get(&call(1))
        .ok_or("harness: no snapshot of call 1")?
        .snapshot()
        .p05
        .amount()
        .minor();
    let live = t.head()?.live.p05.amount().minor();
    Ok(snapshot.min(live))
}

/// I-12, live values: every cap question `step` asks on `t` carries the
/// head P-05 at decision time, bounded by the call snapshot. The NOTE 9
/// decline asks the cap question too, and so does an amendment activation (I-14).
fn check_cap_read(t: &Twin, step: &Step, now: Timestamp, side: &str) -> Result<(), String> {
    let money = matches!(
        step.cmd,
        Command::DetermineAmount { .. }
            | Command::AcceptGrant { .. }
            | Command::ApproveGrant { .. }
            | Command::ContractFact { .. }
            | Command::DeclineNegotiation { .. }
            | Command::ActivateAmendment { .. }
    );
    if !money {
        return Ok(());
    }
    let ctx = step.ctx(now, CommandId::from_bytes(*b"twin:cap:read:00"));
    let Ok(queries) = fstp_domain::queries(&t.observed.core, &step.cmd, &ctx) else {
        return Ok(());
    };
    let expected = expected_cap(t)?;
    for q in queries {
        if let Query::WithinRecipientCap { cap, .. } = q
            && cap.amount().minor() != expected
        {
            return Err(format!(
                "I-12: twin {side}: {:?} asks the cap question with P-05 {} cents, but the head \
                 at decision time and the call snapshot give {expected}",
                step.cmd.kind(),
                cap.amount().minor()
            ));
        }
    }
    Ok(())
}

/// I-12, live values: every exclusion question `queries` holds carries
/// the union of call 1's P-13 snapshot and the head P-13 at decision
/// time (P-13 NOTE 7). Every twin proposal is governed by call 1.
fn check_p13_read(t: &Twin, queries: &[Query], side: &str) -> Result<(), String> {
    let mut expected = t
        .snapshots
        .get(&call(1))
        .ok_or("harness: no snapshot of call 1")?
        .snapshot()
        .p13
        .clone();
    expected.0.extend(t.head()?.live.p13.0.iter().copied());
    for q in queries {
        if let Query::InExcludedClass { classes, .. } = q
            && *classes != expected
        {
            return Err(format!(
                "I-12: twin {side}: an exclusion question carries P-13 {classes:?}, but the call \
                 snapshot and the head at decision time give {expected:?}"
            ));
        }
    }
    Ok(())
}

/// I-12, live values: the reviewer assignment `step` asks the proximity
/// question with the head P-38 list of the reviewer's organisation at
/// decision time, and asks none when the head has no list for it.
fn check_p38_read(t: &Twin, step: &Step, queries: &[Query], side: &str) -> Result<(), String> {
    let Command::Assign {
        reviewer,
        kind: AssignmentKind::Reviewer,
        ..
    } = &step.cmd
    else {
        return Ok(());
    };
    let Some(org) = organisation_of(*reviewer) else {
        return Ok(());
    };
    let expected: BTreeSet<ProximityListId> = t
        .head()?
        .live
        .p38
        .0
        .get(&org)
        .copied()
        .into_iter()
        .collect();
    let asked: BTreeSet<ProximityListId> = queries
        .iter()
        .filter_map(|q| match q {
            Query::DeclaresAffiliationOnList { list, .. } => Some(*list),
            _ => None,
        })
        .collect();
    if asked != expected {
        return Err(format!(
            "I-12: twin {side}: assigning {reviewer:?} asks the proximity lists {asked:?}, but the \
             head P-38 at decision time gives {expected:?}"
        ));
    }
    Ok(())
}

/// I-12: `step` asks the same vault questions on both twins, or meets
/// the same refusal before asking. A question built from the head of a
/// frozen value would differ on twin B. The live reads are checked too.
fn check_queries(pair: &TwinPair, step: &Step, now: Timestamp, via: Via) -> Result<(), String> {
    let qa = pair.a.queries(step, now, via);
    let qb = pair.b.queries(step, now, via);
    if qa != qb {
        return Err(format!(
            "I-12: the twins ask different vault questions for {:?} by {:?} through {via:?}\n  \
             twin A: {qa:?}\n  twin B: {qb:?}",
            step.cmd, step.actor
        ));
    }
    for (side, t, q) in [("A", &pair.a, &qa), ("B", &pair.b, &qb)] {
        if let Ok(q) = q {
            check_p13_read(t, q, side)?;
            check_p38_read(t, step, q, side)?;
        }
    }
    Ok(())
}

/// The latest published call sequence number of `t`'s programme.
fn latest_seq(t: &Twin) -> u32 {
    fstp_domain::programme::latest_published_seq(&t.observed.core, P1).map_or(0, |s| s.get())
}

/// I-12, live values: a binding end pins the head P-12 at the end, and
/// its bar is the latest published call plus that value.
fn check_end_pin(
    before_p12: u8,
    before_seq: u32,
    records: &[Record],
    side: &str,
) -> Result<(), String> {
    for r in records {
        if let Record::BindingEnded(e) = r {
            if e.p12 != CoolingOff(before_p12) {
                return Err(format!(
                    "I-12: twin {side}: the binding end pinned P-12 {:?}, but the head at the end holds {before_p12}",
                    e.p12
                ));
            }
            let bar = before_seq.saturating_add(u32::from(before_p12));
            if e.barred_through != bar {
                return Err(format!(
                    "I-12: twin {side}: the binding end bars through call {} instead of {bar}",
                    e.barred_through
                ));
            }
        }
    }
    Ok(())
}

/// The twin comparison of one step: identical records, or identical refusals.
fn compare(step: &Step, a: &Outcome, b: &Outcome) -> Result<(), String> {
    match (a, b) {
        (Ok(x), Ok(y)) if x == y => Ok(()),
        (Err(x), Err(y)) if x == y => Ok(()),
        _ => Err(format!(
            "I-12: the twins differ on {:?} by {:?}\n  twin A: {a:?}\n  twin B: {b:?}",
            step.cmd, step.actor
        )),
    }
}

/// The teeth fault: a stage 1 close of twin B built from the head P-02
/// instead of call 1's frozen P-02. `None` when the fault does not apply:
/// another command, a refusal, a head equal to the snapshot, or a forged
/// batch that the fold refuses.
fn head_instead_of_snapshot(
    before: &EngineState,
    head_seq: Seq,
    now: Timestamp,
    head_bp: u16,
    honest: &[Record],
) -> Option<(Vec<Record>, EngineState)> {
    let closed = honest.iter().find_map(|r| match r {
        Record::Stage1Closed(c) => Some(c.clone()),
        _ => None,
    })?;
    if closed.threshold().bp() == head_bp {
        return None;
    }
    let ratio = closed.score();
    let score = Frac {
        num: u128::from(ratio.num()),
        den: u128::from(ratio.den().get()),
    };
    let passed = passes_reference(
        Exact {
            num: score.num,
            den: score.den,
        },
        head_bp,
    )
    .ok()?;
    let forged_close = forge_stage1_closed(
        closed.proposal(),
        closed.recorder(),
        score,
        head_bp,
        closed.counted(),
        passed,
    )
    .ok()?;
    let (to, row) = if passed {
        (StateTag::Stage2, Row::Stage1ToStage2)
    } else {
        (StateTag::NotSelected, Row::Stage1ToNotSelected)
    };
    let forged: Vec<Record> = honest
        .iter()
        .map(|r| match r {
            Record::Stage1Closed(_) => forged_close.clone(),
            Record::Transitioned(t) if t.from == StateTag::Stage1 => {
                Record::Transitioned(Transitioned { to, row, ..*t })
            }
            other => other.clone(),
        })
        .collect();
    let mut state = before.clone();
    let mut seq = head_seq.raw();
    for r in &forged {
        seq = seq.saturating_add(1);
        fstp_engine::apply(
            &mut state,
            Seq::from_raw(seq),
            now,
            &fstp_engine::Record::Core(r.clone()),
        )
        .ok()?;
    }
    Some((forged, state))
}

impl TwinPair {
    /// Runs `step` at `now` through `via` on both twins and compares
    /// them. Returns twin A's outcome. With `faulty`, a stage 1 close of
    /// twin B is replaced by the teeth fault.
    fn shared(
        &mut self,
        step: &Step,
        now: Timestamp,
        via: Via,
        faulty: bool,
    ) -> Result<Outcome, String> {
        check_cap_read(&self.a, step, now, "A")?;
        check_cap_read(&self.b, step, now, "B")?;
        check_queries(self, step, now, via)?;
        let before_b = self.b.observed.clone();
        let head_seq = self.b.scenario.engine().head();
        let a = self.a.run_via(step, now, via)?;
        let mut b = self.b.run_via(step, now, via)?;
        if faulty
            && matches!(step.cmd, Command::CloseStage1 { .. })
            && let Ok(honest) = &b
        {
            let head_bp = self.b.head()?.frozen.p02.bp();
            if let Some((forged, state)) =
                head_instead_of_snapshot(&before_b, head_seq, now, head_bp, honest)
            {
                self.b.observed = state;
                b = Ok(forged);
            }
        }
        compare(step, &self.a.norm(&a), &self.b.norm(&b))?;
        Ok(a)
    }

    /// The checks after every command (design 6.2 row I-12).
    pub fn check(&self) -> Result<(), String> {
        for (side, t) in [("A", &self.a), ("B", &self.b)] {
            for (c, snap) in &t.snapshots {
                if t.frozen(*c) != Some(snap) {
                    return Err(format!(
                        "I-12: twin {side}: the frozen policy of call {} changed after its publication",
                        c.raw()
                    ));
                }
            }
        }
        if self.a.frozen(call(1)) != self.b.frozen(call(1)) {
            return Err("I-12: the frozen policy of call 1 differs between the twins".to_owned());
        }
        let (ha, hb) = (self.a.head()?, self.b.head()?);
        if ha.live != hb.live {
            return Err(
                "I-12: the twins' live values differ, though both ran the same live edits"
                    .to_owned(),
            );
        }
        if ha.frozen != self.initial {
            return Err(
                "I-12: twin A's head frozen values changed without a frozen edit".to_owned(),
            );
        }
        if hb.frozen != self.expected_b {
            return Err(
                "I-12: twin B's head does not hold the frozen edits it recorded".to_owned(),
            );
        }
        for (_, p) in TWIN_PROPOSALS {
            let ea = fstp_domain::decision::effective_score(&self.a.observed.core, p);
            let eb = fstp_domain::decision::effective_score(&self.b.observed.core, p);
            if ea != eb {
                return Err(format!(
                    "I-12: the effective score of proposal {} differs between the twins",
                    p.raw()
                ));
            }
        }
        Ok(())
    }

    /// A frozen edit on twin B alone.
    fn frozen_edit(
        &mut self,
        now: Timestamp,
        id: PolicyVersionId,
        edit: &FrozenEdit,
    ) -> Result<(), String> {
        let head = self.b.head()?;
        let mut v = next_version(&head, id);
        for (p, pick) in &edit.changes {
            apply_frozen(&mut v, *p, *pick).map_err(|e| format!("harness: {e}"))?;
        }
        let valid = crate::reference::policy::validate(&v)?.is_ok();
        let step = Step::by(
            PM2,
            Flags::NONE,
            Command::EditPolicy {
                base: head.id,
                version: Box::new(v.clone()),
            },
        );
        match self.b.run_own(&step, now)? {
            Ok(records) => {
                let expected = [Record::PolicyVersionRecorded {
                    version: Box::new(v.clone()),
                    author: PM2,
                }];
                if records != expected {
                    return Err(format!(
                        "I-12: a frozen edit must append exactly one policy version, the one sent, \
                         but appended {records:?}"
                    ));
                }
                if self.b.head()? != v {
                    return Err(
                        "I-12: after the frozen edit the head is not the new version".to_owned(),
                    );
                }
                if v.live != head.live {
                    return Err("harness: a frozen edit changed live values".to_owned());
                }
                self.expected_b = v.frozen;
                Ok(())
            }
            Err(r) if valid => Err(format!(
                "I-12: twin B refused a valid frozen edit {edit:?}: {r}"
            )),
            Err(_) => Ok(()),
        }
    }

    /// A live edit on both twins, each on its own head.
    fn live_edit(
        &mut self,
        now: Timestamp,
        id: PolicyVersionId,
        edit: LiveEdit,
    ) -> Result<(), String> {
        let mut outcomes = Vec::new();
        for t in [&mut self.a, &mut self.b] {
            let head = t.head()?;
            let mut v = next_version(&head, id);
            apply_live(&mut v, edit)?;
            let step = Step::by(
                STAFF_PM,
                Flags::NONE,
                Command::EditPolicy {
                    base: head.id,
                    version: Box::new(v),
                },
            );
            outcomes.push(t.run(&step, now)?.map(|r| r.len()));
        }
        match outcomes.as_slice() {
            [Ok(_), Ok(_)] => Ok(()),
            [Err(x), Err(y)] if x == y => Ok(()),
            _ => Err(format!(
                "I-12: the twins differ on the live edit {edit:?}: {outcomes:?}"
            )),
        }
    }

    /// The publication of call 2 on both twins, each with its own head's
    /// P-21 model. Twin B approves the call again if its approval was revoked.
    fn publish2(&mut self, now: Timestamp) -> Result<Vec<Record>, String> {
        let mut outcomes = Vec::new();
        let mut a_records = Vec::new();
        for (side, t) in [("A", &mut self.a), ("B", &mut self.b)] {
            let head = t.head()?;
            let revoked = fstp_domain::programme::call(&t.observed.core, call(2))
                .is_some_and(|v| v.approval().is_none() && v.seq().is_none());
            if side == "B" && revoked {
                self.approvals = self.approvals.saturating_add(1);
                let approve = Step::by(
                    STAFF_PM,
                    Flags::NONE,
                    Command::ApproveCallPublication {
                        call: call(2),
                        decision: fstp_domain::id::DecisionId::from_raw(
                            APPROVAL_BASE.saturating_add(self.approvals),
                        ),
                    },
                );
                if let Err(r) = t.run_own(&approve, now)? {
                    return Err(format!(
                        "harness: twin B could not approve call 2 again: {r}"
                    ));
                }
            }
            let step = Step::by(
                STAFF_PM,
                Flags::NONE,
                Command::PublishCall {
                    call: call(2),
                    config: fstp_domain::id::LlmConfigId::from_raw(2),
                    config_model: head.frozen.p21.primary.clone(),
                },
            );
            let out = t.run(&step, now)?;
            if side == "A"
                && let Ok(r) = &out
            {
                a_records.clone_from(r);
            }
            if out.is_ok() {
                let f = t
                    .frozen(call(2))
                    .cloned()
                    .ok_or("I-12: call 2 has no frozen policy after its publication")?;
                if *f.values() != head.frozen {
                    return Err(format!(
                        "I-12: twin {side}: call 2 published after the edits does not freeze the head values"
                    ));
                }
                if f.snapshot().p05 != head.live.p05 || f.snapshot().p13 != head.live.p13 {
                    return Err(format!(
                        "I-12: twin {side}: the publication snapshot of P-05 and P-13 is not the head's"
                    ));
                }
                t.snapshots.insert(call(2), f);
            }
            outcomes.push(out.map(|r| {
                r.into_iter()
                    .filter_map(|x| match x {
                        Record::CallPublished {
                            call,
                            seq,
                            config,
                            by,
                            ..
                        } => Some((call, seq, config, by)),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
            }));
        }
        match outcomes.as_slice() {
            [Ok(x), Ok(y)] if x == y => {}
            [Err(x), Err(y)] if x == y => {}
            _ => {
                return Err(format!(
                    "I-12: the twins differ on the publication of call 2: {outcomes:?}"
                ));
            }
        }
        if let (Some(fa), Some(fb)) = (
            self.a.snapshots.get(&call(2)),
            self.b.snapshots.get(&call(2)),
        ) {
            if *fb.values() != self.expected_b {
                return Err("I-12: call 2 does not use twin B's edited values".to_owned());
            }
            if *fa.values() != self.initial {
                return Err("I-12: twin A's call 2 does not use the unedited values".to_owned());
            }
        }
        Ok(a_records)
    }

    /// The end of a spare binding on both twins, with the P-12 pin checks.
    fn end_spare(&mut self, now: Timestamp, binding: BindingId) -> Result<Outcome, String> {
        let step = end(binding, now);
        let pins = [
            (self.a.head()?.live.p12.0, latest_seq(&self.a)),
            (self.b.head()?.live.p12.0, latest_seq(&self.b)),
        ];
        let a = self.a.run(&step, now)?;
        let b = self.b.run(&step, now)?;
        compare(&step, &self.a.norm(&a), &self.b.norm(&b))?;
        for ((side, out), (p12, seq)) in [("A", &a), ("B", &b)].into_iter().zip(pins) {
            if let Ok(records) = out {
                check_end_pin(p12, seq, records, side)?;
            }
        }
        Ok(a)
    }
}

// ---------------------------------------------------------------------------
// The machine
// ---------------------------------------------------------------------------

/// The fstp-prop twin machine of I-12 over the full engine.
#[derive(Debug, Default)]
pub struct TwinMachine {
    /// Commands per case.
    pub max_commands: usize,
    /// Teeth: twin B computes each stage 1 close from the head P-02.
    pub faulty: bool,
    /// Twin A's records of the latest command and its instant, for `next_state`.
    last: RefCell<Option<(Timestamp, Vec<Record>)>>,
}

impl TwinMachine {
    /// The machine with `max_commands` commands per case.
    pub fn new(max_commands: usize) -> TwinMachine {
        TwinMachine {
            max_commands,
            faulty: false,
            last: RefCell::new(None),
        }
    }

    /// The same machine whose twin B reads the head instead of the snapshot.
    pub fn head_reading(max_commands: usize) -> TwinMachine {
        TwinMachine {
            faulty: true,
            ..TwinMachine::new(max_commands)
        }
    }

    fn gen_eval(&self, g: &mut Gen, m: &TwinGhost) -> Option<TwinCmd> {
        let open: Vec<ProposalId> = m
            .states
            .iter()
            .filter(|(_, s)| !s.is_terminal())
            .map(|(p, _)| *p)
            .collect();
        if open.is_empty() {
            return None;
        }
        let weights: Vec<u32> = open.iter().map(|p| progress_weight(m.state(*p))).collect();
        let p = *open.get(g.weighted(&weights))?;
        let s = m.state(p);
        let acts = acts_for(g, m, p, s);
        let weights: Vec<u32> = acts.iter().map(|(w, _)| *w).collect();
        let (_, act) = *acts.get(g.weighted(&weights))?;
        let on = match act {
            Act::CutOff(..) => None,
            _ => Some((p, s)),
        };
        // A cut-off of call 2 is governed by call 2, whose P-77 differs
        // between the twins by design, so it never arrives through MCP.
        let mcp = g.weighted(&[7, 1]) == 1 && !matches!(act, Act::CutOff(c, _) if c != call(1));
        Some(TwinCmd::Eval {
            now: act_time(m, p, act),
            act,
            on,
            mcp,
            steps: act_steps(m, Some(p), act)?,
        })
    }
}

impl StateMachine for TwinMachine {
    type Model = TwinGhost;
    type Sut = TwinSut;
    type Command = TwinCmd;
    type Output = TwinOutput;

    fn init_model(&self) -> TwinGhost {
        TwinGhost::new()
    }

    fn init_sut(&self) -> TwinSut {
        TwinSut::new()
    }

    fn command(&self, g: &mut Gen, m: &TwinGhost) -> TwinCmd {
        let now = m.now;
        let spares: Vec<BindingId> = spare_bindings()
            .into_iter()
            .filter(|b| !m.ended.contains(b))
            .collect();
        let pick = g.weighted(&[
            10,
            3,
            1,
            u32::from(!m.published2),
            u32::from(!spares.is_empty()),
        ]);
        match pick {
            1 => TwinCmd::Frozen {
                now,
                id: PolicyVersionId::from_raw(FROZEN_VERSION_BASE.saturating_add(m.frozen_edits)),
                edit: gen_frozen_edit(g),
            },
            2 => TwinCmd::Live {
                now,
                id: PolicyVersionId::from_raw(LIVE_VERSION_BASE.saturating_add(m.live_edits)),
                edit: match g.weighted(&[1, 1, 1, 1]) {
                    0 => LiveEdit::P05(*g.pick(&[250, 300, 600, 1_000, 2_000])),
                    1 => LiveEdit::P12(g.u8_in(0..=2)),
                    2 => LiveEdit::P13(g.u8_in(0..=2)),
                    _ => LiveEdit::P38(g.u8_in(0..=3)),
                },
            },
            3 => TwinCmd::Publish2 { now },
            4 if !spares.is_empty() => TwinCmd::EndSpare {
                now,
                binding: *g.pick(&spares),
            },
            _ => self.gen_eval(g, m).unwrap_or(TwinCmd::Publish2 { now }),
        }
    }

    fn precondition(&self, m: &TwinGhost, cmd: &TwinCmd) -> bool {
        if cmd.now() < m.now {
            return false;
        }
        match cmd {
            TwinCmd::Eval {
                on: Some((p, s)), ..
            } => m.state(*p) == *s,
            TwinCmd::Publish2 { .. } => !m.published2,
            TwinCmd::EndSpare { binding, .. } => !m.ended.contains(binding),
            _ => true,
        }
    }

    fn run(&self, sut: &mut TwinSut, cmd: &TwinCmd) -> TwinOutput {
        self.last.replace(None);
        let context = format!("{cmd:?}");
        let pair = match sut.pair.as_mut() {
            Ok(p) => p,
            Err(e) => {
                return TwinOutput {
                    context,
                    verdict: Err(format!("harness: genesis failed: {e}")),
                };
            }
        };
        let now = cmd.now();
        let mut echo: Vec<Record> = Vec::new();
        let verdict = (|| -> Result<(), String> {
            match cmd {
                TwinCmd::Eval { steps, mcp, .. } => {
                    let via = if *mcp { Via::Mcp } else { Via::Web };
                    for step in steps {
                        if let Ok(records) = pair.shared(step, now, via, self.faulty)? {
                            echo.extend(records);
                        }
                    }
                    Ok(())
                }
                TwinCmd::Frozen { id, edit, .. } => pair.frozen_edit(now, *id, edit),
                TwinCmd::Live { id, edit, .. } => pair.live_edit(now, *id, *edit),
                TwinCmd::Publish2 { .. } => {
                    echo.extend(pair.publish2(now)?);
                    Ok(())
                }
                TwinCmd::EndSpare { binding, .. } => {
                    if let Ok(records) = pair.end_spare(now, *binding)? {
                        echo.extend(records);
                    }
                    Ok(())
                }
            }
        })();
        self.last.replace(Some((now, echo)));
        TwinOutput { context, verdict }
    }

    fn postcondition(
        &self,
        _m: &TwinGhost,
        _cmd: &TwinCmd,
        out: &TwinOutput,
    ) -> Result<(), String> {
        out.verdict.clone()
    }

    fn next_state(&self, m: &mut TwinGhost, cmd: &TwinCmd) {
        m.now = m.now.max(cmd.now());
        match cmd {
            TwinCmd::Frozen { edit, .. } => {
                m.frozen_edits = m.frozen_edits.saturating_add(1);
                m.edited.extend(edit.changes.iter().map(|(p, _)| *p));
            }
            TwinCmd::Live { .. } => m.live_edits = m.live_edits.saturating_add(1),
            _ => {}
        }
        if let Some((now, records)) = self.last.borrow().as_ref() {
            m.fold(records, *now);
        }
    }

    fn invariant(&self, _m: &TwinGhost, sut: &TwinSut) -> Result<(), String> {
        match &sut.pair {
            Ok(p) => p.check(),
            Err(e) => Err(format!("harness: genesis failed: {e}")),
        }
    }

    fn max_commands(&self) -> usize {
        self.max_commands
    }
}

// ---------------------------------------------------------------------------
// The witness
// ---------------------------------------------------------------------------

/// What the scripted witness run reached.
#[derive(Debug)]
pub struct TwinWitness {
    /// The commands run, in order.
    pub commands: Vec<TwinCmd>,
    /// The ghost at the end.
    pub ghost: TwinGhost,
    /// Both twins at the end.
    pub pair: TwinPair,
}

/// A scripted run through the machine's own run, postcondition, state and
/// invariant. It fails at the first check that fails.
struct Script {
    machine: TwinMachine,
    ghost: TwinGhost,
    sut: TwinSut,
    commands: Vec<TwinCmd>,
}

impl Script {
    fn new() -> Result<Script, String> {
        let machine = TwinMachine::new(0);
        let ghost = machine.init_model();
        let sut = machine.init_sut();
        machine.invariant(&ghost, &sut)?;
        Ok(Script {
            machine,
            ghost,
            sut,
            commands: Vec::new(),
        })
    }

    fn push(&mut self, cmd: TwinCmd) -> Result<(), String> {
        if !self.machine.precondition(&self.ghost, &cmd) {
            return Err(format!("witness: the precondition fails for {cmd:?}"));
        }
        let out = self.machine.run(&mut self.sut, &cmd);
        self.machine.postcondition(&self.ghost, &cmd, &out)?;
        self.machine.next_state(&mut self.ghost, &cmd);
        self.machine.invariant(&self.ghost, &self.sut)?;
        self.commands.push(cmd);
        Ok(())
    }

    fn eval(&mut self, p: ProposalId, act: Act) -> Result<(), String> {
        let g = &self.ghost;
        let cmd = TwinCmd::Eval {
            now: act_time(g, p, act),
            act,
            on: (!matches!(act, Act::CutOff(..))).then(|| (p, g.state(p))),
            mcp: false,
            steps: act_steps(g, Some(p), act)
                .ok_or_else(|| format!("witness: {act:?} on {p:?} cannot be built"))?,
        };
        self.push(cmd)
    }

    fn frozen(&mut self, param: ParamId, pick: u8) -> Result<(), String> {
        let cmd = TwinCmd::Frozen {
            now: self.ghost.now,
            id: PolicyVersionId::from_raw(
                FROZEN_VERSION_BASE.saturating_add(self.ghost.frozen_edits),
            ),
            edit: FrozenEdit {
                changes: vec![(param, pick)],
            },
        };
        self.push(cmd)
    }

    fn live(&mut self, edit: LiveEdit) -> Result<(), String> {
        let cmd = TwinCmd::Live {
            now: self.ghost.now,
            id: PolicyVersionId::from_raw(LIVE_VERSION_BASE.saturating_add(self.ghost.live_edits)),
            edit,
        };
        self.push(cmd)
    }
}

/// The scripted run behind the machine's non-vacuity witness.
///
/// Twin B edits every editable frozen parameter, one per edit, between
/// the evaluation commands. PA goes through stage 1 and "no questions" to
/// the cut-off, IRC review, negotiation and GRANTED. PB is deferred after
/// an unanswered question. Call 2 is published after the edits, and PB
/// re-enters it. PC fails its knock-out. A live P-12 edit precedes a
/// binding end. Live P-05, P-13 and P-38 edits precede the assignments
/// after re-entry and the grant facts, so the cap, exclusion and
/// proximity questions carry values that differ from the call snapshot.
/// Every check of the machine holds after each command.
pub fn witness_run() -> Result<TwinWitness, String> {
    let mut s = Script::new()?;
    let mut params = editable_frozen().into_iter();
    let before: [(ProposalId, Act); 18] = [
        (PA, Act::Admit),
        (PB, Act::Admit),
        (PC, Act::Ineligible),
        (PA, Act::Score(R1, [2, 1])),
        (PA, Act::Score(R2, [2, 2])),
        (PB, Act::Score(R1, [2, 2])),
        (PB, Act::Score(R2, [1, 2])),
        (PA, Act::Close),
        (PB, Act::Close),
        (PA, Act::NoQuestions(R1)),
        (PA, Act::NoQuestions(R2)),
        (PB, Act::Ask(R1)),
        (PA, Act::CutOff(call(1), 1)),
        (PA, Act::AssignIrc(IRC)),
        (PA, Act::AssignIrc(IRC2)),
        (PA, Act::Irc(IRC, true)),
        (PA, Act::Irc(IRC2, true)),
        (PB, Act::Expire),
    ];
    for (i, (p, act)) in (0u8..).zip(before) {
        if let Some(param) = params.next() {
            s.frozen(param, i % 3)?;
        }
        s.eval(p, act)?;
    }
    for param in params {
        s.frozen(param, 1)?;
    }
    let now = s.ghost.now;
    s.push(TwinCmd::Publish2 { now })?;
    s.live(LiveEdit::P12(2))?;
    let [spare, _] = spare_bindings();
    s.push(TwinCmd::EndSpare {
        now,
        binding: spare,
    })?;
    s.live(LiveEdit::P05(600))?;
    s.live(LiveEdit::P13(2))?;
    s.live(LiveEdit::P38(2))?;
    for (p, act) in [
        (PB, Act::ReEnter),
        (PB, Act::Assign(R1)),
        (PB, Act::Assign(R2)),
        (PA, Act::Determine),
        (PA, Act::Accept),
        (PA, Act::Approve),
        (PA, Act::Contract),
    ] {
        s.eval(p, act)?;
    }
    let pair = s.sut.pair?;
    Ok(TwinWitness {
        commands: s.commands,
        ghost: s.ghost,
        pair,
    })
}

/// The scripted run of a repeat grant after a P-26 edit (I-12, I-15).
///
/// PA and PB both reach NEGOTIATION in call 1. PA is granted and its
/// effective milestone gets an accepted deliverable under Apache-2.0,
/// which call 1's P-26 allows. Twin B then edits P-26 to MIT alone, and
/// PB runs every grant fact. PA's record stays complete under call 1's
/// P-26, so a guard that read the head P-26 would ask twin B's vault
/// another I-15 question. Every check of the machine holds after each command.
pub fn witness_repeat_grant_run() -> Result<TwinWitness, String> {
    let mut s = Script::new()?;
    let before: [(ProposalId, Act); 26] = [
        (PA, Act::Admit),
        (PB, Act::Admit),
        (PA, Act::Score(R1, [2, 2])),
        (PA, Act::Score(R2, [2, 2])),
        (PB, Act::Score(R1, [2, 1])),
        (PB, Act::Score(R2, [2, 1])),
        (PA, Act::Close),
        (PB, Act::Close),
        (PA, Act::NoQuestions(R1)),
        (PA, Act::NoQuestions(R2)),
        (PB, Act::NoQuestions(R1)),
        (PB, Act::NoQuestions(R2)),
        (PA, Act::CutOff(call(1), 2)),
        (PA, Act::AssignIrc(IRC)),
        (PA, Act::AssignIrc(IRC2)),
        (PB, Act::AssignIrc(IRC)),
        (PB, Act::AssignIrc(IRC2)),
        (PA, Act::Irc(IRC, true)),
        (PA, Act::Irc(IRC2, true)),
        (PB, Act::Irc(IRC, true)),
        (PB, Act::Irc(IRC2, true)),
        (PA, Act::Determine),
        (PA, Act::Accept),
        (PA, Act::Approve),
        (PA, Act::Contract),
        (PA, Act::Deliverable(1)),
    ];
    for (p, act) in before {
        s.eval(p, act)?;
    }
    s.frozen(ParamId::P26, 1)?;
    for act in [Act::Determine, Act::Accept, Act::Approve, Act::Contract] {
        s.eval(PB, act)?;
    }
    let pair = s.sut.pair?;
    Ok(TwinWitness {
        commands: s.commands,
        ghost: s.ghost,
        pair,
    })
}

/// The scripted run of the NOTE 9 decline and an amendment after frozen
/// edits of P-04 and P-15 (I-12, I-13).
///
/// PA and PB reach NEGOTIATION in call 1. Twin B then edits P-04 to
/// [0, 1.00], which excludes the plan total of 3.00 EUR that call 1's
/// P-04 of [2.00, 4.00] admits. The decline of PA is refused on both
/// twins, since no NOTE 9 reason holds under call 1's P-04. A live P-05
/// edit to 2.50 EUR then lets the decline of PA record "no amount within
/// the cap", and a second live edit restores 10.00 EUR. PB is granted at
/// 3.00 EUR. Twin B edits P-15 to one. An amendment with one IRC member
/// stays inactive under call 1's P-15 of two, and one with two members
/// is activated at 3.00 EUR. Every check of the machine holds after each command.
pub fn witness_decline_run() -> Result<TwinWitness, String> {
    let mut s = Script::new()?;
    let to_negotiation: [(ProposalId, Act); 10] = [
        (PA, Act::Admit),
        (PB, Act::Admit),
        (PC, Act::Ineligible),
        (PA, Act::Stage1All([2, 2], [2, 2])),
        (PB, Act::Stage1All([2, 1], [2, 1])),
        (PA, Act::Stage2All),
        (PB, Act::Stage2All),
        (PA, Act::CutOff(call(1), 2)),
        (PA, Act::IrcAll),
        (PB, Act::IrcAll),
    ];
    for (p, act) in to_negotiation {
        s.eval(p, act)?;
    }
    for p in [PA, PB] {
        if s.ghost.state(p) != StateTag::Negotiation {
            return Err(format!("witness: {p:?} did not reach NEGOTIATION"));
        }
    }
    s.frozen(ParamId::P04, 1)?;
    s.eval(PA, Act::DeclineNegotiation)?;
    if s.ghost.state(PA) != StateTag::Negotiation {
        return Err(
            "witness: the decline of PA was accepted, though call 1's P-04 admits its plan total"
                .to_owned(),
        );
    }
    s.live(LiveEdit::P05(250))?;
    s.eval(PA, Act::DeclineNegotiation)?;
    s.live(LiveEdit::P05(1_000))?;
    s.eval(PB, Act::GrantAll)?;
    if s.ghost.state(PB) != StateTag::Granted {
        return Err("witness: PB was not granted under call 1's P-04".to_owned());
    }
    s.frozen(ParamId::P15, 0)?;
    s.eval(PB, Act::Amend(TWIN_PLAN_CENTS, 1))?;
    if s.ghost.activated != 0 {
        return Err(
            "witness: an amendment with one IRC member was activated under call 1's P-15 of two"
                .to_owned(),
        );
    }
    s.eval(PB, Act::Amend(TWIN_PLAN_CENTS, 2))?;
    let pair = s.sut.pair?;
    Ok(TwinWitness {
        commands: s.commands,
        ghost: s.ghost,
        pair,
    })
}
