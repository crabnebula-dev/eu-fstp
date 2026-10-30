//! Generators, fixtures and the fstp-prop machine for policy, programmes and calls (design section 6.1).
//!
//! Synthetic data only: numeric ids, generated model names and opaque
//! values. No real personal data.
//!
//! - [`base_version`] builds a complete, valid policy version. Its frozen
//!   and live opaque maps hold exactly the untyped parameters, which the
//!   pure I-12 test checks against the spec text.
//! - [`setup`] reaches a start state from genesis through production
//!   commands: programmes, programme managers and call drafters.
//! - [`PolicyWorld`] drives that start state step by step for the
//!   example tests, with a reference [`Ghost`] beside it.
//! - [`PolicyMachine`] is the fstp-prop machine over `CreateProgramme`,
//!   `EditPolicy`, `DraftCall`, `EditCall`, `ApproveCallPublication`,
//!   `PublishCall` and, since M4 change D2, the core `ActivateProgramme`.
//!   Its postconditions compare accept and refuse with the reference in
//!   both directions. Its invariant checks I-12 and I-23 after every step.
//!   A programme the machine creates stays a draft until an activation is
//!   accepted, and the reference refuses call commands on a draft (D3).
//!
//! # I-12: `FrozenPolicy` cannot be forged
//!
//! `FrozenPolicy` is built only by the fold of a `CallPublished` record
//! (design 2.4 point 1). A struct literal does not compile outside the
//! domain crate, and its twin, which only copies one, does:
//!
//! ```compile_fail
//! use fstp_domain::policy::FrozenPolicy;
//! fn forge(f: &FrozenPolicy) -> FrozenPolicy {
//!     FrozenPolicy { call: f.call(), version: f.version(), values: f.values().clone().into(), snapshot: f.snapshot().clone().into() }
//! }
//! ```
//!
//! ```no_run
//! use fstp_domain::policy::FrozenPolicy;
//! fn forge(f: &FrozenPolicy) -> FrozenPolicy {
//!     f.clone()
//! }
//! ```
//!
//! No JSON decoder builds one either (design 2.4, witnesses never
//! implement `FromJson`):
//!
//! ```compile_fail
//! use fstp_json::FromJson;
//! type T = fstp_domain::policy::FrozenPolicy;
//! fn decode(v: &fstp_json::Value) -> Option<T> { T::from_json(v).ok() }
//! ```
//!
//! ```no_run
//! use fstp_json::FromJson;
//! type T = fstp_json::Value;
//! fn decode(v: &fstp_json::Value) -> Option<T> { T::from_json(v).ok() }
//! ```

use core::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::num::{NonZeroU8, NonZeroU16};

use fstp_domain::command::{Actor, Command, Ctx, Via};
use fstp_domain::id::{
    AccountId, BindingId, CallId, ClassId, ContentDigest, CriterionId, DecisionId,
    KnockOutCriterionId, LlmConfigId, PolicyVersionId, ProgrammeId, TextId, TextRef,
};
use fstp_domain::policy::{
    AgentContentAccess, EffectiveScoreRule, ExclusionClasses, FrozenValues, FunderProfileRef,
    InferenceBinding, IrcExemptions, KnockOutCriteria, KnockOutCriterion, LicenceSet, LiveValues,
    McpBindingActions, ModelRef, OpaqueValue, ParamId, PolicyVersion, ProximityLists, ReadAccess,
    ReviewerAnonymity, SpdxId, TieBreakRule, VotingRules,
};
use fstp_domain::record::Record;
use fstp_domain::roles::{CoolingOff, Role};
use fstp_domain::scoring::{Criteria, Criterion};
use fstp_domain::time::{Days, Timestamp, ZoneName};
use fstp_engine::{ExecError, Record as EngineRecord};
use fstp_ledger::{Entry, Seq};
use fstp_money::{Amount, AmountRange, Currency, NonNegAmount, Percent};
use fstp_prop::{Gen, StateMachine};

use crate::harness::prop::{ledger_step, two_way_exec};
use crate::mc::policy_model::check_i12;
use crate::reference::policy::{CallGhost, Ghost, Verdict};
use crate::scenario::Scenario;
use crate::vault::{GroundTruth, IdentityTag};

// ---------------------------------------------------------------------------
// Synthetic accounts and ids
// ---------------------------------------------------------------------------

/// The tenant admin. It holds no programme binding.
pub const ADMIN: AccountId = AccountId::from_raw(1);
/// The second tenant admin, who approves the activation of every setup
/// programme and builds nothing (M4 changes D1, D2 and D8, I-67). It is
/// [`crate::activation::APPROVER`]. It holds no programme binding and is
/// verified with its own identity.
pub const APPROVER: AccountId = crate::activation::APPROVER;
/// Programme manager in programme 1.
pub const PM_A: AccountId = AccountId::from_raw(11);
/// Programme manager in programme 1.
pub const PM_B: AccountId = AccountId::from_raw(12);
/// Programme manager in programmes 1 and 2.
pub const PM_C: AccountId = AccountId::from_raw(13);
/// Programme manager in programme 2.
pub const PM_D: AccountId = AccountId::from_raw(14);
/// Call drafter in programme 1.
pub const DRAFTER_1: AccountId = AccountId::from_raw(21);
/// Call drafter in programme 2.
pub const DRAFTER_2: AccountId = AccountId::from_raw(22);
/// A verified account without any binding.
pub const STRANGER: AccountId = AccountId::from_raw(31);

/// Every account the machine draws an actor from.
pub const ACTORS: [AccountId; 8] = [
    ADMIN, PM_A, PM_B, PM_C, PM_D, DRAFTER_1, DRAFTER_2, STRANGER,
];

/// The first programme.
pub const P1: ProgrammeId = ProgrammeId::from_raw(1);
/// The second programme.
pub const P2: ProgrammeId = ProgrammeId::from_raw(2);

/// The bindings the setup grants: account, programme and role.
pub const BINDINGS_P1: [(AccountId, Role); 4] = [
    (PM_A, Role::ProgrammeManager),
    (PM_B, Role::ProgrammeManager),
    (PM_C, Role::ProgrammeManager),
    (DRAFTER_1, Role::CallDrafter),
];
/// The bindings the setup grants in programme 2.
pub const BINDINGS_P2: [(AccountId, Role); 3] = [
    (PM_C, Role::ProgrammeManager),
    (PM_D, Role::ProgrammeManager),
    (DRAFTER_2, Role::CallDrafter),
];

/// The primary model of the base policy.
pub const MODEL_A: &str = "synthetic-model-a";
/// The fallback model of the base policy.
pub const MODEL_B: &str = "synthetic-model-b";
/// A model on no list of the base policy.
pub const MODEL_C: &str = "synthetic-model-c";

/// Call opening in the machines, far after every command time.
pub const OPENS: Timestamp = Timestamp::from_micros(1_000_000_000_000);
/// Call deadline in the machines.
pub const DEADLINE: Timestamp = Timestamp::from_micros(2_000_000_000_000);
/// The first command time of a setup.
pub const T0: i64 = 1_000_000;

/// The frozen parameters without a typed `FrozenValues` field, as
/// `base_version` fills them (design 2.4). The pure I-12 test checks this
/// list against the spec text. P-75 left the list with M4 change D6,
/// which types it.
pub const FROZEN_OPAQUE: [ParamId; 17] = [
    ParamId::P08,
    ParamId::P23,
    ParamId::P25,
    ParamId::P28,
    ParamId::P29,
    ParamId::P30,
    ParamId::P34,
    ParamId::P44,
    ParamId::P55,
    ParamId::P59,
    ParamId::P60,
    ParamId::P61,
    ParamId::P62,
    ParamId::P63,
    ParamId::P64,
    ParamId::P65,
    ParamId::P66,
];

/// The live programme parameters without a typed `LiveValues` field, as
/// `base_version` fills them.
pub const LIVE_OPAQUE: [ParamId; 27] = [
    ParamId::P06,
    ParamId::P18,
    ParamId::P19,
    ParamId::P22,
    ParamId::P27,
    ParamId::P31,
    ParamId::P32,
    ParamId::P33,
    ParamId::P35,
    ParamId::P36,
    ParamId::P37,
    ParamId::P40,
    ParamId::P41,
    ParamId::P42,
    ParamId::P43,
    ParamId::P45,
    ParamId::P46,
    ParamId::P47,
    ParamId::P48,
    ParamId::P49,
    ParamId::P50,
    ParamId::P51,
    ParamId::P52,
    ParamId::P54,
    ParamId::P57,
    ParamId::P67,
    ParamId::P76,
];

// ---------------------------------------------------------------------------
// Value builders
// ---------------------------------------------------------------------------

/// A text reference with synthetic id `n` and a digest derived from `n`.
pub fn text(n: u128) -> TextRef {
    let mut d = [0u8; 32];
    let (head, _) = d.split_at_mut(16);
    head.copy_from_slice(&n.to_be_bytes());
    TextRef::new(TextId::from_raw(n), ContentDigest::from_bytes(d))
}

/// The opaque value of the JSON string `s`.
pub fn opaque(s: &str) -> Result<OpaqueValue, String> {
    OpaqueValue::from_value(&fstp_json::Value::String(s.to_owned()))
        .map_err(|e| format!("opaque value: {e:?}"))
}

/// A EUR amount of `minor` cents, zero or more.
pub fn eur(minor: i64) -> Result<NonNegAmount, String> {
    let a = Amount::from_minor(minor, Currency::Eur).map_err(|e| format!("amount: {e:?}"))?;
    NonNegAmount::new(a).map_err(|e| format!("amount: {e:?}"))
}

/// The P-01 value with `weights` on criteria 1, 2, 3 and scale maximum `n`.
pub fn criteria(n: u8, weights: [u16; 3]) -> Result<Criteria, String> {
    let scale = NonZeroU8::new(n).ok_or("scale maximum zero")?;
    let mut items = Vec::new();
    for (i, w) in (1u128..).zip(weights) {
        items.push(Criterion {
            id: CriterionId::from_raw(i),
            weight: NonZeroU16::new(w).ok_or("weight zero")?,
        });
    }
    Criteria::new(scale, items).map_err(|e| format!("criteria: {e}"))
}

/// The P-09 value with three knock-out criteria whose texts start at `first_text`.
pub fn knock_outs(first_text: u128) -> KnockOutCriteria {
    KnockOutCriteria(
        (0u128..3)
            .map(|i| KnockOutCriterion {
                id: KnockOutCriterionId::from_raw(i.saturating_add(1)),
                text: text(first_text.saturating_add(i)),
            })
            .collect(),
    )
}

/// A complete and valid policy version with SuperSAFE-shaped values
/// (`SPEC/02-domain/policy-parameters.md`) and N = 4 for P-01.
pub fn base_version(
    id: PolicyVersionId,
    programme: ProgrammeId,
    parent: Option<PolicyVersionId>,
) -> Result<PolicyVersion, String> {
    let one = NonZeroU8::MIN;
    let two = one.checked_add(1).ok_or("two")?;
    let mut frozen_opaque = BTreeMap::new();
    for p in FROZEN_OPAQUE {
        frozen_opaque.insert(p, opaque(&format!("synthetic {}", p.spec_id()))?);
    }
    let mut live_opaque = BTreeMap::new();
    for p in LIVE_OPAQUE {
        live_opaque.insert(p, opaque(&format!("synthetic {}", p.spec_id()))?);
    }
    let p04 =
        AmountRange::new(eur(500_000)?, eur(10_000_000)?).map_err(|e| format!("P-04: {e:?}"))?;
    Ok(PolicyVersion {
        id,
        programme,
        parent,
        currency: Currency::Eur,
        frozen: FrozenValues {
            p01: criteria(4, [30, 40, 30])?,
            p02: Percent::from_bp(7_500).ok_or("P-02")?,
            p03: two,
            p04,
            p07: Days::new(28),
            p09: knock_outs(1_000),
            p10: ReadAccess::AssignedReviewersOnly,
            p11: ReviewerAnonymity::Anonymous,
            p14: IrcExemptions(opaque("synthetic P-14")?),
            p15: two,
            p16: VotingRules(opaque("synthetic P-16")?),
            p17: TieBreakRule(opaque("synthetic P-17")?),
            p21: InferenceBinding {
                provider: opaque("synthetic provider")?,
                primary: ModelRef(MODEL_A.to_owned()),
                fallbacks: vec![ModelRef(MODEL_B.to_owned())],
            },
            p24: EffectiveScoreRule::HigherOfOriginalAndRevised,
            p26: LicenceSet(
                [SpdxId("Apache-2.0".to_owned()), SpdxId("MIT".to_owned())]
                    .into_iter()
                    .collect(),
            ),
            p39: two,
            p53: FunderProfileRef(opaque("synthetic funder profile")?),
            p75: AgentContentAccess::Off,
            p77: McpBindingActions::DraftOnly,
            opaque: frozen_opaque,
        },
        live: LiveValues {
            p05: eur(40_000_000)?,
            p12: CoolingOff(1),
            p13: ExclusionClasses([ClassId::from_raw(1)].into_iter().collect()),
            p38: ProximityLists(BTreeMap::new()),
            p56: Some(eur(200_000_000)?),
            p58: Some(eur(50_000_000)?),
            opaque: live_opaque,
        },
    })
}

/// A copy of `head` as the next version `id`, with `head` as parent.
pub fn next_version(head: &PolicyVersion, id: PolicyVersionId) -> PolicyVersion {
    let mut v = head.clone();
    v.id = id;
    v.parent = Some(head.id);
    v
}

// ---------------------------------------------------------------------------
// Defects and edits
// ---------------------------------------------------------------------------

/// A change to a policy version that makes it invalid, or valid with a
/// warning only. The reference decides which (`reference::policy::validate`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Defect {
    /// No change.
    None,
    /// A frozen opaque key is missing (I-12).
    DropFrozenOpaque(ParamId),
    /// A typed frozen parameter also sits in the frozen opaque map.
    TypedInFrozenOpaque(ParamId),
    /// A live parameter sits in the frozen opaque map, so it would freeze.
    LiveInFrozenOpaque(ParamId),
    /// A frozen parameter sits in the live opaque map, so it would escape freezing (I-12).
    FrozenInLiveOpaque(ParamId),
    /// A tenant-level parameter sits in the live opaque map.
    TenantInLiveOpaque(ParamId),
    /// P-03 set to this value; above 64 is unsafe (design 2.4).
    P03(u8),
    /// P-05 set to this many cents, which may exceed P-58 (I-50).
    P05(i64),
    /// P-58 removed, so P-05 has no funder ceiling.
    NoP58,
    /// P-39 above P-03: a warning only (design 2.4).
    P39AboveP03,
    /// P-04 max above P-05: a warning only (design 2.4).
    P04MaxAboveP05,
    /// The first P-09 criterion id repeated with another text (design 2.4).
    RepeatedP09,
}

/// Applies `defect` to `v`. A defect that cannot be built leaves `v` unchanged.
pub fn apply_defect(v: &mut PolicyVersion, defect: Defect) {
    let filler = opaque("synthetic defect");
    match defect {
        Defect::None => {}
        Defect::DropFrozenOpaque(p) => {
            v.frozen.opaque.remove(&p);
        }
        Defect::TypedInFrozenOpaque(p) | Defect::LiveInFrozenOpaque(p) => {
            if let Ok(x) = filler {
                v.frozen.opaque.insert(p, x);
            }
        }
        Defect::FrozenInLiveOpaque(p) | Defect::TenantInLiveOpaque(p) => {
            if let Ok(x) = filler {
                v.live.opaque.insert(p, x);
            }
        }
        Defect::P03(n) => {
            if let Some(n) = NonZeroU8::new(n) {
                v.frozen.p03 = n;
            }
        }
        Defect::P05(minor) => {
            if let Ok(a) = eur(minor) {
                v.live.p05 = a;
            }
        }
        Defect::NoP58 => v.live.p58 = None,
        Defect::P39AboveP03 => {
            v.frozen.p03 = NonZeroU8::MIN;
            v.frozen.p39 = NonZeroU8::new(3).unwrap_or(NonZeroU8::MIN);
        }
        Defect::P04MaxAboveP05 => {
            if let Ok(a) = eur(1_000_000) {
                v.live.p05 = a;
            }
        }
        Defect::RepeatedP09 => {
            if let Some(first) = v.frozen.p09.0.first().copied() {
                v.frozen.p09.0.push(KnockOutCriterion {
                    id: first.id,
                    text: text(first.text.id().raw().saturating_add(7_000)),
                });
            }
        }
    }
}

/// Draws a defect, mostly none. Invalid and warning-only defects come up
/// often enough to test both directions.
pub fn gen_defect(g: &mut Gen) -> Defect {
    match g.weighted(&[12, 2, 1, 1, 2, 1, 2, 2, 1, 1, 1, 2]) {
        1 => Defect::DropFrozenOpaque(*g.pick(&FROZEN_OPAQUE)),
        // P-75 is typed since M4 change D6, so it may no longer sit in
        // the frozen opaque map either.
        2 => Defect::TypedInFrozenOpaque(*g.pick(&[
            ParamId::P02,
            ParamId::P21,
            ParamId::P77,
            ParamId::P75,
        ])),
        3 => Defect::LiveInFrozenOpaque(*g.pick(&[ParamId::P05, ParamId::P06, ParamId::P13])),
        4 => Defect::FrozenInLiveOpaque(*g.pick(&[ParamId::P08, ParamId::P02, ParamId::P75])),
        5 => Defect::TenantInLiveOpaque(*g.pick(&[ParamId::P20, ParamId::P70, ParamId::P78])),
        6 => Defect::P03(*g.pick(&[1, 2, 3, 64, 65, 200])),
        7 => Defect::P05(*g.pick(&[
            100_000, 1_000_000, 40_000_000, 50_000_000, 50_000_001, 60_000_000,
        ])),
        8 => Defect::NoP58,
        9 => Defect::P39AboveP03,
        10 => Defect::P04MaxAboveP05,
        11 => Defect::RepeatedP09,
        _ => Defect::None,
    }
}

/// One change to a policy version in an edit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Edit {
    /// New P-01 weights and scale.
    P01 {
        /// Scale maximum N.
        n: u8,
        /// Weights of criteria 1, 2 and 3.
        weights: [u16; 3],
    },
    /// New P-02 in basis points.
    P02(u16),
    /// New P-09 texts, starting at this text id.
    P09(u128),
    /// New P-21 primary model, one of the synthetic names.
    P21(u8),
    /// New opaque P-08 value.
    P08(u8),
    /// Add an excluded class to P-13.
    AddP13Class(u128),
    /// Replace P-13 with this one class, which drops the classes it had.
    SetP13(u128),
    /// New P-05 in cents, below or above the base cap.
    P05(i64),
    /// New P-12.
    P12(u8),
    /// A defect from [`Defect`].
    Defect(Defect),
}

/// The synthetic model with index `i`.
pub fn model(i: u8) -> ModelRef {
    let name = match i % 3 {
        0 => MODEL_A,
        1 => MODEL_B,
        _ => MODEL_C,
    };
    ModelRef(name.to_owned())
}

/// Applies `edit` to `v`. An edit that cannot be built leaves `v` unchanged.
pub fn apply_edit(v: &mut PolicyVersion, edit: Edit) {
    match edit {
        Edit::P01 { n, weights } => {
            if let Ok(c) = criteria(n, weights) {
                v.frozen.p01 = c;
            }
        }
        Edit::P02(bp) => {
            if let Some(p) = Percent::from_bp(bp) {
                v.frozen.p02 = p;
            }
        }
        Edit::P09(first) => v.frozen.p09 = knock_outs(first),
        Edit::P21(i) => v.frozen.p21.primary = model(i),
        Edit::P08(i) => {
            if let Ok(x) = opaque(&format!("synthetic P-08 edit {i}")) {
                v.frozen.opaque.insert(ParamId::P08, x);
            }
        }
        Edit::AddP13Class(c) => {
            v.live.p13.0.insert(ClassId::from_raw(c));
        }
        Edit::SetP13(c) => {
            v.live.p13 = ExclusionClasses([ClassId::from_raw(c)].into_iter().collect())
        }
        Edit::P05(minor) => {
            if let Ok(a) = eur(minor) {
                v.live.p05 = a;
            }
        }
        Edit::P12(n) => v.live.p12 = CoolingOff(n),
        Edit::Defect(d) => apply_defect(v, d),
    }
}

/// Draws one edit.
pub fn gen_edit(g: &mut Gen) -> Edit {
    match g.weighted(&[2, 3, 2, 1, 2, 1, 1, 1, 2, 2]) {
        0 => Edit::P01 {
            n: *g.pick(&[2, 4, 5]),
            weights: [g.u16_in(1..=5), g.u16_in(1..=5), g.u16_in(1..=5)],
        },
        1 => Edit::P02(*g.pick(&[0, 5_000, 6_000, 7_500, 10_000])),
        2 => Edit::P09(u128::from(g.u16_in(2_000..=2_100))),
        3 => Edit::P21(g.u8_in(0..=2)),
        4 => Edit::P08(g.u8_in(0..=3)),
        5 => Edit::AddP13Class(u128::from(g.u8_in(2..=4))),
        6 => Edit::P12(g.u8_in(0..=2)),
        7 => Edit::SetP13(u128::from(g.u8_in(1..=4))),
        8 => Edit::P05(*g.pick(&[1_000_000, 30_000_000, 40_000_000, 45_000_000])),
        _ => Edit::Defect(gen_defect(g)),
    }
}

// ---------------------------------------------------------------------------
// Setup from genesis
// ---------------------------------------------------------------------------

/// A scenario after the setup, the reference ghost beside it, and the next
/// command time.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Setup {
    /// The production side.
    pub scenario: Scenario,
    /// The reference side.
    pub ghost: Ghost,
    /// The time of the next command, in microseconds.
    pub now: i64,
    /// The channel that [`Setup::run`] sends commands through. The setup
    /// uses the web interface.
    pub via: Via,
}

/// A vault in which every account of [`ACTORS`] except the admin, and
/// the approver [`APPROVER`], has its own identity and is verified
/// (SoD-09). So `SameIdentityAsAny` is false for every activation of the
/// machines (I-67).
pub fn verified_truth() -> GroundTruth {
    let mut truth = GroundTruth::new();
    for a in ACTORS.into_iter().chain([APPROVER]) {
        if a != ADMIN {
            let tag = u64::try_from(a.raw()).unwrap_or(u64::MAX);
            truth.set_identity(a, IdentityTag::new(tag));
            truth.verify(a);
        }
    }
    truth
}

impl Setup {
    /// A context at the next command time, with a fresh command id.
    pub fn ctx(&mut self, actor: AccountId, tenant_admin: bool) -> Ctx {
        let now = Timestamp::from_micros(self.now);
        self.now = self.now.saturating_add(1);
        let mut ctx = self.scenario.ctx(now, Actor::Account(actor));
        ctx.tenant_admin = tenant_admin;
        ctx
    }

    /// Runs `cmd` by `actor` through [`Setup::via`] and advances the ghost
    /// when production accepts it.
    pub fn run(
        &mut self,
        actor: AccountId,
        tenant_admin: bool,
        cmd: Command,
    ) -> Result<Seq, ExecError> {
        let mut ctx = self.ctx(actor, tenant_admin);
        ctx.via = self.via;
        let r = self
            .scenario
            .execute(fstp_engine::Command::Core(cmd.clone()), ctx);
        if r.is_ok() {
            // The ghost refuses only commands it does not know.
            let _ = self.ghost.apply(Actor::Account(actor), &cmd);
        }
        r
    }

    /// Runs a setup step that must succeed.
    fn must(
        &mut self,
        what: &str,
        actor: AccountId,
        admin: bool,
        cmd: Command,
    ) -> Result<(), String> {
        self.run(actor, admin, cmd)
            .map(|_| ())
            .map_err(|e| format!("setup step {what} failed: {e:?}"))
    }

    /// Grants `role` in `programme` to `account` through production, as the tenant admin.
    pub fn grant(
        &mut self,
        binding: u128,
        account: AccountId,
        programme: ProgrammeId,
        role: Role,
    ) -> Result<(), String> {
        let start = Timestamp::from_micros(self.now);
        let cmd = Command::GrantRole {
            binding: BindingId::from_raw(binding),
            account,
            programme,
            role,
            start,
            second_admin: None,
            confidentiality: Some(text(binding.saturating_add(500))),
            // SoD-10: a committee binding records the organisation.
            organisation: (role == Role::CommitteeMember)
                .then(|| fstp_domain::id::OrganisationId::from_raw(account.raw())),
            end: None,
        };
        self.must(
            &format!("GrantRole {role:?} to {account:?}"),
            ADMIN,
            true,
            cmd,
        )?;
        self.ghost.bind(account, programme, role);
        Ok(())
    }
}

/// The start state from genesis: programme 1 with version 1, and programme
/// 2 with version 2 when `two_programmes`, each activated by [`APPROVER`]
/// right after its creation (M4 changes D1 and D8), then the bindings of
/// [`BINDINGS_P1`] and [`BINDINGS_P2`]. Every step must succeed.
pub fn setup(two_programmes: bool) -> Result<Setup, String> {
    let scenario = Scenario::new(verified_truth()).map_err(|e| format!("scenario: {e}"))?;
    let mut s = Setup {
        scenario,
        ghost: Ghost::new(),
        now: T0,
        via: Via::Web,
    };
    let mut programmes = vec![(P1, PolicyVersionId::from_raw(1))];
    if two_programmes {
        programmes.push((P2, PolicyVersionId::from_raw(2)));
    }
    for (p, v) in &programmes {
        let policy = Box::new(base_version(*v, *p, None)?);
        s.must(
            "CreateProgramme",
            ADMIN,
            true,
            Command::CreateProgramme { policy },
        )?;
        s.must(
            "ActivateProgramme",
            APPROVER,
            true,
            crate::activation::activate_command(*p),
        )?;
    }
    let mut binding: u128 = 0;
    for (a, role) in BINDINGS_P1 {
        binding = binding.saturating_add(1);
        s.grant(binding, a, P1, role)?;
    }
    if two_programmes {
        for (a, role) in BINDINGS_P2 {
            binding = binding.saturating_add(1);
            s.grant(binding, a, P2, role)?;
        }
    }
    Ok(s)
}

/// The reference state after [`setup`], built without production: the
/// same programmes, versions and bindings.
pub fn reference_start(two_programmes: bool) -> Result<Ghost, String> {
    let mut ghost = Ghost::new();
    let mut programmes = vec![(P1, PolicyVersionId::from_raw(1))];
    if two_programmes {
        programmes.push((P2, PolicyVersionId::from_raw(2)));
    }
    for (p, v) in programmes {
        let policy = Box::new(base_version(v, p, None)?);
        ghost.apply(Actor::Account(ADMIN), &Command::CreateProgramme { policy })?;
        ghost.apply(
            Actor::Account(APPROVER),
            &crate::activation::activate_command(p),
        )?;
    }
    for (a, role) in BINDINGS_P1 {
        ghost.bind(a, P1, role);
    }
    if two_programmes {
        for (a, role) in BINDINGS_P2 {
            ghost.bind(a, P2, role);
        }
    }
    Ok(ghost)
}

// ---------------------------------------------------------------------------
// The example driver
// ---------------------------------------------------------------------------

/// A setup with helpers for the example tests. Each helper builds the
/// command from the ghost, runs it and returns the driver result.
#[derive(Clone, Debug)]
pub struct PolicyWorld {
    /// The setup.
    pub setup: Setup,
}

impl PolicyWorld {
    /// A world over [`setup`].
    pub fn new(two_programmes: bool) -> Result<PolicyWorld, String> {
        Ok(PolicyWorld {
            setup: setup(two_programmes)?,
        })
    }

    /// The reference ghost.
    pub fn ghost(&self) -> &Ghost {
        &self.setup.ghost
    }

    /// The production state.
    pub fn state(&self) -> &fstp_domain::state::State {
        &self.setup.scenario.state().core
    }

    /// Every ledger entry.
    pub fn entries(&self) -> Result<Vec<Entry<EngineRecord>>, String> {
        self.setup
            .scenario
            .entries()
            .map_err(|e| format!("entries: {e:?}"))
    }

    /// The core records of every ledger entry, in order.
    pub fn records(&self) -> Result<Vec<Record>, String> {
        Ok(core_records(&self.entries()?))
    }

    /// The reference head of `programme`.
    pub fn head(&self, programme: ProgrammeId) -> Result<PolicyVersion, String> {
        self.ghost()
            .head(programme)
            .cloned()
            .ok_or_else(|| format!("no head for {programme:?}"))
    }

    /// The next free version id.
    pub fn fresh_version(&self) -> PolicyVersionId {
        PolicyVersionId::from_raw(self.ghost().max_version().saturating_add(1))
    }

    /// An `EditPolicy` by `actor` on the head of `programme`, changed by `change`.
    pub fn edit(
        &mut self,
        actor: AccountId,
        programme: ProgrammeId,
        change: impl FnOnce(&mut PolicyVersion),
    ) -> Result<Result<Seq, ExecError>, String> {
        let head = self.head(programme)?;
        let mut v = next_version(&head, self.fresh_version());
        change(&mut v);
        Ok(self.setup.run(
            actor,
            false,
            Command::EditPolicy {
                base: head.id,
                version: Box::new(v),
            },
        ))
    }

    /// A `DraftCall` by `actor` of call `call` in `programme`.
    pub fn draft(
        &mut self,
        actor: AccountId,
        call: u128,
        programme: ProgrammeId,
    ) -> Result<Result<Seq, ExecError>, String> {
        let zone = ZoneName::new("Europe/Brussels").ok_or("zone")?;
        Ok(self.setup.run(
            actor,
            false,
            Command::DraftCall {
                call: CallId::from_raw(call),
                programme,
                opens: OPENS,
                deadline: DEADLINE,
                deadline_zone: zone,
                budget: eur(100_000_000)?,
                text: text(call.saturating_add(10_000)),
            },
        ))
    }

    /// An `EditCall` by `actor` of call `call`, with a new text.
    pub fn edit_call(
        &mut self,
        actor: AccountId,
        call: u128,
    ) -> Result<Result<Seq, ExecError>, String> {
        let zone = ZoneName::new("Europe/Brussels").ok_or("zone")?;
        let next_text = self.setup.now;
        Ok(self.setup.run(
            actor,
            false,
            Command::EditCall {
                call: CallId::from_raw(call),
                opens: OPENS,
                deadline: DEADLINE,
                deadline_zone: zone,
                budget: eur(120_000_000)?,
                text: text(
                    u128::try_from(next_text)
                        .unwrap_or(0)
                        .saturating_add(20_000),
                ),
            },
        ))
    }

    /// An `ApproveCallPublication` by `actor` of call `call`, with a fresh decision.
    pub fn approve(&mut self, actor: AccountId, call: u128) -> Result<Seq, ExecError> {
        let decision = DecisionId::from_raw(self.ghost().max_decision().saturating_add(1));
        self.setup.run(
            actor,
            false,
            Command::ApproveCallPublication {
                call: CallId::from_raw(call),
                decision,
            },
        )
    }

    /// A `PublishCall` by `actor` of call `call` with the head's primary
    /// model and a fresh configuration.
    pub fn publish(
        &mut self,
        actor: AccountId,
        call: u128,
    ) -> Result<Result<Seq, ExecError>, String> {
        let programme = self
            .ghost()
            .calls
            .get(&CallId::from_raw(call))
            .map_or(P1, |c| c.programme);
        let primary = self.head(programme)?.frozen.p21.primary;
        Ok(self.publish_with(actor, call, primary))
    }

    /// A `PublishCall` by `actor` of call `call` naming `model` as the configuration's model.
    pub fn publish_with(
        &mut self,
        actor: AccountId,
        call: u128,
        model: ModelRef,
    ) -> Result<Seq, ExecError> {
        let config = LlmConfigId::from_raw(self.ghost().max_config().saturating_add(1));
        self.setup.run(
            actor,
            false,
            Command::PublishCall {
                call: CallId::from_raw(call),
                config,
                config_model: model,
            },
        )
    }
}

/// The core records of `entries`, in order.
pub fn core_records(entries: &[Entry<EngineRecord>]) -> Vec<Record> {
    entries
        .iter()
        .filter_map(|e| match &e.record {
            EngineRecord::Core(r) => Some(r.clone()),
            EngineRecord::Finding(_) | EngineRecord::Creator(_) | EngineRecord::Import(_) => None,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// The fstp-prop machine
// ---------------------------------------------------------------------------

/// How often the machine draws each command kind, in the order
/// create, edit, draft, edit call, approve, publish and activate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Focus {
    /// Draw weights.
    pub weights: [u32; 7],
    /// Whether the setup creates programme 2 as well (R-PC-01).
    pub two_programmes: bool,
    /// Commands per case.
    pub max_commands: usize,
}

impl Focus {
    /// Frozen edits interleaved with publications (I-12).
    pub const FREEZING: Focus = Focus {
        weights: [1, 6, 3, 1, 3, 3, 2],
        two_programmes: false,
        max_commands: 32,
    };
    /// Two programmes and edits that try to cross between them (R-PC-01).
    pub const PROGRAMMES: Focus = Focus {
        weights: [2, 6, 2, 1, 2, 2, 2],
        two_programmes: true,
        max_commands: 32,
    };
    /// Publication, edits after it and wrong models (R-PC-02).
    pub const PUBLICATION: Focus = Focus {
        weights: [0, 3, 3, 3, 3, 5, 1],
        two_programmes: false,
        max_commands: 32,
    };
    /// Authorship of calls, P-01 and P-09, and approvals (R-PC-03).
    pub const APPROVAL: Focus = Focus {
        weights: [0, 4, 3, 4, 6, 4, 1],
        two_programmes: false,
        max_commands: 32,
    };
}

/// One machine step: a core command, its actor and the shell's tenant admin attestation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyStep {
    /// The actor.
    pub actor: AccountId,
    /// Whether the shell attests the actor is a tenant admin.
    pub tenant_admin: bool,
    /// The command.
    pub cmd: Command,
}

/// The production side of the machine.
#[derive(Clone, Debug)]
pub struct PolicySut {
    /// The setup, or why it failed.
    pub setup: Result<Setup, String>,
    /// The ledger before the latest step.
    pub previous: Vec<Entry<EngineRecord>>,
    /// The ledger after the latest step.
    pub current: Vec<Entry<EngineRecord>>,
}

/// What one machine step returned.
#[derive(Clone, Debug)]
pub struct StepOutput {
    /// The driver result.
    pub result: Result<Seq, ExecError>,
    /// The core records the step appended, or why they could not be read.
    pub appended: Result<Vec<Record>, String>,
}

/// The fstp-prop machine over the policy and call commands (I-12, R-PC-01
/// to R-PC-03). The model is the reference [`Ghost`].
#[derive(Debug)]
pub struct PolicyMachine {
    /// What the machine draws most.
    pub focus: Focus,
    /// Whether production accepted the latest step. The ghost follows
    /// production only where the reference verdict is `Either`.
    last_accepted: Cell<Option<bool>>,
}

impl PolicyMachine {
    /// A machine with `focus`.
    pub fn new(focus: Focus) -> PolicyMachine {
        PolicyMachine {
            focus,
            last_accepted: Cell::new(None),
        }
    }

    fn programmes(&self) -> &'static [ProgrammeId] {
        const TWO: [ProgrammeId; 3] = [P1, P2, ProgrammeId::from_raw(3)];
        const ONE: [ProgrammeId; 2] = [P1, ProgrammeId::from_raw(3)];
        if self.focus.two_programmes {
            &TWO
        } else {
            &ONE
        }
    }
}

/// Draws an actor, mostly a programme manager.
fn gen_actor(g: &mut Gen) -> AccountId {
    match g.weighted(&[1, 3, 3, 3, 2, 2, 1, 1]) {
        0 => ADMIN,
        1 => PM_A,
        2 => PM_B,
        3 => PM_C,
        4 => PM_D,
        5 => DRAFTER_1,
        6 => DRAFTER_2,
        _ => STRANGER,
    }
}

/// The roles that may draft and edit calls.
const WRITERS: [Role; 2] = [Role::ProgrammeManager, Role::CallDrafter];

/// The role that approves and publishes calls and edits policy.
const MANAGERS: [Role; 1] = [Role::ProgrammeManager];

/// Draws, most of the time, an account that holds one of `roles` in
/// `programme` and is not in `avoid`. Otherwise draws any actor, so refusals
/// stay common.
fn gen_holder(
    g: &mut Gen,
    ghost: &Ghost,
    programme: ProgrammeId,
    roles: &[Role],
    avoid: &BTreeSet<AccountId>,
) -> AccountId {
    let holders: Vec<AccountId> = ghost
        .holders
        .iter()
        .filter(|(a, p, r)| *p == programme && roles.contains(r) && !avoid.contains(a))
        .map(|(a, _, _)| *a)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if !holders.is_empty() && g.weighted(&[1, 3]) == 1 {
        *g.pick(&holders)
    } else {
        gen_actor(g)
    }
}

/// Draws, most of the time, a known call that `wanted` selects. Otherwise
/// draws any known call or an unknown one.
fn gen_call(g: &mut Gen, ghost: &Ghost, wanted: impl Fn(&CallGhost) -> bool) -> CallId {
    let preferred: Vec<u128> = ghost
        .calls
        .iter()
        .filter(|(_, c)| wanted(c))
        .map(|(id, _)| id.raw())
        .collect();
    if !preferred.is_empty() && g.weighted(&[1, 3]) == 1 {
        return CallId::from_raw(*g.pick(&preferred));
    }
    let known: Vec<u128> = ghost.calls.keys().map(|c| c.raw()).collect();
    CallId::from_raw(gen_known_or(g, &known, 77, 8))
}

/// Draws an existing id from `known` most of the time, otherwise `fresh`.
fn gen_known_or(g: &mut Gen, known: &[u128], fresh: u128, known_weight: u32) -> u128 {
    if !known.is_empty() && g.weighted(&[1, known_weight]) == 1 {
        *g.pick(known)
    } else {
        fresh
    }
}

impl PolicyMachine {
    fn gen_create(&self, g: &mut Gen, ghost: &Ghost) -> PolicyStep {
        let known: Vec<u128> = ghost.versions.keys().map(|v| v.raw()).collect();
        let id = gen_known_or(g, &known, ghost.max_version().saturating_add(1), 1);
        let programme = *g.pick(self.programmes());
        let parent = g.weighted(&[9, 1]) == 1;
        let actor = if g.weighted(&[1, 4]) == 1 {
            ADMIN
        } else {
            gen_actor(g)
        };
        let tenant_admin = actor == ADMIN && g.weighted(&[1, 6]) == 1;
        let policy = match base_version(
            PolicyVersionId::from_raw(id),
            programme,
            parent.then(|| PolicyVersionId::from_raw(1)),
        ) {
            Ok(mut v) => {
                apply_defect(&mut v, gen_defect(g));
                v
            }
            Err(_) => g.reject(),
        };
        PolicyStep {
            actor,
            tenant_admin,
            cmd: Command::CreateProgramme {
                policy: Box::new(policy),
            },
        }
    }

    fn gen_edit_policy(&self, g: &mut Gen, ghost: &Ghost) -> PolicyStep {
        let programme = *g.pick(self.programmes());
        let Some(head) = ghost.head(programme).or_else(|| ghost.head(P1)).cloned() else {
            g.reject()
        };
        let known: Vec<u128> = ghost.versions.keys().map(|v| v.raw()).collect();
        let base = PolicyVersionId::from_raw(if g.weighted(&[6, 1]) == 0 {
            head.id.raw()
        } else {
            gen_known_or(g, &known, 99, 4)
        });
        let fresh = ghost.max_version().saturating_add(1);
        let id = PolicyVersionId::from_raw(if g.weighted(&[9, 1]) == 0 {
            fresh
        } else {
            gen_known_or(g, &known, fresh, 4)
        });
        let mut v = next_version(&head, id);
        v.parent = match g.weighted(&[18, 1, 1]) {
            0 => Some(base),
            1 => None,
            _ => Some(PolicyVersionId::from_raw(98)),
        };
        if g.weighted(&[18, 1]) == 1 {
            v.programme = *g.pick(self.programmes());
        }
        let count = g.usize_in(0..=3);
        for _ in 0..count {
            apply_edit(&mut v, gen_edit(g));
        }
        PolicyStep {
            actor: gen_holder(g, ghost, programme, &MANAGERS, &BTreeSet::new()),
            tenant_admin: false,
            cmd: Command::EditPolicy {
                base,
                version: Box::new(v),
            },
        }
    }

    fn gen_call_text(&self, g: &mut Gen, ghost: &Ghost) -> (ZoneName, NonNegAmount, TextRef) {
        let zone = ZoneName::new("Europe/Brussels").unwrap_or_else(|| g.reject());
        let budget = eur(*g.pick(&[0, 100_000_000, 250_000_000])).unwrap_or_else(|_| g.reject());
        let n = ghost
            .max_call()
            .saturating_add(u128::from(g.u16_in(10_000..=10_500)));
        (zone, budget, text(n))
    }

    fn gen_draft(&self, g: &mut Gen, ghost: &Ghost) -> PolicyStep {
        let known: Vec<u128> = ghost.calls.keys().map(|c| c.raw()).collect();
        let call = gen_known_or(g, &known, ghost.max_call().saturating_add(1), 1);
        let programme = *g.pick(self.programmes());
        let actor = gen_holder(g, ghost, programme, &WRITERS, &BTreeSet::new());
        let (deadline_zone, budget, text) = self.gen_call_text(g, ghost);
        PolicyStep {
            actor,
            tenant_admin: false,
            cmd: Command::DraftCall {
                call: CallId::from_raw(call),
                programme,
                opens: OPENS,
                deadline: DEADLINE,
                deadline_zone,
                budget,
                text,
            },
        }
    }

    fn gen_edit_call(&self, g: &mut Gen, ghost: &Ghost) -> PolicyStep {
        let call = gen_call(g, ghost, |c| c.published.is_none());
        let programme = ghost.calls.get(&call).map_or(P1, |c| c.programme);
        let actor = gen_holder(g, ghost, programme, &WRITERS, &BTreeSet::new());
        let (deadline_zone, budget, text) = self.gen_call_text(g, ghost);
        PolicyStep {
            actor,
            tenant_admin: false,
            cmd: Command::EditCall {
                call,
                opens: OPENS,
                deadline: DEADLINE,
                deadline_zone,
                budget,
                text,
            },
        }
    }

    fn gen_approve(&self, g: &mut Gen, ghost: &Ghost) -> PolicyStep {
        let call = gen_call(g, ghost, |c| c.published.is_none());
        let programme = ghost.calls.get(&call).map_or(P1, |c| c.programme);
        let actor = gen_holder(g, ghost, programme, &MANAGERS, &ghost.drafters(call));
        let decisions: Vec<u128> = ghost.decisions.iter().map(|d| d.raw()).collect();
        let fresh = ghost.max_decision().saturating_add(1);
        let decision = if g.weighted(&[9, 1]) == 0 {
            fresh
        } else {
            gen_known_or(g, &decisions, fresh, 4)
        };
        PolicyStep {
            actor,
            tenant_admin: false,
            cmd: Command::ApproveCallPublication {
                call,
                decision: DecisionId::from_raw(decision),
            },
        }
    }

    fn gen_publish(&self, g: &mut Gen, ghost: &Ghost) -> PolicyStep {
        let call = gen_call(g, ghost, |c| {
            c.published.is_none() && !c.approvals.is_empty()
        });
        let programme = ghost.calls.get(&call).map_or(P1, |c| c.programme);
        let actor = gen_holder(g, ghost, programme, &MANAGERS, &BTreeSet::new());
        let primary = ghost.head(programme).map(|h| h.frozen.p21.primary.clone());
        let config_model = match (g.weighted(&[5, 1]), primary) {
            (0, Some(m)) => m,
            _ => model(g.u8_in(0..=2)),
        };
        PolicyStep {
            actor,
            tenant_admin: false,
            cmd: Command::PublishCall {
                call,
                config: LlmConfigId::from_raw(ghost.max_config().saturating_add(1)),
                config_model,
            },
        }
    }

    /// A core `ActivateProgramme` (M4 changes D1 to D3, I-67): mostly by
    /// [`APPROVER`] or [`ADMIN`], sometimes by a programme manager whom
    /// the shell attests as a tenant admin, on a draft or an active
    /// programme, with a fresh or a taken decision id, and sometimes
    /// naming creator builders.
    fn gen_activate(&self, g: &mut Gen, ghost: &Ghost) -> PolicyStep {
        let drafts: Vec<ProgrammeId> = ghost
            .programmes
            .iter()
            .filter(|(_, p)| !p.active)
            .map(|(id, _)| *id)
            .collect();
        let programme = if !drafts.is_empty() && g.weighted(&[1, 3]) == 1 {
            *g.pick(&drafts)
        } else {
            *g.pick(self.programmes())
        };
        let actor = match g.weighted(&[4, 2, 2, 1]) {
            0 => APPROVER,
            1 => ADMIN,
            2 => gen_holder(g, ghost, programme, &MANAGERS, &BTreeSet::new()),
            _ => gen_actor(g),
        };
        let tenant_admin = match actor {
            APPROVER | ADMIN => g.weighted(&[1, 8]) == 1,
            _ => g.weighted(&[1, 1]) == 1,
        };
        let decisions: Vec<u128> = ghost.decisions.iter().map(|d| d.raw()).collect();
        let fresh = ghost.max_decision().saturating_add(1);
        let decision = if g.weighted(&[9, 1]) == 0 {
            fresh
        } else {
            gen_known_or(g, &decisions, fresh, 4)
        };
        let creator_builders: BTreeSet<AccountId> = match g.weighted(&[6, 1, 1]) {
            0 => BTreeSet::new(),
            1 => [actor].into_iter().collect(),
            _ => [gen_actor(g)].into_iter().collect(),
        };
        let mut digest = [0u8; 32];
        if let Some(first) = digest.first_mut() {
            *first = g.u8_in(0..=255);
        }
        PolicyStep {
            actor,
            tenant_admin,
            cmd: Command::ActivateProgramme {
                programme,
                decision: DecisionId::from_raw(decision),
                report: fstp_domain::policy::activation::ReportDigest::from_bytes(digest),
                revision: u32::from(g.u8_in(0..=3)),
                creator_builders,
            },
        }
    }
}

impl StateMachine for PolicyMachine {
    type Model = Ghost;
    type Sut = PolicySut;
    type Command = PolicyStep;
    type Output = StepOutput;

    fn init_model(&self) -> Ghost {
        reference_start(self.focus.two_programmes).unwrap_or_default()
    }

    fn init_sut(&self) -> PolicySut {
        let setup = setup(self.focus.two_programmes);
        let current = match &setup {
            Ok(s) => s.scenario.entries().unwrap_or_default(),
            Err(_) => Vec::new(),
        };
        PolicySut {
            setup,
            previous: current.clone(),
            current,
        }
    }

    fn command(&self, g: &mut Gen, model: &Ghost) -> PolicyStep {
        match g.weighted(&self.focus.weights) {
            0 => self.gen_create(g, model),
            1 => self.gen_edit_policy(g, model),
            2 => self.gen_draft(g, model),
            3 => self.gen_edit_call(g, model),
            4 => self.gen_approve(g, model),
            5 => self.gen_publish(g, model),
            _ => self.gen_activate(g, model),
        }
    }

    fn run(&self, sut: &mut PolicySut, step: &PolicyStep) -> StepOutput {
        self.last_accepted.set(None);
        let Ok(setup) = sut.setup.as_mut() else {
            return StepOutput {
                result: Err(ExecError::Refused(
                    fstp_domain::refusal::Refusal::not_implemented(),
                )),
                appended: Err("the setup failed".to_owned()),
            };
        };
        let ctx = setup.ctx(step.actor, step.tenant_admin);
        let result = setup
            .scenario
            .execute(fstp_engine::Command::Core(step.cmd.clone()), ctx);
        self.last_accepted.set(Some(result.is_ok()));
        sut.previous = core::mem::take(&mut sut.current);
        let appended = match setup.scenario.entries() {
            Ok(entries) => {
                sut.current = entries;
                Ok(core_records(
                    sut.current.get(sut.previous.len()..).unwrap_or_default(),
                ))
            }
            Err(e) => Err(format!("entries: {e:?}")),
        };
        StepOutput { result, appended }
    }

    fn postcondition(
        &self,
        model: &Ghost,
        step: &PolicyStep,
        out: &StepOutput,
    ) -> Result<(), String> {
        let actor = Actor::Account(step.actor);
        let verdict = model.verdict(actor, step.tenant_admin, &step.cmd)?;
        let context = format!("{:?} by {:?}", step.cmd.kind(), step.actor);
        match verdict {
            Verdict::Accept => two_way_exec(&context, true, &out.result)?,
            Verdict::Refuse => two_way_exec(&context, false, &out.result)?,
            Verdict::Either => {
                if let Err(e) = &out.result
                    && !matches!(e, ExecError::Refused(_))
                {
                    return Err(format!("{context}: the driver failed with {e:?}"));
                }
            }
        }
        if out.result.is_ok() && verdict != Verdict::Refuse {
            let appended = out.appended.as_ref().map_err(Clone::clone)?;
            for expected in model.expected_records(actor, &step.cmd)? {
                if !appended.contains(&expected) {
                    return Err(format!(
                        "{context}: the batch lacks the record the reference expects\n  expected: {expected:?}\n  batch: {appended:?}"
                    ));
                }
            }
        }
        Ok(())
    }

    fn next_state(&self, model: &mut Ghost, step: &PolicyStep) {
        let actor = Actor::Account(step.actor);
        let accepted = match model.verdict(actor, step.tenant_admin, &step.cmd) {
            Ok(Verdict::Accept) => true,
            Ok(Verdict::Either) => self.last_accepted.get().unwrap_or(false),
            Ok(Verdict::Refuse) | Err(_) => false,
        };
        if accepted {
            // A ghost that cannot follow an accepted command shows up in the
            // invariant as a mismatch with production.
            let _ = model.apply(actor, &step.cmd);
        }
    }

    fn invariant(&self, model: &Ghost, sut: &PolicySut) -> Result<(), String> {
        let setup = sut.setup.as_ref().map_err(Clone::clone)?;
        let state = setup.scenario.state();
        ledger_step(&sut.previous, &sut.current, state)?;
        check_i12(model, &sut.current, &state.core)
    }

    fn max_commands(&self) -> usize {
        self.focus.max_commands
    }
}

/// The set of programmes the ghost knows, for predicates.
pub fn known_programmes(ghost: &Ghost) -> BTreeSet<ProgrammeId> {
    ghost.programmes.keys().copied().collect()
}
