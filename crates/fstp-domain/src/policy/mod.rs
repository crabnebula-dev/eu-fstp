//! Policy engine, parameter catalogue and freezing (design section 2.4, I-12).
//!
//! Owned by lane L-POL (docs/handoff/m2-design.md section 10).
//!
//! - A programme's policy is a chain of immutable versions (I-23).
//!   `CreateProgramme` records the first, and `EditPolicy` appends one on
//!   top of the head. The projection keeps the head and the last authors of
//!   P-01 and P-09, which R-PC-03 needs.
//! - [`validate`] refuses only inconsistent or unsafe values. Cross-checks
//!   the spec does not state are [`ValidationWarning`]s.
//! - Lowering P-05 asks the vault whether every recipient stays within the
//!   new cap, and a "no" refuses the edit (I-14, Q7 A).
//! - I-12 by construction. A [`FrozenPolicy`] is built only by [`freeze`],
//!   which only the fold of `CallPublished` calls. No record changes it
//!   afterwards. Guards read frozen values only through [`frozen_policy`],
//!   and live values through [`live_values`], [`effective_p05`] and
//!   [`effective_p13`]. [`head`] returns the whole head version. Only two
//!   reads take frozen values from it, both about a version that no call
//!   has frozen yet: the P-21 check of `PublishCall` and the P-77 of a
//!   programme-scoped command.
//! - The engine names a per-lane `governing_policy` function for the MCP
//!   P-77 scope (`crate::engine`). It is not the design's frozen read of
//!   design 2.4 point 3, which is [`frozen_policy`] here.
//! - A published call records the P-05 and P-13 snapshot next to the
//!   frozen values. [`effective_p05`] and [`effective_p13`] give the
//!   stricter of the snapshot and the live value (NOTE 7).

use core::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU8;
use std::sync::Arc;

use fstp_money::{AmountRange, Currency, NonNegAmount, Percent};

use crate::command::{Actor, Command, Ctx};
use crate::engine::{FoldError, PolicyScope};
use crate::id::{
    AccountId, CallId, ClassId, KnockOutCriterionId, OrganisationId, PolicyVersionId, ProgrammeId,
    ProximityListId, TextRef,
};
use crate::oracle::{Answers, Query};
use crate::record::Record;
use crate::refusal::{Refusal, RefusalReason, RuleRef};
use crate::roles::{CoolingOff, Role};
use crate::scoring::Criteria;
use crate::state::{State, UsedId};
use crate::time::{Days, Timestamp};

pub use crate::rules::{CATALOGUE, Freeze, Level, ParamId, ParamSpec};

/// A parameter value M2 does not interpret, as RFC 8785 canonical JSON text.
/// Canonical text makes `Eq` and `Hash` exact, so it freezes with the rest (I-12).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OpaqueValue(String);

impl OpaqueValue {
    /// The canonical text of `v`.
    pub fn from_value(v: &fstp_json::Value) -> Result<OpaqueValue, fstp_json::CanonicalError> {
        fstp_json::to_canonical(v).map(OpaqueValue)
    }

    /// The canonical text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A pinned model name, as the tenant's inference provider spells it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ModelRef(pub String);

/// An exact SPDX licence identifier.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SpdxId(pub String);

/// One knock-out criterion of P-09. Its wording is free text held outside the ledger.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KnockOutCriterion {
    /// The criterion.
    pub id: KnockOutCriterionId,
    /// Its wording.
    pub text: TextRef,
}

/// The P-09 value.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct KnockOutCriteria(pub Vec<KnockOutCriterion>);

/// The P-10 options (P-10 NOTE 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReadAccess {
    /// Assigned reviewers only, the default.
    AssignedReviewersOnly,
    /// All committee members, each declaring per proposal.
    AllCommitteeMembers,
    /// Operator staff only. The reading role is open (O-43).
    OperatorStaffOnly,
}

/// The P-11 options.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReviewerAnonymity {
    /// Reviewers appear to applicants only under per-proposal handles.
    Anonymous,
    /// Reviewers appear by name.
    Named,
}

/// The P-14 value. The programme manager decides whether an exemption applies,
/// so M2 keeps the exemptions as an opaque frozen value.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct IrcExemptions(pub OpaqueValue);

/// The P-16 value. Its details are open (O-44), so M2 keeps it opaque.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct VotingRules(pub OpaqueValue);

/// The P-17 value. People apply the recorded rule (design Q17).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TieBreakRule(pub OpaqueValue);

/// The P-21 value: provider, primary model and an ordered fallback list,
/// all pinned at publication (P-21 NOTE 10).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct InferenceBinding {
    /// The inference provider.
    pub provider: OpaqueValue,
    /// The primary pinned model.
    pub primary: ModelRef,
    /// Replacement models in the order they are taken.
    pub fallbacks: Vec<ModelRef>,
}

/// The P-24 options.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EffectiveScoreRule {
    /// Higher of original and revised, the original on a tie (NOTE 4).
    HigherOfOriginalAndRevised,
}

/// The P-26 value: exact SPDX identifiers.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LicenceSet(pub BTreeSet<SpdxId>);

/// The P-53 value.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FunderProfileRef(pub OpaqueValue);

/// The P-77 options.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum McpBindingActions {
    /// Agents draft and the user confirms in the platform.
    DraftOnly,
    /// Agents complete binding actions through MCP.
    Allowed,
}

/// Every frozen programme parameter. Typed where M2 interprets it, opaque
/// otherwise, so every frozen parameter freezes (I-12).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FrozenValues {
    /// P-01: criteria, weights and score scale.
    pub p01: Criteria,
    /// P-02: stage 1 pass threshold, compared strictly.
    pub p02: Percent,
    /// P-03: minimum assigned reviewers per proposal.
    pub p03: NonZeroU8,
    /// P-04: grant range per proposal, inclusive.
    pub p04: AmountRange,
    /// P-07: stage 2 answer window.
    pub p07: Days,
    /// P-09: knock-out criteria.
    pub p09: KnockOutCriteria,
    /// P-10: proposal read access in stages 1 and 2.
    pub p10: ReadAccess,
    /// P-11: reviewer anonymity towards applicants.
    pub p11: ReviewerAnonymity,
    /// P-14: IRC exemptions for amendments.
    pub p14: IrcExemptions,
    /// P-15: minimum IRC members per proposal.
    pub p15: NonZeroU8,
    /// P-16: committee voting rules.
    pub p16: VotingRules,
    /// P-17: tie-break priority.
    pub p17: TieBreakRule,
    /// P-21: inference provider, pinned model and fallbacks.
    pub p21: InferenceBinding,
    /// P-24: effective score rule after stage 2.
    pub p24: EffectiveScoreRule,
    /// P-26: accepted licences for deliverables.
    pub p26: LicenceSet,
    /// P-39: minimum distinct organisations among assigned reviewers.
    pub p39: NonZeroU8,
    /// P-53: funder profile and version.
    pub p53: FunderProfileRef,
    /// P-77: binding actions through MCP.
    pub p77: McpBindingActions,
    /// Every other frozen parameter, keyed by id.
    pub opaque: BTreeMap<ParamId, OpaqueValue>,
}

/// The P-13 value: opaque class ids the vault matches.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExclusionClasses(pub BTreeSet<ClassId>);

/// The P-38 value: one proximity list per partner organisation, held by the vault.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProximityLists(pub BTreeMap<OrganisationId, ProximityListId>);

/// Programme parameters that are not frozen, read live at decision time.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LiveValues {
    /// P-05: cap per recipient over the programme lifetime.
    pub p05: NonNegAmount,
    /// P-12: cooling-off in calls.
    pub p12: CoolingOff,
    /// P-13: excluded affiliation classes.
    pub p13: ExclusionClasses,
    /// P-38: proximity lists per partner organisation.
    pub p38: ProximityLists,
    /// P-56: the action's FSTP budget, when set.
    pub p56: Option<NonNegAmount>,
    /// P-58: the funder's per-recipient ceiling, when set.
    pub p58: Option<NonNegAmount>,
    /// Every other programme-level live parameter, keyed by id.
    pub opaque: BTreeMap<ParamId, OpaqueValue>,
}

/// The publication snapshot of P-05 and P-13 that the published call
/// policy records next to the frozen values (P-05 and P-13 NOTE 7).
/// Enforcement uses the stricter of this snapshot and the live value.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LiveSnapshot {
    /// P-05 at publication.
    pub p05: NonNegAmount,
    /// P-13 at publication.
    pub p13: ExclusionClasses,
}

/// One immutable version of a programme's policy (I-23).
/// [`validate`] checks its values.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PolicyVersion {
    /// The version.
    pub id: PolicyVersionId,
    /// The programme.
    pub programme: ProgrammeId,
    /// The version it replaces, `None` for the first.
    pub parent: Option<PolicyVersionId>,
    /// The programme currency (ADR-006).
    pub currency: Currency,
    /// Frozen parameters.
    pub frozen: FrozenValues,
    /// Live parameters.
    pub live: LiveValues,
}

/// The frozen policy of one published call. Built only by the fold of a
/// `CallPublished` record, so it has no public constructor (I-12, R-PC-02).
/// Only [`freeze`] builds one.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FrozenPolicy {
    call: CallId,
    version: PolicyVersionId,
    values: Arc<FrozenValues>,
    snapshot: Arc<LiveSnapshot>,
}

impl FrozenPolicy {
    /// The published call.
    pub fn call(&self) -> CallId {
        self.call
    }

    /// The policy version frozen at publication.
    pub fn version(&self) -> PolicyVersionId {
        self.version
    }

    /// The frozen values.
    pub fn values(&self) -> &FrozenValues {
        &self.values
    }

    /// The P-05 and P-13 snapshot at publication.
    pub fn snapshot(&self) -> &LiveSnapshot {
        &self.snapshot
    }
}

impl FrozenPolicy {
    /// The frozen policy that a `CallPublished` record creates, built from
    /// the programme head it names. This is the only constructor, and only
    /// [`freeze`] calls it (design 2.4 point 1).
    fn from_head(call: CallId, head: &PolicyVersion) -> FrozenPolicy {
        FrozenPolicy {
            call,
            version: head.id,
            values: Arc::new(head.frozen.clone()),
            snapshot: Arc::new(LiveSnapshot {
                p05: head.live.p05,
                p13: head.live.p13.clone(),
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Typed and opaque parameters
// ---------------------------------------------------------------------------

/// The frozen parameters that have a typed field in [`FrozenValues`].
pub const TYPED_FROZEN: [ParamId; 18] = [
    ParamId::P01,
    ParamId::P02,
    ParamId::P03,
    ParamId::P04,
    ParamId::P07,
    ParamId::P09,
    ParamId::P10,
    ParamId::P11,
    ParamId::P14,
    ParamId::P15,
    ParamId::P16,
    ParamId::P17,
    ParamId::P21,
    ParamId::P24,
    ParamId::P26,
    ParamId::P39,
    ParamId::P53,
    ParamId::P77,
];

/// The live parameters that have a typed field in [`LiveValues`].
pub const TYPED_LIVE: [ParamId; 6] = [
    ParamId::P05,
    ParamId::P12,
    ParamId::P13,
    ParamId::P38,
    ParamId::P56,
    ParamId::P58,
];

/// Whether `id` must be a key of [`FrozenValues::opaque`]: a frozen
/// programme parameter without a typed field (I-12).
pub fn is_frozen_opaque(id: ParamId) -> bool {
    id.spec()
        .is_some_and(|s| s.freeze == Freeze::Frozen && s.level == Level::Programme)
        && !TYPED_FROZEN.contains(&id)
}

/// Whether `id` may be a key of [`LiveValues::opaque`]: a live programme
/// parameter without a typed field. Tenant-level parameters and the fixed
/// P-68 belong to tenant configuration (design 2.4).
pub fn is_live_opaque(id: ParamId) -> bool {
    id.spec()
        .is_some_and(|s| s.freeze == Freeze::Live && s.level == Level::Programme)
        && !TYPED_LIVE.contains(&id)
}

// ---------------------------------------------------------------------------
// Validation (design 2.4)
// ---------------------------------------------------------------------------

/// A cross-check that the spec does not state as a rule. Validation reports
/// it to the M4 creator and never refuses for it (design 2.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ValidationWarning {
    /// The P-04 maximum lies above the P-05 cap.
    P04MaxAboveP05,
    /// P-39 asks for more organisations than P-03 asks for reviewers.
    P39AboveP03,
}

/// The largest P-03 that keeps the exact score arithmetic safe (design 2.4).
pub const P03_MAX: u8 = 64;

/// A refusal of an inconsistent or unsafe value of parameter `p`.
const fn invalid(p: ParamId) -> Refusal {
    Refusal::new(RuleRef::Param(p), RefusalReason::InvalidValue)
}

/// Whether `a` is above `b`, refusing for parameter `p` when the currencies differ.
fn above(a: NonNegAmount, b: NonNegAmount, p: ParamId) -> Result<bool, Refusal> {
    a.amount()
        .cmp_same(b.amount())
        .map(|o| o == Ordering::Greater)
        .map_err(|_| invalid(p))
}

/// Checks that `a` is in currency `c`, refusing for parameter `p` otherwise (ADR-006).
fn same_currency(a: NonNegAmount, c: Currency, p: ParamId) -> Result<(), Refusal> {
    if a.amount().currency() == c {
        Ok(())
    } else {
        Err(invalid(p))
    }
}

/// Validates one policy version on its own values (design 2.4).
///
/// Refuses only values that are inconsistent or unsafe for exact
/// arithmetic, and returns the warnings otherwise:
///
/// - an amount in another currency than the version's (ADR-006);
/// - P-01 empty, with more than 16 criteria, a weight above 1000, a scale
///   maximum above 100 or a repeated criterion;
/// - P-02 above 100.00, P-03 above 64, P-04 minimum above its maximum;
/// - a repeated P-09 criterion;
/// - P-05 above P-58 (I-50);
/// - a frozen parameter missing from the snapshot, or a key in either
///   opaque map that does not belong there (I-12).
pub fn validate(v: &PolicyVersion) -> Result<Vec<ValidationWarning>, Refusal> {
    let f = &v.frozen;
    let l = &v.live;
    let c = v.currency;
    same_currency(f.p04.min(), c, ParamId::P04)?;
    same_currency(f.p04.max(), c, ParamId::P04)?;
    same_currency(l.p05, c, ParamId::P05)?;
    if let Some(a) = l.p56 {
        same_currency(a, c, ParamId::P56)?;
    }
    if let Some(a) = l.p58 {
        same_currency(a, c, ParamId::P58)?;
    }

    let items = f.p01.items();
    let ids: BTreeSet<_> = items.iter().map(|i| i.id).collect();
    if items.is_empty()
        || items.len() > usize::from(Criteria::MAX_CRITERIA)
        || items.iter().any(|i| i.weight.get() > Criteria::MAX_WEIGHT)
        || f.p01.scale_max().get() > Criteria::MAX_SCALE
        || ids.len() != items.len()
    {
        return Err(invalid(ParamId::P01));
    }
    if f.p02.bp() > Percent::MAX_BP {
        return Err(invalid(ParamId::P02));
    }
    if f.p03.get() > P03_MAX {
        return Err(invalid(ParamId::P03));
    }
    if above(f.p04.min(), f.p04.max(), ParamId::P04)? {
        return Err(invalid(ParamId::P04));
    }
    let knock_outs: BTreeSet<_> = f.p09.0.iter().map(|k| k.id).collect();
    if knock_outs.len() != f.p09.0.len() {
        return Err(invalid(ParamId::P09));
    }
    if let Some(ceiling) = l.p58
        && above(l.p05, ceiling, ParamId::P05)?
    {
        return Err(Refusal::new(RuleRef::I50, RefusalReason::InvalidValue));
    }

    let expected: BTreeSet<ParamId> = CATALOGUE
        .iter()
        .map(|s| s.id)
        .filter(|id| is_frozen_opaque(*id))
        .collect();
    if !f.opaque.keys().copied().eq(expected.iter().copied()) {
        return Err(Refusal::new(RuleRef::I12, RefusalReason::InvalidValue));
    }
    if l.opaque.keys().any(|k| !is_live_opaque(*k)) {
        return Err(Refusal::new(RuleRef::I12, RefusalReason::InvalidValue));
    }

    let mut warnings = Vec::new();
    if above(f.p04.max(), l.p05, ParamId::P04)? {
        warnings.push(ValidationWarning::P04MaxAboveP05);
    }
    if f.p39 > f.p03 {
        warnings.push(ValidationWarning::P39AboveP03);
    }
    Ok(warnings)
}

// ---------------------------------------------------------------------------
// The policy part of the projection
// ---------------------------------------------------------------------------

/// One programme's policy facts.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProgrammePolicy {
    /// The programme currency, fixed at creation (ADR-006).
    currency: Currency,
    /// The head version. `None` only between `ProgrammeCreated` and the
    /// first `PolicyVersionRecorded` of the same batch.
    head: Option<Arc<PolicyVersion>>,
    /// The author of the latest version that changed P-01 (R-PC-03).
    last_author_p01: AccountId,
    /// The author of the latest version that changed P-09 (R-PC-03).
    last_author_p09: AccountId,
}

impl ProgrammePolicy {
    /// The programme currency.
    pub fn currency(&self) -> Currency {
        self.currency
    }

    /// The head version.
    pub fn head(&self) -> Option<&PolicyVersion> {
        self.head.as_deref()
    }

    /// The author of the latest version that changed P-01.
    pub fn last_author_p01(&self) -> AccountId {
        self.last_author_p01
    }

    /// The author of the latest version that changed P-09.
    pub fn last_author_p09(&self) -> AccountId {
        self.last_author_p09
    }
}

/// Policy part of the projection: per programme, the currency, the head
/// version and the last authors of P-01 and P-09 (R-PC-03).
///
/// Superseded versions leave the projection, because a published call
/// keeps its own copy in its [`FrozenPolicy`] (design 2.14). The ledger
/// keeps every version.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PolicyState {
    programmes: BTreeMap<ProgrammeId, ProgrammePolicy>,
}

impl PolicyState {
    /// The policy state before any record.
    pub(crate) const fn genesis() -> PolicyState {
        PolicyState {
            programmes: BTreeMap::new(),
        }
    }

    /// The policy facts of `programme`.
    pub fn programme(&self, programme: ProgrammeId) -> Option<&ProgrammePolicy> {
        self.programmes.get(&programme)
    }

    /// The head version of `programme`.
    pub fn head(&self, programme: ProgrammeId) -> Option<&PolicyVersion> {
        self.programmes
            .get(&programme)
            .and_then(ProgrammePolicy::head)
    }
}

// ---------------------------------------------------------------------------
// The read API for guards (design 2.4 points 3 and 4)
// ---------------------------------------------------------------------------

/// The head policy version of `programme` (design 2.4 point 4).
///
/// A guard never reads frozen values here. It reads them from the call's
/// [`FrozenPolicy`] through [`frozen_policy`], and live values through
/// [`live_values`]. The frozen values of the head serve only the two
/// pre-freeze reads in the module docs, and readers such as M4 views.
/// The test `i12_guards_read_frozen_values_only_through_the_snapshot`
/// fails on any other `.frozen` read in the domain crate.
pub fn head(state: &State, programme: ProgrammeId) -> Option<&PolicyVersion> {
    state.policy.head(programme)
}

/// The live values of `programme`, read at decision time.
pub fn live_values(state: &State, programme: ProgrammeId) -> Option<&LiveValues> {
    head(state, programme).map(|v| &v.live)
}

/// The currency of `programme` (ADR-006).
pub fn programme_currency(state: &State, programme: ProgrammeId) -> Option<Currency> {
    state
        .policy
        .programme(programme)
        .map(ProgrammePolicy::currency)
}

/// The frozen policy of `call`, or `None` while it is unpublished (I-12).
///
/// This is the one read of frozen values for every guard (design 2.4
/// point 3). A guard about a proposal passes the call whose policy governs
/// it, which is the original call for a deferred proposal (Q15 A).
///
/// TODO(L-LIFE): the proposal store has no proposal-to-call read yet. Lane
/// L-LIFE adds `governing_frozen_policy(state, ProposalId)` on top of this
/// function and routes every proposal guard through it, so Q15 stays one
/// edit.
pub fn frozen_policy(state: &State, call: CallId) -> Option<&FrozenPolicy> {
    crate::programme::call(state, call).and_then(crate::programme::CallView::frozen)
}

/// The P-05 cap that `call` enforces now: the lower of the publication
/// snapshot and the live value, or the live value before publication
/// (P-05 and P-13 NOTE 7).
pub fn effective_p05(state: &State, call: CallId) -> Result<NonNegAmount, Refusal> {
    let view = crate::programme::call(state, call).ok_or_else(unknown)?;
    let live = live_values(state, view.programme())
        .ok_or_else(unknown)?
        .p05;
    match view.frozen() {
        Some(f) if above(live, f.snapshot().p05, ParamId::P05)? => Ok(f.snapshot().p05),
        _ => Ok(live),
    }
}

/// The P-13 classes that `call` enforces now: every class of the
/// publication snapshot or the live value (P-05 and P-13 NOTE 7).
pub fn effective_p13(state: &State, call: CallId) -> Result<ExclusionClasses, Refusal> {
    let view = crate::programme::call(state, call).ok_or_else(unknown)?;
    let mut classes = live_values(state, view.programme())
        .ok_or_else(unknown)?
        .p13
        .clone();
    if let Some(f) = view.frozen() {
        classes.0.extend(f.snapshot().p13.0.iter().copied());
    }
    Ok(classes)
}

/// The live values before and after an `EditPolicy`, for the lanes that
/// react to a live change in the same batch (enforcement point 3). Lane
/// L-SOD voids the Receiving bindings in a P-13 class the edit adds
/// (NOTE 7), and lane L-REV re-checks P-38.
#[allow(dead_code, reason = "lanes L-SOD and L-REV call it")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LiveChange<'a> {
    /// The programme.
    pub(crate) programme: ProgrammeId,
    /// The live values of the head before the edit.
    pub(crate) before: &'a LiveValues,
    /// The live values of the new version.
    pub(crate) after: &'a LiveValues,
}

#[allow(dead_code, reason = "lanes L-SOD and L-REV call it")]
impl LiveChange<'_> {
    /// The P-13 classes the edit adds.
    pub(crate) fn added_p13(&self) -> ExclusionClasses {
        ExclusionClasses(
            self.after
                .p13
                .0
                .difference(&self.before.p13.0)
                .copied()
                .collect(),
        )
    }

    /// Whether the edit changes P-38.
    pub(crate) fn p38_changed(&self) -> bool {
        self.before.p38 != self.after.p38
    }
}

/// The live change of `cmd` when it is an `EditPolicy` on the current head
/// of its programme. `None` for every other command.
#[allow(dead_code, reason = "lanes L-SOD and L-REV call it")]
pub(crate) fn live_change<'a>(state: &'a State, cmd: &'a Command) -> Option<LiveChange<'a>> {
    let Command::EditPolicy { base, version } = cmd else {
        return None;
    };
    let head = head(state, version.programme)?;
    (head.id == *base).then_some(LiveChange {
        programme: version.programme,
        before: &head.live,
        after: &version.live,
    })
}

/// Builds the frozen policy of a `CallPublished` record from the head of
/// `programme` (I-12 by construction point 1). The fold of
/// `CallPublished` in `crate::programme` is its only caller. Any other
/// record, or a record that names another version than the head, fails.
pub(crate) fn freeze(
    policy: &PolicyState,
    programme: ProgrammeId,
    record: &Record,
) -> Result<FrozenPolicy, FoldError> {
    let Record::CallPublished {
        call,
        policy: version,
        ..
    } = record
    else {
        return Err(FoldError::Inconsistent);
    };
    let head = policy.head(programme).ok_or(FoldError::UnknownEntity)?;
    if head.id != *version {
        return Err(FoldError::Inconsistent);
    }
    Ok(FrozenPolicy::from_head(*call, head))
}

// ---------------------------------------------------------------------------
// Guards
// ---------------------------------------------------------------------------

/// The refusal for an unknown programme, call or version.
const fn unknown() -> Refusal {
    Refusal::new(RuleRef::Input, RefusalReason::UnknownEntity)
}

/// The refusal for a shell-supplied id that is already taken.
const fn reused() -> Refusal {
    Refusal::new(RuleRef::Ledger, RefusalReason::IdReused)
}

/// The account behind the context's actor.
pub(crate) fn actor_account(ctx: &Ctx) -> Result<AccountId, Refusal> {
    match ctx.actor {
        Actor::Account(a) => Ok(a),
        Actor::System(_) => Err(Refusal::new(RuleRef::Actor, RefusalReason::WrongActor)),
    }
}

/// Whether `account` holds an active binding of one of `roles` in `programme` at `now`.
pub(crate) fn holds_any(
    state: &State,
    account: AccountId,
    programme: ProgrammeId,
    roles: &[Role],
    now: Timestamp,
) -> bool {
    roles.iter().any(|r| {
        state
            .roster
            .active_binding(account, *r, programme, now)
            .is_some()
    })
}

/// Refuses unless `account` holds one of `roles` in `programme` at `now`.
pub(crate) fn require_holder(
    state: &State,
    account: AccountId,
    programme: ProgrammeId,
    roles: &[Role],
    now: Timestamp,
) -> Result<(), Refusal> {
    if holds_any(state, account, programme, roles, now) {
        Ok(())
    } else {
        Err(Refusal::new(RuleRef::Actor, RefusalReason::BindingInactive))
    }
}

/// The granted and reserved sum per account in `programme`, for the
/// `AllRecipientsWithinCap` question (I-14, Q7 A).
///
/// Lane L-MONEY owns these sums. Its `MoneyState` exposes no read yet, and
/// no grant or reservation can be recorded before it lands, so every sum
/// is zero today and the question is exact.
///
/// TODO(L-MONEY): read the programme's granted plus reserved sum per
/// account here. Step W5 adds `i14_p05_edit_below_committed_is_refused`,
/// which reaches a non-zero sum through production, and a P-05 edit in
/// `i13_i14_m_money` (design 6.2 and 6.3).
fn committed(state: &State, programme: ProgrammeId) -> BTreeMap<AccountId, NonNegAmount> {
    let _ = (state.money(), programme);
    BTreeMap::new()
}

/// Checks a `CreateProgramme` command and returns its creator.
fn check_create(state: &State, policy: &PolicyVersion, ctx: &Ctx) -> Result<AccountId, Refusal> {
    let by = actor_account(ctx)?;
    if policy.parent.is_some() {
        return Err(Refusal::new(RuleRef::Input, RefusalReason::InvalidValue));
    }
    if state.used_ids.contains(UsedId::Programme(policy.programme))
        || state.policy.programme(policy.programme).is_some()
        || state.used_ids.contains(UsedId::PolicyVersion(policy.id))
    {
        return Err(reused());
    }
    validate(policy)?;
    Ok(by)
}

/// What a checked `EditPolicy` needs to decide.
struct EditPlan<'a> {
    /// The author.
    author: AccountId,
    /// The vault question when the edit lowers P-05 (I-14).
    cap_query: Option<Query>,
    /// The new version.
    version: &'a PolicyVersion,
}

/// Checks an `EditPolicy` command against the head and the validation rules.
fn check_edit<'a>(
    state: &State,
    base: PolicyVersionId,
    version: &'a PolicyVersion,
    ctx: &Ctx,
) -> Result<EditPlan<'a>, Refusal> {
    let author = actor_account(ctx)?;
    let programme = state
        .policy
        .programme(version.programme)
        .ok_or_else(unknown)?;
    require_holder(
        state,
        author,
        version.programme,
        &[Role::ProgrammeManager],
        ctx.now,
    )?;
    let head = programme.head().ok_or_else(unknown)?;
    if head.id != base || version.parent != Some(base) {
        return Err(Refusal::new(RuleRef::Input, RefusalReason::WrongState));
    }
    if state.used_ids.contains(UsedId::PolicyVersion(version.id)) {
        return Err(reused());
    }
    if version.currency != programme.currency() {
        return Err(Refusal::new(RuleRef::Input, RefusalReason::InvalidValue));
    }
    validate(version)?;
    let lowered = above(head.live.p05, version.live.p05, ParamId::P05)?;
    let cap_query = lowered.then(|| Query::AllRecipientsWithinCap {
        committed: committed(state, version.programme),
        cap: version.live.p05,
    });
    Ok(EditPlan {
        author,
        cap_query,
        version,
    })
}

// ---------------------------------------------------------------------------
// Engine entry points of this lane, called by `crate::engine`.
// ---------------------------------------------------------------------------

/// The vault questions of the programme and policy commands. Only an
/// `EditPolicy` that lowers P-05 asks one: whether every recipient stays
/// within the new cap (I-14, Q7 A).
pub(crate) fn queries(state: &State, cmd: &Command, ctx: &Ctx) -> Result<Vec<Query>, Refusal> {
    match cmd {
        Command::CreateProgramme { policy } => {
            check_create(state, policy, ctx)?;
            Ok(Vec::new())
        }
        Command::EditPolicy { base, version } => {
            let plan = check_edit(state, *base, version, ctx)?;
            Ok(plan.cap_query.into_iter().collect())
        }
        _ => Err(Refusal::new(RuleRef::Input, RefusalReason::WrongState)),
    }
}

/// The records of the programme and policy commands.
pub(crate) fn decide(
    state: &State,
    cmd: &Command,
    ctx: &Ctx,
    answers: &Answers,
) -> Result<Vec<Record>, Refusal> {
    match cmd {
        Command::CreateProgramme { policy } => {
            let by = check_create(state, policy, ctx)?;
            Ok(vec![
                Record::ProgrammeCreated {
                    programme: policy.programme,
                    currency: policy.currency,
                    by,
                },
                Record::PolicyVersionRecorded {
                    version: policy.clone(),
                    author: by,
                },
            ])
        }
        Command::EditPolicy { base, version } => {
            let plan = check_edit(state, *base, version, ctx)?;
            let mut out = Vec::new();
            if let Some(q) = &plan.cap_query {
                let a = answers.get(q).ok_or(Refusal::new(
                    RuleRef::FactsIncomplete,
                    RefusalReason::AnswerMissing,
                ))?;
                if !a.holds {
                    return Err(Refusal::new(RuleRef::I14, RefusalReason::VaultRefused));
                }
                out.push(Record::VaultOutcome {
                    kind: q.kind(),
                    digest: a.digest,
                    holds: a.holds,
                    epoch: a.epoch,
                });
            }
            out.push(Record::PolicyVersionRecorded {
                version: Box::new(plan.version.clone()),
                author: plan.author,
            });
            Ok(out)
        }
        _ => Err(Refusal::new(RuleRef::Input, RefusalReason::WrongState)),
    }
}

/// Folds a programme and policy record. The fold checks structure only.
pub(crate) fn apply(
    state: &mut State,
    seq: fstp_ledger::Seq,
    at: Timestamp,
    record: &Record,
) -> Result<(), FoldError> {
    let _ = (seq, at);
    match record {
        Record::ProgrammeCreated {
            programme,
            currency,
            by,
        } => {
            if state.policy.programmes.contains_key(programme)
                || !state.used_ids.insert(UsedId::Programme(*programme))
            {
                return Err(FoldError::DuplicateId);
            }
            state.policy.programmes.insert(
                *programme,
                ProgrammePolicy {
                    currency: *currency,
                    head: None,
                    last_author_p01: *by,
                    last_author_p09: *by,
                },
            );
            Ok(())
        }
        Record::PolicyVersionRecorded { version, author } => fold_version(state, version, *author),
        _ => Err(FoldError::Inconsistent),
    }
}

/// Folds one `PolicyVersionRecorded`: the new head, its last authors, and
/// the end of approvals that a P-01 or P-09 change makes stale (R-PC-03).
fn fold_version(
    state: &mut State,
    version: &PolicyVersion,
    author: AccountId,
) -> Result<(), FoldError> {
    let programme = state
        .policy
        .programmes
        .get(&version.programme)
        .ok_or(FoldError::UnknownEntity)?;
    if programme.currency != version.currency {
        return Err(FoldError::Inconsistent);
    }
    let parent = programme.head.as_ref().map(|h| h.id);
    if parent != version.parent {
        return Err(FoldError::Inconsistent);
    }
    let (p01_changed, p09_changed) = match programme.head.as_deref() {
        Some(h) => (
            h.frozen.p01 != version.frozen.p01,
            h.frozen.p09 != version.frozen.p09,
        ),
        None => (true, true),
    };
    if !state.used_ids.insert(UsedId::PolicyVersion(version.id)) {
        return Err(FoldError::DuplicateId);
    }
    let programme = state
        .policy
        .programmes
        .get_mut(&version.programme)
        .ok_or(FoldError::UnknownEntity)?;
    if p01_changed {
        programme.last_author_p01 = author;
    }
    if p09_changed {
        programme.last_author_p09 = author;
    }
    programme.head = Some(Arc::new(version.clone()));
    if parent.is_some() && (p01_changed || p09_changed) {
        state.calls.revoke_approvals(version.programme);
    }
    Ok(())
}

/// Whether the P-77 of `scope` allows binding actions through MCP (R-MC-05).
/// For a call it is the frozen value, and for a programme the head value.
/// An unpublished call or an unknown programme has no governing P-77, so
/// the command is refused.
pub(crate) fn mcp_binding_allowed(state: &State, scope: PolicyScope) -> Result<bool, Refusal> {
    match scope {
        PolicyScope::Call(call) => call_allows_mcp_binding(state, call),
        PolicyScope::Programme(programme) => programme_allows_mcp_binding(state, programme),
    }
}

/// Whether the frozen P-77 of the published `call` allows binding actions
/// through MCP (R-MC-05, I-12). A later edit of the head never changes it.
/// An unpublished or unknown call is refused.
pub fn call_allows_mcp_binding(state: &State, call: CallId) -> Result<bool, Refusal> {
    let p77 = frozen_policy(state, call).ok_or_else(unknown)?.values().p77;
    Ok(p77 == McpBindingActions::Allowed)
}

/// Whether the head P-77 of `programme` allows binding actions through MCP,
/// for a command that no published call governs (R-MC-05). An unknown
/// programme is refused.
pub fn programme_allows_mcp_binding(
    state: &State,
    programme: ProgrammeId,
) -> Result<bool, Refusal> {
    let p77 = head(state, programme).ok_or_else(unknown)?.frozen.p77;
    Ok(p77 == McpBindingActions::Allowed)
}

/// The vault questions this lane needs for its contribution to the batch of
/// a command that another lane owns. The policy lane contributes nothing.
pub(crate) fn contribute_queries(
    state: &State,
    cmd: &Command,
    ctx: &Ctx,
) -> Result<Vec<Query>, Refusal> {
    let _ = (state, cmd, ctx);
    Ok(Vec::new())
}

/// The records this lane adds to the batch of a command that another lane
/// owns. The policy lane contributes nothing in M2.
pub(crate) fn contribute(
    state: &State,
    cmd: &Command,
    ctx: &Ctx,
    answers: &Answers,
    batch: &[Record],
) -> Result<Vec<Record>, Refusal> {
    let _ = (state, cmd, ctx, answers, batch);
    Ok(Vec::new())
}

/// The policy whose P-77 governs a policy command through MCP (R-MC-05).
/// `EditPolicy` reads the head it is based on, never the new version, so an
/// edit through MCP cannot unlock itself. `CreateProgramme` is high risk
/// and never completes through MCP (I-85).
pub(crate) fn governing_policy(state: &State, cmd: &Command) -> Result<PolicyScope, Refusal> {
    let _ = state;
    match cmd {
        Command::EditPolicy { version, .. } => Ok(PolicyScope::Programme(version.programme)),
        Command::CreateProgramme { .. } => {
            Err(Refusal::new(RuleRef::I85, RefusalReason::NotThroughMcp))
        }
        _ => Err(Refusal::new(RuleRef::Input, RefusalReason::WrongState)),
    }
}
