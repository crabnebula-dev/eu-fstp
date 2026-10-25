//! Policy engine, parameter catalogue and freezing (design section 2.4, I-12).
//!
//! Owned by lane L-POL (docs/handoff/m2-design.md section 10). Step W1c
//! fixed the shapes the interface names: the parameter values, the policy
//! version and the frozen call policy. The catalogue lives in
//! [`crate::rules`] and is re-exported here. Lane L-POL completes
//! validation, the fold of `CallPublished` into [`FrozenPolicy`] and the
//! policy part of the projection.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU8;
use std::sync::Arc;

use fstp_money::{AmountRange, Currency, NonNegAmount, Percent};

use crate::id::{
    CallId, ClassId, KnockOutCriterionId, OrganisationId, PolicyVersionId, ProgrammeId,
    ProximityListId, TextRef,
};
use crate::roles::CoolingOff;
use crate::scoring::Criteria;
use crate::time::Days;

pub use crate::rules::{CATALOGUE, Freeze, Level, ParamId, ParamSpec};

/// A parameter value M2 does not interpret, as RFC 8785 canonical JSON text.
/// Canonical text makes `Eq` and `Hash` exact, so it freezes with the rest (I-12).
///
/// Declared by W1c for the interface. Lane L-POL completes it.
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
///
/// Declared by W1c for the interface. Lane L-POL completes it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ModelRef(pub String);

/// An exact SPDX licence identifier.
///
/// Declared by W1c for the interface. Lane L-POL completes it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SpdxId(pub String);

/// One knock-out criterion of P-09. Its wording is free text held outside the ledger.
///
/// Declared by W1c for the interface. Lane L-POL completes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KnockOutCriterion {
    /// The criterion.
    pub id: KnockOutCriterionId,
    /// Its wording.
    pub text: TextRef,
}

/// The P-09 value.
///
/// Declared by W1c for the interface. Lane L-POL completes it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct KnockOutCriteria(pub Vec<KnockOutCriterion>);

/// The P-10 options (P-10 NOTE 1).
///
/// Declared by W1c for the interface. Lane L-POL completes it.
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
///
/// Declared by W1c for the interface. Lane L-POL completes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReviewerAnonymity {
    /// Reviewers appear to applicants only under per-proposal handles.
    Anonymous,
    /// Reviewers appear by name.
    Named,
}

/// The P-14 value. The programme manager decides whether an exemption applies,
/// so M2 keeps the exemptions as an opaque frozen value.
///
/// Declared by W1c for the interface. Lane L-POL completes it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct IrcExemptions(pub OpaqueValue);

/// The P-16 value. Its details are open (O-44), so M2 keeps it opaque.
///
/// Declared by W1c for the interface. Lane L-POL completes it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct VotingRules(pub OpaqueValue);

/// The P-17 value. People apply the recorded rule (design Q17).
///
/// Declared by W1c for the interface. Lane L-POL completes it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TieBreakRule(pub OpaqueValue);

/// The P-21 value: provider, primary model and an ordered fallback list,
/// all pinned at publication (P-21 NOTE 10).
///
/// Declared by W1c for the interface. Lane L-POL completes it.
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
///
/// Declared by W1c for the interface. Lane L-POL completes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EffectiveScoreRule {
    /// Higher of original and revised, the original on a tie (NOTE 4).
    HigherOfOriginalAndRevised,
}

/// The P-26 value: exact SPDX identifiers.
///
/// Declared by W1c for the interface. Lane L-POL completes it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LicenceSet(pub BTreeSet<SpdxId>);

/// The P-53 value.
///
/// Declared by W1c for the interface. Lane L-POL completes it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FunderProfileRef(pub OpaqueValue);

/// The P-77 options.
///
/// Declared by W1c for the interface. Lane L-POL completes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum McpBindingActions {
    /// Agents draft and the user confirms in the platform.
    DraftOnly,
    /// Agents complete binding actions through MCP.
    Allowed,
}

/// Every frozen programme parameter. Typed where M2 interprets it, opaque
/// otherwise, so every frozen parameter freezes (I-12).
///
/// Declared by W1c for the interface. Lane L-POL completes it.
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
///
/// Declared by W1c for the interface. Lane L-POL completes it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExclusionClasses(pub BTreeSet<ClassId>);

/// The P-38 value: one proximity list per partner organisation, held by the vault.
///
/// Declared by W1c for the interface. Lane L-POL completes it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProximityLists(pub BTreeMap<OrganisationId, ProximityListId>);

/// Programme parameters that are not frozen, read live at decision time.
///
/// Declared by W1c for the interface. Lane L-POL completes it.
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
///
/// Declared by W1c for the interface. Lane L-POL completes it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LiveSnapshot {
    /// P-05 at publication.
    pub p05: NonNegAmount,
    /// P-13 at publication.
    pub p13: ExclusionClasses,
}

/// One immutable version of a programme's policy (I-23).
///
/// Declared by W1c for the interface. Lane L-POL completes validation.
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
///
/// Declared by W1c for the interface. Lane L-POL adds the crate-private
/// constructor that the fold uses.
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

/// Policy part of the projection: per programme, the head version, the
/// versions referenced and the last author of each parameter (R-PC-03).
///
/// Declared empty by W1c so that `State` can hold it. Lane L-POL fills it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PolicyState {
    _pending: (),
}

impl PolicyState {
    /// The policy state before any record.
    pub(crate) const fn genesis() -> PolicyState {
        PolicyState { _pending: () }
    }
}

// ---------------------------------------------------------------------------
// Engine entry points of this lane, called by `crate::engine`.
// ---------------------------------------------------------------------------

/// The vault questions of the programme and policy commands.
///
/// Declared by W1c as a stub. Lane L-POL completes it.
pub(crate) fn queries(
    state: &crate::state::State,
    cmd: &crate::command::Command,
    ctx: &crate::command::Ctx,
) -> Result<Vec<crate::oracle::Query>, crate::refusal::Refusal> {
    let _ = (state, cmd, ctx);
    Err(crate::refusal::Refusal::not_implemented())
}

/// The records of the programme and policy commands.
///
/// Declared by W1c as a stub. Lane L-POL completes it.
pub(crate) fn decide(
    state: &crate::state::State,
    cmd: &crate::command::Command,
    ctx: &crate::command::Ctx,
    answers: &crate::oracle::Answers,
) -> Result<Vec<crate::record::Record>, crate::refusal::Refusal> {
    let _ = (state, cmd, ctx, answers);
    Err(crate::refusal::Refusal::not_implemented())
}

/// Folds a programme and policy record.
///
/// Declared by W1c as a stub. Lane L-POL completes it.
pub(crate) fn apply(
    state: &mut crate::state::State,
    seq: fstp_ledger::Seq,
    at: crate::time::Timestamp,
    record: &crate::record::Record,
) -> Result<(), crate::engine::FoldError> {
    let _ = (state, seq, at, record);
    Err(crate::engine::FoldError::NotImplemented)
}

/// Whether the P-77 of `scope` allows binding actions through MCP (R-MC-05).
/// For a call it is the frozen value, and for a programme the head value.
/// The engine asks it only for a binding action that arrived through MCP,
/// with the scope that the owning lane named.
///
/// Declared by W1c as a stub. Lane L-POL completes it.
pub(crate) fn mcp_binding_allowed(
    state: &crate::state::State,
    scope: crate::engine::PolicyScope,
) -> Result<bool, crate::refusal::Refusal> {
    let _ = (state, scope);
    Err(crate::refusal::Refusal::not_implemented())
}

/// The vault questions this lane needs for its contribution to the batch of
/// a command that another lane owns. It reads only the state and the command.
///
/// Declared by W1c as a stub that asks nothing. Lane L-POL completes it.
pub(crate) fn contribute_queries(
    state: &crate::state::State,
    cmd: &crate::command::Command,
    ctx: &crate::command::Ctx,
) -> Result<Vec<crate::oracle::Query>, crate::refusal::Refusal> {
    let _ = (state, cmd, ctx);
    Ok(Vec::new())
}

/// The records this lane adds to the batch of a command that another lane
/// owns, given the records so far (`crate::engine` module docs).
/// The policy lane is not expected to contribute in M2.
///
/// Declared by W1c as a stub that adds nothing. Lane L-POL completes it.
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
/// (R-MC-05, `crate::engine::PolicyScope`).
///
/// Declared by W1c as a stub. Lane L-POL completes it.
pub(crate) fn governing_policy(
    state: &crate::state::State,
    cmd: &crate::command::Command,
) -> Result<crate::engine::PolicyScope, crate::refusal::Refusal> {
    let _ = (state, cmd);
    Err(crate::refusal::Refusal::not_implemented())
}
