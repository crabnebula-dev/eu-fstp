//! The structured value of each parameter that is more than one scalar.
//!
//! Each type's JSON is the canonical text the policy keeps for an opaque
//! parameter. Where the spec states the options, the type is a closed
//! enum with exactly those options. Where the spec leaves the vocabulary
//! open, the type holds a [`Token`]. Every encoding below is interim,
//! pending Daniel: no design section fixes one, and the W1a test author's
//! readings (`tests/support/readings.rs`) are the contract followed here.

use std::num::{NonZeroU8, NonZeroU16};

use fstp_domain::id::{
    ActivityTypeId, ClassId, CriterionId, KnockOutCriterionId, OrganisationId, ProximityListId,
};
use fstp_json::{FromJsonError, Number, Value};
use fstp_money::{Currency, NonNegAmount};

use crate::value::{
    AnyList, Codec, Date, MAX_LIST, ModelName, Narrative, RawId, Token, U16, UniqueList, array,
    ascending, distinct, list, member, obj, object, option_enum,
};

// ---------------------------------------------------------------------------
// P-01 criteria, P-09 knock-out criteria, P-13 classes, P-55 activity types
// ---------------------------------------------------------------------------

/// One P-01 criterion: its id, its name and its positive integer weight.
/// The name is free text, so it lives in the programme artefacts and never
/// in the policy (ADR-007).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NamedCriterion {
    /// The criterion.
    pub id: CriterionId,
    /// Its name.
    pub name: Narrative,
    /// Its weight (P-01 NOTE 6).
    pub weight: NonZeroU16,
}

impl Codec for NamedCriterion {
    fn decode(v: &Value, c: Currency) -> Result<NamedCriterion, FromJsonError> {
        let o = object(v, &["id", "name", "weight"])?;
        Ok(NamedCriterion {
            id: CriterionId::from_raw(member::<RawId>(o, "id", c)?.0),
            name: member(o, "name", c)?,
            weight: member(o, "weight", c)?,
        })
    }
    fn encode(&self) -> Value {
        obj(vec![
            ("id", RawId(self.id.raw()).encode()),
            ("name", self.name.encode()),
            ("weight", self.weight.encode()),
        ])
    }
    fn placeholder(c: Currency) -> Option<NamedCriterion> {
        Some(NamedCriterion {
            id: CriterionId::from_raw(0),
            name: Narrative::placeholder(c)?,
            weight: NonZeroU16::MIN,
        })
    }
}

/// The P-01 value: the scale maximum N and the criteria in order, with
/// the bounds of `fstp_domain::scoring::Criteria::new`.
///
/// JSON: `{"criteria": [{"id", "name", "weight"}, ...], "scale_max": N}`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScoringCriteria {
    scale_max: NonZeroU8,
    criteria: Vec<NamedCriterion>,
}

impl ScoringCriteria {
    /// The criteria, or `None` outside the M2 bounds: 1 to 16 criteria with
    /// distinct ids, weights at most 1000, a scale maximum at most 100.
    pub fn new(scale_max: NonZeroU8, criteria: Vec<NamedCriterion>) -> Option<ScoringCriteria> {
        let items = criteria
            .iter()
            .map(|c| fstp_domain::scoring::Criterion {
                id: c.id,
                weight: c.weight,
            })
            .collect();
        fstp_domain::scoring::Criteria::new(scale_max, items)
            .is_ok()
            .then_some(ScoringCriteria {
                scale_max,
                criteria,
            })
    }

    /// The scale maximum N.
    pub fn scale_max(&self) -> NonZeroU8 {
        self.scale_max
    }

    /// The criteria in P-01 order.
    pub fn criteria(&self) -> &[NamedCriterion] {
        &self.criteria
    }
}

impl Codec for ScoringCriteria {
    fn decode(v: &Value, c: Currency) -> Result<ScoringCriteria, FromJsonError> {
        let o = object(v, &["criteria", "scale_max"])?;
        let scale_max = member::<NonZeroU8>(o, "scale_max", c)?;
        let criteria = member::<AnyList<NamedCriterion>>(o, "criteria", c)?.0;
        ScoringCriteria::new(scale_max, criteria)
            .ok_or_else(|| FromJsonError::invalid("P-01 is outside its bounds"))
    }
    fn encode(&self) -> Value {
        obj(vec![
            ("criteria", array(&self.criteria)),
            ("scale_max", self.scale_max.encode()),
        ])
    }
    fn placeholder(c: Currency) -> Option<ScoringCriteria> {
        ScoringCriteria::new(NonZeroU8::MIN, vec![NamedCriterion::placeholder(c)?])
    }
}

/// One P-09 knock-out criterion with its wording. The wording is free text:
/// the policy holds only its [`Narrative::policy_ref`], and the text
/// itself lives in the programme artefacts.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KnockOut {
    /// The criterion.
    pub id: KnockOutCriterionId,
    /// Its wording.
    pub text: Narrative,
}

impl Codec for KnockOut {
    fn decode(v: &Value, c: Currency) -> Result<KnockOut, FromJsonError> {
        let o = object(v, &["id", "text"])?;
        Ok(KnockOut {
            id: KnockOutCriterionId::from_raw(member::<RawId>(o, "id", c)?.0),
            text: member(o, "text", c)?,
        })
    }
    fn encode(&self) -> Value {
        obj(vec![
            ("id", RawId(self.id.raw()).encode()),
            ("text", self.text.encode()),
        ])
    }
    fn placeholder(c: Currency) -> Option<KnockOut> {
        Some(KnockOut {
            id: KnockOutCriterionId::from_raw(0),
            text: Narrative::placeholder(c)?,
        })
    }
}

/// One P-13 excluded affiliation class: the opaque class id the vault
/// matches, and its description, which lives in the artefacts.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExclusionClass {
    /// The class.
    pub id: ClassId,
    /// Who it excludes.
    pub description: Narrative,
}

impl Codec for ExclusionClass {
    fn decode(v: &Value, c: Currency) -> Result<ExclusionClass, FromJsonError> {
        let o = object(v, &["description", "id"])?;
        Ok(ExclusionClass {
            id: ClassId::from_raw(member::<RawId>(o, "id", c)?.0),
            description: member(o, "description", c)?,
        })
    }
    fn encode(&self) -> Value {
        obj(vec![
            ("description", self.description.encode()),
            ("id", RawId(self.id.raw()).encode()),
        ])
    }
    fn placeholder(c: Currency) -> Option<ExclusionClass> {
        Some(ExclusionClass {
            id: ClassId::from_raw(0),
            description: Narrative::placeholder(c)?,
        })
    }
}

/// One P-55 activity type: its id and its name, which lives in the
/// artefacts. The policy keeps the list of ids only.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ActivityType {
    /// The activity type.
    pub id: ActivityTypeId,
    /// Its name.
    pub name: Narrative,
}

impl Codec for ActivityType {
    fn decode(v: &Value, c: Currency) -> Result<ActivityType, FromJsonError> {
        let o = object(v, &["id", "name"])?;
        Ok(ActivityType {
            id: ActivityTypeId::from_raw(member::<RawId>(o, "id", c)?.0),
            name: member(o, "name", c)?,
        })
    }
    fn encode(&self) -> Value {
        obj(vec![
            ("id", RawId(self.id.raw()).encode()),
            ("name", self.name.encode()),
        ])
    }
    fn placeholder(c: Currency) -> Option<ActivityType> {
        Some(ActivityType {
            id: ActivityTypeId::from_raw(0),
            name: Narrative::placeholder(c)?,
        })
    }
}

/// A list of entries with distinct ids, in the order given.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Keyed<T>(Vec<T>);

/// An entry of a [`Keyed`] list.
pub(crate) trait HasId {
    /// The entry's id.
    type Id: Ord + Copy;
    /// The id.
    fn key(&self) -> Self::Id;
}

impl HasId for KnockOut {
    type Id = KnockOutCriterionId;
    fn key(&self) -> KnockOutCriterionId {
        self.id
    }
}

impl HasId for ExclusionClass {
    type Id = ClassId;
    fn key(&self) -> ClassId {
        self.id
    }
}

impl HasId for ActivityType {
    type Id = ActivityTypeId;
    fn key(&self) -> ActivityTypeId {
        self.id
    }
}

#[allow(
    private_bounds,
    reason = "HasId is implemented only by this crate's entry types"
)]
impl<T: HasId> Keyed<T> {
    /// The list, or `None` when two entries share an id or it is too long.
    pub fn new(items: Vec<T>) -> Option<Keyed<T>> {
        (items.len() <= MAX_LIST && distinct(items.iter().map(HasId::key))).then_some(Keyed(items))
    }

    /// The entries in order.
    pub fn items(&self) -> &[T] {
        &self.0
    }
}

impl<T: HasId + Codec> Codec for Keyed<T> {
    fn decode(v: &Value, c: Currency) -> Result<Keyed<T>, FromJsonError> {
        Keyed::new(list(v, c)?).ok_or_else(|| FromJsonError::invalid("two entries share an id"))
    }
    fn encode(&self) -> Value {
        array(&self.0)
    }
    fn placeholder(_: Currency) -> Option<Keyed<T>> {
        Some(Keyed(Vec::new()))
    }
}

// ---------------------------------------------------------------------------
// P-14 IRC exemptions
// ---------------------------------------------------------------------------

/// One P-14 exemption from IRC review for an amendment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IrcExemption {
    /// A change of team.
    TeamChange,
    /// A plan change without a budget change.
    PlanChangeWithoutBudgetChange,
    /// Additional tasks in scope at equivalent rates, with the amended
    /// contract total below the amount (`contracts.md`).
    AdditionalTasksInScope {
        /// The amended contract total must stay below this amount.
        total_below: NonNegAmount,
    },
}

impl IrcExemption {
    fn kind(&self) -> u8 {
        match self {
            IrcExemption::TeamChange => 0,
            IrcExemption::PlanChangeWithoutBudgetChange => 1,
            IrcExemption::AdditionalTasksInScope { .. } => 2,
        }
    }
}

impl Codec for IrcExemption {
    /// `{"kind": "team_change"}`, `{"kind": "plan_change_without_budget_change"}`
    /// or `{"kind": "additional_tasks_in_scope_at_equivalent_rates",
    /// "total_below": amount}`.
    fn decode(v: &Value, c: Currency) -> Result<IrcExemption, FromJsonError> {
        let kind = v
            .as_object()
            .and_then(|o| o.get("kind"))
            .and_then(Value::as_str)
            .ok_or_else(|| FromJsonError::invalid("an exemption names its kind"))?;
        match kind {
            "team_change" => object(v, &["kind"]).map(|_| IrcExemption::TeamChange),
            "plan_change_without_budget_change" => {
                object(v, &["kind"]).map(|_| IrcExemption::PlanChangeWithoutBudgetChange)
            }
            "additional_tasks_in_scope_at_equivalent_rates" => {
                let o = object(v, &["kind", "total_below"])?;
                Ok(IrcExemption::AdditionalTasksInScope {
                    total_below: member(o, "total_below", c)?,
                })
            }
            _ => Err(FromJsonError::invalid("not an exemption kind").at_field("kind")),
        }
    }
    fn encode(&self) -> Value {
        match self {
            IrcExemption::TeamChange => obj(vec![("kind", Value::from("team_change"))]),
            IrcExemption::PlanChangeWithoutBudgetChange => obj(vec![(
                "kind",
                Value::from("plan_change_without_budget_change"),
            )]),
            IrcExemption::AdditionalTasksInScope { total_below } => obj(vec![
                (
                    "kind",
                    Value::from("additional_tasks_in_scope_at_equivalent_rates"),
                ),
                ("total_below", total_below.encode()),
            ]),
        }
    }
    fn placeholder(_: Currency) -> Option<IrcExemption> {
        Some(IrcExemption::TeamChange)
    }
}

/// The P-14 value: exemptions, each kind at most once, in the order given.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct IrcExemptions(Vec<IrcExemption>);

impl IrcExemptions {
    /// The exemptions, or `None` when a kind repeats.
    pub fn new(items: Vec<IrcExemption>) -> Option<IrcExemptions> {
        distinct(items.iter().map(IrcExemption::kind)).then_some(IrcExemptions(items))
    }

    /// The exemptions in order.
    pub fn items(&self) -> &[IrcExemption] {
        &self.0
    }
}

impl Codec for IrcExemptions {
    fn decode(v: &Value, c: Currency) -> Result<IrcExemptions, FromJsonError> {
        IrcExemptions::new(list(v, c)?)
            .ok_or_else(|| FromJsonError::invalid("an exemption repeats"))
    }
    fn encode(&self) -> Value {
        array(&self.0)
    }
    fn placeholder(_: Currency) -> Option<IrcExemptions> {
        Some(IrcExemptions(Vec::new()))
    }
}

// ---------------------------------------------------------------------------
// P-16 voting and P-17 tie-break
// ---------------------------------------------------------------------------

option_enum! {
    /// How the committee decides (P-16 NOTE 8). The spec decides one option.
    pub enum VoteDecision {
        /// A majority of the votes cast.
        Majority => "majority",
    }
    placeholder Majority
}

option_enum! {
    /// Who breaks a tie (P-16 NOTE 8). The spec decides one option.
    pub enum CastingVote {
        /// The committee chair.
        Chair => "chair",
    }
    placeholder Chair
}

/// The P-16 value. JSON: `{"casting_vote", "decision", "delegation"}`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VotingRules {
    /// The decision rule.
    pub decision: VoteDecision,
    /// Whether a member may delegate a vote.
    pub delegation: bool,
    /// Who breaks a tie.
    pub casting_vote: CastingVote,
}

impl Codec for VotingRules {
    fn decode(v: &Value, c: Currency) -> Result<VotingRules, FromJsonError> {
        let o = object(v, &["casting_vote", "decision", "delegation"])?;
        Ok(VotingRules {
            decision: member(o, "decision", c)?,
            delegation: member(o, "delegation", c)?,
            casting_vote: member(o, "casting_vote", c)?,
        })
    }
    fn encode(&self) -> Value {
        obj(vec![
            ("casting_vote", self.casting_vote.encode()),
            ("decision", self.decision.encode()),
            ("delegation", self.delegation.encode()),
        ])
    }
    fn placeholder(_: Currency) -> Option<VotingRules> {
        Some(VotingRules {
            decision: VoteDecision::Majority,
            delegation: false,
            casting_vote: CastingVote::Chair,
        })
    }
}

/// The P-17 value. JSON: `{"exception", "priority"}`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TieBreak {
    /// Who receives priority on equal quality.
    pub priority: Token,
    /// When others can still be funded.
    pub exception: Token,
}

impl Codec for TieBreak {
    fn decode(v: &Value, c: Currency) -> Result<TieBreak, FromJsonError> {
        let o = object(v, &["exception", "priority"])?;
        Ok(TieBreak {
            priority: member(o, "priority", c)?,
            exception: member(o, "exception", c)?,
        })
    }
    fn encode(&self) -> Value {
        obj(vec![
            ("exception", self.exception.encode()),
            ("priority", self.priority.encode()),
        ])
    }
    fn placeholder(c: Currency) -> Option<TieBreak> {
        Some(TieBreak {
            priority: Token::placeholder(c)?,
            exception: Token::placeholder(c)?,
        })
    }
}

// ---------------------------------------------------------------------------
// P-21 inference, P-22 trace retention, P-23 pre-check
// ---------------------------------------------------------------------------

/// The P-21 value: provider, primary model and ordered fallbacks (NOTE 10).
/// JSON: `{"fallbacks": [...], "primary", "provider"}`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Inference {
    /// The inference provider.
    pub provider: Token,
    /// The primary pinned model.
    pub primary: ModelName,
    /// Replacement models in the order they are taken, none repeated.
    pub fallbacks: UniqueList<ModelName>,
}

impl Codec for Inference {
    fn decode(v: &Value, c: Currency) -> Result<Inference, FromJsonError> {
        let o = object(v, &["fallbacks", "primary", "provider"])?;
        Ok(Inference {
            provider: member(o, "provider", c)?,
            primary: member(o, "primary", c)?,
            fallbacks: member(o, "fallbacks", c)?,
        })
    }
    fn encode(&self) -> Value {
        obj(vec![
            ("fallbacks", self.fallbacks.encode()),
            ("primary", self.primary.encode()),
            ("provider", self.provider.encode()),
        ])
    }
    fn placeholder(c: Currency) -> Option<Inference> {
        Some(Inference {
            provider: Token::placeholder(c)?,
            primary: ModelName::placeholder(c)?,
            fallbacks: UniqueList::placeholder(c)?,
        })
    }
}

/// The P-22 value: how long traces are kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TraceRetention {
    /// Until the funder retention period P-41 ends: `{"until": "P-41"}`.
    UntilFunderRetentionEnds,
    /// A number of days: `{"days": n}`.
    Days(u16),
}

impl Codec for TraceRetention {
    fn decode(v: &Value, c: Currency) -> Result<TraceRetention, FromJsonError> {
        let is_until = v.as_object().is_some_and(|o| o.contains_key("until"));
        if is_until {
            let o = object(v, &["until"])?;
            return match o.get("until").and_then(Value::as_str) {
                Some("P-41") => Ok(TraceRetention::UntilFunderRetentionEnds),
                _ => Err(FromJsonError::invalid("retention runs until P-41").at_field("until")),
            };
        }
        let o = object(v, &["days"])?;
        member::<U16>(o, "days", c).map(|n| TraceRetention::Days(n.0))
    }
    fn encode(&self) -> Value {
        match self {
            TraceRetention::UntilFunderRetentionEnds => obj(vec![("until", Value::from("P-41"))]),
            TraceRetention::Days(n) => obj(vec![("days", Value::Number(Number::from(*n)))]),
        }
    }
    fn placeholder(_: Currency) -> Option<TraceRetention> {
        Some(TraceRetention::Days(0))
    }
}

/// The P-23 value: whether the pre-check is enabled, and its limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Precheck {
    /// Whether the pre-check is enabled.
    pub enabled: bool,
    /// Checks per day per proposal.
    pub per_day_per_proposal: u16,
    /// Checks per call per proposal.
    pub per_call_per_proposal: u16,
    /// Whether the limits apply per account across drafts in the same call.
    pub account_cap_across_drafts_in_call: bool,
}

impl Codec for Precheck {
    fn decode(v: &Value, c: Currency) -> Result<Precheck, FromJsonError> {
        let o = object(
            v,
            &[
                "account_cap_across_drafts_in_call",
                "enabled",
                "per_call_per_proposal",
                "per_day_per_proposal",
            ],
        )?;
        Ok(Precheck {
            enabled: member(o, "enabled", c)?,
            per_day_per_proposal: member::<U16>(o, "per_day_per_proposal", c)?.0,
            per_call_per_proposal: member::<U16>(o, "per_call_per_proposal", c)?.0,
            account_cap_across_drafts_in_call: member(o, "account_cap_across_drafts_in_call", c)?,
        })
    }
    fn encode(&self) -> Value {
        obj(vec![
            (
                "account_cap_across_drafts_in_call",
                self.account_cap_across_drafts_in_call.encode(),
            ),
            ("enabled", self.enabled.encode()),
            (
                "per_call_per_proposal",
                U16(self.per_call_per_proposal).encode(),
            ),
            (
                "per_day_per_proposal",
                U16(self.per_day_per_proposal).encode(),
            ),
        ])
    }
    fn placeholder(_: Currency) -> Option<Precheck> {
        Some(Precheck {
            enabled: false,
            per_day_per_proposal: 0,
            per_call_per_proposal: 0,
            account_cap_across_drafts_in_call: true,
        })
    }
}

// ---------------------------------------------------------------------------
// P-29 instrument, P-31 reminders, P-32 channels, P-33 escalation
// ---------------------------------------------------------------------------

/// A contract template and its version, which P-29 freezes at call
/// publication (`contracts.md`, R-CT-01). JSON: `{"id": token,
/// "version": n}` with `n` at least 1. Interim, pending Daniel.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContractTemplateRef {
    /// The template, such as `annexe-6-mou`.
    pub id: Token,
    /// Its version.
    pub version: NonZeroU16,
}

impl Codec for ContractTemplateRef {
    fn decode(v: &Value, c: Currency) -> Result<ContractTemplateRef, FromJsonError> {
        let o = object(v, &["id", "version"])?;
        Ok(ContractTemplateRef {
            id: member(o, "id", c)?,
            version: member(o, "version", c)?,
        })
    }
    fn encode(&self) -> Value {
        obj(vec![
            ("id", self.id.encode()),
            ("version", self.version.encode()),
        ])
    }
    fn placeholder(c: Currency) -> Option<ContractTemplateRef> {
        Some(ContractTemplateRef {
            id: Token::placeholder(c)?,
            version: NonZeroU16::MIN,
        })
    }
}

/// The P-29 value: the contract instrument and the template version it
/// uses. JSON: `{"instrument": token, "template": {"id": token,
/// "version": n}}`. Interim, pending Daniel.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContractInstrument {
    /// The instrument, such as `mou`.
    pub instrument: Token,
    /// The contract template and its version.
    pub template: ContractTemplateRef,
}

impl Codec for ContractInstrument {
    fn decode(v: &Value, c: Currency) -> Result<ContractInstrument, FromJsonError> {
        let o = object(v, &["instrument", "template"])?;
        Ok(ContractInstrument {
            instrument: member(o, "instrument", c)?,
            template: member(o, "template", c)?,
        })
    }
    fn encode(&self) -> Value {
        obj(vec![
            ("instrument", self.instrument.encode()),
            ("template", self.template.encode()),
        ])
    }
    fn placeholder(c: Currency) -> Option<ContractInstrument> {
        Some(ContractInstrument {
            instrument: Token::placeholder(c)?,
            template: ContractTemplateRef::placeholder(c)?,
        })
    }
}

/// One message template of creator step 10: the message kind and its text.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MessageTemplate {
    /// The message kind, such as `reminder`.
    pub kind: Token,
    /// The template text.
    pub text: Narrative,
}

impl Codec for MessageTemplate {
    fn decode(v: &Value, c: Currency) -> Result<MessageTemplate, FromJsonError> {
        let o = object(v, &["kind", "text"])?;
        Ok(MessageTemplate {
            kind: member(o, "kind", c)?,
            text: member(o, "text", c)?,
        })
    }
    fn encode(&self) -> Value {
        obj(vec![
            ("kind", self.kind.encode()),
            ("text", self.text.encode()),
        ])
    }
    fn placeholder(c: Currency) -> Option<MessageTemplate> {
        Some(MessageTemplate {
            kind: Token::placeholder(c)?,
            text: Narrative::placeholder(c)?,
        })
    }
}

/// The message templates of creator step 10, one per kind, with kinds
/// strictly ascending so the list has one spelling. JSON: `[{"kind":
/// token, "text": narrative}, ...]`. Interim, pending Daniel.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MessageTemplates(Vec<MessageTemplate>);

impl MessageTemplates {
    /// The templates, or `None` unless their kinds are strictly ascending
    /// and there are at most [`MAX_LIST`].
    pub fn new(items: Vec<MessageTemplate>) -> Option<MessageTemplates> {
        (items.len() <= MAX_LIST && ascending(items.iter().map(|t| &t.kind)))
            .then_some(MessageTemplates(items))
    }

    /// The templates in kind order.
    pub fn items(&self) -> &[MessageTemplate] {
        &self.0
    }
}

impl Codec for MessageTemplates {
    fn decode(v: &Value, c: Currency) -> Result<MessageTemplates, FromJsonError> {
        MessageTemplates::new(list(v, c)?)
            .ok_or_else(|| FromJsonError::invalid("message kinds are strictly ascending"))
    }
    fn encode(&self) -> Value {
        array(&self.0)
    }
    fn placeholder(_: Currency) -> Option<MessageTemplates> {
        Some(MessageTemplates(Vec::new()))
    }
}

/// The longest reminder offset, in days either side of the due date.
pub const MAX_REMINDER_OFFSET_DAYS: i16 = 366;

/// The P-31 value: reminder offsets in days from the due date, strictly
/// ascending. JSON: `{"offsets_days": [-14, -3, 0]}`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReminderOffsets(Vec<i16>);

impl ReminderOffsets {
    /// The offsets, or `None` unless strictly ascending and within
    /// [`MAX_REMINDER_OFFSET_DAYS`].
    pub fn new(offsets: Vec<i16>) -> Option<ReminderOffsets> {
        let bounded = offsets
            .iter()
            .all(|d| (-MAX_REMINDER_OFFSET_DAYS..=MAX_REMINDER_OFFSET_DAYS).contains(d));
        (bounded && offsets.len() <= MAX_LIST && ascending(offsets.iter()))
            .then_some(ReminderOffsets(offsets))
    }

    /// The offsets in ascending order.
    pub fn offsets(&self) -> &[i16] {
        &self.0
    }
}

/// One signed day offset.
struct Offset(i16);

impl Codec for Offset {
    fn decode(v: &Value, _: Currency) -> Result<Offset, FromJsonError> {
        <i16 as fstp_json::FromJson>::from_json(v).map(Offset)
    }
    fn encode(&self) -> Value {
        Value::Number(Number::from(self.0))
    }
    fn placeholder(_: Currency) -> Option<Offset> {
        Some(Offset(0))
    }
}

impl Codec for ReminderOffsets {
    fn decode(v: &Value, c: Currency) -> Result<ReminderOffsets, FromJsonError> {
        let o = object(v, &["offsets_days"])?;
        let raw = member::<AnyList<Offset>>(o, "offsets_days", c)?.0;
        ReminderOffsets::new(raw.into_iter().map(|x| x.0).collect())
            .ok_or_else(|| FromJsonError::invalid("offsets are strictly ascending and bounded"))
    }
    fn encode(&self) -> Value {
        let items: Vec<Value> = self
            .0
            .iter()
            .map(|d| Value::Number(Number::from(*d)))
            .collect();
        obj(vec![("offsets_days", Value::from(items))])
    }
    fn placeholder(_: Currency) -> Option<ReminderOffsets> {
        Some(ReminderOffsets(Vec::new()))
    }
}

option_enum! {
    /// A messaging channel (P-32, `03-architecture/notifications.md`).
    pub enum Channel {
        /// Email.
        Email => "email",
        /// Matrix.
        Matrix => "matrix",
        /// WhatsApp Business.
        WhatsApp => "whatsapp",
    }
    placeholder Email
}

option_enum! {
    /// A group type (P-32).
    pub enum GroupType {
        /// Programme announcements.
        ProgrammeAnnouncements => "programme_announcements",
        /// The committee group.
        CommitteeGroup => "committee_group",
        /// A grantee cohort.
        GranteeCohort => "grantee_cohort",
        /// A project group.
        ProjectGroup => "project_group",
    }
    placeholder ProgrammeAnnouncements
}

/// The P-32 value. JSON: `{"channels", "group_types", "whatsapp_account"}`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Channels {
    /// The enabled channels, none repeated.
    pub channels: UniqueList<Channel>,
    /// The enabled group types, none repeated.
    pub group_types: UniqueList<GroupType>,
    /// Who owns the WhatsApp account, such as `tenant_owned`.
    pub whatsapp_account: Token,
}

impl Codec for Channels {
    fn decode(v: &Value, c: Currency) -> Result<Channels, FromJsonError> {
        let o = object(v, &["channels", "group_types", "whatsapp_account"])?;
        Ok(Channels {
            channels: member(o, "channels", c)?,
            group_types: member(o, "group_types", c)?,
            whatsapp_account: member(o, "whatsapp_account", c)?,
        })
    }
    fn encode(&self) -> Value {
        obj(vec![
            ("channels", self.channels.encode()),
            ("group_types", self.group_types.encode()),
            ("whatsapp_account", self.whatsapp_account.encode()),
        ])
    }
    fn placeholder(c: Currency) -> Option<Channels> {
        Some(Channels {
            channels: UniqueList::placeholder(c)?,
            group_types: UniqueList::placeholder(c)?,
            whatsapp_account: Token::placeholder(c)?,
        })
    }
}

/// The P-33 value. JSON: `{"after_days": n, "to": token}`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Escalation {
    /// Days after the due date.
    pub after_days: u16,
    /// Who receives the escalation, such as `programme_manager`.
    pub to: Token,
}

impl Codec for Escalation {
    fn decode(v: &Value, c: Currency) -> Result<Escalation, FromJsonError> {
        let o = object(v, &["after_days", "to"])?;
        Ok(Escalation {
            after_days: member::<U16>(o, "after_days", c)?.0,
            to: member(o, "to", c)?,
        })
    }
    fn encode(&self) -> Value {
        obj(vec![
            ("after_days", U16(self.after_days).encode()),
            ("to", self.to.encode()),
        ])
    }
    fn placeholder(c: Currency) -> Option<Escalation> {
        Some(Escalation {
            after_days: 0,
            to: Token::placeholder(c)?,
        })
    }
}

// ---------------------------------------------------------------------------
// P-38 proximity lists, P-40 calendar, P-41 retention
// ---------------------------------------------------------------------------

/// One P-38 entry: a partner organisation and its proximity list.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProximityEntry {
    /// The partner organisation.
    pub organisation: OrganisationId,
    /// Its list, held by the vault.
    pub list: ProximityListId,
}

impl Codec for ProximityEntry {
    fn decode(v: &Value, c: Currency) -> Result<ProximityEntry, FromJsonError> {
        let o = object(v, &["list", "organisation"])?;
        Ok(ProximityEntry {
            organisation: OrganisationId::from_raw(member::<RawId>(o, "organisation", c)?.0),
            list: ProximityListId::from_raw(member::<RawId>(o, "list", c)?.0),
        })
    }
    fn encode(&self) -> Value {
        obj(vec![
            ("list", RawId(self.list.raw()).encode()),
            ("organisation", RawId(self.organisation.raw()).encode()),
        ])
    }
    fn placeholder(_: Currency) -> Option<ProximityEntry> {
        Some(ProximityEntry {
            organisation: OrganisationId::from_raw(0),
            list: ProximityListId::from_raw(0),
        })
    }
}

/// The P-38 value: one list per organisation, strictly ascending by
/// organisation, so it has one spelling.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProximityLists(Vec<ProximityEntry>);

impl ProximityLists {
    /// The lists, or `None` unless strictly ascending by organisation.
    pub fn new(entries: Vec<ProximityEntry>) -> Option<ProximityLists> {
        (entries.len() <= MAX_LIST && ascending(entries.iter().map(|e| e.organisation)))
            .then_some(ProximityLists(entries))
    }

    /// The entries by organisation.
    pub fn entries(&self) -> &[ProximityEntry] {
        &self.0
    }
}

impl Codec for ProximityLists {
    fn decode(v: &Value, c: Currency) -> Result<ProximityLists, FromJsonError> {
        ProximityLists::new(list(v, c)?)
            .ok_or_else(|| FromJsonError::invalid("entries are strictly ascending by organisation"))
    }
    fn encode(&self) -> Value {
        array(&self.0)
    }
    fn placeholder(_: Currency) -> Option<ProximityLists> {
        Some(ProximityLists(Vec::new()))
    }
}

option_enum! {
    /// A day of the week, in week order.
    pub enum Weekday {
        /// Monday.
        Monday => "monday",
        /// Tuesday.
        Tuesday => "tuesday",
        /// Wednesday.
        Wednesday => "wednesday",
        /// Thursday.
        Thursday => "thursday",
        /// Friday.
        Friday => "friday",
        /// Saturday.
        Saturday => "saturday",
        /// Sunday.
        Sunday => "sunday",
    }
    placeholder Saturday
}

/// The P-40 value: weekend days and public holidays, each written as a
/// strictly ascending list. JSON: `{"holidays": [dates], "weekend": [days]}`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WorkingCalendar {
    /// The weekend days, in week order.
    pub weekend: crate::value::SortedSet<Weekday>,
    /// The public holidays, in date order.
    pub holidays: crate::value::SortedSet<Date>,
}

impl Codec for WorkingCalendar {
    fn decode(v: &Value, c: Currency) -> Result<WorkingCalendar, FromJsonError> {
        let o = object(v, &["holidays", "weekend"])?;
        Ok(WorkingCalendar {
            weekend: member(o, "weekend", c)?,
            holidays: member(o, "holidays", c)?,
        })
    }
    fn encode(&self) -> Value {
        obj(vec![
            ("holidays", self.holidays.encode()),
            ("weekend", self.weekend.encode()),
        ])
    }
    fn placeholder(c: Currency) -> Option<WorkingCalendar> {
        Some(WorkingCalendar {
            weekend: crate::value::SortedSet::placeholder(c)?,
            holidays: crate::value::SortedSet::placeholder(c)?,
        })
    }
}

/// The P-41 value: whole years after the action's final payment.
/// JSON: `{"years": n}` with n at least 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FunderRetention {
    /// The years.
    pub years: NonZeroU8,
}

impl Codec for FunderRetention {
    fn decode(v: &Value, c: Currency) -> Result<FunderRetention, FromJsonError> {
        let o = object(v, &["years"])?;
        Ok(FunderRetention {
            years: member(o, "years", c)?,
        })
    }
    fn encode(&self) -> Value {
        obj(vec![("years", self.years.encode())])
    }
    fn placeholder(_: Currency) -> Option<FunderRetention> {
        Some(FunderRetention {
            years: NonZeroU8::MIN,
        })
    }
}

// ---------------------------------------------------------------------------
// P-45, P-47, P-53, P-57, P-65 to P-67
// ---------------------------------------------------------------------------

option_enum! {
    /// The P-45 options: the EUDI Wallet relying party mode.
    pub enum RelyingPartyMode {
        /// The tenant registers as relying party.
        TenantRegistration => "tenant_registration",
        /// CrabNebula acts as intermediary. Self-hosted cells cannot use it.
        CrabNebulaIntermediary => "crabnebula_intermediary",
    }
    placeholder TenantRegistration
}

option_enum! {
    /// The P-47 options: the seal level for contractual notices.
    pub enum SealLevel {
        /// An advanced electronic seal.
        Advanced => "advanced",
        /// A qualified electronic seal.
        Qualified => "qualified",
    }
    placeholder Qualified
}

/// The P-53 value: funder profile and version.
/// JSON: `{"profile": token, "version": n}` with n at least 1.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProfileRef {
    /// The profile, such as `horizon-europe`.
    pub profile: Token,
    /// Its version.
    pub version: NonZeroU16,
}

impl Codec for ProfileRef {
    fn decode(v: &Value, c: Currency) -> Result<ProfileRef, FromJsonError> {
        let o = object(v, &["profile", "version"])?;
        Ok(ProfileRef {
            profile: member(o, "profile", c)?,
            version: member(o, "version", c)?,
        })
    }
    fn encode(&self) -> Value {
        obj(vec![
            ("profile", self.profile.encode()),
            ("version", self.version.encode()),
        ])
    }
    fn placeholder(c: Currency) -> Option<ProfileRef> {
        Some(ProfileRef {
            profile: Token::placeholder(c)?,
            version: NonZeroU16::MIN,
        })
    }
}

/// The P-57 value: the action's start and end dates. A start after the
/// end decodes, so that the creator reports it (`ActionDatesInconsistent`).
/// JSON: `{"end": date, "start": date}`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ActionDates {
    /// The first day of the action.
    pub start: Date,
    /// The last day of the action.
    pub end: Date,
}

impl Codec for ActionDates {
    fn decode(v: &Value, c: Currency) -> Result<ActionDates, FromJsonError> {
        let o = object(v, &["end", "start"])?;
        Ok(ActionDates {
            start: member(o, "start", c)?,
            end: member(o, "end", c)?,
        })
    }
    fn encode(&self) -> Value {
        obj(vec![
            ("end", self.end.encode()),
            ("start", self.start.encode()),
        ])
    }
    fn placeholder(c: Currency) -> Option<ActionDates> {
        let d = Date::placeholder(c)?;
        Some(ActionDates { start: d, end: d })
    }
}

option_enum! {
    /// The P-65 options: evidence for a partial claim on a milestone.
    pub enum PartialClaimEvidence {
        /// Public deliverables, as for a full claim.
        PublicDeliverables => "public_deliverables",
        /// A progress report, with deliverables at the final claim.
        ProgressReport => "progress_report_with_final_deliverables",
    }
    placeholder PublicDeliverables
}

/// The P-66 value. JSON: `{"approval": token, "enabled": bool}`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Reallocation {
    /// Whether reallocation between milestones of one task is enabled.
    pub enabled: bool,
    /// Who approves it, such as `assigned_reviewer`.
    pub approval: Token,
}

impl Codec for Reallocation {
    fn decode(v: &Value, c: Currency) -> Result<Reallocation, FromJsonError> {
        let o = object(v, &["approval", "enabled"])?;
        Ok(Reallocation {
            enabled: member(o, "enabled", c)?,
            approval: member(o, "approval", c)?,
        })
    }
    fn encode(&self) -> Value {
        obj(vec![
            ("approval", self.approval.encode()),
            ("enabled", self.enabled.encode()),
        ])
    }
    fn placeholder(c: Currency) -> Option<Reallocation> {
        Some(Reallocation {
            enabled: false,
            approval: Token::placeholder(c)?,
        })
    }
}

option_enum! {
    /// The P-67 options: unclaimed milestone balances at grant end.
    pub enum UnclaimedBalances {
        /// Return to the action's FSTP budget.
        ReturnToFstpBudget => "return_to_fstp_budget",
        /// Lapse and report as unspent.
        LapseAndReportUnspent => "lapse_and_report_unspent",
    }
    placeholder ReturnToFstpBudget
}

option_enum! {
    /// A flow-down obligation of the grant agreement that every contract
    /// passes on under the Horizon Europe profile (I-49,
    /// `02-domain/contracts.md`). Identifiers only: clause wording comes
    /// from the signed grant agreement and legal review.
    pub enum FlowDownObligation {
        /// Conflict of interests.
        ConflictOfInterests => "conflict_of_interests",
        /// Confidentiality and security.
        ConfidentialityAndSecurity => "confidentiality_and_security",
        /// Ethics and values.
        EthicsAndValues => "ethics_and_values",
        /// Visibility of EU funding.
        VisibilityOfEuFunding => "visibility_of_eu_funding",
        /// Specific rules for carrying out the action.
        SpecificRulesForCarryingOutTheAction => "specific_rules_for_carrying_out_the_action",
        /// Information obligations.
        InformationObligations => "information_obligations",
        /// Record-keeping.
        RecordKeeping => "record_keeping",
        /// Access rights for the granting authority and the bodies named there.
        AccessRights => "access_rights",
    }
    placeholder ConflictOfInterests
}
