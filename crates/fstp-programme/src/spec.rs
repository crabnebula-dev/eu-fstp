//! `ProgrammeSpec`, the `FIELDS` table and the spec's JSON form.
//!
//! One table, [`programme_fields!`], names every field once: its step, its
//! JSON member, its value type, its kind, the parameters it sets, whether
//! import may propose it and the rules that bound it. The table generates
//! [`FieldId`], [`FieldValue`], [`FIELDS`], the ten step structs and the
//! spec's strict JSON codec, so they cannot drift apart.
//!
//! The JSON form is one object with the members `schema`, `currency` and
//! one object per creator step. A step object holds exactly its fields'
//! members. A gap is `null`. Every member is required, and unknown members
//! are refused at every level.
//!
//! Placement of the parameters that no creator step names follows M4
//! design section 3.1 (Q36 A). Interim, pending Daniel.

use std::num::{NonZeroU8, NonZeroU16};

use fstp_domain::policy::{EffectiveScoreRule, McpBindingActions, ReadAccess, ReviewerAnonymity};
use fstp_domain::refusal::RuleRef;
use fstp_domain::roles::CoolingOff;
use fstp_domain::rules::ParamId;
use fstp_domain::time::Days;
use fstp_json::{FromJsonError, FromJsonErrorKind, ParseError, Value};
use fstp_money::{AmountRange, Currency, NonNegAmount, Percent};

use crate::kinds::{
    ActionDates, ActivityType, Channels, ContractInstrument, Escalation, ExclusionClass,
    FlowDownObligation, FunderRetention, Inference, IrcExemptions, Keyed, KnockOut,
    MessageTemplates, PartialClaimEvidence, Precheck, ProfileRef, ProximityLists, Reallocation,
    RelyingPartyMode, ReminderOffsets, ScoringCriteria, SealLevel, TieBreak, TraceRetention,
    UnclaimedBalances, VotingRules, WorkingCalendar,
};
use crate::value::{
    ActionNumber, Codec, LanguageCode, Licence, Narrative, ReviewerMinimum, Slug, SortedSet, Token,
    UniqueList, WorkingDays, object,
};

/// A field value or an explicit gap. A gap compiles to the profile's
/// placeholder and is always a validation failure (`FieldUnset`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Field<T> {
    /// The value.
    Set(T),
    /// No value yet.
    Unset,
}

impl<T> Field<T> {
    /// The value, if set.
    pub fn as_set(&self) -> Option<&T> {
        match self {
            Field::Set(v) => Some(v),
            Field::Unset => None,
        }
    }

    /// Whether the field holds a value.
    pub fn is_set(&self) -> bool {
        matches!(self, Field::Set(_))
    }

    /// The field with `f` applied to its value.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Field<U> {
        match self {
            Field::Set(v) => Field::Set(f(v)),
            Field::Unset => Field::Unset,
        }
    }
}

/// The schema of a spec. Only `"fstp.programme/1"` exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SpecSchema {
    /// `"fstp.programme/1"`.
    V1,
}

impl SpecSchema {
    /// The schema name as the JSON form spells it.
    pub const fn as_str(self) -> &'static str {
        match self {
            SpecSchema::V1 => "fstp.programme/1",
        }
    }
}

/// Whether a field sets policy parameters or only programme artefacts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FieldKind {
    /// It sets one or more policy parameters.
    Policy,
    /// It sets a programme artefact only, such as narrative text.
    Artefact,
}

/// One row of [`FIELDS`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldSpec {
    /// The field.
    pub id: FieldId,
    /// Its creator step, 1 to 10, as in `programme-creator.md`.
    pub step: Step,
    /// The parameters it sets. Empty for an artefact field.
    pub params: &'static [ParamId],
    /// Policy or artefact.
    pub kind: FieldKind,
    /// Whether document import may propose a value (I-65).
    pub importable: bool,
    /// The rules that bound its value, such as I-50 for the cap.
    pub bound_by: &'static [RuleRef],
}

/// Why a spec or a field value did not decode.
///
/// Neither variant holds input content (R-NF-02).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The bytes are not JSON within the parse limits.
    Json(ParseError),
    /// The JSON does not have the required shape or values.
    Shape(FromJsonError),
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DecodeError::Json(e) => write!(f, "not JSON: {e}"),
            DecodeError::Shape(e) => write!(f, "not a programme value: {e}"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// A missing member error at `key`.
fn missing(key: &'static str) -> FromJsonError {
    FromJsonError::new(FromJsonErrorKind::MissingField).at_field(key)
}

/// Decodes the step member `key` of a step object: `null` is a gap.
fn step_member<T: Codec>(
    o: &fstp_json::Object,
    key: &'static str,
    c: Currency,
) -> Result<Field<T>, FromJsonError> {
    match o.get(key) {
        None => Err(missing(key)),
        Some(Value::Null) => Ok(Field::Unset),
        Some(v) => T::decode(v, c).map(Field::Set).map_err(|e| e.at_field(key)),
    }
}

/// The JSON of a field: its value, or `null` for a gap.
fn field_json<T: Codec>(f: &Field<T>) -> Value {
    match f {
        Field::Set(v) => v.encode(),
        Field::Unset => Value::Null,
    }
}

macro_rules! programme_fields {
    ($(
        $(#[$sdoc:meta])*
        $step:ident: $Step:ident = $variant:ident($n:literal) {
            $(
                #[doc = $fdoc:literal]
                $member:ident: $id:ident($ty:ty), $kind:ident,
                    [$($p:ident),*], importable $imp:literal, bound [$($r:ident),*];
            )+
        }
    )+) => {
        /// A creator step of `SPEC/02-domain/programme-creator.md`. Step 11,
        /// the review, holds no field.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum Step {
            $( $(#[$sdoc])* $variant ),+
        }

        impl Step {
            /// Every step, in order.
            pub const ALL: &'static [Step] = &[$(Step::$variant),+];

            /// The step number, 1 to 10.
            pub const fn number(self) -> u8 {
                match self { $(Step::$variant => $n),+ }
            }

            /// The step's member name in the spec's JSON form.
            pub const fn name(self) -> &'static str {
                match self { $(Step::$variant => stringify!($step)),+ }
            }
        }

        /// One field of a programme spec. Policy fields are named after the
        /// parameter they set.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum FieldId {
            $($( #[doc = $fdoc] $id, )+)+
        }

        impl FieldId {
            /// Every field id, in table order.
            pub const ALL: &'static [FieldId] = &[$($(FieldId::$id,)+)+];

            /// The field's member name in its step object.
            pub const fn name(self) -> &'static str {
                match self { $($(FieldId::$id => stringify!($member),)+)+ }
            }

            /// The field's creator step.
            pub const fn step(self) -> Step {
                match self { $($(FieldId::$id => Step::$variant,)+)+ }
            }
        }

        /// The `FIELDS` table: one row per field, in step order.
        pub const FIELDS: &[FieldSpec] = &[$($(
            FieldSpec {
                id: FieldId::$id,
                step: Step::$variant,
                params: &[$(ParamId::$p),*],
                kind: FieldKind::$kind,
                importable: $imp,
                bound_by: &[$(RuleRef::$r),*],
            },
        )+)+];

        /// One decoded field value, tagged with its field.
        #[derive(Clone, Debug, PartialEq, Eq, Hash)]
        pub enum FieldValue {
            $($( #[doc = $fdoc] $id($ty), )+)+
        }

        impl FieldValue {
            /// The field this value belongs to.
            pub fn field(&self) -> FieldId {
                match self { $($(FieldValue::$id(_) => FieldId::$id,)+)+ }
            }

            /// Decodes `v` with the strict decoder of `field`.
            pub(crate) fn decode(field: FieldId, v: &Value, c: Currency) -> Result<FieldValue, FromJsonError> {
                match field {
                    $($(FieldId::$id => <$ty as Codec>::decode(v, c).map(FieldValue::$id),)+)+
                }
            }

            /// The JSON value of this value.
            pub(crate) fn to_json(&self) -> Value {
                match self { $($(FieldValue::$id(x) => x.encode(),)+)+ }
            }

            /// The value a gap in `field` compiles to.
            pub(crate) fn placeholder(field: FieldId, c: Currency) -> Option<FieldValue> {
                match field {
                    $($(FieldId::$id => <$ty as Codec>::placeholder(c).map(FieldValue::$id),)+)+
                }
            }
        }

        $(
            $(#[$sdoc])*
            #[derive(Clone, Debug, PartialEq, Eq, Hash)]
            pub struct $Step {
                $( #[doc = $fdoc] pub $member: Field<$ty>, )+
            }

            impl $Step {
                /// The step with every field unset.
                pub const fn unset() -> $Step {
                    $Step { $( $member: Field::Unset, )+ }
                }

                fn from_json(v: &Value, c: Currency) -> Result<$Step, FromJsonError> {
                    let o = object(v, &[$(stringify!($member)),+])?;
                    Ok($Step { $( $member: step_member(o, stringify!($member), c)?, )+ })
                }

                fn to_json(&self) -> Value {
                    crate::value::obj(vec![
                        $( (stringify!($member), field_json(&self.$member)), )+
                    ])
                }
            }
        )+

        /// One programme as the creator captures it. People are never part
        /// of it (I-73).
        #[derive(Clone, Debug, PartialEq, Eq, Hash)]
        pub struct ProgrammeSpec {
            /// The schema, `"fstp.programme/1"`.
            pub schema: SpecSchema,
            /// The programme currency (ADR-006). Every amount is in it.
            pub currency: Currency,
            $( $(#[$sdoc])* pub $step: $Step, )+
        }

        impl ProgrammeSpec {
            /// A spec in `currency` with every field unset.
            pub const fn empty(currency: Currency) -> ProgrammeSpec {
                ProgrammeSpec {
                    schema: SpecSchema::V1,
                    currency,
                    $( $step: $Step::unset(), )+
                }
            }

            /// The value of `field`, or the gap.
            pub fn get(&self, field: FieldId) -> Field<FieldValue> {
                match field {
                    $($(FieldId::$id => self.$step.$member.clone().map(FieldValue::$id),)+)+
                }
            }

            /// Sets the field that `value` belongs to.
            pub fn set(&mut self, value: FieldValue) {
                match value {
                    $($(FieldValue::$id(x) => self.$step.$member = Field::Set(x),)+)+
                }
            }

            /// Leaves `field` unset.
            pub fn unset(&mut self, field: FieldId) {
                match field {
                    $($(FieldId::$id => self.$step.$member = Field::Unset,)+)+
                }
            }

            /// The top-level member names of the JSON form.
            const MEMBERS: &'static [&'static str] = &["currency", "schema", $(stringify!($step)),+];

            fn from_json(v: &Value) -> Result<ProgrammeSpec, FromJsonError> {
                let o = object(v, ProgrammeSpec::MEMBERS)?;
                match o.get("schema") {
                    Some(Value::String(s)) if s == SpecSchema::V1.as_str() => {}
                    Some(_) => {
                        return Err(FromJsonError::invalid("unknown spec schema").at_field("schema"));
                    }
                    None => return Err(missing("schema")),
                }
                let currency = match o.get("currency") {
                    Some(Value::String(s)) => Currency::from_code(s)
                        .map_err(|_| FromJsonError::invalid("unknown currency").at_field("currency"))?,
                    Some(other) => {
                        return Err(FromJsonError::wrong_type("a currency code", other).at_field("currency"));
                    }
                    None => return Err(missing("currency")),
                };
                Ok(ProgrammeSpec {
                    schema: SpecSchema::V1,
                    currency,
                    $( $step: match o.get(stringify!($step)) {
                        Some(s) => $Step::from_json(s, currency).map_err(|e| e.at_field(stringify!($step)))?,
                        None => return Err(missing(stringify!($step))),
                    }, )+
                })
            }

            fn to_json(&self) -> Value {
                crate::value::obj(vec![
                    ("currency", Value::String(self.currency.code().to_owned())),
                    ("schema", Value::String(self.schema.as_str().to_owned())),
                    $( (stringify!($step), self.$step.to_json()), )+
                ])
            }
        }
    };
}

programme_fields! {
    /// Step 1, funder and instrument: P-53, P-56, P-57, P-58, P-41; the
    /// retention periods P-22 and P-46; P-43 (Q36); the action number,
    /// acronym and coordinator the Guide names.
    funder: FunderStep = Funder(1) {
        #[doc = "P-53: funder profile and version."]
        p53_funder_profile: P53(ProfileRef), Policy, [P53], importable false, bound [];
        #[doc = "The action number, such as the grant agreement number (Guide `{{action.number}}`). Interim, pending Daniel."]
        action_number: ActionNumber(ActionNumber), Artefact, [], importable true, bound [];
        #[doc = "The action acronym (Guide `{{action.acronym}}`). Interim, pending Daniel."]
        action_acronym: ActionAcronym(Narrative), Artefact, [], importable true, bound [];
        #[doc = "The name of the coordinator who runs the calls (Guide `{{coordinator.name}}`). Interim, pending Daniel."]
        coordinator_name: CoordinatorName(Narrative), Artefact, [], importable true, bound [];
        #[doc = "P-56: the action's FSTP budget."]
        p56_fstp_budget: P56(NonNegAmount), Policy, [P56], importable true, bound [];
        #[doc = "P-57: the action's start and end dates."]
        p57_action_dates: P57(ActionDates), Policy, [P57], importable true, bound [];
        #[doc = "P-58: the funder's per-recipient ceiling, which bounds P-05 (I-50)."]
        p58_recipient_ceiling: P58(NonNegAmount), Policy, [P58], importable true, bound [I50];
        #[doc = "P-41: the funder retention period after the final payment."]
        p41_funder_retention: P41(FunderRetention), Policy, [P41], importable true, bound [];
        #[doc = "P-22: trace retention."]
        p22_trace_retention: P22(TraceRetention), Policy, [P22], importable false, bound [];
        #[doc = "P-46: data retrieval period after a switch request."]
        p46_switch_retrieval_period: P46(Days), Policy, [P46], importable false, bound [];
        #[doc = "P-43: licence refresh grace period for self-hosted cells."]
        p43_licence_grace_period: P43(Days), Policy, [P43], importable false, bound [];
    }
    /// Step 2, programme identity: name, narrative, scope, P-25, public slug.
    identity: IdentityStep = Identity(2) {
        #[doc = "The programme name."]
        name: ProgrammeName(Narrative), Artefact, [], importable true, bound [];
        #[doc = "The programme narrative."]
        narrative: ProgrammeNarrative(Narrative), Artefact, [], importable true, bound [];
        #[doc = "The programme scope, which proposals must fit."]
        scope: ProgrammeScope(Narrative), Artefact, [], importable true, bound [];
        #[doc = "The public URL segment of the programme."]
        public_slug: PublicSlug(Slug), Artefact, [], importable false, bound [];
        #[doc = "P-25: programme language."]
        p25_language: P25(LanguageCode), Policy, [P25], importable true, bound [];
    }
    /// Step 3, eligibility: the persons supported, P-13, P-17, minors;
    /// verification P-18, P-19, P-45 (Q36).
    eligibility: EligibilityStep = Eligibility(3) {
        #[doc = "The persons and categories supported (I-48, Guide `{{eligibility.persons}}`). Interim, pending Daniel."]
        persons_supported: PersonsSupported(Narrative), Artefact, [], importable true, bound [];
        #[doc = "The programme's statement on minors and guardian consent (R-SB-02, I-18). Interim, pending Daniel."]
        minors: Minors(Narrative), Artefact, [], importable true, bound [];
        #[doc = "P-13: excluded affiliation classes."]
        p13_excluded_classes: P13(Keyed<ExclusionClass>), Policy, [P13], importable true, bound [I04, Sod06];
        #[doc = "P-17: tie-break priority."]
        p17_tie_break: P17(TieBreak), Policy, [P17], importable true, bound [];
        #[doc = "P-18: identity verification methods."]
        p18_verification_methods: P18(UniqueList<Token>), Policy, [P18], importable false, bound [];
        #[doc = "P-19: uploaded document retention after verification."]
        p19_document_retention: P19(Token), Policy, [P19], importable false, bound [];
        #[doc = "P-45: EUDI Wallet relying party mode."]
        p45_relying_party_mode: P45(RelyingPartyMode), Policy, [P45], importable false, bound [];
    }
    /// Step 4, what we fund: P-55, P-26.
    funding: WhatWeFundStep = WhatWeFund(4) {
        #[doc = "P-55: the closed list of eligible activity types."]
        p55_activity_types: P55(Keyed<ActivityType>), Policy, [P55], importable true, bound [];
        #[doc = "P-26: accepted licences for deliverables."]
        p26_licences: P26(SortedSet<Licence>), Policy, [P26], importable true, bound [];
    }
    /// Step 5, evaluation: P-01 to P-03, P-06 to P-11, P-14 to P-16, P-21,
    /// P-23, P-24, P-28, P-39, P-42, P-75, P-77.
    evaluation: EvaluationStep = Evaluation(5) {
        #[doc = "P-01: criteria, weights and score scale."]
        p01_criteria: P01(ScoringCriteria), Policy, [P01], importable true, bound [I08, Rev03];
        #[doc = "P-02: stage 1 pass threshold, strictly above."]
        p02_threshold: P02(Percent), Policy, [P02], importable true, bound [I08, Rev03];
        #[doc = "P-03: minimum assigned reviewers per proposal."]
        p03_reviewers: P03(ReviewerMinimum), Policy, [P03], importable true, bound [I07, Rev02];
        #[doc = "P-06: call cadence."]
        p06_cadence: P06(Token), Policy, [P06], importable true, bound [];
        #[doc = "P-07: stage 2 answer window."]
        p07_stage2_window: P07(Days), Policy, [P07], importable true, bound [Rev07];
        #[doc = "P-08: notification deadline for non-selected proposals."]
        p08_notification_deadline: P08(WorkingDays), Policy, [P08], importable true, bound [];
        #[doc = "P-09: knock-out criteria."]
        p09_knock_outs: P09(Keyed<KnockOut>), Policy, [P09], importable true, bound [Rev01];
        #[doc = "P-10: proposal read access in stages 1 and 2."]
        p10_read_access: P10(ReadAccess), Policy, [P10], importable true, bound [Rac01];
        #[doc = "P-11: reviewer anonymity towards applicants."]
        p11_anonymity: P11(ReviewerAnonymity), Policy, [P11], importable true, bound [Ran01];
        #[doc = "P-14: IRC exemptions for amendments."]
        p14_irc_exemptions: P14(IrcExemptions), Policy, [P14], importable true, bound [Rir04];
        #[doc = "P-15: minimum IRC members per proposal."]
        p15_irc_members: P15(NonZeroU8), Policy, [P15], importable true, bound [Rir01];
        #[doc = "P-16: committee voting rules."]
        p16_voting: P16(VotingRules), Policy, [P16], importable true, bound [Rev09];
        #[doc = "P-21: inference provider, pinned model and fallbacks."]
        p21_inference: P21(Inference), Policy, [P21], importable false, bound [I11, Rla05];
        #[doc = "P-23: pre-check enabled and its rate limits."]
        p23_precheck: P23(Precheck), Policy, [P23], importable true, bound [];
        #[doc = "P-24: effective score rule after stage 2."]
        p24_effective_score: P24(EffectiveScoreRule), Policy, [P24], importable true, bound [I09, Rev06];
        #[doc = "P-28: whether reviewers see indicative LLM rubric bands."]
        p28_rubric_bands: P28(bool), Policy, [P28], importable false, bound [];
        #[doc = "P-39: minimum distinct organisations among assigned reviewers."]
        p39_reviewer_organisations: P39(NonZeroU8), Policy, [P39], importable true, bound [I34, Sod10];
        #[doc = "P-42: whether calibration consent requests are enabled."]
        p42_calibration_consent: P42(bool), Policy, [P42], importable false, bound [];
        #[doc = "P-75: whether reviewers' agents may read full proposal content through MCP."]
        p75_agent_content_reads: P75(bool), Policy, [P75], importable false, bound [];
        #[doc = "P-77: binding actions through MCP."]
        p77_mcp_binding_actions: P77(McpBindingActions), Policy, [P77], importable false, bound [Rmc05];
    }
    /// Step 6, money: P-04, P-05, P-27, P-34, P-36, P-59, P-65 to P-67,
    /// the amount criteria.
    money: MoneyStep = Money(6) {
        #[doc = "The criteria for the exact amount (I-48, Guide `{{annexe.amount_criteria}}`). Interim, pending Daniel."]
        amount_criteria: AmountCriteria(Narrative), Artefact, [], importable true, bound [];
        #[doc = "P-04: grant range per proposal."]
        p04_grant_range: P04(AmountRange), Policy, [P04], importable true, bound [I13, Rng03];
        #[doc = "P-05: cap per recipient over the programme lifetime, bounded by P-58 (I-50)."]
        p05_recipient_cap: P05(NonNegAmount), Policy, [P05], importable true, bound [I50, I14, Rng03];
        #[doc = "P-27: whether the hardship contribution is enabled."]
        p27_hardship_contribution: P27(bool), Policy, [P27], importable true, bound [];
        #[doc = "P-34: payment request evidence requirements."]
        p34_payment_evidence: P34(UniqueList<Token>), Policy, [P34], importable true, bound [];
        #[doc = "P-36: payment hold after a bank detail change."]
        p36_bank_change_hold: P36(Days), Policy, [P36], importable false, bound [];
        #[doc = "P-59: target payment time after payment approval."]
        p59_payment_target: P59(Days), Policy, [P59], importable true, bound [];
        #[doc = "P-65: evidence for a partial claim on a milestone."]
        p65_partial_claim_evidence: P65(PartialClaimEvidence), Policy, [P65], importable true, bound [];
        #[doc = "P-66: reallocation between milestones of the same task."]
        p66_reallocation: P66(Reallocation), Policy, [P66], importable true, bound [];
        #[doc = "P-67: unclaimed milestone balances at grant end."]
        p67_unclaimed_balances: P67(UnclaimedBalances), Policy, [P67], importable true, bound [];
    }
    /// Step 7, contract: P-29, P-30, P-44, P-47 to P-49, and the flow-down
    /// obligations (I-49).
    contract: ContractStep = Contract(7) {
        #[doc = "P-29: contract instrument and template version."]
        p29_instrument: P29(ContractInstrument), Policy, [P29], importable true, bound [];
        #[doc = "P-30: signature level and cascade, in order."]
        p30_signature_cascade: P30(UniqueList<Token>), Policy, [P30], importable true, bound [];
        #[doc = "P-44: legal nature of payments."]
        p44_payment_nature: P44(Token), Policy, [P44], importable true, bound [];
        #[doc = "P-47: seal level for contractual notices."]
        p47_seal_level: P47(SealLevel), Policy, [P47], importable false, bound [];
        #[doc = "P-48: whether notice emails attach the sealed PDF."]
        p48_sealed_pdf: P48(bool), Policy, [P48], importable false, bound [];
        #[doc = "P-49: qualified trust service provider for remote signing."]
        p49_signing_provider: P49(Token), Policy, [P49], importable false, bound [];
        #[doc = "The flow-down obligations every contract passes on (I-49)."]
        flow_down: FlowDown(UniqueList<FlowDownObligation>), Artefact, [], importable false, bound [];
    }
    /// Step 8, support and complaints: P-60, P-61 to P-64.
    support: SupportStep = Support(8) {
        #[doc = "P-60: support programme offered to grantees."]
        p60_support_programme: P60(UniqueList<Token>), Policy, [P60], importable true, bound [];
        #[doc = "P-61: complaint window after a procedural decision is notified."]
        p61_complaint_window: P61(WorkingDays), Policy, [P61], importable true, bound [];
        #[doc = "P-62: coordinator response time to a complaint."]
        p62_coordinator_response: P62(WorkingDays), Policy, [P62], importable true, bound [];
        #[doc = "P-63: escalation window after the coordinator response."]
        p63_escalation_window: P63(WorkingDays), Policy, [P63], importable true, bound [];
        #[doc = "P-64: IRC response time to an escalated complaint."]
        p64_irc_response: P64(WorkingDays), Policy, [P64], importable true, bound [];
    }
    /// Step 9, people: P-12 only. People themselves are never part of the
    /// spec: invitations and grants are creator records (I-73).
    people: PeoplePolicyStep = People(9) {
        #[doc = "P-12: cooling-off between the Drafting, Judging and Receiving groups, in calls."]
        p12_cooling_off: P12(CoolingOff), Policy, [P12], importable false, bound [Sod05];
    }
    /// Step 10, communications: P-31 to P-33, P-35, P-37, P-38, P-40,
    /// P-50 to P-52, P-54, P-76, the message templates, the FAQ and the
    /// contact.
    comms: CommsStep = Comms(10) {
        #[doc = "The message templates, one per message kind. Interim, pending Daniel."]
        message_templates: MessageTemplates(MessageTemplates), Artefact, [], importable false, bound [];
        #[doc = "The frequently asked questions (Guide `{{programme.faq}}`). Interim, pending Daniel."]
        faq: Faq(Narrative), Artefact, [], importable true, bound [];
        #[doc = "The programme's contact channel (Guide `{{programme.contact}}`). Interim, pending Daniel."]
        contact: ProgrammeContact(Narrative), Artefact, [], importable false, bound [];
        #[doc = "P-31: reminder offsets."]
        p31_reminder_offsets: P31(ReminderOffsets), Policy, [P31], importable false, bound [];
        #[doc = "P-32: enabled channels and group types."]
        p32_channels: P32(Channels), Policy, [P32], importable false, bound [];
        #[doc = "P-33: overdue escalation."]
        p33_escalation: P33(Escalation), Policy, [P33], importable false, bound [];
        #[doc = "P-35: group membership removal delay."]
        p35_group_removal_delay: P35(Token), Policy, [P35], importable false, bound [];
        #[doc = "P-37: inbound group message handling."]
        p37_inbound_messages: P37(Token), Policy, [P37], importable false, bound [];
        #[doc = "P-38: proximity lists per partner organisation."]
        p38_proximity_lists: P38(ProximityLists), Policy, [P38], importable false, bound [I35, Sod11];
        #[doc = "P-40: working-day calendar."]
        p40_working_calendar: P40(WorkingCalendar), Policy, [P40], importable false, bound [];
        #[doc = "P-50: maximum public visibility of funded subgrants."]
        p50_funded_visibility: P50(Token), Policy, [P50], importable false, bound [];
        #[doc = "P-51: maximum public visibility of finished subgrants."]
        p51_finished_visibility: P51(Token), Policy, [P51], importable false, bound [];
        #[doc = "P-52: whether the machine-readable public feed is on."]
        p52_public_feed: P52(bool), Policy, [P52], importable false, bound [];
        #[doc = "P-54: minimum number of grants behind any public aggregate."]
        p54_aggregate_minimum: P54(NonZeroU16), Policy, [P54], importable false, bound [];
        #[doc = "P-76: listing in the platform-wide directory of open calls."]
        p76_directory_listing: P76(bool), Policy, [P76], importable false, bound [];
    }
}

impl FieldId {
    /// The row of this field in [`FIELDS`].
    pub fn spec(self) -> Option<&'static FieldSpec> {
        FIELDS.iter().find(|f| f.id == self)
    }

    /// The field that sets parameter `p`, if any. Tenant-level and fixed
    /// parameters have none.
    pub fn for_param(p: ParamId) -> Option<FieldId> {
        FIELDS.iter().find(|f| f.params.contains(&p)).map(|f| f.id)
    }

    /// The field's path in the spec's JSON form, `"<step>.<member>"`, such
    /// as `"funder.action_number"`. Unique per field.
    pub fn key(self) -> String {
        format!("{}.{}", self.step().name(), self.name())
    }

    /// The field whose [`FieldId::key`] is `key`, if any.
    pub fn from_key(key: &str) -> Option<FieldId> {
        let (step, member) = key.split_once('.')?;
        FieldId::ALL
            .iter()
            .copied()
            .find(|f| f.step().name() == step && f.name() == member)
    }
}

/// The canonical RFC 8785 text of `v`.
///
/// Every value this crate builds holds integers below 10^15 and no
/// fractions, which RFC 8785 writes unchanged, so the canonical form always
/// exists. The compact form is the same bytes for such a value once its
/// members are sorted, and serves only as a total fallback.
pub(crate) fn canonical(v: &Value) -> String {
    match fstp_json::to_canonical(v) {
        Ok(s) => s,
        Err(_) => fstp_json::to_compact(v),
    }
}

/// Decodes a spec from its JSON text. Unknown members are rejected at
/// every level, every member is required, and amounts decode only as
/// ADR-006 strings. Fuzzed (`spec_decode`).
pub fn decode_spec(bytes: &[u8]) -> Result<ProgrammeSpec, DecodeError> {
    let v = fstp_json::parse(bytes).map_err(DecodeError::Json)?;
    ProgrammeSpec::from_json(&v).map_err(DecodeError::Shape)
}

/// The canonical RFC 8785 text of `spec`, which [`decode_spec`] reads back
/// to the same spec.
pub fn encode_spec(spec: &ProgrammeSpec) -> String {
    canonical(&spec.to_json())
}

/// Decodes one EUR field value with the strict decoder of `field`. A gap
/// (`null`) is refused: a field value is always a value. Fuzzed
/// (`field_value_decode`).
pub fn decode_field_value(field: FieldId, bytes: &[u8]) -> Result<FieldValue, DecodeError> {
    decode_field_value_in(field, Currency::Eur, bytes)
}

/// Decodes one field value with amounts in `currency`.
pub fn decode_field_value_in(
    field: FieldId,
    currency: Currency,
    bytes: &[u8],
) -> Result<FieldValue, DecodeError> {
    let v = fstp_json::parse(bytes).map_err(DecodeError::Json)?;
    FieldValue::decode(field, &v, currency).map_err(DecodeError::Shape)
}

/// The canonical RFC 8785 text of `value`, which [`decode_field_value`]
/// reads back to the same value.
pub fn encode_field_value(value: &FieldValue) -> String {
    canonical(&value.to_json())
}
