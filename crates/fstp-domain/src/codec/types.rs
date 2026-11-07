//! Wire forms of the domain vocabulary (design sections 2.1 to 2.3).
//!
//! - Ids, `Seq`, vault epochs and timestamps are canonical decimal strings,
//!   because RFC 8785 numbers are exact only up to 2^53.
//! - Digests and handles are lowercase hexadecimal strings.
//! - Amounts and percentages are ADR-006 decimal strings. Amounts decode
//!   with the currency of the enclosing value. A negative signed amount is
//!   an object holding a positive `shortfall`, so no amount has a sign.
//! - Counts below 2^32 are JSON integers.
//! - Fieldless enums are their variant names. Enums with data are objects
//!   with a `type` member.

use std::num::{NonZeroU8, NonZeroU16, NonZeroU32, NonZeroU64};

use fstp_json::{FromJsonError, Object, ToJson, Value};
use fstp_ledger::Seq;
use fstp_money::{
    Amount, AmountRange, Currency, NonNegAmount, Percent, PosAmount, Ratio, amount_from_json,
    nonneg_amount_from_json, percent_from_json, pos_amount_from_json,
};

use super::wire::{
    Cx, Key, R, Wire, fields, flat_struct, newtype_wire, put_decimal, put_hex, str_of, tagged_enum,
    take_hex, take_i64, take_u64, take_u128, unit_enum,
};
use crate::amendment::AmendmentRoute;
use crate::assignment::{AssignmentKind, ReleaseCause};
use crate::command::{Actor, ContractEvent, DeclarationSubject, KnockOutResult, SystemCause};
use crate::decision::{Ballot, Basis, IrcVerdict, NegotiationFailure, Vote};
use crate::grant::IneligibleCost;
use crate::id::{
    AccountId, ActivityTypeId, AmendmentId, AssignmentId, BindingId, CallId, CallSeq, ClassId,
    ContentDigest, ContractId, CriterionId, DecisionId, DeliverableId, Handle, HardshipEvidenceId,
    KnockOutCriterionId, LineId, LlmConfigId, MilestoneId, OrganisationId, PlanVersionId,
    PolicyVersionId, ProgrammeId, ProposalId, ProximityListId, RequestId, RoleInvitationId, TextId, TextRef,
    VaultEpoch,
};
use crate::oracle::QueryKind;
use crate::payment::{CheckKind, CheckPhase, CheckResult, LineEvidence, PaymentKind, PaymentLine};
use crate::policy::activation::ReportDigest;
use crate::policy::{
    AgentContentAccess, EffectiveScoreRule, ExclusionClasses, FunderProfileRef, InferenceBinding,
    IrcExemptions, KnockOutCriteria, KnockOutCriterion, LicenceSet, McpBindingActions, ModelRef,
    OpaqueValue, ParamId, ProximityLists, ReadAccess, ReviewerAnonymity, SpdxId, TieBreakRule,
    VotingRules,
};
use crate::proposal::{
    EthicsDeclaration, Milestone, NoticeVersion, PlanOrigin, ReentryStage, Task,
};
use crate::record::{Declared, OutboxEvent, RulesVersion};
use crate::refusal::RuleRef;
use crate::roles::{BindingScope, CoolingOff, Role};
use crate::rules::{Row, StateTag};
use crate::scoring::{Criteria, Criterion, ScoreKey, ScoreVector, Stage, VoidCause};
use crate::time::{Days, Timestamp, ZoneName};

// ---------------------------------------------------------------------------
// Ids and other wide integers
// ---------------------------------------------------------------------------

macro_rules! id_wire {
    ($($t:ident),* $(,)?) => { $(
        impl Wire for $t {
            fn put(&self) -> Value {
                put_decimal(self.raw())
            }

            fn take(v: &Value, _cx: Cx) -> R<Self> {
                take_u128(v).map($t::from_raw)
            }
        }
    )* };
}

id_wire!(
    ProgrammeId,
    CallId,
    PolicyVersionId,
    AccountId,
    BindingId,
    ProposalId,
    PlanVersionId,
    MilestoneId,
    DeliverableId,
    AssignmentId,
    DecisionId,
    AmendmentId,
    RequestId,
    LineId,
    OrganisationId,
    LlmConfigId,
    TextId,
    CriterionId,
    KnockOutCriterionId,
    ClassId,
    ProximityListId,
    ActivityTypeId,
    ContractId,
    HardshipEvidenceId,
    RoleInvitationId,
);

/// Organisation ids key the P-38 map by their decimal string.
impl Key for OrganisationId {
    fn key(&self) -> String {
        self.raw().to_string()
    }

    fn from_key(s: &str) -> R<Self> {
        take_u128(&Value::String(s.to_owned()))
            .map(OrganisationId::from_raw)
            .map_err(|_| FromJsonError::invalid("map key is not a canonical decimal id"))
    }
}

impl Wire for Seq {
    fn put(&self) -> Value {
        put_decimal(self.raw())
    }

    fn take(v: &Value, _cx: Cx) -> R<Self> {
        take_u64(v).map(Seq::from_raw)
    }
}

impl Wire for VaultEpoch {
    fn put(&self) -> Value {
        put_decimal(self.raw())
    }

    fn take(v: &Value, _cx: Cx) -> R<Self> {
        take_u64(v).map(VaultEpoch::from_raw)
    }
}

/// Microseconds since the Unix epoch, as a decimal string, so every `i64`
/// instant has an exact RFC 8785 form.
impl Wire for Timestamp {
    fn put(&self) -> Value {
        put_decimal(self.micros())
    }

    fn take(v: &Value, _cx: Cx) -> R<Self> {
        take_i64(v).map(Timestamp::from_micros)
    }
}

impl Wire for ContentDigest {
    fn put(&self) -> Value {
        put_hex(&self.bytes())
    }

    fn take(v: &Value, _cx: Cx) -> R<Self> {
        take_hex::<32>(v).map(ContentDigest::from_bytes)
    }
}

/// The digest of a validation report (M4 change D2), as lowercase hexadecimal.
impl Wire for ReportDigest {
    fn put(&self) -> Value {
        put_hex(&self.bytes())
    }

    fn take(v: &Value, _cx: Cx) -> R<Self> {
        take_hex::<32>(v).map(ReportDigest::from_bytes)
    }
}

impl Wire for Handle {
    fn put(&self) -> Value {
        put_hex(&self.bytes())
    }

    fn take(v: &Value, _cx: Cx) -> R<Self> {
        take_hex::<16>(v).map(Handle::from_bytes)
    }
}

/// A free-text reference: the text id and its content digest (ADR-007).
/// The text itself never appears in a body.
impl Wire for TextRef {
    fn put(&self) -> Value {
        let mut o = Object::new();
        let _ = o.insert("id", self.id().put());
        let _ = o.insert("digest", self.digest().put());
        Value::Object(o)
    }

    fn take(v: &Value, cx: Cx) -> R<Self> {
        let f = fields(v, &[&["id", "digest"]])?;
        Ok(TextRef::new(f.get("id", cx)?, f.get("digest", cx)?))
    }
}

// ---------------------------------------------------------------------------
// Small numbers, time and text
// ---------------------------------------------------------------------------

fn zero() -> FromJsonError {
    FromJsonError::invalid("zero where a positive integer is needed")
}

impl Wire for NonZeroU8 {
    fn put(&self) -> Value {
        self.get().put()
    }

    fn take(v: &Value, cx: Cx) -> R<Self> {
        NonZeroU8::new(u8::take(v, cx)?).ok_or_else(zero)
    }
}

impl Wire for NonZeroU16 {
    fn put(&self) -> Value {
        self.get().put()
    }

    fn take(v: &Value, cx: Cx) -> R<Self> {
        NonZeroU16::new(u16::take(v, cx)?).ok_or_else(zero)
    }
}

impl Wire for CallSeq {
    fn put(&self) -> Value {
        self.get().put()
    }

    fn take(v: &Value, cx: Cx) -> R<Self> {
        NonZeroU32::new(u32::take(v, cx)?)
            .map(CallSeq::new)
            .ok_or_else(zero)
    }
}

impl Wire for Days {
    fn put(&self) -> Value {
        self.get().put()
    }

    fn take(v: &Value, cx: Cx) -> R<Self> {
        u16::take(v, cx).map(Days::new)
    }
}

impl Wire for ZoneName {
    fn put(&self) -> Value {
        Value::String(self.as_str().to_owned())
    }

    fn take(v: &Value, _cx: Cx) -> R<Self> {
        let s = str_of(v, "a zone name string")?;
        ZoneName::new(s).ok_or_else(|| FromJsonError::invalid("not a valid zone name"))
    }
}

/// An opaque parameter value, as a string holding its RFC 8785 text. The
/// string must hold canonical text, so the value has one spelling. As a
/// string, the value never adds objects to the schema's own objects.
impl Wire for OpaqueValue {
    fn put(&self) -> Value {
        Value::String(self.as_str().to_owned())
    }

    fn take(v: &Value, _cx: Cx) -> R<Self> {
        let s = str_of(v, "a string of canonical JSON text")?;
        let parsed = fstp_json::parse(s.as_bytes())
            .map_err(|_| FromJsonError::invalid("opaque value is not JSON text"))?;
        let canonical = OpaqueValue::from_value(&parsed)
            .map_err(|_| FromJsonError::invalid("opaque value has no RFC 8785 form"))?;
        if canonical.as_str() != s {
            return Err(FromJsonError::invalid(
                "opaque value is not in RFC 8785 canonical form",
            ));
        }
        Ok(canonical)
    }
}

newtype_wire!(
    NoticeVersion,
    CoolingOff,
    RulesVersion,
    ScoreVector,
    SpdxId,
    ModelRef,
    KnockOutCriteria,
    LicenceSet,
    ExclusionClasses,
    ProximityLists,
    IrcExemptions,
    VotingRules,
    TieBreakRule,
    FunderProfileRef,
);

// ---------------------------------------------------------------------------
// Money and exact numbers (ADR-006)
// ---------------------------------------------------------------------------

impl Wire for Currency {
    fn put(&self) -> Value {
        Value::String(self.code().to_owned())
    }

    fn take(v: &Value, _cx: Cx) -> R<Self> {
        let s = str_of(v, "a currency code string")?;
        Currency::from_code(s).map_err(|_| FromJsonError::invalid("unknown currency code"))
    }
}

/// The member that holds the size of a negative signed amount.
const SHORTFALL: &str = "shortfall";

/// A signed amount, such as the remaining budget of an over-nominated call
/// (design section 3.7). ADR-006 amount strings never carry a sign, so the
/// sign is structural:
///
/// - zero or more is the plain ADR-006 string, such as `"1.00"`;
/// - below zero is `{"shortfall": "1.00"}`, holding a positive amount.
///
/// A signed string such as `"-1.00"` is refused, and a zero shortfall is
/// refused, so every value has one spelling.
impl Wire for Amount {
    fn put(&self) -> Value {
        if self.minor() >= 0 {
            return self.to_json();
        }
        let mut o = Object::new();
        let _ = o.insert(SHORTFALL, self.neg().to_json());
        Value::Object(o)
    }

    fn take(v: &Value, cx: Cx) -> R<Self> {
        let c = cx.currency()?;
        if v.as_object().is_none() {
            return amount_from_json(v, c);
        }
        let f = fields(v, &[&[SHORTFALL]])?;
        let size =
            pos_amount_from_json(f.value(SHORTFALL)?, c).map_err(|e| e.at_field(SHORTFALL))?;
        Ok(size.amount().neg())
    }

    fn currency(&self) -> Option<Currency> {
        Some(Amount::currency(*self))
    }
}

impl Wire for NonNegAmount {
    fn put(&self) -> Value {
        self.to_json()
    }

    fn take(v: &Value, cx: Cx) -> R<Self> {
        nonneg_amount_from_json(v, cx.currency()?)
    }

    fn currency(&self) -> Option<Currency> {
        Some(self.amount().currency())
    }
}

impl Wire for PosAmount {
    fn put(&self) -> Value {
        self.to_json()
    }

    fn take(v: &Value, cx: Cx) -> R<Self> {
        pos_amount_from_json(v, cx.currency()?)
    }

    fn currency(&self) -> Option<Currency> {
        Some(self.amount().currency())
    }
}

/// An inclusive amount range, min at most max.
impl Wire for AmountRange {
    fn put(&self) -> Value {
        let mut o = Object::new();
        let _ = o.insert("min", self.min().put());
        let _ = o.insert("max", self.max().put());
        Value::Object(o)
    }

    fn take(v: &Value, cx: Cx) -> R<Self> {
        let f = fields(v, &[&["min", "max"]])?;
        AmountRange::new(f.get("min", cx)?, f.get("max", cx)?).map_err(|_| {
            FromJsonError::invalid("amount range with min above max or mixed currencies")
        })
    }

    fn currency(&self) -> Option<Currency> {
        Some(self.min().amount().currency())
    }
}

impl Wire for Percent {
    fn put(&self) -> Value {
        self.to_json()
    }

    fn take(v: &Value, _cx: Cx) -> R<Self> {
        percent_from_json(v)
    }
}

/// An exact ratio in lowest terms, numerator and denominator as decimal
/// strings. A ratio not in lowest terms is refused, so it has one spelling.
impl Wire for Ratio {
    fn put(&self) -> Value {
        let mut o = Object::new();
        let _ = o.insert("num", put_decimal(self.num()));
        let _ = o.insert("den", put_decimal(self.den()));
        Value::Object(o)
    }

    fn take(v: &Value, _cx: Cx) -> R<Self> {
        let f = fields(v, &[&["num", "den"]])?;
        let num = take_u64(f.value("num")?).map_err(|e| e.at_field("num"))?;
        let den = take_u64(f.value("den")?).map_err(|e| e.at_field("den"))?;
        let den = NonZeroU64::new(den).ok_or_else(|| zero().at_field("den"))?;
        let r = Ratio::new(num, den);
        if r.num() != num || r.den() != den {
            return Err(FromJsonError::invalid("ratio not in lowest terms"));
        }
        Ok(r)
    }
}

// ---------------------------------------------------------------------------
// Closed vocabularies
// ---------------------------------------------------------------------------

unit_enum!(SystemCause {
    Timeline,
    Vault,
    ContractPort,
    PaymentPort,
});
unit_enum!(ContractEvent { Effective });
unit_enum!(CheckPhase {
    Submission,
    Acceptance
});
unit_enum!(CheckKind {
    PublicLocation,
    Licence,
    Balance,
    Evidence
});
unit_enum!(Vote {
    For,
    Against,
    Abstain
});
unit_enum!(NegotiationFailure {
    IdentityNotVerified,
    Sod09Refused,
    ReceivingVoidedUnderI04,
    ReceivingVoidedUnderI06,
    NoAmountWithinRange,
    NoAmountWithinCap,
    RepeatRecordIncomplete,
    GuardianConsentMissing,
});
unit_enum!(Basis { Original, Revised });
unit_enum!(ReadAccess {
    AssignedReviewersOnly,
    AllCommitteeMembers,
    OperatorStaffOnly,
});
unit_enum!(ReviewerAnonymity { Anonymous, Named });
unit_enum!(EffectiveScoreRule {
    HigherOfOriginalAndRevised
});
unit_enum!(McpBindingActions { DraftOnly, Allowed });
unit_enum!(AgentContentAccess { Off, On });
unit_enum!(Role {
    ProgrammeManager,
    CallDrafter,
    FstpCoordinator,
    CommitteeMember,
    CommitteeChair,
    IrcMember,
    Applicant,
    ApplicantTeamMember,
    Guardian,
    TenantAdmin,
    FinanceApprover,
    PaymentReleaser,
    ContractSignatory,
    FinancialSignatory,
    LegalSignatory,
    Auditor,
});
unit_enum!(Stage { One, Two });
unit_enum!(VoidCause {
    AssignmentReleased,
    Conflict,
    ComplaintRemedy,
});
unit_enum!(PlanOrigin {
    Submitted,
    Stage2Revision,
    Negotiated,
    Amendment,
});
unit_enum!(ReentryStage { Stage2, IrcReview });
unit_enum!(AmendmentRoute { Exempt, Irc });
unit_enum!(ReleaseCause {
    DeclaredConflict,
    DetectedConflict,
    Unassigned,
    BindingEnded,
    BindingSuspended,
    BindingVoided,
});
unit_enum!(QueryKind {
    IsVerified,
    SameIdentityAsAny,
    HasConflict,
    InExcludedClass,
    WithinRecipientCap,
    AllRecipientsWithinCap,
    HasGuardianConsent,
    IsVerifiedAdultAtDeadline,
    DeclaresAffiliationOnList,
    MeetsTieBreakCountry,
    ChangedSince,
    BankReleasable,
    HardshipEvidenceVerified,
});
unit_enum!(Row {
    DraftToSubmitted,
    SubmittedToIneligible,
    SubmittedToStage1,
    Stage1ToNotSelected,
    Stage1ToStage2,
    Stage2ToRanked,
    Stage2ToDeferred,
    RankedToNotSelected,
    RankedToIrcReview,
    IrcReviewToNegotiation,
    IrcReviewToDeferred,
    IrcReviewToDeclined,
    DeferredToStage2,
    DeferredToIrcReview,
    NegotiationToGranted,
    NegotiationToDeclined,
    Withdraw,
    GrantedToInExecution,
    GrantedToTerminated,
    InExecutionToCompleted,
    InExecutionToTerminated,
});

// ---------------------------------------------------------------------------
// Variant tables for the enums named by spec ids
// ---------------------------------------------------------------------------
//
// The checks below are constants, so they loop over slice patterns. Deep
// recursion would pass the compile-time stack limit, and indexing or
// counters would need arithmetic that the crate lints refuse.

/// Whether two strings are equal, usable in a constant.
const fn str_eq(a: &str, b: &str) -> bool {
    let (mut a, mut b) = (a.as_bytes(), b.as_bytes());
    loop {
        match (a, b) {
            ([], []) => return true,
            ([x, xs @ ..], [y, ys @ ..]) if *x == *y => (a, b) = (xs, ys),
            _ => return false,
        }
    }
}

/// Builds `$arr`, the table the decoder of `$t` searches.
///
/// The same variant list feeds the table and an exhaustive match with no
/// wildcard. A variant of `$t` left out of the list fails to compile.
/// `others` covers variants with data, which the table leaves out.
///
/// The table has the length of the domain array `$all`. Constant
/// assertions check that the names, by `$named`, are non-empty and
/// distinct in both. So the table holds every listed variant once, the
/// names decode back to one variant each, and `$all` holds every listed
/// variant too.
macro_rules! every {
    (
        $(#[$doc:meta])*
        $arr:ident: [$t:ident; $all:expr] by $named:path {
            $($v:ident),* $(,)?
        }
        $(others { $($p:pat),* })?
    ) => {
        $(#[$doc])*
        const $arr: [$t; $all.len()] = [$($t::$v),*];

        const _: () = {
            /// Holds the exhaustive match over the list.
            const fn listed(mut xs: &[$t]) -> bool {
                while let [x, rest @ ..] = xs {
                    match *x {
                        $( $t::$v => {} )*
                        $( $( $p => {} )* )?
                    }
                    xs = rest;
                }
                true
            }
            /// Whether the names of `xs` are non-empty and distinct.
            const fn distinct(mut xs: &[$t]) -> bool {
                while let [x, rest @ ..] = xs {
                    let name = $named(*x);
                    if name.is_empty() {
                        return false;
                    }
                    let mut ys = rest;
                    while let [y, more @ ..] = ys {
                        if str_eq(name, $named(*y)) {
                            return false;
                        }
                        ys = more;
                    }
                    xs = rest;
                }
                true
            }
            assert!(listed(&$arr) && distinct(&$arr), concat!(stringify!($arr), " has a bad name"));
            assert!(distinct(&$all), concat!(stringify!($all), " has a bad name"));
        };
    };
}

every! {
    /// Every proposal state.
    STATES: [StateTag; StateTag::ALL] by StateTag::spec_name {
        Draft, Submitted, Ineligible, Stage1, NotSelected, Stage2, Ranked, IrcReview,
        Deferred, Declined, Negotiation, Withdrawn, Granted, InExecution, Completed, Terminated,
    }
}

every! {
    /// Every parameter.
    PARAMS: [ParamId; ParamId::ALL] by ParamId::spec_id {
        P01, P02, P03, P04, P05, P06, P07, P08, P09, P10, P11, P12, P13, P14, P15, P16,
        P17, P18, P19, P20, P21, P22, P23, P24, P25, P26, P27, P28, P29, P30, P31, P32,
        P33, P34, P35, P36, P37, P38, P39, P40, P41, P42, P43, P44, P45, P46, P47, P48,
        P49, P50, P51, P52, P53, P54, P55, P56, P57, P58, P59, P60, P61, P62, P63, P64,
        P65, P66, P67, P68, P69, P70, P71, P72, P73, P74, P75, P76, P77, P78,
    }
}

every! {
    /// Every rule except `Param`, whose rules are `PARAMS`.
    FIXED_RULES: [RuleRef; RuleRef::ALL_FIXED] by rule_name {
        I01, I02, I03, I04, I05, I06, I07, I08, I09, I10, I11, I12, I13, I14, I15, I18,
        I23, I31, I32, I33, I34, I35, I36, I50, I52, I64, I65, I66, I67, I78, I84, I85,
        Sod01, Sod02, Sod03, Sod04, Sod05, Sod06, Sod07, Sod09, Sod10, Sod11, Sod12,
        Rpc01, Rpc02, Rpc03, Rsb01, Rsb02, Rsb03, Rsb05,
        Rev01, Rev02, Rev03, Rev05, Rev06, Rev07, Rev08, Rev09, Rir01, Rir02, Rir04,
        Rng02, Rng03, Rng05, Rng06, Rcf02, Rcf04, Rac01, Ran01, Rla03, Rla05, Rex04, Rpr04, Rmc05,
        Row, Actor, FactsIncomplete, StaleFacts, OracleDown, Ledger, Input, NotImplemented,
    }
    others { RuleRef::Param(_) }
}

/// Whether no fixed rule shares a name with a `Param` rule.
const fn rule_names_disjoint() -> bool {
    let mut rs: &[RuleRef] = &FIXED_RULES;
    while let [r, rest @ ..] = rs {
        let mut ps: &[ParamId] = &PARAMS;
        while let [p, more @ ..] = ps {
            if str_eq(rule_name(*r), p.spec_id()) {
                return false;
            }
            ps = more;
        }
        rs = rest;
    }
    true
}

// With the assertions in `every!`, each rule name decodes to one rule.
const _: () = assert!(
    rule_names_disjoint(),
    "a fixed rule shares a name with a parameter"
);

/// A proposal state, by its spec name such as `"IRC_REVIEW"`.
impl Wire for StateTag {
    fn put(&self) -> Value {
        Value::String(self.spec_name().to_owned())
    }

    fn take(v: &Value, _cx: Cx) -> R<Self> {
        let s = str_of(v, "a state name")?;
        STATES
            .into_iter()
            .find(|t| t.spec_name() == s)
            .ok_or_else(|| FromJsonError::invalid("unknown state name"))
    }
}

fn param_of(s: &str) -> Option<ParamId> {
    PARAMS.into_iter().find(|p| p.spec_id() == s)
}

/// A parameter, by its spec id such as `"P-12"`.
impl Wire for ParamId {
    fn put(&self) -> Value {
        Value::String(self.spec_id().to_owned())
    }

    fn take(v: &Value, _cx: Cx) -> R<Self> {
        let s = str_of(v, "a parameter id")?;
        param_of(s).ok_or_else(|| FromJsonError::invalid("unknown parameter id"))
    }
}

/// Parameters key the opaque maps by their spec id.
impl Key for ParamId {
    fn key(&self) -> String {
        self.spec_id().to_owned()
    }

    fn from_key(s: &str) -> R<Self> {
        param_of(s).ok_or_else(|| FromJsonError::invalid("map key is not a parameter id"))
    }
}

/// The name of a rule: its spec id, such as `"SoD-09"` or `"P-12"`, or
/// the variant name of a rule that is not a spec identifier.
///
/// The match lists every variant with no wildcard, so a new variant fails
/// to compile until it gets a name here. A spec variant whose `spec_id` is
/// `None` gets the empty name. The `FIXED_RULES` assertions reject an
/// empty name at compile time.
const fn rule_name(r: RuleRef) -> &'static str {
    match r {
        RuleRef::Param(p) => p.spec_id(),
        RuleRef::Row => "Row",
        RuleRef::Actor => "Actor",
        RuleRef::FactsIncomplete => "FactsIncomplete",
        RuleRef::StaleFacts => "StaleFacts",
        RuleRef::OracleDown => "OracleDown",
        RuleRef::Ledger => "Ledger",
        RuleRef::Input => "Input",
        RuleRef::NotImplemented => "NotImplemented",
        RuleRef::I01
        | RuleRef::I02
        | RuleRef::I03
        | RuleRef::I04
        | RuleRef::I05
        | RuleRef::I06
        | RuleRef::I07
        | RuleRef::I08
        | RuleRef::I09
        | RuleRef::I10
        | RuleRef::I11
        | RuleRef::I12
        | RuleRef::I13
        | RuleRef::I14
        | RuleRef::I15
        | RuleRef::I18
        | RuleRef::I23
        | RuleRef::I31
        | RuleRef::I32
        | RuleRef::I33
        | RuleRef::I34
        | RuleRef::I35
        | RuleRef::I36
        | RuleRef::I50
        | RuleRef::I52
        | RuleRef::I64
        | RuleRef::I65
        | RuleRef::I66
        | RuleRef::I67
        | RuleRef::I78
        | RuleRef::I84
        | RuleRef::I85
        | RuleRef::Sod01
        | RuleRef::Sod02
        | RuleRef::Sod03
        | RuleRef::Sod04
        | RuleRef::Sod05
        | RuleRef::Sod06
        | RuleRef::Sod07
        | RuleRef::Sod09
        | RuleRef::Sod10
        | RuleRef::Sod11
        | RuleRef::Sod12
        | RuleRef::Rpc01
        | RuleRef::Rpc02
        | RuleRef::Rpc03
        | RuleRef::Rsb01
        | RuleRef::Rsb02
        | RuleRef::Rsb03
        | RuleRef::Rsb05
        | RuleRef::Rev01
        | RuleRef::Rev02
        | RuleRef::Rev03
        | RuleRef::Rev05
        | RuleRef::Rev06
        | RuleRef::Rev07
        | RuleRef::Rev08
        | RuleRef::Rev09
        | RuleRef::Rir01
        | RuleRef::Rir02
        | RuleRef::Rir04
        | RuleRef::Rng02
        | RuleRef::Rng03
        | RuleRef::Rng05
        | RuleRef::Rng06
        | RuleRef::Rcf02
        | RuleRef::Rcf04
        | RuleRef::Rac01
        | RuleRef::Ran01
        | RuleRef::Rla03
        | RuleRef::Rla05
        | RuleRef::Rex04
        | RuleRef::Rpr04
        | RuleRef::Rmc05 => match r.spec_id() {
            Some(s) => s,
            // Ruled out at compile time by the `FIXED_RULES` assertions.
            None => "",
        },
    }
}

/// A rule, by its name from `rule_name`. The decoder searches
/// `FIXED_RULES` and `PARAMS`, which the compile-time checks above prove
/// complete and free of repeated names.
impl Wire for RuleRef {
    fn put(&self) -> Value {
        Value::String(rule_name(*self).to_owned())
    }

    fn take(v: &Value, _cx: Cx) -> R<Self> {
        let s = str_of(v, "a rule name")?;
        FIXED_RULES
            .into_iter()
            .chain(PARAMS.into_iter().map(RuleRef::Param))
            .find(|r| rule_name(*r) == s)
            .ok_or_else(|| FromJsonError::invalid("unknown rule name"))
    }
}

// ---------------------------------------------------------------------------
// Enums with data
// ---------------------------------------------------------------------------

tagged_enum! {
    Actor;
    fields {}
    money {}
    tuple { Account(account), System(cause) }
    flat {}
    flat_money {}
}

tagged_enum! {
    AssignmentKind;
    fields { Reviewer {}, Irc {} }
    money {}
    tuple { Amendment(amendment) }
    flat {}
    flat_money {}
}

tagged_enum! {
    DeclarationSubject;
    fields {}
    money {}
    tuple { Assignment(assignment), Proposal(proposal) }
    flat {}
    flat_money {}
}

tagged_enum! {
    Declared;
    fields { Proposal { proposal, account } }
    money {}
    tuple { Assignment(assignment) }
    flat {}
    flat_money {}
}

tagged_enum! {
    PaymentKind;
    fields { Milestone {} }
    money {}
    tuple { Hardship(evidence) }
    flat {}
    flat_money {}
}

tagged_enum! {
    IrcVerdict;
    fields { Validate {} }
    money {}
    tuple { Concern(concern) }
    flat {}
    flat_money {}
}

tagged_enum! {
    BindingScope;
    fields { Programme {}, Proposal { proposal, call } }
    money {}
    tuple {}
    flat {}
    flat_money {}
}

tagged_enum! {
    OutboxEvent;
    fields {
        ProposalOutcome { proposal, state },
        IrcConcern { proposal, concern },
        NotifiableConflict { proposal },
        BindingEnded { binding },
    }
    money {}
    tuple {}
    flat {}
    flat_money {}
}

// ---------------------------------------------------------------------------
// Structs
// ---------------------------------------------------------------------------

flat_struct!(KnockOutResult { criterion, passed });
flat_struct!(Ballot {
    voter,
    vote,
    delegated_by
});
flat_struct!(ScoreKey {
    assignment,
    stage,
    plan
});
flat_struct!(Criterion { id, weight });
flat_struct!(EthicsDeclaration {
    issues_declared,
    text
});
flat_struct!(KnockOutCriterion { id, text });
flat_struct!(InferenceBinding {
    provider,
    primary,
    fallbacks
});
flat_struct!(IneligibleCost { amount, reason });
flat_struct!(PaymentLine {
    line,
    milestone,
    amount,
    evidence
});
flat_struct!(LineEvidence {
    location,
    release,
    licence,
    report
});
flat_struct!(CheckResult {
    line,
    check,
    failure
});
flat_struct!(Milestone {
    id,
    amount,
    start,
    due,
    activity,
    deliverables
});
flat_struct!(Task { milestones });

/// The P-01 criteria, rebuilt through the checked constructor.
impl Wire for Criteria {
    fn put(&self) -> Value {
        let mut o = Object::new();
        let _ = o.insert("scale_max", self.scale_max().put());
        let _ = o.insert("items", self.items().to_vec().put());
        Value::Object(o)
    }

    fn take(v: &Value, cx: Cx) -> R<Self> {
        let f = fields(v, &[&["scale_max", "items"]])?;
        Criteria::new(f.get("scale_max", cx)?, f.get("items", cx)?)
            .map_err(|_| FromJsonError::invalid("P-01 criteria outside the checked bounds"))
    }
}
