//! The check catalogue and report rows (M4 design section 3.2,
//! "Validation").

use fstp_domain::refusal::RuleRef;
use fstp_programme::FieldId;

use crate::ids::InvitationId;
use crate::probe::{ProbeKind, ProbeOutcome};
use crate::theme::{MandatoryElement, TextRole, ThemeMode};

/// The severity of a check.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// Blocks activation (I-66).
    Failure,
    /// Blocks activation until acknowledged at a live revision (I-66).
    Warning,
}

/// One check of the catalogue. The variant names are the design's check
/// names, and the order is the order of the design table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CheckId {
    /// `fstp_domain::policy::validate` refuses the draft policy.
    PolicyInvalid,
    /// I-50, R-PG-01 AC: P-05 above P-58.
    CapAboveCeiling,
    /// M2 `ValidationWarning`: the P-04 maximum above P-05.
    P04MaxAboveP05,
    /// M2 `ValidationWarning`: P-39 above P-03.
    P39AboveP03,
    /// A field with no value.
    FieldUnset,
    /// P-57: the action starts after it ends.
    ActionDatesInconsistent,
    /// I-48: the call package is incomplete.
    CallPackageIncomplete,
    /// I-52: a required Guide section is missing.
    GuideSectionMissing,
    /// I-51: a parameter-bound placeholder does not resolve.
    GuideBindingUnresolved,
    /// `guide-for-applicants.md` Rules: approved wording is pending. A
    /// failure under Q6, interim, pending Daniel.
    LegalWordingPending,
    /// I-49: a flow-down obligation is missing.
    FlowDownMissing,
    /// SoD-01 to SoD-13 across invited people.
    InviteeRefused,
    /// An invitation not yet accepted cannot be checked yet.
    InviteeWithoutAccount,
    /// SoD-07: fewer than two tenant admins.
    TooFewTenantAdmins,
    /// I-67 strict reading: a builder is unverified (Q2, interim, pending
    /// Daniel).
    BuilderUnverified,
    /// Too few invited committee or IRC members, no chair or no
    /// coordinator.
    RosterShort,
    /// P-13 class ids the vault does not know. An absent vault answer
    /// fails closed (Q35, interim, pending Daniel).
    ExclusionClassUnknown,
    /// P-38: a partner organisation without a declared list. An absent
    /// vault answer reports the warning (Q35, interim, pending Daniel).
    ProximityListMissing,
    /// P-23 enabled while no pre-check provider exists. A failure under
    /// Q38, interim, pending Daniel.
    PrecheckUnavailable,
    /// `ai-act.md` reassessment trigger: P-77 allowed while score tools
    /// exist.
    AiActReassessment,
    /// An enabled channel of P-32 is unreachable. An absent prober reports
    /// it (Q5, interim, pending Daniel).
    ChannelUnreachable,
    /// SPF, DKIM or DMARC of the sending domain fails. An absent prober
    /// reports it (Q5, interim, pending Daniel).
    SendingDomainUnverified,
    /// P-21 inference is unreachable (R-NF-10).
    InferenceUnreachable,
    /// I-69: a mandatory element is missing.
    MandatoryElementMissing,
    /// I-70: a text colour pair fails contrast.
    ContrastFailure,
    /// An import proposal neither confirmed, edited nor dismissed. A
    /// failure under Q30, interim, pending Daniel.
    ImportUnresolved,
}

impl CheckId {
    /// Every check, in catalogue order.
    pub const ALL: [CheckId; 26] = [
        CheckId::PolicyInvalid,
        CheckId::CapAboveCeiling,
        CheckId::P04MaxAboveP05,
        CheckId::P39AboveP03,
        CheckId::FieldUnset,
        CheckId::ActionDatesInconsistent,
        CheckId::CallPackageIncomplete,
        CheckId::GuideSectionMissing,
        CheckId::GuideBindingUnresolved,
        CheckId::LegalWordingPending,
        CheckId::FlowDownMissing,
        CheckId::InviteeRefused,
        CheckId::InviteeWithoutAccount,
        CheckId::TooFewTenantAdmins,
        CheckId::BuilderUnverified,
        CheckId::RosterShort,
        CheckId::ExclusionClassUnknown,
        CheckId::ProximityListMissing,
        CheckId::PrecheckUnavailable,
        CheckId::AiActReassessment,
        CheckId::ChannelUnreachable,
        CheckId::SendingDomainUnverified,
        CheckId::InferenceUnreachable,
        CheckId::MandatoryElementMissing,
        CheckId::ContrastFailure,
        CheckId::ImportUnresolved,
    ];

    /// The design's name of the check.
    pub const fn name(self) -> &'static str {
        match self {
            CheckId::PolicyInvalid => "PolicyInvalid",
            CheckId::CapAboveCeiling => "CapAboveCeiling",
            CheckId::P04MaxAboveP05 => "P04MaxAboveP05",
            CheckId::P39AboveP03 => "P39AboveP03",
            CheckId::FieldUnset => "FieldUnset",
            CheckId::ActionDatesInconsistent => "ActionDatesInconsistent",
            CheckId::CallPackageIncomplete => "CallPackageIncomplete",
            CheckId::GuideSectionMissing => "GuideSectionMissing",
            CheckId::GuideBindingUnresolved => "GuideBindingUnresolved",
            CheckId::LegalWordingPending => "LegalWordingPending",
            CheckId::FlowDownMissing => "FlowDownMissing",
            CheckId::InviteeRefused => "InviteeRefused",
            CheckId::InviteeWithoutAccount => "InviteeWithoutAccount",
            CheckId::TooFewTenantAdmins => "TooFewTenantAdmins",
            CheckId::BuilderUnverified => "BuilderUnverified",
            CheckId::RosterShort => "RosterShort",
            CheckId::ExclusionClassUnknown => "ExclusionClassUnknown",
            CheckId::ProximityListMissing => "ProximityListMissing",
            CheckId::PrecheckUnavailable => "PrecheckUnavailable",
            CheckId::AiActReassessment => "AiActReassessment",
            CheckId::ChannelUnreachable => "ChannelUnreachable",
            CheckId::SendingDomainUnverified => "SendingDomainUnverified",
            CheckId::InferenceUnreachable => "InferenceUnreachable",
            CheckId::MandatoryElementMissing => "MandatoryElementMissing",
            CheckId::ContrastFailure => "ContrastFailure",
            CheckId::ImportUnresolved => "ImportUnresolved",
        }
    }

    /// The check with the design's name `name`.
    pub fn from_name(name: &str) -> Option<CheckId> {
        CheckId::ALL.into_iter().find(|c| c.name() == name)
    }

    /// The severity the catalogue gives the check.
    pub const fn severity(self) -> Severity {
        match self {
            CheckId::P04MaxAboveP05
            | CheckId::P39AboveP03
            | CheckId::InviteeWithoutAccount
            | CheckId::RosterShort
            | CheckId::ProximityListMissing
            // Q38 C (Daniel, 2026-11-06): a missing pre-check provider
            // needs an acknowledgement and never blocks on its own.
            | CheckId::PrecheckUnavailable
            | CheckId::AiActReassessment
            | CheckId::InferenceUnreachable => Severity::Warning,
            CheckId::PolicyInvalid
            | CheckId::CapAboveCeiling
            | CheckId::FieldUnset
            | CheckId::ActionDatesInconsistent
            | CheckId::CallPackageIncomplete
            | CheckId::GuideSectionMissing
            | CheckId::GuideBindingUnresolved
            | CheckId::LegalWordingPending
            | CheckId::FlowDownMissing
            | CheckId::InviteeRefused
            | CheckId::TooFewTenantAdmins
            | CheckId::BuilderUnverified
            | CheckId::ExclusionClassUnknown
            | CheckId::ChannelUnreachable
            | CheckId::SendingDomainUnverified
            | CheckId::MandatoryElementMissing
            | CheckId::ContrastFailure
            | CheckId::ImportUnresolved => Severity::Failure,
        }
    }

    /// The position of the check in the catalogue.
    pub(crate) fn position(self) -> usize {
        CheckId::ALL
            .iter()
            .position(|c| *c == self)
            .unwrap_or(CheckId::ALL.len())
    }
}

/// One row of the check catalogue, with its source.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CheckSpec {
    /// The check.
    pub id: CheckId,
    /// Its severity.
    pub severity: Severity,
    /// The rule or requirement the check comes from.
    pub source: &'static str,
    /// How M4 decides it.
    pub implementation: &'static str,
}

const fn row(id: CheckId, source: &'static str, implementation: &'static str) -> CheckSpec {
    CheckSpec {
        id,
        severity: id.severity(),
        source,
        implementation,
    }
}

/// The check catalogue of design section 3.2, in the order of its table.
pub const CHECKS: &[CheckSpec] = &[
    row(
        CheckId::PolicyInvalid,
        "fstp_domain::policy::validate refusal",
        "Reuses M2 over the draft policy",
    ),
    row(
        CheckId::CapAboveCeiling,
        "I-50, R-PG-01 AC; the detail names P-05 and P-58 as ADR-006 strings",
        "Pure over the draft policy and the profile ceiling",
    ),
    row(CheckId::P04MaxAboveP05, "M2 ValidationWarning", "Reuses M2"),
    row(CheckId::P39AboveP03, "M2 ValidationWarning", "Reuses M2"),
    row(
        CheckId::FieldUnset,
        "A field with no value",
        "Pure over Compiled::unset; fails closed until fstp-programme lands (W1a)",
    ),
    row(
        CheckId::ActionDatesInconsistent,
        "P-57 start after end",
        "Pure over the draft spec; fails closed until fstp-programme lands (W1a)",
    ),
    row(
        CheckId::CallPackageIncomplete,
        "I-48: maximum per recipient, exact amount criteria, closed activity list, persons supported, award criteria and procedure",
        "Pure over the draft spec; fails closed until fstp-programme lands (W1a)",
    ),
    row(
        CheckId::GuideSectionMissing,
        "I-52: every required section of guide-for-applicants.md",
        "fstp_guide preview; fails closed until fstp-guide lands (W2c)",
    ),
    row(
        CheckId::GuideBindingUnresolved,
        "I-51: every parameter-bound placeholder resolves from the draft policy",
        "fstp_guide preview; fails closed until fstp-guide lands (W2c)",
    ),
    row(
        CheckId::LegalWordingPending,
        "guide-for-applicants.md Rules: statements on grant agreement obligations use approved wording (Q6, interim, pending Daniel)",
        "Pure over the profile's wording status; fails closed until fstp-guide lands (W2c)",
    ),
    row(
        CheckId::FlowDownMissing,
        "I-49: the obligations of contracts.md under the Horizon Europe profile",
        "Pure over the flow-down set; fails closed until fstp-programme lands (W1a)",
    ),
    row(
        CheckId::InviteeRefused,
        "SoD-01 to SoD-13 across invited people",
        "preview_grant per invitation with an account, from CreatorInputs::sod",
    ),
    row(
        CheckId::InviteeWithoutAccount,
        "An invitation not yet accepted cannot be checked yet; the grant checks again",
        "Pure",
    ),
    row(
        CheckId::TooFewTenantAdmins,
        "SoD-07, the onboarding rule of at least two tenant admins",
        "The tenant admin set from CreatorInputs",
    ),
    row(
        CheckId::BuilderUnverified,
        "I-67 strict reading: the Sybil check needs every builder verified (Q2, interim, pending Daniel)",
        "IsVerified per builder, from CreatorInputs::vault",
    ),
    row(
        CheckId::RosterShort,
        "Fewer invited committee members than P-03 or P-39 organisations, fewer IRC members than P-15, no chair or no coordinator",
        "Pure",
    ),
    row(
        CheckId::ExclusionClassUnknown,
        "P-13 class ids the vault does not know, so I-04 could not be checked (Q35, interim, pending Daniel)",
        "New vault query from CreatorInputs::vault; an absent answer fails closed",
    ),
    row(
        CheckId::ProximityListMissing,
        "P-38: a partner organisation without a declared list (Q35, interim, pending Daniel)",
        "New vault query from CreatorInputs::vault; an absent answer reports the warning",
    ),
    row(
        CheckId::PrecheckUnavailable,
        "P-23 enabled while no pre-check provider exists (Q38 C: a warning, and the Guide notes the pre-check is not yet available)",
        "Pure over the Precheck port's presence; the M7 provider turns it off",
    ),
    row(
        CheckId::AiActReassessment,
        "ai-act.md reassessment trigger: P-77 allowed while score tools exist",
        "Pure; the acknowledgement records that the AI Act position was reviewed",
    ),
    row(
        CheckId::ChannelUnreachable,
        "Every enabled channel of P-32",
        "Prober; an absent prober reports Failure (Q5, interim, pending Daniel)",
    ),
    row(
        CheckId::SendingDomainUnverified,
        "SPF, DKIM and DMARC of the sending domain",
        "Prober; an absent prober reports Failure (Q5, interim, pending Daniel)",
    ),
    row(
        CheckId::InferenceUnreachable,
        "P-21; R-NF-10 says loss of inference never blocks human evaluation",
        "Prober",
    ),
    row(
        CheckId::MandatoryElementMissing,
        "I-69",
        "Pure over the theme in CreatorInputs, the default theme in M4",
    ),
    row(
        CheckId::ContrastFailure,
        "I-70: every text colour pair, light and dark",
        "Pure integer computation over the theme tokens",
    ),
    row(
        CheckId::ImportUnresolved,
        "A proposal neither confirmed, edited nor dismissed (Q30, interim, pending Daniel)",
        "CreatorInputs::unresolved_imports, a count from the engine",
    ),
];

/// One element of the I-48 call package.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CallPackageElement {
    /// The maximum per recipient.
    MaximumPerRecipient,
    /// The criteria for the exact amount.
    ExactAmountCriteria,
    /// The closed list of activity types.
    ClosedActivityList,
    /// The persons and categories supported.
    PersonsSupported,
    /// The award criteria.
    AwardCriteria,
    /// The award procedure.
    AwardProcedure,
}

impl CallPackageElement {
    /// Every element.
    pub const ALL: [CallPackageElement; 6] = [
        CallPackageElement::MaximumPerRecipient,
        CallPackageElement::ExactAmountCriteria,
        CallPackageElement::ClosedActivityList,
        CallPackageElement::PersonsSupported,
        CallPackageElement::AwardCriteria,
        CallPackageElement::AwardProcedure,
    ];

    /// The element's name in JSON.
    pub const fn name(self) -> &'static str {
        match self {
            CallPackageElement::MaximumPerRecipient => "MaximumPerRecipient",
            CallPackageElement::ExactAmountCriteria => "ExactAmountCriteria",
            CallPackageElement::ClosedActivityList => "ClosedActivityList",
            CallPackageElement::PersonsSupported => "PersonsSupported",
            CallPackageElement::AwardCriteria => "AwardCriteria",
            CallPackageElement::AwardProcedure => "AwardProcedure",
        }
    }

    /// The element with JSON name `name`.
    pub fn from_name(name: &str) -> Option<CallPackageElement> {
        CallPackageElement::ALL
            .into_iter()
            .find(|c| c.name() == name)
    }
}

/// What a report row is about.
///
/// A row never names an account. An `InviteeRefused` row names the
/// invitation and the rule only (R-CF-03).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CheckSubject {
    /// The draft as a whole.
    Draft,
    /// One field.
    Field(FieldId),
    /// One invitation.
    Invitation(InvitationId),
    /// One probe.
    Probe(ProbeKind),
    /// One text colour pair of the theme.
    Colour {
        /// The theme mode.
        mode: ThemeMode,
        /// The text role.
        role: TextRole,
    },
    /// One mandatory element.
    Element(MandatoryElement),
    /// One element of the call package.
    CallPackage(CallPackageElement),
    /// One required Guide section, by heading.
    GuideSection(String),
    /// One unresolved Guide placeholder.
    Placeholder(String),
    /// One flow-down obligation identifier.
    FlowDown(String),
}

/// What a row says beyond its check and subject.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum CheckDetail {
    /// Nothing more.
    None,
    /// R-PG-01 AC: P-05 and P-58 as ADR-006 strings.
    Cap {
        /// P-05.
        p05: String,
        /// P-58.
        p58: String,
    },
    /// The rule of a refusal, such as an SoD rule of a preview.
    Rule(RuleRef),
    /// The engine passed no answer for this subject, so the check fails
    /// closed.
    NotChecked,
    /// The source of the check is not available yet, so the check fails
    /// closed. The text names the missing source.
    Unavailable(&'static str),
    /// The probe outcome that raised the row.
    Probe(ProbeOutcome),
}

/// One row of a validation report.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CheckResult {
    /// The check.
    pub check: CheckId,
    /// Its severity.
    pub severity: Severity,
    /// What the row is about.
    pub subject: CheckSubject,
    /// The detail.
    pub detail: CheckDetail,
}

impl CheckResult {
    /// The key an acknowledgement names.
    pub fn key(&self) -> WarningKey {
        WarningKey {
            check: self.check,
            subject: self.subject.clone(),
        }
    }
}

/// The key of a report row: its check and subject. An acknowledgement
/// names one key.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WarningKey {
    /// The check.
    pub check: CheckId,
    /// The subject.
    pub subject: CheckSubject,
}
