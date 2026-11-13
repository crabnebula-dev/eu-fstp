//! Versioned funder profiles (M9 design sections 1.3 D3 and 2.5, P-53,
//! R-RP-01, I-44).
//!
//! A profile is one I-JSON file per version under
//! `crates/fstp-report/profiles/<id>/profile.v<n>.json`, parsed only
//! through `fstp-json` by [`parse_profile`] (fuzz target
//! `funder_profile_parse`). It names:
//!
//! - its `id` and `version`, which a programme pins through P-53;
//! - its `outputs`: for each output kind of `funder-reporting.md` it
//!   defines, a template ref and a field list;
//! - for each field a name, a label, a level and a `figure`, which is one
//!   of the closed list of ledger folds [`Figure`]. No field can hold a
//!   literal number, so no profile can introduce a figure that does not
//!   reconcile (I-44);
//! - its `visibility_elements`: keys of the funder visibility elements,
//!   each with a wording ref whose status is `TODO(legal)` until Daniel
//!   supplies the approved text (L-08, L-09);
//! - its `reporting_periods`: a reference to the Data Sheet parameter,
//!   never dates.
//!
//! Profiles are shipped, not tenant-authored (D3, interim, pending
//! Daniel). [`shipped`] gives a shipped profile by id and version, and
//! [`for_p53`] the profile a P-53 value pins.

mod parse;

use fstp_domain::id::ContentDigest;
use fstp_report_core::{ProfilePin, ReportKind, p53_profile};

pub use parse::{MAX_PROFILE_BYTES, ProfileError, parse_profile};

/// The Horizon Europe profile, version 1, as shipped.
pub const HORIZON_EUROPE_V1: &[u8] =
    include_bytes!("../../profiles/horizon-europe/profile.v1.json");

/// Every shipped profile file: id, version and bytes.
const SHIPPED: [(&str, u16, &[u8]); 1] = [("horizon-europe", 1, HORIZON_EUROPE_V1)];

/// The level a field's figure is taken at.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    /// The one call of a call-scoped output.
    Call,
    /// One recipient row of one reporting period.
    Recipient,
    /// One reporting period.
    Period,
    /// The whole programme at the snapshot.
    Total,
}

impl Level {
    /// Every level.
    pub const ALL: [Level; 4] = [Level::Call, Level::Recipient, Level::Period, Level::Total];

    /// The stored name.
    pub const fn name(self) -> &'static str {
        match self {
            Level::Call => "call",
            Level::Recipient => "recipient",
            Level::Period => "period",
            Level::Total => "total",
        }
    }

    /// The level of a stored name.
    pub fn from_name(name: &str) -> Option<Level> {
        Level::ALL.into_iter().find(|l| l.name() == name)
    }

    /// The levels an output takes fields at. The open call package and
    /// the audit file hold no figure.
    pub const fn of_output(kind: ReportKind) -> &'static [Level] {
        match kind {
            ReportKind::CallPublicationRecord | ReportKind::DeliverableDraft => &[Level::Call],
            ReportKind::PeriodicReportingData => &[Level::Recipient, Level::Period, Level::Total],
            ReportKind::OpenCallPackage | ReportKind::AuditFile => &[],
        }
    }
}

/// A ledger fold: the closed list of figures a profile field may name
/// (M9 design section 2.5, I-44). Each one is computed by the
/// reconciliation fold of `books.rs` after it found no mismatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Figure {
    /// The budget of the call as last drafted before publication.
    CallBudget,
    /// The proposals created in the call.
    ProposalsCreated,
    /// The proposals of the call submitted at least once.
    ProposalsSubmitted,
    /// The proposals of the call with a knock-out decision.
    KnockOutDecisions,
    /// The grants decided: in the call, in the programme, or listed in
    /// the period (decided before its end).
    RecipientCount,
    /// The grants COMPLETED or TERMINATED.
    GrantsClosed,
    /// The contract amounts of the decided grants.
    Committed,
    /// The approved amounts of released requests, to the snapshot.
    Paid,
    /// The approved amounts of requests released within the period.
    PaidInPeriod,
    /// As [`Figure::PaidInPeriod`], hardship contributions only.
    PaidHardshipInPeriod,
    /// The unpaid commitment of grants closed within the period.
    ReleasedCommitmentInPeriod,
    /// The unpaid commitment of closed grants, to the snapshot.
    ReleasedCommitments,
}

impl Figure {
    /// Every figure.
    pub const ALL: [Figure; 12] = [
        Figure::CallBudget,
        Figure::ProposalsCreated,
        Figure::ProposalsSubmitted,
        Figure::KnockOutDecisions,
        Figure::RecipientCount,
        Figure::GrantsClosed,
        Figure::Committed,
        Figure::Paid,
        Figure::PaidInPeriod,
        Figure::PaidHardshipInPeriod,
        Figure::ReleasedCommitmentInPeriod,
        Figure::ReleasedCommitments,
    ];

    /// The stored name.
    pub const fn name(self) -> &'static str {
        match self {
            Figure::CallBudget => "call_budget",
            Figure::ProposalsCreated => "proposals_created",
            Figure::ProposalsSubmitted => "proposals_submitted",
            Figure::KnockOutDecisions => "knock_out_decisions",
            Figure::RecipientCount => "recipient_count",
            Figure::GrantsClosed => "grants_closed",
            Figure::Committed => "committed",
            Figure::Paid => "paid",
            Figure::PaidInPeriod => "paid_in_period",
            Figure::PaidHardshipInPeriod => "paid_hardship_in_period",
            Figure::ReleasedCommitmentInPeriod => "released_commitment_in_period",
            Figure::ReleasedCommitments => "released_commitments",
        }
    }

    /// The figure of a stored name.
    pub fn from_name(name: &str) -> Option<Figure> {
        Figure::ALL.into_iter().find(|f| f.name() == name)
    }

    /// The levels the fold is defined at.
    pub const fn levels(self) -> &'static [Level] {
        match self {
            Figure::CallBudget
            | Figure::ProposalsCreated
            | Figure::ProposalsSubmitted
            | Figure::KnockOutDecisions => &[Level::Call],
            Figure::RecipientCount => &[Level::Call, Level::Period, Level::Total],
            Figure::GrantsClosed | Figure::Paid | Figure::ReleasedCommitments => {
                &[Level::Call, Level::Total]
            }
            Figure::Committed => &[Level::Call, Level::Recipient, Level::Total],
            Figure::PaidInPeriod
            | Figure::PaidHardshipInPeriod
            | Figure::ReleasedCommitmentInPeriod => &[Level::Recipient, Level::Period],
        }
    }

    /// Whether the figure is an amount of money, else a count.
    pub const fn is_amount(self) -> bool {
        !matches!(
            self,
            Figure::ProposalsCreated
                | Figure::ProposalsSubmitted
                | Figure::KnockOutDecisions
                | Figure::RecipientCount
                | Figure::GrantsClosed
        )
    }
}

/// One field of an output.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FieldSpec {
    name: String,
    label: String,
    level: Level,
    figure: Figure,
}

impl FieldSpec {
    /// The member name in data outputs.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The label in document outputs.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The level.
    pub fn level(&self) -> Level {
        self.level
    }

    /// The ledger fold.
    pub fn figure(&self) -> Figure {
        self.figure
    }
}

/// One output a profile defines.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OutputSpec {
    kind: ReportKind,
    template: String,
    fields: Vec<FieldSpec>,
}

impl OutputSpec {
    /// The output kind.
    pub fn kind(&self) -> ReportKind {
        self.kind
    }

    /// The template ref (R-RP-01).
    pub fn template(&self) -> &str {
        &self.template
    }

    /// The fields, in file order.
    pub fn fields(&self) -> &[FieldSpec] {
        &self.fields
    }

    /// The fields at `level`, in file order.
    pub fn at(&self, level: Level) -> impl Iterator<Item = &FieldSpec> {
        self.fields.iter().filter(move |f| f.level == level)
    }
}

/// The status of a wording ref.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WordingStatus {
    /// The approved wording is pending. Stored as `TODO(legal)`.
    PendingLegal,
}

/// A required funder visibility element (I-69, L-08).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct VisibilityElement {
    key: String,
    wording: String,
    status: WordingStatus,
}

impl VisibilityElement {
    /// The element key.
    pub fn key(&self) -> &str {
        &self.key
    }

    /// The wording ref.
    pub fn wording(&self) -> &str {
        &self.wording
    }

    /// The wording status.
    pub fn status(&self) -> WordingStatus {
        self.status
    }
}

/// Where the reporting periods come from. Never dates in the file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PeriodSource {
    /// The action dates of the Data Sheet, P-57.
    DataSheetP57,
}

/// A parsed funder profile.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FunderProfile {
    id: String,
    version: u16,
    digest: ContentDigest,
    outputs: Vec<OutputSpec>,
    visibility: Vec<VisibilityElement>,
    periods: PeriodSource,
}

impl FunderProfile {
    /// The profile id.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The version.
    pub fn version(&self) -> u16 {
        self.version
    }

    /// The SHA-256 of the file bytes.
    pub fn digest(&self) -> ContentDigest {
        self.digest
    }

    /// The pin `ReportGenerated` records (M9 design section 2.1).
    pub fn pin(&self) -> ProfilePin {
        ProfilePin {
            id: self.id.clone(),
            version: self.version,
            digest: self.digest,
        }
    }

    /// The outputs, in file order.
    pub fn outputs(&self) -> &[OutputSpec] {
        &self.outputs
    }

    /// The output of `kind`, if the profile defines it.
    pub fn output(&self, kind: ReportKind) -> Option<&OutputSpec> {
        self.outputs.iter().find(|o| o.kind == kind)
    }

    /// The funder visibility elements.
    pub fn visibility_elements(&self) -> &[VisibilityElement] {
        &self.visibility
    }

    /// Where the reporting periods come from.
    pub fn reporting_periods(&self) -> PeriodSource {
        self.periods
    }
}

/// The shipped profile `id` at `version`.
pub fn shipped(id: &str, version: u16) -> Result<FunderProfile, ProfileError> {
    let (_, _, bytes) = SHIPPED
        .iter()
        .find(|(i, v, _)| *i == id && *v == version)
        .ok_or(ProfileError::NotShipped)?;
    let p = parse_profile(bytes)?;
    if p.id != id || p.version != version {
        return Err(ProfileError::NotShipped);
    }
    Ok(p)
}

/// Every shipped profile.
pub fn shipped_all() -> Result<Vec<FunderProfile>, ProfileError> {
    SHIPPED.iter().map(|(i, v, _)| shipped(i, *v)).collect()
}

/// The shipped profile the P-53 value `p53_text` pins (R-RP-01). A value
/// that names no shipped profile is refused.
pub fn for_p53(p53_text: &str) -> Result<FunderProfile, ProfileError> {
    let (id, version) = p53_profile(p53_text).ok_or(ProfileError::NotShipped)?;
    shipped(&id, version)
}
