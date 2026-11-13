//! Funder reporting (M5 design lane L-RPT, `SPEC/03-architecture/funder-reporting.md`).
//!
//! - [`Snapshot`] is the data snapshot: a prefix of the core ledger, with
//!   a digest over its canonical form (R-RP-01).
//! - [`profile`]: versioned funder profiles (M9 design section 2.5). The
//!   Horizon Europe profile, version 1, ships in
//!   `profiles/horizon-europe/profile.v1.json`, and a programme pins one
//!   through P-53.
//! - [`generate`] makes one output of a funder profile from a snapshot: the call publication record, the open call package, the
//!   periodic reporting data, the audit file per call and the deliverable
//!   draft (R-RP-04). Every output first reconciles the snapshot. Any
//!   mismatch fails generation and is listed (I-44, R-RP-02). Equal
//!   snapshots give equal bytes (R-RP-01).
//! - [`guide_pdf`] renders the stored Guide as a tagged PDF (R-GA-02,
//!   I-53). It lives here so that `fstp-guide` takes no `fstp-pdf`.
//! - [`ReportRecord`] is the `Report` ledger envelope: `ReportGenerated`
//!   and `ReportApproved`. [`approve`] lets only a Financial signatory who
//!   did not generate a document approve it (R-RP-03, Q3).
//!
//! The platform never submits anything to a funder portal. Documents use
//! `fstp-pdf`, and data outputs are RFC 8785 JSON. Each template carries a
//! `TODO(legal)` marker until its field list is checked (L-09).

#![deny(
    clippy::float_arithmetic,
    clippy::float_cmp,
    clippy::cast_precision_loss,
    clippy::arithmetic_side_effects
)]

mod books;
pub mod guide;
mod output;
pub mod profile;
mod record;
mod snapshot;
mod time;

pub use books::Mismatch;
pub use fstp_report_core::{
    ApprovalRefusal, ENVELOPE, ProfilePin, ReportFoldError, ReportId, ReportKind, ReportRecord,
    ReportStore, Scope, StoredReport, approve, is_financial_signatory,
};
pub use guide::{GuideContent, GuidePdfError, guide_pdf, read_canonical, rendered_guide_pdf};
pub use output::{Content, Output, PackageInputs, Period, Request, generate};
pub use profile::{FunderProfile, ProfileError};
pub use record::generated;
pub use snapshot::{Entry, Snapshot};

/// Why an output was not generated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReportError {
    /// The snapshot is malformed.
    Snapshot(&'static str),
    /// Figures do not reconcile with the ledger (I-44). Every mismatch is
    /// listed.
    Reconciliation(Vec<Mismatch>),
    /// The snapshot holds no such published call or programme.
    UnknownCall,
    /// The reporting periods are empty, empty-ranged or overlap.
    Periods,
    /// The open call package lacks these elements (I-48, data protection
    /// notice).
    Package(Vec<&'static str>),
    /// The stored Guide could not be read.
    Guide(GuidePdfError),
    /// The PDF writer refused the document.
    Pdf(fstp_pdf::WriteError),
    /// A JSON value could not be written canonically.
    Encoding,
    /// A sum overflowed or mixed currencies.
    Money,
    /// The pinned funder profile does not define this output (D3).
    NotInProfile(ReportKind),
    /// The funder profile is malformed or not shipped (P-53).
    Profile(ProfileError),
}

impl std::fmt::Display for ReportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReportError::Snapshot(r) => write!(f, "malformed snapshot: {r}"),
            ReportError::Reconciliation(list) => {
                write!(f, "I-44: {} figure(s) do not reconcile:", list.len())?;
                for m in list {
                    write!(f, " [{m}]")?;
                }
                Ok(())
            }
            ReportError::UnknownCall => f.write_str("no such published call or programme"),
            ReportError::Periods => f.write_str("the reporting periods are malformed"),
            ReportError::Package(missing) => {
                write!(
                    f,
                    "I-48: the open call package lacks: {}",
                    missing.join(", ")
                )
            }
            ReportError::Guide(e) => write!(f, "{e}"),
            ReportError::Pdf(e) => write!(f, "{e}"),
            ReportError::Encoding => f.write_str("a value has no canonical JSON form"),
            ReportError::Money => f.write_str("a sum overflowed or mixed currencies"),
            ReportError::NotInProfile(k) => {
                write!(f, "the funder profile defines no {} output", k.name())
            }
            ReportError::Profile(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ReportError {}
