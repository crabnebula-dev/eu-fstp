//! The pure core of funder reporting (M5 design lane L-RPT).
//!
//! - [`ReportKind`] and [`Scope`]: the outputs of the profile and what
//!   they cover;
//! - the `Report` ledger envelope: [`ReportRecord`], its stored JSON form,
//!   the fold in [`ReportStore`] and [`approve`] (R-RP-03, Q3).
//!
//! `fstp-engine` reaches reports through this crate only, so it stays free
//! of I/O and of third-party crates (M2 layering rule 1). Snapshots, PDF
//! rendering and the generated `ReportGenerated` record from an output
//! stay in `fstp-report`.

#![deny(
    clippy::float_arithmetic,
    clippy::float_cmp,
    clippy::cast_precision_loss,
    clippy::arithmetic_side_effects
)]

mod kind;
mod record;

pub use kind::{ReportKind, Scope};
pub use record::{
    ApprovalRefusal, ENVELOPE, ReportFoldError, ReportId, ReportRecord, ReportStore, StoredReport,
    approve, is_financial_signatory,
};
