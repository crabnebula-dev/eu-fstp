//! I-66 and I-67 `i66_witnesses_cannot_be_forged`: compile-fail twins for
//! the activation witnesses (M4 design sections 3.2 and 8.4).
//!
//! This module holds doc comments only. It is compiled under
//! `cfg(doctest)` alone, so it adds nothing to the library. The test
//! author of lane W2a owns it, as the M2 twins of `fstp-ledger`.
//!
//! The pinned stable rustdoc ignores `compile_fail` error codes. So each
//! forbidden line gets a `compile_fail` doctest and a `no_run` twin. The
//! twin differs only in that one line and must compile. A typo in the
//! shared text then breaks the twin, so no pair passes vacuously.
//!
//! The designed witnesses:
//!
//! - `CleanReport` (I-66): no failure, and every warning acknowledged at
//!   its revision. Only `clean(&ValidationReport, &AckSet)` builds it.
//! - `ActivationClearance` (I-67): the approver is outside the builder
//!   set and shares no verified identity with it. Only `clear_activation`
//!   builds it, from a `CleanReport`.
//! - `ActivationApproved`: the creator record of an approval. Outside the
//!   record decoder, only `ActivationApproved::new(&ActivationClearance)`
//!   builds it. The engine fold pairs every decoded one with its core
//!   `ProgrammeActivated` (D2e), which the fold tests check.
//!
//! Status while lane W2a's production code is absent: the three types do
//! not exist, so each `compile_fail` test passes for the wrong reason and
//! each `no_run` twin fails. The twins are red for that reason.
//!
//! # `CleanReport` cannot be written as a literal
//!
//! ```compile_fail
//! use fstp_creator::CleanReport;
//! fn forge(c: CleanReport) -> CleanReport {
//!     CleanReport { ..c }
//! }
//! ```
//!
//! ```no_run
//! use fstp_creator::CleanReport;
//! fn forge(c: CleanReport) -> CleanReport {
//!     c
//! }
//! ```
//!
//! # `CleanReport` has no `Default`
//!
//! ```compile_fail
//! use fstp_creator::CleanReport;
//! fn forge() -> CleanReport {
//!     Default::default()
//! }
//! ```
//!
//! ```no_run
//! use fstp_creator::CleanReport;
//! fn forge() -> Option<CleanReport> {
//!     None
//! }
//! ```
//!
//! # `CleanReport` does not decode from JSON
//!
//! ```compile_fail
//! use fstp_creator::CleanReport;
//! fn forge(v: &fstp_json::Value) -> Option<CleanReport> {
//!     <CleanReport as fstp_json::FromJson>::from_json(v).ok()
//! }
//! ```
//!
//! ```no_run
//! use fstp_creator::CleanReport;
//! fn forge(v: &fstp_json::Value) -> Option<CleanReport> {
//!     let _ = v;
//!     None
//! }
//! ```
//!
//! # `CleanReport` comes only from `clean`
//!
//! ```compile_fail
//! use fstp_creator::{AckSet, CleanReport, ValidationReport};
//! fn forge(r: &ValidationReport, a: &AckSet) -> Option<CleanReport> {
//!     Some(CleanReport::new(r, a))
//! }
//! ```
//!
//! ```no_run
//! use fstp_creator::{AckSet, CleanReport, ValidationReport};
//! fn forge(r: &ValidationReport, a: &AckSet) -> Option<CleanReport> {
//!     fstp_creator::clean(r, a).ok()
//! }
//! ```
//!
//! # `ActivationClearance` cannot be written as a literal
//!
//! ```compile_fail
//! use fstp_creator::ActivationClearance;
//! fn forge(c: ActivationClearance) -> ActivationClearance {
//!     ActivationClearance { ..c }
//! }
//! ```
//!
//! ```no_run
//! use fstp_creator::ActivationClearance;
//! fn forge(c: ActivationClearance) -> ActivationClearance {
//!     c
//! }
//! ```
//!
//! # `ActivationClearance` has no `Default`
//!
//! ```compile_fail
//! use fstp_creator::ActivationClearance;
//! fn forge() -> ActivationClearance {
//!     Default::default()
//! }
//! ```
//!
//! ```no_run
//! use fstp_creator::ActivationClearance;
//! fn forge() -> Option<ActivationClearance> {
//!     None
//! }
//! ```
//!
//! # `ActivationClearance` does not decode from JSON
//!
//! ```compile_fail
//! use fstp_creator::ActivationClearance;
//! fn forge(v: &fstp_json::Value) -> Option<ActivationClearance> {
//!     <ActivationClearance as fstp_json::FromJson>::from_json(v).ok()
//! }
//! ```
//!
//! ```no_run
//! use fstp_creator::ActivationClearance;
//! fn forge(v: &fstp_json::Value) -> Option<ActivationClearance> {
//!     let _ = v;
//!     None
//! }
//! ```
//!
//! # `ActivationApproved` cannot be written as a literal
//!
//! ```compile_fail
//! use fstp_creator::ActivationApproved;
//! fn forge(a: ActivationApproved) -> ActivationApproved {
//!     ActivationApproved { ..a }
//! }
//! ```
//!
//! ```no_run
//! use fstp_creator::ActivationApproved;
//! fn forge(a: ActivationApproved) -> ActivationApproved {
//!     a
//! }
//! ```
//!
//! # `ActivationApproved` has no `Default`
//!
//! ```compile_fail
//! use fstp_creator::ActivationApproved;
//! fn forge() -> ActivationApproved {
//!     Default::default()
//! }
//! ```
//!
//! ```no_run
//! use fstp_creator::ActivationApproved;
//! fn forge() -> Option<ActivationApproved> {
//!     None
//! }
//! ```
//!
//! # `ActivationApproved::new` takes a clearance, never a bare report
//!
//! ```compile_fail
//! use fstp_creator::{ActivationApproved, ActivationClearance, CleanReport};
//! fn forge(r: &CleanReport, c: &ActivationClearance) -> ActivationApproved {
//!     ActivationApproved::new(r)
//! }
//! ```
//!
//! ```no_run
//! use fstp_creator::{ActivationApproved, ActivationClearance, CleanReport};
//! fn forge(r: &CleanReport, c: &ActivationClearance) -> ActivationApproved {
//!     ActivationApproved::new(c)
//! }
//! ```
