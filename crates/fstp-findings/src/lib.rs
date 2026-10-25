//! Assessment findings as data, kept apart from the domain core.
//!
//! The crate holds [`Finding`], [`UntrustedText`], [`FindingStore`], the I-11
//! check that every finding of a call shares the call's pinned `config_id`,
//! and the finding records and their codec (`docs/handoff/m2-design.md`
//! section 2.13).
//!
//! - Findings are advisory data (`SPEC/04-llm-assessment/assessment.md`).
//!   Nothing in this crate reads a statement, so a finding can never act
//!   as an instruction.
//! - Findings depend on the domain, never the reverse (I-10). The crate
//!   returns only finding values, so a finding can never drive a core
//!   transition. `tools/deps-check` enforces the layering.
//! - The store keeps each call's findings under one configuration (I-11).
//!   A replacement of the pinned model regenerates the call's findings in
//!   one step (`SPEC/02-domain/policy-parameters.md` NOTE 10).
//!
//! Status: lane L-FIND-A of milestone M2. The `decide_finding` routing
//! with the core state lives in `fstp-engine` (lane L-FIND-B).

#![deny(
    clippy::float_arithmetic,
    clippy::float_cmp,
    clippy::cast_precision_loss,
    clippy::arithmetic_side_effects
)]

pub mod codec;
pub mod finding;
pub mod record;
pub mod store;
pub mod text;

pub use finding::{
    Confidence, EvidenceRef, Finding, FindingId, FindingKind, Mark, Severity, TraceRef,
};
pub use record::{FindingCommand, FindingRecord};
pub use store::{FindingRefusal, FindingStore};
pub use text::UntrustedText;
