//! Test support for `fstp-programme`, written by the W1a test author.
//!
//! - [`spec`] reads `SPEC/` markdown at test time: the creator and
//!   onboarding tables of `programme-creator.md` and both parameter tables
//!   of `policy-parameters.md`.
//! - [`readings`] holds the test author's readings of those tables: the
//!   SuperSAFE value of every parameter, the interim placement of the
//!   parameters no creator step names (Q36), and the synthetic placeholders.
//!
//! Nothing here names an `fstp-programme` item, so the reference self-tests
//! in `r_pg_01_spec_reference.rs` build against any version of the crate.
//! Helpers return `Result` with a message and never panic. Only test
//! functions assert.

#![allow(dead_code)]

pub(crate) mod readings;
pub(crate) mod spec;
