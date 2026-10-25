//! Assessment findings as data, kept apart from the domain core.
//!
//! The crate holds `Finding`, `UntrustedText`, `FindingStore`, the I-11
//! check that every finding of a call shares the call's pinned `config_id`,
//! and the finding records and their codec (`docs/handoff/m2-design.md`
//! section 2.13).
//!
//! Findings depend on the domain, never the reverse (I-10). `decide_finding`
//! returns only finding records, so a finding can never drive a core
//! transition.
//!
//! Status: empty skeleton from milestone M2 step W0. Lane L-FIND-A owns the
//! whole crate and lays out its modules.

#![deny(
    clippy::float_arithmetic,
    clippy::float_cmp,
    clippy::cast_precision_loss,
    clippy::arithmetic_side_effects
)]
