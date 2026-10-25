//! Composition of the domain core and findings.
//!
//! The crate holds `EngineState`, the `Command` and `Record` envelopes over
//! core and finding values, the synchronous `IdentityOracle` trait and the
//! synchronous reference driver (`docs/handoff/m2-design.md` section 3.1).
//! Core commands go to `fstp_domain::decide`, which never sees the finding
//! store. Finding commands go to `decide_finding`, which returns only finding
//! records (I-10).
//!
//! Status: module tree from milestone M2 step W0. Every module is an empty
//! stub. Lane W2 owns this file and `driver`, lane L-FIND-B owns `findings`.

#![deny(
    clippy::float_arithmetic,
    clippy::float_cmp,
    clippy::cast_precision_loss,
    clippy::arithmetic_side_effects
)]

pub mod driver;
pub mod findings;
