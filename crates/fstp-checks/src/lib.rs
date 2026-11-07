//! The automated checks of a payment request (M5 design lane L-CHK,
//! `SPEC/02-domain/payment-requests.md` Automated checks).
//!
//! - [`spdx`]: the SPDX licence expression parser and the P-26 test.
//! - [`detect`]: licence detection on a deliverable's licence file.
//! - [`url`]: the deliverable URL subset the checks fetch.
//! - [`snapshot`]: evidence snapshots and their digests (R-PR-03, TH-24).
//! - [`runner`]: the runner that judges a request and builds its
//!   `RecordChecks` (I-32, R-PR-02).
//!
//! The crate does no I/O. The cell gives the runner a [`runner::Fetch`]
//! built on its egress rules (`fstp_cell::egress`). Every parser here has
//! a fuzz target under `fuzz/`.

pub mod detect;
pub mod runner;
pub mod snapshot;
pub mod spdx;
pub mod url;
