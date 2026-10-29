//! Shared helpers for the `fstp-witness` tests (lane W2g, test author).
//!
//! - [`api`] is the one place that calls `fstp-witness`. Each adapter
//!   calls the W0 stub where one exists, or refuses with a gap constant
//!   that names the missing designed API. The production agent re-points
//!   the adapters, and the test files stay unchanged.
//! - [`real_refusal`] tells a real refusal from the stub's
//!   `NotImplemented` or a gap.
//!
//! Links come from `fstp_audit::chain::link`, the one link function of
//! ADR-010, which the witness must also use to recompute a prepare. The
//! link itself is tested against vectors in `fstp-audit`.

#![allow(dead_code, reason = "each test binary uses a different part")]
#![allow(
    unreachable_pub,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test fixtures assert on known-good values"
)]

pub(crate) mod api;
pub(crate) mod codec;

use fstp_witness::WitnessError;

/// The text the interim refusal of receipt signing names (lane W2g
/// scope, ADR-010 "Composite encoding").
pub(crate) const ACCEPTANCE: &str = "ADR-010 composite encoding acceptance (Daniel)";

/// Whether `e` is the W0 stub's `NotImplemented` or an adapter gap.
pub(crate) fn is_stub_or_gap(e: &WitnessError) -> bool {
    match e {
        WitnessError::NotImplemented(op) => !op.contains(ACCEPTANCE),
        #[allow(
            unreachable_patterns,
            reason = "the W0 stub has one variant; W2g adds refusal reasons"
        )]
        _ => false,
    }
}

/// `Ok` when `r` is a refusal other than the stub's `NotImplemented` or a
/// gap. Otherwise a message that names `what`.
pub(crate) fn real_refusal<T: std::fmt::Debug>(
    what: &str,
    r: &Result<T, WitnessError>,
) -> Result<(), String> {
    match r {
        Err(e) if is_stub_or_gap(e) => Err(format!(
            "{what}: refused only because the API is a stub or missing: {e:?}"
        )),
        Err(_) => Ok(()),
        Ok(v) => Err(format!("{what}: accepted, but must be refused: {v:?}")),
    }
}

/// The value of `r`, or a message that names `what` and the refusal.
pub(crate) fn answered<T>(what: &str, r: Result<T, WitnessError>) -> Result<T, String> {
    r.map_err(|e| format!("{what}: no answer: {e:?}"))
}
