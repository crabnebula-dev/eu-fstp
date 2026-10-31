//! Shared helpers for the `fstp-audit` tests (lane W2g, test author).
//!
//! - [`reference`] is a small test-local reference of the ADR-010 byte
//!   layouts over `fstp_crypto::sha256`. It names no `fstp-audit` item.
//!   Its outputs are pinned by vectors that `shasum -a 256` computed from
//!   hex strings, outside Rust (see [`reference::vectors`]).
//! - [`view`] builds honest chains with their anchor rows and witness log,
//!   and applies one attacker mutation with the verdict it must get.
//! - [`api`] is the one place that calls `fstp-audit`. Each adapter either
//!   calls the stub, or refuses with a gap constant where the designed API
//!   does not exist yet. The production agent re-points the adapters.
//! - [`signing`] signs anchors and receipts in the test with
//!   `fstp_crypto::composite`, under the pinned [`ANCHOR_CTX`] and
//!   [`RECEIPT_CTX`], and builds the signature forgeries the verifier must
//!   name.
//! - [`real_refusal`] tells a real refusal from the W0 stub's
//!   `NotImplemented`, a gap or the old acceptance refusal. A refusal test
//!   that accepted any of them would pass against the stub for the wrong
//!   reason.
//!
//! `fstp-celltest` cannot be a dev-dependency here. Layering rule 1 reads
//! every dependency kind of a pure core, and `fstp-celltest` reaches tokio.

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
pub(crate) mod reference;
pub(crate) mod signing;
pub(crate) mod view;

use fstp_audit::AuditError;

/// The text the old interim refusal of every signing and signature check
/// named (ADR-010 "Composite encoding"). Daniel accepted the table on
/// 2026-10-29 (design section 21.0), so a refusal that still names it is
/// a stub refusal.
pub(crate) const ACCEPTANCE: &str = "ADR-010 composite encoding acceptance (Daniel)";

/// The application context `ctx` of draft 19 that every anchor signature
/// passes (ADR-010 "Composite encoding", row "Application context of
/// platform messages", open point 2). Interim reading of lane W2g: the
/// anchor message label. Pinned here once, so the tests change in one
/// place if Daniel decides otherwise.
pub(crate) const ANCHOR_CTX: &[u8] = b"fstp-anchor-v1";

/// The application context of every receipt signature, as
/// [`ANCHOR_CTX`]: the receipt message label (interim reading of lane
/// W2g, ADR-010 open point 2).
pub(crate) const RECEIPT_CTX: &[u8] = b"fstp-receipt-v1";

/// Whether `e` is a stub refusal: the W0 stub's `NotImplemented`, an
/// adapter gap, or a refusal that still names [`ACCEPTANCE`]. None of
/// them is an answer since the table was accepted. The match is on the
/// text, so the tests compile once `AwaitsAcceptance` is removed.
pub(crate) fn is_stub_or_gap(e: &AuditError) -> bool {
    match e {
        AuditError::NotImplemented(_) => true,
        AuditError::Tamper(_) => false,
        #[allow(
            unreachable_patterns,
            reason = "W2g removes the acceptance variant once nothing returns it"
        )]
        other => format!("{other:?}").contains(ACCEPTANCE),
    }
}

/// Whether `e` is the interim refusal that names [`ACCEPTANCE`].
pub(crate) fn is_acceptance_refusal(e: &AuditError) -> bool {
    !matches!(e, AuditError::Tamper(_)) && format!("{e:?}").contains(ACCEPTANCE)
}

/// `Ok` when `r` is a refusal other than the stub's `NotImplemented` or a
/// gap. Otherwise a message that names `what`.
pub(crate) fn real_refusal<T: std::fmt::Debug>(
    what: &str,
    r: &Result<T, AuditError>,
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
pub(crate) fn answered<T>(what: &str, r: Result<T, AuditError>) -> Result<T, String> {
    r.map_err(|e| format!("{what}: no answer: {e:?}"))
}

/// Lower-case hex to bytes. Test constants only.
pub(crate) fn hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex digit"))
        .collect()
}

/// Lower-case hex of a 32-byte constant.
pub(crate) fn hex32(s: &str) -> [u8; 32] {
    hex(s).try_into().expect("32 bytes")
}
