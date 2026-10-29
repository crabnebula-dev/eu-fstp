//! Review reproducer (R-ID-02, design sections 4.3 and 6.7): the vault
//! write kind `VerificationRecorded` carries the outcome's method,
//! document type, checks, time and verifier. A verification fact without
//! them is not the record R-ID-02 asks the vault to store.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code asserts on known-good values"
)]

use fstp_vault_core::fact::kind;
use fstp_vault_core::{Fact, decode_fact};

/// R-ID-02, design section 6.7: a verification body that names only an
/// account and a person, with no method, document type, checks, time or
/// verifier, is refused.
#[test]
fn review_r_id_02_verification_fact_needs_method_checks_time_and_verifier() {
    let got = decode_fact(
        kind::VERIFICATION_RECORDED,
        b"{\"account\":\"1\",\"person\":\"2\"}",
    );
    assert!(
        !matches!(got, Ok(Fact::VerificationRecorded { .. })),
        "R-ID-02: a verification record without method, document type, checks, time or verifier was accepted: {got:?}"
    );
}
