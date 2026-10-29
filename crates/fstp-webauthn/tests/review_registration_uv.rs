//! Reviewer reproducers (lane W2a, spec and security lens).
//!
//! ADR-008 "Expectations" says `RegistrationExpect` fixes user
//! verification, and "User verification" says the cell records whether
//! an applicant passkey gave UV. Design section 8.1 says the same. The
//! current API can neither require UV at registration nor report it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use common::authn::{Key, Reg, flags, reg_expect};
use fstp_webauthn::verify_registration;

/// ADR-008 "User verification", design section 8.1: a registration with
/// UV and one without must not verify to the same `NewCredential`, or
/// the cell cannot record whether UV was given.
#[test]
fn review_adr008_registration_reports_whether_uv_was_given() {
    let key = Key::ed25519(41);
    let with_uv = Reg::valid(&key);
    let mut without_uv = Reg::valid(&key);
    without_uv.flags = flags::UP | flags::AT;
    let a = verify_registration(&with_uv.response(), &reg_expect()).expect("with UV verifies");
    let b = verify_registration(&without_uv.response(), &reg_expect());
    assert_ne!(
        Ok(a),
        b,
        "UV given and UV absent verify to the same credential, so UV is not recorded"
    );
}

/// ADR-008 "Expectations", design section 8.1: `RegistrationExpect`
/// fixes user verification. It has no such field today, so a management
/// invitation ceremony cannot require UV for the first passkey.
#[test]
fn review_adr008_registration_expect_fixes_user_verification() {
    let shown = format!("{:?}", reg_expect());
    assert!(
        shown.contains("user_verification"),
        "RegistrationExpect carries no user verification expectation: {shown}"
    );
}
