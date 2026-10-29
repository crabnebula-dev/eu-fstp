//! Review reproducer (adversarial review of lane W2b, round 2).
//!
//! ADR-008 "User verification" and design section 8.1 require user
//! verification for management accounts. This crate applies that rule at
//! registration: `ceremony::verify_new_passkey` refuses a passkey without
//! UV for a holder or the first admin, in the invitation and `AddPasskey`
//! ceremonies. `recovery::Revocation::new_credential` documents the same
//! rule for recovery: "UV is required unless the path is
//! `EmailThenPasskey`".
//!
//! `recovery::complete` does not apply it. A tenant admin recovered by
//! `SecondAdmin` gets a new passkey registered with `user_verified:
//! false`. The path is only known inside `complete`, so the caller cannot
//! pick the UV rule before it either. The test fails today and passes
//! once `complete` refuses a credential without UV on every path but
//! `EmailThenPasskey`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code asserts on known-good values"
)]

use fstp_auth::recovery::{
    Approval, Case, Deployment, Evidence, IdentityFacts, RecoveryPath, Revocation, complete,
};
use fstp_auth::{RosterView, TenantView};
use fstp_domain::id::AccountId;
use fstp_webauthn::{CoseKey, NewCredential};

/// I-79 and I-77: a `SecondAdmin` recovery of a tenant admin refuses a
/// new passkey that gave no user verification.
#[test]
fn review_i79_second_admin_completion_refuses_a_passkey_without_uv() {
    let holder = AccountId::from_raw(1);
    let admin2 = AccountId::from_raw(2);
    let tenant = TenantView {
        admins: vec![holder, admin2],
    };
    let roster = RosterView::default();
    let approval = Approval::new(
        admin2,
        &tenant,
        Ok(()),
        Ok(IdentityFacts {
            both_verified: false,
            same_identity: false,
        }),
    );
    let case = Case {
        case: [0xCA; 16],
        holder,
        requested: RecoveryPath::SecondAdmin,
        evidence: Evidence {
            email: true,
            approval: Some(approval),
            ticket: None,
            host_console: false,
        },
    };
    let no_uv = NewCredential {
        id: vec![0x09; 16],
        key: CoseKey::Ed25519 { x: [0x03; 32] },
        sign_count: 0,
        user_verified: false,
    };
    let revocation = Revocation {
        credentials: &[],
        sessions: &[],
        new_credential: &no_uv,
    };
    let got = complete(&case, &roster, &tenant, Deployment::Saas, &revocation);
    assert!(
        got.is_err(),
        "a tenant admin's recovery registered a passkey without user verification: {got:?}"
    );
}
