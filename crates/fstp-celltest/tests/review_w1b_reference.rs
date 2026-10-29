//! Review reproducers for lane W1b (reference fidelity). Each test fails
//! against the current reference, models or tests, and passes once the
//! defect it names is fixed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_celltest::mc::auth_model::{self as m, AuthModel, END_AT};
use fstp_celltest::reference::auth::{
    self as r, RefApproval, RefApprovalDeny, RefLifetimes, RefMethod, RefSession,
};
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::roster::{A, ADMIN_2, T0};
use fstp_mc::{Config, explore};

/// I-79, design section 8.5 and ADR-008 "Recovery": a vault outage refuses
/// the approval (fail closed). Whether both accounts are verified is
/// itself a vault fact, so an unanswered vault must refuse even when the
/// caller reports "not both verified".
#[test]
fn review_i79_vault_outage_refuses_approval_whatever_the_verification_flag() {
    let a = RefApproval {
        approver: ADMIN_2,
        approver_admin: true,
        stepup_ok: true,
        same_identity: None,
        both_verified: false,
    };
    assert_eq!(
        r::approve_recovery(A, &a),
        Err(RefApprovalDeny::VaultDown),
        "the reference approved a recovery while the vault could not answer"
    );
}

/// I-77, Q16 A: `i77_scheduled_end_ends_sessions_at_its_instant` starts its
/// session at T0 and probes it at END_AT minus 1 µs, END_AT and END_AT plus
/// 1 µs. That is about 1999 s after T0, beyond the 30 minute P-72 idle
/// lifetime. The reference refuses the session as expired at every probe,
/// so the scenario cannot tell a gate that ignores binding ends from one
/// that honours them. The session must be live just before the end.
#[test]
fn review_i77_scheduled_end_scenario_session_is_live_before_the_end() {
    let s = RefSession {
        id: [0x11; 16],
        account: A,
        method: RefMethod::Passkey,
        device: Some(0),
        started: T0,
        last_used: T0,
        ended: None,
    };
    let before = Timestamp::from_micros(END_AT.micros() - 1);
    assert_eq!(
        r::admit_session(true, &s, false, before, RefLifetimes::DEFAULT),
        Ok(()),
        "the scenario's session is already refused 1 µs before the end instant"
    );
}

/// I-77, design section 14.4: the HTTP machine
/// `i77_management_login_requires_phishing_resistant_method_over_http`
/// must drive suspensions. It draws its actions from M-AUTH, and no
/// reachable M-AUTH state holds a suspended binding. The M2 roster's
/// `held` excludes a conflict-of-interest suspension, while design section
/// 8.2 counts it (m3-base note 2), so nothing checks production there.
#[test]
fn review_i77_http_machine_drives_a_suspended_binding() {
    let space = explore(&AuthModel::new(m::Reference), &Config::default());
    assert!(space.exhaustive, "M-AUTH over the reference did not finish");
    let suspended = space
        .states()
        .any(|s| s.roster().bindings.iter().any(|b| b.suspended));
    assert!(
        suspended,
        "no reachable M-AUTH state, and so no HTTP machine step, holds a suspended binding"
    );
}
