//! The session checks of `gate::admit`, steps 1 and 2 of M3 design
//! section 5.4 (I-77, R-LG-01, R-LG-04, sections 8.2 and 17.2).
//!
//! - A session inside its P-72 idle and absolute lifetimes is admitted;
//!   one microsecond past either is refused as `SessionEnded`.
//! - A management holder (a Drafting, Judging or Operations binding, or
//!   tenant admin) is refused in a weak session, for any action.
//! - A session is refused as `SessionEnded` once any binding of its
//!   account ended after it started, including a scheduled end at its
//!   instant with no command run then (section 8.2).
//! - The session checks come before the step-up checks.
//! - `Admitted` carries the action, the account, no step-up for a low
//!   risk action, and the admission instant.
//!
//! Holdings come from the M2 roster, built by the M2 reference engine
//! over the corpus, and from the tenant fold. Lane W2c's test author wrote
//! these before the gate. They are red until `admit` lands (stub
//! `Deny::NotImplemented`) and the fold does (stub `NotImplemented`).
//!
//! Gaps, reported: `admit` takes a `&SessionView`, so `Deny::NoSession`
//! cannot be reached through it, and a break-glass principal cannot be
//! presented (SoD-08). The P-72 values are the proposed defaults: the
//! login policy form that would carry a tenant value is not defined
//! (`fstp_celltest::mc::auth_model::P72_SEAM`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use common::{
    MINUTE_US, NOW, P72_ABSOLUTE_US, P72_IDLE_US, admit_plain, as_cell, m2_entries, m2_run,
    m2_setup, magic, passkey, plus, session, state_of, with_admins,
};
use fstp_auth::Method;
use fstp_cell_core::gate::{Action, Deny, HighRiskAction, Principal};
use fstp_cell_core::tenant::TenantCommand;
use fstp_cell_core::text::TextCommand;
use fstp_cell_core::{CellCommand, CellState};
use fstp_domain::id::BindingId;
use fstp_domain::roles::Role;
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::roster::{
    A, ADMIN, ADMIN_2, B, C, P1, STAFF_DRAFTER, STAFF_PM, T0, end, grant,
};

/// A low-risk action: a text write.
fn low() -> Action {
    Action::Command(CellCommand::Text(TextCommand::PutText { id: [3; 16] }))
}

/// A high-risk action: a tenant admin grant.
fn high() -> Action {
    Action::Command(CellCommand::Tenant(TenantCommand::GrantTenantAdmin {
        account: ADMIN_2,
    }))
}

/// The cell over the M2 corpus: the programme manager and the call
/// drafter hold bindings from `T0`, and A is a committee member.
fn corpus() -> CellState {
    let mut s = m2_setup().unwrap();
    m2_run(
        &mut s,
        &grant(BindingId::from_raw(4_001), A, P1, Role::CommitteeMember, T0),
        T0,
    )
    .unwrap();
    state_of(&as_cell(&m2_entries(&s).unwrap())).unwrap()
}

/// The binding of C as a second programme manager.
const PM2: BindingId = BindingId::from_raw(301);

/// The cell over the M2 corpus in which C was granted programme manager
/// at `T0` and the end of that binding was decided at `decided` for
/// `at`. With `at == decided` the end is immediate, and with `at` later
/// it is scheduled (`BindingEndScheduled`).
fn with_end(decided: Timestamp, at: Timestamp) -> CellState {
    let mut s = m2_setup().unwrap();
    m2_run(&mut s, &grant(PM2, C, P1, Role::ProgrammeManager, T0), T0).unwrap();
    m2_run(&mut s, &end(PM2, at), decided).unwrap();
    state_of(&as_cell(&m2_entries(&s).unwrap())).unwrap()
}

/// The genesis cell.
fn genesis() -> CellState {
    state_of(&[]).unwrap()
}

// ---------------------------------------------------------------------------
// Admitted.

/// I-77, design section 5.4: a passkey session of an account with no
/// holding is admitted for a low-risk action. `Admitted` carries the
/// action, the session's account as principal, no step-up and the
/// admission instant.
#[test]
fn i77_admit_passkey_session_low_risk_action() {
    let a = admit_plain(&genesis(), &passkey(A), low(), NOW).unwrap();
    assert_eq!(a.action(), &low());
    assert_eq!(a.principal(), Principal::Account(A));
    assert_eq!(a.stepup(), None);
    assert_eq!(a.at(), NOW);
}

/// I-77, R-LG-01: an account that holds Receiving roles only may use a
/// magic-link session for a low-risk action. B holds nothing.
#[test]
fn i77_admit_magic_link_session_of_receiving_only_account() {
    let s = corpus();
    let a = admit_plain(&s, &magic(B), low(), NOW).unwrap();
    assert_eq!(a.principal(), Principal::Account(B));
}

// ---------------------------------------------------------------------------
// Holdings (step 2).

/// I-77: a tenant admin, by the tenant fold, is refused in a magic-link
/// session for every action, low risk included.
#[test]
fn i77_admit_refuses_weak_session_of_tenant_admin() {
    let s = with_admins(&[ADMIN]).unwrap();
    for action in [low(), high()] {
        assert_eq!(
            admit_plain(&s, &magic(ADMIN), action.clone(), NOW),
            Err(Deny::WeakSessionForRole),
            "{action:?}"
        );
    }
    assert!(admit_plain(&s, &passkey(ADMIN), low(), NOW).is_ok());
}

/// I-77: holders of Operations, Drafting and Judging bindings in the M2
/// roster (programme manager, call drafter, committee member) are refused
/// in a magic-link session. Their passkey sessions are admitted.
#[test]
fn i77_admit_refuses_weak_session_of_m2_binding_holders() {
    let s = corpus();
    for holder in [STAFF_PM, STAFF_DRAFTER, A] {
        assert_eq!(
            admit_plain(&s, &magic(holder), low(), NOW),
            Err(Deny::WeakSessionForRole),
            "{holder:?}"
        );
        assert!(
            admit_plain(&s, &passkey(holder), low(), NOW).is_ok(),
            "{holder:?}"
        );
    }
}

/// I-77, design section 8.2: a binding whose end is scheduled counts
/// until its instant, so its holder is still refused a weak session
/// before then.
#[test]
fn i77_scheduled_end_still_holds_before_its_instant() {
    let s = with_end(plus(NOW, -10 * MINUTE_US), plus(NOW, MINUTE_US));
    assert_eq!(
        admit_plain(&s, &magic(C), low(), NOW),
        Err(Deny::WeakSessionForRole)
    );
}

// ---------------------------------------------------------------------------
// Binding ends end sessions (section 8.2).

/// I-77, Q16, design section 8.2: an immediate binding end after the
/// session started ends the session. A session started after the end is
/// not ended by it.
#[test]
fn i77_binding_end_after_session_start_ends_the_session() {
    let ended_at = plus(NOW, -30 * 1_000_000);
    let s = with_end(ended_at, ended_at);
    assert_eq!(
        admit_plain(&s, &passkey(C), low(), NOW),
        Err(Deny::SessionEnded)
    );
    let later = session(0x53, C, Method::Passkey, plus(ended_at, 1), NOW);
    assert!(admit_plain(&s, &later, low(), NOW).is_ok());
}

/// I-77, design sections 5.1 and 8.2: a scheduled end ends every session
/// of the account at its instant, with no command run then and no
/// `EndSessionsAtBindingEnd` record. One microsecond before the instant
/// the session is admitted; at the instant it is refused.
#[test]
fn i77_scheduled_end_ends_sessions_at_its_instant() {
    let instant = NOW;
    let s = with_end(plus(NOW, -10 * MINUTE_US), instant);
    let used = plus(NOW, -MINUTE_US);
    let sess = session(0x54, C, Method::Passkey, plus(NOW, -2 * MINUTE_US), used);
    assert!(admit_plain(&s, &sess, low(), plus(instant, -1)).is_ok());
    assert_eq!(
        admit_plain(&s, &sess, low(), instant),
        Err(Deny::SessionEnded)
    );
}

// ---------------------------------------------------------------------------
// P-72 (step 1).

/// R-LG-04, P-72 (proposed: 30 minutes idle): a session last used just
/// inside the idle lifetime is admitted, and one used one microsecond
/// beyond it is refused as ended.
#[test]
fn r_lg_04_session_idle_lifetime_p72() {
    let s = genesis();
    let started = plus(NOW, -HOUR);
    let fresh = session(
        0x55,
        A,
        Method::Passkey,
        started,
        plus(NOW, -P72_IDLE_US + 1),
    );
    assert!(admit_plain(&s, &fresh, low(), NOW).is_ok());
    let idle = session(
        0x55,
        A,
        Method::Passkey,
        started,
        plus(NOW, -P72_IDLE_US - 1),
    );
    assert_eq!(admit_plain(&s, &idle, low(), NOW), Err(Deny::SessionEnded));
}

const HOUR: i64 = 60 * MINUTE_US;

/// R-LG-04, P-72 (proposed: 12 hours absolute): a session started just
/// inside the absolute lifetime is admitted, and one started one
/// microsecond earlier is refused, however recently it was used.
#[test]
fn r_lg_04_session_absolute_lifetime_p72() {
    let s = genesis();
    let inside = session(
        0x56,
        A,
        Method::Passkey,
        plus(NOW, -P72_ABSOLUTE_US + 1),
        NOW,
    );
    assert!(admit_plain(&s, &inside, low(), NOW).is_ok());
    let old = session(
        0x56,
        A,
        Method::Passkey,
        plus(NOW, -P72_ABSOLUTE_US - 1),
        NOW,
    );
    assert_eq!(admit_plain(&s, &old, low(), NOW), Err(Deny::SessionEnded));
}

// ---------------------------------------------------------------------------
// Order of the checks.

/// I-77, I-78, design section 5.4: the session checks run before the
/// step-up checks. An expired session asking a high-risk action without a
/// step-up is refused as ended, and a tenant admin's magic-link session
/// is refused as weak, not as missing a step-up.
#[test]
fn i77_session_checks_come_before_step_up_checks() {
    let s = with_admins(&[ADMIN]).unwrap();
    let old = session(
        0x57,
        ADMIN,
        Method::Passkey,
        plus(NOW, -P72_ABSOLUTE_US - 1),
        NOW,
    );
    assert_eq!(admit_plain(&s, &old, high(), NOW), Err(Deny::SessionEnded));
    assert_eq!(
        admit_plain(&s, &magic(ADMIN), high(), NOW),
        Err(Deny::WeakSessionForRole)
    );
    assert_eq!(
        admit_plain(&s, &passkey(ADMIN), high(), NOW),
        Err(Deny::StepUpRequired(HighRiskAction::ManagementRoleChange))
    );
}
