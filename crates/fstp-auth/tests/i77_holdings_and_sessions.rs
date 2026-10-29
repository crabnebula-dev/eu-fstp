//! I-77 and R-LG-04 over the lane W2b production API: the holdings rule
//! of design section 8.2, user verification at login (ADR-008), the
//! binding end rule of Q16 A and the session lists of R-LG-04.
//!
//! Lane W2b implementer. The oracles below are written from design
//! section 8.2 and ADR-008, not from the production predicates.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod passkey;

use fstp_auth::session::{
    LoginRefusal, admit_login, admit_session_at, ended_between, ended_by_binding_end,
    ended_by_grant, listed_sessions, may_end_session, verify_passkey_login,
};
use fstp_auth::{
    AdminGrant, BindingFact, EnabledMethods, LoginDeny, Method, RosterView, SessionDeny,
    SessionLifetimes, SessionView, TenantView, holds_management,
};
use fstp_domain::id::AccountId;
use fstp_domain::roles::{Group, Role};
use fstp_domain::time::Timestamp;
use fstp_prop::{Gen, check, prop_assert_eq};

const T0: Timestamp = Timestamp::from_micros(1_700_000_000_000_000);

const fn at(us: i64) -> Timestamp {
    Timestamp::from_micros(T0.micros() + us)
}

const fn acct(n: u128) -> AccountId {
    AccountId::from_raw(n)
}

fn binding(n: u128, role: Role) -> BindingFact {
    BindingFact {
        account: acct(n),
        role,
        end: None,
        suspended: false,
        voided: false,
    }
}

fn session(id: u8, n: u128, method: Method, started: Timestamp) -> SessionView {
    SessionView {
        id: [id; 16],
        account: acct(n),
        method,
        started,
        last_used: started,
    }
}

fn holds(view: &RosterView, n: u128) -> bool {
    holds_management(view, &TenantView::default(), acct(n), T0).unwrap()
}

/// I-77, design section 8.2: a suspended binding still holds, whatever the
/// suspension's rule. The M2 roster's `held` drops a conflict-of-interest
/// suspension; this rule does not.
#[test]
fn i77_suspended_binding_still_holds() {
    let b = BindingFact {
        suspended: true,
        ..binding(7, Role::CommitteeMember)
    };
    assert!(holds(&RosterView::at(&[b], T0), 7));
}

/// I-77, design section 8.2: a voided binding never holds.
#[test]
fn i77_voided_binding_does_not_hold() {
    let b = BindingFact {
        voided: true,
        ..binding(7, Role::ProgrammeManager)
    };
    assert!(!holds(&RosterView::at(&[b], T0), 7));
}

/// I-77, design section 8.2: a binding with a scheduled end holds until
/// the end instant, and not at it.
#[test]
fn i77_scheduled_end_holds_until_its_instant() {
    let b = BindingFact {
        end: Some(at(10)),
        ..binding(7, Role::Auditor)
    };
    assert!(holds(&RosterView::at(&[b], at(9)), 7));
    assert!(!holds(&RosterView::at(&[b], at(10)), 7));
}

/// I-77: a Receiving binding is no management holding.
#[test]
fn i77_receiving_binding_does_not_hold() {
    for role in [Role::Applicant, Role::ApplicantTeamMember, Role::Guardian] {
        assert!(
            !holds(&RosterView::at(&[binding(7, role)], T0), 7),
            "{role:?}"
        );
    }
}

/// I-77, design section 8.2: the roster view lists exactly the accounts
/// with a binding outside Receiving that is not voided and has not
/// reached its end.
#[test]
fn i77_roster_view_follows_the_holdings_rule() {
    check(
        "i77_roster_view_follows_the_holdings_rule",
        |g: &mut Gen| {
            let facts: Vec<BindingFact> = g.vec(0..=6, |g| BindingFact {
                account: acct(u128::from(g.u8_in(1..=4))),
                role: *g.pick(&Role::ALL),
                end: g.option(|g| at(g.i64_in(-3..=3))),
                suspended: g.bool(),
                voided: g.bool(),
            });
            let now = at(g.i64_in(-3..=3));
            let who = acct(u128::from(g.u8_in(1..=4)));
            let want = facts.iter().any(|b| {
                b.account == who
                    && !b.voided
                    && b.role.group() != Group::Receiving
                    && b.end.is_none_or(|e| now < e)
            });
            let view = RosterView::at(&facts, now);
            prop_assert_eq!(view.management.contains(&who), want, "{facts:?} at {now:?}");
            Ok(())
        },
    );
}

/// I-77: the tenant view lists the admins whose grant has not reached its
/// end, and counts the others of an account once each.
#[test]
fn i77_tenant_view_counts_grants_before_their_end() {
    let grants = [
        AdminGrant {
            account: acct(1),
            end: None,
        },
        AdminGrant {
            account: acct(2),
            end: Some(at(5)),
        },
        AdminGrant {
            account: acct(1),
            end: None,
        },
    ];
    let before = TenantView::at(&grants, at(4));
    assert_eq!(before.admins, vec![acct(1), acct(2)]);
    assert_eq!(before.others(acct(1)), 1);
    let after = TenantView::at(&grants, at(5));
    assert_eq!(after.admins, vec![acct(1)]);
    assert_eq!(after.others(acct(1)), 0);
}

/// I-77, ADR-008 "User verification": a holder's login needs user
/// verification; another account's does not.
#[test]
fn i77_holder_login_needs_user_verification() {
    let e = EnabledMethods::default();
    assert_eq!(
        admit_login(true, Method::Passkey, false, &e),
        Err(LoginRefusal::NoUserVerification)
    );
    assert_eq!(admit_login(true, Method::Passkey, true, &e), Ok(()));
    assert_eq!(admit_login(false, Method::Passkey, false, &e), Ok(()));
}

/// I-77: the login rule is the method rule first, then user verification
/// for holders.
#[test]
fn i77_admit_login_is_method_rule_then_user_verification() {
    check(
        "i77_admit_login_is_method_rule_then_user_verification",
        |g: &mut Gen| {
            let holds = g.bool();
            let m = *g.pick(&Method::ALL);
            let uv = g.bool();
            let e = EnabledMethods {
                methods: g.vec(0..=4, |g| *g.pick(&Method::ALL)),
            };
            let method = if holds && !m.phishing_resistant() {
                Err(LoginDeny::WeakMethodForRole)
            } else if !m.built_in_m3() || !(m == Method::Passkey || e.methods.contains(&m)) {
                Err(LoginDeny::MethodDisabled)
            } else {
                Ok(())
            };
            let want = match method {
                Err(d) => Err(LoginRefusal::Method(d)),
                Ok(()) if holds && !uv => Err(LoginRefusal::NoUserVerification),
                Ok(()) => Ok(()),
            };
            prop_assert_eq!(admit_login(holds, m, uv, &e), want);
            Ok(())
        },
    );
}

/// I-77, ADR-008: a holder's passkey login without user verification is
/// refused after the assertion verifies; with it, the login passes.
#[test]
fn i77_passkey_login_of_holder_without_uv_refused() {
    let key = passkey::Passkey::new(3);
    let challenge = [0x11; 32];
    let e = EnabledMethods::default();
    let no_uv = key.assert(&challenge, 1, false);
    let uv = key.assert(&challenge, 1, true);
    assert_eq!(
        verify_passkey_login(true, &e, &no_uv, &key.stored(0), &passkey::rp(), challenge),
        Err(LoginRefusal::NoUserVerification)
    );
    assert!(verify_passkey_login(true, &e, &uv, &key.stored(0), &passkey::rp(), challenge).is_ok());
    assert!(
        verify_passkey_login(false, &e, &no_uv, &key.stored(0), &passkey::rp(), challenge).is_ok()
    );
}

/// ADR-008 "Sign counts": a sign count that goes down refuses the login
/// as a suspect credential.
#[test]
fn adr008_sign_count_regression_marks_the_credential_suspect() {
    let key = passkey::Passkey::new(4);
    let challenge = [0x12; 32];
    let a = key.assert(&challenge, 5, true);
    assert_eq!(
        verify_passkey_login(
            true,
            &EnabledMethods::default(),
            &a,
            &key.stored(9),
            &passkey::rp(),
            challenge
        ),
        Err(LoginRefusal::CredentialSuspect)
    );
}

/// I-77, Q16 A: a session that started before a binding end of its
/// account is refused from the end instant on.
#[test]
fn i77_binding_end_refuses_earlier_sessions_from_its_instant() {
    let s = session(1, 7, Method::Passkey, at(0));
    let ends = [at(100)];
    let p72 = SessionLifetimes::DEFAULT;
    assert_eq!(admit_session_at(true, &s, &ends, at(99), &p72), Ok(()));
    assert_eq!(
        admit_session_at(true, &s, &ends, at(100), &p72),
        Err(SessionDeny::SessionEnded)
    );
}

/// I-77, design section 8.2: a session that started at the end instant
/// did not start before it, so it stays live.
#[test]
fn i77_session_started_at_the_end_instant_stays_live() {
    let s = session(1, 7, Method::Passkey, at(100));
    assert_eq!(
        admit_session_at(true, &s, &[at(100)], at(101), &SessionLifetimes::DEFAULT),
        Ok(())
    );
}

/// I-77: `ended_between` is exactly an end in the half-open interval.
#[test]
fn i77_ended_between_is_the_half_open_interval() {
    check(
        "i77_ended_between_is_the_half_open_interval",
        |g: &mut Gen| {
            let ends: Vec<Timestamp> = g.vec(0..=4, |g| at(g.i64_in(-5..=5)));
            let after = at(g.i64_in(-5..=5));
            let upto = at(g.i64_in(-5..=5));
            let want = ends.iter().any(|e| after < *e && *e <= upto);
            prop_assert_eq!(ended_between(&ends, after, upto), want);
            Ok(())
        },
    );
}

/// I-77, ADR-008: a grant of a management role ends the account's weak
/// sessions in its batch, and no strong one.
#[test]
fn i77_grant_ends_the_weak_sessions_of_the_account_only() {
    let live = [
        session(1, 7, Method::MagicLink, at(0)),
        session(2, 7, Method::Passkey, at(0)),
        session(3, 8, Method::MagicLink, at(0)),
    ];
    assert_eq!(ended_by_grant(&live, acct(7)), vec![[1; 16]]);
}

/// I-77, Q16 A: the batch of a binding end at `at` ends every session of
/// the account that started at or before `at`.
#[test]
fn i77_binding_end_batch_ends_sessions_started_at_or_before_it() {
    let live = [
        session(1, 7, Method::Passkey, at(0)),
        session(2, 7, Method::MagicLink, at(10)),
        session(3, 7, Method::Passkey, at(11)),
        session(4, 8, Method::Passkey, at(0)),
    ];
    assert_eq!(
        ended_by_binding_end(&live, acct(7), at(10)),
        vec![[1; 16], [2; 16]]
    );
}

/// R-LG-04: an account sees and ends only its own live sessions.
#[test]
fn r_lg_04_only_own_live_sessions_listed_and_ended() {
    let live = [
        session(1, 7, Method::Passkey, at(0)),
        session(2, 8, Method::Passkey, at(0)),
        session(3, 7, Method::MagicLink, at(0)),
    ];
    let p72 = SessionLifetimes::DEFAULT;
    assert_eq!(
        listed_sessions(false, &live, acct(7), &[], at(1), &p72),
        vec![[1; 16], [3; 16]]
    );
    assert_eq!(
        listed_sessions(true, &live, acct(7), &[], at(1), &p72),
        vec![[1; 16]],
        "a holder's weak session is not live"
    );
    assert!(may_end_session(&live, acct(7), [1; 16]));
    assert!(!may_end_session(&live, acct(7), [2; 16]));
}
