//! `fstp_auth::holds_management`: the holdings that I-77 and I-79 read
//! (design section 8.2, ADR-008 "Methods in M3", m3-base re-derivation 2).
//!
//! A holding is a Drafting, Judging or Operations binding, or a tenant
//! admin grant. With the W0 `RosterView`, the caller has already listed
//! the accounts with a management binding, so `holds_management` is the
//! union of that list and the current tenant admins.
//!
//! Gap, reported by lane W2b's test author: design section 8.2 and the
//! m3-base re-derivation ask `holds_management` itself to count active,
//! scheduled and suspended bindings, and not voided ones, until each end
//! instant. They also forbid reusing the M2 roster's `held` predicate,
//! which drops a conflict-suspended binding. `RosterView` holds no binding
//! states or instants, so no test here can reach that rule. The W1b test
//! `i77_suspended_holder_magic_link_login_is_refused` and M-AUTH over
//! production check it at the gate.
//!
//! Lane W2b test author. Red until lane W2b lands `holds_management`,
//! because the W0 stub refuses every call with `NotImplemented`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use common::{T0, account, real};
use fstp_auth::{RosterView, TenantView, holds_management};
use fstp_domain::time::Timestamp;
use fstp_prop::{Gen, check, prop_assert_eq};

/// The answer, or a panic that names the stub.
#[track_caller]
fn holds(roster: &RosterView, tenant: &TenantView, n: u128) -> bool {
    match holds_management(roster, tenant, account(n), T0) {
        Ok(h) => h,
        Err(e) => panic!("holds_management refused: {e:?}"),
    }
}

/// I-77: an account with a management binding holds.
#[test]
fn i77_binding_holder_holds() {
    let roster = RosterView {
        management: vec![account(101)],
    };
    assert!(holds(&roster, &TenantView::default(), 101));
}

/// I-77: a tenant admin holds, with no binding at all.
#[test]
fn i77_tenant_admin_holds() {
    let tenant = TenantView {
        admins: vec![account(1)],
    };
    assert!(holds(&RosterView::default(), &tenant, 1));
}

/// I-77: an account in neither list does not hold, so it may use a magic
/// link where the tenant enables one.
#[test]
fn i77_account_outside_both_lists_does_not_hold() {
    let roster = RosterView {
        management: vec![account(101)],
    };
    let tenant = TenantView {
        admins: vec![account(1)],
    };
    assert!(!holds(&roster, &tenant, 102));
}

/// I-77, I-79: `holds_management` is exactly the union of the binding
/// holders and the tenant admins, at any instant.
#[test]
fn i77_holds_management_is_the_union_of_both_lists() {
    check(
        "i77_holds_management_is_the_union_of_both_lists",
        |g: &mut Gen| {
            let management: Vec<_> = g.vec(0..=4, |g| account(u128::from(g.u8_in(1..=6))));
            let admins: Vec<_> = g.vec(0..=3, |g| account(u128::from(g.u8_in(1..=6))));
            let who = account(u128::from(g.u8_in(1..=6)));
            let now = Timestamp::from_micros(g.i64());
            let want = management.contains(&who) || admins.contains(&who);
            let roster = RosterView { management };
            let tenant = TenantView { admins };
            let got = holds_management(&roster, &tenant, who, now);
            real("holds_management", &got)?;
            prop_assert_eq!(got, Ok(want), "{roster:?} {tenant:?} for {who:?}");
            Ok(())
        },
    );
}
