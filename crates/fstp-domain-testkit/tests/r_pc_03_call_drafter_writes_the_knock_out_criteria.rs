//! The roles table of `SPEC/02-domain/roles-and-sod.md`: the call drafter
//! writes the knock-out criteria, and the programme manager sets the
//! policy parameters (lane m4/fast-flow, decided by Daniel on 2026-11-12).
//!
//! - A call drafter may author a policy version whose only change is P-09.
//! - A call drafter may not change any other parameter, alone or with P-09.
//! - The drafter becomes the last author of P-09, so an approval made
//!   before the change no longer counts, and the call must be approved
//!   again by a programme manager who is no drafter (R-PC-03).
//! - The published call freezes the criteria the drafter wrote (I-12,
//!   R-EV-01 reads them at the knock-out check).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::id::CallId;
use fstp_domain::refusal::RuleRef;
use fstp_domain_testkit::r#gen::policy::{
    DRAFTER_1, P1, PM_A, PM_B, PolicyWorld, criteria, knock_outs,
};
use fstp_engine::ExecError;
use fstp_ledger::Seq;

fn world() -> PolicyWorld {
    PolicyWorld::new(false).unwrap_or_else(|e| panic!("{e}"))
}

fn refused(r: &Result<Seq, ExecError>, rule: RuleRef) -> bool {
    matches!(r, Err(ExecError::Refused(x)) if x.rule == rule)
}

/// R-PC-03, R-EV-01: the call drafter writes the knock-out criteria, and
/// the published call freezes them.
#[test]
fn r_pc_03_r_ev_01_call_drafter_writes_the_knock_out_criteria() {
    let mut w = world();
    assert!(w.draft(DRAFTER_1, 1, P1).unwrap().is_ok());
    let written = knock_outs(7_000);
    let r = w
        .edit(DRAFTER_1, P1, |v| v.frozen.p09 = written.clone())
        .unwrap();
    assert!(r.is_ok(), "the call drafter writes P-09: {r:?}");
    assert_eq!(w.head(P1).unwrap().frozen.p09, written);
    assert!(w.approve(PM_B, 1).is_ok());
    assert!(w.publish(PM_A, 1).unwrap().is_ok());
    let frozen = w
        .state()
        .calls()
        .get(CallId::from_raw(1))
        .and_then(|c| c.frozen())
        .map(|f| f.values().p09.clone());
    assert_eq!(frozen, Some(written), "the call freezes the drafter's P-09");
}

/// The roles table: a call drafter sets no other policy parameter, alone
/// or together with P-09.
#[test]
fn r_pc_03_call_drafter_changes_no_other_parameter() {
    let mut w = world();
    let r = w
        .edit(DRAFTER_1, P1, |v| {
            v.frozen.p01 = criteria(4, [20, 50, 30]).unwrap()
        })
        .unwrap();
    assert!(refused(&r, RuleRef::Actor), "P-01 alone: {r:?}");
    let r = w
        .edit(DRAFTER_1, P1, |v| {
            v.frozen.p09 = knock_outs(7_000);
            v.frozen.p01 = criteria(4, [20, 50, 30]).unwrap();
        })
        .unwrap();
    assert!(refused(&r, RuleRef::Actor), "P-09 with P-01: {r:?}");
    let r = w
        .edit(DRAFTER_1, P1, |v| {
            v.frozen.p09 = knock_outs(7_000);
            v.live.opaque.clear();
        })
        .unwrap();
    assert!(refused(&r, RuleRef::Actor), "P-09 with a live value: {r:?}");
}

/// R-PC-03 NOTE: a P-09 change after the approval makes the drafter its
/// last author, so publication on the earlier approval is refused, and a
/// programme manager who is no drafter approves again.
#[test]
fn r_pc_03_knock_out_change_after_approval_needs_a_new_approval() {
    let mut w = world();
    assert!(w.draft(DRAFTER_1, 1, P1).unwrap().is_ok());
    assert!(w.approve(PM_B, 1).is_ok());
    let r = w
        .edit(DRAFTER_1, P1, |v| v.frozen.p09 = knock_outs(7_000))
        .unwrap();
    assert!(r.is_ok(), "{r:?}");
    let r = w.publish(PM_A, 1).unwrap();
    assert!(r.is_err(), "the earlier approval no longer counts: {r:?}");
    assert!(w.approve(PM_B, 1).is_ok());
    assert!(w.publish(PM_A, 1).unwrap().is_ok());
}
