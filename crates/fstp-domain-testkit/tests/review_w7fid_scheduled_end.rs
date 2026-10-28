//! Reviewer reproducers for scheduled role ends (Cooling-off NOTE, decided
//! 2026-10-25): "The binding stays held until that instant. Its bar is
//! pinned then, from the calls published by that instant and the P-12
//! value in force at it."
//!
//! Each story runs a command after the scheduled instant but before the
//! System has recorded the end. The M6 timeline cannot run `due` at the
//! exact instant, so this window is always open.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::id::{BindingId, PolicyVersionId};
use fstp_domain::record::Record;
use fstp_domain::refusal::RuleRef;
use fstp_domain::roles::{CoolingOff, Role};
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::roster::{
    Backend, C, Facts, P1, SodSetup, SodWorld, T0, call, edit_policy, end, grant, publish,
    sod_truth,
};

const SECOND: i64 = 1_000_000;

fn t(n: i64) -> Timestamp {
    Timestamp::from_micros(T0.micros().saturating_add(n.saturating_mul(SECOND)))
}

const CM: BindingId = BindingId::from_raw(301);
const IRC: BindingId = BindingId::from_raw(302);

/// P-12 = 1, calls 1 to 3 drafted, call 1 published. c is a committee
/// member from `T0`, with its end scheduled for `t(10)`.
fn world() -> (SodSetup, SodWorld) {
    let mut setup = SodSetup::one(1, &[1, 2, 3]);
    setup.published = vec![call(1)];
    let mut w = SodWorld::from_setup(Backend::Production, sod_truth(), &setup)
        .unwrap_or_else(|e| panic!("setup: {e}"));
    w.now = T0;
    w.exec(
        &grant(CM, C, P1, Role::CommitteeMember, T0),
        Facts::Effective,
    )
    .unwrap_or_else(|e| panic!("harness: {e}"))
    .unwrap_or_else(|r| panic!("the grant is refused: {r}"));
    w.exec(&end(CM, t(10)), Facts::Effective)
        .unwrap_or_else(|e| panic!("harness: {e}"))
        .unwrap_or_else(|r| panic!("the scheduled end is refused: {r}"));
    (setup, w)
}

/// The committee binding of c ends at `t(10)`. At `t(11)` it is no longer
/// held, so an IRC member grant to c is judged as after the end. With the
/// System end already recorded the grant is accepted. Without it, the
/// verdict must be the same: the instant, not the System's bookkeeping,
/// ends the binding.
#[test]
fn review_w7fid_scheduled_end_binding_is_not_held_after_the_instant() {
    let (_, mut ended) = world();
    ended
        .arrive(t(10))
        .unwrap_or_else(|e| panic!("harness: {e}"))
        .unwrap_or_else(|r| panic!("the System end is refused: {r}"));
    ended.now = t(11);
    let after_end = ended
        .exec(&grant(IRC, C, P1, Role::IrcMember, t(11)), Facts::Effective)
        .unwrap_or_else(|e| panic!("harness: {e}"));
    assert!(
        after_end.is_ok(),
        "baseline: the IRC grant after the recorded end is accepted: {after_end:?}"
    );

    let (_, mut w) = world();
    w.now = t(11);
    let before_system = w
        .exec(&grant(IRC, C, P1, Role::IrcMember, t(11)), Facts::Effective)
        .unwrap_or_else(|e| panic!("harness: {e}"));
    let rule = before_system.as_ref().err().map(|r| r.rule);
    assert!(
        !matches!(rule, Some(RuleRef::I02 | RuleRef::Sod02 | RuleRef::Sod01)),
        "Cooling-off NOTE: the binding stays held only until t(10), yet at t(11) the grant is refused as if it were held: {before_system:?}"
    );
}

/// The end is scheduled for `t(10)`, when call 1 is the latest published
/// call and P-12 is 1, so the bar is 2. Call 2 is published at `t(11)`,
/// after the instant, and the System records the end at `t(12)`. The bar
/// must still be 2, from the calls published by the instant.
#[test]
fn review_w7fid_scheduled_end_bar_ignores_calls_published_after_the_instant() {
    let (_, mut w) = world();
    w.now = t(11);
    let published = w
        .exec(&publish(call(2)), Facts::Effective)
        .unwrap_or_else(|e| panic!("harness: {e}"));
    if published.is_err() {
        // A fix may refuse the publication while the end is overdue.
        return;
    }
    let at = w
        .arrive(t(12))
        .unwrap_or_else(|e| panic!("harness: {e}"))
        .unwrap_or_else(|r| panic!("the System end is refused: {r}"));
    let e = at
        .iter()
        .find_map(|r| match r {
            Record::BindingEnded(e) if e.binding == CM => Some(*e),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no end of c's binding: {at:?}"));
    assert_eq!(
        (e.at, e.barred_through),
        (t(10), 2),
        "Cooling-off NOTE: the bar is pinned at t(10) from call 1 and P-12 = 1, not from call 2 published at t(11)"
    );
}

/// The end is scheduled for `t(10)` with P-12 = 1. P-12 is raised to 3 at
/// `t(11)`, after the instant, and the System records the end at `t(12)`.
/// The end must pin the P-12 value in force at the instant.
#[test]
fn review_w7fid_scheduled_end_pins_the_p12_in_force_at_the_instant() {
    let (setup, mut w) = world();
    let head = setup.version(P1).unwrap_or_else(|e| panic!("head: {e}"));
    let raise = edit_policy(&head, PolicyVersionId::from_raw(2), |v| {
        v.live.p12 = CoolingOff(3);
    });
    w.now = t(11);
    let edited = w
        .exec(&raise, Facts::Effective)
        .unwrap_or_else(|e| panic!("harness: {e}"));
    if edited.is_err() {
        // A fix may refuse the edit while the end is overdue.
        return;
    }
    let at = w
        .arrive(t(12))
        .unwrap_or_else(|e| panic!("harness: {e}"))
        .unwrap_or_else(|r| panic!("the System end is refused: {r}"));
    let e = at
        .iter()
        .find_map(|r| match r {
            Record::BindingEnded(e) if e.binding == CM => Some(*e),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no end of c's binding: {at:?}"));
    assert_eq!(
        (e.p12, e.barred_through),
        (CoolingOff(1), 2),
        "Cooling-off NOTE: the end pins the P-12 in force at t(10), not the value edited at t(11)"
    );
}

/// The end is scheduled for `t(10)`. At `t(15)`, before the System has
/// recorded it, the tenant admin ends the binding "now". That moves the
/// end later than the scheduled instant, which the Cooling-off NOTE never
/// allows. Either the command is refused, or the end it records lies at
/// the scheduled instant.
#[test]
fn review_w7fid_overdue_scheduled_end_is_not_moved_later_by_an_end_now() {
    let (_, mut w) = world();
    w.now = t(15);
    let out = w
        .exec(&end(CM, t(15)), Facts::Effective)
        .unwrap_or_else(|e| panic!("harness: {e}"));
    let Ok(records) = out else {
        return;
    };
    let at = records.iter().find_map(|r| match r {
        Record::BindingEnded(e) if e.binding == CM => Some(e.at),
        _ => None,
    });
    assert!(
        at.is_none_or(|a| a <= t(10)),
        "Cooling-off NOTE: the end scheduled for t(10) is moved later, to {at:?}"
    );
}
