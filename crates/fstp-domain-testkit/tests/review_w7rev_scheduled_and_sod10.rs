//! Review reproducers for the W7 close-out (independent review).
//!
//! `SPEC/02-domain/roles-and-sod.md`, Cooling-off NOTE (decided
//! 2026-10-25): the binding stays held until the scheduled instant, and
//! its bar is pinned then, from the calls published by that instant.
//! Reviewer assignment (decided 2026-10-28): one organisation per reviewer
//! per programme (SoD-10).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::command::Command;
use fstp_domain::id::{BindingId, OrganisationId};
use fstp_domain::record::Record;
use fstp_domain::refusal::RuleRef;
use fstp_domain::roles::Role;
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::roster::{
    A, Backend, C, Facts, Flags, ID_AB, ID_C, P1, SodSetup, SodWorld, Step, T0, call, end, grant,
    publish, reinstate, sod_truth,
};

const SECOND: i64 = 1_000_000;

fn t(n: i64) -> Timestamp {
    Timestamp::from_micros(T0.micros().saturating_add(n.saturating_mul(SECOND)))
}

const PM: BindingId = BindingId::from_raw(301);

fn world() -> SodWorld {
    let mut setup = SodSetup::one(1, &[1, 2, 3]);
    setup.published = vec![call(1)];
    SodWorld::from_setup(Backend::Production, sod_truth(), &setup)
        .unwrap_or_else(|e| panic!("setup: {e}"))
}

fn run(w: &mut SodWorld, now: Timestamp, step: &Step) -> Result<Vec<Record>, RuleRef> {
    w.now = now;
    w.exec(step, Facts::Effective)
        .unwrap_or_else(|e| panic!("harness: {e}"))
        .map_err(|r| r.rule)
}

/// A `PublishCall` of `n` by c, as programme manager.
fn c_publishes(n: u128) -> Step {
    let staff = publish(call(n));
    Step::by(C, Flags::NONE, staff.cmd)
}

/// c holds programme manager from `T0`, with its end scheduled for
/// `t(10)`.
fn scheduled_pm() -> SodWorld {
    let mut w = world();
    run(&mut w, T0, &grant(PM, C, P1, Role::ProgrammeManager, T0))
        .unwrap_or_else(|r| panic!("the grant is refused under {r:?}"));
    run(&mut w, T0, &end(PM, t(10)))
        .unwrap_or_else(|r| panic!("the scheduled end is refused under {r:?}"));
    w
}

/// Cooling-off NOTE: "The binding stays held until that instant." At
/// `t(15)`, past the scheduled `t(10)`, c no longer holds programme
/// manager, even if the System has not yet recorded the end. Production
/// keeps the binding active until `EndScheduledRole` runs, so c still
/// publishes a call as programme manager. The control shows the same
/// publication is accepted at `t(5)`, while the binding is held.
#[test]
fn review_scheduled_end_binding_is_not_held_past_its_instant() {
    let mut control = scheduled_pm();
    let ok = run(&mut control, t(5), &c_publishes(2));
    assert!(
        ok.is_ok(),
        "control: c publishes as programme manager while held: {ok:?}"
    );
    let mut w = scheduled_pm();
    let late = run(&mut w, t(15), &c_publishes(2));
    assert!(
        late.is_err(),
        "Cooling-off NOTE: the binding is held only until t(10), yet c acts as programme manager at t(15): {late:?}"
    );
}

/// Cooling-off NOTE: the bar is pinned at the instant "from the calls
/// published by that instant". c's end is scheduled for `t(10)` with call
/// 1 published and P-12 = 1. Call 2 is published at `t(12)`, after the
/// instant, and the System records the end at `t(15)`. The bar must be
/// 1 + 1 = 2. Production reads the calls when the end is recorded, so it
/// pins 3. A fix that refuses the publication until the end is recorded
/// also passes this test.
#[test]
fn review_scheduled_end_bar_counts_only_calls_published_by_the_instant() {
    let mut w = scheduled_pm();
    if run(&mut w, t(12), &publish(call(2))).is_err() {
        return;
    }
    let at = w
        .arrive(t(15))
        .unwrap_or_else(|e| panic!("harness: {e}"))
        .unwrap_or_else(|r| panic!("the System end is refused: {r}"));
    let e = at
        .iter()
        .find_map(|r| match r {
            Record::BindingEnded(e) if e.binding == PM => Some(*e),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no end of c's binding: {at:?}"));
    assert_eq!(
        (e.at, e.barred_through),
        (t(10), 2),
        "Cooling-off NOTE: call 2 was published after the instant t(10), so it is not in the bar"
    );
}

/// SoD-10 (decided 2026-10-28): one organisation per reviewer per
/// programme. c's committee binding B1 records O-103, and a holds call
/// drafter in P1. The vault gives c the identity of a, so the reaction
/// suspends B1 as a conflict of interest. The vault then gives c its own
/// identity back. A second committee binding B2 of c now records O-999,
/// which the grant check allows because B1 is not held. Reinstating B1
/// would leave c holding two committee bindings with different
/// organisations in P1, so it must be refused. Production reinstates it.
#[test]
fn review_sod10_reinstatement_keeps_one_organisation_per_programme() {
    let b1 = BindingId::from_raw(311);
    let b2 = BindingId::from_raw(312);
    let drafter = BindingId::from_raw(321);
    let mut w = world();
    run(&mut w, T0, &grant(drafter, A, P1, Role::CallDrafter, T0))
        .unwrap_or_else(|r| panic!("a's call drafter binding is refused under {r:?}"));
    run(&mut w, T0, &grant(b1, C, P1, Role::CommitteeMember, T0))
        .unwrap_or_else(|r| panic!("B1 is refused under {r:?}"));
    w.truth.set_identity(C, ID_AB);
    w.sync(Facts::Effective)
        .unwrap_or_else(|e| panic!("harness: {e}"))
        .unwrap_or_else(|r| panic!("the reaction is refused: {r}"));
    let held = w.state.roster().binding(b1).is_some_and(|b| b.held());
    assert!(!held, "setup: B1 is suspended as a conflict of interest");
    w.truth.set_identity(C, ID_C);
    w.sync(Facts::Effective)
        .unwrap_or_else(|e| panic!("harness: {e}"))
        .unwrap_or_else(|r| panic!("the second reaction is refused: {r}"));
    let mut g = grant(b2, C, P1, Role::CommitteeMember, T0);
    if let Command::GrantRole { organisation, .. } = &mut g.cmd {
        *organisation = Some(OrganisationId::from_raw(999));
    }
    run(&mut w, T0, &g).unwrap_or_else(|r| panic!("setup: B2 is refused under {r:?}"));
    let out = run(&mut w, T0, &reinstate(b1));
    let both: Vec<Option<OrganisationId>> = w
        .state
        .roster()
        .bindings()
        .filter(|(_, b)| b.account == C && b.role == Role::CommitteeMember && b.held())
        .map(|(_, b)| b.organisation)
        .collect();
    assert_eq!(
        out.err(),
        Some(RuleRef::Sod10),
        "SoD-10: c would hold committee bindings of {both:?} in P1"
    );
}

/// Cooling-off NOTE: a scheduled end "can be brought forward", never moved
/// later. c's end is scheduled for `t(10)`. At `t(15)`, before the System
/// records it, the tenant admin sends `EndRole` at `t(15)`. Production
/// takes the `at == now` path and ends the binding at `t(15)`, later than
/// the scheduled instant. The end must stay at `t(10)`, or the command be
/// refused.
#[test]
fn review_scheduled_end_is_not_moved_later_by_an_end_at_now() {
    let mut w = scheduled_pm();
    let Ok(records) = run(&mut w, t(15), &end(PM, t(15))) else {
        return;
    };
    let at: Vec<Timestamp> = records
        .iter()
        .filter_map(|r| match r {
            Record::BindingEnded(e) if e.binding == PM => Some(e.at),
            _ => None,
        })
        .collect();
    assert!(
        at.iter().all(|x| *x <= t(10)),
        "Cooling-off NOTE: the end scheduled for t(10) was moved later, to {at:?}"
    );
}
