//! I-01, SoD-05: scheduled role ends (Cooling-off NOTE, decided 2026-10-25).
//!
//! `SPEC/02-domain/roles-and-sod.md`, Cooling-off: an end may be scheduled
//! for a later instant, when the role is granted or afterwards. The
//! binding stays held until that instant. Its bar is pinned then, from the
//! calls published by that instant and the P-12 value in force at it. A
//! scheduled end can be brought forward, never moved earlier than the
//! current time.
//!
//! The API under test, which the stub interface does not declare yet:
//!
//! - `EndRole { binding, at }` with `at` after `ctx.now` schedules the end.
//! - `GrantRole` gains an optional `end`, its JSON member `end`.
//! - The scheduled end is recorded as `BindingEndScheduled { binding, at }`.
//! - `due(state, at)` lists a System command at the instant, and that
//!   command records `BindingEnded` with the bar pinned then.
//!
//! The tests reach the new member and record through their JSON forms, so
//! they compile against the stubs and fail until the API exists. Every
//! step is compared with the roles reference verdict in both directions.
//! Each `_on_the_reference` twin runs the same story on the reference alone.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::id::{BindingId, PolicyVersionId, ProposalId};
use fstp_domain::record::Record;
use fstp_domain::refusal::RuleRef;
use fstp_domain::roles::{CoolingOff, Role};
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::roster::{
    Backend, C, Facts, P1, SodSetup, SodWorld, Step, T0, call, draft, edit_policy, end, grant,
    grant_until, publish, sod_truth,
};
use fstp_domain_testkit::reference::sod::{
    Verdict, check_due_ends, check_ended, check_scheduled, expected_scheduled, scheduled_end_of,
    verdict,
};

/// One second.
const SECOND: i64 = 1_000_000;

/// `T0` plus `n` seconds.
fn t(n: i64) -> Timestamp {
    Timestamp::from_micros(T0.micros().saturating_add(n.saturating_mul(SECOND)))
}

/// The programme manager binding of c in these stories.
const PM: BindingId = BindingId::from_raw(301);

/// P-12 = 1, calls 1 to 3 drafted, call 1 published, from genesis.
fn world(b: Backend) -> (SodSetup, SodWorld) {
    let mut setup = SodSetup::one(1, &[1, 2, 3]);
    setup.published = vec![call(1)];
    let w = SodWorld::from_setup(b, sod_truth(), &setup).unwrap_or_else(|e| panic!("setup: {e}"));
    (setup, w)
}

/// Runs `step` at `now` and compares it with the reference verdict in both
/// directions. An accepted end or scheduled end must record what the
/// reference expects. Returns the records, or the refusal's rule.
fn judged(
    w: &mut SodWorld,
    now: Timestamp,
    step: &Step,
    what: &str,
) -> Result<Vec<Record>, RuleRef> {
    w.now = now;
    let ask = step.ask(now);
    let v = verdict(&w.view, &w.truth, &ask);
    let scheduled = expected_scheduled(&ask);
    let before = w.view.clone();
    let out = w
        .exec(step, Facts::Effective)
        .unwrap_or_else(|e| panic!("{what}: harness: {e}"));
    match (&v, &out) {
        (Verdict::Accept, Err(r)) => {
            panic!("{what}: over-denial, the reference accepts, production refuses with {r}")
        }
        (Verdict::Refuse(why), Ok(records)) => panic!(
            "{what}: over-permission, the reference refuses ({why}), production accepts with {records:?}"
        ),
        _ => {}
    }
    let records = out.map_err(|r| r.rule)?;
    if v.accepts() {
        if let Some((binding, at)) = scheduled {
            check_scheduled(what, binding, at, &records).unwrap_or_else(|e| panic!("{e}"));
        } else if let fstp_domain::command::Command::EndRole { binding, at } = &step.cmd {
            check_ended(what, &before, *binding, *at, &records).unwrap_or_else(|e| panic!("{e}"));
        }
    }
    Ok(records)
}

/// Moves the world to `at` and runs every System command due then. The
/// ends must be exactly the scheduled ends the reference finds due, each
/// with the bar pinned at `at`.
fn arrive(w: &mut SodWorld, at: Timestamp) -> Vec<Record> {
    let before = w.view.clone();
    let records = w
        .arrive(at)
        .unwrap_or_else(|e| panic!("the System commands due at {at:?}: harness: {e}"))
        .unwrap_or_else(|r| panic!("a System command due at {at:?} was refused: {r}"));
    check_due_ends(&before, at, &records).unwrap_or_else(|e| panic!("{e}"));
    records
}

/// Whether `records` end `binding`.
fn ends(records: &[Record], binding: BindingId) -> bool {
    records
        .iter()
        .any(|r| matches!(r, Record::BindingEnded(e) if e.binding == binding))
}

/// The draft of c's proposal `n` in `call_n`.
fn draft_of(n: u128, call_n: u128) -> Step {
    draft(
        C,
        ProposalId::from_raw(n),
        call(call_n),
        BindingId::from_raw(n.saturating_add(400)),
        false,
    )
}

/// c is granted programme manager at `T0`, and its end is scheduled for
/// `t(10)`. Until then the binding is held: no end is recorded, and c's
/// draft in call 1 is refused under SoD-01, not SoD-05. At `t(10)` the
/// System records the end, and the binding no longer counts as held.
fn held_until_the_instant(b: Backend) {
    let (_, mut w) = world(b);
    judged(
        &mut w,
        T0,
        &grant(PM, C, P1, Role::ProgrammeManager, T0),
        "the grant",
    )
    .unwrap_or_else(|r| panic!("the grant is refused under {r:?}"));
    let recs = judged(&mut w, T0, &end(PM, t(10)), "the scheduled end").unwrap_or_else(|r| {
        panic!("Cooling-off NOTE: an end at a later instant is scheduled, refused under {r:?}")
    });
    assert!(!ends(&recs, PM), "the binding stays held: {recs:?}");
    let refused = judged(&mut w, t(5), &draft_of(1, 1), "c's draft while held");
    assert_eq!(
        refused.err(),
        Some(RuleRef::Sod01),
        "SoD-01: the binding is held until the scheduled instant"
    );
    assert!(
        w.view.bindings.get(&PM).is_some_and(|x| x.held()),
        "the reference still holds the binding at t(5)"
    );
    let at = arrive(&mut w, t(10));
    assert!(
        ends(&at, PM),
        "the System ends the binding at t(10): {at:?}"
    );
    assert!(
        w.view.bindings.get(&PM).is_some_and(|x| !x.held()),
        "the binding no longer counts as held"
    );
}

/// I-01, SoD-01 (Cooling-off NOTE): a binding with a scheduled end is held
/// until the instant.
#[test]
fn i01_scheduled_end_keeps_the_binding_held_until_the_instant() {
    held_until_the_instant(Backend::Production);
}

/// I-01, SoD-01 (Cooling-off NOTE): the same story on the reference alone.
#[test]
fn i01_scheduled_end_keeps_the_binding_held_until_the_instant_on_the_reference() {
    held_until_the_instant(Backend::Reference);
}

/// c's end is scheduled at `T0` for `t(10)`, while call 1 is the latest
/// published call and P-12 is 1. Before the instant, call 2 is published
/// and P-12 is raised to 2. The bar is pinned at `t(10)`: 2 + 2 = 4, not
/// 1 + 1 = 2. So once call 3 is published, c's draft in it is refused
/// under SoD-05.
fn bar_pinned_at_the_instant(b: Backend) {
    let (setup, mut w) = world(b);
    judged(
        &mut w,
        T0,
        &grant(PM, C, P1, Role::ProgrammeManager, T0),
        "the grant",
    )
    .unwrap_or_else(|r| panic!("the grant is refused under {r:?}"));
    judged(&mut w, T0, &end(PM, t(10)), "the scheduled end")
        .unwrap_or_else(|r| panic!("the scheduled end is refused under {r:?}"));
    w.now = t(2);
    w.exec(&publish(call(2)), Facts::Effective)
        .unwrap_or_else(|e| panic!("harness: {e}"))
        .unwrap_or_else(|r| panic!("the publication of call 2 is refused: {r}"));
    let head = setup.version(P1).unwrap_or_else(|e| panic!("head: {e}"));
    let raise = edit_policy(&head, PolicyVersionId::from_raw(2), |v| {
        v.live.p12 = CoolingOff(2);
    });
    w.now = t(3);
    w.exec(&raise, Facts::Effective)
        .unwrap_or_else(|e| panic!("harness: {e}"))
        .unwrap_or_else(|r| panic!("the P-12 edit is refused: {r}"));
    let at = arrive(&mut w, t(10));
    let e = at
        .iter()
        .find_map(|r| match r {
            Record::BindingEnded(e) if e.binding == PM => Some(*e),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no end of c's binding at t(10): {at:?}"));
    assert_eq!(
        (e.at, e.barred_through, e.p12),
        (t(10), 4, CoolingOff(2)),
        "SoD-05: the bar is pinned at the instant, from call 2 and P-12 = 2"
    );
    w.now = t(11);
    w.exec(&publish(call(3)), Facts::Effective)
        .unwrap_or_else(|e| panic!("harness: {e}"))
        .unwrap_or_else(|r| panic!("the publication of call 3 is refused: {r}"));
    let inside = judged(&mut w, t(12), &draft_of(2, 3), "c's draft in call 3");
    assert_eq!(
        inside.err(),
        Some(RuleRef::Sod05),
        "SoD-05: call 3 lies inside the bar 4 pinned at the instant"
    );
}

/// I-01, SoD-05 (Cooling-off NOTE): the bar of a scheduled end is pinned at
/// the instant, from the calls published by then and the P-12 value then.
#[test]
fn i01_scheduled_end_pins_the_bar_at_the_instant() {
    bar_pinned_at_the_instant(Backend::Production);
}

/// I-01, SoD-05 (Cooling-off NOTE): the same story on the reference alone.
#[test]
fn i01_scheduled_end_pins_the_bar_at_the_instant_on_the_reference() {
    bar_pinned_at_the_instant(Backend::Reference);
}

/// c's end is scheduled for `t(20)`. At `t(5)` it is brought forward to
/// `t(10)`. The System ends the binding at `t(10)`, and nothing is due at
/// `t(20)`.
fn brought_forward(b: Backend) {
    let (_, mut w) = world(b);
    judged(
        &mut w,
        T0,
        &grant(PM, C, P1, Role::ProgrammeManager, T0),
        "the grant",
    )
    .unwrap_or_else(|r| panic!("the grant is refused under {r:?}"));
    judged(&mut w, T0, &end(PM, t(20)), "the scheduled end")
        .unwrap_or_else(|r| panic!("the scheduled end is refused under {r:?}"));
    judged(&mut w, t(5), &end(PM, t(10)), "the end brought forward").unwrap_or_else(|r| {
        panic!("Cooling-off NOTE: a scheduled end can be brought forward, refused under {r:?}")
    });
    assert!(
        arrive(&mut w, t(9)).is_empty(),
        "nothing is due before t(10)"
    );
    let at = arrive(&mut w, t(10));
    let e = at.iter().find_map(|r| match r {
        Record::BindingEnded(e) if e.binding == PM => Some(e.at),
        _ => None,
    });
    assert_eq!(
        e,
        Some(t(10)),
        "the binding ends at the earlier instant: {at:?}"
    );
    assert!(arrive(&mut w, t(20)).is_empty(), "nothing is due at t(20)");
}

/// I-01, SoD-05 (Cooling-off NOTE): a scheduled end can be brought forward.
#[test]
fn i01_scheduled_end_can_be_brought_forward() {
    brought_forward(Backend::Production);
}

/// I-01, SoD-05 (Cooling-off NOTE): the same story on the reference alone.
#[test]
fn i01_scheduled_end_can_be_brought_forward_on_the_reference() {
    brought_forward(Backend::Reference);
}

/// I-01, SoD-05 (Cooling-off NOTE): a scheduled end is never moved later.
/// c's end is scheduled for `t(10)`, and an `EndRole` at `t(20)` is
/// refused.
#[test]
fn i01_scheduled_end_is_never_moved_later() {
    let (_, mut w) = world(Backend::Production);
    judged(
        &mut w,
        T0,
        &grant(PM, C, P1, Role::ProgrammeManager, T0),
        "the grant",
    )
    .unwrap_or_else(|r| panic!("the grant is refused under {r:?}"));
    judged(&mut w, T0, &end(PM, t(10)), "the scheduled end")
        .unwrap_or_else(|r| panic!("the scheduled end is refused under {r:?}"));
    let later = judged(&mut w, t(1), &end(PM, t(20)), "the end moved later");
    assert!(
        later.is_err(),
        "Cooling-off NOTE: a scheduled end is never moved later: {later:?}"
    );
    let at = arrive(&mut w, t(10));
    assert!(ends(&at, PM), "the binding still ends at t(10): {at:?}");
}

/// I-01, SoD-05 (Cooling-off NOTE): a scheduled end is never moved earlier
/// than the current time. c's end is scheduled for `t(20)`. At `t(10)` an
/// `EndRole` at `t(5)` is refused.
#[test]
fn i01_scheduled_end_is_never_moved_before_now() {
    let (_, mut w) = world(Backend::Production);
    judged(
        &mut w,
        T0,
        &grant(PM, C, P1, Role::ProgrammeManager, T0),
        "the grant",
    )
    .unwrap_or_else(|r| panic!("the grant is refused under {r:?}"));
    judged(&mut w, T0, &end(PM, t(20)), "the scheduled end")
        .unwrap_or_else(|r| panic!("the scheduled end is refused under {r:?}"));
    let past = judged(&mut w, t(10), &end(PM, t(5)), "the end moved into the past");
    assert!(
        past.is_err(),
        "Cooling-off NOTE: a scheduled end is never moved before now: {past:?}"
    );
}

/// I-01, SoD-05 (Cooling-off NOTE): bringing a scheduled end forward to now
/// ends the binding at once, with the bar of now. Nothing is due later.
#[test]
fn i01_scheduled_end_brought_forward_to_now_ends_at_once() {
    let (_, mut w) = world(Backend::Production);
    judged(
        &mut w,
        T0,
        &grant(PM, C, P1, Role::ProgrammeManager, T0),
        "the grant",
    )
    .unwrap_or_else(|r| panic!("the grant is refused under {r:?}"));
    judged(&mut w, T0, &end(PM, t(20)), "the scheduled end")
        .unwrap_or_else(|r| panic!("the scheduled end is refused under {r:?}"));
    let now = judged(&mut w, t(5), &end(PM, t(5)), "the end now")
        .unwrap_or_else(|r| panic!("the end now is refused under {r:?}"));
    assert!(ends(&now, PM), "the binding ends at once: {now:?}");
    assert!(arrive(&mut w, t(20)).is_empty(), "nothing is due at t(20)");
}

/// I-01, SoD-05 (Cooling-off NOTE): `due` lists the System end of a
/// scheduled binding from the instant on, and not before.
#[test]
fn i01_due_lists_the_scheduled_end_from_the_instant() {
    let (_, mut w) = world(Backend::Production);
    judged(
        &mut w,
        T0,
        &grant(PM, C, P1, Role::ProgrammeManager, T0),
        "the grant",
    )
    .unwrap_or_else(|r| panic!("the grant is refused under {r:?}"));
    judged(&mut w, T0, &end(PM, t(10)), "the scheduled end")
        .unwrap_or_else(|r| panic!("the scheduled end is refused under {r:?}"));
    let just_before = Timestamp::from_micros(t(10).micros().saturating_sub(1));
    assert!(
        fstp_domain::due(&w.state, just_before).is_empty(),
        "nothing is due one microsecond before the instant"
    );
    assert_eq!(
        fstp_domain::due(&w.state, t(10)).len(),
        1,
        "the System end is due at the instant"
    );
}

/// c is granted committee member at `T0` with its end scheduled for
/// `t(10)` in the same command. The batch records the binding and the
/// scheduled end. The System ends the binding at `t(10)`.
fn scheduled_at_grant(b: Backend) {
    let (_, mut w) = world(b);
    let g =
        grant_until(PM, C, P1, Role::CommitteeMember, T0, t(10)).unwrap_or_else(|e| panic!("{e}"));
    let recs = judged(&mut w, T0, &g, "the grant with a scheduled end")
        .unwrap_or_else(|r| panic!("the grant with a scheduled end is refused under {r:?}"));
    assert!(
        recs.iter()
            .any(|r| matches!(r, Record::BindingGranted(x) if x.binding == PM)),
        "the batch records the binding: {recs:?}"
    );
    assert_eq!(
        recs.iter().filter_map(scheduled_end_of).collect::<Vec<_>>(),
        vec![(PM, t(10))],
        "the batch records the scheduled end: {recs:?}"
    );
    let at = arrive(&mut w, t(10));
    assert!(
        ends(&at, PM),
        "the System ends the binding at t(10): {at:?}"
    );
}

/// I-01, SoD-05 (Cooling-off NOTE): an end may be scheduled when the role
/// is granted.
#[test]
fn i01_scheduled_end_at_the_grant() {
    scheduled_at_grant(Backend::Production);
}

/// I-01, SoD-05 (Cooling-off NOTE): the same story on the reference alone.
#[test]
fn i01_scheduled_end_at_the_grant_on_the_reference() {
    scheduled_at_grant(Backend::Reference);
}

/// I-01, SoD-05 (Cooling-off NOTE): a scheduled end at the grant lies after
/// the start. A grant from `t(10)` that ends at `t(10)` is refused.
#[test]
fn i01_scheduled_end_at_the_grant_lies_after_the_start() {
    let (_, mut w) = world(Backend::Production);
    let g = grant_until(PM, C, P1, Role::CommitteeMember, t(10), t(10))
        .unwrap_or_else(|e| panic!("{e}"));
    let out = judged(&mut w, T0, &g, "the grant ending at its start");
    assert!(
        out.is_err(),
        "Cooling-off NOTE: an end at the start is no later instant: {out:?}"
    );
}

/// c's end is scheduled for `t(10)`, with call 1 published and P-12 = 1.
/// At `t(11)`, before the System records the end, every command is refused
/// under SoD-05: c's draft, the publication of call 2 and an end of the
/// binding now. The System end then pins the bar of the instant, 2, and
/// the publication is accepted afterwards (W7 fix round 1 reading).
fn nothing_but_the_end_inside_the_window(b: Backend) {
    let (_, mut w) = world(b);
    judged(
        &mut w,
        T0,
        &grant(PM, C, P1, Role::ProgrammeManager, T0),
        "the grant",
    )
    .unwrap_or_else(|r| panic!("the grant is refused under {r:?}"));
    judged(&mut w, T0, &end(PM, t(10)), "the scheduled end")
        .unwrap_or_else(|r| panic!("the scheduled end is refused under {r:?}"));
    let draft = judged(
        &mut w,
        t(11),
        &draft_of(1, 1),
        "c's draft inside the window",
    );
    assert_eq!(
        draft.err(),
        Some(RuleRef::Sod05),
        "Cooling-off NOTE: the draft waits for the System end"
    );
    let now = judged(
        &mut w,
        t(11),
        &end(PM, t(11)),
        "an end now inside the window",
    );
    assert_eq!(
        now.err(),
        Some(RuleRef::Sod05),
        "Cooling-off NOTE: an end now never moves the scheduled end later"
    );
    w.now = t(11);
    let published = w
        .exec(&publish(call(2)), Facts::Effective)
        .unwrap_or_else(|e| panic!("harness: {e}"));
    assert_eq!(
        published.err().map(|r| r.rule),
        Some(RuleRef::Sod05),
        "Cooling-off NOTE: no call is published between the instant and the System end"
    );
    let at = arrive(&mut w, t(11));
    let e = at
        .iter()
        .find_map(|r| match r {
            Record::BindingEnded(e) if e.binding == PM => Some(*e),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no end of c's binding: {at:?}"));
    assert_eq!(
        (e.at, e.barred_through, e.p12),
        (t(10), 2, CoolingOff(1)),
        "SoD-05: the bar is the one of the instant"
    );
    w.exec(&publish(call(2)), Facts::Effective)
        .unwrap_or_else(|e| panic!("harness: {e}"))
        .unwrap_or_else(|r| panic!("the publication after the System end is refused: {r}"));
}

/// I-01, SoD-05 (Cooling-off NOTE): between a scheduled instant and the
/// System end, nothing but that end is recorded.
#[test]
fn i01_scheduled_end_window_admits_only_the_system_end() {
    nothing_but_the_end_inside_the_window(Backend::Production);
}

/// I-01, SoD-05 (Cooling-off NOTE): the same story on the reference alone.
#[test]
fn i01_scheduled_end_window_admits_only_the_system_end_on_the_reference() {
    nothing_but_the_end_inside_the_window(Backend::Reference);
}

/// I-01 (Cooling-off NOTE): a scheduled end lies after the binding's start,
/// as at the grant. c is granted committee member from `t(20)`, and an
/// `EndRole` scheduling its end for `t(10)` or `t(20)` is refused. One for
/// `t(30)` is accepted (W7 fix round 1).
#[test]
fn i01_scheduled_end_at_or_before_the_start_is_refused() {
    let (_, mut w) = world(Backend::Production);
    let g = committee_from(PM, t(20));
    judged(&mut w, T0, &g, "the grant from t(20)")
        .unwrap_or_else(|r| panic!("the grant is refused under {r:?}"));
    for at in [t(10), t(20)] {
        let out = judged(&mut w, T0, &end(PM, at), "an end at or before the start");
        assert!(
            out.is_err(),
            "Cooling-off NOTE: an end at {at:?} lies at or before the start: {out:?}"
        );
    }
    judged(&mut w, T0, &end(PM, t(30)), "an end after the start")
        .unwrap_or_else(|r| panic!("an end after the start is refused under {r:?}"));
}

/// A committee member grant of c from `start`.
fn committee_from(binding: BindingId, start: Timestamp) -> Step {
    grant(binding, C, P1, Role::CommitteeMember, start)
}
