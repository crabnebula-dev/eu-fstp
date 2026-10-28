//! I-01, SoD-05: only the System records a scheduled end, and only from its instant (Cooling-off NOTE, decided 2026-10-25).
//!
//! `EndScheduledRole` is the System command that `due` lists from the
//! scheduled instant on. It records `BindingEnded` at that instant. These
//! tests check its refusals on production: a person may not issue it, the
//! System may not issue it before the instant, and a binding without a
//! scheduled end has none to record. Each story starts from genesis.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::command::{Actor, Command, SystemCause};
use fstp_domain::id::BindingId;
use fstp_domain::record::Record;
use fstp_domain::refusal::{RefusalReason, RuleRef};
use fstp_domain::roles::Role;
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::roster::{
    ADMIN, Backend, C, Facts, Flags, P1, SodSetup, SodWorld, Step, T0, call, end, grant, sod_truth,
};

/// The programme manager binding of c in these stories.
const PM: BindingId = BindingId::from_raw(301);

/// `T0` plus `n` seconds.
fn t(n: i64) -> Timestamp {
    Timestamp::from_micros(T0.micros().saturating_add(n.saturating_mul(1_000_000)))
}

/// P-12 = 1 and call 1 published, with c granted programme manager at
/// `T0`. With `schedule`, its end is scheduled for `t(10)`.
fn world(schedule: bool) -> SodWorld {
    let mut setup = SodSetup::one(1, &[1]);
    setup.published = vec![call(1)];
    let mut w = SodWorld::from_setup(Backend::Production, sod_truth(), &setup)
        .unwrap_or_else(|e| panic!("setup: {e}"));
    w.now = T0;
    let mut steps = vec![grant(PM, C, P1, Role::ProgrammeManager, T0)];
    if schedule {
        steps.push(end(PM, t(10)));
    }
    for s in steps {
        w.exec(&s, Facts::Effective)
            .unwrap_or_else(|e| panic!("harness: {e}"))
            .unwrap_or_else(|r| panic!("{:?} refused: {r}", s.cmd));
    }
    w
}

/// The System's `EndScheduledRole` of c's binding.
fn system_end() -> Step {
    Step {
        actor: Actor::System(SystemCause::Timeline),
        flags: Flags::NONE,
        cmd: Command::EndScheduledRole { binding: PM },
    }
}

/// I-01, SoD-05 (Cooling-off NOTE): a tenant admin cannot record the
/// System's scheduled end, even at the instant (I-84).
#[test]
fn i01_scheduled_end_is_recorded_by_the_system_only() {
    let mut w = world(true);
    w.now = t(10);
    let by_admin = Step::by(
        ADMIN,
        Flags::ADMIN,
        Command::EndScheduledRole { binding: PM },
    );
    let out = w
        .exec(&by_admin, Facts::Effective)
        .unwrap_or_else(|e| panic!("harness: {e}"));
    assert_eq!(
        out.err().map(|r| (r.rule, r.reason)),
        Some((RuleRef::Actor, RefusalReason::WrongActor)),
        "I-84: EndScheduledRole is the System's"
    );
}

/// I-01, SoD-05 (Cooling-off NOTE): before the instant the binding is
/// held, so the System's end is refused and nothing is due. At the
/// instant it records the end at the scheduled instant.
#[test]
fn i01_scheduled_end_is_refused_before_the_instant() {
    let mut w = world(true);
    w.now = t(9);
    let early = w
        .exec(&system_end(), Facts::Effective)
        .unwrap_or_else(|e| panic!("harness: {e}"));
    assert!(early.is_err(), "the end is not due before t(10): {early:?}");
    assert!(fstp_domain::due(&w.state, t(9)).is_empty());
    w.now = t(12);
    let records = w
        .exec(&system_end(), Facts::Effective)
        .unwrap_or_else(|e| panic!("harness: {e}"))
        .unwrap_or_else(|r| panic!("the due end is refused: {r}"));
    let at = records.iter().find_map(|r| match r {
        Record::BindingEnded(e) if e.binding == PM => Some(e.at),
        _ => None,
    });
    assert_eq!(at, Some(t(10)), "the end carries the scheduled instant");
    assert!(fstp_domain::due(&w.state, t(12)).is_empty());
}

/// I-01, SoD-05 (Cooling-off NOTE): a binding without a scheduled end has
/// no end for the System to record, and nothing is due for it.
#[test]
fn i01_binding_without_a_scheduled_end_has_none_to_record() {
    let mut w = world(false);
    w.now = t(10);
    assert!(fstp_domain::due(&w.state, t(10)).is_empty());
    let out = w
        .exec(&system_end(), Facts::Effective)
        .unwrap_or_else(|e| panic!("harness: {e}"));
    assert!(out.is_err(), "no scheduled end to record: {out:?}");
}
