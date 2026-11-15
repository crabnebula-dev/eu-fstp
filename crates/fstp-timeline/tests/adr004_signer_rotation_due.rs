//! The operator's reminder to rotate the notice companion key (ADR-004;
//! Daniel, 2026-11-15 late: "An operator rotates it by hand, and the
//! platform reminds the operator when a year is up"). The timeline
//! schedules a `SIGNER_ROTATION_DUE` event 365 days after the key's latest
//! generation, moves it when the key is rotated (R-NT-01 AC), and fires it
//! once per generation, with no email and no command.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use common::Cell;
use fstp_cell_core::timeline::{EventStatus, TimelineCommand};
use fstp_domain::time::Timestamp;
use fstp_timeline::{SIGNER_LIFETIME_US, diff, firing, kind, signer_events};

const DAY: i64 = 86_400_000_000;

fn plan(c: &mut Cell, generations: &[Timestamp], now: Timestamp) -> usize {
    let derived = signer_events(c.state.timeline(), generations)
        .into_iter()
        .map(|d| (d.id(), d))
        .collect();
    let records = diff(c.state.timeline(), &derived);
    let n = records.len();
    if n > 0 {
        c.run(TimelineCommand::Plan { records }, Vec::new(), now)
            .unwrap();
    }
    n
}

fn events(c: &Cell) -> Vec<(u64, i64, &'static str)> {
    let mut out: Vec<_> = c
        .state
        .timeline()
        .events()
        .filter(|(_, e)| e.kind == kind::SIGNER_ROTATION_DUE)
        .map(|(_, e)| {
            let s = match e.status {
                EventStatus::Scheduled => "scheduled",
                EventStatus::Cancelled(Some(_)) => "superseded",
                EventStatus::Cancelled(None) => "cancelled",
                EventStatus::Fired => "fired",
            };
            (e.source_version, e.due, s)
        })
        .collect();
    out.sort_unstable();
    out
}

/// ADR-004, R-NT-01: no key, no event; a created key is due a year
/// later; a rotation supersedes the event with one a year after the new
/// generation; it fires once, with no message and no command.
#[test]
fn adr004_signer_rotation_due_a_year_after_each_generation() {
    let mut c = Cell::from_engine(common::submitted().entries().unwrap());
    let now = Timestamp::from_micros(c.state.now_floor().micros() + DAY);
    assert_eq!(plan(&mut c, &[], now), 0, "no key, no reminder");
    let made = now;
    assert_eq!(plan(&mut c, &[made], now), 1);
    let due = made.micros() + SIGNER_LIFETIME_US;
    assert_eq!(events(&c), vec![(0, due, "scheduled")]);
    assert_eq!(plan(&mut c, &[made], now), 0, "stable");

    // The operator rotates early: the reminder moves a year on from then.
    let rotated = Timestamp::from_micros(now.micros() + 100 * DAY);
    plan(&mut c, &[made, rotated], rotated);
    let due2 = rotated.micros() + SIGNER_LIFETIME_US;
    assert_eq!(
        events(&c),
        vec![(0, due, "superseded"), (1, due2, "scheduled")]
    );

    let (id, _) = c
        .state
        .timeline()
        .events()
        .find(|(_, e)| e.kind == kind::SIGNER_ROTATION_DUE && e.status == EventStatus::Scheduled)
        .map(|(id, e)| (*id, e.due))
        .unwrap();
    assert!(firing(&c.state, &id, rotated).is_none(), "not due yet");
    let at = Timestamp::from_micros(due2);
    let f = firing(&c.state, &id, at).unwrap();
    match &f.command {
        TimelineCommand::Fire { messages, then, .. } => {
            assert!(messages.is_empty());
            assert!(then.is_none());
        }
        TimelineCommand::Plan { .. } => panic!("not a firing"),
    }
    c.run(f.command, f.bodies, at).unwrap();
    assert_eq!(
        plan(&mut c, &[made, rotated], at),
        0,
        "fires once per generation"
    );
}
