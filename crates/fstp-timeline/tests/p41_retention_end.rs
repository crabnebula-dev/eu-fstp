//! P-41 retention end events (Daniel, 2026-11-15 late, m3-exit-audit
//! section 9): the timeline schedules a `RETENTION_END` event per grant
//! at the confirmation of its last payment request plus P-41 years, moves
//! it when the end moves (R-NT-01 AC), and fires it once, with no email
//! and no command. The end itself comes from `fstp_domain::retention`,
//! whose production test is in `fstp-domain-testkit`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use common::Cell;
use fstp_cell_core::CellRecord;
use fstp_cell_core::timeline::{EventStatus, TimelineCommand, TimelineRecord};
use fstp_domain::id::{ProgrammeId, ProposalId};
use fstp_domain::retention::RetentionEnd;
use fstp_domain::time::Timestamp;
use fstp_timeline::{diff, firing, kind, retention_events};

const DAY: i64 = 86_400_000_000;

fn end_at(t: i64) -> RetentionEnd {
    RetentionEnd {
        grant: ProposalId::from_raw(41),
        programme: ProgrammeId::from_raw(4),
        start: Timestamp::from_micros(t - 7 * 365 * DAY),
        end: Timestamp::from_micros(t),
    }
}

/// Plans `ends` on the cell at `now`, as the timeline task would.
fn plan(c: &mut Cell, ends: &[RetentionEnd], now: Timestamp) -> Vec<TimelineRecord> {
    let derived = retention_events(c.state.timeline(), ends)
        .into_iter()
        .map(|d| (d.id(), d))
        .collect();
    let records = diff(c.state.timeline(), &derived);
    if !records.is_empty() {
        c.run(
            TimelineCommand::Plan {
                records: records.clone(),
            },
            Vec::new(),
            now,
        )
        .unwrap();
    }
    records
}

/// Each retention event: version, due instant and status, with a
/// cancelled one shown as superseded or not.
fn retention(c: &Cell) -> Vec<(u64, i64, &'static str)> {
    c.state
        .timeline()
        .events()
        .filter(|(_, e)| e.kind == kind::RETENTION_END)
        .map(|(_, e)| {
            let s = match e.status {
                EventStatus::Scheduled => "scheduled",
                EventStatus::Cancelled(Some(_)) => "superseded",
                EventStatus::Cancelled(None) => "cancelled",
                EventStatus::Fired => "fired",
            };
            (e.source_version, e.due, s)
        })
        .collect()
}

/// P-41, R-NT-01: one event per grant at its end. A moved end cancels it,
/// superseded by an event at the new end. At the end it fires once with
/// no message and no command, and is never derived again.
#[test]
fn p41_retention_end_is_scheduled_moved_and_fired_once() {
    let mut c = Cell::from_engine(common::submitted().entries().unwrap());
    let now = Timestamp::from_micros(c.state.now_floor().micros() + DAY);
    let first = now.micros() + 100 * DAY;
    let records = plan(&mut c, &[end_at(first)], now);
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(retention(&c), vec![(0, first, "scheduled")]);
    assert!(plan(&mut c, &[end_at(first)], now).is_empty(), "stable");

    // A changed P-41 moves the end.
    let moved = first + 365 * DAY;
    let records = plan(&mut c, &[end_at(moved)], now);
    let superseded = records.iter().any(|r| {
        matches!(
            r,
            TimelineRecord::EventCancelled {
                superseded_by: Some(_),
                ..
            }
        )
    });
    assert!(superseded, "{records:?}");
    let mut seen = retention(&c);
    seen.sort_unstable();
    assert_eq!(
        seen,
        vec![(0, first, "superseded"), (1, moved, "scheduled")]
    );
    assert!(plan(&mut c, &[end_at(moved)], now).is_empty(), "stable");

    // Not due before its end.
    let (id, _) = c
        .state
        .timeline()
        .events()
        .find(|(_, e)| e.kind == kind::RETENTION_END && e.status == EventStatus::Scheduled)
        .map(|(id, e)| (*id, e.due))
        .unwrap();
    assert!(firing(&c.state, &id, now).is_none());
    let due = Timestamp::from_micros(moved);
    let f = firing(&c.state, &id, due).unwrap();
    match &f.command {
        TimelineCommand::Fire { messages, then, .. } => {
            assert!(messages.is_empty(), "no email (lane m5/retention)");
            assert!(then.is_none(), "no command");
        }
        TimelineCommand::Plan { .. } => panic!("not a firing"),
    }
    let ran = c.run(f.command, f.bodies, due).unwrap();
    assert!(
        ran.batch
            .iter()
            .any(|r| matches!(r, CellRecord::Timeline(TimelineRecord::EventFired { .. })))
    );
    assert!(
        retention_events(c.state.timeline(), &[end_at(moved)]).is_empty(),
        "retention ends once"
    );
    assert!(plan(&mut c, &[end_at(moved)], due).is_empty());
}
