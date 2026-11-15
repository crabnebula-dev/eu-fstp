//! P-57 reporting period events (Daniel, 2026-11-15 late;
//! `funder-reporting.md`: "Reporting period ends and report deadlines
//! from the Data Sheet become timeline events with reminders"). The
//! timeline schedules a `REPORTING_PERIOD_END` and a `REPORT_DEADLINE`
//! event per period, moves each when P-57 moves its date (R-NT-01 AC),
//! cancels it when P-57 no longer holds the period, and fires each once,
//! with no email and no command. The periods come from
//! `fstp_domain::reporting`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use common::Cell;
use fstp_cell_core::timeline::{EventStatus, TimelineCommand, TimelineRecord};
use fstp_domain::id::ProgrammeId;
use fstp_domain::reporting::ReportingPeriod;
use fstp_domain::time::Timestamp;
use fstp_timeline::{diff, firing, kind, period_events};

const DAY: i64 = 86_400_000_000;

fn period(end: i64, deadline: i64) -> (ProgrammeId, ReportingPeriod) {
    (
        ProgrammeId::from_raw(4),
        ReportingPeriod {
            index: 1,
            start: Timestamp::from_micros(end - 180 * DAY),
            end: Timestamp::from_micros(end),
            deadline: Timestamp::from_micros(deadline),
        },
    )
}

fn plan(
    c: &mut Cell,
    periods: &[(ProgrammeId, ReportingPeriod)],
    now: Timestamp,
) -> Vec<TimelineRecord> {
    let derived = period_events(c.state.timeline(), periods)
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

fn events(c: &Cell, k: u16) -> Vec<(u64, i64, &'static str)> {
    let mut out: Vec<_> = c
        .state
        .timeline()
        .events()
        .filter(|(_, e)| e.kind == k)
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

/// P-57, R-NT-01: a period end and a report deadline event per period; a
/// moved deadline supersedes its event; each fires once with no message
/// and no command; a removed period cancels what is left.
#[test]
fn p57_period_events_are_scheduled_moved_fired_and_cancelled() {
    let mut c = Cell::from_engine(common::submitted().entries().unwrap());
    let now = Timestamp::from_micros(c.state.now_floor().micros() + DAY);
    let end = now.micros() + 30 * DAY;
    let deadline = end + 60 * DAY;
    assert_eq!(plan(&mut c, &[period(end, deadline)], now).len(), 2);
    assert_eq!(
        events(&c, kind::REPORTING_PERIOD_END),
        vec![(0, end, "scheduled")]
    );
    assert_eq!(
        events(&c, kind::REPORT_DEADLINE),
        vec![(0, deadline, "scheduled")]
    );
    assert!(
        plan(&mut c, &[period(end, deadline)], now).is_empty(),
        "stable"
    );

    // A changed P-57 moves the deadline only.
    let later = deadline + 30 * DAY;
    plan(&mut c, &[period(end, later)], now);
    assert_eq!(
        events(&c, kind::REPORT_DEADLINE),
        vec![(0, deadline, "superseded"), (1, later, "scheduled")]
    );
    assert_eq!(
        events(&c, kind::REPORTING_PERIOD_END),
        vec![(0, end, "scheduled")]
    );

    // The period end fires once, with no message and no command.
    let (id, _) = c
        .state
        .timeline()
        .events()
        .find(|(_, e)| e.kind == kind::REPORTING_PERIOD_END)
        .map(|(id, e)| (*id, e.due))
        .unwrap();
    assert!(firing(&c.state, &id, now).is_none(), "not due yet");
    let at = Timestamp::from_micros(end);
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
        events(&c, kind::REPORTING_PERIOD_END),
        vec![(0, end, "fired")]
    );
    assert!(plan(&mut c, &[period(end, later)], at).is_empty());

    // P-57 drops the period: the deadline still scheduled is cancelled.
    let records = plan(&mut c, &[], at);
    assert!(
        records.iter().any(|r| matches!(
            r,
            TimelineRecord::EventCancelled {
                superseded_by: None,
                ..
            }
        )),
        "{records:?}"
    );
    assert_eq!(
        events(&c, kind::REPORT_DEADLINE),
        vec![(0, deadline, "superseded"), (1, later, "cancelled")]
    );
}
