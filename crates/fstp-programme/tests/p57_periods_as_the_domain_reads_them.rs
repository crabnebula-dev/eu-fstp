//! P-57 (Daniel, 2026-11-15 late; lane m9/answers): P-57 holds the
//! action dates, the reporting period ends and the report deadlines. The
//! domain reads the periods from the canonical opaque text this crate
//! gives the policy, so the timeline, the mailbox and the funder reports
//! read the value the creator saved.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_programme::kinds::{ActionDates, PeriodEnd};
use fstp_programme::value::Date;
use fstp_programme::{FieldValue, opaque_text};

fn d(y: u16, m: u8, day: u8) -> Date {
    Date::new(y, m, day).unwrap()
}

fn dates(periods: Vec<PeriodEnd>) -> ActionDates {
    ActionDates {
        start: d(2026, 1, 1),
        end: d(2028, 12, 31),
        periods,
    }
}

fn period(end: Date, deadline: Date) -> PeriodEnd {
    PeriodEnd { end, deadline }
}

/// P-57: a consistent value reads back as the same periods in the domain,
/// and a value without periods keeps the bytes it had before the
/// decision.
#[test]
fn p57_opaque_text_reads_back_as_the_domain_periods() {
    let v = dates(vec![
        period(d(2027, 6, 30), d(2027, 8, 31)),
        period(d(2028, 12, 31), d(2029, 2, 28)),
    ]);
    assert!(v.consistent());
    let text = opaque_text(&FieldValue::P57(v.clone()));
    let a = fstp_domain::reporting::periods_of(&text).expect("the domain reads it");
    assert_eq!(a.periods.len(), 2, "{text}");
    assert_eq!(a.periods[1].start, a.periods[0].end);
    let plain = opaque_text(&FieldValue::P57(dates(Vec::new())));
    assert_eq!(plain, "{\"end\":\"2028-12-31\",\"start\":\"2026-01-01\"}");
}

/// P-57: the creator reports exactly the values the domain cannot read.
#[test]
fn p57_inconsistent_dates_are_refused_by_creator_and_domain_alike() {
    let bad = [
        ActionDates {
            start: d(2029, 1, 1),
            ..dates(Vec::new())
        },
        dates(vec![period(d(2029, 1, 31), d(2029, 3, 31))]),
        dates(vec![period(d(2027, 6, 30), d(2027, 6, 29))]),
        dates(vec![
            period(d(2027, 6, 30), d(2027, 8, 31)),
            period(d(2027, 6, 30), d(2027, 8, 31)),
        ]),
    ];
    for v in bad {
        assert!(!v.consistent(), "{v:?}");
        let text = opaque_text(&FieldValue::P57(v.clone()));
        assert_eq!(fstp_domain::reporting::periods_of(&text), None, "{text}");
    }
}
