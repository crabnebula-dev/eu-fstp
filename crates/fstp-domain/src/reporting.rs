//! The reporting periods of a programme (P-57).
//!
//! Decided by Daniel on 2026-11-15 (late, `docs/handoff/m9-design.md`,
//! "Decided by Daniel, 2026-11-15 (late)"): P-57 holds the action's start
//! and end dates, the reporting period ends and the report deadlines of
//! the Data Sheet. `funder-reporting.md` makes each period end and each
//! deadline a timeline event with a reminder, and the periodic reporting
//! data is generated per period.
//!
//! P-57 is read from the active spec: the live opaque value of the
//! programme's head policy version, as `fstp-programme` encodes
//! `ActionDates`:
//!
//! ```text
//! {"end":"2028-12-31","periods":[{"deadline":"2027-08-31","end":"2027-06-30"}],"start":"2026-01-01"}
//! ```
//!
//! `periods` may be absent, which reads as no period. Both the cell's
//! timeline and the API core read this one function, so they agree on
//! every date.
//!
//! Readings of lane m9/answers, pending Daniel:
//!
//! - A date is a whole UTC day. Period 1 starts on the action's start
//!   date. Each later period starts the day after the previous period's
//!   end. A period ends at the end of its end date, so its instant
//!   [`ReportingPeriod::end`] is the next midnight in UTC.
//! - A deadline is the last day a report may be sent, so its instant
//!   [`ReportingPeriod::deadline`] is the midnight after it.
//! - The ends are strictly ascending and lie within the action dates, and
//!   no deadline comes before its period's end. Any other value reads as
//!   no period at all: fail closed, no reminder rather than a wrong one.

use crate::id::ProgrammeId;
use crate::rules::ParamId;
use crate::state::State;
use crate::time::{MICROS_PER_DAY, Timestamp};

/// The most reporting periods a P-57 value holds.
pub const MAX_PERIODS: usize = 64;

/// One reporting period of a programme (P-57).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReportingPeriod {
    /// Its number, from 1, in date order.
    pub index: u16,
    /// Its first instant: midnight UTC of its first day.
    pub start: Timestamp,
    /// The instant after its last day: midnight UTC after its end date.
    pub end: Timestamp,
    /// The instant after the last day of its report deadline.
    pub deadline: Timestamp,
}

/// The action dates and reporting periods of a P-57 value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActionPeriods {
    /// Midnight UTC of the action's first day.
    pub start: Timestamp,
    /// Midnight UTC after the action's last day.
    pub end: Timestamp,
    /// The reporting periods, in order. Empty when P-57 names none.
    pub periods: Vec<ReportingPeriod>,
}

/// The P-57 value in its opaque text (module documentation), or `None`
/// for any other text, a start after the end, or periods that break the
/// rules of the module documentation.
pub fn periods_of(text: &str) -> Option<ActionPeriods> {
    let v = fstp_json::parse(text.as_bytes()).ok()?;
    let o = v.as_object()?;
    if o.keys().any(|k| !matches!(k, "start" | "end" | "periods")) {
        return None;
    }
    let start = day(o.get("start")?.as_str()?)?;
    let end = day(o.get("end")?.as_str()?)?;
    if start > end {
        return None;
    }
    let listed = match o.get("periods") {
        None => &[][..],
        Some(p) => &p.as_array()?[..],
    };
    if listed.len() > MAX_PERIODS {
        return None;
    }
    let mut periods = Vec::with_capacity(listed.len());
    let mut first = start;
    for (i, p) in listed.iter().enumerate() {
        let po = p.as_object()?;
        if po.len() != 2 {
            return None;
        }
        let last = day(po.get("end")?.as_str()?)?;
        let deadline = day(po.get("deadline")?.as_str()?)?;
        if last < first || last > end || deadline < last {
            return None;
        }
        periods.push(ReportingPeriod {
            index: u16::try_from(i).ok()?.checked_add(1)?,
            start: at(first)?,
            end: at(last.checked_add(1)?)?,
            deadline: at(deadline.checked_add(1)?)?,
        });
        first = last.checked_add(1)?;
    }
    Some(ActionPeriods {
        start: at(start)?,
        end: at(end.checked_add(1)?)?,
        periods,
    })
}

/// The P-57 periods of `programme` in force: the live value of its head
/// policy version. `None` while P-57 is unset or unreadable.
pub fn action_periods(state: &State, programme: ProgrammeId) -> Option<ActionPeriods> {
    let live = crate::policy::live_values(state, programme)?;
    periods_of(live.opaque.get(&ParamId::P57)?.as_str())
}

/// The reporting periods of `programme`, empty while P-57 names none or
/// is unreadable.
pub fn reporting_periods(state: &State, programme: ProgrammeId) -> Vec<ReportingPeriod> {
    action_periods(state, programme)
        .map(|a| a.periods)
        .unwrap_or_default()
}

/// The reporting periods of every active programme, in programme order:
/// the sources of the timeline's period end and report deadline events
/// and of the programme managers' reminders (`funder-reporting.md`).
pub fn active_reporting_periods(state: &State) -> Vec<(ProgrammeId, ReportingPeriod)> {
    crate::programme::programmes(state)
        .filter(|(_, s)| *s == crate::programme::ProgrammeStatus::Active)
        .flat_map(|(id, _)| {
            reporting_periods(state, id)
                .into_iter()
                .map(move |r| (id, r))
        })
        .collect()
}

/// The days since 1970-01-01 of a date `YYYY-MM-DD`, or `None`.
fn day(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() != 10 || b.get(4) != Some(&b'-') || b.get(7) != Some(&b'-') {
        return None;
    }
    let num = |r: core::ops::Range<usize>| -> Option<i64> {
        let part = s.get(r)?;
        if !part.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        part.parse().ok()
    };
    let (y, m, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    if y < 1970 {
        return None;
    }
    let days = crate::retention::days_from_civil(y, m, d)?;
    // A day past the month's end (such as 2026-02-30) maps to another
    // date: refused, so each date has one spelling.
    (crate::retention::civil_from_days(days)? == (y, m, d)).then_some(days)
}

/// Midnight UTC of `days` since 1970-01-01.
fn at(days: i64) -> Option<Timestamp> {
    days.checked_mul(MICROS_PER_DAY).map(Timestamp::from_micros)
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn midnight(y: i64, m: i64, d: i64) -> Timestamp {
        Timestamp::from_micros(
            crate::retention::days_from_civil(y, m, d).unwrap_or(0) * MICROS_PER_DAY,
        )
    }

    /// P-57 (Daniel, 2026-11-15 late): the value holds the action dates,
    /// the reporting period ends and the report deadlines. Period 1 starts
    /// on the action's start, each later one the day after the previous
    /// end, and each instant is the midnight after its date.
    #[test]
    fn p57_periods_follow_the_data_sheet_dates() {
        let text = "{\"end\":\"2028-12-31\",\"periods\":[\
                    {\"deadline\":\"2027-08-31\",\"end\":\"2027-06-30\"},\
                    {\"deadline\":\"2029-02-28\",\"end\":\"2028-12-31\"}],\
                    \"start\":\"2026-01-01\"}";
        let a = periods_of(text).expect("a valid P-57");
        assert_eq!(a.start, midnight(2026, 1, 1));
        assert_eq!(a.end, midnight(2029, 1, 1));
        assert_eq!(a.periods.len(), 2);
        assert_eq!(a.periods[0].index, 1);
        assert_eq!(a.periods[0].start, midnight(2026, 1, 1));
        assert_eq!(a.periods[0].end, midnight(2027, 7, 1));
        assert_eq!(a.periods[0].deadline, midnight(2027, 9, 1));
        assert_eq!(a.periods[1].index, 2);
        assert_eq!(a.periods[1].start, midnight(2027, 7, 1));
        assert_eq!(a.periods[1].end, midnight(2029, 1, 1));
        assert_eq!(a.periods[1].deadline, midnight(2029, 3, 1));
    }

    /// P-57: the action dates alone read as no period, as every value
    /// written before the decision.
    #[test]
    fn p57_without_periods_reads_as_none() {
        let a = periods_of("{\"end\":\"2028-12-31\",\"start\":\"2026-01-01\"}").expect("valid");
        assert!(a.periods.is_empty());
        let a = periods_of("{\"end\":\"2028-12-31\",\"periods\":[],\"start\":\"2026-01-01\"}")
            .expect("valid");
        assert!(a.periods.is_empty());
    }

    /// P-57: any value that breaks the rules reads as unset (fail closed).
    #[test]
    fn p57_inconsistent_values_read_as_unset() {
        let p = |periods: &str| {
            format!("{{\"end\":\"2028-12-31\",\"periods\":[{periods}],\"start\":\"2026-01-01\"}}")
        };
        for bad in [
            "{\"end\":\"2025-12-31\",\"start\":\"2026-01-01\"}".to_owned(),
            "{\"end\":\"2028-12-31\",\"start\":\"2026-01-01\",\"x\":1}".to_owned(),
            "{\"end\":\"2028-02-30\",\"start\":\"2026-01-01\"}".to_owned(),
            "{\"end\":\"2028-12-31\",\"start\":\"1969-12-31\"}".to_owned(),
            "{\"end\":\"2028-12-31\",\"start\":\"2026-1-01\"}".to_owned(),
            // An end after the action's end.
            p("{\"deadline\":\"2029-02-28\",\"end\":\"2029-01-31\"}"),
            // A deadline before its period's end.
            p("{\"deadline\":\"2027-06-29\",\"end\":\"2027-06-30\"}"),
            // Ends not strictly ascending.
            p("{\"deadline\":\"2027-08-31\",\"end\":\"2027-06-30\"},\
                 {\"deadline\":\"2027-08-31\",\"end\":\"2027-06-30\"}"),
            // An unknown member.
            p("{\"deadline\":\"2027-08-31\",\"end\":\"2027-06-30\",\"x\":1}"),
            p("{\"end\":\"2027-06-30\"}"),
            "".to_owned(),
            "[]".to_owned(),
        ] {
            assert_eq!(periods_of(&bad), None, "{bad}");
        }
    }

    /// P-57: random texts never panic, and a value that reads holds
    /// strictly ascending periods that never overlap (fuzz-style sweep).
    #[test]
    fn p57_random_texts_are_refused_or_ordered() {
        let mut seed: u64 = 0x5eed_0057;
        let alphabet = b"{}[]\":,0123456789-endstartperiodsdeadline ";
        for _ in 0..20_000 {
            let mut s = Vec::new();
            seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let len = (seed >> 58) as usize;
            for _ in 0..len {
                seed = seed
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                s.push(alphabet[(seed >> 33) as usize % alphabet.len()]);
            }
            let text = String::from_utf8_lossy(&s);
            if let Some(a) = periods_of(&text) {
                for w in a.periods.windows(2) {
                    assert!(w[0].end == w[1].start && w[0].end < w[1].end);
                }
            }
        }
    }
}
