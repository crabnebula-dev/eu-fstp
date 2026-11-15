//! The end of the funder retention period of a grant (P-41).
//!
//! Decided by Daniel on 2026-11-15 (late, `docs/handoff/m3-exit-audit.md`
//! section 9, "Retention reminder"):
//!
//! - Retention starts at the confirmation of the grant's last payment
//!   request. It is not a new act and needs no new record.
//! - It ends P-41 years later. A timeline event fires then
//!   (`fstp_timeline::kind::RETENTION_END`), and the tenant admins get a
//!   mailbox message that links to `/app/admin/erasures`.
//!
//! The domain records no instant with `PaymentConfirmed`, so the caller
//! hands in when each request was confirmed: the entry time of its
//! ledger record. Both the cell's timeline and the API core's mailbox
//! read the same function, so they agree on every date.
//!
//! P-41 is read from the active spec: the live opaque value of the
//! programme's head policy version, `{"years": n}` as `fstp-programme`
//! encodes `FunderRetention`. No record carries it separately.
//!
//! Readings of lane m5/retention, pending Daniel:
//!
//! - The last payment request is known only once the grant is COMPLETED
//!   or TERMINATED and no request of it is RELEASED but unconfirmed. A
//!   pending request of a closed grant can no longer be paid (P-67), so it
//!   does not hold retention back. Retention starts at the latest
//!   confirmation of the grant's PAID requests.
//! - A grant with no PAID request has no retention start here, so no
//!   reminder. A grant terminated before any payment is one.
//! - A year is a calendar year in UTC, at the same time of day. A start
//!   on 29 February ends on 1 March when the end year has no 29 February,
//!   so retention is never shorter than P-41 years.
//! - A change of P-41 moves the end of every grant of the programme,
//!   since P-41 is a live parameter.

use std::collections::BTreeMap;
use std::num::NonZeroU8;

use crate::id::{ProgrammeId, ProposalId, RequestId};
use crate::payment::RequestStatus;
use crate::rules::{ParamId, StateTag};
use crate::state::State;
use crate::time::{MICROS_PER_DAY, Timestamp};

/// The end of retention of one grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RetentionEnd {
    /// The grant.
    pub grant: ProposalId,
    /// Its programme, whose P-41 applies.
    pub programme: ProgrammeId,
    /// The confirmation of the grant's last payment request.
    pub start: Timestamp,
    /// The start plus P-41 years.
    pub end: Timestamp,
}

/// The years of a P-41 value in its canonical opaque text,
/// `{"years":n}` with n from 1 to 255. `None` for anything else.
pub fn years_of(text: &str) -> Option<NonZeroU8> {
    let v = fstp_json::parse(text.as_bytes()).ok()?;
    let o = v.as_object()?;
    if o.len() != 1 {
        return None;
    }
    let n = o.get("years")?.as_u64()?;
    NonZeroU8::new(u8::try_from(n).ok()?)
}

/// The P-41 years of `programme` in force: the live value of its head
/// policy version. `None` while P-41 is unset or unreadable, which
/// derives no end (fail closed: no reminder rather than a wrong one).
pub fn p41_years(state: &State, programme: ProgrammeId) -> Option<NonZeroU8> {
    let live = crate::policy::live_values(state, programme)?;
    years_of(live.opaque.get(&ParamId::P41)?.as_str())
}

/// When retention of `grant` starts (module documentation), given the
/// confirmation instant of each confirmed request. `None` while the
/// grant is open, while a request of it is RELEASED but unconfirmed,
/// when no request of it is PAID, or when a PAID request has no known
/// confirmation instant.
pub fn retention_start(
    state: &State,
    grant: ProposalId,
    confirmed: &BTreeMap<RequestId, Timestamp>,
) -> Option<Timestamp> {
    let closed = matches!(
        crate::view::proposal_state(state, grant),
        Some(StateTag::Completed | StateTag::Terminated)
    );
    if !closed {
        return None;
    }
    let mut start: Option<Timestamp> = None;
    for r in state.payments().summaries().filter(|r| r.grant == grant) {
        match r.status {
            RequestStatus::Released => return None,
            RequestStatus::Paid => {
                let at = *confirmed.get(&r.request)?;
                start = Some(start.map_or(at, |s| s.max(at)));
            }
            _ => {}
        }
    }
    start
}

/// Every grant whose retention has a start and an end, in grant order.
pub fn retention_ends(
    state: &State,
    confirmed: &BTreeMap<RequestId, Timestamp>,
) -> Vec<RetentionEnd> {
    let mut grants: Vec<ProposalId> = state.payments().summaries().map(|r| r.grant).collect();
    grants.sort_unstable();
    grants.dedup();
    grants
        .into_iter()
        .filter_map(|grant| {
            let start = retention_start(state, grant, confirmed)?;
            let programme = crate::publicity::programme_of(state, grant)?;
            let years = p41_years(state, programme)?;
            let end = add_years(start, years)?;
            Some(RetentionEnd {
                grant,
                programme,
                start,
                end,
            })
        })
        .collect()
}

/// `t` plus `years` calendar years in UTC, at the same time of day. A
/// 29 February with no counterpart moves to 1 March. `None` outside the
/// supported range of years 0 to 9999.
pub fn add_years(t: Timestamp, years: NonZeroU8) -> Option<Timestamp> {
    let days = t.micros().div_euclid(MICROS_PER_DAY);
    let time = t.micros().rem_euclid(MICROS_PER_DAY);
    let (y, m, d) = civil_from_days(days)?;
    let y2 = y.checked_add(i64::from(years.get()))?;
    if !(0..=9999).contains(&y2) {
        return None;
    }
    let (m2, d2) = if m == 2 && d == 29 && !leap(y2) {
        (3, 1)
    } else {
        (m, d)
    };
    let days2 = days_from_civil(y2, m2, d2)?;
    days2
        .checked_mul(MICROS_PER_DAY)?
        .checked_add(time)
        .map(Timestamp::from_micros)
}

/// Whether `y` is a leap year of the Gregorian calendar.
fn leap(y: i64) -> bool {
    y.rem_euclid(4) == 0 && (y.rem_euclid(100) != 0 || y.rem_euclid(400) == 0)
}

/// Civil date of `days` since 1970-01-01, on integers only (the
/// days-to-civil algorithm of H. Hinnant). `None` outside about years
/// -2200 to 10000.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "days is bounded, so no step can overflow or divide by zero"
)]
fn civil_from_days(days: i64) -> Option<(i64, i64, i64)> {
    if !(-1_500_000..=3_000_000).contains(&days) {
        return None;
    }
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    Some((y, m, d))
}

/// Days since 1970-01-01 of the civil date `y-m-d` (H. Hinnant's
/// days-from-civil). `None` outside years 0 to 9999 or for a month
/// outside 1 to 12.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "the year, month and day are bounded, so no step can overflow"
)]
fn days_from_civil(y: i64, m: i64, d: i64) -> Option<i64> {
    if !(0..=9999).contains(&y) || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    const DAY: i64 = MICROS_PER_DAY;

    fn years(n: u8) -> NonZeroU8 {
        NonZeroU8::new(n).unwrap_or(NonZeroU8::MIN)
    }

    /// P-41 (Daniel, 2026-11-15): the opaque text `{"years":n}` reads as n
    /// years, and any other form reads as unset.
    #[test]
    fn p41_years_reads_the_canonical_text_only() {
        assert_eq!(years_of("{\"years\":7}"), Some(years(7)));
        for bad in [
            "{\"years\":0}",
            "{\"years\":256}",
            "{\"years\":\"7\"}",
            "{\"years\":7,\"x\":1}",
            "{}",
            "7",
            "",
        ] {
            assert_eq!(years_of(bad), None, "{bad}");
        }
    }

    /// P-41: the end is the same date and time of day P-41 years later,
    /// and 29 February moves to 1 March, never earlier.
    #[test]
    fn p41_end_is_the_same_civil_date_years_later() {
        // 2025-11-15T10:00:00Z.
        let start = Timestamp::from_micros(20_407 * DAY + 10 * 3_600_000_000);
        let end = add_years(start, years(5)).unwrap_or(start);
        // 2030-11-15T10:00:00Z, 1826 days later (2028 is a leap year).
        assert_eq!(end.micros(), start.micros() + 1_826 * DAY);
        // 2028-02-29 plus one year is 2029-03-01.
        let leap_day = days_from_civil(2028, 2, 29).unwrap_or(0);
        let next =
            add_years(Timestamp::from_micros(leap_day * DAY), years(1)).map(|t| t.micros() / DAY);
        assert_eq!(next, days_from_civil(2029, 3, 1));
        // Four years on, the 29th exists again.
        let four =
            add_years(Timestamp::from_micros(leap_day * DAY), years(4)).map(|t| t.micros() / DAY);
        assert_eq!(four, days_from_civil(2032, 2, 29));
        // Round trip of the civil conversion over a range of days.
        for days in (-800_000..800_000).step_by(997) {
            let (y, m, d) = civil_from_days(days).unwrap_or((0, 0, 0));
            if (0..=9999).contains(&y) {
                assert_eq!(days_from_civil(y, m, d), Some(days));
            }
        }
    }

    /// P-41: an open grant, or one with no request, has no start.
    #[test]
    fn p41_no_start_without_a_closed_grant() {
        let s = State::genesis();
        let none = BTreeMap::new();
        assert_eq!(retention_start(&s, ProposalId::from_raw(1), &none), None);
        assert!(retention_ends(&s, &none).is_empty());
    }
}
