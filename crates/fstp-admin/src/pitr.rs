//! The time an operator gives `fstp-admin restore --to` (ADR-012 and
//! ADR-028 records of lane `m10/backup-pitr`).
//!
//! One spelling, in UTC: `YYYY-MM-DDTHH:MM:SSZ`, for example
//! `2026-11-24T10:00:00Z`. No offset, no fraction, no leap second, years
//! 1970 to 9999. [`parse_time`] admits exactly that and [`format_time`]
//! spells it back, so a parsed time round trips. Fuzzed
//! (`restore_time_parse`), with [`index_times`], which reads the times of
//! the backup agent's index file.

/// Days from 1970-01-01 to the civil date, by the era-based algorithm.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "years 1970 to 9999 only: every step stays far inside u64"
)]
fn days_from_civil(y: u64, m: u64, d: u64) -> u64 {
    let y = if m <= 2 { y.wrapping_sub(1) } else { y };
    let era = y / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The civil date of `days` after 1970-01-01.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "days of years 1970 to 9999 only: every step stays far inside u64"
)]
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + u64::from(m <= 2);
    (y, m, d)
}

fn days_in_month(y: u64, m: u64) -> u64 {
    match m {
        2 if (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// The digits of `s` as a number, when `s` is only ASCII digits.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "at most four digits: the value stays below 10 000"
)]
fn digits(s: Option<&[u8]>) -> Option<u64> {
    let s = s?;
    let mut v = 0u64;
    for b in s {
        if !b.is_ascii_digit() {
            return None;
        }
        v = v * 10 + u64::from(b - b'0');
    }
    Some(v)
}

/// The Unix seconds of `text` (module documentation). `None` for any
/// other spelling or an impossible date.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "checked fields of years 1970 to 9999: the sum stays far inside u64"
)]
#[must_use]
pub fn parse_time(text: &str) -> Option<u64> {
    let b = text.as_bytes();
    if b.len() != 20 {
        return None;
    }
    for (i, c) in [
        (4, b'-'),
        (7, b'-'),
        (10, b'T'),
        (13, b':'),
        (16, b':'),
        (19, b'Z'),
    ] {
        if b.get(i) != Some(&c) {
            return None;
        }
    }
    let y = digits(b.get(0..4))?;
    let mo = digits(b.get(5..7))?;
    let d = digits(b.get(8..10))?;
    let h = digits(b.get(11..13))?;
    let mi = digits(b.get(14..16))?;
    let s = digits(b.get(17..19))?;
    if !(1970..=9999).contains(&y) || !(1..=12).contains(&mo) {
        return None;
    }
    if d < 1 || d > days_in_month(y, mo) || h > 23 || mi > 59 || s > 59 {
        return None;
    }
    Some(days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + s)
}

/// `unix` in the spelling of [`parse_time`]. Times past 9999 are spelled
/// as the last second of 9999.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "clamped to 9999: every step stays far inside u64"
)]
#[must_use]
pub fn format_time(unix: u64) -> String {
    let unix = unix.min(253_402_300_799);
    let (y, m, d) = civil_from_days(unix / 86_400);
    let s = unix % 86_400;
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        s / 3600,
        (s % 3600) / 60,
        s % 60
    )
}

/// The completion times of the backup agent's index file `text`, in line
/// order: the third field of each line (ADR-012 record of lane L10). A
/// line without one is skipped; the agent's own decoder is strict.
#[must_use]
pub fn index_times(text: &str) -> Vec<u64> {
    text.lines()
        .filter_map(|l| l.split(' ').nth(2)?.parse::<u64>().ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ADR-028 record of lane `m10/backup-pitr`: the operator's time
    /// parses to Unix seconds in UTC and spells back the same.
    #[test]
    fn adr012_pitr_time_round_trips_in_utc() {
        for (text, secs) in [
            ("1970-01-01T00:00:00Z", 0),
            ("2026-11-24T10:00:00Z", 1_795_514_400),
            ("2024-02-29T23:59:59Z", 1_709_251_199),
            ("2000-03-01T00:00:00Z", 951_868_800),
            ("9999-12-31T23:59:59Z", 253_402_300_799),
        ] {
            assert_eq!(parse_time(text), Some(secs), "{text}");
            assert_eq!(format_time(secs), text);
        }
        assert_eq!(format_time(u64::MAX), "9999-12-31T23:59:59Z");
    }

    /// ADR-028 record of lane `m10/backup-pitr`: one spelling only.
    #[test]
    fn adr012_pitr_time_refuses_other_spellings() {
        for bad in [
            "",
            "2026-11-24",
            "2026-11-24 10:00:00Z",
            "2026-11-24T10:00:00",
            "2026-11-24T10:00:00z",
            "2026-11-24T10:00:00+00:00",
            "2026-11-24T10:00:00.5Z",
            "2026-11-24T10:00Z",
            "26-11-24T10:00:00Z",
            "2026-11-31T10:00:00Z",
            "2025-02-29T10:00:00Z",
            "2100-02-29T10:00:00Z",
            "2026-13-01T10:00:00Z",
            "2026-00-01T10:00:00Z",
            "2026-11-00T10:00:00Z",
            "2026-11-24T24:00:00Z",
            "2026-11-24T10:60:00Z",
            "2026-11-24T10:00:60Z",
            "1969-12-31T23:59:59Z",
            "2026-11-24T1a:00:00Z",
            "+026-11-24T10:00:00Z",
            "２026-11-24T10:00:00Z",
        ] {
            assert_eq!(parse_time(bad), None, "{bad}");
        }
    }

    /// ADR-012 record of lane L10: the third field of each index line.
    #[test]
    fn adr012_pitr_time_reads_the_index_times() {
        let a = "ab".repeat(16);
        let text = format!("{a} {a} 1790000000 5\n{a} {a} 1790000100 9\nbad\n");
        assert_eq!(index_times(&text), vec![1_790_000_000, 1_790_000_100]);
        assert!(index_times("").is_empty());
    }
}
