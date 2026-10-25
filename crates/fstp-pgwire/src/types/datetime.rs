//! `timestamptz` and `date`.
//!
//! Both use the server's binary representation: microseconds or days since
//! 2000-01-01 (UTC for `timestamptz`). Infinity and minus infinity are the
//! largest and smallest integers, as in PostgreSQL. Finite values must lie
//! in the server's range, which starts at 4714-11-24 BC; anything else is
//! rejected in both directions, so a value never changes meaning.
//!
//! Years are astronomical: year 0 is 1 BC and year -1 is 2 BC. Calendar
//! conversion uses the proleptic Gregorian calendar, as PostgreSQL does.

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::types::{DecodeError, EncodeError, FromSql, IsNull, ToSql, Type, accepts};

/// Days from 1970-01-01 to 2000-01-01.
const UNIX_TO_PG_DAYS: i64 = 10_957;
/// Microseconds from 1970-01-01 to 2000-01-01.
const UNIX_TO_PG_MICROS: i64 = UNIX_TO_PG_DAYS * MICROS_PER_DAY;
const MICROS_PER_DAY: i64 = 86_400_000_000;
const MICROS_PER_SECOND: i64 = 1_000_000;

/// First valid `timestamptz`, 4714-11-24 00:00:00 UTC BC, in microseconds
/// since 2000-01-01.
pub(crate) const MIN_TIMESTAMP: i64 = -211_813_488_000_000_000;
/// First `timestamptz` after the valid range, 294277-01-01 00:00:00 UTC.
pub(crate) const END_TIMESTAMP: i64 = 9_223_371_331_200_000_000;
/// First valid `date`, 4714-11-24 BC, in days since 2000-01-01.
pub(crate) const MIN_DATE: i32 = -2_451_545;
/// First `date` after the valid range, 5874898-01-01.
pub(crate) const END_DATE: i32 = 2_145_031_949;

/// Days since 1970-01-01 for a proleptic Gregorian date (H. Hinnant's
/// algorithm). `None` on overflow; callers validate the range.
fn days_from_civil(year: i64, month: u32, day: u32) -> Option<i64> {
    let m = i64::from(month);
    let d = i64::from(day);
    let y = if m <= 2 { year.checked_sub(1)? } else { year };
    let era = if y >= 0 { y } else { y.checked_sub(399)? } / 400;
    let yoe = y.checked_sub(era.checked_mul(400)?)?;
    let mp = (m.checked_add(9)?) % 12;
    let doy = (mp.checked_mul(153)?.checked_add(2)? / 5)
        .checked_add(d)?
        .checked_sub(1)?;
    let doe = yoe
        .checked_mul(365)?
        .checked_add(yoe / 4)?
        .checked_sub(yoe / 100)?
        .checked_add(doy)?;
    era.checked_mul(146_097)?
        .checked_add(doe)?
        .checked_sub(719_468)
}

/// The proleptic Gregorian date for days since 1970-01-01.
fn civil_from_days(days: i64) -> Option<(i64, u32, u32)> {
    let z = days.checked_add(719_468)?;
    let era = if z >= 0 { z } else { z.checked_sub(146_096)? } / 146_097;
    let doe = z.checked_sub(era.checked_mul(146_097)?)?;
    let yoe = doe
        .checked_sub(doe / 1460)?
        .checked_add(doe / 36_524)?
        .checked_sub(doe / 146_096)?
        / 365;
    let y = yoe.checked_add(era.checked_mul(400)?)?;
    let doy = doe.checked_sub(
        yoe.checked_mul(365)?
            .checked_add(yoe / 4)?
            .checked_sub(yoe / 100)?,
    )?;
    let mp = doy.checked_mul(5)?.checked_add(2)? / 153;
    let d = doy
        .checked_sub(mp.checked_mul(153)?.checked_add(2)? / 5)?
        .checked_add(1)?;
    let m = if mp < 10 {
        mp.checked_add(3)?
    } else {
        mp.checked_sub(9)?
    };
    let y = if m <= 2 { y.checked_add(1)? } else { y };
    Some((y, u32::try_from(m).ok()?, u32::try_from(d).ok()?))
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ => {
            let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
            if leap { 29 } else { 28 }
        }
    }
}

fn write_year(f: &mut fmt::Formatter<'_>, year: i64) -> fmt::Result {
    if (0..=9999).contains(&year) {
        write!(f, "{year:04}")
    } else if year < 0 {
        write!(f, "-{:04}", year.unsigned_abs())
    } else {
        write!(f, "+{year}")
    }
}

/// A `timestamptz` value: an instant, or plus or minus infinity.
///
/// Display is ISO 8601 in UTC with microseconds, such as
/// `2026-10-24T12:00:00.000000Z`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Timestamptz(i64);

impl Timestamptz {
    /// `infinity`.
    pub const INFINITY: Timestamptz = Timestamptz(i64::MAX);
    /// `-infinity`.
    pub const NEG_INFINITY: Timestamptz = Timestamptz(i64::MIN);

    /// The value with this many microseconds since 2000-01-01 00:00:00 UTC.
    /// `i64::MAX` and `i64::MIN` are the infinities.
    ///
    /// # Errors
    ///
    /// Returns a [`DecodeError`] for a finite value outside the server's
    /// range.
    pub fn from_pg_micros(micros: i64) -> Result<Timestamptz, DecodeError> {
        if micros == i64::MAX
            || micros == i64::MIN
            || (MIN_TIMESTAMP..END_TIMESTAMP).contains(&micros)
        {
            Ok(Timestamptz(micros))
        } else {
            Err(DecodeError("timestamptz is outside the server's range"))
        }
    }

    /// The value with this many microseconds since 1970-01-01 00:00:00 UTC.
    ///
    /// # Errors
    ///
    /// Returns a [`DecodeError`] outside the server's range.
    pub fn from_unix_micros(micros: i64) -> Result<Timestamptz, DecodeError> {
        let pg = micros
            .checked_sub(UNIX_TO_PG_MICROS)
            .ok_or(DecodeError("timestamptz is outside the server's range"))?;
        if pg == i64::MAX || pg == i64::MIN {
            return Err(DecodeError("timestamptz is outside the server's range"));
        }
        Self::from_pg_micros(pg)
    }

    /// The value for a calendar date and time of day in UTC.
    ///
    /// # Errors
    ///
    /// Returns a [`DecodeError`] for an invalid date or time, or one outside
    /// the server's range.
    pub fn from_utc(
        year: i64,
        month: u32,
        day: u32,
        hour: u32,
        minute: u32,
        second: u32,
        micro: u32,
    ) -> Result<Timestamptz, DecodeError> {
        let bad = DecodeError("invalid calendar date or time");
        if !(1..=12).contains(&month)
            || day == 0
            || day > days_in_month(year, month)
            || hour > 23
            || minute > 59
            || second > 59
            || micro > 999_999
        {
            return Err(bad);
        }
        let days = days_from_civil(year, month, day)
            .and_then(|d| d.checked_sub(UNIX_TO_PG_DAYS))
            .ok_or(bad.clone())?;
        let secs = i64::from(hour)
            .checked_mul(3600)
            .and_then(|s| s.checked_add(i64::from(minute).checked_mul(60)?))
            .and_then(|s| s.checked_add(i64::from(second)))
            .ok_or(bad.clone())?;
        let micros = days
            .checked_mul(MICROS_PER_DAY)
            .and_then(|m| m.checked_add(secs.checked_mul(MICROS_PER_SECOND)?))
            .and_then(|m| m.checked_add(i64::from(micro)))
            .ok_or(bad)?;
        if micros == i64::MAX || micros == i64::MIN {
            return Err(DecodeError("timestamptz is outside the server's range"));
        }
        Self::from_pg_micros(micros)
    }

    /// Microseconds since 2000-01-01 00:00:00 UTC, or `i64::MAX` and
    /// `i64::MIN` for the infinities.
    #[must_use]
    pub fn pg_micros(self) -> i64 {
        self.0
    }

    /// True unless this is an infinity.
    #[must_use]
    pub fn is_finite(self) -> bool {
        self.0 != i64::MAX && self.0 != i64::MIN
    }

    /// Microseconds since 1970-01-01 00:00:00 UTC. `None` for the
    /// infinities.
    #[must_use]
    pub fn to_unix_micros(self) -> Option<i64> {
        if !self.is_finite() {
            return None;
        }
        self.0.checked_add(UNIX_TO_PG_MICROS)
    }

    /// The value for a system time.
    ///
    /// # Errors
    ///
    /// Returns a [`DecodeError`] outside the server's range.
    pub fn from_system_time(t: SystemTime) -> Result<Timestamptz, DecodeError> {
        let range = DecodeError("timestamptz is outside the server's range");
        let micros = match t.duration_since(UNIX_EPOCH) {
            Ok(d) => i64::try_from(d.as_micros()).map_err(|_| range.clone())?,
            Err(e) => {
                let d = e.duration();
                // Round towards minus infinity, as the server does.
                let mut m = i64::try_from(d.as_micros()).map_err(|_| range.clone())?;
                if d.subsec_nanos() % 1000 != 0 {
                    m = m.checked_add(1).ok_or(range.clone())?;
                }
                m.checked_neg().ok_or(range)?
            }
        };
        Self::from_unix_micros(micros)
    }

    /// The system time. `None` for the infinities or when the platform
    /// cannot represent it.
    #[must_use]
    pub fn to_system_time(self) -> Option<SystemTime> {
        let micros = self.to_unix_micros()?;
        let d = Duration::from_micros(micros.unsigned_abs());
        if micros >= 0 {
            UNIX_EPOCH.checked_add(d)
        } else {
            UNIX_EPOCH.checked_sub(d)
        }
    }

    /// The UTC calendar fields: year, month, day, hour, minute, second and
    /// microsecond. `None` for the infinities.
    #[must_use]
    pub fn to_utc(self) -> Option<(i64, u32, u32, u32, u32, u32, u32)> {
        if !self.is_finite() {
            return None;
        }
        let days = self.0.div_euclid(MICROS_PER_DAY);
        let rem = self.0.rem_euclid(MICROS_PER_DAY);
        let (y, m, d) = civil_from_days(days.checked_add(UNIX_TO_PG_DAYS)?)?;
        let secs = rem / MICROS_PER_SECOND;
        let micro = u32::try_from(rem % MICROS_PER_SECOND).ok()?;
        let hour = u32::try_from(secs / 3600).ok()?;
        let minute = u32::try_from((secs % 3600) / 60).ok()?;
        let second = u32::try_from(secs % 60).ok()?;
        Some((y, m, d, hour, minute, second, micro))
    }
}

impl fmt::Display for Timestamptz {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.to_utc() {
            None if self.0 == i64::MAX => f.write_str("infinity"),
            None if self.0 == i64::MIN => f.write_str("-infinity"),
            None => f.write_str("invalid"),
            Some((y, mo, d, h, mi, s, us)) => {
                write_year(f, y)?;
                write!(f, "-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{us:06}Z")
            }
        }
    }
}

impl fmt::Debug for Timestamptz {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Timestamptz({self})")
    }
}

accepts!(Timestamptz, Type::TIMESTAMPTZ);

impl ToSql for Timestamptz {
    fn accepts(&self, ty: Type) -> bool {
        ty == Type::TIMESTAMPTZ
    }

    fn rust_type(&self) -> &'static str {
        "Timestamptz"
    }

    fn to_sql(&self, _ty: Type, out: &mut Vec<u8>) -> Result<IsNull, EncodeError> {
        // Values built through the constructors are always in range; this
        // guards against future constructors.
        if Self::from_pg_micros(self.0).is_err() {
            return Err(EncodeError("timestamptz is outside the server's range"));
        }
        out.extend_from_slice(&self.0.to_be_bytes());
        Ok(IsNull::No)
    }
}

impl FromSql for Timestamptz {
    fn accepts(ty: Type) -> bool {
        ty == Type::TIMESTAMPTZ
    }

    fn from_sql(_ty: Type, raw: &[u8]) -> Result<Self, DecodeError> {
        let bytes: [u8; 8] = raw
            .try_into()
            .map_err(|_| DecodeError("timestamptz must be 8 bytes"))?;
        Self::from_pg_micros(i64::from_be_bytes(bytes))
    }
}

/// A `date` value: a calendar day, or plus or minus infinity.
///
/// Display is ISO 8601, such as `2026-10-24`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Date(i32);

impl Date {
    /// `infinity`.
    pub const INFINITY: Date = Date(i32::MAX);
    /// `-infinity`.
    pub const NEG_INFINITY: Date = Date(i32::MIN);

    /// The date this many days after 2000-01-01. `i32::MAX` and `i32::MIN`
    /// are the infinities.
    ///
    /// # Errors
    ///
    /// Returns a [`DecodeError`] for a finite value outside the server's
    /// range.
    pub fn from_pg_days(days: i32) -> Result<Date, DecodeError> {
        if days == i32::MAX || days == i32::MIN || (MIN_DATE..END_DATE).contains(&days) {
            Ok(Date(days))
        } else {
            Err(DecodeError("date is outside the server's range"))
        }
    }

    /// The date for a proleptic Gregorian calendar day.
    ///
    /// # Errors
    ///
    /// Returns a [`DecodeError`] for an invalid day or one outside the
    /// server's range.
    pub fn from_ymd(year: i64, month: u32, day: u32) -> Result<Date, DecodeError> {
        let bad = DecodeError("invalid calendar date");
        if !(1..=12).contains(&month) || day == 0 || day > days_in_month(year, month) {
            return Err(bad);
        }
        let days = days_from_civil(year, month, day)
            .and_then(|d| d.checked_sub(UNIX_TO_PG_DAYS))
            .ok_or(bad.clone())?;
        let days = i32::try_from(days).map_err(|_| bad)?;
        if days == i32::MAX || days == i32::MIN {
            return Err(DecodeError("date is outside the server's range"));
        }
        Self::from_pg_days(days)
    }

    /// Days since 2000-01-01, or `i32::MAX` and `i32::MIN` for the
    /// infinities.
    #[must_use]
    pub fn pg_days(self) -> i32 {
        self.0
    }

    /// True unless this is an infinity.
    #[must_use]
    pub fn is_finite(self) -> bool {
        self.0 != i32::MAX && self.0 != i32::MIN
    }

    /// Year, month and day. `None` for the infinities.
    #[must_use]
    pub fn to_ymd(self) -> Option<(i64, u32, u32)> {
        if !self.is_finite() {
            return None;
        }
        civil_from_days(i64::from(self.0).checked_add(UNIX_TO_PG_DAYS)?)
    }
}

impl fmt::Display for Date {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.to_ymd() {
            None if self.0 == i32::MAX => f.write_str("infinity"),
            None if self.0 == i32::MIN => f.write_str("-infinity"),
            None => f.write_str("invalid"),
            Some((y, m, d)) => {
                write_year(f, y)?;
                write!(f, "-{m:02}-{d:02}")
            }
        }
    }
}

impl fmt::Debug for Date {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Date({self})")
    }
}

accepts!(Date, Type::DATE);

impl ToSql for Date {
    fn accepts(&self, ty: Type) -> bool {
        ty == Type::DATE
    }

    fn rust_type(&self) -> &'static str {
        "Date"
    }

    fn to_sql(&self, _ty: Type, out: &mut Vec<u8>) -> Result<IsNull, EncodeError> {
        if Self::from_pg_days(self.0).is_err() {
            return Err(EncodeError("date is outside the server's range"));
        }
        out.extend_from_slice(&self.0.to_be_bytes());
        Ok(IsNull::No)
    }
}

impl FromSql for Date {
    fn accepts(ty: Type) -> bool {
        ty == Type::DATE
    }

    fn from_sql(_ty: Type, raw: &[u8]) -> Result<Self, DecodeError> {
        let bytes: [u8; 4] = raw
            .try_into()
            .map_err(|_| DecodeError("date must be 4 bytes"))?;
        Self::from_pg_days(i32::from_be_bytes(bytes))
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    #[test]
    fn epoch_and_known_dates() {
        assert_eq!(Date::from_ymd(2000, 1, 1).unwrap().pg_days(), 0);
        assert_eq!(Date::from_ymd(1970, 1, 1).unwrap().pg_days(), -10_957);
        assert_eq!(Date::from_ymd(-4713, 11, 24).unwrap().pg_days(), MIN_DATE);
        assert!(Date::from_ymd(-4713, 11, 23).is_err());
        assert_eq!(
            Date::from_ymd(5_874_897, 12, 31).unwrap().pg_days(),
            END_DATE - 1
        );
        assert!(Date::from_ymd(5_874_898, 1, 1).is_err());
        assert!(Date::from_ymd(2023, 2, 29).is_err());
        assert!(Date::from_ymd(2024, 2, 29).is_ok());
        assert_eq!(Date::from_pg_days(0).unwrap().to_string(), "2000-01-01");
        assert_eq!(
            Date::from_pg_days(MIN_DATE).unwrap().to_string(),
            "-4713-11-24"
        );
        assert_eq!(Date::INFINITY.to_string(), "infinity");
        assert!(Date::from_pg_days(END_DATE).is_err());
        assert!(Date::from_pg_days(MIN_DATE - 1).is_err());
    }

    #[test]
    fn timestamp_bounds_and_display() {
        let min = Timestamptz::from_pg_micros(MIN_TIMESTAMP).unwrap();
        assert_eq!(min.to_string(), "-4713-11-24T00:00:00.000000Z");
        let last = Timestamptz::from_pg_micros(END_TIMESTAMP - 1).unwrap();
        assert_eq!(last.to_string(), "+294276-12-31T23:59:59.999999Z");
        assert!(Timestamptz::from_pg_micros(END_TIMESTAMP).is_err());
        assert!(Timestamptz::from_pg_micros(MIN_TIMESTAMP - 1).is_err());
        assert_eq!(
            Timestamptz::from_utc(2026, 10, 24, 12, 34, 56, 789)
                .unwrap()
                .to_string(),
            "2026-10-24T12:34:56.000789Z"
        );
        assert_eq!(
            Timestamptz::from_unix_micros(0).unwrap().pg_micros(),
            -UNIX_TO_PG_MICROS
        );
        assert_eq!(Timestamptz::NEG_INFINITY.to_string(), "-infinity");
        assert_eq!(Timestamptz::INFINITY.to_unix_micros(), None);
    }

    #[test]
    fn civil_round_trip_property() {
        fstp_prop::check("civil_round_trip", |g| {
            let days = g.i32_in(MIN_DATE..=END_DATE - 1);
            let d = Date::from_pg_days(days).unwrap();
            let (y, m, dd) = d.to_ymd().unwrap();
            fstp_prop::prop_assert_eq!(Date::from_ymd(y, m, dd).unwrap(), d);
            Ok(())
        });
    }

    #[test]
    fn timestamp_fields_round_trip_property() {
        fstp_prop::check("timestamp_fields_round_trip", |g| {
            let micros = g.i64_in(MIN_TIMESTAMP..=END_TIMESTAMP - 1);
            let t = Timestamptz::from_pg_micros(micros).unwrap();
            let (y, mo, d, h, mi, s, us) = t.to_utc().unwrap();
            fstp_prop::prop_assert_eq!(Timestamptz::from_utc(y, mo, d, h, mi, s, us).unwrap(), t);
            Ok(())
        });
    }

    #[test]
    fn system_time_round_trip() {
        let now = SystemTime::now();
        let t = Timestamptz::from_system_time(now).unwrap();
        let back = t.to_system_time().unwrap();
        let diff = now.duration_since(back).unwrap_or_default();
        assert!(diff < Duration::from_micros(1));
        let before = UNIX_EPOCH - Duration::from_nanos(1500);
        assert_eq!(
            Timestamptz::from_system_time(before)
                .unwrap()
                .to_unix_micros(),
            Some(-2)
        );
    }
}
