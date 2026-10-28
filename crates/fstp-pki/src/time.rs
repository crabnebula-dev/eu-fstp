//! Validity instants as RFC 5280 section 4.1.2.5 writes them, in integer
//! arithmetic only.
//!
//! Instants through 2049 are `UTCTime` (`YYMMDDHHMMSSZ`). Instants from
//! 2050 are `GeneralizedTime` (`YYYYMMDDHHMMSSZ`). Neither form has
//! fractional seconds. The profile encodes 1950-01-01T00:00:00Z to
//! 9999-12-31T23:59:59Z.

use crate::PkiError;
use crate::der::{TAG_GENERALIZED_TIME, TAG_UTC_TIME, tlv};

/// The first second the profile can encode: 1950-01-01T00:00:00Z.
pub const MIN_TIME: i64 = -631_152_000;

/// The last second the profile can encode: 9999-12-31T23:59:59Z.
pub const MAX_TIME: i64 = 253_402_300_799;

/// 2050-01-01T00:00:00Z, the first second written as `GeneralizedTime`.
pub(crate) const GENERALIZED_FROM: i64 = 2_524_608_000;

/// Seconds in a day.
const DAY: u64 = 86_400;

/// Days from 0000-03-01 to 1970-01-01 in the proleptic Gregorian calendar.
const EPOCH_SHIFT_DAYS: u64 = 719_468;

/// Days in a 400-year era.
const ERA_DAYS: u64 = 146_097;

/// `MIN_TIME` in whole days after 1970-01-01, negated. 1950 starts on a
/// day boundary, so the division is exact.
const MIN_DAYS_BEFORE_EPOCH: u64 = 7_305;

/// A civil date and time of day, all fields in range.
struct Civil {
    year: u64,
    month: u64,
    day: u64,
    hour: u64,
    minute: u64,
    second: u64,
}

/// The civil date of the instant `t`, which lies in `MIN_TIME ..=
/// MAX_TIME`. This is H. Hinnant's `civil_from_days` on a day count
/// shifted to start at 0000-03-01, so every value stays non-negative.
fn civil(t: i64) -> Option<Civil> {
    let since_min = u64::try_from(t.checked_sub(MIN_TIME)?).ok()?;
    let secs = since_min.checked_rem(DAY)?;
    let days_since_min = since_min.checked_div(DAY)?;
    // Day number counted from 0000-03-01.
    let z = days_since_min
        .checked_add(EPOCH_SHIFT_DAYS)?
        .checked_sub(MIN_DAYS_BEFORE_EPOCH)?;
    let era = z.checked_div(ERA_DAYS)?;
    let doe = z.checked_rem(ERA_DAYS)?;
    let yoe = doe
        .checked_sub(doe.checked_div(1_460)?)?
        .checked_add(doe.checked_div(36_524)?)?
        .checked_sub(doe.checked_div(146_096)?)?
        .checked_div(365)?;
    let doy = doe.checked_sub(
        yoe.checked_mul(365)?
            .checked_add(yoe.checked_div(4)?)?
            .checked_sub(yoe.checked_div(100)?)?,
    )?;
    let mp = doy.checked_mul(5)?.checked_add(2)?.checked_div(153)?;
    let day = doy
        .checked_sub(mp.checked_mul(153)?.checked_add(2)?.checked_div(5)?)?
        .checked_add(1)?;
    let month = if mp < 10 {
        mp.checked_add(3)?
    } else {
        mp.checked_sub(9)?
    };
    let year_from_march = yoe.checked_add(era.checked_mul(400)?)?;
    let year = if month <= 2 {
        year_from_march.checked_add(1)?
    } else {
        year_from_march
    };
    Some(Civil {
        year,
        month,
        day,
        hour: secs.checked_div(3_600)?,
        minute: secs.checked_div(60)?.checked_rem(60)?,
        second: secs.checked_rem(60)?,
    })
}

/// Appends `v` as exactly `width` decimal digits. `None` when `v` needs
/// more digits.
fn push_digits(out: &mut Vec<u8>, v: u64, width: u32) -> Option<()> {
    let mut divisor = 10u64.checked_pow(width.checked_sub(1)?)?;
    if v.checked_div(divisor)? >= 10 {
        return None;
    }
    let mut rest = v;
    for _ in 0..width {
        let digit = rest.checked_div(divisor)?;
        rest = rest.checked_rem(divisor)?;
        let c = char::from_digit(u32::try_from(digit).ok()?, 10)?;
        out.push(u8::try_from(c).ok()?);
        divisor = divisor.checked_div(10)?.max(1);
    }
    Some(())
}

/// The `Time` TLV for the instant `t`.
///
/// # Errors
///
/// [`PkiError::TimeOutOfRange`] when `t` lies outside `MIN_TIME ..=
/// MAX_TIME`.
pub(crate) fn time(t: i64) -> Result<Vec<u8>, PkiError> {
    if !(MIN_TIME..=MAX_TIME).contains(&t) {
        return Err(PkiError::TimeOutOfRange);
    }
    encode(t).ok_or(PkiError::TimeOutOfRange)
}

fn encode(t: i64) -> Option<Vec<u8>> {
    let c = civil(t)?;
    let mut text = Vec::with_capacity(15);
    let tag = if t < GENERALIZED_FROM {
        push_digits(&mut text, c.year.checked_rem(100)?, 2)?;
        TAG_UTC_TIME
    } else {
        push_digits(&mut text, c.year, 4)?;
        TAG_GENERALIZED_TIME
    };
    for field in [c.month, c.day, c.hour, c.minute, c.second] {
        push_digits(&mut text, field, 2)?;
    }
    text.push(b'Z');
    Some(tlv(tag, &text))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::arithmetic_side_effects, reason = "test code")]

    use super::*;

    fn text(t: i64) -> Vec<u8> {
        time(t).unwrap_or_default()
    }

    #[test]
    fn known_instants_have_known_spellings() {
        assert_eq!(text(MIN_TIME), tlv(TAG_UTC_TIME, b"500101000000Z"));
        assert_eq!(text(0), tlv(TAG_UTC_TIME, b"700101000000Z"));
        assert_eq!(text(-1), tlv(TAG_UTC_TIME, b"691231235959Z"));
        assert_eq!(text(951_782_400), tlv(TAG_UTC_TIME, b"000229000000Z"));
        assert_eq!(
            text(GENERALIZED_FROM - 1),
            tlv(TAG_UTC_TIME, b"491231235959Z")
        );
        assert_eq!(
            text(GENERALIZED_FROM),
            tlv(TAG_GENERALIZED_TIME, b"20500101000000Z")
        );
        assert_eq!(
            text(MAX_TIME),
            tlv(TAG_GENERALIZED_TIME, b"99991231235959Z")
        );
    }

    #[test]
    fn out_of_range_instants_are_refused() {
        assert_eq!(time(MIN_TIME - 1), Err(PkiError::TimeOutOfRange));
        assert_eq!(time(MAX_TIME + 1), Err(PkiError::TimeOutOfRange));
        assert_eq!(time(i64::MIN), Err(PkiError::TimeOutOfRange));
        assert_eq!(time(i64::MAX), Err(PkiError::TimeOutOfRange));
    }
}
