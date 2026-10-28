//! Reference validity encoding (RFC 5280 section 4.1.2.5), in integer
//! arithmetic only.

use super::der::tlv;

/// The first second the reference profile can encode:
/// 1950-01-01T00:00:00Z.
pub(crate) const MIN_TIME: i64 = -631_152_000;

/// The last second the reference profile can encode:
/// 9999-12-31T23:59:59Z.
pub(crate) const MAX_TIME: i64 = 253_402_300_799;

/// 2050-01-01T00:00:00Z, the first second written as GeneralizedTime.
pub(crate) const GENERALIZED_FROM: i64 = 2_524_608_000;

/// 2026-10-28T00:00:00Z, a fixed instant for tests that need one.
pub(crate) const T0: i64 = 1_793_145_600;

/// One day in seconds.
pub(crate) const DAY: i64 = 86_400;

/// The 7-day lifetime of role and internal client certificates, in valid
/// seconds (design section 1.3, ADR-005 "Role certificates", ADR-009).
pub(crate) const CLIENT_MAX_LIFETIME: i64 = 7 * DAY;

/// The largest `not_after - not_before` of a client certificate. RFC 5280
/// section 4.1.2.5 counts both ends as valid, so a certificate is valid for
/// the span plus one second. This is the strict reading of the 7-day cap
/// (design section 17.2, interim pending Daniel).
pub(crate) const CLIENT_MAX_SPAN: i64 = CLIENT_MAX_LIFETIME - 1;

/// The civil date of day `z` after 1970-01-01 (H. Hinnant's
/// `civil_from_days`).
pub(crate) fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// The TLV for the instant `t`: UTCTime through 2049, GeneralizedTime from
/// 2050. `None` outside [`MIN_TIME`] ..= [`MAX_TIME`].
pub(crate) fn time(t: i64) -> Option<Vec<u8>> {
    if !(MIN_TIME..=MAX_TIME).contains(&t) {
        return None;
    }
    let days = t.div_euclid(DAY);
    let secs = t.rem_euclid(DAY);
    let (y, m, d) = civil_from_days(days);
    let (hh, mm, ss) = (secs / 3600, (secs / 60) % 60, secs % 60);
    if t < GENERALIZED_FROM {
        let text = format!("{:02}{m:02}{d:02}{hh:02}{mm:02}{ss:02}Z", y % 100);
        Some(tlv(0x17, text.as_bytes()))
    } else {
        let text = format!("{y:04}{m:02}{d:02}{hh:02}{mm:02}{ss:02}Z");
        Some(tlv(0x18, text.as_bytes()))
    }
}

/// The Validity SEQUENCE, or `None` when either end cannot be encoded or
/// `not_before` is after `not_after`.
pub(crate) fn validity(not_before: i64, not_after: i64) -> Option<Vec<u8>> {
    if not_before > not_after {
        return None;
    }
    let nb = time(not_before)?;
    let na = time(not_after)?;
    Some(super::der::seq(&[&nb, &na]))
}
