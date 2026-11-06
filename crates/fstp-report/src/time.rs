//! UTC instants as RFC 3339 text, with integer arithmetic only.

use fstp_domain::time::{MICROS_PER_DAY, Timestamp};

/// The civil date of day `z` after 1970-01-01 (proleptic Gregorian).
fn civil(z: i64) -> (i64, i64, i64) {
    let z = z.saturating_add(719_468);
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = doe
        .saturating_sub(doe / 1_460)
        .saturating_add(doe / 36_524)
        .saturating_sub(doe / 146_096)
        / 365;
    let y = yoe.saturating_add(era.saturating_mul(400));
    let doy = doe.saturating_sub(
        yoe.saturating_mul(365)
            .saturating_add(yoe / 4)
            .saturating_sub(yoe / 100),
    );
    let mp = doy.saturating_mul(5).saturating_add(2) / 153;
    let d = doy
        .saturating_sub(mp.saturating_mul(153).saturating_add(2) / 5)
        .saturating_add(1);
    let m = if mp < 10 {
        mp.saturating_add(3)
    } else {
        mp.saturating_sub(9)
    };
    let y = if m <= 2 { y.saturating_add(1) } else { y };
    (y, m, d)
}

/// `t` as `YYYY-MM-DDTHH:MM:SSZ`. Sub-second parts are dropped.
pub(crate) fn utc(t: Timestamp) -> String {
    let us = t.micros();
    let days = us.div_euclid(MICROS_PER_DAY);
    let secs = us.rem_euclid(MICROS_PER_DAY) / 1_000_000;
    let (y, m, d) = civil(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs / 3_600,
        (secs / 60) % 60,
        secs % 60
    )
}

/// `t` as `YYYY-MM-DD`.
pub(crate) fn date(t: Timestamp) -> String {
    let s = utc(t);
    s.get(..10).unwrap_or(&s).to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_known_instants() {
        assert_eq!(utc(Timestamp::from_micros(0)), "1970-01-01T00:00:00Z");
        assert_eq!(
            utc(Timestamp::from_micros(1_767_571_200_000_000)),
            "2026-01-05T00:00:00Z"
        );
        assert_eq!(
            utc(Timestamp::from_micros(951_782_400_000_000 + 3_723_000_000)),
            "2000-02-29T01:02:03Z"
        );
        assert_eq!(
            utc(Timestamp::from_micros(-1_000_000)),
            "1969-12-31T23:59:59Z"
        );
    }
}
