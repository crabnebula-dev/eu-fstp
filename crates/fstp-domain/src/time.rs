//! Timestamps and day counts (design section 2.2).
//!
//! - `decide` never reads a clock. The shell reads it once per command and
//!   passes the instant in the command context.
//! - Guards only compare times, which keeps the reduced model clock sound.
//! - A call deadline is a UTC instant plus its IANA zone name as text. M2
//!   does not interpret zones. Working days (P-08, P-40) belong to M6.

/// Microseconds in one day of 86 400 seconds.
pub const MICROS_PER_DAY: i64 = 86_400_000_000;

/// A UTC instant in microseconds since the Unix epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(i64);

impl Timestamp {
    /// The instant `micros` microseconds after the Unix epoch.
    pub const fn from_micros(micros: i64) -> Timestamp {
        Timestamp(micros)
    }

    /// Microseconds since the Unix epoch.
    pub const fn micros(self) -> i64 {
        self.0
    }

    /// This instant plus `d` whole days of 86 400 seconds, or `None` on overflow.
    /// The stage 2 window closes at `opened_at` plus P-07 days this way.
    pub const fn checked_add_days(self, d: Days) -> Option<Timestamp> {
        // A u16 day count times MICROS_PER_DAY is below 2^63, so only the addition can overflow.
        let span = (d.0 as i64).saturating_mul(MICROS_PER_DAY);
        match self.0.checked_add(span) {
            Some(t) => Some(Timestamp(t)),
            None => None,
        }
    }

    /// The instant one microsecond earlier, or `None` at the minimum.
    /// The reduced model clock jumps to these instants (design section 6.1).
    pub const fn checked_pred(self) -> Option<Timestamp> {
        match self.0.checked_sub(1) {
            Some(t) => Some(Timestamp(t)),
            None => None,
        }
    }
}

/// A whole number of days.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Days(u16);

impl Days {
    /// `n` days.
    pub const fn new(n: u16) -> Days {
        Days(n)
    }

    /// The number of days.
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// Longest zone name accepted, in bytes.
pub const ZONE_NAME_MAX: usize = 64;

/// An IANA time zone name, kept as text and never interpreted in M2.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ZoneName(String);

impl ZoneName {
    /// The zone name `s`, or `None` unless it is 1 to 64 bytes of ASCII
    /// letters, digits, `/`, `_`, `+` or `-`.
    pub fn new(s: &str) -> Option<ZoneName> {
        let ok = !s.is_empty()
            && s.len() <= ZONE_NAME_MAX
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'_' | b'+' | b'-'));
        if ok {
            Some(ZoneName(s.to_owned()))
        } else {
            None
        }
    }

    /// The name as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
