//! Percentages from 0.00 to 100.00 in basis points.

use core::fmt;

use crate::decimal::{Fault, Refusal, parse_fixed};

/// 0.00 to 100.00 percent in basis points. Canonical JSON form `"75.00"` (Q1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Percent {
    bp: u16,
}

impl Percent {
    /// The largest value, 100.00 percent, in basis points.
    pub const MAX_BP: u16 = 10_000;

    /// Parses the canonical two-decimal spelling, such as `"75.00"`.
    ///
    /// The grammar is `(0|[1-9][0-9]*)\.[0-9]{2}`, as for EUR amounts
    /// (ADR-006). A canonical text above 100.00 is `OutOfRange`. Any other
    /// spelling, including a sign or a `%`, is a syntax error. Spellings are
    /// rejected, never normalised.
    pub fn parse(t: &str) -> Result<Percent, PercentParseError> {
        let value =
            parse_fixed(t.as_bytes(), 2, u64::from(Percent::MAX_BP)).map_err(refusal_to_error)?;
        let bp = u16::try_from(value).map_err(|_| PercentParseError::OutOfRange)?;
        Ok(Percent { bp })
    }

    /// The percentage of `bp` basis points, or `None` above
    /// [`Percent::MAX_BP`].
    pub fn from_bp(bp: u16) -> Option<Percent> {
        (bp <= Percent::MAX_BP).then_some(Percent { bp })
    }

    /// The value in basis points, from 0 to 10 000.
    pub fn bp(self) -> u16 {
        self.bp
    }
}

/// Maps a grammar refusal to the public error: a range error stays one, and
/// every other fault is a syntax error at its offset.
fn refusal_to_error(r: Refusal) -> PercentParseError {
    match r.fault {
        Fault::OutOfRange => PercentParseError::OutOfRange,
        Fault::Empty | Fault::UnexpectedByte | Fault::LeadingZero | Fault::WrongScale => {
            PercentParseError::Syntax { offset: r.offset }
        }
    }
}

impl fmt::Display for Percent {
    /// Writes the canonical two-decimal spelling, such as `75.00`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let int = self.bp.checked_div(100).unwrap_or(0);
        let frac = self.bp.checked_rem(100).unwrap_or(0);
        write!(f, "{int}.{frac:02}")
    }
}

/// Why a text is not a canonical percentage. Never holds input content.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PercentParseError {
    /// The text does not follow the grammar at this byte offset.
    Syntax {
        /// Byte offset of the first offending byte.
        offset: usize,
    },
    /// The value is above 100.00.
    OutOfRange,
}

impl PercentParseError {
    /// A fixed message for the error. It never holds input content.
    pub(crate) const fn message(self) -> &'static str {
        match self {
            PercentParseError::Syntax { .. } => "invalid percentage",
            PercentParseError::OutOfRange => "percentage above 100.00",
        }
    }
}

impl fmt::Display for PercentParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PercentParseError::Syntax { offset } => {
                write!(f, "{} at byte {offset}", self.message())
            }
            PercentParseError::OutOfRange => f.write_str(self.message()),
        }
    }
}

impl std::error::Error for PercentParseError {}

#[cfg(test)]
mod tests {
    use super::Percent;

    /// P-02: `Display` writes the canonical spelling that `parse` reads back,
    /// for every value from 0.00 to 100.00.
    #[test]
    fn p02_percent_display_round_trips_through_parse() {
        for bp in 0..=Percent::MAX_BP {
            let p = Percent::from_bp(bp).expect("in range");
            let text = p.to_string();
            assert_eq!(Percent::parse(&text), Ok(p), "{text}");
        }
    }

    /// P-02: `from_bp` accepts exactly 0 to 10 000 basis points.
    #[test]
    fn p02_percent_from_bp_refuses_above_100_00() {
        assert_eq!(Percent::from_bp(10_000).map(Percent::bp), Some(10_000));
        assert_eq!(Percent::from_bp(0).map(Percent::bp), Some(0));
        assert_eq!(Percent::from_bp(10_001), None);
        assert_eq!(Percent::from_bp(u16::MAX), None);
    }
}
