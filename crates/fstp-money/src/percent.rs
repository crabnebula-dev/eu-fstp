//! Percentages from 0.00 to 100.00 in basis points.

use core::fmt;

/// 0.00 to 100.00 percent in basis points. Canonical JSON form `"75.00"` (Q1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Percent {
    bp: u16,
}

impl Percent {
    /// Parses the canonical two-decimal spelling, such as `"75.00"`.
    ///
    /// Stub: returns `NotImplemented` until lane W1a.
    pub fn parse(t: &str) -> Result<Percent, PercentParseError> {
        let _ = t;
        Err(PercentParseError::NotImplemented)
    }

    /// The value in basis points, from 0 to 10 000.
    pub fn bp(self) -> u16 {
        self.bp
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
    /// Temporary: parsing is still a W0 stub. Lane W1a removes this variant
    /// when it replaces the stub bodies.
    NotImplemented,
}

impl fmt::Display for PercentParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PercentParseError::Syntax { offset } => {
                write!(f, "invalid percentage at byte {offset}")
            }
            PercentParseError::OutOfRange => f.write_str("percentage above 100.00"),
            PercentParseError::NotImplemented => f.write_str("not implemented"),
        }
    }
}

impl std::error::Error for PercentParseError {}
