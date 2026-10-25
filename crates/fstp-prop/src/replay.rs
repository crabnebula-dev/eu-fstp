//! The text format of a choice sequence, used by `FSTP_PROP_REPLAY`.
//!
//! A sequence is written as lowercase hexadecimal numbers separated by commas,
//! for example `3e8,0,1f`. Numbers have no leading zeros, except `0` itself.
//! The empty sequence is the empty string. Leading and trailing ASCII
//! whitespace is ignored when parsing.
//!
//! The format is canonical: every input that parses is exactly what
//! [`format_replay`] writes for the parsed sequence, after trimming
//! whitespace. Parsing is bounded by [`ReplayLimits`].

use core::fmt;

/// Limits enforced by [`parse_replay_with`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplayLimits {
    /// Maximum input length in bytes, after trimming whitespace.
    pub max_input_len: usize,
    /// Maximum number of choices.
    pub max_choices: usize,
}

impl Default for ReplayLimits {
    /// 16 MiB of input and 2^20 choices.
    fn default() -> ReplayLimits {
        ReplayLimits {
            max_input_len: 16 << 20,
            max_choices: 1 << 20,
        }
    }
}

/// Why a replay string failed to parse. Offsets count bytes after trimming.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplayParseError {
    /// The input is longer than [`ReplayLimits::max_input_len`].
    InputTooLong {
        /// The configured limit.
        limit: usize,
    },
    /// The input holds more than [`ReplayLimits::max_choices`] choices.
    TooManyChoices {
        /// The configured limit.
        limit: usize,
    },
    /// A byte that is neither a lowercase hex digit nor a comma.
    InvalidByte {
        /// Offset of the byte.
        offset: usize,
        /// The byte.
        byte: u8,
    },
    /// Two adjacent commas, or a comma at the start or end.
    EmptyElement {
        /// Offset where the empty element starts.
        offset: usize,
    },
    /// A number with a leading zero, which is not canonical.
    LeadingZero {
        /// Offset of the number.
        offset: usize,
    },
    /// A number larger than `u64::MAX`.
    Overflow {
        /// Offset of the number.
        offset: usize,
    },
}

impl fmt::Display for ReplayParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReplayParseError::InputTooLong { limit } => {
                write!(f, "replay input is longer than {limit} bytes")
            }
            ReplayParseError::TooManyChoices { limit } => {
                write!(f, "replay input holds more than {limit} choices")
            }
            ReplayParseError::InvalidByte { offset, byte } => {
                write!(
                    f,
                    "invalid byte {byte:#04x} at offset {offset}; expected lowercase hex digits and commas"
                )
            }
            ReplayParseError::EmptyElement { offset } => {
                write!(f, "empty element at offset {offset}")
            }
            ReplayParseError::LeadingZero { offset } => {
                write!(f, "number with a leading zero at offset {offset}")
            }
            ReplayParseError::Overflow { offset } => {
                write!(f, "number larger than u64::MAX at offset {offset}")
            }
        }
    }
}

impl std::error::Error for ReplayParseError {}

/// Writes a choice sequence in the replay format.
pub fn format_replay(choices: &[u64]) -> String {
    let mut out = String::with_capacity(choices.len().saturating_mul(3));
    for (i, c) in choices.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&format!("{c:x}"));
    }
    out
}

/// Parses a replay string with the default [`ReplayLimits`].
pub fn parse_replay(input: &str) -> Result<Vec<u64>, ReplayParseError> {
    parse_replay_with(input.as_bytes(), &ReplayLimits::default())
}

/// Parses a replay string from raw bytes with explicit limits. Never panics.
pub fn parse_replay_with(
    input: &[u8],
    limits: &ReplayLimits,
) -> Result<Vec<u64>, ReplayParseError> {
    let input = input.trim_ascii();
    if input.len() > limits.max_input_len {
        return Err(ReplayParseError::InputTooLong {
            limit: limits.max_input_len,
        });
    }
    let mut out = Vec::new();
    if input.is_empty() {
        return Ok(out);
    }
    let mut offset = 0usize;
    for element in input.split(|&b| b == b',') {
        if out.len() >= limits.max_choices {
            return Err(ReplayParseError::TooManyChoices {
                limit: limits.max_choices,
            });
        }
        out.push(parse_element(element, offset)?);
        offset = offset.saturating_add(element.len()).saturating_add(1);
    }
    Ok(out)
}

/// Parses one canonical lowercase hex number that starts at `offset`.
fn parse_element(element: &[u8], offset: usize) -> Result<u64, ReplayParseError> {
    match element {
        [] => return Err(ReplayParseError::EmptyElement { offset }),
        [b'0', _, ..] => return Err(ReplayParseError::LeadingZero { offset }),
        _ => {}
    }
    let mut value = 0u64;
    for (i, &b) in element.iter().enumerate() {
        let digit = match b {
            b'0'..=b'9' => b.wrapping_sub(b'0'),
            b'a'..=b'f' => b.wrapping_sub(b'a').wrapping_add(10),
            _ => {
                return Err(ReplayParseError::InvalidByte {
                    offset: offset.saturating_add(i),
                    byte: b,
                });
            }
        };
        value = value
            .checked_mul(16)
            .and_then(|v| v.checked_add(u64::from(digit)))
            .ok_or(ReplayParseError::Overflow { offset })?;
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        for seq in [
            vec![],
            vec![0],
            vec![0, 0],
            vec![1000],
            vec![1, 0, 1, 0, 1],
            vec![u64::MAX, 0, 15, 16, 255],
        ] {
            let s = format_replay(&seq);
            assert_eq!(parse_replay(&s), Ok(seq.clone()), "{s}");
        }
        assert_eq!(format_replay(&[1000, 0, 31]), "3e8,0,1f");
        assert_eq!(parse_replay("  3e8,0,1f\n"), Ok(vec![1000, 0, 31]));
    }

    /// TH-26: the replay parser rejects malformed input with typed errors.
    #[test]
    fn th26_rejects_malformed_input() {
        use ReplayParseError as E;
        assert_eq!(parse_replay(","), Err(E::EmptyElement { offset: 0 }));
        assert_eq!(parse_replay("1,"), Err(E::EmptyElement { offset: 2 }));
        assert_eq!(parse_replay("1,,2"), Err(E::EmptyElement { offset: 2 }));
        assert_eq!(parse_replay("01"), Err(E::LeadingZero { offset: 0 }));
        assert_eq!(parse_replay("1,00"), Err(E::LeadingZero { offset: 2 }));
        assert_eq!(
            parse_replay("1,A"),
            Err(E::InvalidByte {
                offset: 2,
                byte: b'A'
            })
        );
        assert_eq!(
            parse_replay("1 2"),
            Err(E::InvalidByte {
                offset: 1,
                byte: b' '
            })
        );
        assert_eq!(parse_replay("ffffffffffffffff"), Ok(vec![u64::MAX]));
        assert_eq!(
            parse_replay("1,10000000000000000"),
            Err(E::Overflow { offset: 2 })
        );
        let limits = ReplayLimits {
            max_input_len: 5,
            max_choices: 2,
        };
        assert_eq!(
            parse_replay_with(b"1,2,3", &limits),
            Err(E::TooManyChoices { limit: 2 })
        );
        assert_eq!(
            parse_replay_with(b"100000", &limits),
            Err(E::InputTooLong { limit: 5 })
        );
        assert_eq!(parse_replay_with(b"1,2", &limits), Ok(vec![1, 2]));
        assert_eq!(
            parse_replay_with(&[0xff], &limits),
            Err(E::InvalidByte {
                offset: 0,
                byte: 0xff
            })
        );
        assert!(!E::Overflow { offset: 0 }.to_string().is_empty());
    }
}
