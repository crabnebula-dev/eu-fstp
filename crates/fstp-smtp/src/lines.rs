//! CRLF line framing shared by replies, commands and DATA.

use std::fmt;

/// Why a line could not be framed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LineError {
    /// The line, with its CRLF, is longer than the limit.
    TooLong,
    /// A CR is not followed by LF.
    BareCr,
    /// An LF is not preceded by CR.
    BareLf,
}

impl fmt::Display for LineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            LineError::TooLong => "line too long",
            LineError::BareCr => "bare CR",
            LineError::BareLf => "bare LF",
        })
    }
}

impl std::error::Error for LineError {}

/// Finds the first complete line of `buf`.
///
/// Returns its length with the CRLF, or `None` when more bytes are needed.
/// A line may hold at most `max` octets with its CRLF.
///
/// # Errors
///
/// [`LineError`] when the line is too long or holds a bare CR or LF.
pub fn split_line(buf: &[u8], max: usize) -> Result<Option<usize>, LineError> {
    for (i, &b) in buf.iter().enumerate() {
        if i >= max {
            return Err(LineError::TooLong);
        }
        match b {
            b'\r' => {
                return match buf.get(i.saturating_add(1)) {
                    Some(b'\n') => {
                        let len = i.saturating_add(2);
                        if len > max {
                            Err(LineError::TooLong)
                        } else {
                            Ok(Some(len))
                        }
                    }
                    Some(_) => Err(LineError::BareCr),
                    None if i.saturating_add(2) > max => Err(LineError::TooLong),
                    None => Ok(None),
                };
            }
            b'\n' => return Err(LineError::BareLf),
            _ => {}
        }
    }
    Ok(None)
}

/// The line without its CRLF. `line` must be a whole line from
/// [`split_line`].
pub(crate) fn content(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\r\n").unwrap_or(line)
}
