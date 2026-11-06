//! The DATA body on the wire (RFC 5321 sections 4.5.2 and 4.5.3.1.6).
//!
//! [`stuff`] normalises line endings to CRLF, ends the body with CRLF and
//! doubles a leading dot. [`DataDecoder`] is the strict inverse that the
//! test sink uses: it accepts only what [`stuff`] produces, then `.` CRLF.

use std::fmt;

use crate::lines::{LineError, split_line};

/// Most octets in a wire line of DATA, with its CRLF.
pub const MAX_DATA_LINE: usize = 1000;

/// Most octets in a wire line of DATA, without its CRLF.
pub const MAX_BODY_LINE: usize = 998;

/// Why a body cannot be sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BodyError {
    /// A line, with its stuffing dot, is longer than [`MAX_BODY_LINE`].
    LineTooLong,
}

impl fmt::Display for BodyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("body line longer than 998 octets")
    }
}

impl std::error::Error for BodyError {}

/// Normalises and dot-stuffs `body` into its wire form, without the final
/// `.` CRLF. A non-empty result ends with CRLF.
///
/// # Errors
///
/// [`BodyError::LineTooLong`] when a wire line would exceed 998 octets.
pub fn stuff(body: &[u8]) -> Result<Vec<u8>, BodyError> {
    let mut out = Vec::with_capacity(body.len().saturating_add(2));
    let mut line_len = 0usize;
    let mut iter = body.iter().copied().peekable();
    while let Some(b) = iter.next() {
        match b {
            b'\r' => {
                if iter.peek() == Some(&b'\n') {
                    iter.next();
                }
                out.extend(b"\r\n");
                line_len = 0;
            }
            b'\n' => {
                out.extend(b"\r\n");
                line_len = 0;
            }
            _ => {
                if line_len == 0 && b == b'.' {
                    out.push(b'.');
                    line_len = 1;
                }
                out.push(b);
                line_len = line_len.saturating_add(1);
                if line_len > MAX_BODY_LINE {
                    return Err(BodyError::LineTooLong);
                }
            }
        }
    }
    if line_len > 0 {
        out.extend(b"\r\n");
    }
    Ok(out)
}

/// True when every byte of `body` is 7-bit.
pub fn is_7bit(body: &[u8]) -> bool {
    body.is_ascii()
}

/// Why the sink refused DATA.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataError {
    /// The line framing failed.
    Line(LineError),
    /// A line starts with one dot followed by something other than a dot.
    BadDotStuffing,
    /// The message is larger than the decoder allows.
    TooLarge,
    /// A line arrived after the terminator.
    Finished,
}

impl fmt::Display for DataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DataError::Line(e) => write!(f, "data line: {e}"),
            DataError::BadDotStuffing => f.write_str("non-canonical dot-stuffing"),
            DataError::TooLarge => f.write_str("message too large"),
            DataError::Finished => f.write_str("data after the terminator"),
        }
    }
}

impl std::error::Error for DataError {}

/// Decodes DATA one wire line at a time.
#[derive(Debug)]
pub struct DataDecoder {
    out: Vec<u8>,
    max_size: usize,
    done: bool,
}

impl DataDecoder {
    /// A decoder for messages of at most `max_size` octets.
    pub fn new(max_size: usize) -> Self {
        DataDecoder {
            out: Vec::new(),
            max_size,
            done: false,
        }
    }

    /// Takes one complete wire line with its CRLF. Returns `true` when it
    /// was the terminator `.` CRLF.
    ///
    /// # Errors
    ///
    /// [`DataError`] for a malformed line, non-canonical stuffing, an
    /// oversized message or a line after the terminator.
    pub fn feed_line(&mut self, line: &[u8]) -> Result<bool, DataError> {
        if self.done {
            return Err(DataError::Finished);
        }
        match split_line(line, MAX_DATA_LINE).map_err(DataError::Line)? {
            Some(n) if n == line.len() => {}
            _ => return Err(DataError::Line(LineError::BareCr)),
        }
        if line == b".\r\n" {
            self.done = true;
            return Ok(true);
        }
        let kept = match line.strip_prefix(b".") {
            Some(rest) if rest.first() == Some(&b'.') => rest,
            Some(_) => return Err(DataError::BadDotStuffing),
            None => line,
        };
        if self.out.len().saturating_add(kept.len()) > self.max_size {
            return Err(DataError::TooLarge);
        }
        self.out.extend(kept);
        Ok(false)
    }

    /// The decoded message.
    pub fn into_message(self) -> Vec<u8> {
        self.out
    }
}
