//! Strict parser for SMTP replies (RFC 5321 section 4.2).
//!
//! A reply is one or more lines `code "-" text CRLF`, closed by a line
//! `code [SP text] CRLF`. Every line carries the same code. Text is HT and
//! printable ASCII only. Line length and line count are bounded by
//! [`ReplyLimits`]. An accepted reply re-encodes to its exact bytes.

use std::fmt;

use crate::lines::{LineError, content, split_line};

/// Bounds on a reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplyLimits {
    /// Most octets in one line, with its CRLF.
    pub max_line: usize,
    /// Most lines in one reply.
    pub max_lines: usize,
}

impl Default for ReplyLimits {
    /// 1000 octets per line (M6 design section 5.2) and 64 lines.
    fn default() -> Self {
        ReplyLimits {
            max_line: 1000,
            max_lines: 64,
        }
    }
}

/// Why a reply was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplyError {
    /// The line framing failed.
    Line(LineError),
    /// The code is not three digits from 200 to 559 with a second digit
    /// from 0 to 5.
    BadCode,
    /// The code is not followed by SP, `-` or CRLF.
    BadSeparator,
    /// The text holds a byte other than HT and printable ASCII, or the
    /// closing line has SP but no text.
    BadText,
    /// A line carries a different code from the first line.
    CodeMismatch,
    /// More lines than [`ReplyLimits::max_lines`].
    TooManyLines,
    /// A reply needs at least one line.
    NoLines,
}

impl fmt::Display for ReplyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReplyError::Line(e) => write!(f, "reply line: {e}"),
            ReplyError::BadCode => f.write_str("bad reply code"),
            ReplyError::BadSeparator => f.write_str("bad separator after reply code"),
            ReplyError::BadText => f.write_str("bad reply text"),
            ReplyError::CodeMismatch => f.write_str("reply lines carry different codes"),
            ReplyError::TooManyLines => f.write_str("too many reply lines"),
            ReplyError::NoLines => f.write_str("reply without lines"),
        }
    }
}

impl std::error::Error for ReplyError {}

/// The class of a reply, from its first digit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplyClass {
    /// 2yz: completed.
    Positive,
    /// 3yz: more input expected.
    Intermediate,
    /// 4yz: transient failure.
    Transient,
    /// 5yz: permanent failure.
    Permanent,
}

/// One SMTP reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reply {
    code: u16,
    lines: Vec<String>,
}

fn valid_code(code: u16) -> bool {
    (200..=559).contains(&code) && (code / 10) % 10 <= 5
}

fn valid_text(text: &[u8]) -> bool {
    text.iter()
        .all(|&b| b == b'\t' || (0x20..=0x7e).contains(&b))
}

impl Reply {
    /// A reply with `code` and its text lines.
    ///
    /// # Errors
    ///
    /// [`ReplyError`] when the code or a text is not valid, or `lines` is
    /// empty.
    pub fn new(code: u16, lines: Vec<String>) -> Result<Reply, ReplyError> {
        if !valid_code(code) {
            return Err(ReplyError::BadCode);
        }
        if lines.is_empty() {
            return Err(ReplyError::NoLines);
        }
        if lines.iter().any(|l| !valid_text(l.as_bytes())) {
            return Err(ReplyError::BadText);
        }
        Ok(Reply { code, lines })
    }

    /// The three-digit code.
    pub fn code(&self) -> u16 {
        self.code
    }

    /// The text of each line, without code and separator.
    pub fn lines(&self) -> &[String] {
        &self.lines
    }

    /// The class from the first digit.
    pub fn class(&self) -> ReplyClass {
        match self.code / 100 {
            2 => ReplyClass::Positive,
            3 => ReplyClass::Intermediate,
            4 => ReplyClass::Transient,
            _ => ReplyClass::Permanent,
        }
    }

    /// The wire form. Parsing it gives back this reply.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let code = self.code.to_string();
        let last = self.lines.len().saturating_sub(1);
        for (i, text) in self.lines.iter().enumerate() {
            out.extend(code.as_bytes());
            if i < last {
                out.push(b'-');
                out.extend(text.as_bytes());
            } else if !text.is_empty() {
                out.push(b' ');
                out.extend(text.as_bytes());
            }
            out.extend(b"\r\n");
        }
        out
    }
}

fn parse_code(line: &[u8]) -> Result<u16, ReplyError> {
    let digits = line.get(..3).ok_or(ReplyError::BadCode)?;
    let mut code: u16 = 0;
    for &d in digits {
        if !d.is_ascii_digit() {
            return Err(ReplyError::BadCode);
        }
        code = code
            .saturating_mul(10)
            .saturating_add(u16::from(d.wrapping_sub(b'0')));
    }
    if valid_code(code) {
        Ok(code)
    } else {
        Err(ReplyError::BadCode)
    }
}

/// Parses one reply from the start of `buf`.
///
/// Returns the reply and the bytes it used, or `None` when more bytes are
/// needed. Bytes after the reply are left alone.
///
/// # Errors
///
/// [`ReplyError`] when the bytes cannot start a valid reply.
pub fn parse_reply(buf: &[u8], limits: &ReplyLimits) -> Result<Option<(Reply, usize)>, ReplyError> {
    let mut off = 0usize;
    let mut code = None;
    let mut lines = Vec::new();
    loop {
        let rest = buf.get(off..).unwrap_or_default();
        let Some(n) = split_line(rest, limits.max_line).map_err(ReplyError::Line)? else {
            return Ok(None);
        };
        if lines.len() >= limits.max_lines {
            return Err(ReplyError::TooManyLines);
        }
        let line = content(rest.get(..n).unwrap_or_default());
        let c = parse_code(line)?;
        if code.is_some_and(|first| first != c) {
            return Err(ReplyError::CodeMismatch);
        }
        code = Some(c);
        let text = line.get(4..).unwrap_or_default();
        let last = match line.get(3) {
            None => true,
            Some(b' ') if text.is_empty() => return Err(ReplyError::BadText),
            Some(b' ') => true,
            Some(b'-') => false,
            Some(_) => return Err(ReplyError::BadSeparator),
        };
        if !valid_text(text) {
            return Err(ReplyError::BadText);
        }
        // Valid text is ASCII, so this conversion cannot fail.
        lines.push(String::from_utf8_lossy(text).into_owned());
        off = off.saturating_add(n);
        if last {
            return Ok(Some((Reply { code: c, lines }, off)));
        }
    }
}
