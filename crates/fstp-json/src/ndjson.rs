//! Newline-delimited JSON: one JSON text per line.
//!
//! Tenant export files use this format (`schemas/README.md`).
//!
//! # Reader rules
//!
//! - A line ends at a line feed. A carriage return directly before the line
//!   feed is removed, so both LF and CRLF line endings work.
//! - The last line may end without a line feed.
//! - An empty input holds no values and is not an error.
//! - A blank line, empty or holding only JSON whitespace, is an error. A blank
//!   line in an export file signals truncation or concatenation damage, and
//!   import validates everything before writing (`schemas/README.md`).
//! - Each line must be one complete JSON text under the configured
//!   [`ParseLimits`]. Whitespace around the value is allowed.
//! - A line longer than [`NdjsonOptions::max_line_bytes`] is an error. The
//!   reader never buffers more than that limit plus one byte.
//! - The first error ends the stream. Later calls return `None`.
//!
//! # Writer rules
//!
//! The writer emits each value as compact JSON followed by a line feed. Compact
//! output never contains a raw line feed, because the serializer escapes every
//! control character inside strings.

use core::fmt;
use std::io::{self, BufRead, Write};

use crate::parse::{ParseError, ParseLimits, parse_with};
use crate::ser::{WriteOptions, write_value};
use crate::typed::{FromJson, FromJsonError, ToJson};
use crate::value::Value;

/// Settings for an [`NdjsonReader`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NdjsonOptions {
    /// Maximum bytes in one line, excluding the line ending. Default 4 MiB.
    pub max_line_bytes: usize,
    /// Limits applied to each line's JSON text.
    pub limits: ParseLimits,
}

impl Default for NdjsonOptions {
    fn default() -> NdjsonOptions {
        NdjsonOptions {
            max_line_bytes: 4 << 20,
            limits: ParseLimits::default(),
        }
    }
}

/// What went wrong while reading NDJSON.
#[derive(Debug)]
#[non_exhaustive]
pub enum NdjsonErrorKind {
    /// The underlying reader failed.
    Io(io::Error),
    /// The line is longer than [`NdjsonOptions::max_line_bytes`].
    LineTooLong,
    /// The line is empty or holds only whitespace.
    BlankLine,
    /// The line is not one valid JSON text. Its line and column refer to the
    /// line on its own, so the line is always 1.
    Parse(ParseError),
    /// The value does not map to the requested type.
    Typed(FromJsonError),
}

/// An NDJSON read failure with its line number.
///
/// The message never contains input content (R-NF-02).
#[derive(Debug)]
pub struct NdjsonError {
    line: u64,
    kind: NdjsonErrorKind,
}

impl NdjsonError {
    /// The line number, starting at 1.
    pub fn line(&self) -> u64 {
        self.line
    }

    /// What went wrong.
    pub fn kind(&self) -> &NdjsonErrorKind {
        &self.kind
    }

    /// Consumes the error and returns what went wrong.
    pub fn into_kind(self) -> NdjsonErrorKind {
        self.kind
    }
}

impl fmt::Display for NdjsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            NdjsonErrorKind::Io(e) => write!(f, "line {}: read error: {}", self.line, e.kind()),
            NdjsonErrorKind::LineTooLong => write!(f, "line {}: line too long", self.line),
            NdjsonErrorKind::BlankLine => write!(f, "line {}: blank line", self.line),
            NdjsonErrorKind::Parse(e) => write!(
                f,
                "line {}: {} at column {}",
                self.line,
                e.kind().message(),
                e.column()
            ),
            NdjsonErrorKind::Typed(e) => write!(f, "line {}: {e}", self.line),
        }
    }
}

impl std::error::Error for NdjsonError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.kind {
            NdjsonErrorKind::Io(e) => Some(e),
            NdjsonErrorKind::Parse(e) => Some(e),
            NdjsonErrorKind::Typed(e) => Some(e),
            _ => None,
        }
    }
}

/// Reads one JSON value per line from a [`BufRead`].
///
/// ```
/// use fstp_json::NdjsonReader;
/// let input = b"{\"id\":1}\r\n{\"id\":2}\n";
/// let ids: Vec<u64> = NdjsonReader::new(&input[..])
///     .map(|v| v.unwrap().get("id").unwrap().as_u64().unwrap())
///     .collect();
/// assert_eq!(ids, [1, 2]);
/// ```
pub struct NdjsonReader<R> {
    reader: R,
    options: NdjsonOptions,
    line: u64,
    buf: Vec<u8>,
    done: bool,
}

impl<R: BufRead> NdjsonReader<R> {
    /// A reader with the default options.
    pub fn new(reader: R) -> NdjsonReader<R> {
        NdjsonReader::with_options(reader, NdjsonOptions::default())
    }

    /// A reader with the given options.
    pub fn with_options(reader: R, options: NdjsonOptions) -> NdjsonReader<R> {
        NdjsonReader {
            reader,
            options,
            line: 0,
            buf: Vec::new(),
            done: false,
        }
    }

    /// The number of the last line read, starting at 1. 0 before the first line.
    pub fn line(&self) -> u64 {
        self.line
    }

    /// Returns the underlying reader.
    pub fn into_inner(self) -> R {
        self.reader
    }

    fn fail(&mut self, kind: NdjsonErrorKind) -> NdjsonError {
        self.done = true;
        self.buf = Vec::new();
        NdjsonError {
            line: self.line,
            kind,
        }
    }

    /// Reads the next line into `self.buf`, without its line ending.
    /// Returns `Ok(false)` at the end of input.
    fn read_line(&mut self) -> Result<bool, NdjsonErrorKind> {
        self.buf.clear();
        // One extra byte leaves room for the carriage return of a CRLF ending.
        let cap = self.options.max_line_bytes.saturating_add(1);
        let mut saw_bytes = false;
        loop {
            let chunk = match self.reader.fill_buf() {
                Ok(chunk) => chunk,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(NdjsonErrorKind::Io(e)),
            };
            if chunk.is_empty() {
                if !saw_bytes {
                    return Ok(false);
                }
                break;
            }
            saw_bytes = true;
            let newline = chunk.iter().position(|&b| b == b'\n');
            let take = newline.unwrap_or(chunk.len());
            if self.buf.len().saturating_add(take) > cap {
                return Err(NdjsonErrorKind::LineTooLong);
            }
            self.buf
                .extend_from_slice(chunk.get(..take).unwrap_or_default());
            match newline {
                Some(i) => {
                    self.reader.consume(i.saturating_add(1));
                    break;
                }
                None => {
                    let n = chunk.len();
                    self.reader.consume(n);
                }
            }
        }
        if self.buf.last() == Some(&b'\r') {
            self.buf.pop();
        }
        if self.buf.len() > self.options.max_line_bytes {
            return Err(NdjsonErrorKind::LineTooLong);
        }
        Ok(true)
    }

    /// Reads the next value. `None` at the end of input or after an error.
    pub fn next_value(&mut self) -> Option<Result<Value, NdjsonError>> {
        if self.done {
            return None;
        }
        let line = self.line.saturating_add(1);
        match self.read_line() {
            Ok(true) => self.line = line,
            Ok(false) => {
                self.done = true;
                return None;
            }
            Err(kind) => {
                self.line = line;
                return Some(Err(self.fail(kind)));
            }
        }
        if self
            .buf
            .iter()
            .all(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
        {
            return Some(Err(self.fail(NdjsonErrorKind::BlankLine)));
        }
        match parse_with(&self.buf, &self.options.limits) {
            Ok(v) => Some(Ok(v)),
            Err(e) => Some(Err(self.fail(NdjsonErrorKind::Parse(e)))),
        }
    }

    /// Reads the next value and maps it to `T`.
    pub fn next_typed<T: FromJson>(&mut self) -> Option<Result<T, NdjsonError>> {
        let value = match self.next_value()? {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };
        match T::from_json(&value) {
            Ok(t) => Some(Ok(t)),
            Err(e) => Some(Err(self.fail(NdjsonErrorKind::Typed(e)))),
        }
    }
}

impl<R: BufRead> Iterator for NdjsonReader<R> {
    type Item = Result<Value, NdjsonError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_value()
    }
}

/// Writes one compact JSON value per line.
///
/// Wrap unbuffered sinks in a [`std::io::BufWriter`]. Call
/// [`NdjsonWriter::flush`] before dropping it.
pub struct NdjsonWriter<W> {
    inner: W,
    buf: String,
}

impl<W: Write> NdjsonWriter<W> {
    /// A writer over `inner`.
    pub fn new(inner: W) -> NdjsonWriter<W> {
        NdjsonWriter {
            inner,
            buf: String::new(),
        }
    }

    /// Writes `value` as compact JSON and a line feed.
    pub fn write_value(&mut self, value: &Value) -> io::Result<()> {
        self.buf.clear();
        write_value(&mut self.buf, value, WriteOptions::compact());
        self.buf.push('\n');
        self.inner.write_all(self.buf.as_bytes())
    }

    /// Converts `item` with [`ToJson`] and writes it as one line.
    pub fn write<T: ToJson + ?Sized>(&mut self, item: &T) -> io::Result<()> {
        self.write_value(&item.to_json())
    }

    /// Flushes the underlying writer.
    pub fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }

    /// A reference to the underlying writer.
    pub fn get_ref(&self) -> &W {
        &self.inner
    }

    /// Returns the underlying writer without flushing it.
    pub fn into_inner(self) -> W {
        self.inner
    }
}
