//! Strict RFC 8259 parser with the I-JSON restrictions of RFC 7493.
//!
//! The parser keeps an explicit stack of open containers and never recurses,
//! so nesting depth cannot overflow the call stack. Every byte is examined a
//! bounded number of times, and duplicate names are found with a hash index,
//! so parsing takes expected linear time. Every resource is bounded by
//! [`ParseLimits`].

use core::fmt;

use crate::number::{Number, ScanError, scan_number};
use crate::object::{LINEAR_MAX, Object};
use crate::value::{Array, Value, exact_capacity};

/// Resource limits for one parse. Every limit is inclusive.
///
/// The defaults suit untrusted API payloads. With them, the estimated memory
/// of a parsed value is at most 32 MiB, eight times the default input limit
/// (see [`ParseLimits::max_memory_bytes`]). Tools that read large trusted
/// documents raise the limits with the `with_*` methods.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParseLimits {
    /// Maximum input length in bytes. Default 4 MiB.
    pub max_input_bytes: usize,
    /// Maximum nesting depth of arrays and objects. A scalar has depth 0 and
    /// `[[]]` has depth 2. Default 128.
    pub max_depth: usize,
    /// Maximum decoded length of one string or member name, in UTF-8 bytes.
    /// Default 1 MiB.
    pub max_string_bytes: usize,
    /// Maximum length of one number lexeme in bytes, sign included. Default 256.
    pub max_number_len: usize,
    /// Maximum number of elements in one array or members in one object.
    /// Default 100 000.
    pub max_container_len: usize,
    /// Maximum number of values in the document, containers included.
    /// Member names do not count. Default 1 000 000.
    pub max_nodes: usize,
    /// Maximum estimated heap memory of the parsed value, in bytes.
    /// Default 32 MiB.
    ///
    /// The estimate charges:
    ///
    /// - 64 bytes for each value, containers included;
    /// - 64 bytes for each member name;
    /// - the decoded length of every string and member name, and the length
    ///   of every number lexeme;
    /// - for an object with more than 8 members, 128 bytes plus 80 bytes per
    ///   member for its hash index.
    ///
    /// The estimate approximates the heap memory of the finished value on a
    /// 64-bit target. Allocator overhead and fragmentation can add a few
    /// percent. While the parse runs, growing arrays and objects also hold
    /// spare capacity, so peak use can reach about twice the estimate.
    ///
    /// Dense input, such as an array of one-digit numbers, costs about 33
    /// bytes per input byte. It reaches the default limit at about 1 MiB of
    /// input. Output of `cargo metadata` costs about 7 bytes per input byte,
    /// so the default admits about 4 MiB of it.
    pub max_memory_bytes: usize,
}

impl Default for ParseLimits {
    fn default() -> ParseLimits {
        ParseLimits {
            max_input_bytes: 4 << 20,
            max_depth: 128,
            max_string_bytes: 1 << 20,
            max_number_len: 256,
            max_container_len: 100_000,
            max_nodes: 1_000_000,
            max_memory_bytes: 32 << 20,
        }
    }
}

impl ParseLimits {
    /// Sets [`ParseLimits::max_input_bytes`].
    pub fn with_max_input_bytes(mut self, n: usize) -> ParseLimits {
        self.max_input_bytes = n;
        self
    }

    /// Sets [`ParseLimits::max_depth`].
    pub fn with_max_depth(mut self, n: usize) -> ParseLimits {
        self.max_depth = n;
        self
    }

    /// Sets [`ParseLimits::max_string_bytes`].
    pub fn with_max_string_bytes(mut self, n: usize) -> ParseLimits {
        self.max_string_bytes = n;
        self
    }

    /// Sets [`ParseLimits::max_number_len`].
    pub fn with_max_number_len(mut self, n: usize) -> ParseLimits {
        self.max_number_len = n;
        self
    }

    /// Sets [`ParseLimits::max_container_len`].
    pub fn with_max_container_len(mut self, n: usize) -> ParseLimits {
        self.max_container_len = n;
        self
    }

    /// Sets [`ParseLimits::max_nodes`].
    pub fn with_max_nodes(mut self, n: usize) -> ParseLimits {
        self.max_nodes = n;
        self
    }

    /// Sets [`ParseLimits::max_memory_bytes`].
    pub fn with_max_memory_bytes(mut self, n: usize) -> ParseLimits {
        self.max_memory_bytes = n;
        self
    }
}

/// Estimated cost of one value: a 32-byte slot and the overhead of one heap
/// allocation. See [`ParseLimits::max_memory_bytes`].
const VALUE_COST: usize = 64;
/// Estimated cost of one member name: a 24-byte `String` and the overhead of
/// its allocation. The member's value is charged separately.
const MEMBER_COST: usize = 64;
/// Estimated fixed cost of the hash index of a large object.
const INDEX_COST: usize = 128;
/// Estimated cost of one member in the hash index of a large object. A table
/// entry takes 33 bytes and the table can be 16/7 times larger than needed.
const INDEX_MEMBER_COST: usize = 80;
/// Estimated cost of building the index, which covers the members so far
/// and the one that triggers it.
const INDEX_BUILD_COST: usize = INDEX_COST + INDEX_MEMBER_COST * (LINEAR_MAX + 1);

/// Which [`ParseLimits`] field an input exceeded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Limit {
    /// [`ParseLimits::max_input_bytes`].
    InputBytes,
    /// [`ParseLimits::max_depth`].
    Depth,
    /// [`ParseLimits::max_string_bytes`].
    StringBytes,
    /// [`ParseLimits::max_number_len`].
    NumberLength,
    /// [`ParseLimits::max_container_len`].
    ContainerLength,
    /// [`ParseLimits::max_nodes`].
    Nodes,
    /// [`ParseLimits::max_memory_bytes`].
    MemoryBytes,
}

/// What went wrong in a parse.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ParseErrorKind {
    /// The input ended inside a value, or held no value at all.
    UnexpectedEnd,
    /// A byte that the grammar does not allow here.
    UnexpectedCharacter,
    /// A whitespace character that JSON does not allow, such as form feed,
    /// vertical tab, no-break space or U+FEFF. JSON whitespace is only space,
    /// tab, line feed and carriage return.
    InvalidWhitespace,
    /// The input starts with a UTF-8 byte order mark.
    ByteOrderMark,
    /// A `//` or `/*` comment.
    Comment,
    /// A comma directly before `]` or `}`.
    TrailingComma,
    /// More input after the top-level value.
    TrailingCharacters,
    /// A bare word that is not `true`, `false` or `null`, such as `NaN`.
    InvalidLiteral,
    /// A number that breaks the RFC 8259 grammar.
    InvalidNumber,
    /// An integer part with a leading zero, such as `01`.
    LeadingZero,
    /// A raw control character (U+0000 to U+001F) inside a string.
    ControlCharacter,
    /// A backslash escape that RFC 8259 does not define.
    InvalidEscape,
    /// A `\u` escape of a surrogate that is not part of a valid pair (RFC 7493).
    LoneSurrogate,
    /// Bytes inside a string that are not valid UTF-8.
    InvalidUtf8,
    /// An object repeats a member name (RFC 7493).
    DuplicateKey,
    /// An object member name is not followed by `:`.
    ExpectedColon,
    /// An object member does not start with a string name.
    ExpectedKey,
    /// The input exceeds a configured limit.
    LimitExceeded(Limit),
}

impl ParseErrorKind {
    /// A short description with no input content.
    pub fn message(self) -> &'static str {
        match self {
            ParseErrorKind::UnexpectedEnd => "unexpected end of input",
            ParseErrorKind::UnexpectedCharacter => "unexpected character",
            ParseErrorKind::InvalidWhitespace => "whitespace character not allowed in JSON",
            ParseErrorKind::ByteOrderMark => "byte order mark not allowed",
            ParseErrorKind::Comment => "comments are not allowed",
            ParseErrorKind::TrailingComma => "trailing comma",
            ParseErrorKind::TrailingCharacters => "unexpected data after the top-level value",
            ParseErrorKind::InvalidLiteral => "invalid literal",
            ParseErrorKind::InvalidNumber => "invalid number",
            ParseErrorKind::LeadingZero => "leading zero in number",
            ParseErrorKind::ControlCharacter => "unescaped control character in string",
            ParseErrorKind::InvalidEscape => "invalid escape sequence",
            ParseErrorKind::LoneSurrogate => "lone surrogate in \\u escape",
            ParseErrorKind::InvalidUtf8 => "invalid UTF-8",
            ParseErrorKind::DuplicateKey => "duplicate member name",
            ParseErrorKind::ExpectedColon => "expected ':' after member name",
            ParseErrorKind::ExpectedKey => "expected a string member name",
            ParseErrorKind::LimitExceeded(Limit::InputBytes) => "input too large",
            ParseErrorKind::LimitExceeded(Limit::Depth) => "nesting too deep",
            ParseErrorKind::LimitExceeded(Limit::StringBytes) => "string too long",
            ParseErrorKind::LimitExceeded(Limit::NumberLength) => "number too long",
            ParseErrorKind::LimitExceeded(Limit::ContainerLength) => "too many members or elements",
            ParseErrorKind::LimitExceeded(Limit::Nodes) => "too many values",
            ParseErrorKind::LimitExceeded(Limit::MemoryBytes) => "document needs too much memory",
        }
    }
}

/// A parse failure with its position.
///
/// The message and position never contain input content (R-NF-02).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ParseError {
    kind: ParseErrorKind,
    offset: usize,
    line: usize,
    column: usize,
}

impl ParseError {
    /// Builds an error at `offset` in `input`, computing line and column.
    pub(crate) fn at(input: &[u8], offset: usize, kind: ParseErrorKind) -> ParseError {
        let (line, column) = locate(input, offset);
        ParseError {
            kind,
            offset,
            line,
            column,
        }
    }

    /// What went wrong.
    pub fn kind(&self) -> ParseErrorKind {
        self.kind
    }

    /// Byte offset of the error from the start of the input.
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// Line of the error, starting at 1. Only line feeds start new lines.
    pub fn line(&self) -> usize {
        self.line
    }

    /// Column of the error, starting at 1, counted in Unicode scalar values
    /// from the start of the line.
    pub fn column(&self) -> usize {
        self.column
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} at line {}, column {} (byte {})",
            self.kind.message(),
            self.line,
            self.column,
            self.offset
        )
    }
}

impl std::error::Error for ParseError {}

/// Line and column of `offset`. Counts code points as the bytes that are not
/// UTF-8 continuation bytes, so it never fails on invalid input.
fn locate(input: &[u8], offset: usize) -> (usize, usize) {
    let prefix = input.get(..offset).unwrap_or(input);
    let line_start = prefix
        .iter()
        .rposition(|&b| b == b'\n')
        .map_or(0, |i| i.saturating_add(1));
    let line = prefix
        .iter()
        .filter(|&&b| b == b'\n')
        .count()
        .saturating_add(1);
    let column = prefix
        .get(line_start..)
        .unwrap_or_default()
        .iter()
        .filter(|&&b| (b & 0xC0) != 0x80)
        .count()
        .saturating_add(1);
    (line, column)
}

/// Parses one JSON text with the default [`ParseLimits`].
///
/// Any value may be the top-level value. Whitespace may surround it.
///
/// ```
/// let v = fstp_json::parse(br#"{"amount": 12.50, "tags": ["a"]}"#).unwrap();
/// assert_eq!(v.get("amount").unwrap().as_number().unwrap().as_str(), "12.50");
/// assert!(fstp_json::parse(br#"{"a": 1, "a": 2}"#).is_err());
/// ```
pub fn parse(input: &[u8]) -> Result<Value, ParseError> {
    parse_with(input, &ParseLimits::default())
}

/// Parses one JSON text with the given limits.
pub fn parse_with(input: &[u8], limits: &ParseLimits) -> Result<Value, ParseError> {
    Parser {
        input,
        pos: 0,
        limits,
        nodes: 0,
        memory: 0,
    }
    .document()
}

/// Parses one JSON text from a string with the default limits.
pub fn parse_str(input: &str) -> Result<Value, ParseError> {
    parse(input.as_bytes())
}

/// An open container.
enum Frame {
    Array(Vec<Value>),
    /// An object and the name of the member whose value is being parsed.
    Object(Object, String),
}

struct Parser<'a> {
    input: &'a [u8],
    pos: usize,
    limits: &'a ParseLimits,
    nodes: usize,
    /// Estimated heap bytes charged so far (see [`ParseLimits::max_memory_bytes`]).
    memory: usize,
}

const BOM: &[u8] = b"\xEF\xBB\xBF";

impl Parser<'_> {
    fn err(&self, offset: usize, kind: ParseErrorKind) -> ParseError {
        ParseError::at(self.input, offset, kind)
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    fn peek_at(&self, ahead: usize) -> Option<u8> {
        self.input.get(self.pos.saturating_add(ahead)).copied()
    }

    fn bump(&mut self) {
        self.pos = self.pos.saturating_add(1);
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.bump();
        }
    }

    /// The error for an unexpected byte at the current position, or for the
    /// end of input. Refines the kind for common mistakes.
    fn unexpected(&self) -> ParseError {
        let kind = match self.peek() {
            None => ParseErrorKind::UnexpectedEnd,
            Some(b'/') if matches!(self.peek_at(1), Some(b'/' | b'*')) => ParseErrorKind::Comment,
            Some(_) if self.at_invalid_whitespace() => ParseErrorKind::InvalidWhitespace,
            Some(_) => ParseErrorKind::UnexpectedCharacter,
        };
        self.err(self.pos, kind)
    }

    /// Returns true when the input at the current position starts with a
    /// Unicode whitespace character that JSON does not allow.
    fn at_invalid_whitespace(&self) -> bool {
        let rest = self.input.get(self.pos..).unwrap_or_default();
        let decoded = match rest.first() {
            Some(0x0B | 0x0C) => return true,
            Some(&b) if b < 0x80 => return false,
            _ => {
                let len = rest.len().min(4);
                let head = rest.get(..len).unwrap_or_default();
                match core::str::from_utf8(head) {
                    Ok(s) => s.chars().next(),
                    Err(e) => core::str::from_utf8(head.get(..e.valid_up_to()).unwrap_or_default())
                        .ok()
                        .and_then(|s| s.chars().next()),
                }
            }
        };
        decoded.is_some_and(|c| c.is_whitespace() || c == '\u{FEFF}')
    }

    fn count_node(&mut self) -> Result<(), ParseError> {
        self.nodes = self.nodes.saturating_add(1);
        if self.nodes > self.limits.max_nodes {
            return Err(self.err(self.pos, ParseErrorKind::LimitExceeded(Limit::Nodes)));
        }
        self.charge(self.pos, VALUE_COST)
    }

    /// Adds `bytes` to the memory estimate. Fails at `offset` when the
    /// estimate exceeds the limit.
    fn charge(&mut self, offset: usize, bytes: usize) -> Result<(), ParseError> {
        self.memory = self.memory.saturating_add(bytes);
        if self.memory > self.limits.max_memory_bytes {
            return Err(self.err(offset, ParseErrorKind::LimitExceeded(Limit::MemoryBytes)));
        }
        Ok(())
    }

    fn document(mut self) -> Result<Value, ParseError> {
        if self.input.len() > self.limits.max_input_bytes {
            return Err(self.err(
                self.limits.max_input_bytes,
                ParseErrorKind::LimitExceeded(Limit::InputBytes),
            ));
        }
        if self.input.starts_with(BOM) {
            return Err(self.err(0, ParseErrorKind::ByteOrderMark));
        }
        let mut stack: Vec<Frame> = Vec::new();
        'value: loop {
            self.skip_ws();
            if let Some(Frame::Array(items)) = stack.last()
                && items.len() >= self.limits.max_container_len
            {
                return Err(self.err(
                    self.pos,
                    ParseErrorKind::LimitExceeded(Limit::ContainerLength),
                ));
            }
            let start = self.pos;
            self.count_node()?;
            let mut value = match self.peek() {
                Some(b'{') => {
                    self.open(&stack)?;
                    self.skip_ws();
                    if self.peek() == Some(b'}') {
                        self.bump();
                        Value::Object(Object::new())
                    } else {
                        let object = Object::new();
                        let key = self.member_name(&object)?;
                        stack.push(Frame::Object(object, key));
                        continue 'value;
                    }
                }
                Some(b'[') => {
                    self.open(&stack)?;
                    self.skip_ws();
                    if self.peek() == Some(b']') {
                        self.bump();
                        Value::Array(Array::new())
                    } else {
                        stack.push(Frame::Array(Vec::new()));
                        continue 'value;
                    }
                }
                Some(b'"') => Value::String(self.string()?),
                Some(b't') => self.literal(b"true", Value::Bool(true))?,
                Some(b'f') => self.literal(b"false", Value::Bool(false))?,
                Some(b'n') => self.literal(b"null", Value::Null)?,
                Some(b'-' | b'0'..=b'9') => Value::Number(self.number()?),
                Some(b'A'..=b'Z' | b'a'..=b'z') => {
                    return Err(self.err(start, ParseErrorKind::InvalidLiteral));
                }
                _ => return Err(self.unexpected()),
            };
            // Attach the finished value to its parent, closing every
            // container that ends here.
            loop {
                let Some(frame) = stack.last_mut() else {
                    self.skip_ws();
                    if self.pos < self.input.len() {
                        let e = self.unexpected();
                        if e.kind == ParseErrorKind::UnexpectedCharacter {
                            return Err(self.err(self.pos, ParseErrorKind::TrailingCharacters));
                        }
                        return Err(e);
                    }
                    return Ok(value);
                };
                match frame {
                    Frame::Array(items) => {
                        items.push(value);
                        self.skip_ws();
                        match self.peek() {
                            Some(b',') => {
                                self.bump();
                                self.skip_ws();
                                if self.peek() == Some(b']') {
                                    return Err(self.err(self.pos, ParseErrorKind::TrailingComma));
                                }
                                continue 'value;
                            }
                            Some(b']') => {
                                self.bump();
                                let Some(Frame::Array(items)) = stack.pop() else {
                                    return Err(
                                        self.err(self.pos, ParseErrorKind::UnexpectedCharacter)
                                    );
                                };
                                // Drop the growth capacity, as the estimate assumes.
                                value = Value::Array(Array::from(exact_capacity(items)));
                            }
                            _ => return Err(self.unexpected()),
                        }
                    }
                    Frame::Object(object, key) => {
                        object.push_new(core::mem::take(key), value);
                        self.skip_ws();
                        match self.peek() {
                            Some(b',') => {
                                self.bump();
                                self.skip_ws();
                                if self.peek() == Some(b'}') {
                                    return Err(self.err(self.pos, ParseErrorKind::TrailingComma));
                                }
                                let next = self.member_name(object)?;
                                *key = next;
                                continue 'value;
                            }
                            Some(b'}') => {
                                self.bump();
                                let Some(Frame::Object(mut object, _)) = stack.pop() else {
                                    return Err(
                                        self.err(self.pos, ParseErrorKind::UnexpectedCharacter)
                                    );
                                };
                                object.shrink_to_fit();
                                value = Value::Object(object);
                            }
                            _ => return Err(self.unexpected()),
                        }
                    }
                }
            }
        }
    }

    /// Consumes `{` or `[` after checking the depth limit.
    fn open(&mut self, stack: &[Frame]) -> Result<(), ParseError> {
        if stack.len() >= self.limits.max_depth {
            return Err(self.err(self.pos, ParseErrorKind::LimitExceeded(Limit::Depth)));
        }
        self.bump();
        Ok(())
    }

    /// Parses a member name and the `:` after it. Rejects a name that the
    /// object already holds, at the offset of the repeated name.
    fn member_name(&mut self, object: &Object) -> Result<String, ParseError> {
        let start = self.pos;
        if self.peek() != Some(b'"') {
            return Err(match self.unexpected() {
                e if e.kind == ParseErrorKind::UnexpectedCharacter => {
                    self.err(start, ParseErrorKind::ExpectedKey)
                }
                e => e,
            });
        }
        if object.len() >= self.limits.max_container_len {
            return Err(self.err(start, ParseErrorKind::LimitExceeded(Limit::ContainerLength)));
        }
        // The new member goes at position `object.len()`. The object builds
        // its hash index when that position reaches `LINEAR_MAX`.
        let index_cost = match object.len() {
            n if n < LINEAR_MAX => 0,
            LINEAR_MAX => INDEX_BUILD_COST,
            _ => INDEX_MEMBER_COST,
        };
        self.charge(start, MEMBER_COST.saturating_add(index_cost))?;
        let key = self.string()?;
        if object.contains_key(&key) {
            return Err(self.err(start, ParseErrorKind::DuplicateKey));
        }
        self.skip_ws();
        if self.peek() != Some(b':') {
            return Err(match self.unexpected() {
                e if e.kind == ParseErrorKind::UnexpectedCharacter => {
                    self.err(self.pos, ParseErrorKind::ExpectedColon)
                }
                e => e,
            });
        }
        self.bump();
        Ok(key)
    }

    fn literal(&mut self, word: &'static [u8], value: Value) -> Result<Value, ParseError> {
        let end = self.pos.saturating_add(word.len());
        if self.input.get(self.pos..end) == Some(word) {
            self.pos = end;
            Ok(value)
        } else {
            Err(self.err(self.pos, ParseErrorKind::InvalidLiteral))
        }
    }

    fn number(&mut self) -> Result<Number, ParseError> {
        let start = self.pos;
        let end = match scan_number(self.input, start) {
            Ok(end) => end,
            Err((at, ScanError::LeadingZero)) => {
                return Err(self.err(at, ParseErrorKind::LeadingZero));
            }
            Err((at, ScanError::Invalid)) => {
                // `-Infinity` is a literal mistake rather than a digit mistake.
                let after_sign = at == start.saturating_add(1);
                let kind = if after_sign && self.input.get(at).is_some_and(u8::is_ascii_alphabetic)
                {
                    ParseErrorKind::InvalidLiteral
                } else {
                    ParseErrorKind::InvalidNumber
                };
                return Err(self.err(at, kind));
            }
        };
        if end.saturating_sub(start) > self.limits.max_number_len {
            return Err(self.err(start, ParseErrorKind::LimitExceeded(Limit::NumberLength)));
        }
        let lexeme = self.input.get(start..end).unwrap_or_default();
        // The scanner accepted only ASCII digits, signs, `.`, `e` and `E`.
        let lexeme = core::str::from_utf8(lexeme)
            .map_err(|_| self.err(start, ParseErrorKind::InvalidNumber))?;
        self.charge(start, lexeme.len())?;
        self.pos = end;
        Ok(Number::from_validated(lexeme))
    }

    /// Parses a string starting at its opening quote.
    fn string(&mut self) -> Result<String, ParseError> {
        let start = self.pos;
        self.bump();
        let mut out = String::new();
        loop {
            let run_start = self.pos;
            while let Some(b) = self.peek() {
                if b == b'"' || b == b'\\' || b < 0x20 {
                    break;
                }
                self.bump();
            }
            let run = self.input.get(run_start..self.pos).unwrap_or_default();
            if !run.is_empty() {
                // Quotes and backslashes are ASCII, so a run never splits a
                // valid multi-byte sequence.
                let text = core::str::from_utf8(run).map_err(|e| {
                    self.err(
                        run_start.saturating_add(e.valid_up_to()),
                        ParseErrorKind::InvalidUtf8,
                    )
                })?;
                self.check_string_len(start, out.len().saturating_add(text.len()))?;
                if out.is_empty() {
                    // Allocate exactly, so a string without escapes needs
                    // no shrink.
                    out.reserve_exact(text.len());
                }
                out.push_str(text);
            }
            match self.peek() {
                None => return Err(self.err(self.pos, ParseErrorKind::UnexpectedEnd)),
                Some(b'"') => {
                    self.bump();
                    self.charge(start, out.len())?;
                    // Escapes grow the string in steps. Drop the spare
                    // capacity. Shrinking in place is cheaper than a copy.
                    out.shrink_to_fit();
                    return Ok(out);
                }
                Some(b'\\') => {
                    let c = self.escape()?;
                    self.check_string_len(start, out.len().saturating_add(c.len_utf8()))?;
                    out.push(c);
                }
                Some(_) => return Err(self.err(self.pos, ParseErrorKind::ControlCharacter)),
            }
        }
    }

    /// Checks a string's decoded length so far against the string limit and
    /// against the memory left, before the string grows.
    fn check_string_len(&self, start: usize, len: usize) -> Result<(), ParseError> {
        if len > self.limits.max_string_bytes {
            return Err(self.err(start, ParseErrorKind::LimitExceeded(Limit::StringBytes)));
        }
        if self.memory.saturating_add(len) > self.limits.max_memory_bytes {
            return Err(self.err(start, ParseErrorKind::LimitExceeded(Limit::MemoryBytes)));
        }
        Ok(())
    }

    /// Parses one escape sequence starting at its backslash.
    fn escape(&mut self) -> Result<char, ParseError> {
        let start = self.pos;
        self.bump();
        let c = match self.peek() {
            None => return Err(self.err(self.pos, ParseErrorKind::UnexpectedEnd)),
            Some(b'"') => '"',
            Some(b'\\') => '\\',
            Some(b'/') => '/',
            Some(b'b') => '\u{08}',
            Some(b'f') => '\u{0C}',
            Some(b'n') => '\n',
            Some(b'r') => '\r',
            Some(b't') => '\t',
            Some(b'u') => {
                self.bump();
                let unit = self.hex4()?;
                return match unit {
                    0xD800..=0xDBFF => {
                        // A high surrogate must be followed by `\u` and a low surrogate.
                        if self.peek() != Some(b'\\') || self.peek_at(1) != Some(b'u') {
                            return Err(self.err(start, ParseErrorKind::LoneSurrogate));
                        }
                        self.pos = self.pos.saturating_add(2);
                        let low = self.hex4()?;
                        if !(0xDC00..=0xDFFF).contains(&low) {
                            return Err(self.err(start, ParseErrorKind::LoneSurrogate));
                        }
                        // Both halves carry 10 bits; the sum is at most 0x10FFFF.
                        let high_bits = (unit & 0x3FF) << 10;
                        let scalar = 0x1_0000u32
                            .saturating_add(high_bits)
                            .saturating_add(low & 0x3FF);
                        char::from_u32(scalar)
                            .ok_or_else(|| self.err(start, ParseErrorKind::LoneSurrogate))
                    }
                    0xDC00..=0xDFFF => Err(self.err(start, ParseErrorKind::LoneSurrogate)),
                    _ => char::from_u32(unit)
                        .ok_or_else(|| self.err(start, ParseErrorKind::InvalidEscape)),
                };
            }
            Some(_) => return Err(self.err(start, ParseErrorKind::InvalidEscape)),
        };
        self.bump();
        Ok(c)
    }

    /// Reads four hex digits, either case.
    fn hex4(&mut self) -> Result<u32, ParseError> {
        let mut unit: u32 = 0;
        for _ in 0..4 {
            let digit = match self.peek() {
                None => return Err(self.err(self.pos, ParseErrorKind::UnexpectedEnd)),
                Some(b) => char::from(b)
                    .to_digit(16)
                    .ok_or_else(|| self.err(self.pos, ParseErrorKind::InvalidEscape))?,
            };
            unit = (unit << 4) | digit;
            self.bump();
        }
        Ok(unit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locate_counts_lines_and_code_points() {
        assert_eq!(locate(b"abc", 0), (1, 1));
        assert_eq!(locate(b"abc", 2), (1, 3));
        assert_eq!(locate(b"a\nbc", 3), (2, 2));
        assert_eq!(locate("é\nüx".as_bytes(), 6), (2, 3));
        assert_eq!(locate(b"ab", 99), (1, 3));
    }
}
