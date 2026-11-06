//! The PDF object model and a strict, bounded parser (ISO 32000-1 section
//! 7.3).
//!
//! The parser reads only what the platform writes and what the signature
//! increment of ADR-016 may hold. It refuses comments inside objects,
//! indirect stream lengths, duplicate dictionary keys and nesting deeper
//! than [`MAX_DEPTH`]. It never recurses past that depth and never reads
//! past its buffer.

use std::ops::Range;

/// Deepest nesting of arrays and dictionaries the parser accepts.
pub const MAX_DEPTH: u8 = 32;
/// Most elements in one array or dictionary.
pub const MAX_ELEMENTS: usize = 65_536;
/// Longest string in bytes, after decoding.
pub const MAX_STRING: usize = 262_144;
/// Longest name in bytes, after decoding.
pub const MAX_NAME: usize = 127;
/// Longest number token in bytes.
const MAX_NUMBER: usize = 32;

/// What went wrong while parsing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseErrorKind {
    /// The input ended inside a token or object.
    UnexpectedEnd,
    /// A byte that cannot start or continue the expected token.
    UnexpectedByte,
    /// A comment where the platform writes none.
    Comment,
    /// Nesting deeper than [`MAX_DEPTH`].
    DepthExceeded,
    /// An array or dictionary with more than [`MAX_ELEMENTS`] elements.
    TooManyElements,
    /// A number token that is too long or does not fit an `i64`.
    Number,
    /// A name that is empty, too long or holds a bad `#` escape.
    Name,
    /// A string longer than [`MAX_STRING`] or with unbalanced parentheses.
    String,
    /// A hexadecimal string with a non-hex byte.
    HexString,
    /// A dictionary key that is not a name.
    DictKey,
    /// A dictionary key that appears twice.
    DuplicateKey,
    /// A stream whose `/Length` is missing, indirect or out of bounds.
    StreamLength,
    /// An expected keyword is missing.
    Keyword(&'static str),
    /// An object number or generation outside its range.
    ObjectNumber,
    /// The file does not start with a `%PDF-1.x` header.
    Header,
    /// No `startxref` with an offset and `%%EOF` ends the file.
    Tail,
    /// An xref table entry is malformed.
    XrefEntry,
    /// The xref offset points at an xref stream or anything but `xref`.
    XrefStream,
    /// The `/Prev` chain loops or is longer than allowed.
    XrefChain,
    /// The trailer is malformed, or names `/Encrypt` or `/XRefStm`.
    Trailer,
    /// An object is missing, or its header names another number.
    ObjectMissing,
    /// The file is larger than the parser accepts.
    TooLarge,
}

/// A parse failure at a byte offset of the input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParseError {
    /// The byte offset where the failure was found.
    pub offset: usize,
    /// What went wrong.
    pub kind: ParseErrorKind,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PDF parse error at byte {}: {:?}",
            self.offset, self.kind
        )
    }
}

impl std::error::Error for ParseError {}

/// An indirect reference `num gen R`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ref {
    /// The object number.
    pub num: u32,
    /// The generation number.
    pub generation: u16,
}

/// A string object. Equality compares the decoded bytes only, so a
/// literal and a hexadecimal spelling of the same bytes are equal.
#[derive(Clone, Debug)]
pub struct PdfString {
    /// The decoded bytes.
    pub bytes: Vec<u8>,
    /// Whether the input spelled it as a hexadecimal string.
    pub hex: bool,
    /// The byte range of the token in the input, delimiters included.
    pub span: Range<usize>,
}

impl PartialEq for PdfString {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl Eq for PdfString {}

/// A dictionary. Keys are unique and keep their input order.
#[derive(Clone, Debug, Default)]
pub struct Dict {
    entries: Vec<(Vec<u8>, Object)>,
}

impl Dict {
    /// The value under `key`, a name without its slash.
    #[must_use]
    pub fn get(&self, key: &[u8]) -> Option<&Object> {
        self.entries
            .iter()
            .find(|(k, _)| k.as_slice() == key)
            .map(|(_, v)| v)
    }

    /// The entries in input order.
    #[must_use]
    pub fn entries(&self) -> &[(Vec<u8>, Object)] {
        &self.entries
    }

    /// Inserts or replaces the value under `key`.
    pub fn set(&mut self, key: &[u8], value: Object) {
        match self.entries.iter_mut().find(|(k, _)| k.as_slice() == key) {
            Some(slot) => slot.1 = value,
            None => self.entries.push((key.to_vec(), value)),
        }
    }

    /// The number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the dictionary is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The name under `key`, if it is one.
    #[must_use]
    pub fn name(&self, key: &[u8]) -> Option<&[u8]> {
        match self.get(key) {
            Some(Object::Name(n)) => Some(n),
            _ => None,
        }
    }

    /// The reference under `key`, if it is one.
    #[must_use]
    pub fn reference(&self, key: &[u8]) -> Option<Ref> {
        match self.get(key) {
            Some(Object::Ref(r)) => Some(*r),
            _ => None,
        }
    }

    /// The integer under `key`, if it is one.
    #[must_use]
    pub fn int(&self, key: &[u8]) -> Option<i64> {
        match self.get(key) {
            Some(Object::Int(i)) => Some(*i),
            _ => None,
        }
    }
}

/// Order-insensitive: two dictionaries are equal when they hold the same
/// keys with equal values.
impl PartialEq for Dict {
    fn eq(&self, other: &Self) -> bool {
        self.entries.len() == other.entries.len()
            && self
                .entries
                .iter()
                .all(|(k, v)| other.get(k).is_some_and(|w| w == v))
    }
}

impl Eq for Dict {}

/// A stream: its dictionary and the byte range of its raw data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stream {
    /// The stream dictionary.
    pub dict: Dict,
    /// The byte range of the data in the input.
    pub data: Range<usize>,
}

/// A PDF object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Object {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// An integer.
    Int(i64),
    /// A real number, kept as its token bytes. No float is formed.
    Real(Vec<u8>),
    /// A name, decoded, without its slash.
    Name(Vec<u8>),
    /// A string.
    String(PdfString),
    /// An array.
    Array(Vec<Object>),
    /// A dictionary.
    Dict(Dict),
    /// An indirect reference.
    Ref(Ref),
    /// A stream. Only indirect objects hold one.
    Stream(Stream),
}

impl Object {
    /// Appends the canonical spelling of this object to `out`. Strings are
    /// written as hexadecimal strings and streams are refused, so the
    /// output never depends on escapes or raw data.
    ///
    /// Returns `false` when the object holds a stream.
    pub fn write_to(&self, out: &mut Vec<u8>) -> bool {
        match self {
            Object::Null => out.extend_from_slice(b"null"),
            Object::Bool(true) => out.extend_from_slice(b"true"),
            Object::Bool(false) => out.extend_from_slice(b"false"),
            Object::Int(i) => out.extend_from_slice(i.to_string().as_bytes()),
            Object::Real(r) => out.extend_from_slice(r),
            Object::Name(n) => write_name(out, n),
            Object::String(s) => write_hex_string(out, &s.bytes),
            Object::Ref(r) => {
                out.extend_from_slice(format!("{} {} R", r.num, r.generation).as_bytes())
            }
            Object::Array(items) => {
                out.push(b'[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(b' ');
                    }
                    if !item.write_to(out) {
                        return false;
                    }
                }
                out.push(b']');
            }
            Object::Dict(d) => {
                out.extend_from_slice(b"<<");
                for (k, v) in d.entries() {
                    write_name(out, k);
                    out.push(b' ');
                    if !v.write_to(out) {
                        return false;
                    }
                }
                out.extend_from_slice(b">>");
            }
            Object::Stream(_) => return false,
        }
        true
    }
}

/// Appends `/name`, escaping every byte outside the regular printable
/// range with `#xx`.
pub fn write_name(out: &mut Vec<u8>, name: &[u8]) {
    out.push(b'/');
    for &b in name {
        if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'+' | b',' | b':' | b';')
        {
            out.push(b);
        } else {
            out.extend_from_slice(format!("#{b:02X}").as_bytes());
        }
    }
}

/// Appends `<hex>` for `bytes`.
pub fn write_hex_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.push(b'<');
    for b in bytes {
        out.extend_from_slice(format!("{b:02X}").as_bytes());
    }
    out.push(b'>');
}

/// PDF white-space characters (ISO 32000-1 table 1).
#[must_use]
pub fn is_whitespace(b: u8) -> bool {
    matches!(b, 0x00 | 0x09 | 0x0a | 0x0c | 0x0d | 0x20)
}

/// PDF delimiter characters (ISO 32000-1 table 2).
#[must_use]
pub fn is_delimiter(b: u8) -> bool {
    matches!(
        b,
        b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
    )
}

fn is_regular(b: u8) -> bool {
    !is_whitespace(b) && !is_delimiter(b)
}

fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => b.checked_sub(b'0'),
        b'a'..=b'f' => b.checked_sub(b'a').and_then(|v| v.checked_add(10)),
        b'A'..=b'F' => b.checked_sub(b'A').and_then(|v| v.checked_add(10)),
        _ => None,
    }
}

/// A cursor over a byte buffer that reads objects.
#[derive(Clone, Debug)]
pub struct Parser<'a> {
    buf: &'a [u8],
    pos: usize,
}

type Res<T> = Result<T, ParseError>;

impl<'a> Parser<'a> {
    /// A parser over `buf`, starting at `pos`.
    #[must_use]
    pub fn new(buf: &'a [u8], pos: usize) -> Parser<'a> {
        Parser { buf, pos }
    }

    /// The current offset.
    #[must_use]
    pub fn pos(&self) -> usize {
        self.pos
    }

    /// An error of `kind` at the current offset.
    #[must_use]
    pub fn err(&self, kind: ParseErrorKind) -> ParseError {
        ParseError {
            offset: self.pos,
            kind,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.buf.get(self.pos).copied()
    }

    fn peek_at(&self, ahead: usize) -> Option<u8> {
        self.buf.get(self.pos.checked_add(ahead)?).copied()
    }

    fn bump(&mut self) {
        self.pos = self.pos.saturating_add(1);
    }

    fn next_byte(&mut self) -> Res<u8> {
        let b = self.peek().ok_or(self.err(ParseErrorKind::UnexpectedEnd))?;
        self.bump();
        Ok(b)
    }

    /// Whether the parser is at the end of its buffer.
    #[must_use]
    pub fn at_end(&self) -> bool {
        self.pos >= self.buf.len()
    }

    /// Skips white space. A comment is refused.
    ///
    /// # Errors
    ///
    /// [`ParseErrorKind::Comment`] at a `%`.
    pub fn skip_ws(&mut self) -> Res<()> {
        while let Some(b) = self.peek() {
            if b == b'%' {
                return Err(self.err(ParseErrorKind::Comment));
            }
            if !is_whitespace(b) {
                break;
            }
            self.bump();
        }
        Ok(())
    }

    /// Skips one end-of-line marker (CR LF, LF or CR), if one follows.
    pub fn skip_eol(&mut self) {
        match (self.peek(), self.peek_at(1)) {
            (Some(b'\r'), Some(b'\n')) => self.pos = self.pos.saturating_add(2),
            (Some(b'\r' | b'\n'), _) => self.bump(),
            _ => {}
        }
    }

    /// Whether the regular-character run at the cursor is `kw`.
    #[must_use]
    pub fn at_keyword(&self, kw: &[u8]) -> bool {
        let Some(end) = self.pos.checked_add(kw.len()) else {
            return false;
        };
        self.buf.get(self.pos..end) == Some(kw) && self.buf.get(end).is_none_or(|&b| !is_regular(b))
    }

    /// Skips white space and reads the keyword `kw`.
    ///
    /// # Errors
    ///
    /// [`ParseErrorKind::Keyword`] when another token follows.
    pub fn keyword(&mut self, kw: &'static str) -> Res<()> {
        self.skip_ws()?;
        if !self.at_keyword(kw.as_bytes()) {
            return Err(self.err(ParseErrorKind::Keyword(kw)));
        }
        self.pos = self.pos.saturating_add(kw.len());
        Ok(())
    }

    /// Skips white space and reads an unsigned integer.
    ///
    /// # Errors
    ///
    /// [`ParseErrorKind::Number`] when no plain digit run follows or it
    /// does not fit a `u64`.
    pub fn uint(&mut self) -> Res<u64> {
        self.skip_ws()?;
        let start = self.pos;
        let mut v: u64 = 0;
        while let Some(b) = self.peek().filter(u8::is_ascii_digit) {
            v = v
                .checked_mul(10)
                .and_then(|v| v.checked_add(u64::from(b.saturating_sub(b'0'))))
                .ok_or(self.err(ParseErrorKind::Number))?;
            self.bump();
            if self.pos.saturating_sub(start) > MAX_NUMBER {
                return Err(self.err(ParseErrorKind::Number));
            }
        }
        if self.pos == start || self.peek().is_some_and(is_regular) {
            return Err(ParseError {
                offset: start,
                kind: ParseErrorKind::Number,
            });
        }
        Ok(v)
    }

    /// Skips white space and reads one direct object.
    ///
    /// # Errors
    ///
    /// Any [`ParseErrorKind`] of the object grammar.
    pub fn object(&mut self) -> Res<Object> {
        self.object_at(0)
    }

    fn object_at(&mut self, depth: u8) -> Res<Object> {
        if depth > MAX_DEPTH {
            return Err(self.err(ParseErrorKind::DepthExceeded));
        }
        self.skip_ws()?;
        let b = self.peek().ok_or(self.err(ParseErrorKind::UnexpectedEnd))?;
        match b {
            b'/' => self.name().map(Object::Name),
            b'(' => self.literal_string().map(Object::String),
            b'<' if self.peek_at(1) == Some(b'<') => self.dict(depth).map(Object::Dict),
            b'<' => self.hex_string().map(Object::String),
            b'[' => self.array(depth),
            b'+' | b'-' | b'.' | b'0'..=b'9' => self.number_or_ref(),
            _ if self.at_keyword(b"true") => {
                self.pos = self.pos.saturating_add(4);
                Ok(Object::Bool(true))
            }
            _ if self.at_keyword(b"false") => {
                self.pos = self.pos.saturating_add(5);
                Ok(Object::Bool(false))
            }
            _ if self.at_keyword(b"null") => {
                self.pos = self.pos.saturating_add(4);
                Ok(Object::Null)
            }
            _ => Err(self.err(ParseErrorKind::UnexpectedByte)),
        }
    }

    fn name(&mut self) -> Res<Vec<u8>> {
        let start = self.pos;
        self.bump();
        let mut out = Vec::new();
        while let Some(b) = self.peek().filter(|&b| is_regular(b)) {
            self.bump();
            if b == b'#' {
                let hi = self.next_byte().map(hex_value)?;
                let lo = self.next_byte().map(hex_value)?;
                let v = hi
                    .zip(lo)
                    .and_then(|(h, l)| h.checked_mul(16).and_then(|h| h.checked_add(l)))
                    .filter(|&v| v != 0)
                    .ok_or(self.err(ParseErrorKind::Name))?;
                out.push(v);
            } else {
                out.push(b);
            }
            if out.len() > MAX_NAME {
                return Err(self.err(ParseErrorKind::Name));
            }
        }
        if out.is_empty() {
            return Err(ParseError {
                offset: start,
                kind: ParseErrorKind::Name,
            });
        }
        Ok(out)
    }

    fn literal_string(&mut self) -> Res<PdfString> {
        let start = self.pos;
        self.bump();
        let mut out = Vec::new();
        let mut nesting: u32 = 0;
        loop {
            if out.len() > MAX_STRING {
                return Err(self.err(ParseErrorKind::String));
            }
            let b = self.next_byte()?;
            match b {
                b'(' => {
                    nesting = nesting
                        .checked_add(1)
                        .ok_or(self.err(ParseErrorKind::String))?;
                    out.push(b);
                }
                b')' => match nesting.checked_sub(1) {
                    Some(n) => {
                        nesting = n;
                        out.push(b);
                    }
                    None => break,
                },
                b'\\' => {
                    let e = self.next_byte()?;
                    match e {
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'b' => out.push(0x08),
                        b'f' => out.push(0x0c),
                        b'(' | b')' | b'\\' => out.push(e),
                        b'\r' => {
                            if self.peek() == Some(b'\n') {
                                self.bump();
                            }
                        }
                        b'\n' => {}
                        b'0'..=b'7' => {
                            let mut v = u32::from(e.saturating_sub(b'0'));
                            for _ in 0..2 {
                                match self.peek().filter(|b| (b'0'..=b'7').contains(b)) {
                                    Some(d) => {
                                        v = v
                                            .saturating_mul(8)
                                            .saturating_add(u32::from(d.saturating_sub(b'0')));
                                        self.bump();
                                    }
                                    None => break,
                                }
                            }
                            out.push(u8::try_from(v & 0xff).unwrap_or(0));
                        }
                        other => out.push(other),
                    }
                }
                other => out.push(other),
            }
        }
        Ok(PdfString {
            bytes: out,
            hex: false,
            span: start..self.pos,
        })
    }

    fn hex_string(&mut self) -> Res<PdfString> {
        let start = self.pos;
        self.bump();
        let mut out = Vec::new();
        let mut high: Option<u8> = None;
        loop {
            let b = self.next_byte()?;
            if b == b'>' {
                break;
            }
            if is_whitespace(b) {
                continue;
            }
            let v = hex_value(b).ok_or(self.err(ParseErrorKind::HexString))?;
            match high.take() {
                Some(h) => out.push(h.saturating_mul(16).saturating_add(v)),
                None => high = Some(v),
            }
            if out.len() > MAX_STRING {
                return Err(self.err(ParseErrorKind::String));
            }
        }
        if let Some(h) = high {
            out.push(h.saturating_mul(16));
        }
        Ok(PdfString {
            bytes: out,
            hex: true,
            span: start..self.pos,
        })
    }

    fn array(&mut self, depth: u8) -> Res<Object> {
        self.bump();
        let mut items = Vec::new();
        loop {
            self.skip_ws()?;
            match self.peek() {
                None => return Err(self.err(ParseErrorKind::UnexpectedEnd)),
                Some(b']') => {
                    self.bump();
                    return Ok(Object::Array(items));
                }
                Some(_) => {
                    if items.len() >= MAX_ELEMENTS {
                        return Err(self.err(ParseErrorKind::TooManyElements));
                    }
                    items.push(self.object_at(depth.saturating_add(1))?);
                }
            }
        }
    }

    fn dict(&mut self, depth: u8) -> Res<Dict> {
        self.pos = self.pos.saturating_add(2);
        let mut dict = Dict::default();
        loop {
            self.skip_ws()?;
            match self.peek() {
                None => return Err(self.err(ParseErrorKind::UnexpectedEnd)),
                Some(b'>') => {
                    if self.peek_at(1) != Some(b'>') {
                        return Err(self.err(ParseErrorKind::UnexpectedByte));
                    }
                    self.pos = self.pos.saturating_add(2);
                    return Ok(dict);
                }
                Some(b'/') => {
                    let at = self.pos;
                    let key = self.name()?;
                    if dict.get(&key).is_some() {
                        return Err(ParseError {
                            offset: at,
                            kind: ParseErrorKind::DuplicateKey,
                        });
                    }
                    if dict.len() >= MAX_ELEMENTS {
                        return Err(self.err(ParseErrorKind::TooManyElements));
                    }
                    let value = self.object_at(depth.saturating_add(1))?;
                    dict.entries.push((key, value));
                }
                Some(_) => return Err(self.err(ParseErrorKind::DictKey)),
            }
        }
    }

    fn number_token(&mut self) -> Res<(Vec<u8>, bool)> {
        let start = self.pos;
        let mut real = false;
        if matches!(self.peek(), Some(b'+' | b'-')) {
            self.bump();
        }
        let mut digits = 0usize;
        while let Some(b) = self.peek() {
            match b {
                b'0'..=b'9' => digits = digits.saturating_add(1),
                b'.' if !real => real = true,
                _ => break,
            }
            self.bump();
            if self.pos.saturating_sub(start) > MAX_NUMBER {
                return Err(self.err(ParseErrorKind::Number));
            }
        }
        if digits == 0 || self.peek().is_some_and(is_regular) {
            return Err(ParseError {
                offset: start,
                kind: ParseErrorKind::Number,
            });
        }
        let token = self
            .buf
            .get(start..self.pos)
            .ok_or(self.err(ParseErrorKind::Number))?
            .to_vec();
        Ok((token, real))
    }

    fn number_or_ref(&mut self) -> Res<Object> {
        let start = self.pos;
        let (token, real) = self.number_token()?;
        if real {
            return Ok(Object::Real(token));
        }
        let value = parse_i64(&token).ok_or(ParseError {
            offset: start,
            kind: ParseErrorKind::Number,
        })?;
        // `num gen R` is a reference when both are plain digit runs.
        if token.iter().all(u8::is_ascii_digit) {
            let save = self.pos;
            if let Some(r) = self.try_ref_tail(value) {
                return Ok(Object::Ref(r));
            }
            self.pos = save;
        }
        Ok(Object::Int(value))
    }

    fn try_ref_tail(&mut self, num: i64) -> Option<Ref> {
        self.skip_ws().ok()?;
        if !self.peek()?.is_ascii_digit() {
            return None;
        }
        let (token, real) = self.number_token().ok()?;
        if real {
            return None;
        }
        let generation = parse_i64(&token)?;
        self.skip_ws().ok()?;
        if !self.at_keyword(b"R") {
            return None;
        }
        self.bump();
        Some(Ref {
            num: u32::try_from(num).ok()?,
            generation: u16::try_from(generation).ok()?,
        })
    }

    /// Reads one indirect object `num gen obj ... endobj`. A dictionary
    /// followed by `stream` is read as a stream with a direct `/Length`.
    ///
    /// # Errors
    ///
    /// Any [`ParseErrorKind`] of the object grammar.
    pub fn indirect(&mut self) -> Res<(Ref, Object)> {
        let num = self.uint()?;
        let generation = self.uint()?;
        let r = Ref {
            num: u32::try_from(num).map_err(|_| self.err(ParseErrorKind::ObjectNumber))?,
            generation: u16::try_from(generation)
                .map_err(|_| self.err(ParseErrorKind::ObjectNumber))?,
        };
        self.keyword("obj")?;
        let mut obj = self.object()?;
        self.skip_ws()?;
        if self.at_keyword(b"stream") {
            let Object::Dict(dict) = obj else {
                return Err(self.err(ParseErrorKind::Keyword("endobj")));
            };
            self.pos = self.pos.saturating_add(6);
            match (self.peek(), self.peek_at(1)) {
                (Some(b'\r'), Some(b'\n')) => self.pos = self.pos.saturating_add(2),
                (Some(b'\n'), _) => self.bump(),
                _ => return Err(self.err(ParseErrorKind::Keyword("stream"))),
            }
            let len = dict
                .int(b"Length")
                .and_then(|l| usize::try_from(l).ok())
                .ok_or(self.err(ParseErrorKind::StreamLength))?;
            let start = self.pos;
            let end = start
                .checked_add(len)
                .filter(|&e| e <= self.buf.len())
                .ok_or(self.err(ParseErrorKind::StreamLength))?;
            self.pos = end;
            self.skip_eol();
            self.keyword("endstream")?;
            obj = Object::Stream(Stream {
                dict,
                data: start..end,
            });
        }
        self.keyword("endobj")?;
        Ok((r, obj))
    }
}

fn parse_i64(token: &[u8]) -> Option<i64> {
    let (neg, digits) = match token.split_first()? {
        (b'-', rest) => (true, rest),
        (b'+', rest) => (false, rest),
        _ => (false, token),
    };
    let mut v: i64 = 0;
    for &d in digits {
        let d = i64::from(d.checked_sub(b'0').filter(|d| *d <= 9)?);
        v = v.checked_mul(10)?;
        v = if neg {
            v.checked_sub(d)?
        } else {
            v.checked_add(d)?
        };
    }
    Some(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Res<Object> {
        Parser::new(s.as_bytes(), 0).object()
    }

    #[test]
    fn objects_parse() {
        assert_eq!(
            parse("12 0 R"),
            Ok(Object::Ref(Ref {
                num: 12,
                generation: 0
            }))
        );
        assert_eq!(parse("12 0"), Ok(Object::Int(12)));
        assert_eq!(parse("-3"), Ok(Object::Int(-3)));
        assert_eq!(parse("0.5"), Ok(Object::Real(b"0.5".to_vec())));
        assert_eq!(parse("/A#20B"), Ok(Object::Name(b"A B".to_vec())));
        assert!(matches!(parse("<</A 1 /A 2>>"), Err(e) if e.kind == ParseErrorKind::DuplicateKey));
        assert!(matches!(parse("[1 %c\n]"), Err(e) if e.kind == ParseErrorKind::Comment));
        let deep = "[".repeat(40);
        assert!(matches!(parse(&deep), Err(e) if e.kind == ParseErrorKind::DepthExceeded));
    }

    #[test]
    fn strings_compare_by_bytes() {
        let a = parse("(AB)");
        let b = parse("<4142>");
        assert_eq!(a, b);
    }
}
