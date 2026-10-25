//! Compact, pretty and RFC 8785 canonical serializers.
//!
//! Every serializer walks the tree with an explicit stack, so a value of any
//! depth serializes without recursion.
//!
//! Strings are escaped as ECMAScript `JSON.stringify` does, which is also the
//! rule of RFC 8785. The characters `\"`, `\\`, `\b`, `\t`, `\n`, `\f` and
//! `\r` use their short forms. Other control characters use `\u00xx` with
//! lowercase hex. Every other character is written as itself. No serializer
//! ever emits a raw control character. [`WriteOptions::escape_html`] additionally escapes `<`,
//! `>`, `&`, U+2028 and U+2029, which makes the output safe to embed in HTML
//! `<script>` elements and in JavaScript source.

use core::cmp::Ordering;
use core::fmt;

use crate::number::{Decimal, ecmascript_string};
use crate::object::Object;
use crate::path::{Path, Segment};
use crate::value::Value;

/// Output style for [`to_string_with`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WriteOptions {
    /// Spaces per indentation level. `None` writes compact output with no
    /// whitespace at all.
    pub indent: Option<u8>,
    /// Escape `<`, `>`, `&`, U+2028 and U+2029 as `\u` sequences.
    pub escape_html: bool,
}

impl WriteOptions {
    /// Compact output, minimal escaping.
    pub fn compact() -> WriteOptions {
        WriteOptions::default()
    }

    /// Output indented by two spaces per level, minimal escaping.
    pub fn pretty() -> WriteOptions {
        WriteOptions {
            indent: Some(2),
            escape_html: false,
        }
    }

    /// Returns these options with HTML-safe escaping turned on.
    pub fn html_safe(mut self) -> WriteOptions {
        self.escape_html = true;
        self
    }
}

/// Writes compact JSON: no whitespace, members in stored order, number
/// lexemes unchanged.
///
/// The output depends only on the value, so equal trees (by
/// [`Value::identical`]) always give the same bytes.
pub fn to_compact(value: &Value) -> String {
    to_string_with(value, WriteOptions::compact())
}

/// Writes JSON indented by two spaces per level, members in stored order.
///
/// The output has no trailing newline. Empty arrays and objects are written
/// as `[]` and `{}`.
pub fn to_pretty(value: &Value) -> String {
    to_string_with(value, WriteOptions::pretty())
}

/// Writes JSON with the given options.
pub fn to_string_with(value: &Value, options: WriteOptions) -> String {
    let mut out = String::new();
    write_value(&mut out, value, options);
    out
}

/// Appends JSON for `value` to `out` with the given options.
pub fn write_value(out: &mut String, value: &Value, options: WriteOptions) {
    let mut w = Walker::new(out, options.indent, options.escape_html);
    // Stored-order output cannot fail.
    let _ = w.run(value, &mut |out, n| {
        out.push_str(n.as_str());
        Ok(())
    });
}

/// Options for [`to_canonical_with`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CanonicalOptions {
    /// Accept numbers whose canonical form denotes a different decimal value.
    ///
    /// RFC 8785 formats every number through an IEEE 754 double. A lexeme
    /// with more precision than a double, such as `0.30000000000000001` or
    /// `12345678901234567890`, then changes value. By default such numbers
    /// are an error, so canonical bytes always determine the exact value of
    /// every number. Set this to follow RFC 8785 literally.
    pub allow_lossy_numbers: bool,
}

/// Why canonical serialization failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CanonicalErrorKind {
    /// The number is beyond the range of an IEEE 754 double. RFC 8785 cannot
    /// represent it.
    NumberOutOfRange,
    /// The canonical form would denote a different decimal value. See
    /// [`CanonicalOptions::allow_lossy_numbers`].
    LossyNumber,
}

/// A number that has no canonical form under the chosen options.
///
/// `Display` masks member names taken from the input (R-NF-02).
#[derive(Clone, PartialEq, Eq)]
pub struct CanonicalError {
    kind: CanonicalErrorKind,
    path: Path,
}

impl CanonicalError {
    /// What went wrong.
    pub fn kind(&self) -> CanonicalErrorKind {
        self.kind
    }

    /// Where the offending number is. The full rendering may contain input
    /// member names.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl fmt::Display for CanonicalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let what = match self.kind {
            CanonicalErrorKind::NumberOutOfRange => "number beyond the IEEE 754 double range",
            CanonicalErrorKind::LossyNumber => "number would change value in canonical form",
        };
        write!(f, "{}: {what}", self.path.redacted())
    }
}

impl fmt::Debug for CanonicalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CanonicalError")
            .field("kind", &self.kind)
            .field("path", &self.path.redacted())
            .finish()
    }
}

impl std::error::Error for CanonicalError {}

/// Writes RFC 8785 (JCS) canonical JSON, rejecting numbers that would change
/// value.
///
/// Members are sorted by the UTF-16 code units of their names. Strings use
/// the JCS escaping rules. Numbers are written as ECMAScript writes the
/// nearest double. There is no whitespace. This is the form used for content
/// hashes and signatures.
///
/// ```
/// let v = fstp_json::parse_str("{\"b\": 1.50, \"a\": [1E3, \"\\u20ac\"]}").unwrap();
/// assert_eq!(fstp_json::to_canonical(&v).unwrap(), r#"{"a":[1000,"€"],"b":1.5}"#);
/// ```
pub fn to_canonical(value: &Value) -> Result<String, CanonicalError> {
    to_canonical_with(value, CanonicalOptions::default())
}

/// Writes RFC 8785 canonical JSON with the given options.
pub fn to_canonical_with(
    value: &Value,
    options: CanonicalOptions,
) -> Result<String, CanonicalError> {
    let mut out = String::new();
    let mut w = Walker::new(&mut out, None, false);
    w.canonical = true;
    w.run(value, &mut |out, n| {
        let lexeme = canonical_number(n.as_str(), options)?;
        out.push_str(&lexeme);
        Ok(())
    })?;
    Ok(out)
}

/// The RFC 8785 form of a valid number lexeme.
pub(crate) fn canonical_number(
    lexeme: &str,
    options: CanonicalOptions,
) -> Result<String, CanonicalErrorKind> {
    // Integers below 10^15 are exact doubles that ECMAScript prints as plain
    // digits, so the lexeme is already canonical.
    let digits = lexeme.strip_prefix('-').unwrap_or(lexeme);
    if digits.len() <= 15 && digits.bytes().all(|b| b.is_ascii_digit()) {
        return Ok(if digits == "0" {
            "0".to_owned()
        } else {
            lexeme.to_owned()
        });
    }
    let x: f64 = lexeme
        .parse()
        .map_err(|_| CanonicalErrorKind::NumberOutOfRange)?;
    let out = ecmascript_string(x).ok_or(CanonicalErrorKind::NumberOutOfRange)?;
    if !options.allow_lossy_numbers {
        let before = Decimal::parse(lexeme);
        let after = Decimal::parse(&out);
        if before.is_err() || before != after {
            return Err(CanonicalErrorKind::LossyNumber);
        }
    }
    Ok(out)
}

/// Compares two strings by their UTF-16 code units, as RFC 8785 sorts names.
pub fn cmp_utf16(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

/// Appends `s` as a JSON string literal with quotes.
///
/// With `html` set, `<`, `>`, `&`, U+2028 and U+2029 are also escaped.
pub(crate) fn write_string(out: &mut String, s: &str, html: bool) {
    out.push('"');
    let mut run_start = 0;
    for (i, c) in s.char_indices() {
        let escape: Option<&str> = match c {
            '"' => Some("\\\""),
            '\\' => Some("\\\\"),
            '\u{08}' => Some("\\b"),
            '\t' => Some("\\t"),
            '\n' => Some("\\n"),
            '\u{0C}' => Some("\\f"),
            '\r' => Some("\\r"),
            '<' if html => Some("\\u003c"),
            '>' if html => Some("\\u003e"),
            '&' if html => Some("\\u0026"),
            '\u{2028}' if html => Some("\\u2028"),
            '\u{2029}' if html => Some("\\u2029"),
            c if c < '\u{20}' => None,
            _ => continue,
        };
        out.push_str(s.get(run_start..i).unwrap_or_default());
        match escape {
            Some(e) => out.push_str(e),
            None => {
                const HEX: &[u8; 16] = b"0123456789abcdef";
                let b = u32::from(c);
                out.push_str("\\u00");
                for nibble in [b >> 4, b & 0xF] {
                    let i = usize::try_from(nibble).unwrap_or(0);
                    out.push(char::from(HEX.get(i).copied().unwrap_or(b'0')));
                }
            }
        }
        run_start = i.saturating_add(c.len_utf8());
    }
    out.push_str(s.get(run_start..).unwrap_or_default());
    out.push('"');
}

/// Members of an object in output order.
enum Members<'a> {
    Stored(&'a Object),
    Sorted(Vec<(&'a str, &'a Value)>),
}

impl<'a> Members<'a> {
    fn get(&self, i: usize) -> Option<(&'a str, &'a Value)> {
        match self {
            Members::Stored(o) => o.member_at(i),
            Members::Sorted(list) => list.get(i).copied(),
        }
    }

    fn len(&self) -> usize {
        match self {
            Members::Stored(o) => o.len(),
            Members::Sorted(list) => list.len(),
        }
    }
}

/// An open container in the output.
enum Frame<'a> {
    Array { items: &'a [Value], next: usize },
    Object { members: Members<'a>, next: usize },
}

impl Frame<'_> {
    /// The path segment of the child written last.
    fn segment(&self) -> Option<Segment> {
        match self {
            Frame::Array { next, .. } => Some(Segment::Index(next.saturating_sub(1))),
            Frame::Object { members, next } => members
                .get(next.saturating_sub(1))
                .map(|(k, _)| Segment::Key(k.to_owned())),
        }
    }
}

struct Walker<'o, 'a> {
    out: &'o mut String,
    indent: Option<u8>,
    html: bool,
    canonical: bool,
    stack: Vec<Frame<'a>>,
}

type NumberWriter<'f> =
    dyn FnMut(&mut String, &crate::number::Number) -> Result<(), CanonicalErrorKind> + 'f;

impl<'o, 'a> Walker<'o, 'a> {
    fn new(out: &'o mut String, indent: Option<u8>, html: bool) -> Walker<'o, 'a> {
        Walker {
            out,
            indent,
            html,
            canonical: false,
            stack: Vec::new(),
        }
    }

    fn newline(&mut self) {
        if let Some(width) = self.indent {
            self.out.push('\n');
            for _ in 0..self.stack.len() {
                for _ in 0..width {
                    self.out.push(' ');
                }
            }
        }
    }

    fn path(&self) -> Path {
        Path::from_segments(self.stack.iter().filter_map(Frame::segment).collect())
    }

    /// Writes a scalar, or opens a container and pushes its frame.
    fn start(&mut self, v: &'a Value, number: &mut NumberWriter<'_>) -> Result<(), CanonicalError> {
        match v {
            Value::Null => self.out.push_str("null"),
            Value::Bool(true) => self.out.push_str("true"),
            Value::Bool(false) => self.out.push_str("false"),
            Value::Number(n) => {
                if let Err(kind) = number(self.out, n) {
                    return Err(CanonicalError {
                        kind,
                        path: self.path(),
                    });
                }
            }
            Value::String(s) => write_string(self.out, s, self.html),
            Value::Array(a) if a.is_empty() => self.out.push_str("[]"),
            Value::Array(a) => {
                self.out.push('[');
                self.stack.push(Frame::Array { items: a, next: 0 });
            }
            Value::Object(o) if o.is_empty() => self.out.push_str("{}"),
            Value::Object(o) => {
                self.out.push('{');
                let members = if self.canonical {
                    let mut list: Vec<(&str, &Value)> = o.iter().collect();
                    list.sort_by(|a, b| cmp_utf16(a.0, b.0));
                    Members::Sorted(list)
                } else {
                    Members::Stored(o)
                };
                self.stack.push(Frame::Object { members, next: 0 });
            }
        }
        Ok(())
    }

    fn run(
        &mut self,
        root: &'a Value,
        number: &mut NumberWriter<'_>,
    ) -> Result<(), CanonicalError> {
        self.start(root, number)?;
        loop {
            let (child, first, key, close) = match self.stack.last_mut() {
                None => return Ok(()),
                Some(Frame::Array { items, next }) => {
                    let first = *next == 0;
                    match items.get(*next) {
                        Some(child) => {
                            *next = next.saturating_add(1);
                            (Some(child), first, None, ']')
                        }
                        None => (None, first, None, ']'),
                    }
                }
                Some(Frame::Object { members, next }) => {
                    let first = *next == 0;
                    if *next < members.len() {
                        let member = members.get(*next);
                        *next = next.saturating_add(1);
                        match member {
                            Some((k, v)) => (Some(v), first, Some(k), '}'),
                            None => (None, first, None, '}'),
                        }
                    } else {
                        (None, first, None, '}')
                    }
                }
            };
            match child {
                Some(child) => {
                    if !first {
                        self.out.push(',');
                    }
                    self.newline();
                    if let Some(k) = key {
                        write_string(self.out, k, self.html);
                        self.out.push(':');
                        if self.indent.is_some() {
                            self.out.push(' ');
                        }
                    }
                    self.start(child, number)?;
                }
                None => {
                    self.stack.pop();
                    self.newline();
                    self.out.push(close);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn esc(s: &str, html: bool) -> String {
        let mut out = String::new();
        write_string(&mut out, s, html);
        out
    }

    #[test]
    fn escapes_follow_json_stringify() {
        assert_eq!(esc("a\"b\\c", false), r#""a\"b\\c""#);
        assert_eq!(esc("\u{8}\t\n\u{c}\r", false), r#""\b\t\n\f\r""#);
        assert_eq!(esc("\u{0}\u{1f}\u{7f}", false), "\"\\u0000\\u001f\u{7f}\"");
        assert_eq!(esc("/é€😀", false), "\"/é€😀\"");
        assert_eq!(esc("\u{2028}\u{2029}<>&", false), "\"\u{2028}\u{2029}<>&\"");
        assert_eq!(
            esc("\u{2028}\u{2029}<>&", true),
            "\"\\u2028\\u2029\\u003c\\u003e\\u0026\""
        );
    }

    #[test]
    fn utf16_order_differs_from_byte_order() {
        // U+1F600 sorts after U+FB33 by code point (and UTF-8 bytes), but
        // its first UTF-16 unit, the surrogate 0xD83D, sorts before 0xFB33.
        assert_eq!(cmp_utf16("\u{1F600}", "\u{FB33}"), Ordering::Less);
        assert_eq!("\u{1F600}".cmp("\u{FB33}"), Ordering::Greater);
    }

    #[test]
    fn canonical_number_fast_path_matches_the_slow_path() {
        for lexeme in ["0", "-0", "1", "-1", "999999999999999", "-123456789012345"] {
            let fast = canonical_number(lexeme, CanonicalOptions::default()).unwrap();
            let x: f64 = lexeme.parse().unwrap();
            assert_eq!(fast, ecmascript_string(x).unwrap(), "{lexeme}");
        }
    }
}
