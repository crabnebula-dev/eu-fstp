//! Response body decoding: media type, charset and conversion to text.
//!
//! Only HTML and plain text media types are read. Every other type is
//! refused, including scripts, images and PDF. Charsets are UTF-8 and the
//! windows-1252 family, which the WHATWG Encoding Standard also uses for
//! the `iso-8859-1` and `us-ascii` labels.

use crate::html::{Out, PlainText, html_to_text};
use crate::refusal::Refusal;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Html,
    Plain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Charset {
    Utf8,
    Windows1252,
}

/// Decodes a response body to text of at most `max` bytes.
///
/// `content_type` is the Content-Type field value. Without one the body is
/// read as UTF-8 plain text.
///
/// # Errors
///
/// [`Refusal::UnsupportedMediaType`] for a malformed field or a media type
/// other than HTML, XHTML, plain text or Markdown, and
/// [`Refusal::UnsupportedCharset`] for an unknown charset.
pub fn decode_body(
    content_type: Option<&[u8]>,
    body: &[u8],
    max: usize,
) -> Result<PlainText, Refusal> {
    let (kind, charset) = match content_type {
        Some(ct) => media_type(ct)?,
        None => (Kind::Plain, Charset::Utf8),
    };
    let text = match charset {
        Charset::Utf8 => {
            let b = body.strip_prefix(b"\xef\xbb\xbf").unwrap_or(body);
            String::from_utf8_lossy(b).into_owned()
        }
        Charset::Windows1252 => body.iter().map(|b| windows_1252(*b)).collect(),
    };
    Ok(match kind {
        Kind::Html => html_to_text(&text, max),
        Kind::Plain => plain_text(&text, max),
    })
}

/// Plain text keeps its lines and spacing. `\r` and other control
/// characters are removed, and tabs become spaces.
fn plain_text(s: &str, max: usize) -> PlainText {
    let mut out = Out::new(max);
    for c in s.chars() {
        if out.full() {
            break;
        }
        out.pre(c);
    }
    out.finish()
}

fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

fn ows(s: &str) -> &str {
    s.trim_matches([' ', '\t'])
}

/// Parses a Content-Type field value (RFC 9110 section 8.3.1).
fn media_type(ct: &[u8]) -> Result<(Kind, Charset), Refusal> {
    let s = std::str::from_utf8(ct).map_err(|_| Refusal::UnsupportedMediaType)?;
    let (essence, mut params) = match s.split_once(';') {
        Some((e, p)) => (e, Some(p)),
        None => (s, None),
    };
    let essence = ows(essence).to_ascii_lowercase();
    let (ty, sub) = essence
        .split_once('/')
        .ok_or(Refusal::UnsupportedMediaType)?;
    if !is_token(ty) || !is_token(sub) {
        return Err(Refusal::UnsupportedMediaType);
    }
    let kind = match essence.as_str() {
        "text/html" | "application/xhtml+xml" => Kind::Html,
        "text/plain" | "text/markdown" | "text/x-markdown" => Kind::Plain,
        _ => return Err(Refusal::UnsupportedMediaType),
    };
    let mut charset = Charset::Utf8;
    while let Some(p) = params {
        let p = p.trim_start_matches([' ', '\t']);
        if p.is_empty() {
            break;
        }
        if let Some(next) = p.strip_prefix(';') {
            params = Some(next);
            continue;
        }
        let (name, after) = p.split_once('=').ok_or(Refusal::UnsupportedMediaType)?;
        if !is_token(name) {
            return Err(Refusal::UnsupportedMediaType);
        }
        let (value, rest) = param_value(after)?;
        if name.eq_ignore_ascii_case("charset") {
            charset = match value.to_ascii_lowercase().as_str() {
                "utf-8" | "utf8" | "unicode-1-1-utf-8" => Charset::Utf8,
                "windows-1252" | "cp1252" | "x-cp1252" | "iso-8859-1" | "iso8859-1"
                | "iso_8859-1" | "latin1" | "l1" | "us-ascii" | "ascii" => Charset::Windows1252,
                _ => return Err(Refusal::UnsupportedCharset),
            };
        }
        let rest = rest.trim_start_matches([' ', '\t']);
        params = match rest.strip_prefix(';') {
            Some(next) => Some(next),
            None if rest.is_empty() => None,
            None => return Err(Refusal::UnsupportedMediaType),
        };
    }
    Ok((kind, charset))
}

/// Reads a token or quoted-string parameter value. Returns the value and
/// what follows it.
fn param_value(s: &str) -> Result<(String, &str), Refusal> {
    if let Some(inner) = s.strip_prefix('"') {
        let mut value = String::new();
        let mut chars = inner.char_indices();
        while let Some((i, c)) = chars.next() {
            match c {
                '"' => return Ok((value, inner.get(i.saturating_add(1)..).unwrap_or(""))),
                '\\' => match chars.next() {
                    Some((_, e)) => value.push(e),
                    None => break,
                },
                c if c.is_control() && c != '\t' => break,
                c => value.push(c),
            }
        }
        return Err(Refusal::UnsupportedMediaType);
    }
    let end = s.find([';', ' ', '\t']).unwrap_or(s.len());
    let (v, rest) = s.split_at_checked(end).unwrap_or((s, ""));
    if !is_token(v) {
        return Err(Refusal::UnsupportedMediaType);
    }
    Ok((v.to_owned(), rest))
}

/// windows-1252 bytes 0x80 to 0x9F (WHATWG Encoding Standard index).
const W1252_HIGH: [u16; 32] = [
    0x20ac, 0x0081, 0x201a, 0x0192, 0x201e, 0x2026, 0x2020, 0x2021, 0x02c6, 0x2030, 0x0160, 0x2039,
    0x0152, 0x008d, 0x017d, 0x008f, 0x0090, 0x2018, 0x2019, 0x201c, 0x201d, 0x2022, 0x2013, 0x2014,
    0x02dc, 0x2122, 0x0161, 0x203a, 0x0153, 0x009d, 0x017e, 0x0178,
];

fn windows_1252(b: u8) -> char {
    let cp = match b {
        0x80..=0x9f => W1252_HIGH
            .get(usize::from(b.wrapping_sub(0x80)))
            .copied()
            .map_or(0xfffd, u32::from),
        b => u32::from(b),
    };
    char::from_u32(cp).unwrap_or('\u{fffd}')
}
