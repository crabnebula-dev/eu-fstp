//! The MIME builder and its strict parser (M6 design section 5.3).
//!
//! The builder writes RFC 5322 headers and a `multipart/alternative` body
//! with quoted-printable text and HTML parts. A notice PDF, when P-48 says
//! attach, goes in a `multipart/mixed` wrapper as base64. Every byte is
//! 7-bit with CRLF line ends. Boundaries come from the idempotency key
//! and start with `=_`, which neither quoted-printable nor base64 output
//! can contain, so equal input gives equal bytes.
//!
//! The parser reads what the builder writes and little else. Tests, the
//! demo's sent-mail page and the T5 canary scan use it, and so does
//! [`crate::dkim::verify`]. Its fuzz target is `mime_parse`.

use crate::encode::{
    base64_decode, base64_encode_wrapped, encode_phrase, encode_unstructured, hex, qp_decode,
    qp_encode,
};
use crate::placeholder::civil_from_days;
use crate::template::Rendered;
use crate::{MailConfig, MailError, Message};

/// The largest message the parser reads.
pub const MAX_MESSAGE: usize = 32 * 1024 * 1024;
/// The most header fields in one header block.
pub const MAX_FIELDS: usize = 256;
/// The longest line, CRLF excluded (RFC 5322 section 2.1.1).
pub const MAX_LINE: usize = 998;
/// The deepest multipart nesting.
pub const MAX_DEPTH: usize = 4;
/// The most leaf parts.
pub const MAX_PARTS: usize = 64;

/// The file name of an attached notice.
pub const PDF_NAME: &str = "notice.pdf";

/// One header field as it appears in the message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderField {
    /// The name as written.
    pub name: String,
    /// The bytes after the colon up to the final CRLF, folding included.
    pub raw_value: Vec<u8>,
}

impl HeaderField {
    /// The value unfolded, with outer white space removed.
    pub fn value(&self) -> String {
        let s = String::from_utf8_lossy(&self.raw_value).replace("\r\n", "");
        s.trim_matches(|c| c == ' ' || c == '\t').to_owned()
    }
}

/// A leaf part, decoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedPart {
    /// The lower-case media type, such as `text/plain`.
    pub content_type: String,
    /// The attachment file name, if one is given.
    pub filename: Option<String>,
    /// The decoded content.
    pub decoded: Vec<u8>,
}

/// A parsed message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedMessage {
    /// The top-level header fields in order.
    pub fields: Vec<HeaderField>,
    /// The body as it appears after the blank line.
    pub body: Vec<u8>,
    /// Every leaf part in order.
    pub parts: Vec<ParsedPart>,
    header_values: Vec<(String, String)>,
}

impl ParsedMessage {
    /// The unfolded value of the first top-level field named `name`,
    /// compared without case.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.header_values
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

// ------------------------------------------------------------- builder

const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// An RFC 5322 date in UTC, such as `Fri, 06 Nov 2026 14:00:00 +0000`.
fn rfc5322_date(micros: i64) -> Result<String, MailError> {
    let secs = micros.div_euclid(1_000_000);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days).ok_or(MailError::DateOutOfRange)?;
    if !(1900..=9999).contains(&y) {
        return Err(MailError::DateOutOfRange);
    }
    let wd = usize::try_from(days.rem_euclid(7)).map_err(|_| MailError::DateOutOfRange)?;
    // 1970-01-01 was a Thursday.
    let wd = DAYS
        .get(wd.saturating_add(4) % 7)
        .ok_or(MailError::DateOutOfRange)?;
    let mon = usize::try_from(m.saturating_sub(1))
        .ok()
        .and_then(|i| MONTHS.get(i))
        .ok_or(MailError::DateOutOfRange)?;
    Ok(format!(
        "{wd}, {d:02} {mon} {y:04} {:02}:{:02}:{:02} +0000",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    ))
}

/// Appends `Name: value` and CRLF. A value without CRLF of its own is
/// folded before a space wherever the line would pass 78 octets.
fn push_header(out: &mut String, name: &str, value: &str) {
    out.push_str(name);
    out.push(':');
    if value.contains("\r\n") {
        out.push(' ');
        out.push_str(value);
        out.push_str("\r\n");
        return;
    }
    let mut col = name.len().saturating_add(1);
    for (i, word) in value.split(' ').enumerate() {
        if i > 0 && col.saturating_add(1).saturating_add(word.len()) > 78 {
            out.push_str("\r\n");
            col = 0;
        }
        out.push(' ');
        out.push_str(word);
        col = col.saturating_add(1).saturating_add(word.len());
    }
    out.push_str("\r\n");
}

/// Builds the message for `msg` from its rendering `r`. No DKIM
/// signature is added here.
///
/// # Errors
///
/// [`MailError::DateOutOfRange`] for a date outside 1900 to 9999.
pub fn build(cfg: &MailConfig, msg: &Message<'_>, r: &Rendered) -> Result<Vec<u8>, MailError> {
    let tag = hex(msg.idem.get(..8).unwrap_or(&msg.idem));
    let alt = format!("=_fstp_a_{tag}");
    let mixed = format!("=_fstp_m_{tag}");

    let mut h = String::new();
    push_header(&mut h, "Date", &rfc5322_date(msg.date.micros())?);
    let from = match &cfg.from_name {
        Some(n) => format!("{} <{}>", encode_phrase(n.as_str()), cfg.from.as_str()),
        None => format!("<{}>", cfg.from.as_str()),
    };
    push_header(&mut h, "From", &from);
    push_header(&mut h, "To", &format!("<{}>", msg.to.as_str()));
    push_header(&mut h, "Subject", &encode_unstructured(&r.subject));
    push_header(
        &mut h,
        "Message-ID",
        &format!("<{}@{}>", hex(&msg.idem), cfg.from.domain()),
    );
    push_header(&mut h, "MIME-Version", "1.0");
    push_header(&mut h, "Auto-Submitted", "auto-generated");
    push_header(&mut h, "X-FSTP-Event", &hex(&msg.event));
    let t = msg.template;
    push_header(
        &mut h,
        "X-FSTP-Template",
        &format!("{}/{}/{}", t.id().code(), t.version(), t.locale().code()),
    );

    let alt_body = format!(
        "--{alt}\r\nContent-Type: text/plain; charset=utf-8\r\n\
         Content-Transfer-Encoding: quoted-printable\r\n\r\n{text}\r\n\
         --{alt}\r\nContent-Type: text/html; charset=utf-8\r\n\
         Content-Transfer-Encoding: quoted-printable\r\n\r\n{html}\r\n--{alt}--\r\n",
        text = qp_encode(&r.text),
        html = qp_encode(&r.html),
    );
    let body = match msg.pdf {
        None => {
            push_header(
                &mut h,
                "Content-Type",
                &format!("multipart/alternative; boundary=\"{alt}\""),
            );
            alt_body
        }
        Some(pdf) => {
            push_header(
                &mut h,
                "Content-Type",
                &format!("multipart/mixed; boundary=\"{mixed}\""),
            );
            format!(
                "--{mixed}\r\nContent-Type: multipart/alternative; boundary=\"{alt}\"\r\n\r\n\
                 {alt_body}--{mixed}\r\nContent-Type: application/pdf; name=\"{PDF_NAME}\"\r\n\
                 Content-Disposition: attachment; filename=\"{PDF_NAME}\"\r\n\
                 Content-Transfer-Encoding: base64\r\n\r\n{b64}--{mixed}--\r\n",
                b64 = base64_encode_wrapped(pdf),
            )
        }
    };
    h.push_str("\r\n");
    h.push_str(&body);
    Ok(h.into_bytes())
}

// -------------------------------------------------------------- parser

/// Parses a header block at the start of `data`. Returns the fields and
/// the offset of the body after the blank line. A block that ends with
/// the data and no blank line has an empty body.
pub(crate) fn parse_headers(data: &[u8]) -> Result<(Vec<HeaderField>, usize), MailError> {
    let mut fields: Vec<HeaderField> = Vec::new();
    let mut pos = 0usize;
    loop {
        let rest = data.get(pos..).ok_or(MailError::Malformed("header"))?;
        if rest.is_empty() {
            return Ok((fields, pos));
        }
        let end = rest
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or(MailError::Malformed("header line end"))?;
        let line = rest.get(..end).ok_or(MailError::Malformed("header"))?;
        let next = pos.saturating_add(end).saturating_add(2);
        if line.is_empty() {
            return Ok((fields, next));
        }
        if line.len() > MAX_LINE {
            return Err(MailError::TooLarge("header line"));
        }
        if line
            .iter()
            .any(|b| *b == 0 || *b >= 0x80 || *b == b'\r' || *b == b'\n')
        {
            return Err(MailError::Malformed("header byte"));
        }
        match line.first() {
            Some(b' ' | b'\t') => {
                let last = fields
                    .last_mut()
                    .ok_or(MailError::Malformed("continuation"))?;
                last.raw_value.extend_from_slice(b"\r\n");
                last.raw_value.extend_from_slice(line);
            }
            _ => {
                if fields.len() >= MAX_FIELDS {
                    return Err(MailError::TooLarge("header fields"));
                }
                let colon = line
                    .iter()
                    .position(|b| *b == b':')
                    .ok_or(MailError::Malformed("header name"))?;
                let name = line.get(..colon).unwrap_or_default();
                if name.is_empty() || !name.iter().all(|b| (33..=126).contains(b)) {
                    return Err(MailError::Malformed("header name"));
                }
                fields.push(HeaderField {
                    name: String::from_utf8_lossy(name).into_owned(),
                    raw_value: line
                        .get(colon.saturating_add(1)..)
                        .unwrap_or_default()
                        .to_vec(),
                });
            }
        }
        pos = next;
    }
}

fn field<'a>(fields: &'a [HeaderField], name: &str) -> Option<&'a HeaderField> {
    fields.iter().find(|f| f.name.eq_ignore_ascii_case(name))
}

/// A `first; k=v; k="v"` value: the first item in lower case and the
/// parameters with lower-case names.
fn split_params(value: &str) -> Result<(String, Vec<(String, String)>), MailError> {
    let bad = MailError::Malformed("parameters");
    let mut items: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut escaped = false;
    for c in value.chars() {
        if escaped {
            cur.push(c);
            escaped = false;
        } else if quoted && c == '\\' {
            escaped = true;
        } else if c == '"' {
            quoted = !quoted;
            cur.push(c);
        } else if c == ';' && !quoted {
            items.push(std::mem::take(&mut cur));
        } else {
            cur.push(c);
        }
    }
    if quoted || escaped {
        return Err(bad);
    }
    items.push(cur);
    let mut it = items.into_iter();
    let first = it.next().unwrap_or_default().trim().to_ascii_lowercase();
    let mut params = Vec::new();
    for item in it {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let (k, v) = item
            .split_once('=')
            .ok_or(MailError::Malformed("parameter"))?;
        let v = v.trim();
        let v = match v.strip_prefix('"') {
            Some(q) => q
                .strip_suffix('"')
                .ok_or(MailError::Malformed("parameter"))?
                .to_owned(),
            None => v.to_owned(),
        };
        params.push((k.trim().to_ascii_lowercase(), v));
    }
    Ok((first, params))
}

fn token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$&-^_.+".contains(&b))
}

/// A `type/subtype` value with parameters, as [`split_params`] reads it.
fn media_params(value: &str) -> Result<(String, Vec<(String, String)>), MailError> {
    let (media, params) = split_params(value)?;
    let (ty, sub) = media
        .split_once('/')
        .ok_or(MailError::Malformed("media type"))?;
    if !token(ty) || !token(sub) {
        return Err(MailError::Malformed("media type"));
    }
    Ok((media, params))
}

fn param<'a>(params: &'a [(String, String)], name: &str) -> Option<&'a str> {
    params
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

/// Splits a multipart body on `boundary` (RFC 2046 section 5.1.1). The
/// CRLF before a delimiter belongs to it. A close delimiter is required.
fn split_multipart<'a>(body: &'a [u8], boundary: &str) -> Result<Vec<&'a [u8]>, MailError> {
    let delim = format!("--{boundary}");
    let delim = delim.as_bytes();
    let mut parts = Vec::new();
    let mut start: Option<usize> = None;
    let mut line_start = 0usize;
    while line_start <= body.len() {
        let rest = body.get(line_start..).unwrap_or_default();
        let len = rest
            .windows(2)
            .position(|w| w == b"\r\n")
            .unwrap_or(rest.len());
        let line = rest.get(..len).unwrap_or_default();
        let next = line_start.saturating_add(len).saturating_add(2);
        if let Some(tail) = line.strip_prefix(delim) {
            let close = tail.starts_with(b"--");
            let pad = if close {
                tail.get(2..).unwrap_or_default()
            } else {
                tail
            };
            if pad.iter().all(|b| *b == b' ' || *b == b'\t') {
                if let Some(s) = start {
                    let end = line_start.saturating_sub(2).max(s);
                    parts.push(body.get(s..end).ok_or(MailError::Malformed("multipart"))?);
                    if parts.len() > MAX_PARTS {
                        return Err(MailError::TooLarge("parts"));
                    }
                }
                if close {
                    if parts.is_empty() {
                        return Err(MailError::Malformed("multipart without parts"));
                    }
                    return Ok(parts);
                }
                start = Some(next.min(body.len()));
            }
        }
        line_start = next;
    }
    Err(MailError::Malformed("multipart close delimiter"))
}

fn parse_entity(
    fields: &[HeaderField],
    body: &[u8],
    depth: usize,
    out: &mut Vec<ParsedPart>,
) -> Result<(), MailError> {
    if depth > MAX_DEPTH {
        return Err(MailError::TooLarge("nesting"));
    }
    let ct =
        field(fields, "Content-Type").map_or_else(|| "text/plain".to_owned(), HeaderField::value);
    let (media, params) = media_params(&ct)?;
    if media.starts_with("multipart/") {
        let boundary = param(&params, "boundary").ok_or(MailError::Malformed("boundary"))?;
        if boundary.is_empty() || boundary.len() > 70 {
            return Err(MailError::Malformed("boundary"));
        }
        for part in split_multipart(body, boundary)? {
            let (pf, off) = parse_headers(part)?;
            let pbody = part.get(off..).unwrap_or_default();
            parse_entity(&pf, pbody, depth.saturating_add(1), out)?;
        }
        return Ok(());
    }
    let cte = field(fields, "Content-Transfer-Encoding")
        .map_or_else(|| "7bit".to_owned(), |f| f.value().to_ascii_lowercase());
    let decoded = match cte.as_str() {
        "7bit" | "8bit" | "binary" => body.to_vec(),
        "quoted-printable" => qp_decode(body)?,
        "base64" => base64_decode(body)?,
        _ => return Err(MailError::Malformed("transfer encoding")),
    };
    let filename = match field(fields, "Content-Disposition") {
        Some(f) => {
            let (_, dp) = split_params(&f.value())?;
            param(&dp, "filename").map(str::to_owned)
        }
        None => None,
    }
    .or_else(|| param(&params, "name").map(str::to_owned));
    if out.len() >= MAX_PARTS {
        return Err(MailError::TooLarge("parts"));
    }
    out.push(ParsedPart {
        content_type: media,
        filename,
        decoded,
    });
    Ok(())
}

/// Parses a whole message: the top-level fields, the body and every leaf
/// part, decoded.
///
/// # Errors
///
/// [`MailError::Malformed`] or [`MailError::TooLarge`] for input that is
/// not a well-formed message within the bounds of this module.
pub fn parse(raw: &[u8]) -> Result<ParsedMessage, MailError> {
    if raw.len() > MAX_MESSAGE {
        return Err(MailError::TooLarge("message"));
    }
    let (fields, off) = parse_headers(raw)?;
    if fields.is_empty() {
        return Err(MailError::Malformed("no header"));
    }
    let body = raw.get(off..).unwrap_or_default();
    let mut parts = Vec::new();
    parse_entity(&fields, body, 0, &mut parts)?;
    let header_values = fields.iter().map(|f| (f.name.clone(), f.value())).collect();
    Ok(ParsedMessage {
        fields,
        body: body.to_vec(),
        parts,
        header_values,
    })
}
