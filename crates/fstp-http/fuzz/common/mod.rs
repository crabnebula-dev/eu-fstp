//! Helpers shared by the fstp-http fuzz targets.
//!
//! Each target reads a control prefix from the fuzz input:
//!
//! - byte 0: bits 0-2 give the number of split points, bit 3 selects small
//!   limits, bit 4 feeds an end of stream, bit 5 selects HEAD for responses;
//! - bytes 1-4: small limit values when bit 3 is set;
//! - then two bytes per split point (little endian, reduced modulo the
//!   length of the rest);
//! - the rest is the message input.

#![allow(dead_code)]

use fstp_http::{
    ChunkedDecoder, ChunkedEvent, Headers, Limits, Method, ParseErrorKind, RequestDecoder,
    RequestEvent, RequestHead, ResponseDecoder, ResponseEvent, ResponseHead,
};

/// Decoded control prefix.
pub struct Control<'a> {
    pub limits: Limits,
    pub eof: bool,
    pub head: bool,
    pub splits: Vec<usize>,
    pub input: &'a [u8],
}

pub fn control(data: &[u8]) -> Option<Control<'_>> {
    let (&ctl, mut rest) = data.split_first()?;
    let n_splits = usize::from(ctl & 0x07);
    let small = ctl & 0x08 != 0;
    let eof = ctl & 0x10 != 0;
    let head = ctl & 0x20 != 0;
    let limits = if small {
        let l = rest.get(..4)?;
        rest = rest.get(4..)?;
        Limits {
            max_start_line: usize::from(l[0] % 96),
            max_leading_empty_lines: usize::from(l[0] >> 6),
            max_headers: usize::from(l[1] % 12),
            max_header_bytes: usize::from(l[1]),
            max_body_bytes: u64::from(l[2]),
            max_chunk_size: u64::from(l[2] % 64),
            max_chunk_line: usize::from(l[3] % 32),
            max_chunk_ext_bytes: usize::from(l[3] >> 3),
            max_trailers: usize::from(l[3] % 5),
            max_trailer_bytes: usize::from(l[3]),
        }
    } else {
        Limits::default()
    };
    let split_len = (n_splits * 2).min(rest.len());
    let (split_bytes, input) = rest.split_at(split_len);
    let modulus = input.len() + 1;
    let splits = split_bytes
        .chunks(2)
        .map(|c| {
            let v = u16::from_le_bytes([c[0], *c.get(1).unwrap_or(&0)]);
            usize::from(v) % modulus
        })
        .collect();
    Some(Control {
        limits,
        eof,
        head,
        splits,
        input,
    })
}

pub fn pieces<'a>(input: &'a [u8], splits: &[usize]) -> Vec<&'a [u8]> {
    let mut cuts: Vec<usize> = splits.iter().map(|&s| s.min(input.len())).collect();
    cuts.sort_unstable();
    cuts.dedup();
    let mut out = Vec::new();
    let mut prev = 0;
    for c in cuts {
        out.push(&input[prev..c]);
        prev = c;
    }
    out.push(&input[prev..]);
    out
}

/// Outcome of decoding a request stream. Partial bodies of a failing
/// message are not kept, since they may legitimately differ by split.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReqOutcome {
    pub messages: Vec<(RequestHead, Vec<u8>, Headers)>,
    pub pending_head: Option<RequestHead>,
    pub error: Option<ParseErrorKind>,
    pub buffered: Option<usize>,
}

pub fn decode_requests(input: &[u8], splits: &[usize], limits: Limits, eof: bool) -> ReqOutcome {
    let mut d = RequestDecoder::new(limits);
    let mut out = ReqOutcome {
        messages: Vec::new(),
        pending_head: None,
        error: None,
        buffered: None,
    };
    let mut body = Vec::new();
    let mut pieces_iter = pieces(input, splits).into_iter();
    let mut fed_eof = false;
    loop {
        match d.next_event() {
            Ok(Some(RequestEvent::Head(h))) => {
                assert!(out.pending_head.is_none(), "Head while a message is open");
                out.pending_head = Some(*h);
                body.clear();
            }
            Ok(Some(RequestEvent::Data(b))) => {
                assert!(out.pending_head.is_some(), "Data without Head");
                assert!(!b.is_empty(), "empty Data event");
                body.extend_from_slice(&b);
            }
            Ok(Some(RequestEvent::End(t))) => {
                let h = out.pending_head.take().expect("End without Head");
                out.messages.push((h, std::mem::take(&mut body), t));
            }
            Ok(None) => match pieces_iter.next() {
                Some(p) => d.feed(p),
                None if eof && !fed_eof => {
                    fed_eof = true;
                    d.feed_eof();
                }
                None => break,
            },
            Err(e) => {
                out.error = Some(e.kind());
                // Sticky: the same error again.
                assert_eq!(d.next_event().map_err(|e| e.kind()), Err(e.kind()));
                return out;
            }
        }
    }
    out.buffered = Some(d.buffered());
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RespOutcome {
    pub messages: Vec<(ResponseHead, Vec<u8>, Headers)>,
    pub pending_head: Option<ResponseHead>,
    pub error: Option<ParseErrorKind>,
    pub buffered: Option<usize>,
}

pub fn decode_responses(
    input: &[u8],
    splits: &[usize],
    method: &Method,
    limits: Limits,
    eof: bool,
) -> RespOutcome {
    let mut d = ResponseDecoder::new(limits);
    d.expect_response_to(method.clone());
    let mut out = RespOutcome {
        messages: Vec::new(),
        pending_head: None,
        error: None,
        buffered: None,
    };
    let mut body = Vec::new();
    let mut pieces_iter = pieces(input, splits).into_iter();
    let mut fed_eof = false;
    loop {
        match d.next_event() {
            Ok(Some(ResponseEvent::Head(h))) => {
                assert!(out.pending_head.is_none(), "Head while a message is open");
                out.pending_head = Some(*h);
                body.clear();
            }
            Ok(Some(ResponseEvent::Data(b))) => {
                assert!(out.pending_head.is_some(), "Data without Head");
                assert!(!b.is_empty(), "empty Data event");
                body.extend_from_slice(&b);
            }
            Ok(Some(ResponseEvent::End(t))) => {
                let h = out.pending_head.take().expect("End without Head");
                out.messages.push((h, std::mem::take(&mut body), t));
            }
            Ok(None) => match pieces_iter.next() {
                Some(p) => d.feed(p),
                None if eof && !fed_eof => {
                    fed_eof = true;
                    d.feed_eof();
                }
                None => break,
            },
            Err(e) => {
                out.error = Some(e.kind());
                assert_eq!(d.next_event().map_err(|e| e.kind()), Err(e.kind()));
                return out;
            }
        }
    }
    out.buffered = Some(d.buffered());
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkOutcome {
    /// Decoded body, kept only on success.
    pub body: Vec<u8>,
    pub trailers: Option<Headers>,
    pub error: Option<ParseErrorKind>,
    pub remaining: Vec<u8>,
}

pub fn decode_chunked(input: &[u8], splits: &[usize], limits: Limits, eof: bool) -> ChunkOutcome {
    let mut d = ChunkedDecoder::new(limits);
    let mut out = ChunkOutcome {
        body: Vec::new(),
        trailers: None,
        error: None,
        remaining: Vec::new(),
    };
    let mut pieces_iter = pieces(input, splits).into_iter();
    let mut fed_eof = false;
    loop {
        match d.next_event() {
            Ok(Some(ChunkedEvent::Data(b))) => {
                assert!(out.trailers.is_none(), "Data after End");
                out.body.extend_from_slice(&b);
            }
            Ok(Some(ChunkedEvent::End(t))) => out.trailers = Some(t),
            Ok(None) => match pieces_iter.next() {
                Some(p) => d.feed(p),
                None if eof && !fed_eof => {
                    fed_eof = true;
                    d.feed_eof();
                }
                None => break,
            },
            Err(e) => {
                out.error = Some(e.kind());
                out.body.clear();
                return out;
            }
        }
    }
    out.remaining = d.remaining().to_vec();
    out
}

// ---------------------------------------------------------------------------
// Reference chunked decoder: stateless, whole-buffer, written independently
// of the incremental one. It must agree on every input.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefOutcome {
    /// Body, trailers as (name, value) pairs, bytes consumed.
    Done(Vec<u8>, Vec<(Vec<u8>, Vec<u8>)>, usize),
    Incomplete,
    Invalid(ParseErrorKind),
}

fn tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

fn ws(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

/// Finds a CRLF-terminated line at `at` with at most `max_total` bytes.
/// Returns the content end and the next position.
fn ref_line(
    buf: &[u8],
    at: usize,
    max_total: usize,
    too_long: ParseErrorKind,
) -> Result<Option<(usize, usize)>, ParseErrorKind> {
    let rest = &buf[at..];
    if rest.is_empty() {
        return Ok(None);
    }
    let limit = rest.len().min(max_total);
    match rest[..limit].iter().position(|&b| b == b'\n') {
        Some(lf) => {
            if lf == 0 || rest[lf - 1] != b'\r' {
                return Err(ParseErrorKind::BareLf);
            }
            Ok(Some((at + lf - 1, at + lf + 1)))
        }
        None if rest.len() >= max_total => Err(too_long),
        None => Ok(None),
    }
}

fn ref_ext(ext: &[u8]) -> bool {
    // A tiny state machine over the chunk-ext grammar.
    #[derive(PartialEq)]
    enum S {
        Start,
        AfterSemi,
        Name,
        AfterName,
        AfterEq,
        Token,
        Quoted,
        Escape,
        AfterQuote,
    }
    let mut s = S::Start;
    for &b in ext {
        s = match s {
            S::Start | S::AfterQuote | S::Token if b == b';' => S::AfterSemi,
            S::Start if ws(b) => S::Start,
            S::AfterSemi if ws(b) => S::AfterSemi,
            S::AfterSemi if tchar(b) => S::Name,
            S::Name if tchar(b) => S::Name,
            S::Name if b == b';' => S::AfterSemi,
            S::Name | S::AfterName if ws(b) => S::AfterName,
            S::Name | S::AfterName if b == b'=' => S::AfterEq,
            S::AfterName if b == b';' => S::AfterSemi,
            S::AfterEq if ws(b) => S::AfterEq,
            S::AfterEq if b == b'"' => S::Quoted,
            S::AfterEq if tchar(b) => S::Token,
            S::Token if tchar(b) => S::Token,
            S::Token | S::AfterQuote if ws(b) => S::Start,
            S::Quoted if b == b'"' => S::AfterQuote,
            S::Quoted if b == b'\\' => S::Escape,
            S::Quoted
                if b == b'\t'
                    || b == b' '
                    || b == 0x21
                    || (0x23..=0x7E).contains(&b)
                    || b >= 0x80 =>
            {
                S::Quoted
            }
            S::Escape if b == b'\t' || b == b' ' || (0x21..=0x7E).contains(&b) || b >= 0x80 => {
                S::Quoted
            }
            _ => return false,
        };
    }
    // Trailing whitespace without a following `;` is not allowed, and a
    // name or value must be complete.
    matches!(s, S::Start | S::Name | S::Token | S::AfterQuote)
        && !ext.last().is_some_and(|&b| ws(b))
}

fn ref_field(line: &[u8]) -> Result<(Vec<u8>, Vec<u8>), ParseErrorKind> {
    if line.contains(&b'\r') {
        return Err(ParseErrorKind::BareCr);
    }
    if ws(line[0]) {
        return Err(ParseErrorKind::ObsoleteLineFolding);
    }
    let colon = line
        .iter()
        .position(|&b| b == b':')
        .ok_or(ParseErrorKind::MissingColon)?;
    let name = &line[..colon];
    if name.last().is_some_and(|&b| ws(b)) {
        return Err(ParseErrorKind::WhitespaceBeforeColon);
    }
    if name.is_empty() || !name.iter().all(|&b| tchar(b)) {
        return Err(ParseErrorKind::InvalidHeaderName);
    }
    let mut value = &line[colon + 1..];
    while let [first, rest @ ..] = value {
        if ws(*first) {
            value = rest;
        } else {
            break;
        }
    }
    while let [rest @ .., last] = value {
        if ws(*last) {
            value = rest;
        } else {
            break;
        }
    }
    if value.iter().any(|&b| (b < 0x20 && b != b'\t') || b == 0x7F) {
        return Err(ParseErrorKind::InvalidHeaderValue);
    }
    Ok((name.to_ascii_lowercase(), value.to_vec()))
}

pub fn reference_chunked(buf: &[u8], l: &Limits) -> RefOutcome {
    use ParseErrorKind as K;
    let mut at = 0usize;
    let mut body = Vec::new();
    let mut ext_total = 0usize;
    loop {
        let (end, next) = match ref_line(
            buf,
            at,
            l.max_chunk_line.saturating_add(2),
            K::ChunkLineTooLong,
        ) {
            Ok(Some(x)) => x,
            Ok(None) => return RefOutcome::Incomplete,
            Err(k) => return RefOutcome::Invalid(k),
        };
        let line = &buf[at..end];
        if line.contains(&b'\r') {
            return RefOutcome::Invalid(K::BareCr);
        }
        let digits = line.iter().take_while(|b| b.is_ascii_hexdigit()).count();
        if digits == 0 {
            return RefOutcome::Invalid(K::InvalidChunkSize);
        }
        // A size above u64::MAX is too large whatever the limits say. A size
        // that fits but uses more than 16 digits has extra leading zeros.
        let significant = line[..digits].iter().skip_while(|&&b| b == b'0').count();
        if significant > 16 {
            return RefOutcome::Invalid(K::ChunkTooLarge);
        }
        if digits > 16 {
            return RefOutcome::Invalid(K::InvalidChunkSize);
        }
        let ext = &line[digits..];
        if !ref_ext(ext) {
            return RefOutcome::Invalid(K::InvalidChunkExtension);
        }
        ext_total += ext.len();
        if ext_total > l.max_chunk_ext_bytes {
            return RefOutcome::Invalid(K::ChunkExtensionsTooLarge);
        }
        // At most 16 hex digits always fit a u64.
        let size = u64::from_str_radix(std::str::from_utf8(&line[..digits]).unwrap(), 16)
            .expect("16 hex digits fit a u64");
        if size > l.max_chunk_size {
            return RefOutcome::Invalid(K::ChunkTooLarge);
        }
        if (body.len() as u64).saturating_add(size) > l.max_body_bytes {
            return RefOutcome::Invalid(K::BodyTooLarge);
        }
        at = next;
        if size == 0 {
            break;
        }
        let size = size as usize;
        if buf.len() - at < size {
            return RefOutcome::Incomplete;
        }
        body.extend_from_slice(&buf[at..at + size]);
        at += size;
        match &buf[at..] {
            [] | [b'\r'] => return RefOutcome::Incomplete,
            [b'\r', b'\n', ..] => at += 2,
            _ => return RefOutcome::Invalid(K::InvalidChunkTerminator),
        }
    }
    let mut trailers = Vec::new();
    let mut used = 0usize;
    loop {
        let remaining = l.max_trailer_bytes.saturating_sub(used);
        let (end, next) = match ref_line(buf, at, remaining.max(2), K::TrailerSectionTooLarge) {
            Ok(Some(x)) => x,
            Ok(None) => return RefOutcome::Incomplete,
            Err(k) => return RefOutcome::Invalid(k),
        };
        if end == at {
            return RefOutcome::Done(body, trailers, next);
        }
        let total = next - at;
        if total > remaining {
            return RefOutcome::Invalid(K::TrailerSectionTooLarge);
        }
        if trailers.len() >= l.max_trailers {
            return RefOutcome::Invalid(K::TooManyTrailers);
        }
        match ref_field(&buf[at..end]) {
            Ok(f) => trailers.push(f),
            Err(k) => return RefOutcome::Invalid(k),
        }
        used += total;
        at = next;
    }
}

/// Copies `headers` without the named fields.
pub fn without(headers: &Headers, names: &[&str]) -> Headers {
    let mut out = Headers::new();
    for (n, v) in headers {
        if !names.iter().any(|x| n.eq_name(x)) {
            out.append(n.clone(), v.clone());
        }
    }
    out
}

/// Checks that every line in a serialized head ends in CRLF and that no
/// bare CR or LF appears. Returns the number of lines, including the final
/// empty one.
pub fn head_lines(wire: &[u8]) -> usize {
    let end = wire
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("serialized head has no end")
        + 4;
    let head = &wire[..end];
    let mut lines = 0;
    let mut i = 0;
    while i < head.len() {
        match head[i] {
            b'\r' => {
                assert_eq!(head.get(i + 1), Some(&b'\n'), "bare CR in serialized head");
                lines += 1;
                i += 2;
            }
            b'\n' => panic!("bare LF in serialized head"),
            0 => panic!("NUL in serialized head"),
            _ => i += 1,
        }
    }
    lines
}

/// Generous limits for re-parsing a re-encoded message. Re-encoding writes
/// `name: value` with one space, so a head that sat exactly at a limit can
/// grow by a few bytes.
pub fn relaxed() -> Limits {
    Limits {
        max_start_line: 64 * 1024,
        max_leading_empty_lines: 1,
        max_headers: 1000,
        max_header_bytes: 1024 * 1024,
        max_body_bytes: 16 * 1024 * 1024,
        max_chunk_size: 16 * 1024 * 1024,
        max_chunk_line: 4096,
        max_chunk_ext_bytes: 1024 * 1024,
        max_trailers: 1000,
        max_trailer_bytes: 1024 * 1024,
    }
}
