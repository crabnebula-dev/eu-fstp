//! Incremental, sans-IO decoders for HTTP/1.1 messages (RFC 9112).
//!
//! A decoder owns a byte buffer. The caller appends input with `feed`,
//! signals the end of the stream with `feed_eof`, and pulls events with
//! `next_event`:
//!
//! - `Ok(Some(event))`: a head, a piece of body data, or the end of a
//!   message with its trailers.
//! - `Ok(None)`: more input is needed, or the stream ended cleanly between
//!   messages.
//! - `Err(e)`: the input violates the grammar, a framing rule or a limit.
//!   The error is sticky: every later call returns it again.
//!
//! The result does not depend on how the input is split across `feed`
//! calls. The same bytes give the same heads, the same concatenated body,
//! the same trailers and the same error, for any chunking. Body data may
//! arrive in differently sized pieces, and a failing message may yield a
//! different amount of body data before its error.
//!
//! Lines are validated only once they are complete, and length limits are
//! checked in a way that depends on the line, not on the chunking. A line
//! that cannot fit its limit is rejected as soon as enough bytes arrived to
//! prove it, which bounds the buffered bytes for any one line.
//!
//! After a message ends, the decoder parses the next one from the bytes
//! that follow (keep-alive and pipelining).

use crate::chars::{
    is_field_byte, is_field_vchar, is_ows, is_token, skip_ows, token_len, trim_ows,
};
use crate::error::{ParseError, ParseErrorKind as K};
use crate::header::{HeaderName, HeaderValue, Headers};
use crate::limits::Limits;
use crate::message::{BodyKind, Request, RequestHead, Response, ResponseHead};
use crate::method::Method;
use crate::status::StatusCode;
use crate::target::{RequestTarget, valid_host_value};
use crate::version::{Version, VersionParse, parse_version};

/// Consumed bytes are compacted away once this many accumulate.
const COMPACT_THRESHOLD: usize = 4096;

/// An append-only byte queue with a read offset.
#[derive(Debug, Default)]
struct Buf {
    data: Vec<u8>,
    start: usize,
}

impl Buf {
    fn bytes(&self) -> &[u8] {
        self.data.get(self.start..).unwrap_or_default()
    }

    fn len(&self) -> usize {
        self.data.len().saturating_sub(self.start)
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn push(&mut self, input: &[u8]) {
        if self.start > 0
            && (self.start >= COMPACT_THRESHOLD || self.start.saturating_mul(2) >= self.data.len())
        {
            if self.start >= self.data.len() {
                self.data.clear();
            } else {
                self.data.drain(..self.start);
            }
            self.start = 0;
        }
        self.data.extend_from_slice(input);
    }

    fn consume(&mut self, n: usize) {
        self.start = self.start.saturating_add(n).min(self.data.len());
        if self.start == self.data.len() {
            self.data.clear();
            self.start = 0;
        }
    }

    fn take(&mut self, n: usize) -> Vec<u8> {
        let n = n.min(self.len());
        let out = self
            .bytes()
            .get(..n)
            .map(<[u8]>::to_vec)
            .unwrap_or_default();
        self.consume(out.len());
        out
    }
}

/// Why a line could not be taken.
enum LineError {
    /// The line cannot fit the limit.
    TooLong,
    /// The line ends in LF without CR.
    BareLf,
}

/// Input buffer, end-of-stream flag and line scanner.
#[derive(Debug, Default)]
struct Reader {
    buf: Buf,
    /// Bytes of the current line already searched for LF.
    scan: usize,
    eof: bool,
}

impl Reader {
    /// Looks for a complete line of at most `max_total` bytes including
    /// CRLF. Returns the content length (without CRLF) and the total
    /// length.
    ///
    /// The line is too long exactly when no LF occurs among its first
    /// `max_total` bytes. That test gives the same answer whether the bytes
    /// arrive at once or one at a time.
    fn line(&mut self, max_total: usize) -> Result<Option<(usize, usize)>, LineError> {
        let data = self.buf.bytes();
        if data.is_empty() {
            return Ok(None);
        }
        let end = data.len().min(max_total);
        let from = self.scan.min(end);
        let window = data.get(from..end).unwrap_or_default();
        if let Some(off) = window.iter().position(|&b| b == b'\n') {
            self.scan = 0;
            let lf = from.saturating_add(off);
            let Some(cr) = lf.checked_sub(1) else {
                return Err(LineError::BareLf);
            };
            if data.get(cr) != Some(&b'\r') {
                return Err(LineError::BareLf);
            }
            return Ok(Some((cr, lf.saturating_add(1))));
        }
        if data.len() >= max_total {
            self.scan = 0;
            return Err(LineError::TooLong);
        }
        self.scan = end;
        Ok(None)
    }

    fn content(&self, len: usize) -> &[u8] {
        self.buf.bytes().get(..len).unwrap_or_default()
    }
}

fn line_err(e: LineError, too_long: K) -> ParseError {
    match e {
        LineError::TooLong => ParseError::new(too_long),
        LineError::BareLf => ParseError::new(K::BareLf),
    }
}

/// Limits for one field section (headers or trailers).
#[derive(Debug, Clone, Copy)]
struct SectionLimits {
    max_count: usize,
    max_bytes: usize,
    too_many: K,
    too_large: K,
}

/// A field section being read line by line.
#[derive(Debug)]
struct FieldSection {
    headers: Headers,
    bytes: usize,
    limits: SectionLimits,
}

impl FieldSection {
    fn new(limits: SectionLimits) -> FieldSection {
        FieldSection {
            headers: Headers::new(),
            bytes: 0,
            limits,
        }
    }

    /// Reads field lines. Returns `true` once the empty line arrived.
    fn poll(&mut self, rd: &mut Reader) -> Result<bool, ParseError> {
        loop {
            let remaining = self.limits.max_bytes.saturating_sub(self.bytes);
            let found = rd
                .line(remaining.max(2))
                .map_err(|e| line_err(e, self.limits.too_large))?;
            let Some((len, total)) = found else {
                return Ok(false);
            };
            if len == 0 {
                rd.buf.consume(total);
                return Ok(true);
            }
            if total > remaining {
                return Err(self.limits.too_large.into());
            }
            if self.headers.len() >= self.limits.max_count {
                return Err(self.limits.too_many.into());
            }
            let (name, value) = parse_field_line(rd.content(len))?;
            self.headers.append(name, value);
            self.bytes = self.bytes.saturating_add(total);
            rd.buf.consume(total);
        }
    }
}

/// Parses `field-name ":" OWS field-value OWS`.
fn parse_field_line(line: &[u8]) -> Result<(HeaderName, HeaderValue), K> {
    if line.contains(&b'\r') {
        return Err(K::BareCr);
    }
    if line.first().is_some_and(|&b| is_ows(b)) {
        return Err(K::ObsoleteLineFolding);
    }
    let colon = line
        .iter()
        .position(|&b| b == b':')
        .ok_or(K::MissingColon)?;
    let name = line.get(..colon).unwrap_or_default();
    if name.last().is_some_and(|&b| is_ows(b)) {
        return Err(K::WhitespaceBeforeColon);
    }
    let name = HeaderName::from_bytes(name).map_err(|_| K::InvalidHeaderName)?;
    let value = trim_ows(line.get(colon.saturating_add(1)..).unwrap_or_default());
    if !value.iter().all(|&b| is_field_byte(b)) {
        return Err(K::InvalidHeaderValue);
    }
    Ok((name, HeaderValue::from_validated(value)))
}

fn header_limits(l: &Limits) -> SectionLimits {
    SectionLimits {
        max_count: l.max_headers,
        max_bytes: l.max_header_bytes,
        too_many: K::TooManyHeaders,
        too_large: K::HeaderSectionTooLarge,
    }
}

fn trailer_limits(l: &Limits) -> SectionLimits {
    SectionLimits {
        max_count: l.max_trailers,
        max_bytes: l.max_trailer_bytes,
        too_many: K::TooManyTrailers,
        too_large: K::TrailerSectionTooLarge,
    }
}

// ---------------------------------------------------------------------------
// Chunked transfer coding.

/// Result of one body step.
enum BodyStep {
    Data(Vec<u8>),
    End(Headers),
    NeedMore,
}

#[derive(Debug)]
enum ChunkPhase {
    Size,
    Data { remaining: u64 },
    DataCrlf,
    Trailers(FieldSection),
    Done,
}

/// State of a chunked body (RFC 9112 section 7.1).
#[derive(Debug)]
struct Chunked {
    phase: ChunkPhase,
    total: u64,
    ext_total: usize,
    limits: Limits,
}

impl Chunked {
    fn new(limits: Limits) -> Chunked {
        Chunked {
            phase: ChunkPhase::Size,
            total: 0,
            ext_total: 0,
            limits,
        }
    }

    fn step(&mut self, rd: &mut Reader) -> Result<BodyStep, ParseError> {
        loop {
            match &mut self.phase {
                ChunkPhase::Size => {
                    let max = self.limits.max_chunk_line.saturating_add(2);
                    let found = rd.line(max).map_err(|e| line_err(e, K::ChunkLineTooLong))?;
                    let Some((len, total)) = found else {
                        return Ok(BodyStep::NeedMore);
                    };
                    let (size, ext_len) = parse_chunk_line(rd.content(len))?;
                    self.ext_total = self.ext_total.saturating_add(ext_len);
                    if self.ext_total > self.limits.max_chunk_ext_bytes {
                        return Err(K::ChunkExtensionsTooLarge.into());
                    }
                    if size > self.limits.max_chunk_size {
                        return Err(K::ChunkTooLarge.into());
                    }
                    if self.total.saturating_add(size) > self.limits.max_body_bytes {
                        return Err(K::BodyTooLarge.into());
                    }
                    rd.buf.consume(total);
                    self.phase = if size == 0 {
                        ChunkPhase::Trailers(FieldSection::new(trailer_limits(&self.limits)))
                    } else {
                        ChunkPhase::Data { remaining: size }
                    };
                }
                ChunkPhase::Data { remaining } => {
                    let avail = rd.buf.len();
                    if avail == 0 {
                        return Ok(BodyStep::NeedMore);
                    }
                    let n = usize::try_from(*remaining).map_or(avail, |r| r.min(avail));
                    let data = rd.buf.take(n);
                    let got = u64::try_from(data.len()).unwrap_or(u64::MAX);
                    *remaining = remaining.saturating_sub(got);
                    self.total = self.total.saturating_add(got);
                    if *remaining == 0 {
                        self.phase = ChunkPhase::DataCrlf;
                    }
                    return Ok(BodyStep::Data(data));
                }
                ChunkPhase::DataCrlf => {
                    let b = rd.buf.bytes();
                    match (b.first(), b.get(1)) {
                        (None, _) | (Some(b'\r'), None) => return Ok(BodyStep::NeedMore),
                        (Some(b'\r'), Some(b'\n')) => {
                            rd.buf.consume(2);
                            self.phase = ChunkPhase::Size;
                        }
                        _ => return Err(K::InvalidChunkTerminator.into()),
                    }
                }
                ChunkPhase::Trailers(section) => {
                    if !section.poll(rd)? {
                        return Ok(BodyStep::NeedMore);
                    }
                    let trailers = std::mem::take(&mut section.headers);
                    self.phase = ChunkPhase::Done;
                    return Ok(BodyStep::End(trailers));
                }
                ChunkPhase::Done => return Ok(BodyStep::NeedMore),
            }
        }
    }
}

/// Most hex digits in a chunk size, leading zeros included.
///
/// Sixteen digits hold any `u64`. A longer size either overflows or
/// carries only extra leading zeros. Without this cap, leading zeros up to
/// `max_chunk_line` would let a one-byte chunk cost about a kilobyte of
/// input. They count toward no other limit.
const MAX_CHUNK_SIZE_DIGITS: usize = 16;

/// Parses `chunk-size [ chunk-ext ]`. Returns the size and the number of
/// extension bytes.
///
/// A size above `u64::MAX` is `ChunkTooLarge`, whatever the limits say.
/// A size that fits but is written with more than
/// [`MAX_CHUNK_SIZE_DIGITS`] digits is `InvalidChunkSize`.
fn parse_chunk_line(line: &[u8]) -> Result<(u64, usize), K> {
    if line.contains(&b'\r') {
        return Err(K::BareCr);
    }
    let digits = line.iter().take_while(|b| b.is_ascii_hexdigit()).count();
    if digits == 0 {
        return Err(K::InvalidChunkSize);
    }
    let size_digits = line.get(..digits).unwrap_or_default();
    let significant = size_digits.iter().skip_while(|&&b| b == b'0').count();
    if significant > MAX_CHUNK_SIZE_DIGITS {
        return Err(K::ChunkTooLarge);
    }
    if digits > MAX_CHUNK_SIZE_DIGITS {
        return Err(K::InvalidChunkSize);
    }
    let mut size: u64 = 0;
    for &b in size_digits {
        let v = u64::from(crate::chars::hex_val(b).ok_or(K::InvalidChunkSize)?);
        size = size
            .checked_mul(16)
            .and_then(|s| s.checked_add(v))
            .ok_or(K::ChunkTooLarge)?;
    }
    let ext = line.get(digits..).unwrap_or_default();
    if !valid_chunk_ext(ext) {
        return Err(K::InvalidChunkExtension);
    }
    Ok((size, ext.len()))
}

/// `chunk-ext = *( BWS ";" BWS chunk-ext-name [ BWS "=" BWS chunk-ext-val ] )`
/// with `chunk-ext-val = token / quoted-string`.
fn valid_chunk_ext(s: &[u8]) -> bool {
    let mut i = 0usize;
    while i < s.len() {
        i = skip_ows(s, i);
        if s.get(i) != Some(&b';') {
            return false;
        }
        i = skip_ows(s, i.saturating_add(1));
        let n = token_len(s, i);
        if n == 0 {
            return false;
        }
        i = i.saturating_add(n);
        let j = skip_ows(s, i);
        if s.get(j) == Some(&b'=') {
            i = skip_ows(s, j.saturating_add(1));
            if s.get(i) == Some(&b'"') {
                match quoted_string_end(s, i) {
                    Some(end) => i = end,
                    None => return false,
                }
            } else {
                let n = token_len(s, i);
                if n == 0 {
                    return false;
                }
                i = i.saturating_add(n);
            }
        }
    }
    true
}

/// Given `s[start] == '"'`, returns the index after the closing quote.
fn quoted_string_end(s: &[u8], start: usize) -> Option<usize> {
    let mut i = start.saturating_add(1);
    loop {
        let b = *s.get(i)?;
        match b {
            b'"' => return Some(i.saturating_add(1)),
            b'\\' => {
                let q = *s.get(i.saturating_add(1))?;
                if !(is_field_vchar(q) || is_ows(q)) {
                    return None;
                }
                i = i.saturating_add(2);
            }
            b'\t' | b' ' | 0x21 | 0x23..=0x5B | 0x5D..=0x7E | 0x80..=0xFF => {
                i = i.saturating_add(1);
            }
            _ => return None,
        }
    }
}

/// Body framing in progress.
#[derive(Debug)]
enum BodyDecoder {
    Length { remaining: u64 },
    Chunked(Box<Chunked>),
    UntilClose { received: u64, max: u64 },
}

impl BodyDecoder {
    fn new(kind: BodyKind, limits: &Limits) -> BodyDecoder {
        match kind {
            BodyKind::Length(n) => BodyDecoder::Length { remaining: n },
            BodyKind::Chunked => BodyDecoder::Chunked(Box::new(Chunked::new(*limits))),
            BodyKind::UntilClose => BodyDecoder::UntilClose {
                received: 0,
                max: limits.max_body_bytes,
            },
        }
    }

    fn step(&mut self, rd: &mut Reader) -> Result<BodyStep, ParseError> {
        match self {
            BodyDecoder::Length { remaining } => {
                if *remaining == 0 {
                    return Ok(BodyStep::End(Headers::new()));
                }
                let avail = rd.buf.len();
                if avail == 0 {
                    return Ok(BodyStep::NeedMore);
                }
                let n = usize::try_from(*remaining).map_or(avail, |r| r.min(avail));
                let data = rd.buf.take(n);
                *remaining =
                    remaining.saturating_sub(u64::try_from(data.len()).unwrap_or(u64::MAX));
                Ok(BodyStep::Data(data))
            }
            BodyDecoder::Chunked(c) => c.step(rd),
            BodyDecoder::UntilClose { received, max } => {
                let avail = rd.buf.len();
                if avail > 0 {
                    let total = received.saturating_add(u64::try_from(avail).unwrap_or(u64::MAX));
                    if total > *max {
                        return Err(K::BodyTooLarge.into());
                    }
                    *received = total;
                    return Ok(BodyStep::Data(rd.buf.take(avail)));
                }
                if rd.eof {
                    *received = 0;
                    return Ok(BodyStep::End(Headers::new()));
                }
                Ok(BodyStep::NeedMore)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Framing rules shared by requests and responses.

/// Validates the Transfer-Encoding list. `Ok` means exactly one coding,
/// chunked, which is the only one this crate implements.
fn check_transfer_encoding(headers: &Headers) -> Result<(), K> {
    let mut codings: Vec<&[u8]> = Vec::new();
    for v in headers.get_all("transfer-encoding") {
        for item in v.as_bytes().split(|&b| b == b',') {
            let item = trim_ows(item);
            // Empty elements and parameters are rejected. A strict reading
            // leaves no room for disagreement with another parser.
            if !is_token(item) {
                return Err(K::InvalidTransferEncoding);
            }
            codings.push(item);
        }
    }
    let Some((last, rest)) = codings.split_last() else {
        return Err(K::InvalidTransferEncoding);
    };
    if !last.eq_ignore_ascii_case(b"chunked") {
        return Err(K::TransferEncodingNotChunked);
    }
    if rest.iter().any(|c| c.eq_ignore_ascii_case(b"chunked")) {
        return Err(K::ChunkedAppliedTwice);
    }
    if !rest.is_empty() {
        return Err(K::UnsupportedTransferCoding);
    }
    Ok(())
}

/// Parses the single Content-Length value, if present.
fn content_length(headers: &Headers) -> Result<Option<u64>, K> {
    let mut values = headers.get_all("content-length");
    let Some(v) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(K::MultipleContentLength);
    }
    let b = v.as_bytes();
    if b.is_empty() || !b.iter().all(u8::is_ascii_digit) {
        return Err(K::InvalidContentLength);
    }
    let mut n: u64 = 0;
    for &d in b {
        n = n
            .checked_mul(10)
            .and_then(|n| n.checked_add(u64::from(d.wrapping_sub(b'0'))))
            .ok_or(K::BodyTooLarge)?;
    }
    Ok(Some(n))
}

/// Reads the Connection options: (close, keep-alive).
fn connection_options(headers: &Headers) -> Result<(bool, bool), K> {
    let mut close = false;
    let mut keep_alive = false;
    for v in headers.get_all("connection") {
        for item in v.as_bytes().split(|&b| b == b',') {
            let item = trim_ows(item);
            if item.is_empty() {
                continue;
            }
            if !is_token(item) {
                return Err(K::InvalidConnection);
            }
            if item.eq_ignore_ascii_case(b"close") {
                close = true;
            } else if item.eq_ignore_ascii_case(b"keep-alive") {
                keep_alive = true;
            }
        }
    }
    Ok((close, keep_alive))
}

fn persistent(version: Version, close: bool, keep_alive: bool) -> bool {
    !close && (version == Version::Http11 || keep_alive)
}

// ---------------------------------------------------------------------------
// Requests.

struct RequestLine {
    method: Method,
    target: RequestTarget,
    version: Version,
}

/// Parses `method SP request-target SP HTTP-version` with single spaces.
fn parse_request_line(line: &[u8]) -> Result<RequestLine, K> {
    if line.contains(&b'\r') {
        return Err(K::BareCr);
    }
    let mut parts = line.split(|&b| b == b' ');
    let (Some(m), Some(t), Some(v), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(K::InvalidRequestLine);
    };
    let version = match parse_version(v) {
        VersionParse::Ok(v) => v,
        VersionParse::Unsupported => return Err(K::UnsupportedVersion),
        VersionParse::Invalid => return Err(K::InvalidVersion),
    };
    let method = Method::from_bytes(m).map_err(|_| K::InvalidMethod)?;
    if method == Method::CONNECT {
        return Err(K::UnsupportedMethod);
    }
    let target = RequestTarget::parse_wire(t, &method).ok_or(K::InvalidTarget)?;
    Ok(RequestLine {
        method,
        target,
        version,
    })
}

fn check_host(version: Version, headers: &Headers) -> Result<(), K> {
    let mut hosts = headers.get_all("host");
    let first = hosts.next();
    if hosts.next().is_some() {
        return Err(K::MultipleHost);
    }
    match first {
        None if version == Version::Http11 => Err(K::MissingHost),
        None => Ok(()),
        Some(v) if !valid_host_value(v.as_bytes()) => Err(K::InvalidHost),
        Some(_) => Ok(()),
    }
}

fn request_body_kind(version: Version, headers: &Headers, limits: &Limits) -> Result<BodyKind, K> {
    if headers.contains("transfer-encoding") {
        if version == Version::Http10 {
            return Err(K::TransferEncodingInHttp10);
        }
        if headers.contains("content-length") {
            return Err(K::ContentLengthWithTransferEncoding);
        }
        check_transfer_encoding(headers)?;
        return Ok(BodyKind::Chunked);
    }
    match content_length(headers)? {
        Some(n) if n > limits.max_body_bytes => Err(K::BodyTooLarge),
        Some(n) => Ok(BodyKind::Length(n)),
        None => Ok(BodyKind::Length(0)),
    }
}

fn expect_continue(version: Version, headers: &Headers) -> Result<bool, K> {
    // RFC 9110 section 10.1.1: a 100-continue expectation in an HTTP/1.0
    // request is ignored.
    if version == Version::Http10 || !headers.contains("expect") {
        return Ok(false);
    }
    for v in headers.get_all("expect") {
        for item in v.as_bytes().split(|&b| b == b',') {
            if !trim_ows(item).eq_ignore_ascii_case(b"100-continue") {
                return Err(K::UnsupportedExpectation);
            }
        }
    }
    Ok(true)
}

fn finish_request_head(
    line: RequestLine,
    headers: Headers,
    limits: &Limits,
) -> Result<RequestHead, K> {
    check_host(line.version, &headers)?;
    let (close, ka) = connection_options(&headers)?;
    let body = request_body_kind(line.version, &headers, limits)?;
    let expect_continue = expect_continue(line.version, &headers)?;
    Ok(RequestHead {
        keep_alive: persistent(line.version, close, ka),
        method: line.method,
        target: line.target,
        version: line.version,
        headers,
        body,
        expect_continue,
    })
}

/// An event produced by [`RequestDecoder`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestEvent {
    /// A complete request head. Body events follow, then [`RequestEvent::End`].
    Head(Box<RequestHead>),
    /// A piece of the decoded body.
    Data(Vec<u8>),
    /// The end of the request, with trailer fields of a chunked body.
    End(Headers),
}

enum ReqState {
    Start { empty_lines: usize },
    Headers(Box<(RequestLine, FieldSection)>),
    Body(BodyDecoder),
    Failed(ParseError),
}

/// Incremental decoder for a stream of requests. See the
/// [crate docs](crate#decoders).
pub struct RequestDecoder {
    rd: Reader,
    limits: Limits,
    state: ReqState,
}

impl std::fmt::Debug for RequestDecoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestDecoder")
            .field("buffered", &self.rd.buf.len())
            .field("eof", &self.rd.eof)
            .finish_non_exhaustive()
    }
}

impl RequestDecoder {
    /// A decoder that enforces `limits`.
    #[must_use]
    pub fn new(limits: Limits) -> RequestDecoder {
        RequestDecoder {
            rd: Reader::default(),
            limits,
            state: ReqState::Start { empty_lines: 0 },
        }
    }

    /// Appends input.
    ///
    /// The decoder buffers what it is given. Callers bound memory by
    /// feeding more only after [`RequestDecoder::next_event`] returned
    /// `Ok(None)`.
    pub fn feed(&mut self, data: &[u8]) {
        self.rd.buf.push(data);
    }

    /// Signals that the stream ended. A message cut short then fails with
    /// [`ParseErrorKind::UnexpectedEof`](crate::ParseErrorKind::UnexpectedEof).
    pub fn feed_eof(&mut self) {
        self.rd.eof = true;
    }

    /// Number of buffered bytes not yet consumed.
    #[must_use]
    pub fn buffered(&self) -> usize {
        self.rd.buf.len()
    }

    /// True between messages with nothing buffered.
    #[must_use]
    pub fn is_idle(&self) -> bool {
        matches!(self.state, ReqState::Start { .. }) && self.rd.buf.is_empty()
    }

    /// True once the stream ended cleanly between messages.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.rd.eof && self.is_idle()
    }

    /// Returns the next event. See the [crate docs](crate#decoders).
    ///
    /// # Errors
    ///
    /// Returns the [`ParseError`] for the first rule the input violates.
    pub fn next_event(&mut self) -> Result<Option<RequestEvent>, ParseError> {
        if let ReqState::Failed(e) = &self.state {
            return Err(*e);
        }
        let result = self.step();
        if let Err(e) = &result {
            self.state = ReqState::Failed(*e);
        }
        result
    }

    fn need_more(&self) -> Result<Option<RequestEvent>, ParseError> {
        if self.rd.eof && !self.is_idle() {
            return Err(K::UnexpectedEof.into());
        }
        Ok(None)
    }

    fn step(&mut self) -> Result<Option<RequestEvent>, ParseError> {
        loop {
            let placeholder = ReqState::Failed(ParseError::new(K::UnexpectedEof));
            match std::mem::replace(&mut self.state, placeholder) {
                ReqState::Start { empty_lines } => {
                    self.state = ReqState::Start { empty_lines };
                    let max = self.limits.max_start_line.saturating_add(2);
                    let found = self
                        .rd
                        .line(max)
                        .map_err(|e| line_err(e, K::RequestLineTooLong))?;
                    let Some((len, total)) = found else {
                        return self.need_more();
                    };
                    if len == 0 {
                        if empty_lines >= self.limits.max_leading_empty_lines {
                            return Err(K::TooManyEmptyLines.into());
                        }
                        self.rd.buf.consume(total);
                        self.state = ReqState::Start {
                            empty_lines: empty_lines.saturating_add(1),
                        };
                        continue;
                    }
                    let line = parse_request_line(self.rd.content(len))?;
                    self.rd.buf.consume(total);
                    let fields = FieldSection::new(header_limits(&self.limits));
                    self.state = ReqState::Headers(Box::new((line, fields)));
                }
                ReqState::Headers(mut boxed) => {
                    let done = boxed.1.poll(&mut self.rd)?;
                    if !done {
                        self.state = ReqState::Headers(boxed);
                        return self.need_more();
                    }
                    let (line, fields) = *boxed;
                    let head = finish_request_head(line, fields.headers, &self.limits)?;
                    self.state = ReqState::Body(BodyDecoder::new(head.body, &self.limits));
                    return Ok(Some(RequestEvent::Head(Box::new(head))));
                }
                ReqState::Body(mut body) => match body.step(&mut self.rd)? {
                    BodyStep::Data(d) => {
                        self.state = ReqState::Body(body);
                        return Ok(Some(RequestEvent::Data(d)));
                    }
                    BodyStep::End(t) => {
                        self.state = ReqState::Start { empty_lines: 0 };
                        return Ok(Some(RequestEvent::End(t)));
                    }
                    BodyStep::NeedMore => {
                        self.state = ReqState::Body(body);
                        return self.need_more();
                    }
                },
                ReqState::Failed(e) => {
                    self.state = ReqState::Failed(e);
                    return Err(e);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Responses.

/// Parses `HTTP-version SP status-code SP [ reason-phrase ]`. A missing
/// final SP after the code is tolerated, since the reason phrase is ignored.
fn parse_status_line(line: &[u8]) -> Result<(Version, StatusCode), K> {
    if line.contains(&b'\r') {
        return Err(K::BareCr);
    }
    let version = match parse_version(line.get(..8).ok_or(K::InvalidStatusLine)?) {
        VersionParse::Ok(v) => v,
        VersionParse::Unsupported => return Err(K::UnsupportedVersion),
        VersionParse::Invalid => return Err(K::InvalidStatusLine),
    };
    if line.get(8) != Some(&b' ') {
        return Err(K::InvalidStatusLine);
    }
    let digits = line.get(9..12).ok_or(K::InvalidStatusLine)?;
    if !digits.iter().all(u8::is_ascii_digit) {
        return Err(K::InvalidStatusCode);
    }
    let code = digits.iter().fold(0u16, |acc, &d| {
        acc.wrapping_mul(10)
            .wrapping_add(u16::from(d.wrapping_sub(b'0')))
    });
    let status = StatusCode::from_u16(code).map_err(|_| K::InvalidStatusCode)?;
    match line.get(12) {
        None => {}
        Some(b' ') => {
            let reason = line.get(13..).unwrap_or_default();
            if !reason.iter().all(|&b| is_field_byte(b)) {
                return Err(K::InvalidStatusLine);
            }
        }
        Some(_) => return Err(K::InvalidStatusLine),
    }
    Ok((version, status))
}

fn finish_response_head(
    version: Version,
    status: StatusCode,
    headers: Headers,
    request_method: &Method,
    limits: &Limits,
) -> Result<ResponseHead, K> {
    let (close, ka) = connection_options(&headers)?;
    let mut keep_alive = persistent(version, close, ka);
    if status == StatusCode::SWITCHING_PROTOCOLS {
        return Err(K::UnsupportedUpgrade);
    }
    let body = if status.forbids_body() || *request_method == Method::HEAD {
        BodyKind::Length(0)
    } else if headers.contains("transfer-encoding") {
        if version == Version::Http10 {
            return Err(K::TransferEncodingInHttp10);
        }
        if headers.contains("content-length") {
            return Err(K::ContentLengthWithTransferEncoding);
        }
        check_transfer_encoding(&headers)?;
        BodyKind::Chunked
    } else {
        match content_length(&headers)? {
            Some(n) if n > limits.max_body_bytes => return Err(K::BodyTooLarge),
            Some(n) => BodyKind::Length(n),
            None => {
                keep_alive = false;
                BodyKind::UntilClose
            }
        }
    };
    Ok(ResponseHead {
        version,
        status,
        headers,
        body,
        keep_alive,
    })
}

/// An event produced by [`ResponseDecoder`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseEvent {
    /// A complete response head. An interim (1xx) head is followed directly
    /// by [`ResponseEvent::End`], and the final response comes after it.
    Head(Box<ResponseHead>),
    /// A piece of the decoded body.
    Data(Vec<u8>),
    /// The end of the response, with trailer fields of a chunked body.
    End(Headers),
}

enum RespState {
    Start,
    Headers(Box<(Version, StatusCode, FieldSection)>),
    Body(BodyDecoder),
    Failed(ParseError),
}

/// Incremental decoder for a stream of responses. See the
/// [crate docs](crate#decoders).
///
/// Response framing depends on the request method, so call
/// [`ResponseDecoder::expect_response_to`] before each response to a HEAD
/// request. The default is GET.
pub struct ResponseDecoder {
    rd: Reader,
    limits: Limits,
    state: RespState,
    method: Method,
}

impl std::fmt::Debug for ResponseDecoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResponseDecoder")
            .field("buffered", &self.rd.buf.len())
            .field("eof", &self.rd.eof)
            .field("method", &self.method)
            .finish_non_exhaustive()
    }
}

impl ResponseDecoder {
    /// A decoder that enforces `limits`.
    #[must_use]
    pub fn new(limits: Limits) -> ResponseDecoder {
        ResponseDecoder {
            rd: Reader::default(),
            limits,
            state: RespState::Start,
            method: Method::GET,
        }
    }

    /// Sets the method of the request that the next response answers.
    pub fn expect_response_to(&mut self, method: Method) {
        self.method = method;
    }

    /// Appends input.
    pub fn feed(&mut self, data: &[u8]) {
        self.rd.buf.push(data);
    }

    /// Signals that the stream ended. This completes a body delimited by
    /// the connection close.
    pub fn feed_eof(&mut self) {
        self.rd.eof = true;
    }

    /// Number of buffered bytes not yet consumed.
    #[must_use]
    pub fn buffered(&self) -> usize {
        self.rd.buf.len()
    }

    /// True between messages with nothing buffered.
    #[must_use]
    pub fn is_idle(&self) -> bool {
        matches!(self.state, RespState::Start) && self.rd.buf.is_empty()
    }

    /// Returns the next event. See the [crate docs](crate#decoders).
    ///
    /// # Errors
    ///
    /// Returns the [`ParseError`] for the first rule the input violates.
    pub fn next_event(&mut self) -> Result<Option<ResponseEvent>, ParseError> {
        if let RespState::Failed(e) = &self.state {
            return Err(*e);
        }
        let result = self.step();
        if let Err(e) = &result {
            self.state = RespState::Failed(*e);
        }
        result
    }

    fn need_more(&self) -> Result<Option<ResponseEvent>, ParseError> {
        if self.rd.eof && !self.is_idle() {
            return Err(K::UnexpectedEof.into());
        }
        Ok(None)
    }

    fn step(&mut self) -> Result<Option<ResponseEvent>, ParseError> {
        loop {
            let placeholder = RespState::Failed(ParseError::new(K::UnexpectedEof));
            match std::mem::replace(&mut self.state, placeholder) {
                RespState::Start => {
                    self.state = RespState::Start;
                    let max = self.limits.max_start_line.saturating_add(2);
                    let found = self
                        .rd
                        .line(max)
                        .map_err(|e| line_err(e, K::StatusLineTooLong))?;
                    let Some((len, total)) = found else {
                        return self.need_more();
                    };
                    let (version, status) = parse_status_line(self.rd.content(len))?;
                    self.rd.buf.consume(total);
                    let fields = FieldSection::new(header_limits(&self.limits));
                    self.state = RespState::Headers(Box::new((version, status, fields)));
                }
                RespState::Headers(mut boxed) => {
                    let done = boxed.2.poll(&mut self.rd)?;
                    if !done {
                        self.state = RespState::Headers(boxed);
                        return self.need_more();
                    }
                    let (version, status, fields) = *boxed;
                    let head = finish_response_head(
                        version,
                        status,
                        fields.headers,
                        &self.method,
                        &self.limits,
                    )?;
                    self.state = RespState::Body(BodyDecoder::new(head.body, &self.limits));
                    return Ok(Some(ResponseEvent::Head(Box::new(head))));
                }
                RespState::Body(mut body) => match body.step(&mut self.rd)? {
                    BodyStep::Data(d) => {
                        self.state = RespState::Body(body);
                        return Ok(Some(ResponseEvent::Data(d)));
                    }
                    BodyStep::End(t) => {
                        self.state = RespState::Start;
                        return Ok(Some(ResponseEvent::End(t)));
                    }
                    BodyStep::NeedMore => {
                        self.state = RespState::Body(body);
                        return self.need_more();
                    }
                },
                RespState::Failed(e) => {
                    self.state = RespState::Failed(e);
                    return Err(e);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Standalone chunked decoder.

/// An event produced by [`ChunkedDecoder`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChunkedEvent {
    /// A piece of decoded chunk data.
    Data(Vec<u8>),
    /// The last chunk and the trailer section arrived.
    End(Headers),
}

/// Incremental decoder for one chunked body (RFC 9112 section 7.1), with
/// the chunk and trailer limits of [`Limits`].
pub struct ChunkedDecoder {
    rd: Reader,
    inner: Chunked,
    failed: Option<ParseError>,
    done: bool,
}

impl std::fmt::Debug for ChunkedDecoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChunkedDecoder")
            .field("buffered", &self.rd.buf.len())
            .field("done", &self.done)
            .finish_non_exhaustive()
    }
}

impl ChunkedDecoder {
    /// A decoder that enforces the chunk, body and trailer limits in
    /// `limits`.
    #[must_use]
    pub fn new(limits: Limits) -> ChunkedDecoder {
        ChunkedDecoder {
            rd: Reader::default(),
            inner: Chunked::new(limits),
            failed: None,
            done: false,
        }
    }

    /// Appends input.
    pub fn feed(&mut self, data: &[u8]) {
        self.rd.buf.push(data);
    }

    /// Signals that the stream ended.
    pub fn feed_eof(&mut self) {
        self.rd.eof = true;
    }

    /// Bytes after the end of the chunked body, once it ended.
    #[must_use]
    pub fn remaining(&self) -> &[u8] {
        self.rd.buf.bytes()
    }

    /// Returns the next event.
    ///
    /// # Errors
    ///
    /// Returns the [`ParseError`] for the first rule the input violates, or
    /// [`ParseErrorKind::UnexpectedEof`](crate::ParseErrorKind::UnexpectedEof)
    /// when the stream ended inside the body.
    pub fn next_event(&mut self) -> Result<Option<ChunkedEvent>, ParseError> {
        if let Some(e) = self.failed {
            return Err(e);
        }
        if self.done {
            return Ok(None);
        }
        let result = match self.inner.step(&mut self.rd) {
            Ok(BodyStep::Data(d)) => Ok(Some(ChunkedEvent::Data(d))),
            Ok(BodyStep::End(t)) => {
                self.done = true;
                Ok(Some(ChunkedEvent::End(t)))
            }
            Ok(BodyStep::NeedMore) if self.rd.eof => Err(K::UnexpectedEof.into()),
            Ok(BodyStep::NeedMore) => Ok(None),
            Err(e) => Err(e),
        };
        if let Err(e) = &result {
            self.failed = Some(*e);
        }
        result
    }
}

// ---------------------------------------------------------------------------
// Whole-buffer helpers.

/// Result of parsing one message from a buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parsed<T> {
    /// A complete message, and the number of input bytes it used.
    Complete {
        /// The message.
        message: T,
        /// Bytes of input consumed, including the body.
        consumed: usize,
    },
    /// The input ends before the message does.
    Incomplete,
}

/// Parses the first request in `input`.
///
/// # Errors
///
/// Returns the [`ParseError`] for the first rule the input violates.
pub fn parse_request(input: &[u8], limits: &Limits) -> Result<Parsed<Request>, ParseError> {
    let mut d = RequestDecoder::new(*limits);
    d.feed(input);
    let mut head = None;
    let mut body = Vec::new();
    loop {
        match d.next_event()? {
            None => return Ok(Parsed::Incomplete),
            Some(RequestEvent::Head(h)) => head = Some(h),
            Some(RequestEvent::Data(data)) => body.extend_from_slice(&data),
            Some(RequestEvent::End(trailers)) => {
                let Some(h) = head else {
                    return Ok(Parsed::Incomplete);
                };
                return Ok(Parsed::Complete {
                    message: Request::from_parts(*h, body, trailers),
                    consumed: input.len().saturating_sub(d.buffered()),
                });
            }
        }
    }
}

/// Parses the first final response in `input`, skipping interim (1xx)
/// responses. `request_method` is the method of the request it answers.
/// With `eof` set, `input` is the whole stream, which completes a body
/// delimited by the connection close.
///
/// # Errors
///
/// Returns the [`ParseError`] for the first rule the input violates.
pub fn parse_response(
    input: &[u8],
    request_method: &Method,
    limits: &Limits,
    eof: bool,
) -> Result<Parsed<Response>, ParseError> {
    let mut d = ResponseDecoder::new(*limits);
    d.expect_response_to(request_method.clone());
    d.feed(input);
    if eof {
        d.feed_eof();
    }
    let mut head: Option<Box<ResponseHead>> = None;
    let mut body = Vec::new();
    loop {
        match d.next_event()? {
            None => return Ok(Parsed::Incomplete),
            Some(ResponseEvent::Head(h)) => head = Some(h),
            Some(ResponseEvent::Data(data)) => body.extend_from_slice(&data),
            Some(ResponseEvent::End(trailers)) => {
                let Some(h) = head.take() else {
                    return Ok(Parsed::Incomplete);
                };
                if h.status.is_informational() {
                    continue;
                }
                return Ok(Parsed::Complete {
                    message: Response::from_parts(*h, body, trailers),
                    consumed: input.len().saturating_sub(d.buffered()),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(input: &[u8]) -> Result<Parsed<Request>, ParseError> {
        parse_request(input, &Limits::default())
    }

    #[test]
    fn simple_get() {
        let Parsed::Complete { message, consumed } =
            req(b"GET /x?y HTTP/1.1\r\nHost: a\r\n\r\nrest").unwrap()
        else {
            panic!("incomplete");
        };
        assert_eq!(consumed, 30);
        assert_eq!(message.method, Method::GET);
        assert_eq!(message.path(), "/x");
        assert_eq!(message.headers.get("host").unwrap().as_bytes(), b"a");
    }

    #[test]
    fn chunked_body() {
        let input = b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n3;x=\"q\\\"\"\r\nabc\r\n0\r\nT: v\r\n\r\n";
        let Parsed::Complete { message, .. } = req(input).unwrap() else {
            panic!("incomplete");
        };
        assert_eq!(message.body, b"abc");
        assert_eq!(message.trailers.get("t").unwrap().as_bytes(), b"v");
    }

    #[test]
    fn chunk_ext_grammar() {
        assert!(valid_chunk_ext(b""));
        assert!(valid_chunk_ext(b";a"));
        assert!(valid_chunk_ext(b" ; a = b ;c=\"x y\""));
        assert!(!valid_chunk_ext(b" "));
        assert!(!valid_chunk_ext(b";a "));
        assert!(!valid_chunk_ext(b";"));
        assert!(!valid_chunk_ext(b";a="));
        assert!(!valid_chunk_ext(b";a=\"x"));
        assert!(!valid_chunk_ext(b";a=\"\x01\""));
        assert!(!valid_chunk_ext(b"x"));
    }

    /// TH-26, review findings chunk-size-overflow-saturates and
    /// phase-deadline-bypass-streaming: sizes are exact or rejected.
    #[test]
    fn review_chunk_size_digits() {
        assert_eq!(parse_chunk_line(b"0"), Ok((0, 0)));
        assert_eq!(parse_chunk_line(b"aB;x"), Ok((0xab, 2)));
        assert_eq!(parse_chunk_line(b"ffffffffffffffff"), Ok((u64::MAX, 0)));
        assert_eq!(parse_chunk_line(b"0000000000000001"), Ok((1, 0)));
        assert_eq!(
            parse_chunk_line(b"00000000000000001"),
            Err(K::InvalidChunkSize)
        );
        assert_eq!(
            parse_chunk_line(b"10000000000000000"),
            Err(K::ChunkTooLarge)
        );
        assert_eq!(
            parse_chunk_line(b"010000000000000000;x"),
            Err(K::ChunkTooLarge)
        );
    }

    #[test]
    fn line_scanner_limits() {
        let mut rd = Reader::default();
        rd.buf.push(b"abc");
        assert!(matches!(rd.line(5), Ok(None)));
        rd.buf.push(b"\r");
        assert!(matches!(rd.line(5), Ok(None)));
        rd.buf.push(b"\n");
        assert!(matches!(rd.line(5), Ok(Some((3, 5)))));
        let mut rd = Reader::default();
        rd.buf.push(b"abcd\r");
        assert!(matches!(rd.line(5), Err(LineError::TooLong)));
        let mut rd = Reader::default();
        rd.buf.push(b"ab\n");
        assert!(matches!(rd.line(5), Err(LineError::BareLf)));
    }

    #[test]
    fn status_lines() {
        assert!(parse_status_line(b"HTTP/1.1 200 OK").is_ok());
        assert!(parse_status_line(b"HTTP/1.1 200 ").is_ok());
        assert!(parse_status_line(b"HTTP/1.1 200").is_ok());
        assert_eq!(
            parse_status_line(b"HTTP/1.1 20").unwrap_err(),
            K::InvalidStatusLine
        );
        assert_eq!(
            parse_status_line(b"HTTP/1.1 099 x").unwrap_err(),
            K::InvalidStatusCode
        );
        assert_eq!(
            parse_status_line(b"HTTP/1.1 600 x").unwrap_err(),
            K::InvalidStatusCode
        );
        assert_eq!(
            parse_status_line(b"HTTP/1.1 2x0 x").unwrap_err(),
            K::InvalidStatusCode
        );
        assert_eq!(
            parse_status_line(b"HTTP/1.1 200x").unwrap_err(),
            K::InvalidStatusLine
        );
        assert_eq!(
            parse_status_line(b"HTTP/2.0 200 OK").unwrap_err(),
            K::UnsupportedVersion
        );
        assert_eq!(
            parse_status_line(b"HTTP/1.1 200 \x00").unwrap_err(),
            K::InvalidStatusLine
        );
    }
}
