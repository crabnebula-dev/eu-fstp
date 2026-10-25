//! Helpers shared by the integration tests: decoders driven over arbitrary
//! input splits, with outcomes that can be compared across splits.

#![allow(dead_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_http::{
    ChunkedDecoder, ChunkedEvent, Headers, Limits, Method, ParseErrorKind, RequestDecoder,
    RequestEvent, RequestHead, ResponseDecoder, ResponseEvent, ResponseHead,
};

/// Everything a request decoder produced for one input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReqOutcome {
    /// Completed requests: head, body, trailers.
    pub(crate) messages: Vec<(RequestHead, Vec<u8>, Headers)>,
    /// Head of the message in progress when decoding stopped.
    pub(crate) pending_head: Option<RequestHead>,
    /// The error, if decoding failed.
    pub(crate) error: Option<ParseErrorKind>,
    /// Bytes left in the buffer at the end (only without an error).
    pub(crate) buffered: usize,
}

/// Splits `input` at the given offsets (sorted and clamped here).
pub(crate) fn pieces<'a>(input: &'a [u8], splits: &[usize]) -> Vec<&'a [u8]> {
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

/// Every offset, for byte-at-a-time feeding.
pub(crate) fn every_byte(input: &[u8]) -> Vec<usize> {
    (1..input.len()).collect()
}

pub(crate) fn decode_requests(
    input: &[u8],
    splits: &[usize],
    limits: Limits,
    eof: bool,
) -> ReqOutcome {
    let mut d = RequestDecoder::new(limits);
    let mut out = ReqOutcome {
        messages: Vec::new(),
        pending_head: None,
        error: None,
        buffered: 0,
    };
    let mut body = Vec::new();
    let drain = |d: &mut RequestDecoder, out: &mut ReqOutcome, body: &mut Vec<u8>| -> bool {
        loop {
            match d.next_event() {
                Ok(Some(RequestEvent::Head(h))) => {
                    out.pending_head = Some(*h);
                    body.clear();
                }
                Ok(Some(RequestEvent::Data(data))) => body.extend_from_slice(&data),
                Ok(Some(RequestEvent::End(t))) => {
                    let h = out.pending_head.take().expect("End without Head");
                    out.messages.push((h, std::mem::take(body), t));
                }
                Ok(None) => return true,
                Err(e) => {
                    out.error = Some(e.kind());
                    return false;
                }
            }
        }
    };
    for piece in pieces(input, splits) {
        d.feed(piece);
        if !drain(&mut d, &mut out, &mut body) {
            return out;
        }
    }
    if eof {
        d.feed_eof();
        if !drain(&mut d, &mut out, &mut body) {
            return out;
        }
    }
    out.buffered = d.buffered();
    out
}

/// Everything a response decoder produced for one input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RespOutcome {
    pub(crate) messages: Vec<(ResponseHead, Vec<u8>, Headers)>,
    pub(crate) pending_head: Option<ResponseHead>,
    pub(crate) error: Option<ParseErrorKind>,
    pub(crate) buffered: usize,
}

pub(crate) fn decode_responses(
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
        buffered: 0,
    };
    let mut body = Vec::new();
    let drain = |d: &mut ResponseDecoder, out: &mut RespOutcome, body: &mut Vec<u8>| -> bool {
        loop {
            match d.next_event() {
                Ok(Some(ResponseEvent::Head(h))) => {
                    out.pending_head = Some(*h);
                    body.clear();
                }
                Ok(Some(ResponseEvent::Data(data))) => body.extend_from_slice(&data),
                Ok(Some(ResponseEvent::End(t))) => {
                    let h = out.pending_head.take().expect("End without Head");
                    out.messages.push((h, std::mem::take(body), t));
                }
                Ok(None) => return true,
                Err(e) => {
                    out.error = Some(e.kind());
                    return false;
                }
            }
        }
    };
    for piece in pieces(input, splits) {
        d.feed(piece);
        if !drain(&mut d, &mut out, &mut body) {
            return out;
        }
    }
    if eof {
        d.feed_eof();
        if !drain(&mut d, &mut out, &mut body) {
            return out;
        }
    }
    out.buffered = d.buffered();
    out
}

/// Outcome of a standalone chunked decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChunkOutcome {
    pub(crate) body: Vec<u8>,
    pub(crate) trailers: Option<Headers>,
    pub(crate) error: Option<ParseErrorKind>,
    pub(crate) remaining: Vec<u8>,
}

pub(crate) fn decode_chunked(
    input: &[u8],
    splits: &[usize],
    limits: Limits,
    eof: bool,
) -> ChunkOutcome {
    let mut d = ChunkedDecoder::new(limits);
    let mut out = ChunkOutcome {
        body: Vec::new(),
        trailers: None,
        error: None,
        remaining: Vec::new(),
    };
    let drain = |d: &mut ChunkedDecoder, out: &mut ChunkOutcome| -> bool {
        loop {
            match d.next_event() {
                Ok(Some(ChunkedEvent::Data(data))) => out.body.extend_from_slice(&data),
                Ok(Some(ChunkedEvent::End(t))) => out.trailers = Some(t),
                Ok(None) => return true,
                Err(e) => {
                    out.error = Some(e.kind());
                    return false;
                }
            }
        }
    };
    for piece in pieces(input, splits) {
        d.feed(piece);
        if !drain(&mut d, &mut out) {
            out.body.clear();
            return out;
        }
    }
    if eof {
        d.feed_eof();
        if !drain(&mut d, &mut out) {
            out.body.clear();
            return out;
        }
    }
    out.remaining = d.remaining().to_vec();
    out
}

/// Compares the parts of two request outcomes that must not depend on the
/// input split: completed messages, the head in progress, and the error.
pub(crate) fn same_request_outcome(a: &ReqOutcome, b: &ReqOutcome) -> bool {
    a.messages == b.messages
        && a.pending_head == b.pending_head
        && a.error == b.error
        && (a.error.is_some() || a.buffered == b.buffered)
}

pub(crate) fn same_response_outcome(a: &RespOutcome, b: &RespOutcome) -> bool {
    a.messages == b.messages
        && a.pending_head == b.pending_head
        && a.error == b.error
        && (a.error.is_some() || a.buffered == b.buffered)
}

/// Minimal base64 decoder, so expected DER values do not depend on the PEM
/// parser under test.
pub(crate) fn first_der(pem: &[u8]) -> Vec<u8> {
    let text = std::str::from_utf8(pem).unwrap();
    let body: String = text
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN CERTIFICATE-----"))
        .skip(1)
        .take_while(|l| !l.starts_with("-----END"))
        .collect();
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0;
    for c in body.bytes().filter(|c| *c != b'=') {
        let v = ALPHABET.iter().position(|a| *a == c).unwrap() as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out
}
