//! Property tests for the HTTP/1.1 parser and encoder (TH-26, H-05).
//!
//! - Serialize then parse gives back the same request or response.
//! - Parse, serialize, parse gives the same message for any accepted input.
//! - The decoders give the same outcome for any split of the input.
//! - Header values never accept CR, LF or NUL, so an encoded header cannot
//!   start a new field line.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use common::{
    decode_chunked, decode_requests, decode_responses, every_byte, same_request_outcome,
    same_response_outcome,
};
use fstp_http::{
    Framing, HeaderName, HeaderValue, Headers, Limits, Method, Request, RequestTarget, Response,
    StatusCode, Version, encode_request, encode_response,
};
use fstp_prop::{Gen, check, prop_assert, prop_assert_eq};

const TCHARS: &[u8] =
    b"!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const PCHARS: &[u8] = b"abcXYZ019-._~!$&'()*+,;=:@";
const RESERVED: &[&str] = &[
    "host",
    "content-length",
    "transfer-encoding",
    "expect",
    "connection",
];

fn token(g: &mut Gen, max: usize) -> String {
    let n = g.usize_in(1..=max);
    (0..n).map(|_| char::from(*g.pick(TCHARS))).collect()
}

fn header_name(g: &mut Gen) -> HeaderName {
    loop {
        let n = token(g, 12);
        if !RESERVED.iter().any(|r| r.eq_ignore_ascii_case(&n)) {
            return HeaderName::new(&n).unwrap();
        }
    }
}

fn value_byte(g: &mut Gen) -> u8 {
    match g.weighted(&[6, 1, 1, 1]) {
        0 => g.u8_in(0x21..=0x7E),
        1 => b' ',
        2 => b'\t',
        _ => g.u8_in(0x80..=0xFF),
    }
}

fn header_value(g: &mut Gen) -> HeaderValue {
    let mut v = g.vec(0..=24, value_byte);
    while v.first().is_some_and(|b| *b == b' ' || *b == b'\t') {
        v.remove(0);
    }
    while v.last().is_some_and(|b| *b == b' ' || *b == b'\t') {
        v.pop();
    }
    HeaderValue::new(v).unwrap()
}

fn headers(g: &mut Gen, max: usize) -> Headers {
    let mut h = Headers::new();
    let n = g.usize_in(0..=max);
    for _ in 0..n {
        let name = header_name(g);
        let value = header_value(g);
        h.append(name, value);
    }
    h
}

fn pct_or_pchar(g: &mut Gen, extra: &[u8]) -> String {
    if g.weighted(&[8, 1]) == 1 {
        format!("%{:02X}", g.u8())
    } else if !extra.is_empty() && g.weighted(&[6, 1]) == 1 {
        char::from(*g.pick(extra)).to_string()
    } else {
        char::from(*g.pick(PCHARS)).to_string()
    }
}

fn path_and_query(g: &mut Gen) -> String {
    let mut s = String::new();
    let segs = g.usize_in(1..=4);
    for _ in 0..segs {
        s.push('/');
        let n = g.usize_in(0..=6);
        for _ in 0..n {
            s.push_str(&pct_or_pchar(g, b""));
        }
    }
    if g.bool() {
        s.push('?');
        let n = g.usize_in(0..=8);
        for _ in 0..n {
            s.push_str(&pct_or_pchar(g, b"/?"));
        }
    }
    s
}

fn authority(g: &mut Gen) -> String {
    let host = match g.weighted(&[4, 1, 1]) {
        0 => {
            let n = g.usize_in(1..=10);
            (0..n)
                .map(|_| char::from(*g.pick(b"abcxyz0189-._~")))
                .collect::<String>()
        }
        1 => format!("{}.{}.{}.{}", g.u8(), g.u8(), g.u8(), g.u8()),
        _ => "[::1]".to_owned(),
    };
    match g.weighted(&[2, 2, 1]) {
        0 => host,
        1 => format!("{host}:{}", g.u16()),
        _ => format!("{host}:"),
    }
}

fn method(g: &mut Gen) -> Method {
    let standard = [
        Method::GET,
        Method::HEAD,
        Method::POST,
        Method::PUT,
        Method::DELETE,
        Method::OPTIONS,
        Method::TRACE,
        Method::PATCH,
    ];
    if g.weighted(&[4, 1]) == 0 {
        g.pick(&standard).clone()
    } else {
        loop {
            let m = Method::from_bytes(token(g, 8).as_bytes()).unwrap();
            if m != Method::CONNECT {
                return m;
            }
        }
    }
}

fn target(g: &mut Gen, m: &Method) -> RequestTarget {
    match g.weighted(&[6, 2, 1]) {
        0 => RequestTarget::origin(&path_and_query(g)).unwrap(),
        1 => {
            let scheme = if g.bool() { "http" } else { "HTTPS" };
            let pq = if g.bool() {
                path_and_query(g)
            } else {
                String::new()
            };
            RequestTarget::absolute(&format!("{scheme}://{}{pq}", authority(g))).unwrap()
        }
        _ if *m == Method::OPTIONS => RequestTarget::asterisk(),
        _ => RequestTarget::origin("/").unwrap(),
    }
}

/// A random valid request and the framing to encode it with.
fn request(g: &mut Gen) -> (Request, Framing) {
    let m = method(g);
    let t = target(g, &m);
    let version = if g.weighted(&[4, 1]) == 0 {
        Version::Http11
    } else {
        Version::Http10
    };
    let absolute = t.authority().is_some();
    let mut req = Request::new(m, t);
    req.version = version;
    if version == Version::Http11 && (!absolute || g.bool()) {
        req.headers.try_append("Host", authority(g)).unwrap();
    }
    for (n, v) in &headers(g, 6) {
        req.headers.append(n.clone(), v.clone());
    }
    req.body = g.bytes(0..=48);
    let framing = if version == Version::Http11 && g.bool() {
        req.trailers = headers(g, 3);
        Framing::Chunked(g.usize_in(1..=16))
    } else {
        Framing::ContentLength
    };
    (req, framing)
}

fn without(headers: &Headers, names: &[&str]) -> Headers {
    let mut out = Headers::new();
    for (n, v) in headers {
        if !names.iter().any(|x| n.eq_name(x)) {
            out.append(n.clone(), v.clone());
        }
    }
    out
}

/// TH-26: encode a random request, parse it back over random splits, and
/// get the same method, target, version, fields, body and trailers.
#[test]
fn th26_request_serialize_then_parse_round_trips() {
    check("th26_request_serialize_then_parse_round_trips", |g| {
        let (req, framing) = request(g);
        let mut wire = Vec::new();
        encode_request(&req, framing, &mut wire).map_err(|e| e.to_string())?;
        g.note("wire", &String::from_utf8_lossy(&wire));
        let splits = g.vec(0..=4, |g| g.usize_in(0..=wire.len()));
        let o = decode_requests(&wire, &splits, Limits::default(), true);
        prop_assert_eq!(o.error, None);
        prop_assert_eq!(o.messages.len(), 1);
        let (head, body, trailers) = &o.messages[0];
        prop_assert_eq!(&head.method, &req.method);
        prop_assert_eq!(&head.target, &req.target);
        prop_assert_eq!(head.version, req.version);
        prop_assert_eq!(body, &req.body);
        prop_assert_eq!(trailers, &req.trailers);
        let mut got = without(&head.headers, &["content-length", "transfer-encoding"]);
        if !req.headers.contains("host") && req.target.authority().is_some() {
            let host = got.get("host").map(|v| v.as_bytes().to_vec());
            prop_assert_eq!(
                host,
                req.target
                    .authority()
                    .map(|a| a.as_str().as_bytes().to_vec())
            );
            got = without(&got, &["host"]);
        }
        prop_assert_eq!(got, req.headers);
        Ok(())
    });
}

/// TH-26: encode a random response, parse it back over random splits, and
/// get the same status, fields and body. HEAD responses carry no body.
#[test]
fn th26_response_serialize_then_parse_round_trips() {
    check("th26_response_serialize_then_parse_round_trips", |g| {
        let code = loop {
            let c = g.u16_in(100..=599);
            if c != 101 {
                break c;
            }
        };
        let mut resp = Response::new(StatusCode::from_u16(code).unwrap());
        resp.headers = headers(g, 6);
        if !resp.status.forbids_body() {
            resp.body = g.bytes(0..=64);
        }
        let head = g.bool();
        let mut wire = Vec::new();
        encode_response(&resp, head, &mut wire).map_err(|e| e.to_string())?;
        let m = if head { Method::HEAD } else { Method::GET };
        let splits = g.vec(0..=4, |g| g.usize_in(0..=wire.len()));
        let o = decode_responses(&wire, &splits, &m, Limits::default(), false);
        prop_assert_eq!(o.error, None);
        prop_assert_eq!(o.messages.len(), 1);
        prop_assert_eq!(o.buffered, 0);
        let (h, body, _) = &o.messages[0];
        prop_assert_eq!(h.status, resp.status);
        prop_assert_eq!(without(&h.headers, &["content-length"]), resp.headers);
        let expected: &[u8] = if head { b"" } else { &resp.body };
        prop_assert_eq!(body.as_slice(), expected);
        Ok(())
    });
}

const INSERTS: &[&[u8]] = &[
    b"\r",
    b"\n",
    b"\r\n",
    b" ",
    b"\t",
    b":",
    b";",
    b"0",
    b"f",
    b"\0",
    b"\x7f",
    b"\r\n\r\n",
    b"Transfer-Encoding: chunked\r\n",
    b"Content-Length: 3\r\n",
    b"Host: x\r\n",
    b"Expect: 100-continue\r\n",
    b"5\r\nhello\r\n0\r\n\r\n",
];

fn mutate(g: &mut Gen, mut input: Vec<u8>) -> Vec<u8> {
    let n = g.usize_in(0..=4);
    for _ in 0..n {
        let at = g.usize_in(0..=input.len());
        match g.weighted(&[3, 1, 1]) {
            0 => {
                let ins = *g.pick(INSERTS);
                input.splice(at..at, ins.iter().copied());
            }
            1 if at < input.len() => {
                input.remove(at);
            }
            _ if at < input.len() => input[at] = g.u8(),
            _ => {}
        }
    }
    input
}

fn small_limits(g: &mut Gen) -> Limits {
    if g.weighted(&[1, 1]) == 0 {
        return Limits::default();
    }
    Limits {
        max_start_line: g.usize_in(0..=64),
        max_leading_empty_lines: g.usize_in(0..=2),
        max_headers: g.usize_in(0..=8),
        max_header_bytes: g.usize_in(0..=160),
        max_body_bytes: g.u64_in(0..=64),
        max_chunk_size: g.u64_in(0..=32),
        max_chunk_line: g.usize_in(0..=16),
        max_chunk_ext_bytes: g.usize_in(0..=16),
        max_trailers: g.usize_in(0..=4),
        max_trailer_bytes: g.usize_in(0..=64),
    }
}

fn request_stream(g: &mut Gen) -> Vec<u8> {
    let mut input = Vec::new();
    let n = g.usize_in(1..=3);
    for _ in 0..n {
        let (req, framing) = request(g);
        encode_request(&req, framing, &mut input).unwrap();
    }
    mutate(g, input)
}

/// TH-26: the request decoder gives the same messages, head in progress
/// and error for any split of the input, including one byte at a time.
#[test]
fn th26_request_parse_is_independent_of_chunking() {
    check("th26_request_parse_is_independent_of_chunking", |g| {
        let input = request_stream(g);
        let limits = small_limits(g);
        let eof = g.bool();
        g.note("input", &String::from_utf8_lossy(&input));
        let whole = decode_requests(&input, &[], limits, eof);
        let splits = g.vec(1..=8, |g| g.usize_in(0..=input.len()));
        let split = decode_requests(&input, &splits, limits, eof);
        prop_assert!(same_request_outcome(&whole, &split), "{whole:?}\n{split:?}");
        let bytes = decode_requests(&input, &every_byte(&input), limits, eof);
        prop_assert!(same_request_outcome(&whole, &bytes), "{whole:?}\n{bytes:?}");
        Ok(())
    });
}

fn response_stream(g: &mut Gen) -> (Vec<u8>, Method) {
    let mut input = Vec::new();
    let head = g.weighted(&[5, 1]) == 1;
    let n = g.usize_in(1..=3);
    for _ in 0..n {
        let code = g.u16_in(100..=599);
        let mut resp = Response::new(StatusCode::from_u16(code).unwrap());
        resp.headers = headers(g, 4);
        if !resp.status.forbids_body() {
            resp.body = g.bytes(0..=32);
        }
        encode_response(&resp, head, &mut input).unwrap();
    }
    let m = if head { Method::HEAD } else { Method::GET };
    (mutate(g, input), m)
}

/// TH-26: the response decoder gives the same outcome for any split.
#[test]
fn th26_response_parse_is_independent_of_chunking() {
    check("th26_response_parse_is_independent_of_chunking", |g| {
        let (input, m) = response_stream(g);
        let limits = small_limits(g);
        let eof = g.bool();
        let whole = decode_responses(&input, &[], &m, limits, eof);
        let splits = g.vec(1..=8, |g| g.usize_in(0..=input.len()));
        let split = decode_responses(&input, &splits, &m, limits, eof);
        prop_assert!(
            same_response_outcome(&whole, &split),
            "{whole:?}\n{split:?}"
        );
        let bytes = decode_responses(&input, &every_byte(&input), &m, limits, eof);
        prop_assert!(
            same_response_outcome(&whole, &bytes),
            "{whole:?}\n{bytes:?}"
        );
        Ok(())
    });
}

/// TH-26: the chunked decoder gives the same body, trailers and error for
/// any split, and decodes what the encoder produced.
#[test]
fn th26_chunked_decode_is_independent_of_chunking() {
    check("th26_chunked_decode_is_independent_of_chunking", |g| {
        let body = g.bytes(0..=64);
        let mut req = Request::post("http://h/", body.clone()).unwrap();
        req.trailers = headers(g, 2);
        let mut wire = Vec::new();
        encode_request(&req, Framing::Chunked(g.usize_in(1..=9)), &mut wire).unwrap();
        let start = wire.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let chunked = wire[start..].to_vec();
        let clean = decode_chunked(&chunked, &[], Limits::default(), true);
        prop_assert_eq!(clean.error, None);
        prop_assert_eq!(&clean.body, &body);
        prop_assert_eq!(clean.trailers.as_ref(), Some(&req.trailers));
        let input = mutate(g, chunked);
        let limits = small_limits(g);
        let eof = g.bool();
        let whole = decode_chunked(&input, &[], limits, eof);
        let splits = g.vec(1..=8, |g| g.usize_in(0..=input.len()));
        prop_assert_eq!(decode_chunked(&input, &splits, limits, eof), whole.clone());
        prop_assert_eq!(
            decode_chunked(&input, &every_byte(&input), limits, eof),
            whole
        );
        Ok(())
    });
}

/// TH-26: for any input the request decoder accepts, encoding the parsed
/// request and parsing it again gives the same request.
#[test]
fn th26_parse_serialize_parse_is_stable() {
    check("th26_parse_serialize_parse_is_stable", |g| {
        let input = request_stream(g);
        let first = decode_requests(&input, &[], Limits::default(), false);
        for (head, body, trailers) in &first.messages {
            let mut req = Request::from_parts(head.clone(), body.clone(), trailers.clone());
            req.headers = without(&req.headers, &["content-length", "transfer-encoding"]);
            let framing = if trailers.is_empty() {
                Framing::ContentLength
            } else {
                Framing::Chunked(7)
            };
            let mut wire = Vec::new();
            encode_request(&req, framing, &mut wire).map_err(|e| format!("re-encode: {e}"))?;
            let again = decode_requests(&wire, &[], Limits::default(), false);
            prop_assert_eq!(again.error, None);
            prop_assert_eq!(again.messages.len(), 1);
            let (h2, b2, t2) = &again.messages[0];
            prop_assert_eq!(&h2.method, &head.method);
            prop_assert_eq!(&h2.target, &head.target);
            prop_assert_eq!(h2.version, head.version);
            prop_assert_eq!(b2, body);
            prop_assert_eq!(t2, trailers);
            let mut got = without(&h2.headers, &["content-length", "transfer-encoding"]);
            // The encoder derives Host from an absolute target when the
            // request has none, which an HTTP/1.0 request may lack.
            if !req.headers.contains("host") && req.target.authority().is_some() {
                got = without(&got, &["host"]);
            }
            prop_assert_eq!(got, req.headers);
        }
        Ok(())
    });
}

/// TH-26: a header value never holds CR, LF or NUL, and an encoded header
/// parses back as exactly one field with the same value.
#[test]
fn th26_header_values_never_inject_lines() {
    check("th26_header_values_never_inject_lines", |g| {
        let raw = g.vec(0..=16, |g| match g.weighted(&[4, 1, 1, 1, 1]) {
            0 => value_byte(g),
            1 => b'\r',
            2 => b'\n',
            3 => 0,
            _ => g.u8(),
        });
        match HeaderValue::new(raw.clone()) {
            Ok(v) => {
                prop_assert!(!v.as_bytes().iter().any(|b| matches!(b, b'\r' | b'\n' | 0)));
                let resp = Response::new(StatusCode::OK)
                    .with_header(HeaderName::new("x-test").unwrap(), v.clone());
                let mut wire = Vec::new();
                encode_response(&resp, false, &mut wire).map_err(|e| e.to_string())?;
                let o = decode_responses(&wire, &[], &Method::GET, Limits::default(), false);
                prop_assert_eq!(o.error, None);
                let h = &o.messages[0].0.headers;
                prop_assert_eq!(h.len(), 2);
                prop_assert_eq!(h.get("x-test"), Some(&v));
            }
            Err(_) => {
                let bad_byte = raw.iter().any(|&b| (b < 0x20 && b != b'\t') || b == 0x7f);
                let edge_ws = raw.first().is_some_and(|b| *b == b' ' || *b == b'\t')
                    || raw.last().is_some_and(|b| *b == b' ' || *b == b'\t');
                prop_assert!(bad_byte || edge_ws, "rejected a valid value {raw:?}");
            }
        }
        Ok(())
    });
}
