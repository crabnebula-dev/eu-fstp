//! TH-26, H-05: the validating constructors and the encoders never let CR
//! or LF into a serialized message (no request or response splitting).
//!
//! The input is split at the first 0xFF byte into a candidate name and a
//! candidate value. The value also serves as a URL and a path. Properties:
//!
//! - An accepted header value holds no CR, LF or NUL and has no surrounding
//!   whitespace. A rejected one has a forbidden byte or surrounding
//!   whitespace.
//! - A response or request carrying the field serializes into a head whose
//!   lines all end in CRLF, with exactly one line per field, and parses back
//!   into the same field list.
//! - An accepted URL or origin-form path serializes into a single request
//!   line and parses back into the same target.

#![no_main]

#[path = "../common/mod.rs"]
mod common;

use common::{decode_requests, decode_responses, head_lines};
use fstp_http::{
    Framing, HeaderName, HeaderValue, Headers, Limits, Method, Request, RequestTarget, Response,
    StatusCode, encode_request, encode_response,
};
use libfuzzer_sys::fuzz_target;

fn ws(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

fn check_value(value: &[u8]) -> Option<HeaderValue> {
    match HeaderValue::new(value.to_vec()) {
        Ok(v) => {
            assert!(!v.as_bytes().iter().any(|b| matches!(b, b'\r' | b'\n' | 0)));
            assert!(!v.as_bytes().first().is_some_and(|&b| ws(b)));
            assert!(!v.as_bytes().last().is_some_and(|&b| ws(b)));
            Some(v)
        }
        Err(_) => {
            let forbidden = value.iter().any(|&b| (b < 0x20 && b != b'\t') || b == 0x7F);
            let edge =
                value.first().is_some_and(|&b| ws(b)) || value.last().is_some_and(|&b| ws(b));
            assert!(forbidden || edge, "a valid value was rejected");
            None
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let (name, value) = match data.iter().position(|&b| b == 0xFF) {
        Some(i) => (&data[..i], &data[i + 1..]),
        None => (&b"x-fuzz"[..], data),
    };
    let header_name = HeaderName::from_bytes(name).ok();
    if header_name.is_none() {
        // The tolerant helpers must reject the same input.
        let mut h = Headers::new();
        if let Ok(s) = std::str::from_utf8(name) {
            assert!(h.try_append(s, value.to_vec()).is_err());
        }
    }
    let header_value = check_value(value);

    if let (Some(n), Some(v)) = (header_name, header_value) {
        let framing = n.eq_name("content-length") || n.eq_name("transfer-encoding");
        let resp = Response::new(StatusCode::OK).with_header(n.clone(), v.clone());
        let mut wire = Vec::new();
        match encode_response(&resp, false, &mut wire) {
            Ok(()) => {
                assert!(!framing, "encoder accepted a caller-set framing field");
                // Status line, the field, Content-Length, empty line.
                assert_eq!(head_lines(&wire), 4);
                let o = decode_responses(&wire, &[], &Method::GET, Limits::default(), false);
                if o.error.is_none() {
                    let h = &o.messages[0].0.headers;
                    assert_eq!(h.len(), 2);
                    assert_eq!(h.get(n.as_str()), Some(&v));
                } else {
                    // Only semantic fields such as Connection may make the
                    // decoder reject an otherwise well-formed head.
                    assert!(n.eq_name("connection"), "{:?}", o.error);
                }
            }
            Err(_) => assert!(framing, "encoder rejected a valid field"),
        }

        let req = Request::new(Method::GET, RequestTarget::origin("/").unwrap())
            .with_header(
                HeaderName::new("host").unwrap(),
                HeaderValue::new("h").unwrap(),
            )
            .with_header(n.clone(), v.clone());
        let mut wire = Vec::new();
        if encode_request(&req, Framing::ContentLength, &mut wire).is_ok() {
            assert_eq!(head_lines(&wire), 4);
        }
    }

    // URLs and paths built from the same bytes.
    if let Ok(s) = std::str::from_utf8(value) {
        for target in [RequestTarget::absolute(s), RequestTarget::origin(s)]
            .into_iter()
            .flatten()
        {
            let mut req = Request::new(Method::GET, target.clone());
            if target.authority().is_none() {
                req.headers.try_append("host", "h").unwrap();
            }
            let mut wire = Vec::new();
            encode_request(&req, Framing::ContentLength, &mut wire).expect("valid target encodes");
            let first_line_end = wire.windows(2).position(|w| w == b"\r\n").unwrap();
            assert!(!wire[..first_line_end].contains(&b'\n'));
            assert!(!wire[..first_line_end].contains(&b'\r'));
            assert_eq!(head_lines(&wire), 3);
            let o = decode_requests(&wire, &[], Limits::default(), false);
            assert_eq!(o.error, None, "valid target fails to parse");
            assert_eq!(o.messages[0].0.target, target);
        }
    }
});
