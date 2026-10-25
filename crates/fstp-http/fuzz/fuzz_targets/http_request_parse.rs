//! TH-26, H-05: the incremental request decoder against arbitrary input.
//!
//! Properties checked beyond "no panic":
//!
//! - Differential over splits: the input fed at once and fed in pieces at
//!   fuzz-chosen points gives the same messages, the same head in progress,
//!   the same error and the same leftover byte count.
//! - Event order: Head, then Data, then End, with no empty Data events, and
//!   errors are sticky.
//! - Every accepted request is consistent with the framing rules: an
//!   HTTP/1.1 request has exactly one Host, Content-Length and
//!   Transfer-Encoding never appear together, and a Content-Length body has
//!   exactly that length.
//! - Parse, serialize, parse gives the same request.

#![no_main]

#[path = "../common/mod.rs"]
mod common;

use common::{control, decode_requests, head_lines, relaxed, without};
use fstp_http::{BodyKind, Framing, Request, Version, encode_request};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some(c) = control(data) else {
        return;
    };
    let whole = decode_requests(c.input, &[], c.limits, c.eof);
    let split = decode_requests(c.input, &c.splits, c.limits, c.eof);
    assert_eq!(
        whole.messages, split.messages,
        "messages depend on the split"
    );
    assert_eq!(
        whole.pending_head, split.pending_head,
        "head depends on the split"
    );
    assert_eq!(whole.error, split.error, "error depends on the split");
    if whole.error.is_none() {
        assert_eq!(
            whole.buffered, split.buffered,
            "leftover depends on the split"
        );
    }

    for (head, body, trailers) in &whole.messages {
        if head.version == Version::Http11 {
            assert_eq!(
                head.headers.count("host"),
                1,
                "HTTP/1.1 request without one Host"
            );
        }
        assert!(
            !(head.headers.contains("content-length")
                && head.headers.contains("transfer-encoding")),
            "accepted both Content-Length and Transfer-Encoding"
        );
        assert!(head.headers.count("content-length") <= 1);
        match head.body {
            BodyKind::Length(n) => {
                assert_eq!(n, body.len() as u64);
                assert!(trailers.is_empty());
            }
            BodyKind::Chunked => assert!(head.headers.contains("transfer-encoding")),
            BodyKind::UntilClose => panic!("request body delimited by close"),
        }
        assert!(body.len() as u64 <= c.limits.max_body_bytes);

        let mut req = Request::from_parts(head.clone(), body.clone(), trailers.clone());
        req.headers = without(&req.headers, &["content-length", "transfer-encoding"]);
        let framing = if trailers.is_empty() {
            Framing::ContentLength
        } else {
            Framing::Chunked(5)
        };
        let mut wire = Vec::new();
        encode_request(&req, framing, &mut wire).expect("an accepted request re-encodes");
        head_lines(&wire);
        let again = decode_requests(&wire, &[], relaxed(), false);
        assert_eq!(again.error, None, "re-encoded request fails to parse");
        assert_eq!(again.messages.len(), 1);
        let (h2, b2, t2) = &again.messages[0];
        assert_eq!(h2.method, head.method);
        assert_eq!(h2.target, head.target);
        assert_eq!(h2.version, head.version);
        assert_eq!(h2.expect_continue, head.expect_continue);
        assert_eq!(h2.keep_alive, head.keep_alive);
        assert_eq!(b2, body);
        assert_eq!(t2, trailers);
        let mut got = without(&h2.headers, &["content-length", "transfer-encoding"]);
        if !req.headers.contains("host") && req.target.authority().is_some() {
            got = without(&got, &["host"]);
        }
        assert_eq!(got, req.headers);
    }
});
