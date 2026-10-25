//! TH-26, H-05: the incremental response decoder against arbitrary input,
//! as a client sees a hostile server.
//!
//! Properties checked beyond "no panic":
//!
//! - Differential over splits, as for requests.
//! - Framing: responses to HEAD and with status 1xx, 204 or 304 have no
//!   body; a Content-Length body has exactly that length; a body never
//!   exceeds the limit; 101 is never accepted.
//! - Parse, serialize, parse gives the same status, fields and body.

#![no_main]

#[path = "../common/mod.rs"]
mod common;

use common::{control, decode_responses, head_lines, relaxed, without};
use fstp_http::{BodyKind, Method, Response, encode_response};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some(c) = control(data) else {
        return;
    };
    let method = if c.head { Method::HEAD } else { Method::GET };
    let whole = decode_responses(c.input, &[], &method, c.limits, c.eof);
    let split = decode_responses(c.input, &c.splits, &method, c.limits, c.eof);
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
        assert_ne!(head.status.as_u16(), 101, "accepted a protocol switch");
        if c.head || head.status.forbids_body() {
            assert!(body.is_empty(), "body on a response that has none");
            assert_eq!(head.body, BodyKind::Length(0));
        }
        if let BodyKind::Length(n) = head.body {
            assert_eq!(n, body.len() as u64);
        }
        if head.body == BodyKind::UntilClose {
            assert!(
                !head.keep_alive,
                "close-delimited body on a persistent connection"
            );
        }
        assert!(body.len() as u64 <= c.limits.max_body_bytes);

        let mut resp = Response::from_parts(head.clone(), body.clone(), trailers.clone());
        resp.headers = without(&resp.headers, &["content-length", "transfer-encoding"]);
        let mut wire = Vec::new();
        encode_response(&resp, c.head, &mut wire).expect("an accepted response re-encodes");
        head_lines(&wire);
        let again = decode_responses(&wire, &[], &method, relaxed(), false);
        assert_eq!(again.error, None, "re-encoded response fails to parse");
        assert_eq!(again.messages.len(), 1);
        let (h2, b2, _) = &again.messages[0];
        assert_eq!(h2.status, head.status);
        assert_eq!(b2, body);
        assert_eq!(
            without(&h2.headers, &["content-length", "transfer-encoding"]),
            resp.headers
        );
    }
});
