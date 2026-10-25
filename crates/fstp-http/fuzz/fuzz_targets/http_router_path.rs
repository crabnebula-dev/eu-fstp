//! TH-26, H-05: the router's path decoder and dispatch against arbitrary
//! request paths.
//!
//! The input, after a leading `/`, is the path and query of an origin-form
//! target. Inputs that are not valid targets are skipped. Properties
//! checked beyond "no panic":
//!
//! - Agreement with an independent reference decoder. A path that the
//!   reference rejects gets 400 and reaches no handler, the fallback
//!   included.
//! - Agreement with a reference matcher. Every other path reaches exactly
//!   the expected handler, with exactly the expected parameters.
//! - Every captured value is one safe path component. It is non-empty,
//!   never `.` or `..`, and holds no `/`, `\` or control character.
//! - Decoding happens once. A captured value holds no percent-encoded
//!   triple, so decoding it again either changes nothing or fails.
//! - Every captured value re-encodes to a segment that decodes back to it.

#![no_main]

use std::future::Future;
use std::pin::pin;
use std::sync::LazyLock;
use std::task::{Context, Poll, Waker};

use fstp_http::{
    Handler, Method, Request, RequestTarget, Response, Router, StatusCode, handler_fn,
};
use libfuzzer_sys::fuzz_target;

/// A handler that answers 200 with its label and the captured values,
/// each value prefixed with its length.
fn recorder(label: &'static str) -> impl Handler {
    handler_fn(move |req: Request| async move {
        let mut body = label.as_bytes().to_vec();
        body.push(0);
        for (_, v) in req.params() {
            body.extend_from_slice(&(v.len() as u32).to_le_bytes());
            body.extend_from_slice(v.as_bytes());
        }
        let mut resp = Response::new(StatusCode::OK);
        resp.body = body;
        resp
    })
}

static ROUTER: LazyLock<Router> = LazyLock::new(|| {
    Router::new()
        .get("/", recorder("root"))
        .and_then(|r| r.get("/files/latest", recorder("latest")))
        .and_then(|r| r.get("/files/{name}", recorder("file")))
        .and_then(|r| r.get("/files/{name}/raw", recorder("raw")))
        .and_then(|r| r.get("/a/{x}/{y}", recorder("xy")))
        .expect("valid routes")
        .fallback(recorder("fallback"))
});

/// Splits a response body made by [`recorder`].
fn parse_body(body: &[u8]) -> (String, Vec<String>) {
    let nul = body.iter().position(|&b| b == 0).expect("label end");
    let label = String::from_utf8(body[..nul].to_vec()).expect("label");
    let mut rest = &body[nul + 1..];
    let mut values = Vec::new();
    while !rest.is_empty() {
        let len = u32::from_le_bytes(rest[..4].try_into().expect("length")) as usize;
        values.push(String::from_utf8(rest[4..4 + len].to_vec()).expect("UTF-8 value"));
        rest = &rest[4 + len..];
    }
    (label, values)
}

/// Polls a future that never waits. The router and these handlers finish
/// on the first poll.
fn run<F: Future>(f: F) -> F::Output {
    let mut f = pin!(f);
    let mut cx = Context::from_waker(Waker::noop());
    match f.as_mut().poll(&mut cx) {
        Poll::Ready(v) => v,
        Poll::Pending => panic!("the router future did not finish"),
    }
}

/// Percent-decodes one segment, or `None` for a malformed triple.
fn ref_pct_decode(raw: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'%' {
            let pair = raw.get(i + 1..i + 3)?;
            if !pair.iter().all(u8::is_ascii_hexdigit) {
                return None;
            }
            let text = std::str::from_utf8(pair).ok()?;
            out.push(u8::from_str_radix(text, 16).ok()?);
            i += 3;
        } else {
            out.push(raw[i]);
            i += 1;
        }
    }
    Some(out)
}

fn has_triple(s: &str) -> bool {
    s.as_bytes()
        .windows(3)
        .any(|w| w[0] == b'%' && w[1].is_ascii_hexdigit() && w[2].is_ascii_hexdigit())
}

/// The reference decoder: the segments of `path`, or `None` for 400.
fn ref_decode(path: &str) -> Option<Vec<String>> {
    let rest = path.strip_prefix('/')?;
    let mut out = Vec::new();
    for raw in rest.split('/') {
        let s = String::from_utf8(ref_pct_decode(raw.as_bytes())?).ok()?;
        let unsafe_char = s.chars().any(|c| c == '/' || c == '\\' || c.is_control());
        if s == "." || s == ".." || unsafe_char || has_triple(&s) {
            return None;
        }
        out.push(s);
    }
    Some(out)
}

/// The reference matcher: the handler label and captured values.
fn ref_route(segs: &[String]) -> (&'static str, Vec<String>) {
    let s: Vec<&str> = segs.iter().map(String::as_str).collect();
    match s.as_slice() {
        [""] => ("root", vec![]),
        ["files", "latest"] => ("latest", vec![]),
        ["files", name] if !name.is_empty() => ("file", vec![(*name).to_owned()]),
        ["files", name, "raw"] if !name.is_empty() => ("raw", vec![(*name).to_owned()]),
        ["a", x, y] if !x.is_empty() && !y.is_empty() => {
            ("xy", vec![(*x).to_owned(), (*y).to_owned()])
        }
        _ => ("fallback", vec![]),
    }
}

/// Encodes every byte outside the RFC 3986 `unreserved` set.
fn encode(value: &str) -> String {
    let mut out = String::new();
    for &b in value.as_bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let target_text = format!("/{text}");
    let Ok(target) = RequestTarget::origin(&target_text) else {
        return;
    };
    let path = target.path().to_owned();
    let resp = run(ROUTER.handle(Request::new(Method::GET, target)));

    let Some(segs) = ref_decode(&path) else {
        assert_eq!(resp.status, StatusCode::BAD_REQUEST, "accepted {path:?}");
        assert!(resp.body.is_empty(), "a handler saw {path:?}");
        return;
    };
    assert_eq!(resp.status, StatusCode::OK, "rejected {path:?}");
    let (label, values) = parse_body(&resp.body);
    let (want_label, want_values) = ref_route(&segs);
    assert_eq!(label, want_label, "wrong handler for {path:?}");
    assert_eq!(values, want_values, "wrong values for {path:?}");

    for v in &values {
        assert!(!v.is_empty() && v != "." && v != "..", "{v:?}");
        assert!(
            !v.chars().any(|c| c == '/' || c == '\\' || c.is_control()),
            "{v:?}"
        );
        assert!(!has_triple(v), "{v:?} could be decoded again");
        if let Some(again) = ref_pct_decode(v.as_bytes()) {
            assert_eq!(again, v.as_bytes(), "a second decode changed {v:?}");
        }
        let encoded = encode(v);
        assert!(!encoded.contains('/'));
        assert_eq!(
            ref_pct_decode(encoded.as_bytes()).as_deref(),
            Some(v.as_bytes()),
            "re-encoding {v:?} does not round trip"
        );
    }
});
