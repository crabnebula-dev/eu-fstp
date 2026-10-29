//! Body limits and the typed refusals of the surfaces that wait for
//! ADR-013 (M4 design sections 1.1, 3.8 and 15.0, TH-26).
//!
//! The design lists body limits among the adapter's duties. ADR-013, the
//! MCP and OAuth profile, is a draft, so `/mcp`, `/mcp/public`, `/oauth`
//! and the OAuth `/.well-known` documents answer a typed refusal until
//! Daniel accepts it. `web_common` states the readings these tests share.
//! Lane W4e's test author wrote them before the adapter exists, so each
//! is red because the W0 stub of `fstp_web::handle_op_request` refuses.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod web_common;

use web_common::{BODY_LIMIT, adr013_refused, all, baseline, good_fields, request, serve};

/// The response to `POST /api/v1/programmes` with a body of `len` bytes
/// that passes CSRF.
fn post_of_len(len: usize) -> fstp_http::Response {
    let body = vec![b' '; len];
    serve(&request(
        "POST",
        "/api/v1/programmes",
        &good_fields(),
        &body,
    ))
    .unwrap_or_else(|e| panic!("POST of {len} bytes: {e}"))
}

/// TH-26, design section 1.1: an `/api/v1` body over the limit gets 413
/// before any decoding.
#[test]
fn web_body_over_the_limit_is_refused_413() {
    let lens = [BODY_LIMIT + 1, BODY_LIMIT + 4096];
    all(&lens, |n| {
        let s = post_of_len(*n).status.as_u16();
        if s == 413 {
            Ok(())
        } else {
            Err(format!("status {s}"))
        }
    });
}

/// TH-26, design section 1.1: a body at or under the limit is not refused
/// for its size.
#[test]
fn web_body_within_the_limit_is_not_refused_for_size() {
    let lens = [0, 2, BODY_LIMIT];
    all(&lens, |n| {
        let s = post_of_len(*n).status.as_u16();
        if s == 413 {
            Err("413 within the limit".to_owned())
        } else {
            Ok(())
        }
    });
}

/// Design section 15.0: every method on the MCP surfaces answers the typed
/// ADR-013 refusal with the baseline headers.
#[test]
fn adr013_mcp_surfaces_answer_a_typed_refusal() {
    let cases: Vec<(&str, &str)> = ["/mcp", "/mcp/public"]
        .iter()
        .flat_map(|p| ["GET", "POST", "DELETE"].into_iter().map(move |m| (m, *p)))
        .collect();
    all(&cases, |(m, p)| {
        let body: &[u8] = if *m == "POST" {
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}"
        } else {
            b""
        };
        let fields = [("Content-Type", "application/json")];
        let r = serve(&request(m, p, &fields, body)).unwrap_or_else(|e| panic!("{e}"));
        adr013_refused(&r)?;
        baseline(&r, p)
    });
}

/// Design section 15.0: the OAuth endpoints and metadata documents answer
/// the typed ADR-013 refusal with the baseline headers.
#[test]
fn adr013_oauth_surfaces_answer_a_typed_refusal() {
    let cases = [
        ("GET", "/oauth/authorize"),
        ("POST", "/oauth/token"),
        ("POST", "/oauth/register"),
        ("POST", "/oauth/revoke"),
        ("GET", "/.well-known/oauth-protected-resource"),
        ("GET", "/.well-known/oauth-authorization-server"),
    ];
    all(&cases, |(m, p)| {
        let fields = [("Content-Type", "application/x-www-form-urlencoded")];
        let r = serve(&request(m, p, &fields, b"")).unwrap_or_else(|e| panic!("{e}"));
        adr013_refused(&r)?;
        baseline(&r, p)
    });
}
