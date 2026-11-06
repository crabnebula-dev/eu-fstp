//! The MCP and OAuth metadata routes of `fstp-web` (lane W3c scope items
//! 4 and 5, M4 design section 3.8, ADR-013 "Metadata", RFC 8414, RFC
//! 9728).
//!
//! The production router of `fstp_web::router`, over the `ApiCore` of a
//! fake cell for the tenant origin `https://tenant.fstp.test`, as the
//! matrix harness mounts it:
//!
//! - `GET /.well-known/oauth-protected-resource` names this cell's MCP
//!   URL as the resource and the tenant origin as its authorisation
//!   server;
//! - `GET /.well-known/oauth-authorization-server` names the issuer and
//!   `S256` as the only PKCE method;
//! - `/mcp` is mounted: a POST without a token gets the 401 Bearer
//!   challenge naming the resource metadata, and `GET` gets 405;
//! - `/mcp/public` is mounted: `GET` gets 405, and a POST is served with
//!   no credential and no CSRF field.
//!
//! The surfaces were 501 `{"code":"not_available","rule":"ADR-013"}`
//! until this lane, so each test is red until `fstp-web` serves them.
//! Every response keeps the security headers of every surface.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod mcp_support;

use std::sync::Arc;

use fstp_http::{Method, Request, RequestTarget, Response};
use fstp_json::Value;
use fstp_rt::future::block_on;
use mcp_support::{McpCell, ORIGIN, RESOURCE_METADATA, initialize};

/// The production router over a fake cell's core.
fn router(c: &McpCell) -> fstp_web::WebRouter {
    let origin = fstp_web::parse_origin_header(ORIGIN.as_bytes()).unwrap();
    let assets = fstp_web::AssetSet::from_files(
        "main.js",
        &[("main.js", b"// mcp route tests\nexport {};\n".as_slice())],
    )
    .unwrap();
    fstp_web::router(
        Arc::clone(&c.core),
        fstp_web::WebConfig::new(origin, assets),
    )
    .unwrap()
}

/// `method` on `path` with `headers` and `body`.
fn send(
    r: &fstp_web::WebRouter,
    method: Method,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Response {
    let mut req = Request::new(method, RequestTarget::origin(path).unwrap())
        .try_with_header("host", "tenant.fstp.test")
        .unwrap();
    for (k, v) in headers {
        req = req.try_with_header(k, v.as_bytes().to_vec()).unwrap();
    }
    req.body = body.to_vec();
    block_on(r.serve(req))
}

/// The JSON body of `resp`.
fn json(resp: &Response) -> Value {
    fstp_json::parse(&resp.body)
        .unwrap_or_else(|e| panic!("{e:?}: {}", String::from_utf8_lossy(&resp.body)))
}

/// The strings of array member `k` of `v`.
fn strings(v: &Value, k: &str) -> Vec<String> {
    v.as_object()
        .and_then(|o| o.get(k))
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// ADR-013 "Metadata", RFC 9728: the protected resource metadata names
/// this cell's MCP URL and the tenant origin as its one authorisation
/// server, with one CSP like every response.
#[test]
fn adr013_web_serves_protected_resource_metadata() {
    let c = McpCell::new();
    let r = router(&c);
    let resp = send(
        &r,
        Method::GET,
        "/.well-known/oauth-protected-resource",
        &[],
        b"",
    );
    assert_eq!(
        resp.status.as_u16(),
        200,
        "{}",
        String::from_utf8_lossy(&resp.body)
    );
    let v = json(&resp);
    assert_eq!(
        v.as_object()
            .and_then(|o| o.get("resource"))
            .and_then(Value::as_str),
        Some("https://tenant.fstp.test/mcp")
    );
    assert_eq!(strings(&v, "authorization_servers"), [ORIGIN]);
    assert_eq!(resp.headers.count("content-security-policy"), 1);
    assert_eq!(
        format!("{ORIGIN}/.well-known/oauth-protected-resource"),
        RESOURCE_METADATA
    );
}

/// ADR-013 "Metadata", RFC 8414: the authorisation server metadata names
/// the tenant origin as issuer and `S256` as the only PKCE method.
#[test]
fn adr013_web_serves_authorization_server_metadata() {
    let c = McpCell::new();
    let r = router(&c);
    let resp = send(
        &r,
        Method::GET,
        "/.well-known/oauth-authorization-server",
        &[],
        b"",
    );
    assert_eq!(
        resp.status.as_u16(),
        200,
        "{}",
        String::from_utf8_lossy(&resp.body)
    );
    let v = json(&resp);
    assert_eq!(
        v.as_object()
            .and_then(|o| o.get("issuer"))
            .and_then(Value::as_str),
        Some(ORIGIN)
    );
    assert_eq!(strings(&v, "code_challenge_methods_supported"), ["S256"]);
}

/// I-86, RFC 9728 section 5.1: `fstp-web` mounts `/mcp`. A POST without a
/// token gets 401 with a Bearer challenge naming the resource metadata,
/// and `GET` gets 405. Neither sets a cookie.
#[test]
fn adr013_web_mounts_mcp_with_the_bearer_challenge() {
    let c = McpCell::new();
    let r = router(&c);
    let resp = send(
        &r,
        Method::POST,
        "/mcp",
        &[("content-type", "application/json")],
        &initialize(1),
    );
    assert_eq!(
        resp.status.as_u16(),
        401,
        "{}",
        String::from_utf8_lossy(&resp.body)
    );
    let v = resp
        .headers
        .get("www-authenticate")
        .and_then(|h| h.to_str())
        .unwrap_or("");
    assert!(
        v.starts_with("Bearer ")
            && v.contains(&format!("resource_metadata=\"{RESOURCE_METADATA}\"")),
        "{v}"
    );
    let get = send(
        &r,
        Method::GET,
        "/mcp",
        &[("accept", "text/event-stream")],
        b"",
    );
    assert_eq!(get.status.as_u16(), 405);
    assert!(resp.headers.get("set-cookie").is_none() && get.headers.get("set-cookie").is_none());
}

/// I-87, design section 3.8: `fstp-web` mounts `/mcp/public`. A POST with
/// no credential and no CSRF field is served, and `GET` gets 405.
#[test]
fn adr013_web_mounts_mcp_public() {
    let c = McpCell::new();
    let r = router(&c);
    let resp = send(
        &r,
        Method::POST,
        "/mcp/public",
        &[
            ("content-type", "application/json"),
            ("accept", "application/json, text/event-stream"),
        ],
        &initialize(1),
    );
    assert_eq!(
        resp.status.as_u16(),
        200,
        "{}",
        String::from_utf8_lossy(&resp.body)
    );
    let get = send(&r, Method::GET, "/mcp/public", &[], b"");
    assert_eq!(get.status.as_u16(), 405);
}
