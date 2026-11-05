//! The web adapter (M4 design section 1.1).
//!
//! The crate holds the routes over `fstp_http::Router` for `/api/v1`,
//! `/app`, `/p`, `/mcp`, `/mcp/public`, `/oauth` and `/.well-known`, the
//! CSRF and Origin rules, the security headers and the body limits. It
//! calls only `fstp_api_core::ApiCore::dispatch`.
//!
//! It may depend directly on `fstp-api-core`, `fstp-mcp`, `fstp-oauth`,
//! `fstp-web-assets`, `fstp-http`, `fstp-json` and `fstp-rt` only (layering
//! rule A1). It never names a port, the principal or the execution
//! metadata (rule A2b).
//!
//! # Interim readings, pending Daniel
//!
//! ADR-014 and design sections 3.8 to 3.10 fix the rules but not every
//! status code, body or order of checks. Each reading below is interim,
//! pending Daniel (design section 15.0), and is pinned by the tests in
//! `tests/`.
//!
//! - CSRF: every method except `GET` and `HEAD` to a path under
//!   `/api/v1` needs exactly one `Origin` equal to the tenant origin and
//!   exactly one `X-FSTP-Request: 1`. The check runs before routing, with
//!   or without a credential. A refusal is 403 with
//!   `{"code":"refused","rule":"ADR-014"}`.
//! - A bearer token does not lift the CSRF rule in M4, and an
//!   `Authorization` field on `/api/v1` is refused with 400, since the
//!   desktop client seam is not built.
//! - The body limit is 1 MiB on every surface. A longer body gets 413.
//! - A non-empty `/api/v1` body needs one `Content-Type` of
//!   `application/json`, or it gets 415.
//! - `/mcp`, `/mcp/public`, `/oauth/**` and the two OAuth `/.well-known`
//!   documents wait for ADR-013. Each method gets 501 with
//!   `{"code":"not_available","rule":"ADR-013"}`.
//! - `/app/` and every `/app/` path outside `/app/assets/` serve the
//!   shell. Every response but a served asset carries
//!   `Cache-Control: no-store`.
//! - Every response carries `nosniff`, `no-referrer`, COOP and CORP
//!   `same-origin`, HSTS of one year and exactly one CSP for its surface.
//!   No response sets a cookie or an `Access-Control-*` field.
//!
//! # Seams
//!
//! - `/api/v1` waits for lanes W3a and W3b. The W0 stub of
//!   `fstp-api-core` has no route decoder, no `RequestHead` constructor
//!   and no `OpResult` variants, so every call answers 501
//!   `{"code":"not_implemented"}`. The seam is one private function.
//! - `/p` serves the public pages through the public route decoder of
//!   `fstp-api-core` and `ApiCore::dispatch`, with no credential. The
//!   stub dispatch of [`handle_op_request`] answers them 501.

mod api;
mod headers;
mod origin;
mod reply;
mod router;
mod shell;

use std::sync::OnceLock;

use fstp_http::{Handler, Parsed, Response, parse_request};

pub use api::{REQUEST_HEADER, SESSION_COOKIE};
pub use headers::{APP_CSP, HSTS, OTHER_CSP, PUBLIC_CSP};
pub use origin::{Origin, OriginScheme, parse_origin_header};
pub use router::{BODY_LIMIT, WebConfig, WebRouter, limits, router};

/// The asset types a mounting crate needs to build a [`WebConfig`].
/// `fstp-cell` loads the compiled frontend with [`load_dir`] and passes
/// the [`AssetSet`] to [`WebConfig::new`], so it needs no dependency line
/// on `fstp-web-assets` of its own.
pub use fstp_web_assets::{AssetError, AssetSet, load_dir};

/// Why an operation of this crate failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WebError {
    /// Reserved for an operation that waits for another lane. No
    /// operation of this crate returns it now.
    NotImplemented(&'static str),
    /// An `Origin` value that is not one serialised origin.
    BadOrigin,
    /// The input ends before the request does.
    IncompleteRequest,
    /// Bytes follow the one request.
    TrailingBytes,
    /// A route pattern was refused, for the fixed reason given.
    Route(&'static str),
    /// The asset set of the stub configuration was refused.
    Assets(AssetError),
}

impl std::fmt::Display for WebError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WebError::NotImplemented(op) => write!(f, "{op} is not implemented yet"),
            WebError::BadOrigin => f.write_str("the value is not one serialised origin"),
            WebError::IncompleteRequest => f.write_str("the input ends inside the request"),
            WebError::TrailingBytes => f.write_str("bytes follow the request"),
            WebError::Route(why) => write!(f, "invalid route: {why}"),
            WebError::Assets(e) => write!(f, "invalid stub assets: {e}"),
        }
    }
}

impl std::error::Error for WebError {}

/// The reply to one web request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebReply {
    response: Response,
}

impl WebReply {
    /// The response.
    #[must_use]
    pub fn response(&self) -> &Response {
        &self.response
    }

    /// The response, by value.
    #[must_use]
    pub fn into_response(self) -> Response {
        self.response
    }
}

/// The tenant origin of the stub configuration.
pub const STUB_TENANT_ORIGIN: &str = "https://tenant.fstp.test";

/// The one module of the stub asset set.
const STUB_MODULE: &[u8] = b"// fstp-web stub asset set\nexport {};\n";

/// The router of the stub configuration, built once.
fn stub_router() -> Result<&'static WebRouter, WebError> {
    static STUB: OnceLock<Result<WebRouter, WebError>> = OnceLock::new();
    STUB.get_or_init(|| {
        let origin = parse_origin_header(STUB_TENANT_ORIGIN.as_bytes())?;
        let assets = AssetSet::from_files("main.js", &[("main.js", STUB_MODULE)])
            .map_err(WebError::Assets)?;
        router::build(api::Backend::Refusing, WebConfig::new(origin, assets))
    })
    .as_ref()
    .map_err(Clone::clone)
}

/// Handles one raw request over a stub dispatch: route, headers and body.
/// Fuzzed (`web_op_request`).
///
/// It runs the production router over the stub dispatch, which refuses
/// every API call, and a one-module asset set, for the tenant origin
/// [`STUB_TENANT_ORIGIN`]. A request the HTTP parser refuses gets the
/// parser's status with the headers of every response, as the server
/// would send it.
///
/// # Errors
///
/// [`WebError::IncompleteRequest`] when the input ends inside the
/// request, and [`WebError::TrailingBytes`] when more follows it.
pub fn handle_op_request(bytes: &[u8]) -> Result<WebReply, WebError> {
    let router = stub_router()?;
    let response = match parse_request(bytes, &limits()) {
        Err(e) => {
            let mut r = reply::status_only(e.status());
            headers::finish(&mut r, "");
            r
        }
        Ok(Parsed::Incomplete) => return Err(WebError::IncompleteRequest),
        Ok(Parsed::Complete { message, consumed }) => {
            if consumed != bytes.len() {
                return Err(WebError::TrailingBytes);
            }
            fstp_rt::future::block_on(router.handle(message))
        }
    };
    Ok(WebReply { response })
}

#[cfg(test)]
#[allow(clippy::panic, reason = "a test fails by panicking")]
mod tests {
    use super::*;

    /// ADR-014: the stub configuration builds.
    #[test]
    fn adr014_stub_router_builds() {
        assert!(stub_router().is_ok());
    }

    /// TH-26: the router refuses an oversized body itself, before the
    /// CSRF rule, when a server with larger limits mounts it.
    #[test]
    fn th26_router_refuses_an_oversized_body_itself() {
        let Ok(router) = stub_router() else {
            panic!("the stub router does not build");
        };
        let Ok(target) = fstp_http::RequestTarget::origin("/api/v1/programmes") else {
            panic!("the target does not parse");
        };
        let mut req = fstp_http::Request::new(fstp_http::Method::POST, target);
        req.body = vec![b' '; BODY_LIMIT.saturating_add(1)];
        let resp = fstp_rt::future::block_on(router.serve(req));
        assert_eq!(resp.status.as_u16(), 413);
        assert_eq!(resp.headers.count("content-security-policy"), 1);
    }
}
