//! The `/api/v1` surface: the CSRF rule, the credential and the one call
//! into `ApiCore::dispatch` (ADR-014 "CSRF", M4 design sections 3.7 and
//! 3.9, I-84).

use std::sync::Arc;

use fstp_api_core::decode::{Method as ApiMethod, decode_route};
use fstp_api_core::{ApiCore, ApiError, Credential, RequestHead};
use fstp_http::{Headers, Method, Request, Response, StatusCode};
use fstp_json::ToJson;

use crate::Origin;
use crate::origin::parse_origin_header;
use crate::reply;

/// The M3 session cookie name (ADR-008 "Sessions").
pub const SESSION_COOKIE: &str = "__Host-fstp";

/// The request header every state-changing API request carries
/// (ADR-014 "CSRF").
pub const REQUEST_HEADER: &str = "x-fstp-request";

/// What answers `/api/v1` calls.
#[derive(Clone)]
pub(crate) enum Backend {
    /// The cell's API core.
    Core(Arc<ApiCore>),
    /// The stub dispatch of `handle_op_request`, which refuses every call
    /// with `ApiError::NotImplemented`.
    Refusing,
}

/// Whether `method` needs the CSRF rule. Interim, pending Daniel: every
/// method except `GET` and `HEAD`, so `POST`, `PUT`, `PATCH`, `DELETE`
/// and every other method are covered.
pub(crate) fn changes_state(method: &Method) -> bool {
    *method != Method::GET && *method != Method::HEAD
}

/// The CSRF rule of ADR-014 for a state-changing request: exactly one
/// `Origin` equal to `tenant`, and exactly one `X-FSTP-Request: 1`.
///
/// It runs before routing, with or without a credential. A bearer token
/// does not lift it in M4, since the desktop client seam is not built.
pub(crate) fn csrf_passes(headers: &Headers, tenant: &Origin) -> bool {
    let mut origins = headers.get_all("origin");
    let origin_ok = match (origins.next(), origins.next()) {
        (Some(v), None) => parse_origin_header(v.as_bytes()).is_ok_and(|o| o == *tenant),
        _ => false,
    };
    let mut marks = headers.get_all(REQUEST_HEADER);
    let mark_ok = matches!(
        (marks.next(), marks.next()),
        (Some(v), None) if v.as_bytes() == b"1"
    );
    origin_ok && mark_ok
}

/// Whether a request body may be decoded: empty, or with exactly one
/// `Content-Type` of `application/json`, optionally with parameters.
pub(crate) fn json_body(headers: &Headers, body: &[u8]) -> bool {
    if body.is_empty() {
        return true;
    }
    let mut types = headers.get_all("content-type");
    let (Some(v), None) = (types.next(), types.next()) else {
        return false;
    };
    let lower = v.as_bytes().to_ascii_lowercase();
    match lower.strip_prefix(b"application/json") {
        Some(rest) => {
            let rest = rest.trim_ascii_start();
            rest.is_empty() || rest.starts_with(b";")
        }
        None => false,
    }
}

/// Why the credential of a request was refused before dispatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CredentialRefusal {
    /// The session cookie appears more than once.
    Ambiguous,
    /// An `Authorization` field reached `/api/v1`, which M4 does not
    /// serve to bearer tokens (ADR-014 "Desktop client seam").
    Bearer,
}

/// The credential of an API request: the `__Host-fstp` cookie value, as
/// M3 reads it. The adapter attests nothing, so the value goes to
/// `ApiCore` unchecked.
///
/// - Only the exact, case-sensitive name `__Host-fstp` counts. Other
///   cookies are ignored.
/// - Two session cookies, in one field or two, are refused, so a tossed
///   cookie never shadows the real one.
/// - Any `Authorization` field is refused. M4 builds no bearer path for
///   `/api/v1`, and an MCP token must never act through it.
pub(crate) fn credential(headers: &Headers) -> Result<Credential, CredentialRefusal> {
    if headers.contains("authorization") {
        return Err(CredentialRefusal::Bearer);
    }
    let mut found: Option<&[u8]> = None;
    for field in headers.get_all("cookie") {
        for pair in field.as_bytes().split(|b| *b == b';') {
            let pair = pair.trim_ascii();
            let Some(eq) = pair.iter().position(|b| *b == b'=') else {
                continue;
            };
            let (name, value) = pair.split_at(eq);
            if name.trim_ascii() != SESSION_COOKIE.as_bytes() {
                continue;
            }
            if found.is_some() {
                return Err(CredentialRefusal::Ambiguous);
            }
            found = Some(value.get(1..).unwrap_or_default());
        }
    }
    Ok(match found {
        Some(v) => Credential::SessionCookie(v.to_vec()),
        None => Credential::None,
    })
}

/// Answers one `/api/v1` request after the gate of the router.
pub(crate) async fn answer(backend: &Backend, req: Request) -> Response {
    let cred = match credential(&req.headers) {
        Ok(c) => c,
        Err(CredentialRefusal::Ambiguous) => {
            return reply::refused(StatusCode::BAD_REQUEST, "ADR-008");
        }
        Err(CredentialRefusal::Bearer) => {
            return reply::refused(StatusCode::BAD_REQUEST, "ADR-014");
        }
    };
    match backend {
        Backend::Core(core) => call_core(core, cred, req).await,
        Backend::Refusing => api_error(ApiError::NotImplemented("fstp_web stub dispatch")),
    }
}

/// The one call into the API core: the route decoder of `fstp-api-core`,
/// then `ApiCore::dispatch`, then the result as JSON with its status.
/// No request reaches a port by any other path (I-84).
async fn call_core(core: &ApiCore, cred: Credential, req: Request) -> Response {
    let method = match req.method {
        Method::GET => ApiMethod::Get,
        Method::POST => ApiMethod::Post,
        Method::PUT => ApiMethod::Put,
        Method::DELETE => ApiMethod::Delete,
        _ => return reply::get_only(),
    };
    let path = req.target.path();
    let below = path.strip_prefix("/api/v1").unwrap_or(path);
    let op = match decode_route(method, below, &req.body) {
        Ok(op) => op,
        Err(e) => return api_error(e),
    };
    match core.dispatch(cred, &RequestHead::new(), op).await {
        Ok(r) => {
            let status = StatusCode::from_u16(r.http_status()).unwrap_or(StatusCode::OK);
            Response::with_body(
                status,
                "application/json",
                r.to_json().to_compact().into_bytes(),
            )
        }
        Err(e) => api_error(e),
    }
}

/// The response for an [`ApiError`]. It carries a stable code only and
/// never names an account or an operation (R-CF-03).
pub(crate) fn api_error(e: ApiError) -> Response {
    let status = StatusCode::from_u16(e.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    Response::with_body(
        status,
        "application/json",
        e.to_json().to_compact().into_bytes(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(fields: &[(&str, &str)]) -> Headers {
        let mut h = Headers::new();
        for (n, v) in fields {
            assert!(h.try_append(n, *v).is_ok());
        }
        h
    }

    /// ADR-008, ADR-014: the session cookie is read by its exact name,
    /// once, and a bearer field is refused.
    #[test]
    fn adr014_credential_reading() {
        let one = headers(&[("cookie", "a=1; __Host-fstp=abc; b=2")]);
        assert_eq!(
            credential(&one),
            Ok(Credential::SessionCookie(b"abc".to_vec()))
        );
        let other = headers(&[("cookie", "__host-fstp=abc")]);
        assert_eq!(credential(&other), Ok(Credential::None));
        let two = headers(&[("cookie", "__Host-fstp=a"), ("cookie", "__Host-fstp=b")]);
        assert_eq!(credential(&two), Err(CredentialRefusal::Ambiguous));
        let bearer = headers(&[("authorization", "Bearer x")]);
        assert_eq!(credential(&bearer), Err(CredentialRefusal::Bearer));
    }

    /// ADR-014: only an empty body or a JSON media type may be decoded.
    #[test]
    fn adr014_json_body_media_type() {
        let json = headers(&[("content-type", "application/json; charset=utf-8")]);
        assert!(json_body(&json, b"{}"));
        let form = headers(&[("content-type", "application/x-www-form-urlencoded")]);
        assert!(!json_body(&form, b"a=1"));
        let near = headers(&[("content-type", "application/jsonx")]);
        assert!(!json_body(&near, b"{}"));
        assert!(json_body(&Headers::new(), b""));
        assert!(!json_body(&Headers::new(), b"{}"));
    }
}
