//! Fixed responses of the adapter. Each body is a constant, so no
//! response quotes request content (R-NF-02).

use fstp_http::{Response, StatusCode};

/// The media type of every JSON body.
const JSON: &str = "application/json";

/// A JSON response with the constant `body`.
pub(crate) fn json(status: StatusCode, body: &'static [u8]) -> Response {
    Response::with_body(status, JSON, body.to_vec())
}

/// A refusal `{"code":"refused","rule":<rule>}` with `status`. `rule` is a
/// constant rule name.
pub(crate) fn refused(status: StatusCode, rule: &'static str) -> Response {
    let body = format!("{{\"code\":\"refused\",\"rule\":\"{rule}\"}}");
    Response::with_body(status, JSON, body.into_bytes())
}

/// The CSRF refusal of ADR-014: 403 `{"code":"refused","rule":"ADR-014"}`.
pub(crate) fn csrf_refused() -> Response {
    refused(StatusCode::FORBIDDEN, "ADR-014")
}

/// The typed refusal of a surface that waits for ADR-013: 501
/// `{"code":"not_available","rule":"ADR-013"}`.
pub(crate) fn adr013() -> Response {
    json(
        StatusCode::NOT_IMPLEMENTED,
        br#"{"code":"not_available","rule":"ADR-013"}"#,
    )
}

/// 404 `{"code":"not_found"}`.
pub(crate) fn not_found() -> Response {
    json(StatusCode::NOT_FOUND, br#"{"code":"not_found"}"#)
}

/// 413 `{"code":"too_large"}`.
pub(crate) fn too_large() -> Response {
    json(StatusCode::CONTENT_TOO_LARGE, br#"{"code":"too_large"}"#)
}

/// 415 `{"code":"unsupported_media_type"}`.
pub(crate) fn unsupported_media_type() -> Response {
    json(
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        br#"{"code":"unsupported_media_type"}"#,
    )
}

/// 405 with `Allow: GET, HEAD`.
pub(crate) fn get_only() -> Response {
    let mut r = json(
        StatusCode::METHOD_NOT_ALLOWED,
        br#"{"code":"method_not_allowed"}"#,
    );
    // A valid constant, so the insert never fails.
    let _ = r.headers.try_insert("allow", "GET, HEAD");
    r
}

/// An empty response with `status`, for a request the HTTP parser
/// refused.
pub(crate) fn status_only(status: StatusCode) -> Response {
    Response::new(status)
}
