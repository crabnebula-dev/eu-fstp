//! The web adapter (M4 design section 1.1).
//!
//! The crate holds the routes over `fstp_http::Router` for `/api/v1`,
//! `/app`, `/p`, `/mcp`, `/mcp/public`, `/oauth` and `/.well-known`, the
//! CSRF and Origin rules, the security headers and the body limits. It
//! calls only `fstp_api_core::ApiCore::dispatch`.
//!
//! It may depend directly on `fstp-api-core`, `fstp-mcp`, `fstp-oauth`,
//! `fstp-web-assets`, `fstp-http`, `fstp-json` and `fstp-rt` only (layering
//! rule A1), and never names a port, the principal or the execution
//! metadata (rule A2b).
//!
//! Status: W0 stub. Lane W4e (L-WEB) owns this crate. Every operation
//! refuses with [`WebError::NotImplemented`].

/// Why an operation of this crate failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WebError {
    /// The W0 stub of the named operation refuses.
    NotImplemented(&'static str),
}

impl std::fmt::Display for WebError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WebError::NotImplemented(op) => write!(f, "{op} is not implemented yet"),
        }
    }
}

impl std::error::Error for WebError {}

/// A parsed `Origin` header.
///
/// W0 placeholder with no fields. The owning lane writes the designed type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Origin {
    _w0: (),
}

/// Parses an `Origin` header value. A duplicated or unparsable value is refused. Fuzzed (`origin_header_parse`).
pub fn parse_origin_header(bytes: &[u8]) -> Result<Origin, WebError> {
    let _ = bytes;
    Err(WebError::NotImplemented("fstp_web::parse_origin_header"))
}

/// The reply to one web request.
///
/// W0 placeholder with no fields. The owning lane writes the designed type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebReply {
    _w0: (),
}

/// Handles one raw request over a stub dispatch: route, headers and body. Fuzzed (`web_op_request`).
pub fn handle_op_request(bytes: &[u8]) -> Result<WebReply, WebError> {
    let _ = bytes;
    Err(WebError::NotImplemented("fstp_web::handle_op_request"))
}
