//! Strict request decoders, one per operation, under limits.

use crate::{ApiError, Op};

/// A decoded query string.
///
/// W0 placeholder with no fields. Lane W3b writes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryParams {
    _w0: (),
}

/// A decoded page cursor.
///
/// W0 placeholder with no fields. Lane W3b writes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cursor {
    _w0: (),
}

/// A stored pending request, decoded again at confirmation.
///
/// W0 placeholder with no fields. Lane W3b writes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingRequest {
    _w0: (),
}

/// Decodes one operation's request. The first byte selects the operation.
/// JSON numbers for amounts are refused (ADR-006). Fuzzed
/// (`api_request_decode`).
pub fn decode_request(bytes: &[u8]) -> Result<Op, ApiError> {
    let _ = bytes;
    Err(ApiError::NotImplemented(
        "fstp_api_core::decode::decode_request",
    ))
}

/// Decodes a query string. Fuzzed (`query_params_decode`).
pub fn decode_query_params(bytes: &[u8]) -> Result<QueryParams, ApiError> {
    let _ = bytes;
    Err(ApiError::NotImplemented(
        "fstp_api_core::decode::decode_query_params",
    ))
}

/// Decodes a page cursor. Fuzzed (`cursor_decode`).
pub fn decode_cursor(bytes: &[u8]) -> Result<Cursor, ApiError> {
    let _ = bytes;
    Err(ApiError::NotImplemented(
        "fstp_api_core::decode::decode_cursor",
    ))
}

/// Decodes a stored pending request. Fuzzed (`pending_request_decode`).
pub fn decode_pending_request(bytes: &[u8]) -> Result<PendingRequest, ApiError> {
    let _ = bytes;
    Err(ApiError::NotImplemented(
        "fstp_api_core::decode::decode_pending_request",
    ))
}
