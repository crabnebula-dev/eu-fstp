//! Serializers for requests and responses.
//!
//! Every header name and value is checked again before it is written, on
//! top of the checks in [`HeaderName`](crate::HeaderName) and
//! [`HeaderValue`](crate::HeaderValue). No path through this module can
//! emit CR or LF inside a field, a target or a start line, so request and
//! response splitting are impossible through the API (TH-26).
//!
//! The encoder owns message framing. It writes `Content-Length` or
//! `Transfer-Encoding: chunked` itself and rejects messages whose header
//! list already sets either field.

use std::fmt;

use crate::chars::is_token;
use crate::header::{Headers, is_valid_value};
use crate::message::{Request, Response};
use crate::method::Method;
use crate::target::TargetForm;
use crate::version::Version;

/// Why a message could not be serialized.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SerializeError {
    /// A header name is not a token.
    InvalidHeaderName,
    /// A header value holds a forbidden byte or surrounding whitespace.
    InvalidHeaderValue,
    /// The header list sets Content-Length or Transfer-Encoding, which the
    /// encoder owns.
    FramingHeader,
    /// A response with status 1xx, 204 or 304 has a body.
    BodyNotAllowed,
    /// An HTTP/1.1 request has neither a Host field nor an absolute target.
    MissingHost,
    /// The method is not a token, or the target has a form that this method
    /// cannot use.
    InvalidRequestLine,
    /// Trailer fields need the chunked coding, which HTTP/1.0 lacks.
    TrailersNeedChunked,
    /// A chunk size of zero was requested.
    InvalidChunkSize,
}

impl fmt::Display for SerializeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            SerializeError::InvalidHeaderName => "header name is not a token",
            SerializeError::InvalidHeaderValue => "header value holds a forbidden byte",
            SerializeError::FramingHeader => "Content-Length or Transfer-Encoding set by caller",
            SerializeError::BodyNotAllowed => "body on a status that forbids one",
            SerializeError::MissingHost => "HTTP/1.1 request without Host",
            SerializeError::InvalidRequestLine => "invalid request line",
            SerializeError::TrailersNeedChunked => "trailers need the chunked coding",
            SerializeError::InvalidChunkSize => "chunk size must be at least 1",
        };
        write!(f, "cannot serialize HTTP message: {s}")
    }
}

impl std::error::Error for SerializeError {}

/// How a request body is framed on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    /// `Content-Length`. It is omitted for an empty body unless the method
    /// is POST, PUT or PATCH.
    ContentLength,
    /// `Transfer-Encoding: chunked` with chunks of at most this many bytes,
    /// followed by the request's trailer fields. HTTP/1.1 only.
    Chunked(usize),
}

fn write_headers(headers: &Headers, out: &mut Vec<u8>) -> Result<(), SerializeError> {
    for (name, value) in headers {
        let n = name.as_str().as_bytes();
        if !is_token(n) {
            return Err(SerializeError::InvalidHeaderName);
        }
        if !is_valid_value(value.as_bytes()) {
            return Err(SerializeError::InvalidHeaderValue);
        }
        out.extend_from_slice(n);
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    Ok(())
}

fn reject_framing(headers: &Headers) -> Result<(), SerializeError> {
    if headers.contains("content-length") || headers.contains("transfer-encoding") {
        return Err(SerializeError::FramingHeader);
    }
    Ok(())
}

fn write_decimal(out: &mut Vec<u8>, n: usize) {
    out.extend_from_slice(n.to_string().as_bytes());
}

fn write_chunked(
    body: &[u8],
    chunk: usize,
    trailers: &Headers,
    out: &mut Vec<u8>,
) -> Result<(), SerializeError> {
    if chunk == 0 {
        return Err(SerializeError::InvalidChunkSize);
    }
    for piece in body.chunks(chunk) {
        out.extend_from_slice(format!("{:x}", piece.len()).as_bytes());
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(piece);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"0\r\n");
    write_headers(trailers, out)?;
    out.extend_from_slice(b"\r\n");
    Ok(())
}

/// Appends the wire form of `req` to `out`.
///
/// The target is written in the form it holds. An HTTP/1.1 request needs a
/// Host field or an absolute target, from which a Host field is derived.
/// On error, `out` is left unchanged.
///
/// # Errors
///
/// Returns a [`SerializeError`] for an invalid field, a caller-set framing
/// field, a missing Host, a target form the method cannot use, or trailers
/// without chunked framing.
pub fn encode_request(
    req: &Request,
    framing: Framing,
    out: &mut Vec<u8>,
) -> Result<(), SerializeError> {
    let mut buf = Vec::with_capacity(256usize.saturating_add(req.body.len()));
    encode_request_inner(req, framing, &mut buf)?;
    out.extend_from_slice(&buf);
    Ok(())
}

fn encode_request_inner(
    req: &Request,
    framing: Framing,
    out: &mut Vec<u8>,
) -> Result<(), SerializeError> {
    let method = req.method.as_str().as_bytes();
    if !is_token(method) || req.method == Method::CONNECT {
        return Err(SerializeError::InvalidRequestLine);
    }
    if req.target.form() == TargetForm::Asterisk && req.method != Method::OPTIONS {
        return Err(SerializeError::InvalidRequestLine);
    }
    reject_framing(&req.headers)?;
    let chunked = matches!(framing, Framing::Chunked(_));
    if (chunked || !req.trailers.is_empty()) && req.version == Version::Http10 {
        return Err(SerializeError::TrailersNeedChunked);
    }
    if !req.trailers.is_empty() && !chunked {
        return Err(SerializeError::TrailersNeedChunked);
    }
    out.extend_from_slice(method);
    out.push(b' ');
    req.target.write_to(out);
    out.push(b' ');
    out.extend_from_slice(req.version.as_str().as_bytes());
    out.extend_from_slice(b"\r\n");
    if !req.headers.contains("host") {
        match req.target.authority() {
            Some(a) => {
                out.extend_from_slice(b"host: ");
                out.extend_from_slice(a.as_str().as_bytes());
                out.extend_from_slice(b"\r\n");
            }
            None if req.version == Version::Http11 => return Err(SerializeError::MissingHost),
            None => {}
        }
    }
    write_headers(&req.headers, out)?;
    match framing {
        Framing::ContentLength => {
            let wants_length = !req.body.is_empty()
                || req.method == Method::POST
                || req.method == Method::PUT
                || req.method == Method::PATCH;
            if wants_length {
                out.extend_from_slice(b"content-length: ");
                write_decimal(out, req.body.len());
                out.extend_from_slice(b"\r\n");
            }
            out.extend_from_slice(b"\r\n");
            out.extend_from_slice(&req.body);
        }
        Framing::Chunked(size) => {
            out.extend_from_slice(b"transfer-encoding: chunked\r\n\r\n");
            write_chunked(&req.body, size, &req.trailers, out)?;
        }
    }
    Ok(())
}

/// Appends the wire form of `resp` to `out`, always as HTTP/1.1 with
/// `Content-Length` framing.
///
/// With `head_request` set, the body is left out while `Content-Length`
/// still announces its size (RFC 9110 section 9.3.2). Responses with status
/// 1xx, 204 or 304 carry no `Content-Length` and must have an empty body.
/// Trailer fields of `resp` are not sent. On error, `out` is left unchanged.
///
/// # Errors
///
/// Returns a [`SerializeError`] for an invalid field, a caller-set framing
/// field, or a body on a status that forbids one.
pub fn encode_response(
    resp: &Response,
    head_request: bool,
    out: &mut Vec<u8>,
) -> Result<(), SerializeError> {
    let mut buf = Vec::with_capacity(256usize.saturating_add(resp.body.len()));
    encode_response_inner(resp, head_request, &mut buf)?;
    out.extend_from_slice(&buf);
    Ok(())
}

fn encode_response_inner(
    resp: &Response,
    head_request: bool,
    out: &mut Vec<u8>,
) -> Result<(), SerializeError> {
    reject_framing(&resp.headers)?;
    let no_body = resp.status.forbids_body();
    if no_body && !resp.body.is_empty() {
        return Err(SerializeError::BodyNotAllowed);
    }
    out.extend_from_slice(b"HTTP/1.1 ");
    out.extend_from_slice(&resp.status.digits());
    out.push(b' ');
    out.extend_from_slice(resp.status.canonical_reason().as_bytes());
    out.extend_from_slice(b"\r\n");
    write_headers(&resp.headers, out)?;
    if !no_body {
        out.extend_from_slice(b"content-length: ");
        write_decimal(out, resp.body.len());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    if !no_body && !head_request {
        out.extend_from_slice(&resp.body);
    }
    Ok(())
}

/// The interim response that answers `Expect: 100-continue`.
pub const CONTINUE_RESPONSE: &[u8] = b"HTTP/1.1 100 Continue\r\n\r\n";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::{HeaderName, HeaderValue};
    use crate::status::StatusCode;
    use crate::target::RequestTarget;

    #[test]
    fn response_has_length() {
        let r = Response::text(StatusCode::OK, "hi");
        let mut out = Vec::new();
        encode_response(&r, false, &mut out).unwrap();
        assert_eq!(
            out,
            b"HTTP/1.1 200 OK\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: 2\r\n\r\nhi"
        );
        let mut out = Vec::new();
        encode_response(&r, true, &mut out).unwrap();
        assert!(out.ends_with(b"content-length: 2\r\n\r\n"));
    }

    #[test]
    fn framing_is_owned_by_the_encoder() {
        let r = Response::new(StatusCode::OK).with_header(
            HeaderName::new("Content-Length").unwrap(),
            HeaderValue::from_u64(5),
        );
        assert_eq!(
            encode_response(&r, false, &mut Vec::new()),
            Err(SerializeError::FramingHeader)
        );
        let mut r = Response::new(StatusCode::NO_CONTENT);
        r.body = b"x".to_vec();
        assert_eq!(
            encode_response(&r, false, &mut Vec::new()),
            Err(SerializeError::BodyNotAllowed)
        );
    }

    #[test]
    fn request_gets_host_from_url() {
        let r = Request::get("http://example.com:8080/a?b").unwrap();
        let wire = Request {
            target: r.target.to_origin_form(),
            ..r.clone()
        };
        let mut out = Vec::new();
        encode_request(&wire, Framing::ContentLength, &mut out).unwrap_err();
        let mut out = Vec::new();
        encode_request(&r, Framing::ContentLength, &mut out).unwrap();
        assert_eq!(
            out,
            b"GET http://example.com:8080/a?b HTTP/1.1\r\nhost: example.com:8080\r\n\r\n"
        );
        let o = Request::new(Method::OPTIONS, RequestTarget::asterisk())
            .try_with_header("host", "h")
            .unwrap();
        let mut out = Vec::new();
        encode_request(&o, Framing::ContentLength, &mut out).unwrap();
        assert_eq!(out, b"OPTIONS * HTTP/1.1\r\nhost: h\r\n\r\n");
    }

    #[test]
    fn chunked_request() {
        let mut r = Request::post("http://h/", b"hello".to_vec()).unwrap();
        r.trailers.try_append("x-t", "1").unwrap();
        let mut out = Vec::new();
        encode_request(&r, Framing::Chunked(2), &mut out).unwrap();
        assert!(out.ends_with(b"transfer-encoding: chunked\r\n\r\n2\r\nhe\r\n2\r\nll\r\n1\r\no\r\n0\r\nx-t: 1\r\n\r\n"));
        assert_eq!(
            encode_request(&r, Framing::Chunked(0), &mut Vec::new()),
            Err(SerializeError::InvalidChunkSize)
        );
        assert_eq!(
            encode_request(&r, Framing::ContentLength, &mut Vec::new()),
            Err(SerializeError::TrailersNeedChunked)
        );
    }
}
