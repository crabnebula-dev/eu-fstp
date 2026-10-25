//! Request and response messages.
//!
//! `Debug` output of every message type redacts header values, bodies and
//! the request target. It also hides extension method names and
//! unregistered field names, which a sender chooses freely. A logged
//! message therefore carries no content (R-NF-02).

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::error::InvalidInput;
use crate::header::{HeaderName, HeaderValue, Headers};
use crate::method::Method;
use crate::status::StatusCode;
use crate::target::RequestTarget;
use crate::version::Version;

/// How a message body is delimited on the wire (RFC 9112 section 6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BodyKind {
    /// Exactly this many bytes follow the head. Zero means no body.
    Length(u64),
    /// The chunked transfer coding.
    Chunked,
    /// The body runs until the connection closes. Responses only.
    UntilClose,
}

/// A parsed request head: start line, header fields and derived framing.
#[derive(Clone, PartialEq, Eq)]
pub struct RequestHead {
    /// The method.
    pub method: Method,
    /// The request target.
    pub target: RequestTarget,
    /// The protocol version.
    pub version: Version,
    /// The header fields in arrival order.
    pub headers: Headers,
    /// How the body is delimited.
    pub body: BodyKind,
    /// The client sent `Expect: 100-continue` in an HTTP/1.1 request.
    pub expect_continue: bool,
    /// The connection may carry another request after this one.
    pub keep_alive: bool,
}

impl fmt::Debug for RequestHead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestHead")
            .field("method", &self.method)
            .field("target", &self.target)
            .field("version", &self.version)
            .field("headers", &self.headers)
            .field("body", &self.body)
            .field("expect_continue", &self.expect_continue)
            .field("keep_alive", &self.keep_alive)
            .finish()
    }
}

/// A parsed response head: status line, header fields and derived framing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseHead {
    /// The protocol version.
    pub version: Version,
    /// The status code. The reason phrase is not kept (RFC 9112 section 4
    /// asks clients to ignore it).
    pub status: StatusCode,
    /// The header fields in arrival order.
    pub headers: Headers,
    /// How the body is delimited.
    pub body: BodyKind,
    /// The connection may carry another request after this response.
    pub keep_alive: bool,
}

/// Per-request information that the server driver and the router attach.
#[derive(Clone, Default)]
pub(crate) struct RequestContext {
    pub(crate) peer_addr: Option<SocketAddr>,
    pub(crate) client_cert: Option<Arc<[u8]>>,
    pub(crate) params: Vec<(Box<str>, Box<str>)>,
}

/// An HTTP request with a fully buffered body.
///
/// The server driver hands these to a [`Handler`](crate::Handler). The
/// client sends them, in which case the target must be an absolute URL.
#[derive(Clone)]
pub struct Request {
    /// The method.
    pub method: Method,
    /// The request target.
    pub target: RequestTarget,
    /// The protocol version.
    pub version: Version,
    /// The header fields.
    pub headers: Headers,
    /// The body after transfer decoding.
    pub body: Vec<u8>,
    /// Trailer fields of a chunked body. They are never merged into
    /// `headers`.
    pub trailers: Headers,
    pub(crate) context: RequestContext,
}

impl Request {
    /// A request with no header fields and no body.
    #[must_use]
    pub fn new(method: Method, target: RequestTarget) -> Request {
        Request {
            method,
            target,
            version: Version::Http11,
            headers: Headers::new(),
            body: Vec::new(),
            trailers: Headers::new(),
            context: RequestContext::default(),
        }
    }

    /// A GET request for an absolute `http` or `https` URL.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidInput`] when `url` is not a valid absolute URL.
    pub fn get(url: &str) -> Result<Request, InvalidInput> {
        Ok(Request::new(Method::GET, RequestTarget::absolute(url)?))
    }

    /// A POST request with a body for an absolute `http` or `https` URL.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidInput`] when `url` is not a valid absolute URL.
    pub fn post(url: &str, body: impl Into<Vec<u8>>) -> Result<Request, InvalidInput> {
        let mut r = Request::new(Method::POST, RequestTarget::absolute(url)?);
        r.body = body.into();
        Ok(r)
    }

    /// Builds a request from a parsed head and body.
    #[must_use]
    pub fn from_parts(head: RequestHead, body: Vec<u8>, trailers: Headers) -> Request {
        Request {
            method: head.method,
            target: head.target,
            version: head.version,
            headers: head.headers,
            body,
            trailers,
            context: RequestContext::default(),
        }
    }

    /// Adds a validated header field and returns the request.
    #[must_use]
    pub fn with_header(mut self, name: HeaderName, value: HeaderValue) -> Request {
        self.headers.append(name, value);
        self
    }

    /// Validates and adds a header field.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidInput`] when the name or value is invalid.
    pub fn try_with_header(
        mut self,
        name: &str,
        value: impl Into<Vec<u8>>,
    ) -> Result<Request, InvalidInput> {
        self.headers.try_append(name, value)?;
        Ok(self)
    }

    /// The path, still percent-encoded.
    #[must_use]
    pub fn path(&self) -> &str {
        self.target.path()
    }

    /// The query, without `?`.
    #[must_use]
    pub fn query(&self) -> Option<&str> {
        self.target.query()
    }

    /// The peer's socket address, set by the server driver.
    #[must_use]
    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.context.peer_addr
    }

    /// DER of the client's end-entity certificate under mutual TLS
    /// (R-NF-09), set by the server driver.
    #[must_use]
    pub fn client_certificate_der(&self) -> Option<&[u8]> {
        self.context.client_cert.as_deref()
    }

    /// A named path parameter captured by the [`Router`](crate::Router),
    /// percent-decoded once.
    ///
    /// A captured value is one path component. It is never empty, `.` or
    /// `..`, and it holds no `/`, `\`, control character or
    /// percent-encoded triple.
    #[must_use]
    pub fn param(&self, name: &str) -> Option<&str> {
        self.context
            .params
            .iter()
            .find(|(n, _)| &**n == name)
            .map(|(_, v)| &**v)
    }

    /// Every captured path parameter, in pattern order.
    pub fn params(&self) -> impl Iterator<Item = (&str, &str)> {
        self.context.params.iter().map(|(n, v)| (&**n, &**v))
    }
}

impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Request")
            .field("method", &self.method)
            .field("target", &self.target)
            .field("version", &self.version)
            .field("headers", &self.headers)
            .field(
                "body",
                &format_args!("<redacted {} bytes>", self.body.len()),
            )
            .field("trailers", &self.trailers)
            .finish_non_exhaustive()
    }
}

/// An HTTP response with a fully buffered body.
#[derive(Clone, PartialEq, Eq)]
pub struct Response {
    /// The status code.
    pub status: StatusCode,
    /// The protocol version. Servers always send HTTP/1.1.
    pub version: Version,
    /// The header fields. The encoder owns `Content-Length` and
    /// `Transfer-Encoding` and rejects responses that set them.
    pub headers: Headers,
    /// The body.
    pub body: Vec<u8>,
    /// Trailer fields received with a chunked response body.
    pub trailers: Headers,
}

impl Response {
    /// A response with no header fields and no body.
    #[must_use]
    pub fn new(status: StatusCode) -> Response {
        Response {
            status,
            version: Version::Http11,
            headers: Headers::new(),
            body: Vec::new(),
            trailers: Headers::new(),
        }
    }

    /// A response with a `text/plain; charset=utf-8` body.
    #[must_use]
    pub fn text(status: StatusCode, body: impl Into<String>) -> Response {
        Response::with_body(
            status,
            "text/plain; charset=utf-8",
            body.into().into_bytes(),
        )
    }

    /// A response with a body of the given media type.
    ///
    /// An invalid `content_type` is left out instead of failing, since the
    /// argument is normally a constant.
    #[must_use]
    pub fn with_body(status: StatusCode, content_type: &str, body: Vec<u8>) -> Response {
        let mut r = Response::new(status);
        let _ = r.headers.try_insert("content-type", content_type);
        r.body = body;
        r
    }

    /// Builds a response from a parsed head and body.
    #[must_use]
    pub fn from_parts(head: ResponseHead, body: Vec<u8>, trailers: Headers) -> Response {
        Response {
            status: head.status,
            version: head.version,
            headers: head.headers,
            body,
            trailers,
        }
    }

    /// Adds a validated header field and returns the response.
    #[must_use]
    pub fn with_header(mut self, name: HeaderName, value: HeaderValue) -> Response {
        self.headers.append(name, value);
        self
    }

    /// Validates and adds a header field.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidInput`] when the name or value is invalid.
    pub fn try_with_header(
        mut self,
        name: &str,
        value: impl Into<Vec<u8>>,
    ) -> Result<Response, InvalidInput> {
        self.headers.try_append(name, value)?;
        Ok(self)
    }

    /// True when the response carries `Connection: close`.
    #[must_use]
    pub fn wants_close(&self) -> bool {
        self.headers.has_token("connection", "close")
    }
}

impl fmt::Debug for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Response")
            .field("status", &self.status)
            .field("version", &self.version)
            .field("headers", &self.headers)
            .field(
                "body",
                &format_args!("<redacted {} bytes>", self.body.len()),
            )
            .field("trailers", &self.trailers)
            .finish()
    }
}
