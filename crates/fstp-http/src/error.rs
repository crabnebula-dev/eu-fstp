//! Typed parse errors with their HTTP status mapping.
//!
//! Error messages name the rule that failed. They never quote message bytes,
//! so a logged error carries no content (R-NF-02).

use std::fmt;

use crate::status::StatusCode;

/// The rule a message violated.
///
/// Each kind maps to the status code a server sends in reply, through
/// [`ParseErrorKind::status`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ParseErrorKind {
    // Line structure.
    /// A line ended in LF without a preceding CR.
    BareLf,
    /// A CR appeared inside a line instead of before its LF.
    BareCr,
    /// The input ended inside a message.
    UnexpectedEof,
    /// More empty lines preceded the request line than the limit allows.
    TooManyEmptyLines,

    // Start line.
    /// The request line is not `method SP request-target SP HTTP-version`.
    InvalidRequestLine,
    /// The method is not a token.
    InvalidMethod,
    /// The request target is not valid origin-form, absolute-form or
    /// asterisk-form.
    InvalidTarget,
    /// The HTTP version does not match `HTTP/DIGIT.DIGIT`.
    InvalidVersion,
    /// The status line is not `HTTP-version SP status-code SP reason`.
    InvalidStatusLine,
    /// The status code is not three digits in the range 100 to 599.
    InvalidStatusCode,
    /// The request line is longer than the limit.
    RequestLineTooLong,
    /// The status line is longer than the limit.
    StatusLineTooLong,
    /// The HTTP major version is not 1.
    UnsupportedVersion,
    /// The method needs a feature this crate does not implement (CONNECT).
    UnsupportedMethod,

    // Field lines.
    /// A field line has no colon.
    MissingColon,
    /// A field name is empty or not a token.
    InvalidHeaderName,
    /// Whitespace appeared between a field name and the colon.
    WhitespaceBeforeColon,
    /// A field line started with whitespace (obsolete line folding).
    ObsoleteLineFolding,
    /// A field value contains NUL, another control byte or DEL.
    InvalidHeaderValue,
    /// More header fields than the limit.
    TooManyHeaders,
    /// The header section is larger than the limit.
    HeaderSectionTooLarge,

    // Host.
    /// An HTTP/1.1 request has no Host field.
    MissingHost,
    /// A request has more than one Host field line.
    MultipleHost,
    /// The Host field value is not `uri-host [ ":" port ]`.
    InvalidHost,

    // Framing (request smuggling defence).
    /// Both Content-Length and Transfer-Encoding are present.
    ContentLengthWithTransferEncoding,
    /// More than one Content-Length field line.
    MultipleContentLength,
    /// The Content-Length value is not a plain decimal number.
    InvalidContentLength,
    /// The Transfer-Encoding list is malformed.
    InvalidTransferEncoding,
    /// The final transfer coding is not chunked.
    TransferEncodingNotChunked,
    /// The chunked coding appears more than once.
    ChunkedAppliedTwice,
    /// A transfer coding other than chunked was applied.
    UnsupportedTransferCoding,
    /// An HTTP/1.0 message carries Transfer-Encoding.
    TransferEncodingInHttp10,
    /// The Connection field is not a list of tokens.
    InvalidConnection,
    /// The Expect field holds something other than `100-continue`.
    UnsupportedExpectation,
    /// The response announces a protocol switch, which this crate does not
    /// implement.
    UnsupportedUpgrade,

    // Body.
    /// The body is larger than the limit.
    BodyTooLarge,
    /// A chunk is larger than the limit.
    ChunkTooLarge,
    /// A chunk-size line does not start with a hexadecimal size.
    InvalidChunkSize,
    /// A chunk extension does not follow the chunk-ext grammar.
    InvalidChunkExtension,
    /// A chunk-size line is longer than the limit.
    ChunkLineTooLong,
    /// The chunk extensions of one message exceed the limit in total.
    ChunkExtensionsTooLarge,
    /// Chunk data is not followed by CRLF.
    InvalidChunkTerminator,
    /// More trailer fields than the limit.
    TooManyTrailers,
    /// The trailer section is larger than the limit.
    TrailerSectionTooLarge,
}

impl ParseErrorKind {
    /// The status code a server sends for this error.
    ///
    /// - 400 for syntax errors and ambiguous framing.
    /// - 413 when the body or a chunk exceeds its limit.
    /// - 414 when the request line exceeds its limit.
    /// - 417 for an unsupported expectation.
    /// - 431 when the header or trailer section exceeds its limits.
    /// - 501 for unsupported transfer codings and methods.
    /// - 505 for an HTTP major version other than 1.
    #[must_use]
    pub fn status(self) -> StatusCode {
        use ParseErrorKind as K;
        match self {
            K::BodyTooLarge | K::ChunkTooLarge => StatusCode::CONTENT_TOO_LARGE,
            K::RequestLineTooLong => StatusCode::URI_TOO_LONG,
            K::UnsupportedExpectation => StatusCode::EXPECTATION_FAILED,
            K::TooManyHeaders
            | K::HeaderSectionTooLarge
            | K::TooManyTrailers
            | K::TrailerSectionTooLarge => StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            K::UnsupportedTransferCoding | K::UnsupportedMethod => StatusCode::NOT_IMPLEMENTED,
            K::UnsupportedVersion => StatusCode::HTTP_VERSION_NOT_SUPPORTED,
            _ => StatusCode::BAD_REQUEST,
        }
    }

    /// A fixed description of the rule. It never contains message bytes.
    #[must_use]
    pub fn description(self) -> &'static str {
        use ParseErrorKind as K;
        match self {
            K::BareLf => "line ends in LF without CR",
            K::BareCr => "CR inside a line",
            K::UnexpectedEof => "input ended inside a message",
            K::TooManyEmptyLines => "too many empty lines before the request line",
            K::InvalidRequestLine => "malformed request line",
            K::InvalidMethod => "method is not a token",
            K::InvalidTarget => "malformed request target",
            K::InvalidVersion => "malformed HTTP version",
            K::InvalidStatusLine => "malformed status line",
            K::InvalidStatusCode => "status code out of range",
            K::RequestLineTooLong => "request line exceeds the limit",
            K::StatusLineTooLong => "status line exceeds the limit",
            K::UnsupportedVersion => "HTTP major version is not 1",
            K::UnsupportedMethod => "method is not supported",
            K::MissingColon => "field line without colon",
            K::InvalidHeaderName => "field name is not a token",
            K::WhitespaceBeforeColon => "whitespace between field name and colon",
            K::ObsoleteLineFolding => "obsolete line folding",
            K::InvalidHeaderValue => "invalid byte in field value",
            K::TooManyHeaders => "header field count exceeds the limit",
            K::HeaderSectionTooLarge => "header section exceeds the limit",
            K::MissingHost => "HTTP/1.1 request without Host",
            K::MultipleHost => "more than one Host field line",
            K::InvalidHost => "malformed Host value",
            K::ContentLengthWithTransferEncoding => "both Content-Length and Transfer-Encoding",
            K::MultipleContentLength => "more than one Content-Length field line",
            K::InvalidContentLength => "malformed Content-Length value",
            K::InvalidTransferEncoding => "malformed Transfer-Encoding list",
            K::TransferEncodingNotChunked => "final transfer coding is not chunked",
            K::ChunkedAppliedTwice => "chunked coding applied more than once",
            K::UnsupportedTransferCoding => "unsupported transfer coding",
            K::TransferEncodingInHttp10 => "Transfer-Encoding in an HTTP/1.0 message",
            K::InvalidConnection => "malformed Connection value",
            K::UnsupportedExpectation => "unsupported expectation",
            K::UnsupportedUpgrade => "protocol upgrade is not supported",
            K::BodyTooLarge => "body exceeds the limit",
            K::ChunkTooLarge => "chunk exceeds the limit",
            K::InvalidChunkSize => "malformed chunk size",
            K::InvalidChunkExtension => "malformed chunk extension",
            K::ChunkLineTooLong => "chunk-size line exceeds the limit",
            K::ChunkExtensionsTooLarge => "chunk extensions exceed the limit",
            K::InvalidChunkTerminator => "chunk data not followed by CRLF",
            K::TooManyTrailers => "trailer field count exceeds the limit",
            K::TrailerSectionTooLarge => "trailer section exceeds the limit",
        }
    }
}

/// A message that violates the HTTP/1.1 grammar, a framing rule or a limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ParseError {
    kind: ParseErrorKind,
}

impl ParseError {
    /// Creates an error of the given kind.
    #[must_use]
    pub const fn new(kind: ParseErrorKind) -> Self {
        Self { kind }
    }

    /// The rule that failed.
    #[must_use]
    pub const fn kind(&self) -> ParseErrorKind {
        self.kind
    }

    /// The status code a server sends in reply.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        self.kind.status()
    }
}

impl From<ParseErrorKind> for ParseError {
    fn from(kind: ParseErrorKind) -> Self {
        Self::new(kind)
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid HTTP message: {}", self.kind.description())
    }
}

impl std::error::Error for ParseError {}

/// A value rejected by a validating constructor, such as a header name with
/// a space or a header value with CR or LF.
///
/// The message names the rule. It never quotes the rejected value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InvalidInput {
    what: &'static str,
}

impl InvalidInput {
    pub(crate) const fn new(what: &'static str) -> Self {
        Self { what }
    }

    /// A fixed description of the rule that failed.
    #[must_use]
    pub const fn description(&self) -> &'static str {
        self.what
    }
}

impl fmt::Display for InvalidInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid input: {}", self.what)
    }
}

impl std::error::Error for InvalidInput {}
