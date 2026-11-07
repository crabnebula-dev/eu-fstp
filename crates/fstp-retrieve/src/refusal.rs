//! Why the proxy refused a URL or a response.

use core::fmt;

/// A refusal. Messages name the rule that failed and never quote input
/// (R-NF-02).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Refusal {
    /// The URL is not an absolute `http` or `https` URL in the accepted
    /// grammar: another scheme, user information, a percent sign or other
    /// byte outside the host grammar, or no scheme at all.
    MalformedUrl,
    /// The URL is longer than [`MAX_URL_BYTES`](crate::MAX_URL_BYTES).
    UrlTooLong,
    /// The host is an IP literal in any notation (TH-12).
    IpLiteral,
    /// The host is a local name or is not under a listed suffix (TH-12).
    HostNotAllowed,
    /// Plain HTTP where the policy requires HTTPS.
    SchemeNotAllowed,
    /// An explicit port other than the scheme's default.
    PortNotAllowed,
    /// The response has a media type the converter does not read.
    UnsupportedMediaType,
    /// The response names a charset the decoder does not know.
    UnsupportedCharset,
    /// The response body is over the size limit.
    BodyTooLarge,
    /// The whole retrieval took longer than its deadline.
    Timeout,
    /// More redirects than the limit allows.
    TooManyRedirects,
    /// A redirect without a usable Location field.
    BadRedirect,
    /// A final status other than 200.
    HttpStatus(u16),
    /// Connecting, sending or reading failed, or the response broke the
    /// HTTP grammar.
    Transport,
    /// No upstream is configured. Public retrieval waits for a root store
    /// ADR (M7 design Q2).
    RetrievalUnavailable,
}

impl Refusal {
    /// A stable snake-case code for logs and the wire form.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Refusal::MalformedUrl => "malformed_url",
            Refusal::UrlTooLong => "url_too_long",
            Refusal::IpLiteral => "ip_literal",
            Refusal::HostNotAllowed => "host_not_allowed",
            Refusal::SchemeNotAllowed => "scheme_not_allowed",
            Refusal::PortNotAllowed => "port_not_allowed",
            Refusal::UnsupportedMediaType => "unsupported_media_type",
            Refusal::UnsupportedCharset => "unsupported_charset",
            Refusal::BodyTooLarge => "body_too_large",
            Refusal::Timeout => "timeout",
            Refusal::TooManyRedirects => "too_many_redirects",
            Refusal::BadRedirect => "bad_redirect",
            Refusal::HttpStatus(_) => "http_status",
            Refusal::Transport => "transport",
            Refusal::RetrievalUnavailable => "retrieval_unavailable",
        }
    }

    /// The refusal for `code`, with `status` for `http_status`.
    #[must_use]
    pub fn from_code(code: &str, status: Option<u16>) -> Option<Refusal> {
        Some(match code {
            "malformed_url" => Refusal::MalformedUrl,
            "url_too_long" => Refusal::UrlTooLong,
            "ip_literal" => Refusal::IpLiteral,
            "host_not_allowed" => Refusal::HostNotAllowed,
            "scheme_not_allowed" => Refusal::SchemeNotAllowed,
            "port_not_allowed" => Refusal::PortNotAllowed,
            "unsupported_media_type" => Refusal::UnsupportedMediaType,
            "unsupported_charset" => Refusal::UnsupportedCharset,
            "body_too_large" => Refusal::BodyTooLarge,
            "timeout" => Refusal::Timeout,
            "too_many_redirects" => Refusal::TooManyRedirects,
            "bad_redirect" => Refusal::BadRedirect,
            "http_status" => Refusal::HttpStatus(status?),
            "transport" => Refusal::Transport,
            "retrieval_unavailable" => Refusal::RetrievalUnavailable,
            _ => return None,
        })
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::HttpStatus(s) => write!(f, "retrieval refused: http_status {s}"),
            other => write!(f, "retrieval refused: {}", other.code()),
        }
    }
}

impl std::error::Error for Refusal {}
