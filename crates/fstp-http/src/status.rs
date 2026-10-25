//! Status codes (RFC 9110 section 15).

use std::fmt;

use crate::error::InvalidInput;

/// An HTTP status code in the range 100 to 599.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StatusCode(u16);

macro_rules! codes {
    ($($(#[$doc:meta])* $name:ident = $code:literal, $reason:literal;)*) => {
        impl StatusCode {
            $(
                $(#[$doc])*
                pub const $name: StatusCode = StatusCode($code);
            )*

            /// The reason phrase that RFC 9110 suggests for this code, or an
            /// empty string for codes it does not define.
            #[must_use]
            pub const fn canonical_reason(self) -> &'static str {
                match self.0 {
                    $($code => $reason,)*
                    _ => "",
                }
            }
        }
    };
}

codes! {
    /// 100 Continue.
    CONTINUE = 100, "Continue";
    /// 101 Switching Protocols.
    SWITCHING_PROTOCOLS = 101, "Switching Protocols";
    /// 200 OK.
    OK = 200, "OK";
    /// 201 Created.
    CREATED = 201, "Created";
    /// 202 Accepted.
    ACCEPTED = 202, "Accepted";
    /// 204 No Content.
    NO_CONTENT = 204, "No Content";
    /// 301 Moved Permanently.
    MOVED_PERMANENTLY = 301, "Moved Permanently";
    /// 302 Found.
    FOUND = 302, "Found";
    /// 303 See Other.
    SEE_OTHER = 303, "See Other";
    /// 304 Not Modified.
    NOT_MODIFIED = 304, "Not Modified";
    /// 307 Temporary Redirect.
    TEMPORARY_REDIRECT = 307, "Temporary Redirect";
    /// 308 Permanent Redirect.
    PERMANENT_REDIRECT = 308, "Permanent Redirect";
    /// 400 Bad Request.
    BAD_REQUEST = 400, "Bad Request";
    /// 401 Unauthorized.
    UNAUTHORIZED = 401, "Unauthorized";
    /// 403 Forbidden.
    FORBIDDEN = 403, "Forbidden";
    /// 404 Not Found.
    NOT_FOUND = 404, "Not Found";
    /// 405 Method Not Allowed.
    METHOD_NOT_ALLOWED = 405, "Method Not Allowed";
    /// 408 Request Timeout.
    REQUEST_TIMEOUT = 408, "Request Timeout";
    /// 409 Conflict.
    CONFLICT = 409, "Conflict";
    /// 411 Length Required.
    LENGTH_REQUIRED = 411, "Length Required";
    /// 413 Content Too Large.
    CONTENT_TOO_LARGE = 413, "Content Too Large";
    /// 414 URI Too Long.
    URI_TOO_LONG = 414, "URI Too Long";
    /// 415 Unsupported Media Type.
    UNSUPPORTED_MEDIA_TYPE = 415, "Unsupported Media Type";
    /// 417 Expectation Failed.
    EXPECTATION_FAILED = 417, "Expectation Failed";
    /// 422 Unprocessable Content.
    UNPROCESSABLE_CONTENT = 422, "Unprocessable Content";
    /// 429 Too Many Requests.
    TOO_MANY_REQUESTS = 429, "Too Many Requests";
    /// 431 Request Header Fields Too Large.
    REQUEST_HEADER_FIELDS_TOO_LARGE = 431, "Request Header Fields Too Large";
    /// 500 Internal Server Error.
    INTERNAL_SERVER_ERROR = 500, "Internal Server Error";
    /// 501 Not Implemented.
    NOT_IMPLEMENTED = 501, "Not Implemented";
    /// 502 Bad Gateway.
    BAD_GATEWAY = 502, "Bad Gateway";
    /// 503 Service Unavailable.
    SERVICE_UNAVAILABLE = 503, "Service Unavailable";
    /// 504 Gateway Timeout.
    GATEWAY_TIMEOUT = 504, "Gateway Timeout";
    /// 505 HTTP Version Not Supported.
    HTTP_VERSION_NOT_SUPPORTED = 505, "HTTP Version Not Supported";
}

impl StatusCode {
    /// Creates a status code.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidInput`] when `code` is outside 100 to 599.
    pub const fn from_u16(code: u16) -> Result<StatusCode, InvalidInput> {
        if code >= 100 && code <= 599 {
            Ok(StatusCode(code))
        } else {
            Err(InvalidInput::new("status code outside 100 to 599"))
        }
    }

    /// The numeric code.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self.0
    }

    /// True for 1xx codes.
    #[must_use]
    pub const fn is_informational(self) -> bool {
        self.0 >= 100 && self.0 < 200
    }

    /// True for 2xx codes.
    #[must_use]
    pub const fn is_success(self) -> bool {
        self.0 >= 200 && self.0 < 300
    }

    /// True for 3xx codes.
    #[must_use]
    pub const fn is_redirection(self) -> bool {
        self.0 >= 300 && self.0 < 400
    }

    /// True for 4xx codes.
    #[must_use]
    pub const fn is_client_error(self) -> bool {
        self.0 >= 400 && self.0 < 500
    }

    /// True for 5xx codes.
    #[must_use]
    pub const fn is_server_error(self) -> bool {
        self.0 >= 500 && self.0 < 600
    }

    /// True when a response with this code never has content: 1xx, 204 and
    /// 304 (RFC 9112 section 6.3).
    #[must_use]
    pub const fn forbids_body(self) -> bool {
        self.is_informational() || self.0 == 204 || self.0 == 304
    }

    /// The three ASCII digits of the code.
    pub(crate) fn digits(self) -> [u8; 3] {
        let c = self.0;
        // `c` is at most 599, so each digit fits in a byte.
        let d = |v: u16| {
            u8::try_from(v.wrapping_rem(10))
                .unwrap_or(0)
                .wrapping_add(b'0')
        };
        [d(c.wrapping_div(100)), d(c.wrapping_div(10)), d(c)]
    }
}

impl fmt::Debug for StatusCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "StatusCode({})", self.0)
    }
}

impl fmt::Display for StatusCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reason = self.canonical_reason();
        if reason.is_empty() {
            write!(f, "{}", self.0)
        } else {
            write!(f, "{} {}", self.0, reason)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_and_digits() {
        assert!(StatusCode::from_u16(99).is_err());
        assert!(StatusCode::from_u16(600).is_err());
        assert_eq!(StatusCode::from_u16(100).unwrap().digits(), *b"100");
        assert_eq!(StatusCode::from_u16(599).unwrap().digits(), *b"599");
        assert_eq!(StatusCode::OK.digits(), *b"200");
        assert_eq!(
            StatusCode::from_u16(431).unwrap().canonical_reason(),
            "Request Header Fields Too Large"
        );
        assert_eq!(StatusCode::from_u16(299).unwrap().canonical_reason(), "");
        assert!(StatusCode::NOT_MODIFIED.forbids_body());
        assert!(!StatusCode::OK.forbids_body());
    }
}
