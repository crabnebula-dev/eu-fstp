//! HTTP versions this crate speaks.

use std::fmt;

/// An HTTP/1.x protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Version {
    /// HTTP/1.0.
    Http10,
    /// HTTP/1.1. Received minor versions above 1 are treated as 1.1
    /// (RFC 9110 section 2.5).
    Http11,
}

impl Version {
    /// The version as it appears on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Version::Http10 => "HTTP/1.0",
            Version::Http11 => "HTTP/1.1",
        }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Outcome of parsing an `HTTP-version` token.
pub(crate) enum VersionParse {
    Ok(Version),
    /// Grammatically valid, but the major version is not 1.
    Unsupported,
    /// Not `HTTP/DIGIT.DIGIT`.
    Invalid,
}

/// Parses `HTTP-version = HTTP-name "/" DIGIT "." DIGIT`, case-sensitively.
pub(crate) fn parse_version(v: &[u8]) -> VersionParse {
    let [b'H', b'T', b'T', b'P', b'/', major, b'.', minor] = *v else {
        return VersionParse::Invalid;
    };
    if !major.is_ascii_digit() || !minor.is_ascii_digit() {
        return VersionParse::Invalid;
    }
    if major != b'1' {
        return VersionParse::Unsupported;
    }
    if minor == b'0' {
        VersionParse::Ok(Version::Http10)
    } else {
        VersionParse::Ok(Version::Http11)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions() {
        assert!(matches!(
            parse_version(b"HTTP/1.1"),
            VersionParse::Ok(Version::Http11)
        ));
        assert!(matches!(
            parse_version(b"HTTP/1.0"),
            VersionParse::Ok(Version::Http10)
        ));
        assert!(matches!(
            parse_version(b"HTTP/1.9"),
            VersionParse::Ok(Version::Http11)
        ));
        assert!(matches!(
            parse_version(b"HTTP/2.0"),
            VersionParse::Unsupported
        ));
        assert!(matches!(
            parse_version(b"HTTP/0.9"),
            VersionParse::Unsupported
        ));
        assert!(matches!(parse_version(b"http/1.1"), VersionParse::Invalid));
        assert!(matches!(parse_version(b"HTTP/1.10"), VersionParse::Invalid));
        assert!(matches!(parse_version(b"HTTP/1"), VersionParse::Invalid));
        assert!(matches!(parse_version(b"HTTP/a.1"), VersionParse::Invalid));
    }
}
