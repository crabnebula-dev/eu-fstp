//! The `Origin` header parser (ADR-014 "CSRF", TH-26, H-05).

use std::fmt;

use crate::WebError;

/// The longest host, in bytes (RFC 1035 section 2.3.4).
const MAX_HOST: usize = 253;

/// The longest host label, in bytes.
const MAX_LABEL: usize = 63;

/// The scheme of an origin.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OriginScheme {
    /// `http`.
    Http,
    /// `https`.
    Https,
}

impl OriginScheme {
    /// The scheme name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            OriginScheme::Http => "http",
            OriginScheme::Https => "https",
        }
    }

    /// The default port of the scheme.
    #[must_use]
    pub const fn default_port(self) -> u16 {
        match self {
            OriginScheme::Http => 80,
            OriginScheme::Https => 443,
        }
    }
}

/// A parsed serialised origin (RFC 6454 section 6.1): a scheme, a host
/// and an optional port.
///
/// Interim, pending Daniel: the parser accepts one spelling per origin
/// only. The host is lowercase ASCII letters, digits and `-` in labels
/// separated by `.`, and an explicit default port is refused. So two
/// parsed values are equal exactly when their texts are.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Origin {
    scheme: OriginScheme,
    host: String,
    port: Option<u16>,
}

impl Origin {
    /// The scheme.
    #[must_use]
    pub fn scheme(&self) -> OriginScheme {
        self.scheme
    }

    /// The host, in lowercase.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The explicit port, which is never the scheme's default.
    #[must_use]
    pub fn port(&self) -> Option<u16> {
        self.port
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://{}", self.scheme.as_str(), self.host)?;
        if let Some(p) = self.port {
            write!(f, ":{p}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Origin({self})")
    }
}

/// Parses an `Origin` header value. Fuzzed (`origin_header_parse`).
///
/// The value is one serialised origin: `http://` or `https://`, a host of
/// lowercase DNS labels, and an optional `:` with a port from 1 to 65535
/// that is not the scheme's default and has no leading zero. A list,
/// `null`, a path, a query, a fragment, userinfo, an IP literal in
/// brackets, white space and non-ASCII bytes are refused. A duplicated
/// field is refused by the caller, which sees every field line.
///
/// # Errors
///
/// [`WebError::BadOrigin`] for every other value.
pub fn parse_origin_header(bytes: &[u8]) -> Result<Origin, WebError> {
    let (scheme, rest) = if let Some(rest) = bytes.strip_prefix(b"https://") {
        (OriginScheme::Https, rest)
    } else if let Some(rest) = bytes.strip_prefix(b"http://") {
        (OriginScheme::Http, rest)
    } else {
        return Err(WebError::BadOrigin);
    };
    let (host, port) = match rest.iter().position(|b| *b == b':') {
        Some(i) => {
            let (h, p) = rest.split_at(i);
            (h, Some(p.get(1..).ok_or(WebError::BadOrigin)?))
        }
        None => (rest, None),
    };
    let host = parse_host(host)?;
    let port = match port {
        None => None,
        Some(p) => {
            let n = parse_port(p)?;
            if n == scheme.default_port() {
                return Err(WebError::BadOrigin);
            }
            Some(n)
        }
    };
    Ok(Origin { scheme, host, port })
}

/// A host of lowercase DNS labels.
fn parse_host(host: &[u8]) -> Result<String, WebError> {
    if host.is_empty() || host.len() > MAX_HOST {
        return Err(WebError::BadOrigin);
    }
    for label in host.split(|b| *b == b'.') {
        let (Some(first), Some(last)) = (label.first(), label.last()) else {
            return Err(WebError::BadOrigin);
        };
        if label.len() > MAX_LABEL || *first == b'-' || *last == b'-' {
            return Err(WebError::BadOrigin);
        }
        if !label
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
        {
            return Err(WebError::BadOrigin);
        }
    }
    let text = std::str::from_utf8(host).map_err(|_| WebError::BadOrigin)?;
    Ok(text.to_owned())
}

/// A port from 1 to 65535 in plain digits with no leading zero.
fn parse_port(p: &[u8]) -> Result<u16, WebError> {
    if p.is_empty() || p.len() > 5 || p.first() == Some(&b'0') {
        return Err(WebError::BadOrigin);
    }
    let mut n: u32 = 0;
    for b in p {
        let d = match b {
            b'0'..=b'9' => u32::from(b.saturating_sub(b'0')),
            _ => return Err(WebError::BadOrigin),
        };
        n = n
            .checked_mul(10)
            .and_then(|v| v.checked_add(d))
            .ok_or(WebError::BadOrigin)?;
    }
    u16::try_from(n).map_err(|_| WebError::BadOrigin)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ADR-014: the default port and leading zeros are refused, and the
    /// serialised form round-trips.
    #[test]
    fn adr014_origin_one_spelling_only() {
        assert!(parse_origin_header(b"https://a.test:443").is_err());
        assert!(parse_origin_header(b"http://a.test:80").is_err());
        assert!(parse_origin_header(b"https://a.test:080").is_err());
        assert!(parse_origin_header(b"https://A.test").is_err());
        assert!(parse_origin_header(b"https://-a.test").is_err());
        let text = "https://a-1.test:8443";
        let o = parse_origin_header(text.as_bytes()).map(|o| o.to_string());
        assert_eq!(o.as_deref(), Ok(text));
    }
}
