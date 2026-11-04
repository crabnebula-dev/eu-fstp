//! The strict URL subset of ADR-013 (TW-4) and redirect matching.
//!
//! The parser accepts absolute `https` URIs and `http` URIs to a loopback
//! host, in ASCII only. It refuses userinfo, fragments, non-ASCII hosts,
//! uppercase schemes and hosts, dot segments, bad percent-encoding and
//! leading zeros in ports. An accepted URL is kept byte for byte, so the
//! parser never normalises and matching compares the written text.

use crate::OauthError;

/// The longest URL [`parse_url`] reads, in bytes.
pub const MAX_URL_LEN: usize = 2048;

/// Why a URL is outside the strict subset.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum UrlError {
    /// Empty or longer than [`MAX_URL_LEN`].
    Length,
    /// A byte outside visible ASCII: a space, a control character or
    /// non-ASCII text.
    Character,
    /// A fragment, empty or not.
    Fragment,
    /// Not `https://` or `http://`, in lowercase.
    Scheme,
    /// Userinfo before the host.
    Userinfo,
    /// A host outside the subset.
    Host,
    /// A port outside 1 to 65535, empty, or with a leading zero.
    Port,
    /// Plain `http` to a host that is not a loopback host.
    PlainHttp,
    /// A path or query character the subset refuses.
    Path,
    /// A `%` not followed by two hexadecimal digits.
    PercentEncoding,
    /// A `.` or `..` path segment.
    DotSegment,
}

impl std::fmt::Display for UrlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            UrlError::Length => "the URL is empty or too long",
            UrlError::Character => "the URL holds a byte outside visible ASCII",
            UrlError::Fragment => "the URL holds a fragment",
            UrlError::Scheme => "the scheme is not https or http",
            UrlError::Userinfo => "the URL holds userinfo",
            UrlError::Host => "the host is outside the subset",
            UrlError::Port => "the port is outside the subset",
            UrlError::PlainHttp => "plain http is allowed to a loopback host only",
            UrlError::Path => "the path or query holds a refused character",
            UrlError::PercentEncoding => "the URL holds bad percent-encoding",
            UrlError::DotSegment => "the path holds a dot segment",
        };
        f.write_str(s)
    }
}

/// The scheme of a URL in the subset.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Scheme {
    /// `https`.
    Https,
    /// `http`, to a loopback host only.
    Http,
}

/// A parsed URL of the strict subset.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Url {
    text: String,
    scheme: Scheme,
    host: String,
    port: Option<u16>,
    rest_start: usize,
}

impl Url {
    /// The URL as written.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The scheme.
    pub fn scheme(&self) -> Scheme {
        self.scheme
    }

    /// The host as written: a lowercase DNS name, a dotted IPv4 literal or
    /// `[::1]`.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port, when written.
    pub fn port(&self) -> Option<u16> {
        self.port
    }

    /// The path and query as written, possibly empty.
    pub fn path_and_query(&self) -> &str {
        self.text.get(self.rest_start..).unwrap_or("")
    }

    /// Whether the URL has a query.
    pub fn has_query(&self) -> bool {
        self.path_and_query().contains('?')
    }

    /// Whether this is a loopback redirect for a native client: `http` to
    /// `127.0.0.1`, `[::1]` or `localhost` (RFC 8252 sections 7.3 and 8.3).
    pub fn is_loopback(&self) -> bool {
        self.scheme == Scheme::Http && is_loopback_host(&self.host)
    }

    /// The scheme, host and port, with no path.
    pub fn origin(&self) -> &str {
        self.text.get(..self.rest_start).unwrap_or("")
    }
}

impl std::fmt::Display for Url {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text)
    }
}

fn is_loopback_host(host: &str) -> bool {
    host == "127.0.0.1" || host == "[::1]" || host == "localhost"
}

fn is_hex(b: u8) -> bool {
    b.is_ascii_hexdigit()
}

fn valid_ipv4(host: &str) -> bool {
    let mut n = 0usize;
    for part in host.split('.') {
        n = n.saturating_add(1);
        if part.is_empty() || part.len() > 3 || (part.len() > 1 && part.starts_with('0')) {
            return false;
        }
        match part.parse::<u16>() {
            Ok(v) if v <= 255 => {}
            _ => return false,
        }
    }
    n == 4
}

/// Whether the last label of `host` is a number to a WHATWG URL parser:
/// all digits, or `0x` followed by hexadecimal digits or by nothing. A
/// browser then reads the whole host as IPv4, so the host shown on the
/// consent page would not be the host the browser goes to (TW-4, TW-8).
fn ends_in_a_number(host: &str) -> bool {
    let last = host.rsplit('.').next().unwrap_or("");
    let all_digits = !last.is_empty() && last.bytes().all(|b| b.is_ascii_digit());
    let hex = last
        .strip_prefix("0x")
        .is_some_and(|h| h.bytes().all(|b| b.is_ascii_hexdigit()));
    all_digits || hex
}

fn valid_dns(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 || ends_in_a_number(host) {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    })
}

fn valid_host(host: &str) -> bool {
    if host == "[::1]" {
        return true;
    }
    if host.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return valid_ipv4(host);
    }
    valid_dns(host)
}

fn parse_port(digits: &str) -> Result<u16, UrlError> {
    if digits.is_empty()
        || digits.len() > 5
        || digits.starts_with('0')
        || !digits.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(UrlError::Port);
    }
    match digits.parse::<u16>() {
        Ok(p) if p > 0 => Ok(p),
        _ => Err(UrlError::Port),
    }
}

/// Characters RFC 3986 allows in a path or query, beside `%XX`.
fn path_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@/?".contains(&b)
}

fn check_rest(rest: &str) -> Result<(), UrlError> {
    if !rest.is_empty() && !rest.starts_with('/') && !rest.starts_with('?') {
        return Err(UrlError::Path);
    }
    let bytes = rest.as_bytes();
    let mut i = 0usize;
    while let Some(&b) = bytes.get(i) {
        if b == b'%' {
            let hi = bytes.get(i.saturating_add(1)).copied();
            let lo = bytes.get(i.saturating_add(2)).copied();
            match (hi, lo) {
                (Some(h), Some(l)) if is_hex(h) && is_hex(l) => i = i.saturating_add(3),
                _ => return Err(UrlError::PercentEncoding),
            }
            continue;
        }
        if !path_byte(b) {
            return Err(UrlError::Path);
        }
        i = i.saturating_add(1);
    }
    let path = rest.split('?').next().unwrap_or("");
    for segment in path.split('/') {
        let dots = segment.replace("%2e", ".").replace("%2E", ".");
        if dots == "." || dots == ".." {
            return Err(UrlError::DotSegment);
        }
    }
    Ok(())
}

fn parse_inner(bytes: &[u8]) -> Result<Url, UrlError> {
    if bytes.is_empty() || bytes.len() > MAX_URL_LEN {
        return Err(UrlError::Length);
    }
    if !bytes.iter().all(|b| (0x21..=0x7e).contains(b)) {
        return Err(UrlError::Character);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| UrlError::Character)?;
    if text.contains('#') {
        return Err(UrlError::Fragment);
    }
    let (scheme, after) = if let Some(a) = text.strip_prefix("https://") {
        (Scheme::Https, a)
    } else if let Some(a) = text.strip_prefix("http://") {
        (Scheme::Http, a)
    } else {
        return Err(UrlError::Scheme);
    };
    let authority_len = after.find(['/', '?']).unwrap_or(after.len());
    let (authority, rest) = after.split_at(authority_len);
    if authority.contains('@') {
        return Err(UrlError::Userinfo);
    }
    let (host, port) = if authority.starts_with('[') {
        let close = authority.find(']').ok_or(UrlError::Host)?;
        authority.split_at(close.saturating_add(1))
    } else {
        match authority.find(':') {
            Some(i) => authority.split_at(i),
            None => (authority, ""),
        }
    };
    if !valid_host(host) {
        return Err(UrlError::Host);
    }
    let port = if port.is_empty() {
        None
    } else {
        let digits = port.strip_prefix(':').ok_or(UrlError::Port)?;
        Some(parse_port(digits)?)
    };
    if scheme == Scheme::Http && !is_loopback_host(host) {
        return Err(UrlError::PlainHttp);
    }
    check_rest(rest)?;
    let rest_start = text.len().saturating_sub(rest.len());
    Ok(Url {
        text: text.to_owned(),
        scheme,
        host: host.to_owned(),
        port,
        rest_start,
    })
}

/// Parses a URL in the strict RFC 3986 subset. Fuzzed (`url_parse`).
pub fn parse_url(bytes: &[u8]) -> Result<Url, OauthError> {
    parse_inner(bytes).map_err(OauthError::Url)
}

/// Whether `presented` matches `registered` (ADR-013, TW-4): byte for
/// byte, except the port of a loopback redirect (RFC 8252 section 7.3).
/// A loopback match keeps the scheme, the host as written and the path
/// and query as written.
pub fn redirect_matches(registered: &Url, presented: &Url) -> bool {
    if registered.is_loopback() {
        return presented.is_loopback()
            && registered.host == presented.host
            && registered.path_and_query() == presented.path_and_query();
    }
    registered.text == presented.text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(s: &str) -> Url {
        match parse_url(s.as_bytes()) {
            Ok(u) => u,
            Err(e) => panic!("{s} refused: {e}"),
        }
    }

    /// ADR-013, TW-4: the parts of an accepted URL.
    #[test]
    fn adr013_url_parts() {
        let u = ok("https://agent.example:8443/a/b?x=1");
        assert_eq!(u.host(), "agent.example");
        assert_eq!(u.port(), Some(8443));
        assert_eq!(u.path_and_query(), "/a/b?x=1");
        assert_eq!(u.origin(), "https://agent.example:8443");
        assert!(u.has_query());
        assert!(ok("http://[::1]:5/cb").is_loopback());
        assert!(ok("http://localhost/cb").is_loopback());
        assert!(!ok("https://127.0.0.1/cb").is_loopback());
    }

    /// ADR-013, TW-4: refusals beyond the shared test list.
    #[test]
    fn adr013_url_refusals() {
        for s in [
            "https://agent.example/./cb",
            "https://agent.example/a/../cb",
            "https://agent.example/%2E%2e/cb",
            "https://agent.example:080/cb",
            "https://agent.example:/cb",
            "https://agent.example:0/cb",
            "https://Agent.example/cb",
            "HTTPS://agent.example/cb",
            "https://agent.example./cb",
            "https://-agent.example/cb",
            "https://256.1.1.1/cb",
            "https://01.1.1.1/cb",
            "https://[::2]/cb",
            "https://agent.example/a%zz",
            "https://agent.example/a\\b",
            "https://agent.example/a<b",
            "https:///cb",
            "http://127.0.0.2/cb",
            "http://10.0.0.1/cb",
            "https://0x7f.0.0.1/cb",
            "https://0x7f.1/cb",
            "https://0x7f000001/cb",
            "https://agent.0x/cb",
            "https://agent.example.1/cb",
            "https://1.2.3.04a.5/cb",
            "https://127.1/cb",
        ] {
            assert!(parse_url(s.as_bytes()).is_err(), "{s} accepted");
        }
    }

    /// ADR-013, TW-4: a host whose last label is only partly numeric is a
    /// DNS name, as a WHATWG parser reads it too.
    #[test]
    fn adr013_url_last_label_not_numeric_is_dns() {
        for s in [
            "https://agent.0xg/cb",
            "https://1.2.3.4a/cb",
            "https://0x7f.agent/cb",
        ] {
            assert!(parse_url(s.as_bytes()).is_ok(), "{s} refused");
        }
    }

    /// ADR-013, TW-4: loopback redirects match with any port.
    #[test]
    fn adr013_loopback_port_varies() {
        let r = ok("http://127.0.0.1/cb");
        assert!(redirect_matches(&r, &ok("http://127.0.0.1:9/cb")));
        assert!(!redirect_matches(&r, &ok("http://[::1]:9/cb")));
        assert!(!redirect_matches(&r, &ok("http://127.0.0.1:9/cb/")));
        let h = ok("https://agent.example/cb");
        assert!(redirect_matches(&h, &ok("https://agent.example/cb")));
        assert!(!redirect_matches(&h, &ok("https://agent.example:443/cb")));
    }
}
