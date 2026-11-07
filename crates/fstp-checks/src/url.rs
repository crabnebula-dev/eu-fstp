//! Deliverable locations: the strict URL subset the checks fetch
//! (M5 design section 11, "Deliverable fetches").
//!
//! - Scheme `https`, or `http` for the e2e test cell's local forge only.
//!   The cell egress decides which scheme and host it reaches.
//! - The host is a DNS name of at least two labels, `localhost`, or a
//!   dotted IPv4 literal. IPv6 literals, user information, queries and
//!   fragments are refused, and so are dot segments in the path.
//! - The URL is at most [`MAX_URL`] bytes.
//!
//! The licence file of a release lives at
//! `<location>/raw/<release>/LICENSE`, the raw file route of Forgejo and
//! Gitea. The demo forge serves the same route.

use std::fmt;
use std::net::Ipv4Addr;

/// The longest URL the parser reads, in bytes.
pub const MAX_URL: usize = 2048;
/// The longest release identifier, in bytes.
pub const MAX_RELEASE: usize = 128;

/// The scheme of a deliverable URL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    /// TLS.
    Https,
    /// Plain text, for the e2e test cell's local forge only.
    Http,
}

/// A parsed deliverable URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeliverableUrl {
    scheme: Scheme,
    host: String,
    port: Option<u16>,
    path: String,
}

/// Why a URL was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UrlError {
    /// Longer than [`MAX_URL`].
    TooLong,
    /// Not `https://` or `http://`.
    Scheme,
    /// User information, which would carry credentials.
    UserInfo,
    /// A malformed or unsupported host, IPv6 literals included.
    Host,
    /// A malformed port.
    Port,
    /// A malformed path, a query or a fragment.
    Path,
    /// A malformed release identifier.
    Release,
}

impl fmt::Display for UrlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            UrlError::TooLong => "the address is too long",
            UrlError::Scheme => "the address does not start with https://",
            UrlError::UserInfo => "the address carries user information",
            UrlError::Host => "the host name is not valid",
            UrlError::Port => "the port is not valid",
            UrlError::Path => "the path is not valid or carries a query or fragment",
            UrlError::Release => "the release identifier is not valid",
        })
    }
}

fn strip_prefix_ci<'a>(s: &'a str, p: &str) -> Option<&'a str> {
    let head = s.get(..p.len())?;
    head.eq_ignore_ascii_case(p).then(|| s.get(p.len()..))?
}

fn label(l: &str) -> bool {
    !l.is_empty()
        && l.len() <= 63
        && !l.starts_with('-')
        && !l.ends_with('-')
        && l.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn host(raw: &str) -> Result<String, UrlError> {
    let h = raw.to_ascii_lowercase();
    let h = h.strip_suffix('.').unwrap_or(&h).to_owned();
    if h.is_empty() || h.len() > 253 {
        return Err(UrlError::Host);
    }
    let labels: Vec<&str> = h.split('.').collect();
    if !labels.iter().all(|l| label(l)) {
        return Err(UrlError::Host);
    }
    let last_numeric = labels
        .last()
        .is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit()));
    if last_numeric {
        return h
            .parse::<Ipv4Addr>()
            .map(|_| h.clone())
            .map_err(|_| UrlError::Host);
    }
    if labels.len() < 2 && h != "localhost" {
        return Err(UrlError::Host);
    }
    Ok(h)
}

fn path_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'-' | b'.'
                | b'_'
                | b'~'
                | b'!'
                | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'@'
                | b'/'
                | b'%'
        )
}

fn path(p: &str) -> Result<String, UrlError> {
    if p.is_empty() {
        return Ok("/".to_owned());
    }
    let b = p.as_bytes();
    if b.first() != Some(&b'/') || !b.iter().all(|x| path_byte(*x)) {
        return Err(UrlError::Path);
    }
    for (i, x) in b.iter().enumerate() {
        if *x == b'%' {
            let ok = b
                .get(i.saturating_add(1))
                .is_some_and(u8::is_ascii_hexdigit)
                && b.get(i.saturating_add(2))
                    .is_some_and(u8::is_ascii_hexdigit);
            if !ok {
                return Err(UrlError::Path);
            }
        }
    }
    if p.split('/').any(|s| s == "." || s == "..") {
        return Err(UrlError::Path);
    }
    Ok(p.to_owned())
}

impl DeliverableUrl {
    /// Parses `s`.
    ///
    /// # Errors
    ///
    /// A [`UrlError`] for any input outside the subset above.
    pub fn parse(s: &str) -> Result<DeliverableUrl, UrlError> {
        if s.len() > MAX_URL {
            return Err(UrlError::TooLong);
        }
        let (scheme, rest) = if let Some(r) = strip_prefix_ci(s, "https://") {
            (Scheme::Https, r)
        } else if let Some(r) = strip_prefix_ci(s, "http://") {
            (Scheme::Http, r)
        } else {
            return Err(UrlError::Scheme);
        };
        if rest.contains(['?', '#']) {
            return Err(UrlError::Path);
        }
        let (authority, p) = match rest.find('/') {
            Some(i) => (rest.get(..i).unwrap_or(""), rest.get(i..).unwrap_or("")),
            None => (rest, ""),
        };
        if authority.contains('@') {
            return Err(UrlError::UserInfo);
        }
        if authority.contains(['[', ']']) {
            return Err(UrlError::Host);
        }
        let (h, port) = match authority.split_once(':') {
            Some((h, p)) => {
                if p.is_empty() || p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(UrlError::Port);
                }
                let n: u16 = p.parse().map_err(|_| UrlError::Port)?;
                if n == 0 {
                    return Err(UrlError::Port);
                }
                (h, Some(n))
            }
            None => (authority, None),
        };
        Ok(DeliverableUrl {
            scheme,
            host: host(h)?,
            port,
            path: path(p)?,
        })
    }

    /// The scheme.
    pub fn scheme(&self) -> Scheme {
        self.scheme
    }

    /// The host, in lower case and without a trailing dot.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The host as an IPv4 literal, if it is one.
    pub fn ip_literal(&self) -> Option<Ipv4Addr> {
        self.host.parse().ok()
    }

    /// The port, or the scheme's default.
    pub fn port(&self) -> u16 {
        self.port.unwrap_or(match self.scheme {
            Scheme::Https => 443,
            Scheme::Http => 80,
        })
    }

    /// The path, starting with `/`.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The licence file of `release`: `<self>/raw/<release>/LICENSE`.
    ///
    /// # Errors
    ///
    /// [`UrlError::Release`] when `release` is empty, longer than
    /// [`MAX_RELEASE`], a dot segment, or holds a byte outside
    /// `[A-Za-z0-9._-]`. [`UrlError::TooLong`] when the result is.
    pub fn licence_file(&self, release: &str) -> Result<DeliverableUrl, UrlError> {
        let ok = !release.is_empty()
            && release.len() <= MAX_RELEASE
            && release != "."
            && release != ".."
            && release
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
        if !ok {
            return Err(UrlError::Release);
        }
        let path = format!("{}/raw/{release}/LICENSE", self.path.trim_end_matches('/'));
        let out = DeliverableUrl {
            path,
            ..self.clone()
        };
        if out.to_string().len() > MAX_URL {
            return Err(UrlError::TooLong);
        }
        Ok(out)
    }
}

impl fmt::Display for DeliverableUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let scheme = match self.scheme {
            Scheme::Https => "https",
            Scheme::Http => "http",
        };
        write!(f, "{scheme}://{}", self.host)?;
        if let Some(p) = self.port {
            write!(f, ":{p}")?;
        }
        if self.path == "/" {
            Ok(())
        } else {
            f.write_str(&self.path)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// M5 design section 11: the deliverable URL subset.
    #[test]
    fn deliverable_urls_accept_the_subset_and_refuse_the_rest() {
        let u = DeliverableUrl::parse("HTTPS://Forge.Example./synthetic/alpha").ok();
        assert_eq!(
            u.as_ref().map(ToString::to_string).as_deref(),
            Some("https://forge.example/synthetic/alpha")
        );
        let lic = u.and_then(|u| u.licence_file("v1.0.0").ok());
        assert_eq!(
            lic.map(|l| l.to_string()).as_deref(),
            Some("https://forge.example/synthetic/alpha/raw/v1.0.0/LICENSE")
        );
        assert!(DeliverableUrl::parse("http://127.0.0.1:8080/demo/forge/a").is_ok());
        assert!(DeliverableUrl::parse("http://localhost/x").is_ok());
        for bad in [
            "ftp://forge.example/a",
            "https://user:pw@forge.example/a",
            "https://forge.example/a?x=1",
            "https://forge.example/a#f",
            "https://[::1]/a",
            "https://intranet/a",
            "https://0x7f000001/a",
            "https://1.2.3/a",
            "https://forge.example:0/a",
            "https://forge.example:99999/a",
            "https://forge.example/a/../b",
            "https://forge.example/a b",
            "https://forge.example/%zz",
            "https://-bad.example/a",
        ] {
            assert!(DeliverableUrl::parse(bad).is_err(), "{bad}");
        }
        let base = DeliverableUrl::parse("https://forge.example/a").ok();
        for bad in ["", "..", "v1/../x", "v 1", "v1?"] {
            assert!(
                base.as_ref().is_some_and(|b| b.licence_file(bad).is_err()),
                "{bad}"
            );
        }
    }
}
