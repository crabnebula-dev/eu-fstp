//! Request targets (RFC 9112 section 3.2) and absolute `http` and `https`
//! URLs.
//!
//! Every constructor validates its input against the RFC 3986 grammar, so a
//! [`RequestTarget`] never holds SP, CR, LF or another byte that could split
//! a request line.

use std::fmt;
use std::net::Ipv6Addr;

use crate::chars::{is_pchar_plain, is_sub_delim, is_unreserved, valid_pct_str};
use crate::error::InvalidInput;
use crate::method::Method;

/// URL scheme of an absolute-form target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scheme {
    /// `http`, default port 80.
    Http,
    /// `https`, default port 443.
    Https,
}

impl Scheme {
    /// The scheme in lowercase.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Scheme::Http => "http",
            Scheme::Https => "https",
        }
    }

    /// The default port.
    #[must_use]
    pub const fn default_port(self) -> u16 {
        match self {
            Scheme::Http => 80,
            Scheme::Https => 443,
        }
    }
}

/// The authority of a URL or a Host value: `uri-host [ ":" port ]`.
///
/// User information (`user@`) is rejected, as RFC 9110 section 4.2.4
/// advises for `http` and `https`.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Authority {
    text: Box<str>,
    host: Box<str>,
    port: Option<u16>,
}

impl Authority {
    /// Parses `uri-host [ ":" port ]`. The host must not be empty.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidInput`] for an empty or malformed host, user
    /// information, or a port above 65535.
    pub fn parse(s: &str) -> Result<Authority, InvalidInput> {
        parse_authority(s.as_bytes()).ok_or(InvalidInput::new("malformed authority"))
    }

    /// The authority exactly as received or given.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The host. An IPv6 literal keeps its brackets.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The host without IPv6 brackets, as used for name resolution and TLS
    /// server names.
    #[must_use]
    pub fn host_for_connect(&self) -> &str {
        self.host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(&self.host)
    }

    /// The explicit port, if any.
    #[must_use]
    pub fn port(&self) -> Option<u16> {
        self.port
    }
}

impl fmt::Debug for Authority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Authority({:?})", &*self.text)
    }
}

/// Which of the request-target forms a target uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TargetForm {
    /// `absolute-path [ "?" query ]`, the usual form.
    Origin,
    /// `absolute-URI`, with scheme and authority.
    Absolute,
    /// `*`, for server-wide OPTIONS.
    Asterisk,
}

/// A validated request target.
///
/// CONNECT's authority-form is not supported. The parser rejects CONNECT
/// with 501 before it reaches the target.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct RequestTarget {
    repr: Repr,
}

#[derive(Clone, PartialEq, Eq, Hash)]
enum Repr {
    Origin {
        path_and_query: Box<str>,
    },
    Absolute {
        scheme: Scheme,
        authority: Authority,
        path_and_query: Box<str>,
    },
    Asterisk,
}

impl RequestTarget {
    /// An origin-form target such as `/a/b?c=d`.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidInput`] unless `path_and_query` starts with `/` and
    /// follows the RFC 3986 path and query grammar. Fragments are rejected.
    pub fn origin(path_and_query: &str) -> Result<RequestTarget, InvalidInput> {
        let b = path_and_query.as_bytes();
        if b.first() != Some(&b'/') || !valid_path_and_query(b) {
            return Err(InvalidInput::new("malformed origin-form target"));
        }
        Ok(RequestTarget {
            repr: Repr::Origin {
                path_and_query: path_and_query.into(),
            },
        })
    }

    /// An absolute `http` or `https` URL such as `https://host:8443/x?y`.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidInput`] for another scheme, a missing or empty host,
    /// user information, a fragment, or any byte outside the grammar.
    pub fn absolute(url: &str) -> Result<RequestTarget, InvalidInput> {
        parse_absolute(url.as_bytes()).ok_or(InvalidInput::new("malformed absolute URL"))
    }

    /// The asterisk-form target `*`.
    #[must_use]
    pub fn asterisk() -> RequestTarget {
        RequestTarget {
            repr: Repr::Asterisk,
        }
    }

    /// Parses a request target as received on the request line.
    pub(crate) fn parse_wire(t: &[u8], method: &Method) -> Option<RequestTarget> {
        match t.first()? {
            b'/' => {
                if !valid_path_and_query(t) {
                    return None;
                }
                let s = std::str::from_utf8(t).ok()?;
                Some(RequestTarget {
                    repr: Repr::Origin {
                        path_and_query: s.into(),
                    },
                })
            }
            b'*' => (t.len() == 1 && *method == Method::OPTIONS).then(RequestTarget::asterisk),
            _ => parse_absolute(t),
        }
    }

    /// Which form this target uses.
    #[must_use]
    pub fn form(&self) -> TargetForm {
        match self.repr {
            Repr::Origin { .. } => TargetForm::Origin,
            Repr::Absolute { .. } => TargetForm::Absolute,
            Repr::Asterisk => TargetForm::Asterisk,
        }
    }

    /// Path and query. For an absolute target with an empty path this is
    /// empty; [`RequestTarget::path`] still returns `/`. For `*` it is `*`.
    #[must_use]
    pub fn path_and_query(&self) -> &str {
        match &self.repr {
            Repr::Origin { path_and_query } | Repr::Absolute { path_and_query, .. } => {
                path_and_query
            }
            Repr::Asterisk => "*",
        }
    }

    /// The path, still percent-encoded. An empty path reads as `/`.
    #[must_use]
    pub fn path(&self) -> &str {
        let pq = self.path_and_query();
        let path = pq.split_once('?').map_or(pq, |(p, _)| p);
        if path.is_empty() { "/" } else { path }
    }

    /// The query without the leading `?`, if present.
    #[must_use]
    pub fn query(&self) -> Option<&str> {
        self.path_and_query().split_once('?').map(|(_, q)| q)
    }

    /// The scheme of an absolute-form target.
    #[must_use]
    pub fn scheme(&self) -> Option<Scheme> {
        match &self.repr {
            Repr::Absolute { scheme, .. } => Some(*scheme),
            _ => None,
        }
    }

    /// The authority of an absolute-form target.
    #[must_use]
    pub fn authority(&self) -> Option<&Authority> {
        match &self.repr {
            Repr::Absolute { authority, .. } => Some(authority),
            _ => None,
        }
    }

    /// The origin-form equivalent: path and query, with `/` for an empty
    /// path. Clients send this on the request line.
    #[must_use]
    pub fn to_origin_form(&self) -> RequestTarget {
        match &self.repr {
            Repr::Absolute { path_and_query, .. } => {
                let pq: Box<str> = if path_and_query.is_empty() || path_and_query.starts_with('?') {
                    format!("/{path_and_query}").into()
                } else {
                    path_and_query.clone()
                };
                RequestTarget {
                    repr: Repr::Origin { path_and_query: pq },
                }
            }
            _ => self.clone(),
        }
    }

    /// Appends the wire form of the target to `out`.
    pub(crate) fn write_to(&self, out: &mut Vec<u8>) {
        match &self.repr {
            Repr::Origin { path_and_query } => out.extend_from_slice(path_and_query.as_bytes()),
            Repr::Absolute {
                scheme,
                authority,
                path_and_query,
            } => {
                out.extend_from_slice(scheme.as_str().as_bytes());
                out.extend_from_slice(b"://");
                out.extend_from_slice(authority.as_str().as_bytes());
                out.extend_from_slice(path_and_query.as_bytes());
            }
            Repr::Asterisk => out.push(b'*'),
        }
    }

    /// The wire form of the target.
    #[must_use]
    pub fn to_wire_string(&self) -> String {
        let mut out = Vec::new();
        self.write_to(&mut out);
        // Every stored component is ASCII by construction.
        String::from_utf8_lossy(&out).into_owned()
    }
}

impl fmt::Debug for RequestTarget {
    /// Shows only the form and the length. Paths and queries can carry
    /// identifiers, which must not reach logs (R-NF-02).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RequestTarget({:?}, <redacted {} bytes>)",
            self.form(),
            self.path_and_query().len()
        )
    }
}

/// `absolute-path [ "?" query ]` for origin-form, or `path-abempty [ "?"
/// query ]` for absolute-form. The caller checks the leading `/` where it is
/// required.
fn valid_path_and_query(b: &[u8]) -> bool {
    let (path, query) = match b.iter().position(|&c| c == b'?') {
        Some(i) => (b.get(..i).unwrap_or_default(), b.get(i.saturating_add(1)..)),
        None => (b, None),
    };
    if !path.is_empty() && path.first() != Some(&b'/') {
        return false;
    }
    if !valid_pct_str(path, |c| is_pchar_plain(c) || c == b'/') {
        return false;
    }
    match query {
        Some(q) => valid_pct_str(q, |c| is_pchar_plain(c) || c == b'/' || c == b'?'),
        None => true,
    }
}

fn parse_absolute(b: &[u8]) -> Option<RequestTarget> {
    let colon = b.iter().position(|&c| c == b':')?;
    let scheme_bytes = b.get(..colon)?;
    let scheme = if scheme_bytes.eq_ignore_ascii_case(b"http") {
        Scheme::Http
    } else if scheme_bytes.eq_ignore_ascii_case(b"https") {
        Scheme::Https
    } else {
        return None;
    };
    let rest = b.get(colon.saturating_add(1)..)?;
    let rest = rest.strip_prefix(b"//")?;
    let auth_end = rest
        .iter()
        .position(|&c| c == b'/' || c == b'?')
        .unwrap_or(rest.len());
    let authority = parse_authority(rest.get(..auth_end)?)?;
    let pq = rest.get(auth_end..)?;
    if !valid_path_and_query(pq) {
        return None;
    }
    let pq = std::str::from_utf8(pq).ok()?;
    Some(RequestTarget {
        repr: Repr::Absolute {
            scheme,
            authority,
            path_and_query: pq.into(),
        },
    })
}

/// Parses `uri-host [ ":" port ]` with a non-empty host and no user
/// information.
fn parse_authority(b: &[u8]) -> Option<Authority> {
    let (host, port_part) = if b.first() == Some(&b'[') {
        let close = b.iter().position(|&c| c == b']')?;
        let host = b.get(..=close)?;
        let inner = std::str::from_utf8(host.get(1..close)?).ok()?;
        // IPvFuture and zone identifiers are not supported.
        inner.parse::<Ipv6Addr>().ok()?;
        let after = b.get(close.saturating_add(1)..)?;
        let port_part = match after.first() {
            None => None,
            Some(b':') => Some(after.get(1..)?),
            Some(_) => return None,
        };
        (host, port_part)
    } else {
        let (host, port_part) = match b.iter().position(|&c| c == b':') {
            Some(i) => (b.get(..i)?, Some(b.get(i.saturating_add(1)..)?)),
            None => (b, None),
        };
        // reg-name / IPv4address. `@` (user information) is not part of
        // this set, so it is rejected here.
        if host.is_empty() || !valid_pct_str(host, |c| is_unreserved(c) || is_sub_delim(c)) {
            return None;
        }
        (host, port_part)
    };
    let port = match port_part {
        None => None,
        Some([]) => None,
        Some(p) => Some(parse_port(p)?),
    };
    Some(Authority {
        text: std::str::from_utf8(b).ok()?.into(),
        host: std::str::from_utf8(host).ok()?.into(),
        port,
    })
}

fn parse_port(p: &[u8]) -> Option<u16> {
    if p.len() > 5 || !p.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let mut v: u32 = 0;
    for &d in p {
        v = v
            .checked_mul(10)?
            .checked_add(u32::from(d.wrapping_sub(b'0')))?;
    }
    u16::try_from(v).ok()
}

/// Validates a Host field value. An empty value is allowed when the target
/// has no authority (RFC 9112 section 3.2).
pub(crate) fn valid_host_value(v: &[u8]) -> bool {
    v.is_empty() || parse_authority(v).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_form() {
        let t = RequestTarget::origin("/a/b%20c?x=1&y=/?").unwrap();
        assert_eq!(t.path(), "/a/b%20c");
        assert_eq!(t.query(), Some("x=1&y=/?"));
        assert!(RequestTarget::origin("a").is_err());
        assert!(RequestTarget::origin("/a b").is_err());
        assert!(RequestTarget::origin("/a#f").is_err());
        assert!(RequestTarget::origin("/a%zz").is_err());
        assert!(RequestTarget::origin("/\u{e9}").is_err());
        assert!(RequestTarget::origin("/a\r\nX: y").is_err());
    }

    #[test]
    fn absolute_form() {
        let t = RequestTarget::absolute("HTTPS://Example.com:8443/p?q").unwrap();
        assert_eq!(t.scheme(), Some(Scheme::Https));
        assert_eq!(t.authority().unwrap().host(), "Example.com");
        assert_eq!(t.authority().unwrap().port(), Some(8443));
        assert_eq!(t.path(), "/p");
        assert_eq!(t.to_wire_string(), "https://Example.com:8443/p?q");
        let t = RequestTarget::absolute("http://[::1]:80").unwrap();
        assert_eq!(t.authority().unwrap().host_for_connect(), "::1");
        assert_eq!(t.path(), "/");
        assert_eq!(t.to_origin_form().path_and_query(), "/");
        let t = RequestTarget::absolute("http://h?x").unwrap();
        assert_eq!(t.to_origin_form().path_and_query(), "/?x");
        for bad in [
            "ftp://h/",
            "http:/h",
            "http://",
            "http://u@h/",
            "http://h:99999/",
            "http://h:8x/",
            "http://[zz]/",
            "http://h/#f",
            "http://h p/",
        ] {
            assert!(RequestTarget::absolute(bad).is_err(), "{bad}");
        }
        assert!(
            RequestTarget::absolute("http://h:/")
                .unwrap()
                .authority()
                .unwrap()
                .port()
                .is_none()
        );
    }

    #[test]
    fn host_values() {
        assert!(valid_host_value(b""));
        assert!(valid_host_value(b"example.com"));
        assert!(valid_host_value(b"example.com:80"));
        assert!(valid_host_value(b"[::1]:8080"));
        assert!(!valid_host_value(b"a b"));
        assert!(!valid_host_value(b"u@h"));
        assert!(!valid_host_value(b"h:1:2"));
        assert!(!valid_host_value(b":80"));
    }

    #[test]
    fn asterisk_only_for_options() {
        assert!(RequestTarget::parse_wire(b"*", &Method::OPTIONS).is_some());
        assert!(RequestTarget::parse_wire(b"*", &Method::GET).is_none());
        assert!(RequestTarget::parse_wire(b"**", &Method::OPTIONS).is_none());
    }
}
