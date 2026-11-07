//! Absolute `http` and `https` URLs in one canonical form.
//!
//! The parser accepts a strict subset of RFC 3986 so that the proxy, the
//! policy and the classing rule all read the same host and path:
//!
//! - the scheme is `http` or `https`, in any case;
//! - user information is refused;
//! - the host is a dotted name of ASCII letters, digits and hyphens, or a
//!   bracketed IPv6 literal. A percent sign or any other byte refuses it.
//!   One trailing dot is removed and the host is lowercased;
//! - an explicit default port is removed;
//! - the path and query are percent-normalised: unreserved characters are
//!   decoded, other escapes are uppercased, and bytes outside the grammar
//!   are encoded. Dot segments are removed;
//! - the fragment is dropped, since it is never sent.

use crate::refusal::Refusal;

/// The longest URL accepted, in bytes.
pub const MAX_URL_BYTES: usize = 2048;

/// The scheme of a [`SourceUrl`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UrlScheme {
    /// Plain HTTP.
    Http,
    /// HTTP over TLS.
    Https,
}

impl UrlScheme {
    fn as_str(self) -> &'static str {
        match self {
            UrlScheme::Http => "http",
            UrlScheme::Https => "https",
        }
    }

    fn default_port(self) -> u16 {
        match self {
            UrlScheme::Http => 80,
            UrlScheme::Https => 443,
        }
    }
}

/// A parsed absolute URL in canonical form.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SourceUrl {
    scheme: UrlScheme,
    host: String,
    port: Option<u16>,
    path: String,
    query: Option<String>,
    serial: String,
}

impl SourceUrl {
    /// Parses an absolute URL.
    ///
    /// # Errors
    ///
    /// [`Refusal::UrlTooLong`] above [`MAX_URL_BYTES`], otherwise
    /// [`Refusal::MalformedUrl`] for anything outside the accepted grammar.
    pub fn parse(input: &str) -> Result<SourceUrl, Refusal> {
        if input.len() > MAX_URL_BYTES {
            return Err(Refusal::UrlTooLong);
        }
        if input.bytes().any(|b| b <= b' ' || b == 0x7f) {
            return Err(Refusal::MalformedUrl);
        }
        let (scheme, rest) = input.split_once("://").ok_or(Refusal::MalformedUrl)?;
        let scheme = if scheme.eq_ignore_ascii_case("http") {
            UrlScheme::Http
        } else if scheme.eq_ignore_ascii_case("https") {
            UrlScheme::Https
        } else {
            return Err(Refusal::MalformedUrl);
        };
        let auth_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (authority, tail) = rest
            .split_at_checked(auth_end)
            .ok_or(Refusal::MalformedUrl)?;
        let (host, port) = parse_authority(authority)?;
        let port = port.filter(|p| *p != scheme.default_port());
        let tail = tail.split_once('#').map_or(tail, |(t, _)| t);
        let (raw_path, raw_query) = match tail.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (tail, None),
        };
        let path = remove_dot_segments(&normalise(raw_path, false));
        let query = raw_query
            .map(|q| normalise(q, true))
            .filter(|q| !q.is_empty());
        let mut serial = String::with_capacity(input.len());
        serial.push_str(scheme.as_str());
        serial.push_str("://");
        serial.push_str(&host);
        if let Some(p) = port {
            serial.push(':');
            serial.push_str(&p.to_string());
        }
        serial.push_str(&path);
        if let Some(q) = &query {
            serial.push('?');
            serial.push_str(q);
        }
        if serial.len() > MAX_URL_BYTES {
            return Err(Refusal::UrlTooLong);
        }
        Ok(SourceUrl {
            scheme,
            host,
            port,
            path,
            query,
            serial,
        })
    }

    /// Resolves `reference` against this URL, as a browser resolves a
    /// Location field or a link (RFC 3986 section 5.2).
    ///
    /// # Errors
    ///
    /// The refusals of [`SourceUrl::parse`] for the resolved URL, including
    /// any scheme other than `http` and `https`.
    pub fn join(&self, reference: &str) -> Result<SourceUrl, Refusal> {
        if reference.is_empty() || reference.starts_with('#') {
            return Ok(self.clone());
        }
        if has_scheme(reference) {
            return SourceUrl::parse(reference);
        }
        let mut s = String::with_capacity(self.serial.len().saturating_add(reference.len()));
        s.push_str(self.scheme.as_str());
        s.push(':');
        if reference.starts_with("//") {
            s.push_str(reference);
            return SourceUrl::parse(&s);
        }
        s.push_str("//");
        s.push_str(&self.authority());
        if reference.starts_with('/') {
            s.push_str(reference);
        } else if reference.starts_with('?') {
            s.push_str(&self.path);
            s.push_str(reference);
        } else {
            let dir = self
                .path
                .rfind('/')
                .map_or("/", |i| self.path.get(..=i).unwrap_or("/"));
            s.push_str(dir);
            s.push_str(reference);
        }
        SourceUrl::parse(&s)
    }

    /// The canonical URL.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.serial
    }

    /// The scheme.
    #[must_use]
    pub fn scheme(&self) -> UrlScheme {
        self.scheme
    }

    /// The lowercased host without a trailing dot. An IPv6 literal keeps
    /// its brackets.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// An explicit port other than the scheme's default.
    #[must_use]
    pub fn port(&self) -> Option<u16> {
        self.port
    }

    /// The host with an explicit port, as a Host field carries it.
    #[must_use]
    pub fn authority(&self) -> String {
        match self.port {
            Some(p) => format!("{}:{p}", self.host),
            None => self.host.clone(),
        }
    }

    /// The normalised path, never empty.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The normalised query without `?`, when not empty.
    #[must_use]
    pub fn query(&self) -> Option<&str> {
        self.query.as_deref()
    }

    /// The path and query as the request line carries them.
    #[must_use]
    pub fn path_and_query(&self) -> String {
        match &self.query {
            Some(q) => format!("{}?{q}", self.path),
            None => self.path.clone(),
        }
    }
}

fn has_scheme(s: &str) -> bool {
    let Some((scheme, _)) = s.split_once(':') else {
        return false;
    };
    let mut chars = scheme.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

fn parse_authority(a: &str) -> Result<(String, Option<u16>), Refusal> {
    if a.contains('@') || a.is_empty() {
        return Err(Refusal::MalformedUrl);
    }
    let (host, port) = if let Some(inner) = a.strip_prefix('[') {
        let (v6, after) = inner.split_once(']').ok_or(Refusal::MalformedUrl)?;
        if v6.is_empty()
            || !v6
                .chars()
                .all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.')
        {
            return Err(Refusal::MalformedUrl);
        }
        let port = match after {
            "" => None,
            p => Some(p.strip_prefix(':').ok_or(Refusal::MalformedUrl)?),
        };
        (format!("[{}]", v6.to_ascii_lowercase()), port)
    } else {
        let (h, p) = match a.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (a, None),
        };
        (parse_host(h)?, p)
    };
    let port = match port {
        None => None,
        Some(p) => {
            if p.is_empty() || p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit()) {
                return Err(Refusal::MalformedUrl);
            }
            Some(p.parse::<u16>().map_err(|_| Refusal::MalformedUrl)?)
        }
    };
    Ok((host, port))
}

fn parse_host(h: &str) -> Result<String, Refusal> {
    let h = h.strip_suffix('.').unwrap_or(h);
    if h.is_empty() || h.len() > 253 {
        return Err(Refusal::MalformedUrl);
    }
    for label in h.split('.') {
        let ok = !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-');
        if !ok {
            return Err(Refusal::MalformedUrl);
        }
    }
    Ok(h.to_ascii_lowercase())
}

fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

fn is_kept(b: u8, query: bool) -> bool {
    is_unreserved(b)
        || matches!(
            b,
            b'!' | b'$'
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
        )
        || (query && b == b'?')
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(b.wrapping_sub(b'a').wrapping_add(10)),
        b'A'..=b'F' => Some(b.wrapping_sub(b'A').wrapping_add(10)),
        _ => None,
    }
}

const HEX: &[u8; 16] = b"0123456789ABCDEF";

fn push_escape(out: &mut String, b: u8) {
    out.push('%');
    for nibble in [b >> 4, b & 0x0f] {
        if let Some(c) = HEX.get(usize::from(nibble)) {
            out.push(char::from(*c));
        }
    }
}

/// Percent-normalises a path or query (RFC 3986 section 6.2.2).
fn normalise(s: &str, query: bool) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0usize;
    while let Some(&b) = bytes.get(i) {
        if b == b'%' {
            let hi = bytes.get(i.saturating_add(1)).copied().and_then(hex_val);
            let lo = bytes.get(i.saturating_add(2)).copied().and_then(hex_val);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                let v = (hi << 4) | lo;
                if is_unreserved(v) {
                    out.push(char::from(v));
                } else {
                    push_escape(&mut out, v);
                }
                i = i.saturating_add(3);
                continue;
            }
            push_escape(&mut out, b);
        } else if is_kept(b, query) {
            out.push(char::from(b));
        } else {
            push_escape(&mut out, b);
        }
        i = i.saturating_add(1);
    }
    out
}

/// Removes `.` and `..` segments (RFC 3986 section 5.2.4). The result
/// starts with `/`.
fn remove_dot_segments(path: &str) -> String {
    let trimmed = path.strip_prefix('/').unwrap_or(path);
    let segs: Vec<&str> = trimmed.split('/').collect();
    let last = segs.len().saturating_sub(1);
    let mut out: Vec<&str> = Vec::with_capacity(segs.len());
    for (i, seg) in segs.iter().enumerate() {
        match *seg {
            "." => {
                if i == last {
                    out.push("");
                }
            }
            ".." => {
                out.pop();
                if i == last {
                    out.push("");
                }
            }
            s => out.push(s),
        }
    }
    let mut s = String::with_capacity(path.len().saturating_add(1));
    s.push('/');
    s.push_str(&out.join("/"));
    s
}

/// Percent-decodes `s` strictly: every `%` starts two hex digits, and the
/// result is UTF-8.
pub(crate) fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while let Some(&b) = bytes.get(i) {
        if b == b'%' {
            let hi = hex_val(*bytes.get(i.saturating_add(1))?)?;
            let lo = hex_val(*bytes.get(i.saturating_add(2))?)?;
            out.push((hi << 4) | lo);
            i = i.saturating_add(3);
        } else {
            out.push(b);
            i = i.saturating_add(1);
        }
    }
    String::from_utf8(out).ok()
}
