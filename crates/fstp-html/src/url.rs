//! URLs the writer puts into `href`, `src` and `action` (I-68, TW-2).

use crate::HtmlError;

/// Whether `u` is safe in a URL attribute.
///
/// Interim reading, pending Daniel, after ADR-014 `safeUrl` (`web/src/core/
/// dom.ts`), and never looser than it (issue 6 L21): a URL is a same-origin
/// path or an `https:` URL. It holds only ASCII graphic characters and no
/// backslash, and each `%` is followed by two hex digits. A path starts with
/// exactly one `/`. An `https:` URL starts with `https://`, then a host of
/// lower-case LDH labels, an optional `:` and one to five digits, then
/// nothing or `/`, `?` or `#`. No userinfo, and a host whose last label is
/// numeric (an IPv4 form) is refused. The frontend also accepts a
/// fragment-only link; the writer does not, which is stricter and allowed.
pub(crate) fn is_safe_url(u: &str) -> bool {
    if u.is_empty() || !u.bytes().all(|b| (0x21..=0x7e).contains(&b) && b != b'\\') {
        return false;
    }
    if !percent_ok(u.as_bytes()) {
        return false;
    }
    if let Some(rest) = u.strip_prefix("https://") {
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        return rest.get(..end).is_some_and(authority_ok);
    }
    let b = u.as_bytes();
    b.first() == Some(&b'/') && b.get(1).is_none_or(|&c| c != b'/')
}

/// Whether `u` is safe in the `href` of an `a` element: a URL of
/// [`is_safe_url`], or a `mailto:` link to one address (ADR-034, lead
/// decision of 2026-11-22: the funding card's contact can be clicked).
/// No other element or attribute takes a `mailto:` link.
pub(crate) fn is_safe_link(u: &str) -> bool {
    is_safe_url(u) || u.strip_prefix("mailto:").is_some_and(mailto_ok)
}

/// One e-mail address of a `mailto:` link (ADR-034): a local part of 1 to
/// 64 ASCII letters, digits and `. _ + -`, neither starting nor ending with
/// `.`, then `@` and a host of at least two lower-case LDH labels whose last
/// label is not numeric. Nothing else, so no header or body can ride along.
pub(crate) fn mailto_ok(addr: &str) -> bool {
    let Some((local, host)) = addr.split_once('@') else {
        return false;
    };
    let local_ok = (1..=64).contains(&local.len())
        && !local.starts_with('.')
        && !local.ends_with('.')
        && local
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._+-".contains(&c));
    let last = host.rsplit('.').next().unwrap_or("");
    local_ok
        && host.len() <= 253
        && host.contains('.')
        && host.split('.').all(label_ok)
        && !last.bytes().all(|c| c.is_ascii_digit())
}

/// Each `%` is followed by two hex digits.
fn percent_ok(b: &[u8]) -> bool {
    let mut rest = b.iter();
    while let Some(&c) = rest.next() {
        if c == b'%' {
            let first = rest.next().is_some_and(u8::is_ascii_hexdigit);
            let second = rest.next().is_some_and(u8::is_ascii_hexdigit);
            if !first || !second {
                return false;
            }
        }
    }
    true
}

/// One DNS label: lower-case letters, digits and inner hyphens.
fn label_ok(l: &str) -> bool {
    let b = l.as_bytes();
    let edge = |c: &u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    !b.is_empty()
        && b.first().is_some_and(edge)
        && b.last().is_some_and(edge)
        && b.iter().all(|c| edge(c) || *c == b'-')
}

/// A host of LDH labels and an optional port of one to five digits. A last
/// label of digits only, or `0x` and hex digits, is an IPv4 form to the URL
/// parser and is refused.
fn authority_ok(a: &str) -> bool {
    let (host, port) = match a.split_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (a, None),
    };
    if let Some(p) = port
        && !((1..=5).contains(&p.len()) && p.bytes().all(|c| c.is_ascii_digit()))
    {
        return false;
    }
    let last = host.rsplit('.').next().unwrap_or("");
    let numeric = last.bytes().all(|c| c.is_ascii_digit()) && !last.is_empty()
        || last.strip_prefix("0x").is_some_and(|h| {
            h.bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        });
    !host.is_empty() && host.split('.').all(label_ok) && !numeric
}

/// A URL that may go into a URL attribute.
///
/// The only constructor is [`SafeUrl::new`], which refuses every URL that
/// leaves the origin other than by `https:`, runs script, or that a
/// browser could rewrite. The writer escapes the URL like any attribute
/// value and records it in the render trace.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SafeUrl(String);

impl SafeUrl {
    /// The `mailto:` link to `address`, for the `href` of an `a` element
    /// only (ADR-034). The address must pass [`mailto_ok`]: one address,
    /// no query, so no header or body can ride along.
    ///
    /// # Errors
    ///
    /// [`HtmlError::UnsafeUrl`] for any other address.
    pub fn mailto(address: &str) -> Result<SafeUrl, HtmlError> {
        if mailto_ok(address) {
            Ok(SafeUrl(format!("mailto:{address}")))
        } else {
            Err(HtmlError::UnsafeUrl)
        }
    }

    /// Checks `url` and keeps it unchanged.
    pub fn new(url: &str) -> Result<SafeUrl, HtmlError> {
        if is_safe_url(url) {
            Ok(SafeUrl(url.to_owned()))
        } else {
            Err(HtmlError::UnsafeUrl)
        }
    }

    /// The URL as given.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::{is_safe_link, is_safe_url};

    /// ADR-034, I-68: a `mailto:` link names one address and nothing else.
    #[test]
    fn adr034_mailto_names_one_address_only_and_only_in_links() {
        for good in [
            "mailto:privacy@crabnebula.dev",
            "mailto:a.b+c_d-e@sub.example.org",
        ] {
            assert!(is_safe_link(good) && !is_safe_url(good), "{good}");
        }
        for bad in [
            "mailto:",
            "mailto:a@b",
            "mailto:@example.org",
            "mailto:a@Example.org",
            "mailto:.a@example.org",
            "mailto:a@example.org?subject=x",
            "mailto:a@example.org,b@example.org",
            "mailto:a%40@example.org",
            "mailto:a@1.2.3.4",
            "mailto:a b@example.org",
            "MAILTO:a@example.org",
            "mailto:a@example.org\\",
        ] {
            assert!(!is_safe_link(bad), "{bad}");
        }
    }

    /// Issue 6 L21: cases the frontend `safeUrl` refuses and the writer
    /// used to accept, and cases both accept.
    #[test]
    fn issue6_l21_safe_url_is_not_looser_than_the_frontend() {
        for bad in [
            "https://exa%mple.org/",
            "/path%zz",
            "/path%4",
            "https://user@example.org/",
            "https://Example.org/",
            "https://127.0.0.1/",
            "https://0x7f.1/",
            "https://example.org:/",
            "https://example.org:123456/",
            "https://example.org:80a/",
            "https://[::1]/",
            "https://-a.org/",
            "https://a..org/",
            "https://example.org.1/",
            "https:///x",
            "//evil.example",
            "#frag",
        ] {
            assert!(!is_safe_url(bad), "{bad}");
        }
        for good in [
            "/",
            "/a/b?x=%41#f",
            "https://example.org",
            "https://example.org/p",
            "https://sub.example-1.org:8443/p?q#f",
            "https://example.org?x",
            "https://example.org#x",
        ] {
            assert!(is_safe_url(good), "{good}");
        }
    }
}
