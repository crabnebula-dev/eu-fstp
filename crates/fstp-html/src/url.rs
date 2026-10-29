//! URLs the writer puts into `href`, `src` and `action` (I-68, TW-2).

use crate::HtmlError;

/// Whether `u` is safe in a URL attribute.
///
/// Interim reading, pending Daniel, after ADR-014 `safeUrl`: a URL is a
/// same-origin path or an `https:` URL. It holds only ASCII graphic
/// characters and no backslash, so no browser rewrites it into another
/// origin. A path starts with exactly one `/`. An `https:` URL starts
/// with `https://` and a character that is not `/`.
pub(crate) fn is_safe_url(u: &str) -> bool {
    if u.is_empty() || !u.bytes().all(|b| (0x21..=0x7e).contains(&b) && b != b'\\') {
        return false;
    }
    if let Some(rest) = u.strip_prefix("https://") {
        return rest.as_bytes().first().is_some_and(|&b| b != b'/');
    }
    let b = u.as_bytes();
    b.first() == Some(&b'/') && b.get(1).is_none_or(|&c| c != b'/')
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
