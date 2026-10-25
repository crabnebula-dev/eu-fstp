//! Validated header names, header values and ordered header lists.
//!
//! A [`HeaderName`] is always a token and a [`HeaderValue`] never holds CR,
//! LF, NUL or another control byte except HTAB. The serializer checks both
//! again before writing, so CR or LF injection is impossible through this
//! API (response splitting, TH-26).
//!
//! `Debug` output of [`HeaderValue`] and [`Headers`] redacts every value. It
//! also redacts every field name outside a fixed list of registered names,
//! since a sender chooses other names freely. A logged header list
//! therefore carries no content (R-NF-02).

use std::fmt;

use crate::chars::{is_field_byte, is_ows, is_token};
use crate::error::InvalidInput;

/// A header field name: a token, stored in lowercase.
///
/// Field names are case-insensitive (RFC 9110 section 5.1). Lowercase
/// storage makes comparisons cheap and output stable.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HeaderName(Box<str>);

impl HeaderName {
    /// Validates `name` and stores it in lowercase.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidInput`] when `name` is empty or not a token.
    pub fn new(name: &str) -> Result<HeaderName, InvalidInput> {
        HeaderName::from_bytes(name.as_bytes())
    }

    /// Validates `name` and stores it in lowercase.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidInput`] when `name` is empty or not a token.
    pub fn from_bytes(name: &[u8]) -> Result<HeaderName, InvalidInput> {
        if !is_token(name) {
            return Err(InvalidInput::new("header name is not a token"));
        }
        let lower: String = name
            .iter()
            .map(|&b| char::from(b.to_ascii_lowercase()))
            .collect();
        Ok(HeaderName(lower.into_boxed_str()))
    }

    /// The name in lowercase.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// True when this name equals `other`, ignoring ASCII case.
    #[must_use]
    pub fn eq_name(&self, other: &str) -> bool {
        self.0.eq_ignore_ascii_case(other)
    }
}

/// Field names that `Debug` prints, sorted for binary search. They come
/// from RFC 9110, RFC 9111 and other published specifications, so a name
/// on this list says nothing about the message content.
const REGISTERED_NAMES: [&str; 67] = [
    "accept",
    "accept-charset",
    "accept-encoding",
    "accept-language",
    "accept-ranges",
    "access-control-allow-credentials",
    "access-control-allow-headers",
    "access-control-allow-methods",
    "access-control-allow-origin",
    "access-control-expose-headers",
    "access-control-max-age",
    "access-control-request-headers",
    "access-control-request-method",
    "age",
    "allow",
    "authentication-info",
    "authorization",
    "cache-control",
    "connection",
    "content-disposition",
    "content-encoding",
    "content-language",
    "content-length",
    "content-location",
    "content-range",
    "content-security-policy",
    "content-type",
    "cookie",
    "date",
    "etag",
    "expect",
    "expires",
    "forwarded",
    "from",
    "host",
    "if-match",
    "if-modified-since",
    "if-none-match",
    "if-range",
    "if-unmodified-since",
    "keep-alive",
    "last-modified",
    "link",
    "location",
    "max-forwards",
    "origin",
    "pragma",
    "proxy-authenticate",
    "proxy-authentication-info",
    "proxy-authorization",
    "range",
    "referer",
    "referrer-policy",
    "retry-after",
    "server",
    "set-cookie",
    "strict-transport-security",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "user-agent",
    "vary",
    "via",
    "www-authenticate",
    "x-content-type-options",
    "x-frame-options",
];

impl fmt::Debug for HeaderName {
    /// A registered name prints as a quoted string, and any other name as
    /// `<extension>`. A sender chooses other names freely, so they could
    /// carry content (R-NF-02). [`fmt::Display`] prints every name.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if REGISTERED_NAMES.binary_search(&&*self.0).is_ok() {
            write!(f, "{:?}", &*self.0)
        } else {
            f.write_str("<extension>")
        }
    }
}

impl fmt::Display for HeaderName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A header field value.
///
/// It holds only `VCHAR`, `obs-text` (bytes 0x80 to 0xFF), SP and HTAB, and
/// it neither starts nor ends with SP or HTAB. CR, LF, NUL, other control
/// bytes and DEL are rejected. Values are bytes, since `obs-text` is not
/// necessarily UTF-8.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct HeaderValue(Box<[u8]>);

impl HeaderValue {
    /// Validates and stores `value`.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidInput`] when `value` holds a forbidden byte or
    /// starts or ends with whitespace.
    pub fn new(value: impl Into<Vec<u8>>) -> Result<HeaderValue, InvalidInput> {
        let v = value.into();
        if !is_valid_value(&v) {
            return Err(InvalidInput::new(
                "header value holds a control byte or surrounding whitespace",
            ));
        }
        Ok(HeaderValue(v.into_boxed_slice()))
    }

    /// A value holding the decimal form of `n`.
    #[must_use]
    pub fn from_u64(n: u64) -> HeaderValue {
        HeaderValue(n.to_string().into_bytes().into_boxed_slice())
    }

    /// Wraps bytes that the parser already validated.
    pub(crate) fn from_validated(v: &[u8]) -> HeaderValue {
        HeaderValue(v.into())
    }

    /// The raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The value as text, when it is printable ASCII (no `obs-text`).
    #[must_use]
    pub fn to_str(&self) -> Option<&str> {
        if self.0.iter().all(u8::is_ascii) {
            std::str::from_utf8(&self.0).ok()
        } else {
            None
        }
    }

    /// Length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True for an empty value.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// True when `v` is a valid field value with no surrounding whitespace.
pub(crate) fn is_valid_value(v: &[u8]) -> bool {
    if v.first().is_some_and(|&b| is_ows(b)) || v.last().is_some_and(|&b| is_ows(b)) {
        return false;
    }
    v.iter().all(|&b| is_field_byte(b))
}

impl fmt::Debug for HeaderValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<redacted {} bytes>", self.0.len())
    }
}

impl TryFrom<&str> for HeaderValue {
    type Error = InvalidInput;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        HeaderValue::new(s)
    }
}

impl TryFrom<String> for HeaderValue {
    type Error = InvalidInput;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        HeaderValue::new(s)
    }
}

/// An ordered list of header fields. Repeated names are kept as separate
/// entries in arrival order.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Headers {
    entries: Vec<(HeaderName, HeaderValue)>,
}

impl Headers {
    /// An empty list.
    #[must_use]
    pub fn new() -> Headers {
        Headers::default()
    }

    /// Appends a field, keeping existing fields of the same name.
    pub fn append(&mut self, name: HeaderName, value: HeaderValue) {
        self.entries.push((name, value));
    }

    /// Validates and appends a field.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidInput`] when the name or the value is invalid.
    pub fn try_append(
        &mut self,
        name: &str,
        value: impl Into<Vec<u8>>,
    ) -> Result<(), InvalidInput> {
        let name = HeaderName::new(name)?;
        let value = HeaderValue::new(value)?;
        self.append(name, value);
        Ok(())
    }

    /// Replaces every field named `name` with one field.
    pub fn insert(&mut self, name: HeaderName, value: HeaderValue) {
        self.entries.retain(|(n, _)| *n != name);
        self.entries.push((name, value));
    }

    /// Validates and inserts a field, replacing fields of the same name.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidInput`] when the name or the value is invalid.
    pub fn try_insert(
        &mut self,
        name: &str,
        value: impl Into<Vec<u8>>,
    ) -> Result<(), InvalidInput> {
        let name = HeaderName::new(name)?;
        let value = HeaderValue::new(value)?;
        self.insert(name, value);
        Ok(())
    }

    /// The first value of the field named `name`, ignoring case.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&HeaderValue> {
        self.entries
            .iter()
            .find(|(n, _)| n.eq_name(name))
            .map(|(_, v)| v)
    }

    /// Every value of the field named `name`, in order.
    pub fn get_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a HeaderValue> + 'a {
        self.entries
            .iter()
            .filter(move |(n, _)| n.eq_name(name))
            .map(|(_, v)| v)
    }

    /// Number of field lines named `name`.
    #[must_use]
    pub fn count(&self, name: &str) -> usize {
        self.entries.iter().filter(|(n, _)| n.eq_name(name)).count()
    }

    /// True when a field named `name` is present.
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.entries.iter().any(|(n, _)| n.eq_name(name))
    }

    /// Removes every field named `name` and returns how many were removed.
    pub fn remove(&mut self, name: &str) -> usize {
        let before = self.entries.len();
        self.entries.retain(|(n, _)| !n.eq_name(name));
        before.saturating_sub(self.entries.len())
    }

    /// Number of fields.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when there are no fields.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterates over the fields in order.
    pub fn iter(&self) -> impl Iterator<Item = (&HeaderName, &HeaderValue)> {
        self.entries.iter().map(|(n, v)| (n, v))
    }

    /// True when the comma-separated list in the fields named `name`
    /// contains `token`, ignoring case.
    #[must_use]
    pub fn has_token(&self, name: &str, token: &str) -> bool {
        self.get_all(name).any(|v| {
            v.as_bytes()
                .split(|&b| b == b',')
                .any(|item| crate::chars::trim_ows(item).eq_ignore_ascii_case(token.as_bytes()))
        })
    }
}

impl fmt::Debug for Headers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.entries.iter().map(|(n, v)| (n, v)))
            .finish()
    }
}

impl<'a> IntoIterator for &'a Headers {
    type Item = (&'a HeaderName, &'a HeaderValue);
    type IntoIter = std::iter::Map<
        std::slice::Iter<'a, (HeaderName, HeaderValue)>,
        fn(&'a (HeaderName, HeaderValue)) -> (&'a HeaderName, &'a HeaderValue),
    >;

    fn into_iter(self) -> Self::IntoIter {
        fn split(e: &(HeaderName, HeaderValue)) -> (&HeaderName, &HeaderValue) {
            (&e.0, &e.1)
        }
        self.entries.iter().map(split)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_lowercase_tokens() {
        assert_eq!(
            HeaderName::new("Content-Type").unwrap().as_str(),
            "content-type"
        );
        assert!(HeaderName::new("bad name").is_err());
        assert!(HeaderName::new("bad:name").is_err());
        assert!(HeaderName::new("").is_err());
        assert!(HeaderName::new("x\r\ny").is_err());
    }

    #[test]
    fn values_reject_injection() {
        assert!(HeaderValue::new("ok value").is_ok());
        assert!(HeaderValue::new("").is_ok());
        assert!(HeaderValue::new(vec![0x80, b'a']).is_ok());
        for bad in [
            &b"a\r\nb"[..],
            b"a\nb",
            b"a\rb",
            b"a\x00b",
            b"a\x7fb",
            b" lead",
            b"trail\t",
        ] {
            assert!(HeaderValue::new(bad.to_vec()).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn list_operations() {
        let mut h = Headers::new();
        h.try_append("A", "1").unwrap();
        h.try_append("a", "2").unwrap();
        h.try_append("B", "x, Close").unwrap();
        assert_eq!(h.count("A"), 2);
        assert_eq!(h.get("a").unwrap().as_bytes(), b"1");
        assert!(h.has_token("b", "close"));
        h.try_insert("A", "3").unwrap();
        assert_eq!(h.count("a"), 1);
        assert_eq!(h.remove("b"), 1);
        assert_eq!(h.len(), 1);
    }

    /// R-NF-02: Debug output carries no header values.
    #[test]
    fn r_nf_02_debug_redacts_values() {
        let mut h = Headers::new();
        h.try_append("authorization", "Bearer canary-secret-123")
            .unwrap();
        let shown = format!("{h:?}");
        assert!(!shown.contains("canary"), "{shown}");
        assert!(shown.contains("authorization"));
    }

    /// R-NF-02, review finding debug-prints-client-chosen-names: Debug
    /// prints registered field names only.
    #[test]
    fn review_debug_prints_client_chosen_names_headers() {
        assert!(REGISTERED_NAMES.windows(2).all(|w| w[0] < w[1]), "unsorted");
        for name in REGISTERED_NAMES {
            let n = HeaderName::new(name).unwrap();
            assert_eq!(n.as_str(), name, "not lowercase");
            assert_eq!(format!("{n:?}"), format!("{name:?}"));
        }
        let n = HeaderName::new("X-User-Alice-Token").unwrap();
        assert_eq!(format!("{n:?}"), "<extension>");
        assert_eq!(n.to_string(), "x-user-alice-token");
    }
}
