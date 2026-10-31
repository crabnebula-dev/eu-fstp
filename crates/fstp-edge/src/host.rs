//! Host names the edge routes on (M3 design sections 1.5 and 9.4).
//!
//! A [`HostName`] is a DNS name in lowercase LDH form (RFC 1123): labels of
//! 1 to 63 letters, digits and hyphens, no hyphen at either end of a label,
//! at most 253 bytes in all. A trailing dot, an address literal and every
//! other byte are refused, so no such name reaches the route table.

use std::fmt;

/// The most bytes a host name holds (RFC 1035 section 2.3.4, without the
/// trailing dot).
pub const MAX_HOST_LEN: usize = 253;

/// The most bytes one label holds (RFC 1035 section 2.3.4).
pub const MAX_LABEL_LEN: usize = 63;

/// The label that prefixes a cell host to name its vault origin
/// (design section 1.5).
const VAULT_ORIGIN_PREFIX: &[u8] = b"id.";

/// A host name, lowercase ASCII in LDH form.
///
/// It is built only by [`HostName::parse`], so every value is valid and at
/// most [`MAX_HOST_LEN`] bytes long.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HostName(String);

/// Why a host name was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostError {
    /// The name is empty or longer than [`MAX_HOST_LEN`].
    Length,
    /// A label is empty, which covers a leading, trailing or double dot.
    EmptyLabel,
    /// A label is longer than [`MAX_LABEL_LEN`].
    LabelLength,
    /// A byte is not a letter, a digit, a hyphen or a dot.
    Byte,
    /// A label starts or ends with a hyphen.
    Hyphen,
    /// The last label is all digits, as in an IPv4 literal.
    NumericLastLabel,
    /// A byte is an upper case letter where only the lowercase form is
    /// accepted.
    NotLowercase,
}

impl HostName {
    /// Parses a host name in any letter case and folds it to lowercase.
    ///
    /// # Errors
    ///
    /// Returns a [`HostError`] for any name that is not an LDH DNS name.
    pub fn parse(bytes: &[u8]) -> Result<HostName, HostError> {
        let lower: Vec<u8> = bytes.iter().map(u8::to_ascii_lowercase).collect();
        Self::parse_lowercase(&lower)
    }

    /// Parses a host name that is already lowercase. This is the one
    /// spelling the tunnel header carries.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::NotLowercase`] for an upper case letter, and
    /// any other [`HostError`] as [`HostName::parse`] does.
    pub fn parse_lowercase(bytes: &[u8]) -> Result<HostName, HostError> {
        check(bytes)?;
        // `check` admits only ASCII letters, digits, hyphens and dots.
        let text = std::str::from_utf8(bytes).map_err(|_| HostError::Byte)?;
        Ok(HostName(text.to_owned()))
    }

    /// The name.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The name as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// The vault origin host of this cell host, `id.<host>` (design
    /// section 1.5).
    ///
    /// # Errors
    ///
    /// Returns [`HostError::Length`] when the longer name exceeds
    /// [`MAX_HOST_LEN`].
    pub fn vault_origin(&self) -> Result<HostName, HostError> {
        let mut name = VAULT_ORIGIN_PREFIX.to_vec();
        name.extend_from_slice(self.as_bytes());
        Self::parse_lowercase(&name)
    }
}

impl fmt::Debug for HostName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("HostName").field(&self.0).finish()
    }
}

impl fmt::Display for HostName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Checks the LDH rules on a lowercase name.
fn check(bytes: &[u8]) -> Result<(), HostError> {
    if bytes.is_empty() || bytes.len() > MAX_HOST_LEN {
        return Err(HostError::Length);
    }
    let mut last: &[u8] = &[];
    for label in bytes.split(|b| *b == b'.') {
        check_label(label)?;
        last = label;
    }
    if last.iter().all(u8::is_ascii_digit) {
        return Err(HostError::NumericLastLabel);
    }
    Ok(())
}

/// Checks one label.
fn check_label(label: &[u8]) -> Result<(), HostError> {
    if label.is_empty() {
        return Err(HostError::EmptyLabel);
    }
    if label.len() > MAX_LABEL_LEN {
        return Err(HostError::LabelLength);
    }
    for b in label {
        if b.is_ascii_uppercase() {
            return Err(HostError::NotLowercase);
        }
        if !(b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-') {
            return Err(HostError::Byte);
        }
    }
    if label.first() == Some(&b'-') || label.last() == Some(&b'-') {
        return Err(HostError::Hyphen);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// TH-26: the LDH rules in both directions, and the vault origin name.
    #[test]
    fn th26_host_name_rules() {
        assert_eq!(
            HostName::parse(b"Cell.Example").map(|h| h.0),
            Ok("cell.example".to_owned())
        );
        assert_eq!(
            HostName::parse_lowercase(b"Cell.example"),
            Err(HostError::NotLowercase)
        );
        assert_eq!(HostName::parse(b"a.1"), Err(HostError::NumericLastLabel));
        assert_eq!(HostName::parse(b"a..b"), Err(HostError::EmptyLabel));
        assert_eq!(HostName::parse(b"a_b.c"), Err(HostError::Byte));
        assert_eq!(HostName::parse(b"-a.b"), Err(HostError::Hyphen));
        let host = HostName::parse(b"x.example");
        assert_eq!(
            host.and_then(|h| h.vault_origin()).map(|h| h.0),
            Ok("id.x.example".to_owned())
        );
        let long = HostName::parse(&[b'a'; 63]).and_then(|h| h.vault_origin());
        assert!(long.is_ok());
    }
}
