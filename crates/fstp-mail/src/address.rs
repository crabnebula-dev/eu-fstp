//! Addresses and names that come from configuration, never from proposal
//! content: the recipient mailbox, the tenant's sender, its display name
//! and the platform origin that links point to.

use std::fmt;

use crate::MailError;

fn atext(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-/=?^_`{|}~".contains(&b)
}

fn domain_ok(d: &str) -> bool {
    !d.is_empty()
        && d.len() <= 253
        && d.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

/// An ASCII `addr-spec` with a dot-atom local part (RFC 5322 section
/// 3.4.1). The domain is stored in lower case. Quoted local parts and
/// address literals are refused, and so is non-ASCII, since the client
/// never asks for SMTPUTF8.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Mailbox(String);

impl Mailbox {
    /// Checks and stores `addr`.
    ///
    /// # Errors
    ///
    /// [`MailError::InvalidAddress`] for anything but a dot-atom local part
    /// of at most 64 octets, an `@` and a host name, 254 octets in all.
    pub fn new(addr: &str) -> Result<Mailbox, MailError> {
        let (local, domain) = addr.rsplit_once('@').ok_or(MailError::InvalidAddress)?;
        let local_ok = !local.is_empty()
            && local.len() <= 64
            && local
                .split('.')
                .all(|a| !a.is_empty() && a.bytes().all(atext));
        if !local_ok || !domain_ok(domain) || addr.len() > 254 {
            return Err(MailError::InvalidAddress);
        }
        Ok(Mailbox(format!("{local}@{}", domain.to_ascii_lowercase())))
    }

    /// The address.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The domain part.
    pub fn domain(&self) -> &str {
        self.0.rsplit_once('@').map_or("", |(_, d)| d)
    }
}

impl fmt::Display for Mailbox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The display name of the tenant's sender, such as a fund's name. It is
/// tenant configuration, not a person's name.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DisplayName(String);

impl DisplayName {
    /// Checks and stores `name`.
    ///
    /// # Errors
    ///
    /// [`MailError::InvalidDisplayName`] when `name` is empty, longer than
    /// 64 characters, or holds a control character or a double quote.
    pub fn new(name: &str) -> Result<DisplayName, MailError> {
        let n = name.chars().count();
        if n == 0
            || n > 64
            || name.trim() != name
            || name.chars().any(|c| c.is_control() || c == '"')
        {
            return Err(MailError::InvalidDisplayName);
        }
        Ok(DisplayName(name.to_owned()))
    }

    /// The name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The scheme and authority every link starts with, such as
/// `https://cell.example`. It has no path, query or fragment.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Origin(String);

impl Origin {
    /// Checks and stores `origin`. The host is stored in lower case.
    ///
    /// # Errors
    ///
    /// [`MailError::InvalidOrigin`] unless `origin` is `https://` or
    /// `http://`, a host name and an optional port from 1 to 65535.
    pub fn new(origin: &str) -> Result<Origin, MailError> {
        let (scheme, rest) = origin.split_once("://").ok_or(MailError::InvalidOrigin)?;
        if scheme != "https" && scheme != "http" {
            return Err(MailError::InvalidOrigin);
        }
        let (host, port) = match rest.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (rest, None),
        };
        if !domain_ok(host) {
            return Err(MailError::InvalidOrigin);
        }
        if let Some(p) = port {
            let ok = !p.is_empty()
                && p.len() <= 5
                && p.bytes().all(|b| b.is_ascii_digit())
                && !p.starts_with('0')
                && p.parse::<u32>().is_ok_and(|n| n <= 65_535);
            if !ok {
                return Err(MailError::InvalidOrigin);
            }
        }
        Ok(Origin(format!("{scheme}://{}", rest.to_ascii_lowercase())))
    }

    /// The origin.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
