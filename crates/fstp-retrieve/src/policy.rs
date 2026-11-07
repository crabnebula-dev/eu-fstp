//! The destination policy (TH-12).
//!
//! The proxy reaches only hosts under a listed suffix. IP literals in any
//! notation, single-label names and local top-level names are refused
//! whatever the list says, so a misconfigured list never opens the cell's
//! own network.

use crate::refusal::Refusal;
use crate::url::{SourceUrl, UrlScheme};

/// Top-level names that resolve inside a network, never on the internet.
const LOCAL_TLDS: &[&str] = &[
    "localhost",
    "local",
    "localdomain",
    "internal",
    "intranet",
    "lan",
    "home",
    "corp",
    "private",
    "arpa",
    "invalid",
    "onion",
];

/// Which destinations the proxy may reach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestinationPolicy {
    suffixes: Vec<String>,
    allow_http: bool,
}

impl DestinationPolicy {
    /// A policy that admits hosts equal to or under one of `suffixes`.
    /// `allow_http` admits plain HTTP as well as HTTPS.
    #[must_use]
    pub fn new(suffixes: &[&str], allow_http: bool) -> DestinationPolicy {
        DestinationPolicy {
            suffixes: suffixes
                .iter()
                .map(|s| s.trim_matches('.').to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect(),
            allow_http,
        }
    }

    /// The fixture policy of M7: `*.test` hosts (RFC 6761) over HTTP or
    /// HTTPS, served by the fixture web server only.
    #[must_use]
    pub fn fixture() -> DestinationPolicy {
        DestinationPolicy::new(&["test"], true)
    }

    /// Checks `url` against the policy.
    ///
    /// # Errors
    ///
    /// The first rule that fails, in this order: [`Refusal::IpLiteral`],
    /// [`Refusal::HostNotAllowed`], [`Refusal::SchemeNotAllowed`],
    /// [`Refusal::PortNotAllowed`].
    pub fn check(&self, url: &SourceUrl) -> Result<(), Refusal> {
        let host = url.host();
        if is_ip_literal(host) {
            return Err(Refusal::IpLiteral);
        }
        let mut labels = host.rsplit('.');
        let tld = labels.next().unwrap_or("");
        if labels.next().is_none() || LOCAL_TLDS.contains(&tld) {
            return Err(Refusal::HostNotAllowed);
        }
        let listed = self.suffixes.iter().any(|s| {
            host == s
                || host
                    .strip_suffix(s.as_str())
                    .is_some_and(|head| head.ends_with('.'))
        });
        if !listed {
            return Err(Refusal::HostNotAllowed);
        }
        if url.scheme() == UrlScheme::Http && !self.allow_http {
            return Err(Refusal::SchemeNotAllowed);
        }
        if url.port().is_some() {
            return Err(Refusal::PortNotAllowed);
        }
        Ok(())
    }
}

/// An IPv6 literal, or a name whose last label is a number in decimal or
/// `0x` hex, which URL parsers read as IPv4 (WHATWG URL host parsing).
fn is_ip_literal(host: &str) -> bool {
    if host.starts_with('[') {
        return true;
    }
    let last = host.rsplit('.').next().unwrap_or("");
    let decimal = !last.is_empty() && last.bytes().all(|b| b.is_ascii_digit());
    let hex = last
        .strip_prefix("0x")
        .or_else(|| last.strip_prefix("0X"))
        .is_some_and(|h| h.bytes().all(|b| b.is_ascii_hexdigit()));
    decimal || hex
}
