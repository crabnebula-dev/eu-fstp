//! Fuzz target `url_parse` of `fstp-oauth` (TH-26, H-05, M4 design section 9).
//!
//! Design checks: strict RFC 3986 subset; normalisation never changes the
//! match result. An accepted URL keeps its bytes, so it re-parses to
//! itself, holds only visible ASCII and no fragment or userinfo, and
//! matches itself as a redirect URI. A host whose last label is a number
//! is a dotted quad (TW-8).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(url) = fstp_oauth::parse_url(data) else {
        return;
    };
    assert_eq!(url.as_str().as_bytes(), data);
    assert!(data.iter().all(|b| (0x21..=0x7e).contains(b)));
    assert!(!url.as_str().contains('#'));
    assert!(!url.origin().contains('@'));
    let again = fstp_oauth::parse_url(url.as_str().as_bytes());
    assert_eq!(again.as_ref().ok(), Some(&url));
    assert!(fstp_oauth::redirect_matches(&url, &url));
    if url.scheme() == fstp_oauth::Scheme::Http {
        assert!(url.is_loopback());
    }
    // TW-8: a host a browser would read as IPv4 is a dotted quad, so the
    // host shown on the consent page is the host the browser reaches.
    let host = url.host();
    let last = host.rsplit('.').next().unwrap_or("");
    let numeric = (!last.is_empty() && last.bytes().all(|b| b.is_ascii_digit()))
        || last
            .strip_prefix("0x")
            .is_some_and(|h| h.bytes().all(|b| b.is_ascii_hexdigit()));
    if numeric {
        assert!(host.bytes().all(|b| b.is_ascii_digit() || b == b'.'));
        assert_eq!(host.split('.').count(), 4);
    }
    let rebuilt = format!("{}{}", url.origin(), url.path_and_query());
    assert_eq!(rebuilt, url.as_str());
});
