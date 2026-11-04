//! Fuzz target `client_metadata_decode` of `fstp-oauth` (TH-26, H-05, M4
//! design section 9).
//!
//! Design checks: RFC 7591 client metadata; duplicate members rejected.
//! Accepted metadata holds 1 to 8 distinct redirect URIs of the strict
//! subset and a bounded client name.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(meta) = fstp_oauth::decode_client_metadata(data) else {
        return;
    };
    let uris = meta.redirect_uris();
    assert!(!uris.is_empty() && uris.len() <= fstp_oauth::MAX_REDIRECT_URIS);
    for (i, u) in uris.iter().enumerate() {
        assert!(fstp_oauth::parse_url(u.as_str().as_bytes()).is_ok());
        assert!(uris.iter().skip(i + 1).all(|o| o.as_str() != u.as_str()));
    }
    if let Some(n) = meta.client_name() {
        let chars = n.chars().count();
        assert!((1..=fstp_oauth::MAX_CLIENT_NAME_CHARS).contains(&chars));
        assert!(!n.chars().any(char::is_control));
    }
});
