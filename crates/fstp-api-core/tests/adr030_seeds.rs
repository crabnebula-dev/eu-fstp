//! The logo and theme seeds of the `api_request_decode` fuzz target reach
//! their decoders (TH-26, I-68, ADR-030).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;

use fstp_api_core::decode::decode_request;

fn seed(file: &str) -> Vec<u8> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/seeds/api_request_decode");
    std::fs::read(dir.join(file)).unwrap_or_else(|e| panic!("{file}: {e}"))
}

/// I-68, TH-26: the logo seed decodes to `tenant.branding.set_logo`. A
/// body with an unknown member, a mode outside light and dark, or an
/// image that is no string is refused before any operation runs.
#[test]
fn i68_logo_seed_decodes_and_bad_bodies_are_refused() {
    let bytes = seed("tenant_branding_set_logo");
    let op = decode_request(&bytes).unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(op.name(), "tenant.branding.set_logo");
    let text = String::from_utf8(bytes).unwrap();
    for bad in [
        text.replace("\"mode\":\"light\"", "\"mode\":\"sepia\""),
        text.replace("{\"image\"", "{\"svg\":\"<svg/>\",\"image\""),
        text.replace("\"programme\":null", "\"programme\":\"x\""),
        text.replace("\"programme\":null", "\"programme\":7"),
    ] {
        assert!(decode_request(bad.as_bytes()).is_err(), "{bad}");
    }
}

/// ADR-030: the theme seed decodes to `me.set_theme`, and a theme outside
/// the closed list is refused.
#[test]
fn adr030_theme_seed_decodes_and_unknown_theme_is_refused() {
    let bytes = seed("me_set_theme");
    let op = decode_request(&bytes).unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(op.name(), "me.set_theme");
    let text = String::from_utf8(bytes).unwrap();
    assert!(decode_request(text.replace("dark", "purple").as_bytes()).is_err());
}
