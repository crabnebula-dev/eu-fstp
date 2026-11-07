//! I-68: the CSP of every surface stays as designed, with the brand
//! stylesheet route in place (M9 lane B2).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod web_common;

use web_common::{APP_CSP, PUBLIC_CSP, get, header_is};

/// I-68: `/p` keeps `script-src 'none'` and `style-src 'self'`, `/app`
/// keeps its CSP, and the brand route is a non-document with the closed
/// default CSP. A brand path with no brand answers 404 on the stub.
#[test]
fn i68_csp_unchanged() {
    assert!(PUBLIC_CSP.contains("script-src 'none'"));
    assert!(PUBLIC_CSP.contains("style-src 'self'"));
    let r = get("/p/supersafe/");
    header_is(&r, "content-security-policy", PUBLIC_CSP).unwrap();
    let r = get("/app/");
    header_is(&r, "content-security-policy", APP_CSP).unwrap();
    let path = format!("/brand/{}.css", "ab".repeat(32));
    let r = get(&path);
    assert_eq!(r.status.as_u16(), 404);
    header_is(
        &r,
        "content-security-policy",
        "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    )
    .unwrap();
    header_is(&r, "cache-control", "no-store").unwrap();
}
