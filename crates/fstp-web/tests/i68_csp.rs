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
    let r = get("/app/invitation");
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

/// I-68, ADR-030: the logo routes are non-documents with the closed
/// default CSP and `nosniff`. On the stub no logo exists, so each
/// answers 404 and nothing is cached.
#[test]
fn i68_logo_routes_keep_the_closed_csp() {
    for path in [
        format!("/brand/{}.png", "ab".repeat(32)),
        format!("/brand/{}.webp", "ab".repeat(32)),
        "/brand/logo/light".to_owned(),
        "/brand/logo/dark".to_owned(),
    ] {
        let r = get(&path);
        assert_eq!(r.status.as_u16(), 404, "{path}");
        header_is(
            &r,
            "content-security-policy",
            "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        )
        .unwrap();
        header_is(&r, "x-content-type-options", "nosniff").unwrap();
        header_is(&r, "cache-control", "no-store").unwrap();
    }
}

/// I-68, ADR-034: the platform's funding card assets keep the closed CSP
/// and `nosniff`: the Funded by the EU logo as PNG and as SVG, and the
/// cards as JSON, which is never cached.
#[test]
fn adr034_funding_routes_keep_the_closed_csp() {
    for (path, kind) in [
        ("/brand/eu-emblem.png", "image/png"),
        ("/brand/funded-by-eu.svg", "image/svg+xml"),
        ("/brand/funding", "application/json"),
    ] {
        let r = get(path);
        assert_eq!(r.status.as_u16(), 200, "{path}");
        header_is(&r, "content-type", kind).unwrap();
        header_is(
            &r,
            "content-security-policy",
            "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        )
        .unwrap();
        header_is(&r, "x-content-type-options", "nosniff").unwrap();
    }
    header_is(&get("/brand/funding"), "cache-control", "no-store").unwrap();
}
