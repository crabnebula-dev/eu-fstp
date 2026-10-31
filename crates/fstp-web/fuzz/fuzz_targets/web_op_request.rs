//! Fuzz target `web_op_request` of `fstp-web` (TH-26, H-05, ADR-014, M4 design section 9).
//!
//! Design checks: route, headers and body into the adapter over a stub
//! dispatch.
//!
//! - No input panics, and a refusal formats.
//! - The adapter is deterministic.
//! - Every reply carries exactly one CSP, `nosniff` and HSTS, and no
//!   reply sets a cookie or an `Access-Control-Allow-Origin` field.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let first = fstp_web::handle_op_request(data);
    let shown = format!("{first:?}");
    assert!(!shown.is_empty());
    assert_eq!(
        first,
        fstp_web::handle_op_request(data),
        "the adapter is not deterministic"
    );
    if let Ok(reply) = first {
        let r = reply.into_response();
        for name in [
            "content-security-policy",
            "x-content-type-options",
            "strict-transport-security",
        ] {
            assert_eq!(r.headers.count(name), 1, "a reply lacks one {name}");
        }
        assert!(!r.headers.contains("set-cookie"), "a reply sets a cookie");
        assert!(
            !r.headers.contains("access-control-allow-origin"),
            "a reply grants a cross-origin read"
        );
    }
});
