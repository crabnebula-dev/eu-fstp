//! Review reproducers: the `fstp-web` fuzz targets need seeds that reach
//! past the first prefix check (TH-26, H-05, M4 design section 9).
//!
//! `tools/fuzz-all.sh` feeds `fuzz/seeds/<target>` to every target. With
//! no seed, a 30 s run of `origin_header_parse` stays at 43 coverage
//! points and never reaches the host or port grammar.

#![allow(clippy::panic, reason = "a test fails by panicking")]

use std::path::Path;

/// Every seed file of `target`, or a panic naming the missing directory.
fn seeds(target: &str) -> Vec<Vec<u8>> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fuzz/seeds")
        .join(target);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        panic!("{} does not exist", dir.display());
    };
    entries
        .filter_map(Result::ok)
        .filter_map(|e| std::fs::read(e.path()).ok())
        .collect()
}

/// TH-26, H-05: `origin_header_parse` has a seed the parser accepts, so
/// the fuzzer reaches the host and port grammar and the superset check.
#[test]
fn review_origin_fuzz_has_an_accepted_seed() {
    let accepted = seeds("origin_header_parse")
        .iter()
        .any(|s| fstp_web::parse_origin_header(s).is_ok());
    assert!(accepted, "no seed of origin_header_parse is accepted");
}

/// TH-26, H-05: `web_op_request` has a seed that the HTTP parser accepts,
/// so the fuzzer reaches the router, the CSRF rule and the headers.
#[test]
fn review_web_op_request_fuzz_has_a_routed_seed() {
    let routed = seeds("web_op_request")
        .iter()
        .any(|s| fstp_web::handle_op_request(s).is_ok_and(|r| r.response().status.as_u16() != 400));
    assert!(routed, "no seed of web_op_request reaches the router");
}
