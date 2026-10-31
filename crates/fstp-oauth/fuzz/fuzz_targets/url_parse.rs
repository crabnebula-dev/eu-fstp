//! Fuzz target `url_parse` of `fstp-oauth` (TH-26, H-05, M4 design section 9).
//!
//! Design checks: strict RFC 3986 subset; normalisation never changes the match result.
//!
//! W0 skeleton. The code under test is a stub that refuses every input
//! with a typed `NotImplemented` error. Until lane W1e lands it, the
//! target checks only that no input panics and that a refusal formats.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let shown = format!("{:?}", fstp_oauth::parse_url(data));
    assert!(!shown.is_empty());
});
