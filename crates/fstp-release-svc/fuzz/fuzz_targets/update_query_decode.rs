//! Fuzz target `update_query_decode` of `fstp-release-svc` (TH-26, H-05, M3 design section 15).
//!
//! Design checks: only the permitted grammar.
//!
//! W0 skeleton. The code under test is a stub that refuses every input
//! with a typed `NotImplemented` error. Until lane W2j lands it, the
//! target checks only that no input panics and that a refusal formats.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let shown = format!("{:?}", fstp_release_svc::decode_update_query(data));
    assert!(!shown.is_empty());
});
