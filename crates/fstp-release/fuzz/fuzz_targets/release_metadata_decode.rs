//! Fuzz target `release_metadata_decode` of `fstp-release` (TH-26, H-05, M3 design section 15).
//!
//! Design checks: no panic; signature checked before use.
//!
//! W0 skeleton. The code under test is a stub that refuses every input
//! with a typed `NotImplemented` error. Until lane W2j lands it, the
//! target checks only that no input panics and that a refusal formats.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let shown = format!(
        "{:?}",
        fstp_release::metadata::decode_release_metadata(data)
    );
    assert!(!shown.is_empty());
});
