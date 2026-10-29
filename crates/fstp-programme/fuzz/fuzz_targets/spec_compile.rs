//! Fuzz target `spec_compile` of `fstp-programme` (TH-26, H-05, M4 design section 9).
//!
//! Design checks: compile never panics; accepted specs round-trip through decompile.
//!
//! W0 skeleton. The code under test is a stub that refuses every input
//! with a typed `NotImplemented` error. Until lane W1a lands it, the
//! target checks only that no input panics and that a refusal formats.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let shown = format!(
        "{:?}",
        fstp_programme::decode_spec(data).map(|s| fstp_programme::compile(&s))
    );
    assert!(!shown.is_empty());
});
