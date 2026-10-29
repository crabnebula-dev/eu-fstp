//! Fuzz target `guide_render` of `fstp-guide` (TH-26, H-05, M4 design section 9).
//!
//! Design checks: never panics over arbitrary bindings; output passes the fstp-html well-formedness check.
//!
//! W0 skeleton. The code under test is a stub that refuses every input
//! with a typed `NotImplemented` error. Until lane W2c lands it, the
//! target checks only that no input panics and that a refusal formats.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let shown = format!(
        "{:?}",
        fstp_guide::parse_template(data).map(|t| fstp_guide::render(&t))
    );
    assert!(!shown.is_empty());
});
