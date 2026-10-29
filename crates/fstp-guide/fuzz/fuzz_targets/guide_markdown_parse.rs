//! Fuzz target `guide_markdown_parse` of `fstp-guide` (TH-26, H-05, M4 design section 9).
//!
//! Design checks: never panics; constructs outside the subset are refused, never passed through.
//!
//! W0 skeleton. The code under test is a stub that refuses every input
//! with a typed `NotImplemented` error. Until lane W2c lands it, the
//! target checks only that no input panics and that a refusal formats.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let shown = format!("{:?}", fstp_guide::parse_markdown(data));
    assert!(!shown.is_empty());
});
