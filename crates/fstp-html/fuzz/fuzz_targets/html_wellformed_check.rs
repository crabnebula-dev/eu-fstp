//! Fuzz target `html_wellformed_check` of `fstp-html` (TH-26, H-05, M4 design section 9).
//!
//! Design checks: the checker never panics on arbitrary bytes; it accepts every document the writer produces.
//!
//! W0 skeleton. The code under test is a stub that refuses every input
//! with a typed `NotImplemented` error. Until lane W1d lands it, the
//! target checks only that no input panics and that a refusal formats.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let shown = format!("{:?}", fstp_html::check_wellformed(data));
    assert!(!shown.is_empty());
});
