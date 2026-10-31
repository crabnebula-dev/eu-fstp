//! Fuzz target `signup_form_decode` of `fstp-signup` (TH-26, H-05, M4 design section 9).
//!
//! Design checks: duplicate fields, unknown fields, bad percent-encoding and over-long values are refused.
//!
//! W0 skeleton. The code under test is a stub that refuses every input
//! with a typed `NotImplemented` error. Until lane W2f lands it, the
//! target checks only that no input panics and that a refusal formats.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let shown = format!("{:?}", fstp_signup::decode_signup_form(data));
    assert!(!shown.is_empty());
});
