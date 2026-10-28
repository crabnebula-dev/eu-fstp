//! Fuzz target `okms_response_decode` of `fstp-custody` (TH-26, H-05, M3 design section 15).
//!
//! Design checks: no panic; bounded allocation; unknown members refused; key bytes never in error displays.
//!
//! W0 skeleton. The code under test is a stub that refuses every input
//! with a typed `NotImplemented` error. Until lane W2f lands it, the
//! target checks only that no input panics and that a refusal formats.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    match fstp_custody::okms::decode_response(data) {
        Ok(r) => assert!(!format!("{r:?}").is_empty()),
        Err(e) => assert!(!e.to_string().is_empty()),
    }
});
