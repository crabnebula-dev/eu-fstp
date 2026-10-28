//! Fuzz target `keyd_request_decode` of `fstp-keyd` (TH-26, H-05, M3 design section 15).
//!
//! Design checks: no panic; limits enforced.
//!
//! W0 skeleton. The code under test is a stub that refuses every input
//! with a typed `NotImplemented` error. Until lane W2f lands it, the
//! target checks only that no input panics and that a refusal formats.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    match fstp_keyd::decode_request(data) {
        Ok(r) => assert!(!format!("{r:?}").is_empty()),
        Err(e) => assert!(!e.to_string().is_empty()),
    }
});
