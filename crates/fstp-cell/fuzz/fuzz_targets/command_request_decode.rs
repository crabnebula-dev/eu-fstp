//! Fuzz target `command_request_decode` of `fstp-cell` (TH-26, H-05, M3 design section 15).
//!
//! Design checks: no panic; size limits; a minor field is refused.
//!
//! W0 skeleton. The code under test is a stub that refuses every input
//! with a typed `NotImplemented` error. Until lane W3a lands it, the
//! target checks only that no input panics and that a refusal formats.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let shown = format!("{:?}", fstp_cell::http::decode_command_request(data));
    assert!(!shown.is_empty());
});
