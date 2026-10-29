//! Fuzz target `creator_command_decode` of `fstp-creator` (TH-26, H-05, M4 design section 9).
//!
//! Design checks: never panics; round trip.
//!
//! W0 skeleton. The code under test is a stub that refuses every input
//! with a typed `NotImplemented` error. Until lane W2a lands it, the
//! target checks only that no input panics and that a refusal formats.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let shown = format!("{:?}", fstp_creator::decode_command(data));
    assert!(!shown.is_empty());
});
