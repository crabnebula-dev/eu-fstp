//! Fuzz target `origin_write_decode` of `fstp-vault` (TH-26, H-05, M3 design section 15).
//!
//! Design checks: no panic; signature checked before any field is used.
//!
//! W0 skeleton. The code under test is a stub that refuses every input
//! with a typed `NotImplemented` error. Until lane W2d lands it, the
//! target checks only that no input panics and that a refusal formats.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let shown = format!("{:?}", fstp_vault::decode_origin_write(data));
    assert!(!shown.is_empty());
});
