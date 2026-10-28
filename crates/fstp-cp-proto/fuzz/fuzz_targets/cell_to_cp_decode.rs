//! Fuzz target `cell_to_cp_decode` of `fstp-cp-proto` (TH-26, H-05, M3 design section 15).
//!
//! Design checks: no panic; round trip; only declared field classes decode.
//!
//! W0 skeleton. The code under test is a stub that refuses every input
//! with a typed `NotImplemented` error. Until lane W2h lands it, the
//! target checks only that no input panics and that a refusal formats.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let shown = format!("{:?}", fstp_cp_proto::decode_cell_to_cp(data));
    assert!(!shown.is_empty());
});
