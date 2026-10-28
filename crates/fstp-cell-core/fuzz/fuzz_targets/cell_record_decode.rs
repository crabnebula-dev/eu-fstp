//! Fuzz target `cell_record_decode` of `fstp-cell-core` (TH-26, H-05, M3 design section 15).
//!
//! Design checks: every schema version round-trips.
//!
//! W0 skeleton. The code under test is a stub that refuses every input
//! with a typed `NotImplemented` error. Until lane W2c lands it, the
//! target checks only that no input panics and that a refusal formats.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let shown = format!("{:?}", fstp_cell_core::decode_cell_record(data));
    assert!(!shown.is_empty());
});
