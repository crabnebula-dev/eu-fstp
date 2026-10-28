//! Fuzz target `driver_core_sequence` of `fstp-cell-core` (TH-26, H-05, M3 design section 15).
//!
//! Design checks: random needs and events never panic.
//!
//! W0 skeleton. The code under test is a stub that refuses every input
//! with a typed `NotImplemented` error. Until lane W2c lands it, the
//! target checks only that no input panics and that a refusal formats.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let records: Vec<_> = data
        .chunks(64)
        .filter_map(|c| fstp_cell_core::decode_cell_record(c).ok())
        .collect();
    let shown = format!("{:?} {:?}", records, fstp_cell_core::replay(&[]));
    assert!(!shown.is_empty());
});
