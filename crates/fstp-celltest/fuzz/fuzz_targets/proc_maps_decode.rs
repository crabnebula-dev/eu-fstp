//! Fuzz target `proc_maps_decode` of `fstp-celltest` (TH-26, H-05, M3 design section 15).
//!
//! Design checks: no panic. Test-only parser.
//!
//! W0 skeleton. The code under test is a stub that refuses every input
//! with a typed `NotImplemented` error. Until lane W1a lands it, the
//! target checks only that no input panics and that a refusal formats.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let shown = format!("{:?}", fstp_celltest::procmem::decode_proc_maps(data));
    assert!(!shown.is_empty());
});
