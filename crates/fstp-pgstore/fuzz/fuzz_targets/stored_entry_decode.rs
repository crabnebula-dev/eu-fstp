//! Fuzz target `stored_entry_decode` of `fstp-pgstore` (TH-26, H-05, M3 design section 15).
//!
//! Design checks: decrypt and decode never panic on arbitrary rows.
//!
//! W0 skeleton. The code under test is a stub that refuses every input
//! with a typed `NotImplemented` error. Until lane W2e lands it, the
//! target checks only that no input panics and that a refusal formats.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let shown = format!("{:?}", fstp_pgstore::decode_stored_entry(data));
    assert!(!shown.is_empty());
});
