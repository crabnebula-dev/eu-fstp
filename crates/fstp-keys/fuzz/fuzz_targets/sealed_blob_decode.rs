//! Fuzz target `sealed_blob_decode` of `fstp-keys` (TH-26, H-05, M3 design section 15).
//!
//! Design checks: no panic; accepted input re-encodes byte for byte; a mutated byte never opens.
//!
//! W0 skeleton. The code under test is a stub that refuses every input
//! with a typed `NotImplemented` error. Until lane W2f lands it, the
//! target checks only that no input panics and that a refusal formats.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let shown = format!("{:?}", fstp_keys::envelope::decode_sealed_blob(data));
    assert!(!shown.is_empty());
});
