//! Fuzz target `witness_message_decode` of `fstp-witness` (TH-26, H-05, M3 design section 15).
//!
//! Design checks: no panic; round trip; an abort for an unknown prepare refused.
//!
//! W0 skeleton. The code under test is a stub that refuses every input
//! with a typed `NotImplemented` error. Until lane W2g lands it, the
//! target checks only that no input panics and that a refusal formats.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let shown = format!("{:?}", fstp_witness::decode_witness_message(data));
    assert!(!shown.is_empty());
});
