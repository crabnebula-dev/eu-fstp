//! Fuzz target `proposal_decode` of `fstp-import` (TH-26, H-05, M4 design section 9).
//!
//! Design checks: proposer output; UntrustedValue kept byte for byte.
//!
//! W0 skeleton. The code under test is a stub that refuses every input
//! with a typed `NotImplemented` error. Until lane W2b lands it, the
//! target checks only that no input panics and that a refusal formats.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let shown = format!("{:?}", fstp_import::decode_proposal(data));
    assert!(!shown.is_empty());
});
