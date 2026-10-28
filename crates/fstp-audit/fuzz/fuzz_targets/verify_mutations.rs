//! Fuzz target `verify_mutations` of `fstp-audit` (TH-26, H-05, M3 design section 15).
//!
//! Design checks: the verifier never accepts a mutated chain.
//!
//! W0 skeleton. The code under test is a stub that refuses every input
//! with a typed `NotImplemented` error. Until lane W2g lands it, the
//! target checks only that no input panics and that a refusal formats.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let rows: Vec<fstp_audit::ChainRow> = data
        .chunks(48)
        .filter_map(|c| fstp_audit::chain::decode_chain_row(c).ok())
        .collect();
    let shown = format!("{:?}", fstp_audit::verify::verify(&rows, &[], &[], &[]));
    assert!(!shown.is_empty());
});
