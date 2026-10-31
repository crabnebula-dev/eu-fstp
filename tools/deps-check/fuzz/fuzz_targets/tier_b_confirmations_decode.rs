//! Fuzz target for the `deps/tier-b-confirmations.txt` parser of the Tier B
//! release gate (TH-26, H-05, I-74, ADR-001 A5, M3 design section 15).
//!
//! Beyond "no panic": the properties in `deps_check::fuzzing::tier_b_confirmations`,
//! which returns an error when one fails.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Err(e) = deps_check::fuzzing::tier_b_confirmations(data) {
        panic!("tier_b_confirmations: {e}");
    }
});
