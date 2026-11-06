//! Fuzz target for the npm integrity decoder of the SBOM generator
//! (TH-26, H-05, R-NF-07, M9 design lane S1).
//!
//! Beyond "no panic": the properties in
//! `deps_check::fuzzing::sbom_integrity`, which returns an error when one
//! fails.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Err(e) = deps_check::fuzzing::sbom_integrity(data) {
        panic!("sbom_integrity: {e}");
    }
});
