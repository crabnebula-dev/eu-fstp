//! Fuzz target for the `cargo metadata` reader and the graph analysis (TH-26, H-05).
//!
//! Beyond "no panic": accepted documents have consistent indices, and role
//! classification and aggregation run on them with consistent results.
//! The checks live in `deps_check::fuzzing::cargo_metadata`, which returns an error
//! when a property fails.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Err(e) = deps_check::fuzzing::cargo_metadata(data) {
        panic!("cargo_metadata: {e}");
    }
});
