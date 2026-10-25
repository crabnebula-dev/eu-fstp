//! Fuzz target for the `deps/adr-roots.txt` parser (TH-26, H-05).
//!
//! Beyond "no panic": accepted roots carry valid ADR identifiers and feature
//! names, rendering then parsing returns the same roots, and error line
//! numbers stay in range.
//! The checks live in `deps_check::fuzzing::adr_roots`, which returns an error
//! when a property fails.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Err(e) = deps_check::fuzzing::adr_roots(data) {
        panic!("adr_roots: {e}");
    }
});
