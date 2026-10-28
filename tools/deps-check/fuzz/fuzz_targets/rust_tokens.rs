//! Fuzz target for the Rust source lexer of the M3 source scans (TH-26,
//! H-05, M3 design sections 2.4 and 15).
//!
//! Beyond "no panic": the properties in `deps_check::fuzzing::rust_tokens`,
//! which returns an error when one fails.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Err(e) = deps_check::fuzzing::rust_tokens(data) {
        panic!("rust_tokens: {e}");
    }
});
