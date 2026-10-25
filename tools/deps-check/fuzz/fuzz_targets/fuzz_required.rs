//! Fuzz target for the `deps/fuzz-required.txt` parser (TH-26, H-05).
//!
//! Beyond "no panic": accepted names are valid and unique, one name per line
//! parses back to the same list, and error line numbers stay in range.
//! The checks live in `deps_check::fuzzing::fuzz_required`, which returns an error
//! when a property fails.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Err(e) = deps_check::fuzzing::fuzz_required(data) {
        panic!("fuzz_required: {e}");
    }
});
