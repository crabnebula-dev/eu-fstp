//! Fuzz target for the `deps/allowlist.txt` parser (TH-26, H-05).
//!
//! Beyond "no panic": accepted entries are valid and unique, rendering then
//! parsing returns the same entries, and error line numbers stay in range.
//! The checks live in `deps_check::fuzzing::allowlist`, which returns an error
//! when a property fails.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Err(e) = deps_check::fuzzing::allowlist(data) {
        panic!("allowlist: {e}");
    }
});
