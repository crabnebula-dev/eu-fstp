//! Fuzz target for the `Cargo.lock` reader (TH-26, H-05).
//!
//! Beyond "no panic": accepted packages are well formed, rendering then
//! parsing returns the same lockfile, and error line numbers stay in range.
//! The checks live in `deps_check::fuzzing::cargo_lock`, which returns an error
//! when a property fails.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Err(e) = deps_check::fuzzing::cargo_lock(data) {
        panic!("cargo_lock: {e}");
    }
});
