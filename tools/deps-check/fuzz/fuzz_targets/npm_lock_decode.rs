//! Fuzz target for the `package-lock.json` and `package.json` parsers of
//! the npm lockfile gate (TH-26, H-05, ADR-003 amendment, M3 design
//! section 15).
//!
//! Beyond "no panic": the properties in `deps_check::fuzzing::npm_lock`,
//! which returns an error when one fails.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Err(e) = deps_check::fuzzing::npm_lock(data) {
        panic!("npm_lock: {e}");
    }
});
