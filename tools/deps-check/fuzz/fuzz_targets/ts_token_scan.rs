//! Fuzz target for the TypeScript source scan of `web/src` (TH-26, H-05,
//! M4 design section 9, `ts_token_scan`).
//!
//! Beyond "no panic": the properties in `deps_check::fuzzing::ts_token_scan`,
//! which returns an error when one fails.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Err(e) = deps_check::fuzzing::ts_token_scan(data) {
        panic!("ts_token_scan: {e}");
    }
});
