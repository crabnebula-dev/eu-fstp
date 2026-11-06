//! TH-26, H-05: fuzz target `smtp_sink_command`. See `harness.rs` for the properties
//! beyond "no panic".

#![no_main]

#[path = "../harness.rs"]
mod harness;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    harness::sink_command(data);
});
