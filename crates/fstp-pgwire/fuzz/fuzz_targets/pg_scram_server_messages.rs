//! TH-26, H-05: SCRAM server-first and server-final parsing and
//! verification.
//!
//! The input selects the channel binding mode and carries a
//! server-first-message, a server-final-message and extra bytes (used as a
//! certificate and as base64 input). Properties beyond "no panic": the
//! client accepts a server-first-message exactly when an independent
//! reference parser does, its proof equals a reference computation, only
//! the reference server signature verifies, and base64 decoding is strict
//! and canonical. See `harness::scram_server_messages`.

#![no_main]

#[path = "../harness.rs"]
mod harness;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    harness::scram_server_messages(data);
});
