//! TH-26, H-05: backend message framing and decoding on arbitrary bytes.
//!
//! The first two bytes choose the decode limits and the chunk sizes; the
//! rest is a stream of would-be server messages. Properties beyond "no
//! panic": framing the whole input agrees with streaming decoding over
//! arbitrary chunk boundaries, every decoded message re-encodes to its
//! exact bytes, and no decoded message exceeds the limits. See
//! `harness::backend_decode`.

#![no_main]

#[path = "../harness.rs"]
mod harness;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    harness::backend_decode(data);
});
