//! TH-26, H-05: real TLS sessions between this crate's client and server.
//!
//! A mutual TLS client and server run a handshake and then exchange
//! payloads in both directions over an in-memory pipe. The fuzzer chooses
//! the pipe capacity, read and write chunking, injected `Pending` results
//! and payload sizes. It also chooses how each side closes, the order and
//! size of every read and write, and which woken side runs next. An input
//! can add one corrupted byte or a silent cut. Wake-ups are tracked per
//! side, as in the test `handshake_wakeups_are_precise`.
//!
//! An input can also ask for a resumed session (policy P2). A clean session
//! then runs first and leaves the client a ticket. Every run builds its own
//! configurations, so session caches start empty and a crash reproduces
//! from its input alone.
//!
//! This reaches the stream adapter after the handshake: the read loop,
//! truncation detection, `close_notify` handling, writes while rustls holds
//! buffered records, and shutdown.
//!
//! Properties checked beyond "no panic" (see `tests/support/round_trip.rs`):
//!
//! - What a side reads is always a prefix of what its peer sent.
//! - `Ok(0)` comes only after the complete payload and the peer's
//!   `close_notify`. A truncation fails with `UnexpectedEof`.
//! - Without faults, every byte arrives and both sides close cleanly.
//! - Every error is typed, and errors happen only after a fault.
//! - Without corruption, the session resumes exactly when the input asks.
//! - No lost wake-up, no busy loop, and termination within a poll budget.

#![no_main]

#[path = "../../tests/support/round_trip.rs"]
mod round_trip;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Err(violation) = round_trip::run(data) {
        panic!("{violation}");
    }
});
