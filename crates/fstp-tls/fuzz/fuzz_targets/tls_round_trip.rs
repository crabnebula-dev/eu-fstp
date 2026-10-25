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
//! - No lost wake-up, no busy loop, and termination within a poll budget.

#![no_main]

#[path = "../../tests/support/round_trip.rs"]
mod round_trip;

use std::sync::OnceLock;

use fstp_tls::{ClientConfig, ServerConfig};
use libfuzzer_sys::fuzz_target;

const CA: &[u8] = include_bytes!("../../testdata/ca.pem");
const CLIENT: &[u8] = include_bytes!("../../testdata/client.pem");
const CLIENT_KEY: &[u8] = include_bytes!("../../testdata/client-key.pem");
const SERVER: &[u8] = include_bytes!("../../testdata/server.pem");
const SERVER_KEY: &[u8] = include_bytes!("../../testdata/server-key.pem");

fn configs() -> &'static (ClientConfig, ServerConfig) {
    static CFG: OnceLock<(ClientConfig, ServerConfig)> = OnceLock::new();
    CFG.get_or_init(|| {
        let client = ClientConfig::mutual(CA, CLIENT, CLIENT_KEY);
        let server = ServerConfig::mutual(SERVER, SERVER_KEY, CA);
        match (client, server) {
            (Ok(c), Ok(s)) => (c, s),
            (Err(e), _) | (_, Err(e)) => panic!("test certificates are invalid: {e}"),
        }
    })
}

fuzz_target!(|data: &[u8]| {
    let (client, server) = configs();
    if let Err(violation) = round_trip::run(data, client, server) {
        panic!("{violation}");
    }
});
