//! TH-26: real sessions between this crate's client and server, run in the
//! normal test suite.
//!
//! These tests apply the `tls_round_trip` fuzz target's properties to its
//! committed seeds and to deterministic pseudo-random inputs. See
//! `support/round_trip.rs` for the input layout and the properties.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

#[path = "support/round_trip.rs"]
mod round_trip;

use std::collections::BTreeSet;
use std::path::Path;

use fstp_tls::{ClientConfig, ServerConfig};
use round_trip::{Ending, HEADER_LEN, run};

const CA: &[u8] = include_bytes!("../testdata/ca.pem");
const CLIENT: &[u8] = include_bytes!("../testdata/client.pem");
const CLIENT_KEY: &[u8] = include_bytes!("../testdata/client-key.pem");
const SERVER: &[u8] = include_bytes!("../testdata/server.pem");
const SERVER_KEY: &[u8] = include_bytes!("../testdata/server-key.pem");

fn configs() -> (ClientConfig, ServerConfig) {
    (
        ClientConfig::mutual(CA, CLIENT, CLIENT_KEY).unwrap(),
        ServerConfig::mutual(SERVER, SERVER_KEY, CA).unwrap(),
    )
}

/// Deterministic xorshift generator. Not cryptographic.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

/// Finding tls-fuzz-targets-never-reach-stream-adapter, TH-26.
///
/// The committed seeds of the round-trip target run complete sessions,
/// detect truncations, report corruption as typed TLS errors and survive a
/// stalled handshake. Each seed name starts with the ending it must reach.
/// So the fuzz target reaches the stream adapter's reads, writes,
/// backpressure, `close_notify` handling and truncation detection.
#[test]
fn review_tls_fuzz_round_trip_reaches_stream_adapter() {
    let (client, server) = configs();
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/seeds/tls_round_trip");
    let mut paths: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    paths.sort();
    let mut seen = BTreeSet::new();
    for path in paths {
        let name = path.file_name().unwrap().to_str().unwrap().to_owned();
        let input = std::fs::read(&path).unwrap();
        let ending = run(&input, &client, &server).unwrap_or_else(|e| panic!("{name}: {e}"));
        let want = match name.split('-').next() {
            Some("complete") => Ending::Complete,
            Some("truncated") => Ending::Truncated,
            Some("failure") => Ending::TlsFailure,
            Some("stalled") => Ending::Stalled,
            _ => panic!("seed {name} does not name its ending"),
        };
        assert_eq!(ending, want, "{name}");
        seen.insert(format!("{ending:?}"));
    }
    assert_eq!(seen.len(), 4, "every ending needs a seed: {seen:?}");
}

/// TH-26: pseudo-random inputs keep every round-trip property. Payloads
/// stay small here so the suite stays fast; the fuzz target covers the
/// large ones.
#[test]
fn th26_round_trip_properties_hold_for_random_inputs() {
    let (client, server) = configs();
    let mut rng = Rng(0x0dd5_eed5);
    for i in 0..300 {
        let len = HEADER_LEN + (rng.next() % 200) as usize;
        let mut input: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        // Payload lengths of at most 4 KiB, without the 16 KiB extra.
        for (len_at, mode_at) in [(5usize, 4usize), (11, 10)] {
            input[len_at] &= 0x0F;
            input[mode_at] &= !8;
        }
        if let Err(e) = run(&input, &client, &server) {
            panic!("input {i} {input:?}: {e}");
        }
    }
}
