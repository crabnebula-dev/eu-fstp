//! TH-26: handshakes against hostile peers, run in the normal test suite.
//!
//! These tests apply the fuzz targets' properties to the committed seeds and
//! to deterministic mutations of them. They keep the properties checked on
//! every `cargo test`, between fuzzing campaigns.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::path::Path;

use fstp_rt::future::poll_bounded;
use fstp_rt::scripted::ScriptedStream;
use fstp_tls::{ClientConfig, ServerConfig, TlsError, TlsErrorKind, accept, connect};

const CA: &[u8] = include_bytes!("../testdata/ca.pem");
const CLIENT: &[u8] = include_bytes!("../testdata/client.pem");
const CLIENT_KEY: &[u8] = include_bytes!("../testdata/client-key.pem");
const SERVER: &[u8] = include_bytes!("../testdata/server.pem");
const SERVER_KEY: &[u8] = include_bytes!("../testdata/server-key.pem");

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

    fn below(&mut self, n: usize) -> usize {
        (self.next() % (n.max(1) as u64)) as usize
    }
}

fn seeds(target: &str) -> Vec<Vec<u8>> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fuzz/seeds")
        .join(target);
    let mut out: Vec<Vec<u8>> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    out.sort();
    assert!(!out.is_empty(), "no seeds for {target}");
    out
}

fn mutate(rng: &mut Rng, input: &[u8]) -> Vec<u8> {
    let mut v = input.to_vec();
    for _ in 0..=rng.below(4) {
        match rng.below(5) {
            0 if !v.is_empty() => {
                let i = rng.below(v.len());
                v[i] ^= 1 << rng.below(8);
            }
            1 if !v.is_empty() => {
                let i = rng.below(v.len());
                v[i] = rng.next() as u8;
            }
            2 => {
                let cut = rng.below(v.len() + 1);
                v.truncate(cut);
            }
            3 => {
                let i = rng.below(v.len() + 1);
                let n = rng.below(16);
                for _ in 0..n {
                    v.insert(i, rng.next() as u8);
                }
            }
            _ if v.len() > 3 => {
                // Re-roll the IO timing control bytes.
                for b in v.iter_mut().take(3) {
                    *b = rng.next() as u8;
                }
            }
            _ => {}
        }
    }
    v
}

fn check_client(cfg: &ClientConfig, input: &[u8]) {
    let budget = input.len() * 4 + 20_000;
    let io = ScriptedStream::from_fuzz_input(input);
    let res = poll_bounded(connect(cfg, "localhost", io), budget)
        .unwrap_or_else(|| panic!("client handshake did not terminate: {input:?}"));
    let err = match res {
        Ok(_) => panic!("client handshake succeeded against a hostile server"),
        Err(e) => e,
    };
    assert!(TlsError::from_io(&err).is_some(), "untyped error {err:?}");
}

fn check_server(cfg: &ServerConfig, input: &[u8]) {
    let budget = input.len() * 4 + 20_000;
    let io = ScriptedStream::from_fuzz_input(input);
    let res = poll_bounded(accept(cfg, io), budget)
        .unwrap_or_else(|| panic!("server handshake did not terminate: {input:?}"));
    let err = match res {
        Ok(_) => panic!("server handshake succeeded against a hostile client"),
        Err(e) => e,
    };
    assert!(TlsError::from_io(&err).is_some(), "untyped error {err:?}");
}

/// TH-26: a client never completes a handshake with a hostile server, always
/// terminates, and reports typed errors.
#[test]
fn th26_hostile_server_never_completes_client_handshake() {
    let cfg = ClientConfig::mutual(CA, CLIENT, CLIENT_KEY).unwrap();
    let seeds = seeds("tls_client_hostile_server");
    for s in &seeds {
        check_client(&cfg, s);
    }
    let mut rng = Rng(0x7a11_c0de);
    for i in 0..1500 {
        let base = &seeds[i % seeds.len()];
        check_client(&cfg, &mutate(&mut rng, base));
    }
    // Pure noise and edge cases.
    for len in [0usize, 1, 2, 3, 4, 5, 6, 64, 5000] {
        let noise: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        check_client(&cfg, &noise);
    }
}

/// TH-26: a mutual TLS server never completes a handshake with a hostile
/// client, always terminates, and reports typed errors.
#[test]
fn th26_hostile_client_never_completes_server_handshake() {
    let cfg = ServerConfig::mutual(SERVER, SERVER_KEY, CA).unwrap();
    let seeds = seeds("tls_server_hostile_client");
    for s in &seeds {
        check_server(&cfg, s);
    }
    let mut rng = Rng(0x5e7e_c0de);
    for i in 0..1500 {
        let base = &seeds[i % seeds.len()];
        check_server(&cfg, &mutate(&mut rng, base));
    }
    for len in [0usize, 1, 2, 3, 4, 5, 6, 64, 5000] {
        let noise: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        check_server(&cfg, &noise);
    }
}

/// A handshake message of type `msg_type` and body length `len`, split into
/// handshake records that carry `frag` payload bytes each.
fn fragmented_handshake_message(msg_type: u8, len: usize, frag: usize) -> Vec<u8> {
    let mut msg = vec![msg_type];
    msg.extend_from_slice(&u32::try_from(len).unwrap().to_be_bytes()[1..]);
    msg.resize(4 + len, 0);
    let mut out = Vec::new();
    for chunk in msg.chunks(frag) {
        out.extend_from_slice(&[22, 3, 3]);
        out.extend_from_slice(&u16::try_from(chunk.len()).unwrap().to_be_bytes());
        out.extend_from_slice(chunk);
    }
    out
}

/// Finding tls-untyped-buffer-full-error-crashes-fuzz-targets, TH-26.
///
/// A peer that splits one large handshake message into small records fills
/// rustls's 64 KiB handshake buffer, since the record headers count towards
/// it. rustls then reports its own `io::Error` from `read_tls`. Before the
/// fix, that error reached the caller untyped and crashed both fuzz targets.
#[test]
fn th26_regression_fragmented_handshake_buffer_full() {
    let client = ClientConfig::mutual(CA, CLIENT, CLIENT_KEY).unwrap();
    let server = ServerConfig::mutual(SERVER, SERVER_KEY, CA).unwrap();
    let kind = |res: Option<std::io::Result<_>>| match res {
        Some(Err(e)) => TlsError::from_io(&e).map(TlsError::kind),
        Some(Ok(_)) => panic!("handshake succeeded against a hostile peer"),
        None => panic!("handshake did not terminate"),
    };
    for (len, frag) in [
        (60_000usize, 1usize),
        (60_000, 16),
        (65_000, 255),
        (0xffff, 255),
    ] {
        // Control bytes: no read chunk limit, no `Pending`, no write limit.
        let mut input = vec![0xFF, 0x00, 0xFF];
        input.extend(fragmented_handshake_message(1, len, frag));
        check_server(&server, &input);
        let io = ScriptedStream::from_fuzz_input(&input);
        let res = poll_bounded(accept(&server, io), 1_000_000).map(|r| r.map(|_| ()));
        assert_eq!(
            kind(res),
            Some(TlsErrorKind::Protocol),
            "server {len} {frag}"
        );

        let mut input = vec![0xFF, 0x00, 0xFF];
        input.extend(fragmented_handshake_message(2, len, frag));
        check_client(&client, &input);
        let io = ScriptedStream::from_fuzz_input(&input);
        let res = poll_bounded(connect(&client, "localhost", io), 1_000_000).map(|r| r.map(|_| ()));
        assert_eq!(
            kind(res),
            Some(TlsErrorKind::Protocol),
            "client {len} {frag}"
        );
    }
}
