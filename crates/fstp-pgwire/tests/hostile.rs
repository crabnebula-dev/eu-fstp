//! TH-26: the fuzz target properties, run in the normal test suite.
//!
//! These tests apply the fuzz harness (`fuzz/harness.rs`) to the committed
//! seeds and to deterministic mutations of them, so the properties are
//! checked on every `cargo test` between fuzzing campaigns. Crashes found
//! by fuzzing are kept here as `th26_regression_*` tests.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
#![allow(unreachable_pub)]

#[path = "../fuzz/harness.rs"]
mod harness;

use std::path::Path;

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
            2 if !v.is_empty() => {
                let cut = rng.below(v.len());
                v.truncate(cut);
            }
            3 => {
                let i = rng.below(v.len() + 1);
                v.insert(i, rng.next() as u8);
            }
            _ if v.len() > 1 => {
                let i = rng.below(v.len());
                v.remove(i);
            }
            _ => {}
        }
    }
    v
}

fn run(target: &str, mutations: usize, f: fn(&[u8])) {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for seed in seeds(target) {
        f(&seed);
        for _ in 0..mutations {
            f(&mutate(&mut rng, &seed));
        }
    }
}

#[test]
fn th26_backend_decode_seeds_and_mutations() {
    run("pg_backend_decode", 300, harness::backend_decode);
}

#[test]
fn th26_scram_server_messages_seeds_and_mutations() {
    run(
        "pg_scram_server_messages",
        100,
        harness::scram_server_messages,
    );
}

#[test]
fn th26_value_decode_seeds_and_mutations() {
    run("pg_value_decode", 300, harness::value_decode);
}

#[test]
fn th26_hostile_server_seeds_and_mutations() {
    run("pg_hostile_server", 40, harness::hostile_server);
}

#[test]
fn th26_i83_cert_subject_ou_seeds_and_mutations() {
    run("pg_cert_subject_ou", 300, harness::cert_subject_ou);
}

/// I-83: the certificate seeds read as the OUs their subjects list, so the
/// subject OU fuzzer starts from certificates the reader accepts.
#[test]
fn i83_cert_subject_ou_seeds_read_as_their_subjects() {
    use fstp_pgwire::x509::subject_organizational_units as ous;
    let read = |name: &str| -> Vec<Vec<u8>> {
        ous(&seed("pg_cert_subject_ou", name))
            .unwrap()
            .into_iter()
            .map(<[u8]>::to_vec)
            .collect()
    };
    assert_eq!(read("one-ou"), vec![b"vault".to_vec()]);
    assert_eq!(
        read("two-ous"),
        vec![b"vault".to_vec(), b"application".to_vec()]
    );
    assert_eq!(read("multi-valued-rdn").len(), 2);
    assert!(read("no-ou").is_empty());
    assert!(read("test-server").is_empty());
}

/// The transcript seed drives every operation of the harness as scripted,
/// so the hostile-server fuzzer starts from deep states.
#[test]
fn hostile_harness_transcript_reaches_every_operation() {
    let seed = std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/seeds/pg_hostile_server/plaintext"),
    )
    .unwrap();
    for chunk in [1, 3, 64] {
        assert_eq!(
            harness::transcript_ops(&seed[2..], chunk),
            Some(5),
            "chunk {chunk}"
        );
    }
}

/// The SCRAM seeds include an exchange that the client must accept.
#[test]
fn scram_harness_seed_with_reference_signature_authenticates() {
    for mode in 0..3 {
        let seed = std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join(format!("fuzz/seeds/pg_scram_server_messages/mode{mode}-ok")),
        )
        .unwrap();
        harness::scram_server_messages(&seed);
    }
}

/// The same transcript inside a genuine TLS session on the duplex.
#[test]
fn hostile_harness_tls_transcript_reaches_every_operation() {
    let seed = std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/seeds/pg_hostile_server/tls-session"),
    )
    .unwrap();
    assert_eq!(harness::hostile_server_tls(&seed), Some(5));
}

fn seed(target: &str, name: &str) -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fuzz/seeds")
            .join(target)
            .join(name),
    )
    .unwrap()
}

/// R-NF-09: the client stream checks see a real cleartext password. The
/// client sends it only when the session holds a TLS certificate; without
/// one it refuses, and the harness asserts that in every mode.
#[test]
fn hostile_harness_cleartext_password_needs_a_tls_certificate() {
    let script = seed("pg_hostile_server", "cleartext-plaintext");
    let (ops, out) = harness::plaintext_run(&script[2..], 63, true);
    assert_eq!(harness::cleartext_passwords(&out), 1);
    assert_eq!(ops, Some(5));
    let (ops, out) = harness::plaintext_run(&script[2..], 63, false);
    assert_eq!(harness::cleartext_passwords(&out), 0);
    assert_eq!(ops, None);
    // Every mode runs the same script through its own checks.
    for name in [
        "cleartext-plaintext",
        "cleartext-fake-cert",
        "cleartext-default-policy",
        "cleartext-scripted",
        "cleartext-tls-session",
    ] {
        harness::hostile_server(&seed("pg_hostile_server", name));
    }
}

/// The client-output checks reject a cleartext password outside TLS, bytes
/// that are not TLS records after the SSLRequest, and a simple Query.
#[test]
fn hostile_harness_client_output_checks_catch_violations() {
    let mut startup = Vec::new();
    fstp_pgwire::proto::frontend::startup(&[("user", "fuzz")], &mut startup).unwrap();
    let mut password = Vec::new();
    fstp_pgwire::proto::frontend::password(harness::PASSWORD.as_bytes(), &mut password).unwrap();
    let stream = [startup.as_slice(), &password].concat();
    assert_eq!(harness::cleartext_passwords(&stream), 1);
    // A truncated last frame is tolerated, and is not a password.
    assert_eq!(harness::cleartext_passwords(&stream[..stream.len() - 1]), 0);
    let query = [startup.as_slice(), b"Q\0\0\0\x0dSELECT 1\0"].concat();
    assert!(std::panic::catch_unwind(|| harness::cleartext_passwords(&query)).is_err());

    let ssl = fstp_pgwire::proto::frontend::ssl_request();
    let tls_ok = [&ssl[..], b"\x16\x03\x01\x00\x02ab\x17\x03\x03\x00"].concat();
    harness::check_tls_wire(&tls_ok);
    let leaked = [&ssl[..], password.as_slice()].concat();
    assert!(std::panic::catch_unwind(|| harness::check_tls_wire(&leaked)).is_err());
    let no_ssl = [b"\x16\x03\x01\x00\x02ab".as_slice(), &ssl].concat();
    assert!(std::panic::catch_unwind(|| harness::check_tls_wire(&no_ssl)).is_err());
}
