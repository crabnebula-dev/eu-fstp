//! Reviewer reproducers for lane W0 of M3, the `fstp-pki` test edges
//! (design sections 1.3, 15 and 19 row W1i).
//!
//! Each test fails against the reviewed working tree and passes once the
//! dependency line it names is landed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The dependency names declared in the `[section]` table of `manifest`.
fn table_keys(manifest: &str, section: &str) -> Vec<String> {
    let head = format!("[{section}]");
    let mut inside = false;
    let mut out = Vec::new();
    for line in manifest.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            inside = t == head;
            continue;
        }
        if !inside || t.is_empty() || t.starts_with('#') {
            continue;
        }
        if let Some((key, _)) = t.split_once('=') {
            let key = key.trim();
            let name = key.split('.').next().unwrap_or(key).trim_matches('"');
            out.push(name.to_owned());
        }
    }
    out
}

fn read(p: &Path) -> String {
    fs::read_to_string(p).unwrap()
}

/// Design section 1.3 ("Tests validate every output with rustls-webpki")
/// and section 19 row W1i ("rustls-webpki round trips").
/// `webpki::EndEntityCert::verify_for_usage` takes `time: UnixTime`, and
/// `EndEntityCert::try_from` and `anchor_from_trusted_cert` take
/// `&CertificateDer`. Both types live in `rustls-pki-types`. rustls-webpki
/// 0.103.16 does not re-export that crate, and `UnixTime` has no `From`
/// impl, so a test without a direct `rustls-pki-types` edge cannot build
/// the time argument. Path validation and lifetime checks are then out of
/// reach. The edge adds no package: rustls-pki-types 1.15.1 is already an
/// ADR-001 root with the same features.
#[test]
fn review_pki_round_trip_tests_can_name_unix_time() {
    let manifest = read(&crate_dir().join("Cargo.toml"));
    let dev = table_keys(&manifest, "dev-dependencies");
    assert!(
        dev.iter().any(|k| k == "rustls-webpki"),
        "setup: rustls-webpki is a dev-dependency: {dev:?}"
    );
    assert!(
        dev.iter().any(|k| k == "rustls-pki-types"),
        "fstp-pki dev-dependencies {dev:?} hold rustls-webpki without \
         rustls-pki-types, so no test can construct the `UnixTime` that \
         `EndEntityCert::verify_for_usage` requires"
    );
}

/// Design section 15, `fstp-pki` row: the fuzz target
/// `cert_build_roundtrip` checks that "arbitrary names, serials and
/// lifetimes build certificates that rustls-webpki parses with equal
/// fields". The fuzz project is its own workspace, so the dev-dependencies
/// of `fstp-pki` do not reach it. W1i owns `crates/fstp-pki/fuzz/**`, but
/// the lead owns its third-party lines (section 2.5). Without a
/// rustls-webpki line there, W1i cannot write the check.
#[test]
fn review_pki_fuzz_roundtrip_can_parse_with_webpki() {
    let manifest = read(&crate_dir().join("fuzz/Cargo.toml"));
    let deps = table_keys(&manifest, "dependencies");
    assert!(
        deps.iter().any(|k| k == "rustls-webpki"),
        "crates/fstp-pki/fuzz/Cargo.toml [dependencies] is {deps:?}; the \
         cert_build_roundtrip target cannot parse its output with rustls-webpki"
    );
}
