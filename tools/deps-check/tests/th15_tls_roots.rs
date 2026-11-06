//! TH-15: the public TLS root store crate (ADR-001 amendment of
//! 2026-11-06) is registered with deps-check and recorded in ADR-001.
//!
//! These tests read files only. The gate itself runs on the real tree in
//! CI (`cargo run -p deps-check --locked`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(rel: &str) -> String {
    let p = repo_root().join(rel);
    fs::read_to_string(&p).unwrap_or_else(|e| panic!("cannot read {rel}: {e}"))
}

/// The version and checksum `Cargo.lock` records for `name`.
fn locked(name: &str) -> (String, String) {
    let lock = read("Cargo.lock");
    let block = lock
        .split("[[package]]")
        .find(|b| b.contains(&format!("name = \"{name}\"\n")))
        .unwrap_or_else(|| panic!("{name} is not in Cargo.lock"));
    let field = |key: &str| {
        block
            .lines()
            .find_map(|l| l.strip_prefix(&format!("{key} = \"")))
            .and_then(|v| v.strip_suffix('"'))
            .unwrap_or_else(|| panic!("{name}: no {key}"))
            .to_owned()
    };
    (field("version"), field("checksum"))
}

/// TH-15: webpki-roots is pinned in the allowlist with the version and
/// checksum of `Cargo.lock`, as a runtime crate under ADR-001.
#[test]
fn th15_webpki_roots_allowlisted_with_locked_version_and_checksum() {
    let (version, checksum) = locked("webpki-roots");
    let allow = read("deps/allowlist.txt");
    let line = allow
        .lines()
        .find(|l| l.split_whitespace().next() == Some("webpki-roots"))
        .expect("webpki-roots is not in deps/allowlist.txt");
    let fields: Vec<&str> = line.split_whitespace().collect();
    assert_eq!(fields.get(1).copied(), Some(version.as_str()));
    assert_eq!(fields.get(2).copied(), Some(checksum.as_str()));
    assert_eq!(fields.get(3).copied(), Some("ADR-001"));
    assert_eq!(fields.get(4).copied(), Some("runtime"));
}

/// TH-15: webpki-roots is an ADR-001 root with no features, and ADR-001
/// records its exact `name version`.
#[test]
fn th15_webpki_roots_is_an_adr_001_root_recorded_in_the_adr() {
    let roots = read("deps/adr-roots.txt");
    let line = roots
        .lines()
        .find(|l| l.split_whitespace().next() == Some("webpki-roots"))
        .expect("webpki-roots is not in deps/adr-roots.txt");
    let fields: Vec<&str> = line.split_whitespace().collect();
    assert_eq!(fields.get(1).copied(), Some("ADR-001"));
    assert_eq!(fields.get(2).copied(), Some("-"));

    let (version, _) = locked("webpki-roots");
    let adr = read("docs/adr/ADR-001-crypto-allowlist.md");
    assert!(adr.contains(&format!("webpki-roots {version}")));
    assert!(adr.contains("Amendment of 2026-11-06: public TLS root store"));
}

/// TH-15: only fstp-tls depends on webpki-roots directly, so every public
/// root decision goes through one configuration.
#[test]
fn th15_only_fstp_tls_depends_on_webpki_roots() {
    let crates = repo_root().join("crates");
    for entry in fs::read_dir(&crates).unwrap() {
        let dir = entry.unwrap().path();
        let manifest = dir.join("Cargo.toml");
        let Ok(text) = fs::read_to_string(&manifest) else {
            continue;
        };
        let name = dir.file_name().unwrap().to_string_lossy().into_owned();
        if name != "fstp-tls" {
            assert!(
                !text.contains("webpki-roots"),
                "{name} depends on webpki-roots"
            );
        }
    }
}
