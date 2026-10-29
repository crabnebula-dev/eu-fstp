//! I-18, design section 6.9: the shipped `fstp-vault` has no seed path.
//! Test facts are written only through `fstp-celltest` (layering rule 9).
//!
//! The design asks this test to check the vault's route table, its
//! configuration decoder and a source scan. `fstp-vault` has no route
//! table and no configuration decoder yet (lane W2d), so the two source
//! scans below stand for all three. Lane W2d adds the route table and
//! configuration checks here when those exist.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};

/// The identifiers only the test-only seeder may name.
const SEED_NAMES: [&str; 2] = ["SeedSource", "seed_fact"];

/// The crates that hold the vault: the service, its pure core and its
/// wire types.
const VAULT_CRATES: [&str; 3] = ["fstp-vault", "fstp-vault-core", "fstp-vault-proto"];

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for e in entries {
        let p = e.unwrap().path();
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or_default();
        if name == "target" || name.starts_with('.') {
            continue;
        }
        if p.is_dir() {
            rust_files(&p, out);
        } else if name.ends_with(".rs") {
            out.push(p);
        }
    }
}

/// The text of `source` with line comments removed, so doc prose that
/// names the rule does not count.
fn code_only(source: &str) -> String {
    source
        .lines()
        .map(|l| match l.find("//") {
            Some(i) => l.get(..i).unwrap_or_default(),
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// I-18, design section 6.9: `SeedSource` and `seed_fact` appear nowhere
/// outside `fstp-celltest`, except in the deps-check rule that names them.
#[test]
fn fstp_vault_has_no_seed_path() {
    let root = root();
    let mut files = Vec::new();
    rust_files(&root.join("crates"), &mut files);
    rust_files(&root.join("tools"), &mut files);
    assert!(!files.is_empty(), "no source file was found under {root:?}");
    let exempt = [
        root.join("crates/fstp-celltest"),
        root.join("tools/deps-check"),
    ];
    let mut hits = Vec::new();
    for f in files {
        if exempt.iter().any(|e| f.starts_with(e)) {
            continue;
        }
        let text = fs::read_to_string(&f).unwrap();
        for name in SEED_NAMES {
            if text.contains(name) {
                hits.push(format!("{}: {name}", f.display()));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "I-18: seed names outside fstp-celltest: {hits:?}"
    );
}

/// The names of the test-only seeder, its module and its binary. A vault
/// crate that names one reaches the seeder.
const SEEDER_NAMES: [&str; 8] = [
    "SeedSource",
    "SeedLog",
    "SeededWrite",
    "SeedError",
    "seed_fact",
    "vault_seed",
    "fstp-vault-seeded",
    "fstp_vault_seeded",
];

/// The spellings of a seed route, flag or file in a route table, an
/// argument parser or a configuration decoder, lowercased. The bare word
/// "seed" is lawful in vault code, for a key or a DRBG seed.
const SEED_PATHS: [&str; 6] = [
    "\"/seed",
    "/seed\"",
    "\"--seed",
    "seed_file",
    "seed-file",
    "fstp_vault_seed",
];

/// I-18, design section 6.9: the code of the vault crates names neither
/// the test-only seeder nor a seed route, flag or file. Comments may state
/// the rule.
///
/// Reading: the design asks for a scan for `SeedSource` and `seed_fact`
/// plus checks of the route table and the configuration decoder. Lane
/// W2d adds those two checks here, so this scan does not ban the bare
/// word "seed".
#[test]
fn fstp_vault_code_names_no_seeder_and_no_seed_route() {
    let root = root();
    let mut hits = Vec::new();
    let mut scanned = 0usize;
    for c in VAULT_CRATES {
        let mut files = Vec::new();
        rust_files(&root.join("crates").join(c), &mut files);
        for f in files {
            scanned = scanned.saturating_add(1);
            let code = code_only(&fs::read_to_string(&f).unwrap());
            let lower = code.to_lowercase();
            for name in SEEDER_NAMES {
                if code.contains(name) {
                    hits.push(format!("{}: {name}", f.display()));
                }
            }
            for spelling in SEED_PATHS {
                if lower.contains(spelling) {
                    hits.push(format!("{}: {spelling}", f.display()));
                }
            }
        }
    }
    assert!(scanned > 0, "no vault source was found");
    assert!(
        hits.is_empty(),
        "I-18: vault code that names a seed: {hits:?}"
    );
}

/// I-18, layering rule 9: no vault crate depends on `fstp-celltest`, so
/// the seeder cannot reach a shipped vault binary.
#[test]
fn fstp_vault_manifests_do_not_reach_the_seeder() {
    let root = root();
    for c in VAULT_CRATES {
        let manifest = fs::read_to_string(root.join("crates").join(c).join("Cargo.toml")).unwrap();
        assert!(
            !manifest.contains("fstp-celltest"),
            "I-18: crates/{c}/Cargo.toml depends on fstp-celltest"
        );
    }
}
