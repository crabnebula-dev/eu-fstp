//! Review reproducers: the `fstp-web-assets` fuzz targets need seeds that
//! reach past the first prefix check (TH-26, H-05, M4 design section 9).
//!
//! `tools/fuzz-all.sh` feeds `fuzz/seeds/<target>` to every target. With
//! no seed, a 30 s run of `static_path_resolve` stays at 42 coverage
//! points and never reaches the hash grammar.

#![allow(clippy::panic, reason = "a test fails by panicking")]

use std::path::Path;

/// Every seed file of `target`, or a panic naming the missing directory.
fn seeds(target: &str) -> Vec<Vec<u8>> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fuzz/seeds")
        .join(target);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        panic!("{} does not exist", dir.display());
    };
    entries
        .filter_map(Result::ok)
        .filter_map(|e| std::fs::read(e.path()).ok())
        .collect()
}

/// TH-26, H-05: `static_path_resolve` has a seed the resolver accepts,
/// so the fuzzer reaches the hash and extension grammar.
#[test]
fn review_static_path_fuzz_has_an_accepted_seed() {
    let accepted = seeds("static_path_resolve")
        .iter()
        .any(|s| fstp_web_assets::resolve_static_path(s).is_ok());
    assert!(accepted, "no seed of static_path_resolve is accepted");
}

/// TH-26, H-05: `asset_manifest_decode` has a committed seed the decoder
/// accepts. The local `fuzz/corpus` is ignored by git, so CI starts empty.
#[test]
fn review_manifest_fuzz_has_an_accepted_seed() {
    let accepted = seeds("asset_manifest_decode")
        .iter()
        .any(|s| fstp_web_assets::decode_manifest(s).is_ok());
    assert!(accepted, "no seed of asset_manifest_decode is accepted");
}
