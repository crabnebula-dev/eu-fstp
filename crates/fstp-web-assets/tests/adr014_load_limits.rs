//! The refusals of `load_dir` for links and sizes (ADR-014 "Shell,
//! assets and headers", M4 design sections 1.1 and 3.9).
//!
//! A listed path that is a symbolic link, or passes through one, refuses
//! the whole set. So does a file over 8 MiB, or a set over 64 MiB in
//! total. The large files are sparse, so the tests use little disk.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod assets_common;

use assets_common::{
    MANIFEST_FILE, ScratchDir, manifest_for, manifest_json, sample_files, sha_hex,
};
use fstp_web_assets::{AssetError, MAX_ASSET_BYTES, MAX_TOTAL_BYTES, load_dir};

/// Writes a sparse file of `len` zero bytes at `rel` under `dir`.
fn sparse(dir: &ScratchDir, rel: &str, len: u64) {
    let p = dir.path().join(rel);
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::File::create(&p).unwrap().set_len(len).unwrap();
}

/// The SHA-256 text of `len` zero bytes.
fn zeros_hash(len: u64) -> String {
    sha_hex(&vec![0u8; usize::try_from(len).unwrap()])
}

/// A manifest of `n` paths `a0.js` to `a{n-1}.js`, each with `hash`, and
/// entry `a0.js`.
fn many(n: usize, hash: &str) -> String {
    let paths: Vec<String> = (0..n).map(|i| format!("a{i}.js")).collect();
    let pairs: Vec<(&str, &str)> = paths.iter().map(|p| (p.as_str(), hash)).collect();
    manifest_json("a0.js", &pairs)
}

/// ADR-014: a listed file that is a symbolic link refuses the set, even
/// when its target holds the listed bytes.
#[cfg(unix)]
#[test]
fn adr014_load_refuses_a_symlinked_asset() {
    let dir = ScratchDir::new("linkfile");
    let files = sample_files();
    dir.write_all(&files, &manifest_for(&files));
    let real = dir.path().join("core/dom-real.js");
    std::fs::rename(dir.path().join("core/dom.js"), &real).unwrap();
    std::os::unix::fs::symlink(&real, dir.path().join("core/dom.js")).unwrap();
    assert_eq!(
        load_dir(dir.path()).map(|_| ()),
        Err(AssetError::NotAFile("core/dom.js".to_owned()))
    );
}

/// ADR-014: a listed path that passes through a symbolic link to a
/// directory refuses the set, even when the files behind it match.
#[cfg(unix)]
#[test]
fn adr014_load_refuses_a_symlinked_directory() {
    let dir = ScratchDir::new("linkdir");
    let files = sample_files();
    dir.write_all(&files, &manifest_for(&files));
    let real = dir.path().join("core-real");
    std::fs::rename(dir.path().join("core"), &real).unwrap();
    std::os::unix::fs::symlink(&real, dir.path().join("core")).unwrap();
    match load_dir(dir.path()) {
        Err(AssetError::NotAFile(p)) if p.starts_with("core/") => {}
        other => panic!("not refused as a link: {other:?}"),
    }
}

/// ADR-014: a manifest that is a symbolic link refuses the set.
#[cfg(unix)]
#[test]
fn adr014_load_refuses_a_symlinked_manifest() {
    let dir = ScratchDir::new("linkmanifest");
    let files = sample_files();
    dir.write_all(&files, &manifest_for(&files));
    let real = dir.path().join("manifest-real.json");
    std::fs::rename(dir.path().join(MANIFEST_FILE), &real).unwrap();
    std::os::unix::fs::symlink(&real, dir.path().join(MANIFEST_FILE)).unwrap();
    assert_eq!(
        load_dir(dir.path()).map(|_| ()),
        Err(AssetError::NotAFile(MANIFEST_FILE.to_owned()))
    );
}

/// ADR-014: a listed file one byte over 8 MiB refuses the set before it
/// is read, whatever hash the manifest lists.
#[test]
fn adr014_load_refuses_an_oversized_asset() {
    let dir = ScratchDir::new("bigfile");
    sparse(&dir, "a0.js", MAX_ASSET_BYTES + 1);
    dir.write(MANIFEST_FILE, many(1, &"00".repeat(32)).as_bytes());
    assert_eq!(
        load_dir(dir.path()).map(|_| ()),
        Err(AssetError::TooLarge("a0.js".to_owned()))
    );
}

/// ADR-014: a set of exactly 64 MiB, in eight files of exactly 8 MiB,
/// loads. Both limits are inclusive.
#[test]
fn adr014_load_accepts_a_set_at_both_limits() {
    let dir = ScratchDir::new("atlimit");
    let n = usize::try_from(MAX_TOTAL_BYTES / MAX_ASSET_BYTES).unwrap();
    for i in 0..n {
        sparse(&dir, &format!("a{i}.js"), MAX_ASSET_BYTES);
    }
    dir.write(
        MANIFEST_FILE,
        many(n, &zeros_hash(MAX_ASSET_BYTES)).as_bytes(),
    );
    let set = load_dir(dir.path()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(set.len(), 1, "eight equal files share one served asset");
}

/// ADR-014: a set over 64 MiB in total refuses to load, though each file
/// is within the 8 MiB limit and matches its hash.
#[test]
fn adr014_load_refuses_a_set_over_the_total_limit() {
    let dir = ScratchDir::new("overtotal");
    let n = usize::try_from(MAX_TOTAL_BYTES / MAX_ASSET_BYTES).unwrap() + 1;
    for i in 0..n {
        sparse(&dir, &format!("a{i}.js"), MAX_ASSET_BYTES);
    }
    dir.write(
        MANIFEST_FILE,
        many(n, &zeros_hash(MAX_ASSET_BYTES)).as_bytes(),
    );
    match load_dir(dir.path()) {
        Err(AssetError::TooLarge(p)) if p.starts_with('a') => {}
        other => panic!("not refused as too large: {other:?}"),
    }
}
