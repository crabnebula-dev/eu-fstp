//! Rule A9b: the synthetic legal wording never reaches the public crates
//! (M4 design sections 1.3 and 3.10, Q6).
//!
//! The end-to-end cell loads a Guide variant whose legal sections read
//! "SYNTHETIC TEST WORDING. NOT LEGAL TEXT." It lives in
//! `fstp-api-testkit/profiles/synthetic-wording/` only. This test scans
//! every file under the source trees of `fstp-public` and `fstp-guide`,
//! and the shipped profiles, for that marker. The marker is built here
//! from two parts, so this file never holds it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

/// The marker of the synthetic wording, built from two parts.
fn marker() -> String {
    ["SYNTHETIC TEST", " WORDING"].concat()
}

fn files_under(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
    for e in entries {
        let p = e.unwrap_or_else(|e| panic!("{e}")).path();
        if p.is_dir() {
            files_under(&p, out);
        } else {
            out.push(p);
        }
    }
}

/// A9b, Q6: no file of the `fstp-public` and `fstp-guide` sources or of
/// the shipped profiles holds the synthetic wording marker.
#[test]
fn a9b_public_and_guide_sources_hold_no_synthetic_wording() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut files = Vec::new();
    for dir in ["fstp-public/src", "fstp-guide/src", "fstp-guide/profiles"] {
        files_under(&root.join(dir), &mut files);
    }
    assert!(files.len() > 3, "the scan found too few files: {files:?}");
    let m = marker();
    let hits: Vec<String> = files
        .iter()
        .filter(|f| {
            std::fs::read(f)
                .map(|b| String::from_utf8_lossy(&b).contains(&m))
                .unwrap_or(false)
        })
        .map(|f| f.display().to_string())
        .collect();
    assert!(hits.is_empty(), "{hits:?}");
}
