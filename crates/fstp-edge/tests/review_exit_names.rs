//! Review reproducer (W5): the exit test that design section 14.4, the
//! exit checklist of section 20 and ADR-009 "Edge and tunnel" name for the
//! edge must exist under that exact name in this crate.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(read) = fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<PathBuf> = read.map(|e| e.unwrap().path()).collect();
    entries.sort();
    for p in entries {
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// I-19, B5 (design sections 14.4 and 20, ADR-009): a test function named
/// `i19_edge_forwards_bytes_after_client_hello_unchanged` exists in the
/// crate's sources or tests. The exit audit looks it up by that name.
#[test]
fn review_i19_named_edge_pass_through_test_exists() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let needle = format!(
        "fn {}",
        ["i19_edge", "_forwards_bytes_after_client_hello_unchanged"].concat()
    );
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files);
    rust_files(&root.join("tests"), &mut files);
    let found = files.iter().any(|p| {
        let is_review = p
            .file_name()
            .is_some_and(|n| n.to_string_lossy().starts_with("review_"));
        !is_review && fs::read_to_string(p).unwrap().contains(&needle)
    });
    assert!(
        found,
        "no `{needle}` in fstp-edge: the exit test named by design section 14.4 is missing"
    );
}
