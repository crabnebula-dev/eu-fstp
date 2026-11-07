//! I-75 (M9 design section 3, lane C1): moduletto is always used in a
//! hybrid with a classical primitive. ML-KEM is reached only through
//! `hybrid_kem` and ML-DSA only through `composite`.
//!
//! `source_scans.rs` holds the detailed scans of `crates/` and `tools/`
//! and the rules inside `fstp-crypto`. This file widens them to the whole
//! repository and to the manifests. Every `.rs` file anywhere, outside
//! `fstp-crypto`, the test-only `fstp-celltest` and deps-check (whose
//! rules hold the names as data), names none of `moduletto`, `mldsa` and
//! `mlkem` as an identifier. No Cargo manifest outside those crates and
//! the workspace root names moduletto, so no other crate can depend on it.
//! deps-check enforces the same rule over shipped sources as a CI gate
//! (`tools/deps-check/src/pq_hybrid.rs`).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use std::fs;
use std::path::{Path, PathBuf};

use common::{repo_root, strip_comments};

/// The single-half names: the Tier B crate and the two modules that only
/// their hybrid may use.
const SINGLE_HALF: [&str; 3] = ["moduletto", "mldsa", "mlkem"];

/// The directories that may name them, relative to the root.
const ALLOWED: [&str; 3] = [
    "crates/fstp-crypto/",
    "crates/fstp-celltest/",
    "tools/deps-check/",
];

/// Directories never scanned: build output, VCS data, npm trees and other
/// lane worktrees.
const SKIP_DIRS: [&str; 4] = ["target", ".git", "node_modules", ".lanes"];

/// Every `.rs` file and `Cargo.toml` below `dir`, without following
/// symbolic links.
fn files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(read) = fs::read_dir(dir) else {
        return;
    };
    for entry in read.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_symlink() {
            continue;
        }
        if kind.is_dir() {
            if !SKIP_DIRS.iter().any(|s| name == *s) {
                files(&path, out);
            }
        } else if name == "Cargo.toml" || path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

fn ident_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// The I-75 findings over `files` (path relative to the root, text).
/// A raw identifier such as `r#mlkem` splits into `r` and `mlkem`, so it
/// counts too.
fn findings(files: &[(String, String)]) -> Vec<String> {
    let mut out = Vec::new();
    for (rel, text) in files {
        if ALLOWED.iter().any(|a| rel.starts_with(a)) {
            continue;
        }
        if rel.ends_with("Cargo.toml") {
            if rel == "Cargo.toml" {
                continue;
            }
            for (n, line) in text.lines().enumerate() {
                let code = line.split('#').next().unwrap_or("");
                if code.contains(SINGLE_HALF[0]) {
                    out.push(format!("{rel}:{}: names moduletto", n + 1));
                }
            }
            continue;
        }
        for (n, line) in strip_comments(text).lines().enumerate() {
            for word in line.split(|c: char| !ident_char(c)) {
                if SINGLE_HALF.contains(&word) {
                    out.push(format!("{rel}:{}: {word}", n + 1));
                }
            }
        }
    }
    out
}

fn read_tree(root: &Path) -> Vec<(String, String)> {
    let mut paths = Vec::new();
    files(root, &mut paths);
    paths.sort();
    paths
        .iter()
        .map(|p| {
            let rel = p
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            (
                rel,
                String::from_utf8_lossy(&fs::read(p).unwrap()).into_owned(),
            )
        })
        .collect()
}

/// I-75 (M9 design section 3): across the whole repository, only
/// `fstp-crypto`, the test-only `fstp-celltest` and deps-check name
/// moduletto, `mldsa` or `mlkem`, in code or in a manifest. Everything
/// else reaches the post-quantum half through `composite` or `hybrid_kem`.
#[test]
fn i75_pq_only_through_hybrids() {
    let found = findings(&read_tree(&repo_root()));
    assert!(
        found.is_empty(),
        "I-75: single-half use outside the hybrids:\n{found:#?}"
    );
}

/// I-75, teeth: a planted non-hybrid use fails the scan. The plants are a
/// direct ML-DSA call, a raw identifier, a glob-built `mlkem` path, a
/// moduletto import in a script outside `crates/` and `tools/`, and a
/// manifest dependency on moduletto. The same text inside the allowed
/// crates, in comments, or in longer identifiers passes.
#[test]
fn i75_teeth_planted_non_hybrid_use_fails() {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join("i75_planted");
    let _ = fs::remove_dir_all(&root);
    let plants = [
        (
            "crates/fstp-notice/src/sign.rs",
            "fn f(sk: &[u8], m: &[u8]) { fstp_crypto::mldsa::acvp::sign(sk, m, b\"\", &[0; 32]); }\n",
        ),
        (
            "crates/fstp-cell/src/k.rs",
            "fn f() { fc::r#mlkem::generate(); }\n",
        ),
        (
            "crates/fstp-vault/tests/t.rs",
            "use fstp_crypto::*;\nfn f() { mlkem::generate(); }\n",
        ),
        ("scripts/tool/main.rs", "use moduletto::dsa::ml_dsa_65;\n"),
        (
            "crates/fstp-notice/Cargo.toml",
            "[dependencies]\nmoduletto = { workspace = true }\n",
        ),
    ];
    let quiet = [
        (
            "crates/fstp-crypto/src/mldsa.rs",
            "use moduletto::dsa::ml_dsa_65;\n",
        ),
        (
            "crates/fstp-celltest/src/r.rs",
            "fn f() { fstp_crypto::mlkem::generate(); }\n",
        ),
        (
            "crates/fstp-audit/src/a.rs",
            "// mldsa and moduletto in a comment\n\
             const MLDSA_SIG_LEN: usize = fstp_crypto::composite::MLDSA_SIGNATURE_LEN;\n\
             fn f() { let mlkem_len = 3; }\n",
        ),
        (
            "crates/fstp-audit/Cargo.toml",
            "[dependencies]\nfstp-crypto.workspace = true # not moduletto\n",
        ),
        (
            "Cargo.toml",
            "[workspace.dependencies]\nmoduletto = { git = \"x\" }\n",
        ),
    ];
    for (rel, text) in plants.iter().chain(quiet.iter()) {
        let p = root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, text).unwrap();
    }
    let found = findings(&read_tree(&root));
    for (rel, _) in plants {
        assert!(
            found.iter().any(|f| f.starts_with(rel)),
            "the planted use in {rel} was not found: {found:#?}"
        );
    }
    for (rel, _) in quiet {
        assert!(
            !found.iter().any(|f| f.starts_with(rel)),
            "{rel} was reported: {found:#?}"
        );
    }
    fs::remove_dir_all(&root).unwrap();
}
