//! Tests of the `gen-ts` generator and its `--check` mode (M4 design
//! sections 1.1, 3.9 and 13, step W3a; ADR-014 "generated operation
//! types").
//!
//! Written by the W3a test author before the generator exists. The W0
//! skeleton exits with status 2 and writes nothing, so every test here is
//! red until the production agent writes the generator.
//!
//! The generator writes `web/src/gen/api.ts` under `--root`. `--check`
//! compares instead of writing. It exits 0 when the file equals the
//! output, and with a non-zero status otherwise. It prints nothing either
//! way, since the R-NF-02 print ban covers every workspace member, so the
//! exit status is its only answer.
//!
//! Scratch roots live under the system temporary directory and are
//! removed at the end of each test.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

const API_TS: &str = "web/src/gen/api.ts";

/// The repository root, two levels above this tool.
fn repo_root() -> PathBuf {
    [env!("CARGO_MANIFEST_DIR"), "..", ".."].iter().collect()
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_gen-ts"))
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("cannot run gen-ts: {e}"))
}

fn root_arg(root: &Path) -> String {
    root.to_str()
        .unwrap_or_else(|| panic!("non-UTF-8 path {}", root.display()))
        .to_string()
}

/// A fresh scratch root, removed when dropped.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("fstp-gen-ts-{}-{tag}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("web/src/gen"))
            .unwrap_or_else(|e| panic!("cannot create {}: {e}", dir.display()));
        Scratch(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn api_ts(&self) -> PathBuf {
        self.0.join(API_TS)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Runs the generator into `root` and returns the bytes it wrote.
fn generate(root: &Scratch) -> Vec<u8> {
    let out = run(&["--root", &root_arg(root.path())]);
    assert_eq!(out.status.code(), Some(0), "gen-ts write exit status");
    assert!(
        out.stdout.is_empty() && out.stderr.is_empty(),
        "gen-ts printed output"
    );
    std::fs::read(root.api_ts()).unwrap_or_else(|e| panic!("gen-ts wrote no {API_TS}: {e}"))
}

fn check(root: &Path) -> Output {
    run(&["--check", "--root", &root_arg(root)])
}

/// ADR-014, I-84, design section 13 (W3a "generator `--check`"): the
/// checked-in `web/src/gen/api.ts` is the generator's output for the
/// current `OPS`, so `gen-ts --check` passes on the repository and prints
/// nothing.
#[test]
fn adr014_gen_ts_check_passes_on_the_checked_in_api_ts() {
    let out = check(&repo_root());
    assert_eq!(
        out.status.code(),
        Some(0),
        "gen-ts --check on the repository: web/src/gen/api.ts is stale or the generator is a stub"
    );
    assert!(
        out.stdout.is_empty() && out.stderr.is_empty(),
        "gen-ts --check printed output"
    );
}

/// ADR-014: the generator writes the file into a fresh root, and `--check`
/// then passes on that root. The written bytes equal the checked-in file.
#[test]
fn adr014_gen_ts_writes_then_checks_clean() {
    let root = Scratch::new("write");
    let written = generate(&root);
    let out = check(root.path());
    assert_eq!(out.status.code(), Some(0), "--check right after a write");
    let checked_in = std::fs::read(repo_root().join(API_TS))
        .unwrap_or_else(|e| panic!("cannot read the checked-in {API_TS}: {e}"));
    assert!(
        written == checked_in,
        "the checked-in {API_TS} differs from the generator output"
    );
}

/// ADR-014: `--check` fails on a stale file and leaves it as it was. A
/// clean check passes first, so a generator that always fails cannot pass
/// this test.
#[test]
fn adr014_gen_ts_check_fails_on_a_stale_file() {
    let root = Scratch::new("stale");
    let mut bytes = generate(&root);
    assert_eq!(check(root.path()).status.code(), Some(0), "clean --check");
    bytes.extend_from_slice(b"\n// edited by hand\n");
    std::fs::write(root.api_ts(), &bytes).unwrap_or_else(|e| panic!("cannot edit: {e}"));
    let out = check(root.path());
    assert!(
        out.status.code().is_some_and(|c| c != 0),
        "--check passed on an edited file: {:?}",
        out.status
    );
    assert!(
        out.stdout.is_empty() && out.stderr.is_empty(),
        "gen-ts --check printed output"
    );
    let after = std::fs::read(root.api_ts()).unwrap_or_else(|e| panic!("cannot read: {e}"));
    assert!(after == bytes, "--check changed the file");
}

/// ADR-014: `--check` fails when the file is missing, and writes nothing.
#[test]
fn adr014_gen_ts_check_fails_on_a_missing_file() {
    let root = Scratch::new("missing");
    let _ = generate(&root);
    assert_eq!(check(root.path()).status.code(), Some(0), "clean --check");
    std::fs::remove_file(root.api_ts()).unwrap_or_else(|e| panic!("cannot remove: {e}"));
    let out = check(root.path());
    assert!(
        out.status.code().is_some_and(|c| c != 0),
        "--check passed with no file: {:?}",
        out.status
    );
    assert!(!root.api_ts().exists(), "--check wrote the file");
}

/// ADR-014: the output is a pure function of `OPS`. Two runs give the same
/// bytes.
#[test]
fn adr014_gen_ts_output_is_deterministic() {
    let a = generate(&Scratch::new("det-a"));
    let b = generate(&Scratch::new("det-b"));
    assert!(a == b, "two runs gave different bytes");
}

/// ADR-014, I-84: the operation table names every operation of `OPS` and
/// every tool, each as a quoted string, and the registry is not empty.
/// Design section 3.9 places the generated types, table, route segments
/// and validators in this one file.
#[test]
fn adr014_gen_ts_output_names_every_op_and_tool() {
    assert!(!fstp_access::OPS.is_empty(), "the registry is empty");
    let text = String::from_utf8(generate(&Scratch::new("names")))
        .unwrap_or_else(|e| panic!("the output is not UTF-8: {e}"));
    let mut missing = Vec::new();
    for op in fstp_access::OPS {
        if !text.contains(&format!("\"{}\"", op.name)) {
            missing.push(op.name);
        }
        if let Some(tool) = op.tool
            && !text.contains(&format!("\"{}\"", tool.name))
        {
            missing.push(tool.name);
        }
    }
    assert!(
        missing.is_empty(),
        "names missing from {API_TS}: {missing:?}"
    );
}

/// ADR-014: an unknown argument is refused with a non-zero status, so a
/// misspelt `--check` in CI never writes the file.
#[test]
fn adr014_gen_ts_refuses_an_unknown_argument() {
    let root = Scratch::new("args");
    let _ = generate(&root);
    let before = std::fs::read(root.api_ts()).unwrap_or_else(|e| panic!("cannot read: {e}"));
    std::fs::write(root.api_ts(), b"stale").unwrap_or_else(|e| panic!("cannot edit: {e}"));
    let out = run(&["--chek", "--root", &root_arg(root.path())]);
    assert!(
        out.status.code().is_some_and(|c| c != 0),
        "an unknown argument was accepted: {:?}",
        out.status
    );
    let after = std::fs::read(root.api_ts()).unwrap_or_else(|e| panic!("cannot read: {e}"));
    assert!(after == b"stale", "an unknown argument wrote the file");
    assert!(!before.is_empty());
}
