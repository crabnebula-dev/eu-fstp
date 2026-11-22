//! ADR-029 "Generator": `unorm-gen --check` passes on the repository,
//! prints nothing (R-NF-02), and answers a bad root or argument with
//! status 2.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;
use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_unorm-gen"))
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("cannot run unorm-gen: {e}"))
}

/// ADR-029 and R-NF-02: the committed tables pass `--check`, and every
/// answer is an exit status with no output.
#[test]
fn adr029_unorm_gen_check_passes_and_prints_nothing() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let root = root.to_str().unwrap();
    for (args, status) in [
        (vec!["--check", "--root", root], 0),
        (vec!["--check", "--root", "/nonexistent-unorm-gen-root"], 2),
        (vec!["--check", "--check"], 2),
        (vec!["--bogus"], 2),
    ] {
        let out = run(&args);
        assert_eq!(out.status.code(), Some(status), "unorm-gen {args:?}");
        assert!(
            out.stdout.is_empty() && out.stderr.is_empty(),
            "unorm-gen {args:?} printed"
        );
    }
}
