//! End-to-end regressions for the review findings against deps-check.
//!
//! Each test builds a small repository in a temporary directory, with path
//! crates only so that no network or registry access is needed. It then
//! runs the deps-check binary on it. A baseline repository passes. Each
//! scenario adds one reviewer reproducer and expects the gate to fail.
//!
//! `FSTP_DEPS_CHECK_BIN` overrides the binary under test. It exists only to
//! show that these tests fail on an older build of the gate.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// A temporary repository, removed on drop.
struct Repo {
    root: PathBuf,
    outside: PathBuf,
}

impl Drop for Repo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
        let _ = fs::remove_dir_all(&self.outside);
    }
}

fn cargo() -> PathBuf {
    std::env::var_os("CARGO").map_or_else(|| PathBuf::from("cargo"), PathBuf::from)
}

impl Repo {
    /// A minimal repository that passes every gate.
    fn new(tag: &str) -> Repo {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let base =
            std::env::temp_dir().join(format!("deps-check-e2e-{tag}-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let repo = Repo {
            root: base.join("repo"),
            outside: base.join("outside"),
        };
        fs::create_dir_all(&repo.outside).unwrap();
        repo.write(
            "Cargo.toml",
            "[workspace]\nresolver = \"3\"\nmembers = [\"crates/app\"]\n",
        );
        repo.write(
            "crates/app/Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        );
        repo.write("crates/app/src/lib.rs", "//! app\n");
        repo.write("deps/allowlist.txt", "# empty\n");
        repo.write("deps/adr-roots.txt", "# empty\n");
        repo.write("deps/fuzz-required.txt", "# empty\n");
        repo.write("docs/adr/README.md", "ADRs\n");
        repo.lock(".");
        repo
    }

    fn write(&self, rel: &str, text: &str) {
        let p = self.root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, text).unwrap();
    }

    /// Generates the lockfile of the project in `rel`, offline.
    fn lock(&self, rel: &str) {
        let out = Command::new(cargo())
            .args(["generate-lockfile", "--offline", "--manifest-path"])
            .arg(self.root.join(rel).join("Cargo.toml"))
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// Runs deps-check and returns whether it passed, and its report.
    fn check(&self) -> (bool, String) {
        let bin = std::env::var_os("FSTP_DEPS_CHECK_BIN").map_or_else(
            || PathBuf::from(env!("CARGO_BIN_EXE_deps-check")),
            PathBuf::from,
        );
        let out = Command::new(bin)
            .arg("--root")
            .arg(&self.root)
            .arg("--offline")
            .output()
            .unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        (out.status.success(), text)
    }

    fn assert_fails_with(&self, code: &str) {
        let (ok, text) = self.check();
        assert!(!ok, "the gate passed:\n{text}");
        assert!(
            text.contains(&format!("error[{code}]")),
            "no error[{code}]:\n{text}"
        );
    }
}

fn symlink(target: &Path, link: &Path) {
    fs::create_dir_all(link.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(target, link).unwrap();
}

#[test]
fn baseline_repository_passes() {
    let repo = Repo::new("baseline");
    let (ok, text) = repo.check();
    assert!(ok, "{text}");
}

/// Review finding projects-outside-crates-fuzz (P5, TH-15): a second cargo
/// project with its own lockfile outside the known fuzz locations.
#[test]
fn review_projects_outside_crates_fuzz() {
    let repo = Repo::new("elsewhere");
    repo.write(
        "crates/app/fuzz2/Cargo.toml",
        "[package]\nname = \"app-fuzz2\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n\
         [dependencies]\napp = { path = \"..\" }\n\n[workspace]\n",
    );
    repo.write("crates/app/fuzz2/src/lib.rs", "//! x\n");
    repo.lock("crates/app/fuzz2");
    repo.assert_fails_with("project-location");
}

/// Review finding projects-outside-crates-fuzz (P5): a nested workspace
/// without a lockfile is not silently skipped either.
#[test]
fn review_projects_outside_crates_fuzz_without_lockfile() {
    let repo = Repo::new("nolock");
    repo.write(
        "tools/gen/Cargo.toml",
        "[package]\nname = \"gen\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[workspace]\n",
    );
    repo.write("tools/gen/src/lib.rs", "//! x\n");
    repo.assert_fails_with("unanalysed-manifest");
}

/// Review finding symlink-defeats-path-outside-repo (P5): a committed link
/// inside the repository to a crate outside it.
#[test]
fn review_symlink_defeats_path_outside_repo() {
    let repo = Repo::new("symlink");
    let evil = repo.outside.join("evil");
    fs::create_dir_all(evil.join("src")).unwrap();
    fs::write(
        evil.join("Cargo.toml"),
        "[package]\nname = \"evil\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .unwrap();
    fs::write(evil.join("src/lib.rs"), "//! evil\n").unwrap();
    symlink(&evil, &repo.root.join("vendor/evil"));
    repo.write(
        "crates/app/Cargo.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n\
         [dependencies]\nevil = { path = \"../../vendor/evil\" }\n",
    );
    repo.lock(".");
    repo.assert_fails_with("path-outside-repo");
}

/// Review finding source-replacement-tamper (P5): source replacement with
/// a vendor directory configured inside the repository.
#[test]
fn review_source_replacement_tamper() {
    let repo = Repo::new("vendor");
    repo.write(
        ".cargo/config.toml",
        "[source.crates-io]\nreplace-with = \"vendored-sources\"\n\n\
         [source.vendored-sources]\ndirectory = \"vendor\"\n",
    );
    fs::create_dir_all(repo.root.join("vendor")).unwrap();
    repo.assert_fails_with("cargo-config");
}

/// Review finding patch-path-override (P5): a `[patch.crates-io]` section
/// in the workspace manifest.
#[test]
fn review_patch_path_override() {
    let repo = Repo::new("patch");
    repo.write(
        "Cargo.toml",
        "[workspace]\nresolver = \"3\"\nmembers = [\"crates/app\"]\n\n\
         [patch.crates-io]\nsubtle = { path = \"vendor/subtle\" }\n",
    );
    repo.write(
        "vendor/subtle/Cargo.toml",
        "[package]\nname = \"subtle\"\nversion = \"2.6.1\"\nedition = \"2024\"\n",
    );
    repo.write("vendor/subtle/src/lib.rs", "//! patched\n");
    repo.lock(".");
    repo.assert_fails_with("manifest-override");
}

/// Review finding python-scan-skips-any-target-dir (CLAUDE.md): Python in
/// a directory named `target` that is not build output.
#[test]
fn review_python_scan_skips_any_target_dir() {
    let repo = Repo::new("pytarget");
    repo.write("tools/target/gen.py", "print(1)\n");
    repo.assert_fails_with("python-file");
}

/// Review findings python-heuristics-gaps and no-python-gate-heuristic
/// (CLAUDE.md): a shell script that runs Python through a heredoc.
#[test]
fn review_python_heuristics_gaps() {
    let repo = Repo::new("pyinline");
    repo.write(
        "tools/gen.sh",
        "#!/usr/bin/env bash\npython3 - <<EOF\nprint(1)\nEOF\n",
    );
    repo.assert_fails_with("python-invocation");
}

fn ci_workflow() -> String {
    let ci = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.github/workflows/ci.yml");
    fs::read_to_string(ci).unwrap()
}

/// Review finding ci-cancel-in-progress-main: a push to the main branches
/// never cancels the CI run of the commit before it.
#[test]
fn review_ci_cancel_in_progress_main() {
    let text = ci_workflow();
    let lines: Vec<&str> = text
        .lines()
        .filter(|l| l.trim_start().starts_with("cancel-in-progress:"))
        .collect();
    assert_eq!(
        lines,
        vec!["  cancel-in-progress: ${{ github.event_name == 'pull_request' }}"]
    );
}

/// Review finding ci-unvetted-deps-built-before-gate (TH-15): every CI job
/// that builds or runs code waits for deps-check. The gate's own job checks
/// that deps-check builds only in-house code, and the fuzz job proves that
/// its lockfiles stay unchanged through tools/fuzz-all.sh.
#[test]
fn review_ci_unvetted_deps_built_before_gate() {
    let text = ci_workflow();
    assert!(text.contains("cargo tree --locked -p deps-check -e normal,build --target all"));
    let fuzz_all =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../fuzz-all.sh")).unwrap();
    assert!(fuzz_all.contains("metadata --locked --format-version 1"));
    assert!(fuzz_all.contains("check_locks"));
    let mut job = None;
    let mut waits = Vec::new();
    let mut jobs = Vec::new();
    let mut in_jobs = false;
    for line in text.lines() {
        if line == "jobs:" {
            in_jobs = true;
            continue;
        }
        if !in_jobs {
            continue;
        }
        if let Some(name) = line.strip_prefix("  ").and_then(|l| l.strip_suffix(':'))
            && !name.starts_with(' ')
        {
            job = Some(name.to_owned());
            jobs.push(name.to_owned());
        }
        if line.trim() == "needs: deps-check"
            && let Some(j) = &job
        {
            waits.push(j.clone());
        }
    }
    assert!(jobs.contains(&"deps-check".to_owned()), "{jobs:?}");
    for j in jobs.iter().filter(|j| *j != "deps-check") {
        assert!(waits.contains(j), "job {j} does not wait for deps-check");
    }
}

/// I-10, design section 1: the layering gate runs on the workspace graph,
/// so a path from fstp-domain to fstp-findings fails the whole gate.
#[test]
fn i10_layering_gate_rejects_domain_depending_on_findings() {
    let repo = Repo::new("layering");
    repo.write(
        "Cargo.toml",
        "[workspace]\nresolver = \"3\"\n\
         members = [\"crates/app\", \"crates/fstp-domain\", \"crates/fstp-findings\"]\n",
    );
    repo.write(
        "crates/fstp-findings/Cargo.toml",
        "[package]\nname = \"fstp-findings\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    );
    repo.write("crates/fstp-findings/src/lib.rs", "//! findings\n");
    repo.write(
        "crates/fstp-domain/Cargo.toml",
        "[package]\nname = \"fstp-domain\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    );
    repo.write("crates/fstp-domain/src/lib.rs", "//! domain\n");
    repo.lock(".");
    let (ok, text) = repo.check();
    assert!(ok, "the layered baseline fails:\n{text}");

    repo.write(
        "crates/fstp-domain/Cargo.toml",
        "[package]\nname = \"fstp-domain\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n\
         [dev-dependencies]\nfstp-findings = { path = \"../fstp-findings\" }\n",
    );
    repo.lock(".");
    repo.assert_fails_with("layering-i10");
}
