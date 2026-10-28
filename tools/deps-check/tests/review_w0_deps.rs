//! Reviewer reproducers for lane W0 of M3, dependency policy lens
//! (`docs/handoff/m3-design.md` sections 2.1 and 2.5, ADR-001 A2, A3
//! and A6).
//!
//! Each test fails against the reviewed working tree and passes once the
//! defect it names is fixed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The dependency names declared in the `[section]` table of `manifest`.
fn table_keys(manifest: &str, section: &str) -> Vec<String> {
    let head = format!("[{section}]");
    let mut inside = false;
    let mut out = Vec::new();
    for line in manifest.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            inside = t == head;
            continue;
        }
        if !inside || t.is_empty() || t.starts_with('#') {
            continue;
        }
        if let Some((key, _)) = t.split_once('=') {
            let key = key.trim();
            let name = key.split('.').next().unwrap_or(key).trim_matches('"');
            out.push(name.to_owned());
        }
    }
    out
}

/// ADR-001 A6, design sections 2.1 and 3.2: the aws-lc-rs ML-KEM, ML-DSA
/// and X25519 oracles live in the library of `fstp-celltest`.
/// `src/reference/hybrid.rs` builds the reference combiner on them, and
/// other crates' tests sign anchors "through fstp-celltest" (section 14.4).
/// A dev-dependency is visible only to the crate's own tests, so the
/// library cannot name `aws_lc_rs`. The edge must be a normal dependency.
/// The crate never ships (layering rule 9), so this adds no shipped edge.
#[test]
fn review_celltest_oracle_is_a_library_dependency() {
    let manifest = fs::read_to_string(repo_root().join("crates/fstp-celltest/Cargo.toml")).unwrap();
    let normal = table_keys(&manifest, "dependencies");
    assert!(
        normal.iter().any(|k| k == "aws-lc-rs"),
        "aws-lc-rs is not in [dependencies] of fstp-celltest, so \
         src/reference/hybrid.rs and the other library oracles cannot use it; \
         [dependencies] holds {normal:?}, [dev-dependencies] holds {:?}",
        table_keys(&manifest, "dev-dependencies")
    );
}

// ---------------------------------------------------------------------------
// ADR-001 A2: a moved git pin needs a new ADR record.
// ---------------------------------------------------------------------------

fn cargo() -> PathBuf {
    std::env::var_os("CARGO").map_or_else(|| PathBuf::from("cargo"), PathBuf::from)
}

fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .args([
            "-c",
            "user.name=fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "init.defaultBranch=main",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

/// A temporary repository with its own `CARGO_HOME`, removed on drop.
struct Repo {
    base: PathBuf,
    root: PathBuf,
    home: PathBuf,
}

impl Drop for Repo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

impl Repo {
    fn new(tag: &str) -> Repo {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let base = std::env::temp_dir().join(format!(
            "deps-check-review-w0-deps-{tag}-{}-{n}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        let repo = Repo {
            root: base.join("repo"),
            home: base.join("cargo-home"),
            base,
        };
        fs::create_dir_all(&repo.home).unwrap();
        repo
    }

    fn write(&self, rel: &str, text: &str) {
        let p = self.root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, text).unwrap();
    }

    fn lock(&self) {
        let out = Command::new(cargo())
            .env("CARGO_HOME", &self.home)
            .arg("generate-lockfile")
            .arg("--manifest-path")
            .arg(self.root.join("Cargo.toml"))
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn check(&self) -> (bool, String) {
        let bin = std::env::var_os("FSTP_DEPS_CHECK_BIN").map_or_else(
            || PathBuf::from(env!("CARGO_BIN_EXE_deps-check")),
            PathBuf::from,
        );
        let out = Command::new(bin)
            .env("CARGO_HOME", &self.home)
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
}

/// ADR-001 A2 ("That move is a new commit, so it needs a new tree record
/// here") and the A2 row "Commit (full id, as `Cargo.lock` records it)".
/// For a crates.io package, deps-check fails unless each ADR records the
/// exact `name version`. A git package keeps its manifest version when
/// its pin moves, so the commit is its version. Today the ADR record check
/// reads only `name version`. Moving `Cargo.lock` and the allowlist to an
/// unrecorded commit passes while ADR-001 still names the old one.
#[test]
fn review_adr_record_must_name_the_pinned_git_commit() {
    let repo = Repo::new("pin");
    let src = repo.base.join("moduletto-src");
    fs::create_dir_all(src.join("src")).unwrap();
    fs::write(
        src.join("Cargo.toml"),
        "[package]\nname = \"moduletto\"\nversion = \"0.3.0\"\nedition = \"2024\"\n",
    )
    .unwrap();
    fs::write(src.join("src/lib.rs"), "//! moduletto, first commit\n").unwrap();
    git(&src, &["init", "-q"]);
    git(&src, &["add", "."]);
    git(&src, &["commit", "-q", "-m", "first"]);
    let first = git(&src, &["rev-parse", "HEAD"]);
    fs::write(src.join("src/lib.rs"), "//! moduletto, second commit\n").unwrap();
    git(&src, &["commit", "-q", "-a", "-m", "second"]);
    let second = git(&src, &["rev-parse", "HEAD"]);
    let url = format!("file://{}", src.display());
    let pinned = |c: &str| format!("git+{url}?rev={c}#{c}");

    repo.write(
        "Cargo.toml",
        "[workspace]\nresolver = \"3\"\nmembers = [\"crates/app\", \"crates/fstp-crypto\"]\n",
    );
    repo.write(
        "crates/app/Cargo.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n\
         [dependencies]\nfstp-crypto = { path = \"../fstp-crypto\" }\n",
    );
    repo.write("crates/app/src/lib.rs", "//! app\n");
    repo.write(
        "crates/fstp-crypto/Cargo.toml",
        &format!(
            "[package]\nname = \"fstp-crypto\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n\
             [dependencies]\nmoduletto = {{ git = \"{url}\", rev = \"{second}\" }}\n"
        ),
    );
    repo.write(
        "crates/fstp-crypto/src/lib.rs",
        "//! fstp-crypto stand-in\n",
    );
    repo.write(
        "deps/allowlist.txt",
        &format!(
            "moduletto 0.3.0 {} ADR-001 runtime Tier B, git source (A2)\n",
            pinned(&second)
        ),
    );
    repo.write(
        "deps/adr-roots.txt",
        "moduletto ADR-001 - Tier B: post-quantum half\n",
    );
    repo.write("deps/fuzz-required.txt", "# empty\n");
    repo.write("deps/funds-allowed.txt", "# empty in M3\n");
    repo.write("deps/tier-b-confirmations.txt", "# none\n");
    repo.write("docs/adr/README.md", "ADRs\n");
    repo.lock();
    let lock = fs::read_to_string(repo.root.join("Cargo.lock")).unwrap();
    assert!(
        lock.contains(&pinned(&second)),
        "setup: the lockfile pins the second commit:\n{lock}"
    );

    // Control: ADR-001 records the pinned commit, and the gate passes.
    repo.write(
        "docs/adr/ADR-001-crypto.md",
        &format!("# ADR-001\n\n`moduletto 0.3.0`, commit `{second}`\n"),
    );
    let (ok, text) = repo.check();
    assert!(ok, "setup: the recorded pin fails the gate:\n{text}");

    // The defect: ADR-001 still records only the first commit.
    repo.write(
        "docs/adr/ADR-001-crypto.md",
        &format!("# ADR-001\n\n`moduletto 0.3.0`, commit `{first}`\n"),
    );
    let (ok, text) = repo.check();
    assert!(
        !ok,
        "the gate passed although ADR-001 records commit {first} and the \
         allowlist and Cargo.lock pin {second} (ADR-001 A2):\n{text}"
    );
}
