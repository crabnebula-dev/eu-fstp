//! Review reproducers for the M3 deps-check rules (lane W0, gate strength).
//!
//! Each test seeds one violation in a temporary repository and expects the
//! rule's error. Each one fails against the W0 code and passes once the
//! defect it names is fixed.
//!
//! Identifiers that a source scan refuses are assembled at run time, so
//! this file never trips the scans when deps-check runs on the real
//! repository.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn cargo() -> PathBuf {
    std::env::var_os("CARGO").map_or_else(|| PathBuf::from("cargo"), PathBuf::from)
}

/// A temporary repository, removed on drop.
struct Repo {
    base: PathBuf,
    root: PathBuf,
}

impl Drop for Repo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

impl Repo {
    /// A minimal repository that passes every gate.
    fn new(tag: &str) -> Repo {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let base = std::env::temp_dir().join(format!(
            "deps-check-review-m3-{tag}-{}-{n}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        let repo = Repo {
            root: base.join("repo"),
            base,
        };
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
        repo.write("deps/funds-allowed.txt", "# empty in M3\n");
        repo.write("deps/tier-b-confirmations.txt", "# none\n");
        repo.write("docs/adr/README.md", "ADRs\n");
        repo.lock();
        repo
    }

    fn write(&self, rel: &str, text: &str) {
        let p = self.root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, text).unwrap();
    }

    fn lock(&self) {
        let out = Command::new(cargo())
            .arg("generate-lockfile")
            .arg("--offline")
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

    /// Asserts that the gate fails with an error whose code starts with
    /// `code`.
    fn assert_fails_with(&self, code: &str, what: &str) {
        let (ok, text) = self.check();
        let head = format!("error[{code}");
        assert!(
            !ok && text.lines().any(|l| l.trim_start().starts_with(&head)),
            "{what}: no error[{code}...]:\n{text}"
        );
    }
}

/// Review finding npm-node-modules-anywhere (ADR-003 amendment, Rules: npm
/// projects exist only in `web/` and `e2e/`). The gate skips every path
/// with a `node_modules` component, so a committed npm project in
/// `scripts/node_modules/` passes, with any direct package it likes. Only
/// the installed trees `web/node_modules` and `e2e/node_modules` may be
/// skipped.
#[test]
fn review_npm_project_in_node_modules_outside_web_and_e2e() {
    let repo = Repo::new("npm-node-modules");
    let (ok, text) = repo.check();
    assert!(ok, "setup: the baseline fails:\n{text}");
    repo.write(
        "scripts/node_modules/package.json",
        "{\"name\":\"s\",\"devDependencies\":{\"left-pad\":\"1.3.0\"}}\n",
    );
    repo.write(
        "scripts/node_modules/package-lock.json",
        "{\"name\":\"s\",\"lockfileVersion\":3,\"requires\":true,\"packages\":{\"\":{\"name\":\"s\",\
         \"devDependencies\":{\"left-pad\":\"1.3.0\"}},\"node_modules/left-pad\":{\"version\":\"1.3.0\",\
         \"resolved\":\"https://example.org/left-pad-1.3.0.tgz\"}}}\n",
    );
    repo.assert_fails_with("npm", "an npm project under scripts/node_modules/");
}

/// Review finding scan-misses-target-roots (I-80, design section 2.4 rule
/// 7). The source scans read only `src/` and `build.rs`. A binary whose
/// `[[bin]] path` lies outside `src/` ships, yet the scan never reads it,
/// so `RootMaterial` named there passes.
#[test]
fn review_scan_reads_bin_targets_outside_src_i80() {
    let repo = Repo::new("scan-bin-path");
    repo.write(
        "crates/app/Cargo.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n\
         [[bin]]\nname = \"app\"\npath = \"bin/main.rs\"\n",
    );
    let rm = ["Root", "Material"].concat();
    repo.write(
        "crates/app/bin/main.rs",
        &format!("struct {rm};\nfn main() {{ let _ = {rm}; }}\n"),
    );
    repo.lock();
    repo.assert_fails_with(
        "layering-m3-i80",
        "RootMaterial in a shipped bin outside src/",
    );
}

/// Review finding scan-misses-target-roots (I-16, design sections 2.4 rule
/// 11 and 14.4). A payment instruction built in a binary whose root lies
/// outside `src/` passes the funds rule.
#[test]
fn review_scan_reads_bin_targets_outside_src_i16() {
    let repo = Repo::new("funds-bin-path");
    repo.write(
        "crates/app/Cargo.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n\
         [[bin]]\nname = \"pay\"\npath = \"pay/main.rs\"\n",
    );
    let root = ["Cstmr", "CdtTrf", "Initn"].concat();
    repo.write(
        "crates/app/pay/main.rs",
        &format!("fn main() {{ let _ = \"<{root}>\"; }}\n"),
    );
    repo.lock();
    repo.assert_fails_with("funds", "a pain.001 builder in a shipped bin outside src/");
}

/// Review finding scan-misses-target-roots (I-80, rule 7). A custom build
/// script path (`package.build`) ships code into the crate too, and the
/// scan reads only a file named `build.rs`.
#[test]
fn review_scan_reads_custom_build_script_i80() {
    let repo = Repo::new("scan-build-path");
    repo.write(
        "crates/app/Cargo.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2024\"\nbuild = \"gen.rs\"\n",
    );
    let rm = ["Root", "Material"].concat();
    repo.write(
        "crates/app/gen.rs",
        &format!("struct {rm};\nfn main() {{ let _ = {rm}; }}\n"),
    );
    repo.lock();
    repo.assert_fails_with("layering-m3-i80", "RootMaterial in a custom build script");
}
