//! Reviewer reproducers for lane W0 of M3, design fidelity lens
//! (`docs/handoff/m3-design.md` section 2.4).
//!
//! Each test builds a small repository in a temporary directory with path
//! crates only, runs the deps-check binary on it and expects the finding
//! the design asks for.

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
    fn new(tag: &str) -> Repo {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let base = std::env::temp_dir().join(format!(
            "deps-check-review-w0-{tag}-{}-{n}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        let repo = Repo {
            root: base.join("repo"),
            base,
        };
        repo.write("deps/allowlist.txt", "# empty\n");
        repo.write("deps/adr-roots.txt", "# empty\n");
        repo.write("deps/fuzz-required.txt", "# empty\n");
        repo.write("deps/funds-allowed.txt", "# empty in M3\n");
        repo.write("deps/tier-b-confirmations.txt", "# none\n");
        repo.write("docs/adr/README.md", "ADRs\n");
        repo
    }

    fn write(&self, rel: &str, text: &str) {
        let p = self.root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, text).unwrap();
    }

    fn krate(&self, dir: &str, name: &str, deps: &[(&str, &str)]) {
        let mut manifest =
            format!("[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2024\"\n");
        if !deps.is_empty() {
            manifest.push_str("\n[dependencies]\n");
            for (d, path) in deps {
                manifest.push_str(&format!("{d} = {{ path = \"{path}\" }}\n"));
            }
        }
        self.write(&format!("{dir}/Cargo.toml"), &manifest);
        self.write(&format!("{dir}/src/lib.rs"), &format!("//! {name}\n"));
    }

    fn lock(&self) {
        let out = Command::new(cargo())
            .args(["generate-lockfile", "--offline", "--manifest-path"])
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

/// I-74, I-75, design section 2.4 rule 8: "moduletto is reachable only
/// through `fstp-crypto`". Here `fstp-keys` reaches moduletto through a
/// crate that is not a workspace member (as a third-party wrapper crate
/// would be), not through `fstp-crypto`. Rule 8 must report it. The
/// current rule looks only at the direct dependencies of workspace
/// members, so the path is missed.
#[test]
fn review_rule8_moduletto_reached_through_a_non_member_crate_is_reported() {
    let repo = Repo::new("rule8-transitive");
    repo.write(
        "Cargo.toml",
        "[workspace]\nresolver = \"3\"\n\
         members = [\"crates/fstp-crypto\", \"crates/fstp-keys\", \"crates/moduletto\"]\n\
         exclude = [\"vendor\"]\n",
    );
    repo.krate("crates/moduletto", "moduletto", &[]);
    repo.krate(
        "crates/fstp-crypto",
        "fstp-crypto",
        &[("moduletto", "../moduletto")],
    );
    repo.krate(
        "vendor/pq-wrap",
        "pq-wrap",
        &[("moduletto", "../../crates/moduletto")],
    );
    repo.krate(
        "crates/fstp-keys",
        "fstp-keys",
        &[
            ("fstp-crypto", "../fstp-crypto"),
            ("pq-wrap", "../../vendor/pq-wrap"),
        ],
    );
    repo.lock();
    let (ok, text) = repo.check();
    assert!(!ok, "the gate passed:\n{text}");
    let reported = text.lines().any(|l| {
        let l = l.trim_start();
        l.starts_with("error[layering-m3-tier-b") && l.contains("fstp-keys")
    });
    assert!(
        reported,
        "fstp-keys -> pq-wrap -> moduletto is not reported by rule 8:\n{text}"
    );
}
