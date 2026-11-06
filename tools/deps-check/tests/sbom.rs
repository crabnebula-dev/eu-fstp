//! End-to-end tests of `deps-check sbom` (R-NF-07, ADR-003, M9 design
//! lane S1).
//!
//! Each test builds a small repository in a temporary directory, with path
//! crates only and the synthetic `web/` lockfile of the ADR-003 record. It
//! then runs the deps-check binary on it, as `review_gates.rs` does.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

use fstp_json::Value;

static COUNTER: AtomicUsize = AtomicUsize::new(0);

const NODE_SHA: &str = "60e3b0a8500819514aca603487c254298cd776de0698d3cd08f11dba5b8289a8";

const WEB_LOCK: &str = r#"{
  "name": "fixture-web",
  "version": "0.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "fixture-web",
      "version": "0.0.0",
      "devDependencies": {
        "typescript": "6.0.3"
      }
    },
    "node_modules/typescript": {
      "version": "6.0.3",
      "resolved": "https://registry.npmjs.org/typescript/-/typescript-6.0.3.tgz",
      "integrity": "sha512-y2TvuxSZPDyQakkFRPZHKFm+KKVqIisdg9/CZwm9ftvKXLP8NRWj38/ODjNbr43SsoXqNuAisEf1GdCxqWcdBw==",
      "dev": true,
      "license": "Apache-2.0"
    }
  }
}
"#;

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
        let base =
            std::env::temp_dir().join(format!("deps-check-sbom-{tag}-{}-{n}", std::process::id()));
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
        repo.write("deps/tier-b-confirmations.txt", "# empty\n");
        repo.write("docs/adr/README.md", "ADRs\n");
        repo.write("web/package-lock.json", WEB_LOCK);
        let out = Command::new(cargo())
            .args(["generate-lockfile", "--offline", "--manifest-path"])
            .arg(repo.root.join("Cargo.toml"))
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        repo
    }

    fn write(&self, rel: &str, text: &str) {
        let p = self.root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, text).unwrap();
    }

    fn sbom(&self, out: &Path, host: bool) -> Output {
        let mut c = Command::new(env!("CARGO_BIN_EXE_deps-check"));
        c.arg("sbom")
            .arg("--root")
            .arg(&self.root)
            .arg("--offline")
            .arg("--out")
            .arg(out);
        if host {
            c.args([
                "--node-version",
                "24.11.1",
                "--node-sha256",
                NODE_SHA,
                "--npm-version",
                "11.6.2",
            ]);
        }
        c.output().unwrap()
    }
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

/// R-NF-07: `deps-check sbom` writes CycloneDX 1.6 JSON, two runs give
/// identical bytes, and the build-time tools are marked build-time
/// (ADR-003).
#[test]
fn r_nf_07_sbom_cli_writes_identical_bytes() {
    let repo = Repo::new("bytes");
    let a = repo.base.join("a.cdx.json");
    let b = repo.base.join("b.cdx.json");
    let out = repo.sbom(&a, true);
    assert!(out.status.success(), "{}", text(&out));
    let out = repo.sbom(&b, true);
    assert!(out.status.success(), "{}", text(&out));
    let first = fs::read(&a).unwrap();
    assert_eq!(first, fs::read(&b).unwrap());
    let doc = fstp_json::parse(&first).unwrap();
    assert_eq!(doc.get("specVersion").and_then(Value::as_str), Some("1.6"));
    let comps = doc.get("components").and_then(Value::as_array).unwrap();
    let purls: Vec<&str> = comps
        .iter()
        .filter_map(|c| c.get("purl").and_then(Value::as_str))
        .collect();
    assert_eq!(
        purls,
        vec![
            "pkg:generic/node@24.11.1",
            "pkg:npm/npm@11.6.2",
            "pkg:npm/typescript@6.0.3"
        ]
    );
    for c in comps.iter() {
        assert_eq!(c.get("scope").and_then(Value::as_str), Some("excluded"));
    }
}

/// R-NF-07, ADR-003: without the pinned Node.js and npm the SBOM would
/// miss the build hosts, so the command refuses to run.
#[test]
fn r_nf_07_sbom_cli_needs_the_build_hosts() {
    let repo = Repo::new("hosts");
    let a = repo.base.join("a.cdx.json");
    let out = repo.sbom(&a, false);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
    assert!(!a.exists());
}
