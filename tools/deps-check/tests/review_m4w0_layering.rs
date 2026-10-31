//! Reviewer reproducers for lane W0 of M4, layering lens
//! (`docs/handoff/m4-design.md` sections 0.2 and 1.3, rule A2).
//!
//! Each test builds a small repository with path crates only, runs the
//! deps-check binary on it and expects the `layering-m4-a2` finding.

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
    /// A workspace with `fstp-engine` and an `fstp-api-core` that depends
    /// on it and whose library root is `api_core_lib`.
    fn new(tag: &str, api_core_lib: &str, port_rs: &str) -> Repo {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let base = std::env::temp_dir().join(format!(
            "deps-check-review-m4w0-a2-{tag}-{}-{n}",
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
        repo.write("deps/funds-allowed.txt", "# empty\n");
        repo.write("deps/tier-b-confirmations.txt", "# none\n");
        repo.write("docs/adr/README.md", "ADRs\n");
        repo.write(
            "Cargo.toml",
            "[workspace]\nresolver = \"3\"\nmembers = [\"crates/fstp-engine\", \"crates/fstp-api-core\"]\n",
        );
        repo.write(
            "crates/fstp-engine/Cargo.toml",
            "[package]\nname = \"fstp-engine\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        );
        repo.write(
            "crates/fstp-engine/src/lib.rs",
            "//! fstp-engine\npub enum Command {}\n",
        );
        repo.write(
            "crates/fstp-api-core/Cargo.toml",
            "[package]\nname = \"fstp-api-core\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[dependencies]\nfstp-engine = { path = \"../fstp-engine\" }\n",
        );
        repo.write("crates/fstp-api-core/src/lib.rs", api_core_lib);
        repo.write("crates/fstp-api-core/src/port.rs", port_rs);
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

    fn report(&self) -> String {
        let out = Command::new(env!("CARGO_BIN_EXE_deps-check"))
            .arg("--root")
            .arg(&self.root)
            .arg("--offline")
            .output()
            .unwrap();
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    }
}

fn a2_error(text: &str) -> bool {
    text.lines()
        .any(|l| l.trim_start().starts_with("error[layering-m4-a2]"))
}

const PORT: &str = "pub trait CellPorts {}\npub trait AsyncEngine {}\n";

/// I-84, rule A2 and design section 0.2 item 1: "a scan of the public API
/// of `fstp-api-core` refuses any re-export of engine or domain command
/// types". A public type alias re-exports the engine command as
/// `fstp_api_core::EngineCommand`, so an adapter can name and build it.
#[test]
fn review_i84_a2_public_type_alias_of_engine_command_is_refused() {
    let repo = Repo::new(
        "alias",
        "//! fstp-api-core\npub mod port;\npub type EngineCommand = fstp_engine::Command;\n",
        PORT,
    );
    let text = repo.report();
    assert!(
        a2_error(&text),
        "`pub type EngineCommand = fstp_engine::Command;` passes rule A2:\n{text}"
    );
}

/// I-84, rule A2: no public item outside `port.rs` names `CellPorts`,
/// `AsyncEngine` or a port trait. A glob re-export of the port module at
/// the crate root re-exports every port outside `port.rs`.
#[test]
fn review_i84_a2_glob_reexport_of_ports_is_refused() {
    let repo = Repo::new(
        "glob",
        "//! fstp-api-core\npub mod port;\npub use crate::port::*;\n",
        PORT,
    );
    let text = repo.report();
    assert!(
        a2_error(&text),
        "`pub use crate::port::*;` passes rule A2:\n{text}"
    );
}
