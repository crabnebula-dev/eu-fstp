//! Adversarial review reproducers for the M3 deps-check source scans (lane
//! W0, second review pass).
//!
//! Each test seeds one violation in a temporary repository and expects the
//! rule's error. Each one fails against the current code and passes once
//! the defect it names is fixed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn cargo() -> PathBuf {
    std::env::var_os("CARGO").map_or_else(|| PathBuf::from("cargo"), PathBuf::from)
}

/// A temporary repository with one member, removed on drop.
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
        Repo::with_member(tag, "fstp-edge")
    }

    /// A repository whose one member is `krate`, at `crates/<krate>`.
    fn with_member(tag: &str, krate: &str) -> Repo {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let base = std::env::temp_dir().join(format!(
            "deps-check-review-adv-{tag}-{}-{n}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        let repo = Repo {
            root: base.join("repo"),
            base,
        };
        repo.write(
            "Cargo.toml",
            &format!("[workspace]\nresolver = \"3\"\nmembers = [\"crates/{krate}\"]\n"),
        );
        repo.write(
            &format!("crates/{krate}/Cargo.toml"),
            &format!("[package]\nname = \"{krate}\"\nversion = \"0.1.0\"\nedition = \"2024\"\n"),
        );
        repo.write(&format!("crates/{krate}/src/lib.rs"), "//! member\n");
        repo.write("deps/allowlist.txt", "# empty\n");
        repo.write("deps/adr-roots.txt", "# empty\n");
        repo.write("deps/fuzz-required.txt", "# empty\n");
        repo.write("deps/funds-allowed.txt", "# empty in M3\n");
        repo.write("deps/tier-b-confirmations.txt", "# none\n");
        repo.write("docs/adr/README.md", "ADRs\n");
        let out = Command::new(cargo())
            .arg("generate-lockfile")
            .arg("--offline")
            .arg("--manifest-path")
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

    fn has_error(&self, code: &str) -> (bool, String) {
        let (ok, text) = self.check();
        let head = format!("error[{code}");
        let found = !ok && text.lines().any(|l| l.trim_start().starts_with(&head));
        (found, text)
    }
}

/// Review finding tokens-raw-byte-string (I-19, design section 2.4 rule 5).
/// The source tokenizer knows `r"..."` but not `br"..."`. It reads a raw
/// byte string as an ordinary string with backslash escapes, so the
/// literal `br"\"` swallows the code after it. A grouped server import
/// placed there passes the edge TLS scan, although the same import on its
/// own fails.
#[test]
fn review_rule5_raw_byte_string_hides_a_grouped_server_import() {
    let tls = ["fstp", "_tls"].concat();
    let import = format!("use {tls}::{{accept as serve}};\n");

    // Control: the import alone is refused.
    let plain = Repo::new("plain");
    plain.write(
        "crates/fstp-edge/src/lib.rs",
        &format!("//! edge\n{import}"),
    );
    let (caught, text) = plain.has_error("layering-m3-edge-tls");
    assert!(caught, "setup: the plain grouped import passes:\n{text}");

    // The same import after a raw byte string literal holding a backslash.
    let hidden = Repo::new("hidden");
    hidden.write(
        "crates/fstp-edge/src/lib.rs",
        &format!("//! edge\npub const B: &[u8] = br\"\\\";\n{import}pub const S: &str = \"\";\n"),
    );
    let (caught, text) = hidden.has_error("layering-m3-edge-tls");
    assert!(
        caught,
        "a grouped server import after br\"\\\" passes the edge TLS scan:\n{text}"
    );
}

/// Review finding scan-misses-path-modules (I-80, design section 2.4 rule
/// 7). The source scans read `src/`, the target roots and the files beside
/// a root in the package directory. A module that `#[path]` loads from
/// another directory of the package ships in the crate, yet no scan reads
/// it, so `RootMaterial` named there passes.
#[test]
fn review_scan_reads_path_attribute_modules_i80() {
    let repo = Repo::with_member("path-mod", "app");
    let (ok, text) = repo.check();
    assert!(ok, "setup: the baseline fails:\n{text}");
    let rm = ["Root", "Material"].concat();
    repo.write(
        "crates/app/src/lib.rs",
        "//! app\n#[path = \"../gen/keys.rs\"]\npub mod keys;\n",
    );
    repo.write("crates/app/gen/keys.rs", &format!("pub struct {rm};\n"));
    let (caught, text) = repo.has_error("layering-m3-i80");
    assert!(
        caught,
        "RootMaterial in a #[path] module outside src/ passes:\n{text}"
    );
}

/// Review finding scan-misses-symlinked-modules (I-80, design section 2.4
/// rule 7). The scans skip a module file under `src/` that is a symbolic
/// link, and the repository check allows a link to a file. cargo follows
/// the link and compiles its target into the crate, so `RootMaterial`
/// named there passes.
#[cfg(unix)]
#[test]
fn review_scan_reads_symlinked_module_files_i80() {
    let repo = Repo::with_member("symlink-mod", "app");
    let (ok, text) = repo.check();
    assert!(ok, "setup: the baseline fails:\n{text}");
    let rm = ["Root", "Material"].concat();
    repo.write("crates/app/src/lib.rs", "//! app\npub mod keys;\n");
    repo.write("vendor/keys.rs", &format!("pub struct {rm};\n"));
    std::os::unix::fs::symlink(
        "../../../vendor/keys.rs",
        repo.root.join("crates/app/src/keys.rs"),
    )
    .unwrap();
    let (caught, text) = repo.has_error("layering-m3-i80");
    assert!(
        caught,
        "RootMaterial in a symlinked module file passes:\n{text}"
    );
}
