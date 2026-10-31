//! Reviewer reproducers for lane W0 of M4, web scan lens
//! (`docs/handoff/m4-design.md` sections 1.1 and 3.9, ADR-014).
//!
//! Each test builds a small repository with one path crate and one file
//! below `web/src`, runs the deps-check binary on it and checks the
//! `web-scan` result.

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
            "deps-check-review-m4w0-{tag}-{}-{n}",
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
            "[workspace]\nresolver = \"3\"\nmembers = [\"crates/fstp-json\"]\n",
        );
        repo.write(
            "crates/fstp-json/Cargo.toml",
            "[package]\nname = \"fstp-json\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        );
        repo.write("crates/fstp-json/src/lib.rs", "//! fstp-json\n");
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

    /// Runs deps-check and returns its report.
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

/// Whether the report holds a `web-scan` error naming `what`.
fn web_scan_error(text: &str, what: &str) -> bool {
    text.lines().any(|l| {
        let l = l.trim_start();
        l.starts_with("error[web-scan") && l.contains(what)
    })
}

/// ADR-014, design section 3.9: a postfix `++` before a division makes the
/// lexer read a regular expression, which hides the `innerHTML` sink on
/// the same line. The line is valid TypeScript, so tsc accepts it.
#[test]
fn review_adr014_web_scan_postfix_increment_hides_inner_html() {
    let repo = Repo::new("postfix-inc");
    repo.write(
        "web/src/core/render.ts",
        "export function put(el: HTMLElement, s: string, a: number): number {\n  const b = a++ / 2; el.innerHTML = s; const c = b / 1;\n  return c;\n}\n",
    );
    repo.lock();
    let text = repo.report();
    assert!(
        web_scan_error(&text, "innerHTML"),
        "the innerHTML sink after `a++ / 2` is not found:\n{text}"
    );
}

/// ADR-014, design section 3.9: a TypeScript non-null assertion `!`
/// before a division hides the `innerHTML` sink the same way.
#[test]
fn review_adr014_web_scan_non_null_assertion_hides_inner_html() {
    let repo = Repo::new("non-null");
    repo.write(
        "web/src/core/render.ts",
        "export function put(el: HTMLElement, s: string, n: number | undefined): number {\n  const h = n! / 2; el.innerHTML = s; const q = h / 1;\n  return q;\n}\n",
    );
    repo.lock();
    let text = repo.report();
    assert!(
        web_scan_error(&text, "innerHTML"),
        "the innerHTML sink after `n! / 2` is not found:\n{text}"
    );
}

/// ADR-014, design section 3.9: with `noUncheckedIndexedAccess`, an
/// indexed read is often asserted with `!` before a division. The lexer
/// reads the `/` as an unclosed regular expression and refuses the whole
/// file, although it holds no banned sink.
#[test]
fn review_adr014_web_scan_accepts_division_after_non_null_index() {
    let repo = Repo::new("index-div");
    repo.write(
        "web/src/core/ratio.ts",
        "export function half(xs: readonly number[]): number {\n  return xs[0]! / 2;\n}\n",
    );
    repo.lock();
    let text = repo.report();
    assert!(
        !text
            .lines()
            .any(|l| l.trim_start().starts_with("error[web-scan")),
        "a division after `xs[0]!` is refused:\n{text}"
    );
}

/// ADR-014, design section 3.9: `onboarding` is one of the design's own
/// feature folders and names no event handler attribute. A route key or
/// segment of that name is not an `on*` attribute string.
#[test]
fn review_adr014_web_scan_accepts_onboarding_names() {
    let repo = Repo::new("onboarding");
    repo.write(
        "web/src/core/router.ts",
        "export const SEGMENTS = { onboarding: \"onboarding\" } as const;\n",
    );
    repo.lock();
    let text = repo.report();
    assert!(
        !web_scan_error(&text, "onboarding"),
        "the feature name `onboarding` is refused as an event handler:\n{text}"
    );
}
