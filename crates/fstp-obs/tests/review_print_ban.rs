//! Review reproducers for the R-NF-02 print ban (M3 design section 11.1).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if p.is_dir() {
            if name != "target" && !name.starts_with('.') {
                rust_files(&p, out);
            }
        } else if name.ends_with(".rs") {
            out.push(p);
        }
    }
}

/// The macro names, built at run time so this file does not match itself.
fn needles() -> Vec<String> {
    ["println", "eprintln", "print", "eprint", "dbg"]
        .iter()
        .map(|m| format!("{m}{}", '!'))
        .collect()
}

fn uses_print(src: &str, needles: &[String]) -> bool {
    src.lines().any(|l| {
        let t = l.trim_start();
        !t.starts_with("//")
            && needles.iter().any(|n| {
                l.match_indices(n.as_str()).any(|(at, _)| {
                    let before = l[..at].chars().last();
                    !before.is_some_and(|c| c.is_alphanumeric() || c == '_')
                })
            })
    })
}

/// Whitespace is ignored, so a multi-line `#![allow(\n    clippy::disallowed_macros,` counts.
fn allows_ban(src: &str) -> bool {
    let flat: String = src.chars().filter(|c| !c.is_whitespace()).collect();
    flat.contains("allow(clippy::disallowed_macros")
}

/// R-NF-02 (design section 11.1, W2l scope): the print ban must not break the
/// clippy gate. Every non-comment use of a banned print macro in the
/// workspace is either removed or sits under an explicit
/// `allow(clippy::disallowed_macros)` in its file or its crate root. Today
/// the W0 stub mains, fstp-prop, deps-check and the testkit tests use the
/// macros with no allow, so `cargo clippy --workspace -- -D warnings` fails.
#[test]
fn review_print_ban_leaves_the_clippy_gate_green() {
    let root = workspace_root();
    let mut files = Vec::new();
    rust_files(&root.join("crates"), &mut files);
    rust_files(&root.join("tools"), &mut files);
    let needles = needles();
    let mut bad = Vec::new();
    for f in &files {
        let src = std::fs::read_to_string(f).unwrap_or_default();
        if !uses_print(&src, &needles) || allows_ban(&src) {
            continue;
        }
        // A crate-level allow in the crate root covers the crate's own files.
        let crate_dir = f
            .ancestors()
            .find(|a| a.join("Cargo.toml").is_file())
            .map(Path::to_path_buf);
        let root_allows = crate_dir.is_some_and(|d| {
            ["src/lib.rs", "src/main.rs"]
                .iter()
                .any(|r| allows_ban(&std::fs::read_to_string(d.join(r)).unwrap_or_default()))
                && f.starts_with(d.join("src"))
                && !f.starts_with(d.join("src/bin"))
        });
        if !root_allows {
            bad.push(f.strip_prefix(&root).unwrap_or(f).display().to_string());
        }
    }
    bad.sort();
    assert!(
        bad.is_empty(),
        "print macros the clippy ban rejects, with no allow:\n{}",
        bad.join("\n")
    );
}

/// The array that `key` is set to in a TOML text, from `key` to the next
/// line that is only `]`.
fn array_text<'a>(toml: &'a str, key: &str) -> &'a str {
    let Some(start) = toml.find(key) else {
        return "";
    };
    let rest = &toml[start..];
    let end = rest.find("\n]").map_or(rest.len(), |e| e + 2);
    &rest[..end]
}

/// R-NF-02 strength: the clippy.toml comment says shipped crates write no
/// free text to stdout or stderr. The ban covers only the print macros, so
/// `writeln!(std::io::stderr(), "{text}")` and
/// `std::io::stdout().write_all(text)` pass clippy in a shipped crate. The
/// ban needs `std::io::stdout` and `std::io::stderr` too, with fstp-obs as
/// the one allowed writer.
#[test]
fn review_clippy_bans_direct_stdout_and_stderr_handles() {
    let toml = std::fs::read_to_string(workspace_root().join("clippy.toml")).unwrap();
    let methods = array_text(&toml, "disallowed-methods");
    let missing: Vec<&str> = ["std::io::stdout", "std::io::stderr"]
        .into_iter()
        .filter(|p| !methods.contains(&format!("\"{p}\"")))
        .collect();
    assert!(
        missing.is_empty(),
        "free text reaches stdout or stderr without a print macro: \
         disallowed-methods does not name {missing:?}"
    );
}
