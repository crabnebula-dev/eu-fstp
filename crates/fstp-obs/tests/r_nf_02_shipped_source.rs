//! R-NF-02: a source scan of the shipped crates, beside the clippy ban.
//!
//! M3 design section 11.1 bans the print macros in shipped crates. The
//! workspace `clippy.toml` holds the ban. Two gaps remain that clippy cannot
//! close by itself, and this scan closes them.
//!
//! - A shipped crate could opt out with `allow(clippy::disallowed_macros)`,
//!   `allow(clippy::disallowed_methods)`, the `expect` forms, a lint group
//!   that holds them, a `[lints]` table or its own `clippy.toml`. The only
//!   opt-outs in shipped code are the two writers in `fstp-obs`.
//! - A shipped crate could open a file on `/dev/stderr` or
//!   `/proc/self/fd/2` and write to the log stream that way. Shipped
//!   sources hold no such path literal.
//!
//! Test-only crates, `tests/`, `examples/`, `benches/` and fuzz projects
//! are outside the scan. Every other workspace member counts as shipped, so
//! a new crate is scanned from its first commit.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::path::{Path, PathBuf};

/// Workspace members that never ship. They match the test-only crates of
/// tools/deps-check, plus the PostgreSQL test harness and deps-check itself.
const TEST_ONLY: &[&str] = &[
    "crates/fstp-prop",
    "crates/fstp-mc",
    "crates/fstp-domain-testkit",
    "crates/fstp-celltest",
    "crates/fstp-pgtest",
    "tools/deps-check",
];

/// The file that holds the two allowed writers.
const WRITER_FILE: &str = "crates/fstp-obs/src/encode.rs";

/// The functions that may opt out of `clippy::disallowed_methods`.
const WRITERS: &[&str] = &["pub fn log_to_stderr(", "pub fn metric_to_stdout("];

/// Lint names whose `allow` or `expect` turns the print ban off. The two
/// groups and `warnings` hold the disallowed lints.
const BAN_LINTS: &[&str] = &[
    "clippy::disallowed_macros",
    "clippy::disallowed_methods",
    "clippy::style",
    "clippy::all",
    "warnings",
];

/// Path literals that name the standard output or error stream.
const STREAM_PATHS: &[&str] = &[
    "/dev/stdout",
    "/dev/stderr",
    "/dev/fd/",
    "/proc/self/fd",
    "/proc/thread-self/fd",
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The quoted entries of the root `members = [..]` array, with comment
/// lines skipped.
fn members(cargo_toml: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut inside = false;
    for line in cargo_toml.lines() {
        let t = line.trim();
        if !inside {
            inside = t.starts_with("members") && t.ends_with('[');
            continue;
        }
        if t.starts_with(']') {
            break;
        }
        if t.starts_with('#') {
            continue;
        }
        if let Some(name) = t.split('"').nth(1) {
            out.push(name.to_string());
        }
    }
    out
}

/// The shipped workspace members: every member that is not test only.
fn shipped_crates(root: &Path) -> Vec<String> {
    let toml = std::fs::read_to_string(root.join("Cargo.toml")).unwrap();
    members(&toml)
        .into_iter()
        .filter(|m| !TEST_ONLY.contains(&m.as_str()))
        .collect()
}

/// Every file under `dir`, skipping `target` and hidden directories.
fn files_under(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if p.is_dir() {
            if name != "target" && !name.starts_with('.') {
                files_under(&p, out);
            }
        } else {
            out.push(p);
        }
    }
}

/// The Rust sources of a shipped crate that ship: `src/` and `build.rs`.
fn shipped_sources(crate_dir: &Path) -> Vec<PathBuf> {
    let mut all = Vec::new();
    files_under(&crate_dir.join("src"), &mut all);
    all.push(crate_dir.join("build.rs"));
    all.into_iter()
        .filter(|p| p.is_file() && p.extension().is_some_and(|x| x == "rs"))
        .collect()
}

/// Rust source with every comment replaced by a space. String and
/// character literals are kept, so `"a//b"` does not start a comment.
fn strip_comments(src: &str) -> String {
    let b = src.as_bytes();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        let next = b.get(i + 1).copied();
        if c == b'/' && next == Some(b'/') {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
            out.push(' ');
        } else if c == b'/' && next == Some(b'*') {
            let mut depth = 0usize;
            while i < b.len() {
                if b[i] == b'/' && b.get(i + 1) == Some(&b'*') {
                    depth += 1;
                    i += 2;
                } else if b[i] == b'*' && b.get(i + 1) == Some(&b'/') {
                    depth -= 1;
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    i += 1;
                }
            }
            out.push(' ');
        } else if c == b'r' && matches!(next, Some(b'"' | b'#')) && raw_start(b, i) {
            let start = i;
            let mut j = i + 1;
            let mut hashes = 0;
            while b.get(j) == Some(&b'#') {
                hashes += 1;
                j += 1;
            }
            if b.get(j) == Some(&b'"') {
                j += 1;
                loop {
                    match b.get(j) {
                        None => break,
                        Some(b'"') if b[j + 1..].iter().take(hashes).all(|&h| h == b'#') => {
                            j += 1 + hashes;
                            break;
                        }
                        Some(_) => j += 1,
                    }
                }
            }
            let end = j.min(b.len());
            out.push_str(&src[start..end]);
            i = end;
        } else if c == b'"' {
            let start = i;
            i += 1;
            while i < b.len() && b[i] != b'"' {
                i += if b[i] == b'\\' { 2 } else { 1 };
            }
            i = (i + 1).min(b.len());
            out.push_str(&src[start..i]);
        } else if c == b'\'' {
            // A character literal, or a lifetime that has no closing quote.
            let len = if next == Some(b'\\') {
                b.get(i + 3..)
                    .and_then(|r| r.iter().position(|&x| x == b'\''))
                    .map(|p| p + 4)
            } else {
                let ch = src[i + 1..].chars().next().map_or(1, char::len_utf8);
                (b.get(i + 1 + ch) == Some(&b'\'')).then_some(ch + 2)
            };
            let end = (i + len.unwrap_or(1)).min(b.len());
            out.push_str(&src[i..end]);
            i = end;
        } else {
            let ch = src[i..].chars().next().map_or(1, char::len_utf8);
            out.push_str(&src[i..i + ch]);
            i += ch;
        }
    }
    out
}

fn ident_before(b: &[u8], i: usize) -> bool {
    i > 0 && (b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_')
}

/// Whether the `r` at `i` starts a raw string, alone or after a `b`.
fn raw_start(b: &[u8], i: usize) -> bool {
    !ident_before(b, i) || (b[i - 1] == b'b' && !ident_before(b, i - 1))
}

/// One opt-out of the print ban: the lint it names and the code that
/// follows the attribute.
#[derive(Debug)]
struct OptOut {
    lint: &'static str,
    after: String,
}

/// Every `allow(..)` or `expect(..)` in comment-free source that names a
/// lint of [`BAN_LINTS`], including the `cfg_attr` and multi-line forms.
fn opt_outs(code: &str) -> Vec<OptOut> {
    let b = code.as_bytes();
    let mut found = Vec::new();
    for word in ["allow(", "expect("] {
        for (at, _) in code.match_indices(word) {
            if ident_before(b, at) {
                continue;
            }
            let open = at + word.len();
            let mut depth = 1usize;
            let mut close = None;
            for (k, ch) in code[open..].char_indices() {
                match ch {
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            close = Some(open + k);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let Some(close) = close else { continue };
            let items: String = code[open..close]
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            let rest = code[close..].trim_start_matches([')', ']']).trim_start();
            let after: String = rest.chars().take(64).collect();
            for item in items.split(',') {
                if let Some(&lint) = BAN_LINTS.iter().find(|l| **l == item) {
                    found.push(OptOut {
                        lint,
                        after: after.clone(),
                    });
                }
            }
        }
    }
    found
}

/// Whether an opt-out is one of the two allowed writers in `fstp-obs`.
fn is_allowed_writer(rel: &str, o: &OptOut) -> bool {
    rel == WRITER_FILE
        && o.lint == "clippy::disallowed_methods"
        && WRITERS.iter().any(|w| o.after.starts_with(w))
}

/// The refused opt-outs in one Rust source file.
fn refused_in_source(rel: &str, src: &str) -> Vec<String> {
    opt_outs(&strip_comments(src))
        .into_iter()
        .filter(|o| !is_allowed_writer(rel, o))
        .map(|o| format!("{rel}: allows {} before `{}`", o.lint, o.after))
        .collect()
}

/// The lint keys of a `[lints]` table that turn the print ban off.
const BAN_KEYS: &[&str] = &[
    "disallowed_macros",
    "disallowed_methods",
    "style",
    "all",
    "warnings",
];

/// Lines of a `Cargo.toml` that set a lint of [`BAN_KEYS`] to `allow` or
/// `expect`, as in `[lints.clippy]` or `[workspace.lints.clippy]`.
fn refused_in_manifest(rel: &str, toml: &str) -> Vec<String> {
    toml.lines()
        .filter_map(|line| {
            let code = line.split('#').next().unwrap_or("");
            let (key, value) = code.split_once('=')?;
            let key = key.trim().trim_matches('"');
            let off = value.contains("\"allow\"") || value.contains("\"expect\"");
            (BAN_KEYS.contains(&key) && off).then(|| format!("{rel}: {}", line.trim()))
        })
        .collect()
}

/// Stream path literals in comment-free Rust source.
fn stream_paths_in_source(rel: &str, src: &str) -> Vec<String> {
    let code = strip_comments(src);
    STREAM_PATHS
        .iter()
        .filter(|p| code.contains(*p))
        .map(|p| format!("{rel}: names {p}"))
        .collect()
}

fn rel_of(root: &Path, p: &Path) -> String {
    p.strip_prefix(root)
        .unwrap_or(p)
        .to_string_lossy()
        .replace('\\', "/")
}

/// R-NF-02 (design section 11.1): no shipped crate opts out of the print
/// ban. The only opt-outs in shipped code are `log_to_stderr` and
/// `metric_to_stdout` in `fstp-obs`. No shipped crate turns the lints off
/// in a `[lints]` table or replaces the workspace `clippy.toml` with its
/// own.
#[test]
fn r_nf_02_shipped_crates_do_not_opt_out_of_the_print_ban() {
    let root = workspace_root();
    let shipped = shipped_crates(&root);
    assert!(
        shipped.iter().any(|c| c == "crates/fstp-obs")
            && shipped.iter().any(|c| c == "crates/fstp-cell")
            && !shipped.iter().any(|c| c == "crates/fstp-prop"),
        "the member list did not parse: {shipped:?}"
    );
    let mut bad = refused_in_manifest(
        "Cargo.toml",
        &std::fs::read_to_string(root.join("Cargo.toml")).unwrap(),
    );
    let mut writers = 0usize;
    for krate in &shipped {
        let dir = root.join(krate);
        let manifest = dir.join("Cargo.toml");
        let toml = std::fs::read_to_string(&manifest).unwrap();
        bad.extend(refused_in_manifest(&rel_of(&root, &manifest), &toml));
        let mut all = Vec::new();
        files_under(&dir, &mut all);
        for p in &all {
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let in_fuzz = p.strip_prefix(&dir).is_ok_and(|r| r.starts_with("fuzz"));
            if !in_fuzz && (name == "clippy.toml" || name == ".clippy.toml") {
                bad.push(format!("{}: replaces the workspace ban", rel_of(&root, p)));
            }
        }
        for p in shipped_sources(&dir) {
            let rel = rel_of(&root, &p);
            let src = std::fs::read_to_string(&p).unwrap();
            if rel == WRITER_FILE {
                writers += opt_outs(&strip_comments(&src))
                    .iter()
                    .filter(|o| is_allowed_writer(&rel, o))
                    .count();
            }
            bad.extend(refused_in_source(&rel, &src));
        }
    }
    assert!(
        bad.is_empty() && writers == WRITERS.len(),
        "opt-outs of the R-NF-02 print ban in shipped code ({writers} writers):\n{}",
        bad.join("\n")
    );
}

/// R-NF-02 (design section 11.1): no shipped source names a path to the
/// standard output or error stream, so no file opened by path bypasses the
/// clippy ban on the raw handles.
#[test]
fn r_nf_02_shipped_crates_do_not_open_the_standard_streams_by_path() {
    let root = workspace_root();
    let mut bad = Vec::new();
    for krate in shipped_crates(&root) {
        for p in shipped_sources(&root.join(&krate)) {
            let src = std::fs::read_to_string(&p).unwrap();
            bad.extend(stream_paths_in_source(&rel_of(&root, &p), &src));
        }
    }
    assert!(
        bad.is_empty(),
        "stream paths in shipped code:\n{}",
        bad.join("\n")
    );
}

/// Teeth for the opt-out scan: each opt-out form is caught, the two
/// writers pass only in `fstp-obs`, and look-alikes pass.
#[test]
fn r_nf_02_teeth_scan_catches_an_opt_out_in_shipped_source() {
    const CELL: &str = "crates/fstp-cell/src/lib.rs";
    let writer = "#[allow(\n    clippy::disallowed_methods,\n    reason = \"R-NF-02, one writer\"\n)]\npub fn log_to_stderr(e: &E) {}\n";
    let cases: &[(&str, &str, usize)] = &[
        (
            "crates/fstp-cell/src/main.rs",
            "#![allow(\n    clippy::disallowed_macros,\n    clippy::disallowed_methods,\n    reason = \"x\"\n)]\nfn main() {}\n",
            2,
        ),
        (
            CELL,
            "#[expect(clippy::disallowed_methods)]\nfn f() {}\n",
            1,
        ),
        (CELL, "#![allow(clippy::all)]\n", 1),
        (CELL, "#![allow(clippy :: style)]\n", 1),
        (CELL, "#![cfg_attr(test, allow(warnings))]\n", 1),
        (CELL, "// #[allow(clippy::disallowed_macros)]\n", 0),
        (CELL, "/* #[allow(clippy::disallowed_macros)] */\n", 0),
        (CELL, "#![deny(clippy::all)]\nfn f() { p.allow(x); }\n", 0),
        (
            CELL,
            "const S: &str = \"a//b\";\n#[allow(clippy::disallowed_macros)]\nfn f() {}\n",
            1,
        ),
        (WRITER_FILE, writer, 0),
        ("crates/fstp-vault/src/lib.rs", writer, 1),
        (
            WRITER_FILE,
            "#[allow(clippy::disallowed_methods)]\npub fn other() {}\n",
            1,
        ),
        (
            WRITER_FILE,
            "#[allow(clippy::disallowed_macros)]\npub fn log_to_stderr() {}\n",
            1,
        ),
    ];
    let wrong: Vec<String> = cases
        .iter()
        .filter_map(|(rel, src, want)| {
            let got = refused_in_source(rel, src).len();
            (got != *want).then(|| format!("{rel} {src:?}: want {want}, got {got}"))
        })
        .collect();
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// Teeth for the manifest scan: a `[lints]` table that turns a ban lint
/// off is caught, and one that keeps it on passes.
#[test]
fn r_nf_02_teeth_scan_catches_a_lints_table_opt_out() {
    let cases: &[(&str, usize)] = &[
        ("[lints.clippy]\ndisallowed_macros = \"allow\"\n", 1),
        (
            "[lints.clippy]\ndisallowed_methods = { level = \"expect\" }\n",
            1,
        ),
        (
            "[workspace.lints.clippy]\nall = { level = \"allow\", priority = -1 }\n",
            1,
        ),
        ("[lints.rust]\nwarnings = \"allow\"\n", 1),
        (
            "[lints.clippy]\nall = \"warn\"\nunwrap_used = \"deny\"\n",
            0,
        ),
        (
            "[lints]\nworkspace = true\n# disallowed_macros = \"allow\"\n",
            0,
        ),
    ];
    let wrong: Vec<String> = cases
        .iter()
        .filter_map(|(toml, want)| {
            let got = refused_in_manifest("Cargo.toml", toml).len();
            (got != *want).then(|| format!("{toml:?}: want {want}, got {got}"))
        })
        .collect();
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// Teeth for the stream path scan: a path literal to either stream is
/// caught, a mention in a comment passes, and other device paths pass.
#[test]
fn r_nf_02_teeth_scan_catches_a_stream_path_literal() {
    let cases: &[(&str, usize)] = &[
        ("std::fs::write(\"/dev/stderr\", t)", 1),
        (
            "let f = OpenOptions::new().append(true).open(\"/dev/stdout\");",
            1,
        ),
        ("open(\"/proc/self/fd/2\")", 1),
        ("open(r#\"/dev/fd/1\"#)", 1),
        ("let u = \"a//b\"; open(\"/proc/thread-self/fd/2\")", 1),
        ("// never open /dev/stderr here\nopen(\"/dev/null\")", 0),
        ("let c = '\"'; open(\"/dev/urandom\")", 0),
    ];
    let wrong: Vec<String> = cases
        .iter()
        .filter_map(|(src, want)| {
            let got = stream_paths_in_source("crates/fstp-cell/src/lib.rs", src).len();
            (got != *want).then(|| format!("{src:?}: want {want}, got {got}"))
        })
        .collect();
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
