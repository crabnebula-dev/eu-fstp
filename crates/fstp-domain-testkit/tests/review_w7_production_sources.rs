//! Review reproducers for the M2 final review (W7): source scans of the
//! five production crates of M2.
//!
//! Design section 1, "No floats": a testkit source scan fails on `f32`,
//! `f64`, `as_f64_lossy` or `fstp_json::Decimal` in `fstp-money`,
//! `fstp-ledger`, `fstp-domain`, `fstp-findings` and `fstp-engine`. The
//! clippy lints miss an ordered float comparison, a call of
//! `as_f64_lossy` and money decoded through `Decimal`, which normalises
//! `1234.50` to `1234.5` against ADR-006.
//!
//! Design section 1, "M2 crates do no I/O": the layering gate checks the
//! dependency graph. This scan also fails on `std::net`, `std::fs`,
//! `std::process`, `std::env` or `SystemTime` in the same crates.
//!
//! The scan reads lines. It skips line comments and `#[cfg(test)]`
//! modules, inline or in their own file. `Decimal` counts wherever it
//! appears, since these crates define no type of that name.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// The production crates of M2.
const CRATES: [&str; 5] = [
    "fstp-money",
    "fstp-ledger",
    "fstp-domain",
    "fstp-findings",
    "fstp-engine",
];

/// Float tokens (design section 1, ADR-006).
const FLOAT_TOKENS: [&str; 4] = ["f32", "f64", "as_f64_lossy", "Decimal"];

/// I/O paths under `std` (design section 1).
const IO_MODULES: [&str; 4] = ["net", "fs", "process", "env"];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read {dir:?}: {e}"));
    for e in entries {
        let p = e.unwrap_or_else(|e| panic!("entry of {dir:?}: {e}")).path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// The files of a `mod name;` declared in `file`.
fn module_files(file: &Path, name: &str) -> [PathBuf; 2] {
    let dir = file.parent().unwrap_or_else(|| Path::new("."));
    let stem = file.file_stem().and_then(|s| s.to_str()).unwrap_or("");
    let base = if matches!(stem, "mod" | "lib" | "main") {
        dir.to_path_buf()
    } else {
        dir.join(stem)
    };
    [
        base.join(format!("{name}.rs")),
        base.join(name).join("mod.rs"),
    ]
}

/// The opening braces of `line` minus its closing braces.
fn balance(line: &str) -> i64 {
    let count = |c: char| i64::try_from(line.matches(c).count()).unwrap_or(i64::MAX);
    count('{').saturating_sub(count('}'))
}

fn identifiers(line: &str) -> BTreeSet<&str> {
    line.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|t| !t.is_empty())
        .collect()
}

/// The production lines of `text`: each with its number, with line
/// comments and `#[cfg(test)]` modules left out. Test module files
/// declared here are added to `skip`.
fn production_lines<'a>(
    file: &Path,
    text: &'a str,
    skip: &mut BTreeSet<PathBuf>,
) -> Vec<(usize, &'a str)> {
    let mut out = Vec::new();
    let mut cfg_test = false;
    let mut in_attribute = false;
    let mut depth: Option<i64> = None;
    for (i, line) in text.lines().enumerate() {
        let t = line.trim();
        if let Some(d) = depth.as_mut() {
            *d = d.saturating_add(balance(line));
            if *d <= 0 {
                depth = None;
            }
            continue;
        }
        if t.starts_with("//") {
            continue;
        }
        if t == "#[cfg(test)]" {
            cfg_test = true;
            continue;
        }
        if cfg_test {
            if in_attribute {
                in_attribute = !t.ends_with(']');
                continue;
            }
            if t.starts_with("#[") {
                in_attribute = !t.ends_with(']');
                continue;
            }
            cfg_test = false;
            let item = t
                .trim_start_matches("pub(crate) ")
                .trim_start_matches("pub ");
            if let Some(rest) = item.strip_prefix("mod ") {
                if let Some(name) = rest.strip_suffix(';') {
                    skip.extend(module_files(file, name.trim()));
                } else {
                    let d = balance(line);
                    if d > 0 {
                        depth = Some(d);
                    }
                }
                continue;
            }
        }
        let code = line.split("//").next().unwrap_or("");
        out.push((i.saturating_add(1), code));
    }
    out
}

/// Every hit of `check` in the production sources of the five crates.
fn scan(check: impl Fn(&str) -> Option<String>) -> Vec<String> {
    let root = workspace_root();
    let mut files = Vec::new();
    for c in CRATES {
        rust_files(&root.join("crates").join(c).join("src"), &mut files);
    }
    assert!(
        files.len() > 20,
        "the scan found only {} files",
        files.len()
    );
    let mut skip = BTreeSet::new();
    let mut lines = Vec::new();
    for f in &files {
        let text = std::fs::read_to_string(f).unwrap_or_else(|e| panic!("read {f:?}: {e}"));
        for (n, code) in production_lines(f, &text, &mut skip) {
            lines.push((f.clone(), n, code.to_owned()));
        }
    }
    let mut hits = Vec::new();
    for (f, n, code) in lines {
        if skip.contains(&f) {
            continue;
        }
        if let Some(why) = check(&code) {
            hits.push(format!("{}:{n}: {why}: {}", f.display(), code.trim()));
        }
    }
    hits
}

/// Design section 1, ADR-006, I-13: no production line of the five M2
/// crates names `f32`, `f64`, `as_f64_lossy` or `fstp_json::Decimal`.
#[test]
fn review_w7_production_crates_name_no_floats() {
    let hits = scan(|code| {
        let ids = identifiers(code);
        FLOAT_TOKENS
            .iter()
            .find(|t| ids.contains(**t))
            .map(|t| format!("names {t}"))
    });
    assert!(hits.is_empty(), "No floats:\n{}", hits.join("\n"));
}

/// Design section 1: no production line of the five M2 crates names
/// `std::net`, `std::fs`, `std::process`, `std::env` or `SystemTime`.
#[test]
fn review_w7_production_crates_name_no_io() {
    let hits = scan(|code| {
        let compact: String = code.chars().filter(|c| !c.is_whitespace()).collect();
        let ids = identifiers(code);
        if ids.contains("SystemTime") {
            return Some("names SystemTime".to_owned());
        }
        for m in IO_MODULES {
            if compact.contains(&format!("std::{m}")) {
                return Some(format!("names std::{m}"));
            }
            if compact.contains("std::{") && ids.contains(m) {
                return Some(format!("imports std::{m}"));
            }
        }
        None
    });
    assert!(hits.is_empty(), "M2 crates do no I/O:\n{}", hits.join("\n"));
}

/// The scan itself: a float, an I/O path and a test module are told apart.
#[test]
fn review_w7_production_scan_skips_comments_and_test_modules() {
    let text = "fn a() -> f64 { 0.0 }\n// f32 in a comment\n#[cfg(test)]\n#[allow(\n    clippy::unwrap_used\n)]\nmod tests {\n    fn b() -> f32 { 0.0 }\n}\nfn c() {} // f32\n#[cfg(test)]\nmod more;\nuse std::{fs, io};\n";
    let mut skip = BTreeSet::new();
    let lines = production_lines(Path::new("/x/src/lib.rs"), text, &mut skip);
    let numbers: Vec<usize> = lines.iter().map(|(n, _)| *n).collect();
    assert_eq!(numbers, vec![1, 10, 13], "{lines:?}");
    assert!(skip.contains(Path::new("/x/src/more.rs")), "{skip:?}");
    assert!(identifiers(lines[0].1).contains("f64"));
    assert!(!identifiers(lines[1].1).contains("f32"));
}
