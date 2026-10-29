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
//! `std::io`, `std::process`, `std::env`, `SystemTime` or `Instant` in the
//! same crates. A `use` item is read as one statement, so a grouped
//! `use std::{...}` import over several lines is caught too (W7 fix). So
//! is one behind any visibility, such as `pub(super)` or
//! `pub(in crate::x)` (W7 fix round 2).
//!
//! The scan reads lines, and joins the lines of a `use` item. It skips
//! line comments and `#[cfg(test)]` modules, inline or in their own file. `Decimal` counts wherever it
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
const IO_MODULES: [&str; 5] = ["net", "fs", "io", "process", "env"];

/// Wall-clock types under `std::time` (design section 1, design 2.2: time
/// comes only from `Ctx::now`).
const CLOCK_TYPES: [&str; 2] = ["SystemTime", "Instant"];

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

/// `item` without a leading visibility: `pub`, or `pub(...)` with any
/// balanced path inside, such as `pub(super)` or `pub(in crate::x)`.
fn strip_visibility(item: &str) -> &str {
    let Some(rest) = item.strip_prefix("pub") else {
        return item;
    };
    if let Some(rest) = rest.strip_prefix(' ') {
        return rest.trim_start();
    }
    let Some(inner) = rest.strip_prefix('(') else {
        return item;
    };
    let mut depth = 1_usize;
    for (i, c) in inner.char_indices() {
        match c {
            '(' => depth = depth.saturating_add(1),
            ')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return inner.get(i.saturating_add(1)..).unwrap_or("").trim_start();
                }
            }
            _ => {}
        }
    }
    item
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
            let item = strip_visibility(t);
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

/// The statements of `lines`: each line on its own, except that the lines
/// of one `use` item are joined up to its `;`, numbered by its first line.
fn statements(lines: &[(usize, &str)]) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut open: Option<(usize, String)> = None;
    for (n, code) in lines {
        if let Some((first, text)) = open.as_mut() {
            text.push(' ');
            text.push_str(code.trim());
            if code.contains(';') {
                out.push((*first, std::mem::take(text)));
                open = None;
            }
            continue;
        }
        let t = strip_visibility(code.trim());
        if t.starts_with("use ") && !t.contains(';') {
            open = Some((*n, code.trim().to_owned()));
        } else {
            out.push((*n, (*code).to_owned()));
        }
    }
    out.extend(open);
    out
}

/// Why `code` names I/O or the wall clock under `std`, if it does.
fn io_hit(code: &str) -> Option<String> {
    let compact: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    let ids = identifiers(code);
    if let Some(t) = CLOCK_TYPES.iter().find(|t| ids.contains(**t)) {
        return Some(format!("names {t}"));
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
        let own = production_lines(f, &text, &mut skip);
        for (n, code) in statements(&own) {
            lines.push((f.clone(), n, code));
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

/// Design section 1: no production statement of the five M2 crates names
/// `std::net`, `std::fs`, `std::io`, `std::process`, `std::env`,
/// `SystemTime` or `Instant`, grouped imports over several lines included.
#[test]
fn review_w7_production_crates_name_no_io() {
    let hits = scan(io_hit);
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

/// Design section 1 (W7 fix): a grouped `use std::{...}` import over
/// several lines and `std::time::Instant` are caught by the I/O scan.
#[test]
fn review_w7_production_scan_catches_grouped_imports_and_instant() {
    let text = "use std::{\n    collections::BTreeMap,\n    fs,\n};\nuse std::time::Instant;\npub(crate) use std::{\n    process\n};\nuse std::{\n    collections::BTreeSet,\n    sync::Arc,\n};\nfn d() -> Instant { e() }\n";
    let mut skip = BTreeSet::new();
    let lines = production_lines(Path::new("/x/src/lib.rs"), text, &mut skip);
    let joined = statements(&lines);
    let numbers: Vec<usize> = joined.iter().map(|(n, _)| *n).collect();
    assert_eq!(numbers, vec![1, 5, 6, 9, 13], "{joined:?}");
    let hits: Vec<Option<String>> = joined.iter().map(|(_, c)| io_hit(c)).collect();
    assert_eq!(
        hits,
        vec![
            Some("imports std::fs".to_owned()),
            Some("names Instant".to_owned()),
            Some("imports std::process".to_owned()),
            None,
            Some("names Instant".to_owned()),
        ],
        "{joined:?}"
    );
}

/// Design section 1 (W7 fix round 2): a grouped `use std::{...}` import
/// over several lines behind `pub(super)` or `pub(in crate::x)` is joined
/// and caught, and so is `std::io`. A `pub(crate)` test module behind
/// another visibility is skipped as before.
#[test]
fn review_w7_production_scan_catches_imports_behind_any_visibility() {
    let text = "pub(super) use std::{\n    fs,\n};\npub(in crate::x) use std::{\n    net,\n};\nuse std::io::Write;\npub(self) use std::{\n    io,\n};\n#[cfg(test)]\npub(super) mod tests {\n    use std::fs;\n}\n";
    let mut skip = BTreeSet::new();
    let lines = production_lines(Path::new("/x/src/lib.rs"), text, &mut skip);
    let joined = statements(&lines);
    let numbers: Vec<usize> = joined.iter().map(|(n, _)| *n).collect();
    assert_eq!(numbers, vec![1, 4, 7, 8], "{joined:?}");
    let hits: Vec<Option<String>> = joined.iter().map(|(_, c)| io_hit(c)).collect();
    assert_eq!(
        hits,
        vec![
            Some("imports std::fs".to_owned()),
            Some("imports std::net".to_owned()),
            Some("names std::io".to_owned()),
            Some("imports std::io".to_owned()),
        ],
        "{joined:?}"
    );
    assert_eq!(strip_visibility("pub(in crate::a::b) use x;"), "use x;");
    assert_eq!(strip_visibility("pub use x;"), "use x;");
    assert_eq!(strip_visibility("public_fn();"), "public_fn();");
}
