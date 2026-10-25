//! I-12 by construction point 3 (design 2.4): every guard reads frozen
//! values through the call's `FrozenPolicy`, never from a `PolicyVersion`.
//!
//! This test scans the domain crate's source. Outside the policy lane's
//! own files, no code line may read a `.frozen` field, name a
//! `PolicyVersion { .. }` pattern or literal, or bind a `frozen:` field. A
//! call of the method `.frozen()` returns the call's `FrozenPolicy` and is
//! allowed. The codec is excluded because encoding a version is not a guard.
//!
//! Only `policy/mod.rs` and `programme.rs` are the lane's own files. Two
//! pre-freeze reads there take frozen values from the head: the P-21 check
//! of `PublishCall` and the P-77 of a programme-scoped MCP command. The
//! M-POLICY teeth test covers those files. A new file under `policy/` is
//! scanned like any other.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

/// The domain crate's source directory.
fn domain_src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../fstp-domain/src")
}

/// Whether `rel`, relative to the source directory, is excluded from the scan.
fn excluded(rel: &Path) -> bool {
    rel == Path::new("policy/mod.rs")
        || rel == Path::new("programme.rs")
        || rel.starts_with("codec")
}

/// Every `.rs` file under `dir`, recursively.
fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for entry in entries {
        let path = entry.map_err(|e| format!("{}: {e}", dir.display()))?.path();
        if path.is_dir() {
            rust_files(&path, out)?;
        } else if path.extension().is_some_and(|x| x == "rs") {
            out.push(path);
        }
    }
    Ok(())
}

/// Whether `c` can continue an identifier.
fn ident_char(c: char) -> bool {
    c == '_' || c.is_alphanumeric()
}

/// Whether `line` reads a `.frozen` field rather than calling `.frozen()`.
fn reads_frozen_field(line: &str) -> bool {
    let mut rest = line;
    while let Some(i) = rest.find(".frozen") {
        let after = rest.get(i.saturating_add(".frozen".len())..).unwrap_or("");
        match after.chars().next() {
            Some(c) if c == '(' || ident_char(c) => {}
            _ => return true,
        }
        rest = after;
    }
    false
}

/// Whether `line` names a `PolicyVersion { .. }` pattern or literal, which
/// can bind a head's frozen values without the text `.frozen`.
fn names_version_pattern(line: &str) -> bool {
    let mut rest = line;
    while let Some(i) = rest.find("PolicyVersion") {
        let before = rest.get(..i).and_then(|b| b.chars().next_back());
        let after = rest
            .get(i.saturating_add("PolicyVersion".len())..)
            .unwrap_or("");
        if !before.is_some_and(ident_char) && after.trim_start().starts_with('{') {
            return true;
        }
        rest = after;
    }
    false
}

/// Whether `line` binds or sets a field named `frozen` with `frozen:`.
fn binds_frozen_field(line: &str) -> bool {
    let mut rest = line;
    while let Some(i) = rest.find("frozen") {
        let before = rest.get(..i).and_then(|b| b.chars().next_back());
        let after = rest.get(i.saturating_add("frozen".len())..).unwrap_or("");
        let tail = after.trim_start();
        if !before.is_some_and(ident_char)
            && before != Some('.')
            && tail.starts_with(':')
            && !tail.starts_with("::")
        {
            return true;
        }
        rest = after;
    }
    false
}

/// Whether `line` may read a head's frozen values outside the snapshot.
fn suspicious(line: &str) -> bool {
    reads_frozen_field(line) || names_version_pattern(line) || binds_frozen_field(line)
}

/// I-12: no file of the domain crate outside the policy lane reads a
/// head's frozen values, by field, pattern or binding, so no guard there
/// can bypass the snapshot.
#[test]
fn i12_guards_read_frozen_values_only_through_the_snapshot() {
    let src = domain_src();
    let mut files = Vec::new();
    rust_files(&src, &mut files).unwrap_or_else(|e| panic!("{e}"));
    assert!(files.len() > 10, "the scan found too few files: {files:?}");
    let mut hits = Vec::new();
    for file in &files {
        let rel = file.strip_prefix(&src).unwrap_or(file);
        if excluded(rel) {
            continue;
        }
        let text = std::fs::read_to_string(file).unwrap_or_else(|e| panic!("{e}"));
        for (n, line) in text.lines().enumerate() {
            if !line.trim_start().starts_with("//") && suspicious(line) {
                hits.push(format!(
                    "{}:{}: {}",
                    rel.display(),
                    n.saturating_add(1),
                    line.trim()
                ));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "I-12: these lines may read a head's frozen values outside the policy lane. \
         Read frozen values through `policy::frozen_policy` instead:\n{}",
        hits.join("\n")
    );
}

/// I-12: the scan's matchers find field reads, version patterns and
/// `frozen:` bindings, and let the method and the snapshot read pass, so
/// the scan above cannot pass by matching nothing.
#[test]
fn i12_guard_scan_tells_a_field_read_from_the_method() {
    let flagged = [
        "let p = head.frozen.p02;",
        "let f = &v.frozen;",
        "let PolicyVersion { frozen, .. } = policy::head(state, p)?;",
        "Some(crate::policy::PolicyVersion{ frozen: f, .. }) => f.p02,",
        "match v { PolicyVersion {",
        "    frozen: f,",
    ];
    for line in flagged {
        assert!(suspicious(line), "the scan misses {line:?}");
    }
    let allowed = [
        "let f = view.frozen();",
        "let f = policy::frozen_policy(state, call);",
        "let frozen = policy::frozen_policy(state, call)?;",
        "use crate::policy::{FrozenPolicy, PolicyVersion};",
        "fn head(state: &State) -> Option<&PolicyVersion> {",
        "let x = frozen::thing();",
    ];
    for line in allowed {
        assert!(!suspicious(line), "the scan flags {line:?}");
    }
}
