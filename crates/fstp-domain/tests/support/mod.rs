//! In-house markdown helpers for the spec conformance tests.
//!
//! The tests read `SPEC/` at test time, so a spec edit that the interface
//! does not follow fails here. Helpers return `Result` with a message and
//! never panic. Only the test functions assert.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

/// The repository's `SPEC/` directory.
pub(crate) fn spec_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../SPEC")
}

/// The text of `SPEC/<rel>`.
pub(crate) fn read_spec(rel: &str) -> Result<String, String> {
    let path = spec_dir().join(rel);
    std::fs::read_to_string(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))
}

/// Every markdown file under `SPEC/`, concatenated, in sorted path order.
pub(crate) fn read_all_spec() -> Result<String, String> {
    let mut files = Vec::new();
    collect_md(&spec_dir(), &mut files)?;
    files.sort();
    let mut all = String::new();
    for f in files {
        let text =
            std::fs::read_to_string(&f).map_err(|e| format!("cannot read {}: {e}", f.display()))?;
        all.push_str(&text);
        all.push('\n');
    }
    Ok(all)
}

fn collect_md(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries =
        std::fs::read_dir(dir).map_err(|e| format!("cannot list {}: {e}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("cannot list {}: {e}", dir.display()))?;
        let path = entry.path();
        if path.is_dir() {
            collect_md(&path, out)?;
        } else if path.extension().is_some_and(|x| x == "md") {
            out.push(path);
        }
    }
    Ok(())
}

/// The lines after the heading line `heading` up to the next heading of the
/// same or a higher level.
pub(crate) fn section<'a>(doc: &'a str, heading: &str) -> Result<Vec<&'a str>, String> {
    let level = heading.chars().take_while(|c| *c == '#').count();
    let mut lines = doc.lines();
    if !lines.by_ref().any(|l| l.trim_end() == heading) {
        return Err(format!("heading {heading:?} not found"));
    }
    let mut out = Vec::new();
    for line in lines {
        let hashes = line.chars().take_while(|c| *c == '#').count();
        if hashes > 0 && hashes <= level && line.chars().nth(hashes) == Some(' ') {
            break;
        }
        out.push(line);
    }
    Ok(out)
}

/// The cells of one table line, trimmed, without the outer pipes.
pub(crate) fn cells(line: &str) -> Vec<String> {
    let inner = line.trim();
    let inner = inner.strip_prefix('|').unwrap_or(inner);
    let inner = inner.strip_suffix('|').unwrap_or(inner);
    inner.split('|').map(|c| c.trim().to_owned()).collect()
}

/// The body rows of the first table in `lines` whose header cells equal `header`.
/// Fails when no such table exists or a row has another number of cells.
pub(crate) fn table(lines: &[&str], header: &[&str]) -> Result<Vec<Vec<String>>, String> {
    let mut iter = lines.iter().skip_while(|l| {
        let c = cells(l);
        !(l.trim_start().starts_with('|')
            && c.iter().map(String::as_str).eq(header.iter().copied()))
    });
    if iter.next().is_none() {
        return Err(format!("table with header {header:?} not found"));
    }
    match iter.next() {
        Some(sep)
            if cells(sep)
                .iter()
                .all(|c| !c.is_empty() && c.chars().all(|ch| ch == '-' || ch == ':')) => {}
        _ => return Err(format!("table {header:?} has no separator line")),
    }
    let mut rows = Vec::new();
    for line in iter {
        if !line.trim_start().starts_with('|') {
            break;
        }
        let row = cells(line);
        if row.len() != header.len() {
            return Err(format!(
                "row {line:?} has {} cells, expected {}",
                row.len(),
                header.len()
            ));
        }
        rows.push(row);
    }
    if rows.is_empty() {
        return Err(format!("table {header:?} has no rows"));
    }
    Ok(rows)
}

/// `text` with every parenthesised group that starts with `NOTE ` removed,
/// and spaces trimmed. "System (NOTE 13)" becomes "System".
pub(crate) fn strip_note_refs(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(start) = rest.find("(NOTE ") {
        out.push_str(rest.get(..start).unwrap_or(""));
        let after = rest.get(start..).unwrap_or("");
        match after.find(')') {
            Some(end) => rest = after.get(end.saturating_add(1)..).unwrap_or(""),
            None => {
                rest = after;
                break;
            }
        }
    }
    out.push_str(rest);
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Whether `id` occurs in `text` as a whole token: the next character is not
/// a digit or letter, and the previous one is not a letter, digit or `-`.
pub(crate) fn contains_token(text: &str, id: &str) -> bool {
    text.match_indices(id).any(|(at, _)| {
        let before = text.get(..at).and_then(|s| s.chars().next_back());
        let after = text
            .get(at.saturating_add(id.len())..)
            .and_then(|s| s.chars().next());
        let edge_before = before.is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '-'));
        let edge_after = after.is_none_or(|c| !c.is_ascii_alphanumeric());
        edge_before && edge_after
    })
}
