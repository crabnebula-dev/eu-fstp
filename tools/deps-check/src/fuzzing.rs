//! Entry points for the cargo-fuzz project in `tools/deps-check/fuzz`
//! (TH-26, H-05, ADR-003).
//!
//! Each function feeds arbitrary bytes to one of deps-check's parsers and
//! checks properties beyond "no panic". It returns `Err` with a description
//! when a property fails, and the fuzz target turns that into a crash.
//! Invalid UTF-8 is replaced, so the text parsers see every input.

use std::collections::BTreeSet;

use crate::allowlist::{
    self, valid_adr, valid_checksum, valid_crate_name, valid_feature, valid_version,
};
use crate::graph::{self, Context, Graph, ProjectKind, Role};
use crate::lockfile;
use crate::metadata;

/// Checks that error line numbers lie between 1 and the line count, or
/// are 0 for whole-file errors when `allow_zero` is set.
fn lines_in_range(
    errs: &[allowlist::LineError],
    lines: usize,
    allow_zero: bool,
) -> Result<(), String> {
    if errs.is_empty() {
        return Err("parser failed without reporting an error".to_owned());
    }
    for e in errs {
        let ok = (e.line == 0 && allow_zero) || (1..=lines).contains(&e.line);
        if !ok {
            return Err(format!("error line {} outside 1..={lines}: {e}", e.line));
        }
    }
    Ok(())
}

/// `deps/allowlist.txt`: accepted entries are valid and unique, and
/// rendering then parsing returns the same entries.
pub fn allowlist(data: &[u8]) -> Result<(), String> {
    let text = String::from_utf8_lossy(data);
    match allowlist::parse_allowlist(&text) {
        Ok(entries) => {
            let mut seen = BTreeSet::new();
            for e in &entries {
                let valid = valid_crate_name(&e.name)
                    && valid_version(&e.version)
                    && valid_checksum(&e.checksum)
                    && !e.adrs.is_empty()
                    && e.adrs.iter().all(|a| valid_adr(a))
                    && !e.note.is_empty()
                    && e.note.trim() == e.note;
                if !valid {
                    return Err(format!("accepted an invalid entry: {e:?}"));
                }
                if !seen.insert((&e.name, &e.version)) {
                    return Err(format!("accepted a duplicate entry: {e:?}"));
                }
            }
            let rendered = allowlist::render_entries(&entries);
            let back = allowlist::parse_allowlist(&rendered)
                .map_err(|e| format!("rendered allowlist does not parse: {e:?}"))?;
            if back != entries {
                return Err(format!(
                    "round trip changed entries: {entries:?} -> {back:?}"
                ));
            }
            Ok(())
        }
        Err(errs) => lines_in_range(&errs, text.lines().count(), false),
    }
}

/// `deps/adr-roots.txt`: accepted roots are valid, and rendering then
/// parsing returns the same roots.
pub fn adr_roots(data: &[u8]) -> Result<(), String> {
    let text = String::from_utf8_lossy(data);
    match allowlist::parse_roots(&text) {
        Ok(roots) => {
            for (name, r) in &roots {
                let valid = valid_crate_name(name)
                    && valid_adr(&r.adr)
                    && r.features.iter().all(|f| valid_feature(f))
                    && r.note.trim() == r.note;
                if !valid {
                    return Err(format!("accepted an invalid root: {name} {r:?}"));
                }
            }
            let rendered = allowlist::render_roots(&roots);
            let back = allowlist::parse_roots(&rendered)
                .map_err(|e| format!("rendered roots do not parse: {e:?}"))?;
            if back != roots {
                return Err(format!("round trip changed roots: {roots:?} -> {back:?}"));
            }
            Ok(())
        }
        Err(errs) => lines_in_range(&errs, text.lines().count(), false),
    }
}

/// `deps/fuzz-required.txt`: accepted names are valid and unique, and one
/// name per line parses back to the same list.
pub fn fuzz_required(data: &[u8]) -> Result<(), String> {
    let text = String::from_utf8_lossy(data);
    match allowlist::parse_fuzz_required(&text) {
        Ok(names) => {
            let unique: BTreeSet<&String> = names.iter().collect();
            if unique.len() != names.len() || !names.iter().all(|n| valid_crate_name(n)) {
                return Err(format!("accepted invalid or duplicate names: {names:?}"));
            }
            let back = allowlist::parse_fuzz_required(&names.join("\n"))
                .map_err(|e| format!("rendered list does not parse: {e:?}"))?;
            if back != names {
                return Err(format!("round trip changed names: {names:?} -> {back:?}"));
            }
            Ok(())
        }
        Err(errs) => lines_in_range(&errs, text.lines().count(), false),
    }
}

/// `Cargo.lock`: accepted packages are well formed, and rendering then
/// parsing returns the same lockfile.
pub fn cargo_lock(data: &[u8]) -> Result<(), String> {
    let text = String::from_utf8_lossy(data);
    match lockfile::parse(&text) {
        Ok(lock) => {
            for p in &lock.packages {
                let valid = valid_crate_name(&p.name)
                    && valid_version(&p.version)
                    && p.checksum.as_deref().is_none_or(valid_checksum)
                    && (p.checksum.is_none() || p.source.is_some());
                if !valid {
                    return Err(format!("accepted an invalid package: {p:?}"));
                }
            }
            let rendered = lockfile::render(&lock);
            let back = lockfile::parse(&rendered)
                .map_err(|e| format!("rendered lockfile does not parse: {e:?}"))?;
            if back != lock {
                return Err(format!(
                    "round trip changed the lockfile: {lock:?} -> {back:?}"
                ));
            }
            Ok(())
        }
        Err(errs) => lines_in_range(&errs, text.split('\n').count(), true),
    }
}

/// `cargo metadata` output: accepted documents have consistent indices,
/// and the graph analysis runs on them without panicking.
pub fn cargo_metadata(data: &[u8]) -> Result<(), String> {
    let Ok(meta) = metadata::parse_metadata(data) else {
        return Ok(());
    };
    let n = meta.packages.len();
    for (i, node) in meta.nodes.iter().enumerate() {
        if node.pkg >= n || node.deps.iter().any(|d| d.pkg >= n) {
            return Err(format!("node {i} points outside the package list"));
        }
        if meta.node_of_pkg.get(&node.pkg) != Some(&i) {
            return Err(format!(
                "node_of_pkg does not map package {} to node {i}",
                node.pkg
            ));
        }
    }
    if meta.members.iter().any(|&m| m >= n) {
        return Err("a member points outside the package list".to_owned());
    }
    let g = Graph::new(&meta);
    let class = graph::classify(&meta, &g, Role::Runtime);
    if class.roles.keys().any(|&k| k >= meta.nodes.len()) {
        return Err("classification names a node that does not exist".to_owned());
    }
    let ctx = Context {
        label: "fuzz".to_owned(),
        platform: "all targets".to_owned(),
        linux: false,
        all_features: false,
        kind: ProjectKind::Workspace,
        meta: &meta,
    };
    let agg = graph::aggregate(&[ctx], &Default::default());
    if agg.usage.values().any(|u| u.role != Role::Platform) {
        return Err("a package reached only outside Linux has a Linux role".to_owned());
    }
    Ok(())
}
