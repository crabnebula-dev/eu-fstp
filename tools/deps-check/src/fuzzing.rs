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
                    && (valid_checksum(&e.checksum)
                        || crate::git_source::parse_pinned(&e.checksum).is_some())
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
                // ADR-001 A3: a pinned git source names one full commit twice.
                if let Some(src) = &p.source
                    && let Some(g) = crate::git_source::parse_pinned(src)
                {
                    let expected = format!("git+{}?rev={}#{}", g.url, g.commit, g.commit);
                    if !crate::git_source::valid_commit(g.commit) || expected != *src {
                        return Err(format!("accepted a malformed pinned git source: {src}"));
                    }
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

/// `package-lock.json` and `package.json` (ADR-003 amendment): accepted
/// lockfiles have format version 3 and valid package names, and the
/// manifest parser never panics.
pub fn npm_lock(data: &[u8]) -> Result<(), String> {
    let _ = crate::npm::parse_manifest(data);
    let text = String::from_utf8_lossy(data);
    let _ = crate::npm::parse_allowlist(&text);
    let Ok(lock) = crate::npm::parse_lock(data) else {
        return Ok(());
    };
    if !data
        .windows(b"lockfileVersion".len())
        .any(|w| w == b"lockfileVersion")
    {
        return Err("accepted a lockfile without lockfileVersion".to_owned());
    }
    for p in &lock.packages {
        if !crate::npm::valid_name(&p.name) || !p.key.starts_with("node_modules/") {
            return Err(format!("accepted an invalid package: {p:?}"));
        }
    }
    Ok(())
}

/// `deps/tier-b-confirmations.txt` (I-74, ADR-001 A5): accepted rows are
/// valid, every confirmation names a marked crate, and error line numbers
/// stay in range. The same input also feeds the `deps/funds-allowed.txt`
/// parser (I-16).
pub fn tier_b_confirmations(data: &[u8]) -> Result<(), String> {
    let text = String::from_utf8_lossy(data);
    if let Ok(names) = crate::funds::parse_funds_allowed(&text)
        && names.iter().any(|n| !valid_crate_name(n))
    {
        return Err(format!("accepted an invalid funds list: {names:?}"));
    }
    match crate::tier_b::parse(&text) {
        Ok(tier) => {
            for c in &tier.confirmations {
                let valid = valid_crate_name(&c.krate)
                    && valid_version(&c.version)
                    && crate::tier_b::valid_hash(&c.hash)
                    && crate::tier_b::valid_date(&c.date)
                    && !c.findings.is_empty()
                    && tier.markers.contains(&c.krate);
                if !valid {
                    return Err(format!("accepted an invalid confirmation: {c:?}"));
                }
            }
            if tier.markers.iter().any(|m| !valid_crate_name(m)) {
                return Err(format!("accepted an invalid marker: {:?}", tier.markers));
            }
            Ok(())
        }
        Err(errs) => lines_in_range(&errs, text.lines().count(), true),
    }
}

/// The literal prefixes the structured part of [`rust_tokens`] draws.
const LITERAL_PREFIXES: [&str; 6] = ["", "b", "c", "r", "br", "cr"];
/// The identifier placed after the drawn literal.
const PROBE: &str = "zz_probe";

/// The Rust source lexer of the M3 source scans (design section 2.4,
/// rules 5, 7 and 9). On the raw input: no panic, every lexeme is a slice
/// of the input, every line number is in range, and every identifier is
/// one. The edge, re-export and module readers run on the same lexemes.
/// Then the first byte draws a string literal form and the rest is its
/// body: the literal lexes as one string, and an identifier after it is
/// still seen.
pub fn rust_tokens(data: &[u8]) -> Result<(), String> {
    use crate::layering_m3::{self as m3, LexKind};

    let text = String::from_utf8_lossy(data);
    let lines = text.split('\n').count();
    let lexed = m3::lex(&text);
    let base = text.as_ptr() as usize;
    let end = base.saturating_add(text.len());
    for l in &lexed.lexemes {
        let at = l.s.as_ptr() as usize;
        if at < base || at.saturating_add(l.s.len()) > end {
            return Err(format!("lexeme {:?} is not a slice of the input", l.s));
        }
        if !(1..=lines).contains(&l.line) {
            return Err(format!(
                "lexeme {:?} on line {} outside 1..={lines}",
                l.s, l.line
            ));
        }
        let ident_ok =
            l.s.bytes()
                .next()
                .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
                && l.s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
        let punct_ok = l.s == "::" || (l.s.len() == 1 && l.s.bytes().all(|b| b.is_ascii_graphic()));
        match l.kind {
            LexKind::Ident if !ident_ok => return Err(format!("bad identifier {:?}", l.s)),
            LexKind::Punct if !punct_ok => return Err(format!("bad punctuation {:?}", l.s)),
            _ => {}
        }
    }
    let toks = m3::tokens(&text);
    for (line, _) in m3::edge_tls_paths(&toks) {
        if !(1..=lines).contains(&line) {
            return Err(format!("edge finding on line {line} outside 1..={lines}"));
        }
    }
    let _ = m3::aws_lc_reexports(&toks);
    let _ = m3::aws_lc_indirect_reexports(&[toks.as_slice()]);
    let refs = m3::module_refs(&lexed.lexemes, std::path::Path::new("src/lib.rs"));
    if refs
        .unresolved
        .iter()
        .any(|(l, _)| !(1..=lines).contains(l))
    {
        return Err("a module reference line is out of range".to_owned());
    }

    let Some((&sel, body)) = data.split_first() else {
        return Ok(());
    };
    let prefix = LITERAL_PREFIXES
        .get(
            usize::from(sel)
                .checked_rem(LITERAL_PREFIXES.len())
                .unwrap_or(0),
        )
        .copied()
        .unwrap_or("");
    let raw = prefix.ends_with('r');
    let hashes = if raw {
        "#".repeat(usize::from(
            sel.checked_div(6)
                .and_then(|x| x.checked_rem(4))
                .unwrap_or(0),
        ))
    } else {
        String::new()
    };
    let body: String = String::from_utf8_lossy(body)
        .chars()
        .filter(|&c| c != '"' && (raw || c != '\\'))
        .collect();
    let literal = format!("{prefix}{hashes}\"{body}\"{hashes} {PROBE}");
    let lexed = m3::lex(&literal);
    let kinds: Vec<(LexKind, &str)> = lexed.lexemes.iter().map(|l| (l.kind, l.s)).collect();
    if !lexed.closed || kinds != [(LexKind::Str, body.as_str()), (LexKind::Ident, PROBE)] {
        return Err(format!("{literal:?} lexes as {kinds:?}"));
    }
    Ok(())
}
