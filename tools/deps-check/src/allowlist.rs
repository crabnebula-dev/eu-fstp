//! The policy files under `deps/` and the comparison against the graph.
//!
//! `deps/allowlist.txt` has one entry per line, with fields separated by
//! whitespace:
//!
//! ```text
//! <name> <exact version> <sha256> <ADR ids, comma-separated> <role> <note>
//! ```
//!
//! The SHA-256 is the `.crate` checksum that every `Cargo.lock` must record
//! for the package. A git package records its pinned lockfile source
//! string `git+<URL>?rev=<commit>#<commit>` in that field instead
//! (ADR-001 A3, `git_source.rs`). The role is `runtime`, `build`, `test` or `platform`.
//! The note is the rest of the line and must not be empty. Lines that start
//! with `#` and blank lines are ignored.
//!
//! `deps/adr-roots.txt` names the crates that an ADR allowlists by name:
//! `<name> <ADR id> <features> [note]`. The features field is the exact,
//! comma-separated set of features cargo enables on the crate, or `-` for
//! none. Every other third-party package must sit in the resolved tree of a
//! root.
//!
//! `deps/fuzz-required.txt` lists the parser-bearing crates, one per line.

use std::collections::{BTreeMap, BTreeSet};

use crate::graph::{Aggregate, PkgKey, Role};
use crate::report::Finding;

/// Upper bound on the length of one policy-file line.
const MAX_LINE: usize = 1024;
/// Upper bound on the number of entries in one policy file.
const MAX_ENTRIES: usize = 10_000;
/// Upper bound on the features of one root.
const MAX_FEATURES: usize = 256;

/// One allowlist entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Entry {
    /// Crate name.
    pub(crate) name: String,
    /// Exact version.
    pub(crate) version: String,
    /// SHA-256 of the `.crate` file, 64 lowercase hex digits. For a git
    /// package it is the pinned lockfile source string (ADR-001 A3).
    pub(crate) checksum: String,
    /// ADR identifiers whose tree contains the crate.
    pub(crate) adrs: BTreeSet<String>,
    /// Highest role the crate may have.
    pub(crate) role: Role,
    /// Free-text justification.
    pub(crate) note: String,
}

/// One line of `deps/adr-roots.txt`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Root {
    /// The ADR that allowlists the crate by name.
    pub(crate) adr: String,
    /// The exact set of features cargo may enable on the crate.
    pub(crate) features: BTreeSet<String>,
    /// Free-text note, possibly empty.
    pub(crate) note: String,
}

/// A parse error with its 1-based line number, or 0 for the whole file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LineError {
    /// 1-based line number, or 0 when the error concerns the whole file.
    pub(crate) line: usize,
    /// What is wrong.
    pub(crate) message: String,
}

impl std::fmt::Display for LineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

/// Splits off the first whitespace-separated field.
fn next_field(s: &str) -> Option<(&str, &str)> {
    let s = s.trim_start();
    if s.is_empty() {
        return None;
    }
    let end = s.find(char::is_whitespace).unwrap_or(s.len());
    Some((s.get(..end)?, s.get(end..)?))
}

/// Content lines with their 1-based numbers, without comments and blanks.
fn content_lines(text: &str) -> impl Iterator<Item = (usize, &str)> {
    text.lines()
        .enumerate()
        .map(|(i, l)| (i.saturating_add(1), l))
        .filter(|(_, l)| {
            let t = l.trim();
            !t.is_empty() && !t.starts_with('#')
        })
}

/// Whether `s` is a valid crate name.
pub(crate) fn valid_crate_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        && s.starts_with(|c: char| c.is_ascii_alphabetic())
}

/// Whether `s` is an exact semantic version such as `1.2.3`, `1.0.0-rc.1`
/// or `0.11.1+wasi-snapshot-preview1`.
pub(crate) fn valid_version(s: &str) -> bool {
    let (core, rest) = match s.find(['-', '+']) {
        Some(i) => (s.get(..i).unwrap_or(""), s.get(i..).unwrap_or("")),
        None => (s, ""),
    };
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.len() <= 20 && p.chars().all(|c| c.is_ascii_digit()))
        && rest.len() <= 128
        && rest
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '+' | '.'))
}

/// Whether `s` is a SHA-256 checksum as cargo writes it: 64 lowercase hex digits.
pub(crate) fn valid_checksum(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Whether `s` is an ADR identifier such as `ADR-001`.
pub(crate) fn valid_adr(s: &str) -> bool {
    s.strip_prefix("ADR-")
        .is_some_and(|n| n.len() == 3 && n.chars().all(|c| c.is_ascii_digit()))
}

/// Whether `s` is a cargo feature name.
pub(crate) fn valid_feature(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '+' | '.'))
}

/// Parses `deps/allowlist.txt`.
pub(crate) fn parse_allowlist(text: &str) -> Result<Vec<Entry>, Vec<LineError>> {
    let mut entries: Vec<Entry> = Vec::new();
    let mut errors = Vec::new();
    let mut seen = BTreeSet::new();
    for (line, raw) in content_lines(text) {
        let err = |message: String| LineError { line, message };
        if raw.len() > MAX_LINE {
            errors.push(err(format!("longer than {MAX_LINE} bytes")));
            continue;
        }
        if entries.len() >= MAX_ENTRIES {
            errors.push(err(format!("more than {MAX_ENTRIES} entries")));
            break;
        }
        let Some((name, rest)) = next_field(raw) else {
            continue;
        };
        let Some((version, rest)) = next_field(rest) else {
            errors.push(err("missing version".into()));
            continue;
        };
        let Some((checksum, rest)) = next_field(rest) else {
            errors.push(err("missing checksum".into()));
            continue;
        };
        let Some((adrs, rest)) = next_field(rest) else {
            errors.push(err("missing ADR identifier".into()));
            continue;
        };
        let Some((role, rest)) = next_field(rest) else {
            errors.push(err("missing role".into()));
            continue;
        };
        let note = rest.trim();
        if !valid_crate_name(name) {
            errors.push(err(format!("invalid crate name `{name}`")));
            continue;
        }
        if !valid_version(version) {
            errors.push(err(format!(
                "`{version}` is not an exact version such as 1.2.3"
            )));
            continue;
        }
        if !valid_checksum(checksum) && crate::git_source::parse_pinned(checksum).is_none() {
            errors.push(err(format!(
                "`{checksum}` is not a SHA-256 checksum of 64 lowercase hex digits, \
                 nor a pinned git source git+<URL>?rev=<commit>#<commit> (ADR-001 A3)"
            )));
            continue;
        }
        let adr_set: BTreeSet<String> = adrs.split(',').map(str::to_owned).collect();
        if adr_set.iter().any(|a| !valid_adr(a)) {
            errors.push(err(format!(
                "`{adrs}` is not a comma-separated list of ADR identifiers such as ADR-001"
            )));
            continue;
        }
        let Some(role) = Role::parse(role) else {
            errors.push(err(format!(
                "role `{role}` is not one of runtime, build, test, platform"
            )));
            continue;
        };
        if note.is_empty() {
            errors.push(err("missing note".into()));
            continue;
        }
        if !seen.insert((name.to_owned(), version.to_owned())) {
            errors.push(err(format!("duplicate entry for {name} {version}")));
            continue;
        }
        entries.push(Entry {
            name: name.to_owned(),
            version: version.to_owned(),
            checksum: checksum.to_owned(),
            adrs: adr_set,
            role,
            note: note.to_owned(),
        });
    }
    if errors.is_empty() {
        Ok(entries)
    } else {
        Err(errors)
    }
}

/// Renders entries in the allowlist format, columns aligned.
pub(crate) fn render_entries(entries: &[Entry]) -> String {
    let width = |f: &dyn Fn(&Entry) -> usize| entries.iter().map(f).max().unwrap_or(0);
    let wn = width(&|e| e.name.len());
    let wv = width(&|e| e.version.len());
    let wa = width(&|e| adr_field(e).len());
    let mut out = String::new();
    for e in entries {
        out.push_str(&format!(
            "{:<wn$}  {:<wv$}  {}  {:<wa$}  {:<8}  {}\n",
            e.name,
            e.version,
            e.checksum,
            adr_field(e),
            e.role.label(),
            e.note
        ));
    }
    out
}

fn adr_field(e: &Entry) -> String {
    e.adrs.iter().cloned().collect::<Vec<_>>().join(",")
}

/// The features field of `deps/adr-roots.txt`: comma-separated, or `-`.
pub(crate) fn features_field(features: &BTreeSet<String>) -> String {
    if features.is_empty() {
        "-".to_owned()
    } else {
        features.iter().cloned().collect::<Vec<_>>().join(",")
    }
}

/// Parses `deps/adr-roots.txt` into a map from crate name to its root entry.
pub(crate) fn parse_roots(text: &str) -> Result<BTreeMap<String, Root>, Vec<LineError>> {
    let mut roots = BTreeMap::new();
    let mut errors = Vec::new();
    for (line, raw) in content_lines(text) {
        let err = |message: String| LineError { line, message };
        if raw.len() > MAX_LINE || roots.len() >= MAX_ENTRIES {
            errors.push(err("line too long or too many entries".into()));
            break;
        }
        let Some((name, rest)) = next_field(raw) else {
            continue;
        };
        let Some((adr, rest)) = next_field(rest) else {
            errors.push(err("missing ADR identifier".into()));
            continue;
        };
        let Some((features, note)) = next_field(rest) else {
            errors.push(err("missing features field (use `-` for none)".into()));
            continue;
        };
        let feature_set: BTreeSet<String> = if features == "-" {
            BTreeSet::new()
        } else {
            features.split(',').map(str::to_owned).collect()
        };
        if !valid_crate_name(name) {
            errors.push(err(format!("invalid crate name `{name}`")));
        } else if !valid_adr(adr) {
            errors.push(err(format!("`{adr}` is not an ADR identifier")));
        } else if feature_set.len() > MAX_FEATURES || feature_set.iter().any(|f| !valid_feature(f))
        {
            errors.push(err(format!(
                "`{features}` is not `-` or a comma-separated list of feature names"
            )));
        } else if roots
            .insert(
                name.to_owned(),
                Root {
                    adr: adr.to_owned(),
                    features: feature_set,
                    note: note.trim().to_owned(),
                },
            )
            .is_some()
        {
            errors.push(err(format!("duplicate root {name}")));
        }
    }
    if errors.is_empty() {
        Ok(roots)
    } else {
        Err(errors)
    }
}

/// Renders roots in the `deps/adr-roots.txt` format.
pub(crate) fn render_roots(roots: &BTreeMap<String, Root>) -> String {
    let mut out = String::new();
    for (name, r) in roots {
        let line = format!(
            "{name}  {}  {}  {}",
            r.adr,
            features_field(&r.features),
            r.note
        );
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

/// Parses `deps/fuzz-required.txt`.
pub(crate) fn parse_fuzz_required(text: &str) -> Result<Vec<String>, Vec<LineError>> {
    let mut names = Vec::new();
    let mut errors = Vec::new();
    for (line, raw) in content_lines(text) {
        let name = raw.trim();
        if raw.len() > MAX_LINE || names.len() >= MAX_ENTRIES {
            errors.push(LineError {
                line,
                message: "line too long or too many entries".into(),
            });
            break;
        }
        if !valid_crate_name(name) {
            errors.push(LineError {
                line,
                message: format!("invalid crate name `{name}`"),
            });
        } else if names.iter().any(|n| n == name) {
            errors.push(LineError {
                line,
                message: format!("duplicate crate {name}"),
            });
        } else {
            names.push(name.to_owned());
        }
    }
    if errors.is_empty() {
        Ok(names)
    } else {
        Err(errors)
    }
}

/// Compares the graph against the allowlist.
///
/// Errors: unlisted package, version mismatch, role escalation, a package
/// in the tree of an ADR its entry does not name. Warnings: stale entries,
/// entries whose role or ADR list is wider than the graph needs.
pub(crate) fn compare(agg: &Aggregate, entries: &[Entry]) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut matched = BTreeSet::new();
    for ((name, version), u) in &agg.usage {
        let same_name: Vec<&Entry> = entries.iter().filter(|e| &e.name == name).collect();
        let Some(entry) = same_name.iter().find(|e| &e.version == version) else {
            if same_name.is_empty() {
                out.push(Finding::error(
                    "unlisted",
                    format!(
                        "{name} {version} ({}) is not in deps/allowlist.txt",
                        u.role.label()
                    ),
                ));
            } else {
                let listed: Vec<&str> = same_name.iter().map(|e| e.version.as_str()).collect();
                out.push(Finding::error(
                    "version-mismatch",
                    format!(
                        "{name} resolves to {version}, but deps/allowlist.txt allows only {}",
                        listed.join(", ")
                    ),
                ));
            }
            continue;
        };
        matched.insert((name.clone(), version.clone()));
        if u.role > entry.role {
            out.push(Finding::error(
                "role-escalation",
                format!(
                    "{name} {version} is allowlisted as {} but reaches {} through {}",
                    entry.role.label(),
                    u.role.label(),
                    u.contexts
                        .iter()
                        .filter(|(_, r)| **r > entry.role)
                        .map(|(c, _)| c.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            ));
        } else if u.role < entry.role {
            out.push(Finding::warning(
                "role-narrower",
                format!(
                    "{name} {version} is allowlisted as {} but is only used as {}",
                    entry.role.label(),
                    u.role.label()
                ),
            ));
        }
        let missing: Vec<&String> = u.adrs.difference(&entry.adrs).collect();
        if !missing.is_empty() {
            out.push(Finding::error(
                "adr-not-listed",
                format!(
                    "{name} {version} is in the tree of {} but its entry names only {}",
                    missing
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                    adr_field(entry)
                ),
            ));
        }
        let extra: Vec<&String> = entry.adrs.difference(&u.adrs).collect();
        if !extra.is_empty() && !u.adrs.is_empty() {
            out.push(Finding::warning(
                "adr-wider",
                format!(
                    "{name} {version} names {} but is not in that tree any more",
                    extra
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(",")
                ),
            ));
        }
    }
    for e in entries {
        if !matched.contains(&(e.name.clone(), e.version.clone())) {
            out.push(Finding::warning(
                "stale-entry",
                format!(
                    "deps/allowlist.txt lists {} {}, which no build uses",
                    e.name, e.version
                ),
            ));
        }
    }
    out
}

/// Compares the features cargo enables on each ADR root with
/// `deps/adr-roots.txt` (ADR-001, ADR-002).
///
/// The enabled set is the union over every analysed context, so a feature
/// that only `--all-features` or another target enables still counts.
pub(crate) fn compare_root_features(
    agg: &Aggregate,
    roots: &BTreeMap<String, Root>,
) -> Vec<Finding> {
    let mut out = Vec::new();
    for (name, enabled) in &agg.root_features {
        let Some(root) = roots.get(name) else {
            continue;
        };
        if enabled == &root.features {
            continue;
        }
        let added: Vec<&str> = enabled
            .difference(&root.features)
            .map(String::as_str)
            .collect();
        let removed: Vec<&str> = root
            .features
            .difference(enabled)
            .map(String::as_str)
            .collect();
        let mut parts = Vec::new();
        if !added.is_empty() {
            parts.push(format!("enabled but not recorded: {}", added.join(",")));
        }
        if !removed.is_empty() {
            parts.push(format!("recorded but not enabled: {}", removed.join(",")));
        }
        out.push(Finding::error(
            "root-features",
            format!(
                "{name} ({}) features changed; {}. Record the reviewed set in \
                 deps/adr-roots.txt and the ADR",
                root.adr,
                parts.join("; ")
            ),
        ));
    }
    out
}

/// Builds allowlist entries from the graph, keeping notes from `previous`.
///
/// `checksums` maps each package to the checksum its lockfiles record. A
/// package without one gets a placeholder that does not parse, so the
/// generated file cannot be used unreviewed.
pub(crate) fn generate(
    agg: &Aggregate,
    previous: &[Entry],
    checksums: &BTreeMap<PkgKey, String>,
) -> Vec<Entry> {
    agg.usage
        .iter()
        .map(|((name, version), u)| {
            let note = previous
                .iter()
                .find(|e| &e.name == name && &e.version == version)
                .or_else(|| previous.iter().find(|e| &e.name == name))
                .map(|e| e.note.clone())
                .unwrap_or_else(|| {
                    let roots: Vec<&str> = u.roots.iter().map(String::as_str).collect();
                    if roots.iter().any(|r| r == name) {
                        "ADR root".to_owned()
                    } else {
                        format!("in the tree of {}", roots.join(", "))
                    }
                });
            Entry {
                name: name.clone(),
                version: version.clone(),
                checksum: checksums
                    .get(&(name.clone(), version.clone()))
                    .cloned()
                    .unwrap_or_else(|| "missing-checksum".to_owned()),
                adrs: u.adrs.clone(),
                role: u.role,
                note,
            }
        })
        .collect()
}

/// Checks that each ADR an entry names records the exact crate and version.
///
/// `adr_text` maps an ADR identifier to its file content, or to `None` when
/// no file exists. The record must contain `` `name version` ``.
pub(crate) fn check_adr_records(
    entries: &[Entry],
    adr_text: &BTreeMap<String, Option<String>>,
) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut missing_files = BTreeSet::new();
    for e in entries {
        let needle = format!("`{} {}`", e.name, e.version);
        for adr in &e.adrs {
            match adr_text.get(adr) {
                Some(Some(text)) => {
                    if !text.contains(&needle) {
                        out.push(Finding::error(
                            "adr-record-missing",
                            format!(
                                "{adr} does not record {needle}; add it to the ADR's resolved tree"
                            ),
                        ));
                    }
                }
                _ => {
                    if missing_files.insert(adr.clone()) {
                        out.push(Finding::error(
                            "adr-missing",
                            format!("no file docs/adr/{adr}-*.md for {adr}"),
                        ));
                    }
                }
            }
        }
    }
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::graph::Usage;
    use crate::report::Severity;
    use fstp_prop::{Gen, prop_assert, prop_assert_eq};

    /// A syntactically valid checksum for fixtures. It is not the real
    /// checksum of any crate.
    pub(crate) const SUM_A: &str =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    /// A second fixture checksum, different from [`SUM_A`].
    pub(crate) const SUM_B: &str =
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn usage(role: Role, adrs: &[&str]) -> Usage {
        Usage {
            role,
            linux: role != Role::Platform,
            adrs: adrs.iter().map(|s| (*s).to_owned()).collect(),
            roots: BTreeSet::new(),
            contexts: BTreeMap::from([("workspace".to_owned(), role)]),
            platforms: BTreeSet::new(),
        }
    }

    fn agg(items: &[(&str, &str, Role, &[&str])]) -> Aggregate {
        let mut a = Aggregate::default();
        for (n, v, r, adrs) in items {
            a.usage
                .insert(((*n).to_owned(), (*v).to_owned()), usage(*r, adrs));
        }
        a
    }

    fn sample() -> String {
        format!(
            "\
# comment
tokio     1.54.1   {SUM_A}  ADR-002          runtime   async runtime
libc      0.2.191  {SUM_A}  ADR-001,ADR-002  runtime   tokio and cc tree
cc        1.10.0   {SUM_A}  ADR-001          build     aws-lc-sys build script
arbitrary 1.5.0    {SUM_A}  ADR-003          test      libfuzzer-sys input type

old       1.0.0    {SUM_A}  ADR-001          runtime   no longer used
windows-sys 0.61.2 {SUM_B}  ADR-002          platform  tokio on Windows
"
        )
    }

    #[test]
    fn parses_sample() {
        let e = parse_allowlist(&sample()).unwrap();
        assert_eq!(e.len(), 6);
        assert_eq!(e[1].name, "libc");
        assert_eq!(
            e[1].adrs,
            BTreeSet::from(["ADR-001".to_owned(), "ADR-002".to_owned()])
        );
        assert_eq!(e[2].role, Role::Build);
        assert_eq!(e[3].note, "libfuzzer-sys input type");
        assert_eq!(e[5].role, Role::Platform);
        assert_eq!(e[5].checksum, SUM_B);
    }

    #[test]
    fn reports_every_bad_line() {
        // `ADR-two` stands for a malformed identifier. It deliberately has no
        // digits, so it cannot be read as a real ADR number.
        let text = format!(
            "\
tokio 1.54 {SUM_A} ADR-002 runtime short version
tokio 1.54.1 {SUM_A} ADR-two runtime bad adr
tokio 1.54.1 {SUM_A} ADR-002 shipped bad role
tokio 1.54.1 {SUM_A} ADR-002 runtime
-bad 1.0.0 {SUM_A} ADR-001 runtime bad name
tokio 1.54.1 {SUM_A} ADR-002 runtime ok
tokio 1.54.1 {SUM_A} ADR-002 runtime duplicate
tokio
tokio 1.54.1 ABCD ADR-002 runtime bad checksum
tokio 1.54.1 ADR-002 runtime missing checksum
"
        );
        let errs = parse_allowlist(&text).unwrap_err();
        let lines: Vec<usize> = errs.iter().map(|e| e.line).collect();
        assert_eq!(lines, vec![1, 2, 3, 4, 5, 7, 8, 9, 10]);
        assert!(errs[3].message.contains("missing note"));
        assert!(errs[5].message.contains("duplicate"));
        assert!(errs[7].message.contains("SHA-256"));
        assert!(errs[8].message.contains("SHA-256"));
    }

    #[test]
    fn version_and_checksum_syntax() {
        for ok in [
            "1.2.3",
            "0.0.0",
            "1.0.0-rc.1",
            "0.11.1+wasi-snapshot-preview1",
        ] {
            assert!(valid_version(ok), "{ok}");
        }
        for bad in [
            "", "1", "1.2", "1.2.3.4", "^1.2.3", "1.2.x", "=1.2.3", "1..3",
        ] {
            assert!(!valid_version(bad), "{bad}");
        }
        assert!(valid_checksum(SUM_A));
        assert!(!valid_checksum(&SUM_A.to_uppercase()));
        assert!(!valid_checksum(&SUM_A[1..]));
        assert!(!valid_checksum(&format!("{}g", &SUM_A[1..])));
    }

    /// TH-15: unlisted packages, version drift and role escalation fail;
    /// stale entries only warn.
    #[test]
    fn th15_compare_classifies_drift() {
        let entries = parse_allowlist(&sample()).unwrap();
        let a = agg(&[
            ("tokio", "1.54.2", Role::Runtime, &["ADR-002"]),
            ("libc", "0.2.191", Role::Runtime, &["ADR-001", "ADR-002"]),
            ("cc", "1.10.0", Role::Runtime, &["ADR-001"]),
            ("arbitrary", "1.5.0", Role::Test, &["ADR-003", "ADR-001"]),
            ("newcomer", "0.1.0", Role::Build, &["ADR-001"]),
            ("windows-sys", "0.61.2", Role::Platform, &["ADR-002"]),
        ]);
        let f = compare(&a, &entries);
        let codes: Vec<(&str, Severity)> = f.iter().map(|f| (f.code, f.severity)).collect();
        assert!(
            codes.contains(&("version-mismatch", Severity::Error)),
            "{f:?}"
        );
        assert!(
            codes.contains(&("role-escalation", Severity::Error)),
            "{f:?}"
        );
        assert!(
            codes.contains(&("adr-not-listed", Severity::Error)),
            "{f:?}"
        );
        assert!(codes.contains(&("unlisted", Severity::Error)), "{f:?}");
        assert!(codes.contains(&("stale-entry", Severity::Warning)), "{f:?}");
        let stale: Vec<_> = f.iter().filter(|f| f.code == "stale-entry").collect();
        // tokio 1.54.1 and old 1.0.0 are both unused.
        assert_eq!(stale.len(), 2, "{stale:?}");
        let esc = f.iter().find(|f| f.code == "role-escalation").unwrap();
        assert!(
            esc.message
                .contains("cc 1.10.0 is allowlisted as build but reaches runtime")
        );
    }

    /// TH-15: a test-only crate that reaches runtime fails the gate.
    #[test]
    fn th15_test_only_crate_reaching_runtime_fails() {
        let entries = parse_allowlist(&format!(
            "arbitrary 1.5.0 {SUM_A} ADR-003 test fuzz input\n"
        ))
        .unwrap();
        let a = agg(&[("arbitrary", "1.5.0", Role::Runtime, &["ADR-003"])]);
        let f = compare(&a, &entries);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].code, "role-escalation");
        assert_eq!(f[0].severity, Severity::Error);
    }

    /// TH-15, P5: a crate allowlisted for other platforms only fails once a
    /// Linux build reaches it.
    #[test]
    fn th15_platform_crate_built_on_linux_fails() {
        let entries = parse_allowlist(&format!(
            "windows-sys 0.61.2 {SUM_B} ADR-002 platform tokio on Windows\n"
        ))
        .unwrap();
        let a = agg(&[("windows-sys", "0.61.2", Role::Test, &["ADR-002"])]);
        let f = compare(&a, &entries);
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].code, "role-escalation");
        let a = agg(&[("windows-sys", "0.61.2", Role::Platform, &["ADR-002"])]);
        assert!(compare(&a, &entries).is_empty());
    }

    #[test]
    fn narrower_role_and_wider_adr_warn() {
        let entries =
            parse_allowlist(&format!("cc 1.10.0 {SUM_A} ADR-001,ADR-003 runtime x\n")).unwrap();
        let a = agg(&[("cc", "1.10.0", Role::Build, &["ADR-001"])]);
        let f = compare(&a, &entries);
        assert!(f.iter().all(|f| f.severity == Severity::Warning), "{f:?}");
        assert_eq!(f.len(), 2);
    }

    #[test]
    fn roots_and_fuzz_required_parse() {
        let r = parse_roots("# x\ntokio ADR-002 net,rt runtime\nrustls ADR-001 -\n").unwrap();
        let tokio = r.get("tokio").unwrap();
        assert_eq!(tokio.adr, "ADR-002");
        assert_eq!(
            tokio.features,
            BTreeSet::from(["net".to_owned(), "rt".to_owned()])
        );
        assert_eq!(tokio.note, "runtime");
        assert!(r.get("rustls").unwrap().features.is_empty());
        assert!(parse_roots("tokio\n").is_err());
        assert!(parse_roots("tokio ADR-002\n").is_err());
        assert!(parse_roots("tokio ADR-002 net,,rt\n").is_err());
        assert!(parse_roots("tokio ADR-002 -\ntokio ADR-001 -\n").is_err());
        let f = parse_fuzz_required("fstp-json\n\n# c\nfstp-http\n").unwrap();
        assert_eq!(f, vec!["fstp-json".to_owned(), "fstp-http".to_owned()]);
        assert!(parse_fuzz_required("fstp json\n").is_err());
        assert!(parse_fuzz_required("a\na\n").is_err());
    }

    /// Regression for review finding feature-changes-unchecked (ADR-001,
    /// ADR-002): enabling `tls12` on rustls or another tokio feature changes
    /// what is compiled without adding a package. The gate must fail.
    #[test]
    fn review_feature_changes_unchecked() {
        let roots = parse_roots(
            "rustls ADR-001 aws-lc-rs,aws_lc_rs,prefer-post-quantum,std\n\
             tokio ADR-002 libc,mio,net,rt,rt-multi-thread,socket2,time,windows-sys\n",
        )
        .unwrap();
        let mut a = Aggregate::default();
        let set = |s: &str| s.split(',').map(str::to_owned).collect::<BTreeSet<_>>();
        a.root_features.insert(
            "rustls".into(),
            set("aws-lc-rs,aws_lc_rs,prefer-post-quantum,std"),
        );
        a.root_features.insert(
            "tokio".into(),
            set("libc,mio,net,rt,rt-multi-thread,socket2,time,windows-sys"),
        );
        assert!(compare_root_features(&a, &roots).is_empty());
        a.root_features.insert(
            "rustls".into(),
            set("aws-lc-rs,aws_lc_rs,prefer-post-quantum,std,tls12"),
        );
        a.root_features.insert(
            "tokio".into(),
            set("fs,libc,mio,net,rt,rt-multi-thread,socket2,sync,time,windows-sys"),
        );
        let f = compare_root_features(&a, &roots);
        assert_eq!(f.len(), 2, "{f:?}");
        assert!(f.iter().all(|f| f.severity == Severity::Error));
        assert!(
            f[0].message.contains("enabled but not recorded: tls12"),
            "{f:?}"
        );
        assert!(f[1].message.contains("fs,sync"), "{f:?}");
    }

    #[test]
    fn adr_record_check() {
        let entries = parse_allowlist(&format!(
            "tokio 1.54.1 {SUM_A} ADR-002 runtime x\nlibc 0.2.191 {SUM_A} ADR-001,ADR-002 runtime y\n"
        ))
        .unwrap();
        let mut texts = BTreeMap::new();
        texts.insert(
            "ADR-002".to_owned(),
            Some("| tree | `tokio 1.54.1`, `libc 0.2.191` |".to_owned()),
        );
        let f = check_adr_records(&entries, &texts);
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].code, "adr-missing");
        texts.insert("ADR-001".to_owned(), Some("`libc 0.2.1910`".to_owned()));
        let f = check_adr_records(&entries, &texts);
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].code, "adr-record-missing");
    }

    fn gen_entry(g: &mut Gen) -> Entry {
        let alpha: Vec<char> = ('a'..='z').collect();
        let tail: Vec<char> = ('a'..='z').chain('0'..='9').chain(['-', '_']).collect();
        let hex: Vec<char> = ('0'..='9').chain('a'..='f').collect();
        let mut name = String::from(*g.pick(&alpha));
        for _ in 0..g.usize_in(0..=12) {
            name.push(*g.pick(&tail));
        }
        let version = format!("{}.{}.{}", g.u32(), g.u16(), g.u8());
        let checksum: String = (0..64).map(|_| *g.pick(&hex)).collect();
        // Real ADR identifiers only, so no invented identifier is generated.
        let adrs: BTreeSet<String> = g
            .vec(1..=3, |g| {
                (*g.pick(&["ADR-001", "ADR-002", "ADR-003", "ADR-004", "ADR-005"])).to_owned()
            })
            .into_iter()
            .collect();
        let role = *g.pick(&Role::ALL);
        let mut note = g.ascii_string(1..=40).replace(['\n', '\r'], " ");
        note = note.trim().to_owned();
        if note.is_empty() {
            note = "n".to_owned();
        }
        Entry {
            name,
            version,
            checksum,
            adrs,
            role,
            note,
        }
    }

    /// TH-15: rendering then parsing the allowlist returns the same entries.
    #[test]
    fn th15_allowlist_round_trip() {
        fstp_prop::check("th15_allowlist_round_trip", |g| {
            let mut entries = g.vec(0..=8, gen_entry);
            let mut seen = BTreeSet::new();
            entries.retain(|e| seen.insert((e.name.clone(), e.version.clone())));
            let text = render_entries(&entries);
            g.note("text", &text);
            let back = parse_allowlist(&text).map_err(|e| format!("{e:?}"))?;
            prop_assert_eq!(back, entries);
            Ok(())
        });
    }

    /// TH-15: the policy-file parsers return errors, never panic, on any input.
    #[test]
    fn th15_policy_parsers_total() {
        fstp_prop::check("th15_policy_parsers_total", |g| {
            let pieces = [
                "tokio", " ", "1.54.1", "ADR-002", ",", "runtime", "test", "\n", "#", "\t", "é",
                "\r\n", "-", "+", ".", "ADR-", SUM_A, "platform", "net,rt",
            ];
            let mut text = String::new();
            for _ in 0..g.usize_in(0..=40) {
                if g.bool() {
                    text.push_str(g.pick(&pieces));
                } else {
                    text.push_str(&g.string(0..=4));
                }
            }
            let a = parse_allowlist(&text);
            if let Ok(entries) = &a {
                prop_assert!(entries.iter().all(|e| !e.note.is_empty()));
            }
            if let Ok(roots) = parse_roots(&text) {
                let back = parse_roots(&render_roots(&roots)).map_err(|e| format!("{e:?}"))?;
                prop_assert_eq!(back, roots);
            }
            let _ = parse_fuzz_required(&text);
            Ok(())
        });
    }
}
