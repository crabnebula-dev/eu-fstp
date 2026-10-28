//! The Tier B release gate (I-74, R-CR-02, ADR-001 "Release gate" and A5,
//! `docs/handoff/m3-design.md` section 2.6).
//!
//! `deps/tier-b-confirmations.txt` names each Tier B crate and mirrors the
//! confirmation table of ADR-001, one entry per line:
//!
//! ```text
//! tier-b <crate>
//! confirmed <crate> <version> <source hash> <YYYY-MM-DD> <findings reference>
//! ```
//!
//! The gate reads the resolved tree of each shipped `[[bin]]` target: the
//! normal and build dependencies of its package, transitively, in every
//! Linux context of the main workspace. Every Tier B package there needs a
//! confirmation for its exact version and source hash. The source hash of
//! a crates.io package is the `.crate` SHA-256 that `deps/allowlist.txt`
//! pins. For a git package it is the full commit id of its allowlist
//! source string (ADR-001 A3).
//!
//! A package is Tier B when it has a marker, or when its git source names
//! the repository URL of a marked crate, at any commit. ADR-001 A3 lets
//! further packages from moduletto's repository onto the allowlist, each
//! pinned to a full commit of its own. Such a package needs its own marker
//! before a confirmation row can name it, so it never ships in a release
//! unconfirmed.
//!
//! `deps-check --release` fails without a matching confirmation. A
//! development build reports it as a warning and passes, since Tier B use
//! in development is allowed. A malformed mirror line fails every build,
//! so a typo cannot hide a confirmation. The test-only crates never ship,
//! so their binaries are not read.

use std::collections::{BTreeMap, BTreeSet};

use crate::allowlist::{Entry, LineError, valid_checksum, valid_crate_name, valid_version};
use crate::git_source;
use crate::graph::Context;
use crate::layering::{SHIPPED, members, reach};
use crate::layering_m3::{SCANNER, TEST_ONLY};
use crate::report::Finding;

/// The mirror file.
pub(crate) const MIRROR: &str = "deps/tier-b-confirmations.txt";
/// Upper bound on the length of one line.
const MAX_LINE: usize = 1024;
/// Upper bound on the number of entries.
const MAX_ENTRIES: usize = 10_000;

/// One confirmation row.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Confirmation {
    /// Crate name.
    pub(crate) krate: String,
    /// Exact version.
    pub(crate) version: String,
    /// Source hash: 64 lowercase hex digits, or a 40-digit git commit.
    pub(crate) hash: String,
    /// Confirmation date, `YYYY-MM-DD`.
    pub(crate) date: String,
    /// Findings reference, the rest of the line.
    pub(crate) findings: String,
}

/// The parsed mirror.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct TierB {
    /// The Tier B crates.
    pub(crate) markers: BTreeSet<String>,
    /// The confirmations.
    pub(crate) confirmations: Vec<Confirmation>,
}

/// Whether `s` is a source hash: a `.crate` SHA-256 or a full git commit
/// id, in lowercase hex.
pub(crate) fn valid_hash(s: &str) -> bool {
    valid_checksum(s) || git_source::valid_commit(s)
}

/// Whether `s` is a calendar date `YYYY-MM-DD`.
pub(crate) fn valid_date(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    let [y, m, d] = parts.as_slice() else {
        return false;
    };
    let digits = |p: &str, n: usize| p.len() == n && p.bytes().all(|b| b.is_ascii_digit());
    if !(digits(y, 4) && digits(m, 2) && digits(d, 2)) {
        return false;
    }
    let (Ok(year), Ok(month), Ok(day)) = (y.parse::<u32>(), m.parse::<u32>(), d.parse::<u32>())
    else {
        return false;
    };
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=days).contains(&day)
}

/// Parses the mirror.
pub(crate) fn parse(text: &str) -> Result<TierB, Vec<LineError>> {
    let mut out = TierB::default();
    let mut errors = Vec::new();
    let mut seen = BTreeSet::new();
    let mut entries = 0usize;
    for (i, raw) in text.lines().enumerate() {
        let line = i.saturating_add(1);
        let t = raw.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let err = |message: String| LineError { line, message };
        if raw.len() > MAX_LINE {
            errors.push(err(format!("longer than {MAX_LINE} bytes")));
            continue;
        }
        entries = entries.saturating_add(1);
        if entries > MAX_ENTRIES {
            errors.push(err(format!("more than {MAX_ENTRIES} entries")));
            break;
        }
        let fields: Vec<&str> = t.split_whitespace().collect();
        match fields.as_slice() {
            ["tier-b", name] => {
                if !valid_crate_name(name) {
                    errors.push(err(format!("invalid crate name `{name}`")));
                } else if !out.markers.insert((*name).to_owned()) {
                    errors.push(err(format!("duplicate marker for {name}")));
                }
            }
            ["tier-b", ..] => errors.push(err(
                "a marker is `tier-b <crate>`, with exactly one crate name".to_owned(),
            )),
            ["confirmed", name, version, hash, date, findings @ ..] if !findings.is_empty() => {
                if !valid_crate_name(name) {
                    errors.push(err(format!("invalid crate name `{name}`")));
                } else if !valid_version(version) {
                    errors.push(err(format!("`{version}` is not an exact version")));
                } else if !valid_hash(hash) {
                    errors.push(err(format!(
                        "`{hash}` is not a source hash: 64 lowercase hex digits, or a full git commit id"
                    )));
                } else if !valid_date(date) {
                    errors.push(err(format!("`{date}` is not a date YYYY-MM-DD")));
                } else if !seen.insert(((*name).to_owned(), (*version).to_owned(), (*hash).to_owned())) {
                    errors.push(err(format!("duplicate confirmation for {name} {version}")));
                } else {
                    out.confirmations.push(Confirmation {
                        krate: (*name).to_owned(),
                        version: (*version).to_owned(),
                        hash: (*hash).to_owned(),
                        date: (*date).to_owned(),
                        findings: findings.join(" "),
                    });
                }
            }
            ["confirmed", ..] => errors.push(err(
                "a confirmation is `confirmed <crate> <version> <source hash> <YYYY-MM-DD> <findings reference>`"
                    .to_owned(),
            )),
            [other, ..] => errors.push(err(format!(
                "unknown entry `{other}`; expected `tier-b` or `confirmed`"
            ))),
            [] => {}
        }
    }
    for c in &out.confirmations {
        if !out.markers.contains(&c.krate) {
            errors.push(LineError {
                line: 0,
                message: format!(
                    "the confirmation for {} {} names a crate without a `tier-b` marker",
                    c.krate, c.version
                ),
            });
        }
    }
    if errors.is_empty() {
        Ok(out)
    } else {
        Err(errors)
    }
}

/// The source hash a confirmation must carry for an allowlisted package:
/// the `.crate` SHA-256, or the commit of a git source string.
fn expected_hash(entries: &[Entry], name: &str, version: &str) -> Option<String> {
    let entry = entries
        .iter()
        .find(|e| e.name == name && e.version == version)?;
    if valid_checksum(&entry.checksum) {
        Some(entry.checksum.clone())
    } else {
        git_source::parse_pinned(&entry.checksum).map(|g| g.commit.to_owned())
    }
}

/// A Tier B package in a shipped binary's tree.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Shipped {
    name: String,
    version: String,
}

/// Runs the gate over the main workspace contexts. `tier` is the parsed
/// mirror, or `None` when it is missing or malformed.
pub(crate) fn check(
    contexts: &[&Context<'_>],
    entries: &[Entry],
    tier: Option<&TierB>,
    release: bool,
) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some(tier) = tier else {
        return out;
    };
    // ADR-001 A3: git_source admits further packages from a Tier B crate's
    // git repository, at any pinned commit. Each package from that
    // repository is Tier B too, with or without a marker of its own. The
    // key is the repository URL, not the whole source string, so a sibling
    // pinned at another commit is caught as well.
    let mut repos: BTreeSet<String> = entries
        .iter()
        .filter(|e| tier.markers.contains(&e.name))
        .filter_map(|e| git_source::repo_url(&e.checksum))
        .map(str::to_owned)
        .collect();
    for c in contexts.iter().filter(|c| c.linux) {
        repos.extend(
            c.meta
                .packages
                .iter()
                .filter(|p| tier.markers.contains(&p.name))
                .filter_map(|p| p.source.as_deref())
                .filter_map(git_source::repo_url)
                .map(str::to_owned),
        );
    }
    let is_tier_b = |p: &crate::metadata::Package| {
        tier.markers.contains(&p.name)
            || p.source
                .as_deref()
                .and_then(git_source::repo_url)
                .is_some_and(|u| repos.contains(u))
    };
    // Tier B package -> the binaries that ship it.
    let mut shipped: BTreeMap<Shipped, BTreeSet<String>> = BTreeMap::new();
    for c in contexts.iter().filter(|c| c.linux) {
        let meta = c.meta;
        for (&krate, &start) in &members(meta) {
            if TEST_ONLY.contains(&krate) || krate == SCANNER {
                continue;
            }
            let Some(pkg) = meta.packages.get(start) else {
                continue;
            };
            let bins: Vec<&str> = pkg
                .targets
                .iter()
                .filter(|t| t.kinds.iter().any(|k| k == "bin"))
                .map(|t| t.name.as_str())
                .collect();
            if bins.is_empty() {
                continue;
            }
            let parent = reach(meta, start, &SHIPPED);
            for &i in parent.keys() {
                let Some(p) = meta.packages.get(i) else {
                    continue;
                };
                if is_tier_b(p) {
                    let slot = shipped
                        .entry(Shipped {
                            name: p.name.clone(),
                            version: p.version.clone(),
                        })
                        .or_default();
                    for b in &bins {
                        slot.insert(format!("{krate}/{b}"));
                    }
                }
            }
        }
    }
    for (s, bins) in &shipped {
        let hash = expected_hash(entries, &s.name, &s.version);
        let confirmed = hash.as_ref().is_some_and(|h| {
            tier.confirmations
                .iter()
                .any(|c| c.krate == s.name && c.version == s.version && &c.hash == h)
        });
        if confirmed {
            continue;
        }
        let bins: Vec<&str> = bins.iter().map(String::as_str).collect();
        let message = format!(
            "Tier B crate {} {} (source hash {}) ships in {} without a release confirmation in {MIRROR} (I-74, ADR-001 A5){}",
            s.name,
            s.version,
            hash.as_deref().unwrap_or("unknown: no allowlist entry"),
            bins.join(", "),
            if release {
                ""
            } else {
                "; development builds may use it"
            }
        );
        out.push(if release {
            Finding::error("tier-b-unconfirmed", message)
        } else {
            Finding::warning("tier-b-unconfirmed", message)
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUM: &str = "e13084392c5e4bc371903e2935a5eaeed24905a7511356b883835e18a78f6879";

    /// I-74, ADR-001 A5: the mirror parses markers and confirmation rows.
    #[test]
    fn i74_mirror_parses_markers_and_rows() {
        let text = format!(
            "# c\ntier-b zeroize\nconfirmed zeroize 1.9.1 {SUM} 2026-10-28 MYTHOS-0 part 2\n"
        );
        let t = parse(&text).unwrap_or_default();
        assert!(t.markers.contains("zeroize"));
        assert_eq!(t.confirmations.len(), 1);
        assert_eq!(
            t.confirmations.first().map(|c| c.findings.as_str()),
            Some("MYTHOS-0 part 2")
        );
    }

    /// I-74, ADR-001 A5: malformed rows and unmarked confirmations fail.
    #[test]
    fn i74_mirror_refuses_malformed_rows() {
        for bad in [
            "tier-b\n".to_owned(),
            "tier-b a b\n".to_owned(),
            "approved zeroize 1.9.1\n".to_owned(),
            format!("tier-b zeroize\nconfirmed zeroize 1.9.1 {SUM} 2026-02-30 M\n"),
            format!("tier-b zeroize\nconfirmed zeroize 1.9 {SUM} 2026-10-28 M\n"),
            "tier-b zeroize\nconfirmed zeroize 1.9.1 abc 2026-10-28 M\n".to_owned(),
            format!("confirmed zeroize 1.9.1 {SUM} 2026-10-28 M\n"),
            "tier-b x\ntier-b x\n".to_owned(),
        ] {
            assert!(parse(&bad).is_err(), "accepted {bad:?}");
        }
    }

    const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

    fn source() -> String {
        format!("git+https://example.org/moduletto.git?rev={COMMIT}#{COMMIT}")
    }

    /// A workspace whose binary `app` depends on `moduletto` and on its
    /// sibling `moduletto-pq`, both from one git source.
    fn sibling_meta() -> crate::metadata::Metadata {
        use crate::metadata::{DepKind, Metadata, Node, NodeDep, Package, Target};
        let mut m = Metadata::default();
        for (i, name) in ["app", "moduletto", "moduletto-pq"].iter().enumerate() {
            let member = i == 0;
            m.packages.push(Package {
                id: (*name).into(),
                name: (*name).into(),
                version: if member { "0.1.0" } else { "0.3.0" }.into(),
                source: (!member).then(source),
                manifest_path: format!("/repo/{name}/Cargo.toml"),
                features: Default::default(),
                dependencies: vec![],
                targets: if member {
                    vec![Target {
                        name: "app".into(),
                        kinds: vec!["bin".into()],
                        src_path: "/repo/app/src/main.rs".into(),
                    }]
                } else {
                    vec![]
                },
                cargo_fuzz: false,
            });
            let deps = if member {
                vec![1, 2]
                    .into_iter()
                    .map(|pkg| NodeDep {
                        pkg,
                        kinds: vec![DepKind::Normal],
                    })
                    .collect()
            } else {
                vec![]
            };
            m.nodes.push(Node {
                pkg: i,
                deps,
                features: vec![],
            });
            m.node_of_pkg.insert(i, i);
        }
        m.members.push(0);
        m
    }

    fn entry(name: &str) -> Entry {
        Entry {
            name: name.into(),
            version: "0.3.0".into(),
            checksum: source(),
            adrs: BTreeSet::from(["ADR-001".to_owned()]),
            role: crate::graph::Role::Runtime,
            note: "Tier B, git source".into(),
        }
    }

    /// I-74, ADR-001 A3 and A5: a package from the git source of a Tier B
    /// crate is Tier B, even without its own marker. With moduletto
    /// confirmed, its unmarked sibling still fails the release gate, and a
    /// development build reports it.
    #[test]
    fn i74_release_gate_treats_a_package_from_a_tier_b_git_source_as_tier_b() {
        let meta = sibling_meta();
        let ctx = Context {
            label: "workspace".into(),
            platform: "x86_64-unknown-linux-gnu".into(),
            linux: true,
            all_features: false,
            kind: crate::graph::ProjectKind::Workspace,
            meta: &meta,
        };
        let text =
            format!("tier-b moduletto\nconfirmed moduletto 0.3.0 {COMMIT} 2026-10-28 MYTHOS-0\n");
        let tier = parse(&text).unwrap_or_default();
        let entries = [entry("moduletto"), entry("moduletto-pq")];
        let release = check(&[&ctx], &entries, Some(&tier), true);
        let errors: Vec<&Finding> = release
            .iter()
            .filter(|f| f.severity == crate::report::Severity::Error)
            .collect();
        assert_eq!(errors.len(), 1, "{release:?}");
        assert!(
            errors
                .iter()
                .all(|f| f.message.contains("moduletto-pq 0.3.0")),
            "{release:?}"
        );
        let dev = check(&[&ctx], &entries, Some(&tier), false);
        assert!(
            dev.iter()
                .any(|f| f.severity == crate::report::Severity::Warning
                    && f.message.contains("moduletto-pq 0.3.0")),
            "{dev:?}"
        );
    }

    #[test]
    fn dates_are_calendar_dates() {
        assert!(valid_date("2024-02-29"));
        assert!(!valid_date("2026-02-29"));
        assert!(!valid_date("2026-13-01"));
        assert!(!valid_date("28.10.2026"));
        assert!(!valid_date("2026-1-01"));
    }
}

#[cfg(test)]
mod review_tests {
    use super::*;
    use crate::metadata::{DepKind, Metadata, Node, NodeDep, Package, Target};

    const A: &str = "0123456789abcdef0123456789abcdef01234567";
    const B: &str = "89abcdef0123456789abcdef0123456789abcdef";

    fn src(commit: &str) -> String {
        format!("git+https://example.org/moduletto.git?rev={commit}#{commit}")
    }

    /// Review finding tier-b-source-string (I-74, ADR-001 A3 and A5).
    /// git_source admits a package from moduletto's recorded repository URL
    /// at any pinned commit with its own allowlist entry. The release gate
    /// treats a package as Tier B only when its whole source string equals a
    /// marked crate's. A sibling from the same repository at another commit
    /// then ships in a release build without a confirmation.
    #[test]
    fn review_i74_release_gate_sibling_at_another_commit_is_tier_b() {
        let mut m = Metadata::default();
        let pkgs = [
            ("app", None),
            ("moduletto", Some(src(A))),
            ("moduletto-pq", Some(src(B))),
        ];
        for (i, (name, source)) in pkgs.iter().enumerate() {
            let member = i == 0;
            m.packages.push(Package {
                id: (*name).into(),
                name: (*name).into(),
                version: if member { "0.1.0" } else { "0.3.0" }.into(),
                source: source.clone(),
                manifest_path: format!("/repo/{name}/Cargo.toml"),
                features: Default::default(),
                dependencies: vec![],
                targets: if member {
                    vec![Target {
                        name: "app".into(),
                        kinds: vec!["bin".into()],
                        src_path: "/repo/app/src/main.rs".into(),
                    }]
                } else {
                    vec![]
                },
                cargo_fuzz: false,
            });
            let deps = if member {
                [1, 2]
                    .into_iter()
                    .map(|pkg| NodeDep {
                        pkg,
                        kinds: vec![DepKind::Normal],
                    })
                    .collect()
            } else {
                vec![]
            };
            m.nodes.push(Node {
                pkg: i,
                deps,
                features: vec![],
            });
            m.node_of_pkg.insert(i, i);
        }
        m.members.push(0);
        let ctx = Context {
            label: "workspace".into(),
            platform: "x86_64-unknown-linux-gnu".into(),
            linux: true,
            all_features: false,
            kind: crate::graph::ProjectKind::Workspace,
            meta: &m,
        };
        let entry = |name: &str, commit: &str| Entry {
            name: name.into(),
            version: "0.3.0".into(),
            checksum: src(commit),
            adrs: BTreeSet::from(["ADR-001".to_owned()]),
            role: crate::graph::Role::Runtime,
            note: "Tier B, git source".into(),
        };
        let entries = [entry("moduletto", A), entry("moduletto-pq", B)];
        let text = format!("tier-b moduletto\nconfirmed moduletto 0.3.0 {A} 2026-10-28 MYTHOS-0\n");
        let tier = parse(&text).unwrap_or_default();
        let release = check(&[&ctx], &entries, Some(&tier), true);
        assert!(
            release
                .iter()
                .any(|f| f.severity == crate::report::Severity::Error
                    && f.message.contains("moduletto-pq 0.3.0")),
            "moduletto-pq from moduletto's repository ships in a release unconfirmed: {release:?}"
        );
    }
}
