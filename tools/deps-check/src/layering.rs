//! The layering gate for the M2 domain crates (`docs/handoff/m2-design.md`
//! section 1).
//!
//! It reads the main workspace's resolve graph and enforces three rules:
//!
//! 1. No I/O. No M2 crate depends on `fstp-rt`, `fstp-http`, `fstp-tls`,
//!    `fstp-pgwire`, `fstp-pgtest`, `fstp-migrate` or `fstp-crypto`. Nor
//!    does it depend on the third-party roots that do I/O or run async
//!    code: `tokio`, `mio`, `socket2`, the `rustls` crates and `aws-lc-rs`
//!    (ADR-001, ADR-002). Beyond that, the five M2 production crates take
//!    no third-party crate at all as a normal or build dependency, directly
//!    or through another crate, since they use none (W7 fix). Every
//!    package that is not a workspace member is third-party, whatever its
//!    source. A path dependency outside the workspace, such as a vendored
//!    crate, has no source and is caught too. A name list alone
//!    would let a new third-party crate through, because an in-house crate
//!    may depend on any ADR root.
//! 2. The I-10 boundary. `fstp-domain` has no dependency path to
//!    `fstp-findings` or `fstp-engine`.
//! 3. The testkit never ships. No crate other than `fstp-domain-testkit`
//!    takes `fstp-domain-testkit`, `fstp-prop` or `fstp-mc` as a normal or
//!    build dependency.
//!
//! A dependency path is what cargo builds for the crate and its tests: any
//! edge out of the crate itself, then normal and build edges only. Dev
//! edges of other crates are never built for it, so they never count. Rule 3
//! starts from normal and build edges only, so dev-dependencies stay
//! allowed. A crate that is not a workspace member is not checked here; the
//! fuzz gate already fails when a parser-bearing M2 crate goes missing.

use std::collections::{BTreeMap, VecDeque};

use crate::metadata::{DepKind, Metadata};
use crate::report::Finding;

/// The crates of milestone M2.
const M2_CRATES: [&str; 6] = [
    "fstp-money",
    "fstp-ledger",
    "fstp-domain",
    "fstp-findings",
    "fstp-engine",
    "fstp-domain-testkit",
];

/// Crates that do I/O or run async code, which no M2 crate may reach
/// (rule 1). The in-house I/O crates come first. The third-party ADR roots
/// follow: an in-house crate may depend on any root
/// (`deps/adr-roots.txt`), so the allowlist gate alone lets them through.
const IO_CRATES: [&str; 15] = [
    "fstp-rt",
    "fstp-http",
    "fstp-tls",
    "fstp-pgwire",
    "fstp-pgtest",
    "fstp-migrate",
    "fstp-crypto",
    "tokio",
    "mio",
    "socket2",
    "rustls",
    "rustls-webpki",
    "rustls-pki-types",
    "aws-lc-rs",
    "aws-lc-sys",
];

/// The M2 crates that ship: they take no third-party crate as a normal or
/// build dependency (rule 1). The testkit is a test crate, so it is not
/// among them.
const M2_PRODUCTION: [&str; 5] = [
    "fstp-money",
    "fstp-ledger",
    "fstp-domain",
    "fstp-findings",
    "fstp-engine",
];

/// The crate that must not reach the findings side (rule 2).
const DOMAIN: &str = "fstp-domain";
/// The findings side of the I-10 boundary (rule 2).
const FINDINGS_SIDE: [&str; 2] = ["fstp-findings", "fstp-engine"];

/// The only crate that may take a test-only crate as a normal dependency (rule 3).
const TESTKIT: &str = "fstp-domain-testkit";
/// The M3 isolation harness, test only too (M3 design section 2.4, rule 9).
/// It may take the test-only crates as normal dependencies, and
/// `layering_m3` keeps every other crate from taking it.
const CELLTEST: &str = "fstp-celltest";
/// Test-only crates that never ship (rule 3).
const TEST_ONLY: [&str; 3] = ["fstp-domain-testkit", "fstp-prop", "fstp-mc"];

/// Every edge kind, for the first step out of a crate.
pub(crate) const ANY_KIND: [DepKind; 3] = [DepKind::Normal, DepKind::Build, DepKind::Dev];
/// The edge kinds that ship with a crate.
pub(crate) const SHIPPED: [DepKind; 2] = [DepKind::Normal, DepKind::Build];

/// The path packages that are workspace members, by name.
pub(crate) fn members(meta: &Metadata) -> BTreeMap<&str, usize> {
    meta.members
        .iter()
        .filter_map(|&i| meta.packages.get(i).map(|p| (p.name.as_str(), i)))
        .collect()
}

/// Every package reachable from `start`, with the package it was reached
/// from. Edges out of `start` count when they carry one of `first`. Every
/// later edge counts when it carries a normal or build kind.
pub(crate) fn reach(meta: &Metadata, start: usize, first: &[DepKind]) -> BTreeMap<usize, usize> {
    let mut parent: BTreeMap<usize, usize> = BTreeMap::new();
    let mut queue = VecDeque::from([start]);
    while let Some(pkg) = queue.pop_front() {
        let kinds: &[DepKind] = if pkg == start { first } else { &SHIPPED };
        let Some(node) = meta.node_of_pkg.get(&pkg).and_then(|&n| meta.nodes.get(n)) else {
            continue;
        };
        for dep in &node.deps {
            if dep.pkg == start || parent.contains_key(&dep.pkg) {
                continue;
            }
            if dep.kinds.iter().any(|k| kinds.contains(k)) {
                parent.insert(dep.pkg, pkg);
                queue.push_back(dep.pkg);
            }
        }
    }
    parent
}

/// The path from `start` to `to` as `a -> b -> c`.
pub(crate) fn render_path(
    meta: &Metadata,
    parent: &BTreeMap<usize, usize>,
    start: usize,
    to: usize,
) -> String {
    let name = |i: usize| meta.packages.get(i).map_or("?", |p| p.name.as_str());
    let mut names = vec![name(to)];
    let mut at = to;
    while at != start {
        let Some(&p) = parent.get(&at) else { break };
        names.push(name(p));
        at = p;
    }
    names.reverse();
    names.join(" -> ")
}

/// Each package named in `targets` that `parent` reaches, in `targets` order.
pub(crate) fn hits<'a>(
    meta: &Metadata,
    parent: &BTreeMap<usize, usize>,
    targets: &[&'a str],
) -> Vec<(&'a str, usize)> {
    let mut out = Vec::new();
    for &target in targets {
        if let Some(&pkg) = parent
            .keys()
            .find(|&&i| meta.packages.get(i).is_some_and(|p| p.name == target))
        {
            out.push((target, pkg));
        }
    }
    out
}

/// Runs the three rules over one workspace context.
pub(crate) fn check(meta: &Metadata) -> Vec<Finding> {
    let mut findings = Vec::new();
    let members = members(meta);

    for krate in M2_CRATES {
        let Some(&start) = members.get(krate) else {
            continue;
        };
        let parent = reach(meta, start, &ANY_KIND);
        for (io, pkg) in hits(meta, &parent, &IO_CRATES) {
            findings.push(Finding::error(
                "layering-io",
                format!(
                    "{krate} depends on {io} ({}); M2 crates do no I/O",
                    render_path(meta, &parent, start, pkg)
                ),
            ));
        }
    }

    for krate in M2_PRODUCTION {
        let Some(&start) = members.get(krate) else {
            continue;
        };
        let parent = reach(meta, start, &SHIPPED);
        for &pkg in parent.keys() {
            let Some(p) = meta.packages.get(pkg) else {
                continue;
            };
            if meta.members.contains(&pkg) {
                continue;
            }
            findings.push(Finding::error(
                "layering-third-party",
                format!(
                    "{krate} depends on the third-party crate {} ({}); the M2 production crates take no third-party crate",
                    p.name,
                    render_path(meta, &parent, start, pkg)
                ),
            ));
        }
    }

    if let Some(&start) = members.get(DOMAIN) {
        let parent = reach(meta, start, &ANY_KIND);
        for (side, pkg) in hits(meta, &parent, &FINDINGS_SIDE) {
            findings.push(Finding::error(
                "layering-i10",
                format!(
                    "{DOMAIN} has a dependency path to {side} ({}); findings depend on the domain, never the reverse (I-10)",
                    render_path(meta, &parent, start, pkg)
                ),
            ));
        }
    }

    for (&krate, &start) in &members {
        if krate == TESTKIT || krate == CELLTEST {
            continue;
        }
        let parent = reach(meta, start, &SHIPPED);
        for (test_only, pkg) in hits(meta, &parent, &TEST_ONLY) {
            findings.push(Finding::error(
                "layering-test-only",
                format!(
                    "{krate} takes {test_only} as a normal or build dependency ({}); only {TESTKIT} may, and only as a test crate",
                    render_path(meta, &parent, start, pkg)
                ),
            ));
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::{Node, NodeDep, Package};

    const N: DepKind = DepKind::Normal;
    const B: DepKind = DepKind::Build;
    const D: DepKind = DepKind::Dev;

    /// A workspace of path members. Each entry is a crate and its edges.
    fn graph(crates: &[(&str, &[(&str, DepKind)])]) -> Metadata {
        let mut names: Vec<&str> = Vec::new();
        for (name, deps) in crates {
            for n in std::iter::once(name).chain(deps.iter().map(|(d, _)| d)) {
                if !names.contains(n) {
                    names.push(n);
                }
            }
        }
        let mut m = Metadata::default();
        for (i, name) in names.iter().enumerate() {
            m.packages.push(Package {
                id: (*name).into(),
                name: (*name).into(),
                version: "0.1.0".into(),
                source: None,
                manifest_path: format!("/repo/crates/{name}/Cargo.toml"),
                features: Default::default(),
                dependencies: vec![],
                targets: vec![],
                cargo_fuzz: false,
            });
            m.members.push(i);
            let deps = crates
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, d)| *d)
                .unwrap_or(&[]);
            let mut edges: Vec<NodeDep> = Vec::new();
            for (dep, kind) in deps {
                let pkg = names.iter().position(|n| n == dep).unwrap();
                match edges.iter_mut().find(|e| e.pkg == pkg) {
                    Some(e) => e.kinds.push(*kind),
                    None => edges.push(NodeDep {
                        pkg,
                        kinds: vec![*kind],
                    }),
                }
            }
            m.nodes.push(Node {
                pkg: i,
                deps: edges,
                features: vec![],
            });
            m.node_of_pkg.insert(i, i);
        }
        m
    }

    /// The M2 graph of design section 1, with the M1 crates around it.
    fn designed() -> Vec<(&'static str, Vec<(&'static str, DepKind)>)> {
        vec![
            ("fstp-json", vec![("fstp-prop", D)]),
            ("fstp-mc", vec![("fstp-prop", D)]),
            ("fstp-rt", vec![("fstp-prop", D)]),
            ("fstp-tls", vec![("fstp-rt", N), ("fstp-prop", D)]),
            ("fstp-money", vec![("fstp-json", N), ("fstp-prop", D)]),
            ("fstp-ledger", vec![("fstp-json", N), ("fstp-prop", D)]),
            (
                "fstp-domain",
                vec![
                    ("fstp-money", N),
                    ("fstp-ledger", N),
                    ("fstp-json", N),
                    ("fstp-prop", D),
                ],
            ),
            (
                "fstp-findings",
                vec![("fstp-domain", N), ("fstp-money", N), ("fstp-prop", D)],
            ),
            (
                "fstp-engine",
                vec![("fstp-domain", N), ("fstp-findings", N), ("fstp-prop", D)],
            ),
            (
                "fstp-domain-testkit",
                vec![
                    ("fstp-engine", N),
                    ("fstp-findings", N),
                    ("fstp-domain", N),
                    ("fstp-prop", N),
                    ("fstp-mc", N),
                ],
            ),
        ]
    }

    /// Builds the designed graph with `extra` edges added.
    fn designed_with(extra: &[(&'static str, &'static str, DepKind)]) -> Metadata {
        let mut crates = designed();
        for (from, to, kind) in extra {
            match crates.iter_mut().find(|(n, _)| n == from) {
                Some((_, deps)) => deps.push((to, *kind)),
                None => crates.push((from, vec![(to, *kind)])),
            }
        }
        let borrowed: Vec<(&str, &[(&str, DepKind)])> =
            crates.iter().map(|(n, d)| (*n, d.as_slice())).collect();
        graph(&borrowed)
    }

    /// Marks the packages named in `names` as third-party: a registry source.
    fn third_party(meta: &mut Metadata, names: &[&str]) {
        for p in &mut meta.packages {
            if names.contains(&p.name.as_str()) {
                p.source = Some("registry+https://github.com/rust-lang/crates.io-index".into());
            }
        }
        meta.members.retain(|&i| {
            meta.packages
                .get(i)
                .is_some_and(|p| !names.contains(&p.name.as_str()))
        });
    }

    /// The designed graph with `extra` edges, the packages in `outside` third-party.
    fn with_third_party(
        extra: &[(&'static str, &'static str, DepKind)],
        outside: &[&str],
    ) -> Metadata {
        let mut m = designed_with(extra);
        third_party(&mut m, outside);
        m
    }

    /// Whether a layering error names both `krate` and `dep`.
    fn rejects(findings: &[Finding], krate: &str, dep: &str) -> bool {
        findings.iter().any(|f| {
            f.code.starts_with("layering")
                && f.message.starts_with(krate)
                && f.message.contains(dep)
        })
    }

    fn messages(findings: &[Finding], code: &str) -> Vec<String> {
        findings
            .iter()
            .filter(|f| f.code == code)
            .map(|f| f.message.clone())
            .collect()
    }

    #[test]
    fn designed_graph_passes() {
        let findings = check(&designed_with(&[]));
        assert!(findings.is_empty(), "{findings:?}");
    }

    /// Design section 1, rule 1, ADR-002: the third-party ADR roots that do
    /// I/O or run async code fail too, directly or through another crate.
    /// An in-house crate may depend on any ADR root, so the allowlist gate
    /// alone lets them through.
    #[test]
    fn review_w7_third_party_io_roots_are_rejected() {
        for root in [
            "tokio",
            "mio",
            "socket2",
            "rustls",
            "rustls-webpki",
            "aws-lc-rs",
        ] {
            let direct = check(&designed_with(&[("fstp-ledger", root, N)]));
            let msgs = messages(&direct, "layering-io");
            assert!(
                msgs.contains(&format!(
                    "fstp-ledger depends on {root} (fstp-ledger -> {root}); M2 crates do no I/O"
                )),
                "{root}: {msgs:?}"
            );
        }
        let transitive = check(&designed_with(&[
            ("fstp-domain", "fstp-x", N),
            ("fstp-x", "tokio", N),
        ]));
        let msgs = messages(&transitive, "layering-io");
        assert!(
            msgs.iter()
                .any(|m| m.contains("fstp-domain -> fstp-x -> tokio")),
            "{msgs:?}"
        );
    }

    /// Design section 1, rule 1: a direct, a transitive and a dev edge to an
    /// I/O crate each fail.
    #[test]
    fn io_crates_are_rejected_on_any_path() {
        let direct = check(&designed_with(&[("fstp-money", "fstp-rt", N)]));
        let msgs = messages(&direct, "layering-io");
        assert_eq!(
            msgs.first().map(String::as_str),
            Some("fstp-money depends on fstp-rt (fstp-money -> fstp-rt); M2 crates do no I/O"),
            "{direct:?}"
        );
        // Every M2 crate above fstp-money reaches fstp-rt through it.
        assert_eq!(msgs.len(), 5, "{msgs:?}");
        assert!(
            msgs.contains(
                &"fstp-engine depends on fstp-rt (fstp-engine -> fstp-domain -> fstp-money -> fstp-rt); M2 crates do no I/O"
                    .to_owned()
            ),
            "{msgs:?}"
        );

        let transitive = check(&designed_with(&[
            ("fstp-ledger", "fstp-x", N),
            ("fstp-x", "fstp-tls", B),
        ]));
        let msgs = messages(&transitive, "layering-io");
        assert!(
            msgs.iter()
                .any(|m| m.starts_with("fstp-ledger depends on fstp-rt")
                    && m.contains("fstp-ledger -> fstp-x -> fstp-tls -> fstp-rt")),
            "{msgs:?}"
        );
        assert!(
            msgs.iter()
                .any(|m| m.starts_with("fstp-ledger depends on fstp-tls")),
            "{msgs:?}"
        );
        // Every crate above fstp-ledger reaches the I/O crate too.
        for upper in [
            "fstp-domain",
            "fstp-findings",
            "fstp-engine",
            "fstp-domain-testkit",
        ] {
            assert!(
                msgs.iter()
                    .any(|m| m.starts_with(&format!("{upper} depends on fstp-tls"))),
                "{upper}: {msgs:?}"
            );
        }

        let dev = check(&designed_with(&[("fstp-engine", "fstp-pgtest", D)]));
        assert_eq!(messages(&dev, "layering-io").len(), 1, "{dev:?}");
    }

    /// Design section 1, rule 1: dev edges of a dependency are never built
    /// for the dependent, so they do not count.
    #[test]
    fn dev_edges_of_dependencies_do_not_count() {
        let findings = check(&designed_with(&[("fstp-json", "fstp-crypto", D)]));
        assert!(findings.is_empty(), "{findings:?}");
    }

    /// Design section 1, rule 1: crates outside M2 may use I/O crates.
    #[test]
    fn io_crates_are_allowed_outside_m2() {
        let findings = check(&designed_with(&[("fstp-http", "fstp-tls", N)]));
        assert!(findings.is_empty(), "{findings:?}");
    }

    /// I-10, design section 1, rule 2: fstp-domain has no dependency path to
    /// fstp-findings or fstp-engine, whether direct, transitive or dev.
    #[test]
    fn i10_layering_rejects_domain_path_to_findings() {
        let direct = check(&designed_with(&[("fstp-domain", "fstp-findings", N)]));
        assert_eq!(
            messages(&direct, "layering-i10"),
            vec![
                "fstp-domain has a dependency path to fstp-findings (fstp-domain -> fstp-findings); findings depend on the domain, never the reverse (I-10)"
                    .to_owned()
            ],
            "{direct:?}"
        );

        let transitive = check(&designed_with(&[
            ("fstp-ledger", "fstp-y", N),
            ("fstp-y", "fstp-engine", N),
        ]));
        let msgs = messages(&transitive, "layering-i10");
        assert!(
            msgs.iter().any(|m| m.contains(
                "path to fstp-engine (fstp-domain -> fstp-ledger -> fstp-y -> fstp-engine)"
            )),
            "{msgs:?}"
        );
        assert!(
            msgs.iter().any(|m| m.contains("path to fstp-findings")),
            "{msgs:?}"
        );

        // A dev-dependency on the testkit would put findings in the domain's tests.
        let dev = check(&designed_with(&[("fstp-domain", "fstp-domain-testkit", D)]));
        let msgs = messages(&dev, "layering-i10");
        assert_eq!(msgs.len(), 2, "{msgs:?}");
        assert!(
            msgs.iter()
                .all(|m| m.contains("fstp-domain -> fstp-domain-testkit -> ")),
            "{msgs:?}"
        );
        // The dev edge itself is not shipping, so rule 3 stays quiet.
        assert!(messages(&dev, "layering-test-only").is_empty(), "{dev:?}");
    }

    /// Design section 1, rule 3: only the testkit takes test-only crates as
    /// normal or build dependencies.
    #[test]
    fn test_only_crates_never_ship() {
        let normal = check(&designed_with(&[("fstp-engine", "fstp-prop", N)]));
        assert_eq!(
            messages(&normal, "layering-test-only"),
            vec![
                "fstp-engine takes fstp-prop as a normal or build dependency (fstp-engine -> fstp-prop); only fstp-domain-testkit may, and only as a test crate"
                    .to_owned()
            ],
            "{normal:?}"
        );

        let build = check(&designed_with(&[("fstp-money", "fstp-mc", B)]));
        let msgs = messages(&build, "layering-test-only");
        assert!(
            msgs.iter()
                .any(|m| m.starts_with("fstp-money takes fstp-mc")),
            "{msgs:?}"
        );
        // Everything that ships fstp-money now ships fstp-mc as well.
        assert!(
            msgs.iter()
                .any(|m| m.contains("(fstp-engine -> fstp-domain -> fstp-money -> fstp-mc)")),
            "{msgs:?}"
        );

        let testkit = check(&designed_with(&[(
            "fstp-findings",
            "fstp-domain-testkit",
            N,
        )]));
        assert!(
            messages(&testkit, "layering-test-only")
                .iter()
                .any(|m| m.starts_with("fstp-findings takes fstp-domain-testkit")),
            "{testkit:?}"
        );

        // The rule covers every workspace member, not only the M2 crates.
        let elsewhere = check(&designed_with(&[("fstp-http", "fstp-prop", N)]));
        assert_eq!(
            messages(&elsewhere, "layering-test-only").len(),
            1,
            "{elsewhere:?}"
        );
    }

    /// Design section 1, rule 1 (W7 fix): the five M2 production crates
    /// take no third-party crate at all as a normal or build dependency,
    /// whatever its name. A fixed list of I/O names would let a new
    /// third-party crate through, since an in-house crate may depend on
    /// any ADR root.
    #[test]
    fn review_w7_any_third_party_crate_is_rejected_in_m2_production_crates() {
        for krate in [
            "fstp-money",
            "fstp-ledger",
            "fstp-domain",
            "fstp-findings",
            "fstp-engine",
        ] {
            for kind in [N, B] {
                let findings = check(&with_third_party(&[(krate, "itoa", kind)], &["itoa"]));
                assert!(
                    rejects(&findings, krate, "itoa"),
                    "{krate} with itoa as a {kind:?} dependency: {findings:?}"
                );
            }
        }
    }

    /// Design section 1, rule 1 (W7 fix): a third-party crate reached
    /// through an in-house crate ships with the M2 crate too, so it fails.
    #[test]
    fn review_w7_third_party_crate_through_an_in_house_crate_is_rejected() {
        let findings = check(&with_third_party(
            &[("fstp-json", "memchr", N)],
            &["memchr"],
        ));
        for krate in ["fstp-money", "fstp-ledger", "fstp-domain"] {
            assert!(
                rejects(&findings, krate, "memchr"),
                "{krate} ships memchr through fstp-json: {findings:?}"
            );
        }
    }

    /// Design section 1, rule 1 (W7 fix): the third-party rule covers what
    /// ships. A dev-dependency of an M2 crate, a third-party crate of the
    /// testkit and one of a crate outside M2 are no finding of it.
    #[test]
    fn review_w7_third_party_rule_covers_only_shipped_m2_production_edges() {
        let dev = check(&with_third_party(&[("fstp-domain", "itoa", D)], &["itoa"]));
        assert!(!rejects(&dev, "fstp-domain", "itoa"), "{dev:?}");
        let testkit = check(&with_third_party(
            &[("fstp-domain-testkit", "itoa", N)],
            &["itoa"],
        ));
        assert!(
            !rejects(&testkit, "fstp-domain-testkit", "itoa"),
            "{testkit:?}"
        );
        let outside = check(&with_third_party(&[("fstp-http", "itoa", N)], &["itoa"]));
        assert!(outside.is_empty(), "{outside:?}");
    }

    /// Design section 1, rule 1 (W7 fix round 1): a path dependency outside
    /// the workspace, such as a vendored third-party crate, has no source in
    /// `cargo metadata`. It is not a workspace member, so it is third-party
    /// and fails all the same.
    #[test]
    fn review_w7_vendored_path_crate_outside_the_workspace_is_rejected() {
        let mut m = designed_with(&[("fstp-domain", "vendored", N)]);
        m.members
            .retain(|&i| m.packages.get(i).is_some_and(|p| p.name != "vendored"));
        assert!(
            m.packages
                .iter()
                .any(|p| p.name == "vendored" && p.source.is_none()),
            "setup: the vendored crate has no source"
        );
        let findings = check(&m);
        assert!(
            rejects(&findings, "fstp-domain", "vendored"),
            "{findings:?}"
        );
    }
}
