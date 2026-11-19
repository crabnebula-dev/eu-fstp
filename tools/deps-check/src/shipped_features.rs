//! The test-cell guard (issue 6 item 9, ADR-001 A-series test-only rule).
//!
//! `test-cell` is a test-only feature of `fstp-oauth` and `fstp-web`
//! (`new_test_cell`, which admits a plain `http` issuer under
//! `.localhost`). Only `fstp-api-testkit` enables it. A workspace-wide
//! build unifies features across every selected package, so a shipped
//! binary that links one of those crates would then carry the test code.
//! Two checks hold the line, over each shipped binary package:
//!
//! - `shipped-test-cell`: no package in the binary's normal and build
//!   closure has the feature `test-cell` enabled in the workspace
//!   resolve. The resolve is unified, so this also catches the unification
//!   case a per-package build would hide. Contexts that run with
//!   `--all-features` are not read: they enable every feature on purpose
//!   and are no release build.
//! - `shipped-test-crate`: that closure holds none of the test-only
//!   workspace crates in [`TEST_CRATES`]. Dev edges do not ship.

use crate::layering::{SHIPPED, members, reach, render_path};
use crate::metadata::Metadata;
use crate::report::Finding;

/// The shipped binary packages. No list of release binaries exists in the
/// tool, the ADRs or CI, so this is the list: every workspace package with
/// a `[[bin]]` that is not a test or demo tool.
pub(crate) const SHIPPED_BINARY_PACKAGES: [&str; 9] = [
    "fstp-cell",
    "fstp-vault",
    "fstp-edge",
    "fstp-keyd",
    "fstp-backup",
    "fstp-assessor",
    "fstp-witness",
    "fstp-control",
    "fstp-release-svc",
];

/// The feature no shipped binary may have enabled.
const FEATURE: &str = "test-cell";

/// Workspace crates that exist for tests only.
const TEST_CRATES: [&str; 4] = [
    "fstp-api-testkit",
    "fstp-celltest",
    "fstp-pgtest",
    "fstp-domain-testkit",
];

/// Runs both checks over one workspace context.
pub(crate) fn check(meta: &Metadata) -> Vec<Finding> {
    check_packages(meta, &SHIPPED_BINARY_PACKAGES)
}

fn check_packages(meta: &Metadata, shipped: &[&str]) -> Vec<Finding> {
    let mut out = Vec::new();
    let all = members(meta);
    for &name in shipped {
        let Some(&start) = all.get(name) else {
            continue;
        };
        let parent = reach(meta, start, &SHIPPED);
        let closure = std::iter::once(start).chain(parent.keys().copied());
        for pkg in closure {
            let Some(p) = meta.packages.get(pkg) else {
                continue;
            };
            let enabled = meta
                .node_of_pkg
                .get(&pkg)
                .and_then(|&n| meta.nodes.get(n))
                .is_some_and(|n| n.features.iter().any(|f| f == FEATURE));
            let path = || {
                if pkg == start {
                    name.to_owned()
                } else {
                    render_path(meta, &parent, start, pkg)
                }
            };
            if enabled {
                out.push(Finding::error(
                    "shipped-test-cell",
                    format!(
                        "the shipped binary package {name} reaches {} with feature {FEATURE} enabled ({}); a release build must not carry test-only code",
                        p.name,
                        path()
                    ),
                ));
            }
            if TEST_CRATES.contains(&p.name.as_str()) {
                out.push(Finding::error(
                    "shipped-test-crate",
                    format!(
                        "the shipped binary package {name} depends on the test-only crate {} outside dev-dependencies ({})",
                        p.name,
                        path()
                    ),
                ));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::{DepKind, Node, NodeDep, Package};

    /// A synthetic workspace: `names` all members, normal edges `edges`,
    /// and `featured` names the packages with `test-cell` enabled.
    fn world(names: &[&str], edges: &[(&str, &str)], featured: &[&str]) -> Metadata {
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
            let deps = edges
                .iter()
                .filter(|(from, _)| from == name)
                .filter_map(|(_, to)| names.iter().position(|n| n == to))
                .map(|pkg| NodeDep {
                    pkg,
                    kinds: vec![DepKind::Normal],
                })
                .collect();
            m.nodes.push(Node {
                pkg: i,
                deps,
                features: if featured.contains(name) {
                    vec![FEATURE.to_owned()]
                } else {
                    vec![]
                },
            });
            m.node_of_pkg.insert(i, i);
        }
        m
    }

    /// Issue 6 item 9: a shipped binary whose closure reaches a crate with
    /// `test-cell` enabled is refused, with the path. A clean closure, and
    /// a test crate that only the testkit's own binary reaches, are not.
    #[test]
    fn issue6_test_cell_feature_never_reaches_a_shipped_binary() {
        let names = ["fstp-cell", "fstp-web", "fstp-oauth", "fstp-api-testkit"];
        let bad = world(
            &names,
            &[
                ("fstp-cell", "fstp-web"),
                ("fstp-web", "fstp-oauth"),
                ("fstp-api-testkit", "fstp-web"),
            ],
            &["fstp-web", "fstp-oauth"],
        );
        let f = check_packages(&bad, &["fstp-cell"]);
        let has = |path: &str| {
            f.iter()
                .any(|f| f.code == "shipped-test-cell" && f.message.contains(path))
        };
        assert!(has("(fstp-cell -> fstp-web)"), "{f:?}");
        assert!(has("(fstp-cell -> fstp-web -> fstp-oauth)"), "{f:?}");
        assert_eq!(f.len(), 2, "{f:?}");

        // The same graph with nothing shipped linking them is clean, even
        // though the testkit itself has the feature.
        let clean = world(
            &names,
            &[("fstp-api-testkit", "fstp-web"), ("fstp-web", "fstp-oauth")],
            &["fstp-web", "fstp-oauth"],
        );
        assert!(check_packages(&clean, &["fstp-cell"]).is_empty());
        // And a shipped binary with the crates linked but the feature off.
        let off = world(
            &names,
            &[("fstp-cell", "fstp-web"), ("fstp-web", "fstp-oauth")],
            &[],
        );
        assert!(check_packages(&off, &["fstp-cell"]).is_empty());
    }

    /// Issue 6 item 9: a shipped binary with a test-only crate as a normal
    /// dependency is refused.
    #[test]
    fn issue6_shipped_binary_never_links_a_test_crate() {
        let names = ["fstp-vault", "fstp-celltest"];
        let bad = world(&names, &[("fstp-vault", "fstp-celltest")], &[]);
        let f = check_packages(&bad, &["fstp-vault"]);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].code, "shipped-test-crate");
    }
}
