//! Reachability and role classification over the cargo resolve graph.
//!
//! `cargo metadata` lists some edges that cargo never builds. The known case
//! is a weak optional dependency (`dep?/feature`): the resolve graph and the
//! lockfile list the dependency even when no feature activates it. This
//! module therefore re-checks every edge against the manifest declaration
//! and the enabled features, and drops the edges cargo does not activate.
//!
//! Roles follow the edges. A workspace member is `runtime`. A normal edge
//! keeps the role, a build edge caps it at `build`, and a dev edge makes it
//! `test`. Every package of a fuzz project is `test`. A package's role is the
//! highest role over all paths, contexts and platforms (ADR-003, R-NF-07).
//! A package that no supported Linux context builds gets the role
//! `platform` instead, whatever it does on other targets (P5).

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use crate::allowlist::Root;
use crate::metadata::{DepKind, Metadata, Node, Package};
use crate::report::Finding;

/// How far a third-party package reaches into the build.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Role {
    /// Never built for x86_64 or aarch64 Linux without extra cfgs. Only
    /// another target, or a custom cfg, reaches it (P5).
    Platform,
    /// Used only by tests, dev-dependencies and fuzz projects.
    #[default]
    Test,
    /// Runs at build time only, through build-dependency edges.
    Build,
    /// Linked into shipped artifacts.
    Runtime,
}

impl Role {
    /// All roles, lowest first.
    pub(crate) const ALL: [Role; 4] = [Role::Platform, Role::Test, Role::Build, Role::Runtime];

    /// The allowlist spelling.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Role::Platform => "platform",
            Role::Test => "test",
            Role::Build => "build",
            Role::Runtime => "runtime",
        }
    }

    /// Parses the allowlist spelling.
    pub(crate) fn parse(s: &str) -> Option<Role> {
        Role::ALL.into_iter().find(|r| r.label() == s)
    }

    /// The role of a dependency reached over an edge of `kind` from a
    /// package with this role.
    pub(crate) fn through(self, kind: DepKind) -> Role {
        match kind {
            DepKind::Normal => self,
            DepKind::Build => self.min(Role::Build),
            DepKind::Dev => self.min(Role::Test),
        }
    }
}

/// Whether cargo activates an edge.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Activation {
    /// A non-optional declaration, or an optional one that an enabled feature activates.
    Active,
    /// Every matching declaration is optional and no enabled feature activates it.
    Inactive,
    /// No declaration matches. The edge is kept, so the check stays conservative.
    Undeclared,
}

/// Decides whether the edge from `from` to package `to_pkg` of `kind` is built.
pub(crate) fn edge_activation(
    meta: &Metadata,
    from: &Node,
    to_pkg: usize,
    kind: DepKind,
) -> Activation {
    let (Some(src), Some(dst)) = (meta.packages.get(from.pkg), meta.packages.get(to_pkg)) else {
        return Activation::Undeclared;
    };
    let mut declared = false;
    for decl in src
        .dependencies
        .iter()
        .filter(|d| d.name == dst.name && d.kind == kind)
    {
        declared = true;
        if !decl.optional || optional_enabled(src, &from.features, decl.key()) {
            return Activation::Active;
        }
    }
    if declared {
        Activation::Inactive
    } else {
        Activation::Undeclared
    }
}

/// Whether one of the `enabled` features of `pkg` activates the optional
/// dependency declared under `key`.
///
/// `dep:key` and `key/feature` activate it. The weak form `key?/feature`
/// does not. An enabled feature without a definition is the implicit
/// feature of an optional dependency of the same name.
fn optional_enabled(pkg: &Package, enabled: &[String], key: &str) -> bool {
    enabled.iter().any(|f| match pkg.features.get(f) {
        Some(values) => values.iter().any(|v| activates(v, key)),
        None => f == key,
    })
}

fn activates(value: &str, key: &str) -> bool {
    if let Some(dep) = value.strip_prefix("dep:") {
        return dep == key;
    }
    value
        .strip_prefix(key)
        .is_some_and(|rest| rest.starts_with('/'))
}

/// One edge with its activation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Edge {
    /// Target node index.
    pub(crate) to: usize,
    /// Edge kind.
    pub(crate) kind: DepKind,
    /// Whether cargo builds it.
    pub(crate) activation: Activation,
}

/// The resolve graph with per-edge activation, indexed by node.
#[derive(Clone, Debug)]
pub(crate) struct Graph {
    /// Outgoing edges of each node.
    pub(crate) edges: Vec<Vec<Edge>>,
}

impl Graph {
    /// Builds the graph. Edges to packages without a resolve node are dropped,
    /// because cargo always emits a node for every package it resolves.
    pub(crate) fn new(meta: &Metadata) -> Graph {
        let edges = meta
            .nodes
            .iter()
            .map(|node| {
                let mut out = Vec::new();
                for dep in &node.deps {
                    let Some(&to) = meta.node_of_pkg.get(&dep.pkg) else {
                        continue;
                    };
                    for &kind in &dep.kinds {
                        out.push(Edge {
                            to,
                            kind,
                            activation: edge_activation(meta, node, dep.pkg, kind),
                        });
                    }
                }
                out
            })
            .collect();
        Graph { edges }
    }

    fn out(&self, node: usize) -> &[Edge] {
        self.edges.get(node).map_or(&[], Vec::as_slice)
    }

    /// Nodes reachable from `start` over built edges, including `start`.
    pub(crate) fn tree(&self, start: usize) -> BTreeSet<usize> {
        let mut seen = BTreeSet::from([start]);
        let mut stack = vec![start];
        while let Some(n) = stack.pop() {
            for e in self.out(n) {
                if e.activation != Activation::Inactive && seen.insert(e.to) {
                    stack.push(e.to);
                }
            }
        }
        seen
    }
}

/// An edge identified by its endpoints and kind.
pub(crate) type EdgeKey = (usize, usize, DepKind);

/// The classification of one metadata document.
#[derive(Clone, Debug, Default)]
pub(crate) struct Classification {
    /// The highest role of each reached node.
    pub(crate) roles: BTreeMap<usize, Role>,
    /// Edges from reached nodes that cargo does not activate.
    pub(crate) inactive: BTreeSet<EdgeKey>,
    /// Edges from reached nodes without a matching declaration.
    pub(crate) undeclared: BTreeSet<EdgeKey>,
}

/// Propagates roles from the workspace members, which start at `root_role`.
pub(crate) fn classify(meta: &Metadata, graph: &Graph, root_role: Role) -> Classification {
    let mut roles: HashMap<usize, Role> = HashMap::new();
    let mut queue = VecDeque::new();
    for member in &meta.members {
        if let Some(&n) = meta.node_of_pkg.get(member)
            && roles.insert(n, root_role) != Some(root_role)
        {
            queue.push_back(n);
        }
    }
    let mut out = Classification::default();
    // A node's role only rises, and there are three roles, so each node is
    // queued at most three times.
    while let Some(n) = queue.pop_front() {
        let Some(&role) = roles.get(&n) else { continue };
        for e in graph.out(n) {
            match e.activation {
                Activation::Inactive => {
                    out.inactive.insert((n, e.to, e.kind));
                    continue;
                }
                Activation::Undeclared => {
                    out.undeclared.insert((n, e.to, e.kind));
                }
                Activation::Active => {}
            }
            let next = role.through(e.kind);
            if roles.get(&e.to).is_none_or(|&old| next > old) {
                roles.insert(e.to, next);
                queue.push_back(e.to);
            }
        }
    }
    out.roles = roles.into_iter().collect();
    out
}

/// What kind of cargo project a context describes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProjectKind {
    /// The main workspace, or any project outside the known fuzz locations.
    Workspace,
    /// A cargo-fuzz project.
    Fuzz,
}

impl ProjectKind {
    /// The role of the project's members.
    pub(crate) fn root_role(self) -> Role {
        match self {
            ProjectKind::Workspace => Role::Runtime,
            ProjectKind::Fuzz => Role::Test,
        }
    }
}

/// One metadata document to analyse.
pub(crate) struct Context<'a> {
    /// Project label, such as `workspace` or `crates/fstp-json/fuzz`.
    pub(crate) label: String,
    /// Target triple of `--filter-platform`, or `all targets`.
    pub(crate) platform: String,
    /// Whether the context is one of the supported Linux platforms. The
    /// other contexts run without `--filter-platform`.
    pub(crate) linux: bool,
    /// Whether the context ran with `--all-features`.
    pub(crate) all_features: bool,
    /// Project kind.
    pub(crate) kind: ProjectKind,
    /// The parsed metadata.
    pub(crate) meta: &'a Metadata,
}

impl Context<'_> {
    /// A short description such as `workspace (x86_64-unknown-linux-gnu, all features)`.
    pub(crate) fn describe(&self) -> String {
        let features = if self.all_features {
            "all features"
        } else {
            "default features"
        };
        format!("{} ({}, {features})", self.label, self.platform)
    }
}

/// How a third-party package is used across all contexts.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Usage {
    /// The highest role, or [`Role::Platform`] when no Linux context builds it.
    pub(crate) role: Role,
    /// Whether a supported Linux context builds it.
    pub(crate) linux: bool,
    /// ADRs of the roots whose tree contains the package.
    pub(crate) adrs: BTreeSet<String>,
    /// Roots whose tree contains the package.
    pub(crate) roots: BTreeSet<String>,
    /// The highest role in each context label where it is reached.
    pub(crate) contexts: BTreeMap<String, Role>,
    /// Platforms where it is reached.
    pub(crate) platforms: BTreeSet<String>,
}

/// Where a fact holds: project labels and platforms.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Seen {
    /// Project labels.
    pub(crate) labels: BTreeSet<String>,
    /// Target triples.
    pub(crate) platforms: BTreeSet<String>,
}

/// A package (name, version) pair.
pub(crate) type PkgKey = (String, String);

/// A third-party package with its source: (name, version, source).
pub(crate) type SourcedKey = (String, String, String);

/// The combined result over all contexts.
#[derive(Clone, Debug, Default)]
pub(crate) struct Aggregate {
    /// Usage of every reached third-party package.
    pub(crate) usage: BTreeMap<PkgKey, Usage>,
    /// Third-party packages that appear in a resolve graph but are never
    /// built, with each reason and where it applies.
    pub(crate) excluded: BTreeMap<PkgKey, BTreeMap<String, Seen>>,
    /// Every third-party resolve node of each project label, reached or
    /// not. Each lockfile is reconciled against this set.
    pub(crate) resolved: BTreeMap<String, BTreeSet<SourcedKey>>,
    /// The union of the features cargo enables on each reached ADR root.
    pub(crate) root_features: BTreeMap<String, BTreeSet<String>>,
    /// Problems found while aggregating.
    pub(crate) findings: Vec<Finding>,
}

/// Sources that count as crates.io.
pub(crate) const CRATES_IO: [&str; 2] = [
    "registry+https://github.com/rust-lang/crates.io-index",
    "sparse+https://index.crates.io/",
];

fn key(p: &Package) -> PkgKey {
    (p.name.clone(), p.version.clone())
}

fn describe(p: &Package) -> String {
    format!("{} {}", p.name, p.version)
}

/// Analyses every context and merges the results.
///
/// `roots` maps a root crate name to its `deps/adr-roots.txt` entry. Checks
/// that need the file system, such as where a path package really lives,
/// are in the `provenance` module.
pub(crate) fn aggregate(contexts: &[Context<'_>], roots: &BTreeMap<String, Root>) -> Aggregate {
    let mut agg = Aggregate::default();
    let mut findings = BTreeSet::new();
    for ctx in contexts {
        let meta = ctx.meta;
        let graph = Graph::new(meta);
        let class = classify(meta, &graph, ctx.kind.root_role());
        let pkg_of = |n: usize| {
            meta.nodes
                .get(n)
                .and_then(|node| meta.packages.get(node.pkg))
        };
        let where_ = ctx.describe();

        let resolved = agg.resolved.entry(ctx.label.clone()).or_default();
        for node in &meta.nodes {
            if let Some(p) = meta.packages.get(node.pkg)
                && let Some(src) = &p.source
            {
                resolved.insert((p.name.clone(), p.version.clone(), src.clone()));
            }
        }

        for (&n, &role) in &class.roles {
            let Some(p) = pkg_of(n) else { continue };
            if p.is_path() {
                continue;
            }
            if let Some(src) = &p.source
                && !CRATES_IO.contains(&src.as_str())
                && !crate::git_source::is_git(src)
            {
                findings.insert(Finding::error(
                    "non-crates-io-source",
                    format!(
                        "{where_}: {} comes from {src}; only crates.io sources are allowed",
                        describe(p)
                    ),
                ));
            }
            let u = agg.usage.entry(key(p)).or_default();
            u.role = u.role.max(role);
            u.linux |= ctx.linux;
            let slot = u.contexts.entry(ctx.label.clone()).or_insert(role);
            *slot = (*slot).max(role);
            u.platforms.insert(ctx.platform.clone());
            if roots.contains_key(&p.name)
                && let Some(node) = meta.nodes.get(n)
            {
                agg.root_features
                    .entry(p.name.clone())
                    .or_default()
                    .extend(node.features.iter().cloned());
            }
        }

        for &n in class.roles.keys() {
            let Some(p) = pkg_of(n) else { continue };
            for e in graph.out(n) {
                if e.activation == Activation::Inactive {
                    continue;
                }
                let Some(dep) = pkg_of(e.to) else { continue };
                if p.is_path() && !dep.is_path() && !roots.contains_key(&dep.name) {
                    // Direct third-party dependencies of in-house code must be ADR roots.
                    findings.insert(Finding::error(
                        "direct-non-root",
                        format!(
                            "{where_}: in-house package {} depends directly ({}) on {}, \
                             which deps/adr-roots.txt does not list as an ADR root",
                            p.name,
                            e.kind.label(),
                            describe(dep)
                        ),
                    ));
                }
                if !p.is_path() && dep.is_path() {
                    // Only [patch], [replace] or a `paths` override can make a
                    // registry package depend on a path package.
                    findings.insert(Finding::error(
                        "registry-to-path",
                        format!(
                            "{where_}: registry package {} depends on path package {} at {}; \
                             a patch or override replaces a crates.io crate",
                            describe(p),
                            describe(dep),
                            dep.manifest_path
                        ),
                    ));
                }
            }
        }

        // ADR attribution: every package in the tree of a reached root.
        for &n in class.roles.keys() {
            let Some(p) = pkg_of(n) else { continue };
            if p.is_path() {
                continue;
            }
            let Some(root) = roots.get(&p.name) else {
                continue;
            };
            for m in graph.tree(n) {
                let Some(q) = pkg_of(m) else { continue };
                if q.is_path() {
                    continue;
                }
                if let Some(u) = agg.usage.get_mut(&key(q)) {
                    u.adrs.insert(root.adr.clone());
                    u.roots.insert(p.name.clone());
                }
            }
        }

        for &(from, to, kind) in &class.undeclared {
            if let (Some(a), Some(b)) = (pkg_of(from), pkg_of(to)) {
                findings.insert(Finding::warning(
                    "undeclared-edge",
                    format!(
                        "{where_}: edge {} -> {} ({}) matches no manifest declaration; kept",
                        describe(a),
                        describe(b),
                        kind.label()
                    ),
                ));
            }
        }

        // Explain every resolve node that is never built.
        let unreached: BTreeSet<usize> = (0..meta.nodes.len())
            .filter(|n| !class.roles.contains_key(n))
            .collect();
        for &u in &unreached {
            let Some(p) = pkg_of(u) else { continue };
            if p.is_path() {
                continue;
            }
            let mut reasons = BTreeSet::new();
            for &(from, to, kind) in &class.inactive {
                if to != u {
                    continue;
                }
                if let (Some(a), Some(node)) = (pkg_of(from), meta.nodes.get(from)) {
                    reasons.insert(format!(
                        "optional {} dependency of {}, not activated (enabled features: {})",
                        kind.label(),
                        describe(a),
                        if node.features.is_empty() {
                            "none".to_owned()
                        } else {
                            node.features.join(", ")
                        }
                    ));
                }
            }
            for &v in &unreached {
                if graph.out(v).iter().any(|e| e.to == u)
                    && let Some(a) = pkg_of(v)
                {
                    reasons.insert(format!("only reachable through {}", describe(a)));
                }
            }
            if reasons.is_empty() {
                reasons.insert("not reachable from any workspace member".to_owned());
            }
            let entry = agg.excluded.entry(key(p)).or_default();
            for r in reasons {
                let seen = entry.entry(r).or_default();
                seen.labels.insert(ctx.label.clone());
                seen.platforms.insert(ctx.platform.clone());
            }
        }
    }
    // A package excluded in one context but built in another is used.
    agg.excluded.retain(|k, _| !agg.usage.contains_key(k));

    for ((name, version), u) in agg.usage.iter_mut() {
        if !u.linux {
            u.role = Role::Platform;
            for r in u.contexts.values_mut() {
                *r = Role::Platform;
            }
        }
        if u.adrs.is_empty() {
            findings.insert(Finding::error(
                "no-adr-tree",
                format!(
                    "{name} {version} is not in the resolved tree of any ADR root in deps/adr-roots.txt"
                ),
            ));
        }
    }
    for (root, r) in roots {
        if !contexts.is_empty() && !agg.usage.keys().any(|(name, _)| name == root) {
            findings.insert(Finding::warning(
                "stale-root",
                format!(
                    "deps/adr-roots.txt lists {root} ({}), which no build uses",
                    r.adr
                ),
            ));
        }
    }
    agg.findings = findings.into_iter().collect();
    agg
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::metadata::{DepDecl, NodeDep, parse_metadata};
    use crate::report::Severity;

    const WEAK: &str = include_str!("../testdata/weak-optional.json");
    const ROLES: &str = include_str!("../testdata/roles.json");
    const REAL: &str = include_str!("../testdata/workspace-x86_64.json");

    /// Roots for the fixtures. alpha, beta and gamma are synthetic crates
    /// in roles.json; they borrow real ADR identifiers so that no invented
    /// identifier appears.
    pub(crate) fn roots() -> BTreeMap<String, Root> {
        [
            ("rustls", "ADR-001"),
            ("aws-lc-rs", "ADR-001"),
            ("rustls-pki-types", "ADR-001"),
            ("rustls-webpki", "ADR-001"),
            ("tokio", "ADR-002"),
            ("libfuzzer-sys", "ADR-003"),
            ("alpha", "ADR-004"),
            ("beta", "ADR-005"),
            ("gamma", "ADR-003"),
        ]
        .into_iter()
        .map(|(a, b)| {
            (
                a.to_owned(),
                Root {
                    adr: b.to_owned(),
                    features: BTreeSet::new(),
                    note: String::new(),
                },
            )
        })
        .collect()
    }

    fn ctx<'a>(meta: &'a Metadata, kind: ProjectKind, linux: bool) -> Context<'a> {
        Context {
            label: "workspace".into(),
            platform: if linux {
                "x86_64-unknown-linux-gnu".into()
            } else {
                "all targets".into()
            },
            linux,
            all_features: false,
            kind,
            meta,
        }
    }

    fn run(json: &str, kind: ProjectKind) -> Aggregate {
        let meta = parse_metadata(json.as_bytes()).unwrap();
        aggregate(&[ctx(&meta, kind, true)], &roots())
    }

    fn role_of(agg: &Aggregate, name: &str) -> Option<Role> {
        agg.usage
            .iter()
            .find(|((n, _), _)| n == name)
            .map(|(_, u)| u.role)
    }

    #[test]
    fn weak_optional_activation_rules() {
        let pkg = Package {
            id: "p".into(),
            name: "p".into(),
            version: "1.0.0".into(),
            source: None,
            manifest_path: "/repo/Cargo.toml".into(),
            features: [
                ("alloc".to_owned(), vec!["ring?/alloc".to_owned()]),
                ("strong".to_owned(), vec!["ring/alloc".to_owned()]),
                ("explicit".to_owned(), vec!["dep:ring".to_owned()]),
                ("ringish".to_owned(), vec!["ringo/alloc".to_owned()]),
            ]
            .into_iter()
            .collect(),
            dependencies: vec![],
            targets: vec![],
            cargo_fuzz: false,
        };
        let on = |fs: &[&str]| {
            let v: Vec<String> = fs.iter().map(|s| (*s).to_owned()).collect();
            optional_enabled(&pkg, &v, "ring")
        };
        assert!(!on(&[]));
        assert!(!on(&["alloc"]), "weak feature must not activate");
        assert!(
            !on(&["ringish"]),
            "prefix of another name must not activate"
        );
        assert!(on(&["strong"]));
        assert!(on(&["explicit"]));
        assert!(on(&["ring"]), "implicit feature activates");
    }

    /// TH-15, ADR-001: ring is listed in the lockfile and the resolve graph as
    /// a weak optional dependency of rustls-webpki, but no feature activates
    /// it. It must not count as used.
    #[test]
    fn th15_weak_optional_ring_is_not_used() {
        let agg = run(WEAK, ProjectKind::Workspace);
        assert_eq!(role_of(&agg, "ring"), None);
        assert_eq!(role_of(&agg, "getrandom"), None);
        assert_eq!(role_of(&agg, "cfg-if"), None);
        assert_eq!(role_of(&agg, "rustls-webpki"), Some(Role::Runtime));
        assert_eq!(role_of(&agg, "untrusted"), Some(Role::Runtime));
        let ring = agg
            .excluded
            .get(&("ring".to_owned(), "0.17.14".to_owned()))
            .unwrap();
        assert!(
            ring.keys().any(|r| r
                .contains("optional normal dependency of rustls-webpki 0.103.16, not activated")),
            "{ring:?}"
        );
        let getrandom = agg
            .excluded
            .get(&("getrandom".to_owned(), "0.2.17".to_owned()))
            .unwrap();
        assert!(
            getrandom
                .keys()
                .any(|r| r.contains("only reachable through ring 0.17.14")),
            "{getrandom:?}"
        );
    }

    /// ADR-003, R-NF-07: build edges cap the role at build, dev edges make
    /// it test, and the highest role over all paths wins.
    #[test]
    fn r_nf_07_roles_follow_edge_kinds() {
        let agg = run(ROLES, ProjectKind::Workspace);
        assert_eq!(role_of(&agg, "alpha"), Some(Role::Runtime));
        assert_eq!(role_of(&agg, "alpha-build"), Some(Role::Build));
        assert_eq!(role_of(&agg, "beta"), Some(Role::Build));
        assert_eq!(role_of(&agg, "beta-child"), Some(Role::Build));
        assert_eq!(role_of(&agg, "gamma"), Some(Role::Test));
        assert_eq!(role_of(&agg, "gamma-child"), Some(Role::Test));
        // shared is reached from gamma (test) and from alpha (runtime).
        assert_eq!(role_of(&agg, "shared"), Some(Role::Runtime));
        // opt is optional and activated by its implicit feature.
        assert_eq!(role_of(&agg, "opt"), Some(Role::Runtime));
        // never is optional and not activated.
        assert_eq!(role_of(&agg, "never"), None);
        let shared = agg
            .usage
            .get(&("shared".to_owned(), "1.0.0".to_owned()))
            .unwrap();
        assert_eq!(
            shared.adrs,
            BTreeSet::from(["ADR-003".to_owned(), "ADR-004".to_owned()])
        );
    }

    /// TH-15: a fuzz project only ever contributes test roles.
    #[test]
    fn th15_fuzz_project_packages_are_test_only() {
        let agg = run(ROLES, ProjectKind::Fuzz);
        assert!(agg.usage.values().all(|u| u.role == Role::Test));
    }

    /// TH-15: an in-house crate that uses a transitive crate directly needs
    /// its own ADR decision.
    #[test]
    fn th15_direct_use_of_non_root_is_an_error() {
        let agg = run(ROLES, ProjectKind::Workspace);
        let direct: Vec<_> = agg
            .findings
            .iter()
            .filter(|f| f.code == "direct-non-root")
            .collect();
        assert_eq!(direct.len(), 1, "{:?}", agg.findings);
        assert!(direct[0].message.contains("loner 1.0.0"));
        assert!(
            agg.findings
                .iter()
                .any(|f| f.code == "no-adr-tree" && f.message.contains("loner"))
        );
    }

    /// Regression for review finding cfg-and-platform-deps-ignored (P5): a
    /// crate that only an all-targets context reaches, such as one behind
    /// `cfg(target_os = "macos")` or a custom cfg, is used with role
    /// `platform`. It is no longer invisible.
    #[test]
    fn review_cfg_and_platform_deps_ignored() {
        let meta = parse_metadata(ROLES.as_bytes()).unwrap();
        // Drop gamma from the Linux view, as --filter-platform does for a
        // target-specific dependency.
        let mut linux = meta.clone();
        for node in &mut linux.nodes {
            node.deps
                .retain(|d| linux.packages.get(d.pkg).is_none_or(|p| p.name != "gamma"));
        }
        let agg = aggregate(
            &[
                ctx(&linux, ProjectKind::Workspace, true),
                ctx(&meta, ProjectKind::Workspace, false),
            ],
            &roots(),
        );
        assert_eq!(role_of(&agg, "gamma"), Some(Role::Platform));
        assert_eq!(role_of(&agg, "gamma-child"), Some(Role::Platform));
        assert_eq!(role_of(&agg, "alpha"), Some(Role::Runtime));
        // shared is still built on Linux through alpha.
        assert_eq!(role_of(&agg, "shared"), Some(Role::Runtime));
        let gamma = agg
            .usage
            .get(&("gamma".to_owned(), "1.0.0".to_owned()))
            .unwrap();
        assert!(!gamma.linux);
        assert_eq!(gamma.adrs, BTreeSet::from(["ADR-003".to_owned()]));
    }

    /// Regression for review finding patch-path-override (P5): a registry
    /// package that depends on a path package can only come from a patch
    /// or an override, and fails the gate.
    #[test]
    fn review_patch_path_override() {
        let mut meta = parse_metadata(ROLES.as_bytes()).unwrap();
        // Turn shared, a dependency of the registry crate alpha, into a path
        // package, which is what [patch.crates-io] shared = { path = .. } does.
        for p in &mut meta.packages {
            if p.name == "shared" {
                p.source = None;
                p.manifest_path = "/repo/vendor/shared/Cargo.toml".into();
            }
        }
        let agg = aggregate(&[ctx(&meta, ProjectKind::Workspace, true)], &roots());
        let hits: Vec<_> = agg
            .findings
            .iter()
            .filter(|f| f.code == "registry-to-path" && f.severity == Severity::Error)
            .collect();
        assert!(!hits.is_empty(), "{:?}", agg.findings);
        assert!(hits[0].message.contains("shared 1.0.0"), "{hits:?}");
    }

    /// ADR-001, ADR-002: the features enabled on each root are collected
    /// over every context.
    #[test]
    fn root_features_are_the_union_over_contexts() {
        let agg = run(REAL, ProjectKind::Workspace);
        let rustls = agg.root_features.get("rustls").unwrap();
        assert!(rustls.contains("aws_lc_rs"), "{rustls:?}");
        assert!(!rustls.contains("tls12"), "{rustls:?}");
        assert!(agg.root_features.contains_key("tokio"));
        assert!(!agg.root_features.contains_key("subtle"));
    }

    /// TH-15, ADR-001, ADR-002: the real workspace graph on x86_64 Linux,
    /// trimmed to the fields deps-check reads. It matches `cargo tree -e
    /// normal,build`, which omits ring, getrandom 0.2.17 and cfg-if.
    #[test]
    fn th15_real_workspace_graph() {
        let agg = run(REAL, ProjectKind::Workspace);
        let got: Vec<String> = agg
            .usage
            .iter()
            .map(|((n, v), u)| format!("{n} {v} {}", u.role.label()))
            .collect();
        let want = [
            "aws-lc-rs 1.18.2 runtime",
            "aws-lc-sys 0.46.0 runtime",
            "cc 1.10.0 build",
            "cmake 0.1.58 build",
            "dunce 1.0.5 build",
            "find-msvc-tools 0.1.15 build",
            "fs_extra 1.3.0 build",
            "jobserver 0.1.35 build",
            "libc 0.2.191 runtime",
            "mio 1.2.4 runtime",
            "once_cell 1.21.4 runtime",
            "pin-project-lite 0.2.17 runtime",
            "pkg-config 0.3.34 build",
            "rustls 0.23.46 runtime",
            "rustls-pki-types 1.15.1 runtime",
            "rustls-webpki 0.103.16 runtime",
            "shlex 2.0.1 build",
            "socket2 0.6.5 runtime",
            "subtle 2.6.1 runtime",
            "tokio 1.54.1 runtime",
            "untrusted 0.9.0 runtime",
            "zeroize 1.9.1 runtime",
        ];
        assert_eq!(got, want);
        assert!(
            agg.excluded
                .contains_key(&("ring".to_owned(), "0.17.14".to_owned()))
        );
        let libc = agg
            .usage
            .get(&("libc".to_owned(), "0.2.191".to_owned()))
            .unwrap();
        assert_eq!(
            libc.adrs,
            BTreeSet::from(["ADR-001".to_owned(), "ADR-002".to_owned()])
        );
        assert!(
            agg.findings.iter().all(|f| f.severity != Severity::Error),
            "{:?}",
            agg.findings
        );
        // libfuzzer-sys is a root, but only fuzz projects use it.
        assert!(
            agg.findings
                .iter()
                .any(|f| f.code == "stale-root" && f.message.contains("libfuzzer-sys")),
            "{:?}",
            agg.findings
        );
    }

    // ---- property: classification equals a path-enumerating reference ----

    #[derive(Clone, Debug)]
    struct RandEdge {
        from: usize,
        to: usize,
        kind: DepKind,
        optional: bool,
        enabled: bool,
    }

    /// Builds metadata for a DAG: node 0 is the only member, edges go from a
    /// lower to a higher index.
    fn dag_metadata(n: usize, edges: &[RandEdge]) -> Metadata {
        let mut meta = Metadata {
            workspace_root: "/repo".into(),
            members: vec![0],
            ..Metadata::default()
        };
        for i in 0..n {
            let name = format!("p{i}");
            let mut features = BTreeMap::new();
            let mut enabled = Vec::new();
            let mut deps = Vec::new();
            let mut node_deps: Vec<NodeDep> = Vec::new();
            for e in edges.iter().filter(|e| e.from == i) {
                let dep_name = format!("p{}", e.to);
                // Each edge gets its own rename key so features stay per edge.
                let key = format!("k{}_{}_{}", e.from, e.to, e.kind.label());
                deps.push(DepDecl {
                    name: dep_name,
                    rename: Some(key.clone()),
                    kind: e.kind,
                    optional: e.optional,
                });
                if e.optional {
                    let feat = format!("f_{key}");
                    features.insert(feat.clone(), vec![format!("dep:{key}")]);
                    // A weak reference never activates anything.
                    features.insert(format!("w_{key}"), vec![format!("{key}?/x")]);
                    enabled.push(format!("w_{key}"));
                    if e.enabled {
                        enabled.push(feat);
                    }
                }
                match node_deps.iter_mut().find(|d| d.pkg == e.to) {
                    Some(d) => {
                        if !d.kinds.contains(&e.kind) {
                            d.kinds.push(e.kind);
                        }
                    }
                    None => node_deps.push(NodeDep {
                        pkg: e.to,
                        kinds: vec![e.kind],
                    }),
                }
            }
            meta.packages.push(Package {
                id: name.clone(),
                name,
                version: "1.0.0".into(),
                source: Some(CRATES_IO[0].into()),
                manifest_path: format!("/x/p{i}/Cargo.toml"),
                features,
                dependencies: deps,
                targets: vec![],
                cargo_fuzz: false,
            });
            meta.node_of_pkg.insert(i, i);
            meta.nodes.push(Node {
                pkg: i,
                deps: node_deps,
                features: enabled,
            });
        }
        meta
    }

    /// Reference semantics: the best role over every path of built edges.
    fn reference(n: usize, edges: &[RandEdge]) -> BTreeMap<usize, Role> {
        fn walk(
            at: usize,
            role: Role,
            edges: &[RandEdge],
            best: &mut BTreeMap<usize, Role>,
            depth: usize,
        ) {
            let slot = best.entry(at).or_insert(role);
            if role > *slot {
                *slot = role;
            }
            if depth > 16 {
                return;
            }
            for e in edges.iter().filter(|e| e.from == at) {
                if e.optional && !e.enabled {
                    continue;
                }
                let next = match e.kind {
                    DepKind::Normal => role,
                    DepKind::Build => {
                        if role == Role::Runtime {
                            Role::Build
                        } else {
                            role
                        }
                    }
                    DepKind::Dev => Role::Test,
                };
                walk(e.to, next, edges, best, depth.saturating_add(1));
            }
        }
        let mut best = BTreeMap::new();
        if n > 0 {
            walk(0, Role::Runtime, edges, &mut best, 0);
        }
        best
    }

    /// ADR-003, R-NF-07: on random DAGs with optional, weak and differently
    /// kinded edges, role propagation equals exhaustive path enumeration.
    #[test]
    fn r_nf_07_classification_matches_reference() {
        fstp_prop::check("r_nf_07_classification_matches_reference", |g| {
            let n = g.usize_in(1..=7);
            let mut edges = Vec::new();
            let count = g.usize_in(0..=14);
            for _ in 0..count {
                let last = n.saturating_sub(1);
                let from = g.usize_in(0..=last);
                if from >= last {
                    continue;
                }
                let to = g.usize_in(from.saturating_add(1)..=last);
                let kind = *g.pick(&[DepKind::Normal, DepKind::Build, DepKind::Dev]);
                // Cargo forbids optional dev-dependencies.
                let optional = kind != DepKind::Dev && g.bool();
                let enabled = g.bool();
                if edges
                    .iter()
                    .any(|e: &RandEdge| e.from == from && e.to == to && e.kind == kind)
                {
                    continue;
                }
                edges.push(RandEdge {
                    from,
                    to,
                    kind,
                    optional,
                    enabled,
                });
            }
            g.note("edges", &edges);
            let meta = dag_metadata(n, &edges);
            let graph = Graph::new(&meta);
            let got = classify(&meta, &graph, Role::Runtime).roles;
            let want = reference(n, &edges);
            fstp_prop::prop_assert_eq!(got, want);
            Ok(())
        });
    }
}
