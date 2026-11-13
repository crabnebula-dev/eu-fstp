//! The layering gate of the M3 crates (`docs/handoff/m3-design.md` section
//! 2.4).
//!
//! It reuses the reach logic of `layering.rs` and adds these rules. Each
//! finding code starts with `layering-m3-`.
//!
//! 1. `pure-io`: the pure cores reach no I/O crate and no runtime.
//! 2. `vault`: the vault crates reach no domain crate, and no crate outside
//!    `fstp-vault` reaches `fstp-vault-core`, except the test-only
//!    `fstp-celltest`.
//! 3. `composer`: only `fstp-cell` reaches both `fstp-cell-core` and
//!    `fstp-pgstore`.
//! 4. `control-plane`: the control-plane crates reach no crate that defines
//!    tenant records, account types or vault data (I-19, I-20).
//! 5. `edge-tls`: a source scan refuses a TLS server configuration in
//!    `fstp-edge` (I-19). Every `fstp_tls` path there, grouped or not, must
//!    name the client API. An alias, a glob and a renamed dependency fail.
//! 6. `i39`: only `fstp-cell` and `fstp-release-svc` reach `fstp-release`.
//!    The test-only `fstp-celltest` may too, since it tests I-39.
//! 7. `i80`: a source scan allows `RootMaterial` only in `fstp-keyd` and
//!    `fstp-celltest`, and only the listed crates reach `fstp-custody`.
//! 8. `tier-b`: moduletto is reachable only through `fstp-crypto` (I-74,
//!    I-75). Each other member's graph is walked without entering
//!    `fstp-crypto`. Any moduletto package it still reaches fails, and so
//!    does any git package from moduletto's repository URL, at any commit.
//! 9. `test-only`: no crate takes `fstp-celltest` as a normal or build
//!    dependency. Source scans refuse the vault seeding identifiers and the
//!    aws-lc-rs post-quantum oracles outside `fstp-celltest`. The oracle
//!    scan reads every file of a crate that names aws-lc-rs anywhere. A
//!    public re-export of the aws-lc-rs crate and a renamed aws-lc-rs
//!    dependency fail too.
//!
//! Rule 10 lives in `runtime.rs`, rule 11 in `funds.rs`, and rule 12 is the
//! M2 gate in `layering.rs`, which stands unchanged except that
//! `fstp-celltest` joins the test-only crates.
//!
//! Rules 2, 6, 7 and 9 exempt only the crates each one names. Rule 3
//! exempts the test-only crates `fstp-celltest`, `fstp-domain-testkit` and
//! `fstp-api-testkit`, which never ship. The source scans read every file
//! that can ship with a workspace member: every `.rs` file of its package
//! directory outside `tests/`, `benches/`, `examples/`, `fuzz/` and
//! `target/`, each shipped target root, and every file a `mod`,
//! `#[path]` or `include!` loads from those, wherever it lies (see
//! [`member_sources`]). They skip deps-check itself, whose rules hold the
//! scanned names as data.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};

use crate::git_source;
use crate::layering::{ANY_KIND, SHIPPED, hits, members, reach, render_path};
use crate::metadata::{DepKind, Metadata};
use crate::report::Finding;

/// The test-only crates, which never ship.
pub(crate) const TEST_ONLY: [&str; 2] = ["fstp-celltest", "fstp-domain-testkit"];
/// The isolation harness.
const CELLTEST: &str = "fstp-celltest";
/// The crate whose sources hold the scanned names as rule data.
pub(crate) const SCANNER: &str = "deps-check";

/// Rule 1: the pure cores.
const PURE_CORES: [&str; 9] = [
    "fstp-keys",
    "fstp-audit",
    "fstp-vault-proto",
    "fstp-vault-core",
    "fstp-webauthn",
    "fstp-auth",
    "fstp-cell-core",
    "fstp-cp-proto",
    "fstp-pki",
];
/// Rule 1: what a pure core may not reach. smol joins tokio, since ADR-002
/// allowlists both runtimes.
const IO_CRATES: [&str; 8] = [
    "fstp-rt",
    "fstp-http",
    "fstp-tls",
    "fstp-pgwire",
    "fstp-pgtest",
    "fstp-migrate",
    "tokio",
    "smol",
];

/// Rule 2: the vault crates.
const VAULT_CRATES: [&str; 3] = ["fstp-vault", "fstp-vault-core", "fstp-vault-proto"];
/// Rule 2: what a vault crate may not reach.
const DOMAIN_SIDE: [&str; 4] = [
    "fstp-domain",
    "fstp-engine",
    "fstp-findings",
    "fstp-cell-core",
];
/// Rule 2: the vault core and the crates that may reach it.
const VAULT_CORE: &str = "fstp-vault-core";
const VAULT_CORE_USERS: [&str; 2] = ["fstp-vault", CELLTEST];

/// Rule 3: the composer and the two crates only it combines.
const COMPOSER: &str = "fstp-cell";
const CORE: &str = "fstp-cell-core";
const STORE: &str = "fstp-pgstore";
/// Rule 3: the M4 test kit composes a test cell (its demo cell runs the real
/// timeline and dispatcher). It is test only (M4 design section 1.3, rule
/// A9) and never ships.
const API_TESTKIT: &str = "fstp-api-testkit";

/// Rule 4: the control-plane crates.
const CONTROL_PLANE: [&str; 6] = [
    "fstp-control",
    "fstp-cp-proto",
    "fstp-witness",
    "fstp-edge",
    "fstp-release",
    "fstp-release-svc",
];
/// Rule 4: the crates that define tenant records, account types or vault data.
const TENANT_CRATES: [&str; 9] = [
    "fstp-domain",
    "fstp-engine",
    "fstp-findings",
    "fstp-auth",
    "fstp-cell-core",
    "fstp-pgstore",
    "fstp-vault",
    "fstp-vault-core",
    "fstp-vault-proto",
];

/// Rule 5: the edge and the names of a TLS server configuration.
const EDGE: &str = "fstp-edge";
const SERVER_TLS: [&str; 4] = [
    "ServerConfig",
    "ServerConnection",
    "fstp_tls::accept",
    "rustls::server",
];
/// Rule 5: the crate name the edge scan reads, and the names of the fstp-tls
/// client API. Every `fstp_tls` path in `fstp-edge` must name one of these.
/// `accept`, `ServerConfig` and `ServerConfigBuilder` are the server API.
const TLS_CRATE: &str = "fstp_tls";
const CLIENT_TLS: [&str; 12] = [
    "ClientConfig",
    "ClientConfigBuilder",
    "connect",
    "TlsStream",
    "TlsError",
    "TlsErrorKind",
    "PemLimits",
    "MAX_ALPN_LEN",
    "MAX_ALPN_PROTOCOLS",
    "CIPHER_SUITES",
    "KEY_EXCHANGE_GROUPS",
    "MAX_RESUMPTION_AGE",
];

/// Rule 6: the release crate and the crates that may reach it.
const RELEASE: &str = "fstp-release";
const RELEASE_USERS: [&str; 3] = ["fstp-cell", "fstp-release-svc", CELLTEST];

/// Rule 7: the root material identifier and where it may appear.
const ROOT_MATERIAL: &str = "RootMaterial";
const ROOT_MATERIAL_CRATES: [&str; 2] = ["fstp-keyd", CELLTEST];
/// Rule 7: custody and the crates that may reach it. The witness opens its
/// receipt key through its own fstp-keyd entry (Daniel, 2026-11-13,
/// m3-finish Q-D; ADR-004 ControlPlane row).
const CUSTODY: &str = "fstp-custody";
const CUSTODY_USERS: [&str; 7] = [
    "fstp-cell",
    "fstp-vault",
    "fstp-control",
    "fstp-witness",
    "fstp-backup",
    "fstp-keyd",
    CELLTEST,
];

/// Rule 8: the Tier B crate and the only crate that may depend on it.
const MODULETTO: &str = "moduletto";
const CRYPTO: &str = "fstp-crypto";

/// Rule 9: the identifiers of the vault seeding path.
const SEED_NAMES: [&str; 2] = ["SeedSource", "seed_fact"];
/// Rule 9: the aws-lc-rs post-quantum APIs, test oracles only.
const PQ_ORACLES: [&str; 8] = [
    "ML_KEM_512",
    "ML_KEM_768",
    "ML_KEM_1024",
    "ML_DSA_44",
    "ML_DSA_65",
    "ML_DSA_87",
    "PqdsaKeyPair",
    "aws_lc_rs::kem",
];
/// Rule 9: a crate names the oracles only when one of its files names
/// aws-lc-rs, so the oracle scan reads every file of such a crate.
const AWS_LC: &str = "aws_lc_rs";
/// Rule 9: the package name of aws-lc-rs, which no member but
/// `fstp-celltest` may rename.
const AWS_LC_PACKAGE: &str = "aws-lc-rs";

/// The target kinds that ship with a crate. Tests, benches and examples
/// do not.
const SHIPPED_TARGETS: [&str; 8] = [
    "lib",
    "rlib",
    "dylib",
    "cdylib",
    "staticlib",
    "proc-macro",
    "bin",
    "custom-build",
];

/// Upper bound on the size of one scanned source file.
const MAX_SOURCE: u64 = 8 << 20;
/// Upper bound on directory depth below a package directory.
const MAX_DEPTH: usize = 32;
/// Upper bound on the source files read for one crate.
const MAX_FILES: usize = 20_000;
/// The top-level directories of a package that hold no shipped code:
/// integration tests, benches, examples, the fuzz project and build output.
const UNSHIPPED_DIRS: [&str; 5] = ["tests", "benches", "examples", "fuzz", "target"];

/// Runs the graph rules over one workspace context.
pub(crate) fn check(meta: &Metadata) -> Vec<Finding> {
    let mut out = Vec::new();
    let members = members(meta);

    // Rule 1.
    for krate in PURE_CORES {
        let Some(&start) = members.get(krate) else {
            continue;
        };
        let parent = reach(meta, start, &ANY_KIND);
        for (io, pkg) in hits(meta, &parent, &IO_CRATES) {
            out.push(Finding::error(
                "layering-m3-pure-io",
                format!(
                    "{krate} depends on {io} ({}); the M3 pure cores do no I/O (design section 2.4 rule 1)",
                    render_path(meta, &parent, start, pkg)
                ),
            ));
        }
    }

    // Rule 2.
    for krate in VAULT_CRATES {
        let Some(&start) = members.get(krate) else {
            continue;
        };
        let parent = reach(meta, start, &ANY_KIND);
        for (side, pkg) in hits(meta, &parent, &DOMAIN_SIDE) {
            out.push(Finding::error(
                "layering-m3-vault",
                format!(
                    "{krate} depends on {side} ({}); the vault crates reach no domain crate (design section 2.4 rule 2)",
                    render_path(meta, &parent, start, pkg)
                ),
            ));
        }
    }
    reached_only_by(
        meta,
        &members,
        VAULT_CORE,
        &VAULT_CORE_USERS,
        &ANY_KIND,
        "layering-m3-vault",
        "only fstp-vault, and the test-only fstp-celltest, may reach it (design section 2.4 rule 2)",
        &mut out,
    );

    // Rule 3.
    for (&krate, &start) in &members {
        if krate == COMPOSER || krate == API_TESTKIT || TEST_ONLY.contains(&krate) {
            continue;
        }
        let parent = reach(meta, start, &SHIPPED);
        let found = hits(meta, &parent, &[CORE, STORE]);
        if let [(_, core), (_, store)] = found.as_slice() {
            out.push(Finding::error(
                "layering-m3-composer",
                format!(
                    "{krate} reaches both {CORE} ({}) and {STORE} ({}); only {COMPOSER} composes them (design section 2.4 rule 3)",
                    render_path(meta, &parent, start, *core),
                    render_path(meta, &parent, start, *store)
                ),
            ));
        }
    }

    // Rule 4.
    for krate in CONTROL_PLANE {
        let Some(&start) = members.get(krate) else {
            continue;
        };
        let parent = reach(meta, start, &ANY_KIND);
        for (tenant, pkg) in hits(meta, &parent, &TENANT_CRATES) {
            out.push(Finding::error(
                "layering-m3-control-plane",
                format!(
                    "{krate} depends on {tenant} ({}); the control plane cannot decode tenant data (I-19, I-20, design section 2.4 rule 4)",
                    render_path(meta, &parent, start, pkg)
                ),
            ));
        }
    }

    // Rule 6.
    reached_only_by(
        meta,
        &members,
        RELEASE,
        &RELEASE_USERS,
        &ANY_KIND,
        "layering-m3-i39",
        "only fstp-cell and fstp-release-svc, and the test-only fstp-celltest, may reach it, so no command path depends on the licence (I-39, design section 2.4 rule 6)",
        &mut out,
    );

    // Rule 7, reach.
    reached_only_by(
        meta,
        &members,
        CUSTODY,
        &CUSTODY_USERS,
        &ANY_KIND,
        "layering-m3-i80",
        "only fstp-cell, fstp-vault, fstp-control, fstp-witness, fstp-backup, fstp-keyd and fstp-celltest may reach it (I-80, design section 2.4 rule 7)",
        &mut out,
    );

    // Rule 8. moduletto is reachable only through fstp-crypto, whatever the
    // workspace. Each other member's graph is walked without stepping into
    // fstp-crypto, and any Tier B package it still reaches is reported. A
    // package from moduletto's repository, at any commit, counts as Tier B
    // too, since ADR-001 A3 admits further packages from that repository.
    let tier_b = tier_b_packages(meta);
    for (&krate, &start) in &members {
        if krate == CRYPTO || tier_b.contains(&start) {
            continue;
        }
        let parent = reach_avoiding(meta, start, &ANY_KIND, &[CRYPTO]);
        for &pkg in parent.keys().filter(|p| tier_b.contains(p)) {
            out.push(Finding::error(
                "layering-m3-tier-b",
                format!(
                    "{krate} reaches the Tier B package {} ({}) around {CRYPTO}; {MODULETTO} is reachable only through {CRYPTO} (I-74, I-75, design section 2.4 rule 8)",
                    meta.packages.get(pkg).map_or("?", |p| p.name.as_str()),
                    render_path(meta, &parent, start, pkg)
                ),
            ));
        }
    }

    // Rule 9, graph.
    reached_only_by(
        meta,
        &members,
        CELLTEST,
        &[],
        &SHIPPED,
        "layering-m3-test-only",
        "it is test only and never ships, so no crate takes it as a normal or build dependency (design section 2.4 rule 9)",
        &mut out,
    );

    // Rules 5 and 9, names. The source scans match the crate names
    // `fstp_tls` and `aws_lc_rs`, so neither crate may be renamed where the
    // scan reads it.
    refuse_renames(
        meta,
        &members,
        Some(EDGE),
        "fstp-tls",
        &[],
        "layering-m3-edge-tls",
        "the edge TLS scan reads the name fstp_tls (I-19, design section 2.4 rule 5)",
        &mut out,
    );
    refuse_renames(
        meta,
        &members,
        None,
        AWS_LC_PACKAGE,
        &[CELLTEST],
        "layering-m3-test-only",
        "the post-quantum oracle scan reads the name aws_lc_rs (design section 2.4 rule 9, ADR-001 A6)",
        &mut out,
    );
    out
}

/// Reports every member outside `allowed` that reaches `target`, with the
/// first step out of the member over `first`. Only the crates each rule
/// names in `allowed` are exempt.
#[allow(
    clippy::too_many_arguments,
    reason = "one call per rule reads better than a struct per rule"
)]
fn reached_only_by(
    meta: &Metadata,
    members: &BTreeMap<&str, usize>,
    target: &str,
    allowed: &[&str],
    first: &[DepKind],
    code: &'static str,
    why: &str,
    out: &mut Vec<Finding>,
) {
    for (&krate, &start) in members {
        if krate == target || allowed.contains(&krate) {
            continue;
        }
        let parent = reach(meta, start, first);
        for (_, pkg) in hits(meta, &parent, &[target]) {
            out.push(Finding::error(
                code,
                format!(
                    "{krate} reaches {target} ({}); {why}",
                    render_path(meta, &parent, start, pkg)
                ),
            ));
        }
    }
}

/// The packages rule 8 confines: every package named moduletto, and every
/// git package from the repository URL of one, at any commit (ADR-001 A3).
fn tier_b_packages(meta: &Metadata) -> BTreeSet<usize> {
    let repos: BTreeSet<&str> = meta
        .packages
        .iter()
        .filter(|p| p.name == MODULETTO)
        .filter_map(|p| p.source.as_deref())
        .filter_map(git_source::repo_url)
        .collect();
    meta.packages
        .iter()
        .enumerate()
        .filter(|(_, p)| {
            p.name == MODULETTO
                || p.source
                    .as_deref()
                    .and_then(git_source::repo_url)
                    .is_some_and(|u| repos.contains(u))
        })
        .map(|(i, _)| i)
        .collect()
}

/// The same walk as `reach`, except that it never steps into a package
/// named in `avoid`, so everything it returns is reached around them.
fn reach_avoiding(
    meta: &Metadata,
    start: usize,
    first: &[DepKind],
    avoid: &[&str],
) -> BTreeMap<usize, usize> {
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
            let avoided = meta
                .packages
                .get(dep.pkg)
                .is_some_and(|p| avoid.contains(&p.name.as_str()));
            if !avoided && dep.kinds.iter().any(|k| kinds.contains(k)) {
                parent.insert(dep.pkg, pkg);
                queue.push_back(dep.pkg);
            }
        }
    }
    parent
}

/// Reports every member outside `exempt` that declares the package `dep`
/// under another name. A source scan that looks for the crate's own name
/// would miss every path through the new name.
#[allow(
    clippy::too_many_arguments,
    reason = "one call per rule reads better than a struct per rule"
)]
fn refuse_renames(
    meta: &Metadata,
    members: &BTreeMap<&str, usize>,
    only: Option<&str>,
    dep: &str,
    exempt: &[&str],
    code: &'static str,
    why: &str,
    out: &mut Vec<Finding>,
) {
    for (&krate, &i) in members {
        if exempt.contains(&krate) || only.is_some_and(|o| o != krate) {
            continue;
        }
        let Some(pkg) = meta.packages.get(i) else {
            continue;
        };
        for d in pkg.dependencies.iter().filter(|d| d.name == dep) {
            if let Some(rename) = &d.rename {
                out.push(Finding::error(
                    code,
                    format!(
                        "{krate} declares {dep} under the name `{rename}` ({} dependency); {why}",
                        d.kind.label()
                    ),
                ));
            }
        }
    }
}

/// One source file of a workspace member.
pub(crate) struct SourceFile {
    /// The package name.
    pub(crate) krate: String,
    /// The path relative to the workspace root.
    pub(crate) rel: String,
    /// The text, with invalid UTF-8 replaced.
    pub(crate) text: String,
}

/// Collects the `.rs` files under `dir`, in order. A symlinked `.rs` file
/// is followed, since cargo compiles its target. A symlinked directory is
/// not entered, and the repository check refuses it. A subdirectory with
/// its own `Cargo.toml` is another package and is skipped. So is each name
/// in `skip`, directly below `dir` only.
fn collect_rs(
    dir: &Path,
    depth: usize,
    skip: &[&str],
    out: &mut Vec<PathBuf>,
    findings: &mut Vec<Finding>,
) {
    if depth > MAX_DEPTH {
        findings.push(Finding::error(
            "scan-limit",
            format!("{} is nested deeper than {MAX_DEPTH} levels", dir.display()),
        ));
        return;
    }
    let Ok(reader) = fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<PathBuf> = reader.flatten().map(|e| e.path()).collect();
    entries.sort();
    for p in entries {
        let Ok(meta) = fs::symlink_metadata(&p) else {
            continue;
        };
        let rs = p.extension().is_some_and(|e| e == "rs");
        if meta.is_dir() {
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if skip.contains(&name) || p.join("Cargo.toml").exists() {
                continue;
            }
            collect_rs(&p, depth.saturating_add(1), &[], out, findings);
        } else if rs && (meta.is_file() || fs::metadata(&p).is_ok_and(|m| m.is_file())) {
            out.push(p);
        }
    }
}

/// What one source file loads from other files.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ModRefs {
    /// Every file a `mod name;` declaration, a `#[path]` attribute or an
    /// `include!` may load. Each reading of the module rules gives one
    /// candidate, so the list may name files that do not exist.
    pub(crate) candidates: Vec<PathBuf>,
    /// A `#[path]` value or an `include!` argument that is not a plain
    /// string literal, as a line and a description.
    pub(crate) unresolved: Vec<(usize, String)>,
}

/// Whether `l` is a string literal the module rules can read as a path.
fn plain_path(l: &Lexeme<'_>) -> bool {
    l.kind == LexKind::Str && !l.s.contains('\\') && !l.s.is_empty()
}

/// The files that `file`, lexed as `lx`, loads. This follows the Rust
/// module rules loosely and errs towards more candidates: a module file
/// may sit beside the declaring file or in a directory named after it,
/// below any inline modules around the declaration.
pub(crate) fn module_refs(lx: &[Lexeme<'_>], file: &Path) -> ModRefs {
    let mut out = ModRefs::default();
    let fdir = file.parent().map(Path::to_path_buf).unwrap_or_default();
    let stem = file.file_stem().map(PathBuf::from).unwrap_or_default();
    let bases = [fdir.clone(), fdir.join(&stem)];
    let is = |j: usize, kind: LexKind, text: &str| {
        lx.get(j).is_some_and(|l| l.kind == kind && l.s == text)
    };
    let mut depth = 0usize;
    // Inline modules around the current position, with the brace depth at
    // which each opened.
    let mut inline: Vec<(PathBuf, usize)> = Vec::new();
    // `#[path]` values waiting for the next item.
    let mut pending: Vec<&str> = Vec::new();
    let mut i = 0usize;
    while let Some(l) = lx.get(i) {
        if is(i, LexKind::Punct, "#") {
            let mut j = i.saturating_add(1);
            if is(j, LexKind::Punct, "!") {
                j = j.saturating_add(1);
            }
            if is(j, LexKind::Punct, "[") {
                let mut brackets = 0usize;
                while let Some(a) = lx.get(j) {
                    if a.kind == LexKind::Punct && a.s == "[" {
                        brackets = brackets.saturating_add(1);
                    } else if a.kind == LexKind::Punct && a.s == "]" {
                        brackets = brackets.saturating_sub(1);
                        if brackets == 0 {
                            break;
                        }
                    } else if a.kind == LexKind::Ident
                        && a.s == "path"
                        && is(j.saturating_add(1), LexKind::Punct, "=")
                    {
                        match lx.get(j.saturating_add(2)) {
                            Some(v) if plain_path(v) => pending.push(v.s),
                            _ => out.unresolved.push((
                                a.line,
                                "a `path` attribute whose value is not a plain string literal"
                                    .to_owned(),
                            )),
                        }
                    }
                    j = j.saturating_add(1);
                }
                i = j.saturating_add(1);
                continue;
            }
        }
        let next_ident = lx
            .get(i.saturating_add(1))
            .filter(|n| n.kind == LexKind::Ident);
        match (l.kind, l.s, next_ident) {
            (LexKind::Ident, "mod", Some(n)) => {
                let name = n.s;
                let inl: PathBuf = inline.iter().map(|(c, _)| c.as_path()).collect();
                if is(i.saturating_add(2), LexKind::Punct, ";") {
                    if pending.is_empty() {
                        for b in &bases {
                            let d = b.join(&inl);
                            out.candidates.push(d.join(format!("{name}.rs")));
                            out.candidates.push(d.join(name).join("mod.rs"));
                        }
                    } else if inline.is_empty() {
                        out.candidates.extend(pending.iter().map(|p| fdir.join(p)));
                    } else {
                        for p in &pending {
                            out.candidates
                                .extend(bases.iter().map(|b| b.join(&inl).join(p)));
                        }
                    }
                    pending.clear();
                    i = i.saturating_add(3);
                    continue;
                }
                if is(i.saturating_add(2), LexKind::Punct, "{") {
                    let comp = pending
                        .first()
                        .map_or_else(|| PathBuf::from(name), PathBuf::from);
                    inline.push((comp, depth));
                    pending.clear();
                    i = i.saturating_add(2);
                    continue;
                }
            }
            (LexKind::Ident, "include", _) if is(i.saturating_add(1), LexKind::Punct, "!") => {
                let open = i.saturating_add(2);
                let arg = lx.get(open.saturating_add(1));
                let close = lx.get(open.saturating_add(2));
                let opens = ["(", "[", "{"].iter().any(|o| is(open, LexKind::Punct, o));
                let closes = close
                    .is_some_and(|c| c.kind == LexKind::Punct && matches!(c.s, ")" | "]" | "}"));
                match arg {
                    Some(v) if opens && closes && plain_path(v) => {
                        out.candidates.push(fdir.join(v.s));
                    }
                    _ => out.unresolved.push((
                        l.line,
                        "an `include!` whose argument is not a plain string literal".to_owned(),
                    )),
                }
            }
            (LexKind::Punct, "{", _) => {
                depth = depth.saturating_add(1);
                pending.clear();
            }
            (LexKind::Punct, "}", _) => {
                depth = depth.saturating_sub(1);
                while inline.last().is_some_and(|(_, d)| *d >= depth) {
                    inline.pop();
                }
                pending.clear();
            }
            (LexKind::Punct, ";", _) => pending.clear(),
            _ => {}
        }
        i = i.saturating_add(1);
    }
    out
}

/// The shipped sources of every workspace member except deps-check.
///
/// The scan starts from every `.rs` file in the package directory, except
/// below `tests/`, `benches/`, `examples/`, `fuzz/` and `target/`, and from
/// every shipped target root that cargo metadata reports, with the
/// directory tree below it. It then follows each `mod` declaration,
/// `#[path]` attribute and `include!` of every file it reads, wherever the
/// file lies, so a module loaded from another directory is read too. A
/// symlinked `.rs` file is read through the link. A `#[path]` or
/// `include!` whose value is not a plain string literal is refused, and so
/// is a shipped root outside the package directory.
pub(crate) fn member_sources(meta: &Metadata, findings: &mut Vec<Finding>) -> Vec<SourceFile> {
    let root = Path::new(&meta.workspace_root);
    let mut out = Vec::new();
    for (&krate, &i) in &members(meta) {
        if krate == SCANNER {
            continue;
        }
        let Some(pkg) = meta.packages.get(i) else {
            continue;
        };
        let Some(dir) = Path::new(&pkg.manifest_path).parent() else {
            continue;
        };
        let mut start = Vec::new();
        collect_rs(dir, 0, &UNSHIPPED_DIRS, &mut start, findings);
        let shipped = pkg.targets.iter().filter(|t| {
            t.kinds
                .iter()
                .any(|k| SHIPPED_TARGETS.contains(&k.as_str()))
        });
        for t in shipped {
            let target_root = PathBuf::from(&t.src_path);
            let Some(parent) = target_root
                .strip_prefix(dir)
                .ok()
                .and_then(|_| target_root.parent())
            else {
                findings.push(Finding::error(
                    "scan-target-root",
                    format!(
                        "{krate} ships the target {} from {}, outside its package directory; the M3 source scans read only the package's own files (design section 2.4)",
                        t.name, t.src_path
                    ),
                ));
                continue;
            };
            if parent != dir {
                collect_rs(parent, 0, &[], &mut start, findings);
            }
            start.push(target_root);
        }
        let mut q = Queue {
            seen: BTreeSet::new(),
            queue: VecDeque::new(),
        };
        for p in start {
            q.add(p, krate, findings);
        }
        let mut files: Vec<(PathBuf, String)> = Vec::new();
        while let Some(f) = q.queue.pop_front() {
            let rel = f.strip_prefix(root).unwrap_or(&f).display().to_string();
            let Some(text) = read_source(&f, &rel, findings) else {
                continue;
            };
            let refs = module_refs(&lex(&text).lexemes, &f);
            for (line, what) in refs.unresolved {
                findings.push(Finding::error(
                    "scan-module-path",
                    format!(
                        "{krate} has {what} in {rel}:{line}; the M3 source scans must read every file a crate loads (design section 2.4)"
                    ),
                ));
            }
            for c in refs.candidates {
                if fs::metadata(&c).is_ok_and(|m| m.is_file()) {
                    q.add(c, krate, findings);
                }
            }
            files.push((f, text));
        }
        files.sort();
        for (f, text) in files {
            let rel = f.strip_prefix(root).unwrap_or(&f).display().to_string();
            out.push(SourceFile {
                krate: krate.to_owned(),
                rel,
                text,
            });
        }
    }
    out
}

/// Reads one source file within the size bound, or reports why not.
fn read_source(f: &Path, rel: &str, findings: &mut Vec<Finding>) -> Option<String> {
    match fs::metadata(f) {
        Ok(m) if m.len() > MAX_SOURCE => {
            findings.push(Finding::error(
                "scan-limit",
                format!("{rel} is larger than {MAX_SOURCE} bytes"),
            ));
            return None;
        }
        Ok(_) => {}
        Err(e) => {
            findings.push(Finding::error("scan-io", format!("cannot read {rel}: {e}")));
            return None;
        }
    }
    match fs::read(f) {
        Ok(bytes) => Some(String::from_utf8_lossy(&bytes).into_owned()),
        Err(e) => {
            findings.push(Finding::error("scan-io", format!("cannot read {rel}: {e}")));
            None
        }
    }
}

/// The files of one crate still to read. Every file is read once, keyed by
/// its resolved path.
struct Queue {
    seen: BTreeSet<PathBuf>,
    queue: VecDeque<PathBuf>,
}

impl Queue {
    fn add(&mut self, p: PathBuf, krate: &str, findings: &mut Vec<Finding>) {
        let key = fs::canonicalize(&p).unwrap_or_else(|_| p.clone());
        if self.seen.contains(&key) {
            return;
        }
        if self.seen.len() >= MAX_FILES {
            findings.push(Finding::error(
                "scan-limit",
                format!("{krate} loads more than {MAX_FILES} source files"),
            ));
            return;
        }
        self.seen.insert(key);
        self.queue.push_back(p);
    }
}

/// Whether `b` extends a token: an ASCII letter, digit or `_`, or one of
/// `extra`.
fn token_byte(b: u8, extra: &[u8]) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || extra.contains(&b)
}

/// Every occurrence of `needle` in `text`, as a 1-based line number and
/// the whole token around it. A token extends over ASCII letters, digits,
/// `_` and the bytes in `extra`.
pub(crate) fn occurrences(text: &str, needle: &str, extra: &[u8]) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    if needle.is_empty() {
        return out;
    }
    for (i, line) in text.lines().enumerate() {
        let bytes = line.as_bytes();
        let mut from = 0;
        while let Some(found) = line.get(from..).and_then(|rest| rest.find(needle)) {
            let at = from.saturating_add(found);
            let end_needle = at.saturating_add(needle.len());
            let mut start = at;
            while start > 0
                && bytes
                    .get(start.saturating_sub(1))
                    .is_some_and(|&b| token_byte(b, extra))
            {
                start = start.saturating_sub(1);
            }
            let mut end = end_needle;
            while bytes.get(end).is_some_and(|&b| token_byte(b, extra)) {
                end = end.saturating_add(1);
            }
            let token = line.get(start..end).unwrap_or(needle).to_owned();
            out.push((i.saturating_add(1), token));
            from = end_needle;
        }
    }
    out
}

/// One token of a Rust source file: an identifier, `::`, or one other
/// ASCII byte. Comments and string and character literals are dropped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Tok<'a> {
    /// The token text.
    pub(crate) s: &'a str,
    /// The 1-based line.
    pub(crate) line: usize,
}

/// The kind of a lexeme.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LexKind {
    /// An identifier or keyword. A raw identifier `r#name` is `name`.
    Ident,
    /// `::`, or one other ASCII punctuation byte.
    Punct,
    /// The contents of a string literal of any kind, without its prefix,
    /// quotes and hashes. Escapes are left as written.
    Str,
}

/// One lexeme of a Rust source file. Comments and character literals are
/// dropped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Lexeme<'a> {
    /// The text, a slice of the input.
    pub(crate) s: &'a str,
    /// The 1-based line where it starts.
    pub(crate) line: usize,
    /// What it is.
    pub(crate) kind: LexKind,
}

/// The lexemes of one file.
pub(crate) struct Lexed<'a> {
    /// The lexemes, in order.
    pub(crate) lexemes: Vec<Lexeme<'a>>,
    /// Whether every comment and literal was closed before the end.
    pub(crate) closed: bool,
}

/// The lexer state over one file.
struct Lexer<'a> {
    text: &'a str,
    i: usize,
    line: usize,
    out: Vec<Lexeme<'a>>,
    closed: bool,
}

impl<'a> Lexer<'a> {
    fn peek(&self, k: usize) -> Option<u8> {
        self.text.as_bytes().get(self.i.saturating_add(k)).copied()
    }

    /// Steps over one byte, counting lines.
    fn bump(&mut self) {
        if self.peek(0) == Some(b'\n') {
            self.line = self.line.saturating_add(1);
        }
        self.i = self.i.saturating_add(1);
    }

    fn push(&mut self, start: usize, end: usize, line: usize, kind: LexKind) {
        if let Some(s) = self.text.get(start..end) {
            self.out.push(Lexeme { s, line, kind });
        }
    }

    fn ident_end(&self, from: usize) -> usize {
        let b = self.text.as_bytes();
        let mut j = from;
        while b
            .get(j)
            .is_some_and(|x| x.is_ascii_alphanumeric() || *x == b'_')
        {
            j = j.saturating_add(1);
        }
        j
    }

    /// A block comment at `/*`. Rust block comments nest.
    fn block_comment(&mut self) {
        self.i = self.i.saturating_add(2);
        let mut depth = 1usize;
        while let Some(x) = self.peek(0) {
            if x == b'/' && self.peek(1) == Some(b'*') {
                depth = depth.saturating_add(1);
                self.i = self.i.saturating_add(2);
            } else if x == b'*' && self.peek(1) == Some(b'/') {
                depth = depth.saturating_sub(1);
                self.i = self.i.saturating_add(2);
                if depth == 0 {
                    return;
                }
            } else {
                self.bump();
            }
        }
        self.closed = false;
    }

    /// A string with escapes, at its opening quote.
    fn string(&mut self) {
        let line = self.line;
        self.i = self.i.saturating_add(1);
        let start = self.i;
        while let Some(x) = self.peek(0) {
            if x == b'\\' {
                self.bump();
                if self.peek(0).is_some() {
                    self.bump();
                }
                continue;
            }
            if x == b'"' {
                let end = self.i;
                self.i = self.i.saturating_add(1);
                self.push(start, end, line, LexKind::Str);
                return;
            }
            self.bump();
        }
        self.push(start, self.i, line, LexKind::Str);
        self.closed = false;
    }

    /// A raw string body at its first `#` or its quote. Returns false, and
    /// moves nothing, when no quote follows the hashes.
    fn raw_string(&mut self) -> bool {
        let save = self.i;
        let mut hashes = 0usize;
        while self.peek(0) == Some(b'#') {
            hashes = hashes.saturating_add(1);
            self.i = self.i.saturating_add(1);
        }
        if self.peek(0) != Some(b'"') {
            self.i = save;
            return false;
        }
        let line = self.line;
        self.i = self.i.saturating_add(1);
        let start = self.i;
        while let Some(x) = self.peek(0) {
            if x == b'"' && (1..=hashes).all(|h| self.peek(h) == Some(b'#')) {
                let end = self.i;
                self.i = self.i.saturating_add(1).saturating_add(hashes);
                self.push(start, end, line, LexKind::Str);
                return true;
            }
            self.bump();
        }
        self.push(start, self.i, line, LexKind::Str);
        self.closed = false;
        true
    }

    /// A character literal at its quote, such as 'a' or '\n'. A lifetime
    /// has no closing quote, so it returns false and moves nothing.
    fn char_lit(&mut self) -> bool {
        if !(self.peek(2) == Some(b'\'') || self.peek(1) == Some(b'\\')) {
            return false;
        }
        self.i = self.i.saturating_add(1);
        while let Some(x) = self.peek(0) {
            if x == b'\\' {
                self.bump();
                if self.peek(0).is_some() {
                    self.bump();
                }
                continue;
            }
            self.bump();
            if x == b'\'' {
                return true;
            }
        }
        self.closed = false;
        true
    }

    /// An identifier, or the literal it prefixes: `r"`, `r#"`, `br"`,
    /// `cr"`, `b"`, `c"` and `b'`. A raw identifier `r#name` gives `name`.
    fn ident(&mut self) {
        let start = self.i;
        let end = self.ident_end(start);
        let line = self.line;
        self.i = end;
        let s = self.text.get(start..end).unwrap_or("");
        let next = self.peek(0);
        match (s, next) {
            ("r" | "br" | "cr", Some(b'"' | b'#')) => {
                if self.raw_string() {
                    return;
                }
                if s == "r" && next == Some(b'#') {
                    let from = self.i.saturating_add(1);
                    let to = self.ident_end(from);
                    // A raw identifier starts like any identifier, never
                    // with a digit: `r#2` is `r`, `#` and a number.
                    let starts = self
                        .text
                        .as_bytes()
                        .get(from)
                        .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_' || *b >= 0x80);
                    if to > from && starts {
                        self.i = to;
                        self.push(from, to, line, LexKind::Ident);
                        return;
                    }
                }
            }
            ("b" | "c", Some(b'"')) => {
                self.string();
                return;
            }
            ("b", Some(b'\'')) if self.char_lit() => return,
            _ => {}
        }
        self.push(start, end, line, LexKind::Ident);
    }

    fn run(mut self) -> Lexed<'a> {
        while let Some(c) = self.peek(0) {
            let next = self.peek(1);
            if c == b'\n' {
                self.bump();
            } else if c == b'/' && next == Some(b'/') {
                while self.peek(0).is_some_and(|x| x != b'\n') {
                    self.i = self.i.saturating_add(1);
                }
            } else if c == b'/' && next == Some(b'*') {
                self.block_comment();
            } else if c == b'"' {
                self.string();
            } else if c == b'\'' && self.char_lit() {
                // Consumed.
            } else if c.is_ascii_alphabetic() || c == b'_' {
                self.ident();
            } else if c == b':' && next == Some(b':') {
                let (at, line) = (self.i, self.line);
                self.i = self.i.saturating_add(2);
                self.push(at, self.i, line, LexKind::Punct);
            } else if c.is_ascii_graphic() {
                let (at, line) = (self.i, self.line);
                self.i = self.i.saturating_add(1);
                self.push(at, self.i, line, LexKind::Punct);
            } else {
                self.i = self.i.saturating_add(1);
            }
        }
        Lexed {
            lexemes: self.out,
            closed: self.closed,
        }
    }
}

/// Splits `text` into lexemes. This is a scanner for the source rules, not
/// a Rust parser: it only has to keep identifiers, path punctuation and
/// string contents apart from comments and from each other.
pub(crate) fn lex(text: &str) -> Lexed<'_> {
    Lexer {
        text,
        i: 0,
        line: 1,
        out: Vec::new(),
        closed: true,
    }
    .run()
}

/// Splits `text` into tokens: every lexeme except string contents.
pub(crate) fn tokens(text: &str) -> Vec<Tok<'_>> {
    lex(text)
        .lexemes
        .into_iter()
        .filter(|l| l.kind != LexKind::Str)
        .map(|l| Tok {
            s: l.s,
            line: l.line,
        })
        .collect()
}

/// Every `fstp_tls` path in `toks` that names something other than the
/// client API, as a line and a description. An alias, a glob and an
/// unlisted name are each refused, so a grouped import or a renamed path
/// cannot reach the server API (rule 5).
pub(crate) fn edge_tls_paths(toks: &[Tok<'_>]) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let s = |j: usize| toks.get(j).map_or("", |t| t.s);
    for (i, t) in toks.iter().enumerate() {
        if t.s != TLS_CRATE {
            continue;
        }
        let j = i.saturating_add(1);
        match s(j) {
            "as" => out.push((
                t.line,
                format!("`{TLS_CRATE} as {}`", s(j.saturating_add(1))),
            )),
            "::" => {
                let k = j.saturating_add(1);
                match s(k) {
                    "{" => group_names(toks, k, &mut out),
                    "*" => out.push((t.line, format!("`{TLS_CRATE}::*`"))),
                    name if !CLIENT_TLS.contains(&name) => {
                        out.push((t.line, format!("`{TLS_CRATE}::{name}`")));
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
    out
}

/// Checks the names of a use group that opens at `toks[open]`, at any
/// depth. Each item's first segment must be a client name, or `self`
/// without an alias.
fn group_names(toks: &[Tok<'_>], open: usize, out: &mut Vec<(usize, String)>) {
    let s = |j: usize| toks.get(j).map_or("", |t| t.s);
    let line = |j: usize| toks.get(j).map_or(0, |t| t.line);
    let mut depth = 0usize;
    // Whether the next token starts an item of the outermost group.
    let mut item_start = false;
    let mut i = open;
    while let Some(t) = toks.get(i) {
        match t.s {
            "{" => {
                depth = depth.saturating_add(1);
                item_start = depth == 1;
            }
            "}" => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return;
                }
            }
            "," => item_start = depth == 1,
            name if item_start => {
                item_start = false;
                if name == "*" {
                    out.push((t.line, format!("`{TLS_CRATE}::{{*}}`")));
                } else if name == "self" {
                    if s(i.saturating_add(1)) == "as" {
                        out.push((
                            line(i),
                            format!("`{TLS_CRATE}::{{self as {}}}`", s(i.saturating_add(2))),
                        ));
                    }
                } else if !CLIENT_TLS.contains(&name) {
                    out.push((t.line, format!("`{TLS_CRATE}::{{{name}}}`")));
                }
            }
            _ => {}
        }
        i = i.saturating_add(1);
    }
}

/// Every public re-export of the `aws_lc_rs` crate in `toks`: `pub use
/// aws_lc_rs...` or `pub extern crate aws_lc_rs`. A re-export would let
/// another crate reach the oracles without naming aws-lc-rs (rule 9).
pub(crate) fn aws_lc_reexports(toks: &[Tok<'_>]) -> Vec<usize> {
    let mut out = Vec::new();
    let s = |j: usize| toks.get(j).map_or("", |t| t.s);
    for (i, t) in toks.iter().enumerate() {
        if t.s != "pub" {
            continue;
        }
        let mut j = i.saturating_add(1);
        let reexport = match s(j) {
            "use" => {
                j = j.saturating_add(1);
                if s(j) == "::" {
                    j = j.saturating_add(1);
                }
                s(j) == AWS_LC
            }
            "extern" => s(j.saturating_add(1)) == "crate" && s(j.saturating_add(2)) == AWS_LC,
            _ => false,
        };
        if reexport {
            out.push(t.line);
        }
    }
    out
}

/// One leaf of a `use` tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UseLeaf<'a> {
    /// The path segments. A leading `::` and a `self` segment are dropped,
    /// and a glob ends in `*`.
    pub(crate) segs: Vec<&'a str>,
    /// The name the leaf binds, if any.
    pub(crate) bound: Option<&'a str>,
    /// Whether the `use` item is `pub` without a restriction.
    pub(crate) public: bool,
    /// The line of the `use` keyword.
    pub(crate) line: usize,
}

/// Upper bound on the nesting of use groups.
const MAX_USE_DEPTH: usize = 64;

fn is_ident(s: &str) -> bool {
    s.bytes()
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
}

/// Every leaf of every `use` item in `toks`.
pub(crate) fn use_leaves<'a>(toks: &[Tok<'a>]) -> Vec<UseLeaf<'a>> {
    let mut out = Vec::new();
    for (i, t) in toks.iter().enumerate() {
        if t.s != "use" {
            continue;
        }
        let public = i
            .checked_sub(1)
            .and_then(|j| toks.get(j))
            .is_some_and(|p| p.s == "pub");
        let mut leaves = Vec::new();
        use_tree(toks, i.saturating_add(1), Vec::new(), 0, &mut leaves);
        out.extend(leaves.into_iter().map(|(segs, bound)| UseLeaf {
            segs,
            bound,
            public,
            line: t.line,
        }));
    }
    out
}

/// One parsed leaf: its segments and the name it binds.
type Leaf<'a> = (Vec<&'a str>, Option<&'a str>);

/// Parses one use tree at `toks[pos]` below the segments `segs`, and
/// returns the position after it.
fn use_tree<'a>(
    toks: &[Tok<'a>],
    mut pos: usize,
    mut segs: Vec<&'a str>,
    depth: usize,
    out: &mut Vec<Leaf<'a>>,
) -> usize {
    let s = |j: usize| toks.get(j).map_or("", |t| t.s);
    if depth > MAX_USE_DEPTH {
        return pos;
    }
    loop {
        match s(pos) {
            "::" => pos = pos.saturating_add(1),
            "{" => {
                pos = pos.saturating_add(1);
                loop {
                    match s(pos) {
                        "}" => return pos.saturating_add(1),
                        "," => pos = pos.saturating_add(1),
                        "" | ";" => return pos,
                        _ => {
                            let next =
                                use_tree(toks, pos, segs.clone(), depth.saturating_add(1), out);
                            if next == pos {
                                return pos.saturating_add(1);
                            }
                            pos = next;
                        }
                    }
                }
            }
            "*" => {
                segs.push("*");
                out.push((segs, None));
                return pos.saturating_add(1);
            }
            name if is_ident(name) => {
                if name != "self" {
                    segs.push(name);
                }
                pos = pos.saturating_add(1);
                match s(pos) {
                    "::" => {}
                    "as" => {
                        out.push((segs, Some(s(pos.saturating_add(1)))));
                        return pos.saturating_add(2);
                    }
                    _ => {
                        let bound = segs.last().copied();
                        out.push((segs, bound));
                        return pos;
                    }
                }
            }
            _ => return pos,
        }
    }
}

/// Every alias that `extern crate aws_lc_rs as <alias>` binds in `toks`.
fn aws_lc_extern_aliases<'a>(toks: &[Tok<'a>]) -> Vec<&'a str> {
    let s = |j: usize| toks.get(j).map_or("", |t| t.s);
    let mut out = Vec::new();
    for i in 0..toks.len() {
        let at = |k: usize| s(i.saturating_add(k));
        if at(0) == "extern" && at(1) == "crate" && at(2) == AWS_LC && at(3) == "as" {
            out.push(at(4));
        }
    }
    out
}

/// Whether `leaf` reaches a name that came from aws-lc-rs: it starts at
/// the aws-lc-rs crate, at a `tainted` name, or at `crate`, `self` or
/// `super` with a `tainted` name further on.
fn from_aws_lc(leaf: &UseLeaf<'_>, tainted: &BTreeSet<&str>) -> bool {
    match leaf.segs.split_first() {
        Some((&first, rest)) => {
            first == AWS_LC
                || tainted.contains(first)
                || (matches!(first, "crate" | "super") && rest.iter().any(|s| tainted.contains(s)))
        }
        None => false,
    }
}

/// The indirect re-exports of aws-lc-rs in one crate, whose files hold
/// the tokens `files` (rule 9). A name a `use aws_lc_rs::...` item or an
/// `extern crate aws_lc_rs as` alias binds is tainted, and so is each name
/// a later `use` binds from a tainted one. A public `use` of a tainted
/// name is refused, and so is any glob import from aws-lc-rs or a tainted
/// name, since the names it binds cannot be followed. A direct `pub use
/// aws_lc_rs` is left to [`aws_lc_reexports`]. Returns the file index, the
/// line and the path for each.
pub(crate) fn aws_lc_indirect_reexports(files: &[&[Tok<'_>]]) -> Vec<(usize, usize, String)> {
    let leaves: Vec<(usize, UseLeaf<'_>)> = files
        .iter()
        .enumerate()
        .flat_map(|(n, toks)| use_leaves(toks).into_iter().map(move |l| (n, l)))
        .collect();
    let mut tainted: BTreeSet<&str> = files
        .iter()
        .flat_map(|toks| aws_lc_extern_aliases(toks))
        .collect();
    loop {
        let before = tainted.len();
        for (_, leaf) in &leaves {
            if from_aws_lc(leaf, &tainted)
                && let Some(b) = leaf.bound
                && b != "_"
            {
                tainted.insert(b);
            }
        }
        if tainted.len() == before {
            break;
        }
    }
    let mut out = Vec::new();
    for (n, leaf) in &leaves {
        if !from_aws_lc(leaf, &tainted) {
            continue;
        }
        let direct = leaf.segs.first() == Some(&AWS_LC);
        let glob = leaf.segs.last() == Some(&"*");
        if (leaf.public && !direct) || (glob && !(leaf.public && direct)) {
            out.push((*n, leaf.line, leaf.segs.join("::")));
        }
    }
    out
}

/// Runs the source-scan rules 5, 7 and 9 over `sources`.
pub(crate) fn scan(sources: &[SourceFile]) -> Vec<Finding> {
    let mut out = Vec::new();
    // Rule 9 reads a whole crate once any of its files names aws-lc-rs, so
    // an alias declared in one file and used in another is still read.
    let names_aws_lc: BTreeSet<&str> = sources
        .iter()
        .filter(|f| f.text.contains(AWS_LC))
        .map(|f| f.krate.as_str())
        .collect();
    let all_toks: Vec<Vec<Tok<'_>>> = sources.iter().map(|f| tokens(&f.text)).collect();
    for (f, toks) in sources.iter().zip(&all_toks) {
        let k = f.krate.as_str();
        if k == EDGE {
            for needle in SERVER_TLS {
                for (line, token) in occurrences(&f.text, needle, b":") {
                    out.push(Finding::error(
                        "layering-m3-edge-tls",
                        format!(
                            "{k} names `{token}` in {}:{line}; the edge holds no tenant TLS server (I-19, design section 2.4 rule 5)",
                            f.rel
                        ),
                    ));
                }
            }
            for (line, what) in edge_tls_paths(toks) {
                out.push(Finding::error(
                    "layering-m3-edge-tls",
                    format!(
                        "{k} names {what} in {}:{line}; the edge uses only the fstp-tls client API, so it holds no tenant TLS server (I-19, design section 2.4 rule 5)",
                        f.rel
                    ),
                ));
            }
        }
        if !ROOT_MATERIAL_CRATES.contains(&k) {
            for (line, token) in occurrences(&f.text, ROOT_MATERIAL, b"") {
                out.push(Finding::error(
                    "layering-m3-i80",
                    format!(
                        "{k} names `{token}` in {}:{line}; only fstp-keyd and fstp-celltest may (I-80, design section 2.4 rule 7)",
                        f.rel
                    ),
                ));
            }
        }
        if k != CELLTEST {
            for needle in SEED_NAMES {
                for (line, token) in occurrences(&f.text, needle, b"") {
                    out.push(Finding::error(
                        "layering-m3-test-only",
                        format!(
                            "{k} names the vault seeding identifier `{token}` in {}:{line}; only fstp-celltest may (design sections 2.4 rule 9 and 6.9)",
                            f.rel
                        ),
                    ));
                }
            }
            if names_aws_lc.contains(k) {
                for needle in PQ_ORACLES {
                    for (line, token) in occurrences(&f.text, needle, b":") {
                        out.push(Finding::error(
                            "layering-m3-test-only",
                            format!(
                                "{k} uses the aws-lc-rs post-quantum oracle `{token}` in {}:{line}; it serves only as a test oracle from fstp-celltest (design section 2.4 rule 9, ADR-001 A6)",
                                f.rel
                            ),
                        ));
                    }
                }
            }
            for line in aws_lc_reexports(toks) {
                out.push(Finding::error(
                    "layering-m3-test-only",
                    format!(
                        "{k} re-exports the aws_lc_rs crate in {}:{line}; another crate could then reach the post-quantum oracles without naming aws-lc-rs (design section 2.4 rule 9, ADR-001 A6)",
                        f.rel
                    ),
                ));
            }
        }
    }
    // Rule 9, indirect re-exports, over each crate that names aws-lc-rs.
    for &k in names_aws_lc.iter().filter(|&&k| k != CELLTEST) {
        let files: Vec<(&SourceFile, &[Tok<'_>])> = sources
            .iter()
            .zip(&all_toks)
            .filter(|(f, _)| f.krate == k)
            .map(|(f, t)| (f, t.as_slice()))
            .collect();
        let toks: Vec<&[Tok<'_>]> = files.iter().map(|(_, t)| *t).collect();
        for (n, line, path) in aws_lc_indirect_reexports(&toks) {
            let rel = files.get(n).map_or("?", |(f, _)| f.rel.as_str());
            out.push(Finding::error(
                "layering-m3-test-only",
                format!(
                    "{k} re-exports or glob-imports `{path}` in {rel}:{line}, a name that comes from the aws_lc_rs crate; another crate could then reach the post-quantum oracles without naming aws-lc-rs (design section 2.4 rule 9, ADR-001 A6)"
                ),
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn occurrences_report_the_whole_token_and_line() {
        let text = "a\nlet x = fstp_tls::ServerConfig::builder();\nServerConfigBuilder\n";
        let found = occurrences(text, "ServerConfig", b":");
        assert_eq!(
            found,
            vec![
                (2, "fstp_tls::ServerConfig::builder".to_owned()),
                (3, "ServerConfigBuilder".to_owned()),
            ]
        );
        let ns = occurrences(
            "x = \"urn:iso:std:iso:20022:tech:xsd:pain.001.001.09\";",
            "pain.",
            b":.-",
        );
        assert_eq!(
            ns,
            vec![(
                1,
                "urn:iso:std:iso:20022:tech:xsd:pain.001.001.09".to_owned()
            )]
        );
        assert!(occurrences("no match here", "Root", b"").is_empty());
        assert!(occurrences("é RootMaterial é", "RootMaterial", b"").len() == 1);
    }

    use crate::metadata::{DepDecl, Node, NodeDep, Package};

    /// A workspace whose members are `members`, plus the packages `others`
    /// with their sources, joined by the given normal edges.
    fn workspace(
        members: &[&str],
        others: &[(&str, Option<&str>)],
        edges: &[(&str, &str)],
    ) -> Metadata {
        let names: Vec<&str> = members
            .iter()
            .copied()
            .chain(others.iter().map(|(n, _)| *n))
            .collect();
        let mut m = Metadata::default();
        for (i, name) in names.iter().enumerate() {
            let member = members.contains(name);
            let source = others
                .iter()
                .find(|(n, _)| n == name)
                .and_then(|(_, s)| s.map(str::to_owned));
            m.packages.push(Package {
                id: (*name).into(),
                name: (*name).into(),
                version: "0.1.0".into(),
                source,
                manifest_path: format!("/repo/crates/{name}/Cargo.toml"),
                features: Default::default(),
                dependencies: vec![],
                targets: vec![],
                cargo_fuzz: false,
            });
            if member {
                m.members.push(i);
            }
            let deps: Vec<NodeDep> = edges
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
                features: vec![],
            });
            m.node_of_pkg.insert(i, i);
        }
        m
    }

    fn has(findings: &[Finding], code: &str, names: &[&str]) -> bool {
        findings
            .iter()
            .any(|f| f.code == code && names.iter().all(|n| f.message.contains(n)))
    }

    fn file(krate: &str, rel: &str, text: &str) -> SourceFile {
        SourceFile {
            krate: krate.into(),
            rel: rel.into(),
            text: text.into(),
        }
    }

    const GIT: &str = "git+https://example.org/moduletto.git?rev=0123456789abcdef0123456789abcdef01234567#0123456789abcdef0123456789abcdef01234567";

    /// I-74, I-75, design section 2.4 rule 8, ADR-001 A3: a package from
    /// moduletto's own source counts as Tier B. A member that depends on it
    /// directly, without reaching moduletto itself, is reported.
    #[test]
    fn i74_rule8_package_from_the_moduletto_source_is_confined_too() {
        let meta = workspace(
            &["fstp-crypto", "fstp-keys"],
            &[("moduletto", Some(GIT)), ("moduletto-pq", Some(GIT))],
            &[("fstp-crypto", "moduletto"), ("fstp-keys", "moduletto-pq")],
        );
        let findings = check(&meta);
        assert!(
            has(
                &findings,
                "layering-m3-tier-b",
                &["fstp-keys", "moduletto-pq"]
            ),
            "{findings:?}"
        );
    }

    /// I-74, I-75, design section 2.4 rule 8: a path through fstp-crypto
    /// is the designed one and passes.
    #[test]
    fn i74_rule8_moduletto_through_fstp_crypto_passes() {
        let meta = workspace(
            &["fstp-crypto", "fstp-keys", "fstp-celltest"],
            &[("moduletto", Some(GIT))],
            &[
                ("fstp-crypto", "moduletto"),
                ("fstp-keys", "fstp-crypto"),
                ("fstp-celltest", "fstp-keys"),
            ],
        );
        let findings = check(&meta);
        assert!(
            !findings.iter().any(|f| f.code == "layering-m3-tier-b"),
            "{findings:?}"
        );
    }

    /// I-80, design section 2.4 rules 2 and 7: only the crates each rule
    /// names may reach `fstp-vault-core` and `fstp-custody`. The test-only
    /// `fstp-domain-testkit` is not one of them.
    #[test]
    fn i80_rules_2_and_7_exempt_only_the_named_crates() {
        let meta = workspace(
            &[
                "fstp-domain-testkit",
                "fstp-celltest",
                "fstp-custody",
                "fstp-vault-core",
            ],
            &[],
            &[
                ("fstp-domain-testkit", "fstp-custody"),
                ("fstp-domain-testkit", "fstp-vault-core"),
                ("fstp-celltest", "fstp-custody"),
                ("fstp-celltest", "fstp-vault-core"),
            ],
        );
        let findings = check(&meta);
        assert!(
            has(
                &findings,
                "layering-m3-i80",
                &["fstp-domain-testkit", "fstp-custody"]
            ) && has(
                &findings,
                "layering-m3-vault",
                &["fstp-domain-testkit", "fstp-vault-core"]
            ),
            "{findings:?}"
        );
        assert!(
            !findings
                .iter()
                .any(|f| f.message.starts_with("fstp-celltest")),
            "{findings:?}"
        );
    }

    /// I-19, design section 2.4 rule 5: a grouped, aliased or glob import
    /// of the fstp-tls server API is refused. The client API passes.
    #[test]
    fn i19_rule5_grouped_and_aliased_server_imports_are_refused() {
        let refused = [
            "use fstp_tls::{accept, connect};\n",
            "use fstp_tls::{connect, stream::{accept}};\n",
            "use fstp_tls as t;\nfn f() { t::accept(); }\n",
            "use fstp_tls::*;\n",
            "use fstp_tls::{self as t};\n",
            "use fstp_tls::{\n    TlsStream,\n    accept as a,\n};\n",
            "fn f() { let _ = ::fstp_tls::accept; }\n",
            "extern crate fstp_tls as t;\n",
        ];
        for text in refused {
            let found = scan(&[file(EDGE, "crates/fstp-edge/src/lib.rs", text)]);
            assert!(
                found.iter().any(|f| f.code == "layering-m3-edge-tls"),
                "not refused: {text:?}"
            );
        }
        let client = "//! The tunnel client.\n\
                      use fstp_tls::{self, ClientConfig, TlsStream, connect};\n\
                      fn f() { let _ = fstp_tls::connect; let s = \"fstp_tls::Server\"; }\n";
        let found = scan(&[file(EDGE, "crates/fstp-edge/src/lib.rs", client)]);
        assert!(found.is_empty(), "{found:?}");
    }

    /// I-19, design section 2.4 rule 5: the edge may not rename fstp-tls,
    /// since the scan reads the name `fstp_tls`.
    #[test]
    fn i19_rule5_renamed_fstp_tls_in_the_edge_is_refused() {
        let mut meta = workspace(
            &["fstp-edge", "fstp-tls"],
            &[],
            &[("fstp-edge", "fstp-tls")],
        );
        if let Some(p) = meta.packages.first_mut() {
            p.dependencies.push(DepDecl {
                name: "fstp-tls".into(),
                rename: Some("tls".into()),
                kind: DepKind::Normal,
                optional: false,
            });
        }
        let findings = check(&meta);
        assert!(
            has(&findings, "layering-m3-edge-tls", &["fstp-edge", "`tls`"]),
            "{findings:?}"
        );
    }

    /// Design section 2.4 rule 9, ADR-001 A6: an alias declared in one
    /// file and used in another is still read, since the oracle scan reads
    /// every file of a crate that names aws-lc-rs.
    #[test]
    fn rule9_oracle_scan_reads_the_whole_crate() {
        let found = scan(&[
            file(
                "fstp-keys",
                "crates/fstp-keys/src/lib.rs",
                "use aws_lc_rs as al;\nmod kem;\n",
            ),
            file(
                "fstp-keys",
                "crates/fstp-keys/src/kem.rs",
                "pub fn k() { let _ = &crate::al::kem::ML_KEM_768; }\n",
            ),
        ]);
        assert!(
            found.iter().any(|f| f.code == "layering-m3-test-only"
                && f.message.contains("ML_KEM_768")
                && f.message.contains("kem.rs")),
            "{found:?}"
        );
    }

    /// Design section 2.4 rule 9, ADR-001 A6: a public re-export of the
    /// aws-lc-rs crate is refused outside `fstp-celltest`, so no crate can
    /// reach the oracles through another crate's name.
    #[test]
    fn rule9_aws_lc_reexport_is_refused() {
        for text in [
            "pub use aws_lc_rs as al;\n",
            "pub use ::aws_lc_rs::kem;\n",
            "pub use aws_lc_rs::{self, signature};\n",
            "pub extern crate aws_lc_rs;\n",
        ] {
            let found = scan(&[file("fstp-crypto", "crates/fstp-crypto/src/lib.rs", text)]);
            assert!(
                found
                    .iter()
                    .any(|f| f.code == "layering-m3-test-only" && f.message.contains("re-exports")),
                "not refused: {text:?}"
            );
            let found = scan(&[file(CELLTEST, "crates/fstp-celltest/src/lib.rs", text)]);
            assert!(found.is_empty(), "{found:?}");
        }
        let private = "use aws_lc_rs::digest;\npub use rustls::crypto::aws_lc_rs::kx_group;\n";
        let found = scan(&[file(
            "fstp-crypto",
            "crates/fstp-crypto/src/lib.rs",
            private,
        )]);
        assert!(found.is_empty(), "{found:?}");
    }

    /// Design section 2.4 rule 9: a renamed aws-lc-rs dependency is refused
    /// outside `fstp-celltest`.
    #[test]
    fn rule9_renamed_aws_lc_is_refused() {
        let mut meta = workspace(&["fstp-keys"], &[("aws-lc-rs", None)], &[]);
        if let Some(p) = meta.packages.first_mut() {
            p.dependencies.push(DepDecl {
                name: "aws-lc-rs".into(),
                rename: Some("al".into()),
                kind: DepKind::Normal,
                optional: false,
            });
        }
        let findings = check(&meta);
        assert!(
            has(&findings, "layering-m3-test-only", &["fstp-keys", "`al`"]),
            "{findings:?}"
        );
    }

    #[test]
    fn tokens_drop_comments_and_literals() {
        let text = "a /* fstp_tls\n */ b // c\n\"d\\\"e\" r#\"f\"# 'g' '\\n' h::i 'life\n";
        let toks: Vec<(&str, usize)> = tokens(text).iter().map(|t| (t.s, t.line)).collect();
        assert_eq!(
            toks,
            vec![
                ("a", 1),
                ("b", 2),
                ("h", 3),
                ("::", 3),
                ("i", 3),
                ("'", 3),
                ("life", 3)
            ]
        );
    }

    /// I-19, design section 2.4 rules 5 and 9: every string literal form
    /// lexes as one string, so code after a raw byte string, a C string or
    /// a raw C string is still read. Block comments nest, as in Rust, and a
    /// raw identifier reads as its name. A digit after `r#` starts no raw
    /// identifier (the `rust_tokens` fuzz crash on `;cr;r#2#\0`).
    #[test]
    fn i19_tokens_read_every_literal_prefix() {
        let text = concat!(
            "br\"\\\" a\n",
            "br#\"\"\\\"# b\n",
            "cr\"\\\" c\n",
            "b\"\\\"\" d\n",
            "c\"x\" e\n",
            "b'\\'' f\n",
            "/* /* */ hidden */ g\n",
            "r#fstp_tls h\n",
            "\"line\\\ncontinued\" i\n",
        );
        let toks: Vec<(&str, usize)> = tokens(text).iter().map(|t| (t.s, t.line)).collect();
        assert_eq!(
            toks,
            vec![
                ("a", 1),
                ("b", 2),
                ("c", 3),
                ("d", 4),
                ("e", 5),
                ("f", 6),
                ("g", 7),
                ("fstp_tls", 8),
                ("h", 8),
                ("i", 10),
            ]
        );
        assert!(lex(text).closed);
        assert!(!lex("br#\"open").closed);
        assert!(!lex("/* /* */").closed);
    }

    /// A digit after `r#` starts no raw identifier, so no token is a bare
    /// number read as an identifier (the `rust_tokens` fuzz crash).
    #[test]
    fn i19_tokens_raw_prefix_before_a_digit_is_no_identifier() {
        for text in [";cr;r#2#\0", "2r#3#", "r#9"] {
            let lexed = lex(text);
            let bad: Vec<&str> = lexed
                .lexemes
                .iter()
                .filter(|l| l.kind == LexKind::Ident)
                .filter(|l| l.s.bytes().next().is_some_and(|b| b.is_ascii_digit()))
                .map(|l| l.s)
                .collect();
            assert!(bad.is_empty(), "{text:?} gave identifiers {bad:?}");
        }
    }

    /// I-19, design section 2.4 rule 5: a grouped server import after a
    /// raw byte string that ends in a backslash is refused.
    #[test]
    fn i19_rule5_server_import_after_a_raw_byte_string_is_refused() {
        for lit in ["br\"\\\"", "br#\"\\\"#", "cr\"\\\"", "b\"\\\\\""] {
            let text = format!("const B: &[u8] = {lit};\nuse fstp_tls::{{accept as serve}};\n");
            let found = scan(&[file(EDGE, "crates/fstp-edge/src/lib.rs", &text)]);
            assert!(
                found.iter().any(|f| f.code == "layering-m3-edge-tls"),
                "not refused after {lit}: {found:?}"
            );
        }
    }

    /// Design section 2.4 rule 9, ADR-001 A6: a name imported from aws-lc-rs
    /// and re-exported in a second step is refused, in the same file or in
    /// another file of the crate. So is a glob import from aws-lc-rs.
    #[test]
    fn rule9_two_step_aws_lc_reexport_is_refused() {
        let refused: [&[&str]; 6] = [
            &["use aws_lc_rs::{kem};\npub use kem as pq;\n"],
            &["use aws_lc_rs::kem;\n", "pub use crate::kem as pq;\n"],
            &["use aws_lc_rs::{self as al};\npub use al::kem;\n"],
            &[
                "use aws_lc_rs::kem as k;\npub(crate) use k as k2;\n",
                "pub use super::k2::ML_KEM_768 as X;\n",
            ],
            &[
                "extern crate aws_lc_rs as al;\n",
                "pub use crate::al::kem;\n",
            ],
            &["use aws_lc_rs::*;\n"],
        ];
        for texts in refused {
            let files: Vec<SourceFile> = texts
                .iter()
                .enumerate()
                .map(|(n, t)| file("fstp-crypto", &format!("crates/fstp-crypto/src/f{n}.rs"), t))
                .collect();
            let found = scan(&files);
            assert!(
                found
                    .iter()
                    .any(|f| f.code == "layering-m3-test-only" && f.message.contains("re-export")),
                "not refused: {texts:?}"
            );
            let files: Vec<SourceFile> = texts
                .iter()
                .enumerate()
                .map(|(n, t)| file(CELLTEST, &format!("crates/fstp-celltest/src/f{n}.rs"), t))
                .collect();
            assert!(scan(&files).is_empty(), "celltest refused: {texts:?}");
        }
        let allowed = [
            "use aws_lc_rs::{constant_time, digest, hmac, pbkdf2, rand};\npub use crate::config::Config;\n",
            "use rustls::crypto::aws_lc_rs::{self, kx_group};\npub use crate::provider::{CIPHER_SUITES, KEY_EXCHANGE_GROUPS};\n",
            "use aws_lc_rs::digest;\npub use rustls::crypto::aws_lc_rs::kx_group;\n",
        ];
        for text in allowed {
            let found = scan(&[file("fstp-crypto", "crates/fstp-crypto/src/lib.rs", text)]);
            assert!(found.is_empty(), "{text:?}: {found:?}");
        }
    }

    /// Design section 2.4 rules 5, 7 and 9: the module reader names every
    /// file a `mod`, `#[path]` or `include!` may load, and refuses a value
    /// that is not a plain string literal.
    #[test]
    fn rule7_module_refs_name_every_loaded_file() {
        let text = concat!(
            "mod a;\n",
            "#[path = \"../gen/keys.rs\"]\n",
            "pub mod keys;\n",
            "#[cfg_attr(unix, path = \"unix.rs\")]\n",
            "mod sys;\n",
            "mod outer {\n",
            "    mod inner;\n",
            "}\n",
            "include!(\"gen.rs\");\n",
            "include!(concat!(env!(\"OUT_DIR\"), \"/x.rs\"));\n",
            "#[path = concat!(\"x\", \".rs\")]\n",
            "mod bad;\n",
        );
        let lx = lex(text);
        let refs = module_refs(&lx.lexemes, Path::new("/p/src/lib.rs"));
        for want in [
            "/p/src/a.rs",
            "/p/src/a/mod.rs",
            "/p/src/../gen/keys.rs",
            "/p/src/unix.rs",
            "/p/src/outer/inner.rs",
            "/p/src/outer/inner/mod.rs",
            "/p/src/gen.rs",
        ] {
            assert!(
                refs.candidates.contains(&PathBuf::from(want)),
                "{want} missing from {:?}",
                refs.candidates
            );
        }
        let lines: Vec<usize> = refs.unresolved.iter().map(|(l, _)| *l).collect();
        assert_eq!(lines, vec![10, 11], "{:?}", refs.unresolved);
    }

    /// Design section 2.4: the lexer properties that the `rust_tokens` fuzz
    /// target checks hold on the review inputs.
    #[test]
    fn rule5_rust_tokens_fuzz_properties_hold_on_review_inputs() {
        for data in [
            &b"br\"\\\"\nuse fstp_tls::{accept as serve};\n"[..],
            b"\x04\\\"",
            b"\x0a#\"x",
            b"/* /* */",
            b"'\\",
            b"r#",
            b"\xff\xfe mod x; #[path",
        ] {
            assert_eq!(crate::fuzzing::rust_tokens(data), Ok(()), "{data:?}");
        }
    }
}

#[cfg(test)]
mod review_tests {
    use super::*;
    use crate::metadata::{Node, NodeDep, Package};

    /// A workspace whose members are `members`, plus the third-party
    /// packages `others`, with the given normal edges.
    fn graph(members: &[&str], others: &[&str], edges: &[(&str, &str)]) -> Metadata {
        let names: Vec<&str> = members.iter().chain(others.iter()).copied().collect();
        let mut m = Metadata::default();
        for (i, name) in names.iter().enumerate() {
            let member = members.contains(name);
            m.packages.push(Package {
                id: (*name).into(),
                name: (*name).into(),
                version: "0.1.0".into(),
                source: if member {
                    None
                } else {
                    Some("git+https://example.org/moduletto.git?rev=0123456789abcdef0123456789abcdef01234567#0123456789abcdef0123456789abcdef01234567".into())
                },
                manifest_path: format!("/repo/crates/{name}/Cargo.toml"),
                features: Default::default(),
                dependencies: vec![],
                targets: vec![],
                cargo_fuzz: false,
            });
            if member {
                m.members.push(i);
            }
            let deps: Vec<NodeDep> = edges
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
                features: vec![],
            });
            m.node_of_pkg.insert(i, i);
        }
        m
    }

    /// Review finding rule8-direct-only (I-74, I-75, design section 2.4
    /// rule 8): moduletto must be reachable only through `fstp-crypto`. A
    /// member that reaches it through another package from moduletto's
    /// repository, which ADR-001 A3 lets onto the allowlist, must fail.
    #[test]
    fn review_rule8_moduletto_reached_around_fstp_crypto() {
        let meta = graph(
            &["fstp-crypto", "fstp-cell"],
            &["moduletto-hybrid", "moduletto"],
            &[
                ("fstp-crypto", "moduletto"),
                ("fstp-cell", "moduletto-hybrid"),
                ("moduletto-hybrid", "moduletto"),
            ],
        );
        let findings = check(&meta);
        assert!(
            findings
                .iter()
                .any(|f| f.code == "layering-m3-tier-b" && f.message.contains("fstp-cell")),
            "fstp-cell reaches moduletto around fstp-crypto, and rule 8 is silent: {findings:?}"
        );
    }

    /// Review finding tier-b-source-string (I-74, I-75, design section 2.4
    /// rule 8, ADR-001 A3). git_source admits any package from the
    /// repository URL that moduletto's allowlist entry records, at any
    /// pinned commit. Rule 8 confines only packages whose whole source string
    /// equals moduletto's, so a sibling from the same repository at another
    /// commit reaches a member around fstp-crypto unreported.
    #[test]
    fn review_rule8_sibling_from_the_moduletto_repository_at_another_commit() {
        let mut meta = graph(
            &["fstp-crypto", "fstp-cell"],
            &["moduletto", "moduletto-pq"],
            &[("fstp-crypto", "moduletto"), ("fstp-cell", "moduletto-pq")],
        );
        let other = "89abcdef0123456789abcdef0123456789abcdef";
        if let Some(p) = meta.packages.iter_mut().find(|p| p.name == "moduletto-pq") {
            p.source = Some(format!(
                "git+https://example.org/moduletto.git?rev={other}#{other}"
            ));
        }
        let findings = check(&meta);
        assert!(
            findings
                .iter()
                .any(|f| f.code == "layering-m3-tier-b" && f.message.contains("moduletto-pq")),
            "fstp-cell reaches a package from moduletto's repository around fstp-crypto, and rule 8 is silent: {findings:?}"
        );
    }
}
