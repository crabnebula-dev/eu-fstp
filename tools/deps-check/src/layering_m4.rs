//! The layering gate of the M4 crates (`docs/handoff/m4-design.md`
//! section 1.3).
//!
//! It reuses the reach logic of `layering.rs` and the lexer of
//! `layering_m3.rs`. Each finding code starts with `layering-m4-`.
//!
//! - `a1`: the adapters `fstp-mcp` and `fstp-web` have a fixed set of
//!   direct normal and build dependencies. No dependency of any kind names
//!   a domain, engine, creator, import, programme, public, access or M3
//!   crate (I-84).
//! - `a2`: a source scan of `fstp-api-core`. A public `use` of an in-house
//!   crate is allowed only in `ids.rs` for id types and in `meta.rs` for
//!   `ToolDef`, `Scope` and `Classification`. The engine, domain command,
//!   `Actor`, creator command and principal names are refused everywhere.
//!   No public item outside `port.rs` names `CellPorts`, `AsyncEngine` or a
//!   port trait, or re-exports the port module by name or glob. No public
//!   item outside `port.rs`, a type alias or field included, names an
//!   engine path, a domain command path, a refused name or a name bound
//!   from one by `use` or `type` (I-84).
//! - `a2b`: a source scan of the adapters refuses the `port` module,
//!   `CellPorts`, `AsyncEngine`, `Principal` and `ExecMeta` (I-84).
//! - `a3`: `fstp-domain`, `fstp-programme` and `fstp-creator` have no
//!   path to `fstp-import`, and `fstp-import` none to `fstp-creator` or
//!   `fstp-engine`. Only `fstp-engine`, `fstp-access` and `fstp-api-core`
//!   depend directly on both `fstp-import` and `fstp-creator`, besides the
//!   test-only `fstp-api-testkit` (I-65).
//! - `a4`: `fstp-programme`, `fstp-creator`, `fstp-guide` and
//!   `fstp-public` have no path to `fstp-findings` or `fstp-engine`, and
//!   `fstp-findings` none to `fstp-import`. A source scan allows only
//!   `fstp_findings::text::UntrustedText` in `fstp-import` (I-10).
//! - `a5`: `fstp-mcp`, `fstp-public`, `fstp-access` and `fstp-api-core`
//!   have no path to the M3 vault client crates (I-86).
//! - `a6`: a source scan of `fstp-public/src/{html,tools,feed}.rs`. They
//!   name no state type: no `State` or `EngineState`, no `fstp_engine` or
//!   `fstp_findings` path, no `fstp_domain` path outside `id` and `time`,
//!   and no name the crate imported from those or aliased with `type` (I-87).
//! - `a7`: `fstp-api-core`, `fstp-mcp` and `fstp-oauth` never name
//!   `SystemCause` or `Actor::System`, through a `use` or `type` alias or
//!   not. Interim reading: it serves I-84, since the design names no
//!   identifier for it.
//! - `a8`: no M4 crate reaches a package licensed under the EUPL, which
//!   only the export and import executable uses (R-TD-03).
//! - `a9`: no crate takes `fstp-api-testkit` as a normal or build
//!   dependency, and `fstp-cell` and `fstp-control` take it as no
//!   dependency at all.
//! - `a9b`: `fstp-cell` and `fstp-control` implement no `ProfileSource`,
//!   under its name or a `use` alias, and name no profile set but
//!   `ShippedProfiles`. The synthetic marker
//!   appears in no shipped source outside `fstp-api-testkit`, and in no
//!   file under `crates/fstp-guide/profiles/`.
//! - `a10`: the pure M4 crates reach no I/O crate or runtime, carry the
//!   M2 lint header in their library root, and name no float type or
//!   float literal in their shipped sources.
//! - `rename`: the crates these scans read rename no in-house dependency,
//!   since the scans match crate names.
//!
//! Interim readings, pending Daniel:
//!
//! - The vault client crates of rule A5 are `fstp-vault`,
//!   `fstp-vault-core`, `fstp-vault-proto` and `fstp-cell`.
//! - Rule A8 matches the EUPL by the `license` field of each reached
//!   package.
//! - Rule A9 reads "checked by name" as no edge of any kind from
//!   `fstp-cell` or `fstp-control`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::layering::{ANY_KIND, SHIPPED, hits, members, reach, render_path};
use crate::layering_m3::{LexKind, SourceFile, Tok, UseLeaf, lex, tokens, use_leaves};
use crate::metadata::{DepKind, Metadata};
use crate::report::Finding;

/// The MCP adapter.
const MCP: &str = "fstp-mcp";
/// The web adapter.
const WEB: &str = "fstp-web";
/// Rule A1: the direct normal and build dependencies each adapter may have.
const MCP_DEPS: [&str; 4] = ["fstp-api-core", "fstp-oauth", "fstp-http", "fstp-json"];
const WEB_DEPS: [&str; 7] = [
    "fstp-api-core",
    "fstp-oauth",
    "fstp-http",
    "fstp-json",
    "fstp-mcp",
    "fstp-web-assets",
    "fstp-rt",
];
/// Rule A1: what no adapter dependency of any kind may name.
const ADAPTER_FORBIDDEN: [&str; 9] = [
    "fstp-engine",
    "fstp-domain",
    "fstp-findings",
    "fstp-creator",
    "fstp-import",
    "fstp-programme",
    "fstp-public",
    "fstp-access",
    "fstp-domain-testkit",
];
/// The M3 crates (`docs/handoff/m3-design.md` section 2.1). No adapter
/// depends on one (rule A1).
const M3_CRATES: [&str; 22] = [
    "fstp-pki",
    "fstp-keys",
    "fstp-custody",
    "fstp-keyd",
    "fstp-audit",
    "fstp-obs",
    "fstp-pgstore",
    "fstp-vault-proto",
    "fstp-vault-core",
    "fstp-vault",
    "fstp-webauthn",
    "fstp-auth",
    "fstp-cell-core",
    "fstp-cell",
    "fstp-cp-proto",
    "fstp-control",
    "fstp-witness",
    "fstp-edge",
    "fstp-release",
    "fstp-release-svc",
    "fstp-backup",
    "fstp-celltest",
];

/// The API core.
const API_CORE: &str = "fstp-api-core";
/// The crate names, as Rust paths, of the in-house crates the API core
/// depends on. A public `use` of one is allowed only in `ids.rs` and
/// `meta.rs` (rule A2).
const API_CORE_INNER: [&str; 13] = [
    "fstp_engine",
    "fstp_domain",
    "fstp_findings",
    "fstp_creator",
    "fstp_import",
    "fstp_public",
    "fstp_guide",
    "fstp_tenant",
    "fstp_access",
    "fstp_programme",
    "fstp_ledger",
    "fstp_money",
    "fstp_json",
];
/// Rule A2: what `meta.rs` may re-export.
const META_NAMES: [&str; 3] = ["ToolDef", "Scope", "Classification"];
/// Rule A2: names no public `use` in the API core may bind or pass.
const API_CORE_REFUSED: [&str; 4] = ["Principal", "Actor", "CreatorCommand", "CreatorRecord"];
/// Rules A2 and A2b: the ports of design section 6.1.
const PORT_TRAITS: [&str; 22] = [
    "CellPorts",
    "AsyncEngine",
    "Sessions",
    "StepUp",
    "Accounts",
    "AsyncIdentityOracle",
    "Vault",
    "AuditSink",
    "TextStore",
    "BlobStore",
    "Sealer",
    "VaultAudit",
    "SessionsAdmin",
    "Recovery",
    "BreakGlass",
    "Precheck",
    "TenantConfig",
    "Outbox",
    "Prober",
    "Clock",
    "Ids",
    "Provisioner",
];
/// Rule A2b: what an adapter may not name.
const ADAPTER_REFUSED: [&str; 4] = ["CellPorts", "AsyncEngine", "Principal", "ExecMeta"];

/// Rule A3.
const IMPORT: &str = "fstp-import";
const CREATOR: &str = "fstp-creator";
const IMPORT_FREE: [&str; 3] = ["fstp-domain", "fstp-programme", CREATOR];
const IMPORT_AVOIDS: [&str; 2] = [CREATOR, "fstp-engine"];
const BOTH_ALLOWED: [&str; 3] = ["fstp-engine", "fstp-access", API_CORE];

/// Rule A4.
const FINDINGS_FREE: [&str; 4] = ["fstp-programme", CREATOR, "fstp-guide", "fstp-public"];
const FINDINGS_SIDE: [&str; 2] = ["fstp-findings", "fstp-engine"];
const FINDINGS: &str = "fstp-findings";

/// Rule A5: the M3 vault client crates (interim reading).
const VAULT_FREE: [&str; 4] = [MCP, "fstp-public", "fstp-access", API_CORE];
const VAULT_CLIENT: [&str; 4] = [
    "fstp-vault",
    "fstp-vault-core",
    "fstp-vault-proto",
    "fstp-cell",
];

/// Rule A6: the public crate and the files that take only a `PublicView`.
const PUBLIC: &str = "fstp-public";
const PUBLIC_VIEW_FILES: [&str; 3] = ["src/html.rs", "src/tools.rs", "src/feed.rs"];
const STATE_TYPES: [&str; 2] = ["State", "EngineState"];
const STATE_CRATES: [&str; 3] = ["fstp_domain", "fstp_engine", "fstp_findings"];
const DOMAIN_VALUE_MODULES: [&str; 2] = ["id", "time"];

/// Rule A7.
const NO_SYSTEM: [&str; 3] = [API_CORE, MCP, "fstp-oauth"];

/// The M4 crates of design section 1.1, test kit included.
const M4_CRATES: [&str; 15] = [
    "fstp-programme",
    CREATOR,
    IMPORT,
    "fstp-html",
    "fstp-guide",
    PUBLIC,
    "fstp-tenant",
    "fstp-access",
    API_CORE,
    "fstp-oauth",
    MCP,
    "fstp-signup",
    WEB,
    "fstp-web-assets",
    TESTKIT,
];

/// Rule A9.
const TESTKIT: &str = "fstp-api-testkit";
const CELL: &str = "fstp-cell";
const CONTROL: &str = "fstp-control";

/// Rule A9b.
const PROFILE_TRAIT: &str = "ProfileSource";
const SHIPPED_PROFILES: &str = "ShippedProfiles";
/// The marker of the synthetic legal-wording profile, assembled so that
/// this file holds no copy of it.
fn marker() -> String {
    ["SYNTHETIC", "TEST", "WORDING"].join(" ")
}
/// The shipped profile tree of `fstp-guide`, relative to the workspace.
const GUIDE_PROFILES: &str = "crates/fstp-guide/profiles";
/// Upper bound on the files read below the profile tree.
const MAX_PROFILE_FILES: usize = 10_000;
/// Upper bound on the size of one profile file.
const MAX_PROFILE_FILE: u64 = 16 << 20;

/// Rule A10.
const PURE_M4: [&str; 9] = [
    "fstp-programme",
    CREATOR,
    IMPORT,
    "fstp-guide",
    PUBLIC,
    "fstp-tenant",
    "fstp-access",
    "fstp-signup",
    "fstp-html",
];
const IO_CRATES: [&str; 10] = [
    "fstp-rt",
    "fstp-http",
    "fstp-tls",
    "fstp-pgwire",
    "fstp-pgtest",
    "fstp-migrate",
    "tokio",
    "smol",
    "mio",
    "socket2",
];
const LINT_HEADER: [&str; 4] = [
    "float_arithmetic",
    "float_cmp",
    "cast_precision_loss",
    "arithmetic_side_effects",
];

/// Runs the graph rules over one workspace context.
pub(crate) fn check(meta: &Metadata) -> Vec<Finding> {
    let mut out = Vec::new();
    let members = members(meta);

    // A1.
    for (adapter, allowed) in [(MCP, &MCP_DEPS[..]), (WEB, &WEB_DEPS[..])] {
        let Some(&start) = members.get(adapter) else {
            continue;
        };
        for (name, kinds) in direct_deps(meta, start) {
            let shipped = kinds.iter().any(|k| SHIPPED.contains(k));
            let forbidden = ADAPTER_FORBIDDEN.contains(&name) || M3_CRATES.contains(&name);
            if forbidden || (shipped && !allowed.contains(&name)) {
                out.push(Finding::error(
                    "layering-m4-a1",
                    format!(
                        "{adapter} depends directly on {name}; an adapter may depend only on {} and never on a domain, engine, access or M3 crate, so it cannot build an engine command (I-84, M4 design section 1.3 rule A1)",
                        allowed.join(", ")
                    ),
                ));
            }
        }
    }

    // A3.
    for krate in IMPORT_FREE {
        path_rule(
            meta,
            &members,
            krate,
            &[IMPORT],
            "layering-m4-a3",
            "import proposals stay in a store the creator and the domain cannot name (I-65, M4 design section 1.3 rule A3)",
            &mut out,
        );
    }
    path_rule(
        meta,
        &members,
        IMPORT,
        &IMPORT_AVOIDS,
        "layering-m4-a3",
        "the import store never reaches the creator or the engine (I-65, M4 design section 1.3 rule A3)",
        &mut out,
    );
    for (&krate, &start) in &members {
        if BOTH_ALLOWED.contains(&krate) || krate == TESTKIT {
            continue;
        }
        let direct: BTreeSet<&str> = direct_deps(meta, start).into_keys().collect();
        if direct.contains(IMPORT) && direct.contains(CREATOR) {
            out.push(Finding::error(
                "layering-m4-a3",
                format!(
                    "{krate} depends directly on both {IMPORT} and {CREATOR}; only {} name both (I-65, M4 design section 1.3 rule A3)",
                    BOTH_ALLOWED.join(", ")
                ),
            ));
        }
    }

    // A4.
    for krate in FINDINGS_FREE {
        path_rule(
            meta,
            &members,
            krate,
            &FINDINGS_SIDE,
            "layering-m4-a4",
            "findings never reach the programme, the creator, the Guide or public pages (I-10, M4 design section 1.3 rule A4)",
            &mut out,
        );
    }
    path_rule(
        meta,
        &members,
        FINDINGS,
        &[IMPORT],
        "layering-m4-a4",
        "findings cannot reach the import store (I-10, M4 design section 1.3 rule A4)",
        &mut out,
    );

    // A5.
    for krate in VAULT_FREE {
        path_rule(
            meta,
            &members,
            krate,
            &VAULT_CLIENT,
            "layering-m4-a5",
            "the vault reaches it only through the engine oracle and the write-only intake port (I-86, M4 design section 1.3 rule A5)",
            &mut out,
        );
    }

    // A8.
    let mut licences = LicenceCache::default();
    for krate in M4_CRATES {
        let Some(&start) = members.get(krate) else {
            continue;
        };
        let parent = reach(meta, start, &ANY_KIND);
        let reached = std::iter::once(start).chain(parent.keys().copied());
        for pkg in reached {
            let Some(p) = meta.packages.get(pkg) else {
                continue;
            };
            if licences.is_eupl(Path::new(&p.manifest_path)) {
                out.push(Finding::error(
                    "layering-m4-a8",
                    format!(
                        "{krate} reaches {}, which is licensed under the EUPL ({}); the platform contains no EUPL code, and the export and import executable stays separate (R-TD-03, M4 design section 1.3 rule A8)",
                        p.name,
                        render_path(meta, &parent, start, pkg)
                    ),
                ));
            }
        }
    }

    // A9.
    for (&krate, &start) in &members {
        if krate == TESTKIT {
            continue;
        }
        let kinds: &[DepKind] = if krate == CELL || krate == CONTROL {
            &ANY_KIND
        } else {
            &SHIPPED
        };
        let parent = reach(meta, start, kinds);
        for (_, pkg) in hits(meta, &parent, &[TESTKIT]) {
            out.push(Finding::error(
                "layering-m4-a9",
                format!(
                    "{krate} reaches {TESTKIT} ({}); test code never ships, and {CELL} and {CONTROL} take it as no dependency at all (M4 design section 1.3 rule A9)",
                    render_path(meta, &parent, start, pkg)
                ),
            ));
        }
    }

    // A10.
    for krate in PURE_M4 {
        path_rule(
            meta,
            &members,
            krate,
            &IO_CRATES,
            "layering-m4-a10",
            "the pure M4 crates do no I/O (M4 design section 1.3 rule A10)",
            &mut out,
        );
    }

    // The source scans match crate names, so the scanned crates rename no
    // in-house dependency.
    for (&krate, &i) in &members {
        if !(M4_CRATES.contains(&krate) || krate == CELL || krate == CONTROL) {
            continue;
        }
        let Some(pkg) = meta.packages.get(i) else {
            continue;
        };
        for d in pkg
            .dependencies
            .iter()
            .filter(|d| d.name.starts_with("fstp-"))
        {
            if let Some(rename) = &d.rename {
                out.push(Finding::error(
                    "layering-m4-rename",
                    format!(
                        "{krate} declares {} under the name `{rename}` ({} dependency); the M4 source scans read the crate names (M4 design section 1.3)",
                        d.name,
                        d.kind.label()
                    ),
                ));
            }
        }
    }
    out
}

/// The direct dependencies of `start`, by package name, with every kind
/// each edge carries.
fn direct_deps(meta: &Metadata, start: usize) -> BTreeMap<&str, Vec<DepKind>> {
    let mut out: BTreeMap<&str, Vec<DepKind>> = BTreeMap::new();
    let Some(node) = meta
        .node_of_pkg
        .get(&start)
        .and_then(|&n| meta.nodes.get(n))
    else {
        return out;
    };
    for dep in &node.deps {
        if let Some(p) = meta.packages.get(dep.pkg) {
            out.entry(p.name.as_str())
                .or_default()
                .extend(dep.kinds.iter().copied());
        }
    }
    out
}

/// Reports each of `targets` that `krate` reaches, with the first step
/// over any edge kind.
fn path_rule(
    meta: &Metadata,
    members: &BTreeMap<&str, usize>,
    krate: &str,
    targets: &[&str],
    code: &'static str,
    why: &str,
    out: &mut Vec<Finding>,
) {
    let Some(&start) = members.get(krate) else {
        return;
    };
    let parent = reach(meta, start, &ANY_KIND);
    for (target, pkg) in hits(meta, &parent, targets) {
        out.push(Finding::error(
            code,
            format!(
                "{krate} reaches {target} ({}); {why}",
                render_path(meta, &parent, start, pkg)
            ),
        ));
    }
}

/// Reads and remembers whether a manifest declares an EUPL licence.
#[derive(Default)]
struct LicenceCache {
    seen: BTreeMap<PathBuf, bool>,
}

impl LicenceCache {
    fn is_eupl(&mut self, manifest: &Path) -> bool {
        if let Some(&v) = self.seen.get(manifest) {
            return v;
        }
        let v = manifest_licence(manifest).is_some_and(|l| l.to_ascii_uppercase().contains("EUPL"));
        self.seen.insert(manifest.to_path_buf(), v);
        v
    }
}

/// The `license` value of a manifest's `[package]` table, following
/// `license.workspace = true` to the nearest workspace manifest above it.
pub(crate) fn manifest_licence(manifest: &Path) -> Option<String> {
    let text = fs::read_to_string(manifest).ok()?;
    match table_licence(&text, "package")? {
        Licence::Value(v) => Some(v),
        Licence::Workspace => {
            let mut dir = manifest.parent()?.parent();
            while let Some(d) = dir {
                let candidate = d.join("Cargo.toml");
                if let Ok(t) = fs::read_to_string(&candidate)
                    && t.lines().any(|l| l.trim() == "[workspace]")
                {
                    return match table_licence(&t, "workspace.package")? {
                        Licence::Value(v) => Some(v),
                        Licence::Workspace => None,
                    };
                }
                dir = d.parent();
            }
            None
        }
    }
}

/// A licence field: a value, or inherited from the workspace.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Licence {
    Value(String),
    Workspace,
}

/// The licence field of the TOML table `table` in `text`. This reads the
/// simple forms cargo writes and the repository uses: `license = "..."`,
/// `license.workspace = true` and `license = { workspace = true }`.
fn table_licence(text: &str, table: &str) -> Option<Licence> {
    let header = format!("[{table}]");
    let mut inside = false;
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.starts_with('[') {
            inside = line == header;
            continue;
        }
        if !inside {
            continue;
        }
        let compact: String = line.chars().filter(|c| !c.is_whitespace()).collect();
        if compact == "license.workspace=true" || compact == "license={workspace=true}" {
            return Some(Licence::Workspace);
        }
        if compact.starts_with("license=") {
            // The value keeps its spaces: `MIT OR Apache-2.0` (R-NF-07).
            let value = line.split_once('=').map_or("", |(_, v)| v.trim());
            return Some(Licence::Value(value.trim_matches('"').to_owned()));
        }
    }
    None
}

/// Whether `f` is one of the files of rule A6.
fn public_view_file(f: &SourceFile) -> bool {
    f.krate == PUBLIC
        && PUBLIC_VIEW_FILES
            .iter()
            .any(|p| f.rel.ends_with(&format!("/{p}")) || f.rel == *p)
}

/// Whether `leaf` comes from one of the crates `roots`, directly.
fn rooted_at(leaf: &UseLeaf<'_>, roots: &[&str]) -> bool {
    leaf.segs.first().is_some_and(|s| roots.contains(s))
}

/// Grows `tainted` with every name a `use` binds from a tainted name or
/// from `crate`, `self` or `super` through one, until nothing changes.
fn close_taint<'a>(leaves: &[UseLeaf<'a>], tainted: &mut BTreeSet<&'a str>) {
    loop {
        let before = tainted.len();
        for leaf in leaves {
            let from_tainted = match leaf.segs.split_first() {
                Some((first, rest)) => {
                    tainted.contains(first)
                        || (matches!(*first, "crate" | "self" | "super")
                            && rest.iter().any(|s| tainted.contains(s)))
                }
                None => false,
            };
            if from_tainted && let Some(b) = leaf.bound.filter(|b| *b != "_") {
                tainted.insert(b);
            }
        }
        if tainted.len() == before {
            break;
        }
    }
}

/// Every type alias in `toks`, as the name it binds and the tokens of its
/// right-hand side: `type Name<..> = rhs;`. An associated type with a
/// bound and no `=` binds nothing.
fn type_aliases<'a>(toks: &[Tok<'a>]) -> Vec<(&'a str, Vec<&'a str>)> {
    let mut out = Vec::new();
    let s = |j: usize| toks.get(j).map_or("", |t| t.s);
    for i in 0..toks.len() {
        if s(i) != "type" || i.checked_sub(1).is_some_and(|p| s(p) == "::") {
            continue;
        }
        let name = s(i.saturating_add(1));
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            continue;
        }
        let mut j = i.saturating_add(2);
        if s(j) == "<" {
            let mut depth = 0usize;
            while let Some(t) = toks.get(j) {
                match t.s {
                    "<" => depth = depth.saturating_add(1),
                    ">" if j.checked_sub(1).is_some_and(|k| s(k) != "-") => {
                        depth = depth.saturating_sub(1);
                        if depth == 0 {
                            j = j.saturating_add(1);
                            break;
                        }
                    }
                    _ => {}
                }
                j = j.saturating_add(1);
            }
        }
        if s(j) != "=" {
            continue;
        }
        let mut rhs = Vec::new();
        j = j.saturating_add(1);
        while let Some(t) = toks.get(j) {
            if t.s == ";" {
                break;
            }
            rhs.push(t.s);
            j = j.saturating_add(1);
        }
        out.push((name, rhs));
    }
    out
}

/// Grows `tainted` as [`close_taint`] does, and also with every name a
/// type alias binds to a right-hand side that `hit` accepts, until
/// nothing changes. `hit` sees the right-hand side and the current set.
fn close_taint_aliases<'a>(
    leaves: &[UseLeaf<'a>],
    aliases: &[(&'a str, Vec<&'a str>)],
    tainted: &mut BTreeSet<&'a str>,
    hit: impl Fn(&[&'a str], &BTreeSet<&'a str>) -> bool,
) {
    loop {
        let before = tainted.len();
        close_taint(leaves, tainted);
        for (name, rhs) in aliases {
            if !tainted.contains(name) && hit(rhs, tainted) {
                tainted.insert(name);
            }
        }
        if tainted.len() == before {
            break;
        }
    }
}

/// Whether `toks` hold a path into an engine type, the domain command
/// module or a name of `tainted` (rule A2).
fn names_engine_or_command(toks: &[&str], tainted: &BTreeSet<&str>) -> Option<String> {
    for (i, t) in toks.iter().enumerate() {
        let at = |k: usize| toks.get(i.saturating_add(k)).copied().unwrap_or("");
        if *t == "fstp_engine" {
            return Some("`fstp_engine`".to_owned());
        }
        if *t == "fstp_domain" && at(1) == "::" && at(2) == "command" {
            return Some("`fstp_domain::command`".to_owned());
        }
        if tainted.contains(t) {
            return Some(format!("`{t}`"));
        }
    }
    None
}

/// Whether `toks` name a state type (rule A6): a `fstp_engine` or
/// `fstp_findings` path, a `fstp_domain` path outside `id` and `time`, or
/// a name of `tainted`.
fn state_path(toks: &[&str], tainted: &BTreeSet<&str>) -> Option<String> {
    for (i, t) in toks.iter().enumerate() {
        let at = |k: usize| toks.get(i.saturating_add(k)).copied().unwrap_or("");
        if *t == "fstp_domain" {
            if !(at(1) == "::" && DOMAIN_VALUE_MODULES.contains(&at(2))) {
                return Some("a `fstp_domain` path outside `id` and `time`".to_owned());
            }
        } else if *t == "fstp_engine" || *t == "fstp_findings" || tainted.contains(t) {
            return Some(format!("`{t}`"));
        }
    }
    None
}

/// The text of each public item outside `port.rs`: the tokens from an
/// unrestricted `pub` to the end of its signature, as a line and a list.
/// A signature ends at `{`, `;` or `,` outside brackets.
fn public_signatures<'a>(toks: &[Tok<'a>]) -> Vec<(usize, Vec<&'a str>)> {
    let mut out = Vec::new();
    let s = |j: usize| toks.get(j).map_or("", |t| t.s);
    for (i, t) in toks.iter().enumerate() {
        if t.s != "pub" || s(i.saturating_add(1)) == "(" {
            continue;
        }
        let mut depth = 0usize;
        let mut sig = Vec::new();
        let mut j = i.saturating_add(1);
        while let Some(x) = toks.get(j) {
            match x.s {
                "(" | "[" => depth = depth.saturating_add(1),
                ")" | "]" => depth = depth.saturating_sub(1),
                "<" => depth = depth.saturating_add(1),
                ">" if j.checked_sub(1).is_some_and(|k| s(k) != "-") => {
                    depth = depth.saturating_sub(1);
                }
                "{" | ";" if depth == 0 => break,
                "," if depth == 0 => break,
                _ => {}
            }
            sig.push(x.s);
            j = j.saturating_add(1);
        }
        out.push((t.line, sig));
    }
    out
}

/// Runs the source-scan rules over `sources`. `meta` gives the workspace
/// root, for the profile tree of rule A9b, and each library root, for the
/// lint header of rule A10.
pub(crate) fn scan(sources: &[SourceFile], meta: &Metadata) -> Vec<Finding> {
    let mut out = Vec::new();
    let all_toks: Vec<Vec<Tok<'_>>> = sources.iter().map(|f| tokens(&f.text)).collect();
    let all_leaves: Vec<Vec<UseLeaf<'_>>> = all_toks.iter().map(|t| use_leaves(t)).collect();
    let by_crate = |k: &str| -> Vec<usize> {
        sources
            .iter()
            .enumerate()
            .filter(|(_, f)| f.krate == k)
            .map(|(n, _)| n)
            .collect()
    };

    // A2.
    let core_files = by_crate(API_CORE);
    let core_leaves: Vec<UseLeaf<'_>> = core_files
        .iter()
        .filter_map(|&n| all_leaves.get(n))
        .flatten()
        .cloned()
        .collect();
    let core_aliases: Vec<(&str, Vec<&str>)> = core_files
        .iter()
        .filter_map(|&n| all_toks.get(n))
        .flat_map(|t| type_aliases(t))
        .collect();
    let mut port_names: BTreeSet<&str> = PORT_TRAITS.iter().copied().collect();
    for leaf in &core_leaves {
        if leaf.segs.last().is_some_and(|s| PORT_TRAITS.contains(s))
            && let Some(b) = leaf.bound.filter(|b| *b != "_")
        {
            port_names.insert(b);
        }
    }
    close_taint_aliases(&core_leaves, &core_aliases, &mut port_names, |rhs, set| {
        rhs.iter().any(|s| set.contains(s))
    });
    // The names that stand for an engine type, a domain command type or a
    // refused name: those a `use` binds from one, and the type aliases of
    // one.
    let mut engine_names: BTreeSet<&str> = API_CORE_REFUSED.iter().copied().collect();
    for leaf in &core_leaves {
        let engine = leaf.segs.first() == Some(&"fstp_engine");
        let command =
            leaf.segs.first() == Some(&"fstp_domain") && leaf.segs.get(1) == Some(&"command");
        let refused = leaf.segs.iter().any(|s| API_CORE_REFUSED.contains(s));
        if (engine || command || refused)
            && let Some(b) = leaf.bound.filter(|b| *b != "_")
        {
            engine_names.insert(b);
        }
    }
    close_taint_aliases(
        &core_leaves,
        &core_aliases,
        &mut engine_names,
        |rhs, set| names_engine_or_command(rhs, set).is_some(),
    );
    for &n in &core_files {
        let (Some(f), Some(toks), Some(leaves)) =
            (sources.get(n), all_toks.get(n), all_leaves.get(n))
        else {
            continue;
        };
        let file = f.rel.rsplit('/').next().unwrap_or("");
        let in_port = f.rel.contains("/src/port.rs") || f.rel.contains("/src/port/");
        for leaf in leaves.iter().filter(|l| l.public) {
            let path = leaf.segs.join("::");
            let named_refused = leaf
                .segs
                .iter()
                .chain(leaf.bound.iter())
                .any(|s| API_CORE_REFUSED.contains(s));
            let domain_command =
                leaf.segs.first() == Some(&"fstp_domain") && leaf.segs.get(1) == Some(&"command");
            let engine = leaf.segs.first() == Some(&"fstp_engine");
            let inner = rooted_at(leaf, &API_CORE_INNER);
            let glob = leaf.segs.last() == Some(&"*");
            let allowed_inner = !glob
                && match file {
                    "ids.rs" => leaf.bound.is_some_and(|b| b.ends_with("Id")),
                    "meta.rs" => leaf.bound.is_some_and(|b| META_NAMES.contains(&b)),
                    _ => false,
                };
            if named_refused || domain_command || engine || (inner && !allowed_inner) {
                out.push(Finding::error(
                    "layering-m4-a2",
                    format!(
                        "{API_CORE} re-exports `{path}` in {}:{}; the API core exposes no engine, domain command, creator command or principal type, ids only through `ids` and tool metadata only through `meta` (I-84, M4 design section 1.3 rule A2)",
                        f.rel, leaf.line
                    ),
                ));
            }
            // The port module itself, under any name or as a glob.
            let port_module =
                leaf.segs.last() == Some(&"port") || (glob && leaf.segs.contains(&"port"));
            if !in_port
                && (port_module
                    || leaf
                        .segs
                        .last()
                        .into_iter()
                        .chain(leaf.bound.iter())
                        .any(|s| port_names.contains(s)))
            {
                out.push(Finding::error(
                    "layering-m4-a2",
                    format!(
                        "{API_CORE} re-exports the port `{path}` outside port.rs in {}:{} (I-84, M4 design section 1.3 rule A2)",
                        f.rel, leaf.line
                    ),
                ));
            }
        }
        if !in_port {
            for (line, sig) in public_signatures(toks) {
                if let Some(name) = sig.iter().find(|s| port_names.contains(*s)) {
                    out.push(Finding::error(
                        "layering-m4-a2",
                        format!(
                            "{API_CORE} names the port `{name}` in a public item outside port.rs in {}:{line}; adapters must not reach a port around dispatch (I-84, M4 design section 1.3 rule A2)",
                            f.rel
                        ),
                    ));
                }
                // A `pub use` is read through its leaves above.
                if sig.first() == Some(&"use") {
                    continue;
                }
                if let Some(what) = names_engine_or_command(&sig, &engine_names) {
                    out.push(Finding::error(
                        "layering-m4-a2",
                        format!(
                            "{API_CORE} names {what} in a public item outside port.rs in {}:{line}; a public type alias, field or signature re-exports an engine, domain command, creator command or principal type (I-84, M4 design sections 0.2 and 1.3 rule A2)",
                            f.rel
                        ),
                    ));
                }
            }
        }
    }

    // A2b.
    for adapter in [MCP, WEB] {
        for n in by_crate(adapter) {
            let (Some(f), Some(toks), Some(leaves)) =
                (sources.get(n), all_toks.get(n), all_leaves.get(n))
            else {
                continue;
            };
            let mut hits: BTreeSet<(usize, String)> = BTreeSet::new();
            for (i, t) in toks.iter().enumerate() {
                let prev = i
                    .checked_sub(1)
                    .and_then(|j| toks.get(j))
                    .map_or("", |x| x.s);
                let next = toks.get(i.saturating_add(1)).map_or("", |x| x.s);
                if ADAPTER_REFUSED.contains(&t.s) {
                    hits.insert((t.line, format!("`{}`", t.s)));
                }
                if t.s == "port" && (prev == "::" || next == "::") {
                    hits.insert((t.line, "the `port` module".to_owned()));
                }
            }
            for leaf in leaves {
                if leaf.segs.contains(&"port") {
                    hits.insert((leaf.line, "the `port` module".to_owned()));
                }
            }
            for (line, what) in hits {
                out.push(Finding::error(
                    "layering-m4-a2b",
                    format!(
                        "{adapter} names {what} in {}:{line}; adapters reach the cell only through `ApiCore::dispatch` (I-84, M4 design section 1.3 rule A2b)",
                        f.rel
                    ),
                ));
            }
        }
    }

    // A4, the import scan.
    for n in by_crate(IMPORT) {
        let (Some(f), Some(toks)) = (sources.get(n), all_toks.get(n)) else {
            continue;
        };
        for (line, what) in findings_paths(toks) {
            out.push(Finding::error(
                "layering-m4-a4",
                format!(
                    "{IMPORT} names {what} in {}:{line}; it uses only `fstp_findings::text::UntrustedText` (I-10, M4 design section 1.3 rule A4)",
                    f.rel
                ),
            ));
        }
    }

    // A6.
    let public_files = by_crate(PUBLIC);
    let public_leaves: Vec<UseLeaf<'_>> = public_files
        .iter()
        .filter_map(|&n| all_leaves.get(n))
        .flatten()
        .cloned()
        .collect();
    let mut tainted: BTreeSet<&str> = STATE_TYPES.iter().copied().collect();
    for leaf in &public_leaves {
        let state_root = match leaf.segs.split_first() {
            Some((&"fstp_domain", rest)) => rest
                .first()
                .is_none_or(|m| !DOMAIN_VALUE_MODULES.contains(m)),
            Some((first, _)) => STATE_CRATES.contains(first),
            None => false,
        };
        if state_root && let Some(b) = leaf.bound.filter(|b| *b != "_") {
            tainted.insert(b);
        }
    }
    let public_aliases: Vec<(&str, Vec<&str>)> = public_files
        .iter()
        .filter_map(|&n| all_toks.get(n))
        .flat_map(|t| type_aliases(t))
        .collect();
    close_taint_aliases(&public_leaves, &public_aliases, &mut tainted, |rhs, set| {
        state_path(rhs, set).is_some()
    });
    for &n in &public_files {
        let (Some(f), Some(toks), Some(leaves)) =
            (sources.get(n), all_toks.get(n), all_leaves.get(n))
        else {
            continue;
        };
        for leaf in leaves {
            if rooted_at(leaf, &STATE_CRATES) && leaf.segs.last() == Some(&"*") {
                out.push(Finding::error(
                    "layering-m4-a6",
                    format!(
                        "{PUBLIC} glob-imports `{}` in {}:{}; the names it binds cannot be followed, so the I-87 scan refuses it (M4 design section 1.3 rule A6)",
                        leaf.segs.join("::"),
                        f.rel,
                        leaf.line
                    ),
                ));
            }
        }
        if !public_view_file(f) {
            continue;
        }
        let mut hits: BTreeSet<(usize, String)> = BTreeSet::new();
        for (i, t) in toks.iter().enumerate() {
            let at = |k: usize| toks.get(i.saturating_add(k)).map_or("", |x| x.s);
            if t.s == "fstp_domain" {
                if !(at(1) == "::" && DOMAIN_VALUE_MODULES.contains(&at(2))) {
                    hits.insert((
                        t.line,
                        "a `fstp_domain` path outside `id` and `time`".to_owned(),
                    ));
                }
            } else if t.s == "fstp_engine" || t.s == "fstp_findings" || tainted.contains(t.s) {
                hits.insert((t.line, format!("`{}`", t.s)));
            }
        }
        for (line, what) in hits {
            out.push(Finding::error(
                "layering-m4-a6",
                format!(
                    "{PUBLIC} names {what} in {}:{line}; pages, tools and the feed take only a `PublicView` (I-87, M4 design section 1.3 rule A6)",
                    f.rel
                ),
            ));
        }
    }

    // A7.
    for krate in NO_SYSTEM {
        let files = by_crate(krate);
        let leaves: Vec<UseLeaf<'_>> = files
            .iter()
            .filter_map(|&n| all_leaves.get(n))
            .flatten()
            .cloned()
            .collect();
        let mut actor: BTreeSet<&str> = BTreeSet::from(["Actor"]);
        for leaf in &leaves {
            if leaf.segs.last() == Some(&"Actor")
                && let Some(b) = leaf.bound
            {
                actor.insert(b);
            }
        }
        let aliases: Vec<(&str, Vec<&str>)> = files
            .iter()
            .filter_map(|&n| all_toks.get(n))
            .flat_map(|t| type_aliases(t))
            .collect();
        close_taint_aliases(&leaves, &aliases, &mut actor, |rhs, set| {
            rhs.iter().any(|s| set.contains(s))
        });
        for &n in &files {
            let (Some(f), Some(toks), Some(file_leaves)) =
                (sources.get(n), all_toks.get(n), all_leaves.get(n))
            else {
                continue;
            };
            let mut hits: BTreeSet<usize> = BTreeSet::new();
            for (i, t) in toks.iter().enumerate() {
                let at = |k: usize| toks.get(i.saturating_add(k)).map_or("", |x| x.s);
                if t.s == "SystemCause"
                    || (actor.contains(t.s) && at(1) == "::" && at(2) == "System")
                {
                    hits.insert(t.line);
                }
            }
            for leaf in file_leaves {
                let through_actor = leaf.segs.windows(2).any(
                    |w| matches!(w, [a, b] if actor.contains(a) && (*b == "System" || *b == "*")),
                );
                if through_actor {
                    hits.insert(leaf.line);
                }
            }
            for line in hits {
                out.push(Finding::error(
                    "layering-m4-a7",
                    format!(
                        "{krate} names `SystemCause` or `Actor::System` in {}:{line}; no adapter or API core path issues a system command (M4 design section 1.3 rule A7)",
                        f.rel
                    ),
                ));
            }
        }
    }

    // A9b, names. A `use` may bind `ProfileSource` under another name.
    for krate in [CELL, CONTROL] {
        let files = by_crate(krate);
        let leaves: Vec<UseLeaf<'_>> = files
            .iter()
            .filter_map(|&n| all_leaves.get(n))
            .flatten()
            .cloned()
            .collect();
        let mut profile_trait: BTreeSet<&str> = BTreeSet::from([PROFILE_TRAIT]);
        for leaf in &leaves {
            if leaf.segs.last() == Some(&PROFILE_TRAIT)
                && let Some(b) = leaf.bound.filter(|b| *b != "_")
            {
                profile_trait.insert(b);
            }
        }
        close_taint(&leaves, &mut profile_trait);
        for n in files {
            let (Some(f), Some(toks)) = (sources.get(n), all_toks.get(n)) else {
                continue;
            };
            for (i, t) in toks.iter().enumerate() {
                let next = toks.get(i.saturating_add(1)).map_or("", |x| x.s);
                let implements = profile_trait.contains(t.s) && next == "for";
                let other_set = t.s.ends_with("Profiles") && t.s != SHIPPED_PROFILES;
                if implements || other_set {
                    out.push(Finding::error(
                        "layering-m4-a9b",
                        format!(
                            "{krate} names `{}` in {}:{}; production loads the shipped profiles only, through `{SHIPPED_PROFILES}` (M4 design section 1.3 rule A9b)",
                            t.s, f.rel, t.line
                        ),
                    ));
                }
            }
        }
    }

    // A9b, the marker in shipped sources.
    let mark = marker();
    for f in sources.iter().filter(|f| f.krate != TESTKIT) {
        for (i, line) in f.text.lines().enumerate() {
            if line.contains(&mark) {
                out.push(Finding::error(
                    "layering-m4-a9b",
                    format!(
                        "{} holds the synthetic legal-wording marker in {}:{}; it lives only in {TESTKIT} (M4 design section 1.3 rule A9b)",
                        f.krate,
                        f.rel,
                        i.saturating_add(1)
                    ),
                ));
            }
        }
    }

    // A9b, the marker in the shipped profile tree.
    let profiles = Path::new(&meta.workspace_root).join(GUIDE_PROFILES);
    let mut files = Vec::new();
    collect_files(&profiles, 0, &mut files, &mut out);
    for p in files {
        let rel = p
            .strip_prefix(&meta.workspace_root)
            .unwrap_or(&p)
            .display()
            .to_string();
        match fs::metadata(&p) {
            Ok(m) if m.len() > MAX_PROFILE_FILE => {
                out.push(Finding::error(
                    "scan-limit",
                    format!("{rel} is larger than {MAX_PROFILE_FILE} bytes"),
                ));
                continue;
            }
            Ok(_) => {}
            Err(e) => {
                out.push(Finding::error("scan-io", format!("cannot read {rel}: {e}")));
                continue;
            }
        }
        match fs::read(&p) {
            Ok(bytes) if String::from_utf8_lossy(&bytes).contains(&mark) => {
                out.push(Finding::error(
                    "layering-m4-a9b",
                    format!(
                        "{rel} holds the synthetic legal-wording marker; the shipped profiles of fstp-guide never carry it (M4 design section 1.3 rule A9b)"
                    ),
                ));
            }
            Ok(_) => {}
            Err(e) => out.push(Finding::error("scan-io", format!("cannot read {rel}: {e}"))),
        }
    }

    // A10, sources.
    let members = members(meta);
    for krate in PURE_M4 {
        let lib_root = members
            .get(krate)
            .and_then(|&i| meta.packages.get(i))
            .and_then(|p| {
                p.targets
                    .iter()
                    .find(|t| t.kinds.iter().any(|k| k == "lib" || k == "rlib"))
            })
            .map(|t| t.src_path.clone());
        for n in by_crate(krate) {
            let (Some(f), Some(toks)) = (sources.get(n), all_toks.get(n)) else {
                continue;
            };
            let is_root = lib_root.as_deref().is_some_and(|r| r.ends_with(&f.rel));
            if is_root {
                let missing: Vec<&str> = LINT_HEADER
                    .iter()
                    .copied()
                    .filter(|l| !denied_lints(toks).contains(l))
                    .collect();
                if !missing.is_empty() {
                    out.push(Finding::error(
                        "layering-m4-a10",
                        format!(
                            "{krate} does not deny clippy::{} in its library root {}; the pure M4 crates carry the M2 lint header (M4 design section 1.3 rule A10)",
                            missing.join(", clippy::"),
                            f.rel
                        ),
                    ));
                }
            }
            for (line, what) in floats(&f.text) {
                out.push(Finding::error(
                    "layering-m4-a10",
                    format!(
                        "{krate} names {what} in {}:{line}; the pure M4 crates use no floats (M4 design section 1.3 rule A10)",
                        f.rel
                    ),
                ));
            }
        }
    }
    out
}

/// Every `fstp_findings` path in `toks` that is not
/// `fstp_findings::text::UntrustedText`, as a line and a description. An
/// alias, a glob and a group with any other name fail (rule A4).
pub(crate) fn findings_paths(toks: &[Tok<'_>]) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let s = |j: usize| toks.get(j).map_or("", |t| t.s);
    for (i, t) in toks.iter().enumerate() {
        if t.s != "fstp_findings" {
            continue;
        }
        let at = |k: usize| s(i.saturating_add(k));
        let direct = at(1) == "::" && at(2) == "text" && at(3) == "::" && at(4) == "UntrustedText";
        let grouped = at(1) == "::"
            && at(2) == "text"
            && at(3) == "::"
            && at(4) == "{"
            && at(5) == "UntrustedText"
            && (at(6) == "}" || (at(6) == "," && at(7) == "}"));
        let ok = (direct && at(5) != "as") || grouped;
        if !ok {
            let shown: Vec<&str> = (0..6).map(at).take_while(|x| !x.is_empty()).collect();
            out.push((t.line, format!("`{}`", shown.join(""))));
        }
    }
    out
}

/// The clippy lints a `#![deny(...)]` or `#![forbid(...)]` inner attribute
/// in `toks` names.
pub(crate) fn denied_lints<'a>(toks: &[Tok<'a>]) -> BTreeSet<&'a str> {
    let mut out = BTreeSet::new();
    let s = |j: usize| toks.get(j).map_or("", |t| t.s);
    for i in 0..toks.len() {
        let at = |k: usize| s(i.saturating_add(k));
        if !(at(0) == "#"
            && at(1) == "!"
            && at(2) == "["
            && matches!(at(3), "deny" | "forbid")
            && at(4) == "(")
        {
            continue;
        }
        let mut j = i.saturating_add(5);
        while let Some(t) = toks.get(j) {
            if t.s == ")" {
                break;
            }
            if t.s == "clippy" && s(j.saturating_add(1)) == "::" {
                let name = s(j.saturating_add(2));
                if !name.is_empty() {
                    out.insert(name);
                }
            }
            j = j.saturating_add(1);
        }
    }
    out
}

/// Every float type name and float literal in the code of `text`, as a
/// line and a description. Comments and string literals are skipped.
pub(crate) fn floats(text: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let base = text.as_ptr() as usize;
    let bytes = text.as_bytes();
    let lexed = lex(text);
    let mut skip_to = 0usize;
    for l in &lexed.lexemes {
        let at = (l.s.as_ptr() as usize).saturating_sub(base);
        if at < skip_to {
            continue;
        }
        match l.kind {
            LexKind::Ident if l.s == "f32" || l.s == "f64" => {
                out.push((l.line, format!("the float type `{}`", l.s)));
            }
            LexKind::Punct if l.s.bytes().all(|b| b.is_ascii_digit()) => {
                // A literal starts at a digit that does not continue an
                // identifier, a number or a tuple index.
                let prev = at.checked_sub(1).and_then(|p| bytes.get(p)).copied();
                if prev.is_some_and(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.') {
                    continue;
                }
                let mut end = at;
                while bytes
                    .get(end)
                    .is_some_and(|&b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.')
                {
                    end = end.saturating_add(1);
                }
                skip_to = end;
                let lit = text.get(at..end).unwrap_or("");
                // A trailing `.` before a non-ASCII identifier is a field
                // or method access, not a float.
                let field_after = lit.ends_with('.') && bytes.get(end).is_some_and(|&b| b >= 0x80);
                if float_literal(lit) && !field_after {
                    out.push((l.line, format!("the float literal `{lit}`")));
                }
            }
            _ => {}
        }
    }
    out
}

/// Whether a numeric token, as written, is a float literal.
fn float_literal(lit: &str) -> bool {
    let lower = lit.to_ascii_lowercase();
    if lower.starts_with("0x") || lower.starts_with("0o") || lower.starts_with("0b") {
        return false;
    }
    if lower.ends_with("f32") || lower.ends_with("f64") {
        return true;
    }
    // The number part ends at the first `.`. It is a float when a digit
    // follows the `.` or nothing does, as in `1.`. So `1.max(2)` and
    // `0..5` are integers, and `1.` is a float.
    let b = lower.as_bytes();
    let mut i = 0usize;
    while let Some(&c) = b.get(i) {
        match c {
            b'.' => {
                return b.get(i.saturating_add(1)).is_none_or(u8::is_ascii_digit);
            }
            b'e' => {
                let next = b.get(i.saturating_add(1));
                return next.is_some_and(|n| n.is_ascii_digit() || *n == b'+' || *n == b'-');
            }
            b'0'..=b'9' | b'_' => i = i.saturating_add(1),
            _ => return false,
        }
    }
    false
}

/// Collects every file below `dir`, in order, without following symbolic
/// links. A missing directory gives no file.
fn collect_files(dir: &Path, depth: usize, out: &mut Vec<PathBuf>, findings: &mut Vec<Finding>) {
    if depth > 32 {
        findings.push(Finding::error(
            "scan-limit",
            format!("{} is nested deeper than 32 levels", dir.display()),
        ));
        return;
    }
    let Ok(reader) = fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<PathBuf> = reader.flatten().map(|e| e.path()).collect();
    entries.sort();
    for p in entries {
        let Ok(m) = fs::symlink_metadata(&p) else {
            continue;
        };
        if m.is_dir() {
            collect_files(&p, depth.saturating_add(1), out, findings);
        } else if m.is_file() {
            if out.len() >= MAX_PROFILE_FILES {
                findings.push(Finding::error(
                    "scan-limit",
                    format!("{GUIDE_PROFILES} holds more than {MAX_PROFILE_FILES} files"),
                ));
                return;
            }
            out.push(p);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(krate: &str, rel: &str, text: &str) -> SourceFile {
        SourceFile {
            krate: krate.into(),
            rel: rel.into(),
            text: text.into(),
        }
    }

    fn scan_one(krate: &str, rel: &str, text: &str) -> Vec<Finding> {
        scan(&[file(krate, rel, text)], &Metadata::default())
    }

    fn has(findings: &[Finding], code: &str) -> bool {
        findings.iter().any(|f| f.code == code)
    }

    /// I-84, rule A2: the API core re-exports ids only through `ids`, tool
    /// metadata only through `meta`, and no engine, domain command,
    /// `Actor`, creator command or principal anywhere.
    #[test]
    fn i84_a2_api_core_reexports() {
        let refused = [
            ("src/lib.rs", "pub use fstp_engine::Command;\n"),
            ("src/lib.rs", "pub use fstp_domain::command::Ctx;\n"),
            ("src/lib.rs", "pub use fstp_domain::{Actor};\n"),
            (
                "src/ids.rs",
                "pub use fstp_access::Principal as PrincipalId;\n",
            ),
            ("src/ids.rs", "pub use fstp_domain::id::*;\n"),
            ("src/meta.rs", "pub use fstp_access::OpSpec;\n"),
            ("src/lib.rs", "pub use fstp_creator::CreatorCommand;\n"),
            ("src/lib.rs", "pub use fstp_domain::id::AccountId;\n"),
            ("src/lib.rs", "pub use port::CellPorts;\n"),
            ("src/read.rs", "pub fn f<P: CellPorts>(p: P) {}\n"),
            (
                "src/read.rs",
                "use crate::port::AsyncEngine as E;\npub struct X;\nimpl X { pub fn g(&self, e: &dyn E) {} }\n",
            ),
            ("src/read.rs", "pub type Ports = Box<dyn Sessions>;\n"),
            (
                "src/lib.rs",
                "pub type EngineCommand = fstp_engine::Command;\n",
            ),
            (
                "src/lib.rs",
                "use fstp_engine::Command;\npub struct W { pub cmd: Command }\n",
            ),
            ("src/lib.rs", "pub use crate::port::*;\n"),
            ("src/lib.rs", "pub use self::port as ports;\n"),
            (
                "src/read.rs",
                "type C = fstp_domain::command::Ctx;\npub type D = C;\n",
            ),
            ("src/read.rs", "pub fn anon() -> Principal { x() }\n"),
            ("src/ids.rs", "pub type Cmd = fstp_engine::Command;\n"),
            (
                "src/read.rs",
                "type S = dyn Sessions;\npub fn f(s: &S) {}\n",
            ),
        ];
        for (rel, text) in refused {
            let found = scan_one(API_CORE, &format!("crates/fstp-api-core/{rel}"), text);
            assert!(
                has(&found, "layering-m4-a2"),
                "not refused: {rel}: {text:?}"
            );
        }
        let allowed = [
            (
                "src/ids.rs",
                "pub use fstp_domain::id::{AccountId, CallId};\npub use crate::port::SessionId;\n",
            ),
            (
                "src/meta.rs",
                "pub use fstp_access::{Classification, Scope, ToolDef};\n",
            ),
            (
                "src/port.rs",
                "pub trait CellPorts {}\npub fn api_core<P: CellPorts>(p: P) {}\n",
            ),
            (
                "src/lib.rs",
                "pub struct ApiCore { inner: Box<dyn port::Dispatch> }\npub(crate) fn x<P: CellPorts>() {}\n",
            ),
            (
                "src/lib.rs",
                "pub mod port;\npub type Res = Result<OpResult, ApiError>;\npub(crate) type C = fstp_engine::Command;\n",
            ),
            (
                "src/port.rs",
                "pub trait AsyncEngine { fn execute(&self, cmd: fstp_engine::Command); }\n",
            ),
        ];
        for (rel, text) in allowed {
            let found = scan_one(API_CORE, &format!("crates/fstp-api-core/{rel}"), text);
            assert!(found.is_empty(), "{rel}: {text:?}: {found:?}");
        }
    }

    /// I-84, rule A2b: adapters name no port, principal or execution
    /// metadata.
    #[test]
    fn i84_a2b_adapters_name_no_port() {
        for text in [
            "use fstp_api_core::port::CellPorts;\n",
            "use fstp_api_core::{port};\n",
            "use fstp_api_core::port as p;\n",
            "fn f(m: ExecMeta) {}\n",
            "fn f() -> Principal { todo() }\n",
        ] {
            let found = scan_one(MCP, "crates/fstp-mcp/src/lib.rs", text);
            assert!(has(&found, "layering-m4-a2b"), "not refused: {text:?}");
        }
        let found = scan_one(
            WEB,
            "crates/fstp-web/src/lib.rs",
            "use fstp_api_core::{ApiCore, ids::SessionId};\nfn f(port: u16) { let _ = port; }\n",
        );
        assert!(found.is_empty(), "{found:?}");
    }

    /// I-10, rule A4: `fstp-import` names only
    /// `fstp_findings::text::UntrustedText`.
    #[test]
    fn i10_a4_import_names_only_untrusted_text() {
        for text in [
            "use fstp_findings::Finding;\n",
            "use fstp_findings::text::{UntrustedText, Other};\n",
            "use fstp_findings as f;\n",
            "use fstp_findings::text::UntrustedText as T;\n",
            "use fstp_findings::*;\n",
        ] {
            let found = scan_one(IMPORT, "crates/fstp-import/src/lib.rs", text);
            assert!(has(&found, "layering-m4-a4"), "not refused: {text:?}");
        }
        for text in [
            "use fstp_findings::text::UntrustedText;\n",
            "use fstp_findings::text::{UntrustedText};\nfn f(t: fstp_findings::text::UntrustedText) {}\n",
        ] {
            let found = scan_one(IMPORT, "crates/fstp-import/src/lib.rs", text);
            assert!(found.is_empty(), "{text:?}: {found:?}");
        }
    }

    /// I-87, rule A6: pages, tools and the feed name no state type, also
    /// through a name the crate imported elsewhere.
    #[test]
    fn i87_a6_view_files_name_no_state_type() {
        for (other, text) in [
            ("", "fn f(s: &State) {}\n"),
            ("", "use fstp_domain::state::Proposal;\n"),
            ("", "fn f(s: &fstp_engine::EngineState) {}\n"),
            (
                "pub use fstp_domain::State as Core;\n",
                "use crate::Core;\n",
            ),
            (
                "pub use fstp_domain::proposal as p;\n",
                "fn f(x: &p::Proposal) {}\n",
            ),
            (
                "type Core = fstp_domain::State;\n",
                "fn f(c: &crate::Core) {}\n",
            ),
            (
                "type P = fstp_domain::proposal::Proposal;\npub type Q = P;\n",
                "fn f(x: &crate::Q) {}\n",
            ),
        ] {
            let found = scan(
                &[
                    file(PUBLIC, "crates/fstp-public/src/lib.rs", other),
                    file(PUBLIC, "crates/fstp-public/src/html.rs", text),
                ],
                &Metadata::default(),
            );
            assert!(
                has(&found, "layering-m4-a6"),
                "not refused: {other:?} {text:?}"
            );
        }
        let found = scan(
            &[
                file(
                    PUBLIC,
                    "crates/fstp-public/src/view.rs",
                    "use fstp_domain::State;\nuse fstp_domain::id::ProgrammeId;\n",
                ),
                file(
                    PUBLIC,
                    "crates/fstp-public/src/feed.rs",
                    "use crate::view::PublicView;\nuse fstp_domain::id::ProgrammeId;\nfn f(v: &PublicView, p: ProgrammeId) {}\n",
                ),
            ],
            &Metadata::default(),
        );
        assert!(found.is_empty(), "{found:?}");
    }

    /// I-84, rule A7: no system actor from adapters or the API core. Design
    /// section 1.3 gives rule A7 no identifier. Interim reading: it serves
    /// I-84, since a system actor would skip the policy every call passes.
    #[test]
    fn i84_a7_no_system_actor() {
        for text in [
            "fn f() -> Actor { Actor::System(c) }\n",
            "use fstp_domain::command::SystemCause;\n",
            "use fstp_domain::Actor as A;\nfn f() { let _ = A::System; }\n",
            "use fstp_domain::Actor::System;\n",
            "use fstp_domain::Actor::*;\n",
            "type A = fstp_domain::Actor;\nfn f() { let _ = A::System; }\n",
        ] {
            let found = scan_one("fstp-oauth", "crates/fstp-oauth/src/lib.rs", text);
            assert!(has(&found, "layering-m4-a7"), "not refused: {text:?}");
        }
        let found = scan_one(
            API_CORE,
            "crates/fstp-api-core/src/x.rs",
            "fn f(a: AccountId) -> Actor { Actor::Account(a) }\n",
        );
        assert!(!has(&found, "layering-m4-a7"), "{found:?}");
    }

    /// Rule A9b: the cell implements no other profile source, and the
    /// synthetic marker stays in the test kit. Design section 1.3 gives
    /// rule A9b no I- or R- identifier, and none applies.
    #[test]
    fn a9b_cell_loads_shipped_profiles_only() {
        let found = scan_one(
            CELL,
            "crates/fstp-cell/src/routes/m4.rs",
            "use fstp_guide::ProfileSource as P;\nimpl P for Mine {}\n",
        );
        assert!(has(&found, "layering-m4-a9b"), "{found:?}");
        let found = scan_one(
            CELL,
            "crates/fstp-cell/src/routes/m4.rs",
            "impl ProfileSource for Mine {}\n",
        );
        assert!(has(&found, "layering-m4-a9b"), "{found:?}");
        let found = scan_one(
            CELL,
            "crates/fstp-cell/src/routes/m4.rs",
            "fn f() -> SyntheticProfiles { x }\n",
        );
        assert!(has(&found, "layering-m4-a9b"), "{found:?}");
        let text = format!("const W: &str = \"{}\";\n", marker());
        let found = scan_one("fstp-guide", "crates/fstp-guide/src/lib.rs", &text);
        assert!(has(&found, "layering-m4-a9b"), "{found:?}");
        let found = scan_one(TESTKIT, "crates/fstp-api-testkit/src/profiles.rs", &text);
        assert!(found.is_empty(), "{found:?}");
        let found = scan_one(
            CELL,
            "crates/fstp-cell/src/lib.rs",
            "fn f(p: &ShippedProfiles) {}\n",
        );
        assert!(found.is_empty(), "{found:?}");
    }

    /// ADR-006 and I-70, rule A10: float types and literals are found, and
    /// integers, ranges, tuple indices and method calls are not.
    #[test]
    fn adr006_a10_floats_found_in_code_only() {
        let text = "let a: f64 = 1.5;\nlet b = 2e3;\nlet c = 3f32;\nlet d = 0..5;\nlet e = t.0.1;\nlet f = 1.max(2);\nlet g = 0x1e5;\n// 4.5 in a comment\nlet h = \"6.5\";\nlet i = 1_000.25;\n";
        let found: Vec<usize> = floats(text).into_iter().map(|(l, _)| l).collect();
        assert_eq!(found, vec![1, 1, 2, 3, 10], "{:?}", floats(text));
    }

    /// ADR-006 and I-70, rule A10: a literal with a trailing `.` is a
    /// float, and a range or a method call on an integer is not.
    #[test]
    fn adr006_a10_trailing_dot_literal_is_a_float() {
        let text = "let a = 1.;\nlet b = (2.);\nlet c = 0..;\nlet d = 3.min(4);\nlet e = 5..=6;\n";
        let found: Vec<usize> = floats(text).into_iter().map(|(l, _)| l).collect();
        assert_eq!(found, vec![1, 2], "{:?}", floats(text));
    }

    /// ADR-006 and I-70, rule A10: the lint header is read from the inner
    /// attribute.
    #[test]
    fn adr006_a10_lint_header_is_read() {
        let text = "//! x\n#![deny(\n    clippy::float_arithmetic,\n    clippy::float_cmp,\n    clippy::cast_precision_loss,\n    clippy::arithmetic_side_effects\n)]\n";
        let toks = tokens(text);
        let got = denied_lints(&toks);
        assert!(LINT_HEADER.iter().all(|l| got.contains(l)), "{got:?}");
        assert!(denied_lints(&tokens("#[deny(clippy::float_cmp)]\n")).is_empty());
    }

    /// Rule A8: the licence of a manifest is read, with workspace
    /// inheritance.
    #[test]
    fn a8_licence_fields_are_read() {
        assert_eq!(
            table_licence(
                "[package]\nname = \"x\"\nlicense = \"EUPL-1.2\"\n",
                "package"
            ),
            Some(Licence::Value("EUPL-1.2".into()))
        );
        assert_eq!(
            table_licence("[package]\nlicense.workspace = true\n", "package"),
            Some(Licence::Workspace)
        );
        assert_eq!(
            table_licence(
                "[package]\nlicense = { workspace = true }\n[dependencies]\nlicense = \"no\"\n",
                "package"
            ),
            Some(Licence::Workspace)
        );
        assert_eq!(
            table_licence(
                "[workspace.package]\nlicense = \"PolyForm-Noncommercial-1.0.0\"\n",
                "workspace.package"
            ),
            Some(Licence::Value("PolyForm-Noncommercial-1.0.0".into()))
        );
        assert_eq!(
            table_licence("[dependencies]\nlicense = \"EUPL\"\n", "package"),
            None
        );
    }

    /// R-NF-07: the SBOM reads the same field, so an SPDX expression keeps
    /// its spaces.
    #[test]
    fn r_nf_07_licence_expression_keeps_spaces() {
        assert_eq!(
            table_licence("[package]\nlicense = \"MIT OR Apache-2.0\"\n", "package"),
            Some(Licence::Value("MIT OR Apache-2.0".into()))
        );
    }
}
