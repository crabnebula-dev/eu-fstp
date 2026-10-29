//! End-to-end fixtures for the M4 rules of deps-check
//! (`docs/handoff/m4-design.md` sections 1.3 and 3.9, ADR-014).
//!
//! Each test builds a small repository in a temporary directory and runs
//! the deps-check binary on it, as `m3_rules.rs` does. The designed M4
//! graph passes. Each test then seeds violations of one rule and expects
//! the rule's error for each.
//!
//! | Rule | Code |
//! | --- | --- |
//! | A1, adapter dependencies (I-84) | `layering-m4-a1` |
//! | A2, the API core exposes no command type and no port (I-84) | `layering-m4-a2` |
//! | A2b, adapters never name ports (I-84) | `layering-m4-a2b` |
//! | A3, the I-65 boundary | `layering-m4-a3` |
//! | A4, the I-10 boundary | `layering-m4-a4` |
//! | A5, the I-86 boundary | `layering-m4-a5` |
//! | A6, the I-87 boundary | `layering-m4-a6` |
//! | A7, no system actors from adapters | `layering-m4-a7` |
//! | A8, the EUPL boundary (R-TD-03) | `layering-m4-a8` |
//! | A9, test code never ships | `layering-m4-a9` |
//! | A9b, production loads shipped profiles only | `layering-m4-a9b` |
//! | A10, pure crates stay pure | `layering-m4-a10` |
//! | The scanned crates rename no in-house crate | `layering-m4-rename` |
//! | The TypeScript source scan (ADR-014) | `web-scan` |
//!
//! Identifiers and markers that a source scan refuses are assembled at run
//! time. This file then never trips the scans it tests when deps-check
//! runs on the real repository.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// The marker of the synthetic legal-wording profile (rule A9b).
fn marker() -> String {
    ["SYNTHETIC", "TEST", "WORDING"].join(" ")
}

/// The M2 lint header that rule A10 requires.
const HEADER: &str = "#![deny(\n    clippy::float_arithmetic,\n    clippy::float_cmp,\n    clippy::cast_precision_loss,\n    clippy::arithmetic_side_effects\n)]\n";

fn cargo() -> PathBuf {
    std::env::var_os("CARGO").map_or_else(|| PathBuf::from("cargo"), PathBuf::from)
}

/// A temporary repository, removed on drop.
struct Repo {
    base: PathBuf,
    root: PathBuf,
}

impl Drop for Repo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

impl Repo {
    fn new(tag: &str) -> Repo {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let base =
            std::env::temp_dir().join(format!("deps-check-m4-{tag}-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let repo = Repo {
            root: base.join("repo"),
            base,
        };
        repo.write("deps/allowlist.txt", "# empty\n");
        repo.write("deps/adr-roots.txt", "# empty\n");
        repo.write("deps/fuzz-required.txt", "# empty\n");
        repo.write("deps/funds-allowed.txt", "# empty\n");
        repo.write("deps/tier-b-confirmations.txt", "# none\n");
        repo.write("docs/adr/README.md", "ADRs\n");
        repo
    }

    fn write(&self, rel: &str, text: &str) {
        let p = self.root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, text).unwrap();
    }

    fn lock(&self) {
        let out = Command::new(cargo())
            .arg("generate-lockfile")
            .arg("--offline")
            .arg("--manifest-path")
            .arg(self.root.join("Cargo.toml"))
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// Runs deps-check and returns whether it passed, and its report.
    fn check(&self) -> (bool, String) {
        let bin = std::env::var_os("FSTP_DEPS_CHECK_BIN").map_or_else(
            || PathBuf::from(env!("CARGO_BIN_EXE_deps-check")),
            PathBuf::from,
        );
        let out = Command::new(bin)
            .arg("--root")
            .arg(&self.root)
            .arg("--offline")
            .output()
            .unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        (out.status.success(), text)
    }
}

/// Whether `text` holds an error line `error[code...]: ...` that names
/// each of `names`.
fn has_finding(text: &str, code: &str, names: &[&str]) -> bool {
    let head = format!("error[{code}");
    text.lines().any(|l| {
        let l = l.trim_start();
        l.starts_with(&head) && names.iter().all(|n| l.contains(n))
    })
}

/// Asserts that the gate fails with one finding of `code` for each entry
/// of `expected`.
fn assert_all(repo: &Repo, code: &str, expected: &[&[&str]]) {
    let (ok, text) = repo.check();
    assert!(!ok, "the gate passed:\n{text}");
    for names in expected {
        assert!(
            has_finding(&text, code, names),
            "no error[{code}] naming {names:?}:\n{text}"
        );
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Normal,
    Dev,
}

const N: Kind = Kind::Normal;
const D: Kind = Kind::Dev;

struct CrateSpec {
    name: &'static str,
    deps: Vec<(&'static str, Kind)>,
    bin: bool,
    /// Extra manifest lines in `[package]`.
    package_extra: String,
    /// Source files below the crate directory, beyond `src/lib.rs`.
    files: Vec<(String, String)>,
    lib: String,
}

/// The designed graph: M1 and M2 crates, the M4 crates of design section
/// 1.1 and the M3 crates the M4 rules name.
struct Graph {
    crates: Vec<CrateSpec>,
    /// Files outside any crate, such as `web/src/**`.
    files: Vec<(String, String)>,
}

/// The pure M4 crates (rule A10).
const PURE: [&str; 9] = [
    "fstp-programme",
    "fstp-creator",
    "fstp-import",
    "fstp-guide",
    "fstp-public",
    "fstp-tenant",
    "fstp-access",
    "fstp-signup",
    "fstp-html",
];

const M4: [&str; 15] = [
    "fstp-programme",
    "fstp-creator",
    "fstp-import",
    "fstp-html",
    "fstp-guide",
    "fstp-public",
    "fstp-tenant",
    "fstp-access",
    "fstp-api-core",
    "fstp-oauth",
    "fstp-mcp",
    "fstp-signup",
    "fstp-web",
    "fstp-web-assets",
    "fstp-api-testkit",
];

fn designed() -> Graph {
    let table: Vec<(&'static str, Vec<&'static str>)> = vec![
        ("tokio", vec![]),
        ("fstp-prop", vec![]),
        ("fstp-mc", vec![]),
        ("fstp-json", vec![]),
        ("fstp-crypto", vec![]),
        ("fstp-rt", vec!["tokio"]),
        ("fstp-tls", vec!["fstp-rt"]),
        ("fstp-http", vec!["fstp-rt", "fstp-tls"]),
        ("fstp-money", vec!["fstp-json"]),
        ("fstp-ledger", vec!["fstp-json"]),
        (
            "fstp-domain",
            vec!["fstp-money", "fstp-ledger", "fstp-json"],
        ),
        (
            "fstp-findings",
            vec!["fstp-domain", "fstp-money", "fstp-ledger", "fstp-json"],
        ),
        // The engine names both sides of the import bridge (rule A3).
        (
            "fstp-engine",
            vec![
                "fstp-domain",
                "fstp-findings",
                "fstp-money",
                "fstp-ledger",
                "fstp-json",
                "fstp-import",
                "fstp-creator",
            ],
        ),
        (
            "fstp-domain-testkit",
            vec![
                "fstp-engine",
                "fstp-findings",
                "fstp-domain",
                "fstp-prop",
                "fstp-mc",
            ],
        ),
        // M4, design section 1.1.
        (
            "fstp-programme",
            vec!["fstp-domain", "fstp-money", "fstp-json"],
        ),
        ("fstp-html", vec!["fstp-json"]),
        (
            "fstp-guide",
            vec!["fstp-domain", "fstp-programme", "fstp-html"],
        ),
        (
            "fstp-creator",
            vec![
                "fstp-programme",
                "fstp-guide",
                "fstp-domain",
                "fstp-ledger",
                "fstp-money",
                "fstp-json",
            ],
        ),
        (
            "fstp-import",
            vec![
                "fstp-programme",
                "fstp-ledger",
                "fstp-json",
                "fstp-findings",
            ],
        ),
        (
            "fstp-public",
            vec![
                "fstp-domain",
                "fstp-programme",
                "fstp-guide",
                "fstp-html",
                "fstp-json",
            ],
        ),
        (
            "fstp-tenant",
            vec!["fstp-domain", "fstp-ledger", "fstp-json"],
        ),
        (
            "fstp-access",
            vec![
                "fstp-domain",
                "fstp-engine",
                "fstp-creator",
                "fstp-import",
                "fstp-tenant",
            ],
        ),
        (
            "fstp-api-core",
            vec![
                "fstp-access",
                "fstp-engine",
                "fstp-domain",
                "fstp-ledger",
                "fstp-creator",
                "fstp-import",
                "fstp-public",
                "fstp-guide",
                "fstp-tenant",
                "fstp-json",
                "fstp-money",
                "fstp-crypto",
                "fstp-rt",
            ],
        ),
        ("fstp-oauth", vec!["fstp-json", "fstp-crypto"]),
        (
            "fstp-mcp",
            vec!["fstp-api-core", "fstp-oauth", "fstp-http", "fstp-json"],
        ),
        (
            "fstp-signup",
            vec!["fstp-html", "fstp-json", "fstp-crypto", "fstp-ledger"],
        ),
        (
            "fstp-web-assets",
            vec!["fstp-http", "fstp-crypto", "fstp-json"],
        ),
        (
            "fstp-web",
            vec![
                "fstp-api-core",
                "fstp-mcp",
                "fstp-oauth",
                "fstp-web-assets",
                "fstp-http",
                "fstp-json",
                "fstp-rt",
            ],
        ),
        (
            "fstp-api-testkit",
            vec![
                "fstp-programme",
                "fstp-creator",
                "fstp-import",
                "fstp-html",
                "fstp-guide",
                "fstp-public",
                "fstp-tenant",
                "fstp-access",
                "fstp-api-core",
                "fstp-oauth",
                "fstp-mcp",
                "fstp-signup",
                "fstp-web",
                "fstp-web-assets",
                "fstp-domain",
                "fstp-engine",
                "fstp-ledger",
                "fstp-json",
                "fstp-rt",
                "fstp-domain-testkit",
                "fstp-prop",
                "fstp-mc",
            ],
        ),
        ("gen-ts", vec!["fstp-access"]),
        // The M3 crates the M4 rules name.
        ("fstp-vault-proto", vec!["fstp-json", "fstp-money"]),
        ("fstp-vault-core", vec!["fstp-vault-proto", "fstp-money"]),
        (
            "fstp-vault",
            vec!["fstp-vault-core", "fstp-http", "fstp-tls", "fstp-rt"],
        ),
        (
            "fstp-cell",
            vec![
                "fstp-web",
                "fstp-api-core",
                "fstp-vault-proto",
                "fstp-http",
                "fstp-tls",
                "fstp-rt",
            ],
        ),
        ("fstp-control", vec!["fstp-signup", "fstp-http", "fstp-tls"]),
    ];
    let bins = [
        "fstp-cell",
        "fstp-control",
        "fstp-vault",
        "fstp-api-testkit",
        "gen-ts",
    ];
    let mut crates: Vec<CrateSpec> = table
        .into_iter()
        .map(|(name, deps)| CrateSpec {
            name,
            deps: deps.into_iter().map(|d| (d, N)).collect(),
            bin: bins.contains(&name),
            package_extra: String::new(),
            files: Vec::new(),
            lib: if PURE.contains(&name) {
                HEADER.to_owned()
            } else {
                String::new()
            },
        })
        .collect();
    for c in &mut crates {
        if M4.contains(&c.name) && c.name != "fstp-api-testkit" {
            c.deps.push(("fstp-prop", D));
        }
    }
    let mut g = Graph {
        crates,
        files: Vec::new(),
    };
    // The designed sources the scans read.
    g = g
        .file(
            "fstp-api-core",
            "src/port.rs",
            "pub trait CellPorts {}\npub trait AsyncEngine {}\npub fn api_core<P: CellPorts>(ports: P) {}\n",
        )
        .file(
            "fstp-api-core",
            "src/ids.rs",
            "pub use fstp_domain::id::{AccountId, ProgrammeId};\npub use crate::port::SessionId;\n",
        )
        .file(
            "fstp-api-core",
            "src/meta.rs",
            "pub use fstp_access::{Classification, Scope, ToolDef};\npub fn tools() {}\n",
        )
        .src(
            "fstp-api-core",
            "pub mod ids;\npub mod meta;\npub mod port;\npub struct ApiCore { inner: Box<dyn Dispatch> }\n",
        )
        .src(
            "fstp-import",
            "use fstp_findings::text::UntrustedText;\npub struct ExtractedText(UntrustedText);\n",
        )
        .file(
            "fstp-public",
            "src/view.rs",
            "use fstp_domain::State;\nuse fstp_domain::id::ProgrammeId;\npub struct PublicView;\npub fn public_view(core: &State, p: ProgrammeId) {}\n",
        )
        .file(
            "fstp-public",
            "src/html.rs",
            "use crate::view::PublicView;\nuse fstp_domain::id::ProgrammeId;\npub fn render_html(view: &PublicView, p: ProgrammeId) {}\n",
        )
        .src("fstp-mcp", "use fstp_api_core::{ApiCore, ids::SessionId};\n")
        .src("fstp-web", "pub fn serve(core: &fstp_api_core::ApiCore, port: u16) {}\n")
        .src(
            "fstp-oauth",
            "fn actor(a: AccountId) -> Actor { Actor::Account(a) }\n",
        )
        .src(
            "fstp-cell",
            "use fstp_guide::{ProfileSource, ShippedProfiles};\nfn profiles() -> ShippedProfiles { ShippedProfiles }\n",
        )
        .file(
            "fstp-api-testkit",
            "src/profiles.rs",
            &format!("pub const WORDING: &str = \"{}\";\n", marker()),
        );
    g.files.push((
        "crates/fstp-guide/profiles/horizon-europe/guide.v1.md".to_owned(),
        "# Guide for Applicants\n\nTODO(legal) wording pending.\n".to_owned(),
    ));
    g.files.push((
        "web/src/core/dom.ts".to_owned(),
        "import type { Operation } from \"../gen/api.js\";\nexport function text(el: HTMLElement, s: string): void {\n  el.textContent = s;\n}\n".to_owned(),
    ));
    g.files.push((
        "web/src/gen/api.ts".to_owned(),
        "export interface Operation { readonly name: string }\nexport const OPERATIONS: readonly Operation[] = [];\n".to_owned(),
    ));
    g
}

impl Graph {
    fn get_mut(&mut self, name: &str) -> &mut CrateSpec {
        self.crates
            .iter_mut()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("no crate {name} in the fixture"))
    }

    /// Adds a dependency edge, adding either crate when it is new.
    fn edge(mut self, from: &'static str, to: &'static str, kind: Kind) -> Graph {
        for name in [from, to] {
            if !self.crates.iter().any(|c| c.name == name) {
                self.crates.push(CrateSpec {
                    name,
                    deps: vec![],
                    bin: false,
                    package_extra: String::new(),
                    files: Vec::new(),
                    lib: String::new(),
                });
            }
        }
        self.get_mut(from).deps.push((to, kind));
        self
    }

    /// Appends `text` to a crate's `src/lib.rs`.
    fn src(mut self, krate: &'static str, text: &str) -> Graph {
        self.get_mut(krate).lib.push_str(text);
        self
    }

    /// Adds a file below a crate's directory.
    fn file(mut self, krate: &'static str, rel: &str, text: &str) -> Graph {
        self.get_mut(krate)
            .files
            .push((rel.to_owned(), text.to_owned()));
        self
    }

    /// Writes the workspace into a new repository and locks it.
    fn repo(&self, tag: &str) -> Repo {
        let repo = Repo::new(tag);
        let members: Vec<String> = self
            .crates
            .iter()
            .map(|c| format!("\"crates/{}\"", c.name))
            .collect();
        repo.write(
            "Cargo.toml",
            &format!(
                "[workspace]\nresolver = \"3\"\nmembers = [{}]\n",
                members.join(", ")
            ),
        );
        for c in &self.crates {
            let mut manifest = format!(
                "[package]\nname = \"{}\"\nversion = \"0.1.0\"\nedition = \"2024\"\n{}",
                c.name, c.package_extra
            );
            for (section, kind) in [("dependencies", N), ("dev-dependencies", D)] {
                let deps: Vec<String> = c
                    .deps
                    .iter()
                    .filter(|(_, k)| *k == kind)
                    .map(|(d, _)| format!("{d} = {{ path = \"../{d}\" }}\n"))
                    .collect();
                if !deps.is_empty() {
                    manifest.push_str(&format!("\n[{section}]\n{}", deps.concat()));
                }
            }
            repo.write(&format!("crates/{}/Cargo.toml", c.name), &manifest);
            repo.write(
                &format!("crates/{}/src/lib.rs", c.name),
                &format!("//! {}\n{}", c.name, c.lib),
            );
            for (rel, text) in &c.files {
                repo.write(&format!("crates/{}/{rel}", c.name), text);
            }
            if c.bin {
                repo.write(&format!("crates/{}/src/main.rs", c.name), "fn main() {}\n");
            }
        }
        for (rel, text) in &self.files {
            repo.write(rel, text);
        }
        repo.lock();
        repo
    }
}

/// M4 design section 1.3: the designed M4 graph and sources pass every
/// rule, M1 to M4. The test-only `fstp-api-testkit` takes `fstp-prop`,
/// `fstp-mc` and `fstp-domain-testkit` as normal dependencies, which the
/// M2 rule 3 allows for it.
#[test]
fn layering_m4_designed_graph_passes() {
    let repo = designed().repo("designed");
    let (ok, text) = repo.check();
    assert!(ok, "the designed M4 graph fails:\n{text}");
}

/// I-84, rule A1: an adapter depends on nothing outside its fixed set, and
/// no edge of any kind names a domain, engine or M3 crate.
#[test]
fn i84_layering_m4_a1_adapters_have_a_fixed_dependency_set() {
    let g = designed()
        .edge("fstp-mcp", "fstp-engine", N)
        .edge("fstp-web", "fstp-domain", D)
        .edge("fstp-mcp", "fstp-vault-proto", N)
        .edge("fstp-web", "fstp-money", N);
    let repo = g.repo("a1");
    assert_all(
        &repo,
        "layering-m4-a1",
        &[
            &["fstp-mcp", "fstp-engine"],
            &["fstp-web", "fstp-domain"],
            &["fstp-mcp", "fstp-vault-proto"],
            &["fstp-web", "fstp-money"],
        ],
    );
}

/// I-84, rule A2: the API core re-exports no engine or domain command
/// type, no principal and no port, and names no port in a public item
/// outside `port.rs`.
#[test]
fn i84_layering_m4_a2_api_core_exposes_no_command_or_port() {
    let g = designed()
        .src("fstp-api-core", "pub use fstp_engine::Command;\n")
        .file(
            "fstp-api-core",
            "src/read.rs",
            "pub fn engine<E: AsyncEngine>(e: &E) {}\npub use fstp_access::Principal;\n",
        );
    let repo = g.repo("a2");
    assert_all(
        &repo,
        "layering-m4-a2",
        &[
            &["fstp_engine::Command", "src/lib.rs"],
            &["AsyncEngine", "src/read.rs"],
            &["fstp_access::Principal", "src/read.rs"],
        ],
    );
}

/// I-84, rule A2b: adapters never name the port module, the principal or
/// the execution metadata.
#[test]
fn i84_layering_m4_a2b_adapters_never_name_ports() {
    let g = designed()
        .src("fstp-web", "use fstp_api_core::port::CellPorts;\n")
        .src("fstp-mcp", "fn meta(m: ExecMeta) {}\n");
    let repo = g.repo("a2b");
    assert_all(
        &repo,
        "layering-m4-a2b",
        &[&["fstp-web", "port"], &["fstp-mcp", "ExecMeta"]],
    );
}

/// I-65, rule A3: the creator, the programme and the domain cannot reach
/// the import store, the import store cannot reach the creator or the
/// engine, and only the bridge crates name both.
#[test]
fn i65_layering_m4_a3_import_boundary() {
    let g = designed()
        .edge("fstp-programme", "fstp-import", D)
        .edge("fstp-tenant", "fstp-creator", N)
        .edge("fstp-tenant", "fstp-import", N);
    let repo = g.repo("a3");
    assert_all(
        &repo,
        "layering-m4-a3",
        &[&["fstp-programme", "fstp-import"], &["fstp-tenant", "both"]],
    );
}

/// I-65, rule A3: the import store cannot reach the creator, even
/// through another crate.
#[test]
fn i65_layering_m4_a3_import_never_reaches_creator() {
    let repo = designed()
        .edge("fstp-import", "fstp-tenant", N)
        .edge("fstp-tenant", "fstp-creator", N)
        .repo("a3-creator");
    assert_all(
        &repo,
        "layering-m4-a3",
        &[&["fstp-import", "fstp-tenant", "fstp-creator"]],
    );
}

/// I-10, rule A4: the programme, the creator, the Guide and public pages
/// have no path to findings, and the import store names only
/// `fstp_findings::text::UntrustedText`.
#[test]
fn i10_layering_m4_a4_findings_boundary() {
    let g = designed()
        .edge("fstp-guide", "fstp-findings", N)
        .edge("fstp-public", "fstp-engine", D)
        .src("fstp-import", "use fstp_findings::Finding;\n");
    let repo = g.repo("a4");
    assert_all(
        &repo,
        "layering-m4-a4",
        &[
            &["fstp-guide", "fstp-findings"],
            &["fstp-creator", "fstp-findings"],
            &["fstp-public", "fstp-engine"],
            &["fstp-import", "fstp_findings::Finding"],
        ],
    );
}

/// I-86, rule A5: the MCP server, public pages, access and the API core
/// have no path to the vault client crates.
#[test]
fn i86_layering_m4_a5_vault_boundary() {
    let g =
        designed()
            .edge("fstp-public", "fstp-vault", N)
            .edge("fstp-access", "fstp-vault-proto", N);
    let repo = g.repo("a5");
    assert_all(
        &repo,
        "layering-m4-a5",
        &[
            &["fstp-public", "fstp-vault"],
            &["fstp-access", "fstp-vault-proto"],
            &["fstp-api-core", "fstp-vault-proto"],
            &["fstp-mcp", "fstp-vault-proto"],
        ],
    );
}

/// I-87, rule A6: pages, tools and the feed name no state type, directly
/// or through a name the crate imported.
#[test]
fn i87_layering_m4_a6_public_files_name_no_state_type() {
    let g = designed()
        .src("fstp-public", "pub use fstp_domain::State as Core;\n")
        .file(
            "fstp-public",
            "src/feed.rs",
            "use crate::Core;\npub fn feed(c: &Core) {}\n",
        )
        .file(
            "fstp-public",
            "src/tools.rs",
            "pub fn select(s: &fstp_engine::EngineState) {}\n",
        );
    let repo = g.repo("a6");
    assert_all(
        &repo,
        "layering-m4-a6",
        &[&["src/feed.rs", "Core"], &["src/tools.rs", "fstp_engine"]],
    );
}

/// I-84, rule A7: the API core, the MCP server and OAuth never build a
/// system actor (design section 1.3). The design gives rule A7 no
/// identifier. Interim reading: it serves I-84, since a system actor
/// would skip the policy every call passes.
#[test]
fn i84_layering_m4_a7_no_system_actor_from_adapters() {
    let g = designed()
        .src(
            "fstp-mcp",
            "fn sys(c: Cause) -> Actor { Actor::System(c) }\n",
        )
        .src(
            "fstp-api-core",
            "use fstp_domain::Actor as A;\nfn s() { let _ = A::System; }\n",
        );
    let repo = g.repo("a7");
    assert_all(
        &repo,
        "layering-m4-a7",
        &[
            &["fstp-mcp", "src/lib.rs"],
            &["fstp-api-core", "src/lib.rs"],
        ],
    );
}

/// R-TD-03, rule A8: no M4 crate reaches a package under the EUPL.
#[test]
fn r_td_03_layering_m4_a8_no_eupl_package() {
    let mut g =
        designed()
            .edge("fstp-signup", "fstp-export", N)
            .edge("fstp-export", "fstp-json", N);
    g.get_mut("fstp-export").package_extra = "license = \"EUPL-1.2\"\n".to_owned();
    let repo = g.repo("a8");
    assert_all(
        &repo,
        "layering-m4-a8",
        &[
            &["fstp-signup", "fstp-export"],
            &["fstp-api-testkit", "fstp-export"],
        ],
    );
}

/// Rule A9: no crate takes the M4 test kit as a normal dependency, and
/// the cell and the control plane take it as no dependency at all. Design
/// section 1.3 gives rule A9 no I- or R- identifier, and none applies.
#[test]
fn layering_m4_a9_test_kit_never_ships() {
    let g = designed().edge("fstp-tool", "fstp-api-testkit", N).edge(
        "fstp-control",
        "fstp-api-testkit",
        D,
    );
    let repo = g.repo("a9");
    assert_all(
        &repo,
        "layering-m4-a9",
        &[
            &["fstp-tool", "fstp-api-testkit"],
            &["fstp-control", "fstp-api-testkit"],
        ],
    );
}

/// Rule A9b: the cell implements no other profile source, and the
/// synthetic marker appears neither in shipped sources nor in the shipped
/// profile tree of `fstp-guide`. Design section 1.3 gives rule A9b no I-
/// or R- identifier, and none applies.
#[test]
fn layering_m4_a9b_production_loads_shipped_profiles_only() {
    let mut g = designed()
        .src(
            "fstp-cell",
            "struct Mine;\nimpl ProfileSource for Mine {}\n",
        )
        .src(
            "fstp-guide",
            &format!("pub const W: &str = \"{}\";\n", marker()),
        );
    g.files.push((
        "crates/fstp-guide/profiles/horizon-europe/annex.md".to_owned(),
        format!("{}. NOT LEGAL TEXT.\n", marker()),
    ));
    let repo = g.repo("a9b");
    assert_all(
        &repo,
        "layering-m4-a9b",
        &[
            &["fstp-cell", "ProfileSource"],
            &["fstp-guide", "src/lib.rs"],
            &["crates/fstp-guide/profiles/horizon-europe/annex.md"],
        ],
    );
}

/// ADR-006 and I-70, rule A10: the pure crates reach no I/O crate, carry
/// the M2 lint header and name no float. ADR-006 keeps floats from
/// amounts, and I-70 contrast is computed without floats (design section
/// 3.2).
#[test]
fn adr006_layering_m4_a10_pure_crates_stay_pure() {
    let mut g = designed()
        .edge("fstp-html", "fstp-rt", N)
        .src("fstp-programme", "pub fn ratio() -> f64 { 0.5 }\n");
    g.get_mut("fstp-tenant").lib = String::new();
    let repo = g.repo("a10");
    assert_all(
        &repo,
        "layering-m4-a10",
        &[
            &["fstp-html", "fstp-rt"],
            &["fstp-guide", "fstp-rt"],
            &["fstp-tenant", "float_arithmetic"],
            &["fstp-programme", "f64"],
            &["fstp-programme", "0.5"],
        ],
    );
}

/// Design section 1.3: the scanned crates rename no in-house dependency,
/// since the source scans match crate names.
#[test]
fn layering_m4_scanned_crates_rename_no_in_house_crate() {
    let repo = designed().repo("rename");
    let manifest = repo.root.join("crates/fstp-mcp/Cargo.toml");
    let text = fs::read_to_string(&manifest).unwrap().replace(
        "fstp-api-core = { path = \"../fstp-api-core\" }",
        "core = { package = \"fstp-api-core\", path = \"../fstp-api-core\" }",
    );
    fs::write(&manifest, text).unwrap();
    repo.lock();
    assert_all(
        &repo,
        "layering-m4-rename",
        &[&["fstp-mcp", "fstp-api-core", "`core`"]],
    );
}

/// ADR-014, design section 3.9: the web scan rejects `innerHTML` and an
/// import from outside `web/src`, and refuses a JavaScript file there.
#[test]
fn adr014_web_scan_rejects_inner_html_and_foreign_imports() {
    let mut g = designed();
    g.files.push((
        "web/src/core/render.ts".to_owned(),
        "import { x } from \"../../../e2e/helpers.js\";\nexport function put(el: HTMLElement, s: string): void {\n  el.innerHTML = s;\n}\n".to_owned(),
    ));
    g.files.push((
        "web/src/core/legacy.js".to_owned(),
        "export {};\n".to_owned(),
    ));
    let repo = g.repo("web-scan");
    assert_all(
        &repo,
        "web-scan",
        &[
            &["web/src/core/render.ts:3", "innerHTML"],
            &["web/src/core/render.ts:1", "e2e/helpers.js"],
            &["web/src/core/legacy.js"],
        ],
    );
}
