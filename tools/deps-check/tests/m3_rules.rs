//! End-to-end fixtures for the M3 rules of deps-check (`docs/handoff/m3-design.md`
//! sections 2.4 to 2.6, ADR-001 A3 and A5, ADR-002, ADR-003 amendment).
//!
//! Each test builds a small repository in a temporary directory and runs the
//! deps-check binary on it, as `review_gates.rs` does. A layered baseline
//! passes. Each test then seeds one violation and expects the rule's error.
//!
//! The rules match by finding code. These are the codes the tests expect:
//!
//! | Rule | Code |
//! | --- | --- |
//! | 2.4 rule 1, pure cores do no I/O | `layering-m3-pure-io` |
//! | 2.4 rule 2, vault narrowness | `layering-m3-vault` |
//! | 2.4 rule 3, one composer | `layering-m3-composer` |
//! | 2.4 rule 4, control plane (I-19, I-20) | `layering-m3-control-plane` |
//! | 2.4 rule 5, no tenant TLS server at the edge | `layering-m3-edge-tls` |
//! | 2.4 rule 6, I-39 | `layering-m3-i39` |
//! | 2.4 rule 7, I-80 | `layering-m3-i80` |
//! | 2.4 rule 8, Tier B confinement | `layering-m3-tier-b` |
//! | 2.4 rule 9, test and dev crates never ship | `layering-m3-test-only` |
//! | 2.4 rule 10, one runtime per binary (ADR-002) | `runtime-one-per-binary` |
//! | ADR-002, a runtime only behind `fstp-rt` | `runtime-direct` |
//! | 2.4 rule 11, funds (I-16) | `funds` |
//! | ADR-003 amendment, npm lockfile gate | any code starting with `npm` |
//! | 2.6 and ADR-001 A5, Tier B release gate | any code starting with `tier-b` |
//!
//! The git-source tests (ADR-001 A3) first show that the recorded source
//! passes, then seed one change and expect the gate to fail.
//!
//! Identifiers that a source scan refuses are assembled at run time. This
//! file then never trips the scans it tests when deps-check runs on the
//! real repository.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// `RootMaterial`, the identifier rule 7 confines to `fstp-keyd`.
fn root_material() -> String {
    ["Root", "Material"].concat()
}

/// `SeedSource` and `seed_fact`, the identifiers rule 9 confines to `fstp-celltest`.
fn seed_names() -> [String; 2] {
    [["Seed", "Source"].concat(), ["seed", "_fact"].concat()]
}

/// SEPA credit transfer (ISO 20022 pain.001) element names and the
/// document namespace. The funds rule refuses each in a crate's source.
fn sepa_terms() -> [String; 4] {
    [
        ["Cstmr", "CdtTrf", "Initn"].concat(),
        ["CdtTrf", "TxInf"].concat(),
        ["Dbtr", "Acct"].concat(),
        ["urn:iso:std:iso:20022:tech:xsd:", "pain.001.001.09"].concat(),
    ]
}

/// A payment account type that no M3 crate may name (I-16).
fn debtor_account() -> String {
    ["Debtor", "Account"].concat()
}

fn cargo() -> PathBuf {
    std::env::var_os("CARGO").map_or_else(|| PathBuf::from("cargo"), PathBuf::from)
}

/// A temporary repository, removed on drop.
struct Repo {
    base: PathBuf,
    root: PathBuf,
    /// A private `CARGO_HOME`, for fixtures with git sources.
    cargo_home: Option<PathBuf>,
}

impl Drop for Repo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

impl Repo {
    /// A minimal repository that passes every gate.
    fn new(tag: &str) -> Repo {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let base =
            std::env::temp_dir().join(format!("deps-check-m3-{tag}-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let repo = Repo {
            root: base.join("repo"),
            base,
            cargo_home: None,
        };
        repo.write(
            "Cargo.toml",
            "[workspace]\nresolver = \"3\"\nmembers = [\"crates/app\"]\n",
        );
        repo.write(
            "crates/app/Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        );
        repo.write("crates/app/src/lib.rs", "//! app\n");
        repo.write("deps/allowlist.txt", "# empty\n");
        repo.write("deps/adr-roots.txt", "# empty\n");
        repo.write("deps/fuzz-required.txt", "# empty\n");
        repo.write("deps/funds-allowed.txt", "# empty in M3\n");
        repo.write("deps/tier-b-confirmations.txt", "# none\n");
        repo.write("docs/adr/README.md", "ADRs\n");
        repo.lock(".");
        repo
    }

    /// The same, with its own `CARGO_HOME`, so git checkouts stay private.
    fn with_cargo_home(tag: &str) -> Repo {
        let mut repo = Repo::new(tag);
        let home = repo.base.join("cargo-home");
        fs::create_dir_all(&home).unwrap();
        repo.cargo_home = Some(home);
        repo
    }

    fn write(&self, rel: &str, text: &str) {
        let p = self.root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, text).unwrap();
    }

    fn remove(&self, rel: &str) {
        fs::remove_file(self.root.join(rel)).unwrap();
    }

    fn command(&self, program: &Path) -> Command {
        let mut c = Command::new(program);
        if let Some(home) = &self.cargo_home {
            c.env("CARGO_HOME", home);
        }
        c
    }

    /// Generates the lockfile of the project in `rel`. Offline, except for
    /// a repository with its own `CARGO_HOME`, whose git sources are local
    /// `file://` repositories.
    fn lock(&self, rel: &str) {
        let mut c = self.command(&cargo());
        c.arg("generate-lockfile");
        if self.cargo_home.is_none() {
            c.arg("--offline");
        }
        let out = c
            .arg("--manifest-path")
            .arg(self.root.join(rel).join("Cargo.toml"))
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// Runs deps-check with `extra` arguments and returns whether it
    /// passed, and its report.
    fn check_with(&self, extra: &[&str]) -> (bool, String) {
        let bin = std::env::var_os("FSTP_DEPS_CHECK_BIN").map_or_else(
            || PathBuf::from(env!("CARGO_BIN_EXE_deps-check")),
            PathBuf::from,
        );
        let out = self
            .command(&bin)
            .arg("--root")
            .arg(&self.root)
            .arg("--offline")
            .args(extra)
            .output()
            .unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        (out.status.success(), text)
    }

    fn assert_passes(&self, extra: &[&str], what: &str) {
        let (ok, text) = self.check_with(extra);
        assert!(ok, "{what}: the gate fails:\n{text}");
    }

    fn assert_fails(&self, extra: &[&str], what: &str) -> String {
        let (ok, text) = self.check_with(extra);
        assert!(!ok, "{what}: the gate passed:\n{text}");
        text
    }

    /// Asserts that the gate fails with a `severity[code...]` finding whose
    /// line names every one of `names`.
    fn assert_finding(&self, extra: &[&str], severity: &str, code: &str, names: &[&str]) {
        let (ok, text) = self.check_with(extra);
        if severity == "error" {
            assert!(!ok, "the gate passed:\n{text}");
        }
        assert!(
            has_finding(&text, severity, code, names),
            "no {severity}[{code}...] naming {names:?}:\n{text}"
        );
    }
}

/// Whether `text` holds a finding line `severity[code...]: ...` that names
/// each of `names`.
fn has_finding(text: &str, severity: &str, code: &str, names: &[&str]) -> bool {
    let head = format!("{severity}[{code}");
    text.lines().any(|l| {
        let l = l.trim_start();
        l.starts_with(&head) && names.iter().all(|n| l.contains(n))
    })
}

// ---------------------------------------------------------------------------
// The designed M3 graph (design section 2.1) as path crates.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Normal,
    Dev,
}

struct CrateSpec {
    name: &'static str,
    deps: Vec<(&'static str, Kind)>,
    bin: bool,
    src: String,
}

/// Every crate of the M1, M2 and M3 workspaces with its in-house edges.
/// `tokio`, `smol` and `moduletto` stand in as path crates: the M3 rules
/// match them by package name, whatever their source, as the M2 layering
/// rules do.
struct Graph {
    crates: Vec<CrateSpec>,
}

const N: Kind = Kind::Normal;
const D: Kind = Kind::Dev;

/// The binaries of design section 2.3, by crate.
const BIN_CRATES: [&str; 9] = [
    "fstp-cell",
    "fstp-vault",
    "fstp-keyd",
    "fstp-control",
    "fstp-witness",
    "fstp-edge",
    "fstp-release-svc",
    "fstp-backup",
    "fstp-celltest",
];

fn designed() -> Graph {
    let table: Vec<(&'static str, Vec<&'static str>)> = vec![
        // Stand-ins for third-party roots.
        ("tokio", vec![]),
        ("moduletto", vec![]),
        // M1.
        ("fstp-prop", vec![]),
        ("fstp-mc", vec![]),
        ("fstp-json", vec![]),
        ("fstp-crypto", vec!["moduletto"]),
        ("fstp-rt", vec!["tokio"]),
        ("fstp-tls", vec!["fstp-rt"]),
        ("fstp-http", vec!["fstp-rt", "fstp-tls"]),
        (
            "fstp-pgwire",
            vec!["fstp-rt", "fstp-tls", "fstp-crypto", "fstp-json"],
        ),
        ("fstp-pgtest", vec!["fstp-pgwire", "fstp-tls"]),
        (
            "fstp-migrate",
            vec!["fstp-pgwire", "fstp-crypto", "fstp-rt"],
        ),
        // M2.
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
        (
            "fstp-engine",
            vec![
                "fstp-domain",
                "fstp-findings",
                "fstp-money",
                "fstp-ledger",
                "fstp-json",
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
        // M3, design section 2.1.
        ("fstp-pki", vec!["fstp-crypto"]),
        ("fstp-keys", vec!["fstp-crypto", "fstp-json"]),
        (
            "fstp-custody",
            vec![
                "fstp-keys",
                "fstp-crypto",
                "fstp-json",
                "fstp-http",
                "fstp-tls",
                "fstp-rt",
            ],
        ),
        ("fstp-keyd", vec!["fstp-custody", "fstp-crypto", "fstp-rt"]),
        (
            "fstp-audit",
            vec!["fstp-crypto", "fstp-json", "fstp-ledger"],
        ),
        ("fstp-obs", vec!["fstp-json"]),
        (
            "fstp-pgstore",
            vec![
                "fstp-pgwire",
                "fstp-migrate",
                "fstp-ledger",
                "fstp-audit",
                "fstp-keys",
                "fstp-rt",
            ],
        ),
        ("fstp-vault-proto", vec!["fstp-json", "fstp-money"]),
        ("fstp-vault-core", vec!["fstp-vault-proto", "fstp-money"]),
        (
            "fstp-vault",
            vec![
                "fstp-vault-core",
                "fstp-keys",
                "fstp-custody",
                "fstp-audit",
                "fstp-pgwire",
                "fstp-migrate",
                "fstp-http",
                "fstp-tls",
                "fstp-obs",
                "fstp-rt",
            ],
        ),
        ("fstp-webauthn", vec!["fstp-crypto", "fstp-json"]),
        (
            "fstp-auth",
            vec!["fstp-webauthn", "fstp-domain", "fstp-json"],
        ),
        (
            "fstp-cell-core",
            vec![
                "fstp-engine",
                "fstp-domain",
                "fstp-auth",
                "fstp-keys",
                "fstp-ledger",
                "fstp-crypto",
                "fstp-json",
            ],
        ),
        ("fstp-cp-proto", vec!["fstp-json"]),
        ("fstp-edge", vec!["fstp-tls", "fstp-rt", "fstp-json"]),
        (
            "fstp-release",
            vec!["fstp-crypto", "fstp-json", "fstp-http", "fstp-tls"],
        ),
        (
            "fstp-cell",
            vec![
                "fstp-cell-core",
                "fstp-pgstore",
                "fstp-custody",
                "fstp-vault-proto",
                "fstp-cp-proto",
                "fstp-release",
                "fstp-edge",
                "fstp-http",
                "fstp-tls",
                "fstp-obs",
                "fstp-rt",
            ],
        ),
        (
            "fstp-control",
            vec![
                "fstp-cp-proto",
                "fstp-pki",
                "fstp-custody",
                "fstp-webauthn",
                "fstp-pgwire",
                "fstp-migrate",
                "fstp-http",
                "fstp-tls",
                "fstp-obs",
            ],
        ),
        (
            "fstp-witness",
            vec![
                "fstp-audit",
                "fstp-cp-proto",
                "fstp-pgwire",
                "fstp-http",
                "fstp-tls",
            ],
        ),
        (
            "fstp-release-svc",
            vec![
                "fstp-release",
                "fstp-pgwire",
                "fstp-migrate",
                "fstp-http",
                "fstp-tls",
            ],
        ),
        (
            "fstp-backup",
            vec![
                "fstp-keys",
                "fstp-custody",
                "fstp-crypto",
                "fstp-http",
                "fstp-tls",
            ],
        ),
        (
            "fstp-celltest",
            vec![
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
                "fstp-pgtest",
                "fstp-prop",
                "fstp-mc",
                "fstp-domain-testkit",
            ],
        ),
    ];
    let mut crates: Vec<CrateSpec> = table
        .into_iter()
        .map(|(name, deps)| CrateSpec {
            name,
            deps: deps.into_iter().map(|d| (d, N)).collect(),
            bin: BIN_CRATES.contains(&name),
            src: String::new(),
        })
        .collect();
    // Every M2 and M3 crate tests with fstp-prop.
    for c in &mut crates {
        if c.name.starts_with("fstp-") && !matches!(c.name, "fstp-prop" | "fstp-celltest") {
            c.deps.push(("fstp-prop", D));
        }
    }
    let mut g = Graph { crates };
    // The places where rules 7 and 9 allow their identifiers.
    let rm = root_material();
    let [seed_source, seed_fact] = seed_names();
    g = g.src(
        "fstp-keyd",
        &format!("/// Root bytes of file custody.\npub struct {rm};\n"),
    );
    g = g.src(
        "fstp-celltest",
        &format!(
            "pub struct {rm};\npub struct {seed_source};\npub fn {seed_fact}() {{}}\n\
             pub use aws_lc_rs::kem::ML_KEM_768;\npub use aws_lc_rs::signature::ML_DSA_65;\n"
        ),
    );
    g
}

impl Graph {
    fn get_mut(&mut self, name: &str) -> &mut CrateSpec {
        self.crates
            .iter_mut()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("no crate {name} in the fixture"))
    }

    /// Adds a dependency edge.
    fn edge(mut self, from: &'static str, to: &'static str, kind: Kind) -> Graph {
        if !self.crates.iter().any(|c| c.name == from) {
            self.crates.push(CrateSpec {
                name: from,
                deps: vec![],
                bin: false,
                src: String::new(),
            });
        }
        if !self.crates.iter().any(|c| c.name == to) {
            self.crates.push(CrateSpec {
                name: to,
                deps: vec![],
                bin: false,
                src: String::new(),
            });
        }
        self.get_mut(from).deps.push((to, kind));
        self
    }

    /// Appends `text` to a crate's `src/lib.rs`.
    fn src(mut self, krate: &'static str, text: &str) -> Graph {
        self.get_mut(krate).src.push_str(text);
        self
    }

    /// Writes the workspace into `repo` and locks it.
    fn install(&self, repo: &Repo) {
        let members: Vec<String> = self
            .crates
            .iter()
            .map(|c| format!("\"crates/{}\"", c.name))
            .collect();
        repo.write(
            "Cargo.toml",
            &format!(
                "[workspace]\nresolver = \"3\"\nmembers = [\"crates/app\", {}]\n",
                members.join(", ")
            ),
        );
        for c in &self.crates {
            let mut manifest = format!(
                "[package]\nname = \"{}\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
                c.name
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
                &format!("//! {}\n{}", c.name, c.src),
            );
            if c.bin {
                repo.write(&format!("crates/{}/src/main.rs", c.name), "fn main() {}\n");
            }
        }
        repo.lock(".");
    }
}

/// A repository holding `g`.
fn repo_with(tag: &str, g: &Graph) -> Repo {
    let repo = Repo::new(tag);
    g.install(&repo);
    repo
}

// ---------------------------------------------------------------------------
// Layering rules of design section 2.4.
// ---------------------------------------------------------------------------

/// Design section 2.4: the designed M3 graph passes every rule. Rule 9 adds
/// `fstp-celltest` to the test-only crates, so its normal edges to
/// `fstp-prop`, `fstp-mc` and `fstp-domain-testkit` are allowed (rule 12
/// keeps the M2 rules). Rules 2, 6 and 7 allow it as the test harness.
#[test]
fn layering_m3_designed_graph_passes() {
    let repo = repo_with("designed", &designed());
    repo.assert_passes(&[], "the designed M3 graph");
}

/// Design section 2.4 rule 1: each pure core fails when it reaches an
/// in-house I/O crate or tokio, directly or through another crate.
#[test]
fn layering_m3_rule1_pure_cores_reach_no_io_crate() {
    let seeded = [
        ("fstp-keys", "fstp-rt"),
        ("fstp-audit", "fstp-http"),
        ("fstp-vault-proto", "fstp-tls"),
        ("fstp-vault-core", "fstp-pgwire"),
        ("fstp-webauthn", "fstp-pgtest"),
        ("fstp-auth", "fstp-migrate"),
        ("fstp-cell-core", "tokio"),
        ("fstp-cp-proto", "fstp-rt"),
        ("fstp-pki", "fstp-tls"),
    ];
    let mut g = designed();
    for (from, to) in seeded {
        g = g.edge(from, to, N);
    }
    let repo = repo_with("pure-io", &g);
    let (ok, text) = repo.check_with(&[]);
    assert!(!ok, "the gate passed:\n{text}");
    for (from, to) in seeded {
        assert!(
            has_finding(&text, "error", "layering-m3-pure-io", &[from, to]),
            "{from} -> {to} is not reported:\n{text}"
        );
    }
    // A transitive path counts: fstp-cell-core reaches fstp-migrate through fstp-auth.
    assert!(
        has_finding(
            &text,
            "error",
            "layering-m3-pure-io",
            &["fstp-cell-core", "fstp-auth", "fstp-migrate"]
        ),
        "{text}"
    );
}

/// Design section 2.4 rule 2: the vault crates reach none of the domain
/// crates.
#[test]
fn layering_m3_rule2_vault_reaches_no_domain_crate() {
    let seeded = [
        ("fstp-vault-core", "fstp-domain"),
        ("fstp-vault-proto", "fstp-engine"),
        ("fstp-vault", "fstp-findings"),
        ("fstp-vault", "fstp-cell-core"),
    ];
    let mut g = designed();
    for (from, to) in seeded {
        g = g.edge(from, to, N);
    }
    let repo = repo_with("vault", &g);
    let (ok, text) = repo.check_with(&[]);
    assert!(!ok, "the gate passed:\n{text}");
    for (from, to) in seeded {
        assert!(
            has_finding(&text, "error", "layering-m3-vault", &[from, to]),
            "{from} -> {to} is not reported:\n{text}"
        );
    }
}

/// Design section 2.4 rule 2: no crate outside `fstp-vault` reaches
/// `fstp-vault-core`, except the test-only `fstp-celltest`.
#[test]
fn layering_m3_rule2_only_vault_reaches_vault_core() {
    let g = designed().edge("fstp-cell", "fstp-vault-core", N);
    let repo = repo_with("vault-core", &g);
    repo.assert_finding(
        &[],
        "error",
        "layering-m3-vault",
        &["fstp-cell", "fstp-vault-core"],
    );
}

/// Design section 2.4 rule 3: only `fstp-cell` depends on both
/// `fstp-cell-core` and `fstp-pgstore`.
#[test]
fn layering_m3_rule3_only_fstp_cell_composes_core_and_store() {
    let g =
        designed()
            .edge("fstp-backup", "fstp-cell-core", N)
            .edge("fstp-backup", "fstp-pgstore", N);
    let repo = repo_with("composer", &g);
    repo.assert_finding(
        &[],
        "error",
        "layering-m3-composer",
        &["fstp-backup", "fstp-cell-core", "fstp-pgstore"],
    );
}

/// I-19, I-20, design section 2.4 rule 4: the control-plane crates reach no
/// crate that defines tenant records, account types or vault data.
#[test]
fn i19_i20_layering_m3_rule4_control_plane_reaches_no_tenant_crate() {
    let seeded = [
        ("fstp-control", "fstp-domain"),
        ("fstp-cp-proto", "fstp-auth"),
        ("fstp-witness", "fstp-pgstore"),
        ("fstp-edge", "fstp-vault-proto"),
        ("fstp-release", "fstp-findings"),
        ("fstp-release-svc", "fstp-engine"),
        ("fstp-control", "fstp-cell-core"),
        ("fstp-witness", "fstp-vault"),
    ];
    let mut g = designed();
    for (from, to) in seeded {
        g = g.edge(from, to, N);
    }
    let repo = repo_with("control-plane", &g);
    let (ok, text) = repo.check_with(&[]);
    assert!(!ok, "the gate passed:\n{text}");
    for (from, to) in seeded {
        assert!(
            has_finding(&text, "error", "layering-m3-control-plane", &[from, to]),
            "{from} -> {to} is not reported:\n{text}"
        );
    }
}

/// I-19, design section 2.4 rule 5: a source scan refuses a TLS server
/// configuration constructor in `fstp-edge`, which reaches `fstp-tls` for
/// its tunnel client only.
#[test]
fn i19_layering_m3_rule5_edge_builds_no_tls_server_config() {
    let g = designed().src(
        "fstp-edge",
        "pub fn terminate(c: &[u8], k: &[u8]) {\n    \
         let _ = fstp_tls::ServerConfig::builder(c, k).build();\n}\n",
    );
    let repo = repo_with("edge-tls", &g);
    repo.assert_finding(
        &[],
        "error",
        "layering-m3-edge-tls",
        &["fstp-edge", "ServerConfig"],
    );
}

/// I-39, design section 2.4 rule 6: only `fstp-cell` and `fstp-release-svc`
/// reach `fstp-release`.
#[test]
fn i39_layering_m3_rule6_only_cell_and_release_svc_reach_release() {
    let seeded = [
        "fstp-cell-core",
        "fstp-pgstore",
        "fstp-vault",
        "fstp-backup",
        "fstp-control",
    ];
    let mut g = designed();
    for from in seeded {
        g = g.edge(from, "fstp-release", N);
    }
    let repo = repo_with("i39", &g);
    let (ok, text) = repo.check_with(&[]);
    assert!(!ok, "the gate passed:\n{text}");
    for from in seeded {
        assert!(
            has_finding(&text, "error", "layering-m3-i39", &[from, "fstp-release"]),
            "{from} -> fstp-release is not reported:\n{text}"
        );
    }
    // A command-path crate above fstp-cell-core reaches it transitively too.
    assert!(
        has_finding(
            &text,
            "error",
            "layering-m3-i39",
            &["fstp-cell-core", "fstp-release"]
        ),
        "{text}"
    );
}

/// I-80, design section 2.4 rule 7: the identifier `RootMaterial` appears
/// only in `fstp-keyd` and `fstp-celltest`.
#[test]
fn i80_layering_m3_rule7_root_material_named_only_in_keyd() {
    let rm = root_material();
    let g = designed().src("fstp-custody", &format!("pub struct {rm}(Vec<u8>);\n"));
    let repo = repo_with("i80-name", &g);
    repo.assert_finding(&[], "error", "layering-m3-i80", &["fstp-custody", &rm]);
}

/// I-80, design section 2.4 rule 7: only the cell, vault, control plane,
/// backup agent, file custody server and test harness reach
/// `fstp-custody`.
#[test]
fn i80_layering_m3_rule7_only_listed_crates_reach_custody() {
    let seeded = ["fstp-witness", "fstp-edge", "fstp-release-svc"];
    let mut g = designed();
    for from in seeded {
        g = g.edge(from, "fstp-custody", N);
    }
    let repo = repo_with("i80-reach", &g);
    let (ok, text) = repo.check_with(&[]);
    assert!(!ok, "the gate passed:\n{text}");
    for from in seeded {
        assert!(
            has_finding(&text, "error", "layering-m3-i80", &[from, "fstp-custody"]),
            "{from} -> fstp-custody is not reported:\n{text}"
        );
    }
}

/// I-74, I-75, design section 2.4 rule 8: moduletto is reachable only
/// through `fstp-crypto`.
#[test]
fn i74_layering_m3_rule8_moduletto_reachable_only_through_fstp_crypto() {
    let seeded = ["fstp-keys", "fstp-pki", "fstp-celltest"];
    let mut g = designed();
    for from in seeded {
        g = g.edge(from, "moduletto", N);
    }
    let repo = repo_with("tier-b-reach", &g);
    let (ok, text) = repo.check_with(&[]);
    assert!(!ok, "the gate passed:\n{text}");
    for from in seeded {
        assert!(
            has_finding(&text, "error", "layering-m3-tier-b", &[from, "moduletto"]),
            "{from} -> moduletto is not reported:\n{text}"
        );
    }
}

/// Design section 2.4 rule 9: `fstp-celltest` joins the test-only crates,
/// so no other crate takes it as a normal dependency.
#[test]
fn layering_m3_rule9_celltest_never_ships() {
    let g = designed().edge("fstp-tool", "fstp-celltest", N);
    let repo = repo_with("celltest-ships", &g);
    repo.assert_finding(
        &[],
        "error",
        "layering-m3-test-only",
        &["fstp-tool", "fstp-celltest"],
    );
}

/// Design section 2.4 rule 9, section 6.9: a source scan refuses the
/// identifiers `SeedSource` and `seed_fact` outside `fstp-celltest`, so no
/// shipped binary writes a vault fact around the vault's own write rules.
#[test]
fn layering_m3_rule9_seed_path_named_only_in_celltest() {
    let [seed_source, seed_fact] = seed_names();
    let g = designed()
        .src("fstp-vault", &format!("pub struct {seed_source};\n"))
        .src("fstp-cell", &format!("pub fn {seed_fact}() {{}}\n"));
    let repo = repo_with("seed", &g);
    let (ok, text) = repo.check_with(&[]);
    assert!(!ok, "the gate passed:\n{text}");
    for (krate, ident) in [("fstp-vault", &seed_source), ("fstp-cell", &seed_fact)] {
        assert!(
            has_finding(&text, "error", "layering-m3-test-only", &[krate, ident]),
            "{ident} in {krate} is not reported:\n{text}"
        );
    }
}

/// Design section 2.4 rule 9, ADR-001 A6: the aws-lc-rs ML-KEM and ML-DSA
/// APIs serve only as test oracles from `fstp-celltest`. Production uses
/// moduletto through `fstp-crypto` for these.
#[test]
fn layering_m3_rule9_aws_lc_pq_oracles_only_in_celltest() {
    let g = designed()
        .src("fstp-keys", "pub use aws_lc_rs::kem::ML_KEM_768;\n")
        .src("fstp-crypto", "pub use aws_lc_rs::signature::ML_DSA_65;\n");
    let repo = repo_with("pq-oracle", &g);
    let (ok, text) = repo.check_with(&[]);
    assert!(!ok, "the gate passed:\n{text}");
    for (krate, ident) in [("fstp-keys", "ML_KEM_768"), ("fstp-crypto", "ML_DSA_65")] {
        assert!(
            has_finding(&text, "error", "layering-m3-test-only", &[krate, ident]),
            "{ident} in {krate} is not reported:\n{text}"
        );
    }
}

// ---------------------------------------------------------------------------
// Runtime rule (ADR-002, design section 2.4 rule 10).
// ---------------------------------------------------------------------------

/// ADR-002, design section 2.4 rule 10: a binary whose resolved graph
/// holds both tokio and smol fails, and the report names the binary.
#[test]
fn adr002_runtime_rule_refuses_two_runtimes_in_one_binary() {
    let g = designed().edge("fstp-rt", "smol", N);
    let repo = repo_with("two-runtimes", &g);
    let (ok, text) = repo.check_with(&[]);
    assert!(!ok, "the gate passed:\n{text}");
    for bin in ["fstp-cell", "fstp-edge", "fstp-keyd"] {
        assert!(
            has_finding(
                &text,
                "error",
                "runtime-one-per-binary",
                &[bin, "tokio", "smol"]
            ),
            "{bin} is not reported:\n{text}"
        );
    }
}

/// ADR-002 Decision: in-house code uses a runtime only through the
/// internal trait in `fstp-rt`. A direct edge from another crate fails.
#[test]
fn adr002_runtime_rule_refuses_a_runtime_outside_fstp_rt() {
    let g = designed()
        .edge("fstp-http", "tokio", N)
        .edge("fstp-edge", "smol", N);
    let repo = repo_with("direct-runtime", &g);
    let (ok, text) = repo.check_with(&[]);
    assert!(!ok, "the gate passed:\n{text}");
    for (krate, rt) in [("fstp-http", "tokio"), ("fstp-edge", "smol")] {
        assert!(
            has_finding(&text, "error", "runtime-direct", &[krate, rt]),
            "{krate} -> {rt} is not reported:\n{text}"
        );
    }
}

// ---------------------------------------------------------------------------
// Funds rule (I-16, design sections 2.4 rule 11 and 14.4).
// ---------------------------------------------------------------------------

/// I-16, design section 14.4: a source scan refuses SEPA credit transfer
/// element names in any crate that `deps/funds-allowed.txt` does not list.
/// This is the teeth test the exit checklist names.
#[test]
fn i16_teeth_seeded_instruction_crate_is_caught() {
    let terms = sepa_terms();
    let seeded = ["fstp-cell", "fstp-control", "fstp-backup", "fstp-release"];
    let mut g = designed();
    for (krate, term) in seeded.iter().zip(terms.iter()) {
        g = g.src(krate, &format!("pub const ELEMENT: &str = \"{term}\";\n"));
    }
    let repo = repo_with("funds", &g);
    let (ok, text) = repo.check_with(&[]);
    assert!(!ok, "the gate passed:\n{text}");
    for (krate, term) in seeded.iter().zip(terms.iter()) {
        assert!(
            has_finding(&text, "error", "funds", &[krate, term]),
            "{term} in {krate} is not reported:\n{text}"
        );
    }
}

/// I-16, design section 14.4: no crate names a payment account type.
#[test]
fn i16_funds_rule_refuses_a_debtor_account_type() {
    let ty = debtor_account();
    let g = designed().src(
        "fstp-control",
        &format!("pub struct {ty} {{ pub iban: [u8; 34] }}\n"),
    );
    let repo = repo_with("debtor", &g);
    repo.assert_finding(&[], "error", "funds", &["fstp-control", &ty]);
}

/// I-16, design section 13.3: `deps/funds-allowed.txt` is empty in M3. A
/// crate it lists may name payment elements (the M5 adapter path). The same
/// crate fails once the list drops it.
#[test]
fn i16_funds_rule_allows_only_crates_in_funds_allowed() {
    let [term, ..] = sepa_terms();
    let g = designed().edge("fstp-adapter", "fstp-json", N).src(
        "fstp-adapter",
        &format!("pub const DOC: &str = \"{term}\";\n"),
    );
    let repo = repo_with("funds-allowed", &g);
    repo.write("deps/funds-allowed.txt", "# M5 adapter\nfstp-adapter\n");
    repo.assert_passes(&[], "a listed adapter");
    repo.write("deps/funds-allowed.txt", "# empty in M3\n");
    repo.assert_finding(&[], "error", "funds", &["fstp-adapter", &term]);
}

// ---------------------------------------------------------------------------
// npm lockfile gate (ADR-003 amendment, Lockfile gate).
// ---------------------------------------------------------------------------

/// A fixture integrity value. It is synthetic: the gate compares it with
/// the allowlist and never fetches the package.
fn integrity(tag: &str) -> String {
    format!("sha512-{}{tag}==", "A".repeat(80))
}

struct NpmPkg {
    name: &'static str,
    version: &'static str,
    resolved: Option<String>,
    integrity: Option<String>,
    extra: &'static str,
}

impl NpmPkg {
    fn registry(name: &'static str, version: &'static str) -> NpmPkg {
        let file = name.rsplit('/').next().unwrap_or(name);
        NpmPkg {
            name,
            version,
            resolved: Some(format!(
                "https://registry.npmjs.org/{name}/-/{file}-{version}.tgz"
            )),
            integrity: Some(integrity(file)),
            extra: "",
        }
    }

    fn entry(&self) -> String {
        let mut fields = vec![format!("\"version\": \"{}\"", self.version)];
        if let Some(r) = &self.resolved {
            fields.push(format!("\"resolved\": \"{r}\""));
        }
        if let Some(i) = &self.integrity {
            fields.push(format!("\"integrity\": \"{i}\""));
        }
        fields.push("\"dev\": true".to_owned());
        if !self.extra.is_empty() {
            fields.push(self.extra.to_owned());
        }
        format!(
            "    \"node_modules/{}\": {{\n      {}\n    }}",
            self.name,
            fields.join(",\n      ")
        )
    }

    fn allow_line(&self) -> String {
        let i = self.integrity.clone().unwrap_or_else(|| integrity("none"));
        format!(
            "{} {} {i} ADR-003 fixture package\n",
            self.name, self.version
        )
    }
}

/// `package.json` with the given direct dev dependencies.
fn package_json(project: &str, direct: &[(&str, &str)]) -> String {
    let deps: Vec<String> = direct
        .iter()
        .map(|(n, v)| format!("    \"{n}\": \"{v}\""))
        .collect();
    format!(
        "{{\n  \"name\": \"{project}\",\n  \"version\": \"0.0.0\",\n  \"private\": true,\n  \
         \"devDependencies\": {{\n{}\n  }}\n}}\n",
        deps.join(",\n")
    )
}

/// `package-lock.json` in lockfile format `version`.
fn package_lock(project: &str, version: u32, direct: &[(&str, &str)], pkgs: &[NpmPkg]) -> String {
    let deps: Vec<String> = direct
        .iter()
        .map(|(n, v)| format!("        \"{n}\": \"{v}\""))
        .collect();
    let mut entries = vec![format!(
        "    \"\": {{\n      \"name\": \"{project}\",\n      \"version\": \"0.0.0\",\n      \
         \"devDependencies\": {{\n{}\n      }}\n    }}",
        deps.join(",\n")
    )];
    entries.extend(pkgs.iter().map(NpmPkg::entry));
    format!(
        "{{\n  \"name\": \"{project}\",\n  \"version\": \"0.0.0\",\n  \"lockfileVersion\": {version},\n  \
         \"requires\": true,\n  \"packages\": {{\n{}\n  }}\n}}\n",
        entries.join(",\n")
    )
}

const DIRECT: [(&str, &str); 2] = [("typescript", "5.9.3"), ("@playwright/test", "1.56.1")];

/// The clean npm tree: the two direct packages and Playwright's two
/// transitive packages.
fn clean_pkgs() -> Vec<NpmPkg> {
    vec![
        NpmPkg::registry("typescript", "5.9.3"),
        NpmPkg::registry("@playwright/test", "1.56.1"),
        NpmPkg::registry("playwright", "1.56.1"),
        NpmPkg::registry("playwright-core", "1.56.1"),
    ]
}

/// A repository with a `web/` and an `e2e/` npm project over `pkgs`, every
/// package of `allow` on the npm allowlist (`deps/npm-allowlist.txt`).
fn npm_repo(tag: &str, pkgs: &[NpmPkg], allow: &[NpmPkg]) -> Repo {
    let repo = Repo::new(tag);
    for project in ["web", "e2e"] {
        repo.write(
            &format!("{project}/package.json"),
            &package_json(project, &DIRECT),
        );
        repo.write(
            &format!("{project}/package-lock.json"),
            &package_lock(project, 3, &DIRECT, pkgs),
        );
    }
    let lines: Vec<String> = allow.iter().map(NpmPkg::allow_line).collect();
    repo.write(
        "deps/npm-allowlist.txt",
        &format!("# npm packages under ADR-003\n{}", lines.concat()),
    );
    repo
}

/// ADR-003 amendment, Lockfile gate: pinned registry packages with
/// integrity values that match the allowlist pass.
#[test]
fn adr003_npm_gate_accepts_a_pinned_registry_lockfile() {
    let repo = npm_repo("npm-clean", &clean_pkgs(), &clean_pkgs());
    repo.assert_passes(&[], "a clean npm tree");
}

/// ADR-003 amendment, Lockfile gate: git, file, link and other tarball
/// sources fail, even with an allowlist entry for the name, version and
/// integrity value.
#[test]
fn adr003_npm_gate_refuses_git_file_link_and_foreign_sources() {
    let bad = [
        (
            "git-pkg",
            "git+ssh://git@example.org/x/git-pkg.git#0123456789abcdef",
        ),
        ("file-pkg", "file:../vendor/file-pkg"),
        ("link-pkg", "../vendor/link-pkg"),
        ("tarball-pkg", "https://example.org/tarball-pkg-1.0.0.tgz"),
    ];
    for (name, resolved) in bad {
        let mut pkgs = clean_pkgs();
        pkgs.push(NpmPkg {
            name,
            version: "1.0.0",
            resolved: Some(resolved.to_owned()),
            integrity: Some(integrity(name)),
            extra: if name == "link-pkg" {
                "\"link\": true"
            } else {
                ""
            },
        });
        let allow: Vec<NpmPkg> = pkgs
            .iter()
            .map(|p| NpmPkg {
                name: p.name,
                version: p.version,
                resolved: p.resolved.clone(),
                integrity: p.integrity.clone(),
                extra: "",
            })
            .collect();
        let repo = npm_repo("npm-source", &pkgs, &allow);
        repo.assert_finding(&[], "error", "npm", &[name]);
    }
}

/// ADR-003 amendment, Lockfile gate: every package carries an `integrity`
/// value.
#[test]
fn adr003_npm_gate_refuses_a_package_without_integrity() {
    let mut pkgs = clean_pkgs();
    if let Some(p) = pkgs.iter_mut().find(|p| p.name == "playwright-core") {
        p.integrity = None;
    }
    let repo = npm_repo("npm-integrity", &pkgs, &clean_pkgs());
    repo.assert_finding(&[], "error", "npm", &["playwright-core"]);
}

/// ADR-003 amendment, Lockfile gate: a package off the allowlist fails.
#[test]
fn adr003_npm_gate_refuses_a_package_off_the_allowlist() {
    let mut pkgs = clean_pkgs();
    pkgs.push(NpmPkg::registry("left-pad", "1.3.0"));
    let repo = npm_repo("npm-unlisted", &pkgs, &clean_pkgs());
    repo.assert_finding(&[], "error", "npm", &["left-pad"]);
}

/// ADR-003 amendment, Lockfile gate: name, version and integrity value must
/// all match the allowlist entry.
#[test]
fn adr003_npm_gate_refuses_a_version_or_integrity_mismatch() {
    let mut allow = clean_pkgs();
    if let Some(p) = allow.iter_mut().find(|p| p.name == "playwright") {
        p.integrity = Some(integrity("other"));
    }
    let repo = npm_repo("npm-hash", &clean_pkgs(), &allow);
    repo.assert_finding(&[], "error", "npm", &["playwright"]);

    let mut allow = clean_pkgs();
    if let Some(p) = allow.iter_mut().find(|p| p.name == "typescript") {
        p.version = "5.9.2";
    }
    let repo = npm_repo("npm-version", &clean_pkgs(), &allow);
    repo.assert_finding(&[], "error", "npm", &["typescript"]);
}

/// ADR-003 amendment, Rules: npm projects exist only in `web/` and `e2e/`.
#[test]
fn adr003_npm_gate_refuses_npm_projects_outside_web_and_e2e() {
    for dir in ["tools/site", "crates/fstp-cell/assets", "."] {
        let repo = npm_repo("npm-place", &clean_pkgs(), &clean_pkgs());
        let prefix = if dir == "." {
            String::new()
        } else {
            format!("{dir}/")
        };
        repo.write(
            &format!("{prefix}package.json"),
            &package_json("stray", &DIRECT),
        );
        repo.write(
            &format!("{prefix}package-lock.json"),
            &package_lock("stray", 3, &DIRECT, &clean_pkgs()),
        );
        repo.assert_finding(&[], "error", "npm", &[&format!("{prefix}package")]);
    }
}

/// ADR-003 amendment, Rules: `package.json` lists only `typescript` and
/// `@playwright/test`.
#[test]
fn adr003_npm_gate_refuses_a_direct_package_beyond_typescript_and_playwright() {
    let mut pkgs = clean_pkgs();
    pkgs.push(NpmPkg::registry("react", "19.2.0"));
    let direct = [
        ("typescript", "5.9.3"),
        ("@playwright/test", "1.56.1"),
        ("react", "19.2.0"),
    ];
    let repo = npm_repo("npm-direct", &pkgs, &pkgs);
    repo.write("web/package.json", &package_json("web", &direct));
    repo.write(
        "web/package-lock.json",
        &package_lock("web", 3, &direct, &pkgs),
    );
    repo.assert_finding(&[], "error", "npm", &["react"]);
}

/// ADR-003 amendment, Lockfile gate: only the lockfile format version the
/// pinned npm writes is accepted. This fixture takes version 3, the format
/// current npm writes. Unknown structure fails.
#[test]
fn adr003_npm_gate_refuses_an_unknown_lockfile_version() {
    let repo = npm_repo("npm-format", &clean_pkgs(), &clean_pkgs());
    repo.write(
        "e2e/package-lock.json",
        &package_lock("e2e", 1, &DIRECT, &clean_pkgs()),
    );
    repo.assert_finding(&[], "error", "npm", &["e2e/package-lock.json"]);

    let repo = npm_repo("npm-shape", &clean_pkgs(), &clean_pkgs());
    repo.write(
        "web/package-lock.json",
        "{\"lockfileVersion\": 3, \"packages\": [1]}\n",
    );
    repo.assert_finding(&[], "error", "npm", &["web/package-lock.json"]);
}

/// ADR-003 amendment, Lockfile gate: a package marked as having an install
/// script fails unless its allowlist entry accepts it with a note.
#[test]
fn adr003_npm_gate_refuses_an_install_script_without_acceptance() {
    let mut pkgs = clean_pkgs();
    if let Some(p) = pkgs.iter_mut().find(|p| p.name == "playwright") {
        p.extra = "\"hasInstallScript\": true";
    }
    let repo = npm_repo("npm-script", &pkgs, &clean_pkgs());
    repo.assert_finding(&[], "error", "npm", &["playwright"]);
}

/// ADR-003 amendment, Rules: each npm project has a committed
/// `package-lock.json`.
#[test]
fn adr003_npm_gate_refuses_a_package_json_without_lockfile() {
    let repo = npm_repo("npm-nolock", &clean_pkgs(), &clean_pkgs());
    repo.remove("web/package-lock.json");
    repo.assert_finding(&[], "error", "npm", &["web"]);
}

// ---------------------------------------------------------------------------
// Tier B release gate (I-74, design section 2.6, ADR-001 A5).
// ---------------------------------------------------------------------------

/// The `.crate` SHA-256 of zeroize 1.9.1, as `deps/allowlist.txt` pins it.
const ZEROIZE_SHA: &str = "e13084392c5e4bc371903e2935a5eaeed24905a7511356b883835e18a78f6879";
/// Another well-formed hash.
const OTHER_SHA: &str = "0000000000000000000000000000000000000000000000000000000000000001";

/// A repository whose binary `app` ships zeroize 1.9.1 through the library
/// `mid`, with zeroize marked Tier B in `deps/tier-b-confirmations.txt`.
/// zeroize is a stand-in: it is in the offline cargo cache and has no
/// dependencies. `confirmations` holds the confirmation rows.
fn tier_b_repo(tag: &str, confirmations: &str) -> Repo {
    let repo = Repo::new(tag);
    repo.write(
        "Cargo.toml",
        "[workspace]\nresolver = \"3\"\nmembers = [\"crates/app\", \"crates/mid\"]\n",
    );
    repo.write(
        "crates/mid/Cargo.toml",
        "[package]\nname = \"mid\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n\
         [dependencies]\nzeroize = { version = \"=1.9.1\", default-features = false, features = [\"alloc\"] }\n",
    );
    repo.write("crates/mid/src/lib.rs", "//! mid\n");
    repo.write(
        "crates/app/Cargo.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n\
         [dependencies]\nmid = { path = \"../mid\" }\n",
    );
    repo.write("crates/app/src/main.rs", "fn main() {}\n");
    repo.write(
        "deps/allowlist.txt",
        &format!("zeroize 1.9.1 {ZEROIZE_SHA} ADR-001 runtime Tier B stand-in\n"),
    );
    repo.write(
        "deps/adr-roots.txt",
        "zeroize ADR-001 alloc Tier B stand-in\n",
    );
    repo.write(
        "docs/adr/ADR-001-crypto.md",
        "# ADR-001\n\n`zeroize 1.9.1`\n",
    );
    repo.write(
        "deps/tier-b-confirmations.txt",
        &format!(
            "# Tier B crates and their release confirmations (ADR-001).\n\
             # tier-b <crate>\n\
             # confirmed <crate> <version> <source hash> <date> <findings reference>\n\
             tier-b zeroize\n{confirmations}"
        ),
    );
    repo.lock(".");
    repo
}

/// I-74, ADR-001 A5: a development build reports the missing confirmation
/// as a warning and passes, since Tier B use in development is allowed.
#[test]
fn i74_dev_build_reports_but_passes() {
    let repo = tier_b_repo("tier-b-dev", "");
    let (ok, text) = repo.check_with(&[]);
    assert!(ok, "a development build fails:\n{text}");
    assert!(
        has_finding(&text, "warning", "tier-b", &["zeroize", "1.9.1"]),
        "the missing confirmation is not reported:\n{text}"
    );
}

/// I-74, R-CR-02, ADR-001 A5: `--release` fails when a shipped binary holds
/// a Tier B version without a confirmation. A confirmation for another
/// version does not count.
#[test]
fn i74_release_gate_refuses_unconfirmed_tier_b_version() {
    let repo = tier_b_repo("tier-b-none", "");
    repo.assert_finding(&["--release"], "error", "tier-b", &["zeroize", "1.9.1"]);

    let repo = tier_b_repo(
        "tier-b-version",
        &format!("confirmed zeroize 1.9.0 {ZEROIZE_SHA} 2026-10-28 MYTHOS-0\n"),
    );
    repo.assert_finding(&["--release"], "error", "tier-b", &["zeroize", "1.9.1"]);
}

/// I-74, ADR-001 A5: the confirmation's source hash must equal the hash
/// that `deps/allowlist.txt` pins.
#[test]
fn i74_release_gate_refuses_a_confirmation_for_another_hash() {
    let repo = tier_b_repo(
        "tier-b-hash",
        &format!("confirmed zeroize 1.9.1 {OTHER_SHA} 2026-10-28 MYTHOS-0\n"),
    );
    repo.assert_finding(&["--release"], "error", "tier-b", &["zeroize", "1.9.1"]);
}

/// I-74, ADR-001 A5: a confirmation for the exact version and hash lets
/// the release gate pass.
#[test]
fn i74_release_gate_accepts_a_matching_confirmation() {
    let repo = tier_b_repo(
        "tier-b-ok",
        &format!("confirmed zeroize 1.9.1 {ZEROIZE_SHA} 2026-10-28 MYTHOS-0\n"),
    );
    repo.assert_passes(&["--release"], "a confirmed Tier B version");
}

/// I-74, design section 2.6: the gate reads the whole resolved tree of each
/// shipped binary. A gate that checked only direct dependencies, or only
/// libraries, would let this fixture through: the Tier B crate reaches the
/// binary through the library `mid`.
#[test]
fn i74_teeth_gate_skipping_tier_b_is_caught() {
    let repo = tier_b_repo("tier-b-teeth", "");
    let (ok, text) = repo.check_with(&["--release"]);
    assert!(!ok, "the release gate passed:\n{text}");
    assert!(
        has_finding(&text, "error", "tier-b", &["zeroize", "1.9.1"]),
        "{text}"
    );
    // The same tree in a development build must pass, so the failure above
    // comes from the release gate and not from another rule.
    repo.assert_passes(&[], "the development build of the teeth fixture");
}

/// I-74, ADR-001 A5: a malformed mirror line fails in every build, so a
/// typo cannot hide a confirmation row.
#[test]
fn i74_tier_b_mirror_refuses_malformed_rows() {
    for row in [
        "confirmed zeroize 1.9.1 nothex 2026-10-28 MYTHOS-0\n",
        &format!("confirmed zeroize 1.9.1 {ZEROIZE_SHA} 28.10.2026 MYTHOS-0\n"),
        &format!("confirmed zeroize 1.9.1 {ZEROIZE_SHA} 2026-10-28\n"),
        "tier-b\n",
        "approved zeroize 1.9.1\n",
    ] {
        let repo = tier_b_repo("tier-b-syntax", row);
        repo.assert_finding(&[], "error", "tier-b", &["deps/tier-b-confirmations.txt"]);
    }
}

// ---------------------------------------------------------------------------
// git-source rule (ADR-001 A3, TH-15).
// ---------------------------------------------------------------------------

fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .args([
            "-c",
            "user.name=fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "init.defaultBranch=main",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "tag.gpgsign=false",
        ])
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

/// A local git repository holding the crate `name` at version 0.3.0.
/// Returns its `file://` URL and its first commit.
fn git_crate(repo: &Repo, dir: &str, name: &str) -> (String, String) {
    let path = repo.base.join(dir);
    fs::create_dir_all(path.join("src")).unwrap();
    fs::write(
        path.join("Cargo.toml"),
        format!("[package]\nname = \"{name}\"\nversion = \"0.3.0\"\nedition = \"2024\"\n"),
    )
    .unwrap();
    fs::write(path.join("src/lib.rs"), format!("//! {name}\n")).unwrap();
    git(&path, &["init", "-q"]);
    git(&path, &["add", "."]);
    git(&path, &["commit", "-q", "-m", "first"]);
    git(&path, &["tag", "v0.3.0"]);
    let commit = git(&path, &["rev-parse", "HEAD"]);
    (format!("file://{}", path.display()), commit)
}

/// The exact `Cargo.lock` source string of a pinned git dependency.
fn pinned(url: &str, commit: &str) -> String {
    format!("git+{url}?rev={commit}#{commit}")
}

/// The manifest of the `fstp-crypto` stand-in, the only crate that may
/// depend on moduletto (design section 2.4 rule 8).
const CRYPTO_MANIFEST: &str = "crates/fstp-crypto/Cargo.toml";

/// The `fstp-crypto` stand-in manifest with the dependency lines `deps`.
fn crypto_manifest(deps: &str) -> String {
    format!(
        "[package]\nname = \"fstp-crypto\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n\
         [dependencies]\n{deps}"
    )
}

/// Turns the minimal repository into a workspace where `app` reaches the
/// git crates only through the `fstp-crypto` stand-in, as rule 8 asks.
fn route_through_crypto(repo: &Repo) {
    repo.write(
        "Cargo.toml",
        "[workspace]\nresolver = \"3\"\nmembers = [\"crates/app\", \"crates/fstp-crypto\"]\n",
    );
    repo.write(
        "crates/app/Cargo.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n\
         [dependencies]\nfstp-crypto = { path = \"../fstp-crypto\" }\n",
    );
    repo.write(
        "crates/fstp-crypto/src/lib.rs",
        "//! fstp-crypto stand-in\n",
    );
}

/// Points the `fstp-crypto` stand-in at `name` from git with the manifest `spec`
/// (`rev = "..."`, `branch = "..."` or `tag = "..."`), and records `source`
/// on the allowlist with the root line and the ADR record the existing
/// gates ask for.
fn use_git_crate(repo: &Repo, name: &str, url: &str, spec: &str, source: &str) {
    repo.write(
        CRYPTO_MANIFEST,
        &crypto_manifest(&format!("{name} = {{ git = \"{url}\", {spec} }}\n")),
    );
    repo.write(
        "deps/allowlist.txt",
        &format!("{name} 0.3.0 {source} ADR-001 runtime Tier B, git source (A2)\n"),
    );
    repo.write(
        "deps/adr-roots.txt",
        &format!("{name} ADR-001 - Tier B: post-quantum half\n"),
    );
    // ADR-001 A2: the record names the pinned commit too, since a git
    // package keeps its manifest version when its pin moves.
    let commit = source.rsplit_once('#').map_or("", |(_, c)| c);
    repo.write(
        "docs/adr/ADR-001-crypto.md",
        &format!("# ADR-001\n\n`{name} 0.3.0`, commit `{commit}`\n"),
    );
    repo.lock(".");
}

/// A repository whose only third-party crate is moduletto from a local git
/// repository, pinned to its full first commit and recorded byte for byte.
/// `app` reaches it through the `fstp-crypto` stand-in, so rule 8 holds and
/// each failure below comes from the git-source rule.
fn git_repo(tag: &str) -> (Repo, String, String) {
    let repo = Repo::with_cargo_home(tag);
    route_through_crypto(&repo);
    let (url, commit) = git_crate(&repo, "moduletto-src", "moduletto");
    use_git_crate(
        &repo,
        "moduletto",
        &url,
        &format!("rev = \"{commit}\""),
        &pinned(&url, &commit),
    );
    (repo, url, commit)
}

/// Asserts that the gate fails with a git-source error, and that rule 8
/// stays silent, so the failure comes from the rule under test.
fn assert_git_refused(repo: &Repo, what: &str) -> String {
    let text = repo.assert_fails(&[], what);
    assert!(
        text.lines()
            .any(|l| l.trim_start().starts_with("error[git-source")),
        "{what}: no git-source error:\n{text}"
    );
    assert!(
        !text.contains("layering-m3-tier-b"),
        "{what}: rule 8 fired in a git-source fixture:\n{text}"
    );
    text
}

/// TH-15, ADR-001 A3: a git package passes when crate, version and the
/// exact `git+<URL>?rev=<commit>#<commit>` source string match an allowlist
/// entry.
#[test]
fn th15_git_source_accepts_only_the_recorded_source() {
    let (repo, url, commit) = git_repo("git-ok");
    let lock = fs::read_to_string(repo.root.join("Cargo.lock")).unwrap();
    assert!(
        lock.contains(&format!("source = \"{}\"", pinned(&url, &commit))),
        "setup: the lockfile records the pinned source:\n{lock}"
    );
    repo.assert_passes(&[], "the recorded git source");
}

/// TH-15, ADR-001 A3: another URL fails, including the same commit served
/// from a second repository.
#[test]
fn th15_git_source_refuses_unlisted_url() {
    let (repo, url, commit) = git_repo("git-url");
    repo.assert_passes(&[], "the recorded git source");

    // The allowlist names another URL for the commit the lockfile holds.
    let other = format!("{url}-mirror");
    repo.write(
        "deps/allowlist.txt",
        &format!(
            "moduletto 0.3.0 {} ADR-001 runtime Tier B, git source (A2)\n",
            pinned(&other, &commit)
        ),
    );
    assert_git_refused(&repo, "an allowlist entry for another URL");

    // The same commit, fetched from a clone at another path.
    let clone = repo.base.join("moduletto-clone");
    git(
        &repo.base,
        &["clone", "-q", &url, &clone.display().to_string()],
    );
    let clone_url = format!("file://{}", clone.display());
    repo.write(
        CRYPTO_MANIFEST,
        &crypto_manifest(&format!(
            "moduletto = {{ git = \"{clone_url}\", rev = \"{commit}\" }}\n"
        )),
    );
    repo.write(
        "deps/allowlist.txt",
        &format!(
            "moduletto 0.3.0 {} ADR-001 runtime Tier B, git source (A2)\n",
            pinned(&url, &commit)
        ),
    );
    repo.lock(".");
    assert_git_refused(&repo, "the recorded commit from another URL");
}

/// TH-15, ADR-001 A3: another commit fails, even with the same manifest
/// version.
#[test]
fn th15_git_source_refuses_other_commit() {
    let (repo, url, commit) = git_repo("git-commit");
    repo.assert_passes(&[], "the recorded git source");

    let src = repo.base.join("moduletto-src");
    fs::write(src.join("src/lib.rs"), "//! moduletto, second commit\n").unwrap();
    git(&src, &["commit", "-q", "-a", "-m", "second"]);
    let second = git(&src, &["rev-parse", "HEAD"]);
    repo.write(
        CRYPTO_MANIFEST,
        &crypto_manifest(&format!(
            "moduletto = {{ git = \"{url}\", rev = \"{second}\" }}\n"
        )),
    );
    repo.lock(".");
    let lock = fs::read_to_string(repo.root.join("Cargo.lock")).unwrap();
    assert!(lock.contains(&second), "setup: the lockfile moved:\n{lock}");
    assert!(
        fs::read_to_string(repo.root.join("deps/allowlist.txt"))
            .unwrap()
            .contains(&commit),
        "setup: the allowlist still names the first commit"
    );
    assert_git_refused(&repo, "a commit the allowlist does not record");
}

/// TH-15, ADR-001 A3: a branch or tag reference fails, even when the
/// allowlist records the lockfile's source string byte for byte.
#[test]
fn th15_git_source_refuses_branch_or_tag_reference() {
    let (repo, url, commit) = git_repo("git-ref");
    repo.assert_passes(&[], "the recorded git source");

    for (spec, query) in [
        ("branch = \"main\"", "branch=main"),
        ("tag = \"v0.3.0\"", "tag=v0.3.0"),
    ] {
        let source = format!("git+{url}?{query}#{commit}");
        use_git_crate(&repo, "moduletto", &url, spec, &source);
        let lock = fs::read_to_string(repo.root.join("Cargo.lock")).unwrap();
        assert!(
            lock.contains(&source),
            "setup: the lockfile holds {source}:\n{lock}"
        );
        assert_git_refused(&repo, spec);
    }
}

/// TH-15, ADR-001 A3: a shortened rev fails, even when the allowlist
/// records the lockfile's source string byte for byte.
#[test]
fn th15_git_source_refuses_a_shortened_rev() {
    let (repo, url, commit) = git_repo("git-short");
    repo.assert_passes(&[], "the recorded git source");

    let short = commit.get(..12).unwrap().to_owned();
    let source = format!("git+{url}?rev={short}#{commit}");
    use_git_crate(
        &repo,
        "moduletto",
        &url,
        &format!("rev = \"{short}\""),
        &source,
    );
    let lock = fs::read_to_string(repo.root.join("Cargo.lock")).unwrap();
    assert!(
        lock.contains(&source),
        "setup: the lockfile holds {source}:\n{lock}"
    );
    assert_git_refused(&repo, "a shortened rev");
}

/// TH-15, ADR-001 A3: only moduletto and packages from its recorded
/// repository may use the git form. A crate from another git repository
/// fails, even with an exact allowlist entry, a root line and an ADR record.
#[test]
fn th15_git_source_refuses_a_git_entry_from_another_repository() {
    let (repo, url, commit) = git_repo("git-other");
    repo.assert_passes(&[], "the recorded git source");

    let (other_url, other_commit) = git_crate(&repo, "other-src", "othercrate");
    repo.write(
        CRYPTO_MANIFEST,
        &crypto_manifest(&format!(
            "moduletto = {{ git = \"{url}\", rev = \"{commit}\" }}\n\
             othercrate = {{ git = \"{other_url}\", rev = \"{other_commit}\" }}\n"
        )),
    );
    repo.write(
        "deps/allowlist.txt",
        &format!(
            "moduletto 0.3.0 {} ADR-001 runtime Tier B, git source (A2)\n\
             othercrate 0.3.0 {} ADR-001 runtime another git source\n",
            pinned(&url, &commit),
            pinned(&other_url, &other_commit)
        ),
    );
    repo.write(
        "deps/adr-roots.txt",
        "moduletto ADR-001 - Tier B: post-quantum half\nothercrate ADR-001 - another git root\n",
    );
    repo.write(
        "docs/adr/ADR-001-crypto.md",
        "# ADR-001\n\n`moduletto 0.3.0`\n\n`othercrate 0.3.0`\n",
    );
    repo.lock(".");
    let text = assert_git_refused(&repo, "a git crate from another repository");
    assert!(text.contains("othercrate"), "{text}");
}

/// ADR-003 amendment, Rules: another package manager's lockfile fails
/// everywhere, in `web/` and `e2e/` too. Review finding npm-bun-lock: the
/// bun and deno lockfiles were missing from the refused list.
#[test]
fn adr003_npm_gate_refuses_other_package_manager_lockfiles() {
    let locks = [
        "npm-shrinkwrap.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "bun.lock",
        "bun.lockb",
        "deno.lock",
    ];
    let repo = Repo::new("npm-foreign-lock");
    let dirs = ["web", "e2e", "tools"];
    for dir in dirs {
        for name in locks {
            repo.write(&format!("{dir}/{name}"), "{}\n");
        }
    }
    let text = repo.assert_fails(&[], "foreign lockfiles");
    for dir in dirs {
        for name in locks {
            let rel = format!("{dir}/{name}");
            assert!(
                has_finding(&text, "error", "npm-place", &[&rel]),
                "{rel} passes the npm gate:\n{text}"
            );
        }
    }
}
