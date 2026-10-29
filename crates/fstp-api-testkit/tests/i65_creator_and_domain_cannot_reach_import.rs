//! I-65 layering gate, rule A3 (M4 design sections 1.3 and 8.4).
//!
//! `fstp-domain`, `fstp-programme` and `fstp-creator` have no dependency
//! path to `fstp-import`, so no domain or creator code can read an import
//! proposal. `fstp-import` has no path to `fstp-creator` or `fstp-engine`,
//! so the import side cannot write a draft. Only the engine bridge names
//! both. Rule A4 holds too: `fstp-findings` cannot reach `fstp-import`,
//! and `fstp-import` names only `fstp_findings::text::UntrustedText`.
//!
//! The dependency check reads `cargo metadata` for the workspace, as the
//! I-10 gate of `fstp-domain-testkit` does. A path is any edge out of the
//! start crate itself, then normal and build edges only. The same rule
//! runs in `tools/deps-check`. This test keeps it in the I-65 suite.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::process::Command;

use fstp_json::{ParseLimits, Value};

/// The crates that must never reach the import store (rule A3).
const DRAFT_SIDE: [&str; 3] = ["fstp-domain", "fstp-programme", "fstp-creator"];

/// The crates the import store must never reach (rule A3).
const WRITER_SIDE: [&str; 2] = ["fstp-creator", "fstp-engine"];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

/// The workspace's `cargo metadata` document.
fn metadata() -> Value {
    let root = workspace_root();
    let out = Command::new(env!("CARGO"))
        .args(["metadata", "--format-version", "1", "--locked"])
        .arg("--manifest-path")
        .arg(root.join("Cargo.toml"))
        .output()
        .expect("cargo metadata runs");
    assert!(
        out.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let limits = ParseLimits::default()
        .with_max_input_bytes(256 << 20)
        .with_max_depth(64)
        .with_max_string_bytes(16 << 20)
        .with_max_container_len(1_000_000)
        .with_max_nodes(50_000_000);
    fstp_json::parse_with(&out.stdout, &limits).expect("cargo metadata prints JSON")
}

/// The dependency graph: package id to name, and package id to its
/// edges, each with whether it is a dev-only edge.
struct Graph {
    names: BTreeMap<String, String>,
    edges: BTreeMap<String, Vec<(String, bool)>>,
}

fn graph(meta: &Value) -> Graph {
    let mut names = BTreeMap::new();
    for p in meta
        .get("packages")
        .and_then(Value::as_array)
        .expect("packages")
        .iter()
    {
        let id = p.get("id").and_then(Value::as_str).expect("package id");
        let name = p.get("name").and_then(Value::as_str).expect("package name");
        names.insert(id.to_owned(), name.to_owned());
    }
    let mut edges = BTreeMap::new();
    let nodes = meta
        .get("resolve")
        .and_then(|r| r.get("nodes"))
        .and_then(Value::as_array)
        .expect("resolve.nodes");
    for n in nodes.iter() {
        let id = n.get("id").and_then(Value::as_str).expect("node id");
        let mut out = Vec::new();
        for d in n
            .get("deps")
            .and_then(Value::as_array)
            .expect("deps")
            .iter()
        {
            let pkg = d.get("pkg").and_then(Value::as_str).expect("dep pkg");
            let kinds = d
                .get("dep_kinds")
                .and_then(Value::as_array)
                .expect("dep_kinds");
            let dev_only = kinds
                .iter()
                .all(|k| k.get("kind").and_then(Value::as_str) == Some("dev"));
            out.push((pkg.to_owned(), dev_only));
        }
        edges.insert(id.to_owned(), out);
    }
    Graph { names, edges }
}

/// The names of every package reachable from the package named `start`:
/// any edge out of `start`, then normal and build edges only.
fn reachable(g: &Graph, start: &str) -> BTreeSet<String> {
    let id = g
        .names
        .iter()
        .find(|(_, n)| n.as_str() == start)
        .map(|(id, _)| id.clone())
        .unwrap_or_else(|| panic!("{start} is not in the workspace"));
    let mut seen = BTreeSet::new();
    let mut queue = VecDeque::from([(id.clone(), true)]);
    while let Some((pkg, first)) = queue.pop_front() {
        for (dep, dev_only) in g.edges.get(&pkg).map(Vec::as_slice).unwrap_or_default() {
            if (*dev_only && !first) || *dep == id || !seen.insert(dep.clone()) {
                continue;
            }
            queue.push_back((dep.clone(), false));
        }
    }
    seen.iter()
        .filter_map(|p| g.names.get(p).cloned())
        .collect()
}

/// I-65, rule A3: the domain, the programme and the creator have no
/// dependency path to the import store.
#[test]
fn i65_creator_and_domain_cannot_reach_import() {
    let g = graph(&metadata());
    // The graph is read correctly: the test kit and the import crate
    // reach what they depend on.
    assert!(
        reachable(&g, "fstp-api-testkit").contains("fstp-import"),
        "the metadata graph lost the edge fstp-api-testkit -> fstp-import"
    );
    assert!(
        reachable(&g, "fstp-import").contains("fstp-programme"),
        "the metadata graph lost the edge fstp-import -> fstp-programme"
    );
    let mut hits = Vec::new();
    for side in DRAFT_SIDE {
        if reachable(&g, side).contains("fstp-import") {
            hits.push(format!("{side} -> fstp-import"));
        }
    }
    assert!(
        hits.is_empty(),
        "I-65: a draft-side crate can name import proposals: {}",
        hits.join(", ")
    );
}

/// I-65, rule A3: the import store has no dependency path to the creator
/// or the engine, so it cannot write a draft.
#[test]
fn i65_import_cannot_reach_creator_or_engine() {
    let g = graph(&metadata());
    assert!(
        reachable(&g, "fstp-import").contains("fstp-findings"),
        "the metadata graph lost the edge fstp-import -> fstp-findings"
    );
    let from_import = reachable(&g, "fstp-import");
    let hits: Vec<&str> = WRITER_SIDE
        .iter()
        .copied()
        .filter(|w| from_import.contains(*w))
        .collect();
    assert!(
        hits.is_empty(),
        "I-65: fstp-import has a dependency path to {hits:?}"
    );
}

/// I-65 and I-10, rule A4: `fstp-findings` cannot reach `fstp-import`.
#[test]
fn i65_findings_cannot_reach_import() {
    let g = graph(&metadata());
    assert!(
        !reachable(&g, "fstp-findings").contains("fstp-import"),
        "I-65, rule A4: fstp-findings has a dependency path to fstp-import"
    );
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).expect("read dir") {
        let p = e.expect("dir entry").path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// The code lines of every Rust source under `crates/<krate>/src`, with
/// comment lines removed, as `(path:line, text)`.
fn code_lines(krate: &str) -> Vec<(String, String)> {
    let dir = workspace_root().join("crates").join(krate).join("src");
    let mut files = Vec::new();
    rust_files(&dir, &mut files);
    assert!(!files.is_empty(), "no {krate} sources found");
    let mut out = Vec::new();
    for f in &files {
        let text = std::fs::read_to_string(f).expect("read source");
        for (i, line) in text.lines().enumerate() {
            if line.trim_start().starts_with("//") {
                continue;
            }
            out.push((
                format!("{}:{}", f.display(), i.saturating_add(1)),
                line.to_owned(),
            ));
        }
    }
    out
}

/// I-65, rule A3: no source line or manifest entry of the domain, the
/// programme or the creator names the import crate.
#[test]
fn i65_draft_side_sources_never_name_import() {
    let mut hits = Vec::new();
    for krate in DRAFT_SIDE {
        for (at, line) in code_lines(krate) {
            if line.contains("fstp_import") {
                hits.push(format!("{at}: {line}"));
            }
        }
        let manifest = workspace_root()
            .join("crates")
            .join(krate)
            .join("Cargo.toml");
        let text = std::fs::read_to_string(&manifest).expect("read manifest");
        for (i, line) in text.lines().enumerate() {
            if line.contains("fstp-import") {
                hits.push(format!(
                    "{}:{}: {line}",
                    manifest.display(),
                    i.saturating_add(1)
                ));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "I-65: the draft side names the import crate:\n{}",
        hits.join("\n")
    );
}

/// I-65, rule A4: `fstp-import` names no `fstp_findings` item other than
/// `fstp_findings::text::UntrustedText`.
#[test]
fn i65_import_names_only_untrusted_text_from_findings() {
    let mut hits = Vec::new();
    for (at, line) in code_lines("fstp-import") {
        let mut rest = line.as_str();
        while let Some(i) = rest.find("fstp_findings") {
            let tail = rest.get(i..).unwrap_or_default();
            if !tail.starts_with("fstp_findings::text::UntrustedText") {
                hits.push(format!("{at}: {line}"));
                break;
            }
            rest = tail.get("fstp_findings".len()..).unwrap_or_default();
        }
    }
    assert!(
        hits.is_empty(),
        "I-65, rule A4: fstp-import names other fstp_findings items:\n{}",
        hits.join("\n")
    );
}
