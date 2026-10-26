//! I-10 layering gate (design sections 1 and 6.2).
//!
//! `fstp-domain` cannot name a finding: it has no dependency path to
//! `fstp-findings` or `fstp-engine`, and its sources never name either
//! crate. So no domain guard, score or decision can read a finding, and
//! the ranking view cannot hold one.
//!
//! The dependency check reads `cargo metadata` for the workspace. A path
//! is any edge out of `fstp-domain` itself, then normal and build edges
//! only, which is what cargo builds for the crate and its tests. The
//! same rule runs in `tools/deps-check`. This test keeps it in the I-10
//! suite.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::process::Command;

use fstp_json::{ParseLimits, Value};

/// The crates on the findings side of the I-10 boundary.
const FINDINGS_SIDE: [&str; 2] = ["fstp-findings", "fstp-engine"];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

/// The workspace's `cargo metadata` document.
fn metadata() -> Value {
    let root = workspace_root();
    let out = Command::new(env!("CARGO"))
        .args(["metadata", "--format-version", "1", "--locked", "--offline"])
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

/// I-10: fstp-domain has no dependency path to fstp-findings or fstp-engine.
#[test]
fn i10_domain_crates_cannot_reach_findings() {
    let g = graph(&metadata());
    // The graph is read correctly: the findings crate does reach the domain.
    assert!(
        reachable(&g, "fstp-findings").contains("fstp-domain"),
        "the metadata graph lost the edge fstp-findings -> fstp-domain"
    );
    let from_domain = reachable(&g, "fstp-domain");
    for side in FINDINGS_SIDE {
        assert!(
            !from_domain.contains(side),
            "I-10: fstp-domain has a dependency path to {side}; findings depend on the domain, never the reverse"
        );
    }
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

/// I-10: no fstp-domain source line or manifest entry names fstp-findings
/// or fstp-engine, so the domain cannot name a finding type.
#[test]
fn i10_domain_sources_never_name_the_findings_crates() {
    let domain = workspace_root().join("crates").join("fstp-domain");
    let mut files = Vec::new();
    rust_files(&domain.join("src"), &mut files);
    assert!(!files.is_empty(), "no fstp-domain sources found");
    let mut hits = Vec::new();
    for f in &files {
        let text = std::fs::read_to_string(f).expect("read source");
        for (i, line) in text.lines().enumerate() {
            let code = line.trim_start();
            if code.starts_with("//") {
                continue;
            }
            if code.contains("fstp_findings") || code.contains("fstp_engine") {
                hits.push(format!("{}:{}: {line}", f.display(), i + 1));
            }
        }
    }
    let manifest = std::fs::read_to_string(domain.join("Cargo.toml")).expect("read manifest");
    for (i, line) in manifest.lines().enumerate() {
        if line.contains("fstp-findings") || line.contains("fstp-engine") {
            hits.push(format!("Cargo.toml:{}: {line}", i + 1));
        }
    }
    assert!(
        hits.is_empty(),
        "I-10: fstp-domain names the findings side:\n{}",
        hits.join("\n")
    );
}
