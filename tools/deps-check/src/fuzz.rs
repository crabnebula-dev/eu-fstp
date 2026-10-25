//! The fuzz-target presence gate (TH-26, H-05, ADR-003).
//!
//! Every crate in `deps/fuzz-required.txt` must own a cargo-fuzz project at
//! `<crate>/fuzz/` with at least one target. The projects come from the
//! repository walk, so `crates/*/fuzz` and `tools/*/fuzz` both count. Every
//! fuzz project must be a well-formed cargo-fuzz project: `cargo-fuzz = true`
//! metadata, a dependency on its parent crate and on libfuzzer-sys, and a
//! source file for every target.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::metadata::Metadata;
use crate::report::{Finding, FuzzSummary};

/// A discovered fuzz project.
pub(crate) struct FuzzProject {
    /// The `fuzz` directory, canonical.
    pub(crate) dir: PathBuf,
    /// Its metadata for the primary platform, or why it could not be read.
    pub(crate) meta: Result<Metadata, String>,
}

/// The workspace member whose manifest sits in `dir`, by package name.
///
/// Both sides are canonicalized, so a symbolic link cannot make a fuzz
/// project claim another crate.
fn crate_in_dir(workspace: &Metadata, dir: &Path) -> Option<String> {
    let manifest = fs::canonicalize(dir.join("Cargo.toml")).ok()?;
    workspace
        .members
        .iter()
        .filter_map(|&m| workspace.packages.get(m))
        .find(|p| fs::canonicalize(&p.manifest_path).is_ok_and(|c| c == manifest))
        .map(|p| p.name.clone())
}

/// Checks one fuzz project and returns its usable target names.
fn check_project(
    p: &FuzzProject,
    parent: Option<&str>,
    label: &str,
    findings: &mut Vec<Finding>,
) -> Vec<String> {
    let Ok(meta) = &p.meta else {
        // The metadata runner already reported the failure.
        return Vec::new();
    };
    let mut ok = true;
    let [member] = meta.members.as_slice() else {
        findings.push(Finding::error(
            "fuzz-shape",
            format!("{label}: expected exactly one package in its own workspace"),
        ));
        return Vec::new();
    };
    let Some(pkg) = meta.packages.get(*member) else {
        return Vec::new();
    };
    if !pkg.cargo_fuzz {
        ok = false;
        findings.push(Finding::error(
            "fuzz-shape",
            format!("{label}: [package.metadata] cargo-fuzz = true is missing"),
        ));
    }
    let deps: Vec<(&str, bool)> = meta
        .node_of_pkg
        .get(member)
        .and_then(|&n| meta.nodes.get(n))
        .map(|node| {
            node.deps
                .iter()
                .filter_map(|d| meta.packages.get(d.pkg))
                .map(|q| (q.name.as_str(), q.is_path()))
                .collect()
        })
        .unwrap_or_default();
    match parent {
        Some(name) if deps.contains(&(name, true)) => {}
        Some(name) => {
            ok = false;
            findings.push(Finding::error(
                "fuzz-shape",
                format!("{label}: does not depend on its parent crate {name}"),
            ));
        }
        None => {
            ok = false;
            findings.push(Finding::error(
                "fuzz-shape",
                format!("{label}: its parent directory is not a workspace member crate"),
            ));
        }
    }
    if !deps.contains(&("libfuzzer-sys", false)) {
        ok = false;
        findings.push(Finding::error(
            "fuzz-shape",
            format!("{label}: does not depend on libfuzzer-sys"),
        ));
    }
    let mut targets = Vec::new();
    for t in &pkg.targets {
        if !t.kinds.iter().any(|k| k == "bin") {
            continue;
        }
        if Path::new(&t.src_path).is_file() {
            targets.push(t.name.clone());
        } else {
            ok = false;
            findings.push(Finding::error(
                "fuzz-target-missing",
                format!("{label}: target {} has no source at {}", t.name, t.src_path),
            ));
        }
    }
    targets.sort();
    if ok { targets } else { Vec::new() }
}

/// Runs the gate.
pub(crate) fn check(
    root: &Path,
    required: &[String],
    workspace: Option<&Metadata>,
    projects: &[FuzzProject],
) -> (Vec<FuzzSummary>, Vec<Finding>) {
    let mut findings = Vec::new();
    let mut by_crate: BTreeMap<String, FuzzSummary> = BTreeMap::new();
    for p in projects {
        let label = p
            .dir
            .strip_prefix(root)
            .unwrap_or(&p.dir)
            .display()
            .to_string();
        let parent_dir = p.dir.parent().unwrap_or(&p.dir);
        let parent = workspace.and_then(|w| crate_in_dir(w, parent_dir));
        let targets = check_project(p, parent.as_deref(), &label, &mut findings);
        let krate = parent.unwrap_or(label);
        if targets.is_empty() && p.meta.is_ok() {
            findings.push(Finding::error(
                "fuzz-no-targets",
                format!("{krate}: the fuzz project has no usable target"),
            ));
        }
        by_crate.insert(
            krate.clone(),
            FuzzSummary {
                required: required.contains(&krate),
                krate,
                targets,
            },
        );
    }
    for name in required {
        if let Some(w) = workspace {
            let known = w
                .members
                .iter()
                .filter_map(|&m| w.packages.get(m))
                .any(|p| &p.name == name);
            if !known {
                findings.push(Finding::error(
                    "fuzz-required-unknown",
                    format!("deps/fuzz-required.txt lists {name}, which is not a workspace member"),
                ));
                continue;
            }
        }
        match by_crate.get(name) {
            Some(s) if !s.targets.is_empty() => {}
            Some(_) => findings.push(Finding::error(
                "fuzz-required",
                format!("{name} is parser-bearing but its fuzz project has no usable target"),
            )),
            None => {
                findings.push(Finding::error(
                    "fuzz-required",
                    format!(
                        "{name} is parser-bearing but has no cargo-fuzz project (TH-26, ADR-003)"
                    ),
                ));
                by_crate.insert(
                    name.clone(),
                    FuzzSummary {
                        krate: name.clone(),
                        targets: Vec::new(),
                        required: true,
                    },
                );
            }
        }
    }
    (by_crate.into_values().collect(), findings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::{DepKind, Node, NodeDep, Package, Target};
    use crate::python::tests::TempDir;

    fn pkg(name: &str, manifest: &Path, path: bool) -> Package {
        Package {
            id: name.into(),
            name: name.into(),
            version: "0.1.0".into(),
            source: if path {
                None
            } else {
                Some("registry+https://github.com/rust-lang/crates.io-index".into())
            },
            manifest_path: manifest.display().to_string(),
            features: Default::default(),
            dependencies: vec![],
            targets: vec![],
            cargo_fuzz: false,
        }
    }

    fn workspace(root: &Path, crates: &[&str]) -> Metadata {
        let mut m = Metadata::default();
        for (i, c) in crates.iter().enumerate() {
            m.packages.push(pkg(
                c,
                &root.join("crates").join(c).join("Cargo.toml"),
                true,
            ));
            m.members.push(i);
        }
        m
    }

    fn fuzz_meta(root: &Path, krate: &str, targets: &[&str], with_libfuzzer: bool) -> Metadata {
        let dir = root.join("crates").join(krate).join("fuzz");
        let mut member = pkg(&format!("{krate}-fuzz"), &dir.join("Cargo.toml"), true);
        member.cargo_fuzz = true;
        member.targets = targets
            .iter()
            .map(|t| Target {
                name: (*t).into(),
                kinds: vec!["bin".into()],
                src_path: dir
                    .join("fuzz_targets")
                    .join(format!("{t}.rs"))
                    .display()
                    .to_string(),
            })
            .collect();
        let parent = pkg(
            krate,
            &root.join("crates").join(krate).join("Cargo.toml"),
            true,
        );
        let lf = pkg("libfuzzer-sys", Path::new("/registry/libfuzzer-sys"), false);
        let mut m = Metadata {
            packages: vec![member, parent, lf],
            members: vec![0],
            ..Metadata::default()
        };
        let mut deps = vec![NodeDep {
            pkg: 1,
            kinds: vec![DepKind::Normal],
        }];
        if with_libfuzzer {
            deps.push(NodeDep {
                pkg: 2,
                kinds: vec![DepKind::Normal],
            });
        }
        m.nodes = vec![
            Node {
                pkg: 0,
                deps,
                features: vec![],
            },
            Node {
                pkg: 1,
                deps: vec![],
                features: vec![],
            },
            Node {
                pkg: 2,
                deps: vec![],
                features: vec![],
            },
        ];
        m.node_of_pkg = [(0, 0), (1, 1), (2, 2)].into_iter().collect();
        m
    }

    /// TH-26, ADR-003: a parser-bearing crate without a fuzz project, or
    /// with a project whose targets are unusable, fails the gate.
    #[test]
    fn th26_required_crates_need_fuzz_targets() {
        let t = TempDir::new("fuzz");
        let root = fs::canonicalize(&t.0).unwrap();
        for c in ["a", "b", "c", "d"] {
            t.write(&format!("crates/{c}/Cargo.toml"), b"");
        }
        t.write("crates/a/fuzz/Cargo.toml", b"");
        t.write("crates/a/fuzz/fuzz_targets/parse.rs", b"");
        t.write("crates/b/fuzz/Cargo.toml", b"");
        t.write("crates/d/fuzz/Cargo.toml", b"");
        t.write("crates/d/fuzz/fuzz_targets/x.rs", b"");
        fs::create_dir_all(root.join("crates/c/fuzz")).unwrap();

        let ws = workspace(&root, &["a", "b", "c", "d"]);
        let projects = vec![
            FuzzProject {
                dir: root.join("crates/a/fuzz"),
                meta: Ok(fuzz_meta(&root, "a", &["parse"], true)),
            },
            FuzzProject {
                dir: root.join("crates/b/fuzz"),
                // The target's source file does not exist.
                meta: Ok(fuzz_meta(&root, "b", &["gone"], true)),
            },
            FuzzProject {
                dir: root.join("crates/d/fuzz"),
                meta: Ok(fuzz_meta(&root, "d", &["x"], false)),
            },
        ];
        let required: Vec<String> = ["a", "b", "c", "zz"].iter().map(|s| (*s).into()).collect();
        let (summary, findings) = check(&root, &required, Some(&ws), &projects);
        let codes: Vec<&str> = findings.iter().map(|f| f.code).collect();
        assert!(codes.contains(&"fuzz-target-missing"), "{findings:?}");
        assert!(codes.contains(&"fuzz-required-unknown"), "{findings:?}");
        let required_fail: Vec<&str> = findings
            .iter()
            .filter(|f| f.code == "fuzz-required")
            .map(|f| f.message.as_str())
            .collect();
        assert_eq!(required_fail.len(), 2, "{required_fail:?}");
        assert!(required_fail[0].starts_with("b is parser-bearing"));
        assert!(required_fail[1].starts_with("c is parser-bearing but has no cargo-fuzz"));
        assert!(
            findings
                .iter()
                .any(|f| f.message.contains("does not depend on libfuzzer-sys"))
        );
        let a = summary.iter().find(|s| s.krate == "a").unwrap();
        assert_eq!(a.targets, vec!["parse".to_owned()]);
        assert!(a.required);
        let d = summary.iter().find(|s| s.krate == "d").unwrap();
        assert!(!d.required);
        assert!(d.targets.is_empty());
    }

    #[test]
    fn th26_failed_metadata_counts_as_missing_targets() {
        let t = TempDir::new("fuzzmeta");
        let root = fs::canonicalize(&t.0).unwrap();
        t.write("crates/a/Cargo.toml", b"");
        t.write("crates/a/fuzz/Cargo.toml", b"");
        let ws = workspace(&root, &["a"]);
        let projects = vec![FuzzProject {
            dir: root.join("crates/a/fuzz"),
            meta: Err("lockfile out of date".into()),
        }];
        let (_, findings) = check(&root, &["a".to_owned()], Some(&ws), &projects);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].code, "fuzz-required");
    }
}
