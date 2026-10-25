//! The repository's files and cargo projects, from one walk shared by every gate.
//!
//! The walk does not follow symbolic links. It skips only what the root
//! `.gitignore` ignores as build output:
//!
//! - every `.git` directory, which git never commits;
//! - `target` at the repository root;
//! - `target`, `corpus`, `artifacts` and `coverage` directly under a
//!   directory named `fuzz`;
//! - the directory that `CARGO_TARGET_DIR` names, when it lies inside the
//!   repository.
//!
//! A directory named `target` anywhere else is scanned like any other.

use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use crate::graph::{Context, ProjectKind};
use crate::report::Finding;

/// Upper bound on directory entries, so a runaway tree cannot stall CI.
const MAX_ENTRIES: usize = 2_000_000;
/// Upper bound on directory depth.
const MAX_DEPTH: usize = 64;
/// Upper bound on the size of a manifest the override scan reads.
const MAX_MANIFEST: u64 = 1 << 20;

/// What a directory entry is, without following symbolic links.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    /// A regular file.
    File,
    /// A symbolic link.
    Symlink,
    /// A socket, FIFO or device.
    Other,
}

/// One non-directory entry of the repository.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RepoFile {
    /// Path relative to the repository root.
    pub(crate) rel: PathBuf,
    /// Entry kind.
    pub(crate) kind: Kind,
}

/// The result of a walk.
#[derive(Debug, Default)]
pub(crate) struct Walk {
    /// Every non-directory entry, sorted by path.
    pub(crate) files: Vec<RepoFile>,
    /// Every directory that was entered, relative to the root.
    pub(crate) dirs: Vec<PathBuf>,
    /// Walk problems.
    pub(crate) findings: Vec<Finding>,
}

impl Walk {
    /// Regular files whose name is `name`.
    pub(crate) fn named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a RepoFile> {
        self.files
            .iter()
            .filter(move |f| f.kind == Kind::File && f.rel.file_name().is_some_and(|n| n == name))
    }
}

fn file_name(p: &Path) -> &str {
    p.file_name().and_then(|n| n.to_str()).unwrap_or("")
}

fn parent_name(p: &Path) -> &str {
    p.parent().map(file_name).unwrap_or("")
}

/// Whether the walk skips the directory at `rel` (absolute path `abs`).
fn skipped(rel: &Path, abs: &Path, skip: &[PathBuf]) -> bool {
    let name = file_name(rel);
    name == ".git"
        || rel == Path::new("target")
        || (parent_name(rel) == "fuzz"
            && matches!(name, "target" | "corpus" | "artifacts" | "coverage"))
        || skip.iter().any(|s| s == abs)
}

/// The `CARGO_TARGET_DIR` in use, canonicalized, if it lies inside `root`.
pub(crate) fn target_dir_inside(root: &Path) -> Vec<PathBuf> {
    std::env::var_os("CARGO_TARGET_DIR")
        .map(|d| {
            let d = PathBuf::from(d);
            if d.is_absolute() { d } else { root.join(d) }
        })
        .and_then(|d| fs::canonicalize(d).ok())
        .filter(|d| d.starts_with(root) && d != root)
        .into_iter()
        .collect()
}

/// Walks `root`, which must be canonical. `skip` lists extra absolute
/// directories to leave out.
pub(crate) fn walk(root: &Path, skip: &[PathBuf]) -> Walk {
    let mut out = Walk::default();
    let mut stack: Vec<(PathBuf, usize)> = vec![(PathBuf::new(), 0)];
    let mut entries = 0usize;
    while let Some((rel_dir, depth)) = stack.pop() {
        let dir = root.join(&rel_dir);
        let reader = match fs::read_dir(&dir) {
            Ok(r) => r,
            Err(e) => {
                out.findings.push(Finding::error(
                    "scan-io",
                    format!("cannot read directory {}: {e}", rel_dir.display()),
                ));
                continue;
            }
        };
        out.dirs.push(rel_dir.clone());
        for item in reader {
            entries = entries.saturating_add(1);
            if entries > MAX_ENTRIES {
                out.findings.push(Finding::error(
                    "scan-limit",
                    format!("more than {MAX_ENTRIES} entries; scan stopped"),
                ));
                out.files.sort_by(|a, b| a.rel.cmp(&b.rel));
                return out;
            }
            let item = match item {
                Ok(i) => i,
                Err(e) => {
                    out.findings.push(Finding::error(
                        "scan-io",
                        format!("cannot list {}: {e}", rel_dir.display()),
                    ));
                    continue;
                }
            };
            let rel = rel_dir.join(item.file_name());
            let abs = root.join(&rel);
            let Ok(meta) = fs::symlink_metadata(&abs) else {
                out.findings.push(Finding::error(
                    "scan-io",
                    format!("cannot stat {}", rel.display()),
                ));
                continue;
            };
            let ft = meta.file_type();
            if ft.is_dir() {
                if skipped(&rel, &abs, skip) {
                    continue;
                }
                if depth >= MAX_DEPTH {
                    out.findings.push(Finding::error(
                        "scan-limit",
                        format!("{} is nested deeper than {MAX_DEPTH} levels", rel.display()),
                    ));
                    continue;
                }
                stack.push((rel, depth.saturating_add(1)));
                continue;
            }
            let kind = if ft.is_file() {
                Kind::File
            } else if ft.is_symlink() {
                Kind::Symlink
            } else {
                Kind::Other
            };
            out.files.push(RepoFile { rel, kind });
        }
    }
    out.files.sort_by(|a, b| a.rel.cmp(&b.rel));
    out.dirs.sort();
    out
}

/// A cargo project: a directory that holds a `Cargo.lock` and a `Cargo.toml`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProjectDir {
    /// Directory relative to the repository root; empty for the root.
    pub(crate) rel: PathBuf,
    /// `workspace` for the root, otherwise the relative path.
    pub(crate) label: String,
    /// Fuzz for a directory named `fuzz`, otherwise Workspace.
    pub(crate) kind: ProjectKind,
}

/// Whether `rel` is `crates/<name>/fuzz` or `tools/<name>/fuzz`.
pub(crate) fn known_fuzz_location(rel: &Path) -> bool {
    let parts: Vec<Component<'_>> = rel.components().collect();
    matches!(
        parts.as_slice(),
        [Component::Normal(top), Component::Normal(_), Component::Normal(f)]
            if (*top == "crates" || *top == "tools") && *f == "fuzz"
    )
}

/// Finds every cargo project. Every project is analysed. Projects other
/// than the root and the fuzz projects at known locations are errors,
/// because CI's fmt, clippy and fuzz loops would not cover them.
pub(crate) fn projects(walk: &Walk) -> (Vec<ProjectDir>, Vec<Finding>) {
    let mut findings = Vec::new();
    let manifests: BTreeSet<PathBuf> = walk
        .named("Cargo.toml")
        .filter_map(|f| f.rel.parent().map(Path::to_path_buf))
        .collect();
    let mut out = Vec::new();
    for lock in walk.named("Cargo.lock") {
        let dir = lock.rel.parent().map(Path::to_path_buf).unwrap_or_default();
        if !manifests.contains(&dir) {
            findings.push(Finding::error(
                "lockfile-orphan",
                format!("{} has no Cargo.toml next to it", lock.rel.display()),
            ));
            continue;
        }
        let root = dir.as_os_str().is_empty();
        let fuzz = !root && file_name(&dir) == "fuzz";
        if !root && !known_fuzz_location(&dir) {
            findings.push(Finding::error(
                "project-location",
                format!(
                    "{} is a cargo project outside crates/*/fuzz and tools/*/fuzz; CI's fmt, \
                     clippy and fuzz steps do not cover it (analysed anyway)",
                    dir.display()
                ),
            ));
        }
        out.push(ProjectDir {
            label: if root {
                "workspace".to_owned()
            } else {
                dir.display().to_string()
            },
            rel: dir,
            kind: if fuzz {
                ProjectKind::Fuzz
            } else {
                ProjectKind::Workspace
            },
        });
    }
    if !out.iter().any(|p| p.rel.as_os_str().is_empty()) {
        findings.push(Finding::error(
            "no-root-lockfile",
            "the repository root has no Cargo.lock next to its Cargo.toml",
        ));
    }
    for d in &walk.dirs {
        if known_fuzz_location(d) && !manifests.contains(d) {
            findings.push(Finding::warning(
                "fuzz-no-manifest",
                format!("{} has no Cargo.toml", d.display()),
            ));
        }
    }
    out.sort_by(|a, b| a.rel.cmp(&b.rel));
    (out, findings)
}

/// Refuses cargo configuration and vendored sources in the repository (P5).
///
/// Any `.cargo/config` or `.cargo/config.toml` in the repository is an
/// error. Source replacement, `[patch]`, `paths` overrides and registry
/// settings all live there, and the repository needs none of them. A
/// `.cargo-checksum.json` marks a vendored crate. Configuration in an
/// ancestor directory or in cargo's home also applies to every build, so
/// it is reported as a warning. The location checks in `provenance` catch
/// its effects.
///
/// Names are compared without regard to ASCII case. On a case-insensitive
/// file system, such as the macOS and Windows defaults, cargo opens
/// `.Cargo/CONFIG.toml` as its configuration and `cargo.lock` as the
/// lockfile. A manifest or lockfile name that differs from cargo's only in
/// case is an error too, because a checkout there can also replace the
/// checked file with it.
pub(crate) fn check_cargo_config(root: &Path, walk: &Walk) -> Vec<Finding> {
    let mut out = Vec::new();
    for f in &walk.files {
        let name = file_name(&f.rel);
        let lower = name.to_ascii_lowercase();
        if parent_name(&f.rel).eq_ignore_ascii_case(".cargo")
            && matches!(lower.as_str(), "config" | "config.toml")
        {
            out.push(Finding::error(
                "cargo-config",
                format!(
                    "{} configures cargo inside the repository; source replacement, [patch], \
                     `paths` and registry settings are not allowed",
                    f.rel.display()
                ),
            ));
        } else if lower == ".cargo" && f.kind == Kind::Symlink {
            out.push(Finding::error(
                "cargo-config",
                format!(
                    "{} is a symbolic link where cargo looks for configuration",
                    f.rel.display()
                ),
            ));
        } else if lower == ".cargo-checksum.json" {
            out.push(Finding::error(
                "vendored-crate",
                format!(
                    "{} marks a vendored crate; vendoring is not allowed",
                    f.rel.display()
                ),
            ));
        } else if matches!(lower.as_str(), "cargo.toml" | "cargo.lock")
            && !matches!(name, "Cargo.toml" | "Cargo.lock")
        {
            out.push(Finding::error(
                "manifest-case-variant",
                format!(
                    "{} differs from a cargo file name only in case; a case-insensitive \
                     file system treats it as that file",
                    f.rel.display()
                ),
            ));
        }
    }
    let mut outside: Vec<PathBuf> = root.ancestors().skip(1).map(|a| a.join(".cargo")).collect();
    if let Some(home) = std::env::var_os("CARGO_HOME") {
        outside.push(PathBuf::from(home));
    } else if let Some(home) = std::env::var_os("HOME") {
        outside.push(PathBuf::from(home).join(".cargo"));
    }
    let mut seen = BTreeSet::new();
    for dir in outside {
        for name in ["config", "config.toml"] {
            let p = dir.join(name);
            if p.is_file() && seen.insert(p.clone()) {
                out.push(Finding::warning(
                    "cargo-config-outside",
                    format!(
                        "{} applies to this build; deps-check relies on its location checks \
                         to catch source replacement or overrides there",
                        p.display()
                    ),
                ));
            }
        }
    }
    out
}

/// Fails on symbolic links that cargo, bash globs or the scans would
/// follow into code that deps-check never inspects.
///
/// A link named `Cargo.toml` or `Cargo.lock` and a link to a directory are
/// errors.
pub(crate) fn check_symlinks(root: &Path, walk: &Walk) -> Vec<Finding> {
    let mut out = Vec::new();
    for f in walk.files.iter().filter(|f| f.kind == Kind::Symlink) {
        let name = file_name(&f.rel);
        if matches!(name, "Cargo.toml" | "Cargo.lock") {
            out.push(Finding::error(
                "symlinked-manifest",
                format!("{} is a symbolic link", f.rel.display()),
            ));
        } else if root.join(&f.rel).is_dir() {
            out.push(Finding::error(
                "symlinked-directory",
                format!(
                    "{} links to a directory, which deps-check does not follow",
                    f.rel.display()
                ),
            ));
        }
    }
    out
}

/// The first key segment of a TOML key or table header, without quotes
/// and whitespace. `[ "patch" . crates-io ]` yields `patch`.
fn first_segment(s: &str) -> String {
    let cleaned: String = s
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '"' && *c != '\'')
        .collect();
    cleaned.split('.').next().unwrap_or("").to_owned()
}

/// Lines of a manifest that declare `[patch]` or `[replace]`, with their
/// 1-based numbers.
///
/// This is a text scan, not a TOML parser, and it errs towards reporting.
/// A key written with escape sequences can slip past it; the graph and
/// location checks catch the effect of such a patch.
pub(crate) fn manifest_overrides(text: &str) -> Vec<usize> {
    let mut hits = Vec::new();
    let mut in_root_table = true;
    for (i, line) in text.lines().enumerate() {
        let t = line.trim_start();
        if t.starts_with('#') || t.is_empty() {
            continue;
        }
        let flagged = if let Some(header) = t.strip_prefix('[') {
            in_root_table = false;
            let header = header.trim_start_matches('[');
            let header = header.split(']').next().unwrap_or("");
            matches!(first_segment(header).as_str(), "patch" | "replace")
        } else if in_root_table {
            let key = t.split('=').next().unwrap_or("");
            matches!(first_segment(key).as_str(), "patch" | "replace")
        } else {
            false
        };
        if flagged {
            hits.push(i.saturating_add(1));
        }
    }
    hits
}

/// Refuses `[patch]` and `[replace]` in every manifest of the repository (P5).
pub(crate) fn check_manifest_overrides(root: &Path, walk: &Walk) -> Vec<Finding> {
    let mut out = Vec::new();
    for f in walk.named("Cargo.toml") {
        let mut text = String::new();
        let read = fs::File::open(root.join(&f.rel)).and_then(|file| {
            file.take(MAX_MANIFEST.saturating_add(1))
                .read_to_string(&mut text)
        });
        match read {
            Err(e) => out.push(Finding::error(
                "scan-io",
                format!("cannot read {}: {e}", f.rel.display()),
            )),
            Ok(n) if n as u64 > MAX_MANIFEST => out.push(Finding::error(
                "scan-limit",
                format!("{} is larger than {MAX_MANIFEST} bytes", f.rel.display()),
            )),
            Ok(_) => {
                for line in manifest_overrides(&text) {
                    out.push(Finding::error(
                        "manifest-override",
                        format!(
                            "{}:{line} declares [patch] or [replace]; overriding crates.io \
                             crates is not allowed",
                            f.rel.display()
                        ),
                    ));
                }
            }
        }
    }
    out
}

/// Fails on any `Cargo.toml` that no analysed project contains, such as a
/// nested workspace without a committed lockfile.
pub(crate) fn check_manifest_coverage(
    root: &Path,
    walk: &Walk,
    contexts: &[Context<'_>],
) -> Vec<Finding> {
    let mut known: BTreeSet<PathBuf> = BTreeSet::new();
    for ctx in contexts {
        // The workspace manifest, which may be virtual and name no package.
        if let Ok(c) = fs::canonicalize(Path::new(&ctx.meta.workspace_root).join("Cargo.toml")) {
            known.insert(c);
        }
        for p in &ctx.meta.packages {
            if p.is_path()
                && let Ok(c) = fs::canonicalize(&p.manifest_path)
            {
                known.insert(c);
            }
        }
    }
    let mut out = Vec::new();
    for f in walk.named("Cargo.toml") {
        let covered = fs::canonicalize(root.join(&f.rel)).is_ok_and(|c| known.contains(&c));
        if !covered {
            out.push(Finding::error(
                "unanalysed-manifest",
                format!(
                    "{} belongs to no analysed cargo project; a project needs a committed \
                     Cargo.lock at crates/*/fuzz or tools/*/fuzz",
                    f.rel.display()
                ),
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::python::tests::TempDir;

    fn rels(w: &Walk) -> Vec<String> {
        w.files
            .iter()
            .map(|f| f.rel.display().to_string())
            .collect()
    }

    #[test]
    fn walk_skips_only_build_output() {
        let t = TempDir::new("walk");
        for f in [
            "Cargo.toml",
            "target/debug/x",
            "tools/target/gen.sh",
            "crates/x/src/target/helper.rs",
            "crates/x/fuzz/target/y",
            "crates/x/fuzz/corpus/z",
            "crates/x/fuzz/artifacts/a",
            "crates/x/fuzz/seeds/s",
            "crates/x/.git/config",
            "build/out",
        ] {
            t.write(f, b"");
        }
        let root = fs::canonicalize(&t.0).unwrap();
        let w = walk(&root, &[root.join("build")]);
        assert_eq!(
            rels(&w),
            vec![
                "Cargo.toml",
                "crates/x/fuzz/seeds/s",
                "crates/x/src/target/helper.rs",
                "tools/target/gen.sh",
            ]
        );
    }

    /// Regression for review finding projects-outside-crates-fuzz (P5): a
    /// cargo project with its own lockfile anywhere in the repository is
    /// found and analysed. One outside the known fuzz locations is an error.
    #[test]
    fn review_projects_outside_crates_fuzz() {
        let t = TempDir::new("projects");
        for f in [
            "Cargo.toml",
            "Cargo.lock",
            "crates/a/Cargo.toml",
            "crates/a/fuzz/Cargo.toml",
            "crates/a/fuzz/Cargo.lock",
            "tools/deps-check/fuzz/Cargo.toml",
            "tools/deps-check/fuzz/Cargo.lock",
            "crates/a/fuzz2/Cargo.toml",
            "crates/a/fuzz2/Cargo.lock",
            "crates/b/pgtests/Cargo.toml",
            "crates/b/pgtests/Cargo.lock",
            "stray/Cargo.lock",
        ] {
            t.write(f, b"");
        }
        std::fs::create_dir_all(t.0.join("crates/c/fuzz")).unwrap();
        let root = fs::canonicalize(&t.0).unwrap();
        let (found, findings) = projects(&walk(&root, &[]));
        let labels: Vec<(&str, ProjectKind)> =
            found.iter().map(|p| (p.label.as_str(), p.kind)).collect();
        assert_eq!(
            labels,
            vec![
                ("workspace", ProjectKind::Workspace),
                ("crates/a/fuzz", ProjectKind::Fuzz),
                ("crates/a/fuzz2", ProjectKind::Workspace),
                ("crates/b/pgtests", ProjectKind::Workspace),
                ("tools/deps-check/fuzz", ProjectKind::Fuzz),
            ]
        );
        let got: Vec<(&str, String)> = findings
            .iter()
            .map(|f| (f.code, f.message.split(' ').next().unwrap_or("").to_owned()))
            .collect();
        assert_eq!(
            got,
            vec![
                ("project-location", "crates/a/fuzz2".to_owned()),
                ("project-location", "crates/b/pgtests".to_owned()),
                ("lockfile-orphan", "stray/Cargo.lock".to_owned()),
                ("fuzz-no-manifest", "crates/c/fuzz".to_owned()),
            ]
        );
    }

    /// Regression for review finding source-replacement-tamper (P5): a
    /// cargo configuration or a vendored crate inside the repository fails.
    #[test]
    fn review_source_replacement_config_refused() {
        let t = TempDir::new("config");
        t.write(
            ".cargo/config.toml",
            b"[source.crates-io]\nreplace-with = \"vendored-sources\"\n",
        );
        t.write("tools/x/.cargo/config", b"");
        t.write("vendor/subtle/.cargo-checksum.json", b"{\"files\":{}}");
        let root = fs::canonicalize(&t.0).unwrap();
        let f = check_cargo_config(&root, &walk(&root, &[]));
        let codes: Vec<&str> = f
            .iter()
            .filter(|f| f.code != "cargo-config-outside")
            .map(|f| f.code)
            .collect();
        assert_eq!(
            codes,
            vec!["cargo-config", "cargo-config", "vendored-crate"],
            "{f:?}"
        );
    }

    /// Review finding source-replacement-tamper (P5), other platforms. On
    /// a case-insensitive file system cargo reads `.Cargo/CONFIG.toml` as
    /// its configuration, a `.Cargo-Checksum.json` as a vendored crate's
    /// checksums and `cargo.lock` as the lockfile. Each case variant fails.
    #[test]
    fn review_source_replacement_case_variants_refused() {
        let t = TempDir::new("config-case");
        t.write(
            ".Cargo/CONFIG.toml",
            b"[source.crates-io]\nreplace-with = \"vendored-sources\"\n",
        );
        t.write("tools/x/.CARGO/Config", b"");
        t.write("vendor/subtle/.Cargo-Checksum.json", b"{\"files\":{}}");
        t.write("crates/a/cargo.toml", b"[package]\n");
        t.write("crates/a/CARGO.LOCK", b"version = 4\n");
        let root = fs::canonicalize(&t.0).unwrap();
        let f = check_cargo_config(&root, &walk(&root, &[]));
        let mut codes: Vec<&str> = f
            .iter()
            .filter(|f| f.code != "cargo-config-outside")
            .map(|f| f.code)
            .collect();
        codes.sort_unstable();
        assert_eq!(
            codes,
            vec![
                "cargo-config",
                "cargo-config",
                "manifest-case-variant",
                "manifest-case-variant",
                "vendored-crate"
            ],
            "{f:?}"
        );
    }

    /// Regression for review finding patch-path-override (P5): `[patch]`
    /// and `[replace]` in any manifest fail, in each TOML spelling the scan
    /// can see.
    #[test]
    fn review_patch_sections_refused() {
        for (text, want) in [
            (
                "[patch.crates-io]\nsubtle = { path = \"vendor/subtle\" }\n",
                vec![1],
            ),
            (
                "[package]\nname = \"a\"\n\n[ \"patch\" . 'crates-io' ]\n",
                vec![4],
            ),
            ("[replace]\n\"subtle:2.6.1\" = { path = \"x\" }\n", vec![1]),
            (
                "patch.crates-io.subtle = { path = \"x\" }\n[package]\n",
                vec![1],
            ),
            ("[[patch.crates-io]]\n", vec![1]),
            // Keys inside other tables are not the root [patch] table.
            ("[package.metadata.x]\npatch = 1\nreplace = 2\n", vec![]),
            (
                "[dependencies]\npatchy = \"1\"\n# [patch.crates-io]\n",
                vec![],
            ),
        ] {
            assert_eq!(manifest_overrides(text), want, "{text}");
        }
        let t = TempDir::new("patch");
        t.write(
            "Cargo.toml",
            b"[workspace]\n[patch.crates-io]\nsubtle = { path = \"v\" }\n",
        );
        let root = fs::canonicalize(&t.0).unwrap();
        let f = check_manifest_overrides(&root, &walk(&root, &[]));
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].code, "manifest-override");
    }

    #[test]
    fn symlinked_manifests_and_directories_fail() {
        let t = TempDir::new("links");
        t.write("real/Cargo.toml", b"");
        t.write("real/file.txt", b"");
        std::os::unix::fs::symlink(t.0.join("real"), t.0.join("dirlink")).unwrap();
        std::os::unix::fs::symlink(t.0.join("real/Cargo.toml"), t.0.join("Cargo.toml")).unwrap();
        std::os::unix::fs::symlink(t.0.join("real/file.txt"), t.0.join("filelink")).unwrap();
        let root = fs::canonicalize(&t.0).unwrap();
        let f = check_symlinks(&root, &walk(&root, &[]));
        let codes: Vec<&str> = f.iter().map(|f| f.code).collect();
        assert_eq!(
            codes,
            vec!["symlinked-manifest", "symlinked-directory"],
            "{f:?}"
        );
    }

    #[test]
    fn known_fuzz_locations() {
        for ok in ["crates/a/fuzz", "tools/deps-check/fuzz"] {
            assert!(known_fuzz_location(Path::new(ok)), "{ok}");
        }
        for bad in [
            "fuzz",
            "crates/fuzz",
            "crates/a/b/fuzz",
            "other/a/fuzz",
            "crates/a/fuzz2",
        ] {
            assert!(!known_fuzz_location(Path::new(bad)), "{bad}");
        }
    }
}
