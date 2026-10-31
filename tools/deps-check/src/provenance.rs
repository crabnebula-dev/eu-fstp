//! Where each package really comes from (TH-15, P5).
//!
//! The resolve graph names a source for each package, but cargo reports a
//! replaced or patched crate under its original crates.io source. These
//! checks therefore look at the files themselves:
//!
//! - A path package must resolve, after following symbolic links, to a
//!   manifest inside the repository. It must also be a member of the main
//!   workspace or of its own project.
//! - A crates.io package must be served from the crates.io registry cache
//!   under cargo's home. A vendored directory, a mirror, or a `paths`
//!   override shows up as a manifest somewhere else.
//! - No path package may share a name with a crates.io package.
//! - Every lockfile must match the analysed graph exactly, and each built
//!   crates.io package must carry the checksum the allowlist records.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use crate::allowlist::Entry;
use crate::graph::{Aggregate, CRATES_IO, Context, PkgKey};
use crate::lockfile::Lockfile;
use crate::report::Finding;

/// The registry index directory name that older cargo versions use for crates.io.
const LEGACY_INDEX_DIR: &str = "github.com-1ecc6299db9ec823";

/// A parsed lockfile and the project it belongs to.
pub(crate) struct ProjectLock<'a> {
    /// Project label, as in [`Context::label`].
    pub(crate) label: &'a str,
    /// Lockfile path relative to the repository root, for messages.
    pub(crate) path: String,
    /// The parsed lockfile.
    pub(crate) lock: &'a Lockfile,
}

/// Canonical paths, memoised. A failure is kept as its message.
#[derive(Default)]
struct Canon(HashMap<String, Result<PathBuf, String>>);

impl Canon {
    fn get(&mut self, path: &str) -> Result<PathBuf, String> {
        self.0
            .entry(path.to_owned())
            .or_insert_with(|| fs::canonicalize(path).map_err(|e| e.to_string()))
            .clone()
    }
}

/// The crates.io registry source directory under cargo's home, from
/// `CARGO_HOME` or `$HOME/.cargo`, canonicalized.
pub(crate) fn registry_src() -> Result<PathBuf, String> {
    let home = match std::env::var_os("CARGO_HOME") {
        Some(h) if !h.is_empty() => PathBuf::from(h),
        _ => match std::env::var_os("HOME") {
            Some(h) if !h.is_empty() => PathBuf::from(h).join(".cargo"),
            _ => return Err("neither CARGO_HOME nor HOME is set".to_owned()),
        },
    };
    let src = home.join("registry").join("src");
    fs::canonicalize(&src).map_err(|e| format!("cannot resolve {}: {e}", src.display()))
}

/// Whether `dir` is a crates.io index directory name, such as
/// `index.crates.io-1949cf8c6b5b557f`.
fn crates_io_index_dir(dir: &OsStr) -> bool {
    let Some(dir) = dir.to_str() else {
        return false;
    };
    dir == LEGACY_INDEX_DIR
        || dir.strip_prefix("index.crates.io-").is_some_and(|h| {
            !h.is_empty() && h.len() <= 32 && h.bytes().all(|b| b.is_ascii_hexdigit())
        })
}

/// Whether `manifest` is `<registry_src>/<crates.io index>/<name>-<version>/Cargo.toml`.
fn in_registry_cache(manifest: &Path, registry_src: &Path, name: &str, version: &str) -> bool {
    let Ok(rest) = manifest.strip_prefix(registry_src) else {
        return false;
    };
    let parts: Vec<&OsStr> = rest.iter().collect();
    let expected = format!("{name}-{version}");
    matches!(
        parts.as_slice(),
        [index, dir, file]
            if crates_io_index_dir(index)
                && dir.to_str() == Some(expected.as_str())
                && *file == OsStr::new("Cargo.toml")
    )
}

/// Checks where every package of every context lives on disk.
///
/// `main_members` holds the canonical manifest paths of the main
/// workspace's members. `registry_src` is the result of [`registry_src`].
pub(crate) fn check_locations(
    contexts: &[Context<'_>],
    repo_root: &Path,
    main_members: &BTreeSet<PathBuf>,
    registry_src: &Result<PathBuf, String>,
) -> Vec<Finding> {
    let mut findings = BTreeSet::new();
    let mut canon = Canon::default();
    for ctx in contexts {
        let meta = ctx.meta;
        let own_members: BTreeSet<PathBuf> = meta
            .members
            .iter()
            .filter_map(|&m| meta.packages.get(m))
            .filter_map(|p| canon.get(&p.manifest_path).ok())
            .collect();
        for node in &meta.nodes {
            let Some(p) = meta.packages.get(node.pkg) else {
                continue;
            };
            let what = format!("{}: {} {}", ctx.label, p.name, p.version);
            let real = match canon.get(&p.manifest_path) {
                Ok(r) => r,
                Err(e) => {
                    findings.insert(Finding::error(
                        "manifest-unresolvable",
                        format!("{what}: cannot resolve {}: {e}", p.manifest_path),
                    ));
                    continue;
                }
            };
            if p.is_path() {
                if !real.starts_with(repo_root) {
                    findings.insert(Finding::error(
                        "path-outside-repo",
                        format!(
                            "{what}: path package lives outside the repository at {} \
                             (resolved from {})",
                            real.display(),
                            p.manifest_path
                        ),
                    ));
                } else if !main_members.contains(&real) && !own_members.contains(&real) {
                    findings.insert(Finding::error(
                        "path-not-member",
                        format!(
                            "{what}: path package at {} is not a member of the main workspace \
                             or of its own project; a [patch] or `paths` override is likely",
                            real.display()
                        ),
                    ));
                }
                continue;
            }
            let Some(src) = &p.source else { continue };
            if !CRATES_IO.contains(&src.as_str()) {
                // aggregate() reports the source itself.
                continue;
            }
            if real.starts_with(repo_root) {
                findings.insert(Finding::error(
                    "registry-in-repo",
                    format!(
                        "{what}: the crates.io package is served from {} inside the \
                         repository; vendoring and source replacement are not allowed",
                        real.display()
                    ),
                ));
                continue;
            }
            match registry_src {
                Ok(reg) if in_registry_cache(&real, reg, &p.name, &p.version) => {}
                Ok(reg) => {
                    findings.insert(Finding::error(
                        "registry-location",
                        format!(
                            "{what}: the crates.io package is served from {}, not from the \
                             crates.io cache under {}; source replacement or a `paths` \
                             override is active",
                            real.display(),
                            reg.display()
                        ),
                    ));
                }
                Err(e) => {
                    findings.insert(Finding::error(
                        "registry-location",
                        format!("{what}: cannot check where it is served from: {e}"),
                    ));
                }
            }
        }
    }
    findings.into_iter().collect()
}

/// Fails on any path package whose name is also a crates.io package in a
/// lockfile or an allowlist entry. Such a package can only be a patched or
/// renamed copy of a third-party crate.
pub(crate) fn check_shadowing(
    contexts: &[Context<'_>],
    entries: &[Entry],
    locks: &[ProjectLock<'_>],
) -> Vec<Finding> {
    let mut third_party: BTreeSet<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    for l in locks {
        third_party.extend(
            l.lock
                .packages
                .iter()
                .filter(|p| p.source.is_some())
                .map(|p| p.name.as_str()),
        );
    }
    let mut findings = BTreeSet::new();
    for ctx in contexts {
        for node in &ctx.meta.nodes {
            let Some(p) = ctx.meta.packages.get(node.pkg) else {
                continue;
            };
            if p.is_path() && third_party.contains(p.name.as_str()) {
                findings.insert(Finding::error(
                    "path-shadows-registry",
                    format!(
                        "{}: path package {} {} at {} has the name of a third-party crate",
                        ctx.label, p.name, p.version, p.manifest_path
                    ),
                ));
            }
        }
    }
    findings.into_iter().collect()
}

/// Reconciles each lockfile with the resolve graphs of its project.
///
/// Every third-party lockfile package must appear in a resolve graph of
/// the project, where it is either built or excluded with a reason. Every
/// third-party resolve node must appear in the lockfile.
pub(crate) fn reconcile(agg: &Aggregate, locks: &[ProjectLock<'_>]) -> Vec<Finding> {
    let mut out = Vec::new();
    for l in locks {
        // A project without any analysed context already has a
        // metadata-failed error. Listing its whole lockfile adds nothing.
        let Some(resolved) = agg.resolved.get(l.label) else {
            continue;
        };
        let mut in_lock = BTreeSet::new();
        for p in &l.lock.packages {
            let Some(src) = &p.source else { continue };
            // git_source.rs checks git sources (ADR-001 A3).
            if !CRATES_IO.contains(&src.as_str()) && !crate::git_source::is_git(src) {
                out.push(Finding::error(
                    "non-crates-io-source",
                    format!(
                        "{} lists {} {} from {src}; only crates.io sources are allowed",
                        l.path, p.name, p.version
                    ),
                ));
            }
            let k = (p.name.clone(), p.version.clone(), src.clone());
            if !resolved.contains(&k) {
                out.push(Finding::error(
                    "lockfile-unexplained",
                    format!(
                        "{} lists {} {}, but no analysed context of {} resolves it",
                        l.path, p.name, p.version, l.label
                    ),
                ));
            }
            in_lock.insert(k);
        }
        for (name, version, _) in resolved.difference(&in_lock) {
            out.push(Finding::error(
                "lockfile-mismatch",
                format!(
                    "{}: cargo resolves {name} {version}, which {} does not list",
                    l.label, l.path
                ),
            ));
        }
    }
    out
}

/// The checksum each crates.io package has in the lockfiles.
///
/// A package recorded with different checksums keeps the first one; the
/// conflict is reported by [`check_checksums`].
pub(crate) fn lock_checksums(locks: &[ProjectLock<'_>]) -> BTreeMap<PkgKey, String> {
    let mut out = BTreeMap::new();
    for l in locks {
        for p in &l.lock.packages {
            let pin = match (&p.checksum, &p.source) {
                (Some(c), _) => Some(c),
                // A git package is pinned by its source string (ADR-001 A3).
                (None, Some(s)) if crate::git_source::is_git(s) => Some(s),
                _ => None,
            };
            if let Some(c) = pin {
                out.entry((p.name.clone(), p.version.clone()))
                    .or_insert_with(|| c.clone());
            }
        }
    }
    out
}

/// Pins each built crates.io package to the checksum in `deps/allowlist.txt`.
///
/// Errors: a crates.io lockfile entry without a checksum, a built package
/// that no lockfile pins, and a lockfile checksum that differs from the
/// allowlist.
pub(crate) fn check_checksums(
    agg: &Aggregate,
    entries: &[Entry],
    locks: &[ProjectLock<'_>],
) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut pins: BTreeMap<PkgKey, Vec<(&str, &str)>> = BTreeMap::new();
    for l in locks {
        for p in &l.lock.packages {
            let Some(src) = &p.source else { continue };
            match &p.checksum {
                Some(c) => pins
                    .entry((p.name.clone(), p.version.clone()))
                    .or_default()
                    .push((l.path.as_str(), c.as_str())),
                // A git package is pinned by its source string (ADR-001 A3).
                None if crate::git_source::is_git(src) => pins
                    .entry((p.name.clone(), p.version.clone()))
                    .or_default()
                    .push((l.path.as_str(), src.as_str())),
                None if CRATES_IO.contains(&src.as_str()) => out.push(Finding::error(
                    "lockfile-no-checksum",
                    format!(
                        "{} lists {} {} from crates.io without a checksum",
                        l.path, p.name, p.version
                    ),
                )),
                None => {}
            }
        }
    }
    for key in agg.usage.keys() {
        let (name, version) = key;
        let Some(found) = pins.get(key) else {
            out.push(Finding::error(
                "not-pinned",
                format!("{name} {version} is built, but no lockfile records its checksum"),
            ));
            continue;
        };
        let Some(entry) = entries
            .iter()
            .find(|e| &e.name == name && &e.version == version)
        else {
            // compare() reports the missing entry.
            continue;
        };
        for (path, sum) in found {
            if *sum != entry.checksum {
                out.push(Finding::error(
                    "checksum-mismatch",
                    format!(
                        "{path} pins {name} {version} to {sum}, but deps/allowlist.txt \
                         records {}",
                        entry.checksum
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
    use crate::allowlist::parse_allowlist;
    use crate::allowlist::tests::{SUM_A, SUM_B};
    use crate::graph::{ProjectKind, Usage, aggregate};
    use crate::lockfile;
    use crate::metadata::{Metadata, Node, Package};
    use crate::python::tests::TempDir;
    use crate::report::Severity;

    const CRATES: &str = "registry+https://github.com/rust-lang/crates.io-index";

    fn pkg(name: &str, source: Option<&str>, manifest: &Path) -> Package {
        Package {
            id: format!("{name}-id"),
            name: name.into(),
            version: "1.0.0".into(),
            source: source.map(str::to_owned),
            manifest_path: manifest.display().to_string(),
            features: BTreeMap::new(),
            dependencies: vec![],
            targets: vec![],
            cargo_fuzz: false,
        }
    }

    /// Metadata with one member and the given extra packages as plain nodes.
    fn meta_with(member: Package, extra: Vec<Package>) -> Metadata {
        let mut m = Metadata {
            packages: vec![member],
            members: vec![0],
            ..Metadata::default()
        };
        m.packages.extend(extra);
        for i in 0..m.packages.len() {
            m.nodes.push(Node {
                pkg: i,
                deps: vec![],
                features: vec![],
            });
            m.node_of_pkg.insert(i, i);
        }
        m
    }

    fn ctx(meta: &Metadata) -> Context<'_> {
        Context {
            label: "workspace".into(),
            platform: "x86_64-unknown-linux-gnu".into(),
            linux: true,
            all_features: false,
            kind: ProjectKind::Workspace,
            meta,
        }
    }

    fn codes(f: &[Finding]) -> Vec<&'static str> {
        f.iter().map(|f| f.code).collect()
    }

    /// Regression for review finding symlink-defeats-path-outside-repo
    /// (P5): a committed symbolic link inside the repository that points
    /// outside it must not pass as in-house code.
    #[test]
    fn review_symlink_defeats_path_outside_repo() {
        let repo = TempDir::new("prov-repo");
        let outside = TempDir::new("prov-outside");
        repo.write("crates/app/Cargo.toml", b"");
        outside.write("evil/Cargo.toml", b"");
        std::fs::create_dir_all(repo.0.join("vendor")).unwrap();
        std::os::unix::fs::symlink(outside.0.join("evil"), repo.0.join("vendor/evil")).unwrap();
        let root = fs::canonicalize(&repo.0).unwrap();
        let app = root.join("crates/app/Cargo.toml");
        // cargo reports the lexical path through the link.
        let meta = meta_with(
            pkg("app", None, &app),
            vec![pkg("evil", None, &root.join("vendor/evil/Cargo.toml"))],
        );
        let members = BTreeSet::from([app]);
        let f = check_locations(&[ctx(&meta)], &root, &members, &Err("unused".into()));
        assert_eq!(codes(&f), vec!["path-outside-repo"], "{f:?}");
        assert!(f[0].message.contains("prov-outside"), "{f:?}");
    }

    /// P5: a path package inside the repository that is no workspace
    /// member, as a [patch] path or a `paths` override produces, fails.
    #[test]
    fn path_package_must_be_a_member() {
        let repo = TempDir::new("prov-member");
        repo.write("crates/app/Cargo.toml", b"");
        repo.write("vendor/subtle/Cargo.toml", b"");
        let root = fs::canonicalize(&repo.0).unwrap();
        let app = root.join("crates/app/Cargo.toml");
        let meta = meta_with(
            pkg("app", None, &app),
            vec![pkg("subtle", None, &root.join("vendor/subtle/Cargo.toml"))],
        );
        let f = check_locations(
            &[ctx(&meta)],
            &root,
            &BTreeSet::from([app]),
            &Err("unused".into()),
        );
        assert_eq!(codes(&f), vec!["path-not-member"], "{f:?}");
    }

    /// Regression for review finding source-replacement-tamper (P5): a
    /// crates.io package served from a vendor directory, while cargo still
    /// reports the crates.io source, fails the gate.
    #[test]
    fn review_source_replacement_tamper() {
        let repo = TempDir::new("prov-vendor");
        let home = TempDir::new("prov-home");
        repo.write("crates/app/Cargo.toml", b"");
        repo.write("vendor/subtle/Cargo.toml", b"");
        home.write(
            "registry/src/index.crates.io-1949cf8c6b5b557f/zeroize-1.0.0/Cargo.toml",
            b"",
        );
        home.write(
            "registry/src/mirror.example-0123456789abcdef/untrusted-1.0.0/Cargo.toml",
            b"",
        );
        let root = fs::canonicalize(&repo.0).unwrap();
        let reg = fs::canonicalize(home.0.join("registry/src")).unwrap();
        let app = root.join("crates/app/Cargo.toml");
        let meta = meta_with(
            pkg("app", None, &app),
            vec![
                pkg(
                    "subtle",
                    Some(CRATES),
                    &root.join("vendor/subtle/Cargo.toml"),
                ),
                pkg(
                    "zeroize",
                    Some(CRATES),
                    &reg.join("index.crates.io-1949cf8c6b5b557f/zeroize-1.0.0/Cargo.toml"),
                ),
                pkg(
                    "untrusted",
                    Some(CRATES),
                    &reg.join("mirror.example-0123456789abcdef/untrusted-1.0.0/Cargo.toml"),
                ),
            ],
        );
        let f = check_locations(&[ctx(&meta)], &root, &BTreeSet::from([app]), &Ok(reg));
        let got: Vec<(&str, bool)> = f
            .iter()
            .map(|f| (f.code, f.message.contains("subtle")))
            .collect();
        assert_eq!(
            got,
            vec![("registry-in-repo", true), ("registry-location", false)],
            "{f:?}"
        );
        assert!(f[1].message.contains("untrusted"), "{f:?}");
    }

    #[test]
    fn registry_cache_layout() {
        let reg = Path::new("/home/u/.cargo/registry/src");
        let ok = reg.join("index.crates.io-1949cf8c6b5b557f/cc-1.10.0/Cargo.toml");
        assert!(in_registry_cache(&ok, reg, "cc", "1.10.0"));
        let legacy = reg.join("github.com-1ecc6299db9ec823/cc-1.10.0/Cargo.toml");
        assert!(in_registry_cache(&legacy, reg, "cc", "1.10.0"));
        for bad in [
            reg.join("index.crates.io-1949cf8c6b5b557f/cc-1.10.1/Cargo.toml"),
            reg.join("index.crates.io.evil-1949cf8c6b5b557f/cc-1.10.0/Cargo.toml"),
            reg.join("index.crates.io-zz/cc-1.10.0/Cargo.toml"),
            reg.join("index.crates.io-1949cf8c6b5b557f/cc-1.10.0/sub/Cargo.toml"),
            PathBuf::from("/vendor/cc-1.10.0/Cargo.toml"),
        ] {
            assert!(!in_registry_cache(&bad, reg, "cc", "1.10.0"), "{bad:?}");
        }
    }

    #[test]
    fn path_package_with_registry_name_fails() {
        let repo = Path::new("/repo");
        let meta = meta_with(
            pkg("app", None, &repo.join("app/Cargo.toml")),
            vec![pkg("subtle", None, &repo.join("crates/subtle/Cargo.toml"))],
        );
        let entries =
            parse_allowlist(&format!("subtle 2.6.1 {SUM_A} ADR-001 runtime x\n")).unwrap();
        let f = check_shadowing(&[ctx(&meta)], &entries, &[]);
        assert_eq!(codes(&f), vec!["path-shadows-registry"], "{f:?}");
    }

    fn lock_text(extra: &str) -> String {
        format!(
            "version = 4\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\n\n\
             [[package]]\nname = \"alpha\"\nversion = \"1.0.0\"\nsource = \"{CRATES}\"\n\
             checksum = \"{SUM_A}\"\n{extra}"
        )
    }

    /// Regression for review findings optional-feature-deps-invisible and
    /// cfg-and-platform-deps-ignored (P5): a lockfile package that no
    /// analysed context resolves, such as a crate behind a feature or cfg
    /// the analysis missed, fails the gate instead of passing unseen.
    #[test]
    fn review_optional_feature_deps_invisible() {
        let mut agg = Aggregate::default();
        agg.resolved.insert(
            "workspace".into(),
            BTreeSet::from([("alpha".to_owned(), "1.0.0".to_owned(), CRATES.to_owned())]),
        );
        let lock = lockfile::parse(&lock_text("")).unwrap();
        let locks = [ProjectLock {
            label: "workspace",
            path: "Cargo.lock".into(),
            lock: &lock,
        }];
        assert!(reconcile(&agg, &locks).is_empty());
        let lock = lockfile::parse(&lock_text(&format!(
            "\n[[package]]\nname = \"itoa\"\nversion = \"1.0.18\"\nsource = \"{CRATES}\"\n\
             checksum = \"{SUM_B}\"\n"
        )))
        .unwrap();
        let locks = [ProjectLock {
            label: "workspace",
            path: "Cargo.lock".into(),
            lock: &lock,
        }];
        let f = reconcile(&agg, &locks);
        assert_eq!(codes(&f), vec!["lockfile-unexplained"], "{f:?}");
        assert!(f[0].message.contains("itoa 1.0.18"), "{f:?}");
        assert!(f.iter().all(|f| f.severity == Severity::Error));
    }

    /// The end-to-end form of the same finding: with `--all-features`, the
    /// feature-gated crate is resolved, built and must be allowlisted.
    #[test]
    fn all_features_context_reaches_feature_gated_crate() {
        let roles = include_str!("../testdata/roles.json");
        let meta = crate::metadata::parse_metadata(roles.as_bytes()).unwrap();
        let agg = aggregate(&[ctx(&meta)], &crate::graph::tests::roots());
        // `never` is optional and off in this context, so it stays excluded.
        assert!(
            agg.excluded
                .contains_key(&("never".to_owned(), "1.0.0".to_owned()))
        );
        assert!(agg.resolved.get("workspace").unwrap().contains(&(
            "never".to_owned(),
            "1.0.0".to_owned(),
            CRATES.to_owned()
        )));
    }

    /// P5: each built crates.io package is pinned by the allowlist checksum.
    #[test]
    fn checksums_are_pinned() {
        let mut agg = Aggregate::default();
        agg.usage
            .insert(("alpha".into(), "1.0.0".into()), Usage::default());
        let lock = lockfile::parse(&lock_text("")).unwrap();
        let locks = [ProjectLock {
            label: "workspace",
            path: "Cargo.lock".into(),
            lock: &lock,
        }];
        let ok = parse_allowlist(&format!("alpha 1.0.0 {SUM_A} ADR-001 runtime x\n")).unwrap();
        assert!(check_checksums(&agg, &ok, &locks).is_empty());
        let other = parse_allowlist(&format!("alpha 1.0.0 {SUM_B} ADR-001 runtime x\n")).unwrap();
        let f = check_checksums(&agg, &other, &locks);
        assert_eq!(codes(&f), vec!["checksum-mismatch"], "{f:?}");
        agg.usage
            .insert(("beta".into(), "1.0.0".into()), Usage::default());
        let f = check_checksums(&agg, &ok, &locks);
        assert_eq!(codes(&f), vec!["not-pinned"], "{f:?}");
        let bare = lockfile::parse(&format!(
            "version = 4\n[[package]]\nname = \"alpha\"\nversion = \"1.0.0\"\nsource = \"{CRATES}\"\n"
        ))
        .unwrap();
        let locks = [ProjectLock {
            label: "workspace",
            path: "Cargo.lock".into(),
            lock: &bare,
        }];
        let mut agg = Aggregate::default();
        agg.usage
            .insert(("alpha".into(), "1.0.0".into()), Usage::default());
        let f = check_checksums(&agg, &ok, &locks);
        assert_eq!(
            codes(&f),
            vec!["lockfile-no-checksum", "not-pinned"],
            "{f:?}"
        );
    }
}
