//! The npm lockfile gate (ADR-003 amendment of 2026-10-28, "Rules" and
//! "Lockfile gate"; `docs/handoff/m3-design.md` section 2.2).
//!
//! - npm projects exist only in `web/` and `e2e/`. A `package.json` or
//!   `package-lock.json` anywhere else fails, and so does any other
//!   package manager's lockfile. Only the installed trees `web/node_modules`
//!   and `e2e/node_modules` are skipped. Any other file under a
//!   `node_modules` directory fails.
//! - Each project has a committed `package.json` and `package-lock.json`.
//! - `package.json` lists only `typescript` and `@playwright/test`, each at
//!   an exact version.
//! - The lockfile has format version 3, the one current npm writes, and no
//!   unknown structure.
//! - Every package has an exact version, a `resolved` URL that is its own
//!   tarball on the public npm registry, and a `sha512` integrity value.
//!   Git, file, link and other tarball sources fail.
//! - Name, version and integrity match an entry of `deps/npm-allowlist.txt`.
//! - A package marked `hasInstallScript` fails unless its allowlist entry
//!   accepts it: the note must contain `install script accepted`. The
//!   script still never runs, since installs use `npm ci --ignore-scripts`.
//!
//! `deps/npm-allowlist.txt` has one entry per line:
//!
//! ```text
//! <name> <version> <integrity> ADR-003 <note>
//! ```
//!
//! The parsers here have the fuzz target `npm_lock_decode`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use fstp_json::{Object, ParseLimits, Value};

use crate::allowlist::{LineError, valid_version};
use crate::repo::{Kind, Walk};
use crate::report::Finding;

/// The npm allowlist.
pub(crate) const NPM_ALLOWLIST: &str = "deps/npm-allowlist.txt";
/// The directories that may hold an npm project.
const PROJECT_DIRS: [&str; 2] = ["web", "e2e"];
/// The only direct packages.
const DIRECT: [&str; 2] = ["typescript", "@playwright/test"];
/// The public npm registry.
const REGISTRY: &str = "https://registry.npmjs.org/";
/// The lockfile format version the gate accepts.
const LOCKFILE_VERSION: u64 = 3;
/// The note that accepts an install script.
const INSTALL_SCRIPT_ACCEPTED: &str = "install script accepted";
/// Lockfiles of other package managers, refused everywhere, including in
/// `web/` and `e2e/`: npm's shrinkwrap, yarn, pnpm, bun (text and binary)
/// and deno.
const FOREIGN_LOCKS: [&str; 6] = [
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lock",
    "bun.lockb",
    "deno.lock",
];
/// The dependency sections of a manifest.
const DEP_SECTIONS: [&str; 5] = [
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
    "bundleDependencies",
];
/// The top-level members of a lockfile.
const LOCK_MEMBERS: [&str; 5] = ["name", "version", "lockfileVersion", "requires", "packages"];
/// The members of a package entry that npm writes for registry packages.
const PACKAGE_MEMBERS: [&str; 21] = [
    "version",
    "resolved",
    "integrity",
    "dev",
    "optional",
    "devOptional",
    "peer",
    "link",
    "license",
    "engines",
    "bin",
    "dependencies",
    "peerDependencies",
    "peerDependenciesMeta",
    "optionalDependencies",
    "funding",
    "cpu",
    "os",
    "libc",
    "hasInstallScript",
    "deprecated",
];
/// The members of the root entry `""`.
const ROOT_MEMBERS: [&str; 9] = [
    "name",
    "version",
    "license",
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
    "engines",
    "workspaces",
];
/// Upper bound on a lockfile or manifest.
const MAX_FILE: u64 = 32 << 20;
/// Upper bound on the length of one allowlist line.
const MAX_LINE: usize = 1024;

/// One npm allowlist entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NpmEntry {
    /// Package name, possibly scoped.
    pub(crate) name: String,
    /// Exact version.
    pub(crate) version: String,
    /// The integrity value.
    pub(crate) integrity: String,
    /// Free-text note.
    pub(crate) note: String,
}

/// One package of a lockfile.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct LockPackage {
    /// The `packages` key, such as `node_modules/typescript`.
    pub(crate) key: String,
    /// The package name the key names.
    pub(crate) name: String,
    /// The `version` member.
    pub(crate) version: Option<String>,
    /// The `resolved` member.
    pub(crate) resolved: Option<String>,
    /// The `integrity` member.
    pub(crate) integrity: Option<String>,
    /// Whether `link` is true.
    pub(crate) link: bool,
    /// Whether `hasInstallScript` is true.
    pub(crate) install_script: bool,
}

/// A parsed lockfile.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct NpmLock {
    /// The direct dependency names of the root entry.
    pub(crate) root_deps: Vec<String>,
    /// Every other package.
    pub(crate) packages: Vec<LockPackage>,
}

/// Whether `s` is an npm package name, possibly scoped.
pub(crate) fn valid_name(s: &str) -> bool {
    let part = |p: &str| {
        !p.is_empty()
            && p.len() <= 214
            && !p.starts_with('.')
            && p.bytes().all(|b| {
                b.is_ascii_lowercase()
                    || b.is_ascii_digit()
                    || matches!(b, b'-' | b'.' | b'_' | b'~')
            })
    };
    match s.strip_prefix('@') {
        Some(scoped) => scoped
            .split_once('/')
            .is_some_and(|(scope, name)| part(scope) && part(name)),
        None => part(s),
    }
}

/// Whether `s` is a `sha512` integrity value.
pub(crate) fn valid_integrity(s: &str) -> bool {
    s.strip_prefix("sha512-").is_some_and(|rest| {
        !rest.is_empty() && rest.len() <= 256 && rest.bytes().all(|b| b.is_ascii_graphic())
    })
}

/// The tarball URL the public registry serves for `name` at `version`.
fn tarball_url(name: &str, version: &str) -> String {
    let base = name.rsplit('/').next().unwrap_or(name);
    format!("{REGISTRY}{name}/-/{base}-{version}.tgz")
}

/// Parses `deps/npm-allowlist.txt`.
pub(crate) fn parse_allowlist(text: &str) -> Result<Vec<NpmEntry>, Vec<LineError>> {
    let mut out: Vec<NpmEntry> = Vec::new();
    let mut errors = Vec::new();
    let mut seen = BTreeSet::new();
    for (i, raw) in text.lines().enumerate() {
        let line = i.saturating_add(1);
        let t = raw.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let err = |message: String| LineError { line, message };
        if raw.len() > MAX_LINE {
            errors.push(err(format!("longer than {MAX_LINE} bytes")));
            continue;
        }
        let mut fields = t.split_whitespace();
        let (Some(name), Some(version), Some(integrity), Some(adr)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            errors.push(err(
                "expected `<name> <version> <integrity> ADR-003 <note>`".to_owned(),
            ));
            continue;
        };
        let note: Vec<&str> = fields.collect();
        if !valid_name(name) {
            errors.push(err(format!("invalid npm package name `{name}`")));
        } else if !valid_version(version) {
            errors.push(err(format!("`{version}` is not an exact version")));
        } else if !valid_integrity(integrity) {
            errors.push(err(format!(
                "`{integrity}` is not a sha512 integrity value"
            )));
        } else if adr != "ADR-003" {
            errors.push(err(format!("`{adr}` is not ADR-003")));
        } else if note.is_empty() {
            errors.push(err("missing note".to_owned()));
        } else if !seen.insert((name.to_owned(), version.to_owned())) {
            errors.push(err(format!("duplicate entry for {name} {version}")));
        } else {
            out.push(NpmEntry {
                name: name.to_owned(),
                version: version.to_owned(),
                integrity: integrity.to_owned(),
                note: note.join(" "),
            });
        }
    }
    if errors.is_empty() {
        Ok(out)
    } else {
        Err(errors)
    }
}

fn limits() -> ParseLimits {
    ParseLimits::default()
        .with_max_input_bytes(32 << 20)
        .with_max_depth(32)
        .with_max_string_bytes(1 << 20)
        .with_max_container_len(200_000)
        .with_max_nodes(5_000_000)
}

fn object<'a>(v: &'a Value, what: &str) -> Result<&'a Object, String> {
    v.as_object()
        .ok_or_else(|| format!("{what} is not an object"))
}

fn only_members(o: &Object, allowed: &[&str], what: &str) -> Result<(), String> {
    match o.keys().find(|k| !allowed.contains(k)) {
        Some(k) => Err(format!("{what} has the unknown member `{k}`")),
        None => Ok(()),
    }
}

fn opt_string(o: &Object, key: &str, what: &str) -> Result<Option<String>, String> {
    match o.get(key) {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(format!("{what}: `{key}` is not a string")),
    }
}

fn flag(o: &Object, key: &str, what: &str) -> Result<bool, String> {
    match o.get(key) {
        None => Ok(false),
        Some(v) => v
            .as_bool()
            .ok_or_else(|| format!("{what}: `{key}` is not a boolean")),
    }
}

/// The dependency names of a manifest object, over every section.
fn dependency_names(o: &Object, what: &str) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    for section in DEP_SECTIONS {
        let Some(v) = o.get(section) else { continue };
        let deps = object(v, &format!("{what}: `{section}`"))?;
        for (name, spec) in deps.iter() {
            let spec = spec
                .as_str()
                .ok_or_else(|| format!("{what}: `{section}.{name}` is not a string"))?;
            out.push((name.to_owned(), spec.to_owned()));
        }
    }
    Ok(out)
}

/// Parses a `package-lock.json` of format version 3.
pub(crate) fn parse_lock(bytes: &[u8]) -> Result<NpmLock, String> {
    let v = fstp_json::parse_with(bytes, &limits()).map_err(|e| format!("not JSON: {e}"))?;
    let top = object(&v, "the lockfile")?;
    only_members(top, &LOCK_MEMBERS, "the lockfile")?;
    match top.get("lockfileVersion").and_then(Value::as_u64) {
        Some(LOCKFILE_VERSION) => {}
        _ => {
            return Err(format!(
                "`lockfileVersion` is not {LOCKFILE_VERSION}, the format the pinned npm writes"
            ));
        }
    }
    let packages = object(
        top.get("packages")
            .ok_or_else(|| "the lockfile has no `packages`".to_owned())?,
        "`packages`",
    )?;
    let mut out = NpmLock::default();
    for (key, entry) in packages.iter() {
        let what = format!("package `{key}`");
        let o = object(entry, &what)?;
        if key.is_empty() {
            only_members(o, &ROOT_MEMBERS, "the root package")?;
            if o.contains_key("workspaces") {
                return Err("the root package declares workspaces".to_owned());
            }
            out.root_deps = dependency_names(o, "the root package")?
                .into_iter()
                .map(|(n, _)| n)
                .collect();
            continue;
        }
        only_members(o, &PACKAGE_MEMBERS, &what)?;
        let name = key
            .rsplit_once("node_modules/")
            .map(|(_, n)| n)
            .filter(|_| key.starts_with("node_modules/"))
            .ok_or_else(|| format!("{what} is not under node_modules/"))?;
        if !valid_name(name) {
            return Err(format!("{what} names the invalid package `{name}`"));
        }
        out.packages.push(LockPackage {
            key: key.to_owned(),
            name: name.to_owned(),
            version: opt_string(o, "version", &what)?,
            resolved: opt_string(o, "resolved", &what)?,
            integrity: opt_string(o, "integrity", &what)?,
            link: flag(o, "link", &what)?,
            install_script: flag(o, "hasInstallScript", &what)?,
        });
    }
    Ok(out)
}

/// Parses a `package.json` and returns its direct dependencies.
pub(crate) fn parse_manifest(bytes: &[u8]) -> Result<Vec<(String, String)>, String> {
    let v = fstp_json::parse_with(bytes, &limits()).map_err(|e| format!("not JSON: {e}"))?;
    dependency_names(object(&v, "package.json")?, "package.json")
}

/// Reads a file of at most [`MAX_FILE`] bytes.
fn read(path: &Path) -> Result<Vec<u8>, String> {
    let len = fs::metadata(path).map_err(|e| e.to_string())?.len();
    if len > MAX_FILE {
        return Err(format!("larger than {MAX_FILE} bytes"));
    }
    fs::read(path).map_err(|e| e.to_string())
}

/// Checks one lockfile against the allowlist.
fn check_lock(rel: &str, lock: &NpmLock, allow: &[NpmEntry], out: &mut Vec<Finding>) {
    for n in lock
        .root_deps
        .iter()
        .filter(|n| !DIRECT.contains(&n.as_str()))
    {
        out.push(Finding::error(
            "npm-direct",
            format!("{rel} lists the direct package {n}; only typescript and @playwright/test are allowed (ADR-003)"),
        ));
    }
    for p in &lock.packages {
        let name = &p.name;
        let at = format!("{rel}: {name} (`{}`)", p.key);
        if p.link {
            out.push(Finding::error(
                "npm-source",
                format!("{at} is a link; only registry packages are allowed (ADR-003)"),
            ));
            continue;
        }
        let Some(version) = p.version.as_deref().filter(|v| valid_version(v)) else {
            out.push(Finding::error(
                "npm-version",
                format!("{at} has no exact version (ADR-003)"),
            ));
            continue;
        };
        let expected = tarball_url(name, version);
        match p.resolved.as_deref() {
            Some(r) if r == expected => {}
            Some(r) => {
                out.push(Finding::error(
                    "npm-source",
                    format!("{at} resolves to {r}, not to its tarball {expected} on the public npm registry (ADR-003)"),
                ));
                continue;
            }
            None => {
                out.push(Finding::error(
                    "npm-source",
                    format!("{at} has no `resolved` URL on the public npm registry (ADR-003)"),
                ));
                continue;
            }
        }
        let Some(integrity) = p.integrity.as_deref().filter(|i| valid_integrity(i)) else {
            out.push(Finding::error(
                "npm-integrity",
                format!("{at} has no sha512 integrity value (ADR-003)"),
            ));
            continue;
        };
        let same_name: Vec<&NpmEntry> = allow.iter().filter(|e| &e.name == name).collect();
        let Some(entry) = same_name.iter().find(|e| e.version == version) else {
            out.push(Finding::error(
                "npm-unlisted",
                format!("{at} {version} is not in {NPM_ALLOWLIST} (ADR-003)"),
            ));
            continue;
        };
        if entry.integrity != integrity {
            out.push(Finding::error(
                "npm-mismatch",
                format!("{at} {version} has integrity {integrity}, but {NPM_ALLOWLIST} records {} (ADR-003)", entry.integrity),
            ));
        }
        if p.install_script && !entry.note.contains(INSTALL_SCRIPT_ACCEPTED) {
            out.push(Finding::error(
                "npm-install-script",
                format!("{at} {version} has an install script, and its {NPM_ALLOWLIST} entry does not say `{INSTALL_SCRIPT_ACCEPTED}` (ADR-003)"),
            ));
        }
    }
}

/// Runs the gate over the repository walk.
pub(crate) fn check(root: &Path, walk: &Walk) -> Vec<Finding> {
    let mut out = Vec::new();
    // Project directory -> which of the two files it has.
    let mut projects: BTreeMap<String, (bool, bool)> = BTreeMap::new();
    // The node_modules trees outside web/ and e2e/ already reported.
    let mut foreign_trees: BTreeSet<std::path::PathBuf> = BTreeSet::new();
    for f in walk.files.iter().filter(|f| f.kind == Kind::File) {
        let components: Vec<&std::ffi::OsStr> = f.rel.iter().collect();
        // Only the installed trees `web/node_modules` and `e2e/node_modules`
        // are skipped. Any other file under a `node_modules` directory is a
        // committed npm tree outside the two projects.
        if let [project, nm, ..] = components.as_slice()
            && *nm == "node_modules"
            && PROJECT_DIRS.iter().any(|d| project == d)
        {
            continue;
        }
        if let Some(at) = components.iter().position(|c| *c == "node_modules") {
            // One finding per tree, which names the first file found in it.
            let tree: std::path::PathBuf = components.iter().take(at.saturating_add(1)).collect();
            if foreign_trees.insert(tree.clone()) {
                out.push(Finding::error(
                    "npm-place",
                    format!(
                        "{} holds {}: a node_modules tree exists only as the installed tree of web/ or e2e/, and npm projects exist only in web/ and e2e/ (ADR-003)",
                        tree.display(),
                        f.rel.display()
                    ),
                ));
            }
            continue;
        }
        let Some(name) = f.rel.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let rel = f.rel.display().to_string();
        if FOREIGN_LOCKS.contains(&name) {
            out.push(Finding::error(
                "npm-place",
                format!("{rel} belongs to another package manager; npm projects use package-lock.json only (ADR-003)"),
            ));
            continue;
        }
        let is_manifest = name == "package.json";
        if !is_manifest && name != "package-lock.json" {
            continue;
        }
        let dir = f
            .rel
            .parent()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        if !PROJECT_DIRS.contains(&dir.as_str()) {
            out.push(Finding::error(
                "npm-place",
                format!("{rel}: npm projects exist only in web/ and e2e/ (ADR-003)"),
            ));
            continue;
        }
        let slot = projects.entry(dir).or_default();
        if is_manifest {
            slot.0 = true;
        } else {
            slot.1 = true;
        }
    }
    if projects.is_empty() {
        return out;
    }
    let allow = match fs::read_to_string(root.join(NPM_ALLOWLIST)) {
        Ok(text) => match parse_allowlist(&text) {
            Ok(a) => a,
            Err(errs) => {
                for e in errs {
                    out.push(Finding::error(
                        "npm-allowlist",
                        format!("{NPM_ALLOWLIST} {e}"),
                    ));
                }
                Vec::new()
            }
        },
        Err(e) => {
            out.push(Finding::error(
                "npm-allowlist",
                format!("cannot read {NPM_ALLOWLIST}, which the npm projects need: {e}"),
            ));
            Vec::new()
        }
    };
    for (dir, (manifest, lock)) in &projects {
        if !manifest {
            out.push(Finding::error(
                "npm-no-manifest",
                format!("{dir}/package-lock.json has no {dir}/package.json (ADR-003)"),
            ));
        }
        if !lock {
            out.push(Finding::error(
                "npm-no-lockfile",
                format!("{dir}/package.json has no committed {dir}/package-lock.json (ADR-003)"),
            ));
        }
        if *manifest {
            let rel = format!("{dir}/package.json");
            match read(&root.join(&rel)).and_then(|b| parse_manifest(&b)) {
                Ok(direct) => {
                    for (name, spec) in direct {
                        if !DIRECT.contains(&name.as_str()) {
                            out.push(Finding::error(
                                "npm-direct",
                                format!("{rel} lists {name}; only typescript and @playwright/test are allowed (ADR-003)"),
                            ));
                        } else if !valid_version(&spec) {
                            out.push(Finding::error(
                                "npm-direct",
                                format!(
                                    "{rel} asks for {name} `{spec}`, not an exact version (ADR-003)"
                                ),
                            ));
                        }
                    }
                }
                Err(e) => out.push(Finding::error("npm-manifest", format!("{rel}: {e}"))),
            }
        }
        if *lock {
            let rel = format!("{dir}/package-lock.json");
            match read(&root.join(&rel)).and_then(|b| parse_lock(&b)) {
                Ok(l) => check_lock(&rel, &l, &allow, &mut out),
                Err(e) => out.push(Finding::error(
                    "npm-lockfile",
                    format!("{rel}: {e}; unknown structure fails (ADR-003)"),
                )),
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adr003_names_integrity_and_tarballs() {
        assert!(valid_name("typescript"));
        assert!(valid_name("@playwright/test"));
        assert!(!valid_name("@playwright"));
        assert!(!valid_name("Left-Pad"));
        assert!(!valid_name(".hidden"));
        assert!(valid_integrity("sha512-abc+/="));
        assert!(!valid_integrity("sha1-abc"));
        assert!(!valid_integrity("sha512-"));
        assert_eq!(
            tarball_url("@playwright/test", "1.56.1"),
            "https://registry.npmjs.org/@playwright/test/-/test-1.56.1.tgz"
        );
    }

    #[test]
    fn adr003_lockfile_shape_is_strict() {
        let ok = br#"{"name":"w","lockfileVersion":3,"requires":true,"packages":{"":{"name":"w","devDependencies":{"typescript":"5.9.3"}},"node_modules/typescript":{"version":"5.9.3","resolved":"https://registry.npmjs.org/typescript/-/typescript-5.9.3.tgz","integrity":"sha512-x","dev":true}}}"#;
        let lock = parse_lock(ok);
        assert_eq!(lock.as_ref().map(|l| l.packages.len()), Ok(1), "{lock:?}");
        for bad in [
            &br#"{"lockfileVersion":2,"packages":{}}"#[..],
            br#"{"lockfileVersion":3,"packages":[1]}"#,
            br#"{"lockfileVersion":3,"packages":{},"dependencies":{}}"#,
            br#"{"lockfileVersion":3,"packages":{"node_modules/a":{"inBundle":true}}}"#,
            br#"{"lockfileVersion":3,"packages":{"vendor/a":{}}}"#,
            br#"{"lockfileVersion":3}"#,
        ] {
            assert!(parse_lock(bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn adr003_allowlist_parses_strictly() {
        let ok = "# c\ntypescript 5.9.3 sha512-x ADR-003 the compiler\n";
        assert_eq!(parse_allowlist(ok).map(|v| v.len()), Ok(1));
        for bad in [
            "typescript 5.9.3 sha512-x ADR-001 note\n",
            "typescript 5.9 sha512-x ADR-003 note\n",
            "typescript 5.9.3 sha1-x ADR-003 note\n",
            "typescript 5.9.3 sha512-x ADR-003\n",
            "typescript 5.9.3 sha512-x ADR-003 a\ntypescript 5.9.3 sha512-y ADR-003 b\n",
        ] {
            assert!(parse_allowlist(bad).is_err(), "{bad}");
        }
    }
}
