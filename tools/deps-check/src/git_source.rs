//! The git-source rule (TH-15, ADR-001 A2 and A3).
//!
//! deps-check refuses every source other than crates.io, with one
//! exception. A git package passes only when all of these hold:
//!
//! - its lockfile source string is pinned: `git+<URL>?rev=<commit>#<commit>`
//!   with the same full commit id twice. A branch, a tag and a shortened
//!   rev fail, even when the allowlist records that string;
//! - it carries no checksum, since cargo writes none for git packages;
//! - it is moduletto, or comes from the repository URL that moduletto's
//!   allowlist entry records. Any other git crate needs its own ADR first;
//! - an allowlist entry names the same crate and version, and its checksum
//!   field holds the same source string, byte for byte;
//! - cargo serves it from its git checkout directory,
//!   `$CARGO_HOME/git/checkouts/<name>-<hash>/<short commit>/`, at the
//!   pinned commit. A `paths` override or source replacement then cannot
//!   shadow it.
//!
//! Every other git source fails: another URL, another commit, a branch or
//! tag reference, a shortened rev, and the same commit at another URL.

use std::fs;
use std::path::{Path, PathBuf};

use crate::allowlist::Entry;
use crate::graph::Context;
use crate::provenance::ProjectLock;
use crate::report::Finding;

/// The crates that may come from git (ADR-001 A3).
const GIT_ROOTS: [&str; 1] = ["moduletto"];
/// The prefix of every git source string.
const PREFIX: &str = "git+";
/// The length of cargo's short commit id in checkout paths.
const SHORT_ID: usize = 7;
/// Upper bound on the length of a source string.
const MAX_SOURCE: usize = 512;

/// A pinned git source string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GitSource<'a> {
    /// The repository URL.
    pub(crate) url: &'a str,
    /// The full commit id.
    pub(crate) commit: &'a str,
}

/// Whether `src` is a git source.
pub(crate) fn is_git(src: &str) -> bool {
    src.starts_with(PREFIX)
}

/// The repository URL of any git source string: the text after `git+` and
/// before the first `?` or `#`. Unlike [`parse_pinned`] it accepts every
/// reference form, so a branch or tag source still names its repository.
pub(crate) fn repo_url(src: &str) -> Option<&str> {
    let rest = src.strip_prefix(PREFIX)?;
    let end = rest.find(['?', '#']).unwrap_or(rest.len());
    rest.get(..end).filter(|u| !u.is_empty())
}

/// Whether `s` is a full git commit id: 40 lowercase hex digits for SHA-1
/// object ids, or 64 for SHA-256.
pub(crate) fn valid_commit(s: &str) -> bool {
    (s.len() == 40 || s.len() == 64)
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Parses a pinned source string `git+<URL>?rev=<commit>#<commit>`, or
/// returns `None` for every other form.
pub(crate) fn parse_pinned(src: &str) -> Option<GitSource<'_>> {
    if src.len() > MAX_SOURCE || src.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return None;
    }
    let rest = src.strip_prefix(PREFIX)?;
    let (url, query) = rest.split_once('?')?;
    let (rev, fragment) = query.split_once('#')?;
    let rev = rev.strip_prefix("rev=")?;
    let url_ok = !url.is_empty() && !url.contains('#') && url.contains("://");
    (url_ok && rev == fragment && valid_commit(rev)).then_some(GitSource { url, commit: rev })
}

/// cargo's git checkout directory, canonicalized.
fn checkouts_dir() -> Result<PathBuf, String> {
    let home = match std::env::var_os("CARGO_HOME") {
        Some(h) if !h.is_empty() => PathBuf::from(h),
        _ => match std::env::var_os("HOME") {
            Some(h) if !h.is_empty() => PathBuf::from(h).join(".cargo"),
            _ => return Err("neither CARGO_HOME nor HOME is set".to_owned()),
        },
    };
    let dir = home.join("git").join("checkouts");
    fs::canonicalize(&dir).map_err(|e| format!("cannot resolve {}: {e}", dir.display()))
}

/// Whether `manifest` is `<checkouts>/<repo dir>/<short commit>/.../Cargo.toml`
/// for `commit`.
fn in_checkout(manifest: &Path, checkouts: &Path, commit: &str) -> bool {
    let Ok(rest) = manifest.strip_prefix(checkouts) else {
        return false;
    };
    let parts: Vec<&std::ffi::OsStr> = rest.iter().collect();
    match parts.as_slice() {
        [_repo, short, .., file] if parts.len() >= 3 => {
            short
                .to_str()
                .is_some_and(|s| s.len() >= SHORT_ID && commit.starts_with(s))
                && *file == std::ffi::OsStr::new("Cargo.toml")
        }
        _ => false,
    }
}

/// Runs the rule over every lockfile and every analysed context.
pub(crate) fn check(
    locks: &[ProjectLock<'_>],
    entries: &[Entry],
    contexts: &[Context<'_>],
) -> Vec<Finding> {
    let mut out = Vec::new();
    // The repositories moduletto's allowlist entries record.
    let root_urls: Vec<&str> = entries
        .iter()
        .filter(|e| GIT_ROOTS.contains(&e.name.as_str()))
        .filter_map(|e| parse_pinned(&e.checksum).map(|g| g.url))
        .collect();
    for l in locks {
        for p in &l.lock.packages {
            let Some(src) = &p.source else { continue };
            if !is_git(src) {
                continue;
            }
            let what = format!("{} lists {} {} from {src}", l.path, p.name, p.version);
            if p.checksum.is_some() {
                out.push(Finding::error(
                    "git-source-checksum",
                    format!(
                        "{what} with a checksum; cargo writes none for a git package (ADR-001 A3)"
                    ),
                ));
            }
            let Some(pinned) = parse_pinned(src) else {
                out.push(Finding::error(
                    "git-source-not-pinned",
                    format!(
                        "{what}; a git source must pin one full commit as git+<URL>?rev=<commit>#<commit>, \
                         never a branch, a tag or a shortened rev (ADR-001 A3)"
                    ),
                ));
                continue;
            };
            if !GIT_ROOTS.contains(&p.name.as_str()) && !root_urls.contains(&pinned.url) {
                out.push(Finding::error(
                    "git-source-crate",
                    format!(
                        "{what}; only moduletto and packages from its recorded repository may use a git source (ADR-001 A3)"
                    ),
                ));
            }
            let listed = entries.iter().any(|e| {
                e.name == p.name && e.version == p.version && e.checksum.as_str() == src.as_str()
            });
            if !listed {
                out.push(Finding::error(
                    "git-source-unlisted",
                    format!(
                        "{what}; no deps/allowlist.txt entry records this crate, version and source string byte for byte (ADR-001 A3)"
                    ),
                ));
            }
        }
    }

    let checkouts = checkouts_dir();
    let mut seen = std::collections::BTreeSet::new();
    for ctx in contexts {
        for node in &ctx.meta.nodes {
            let Some(p) = ctx.meta.packages.get(node.pkg) else {
                continue;
            };
            let Some(src) = &p.source else { continue };
            if !is_git(src) || !seen.insert((p.manifest_path.clone(), src.clone())) {
                continue;
            }
            let Some(pinned) = parse_pinned(src) else {
                // The lockfile check above reports the source.
                continue;
            };
            let real = fs::canonicalize(&p.manifest_path);
            let ok = match (&checkouts, &real) {
                (Ok(dir), Ok(m)) => in_checkout(m, dir, pinned.commit),
                _ => false,
            };
            if !ok {
                let at = match &real {
                    Ok(m) => m.display().to_string(),
                    Err(e) => format!("{} ({e})", p.manifest_path),
                };
                let dir = match &checkouts {
                    Ok(d) => d.display().to_string(),
                    Err(e) => e.clone(),
                };
                out.push(Finding::error(
                    "git-source-location",
                    format!(
                        "{}: {} {} from {src} is served from {at}, not from cargo's checkout of commit {} under {dir}; \
                         a `paths` override or source replacement is active (ADR-001 A3)",
                        ctx.label, p.name, p.version, pinned.commit
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

    const C: &str = "0123456789abcdef0123456789abcdef01234567";

    /// TH-15, ADR-001 A3: only the pinned form parses.
    #[test]
    fn th15_only_the_pinned_form_parses() {
        let ok = format!("git+https://example.org/m.git?rev={C}#{C}");
        assert_eq!(
            parse_pinned(&ok),
            Some(GitSource {
                url: "https://example.org/m.git",
                commit: C
            })
        );
        for bad in [
            format!("git+https://example.org/m.git?branch=main#{C}"),
            format!("git+https://example.org/m.git?tag=v1#{C}"),
            format!("git+https://example.org/m.git?rev=0123456789ab#{C}"),
            format!("git+https://example.org/m.git#{C}"),
            format!(
                "git+https://example.org/m.git?rev={C}#{}",
                C.replace('0', "1")
            ),
            format!(
                "git+https://example.org/m.git?rev={}#{}",
                C.to_uppercase(),
                C.to_uppercase()
            ),
            format!("registry+https://example.org?rev={C}#{C}"),
            format!("git+?rev={C}#{C}"),
            format!("git+https://example.org/m git?rev={C}#{C}"),
        ] {
            assert_eq!(parse_pinned(&bad), None, "{bad}");
        }
    }

    /// I-74, ADR-001 A3: every git reference form names its repository.
    #[test]
    fn i74_repo_url_reads_every_reference_form() {
        for src in [
            format!("git+https://example.org/m.git?rev={C}#{C}"),
            "git+https://example.org/m.git?branch=main#abc".to_owned(),
            "git+https://example.org/m.git#abc".to_owned(),
            "git+https://example.org/m.git".to_owned(),
        ] {
            assert_eq!(repo_url(&src), Some("https://example.org/m.git"), "{src}");
        }
        assert_eq!(repo_url("registry+https://example.org"), None);
        assert_eq!(repo_url("git+?rev=x"), None);
    }

    #[test]
    fn checkout_paths_name_the_short_commit() {
        let dir = Path::new("/home/u/.cargo/git/checkouts");
        assert!(in_checkout(
            &dir.join("moduletto-1a2b/0123456/Cargo.toml"),
            dir,
            C
        ));
        assert!(in_checkout(
            &dir.join("moduletto-1a2b/0123456/sub/Cargo.toml"),
            dir,
            C
        ));
        assert!(!in_checkout(
            &dir.join("moduletto-1a2b/fffffff/Cargo.toml"),
            dir,
            C
        ));
        assert!(!in_checkout(
            Path::new("/tmp/moduletto/0123456/Cargo.toml"),
            dir,
            C
        ));
    }
}
