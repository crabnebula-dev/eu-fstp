//! A strict reader for `Cargo.lock` files, format versions 3 and 4.
//!
//! deps-check reads every lockfile in the repository for two reasons. Each
//! package in a lockfile must be explained by the dependency analysis, and
//! each crates.io package is pinned by the SHA-256 checksum that the
//! lockfile records (TH-15).
//!
//! The reader accepts only the subset of TOML that cargo writes:
//!
//! ```text
//! # comment
//! version = 4
//!
//! [[package]]
//! name = "cc"
//! version = "1.10.0"
//! source = "registry+https://github.com/rust-lang/crates.io-index"
//! checksum = "<64 hex digits>"
//! dependencies = [
//!  "shlex",
//! ]
//! ```
//!
//! Anything else is an error, including `[[patch.unused]]`, `[metadata]`,
//! a `replace` key and unknown keys. A gate that fails on an unfamiliar
//! lockfile is safer than one that skips what it does not understand.

use std::collections::BTreeSet;

use crate::allowlist::{LineError, valid_checksum, valid_crate_name, valid_version};

/// Upper bound on the size of one lockfile.
const MAX_BYTES: usize = 16 << 20;
/// Upper bound on the length of one line.
const MAX_LINE: usize = 4096;
/// Upper bound on the number of packages.
const MAX_PACKAGES: usize = 100_000;
/// Upper bound on the dependencies of one package.
const MAX_DEPS: usize = 10_000;

/// One `[[package]]` table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LockPackage {
    /// Crate name.
    pub(crate) name: String,
    /// Exact version.
    pub(crate) version: String,
    /// Source, or `None` for a path package.
    pub(crate) source: Option<String>,
    /// SHA-256 of the `.crate` file, for registry packages.
    pub(crate) checksum: Option<String>,
    /// Dependency references as cargo writes them.
    pub(crate) dependencies: Vec<String>,
}

/// A parsed lockfile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Lockfile {
    /// The `version` marker, 3 or 4.
    pub(crate) version: u32,
    /// Packages in file order.
    pub(crate) packages: Vec<LockPackage>,
}

#[derive(Default)]
struct Partial {
    line: usize,
    name: Option<String>,
    version: Option<String>,
    source: Option<String>,
    checksum: Option<String>,
    dependencies: Option<Vec<String>>,
}

enum State {
    /// Before the first table.
    Top,
    /// Inside a `[[package]]` table.
    Package(Partial),
    /// Inside a multi-line `dependencies` array.
    Deps(Partial, Vec<String>),
}

/// Reads a basic string `"..."` that holds no quote, backslash or control
/// character, and returns its content and the rest of the line.
fn quoted(s: &str) -> Option<(&str, &str)> {
    let inner = s.strip_prefix('"')?;
    let end = inner.find('"')?;
    let value = inner.get(..end)?;
    if value.chars().any(|c| c == '\\' || c.is_control()) {
        return None;
    }
    Some((value, inner.get(end.saturating_add(1)..)?))
}

/// Whether `s` is a dependency reference: `name`, `name version` or
/// `name version (source)`.
fn valid_dep_ref(s: &str) -> bool {
    let mut parts = s.splitn(3, ' ');
    let name = parts.next().unwrap_or("");
    let version = parts.next();
    let source = parts.next();
    valid_crate_name(name)
        && version.is_none_or(valid_version)
        && source.is_none_or(|src| {
            src.len() > 2 && src.starts_with('(') && src.ends_with(')') && !src.contains(' ')
        })
}

fn finish(p: Partial, out: &mut Vec<LockPackage>, errors: &mut Vec<LineError>) {
    let err = |message: String| LineError {
        line: p.line,
        message,
    };
    let (Some(name), Some(version)) = (p.name.clone(), p.version.clone()) else {
        errors.push(err("[[package]] needs both name and version".into()));
        return;
    };
    if p.checksum.is_some() && p.source.is_none() {
        errors.push(err(format!(
            "{name} {version} has a checksum but no source"
        )));
        return;
    }
    if out.len() >= MAX_PACKAGES {
        errors.push(err(format!("more than {MAX_PACKAGES} packages")));
        return;
    }
    out.push(LockPackage {
        name,
        version,
        source: p.source,
        checksum: p.checksum,
        dependencies: p.dependencies.unwrap_or_default(),
    });
}

/// Applies one `key = value` line to a package table. Returns the new state.
fn package_key(mut p: Partial, line: usize, raw: &str, errors: &mut Vec<LineError>) -> State {
    let err = |message: String| LineError { line, message };
    let Some((key, value)) = raw.split_once('=') else {
        errors.push(err("expected `key = value`".into()));
        return State::Package(p);
    };
    let key = key.trim();
    let value = value.trim();
    if key == "dependencies" {
        if p.dependencies.is_some() {
            errors.push(err("duplicate key `dependencies`".into()));
            return State::Package(p);
        }
        return match value {
            "[" => State::Deps(p, Vec::new()),
            "[]" => {
                p.dependencies = Some(Vec::new());
                State::Package(p)
            }
            _ => {
                errors.push(err("`dependencies` must open a multi-line array".into()));
                State::Package(p)
            }
        };
    }
    let Some((text, rest)) = quoted(value) else {
        errors.push(err(format!("`{key}` needs a plain quoted string")));
        return State::Package(p);
    };
    if !rest.trim().is_empty() {
        errors.push(err(format!("unexpected text after `{key}`")));
        return State::Package(p);
    }
    let (slot, ok) = match key {
        "name" => (&mut p.name, valid_crate_name(text)),
        "version" => (&mut p.version, valid_version(text)),
        "source" => (&mut p.source, !text.is_empty() && !text.contains(' ')),
        "checksum" => (&mut p.checksum, valid_checksum(text)),
        _ => {
            errors.push(err(format!(
                "unknown key `{key}`; deps-check reads only name, version, source, \
                 checksum and dependencies"
            )));
            return State::Package(p);
        }
    };
    if slot.is_some() {
        errors.push(err(format!("duplicate key `{key}`")));
    } else if !ok {
        errors.push(err(format!("invalid `{key}` value `{text}`")));
    } else {
        *slot = Some(text.to_owned());
    }
    State::Package(p)
}

/// Parses a lockfile.
pub(crate) fn parse(text: &str) -> Result<Lockfile, Vec<LineError>> {
    if text.len() > MAX_BYTES {
        return Err(vec![LineError {
            line: 0,
            message: format!("larger than {MAX_BYTES} bytes"),
        }]);
    }
    let mut errors: Vec<LineError> = Vec::new();
    let mut packages = Vec::new();
    let mut version: Option<u32> = None;
    let mut state = State::Top;
    let mut last_line = 0usize;
    for (i, raw) in text.split('\n').enumerate() {
        let line = i.saturating_add(1);
        last_line = line;
        let raw = raw.strip_suffix('\r').unwrap_or(raw);
        let err = |message: String| LineError { line, message };
        if raw.len() > MAX_LINE {
            errors.push(err(format!("longer than {MAX_LINE} bytes")));
            break;
        }
        let t = raw.trim();
        state = match state {
            State::Deps(mut p, mut deps) => {
                if t == "]" {
                    p.dependencies = Some(deps);
                    State::Package(p)
                } else if let Some((dep, rest)) = quoted(t)
                    && rest == ","
                {
                    if !valid_dep_ref(dep) {
                        errors.push(err(format!("invalid dependency reference `{dep}`")));
                    } else if deps.len() >= MAX_DEPS {
                        errors.push(err(format!("more than {MAX_DEPS} dependencies")));
                    } else {
                        deps.push(dep.to_owned());
                    }
                    State::Deps(p, deps)
                } else {
                    errors.push(err(
                        "expected a quoted dependency followed by a comma, or `]`".into(),
                    ));
                    State::Deps(p, deps)
                }
            }
            s if t.is_empty() || t.starts_with('#') => s,
            s if t.starts_with('[') => {
                if let State::Package(p) = s {
                    finish(p, &mut packages, &mut errors);
                }
                if t == "[[package]]" {
                    if version.is_none() {
                        errors.push(err("missing `version = 3` or `version = 4` marker".into()));
                    }
                    State::Package(Partial {
                        line,
                        ..Partial::default()
                    })
                } else {
                    errors.push(err(format!(
                        "unsupported table `{t}`; only [[package]] is allowed (no [patch] or \
                         [metadata])"
                    )));
                    State::Top
                }
            }
            State::Top => {
                match t.split_once('=').map(|(k, v)| (k.trim(), v.trim())) {
                    Some(("version", v)) if version.is_none() && packages.is_empty() => match v {
                        "3" => version = Some(3),
                        "4" => version = Some(4),
                        _ => errors.push(err(format!(
                            "lockfile version {v} is not supported; expected 3 or 4"
                        ))),
                    },
                    _ => errors.push(err(
                        "only `version = <n>` may appear before the first [[package]]".into(),
                    )),
                }
                State::Top
            }
            State::Package(p) => package_key(p, line, t, &mut errors),
        };
    }
    match state {
        State::Package(p) => finish(p, &mut packages, &mut errors),
        State::Deps(..) => errors.push(LineError {
            line: last_line,
            message: "unterminated `dependencies` array".into(),
        }),
        State::Top => {}
    }
    let mut seen = BTreeSet::new();
    for p in &packages {
        if !seen.insert((&p.name, &p.version, &p.source)) {
            errors.push(LineError {
                line: 0,
                message: format!("duplicate package {} {}", p.name, p.version),
            });
        }
    }
    let Some(version) = version else {
        errors.push(LineError {
            line: 0,
            message: "missing `version = 3` or `version = 4` marker".into(),
        });
        return Err(errors);
    };
    if errors.is_empty() {
        Ok(Lockfile { version, packages })
    } else {
        Err(errors)
    }
}

/// Renders a lockfile in the format cargo writes.
pub(crate) fn render(lock: &Lockfile) -> String {
    let mut out = format!(
        "# This file is automatically @generated by Cargo.\n\
         # It is not intended for manual editing.\nversion = {}\n",
        lock.version
    );
    for p in &lock.packages {
        out.push_str(&format!(
            "\n[[package]]\nname = \"{}\"\nversion = \"{}\"\n",
            p.name, p.version
        ));
        if let Some(s) = &p.source {
            out.push_str(&format!("source = \"{s}\"\n"));
        }
        if let Some(c) = &p.checksum {
            out.push_str(&format!("checksum = \"{c}\"\n"));
        }
        if !p.dependencies.is_empty() {
            out.push_str("dependencies = [\n");
            for d in &p.dependencies {
                out.push_str(&format!(" \"{d}\",\n"));
            }
            out.push_str("]\n");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use fstp_prop::{Gen, prop_assert_eq};

    const CRATES_IO: &str = "registry+https://github.com/rust-lang/crates.io-index";
    const SUM: &str = "3bc62ac97cc33321f50863d514c3bc38a453947a8f9e781137e47c7401020aed";

    fn sample() -> String {
        format!(
            "# This file is automatically @generated by Cargo.\n\
             # It is not intended for manual editing.\n\
             version = 4\n\n\
             [[package]]\nname = \"arbitrary\"\nversion = \"1.5.0\"\n\
             source = \"{CRATES_IO}\"\nchecksum = \"{SUM}\"\n\n\
             [[package]]\nname = \"fstp-json\"\nversion = \"0.1.0\"\n\n\
             [[package]]\nname = \"fstp-json-fuzz\"\nversion = \"0.0.0\"\n\
             dependencies = [\n \"arbitrary 1.5.0\",\n \"fstp-json\",\n]\n"
        )
    }

    #[test]
    fn parses_cargo_output() {
        let lock = parse(&sample()).unwrap();
        assert_eq!(lock.version, 4);
        assert_eq!(lock.packages.len(), 3);
        assert_eq!(lock.packages[0].checksum.as_deref(), Some(SUM));
        assert_eq!(lock.packages[1].source, None);
        assert_eq!(
            lock.packages[2].dependencies,
            vec!["arbitrary 1.5.0".to_owned(), "fstp-json".to_owned()]
        );
        assert_eq!(render(&lock), sample());
    }

    /// The repository's own lockfiles parse.
    #[test]
    fn parses_repository_lockfiles() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let text = std::fs::read_to_string(root.join("Cargo.lock")).unwrap();
        let lock = parse(&text).unwrap();
        assert!(lock.packages.iter().any(|p| p.name == "rustls"));
    }

    /// TH-15, P5: a lockfile that records a patch, a replacement or an
    /// unknown structure is refused rather than skipped.
    #[test]
    fn th15_refuses_patch_and_unknown_structure() {
        let base = sample();
        let orphan_sum = format!("checksum = \"{SUM}\"\n");
        for (extra, needle) in [
            (
                "\n[[patch.unused]]\nname = \"subtle\"\nversion = \"2.6.1\"\n",
                "unsupported table",
            ),
            ("\n[metadata]\n", "unsupported table"),
            ("replace = \"subtle 2.6.1\"\n", "unknown key"),
            ("checksum = \"abc\"\n", "invalid `checksum`"),
            (orphan_sum.as_str(), "has a checksum but no source"),
        ] {
            let text = format!("{base}{extra}");
            let errs = parse(&text).unwrap_err();
            assert!(
                errs.iter().any(|e| e.message.contains(needle)),
                "{extra}: {errs:?}"
            );
        }
        for bad in [
            "",
            "[[package]]\nname = \"a\"\nversion = \"1.0.0\"\n",
            "version = 2\n",
            "version = 4\nversion = 4\n",
            "version = 4\n[[package]]\nname = \"a\"\n",
            "version = 4\n[[package]]\nname = \"a\"\nversion = \"1.0.0\"\ndependencies = [\n",
            "version = 4\n[[package]]\nname = \"a\"\nversion = \"1.0.0\"\nname = \"b\"\n",
            "version = 4\n[[package]]\nname = \"a\\u0062\"\nversion = \"1.0.0\"\n",
            "version = 4\n[[package]]\nname = \"a\"\nversion = \"1.0.0\"\n\
             [[package]]\nname = \"a\"\nversion = \"1.0.0\"\n",
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
    }

    fn gen_lock(g: &mut Gen) -> Lockfile {
        let names = ["cc", "libc", "fstp-json", "a_b", "x9"];
        let versions = [
            "1.0.0",
            "0.2.191",
            "0.11.1+wasi-snapshot-preview1",
            "1.0.0-rc.1",
        ];
        let mut packages: Vec<LockPackage> = Vec::new();
        for _ in 0..g.usize_in(0..=6) {
            let registry = g.bool();
            let p = LockPackage {
                name: (*g.pick(&names)).to_owned(),
                version: (*g.pick(&versions)).to_owned(),
                source: registry.then(|| CRATES_IO.to_owned()),
                checksum: (registry && g.bool()).then(|| SUM.to_owned()),
                dependencies: g.vec(0..=3, |g| {
                    let mut d = (*g.pick(&names)).to_owned();
                    if g.bool() {
                        d.push(' ');
                        d.push_str(g.pick(&versions));
                    }
                    d
                }),
            };
            if !packages
                .iter()
                .any(|q| q.name == p.name && q.version == p.version && q.source == p.source)
            {
                packages.push(p);
            }
        }
        Lockfile {
            version: *g.pick(&[3, 4]),
            packages,
        }
    }

    /// TH-26: rendering then parsing a lockfile returns the same packages.
    #[test]
    fn th26_lockfile_round_trip() {
        fstp_prop::check("th26_lockfile_round_trip", |g| {
            let lock = gen_lock(g);
            let text = render(&lock);
            g.note("text", &text);
            let back = parse(&text).map_err(|e| format!("{e:?}"))?;
            prop_assert_eq!(back, lock);
            Ok(())
        });
    }

    /// TH-26: the lockfile reader returns errors, never panics, on mutated input.
    #[test]
    fn th26_lockfile_parser_total() {
        fstp_prop::check("th26_lockfile_parser_total", |g| {
            let mut bytes = sample().into_bytes();
            for _ in 0..g.usize_in(1..=6) {
                if bytes.is_empty() {
                    break;
                }
                let at = g.usize_in(0..=bytes.len().saturating_sub(1));
                match g.u8_in(0..=2) {
                    0 => bytes[at] = *g.pick(b"\"[]=,\n\r #\\ab1."),
                    1 => {
                        bytes.remove(at);
                    }
                    _ => bytes.insert(at, *g.pick(b"\"[]=,\n ")),
                }
            }
            let text = String::from_utf8_lossy(&bytes);
            if let Ok(lock) = parse(&text) {
                let back = parse(&render(&lock)).map_err(|e| format!("{e:?}"))?;
                prop_assert_eq!(back, lock);
            }
            Ok(())
        });
    }
}
