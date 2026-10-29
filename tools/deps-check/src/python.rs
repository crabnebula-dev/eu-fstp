//! The no-Python gate (CLAUDE.md: no Python anywhere).
//!
//! The gate inspects every entry of the repository walk (see `repo`). An
//! entry fails in any of these cases:
//!
//! - Its extension marks Python source, bytecode, a zipapp, Cython or a
//!   notebook.
//! - Its name is a Python packaging file such as `pyproject.toml` or
//!   `requirements.txt`.
//! - Its first line is a shebang that runs Python, also through `uv run`,
//!   `uvx` or `pipx run`.
//! - It is a script, workflow, makefile or build script. One of its lines
//!   invokes a Python tool, such as `python3 - <<EOF` or `pip install`.
//!
//! The last check reads lowercase command words outside comment lines. A
//! sentence that names Python with a capital letter does not match.

use std::fs;
use std::io::Read;
use std::path::Path;

use crate::repo::{Kind, Walk};
use crate::report::Finding;

/// File extensions that mark Python source, bytecode, packaging or notebooks.
const PY_EXTENSIONS: [&str; 12] = [
    "py", "pyi", "pyw", "pyc", "pyo", "pyd", "pyz", "pyzw", "pyx", "pxd", "pxi", "ipynb",
];
/// File names that only Python tooling uses.
const PY_NAMES: [&str; 8] = [
    "pyproject.toml",
    "setup.cfg",
    "pipfile",
    "pipfile.lock",
    "poetry.lock",
    "uv.lock",
    "tox.ini",
    ".python-version",
];
/// Extensions of files that the invocation scan reads.
const SCRIPT_EXTENSIONS: [&str; 14] = [
    "sh", "bash", "zsh", "ksh", "yml", "yaml", "mk", "js", "mjs", "cjs", "ts", "mts", "cts", "ps1",
];
/// File names that the invocation scan reads.
const SCRIPT_NAMES: [&str; 8] = [
    "makefile",
    "gnumakefile",
    "dockerfile",
    "containerfile",
    "justfile",
    "build.rs",
    ".envrc",
    "action.yml",
];
/// Command words that run Python or its package managers. A word may carry
/// a version suffix, as in `python3.12` or `pip3`.
const PY_COMMANDS: [&str; 9] = [
    "python", "pypy", "pip", "pipx", "uvx", "jython", "graalpy", "ipython", "cython",
];
/// `uv` subcommands that run or install Python code.
const UV_SUBCOMMANDS: [&str; 7] = ["run", "tool", "pip", "venv", "sync", "init", "add"];
/// Bytes read from the start of each file to find a shebang.
const SHEBANG_PREFIX: usize = 256;
/// Bytes of a script that the invocation scan reads.
const SCRIPT_PREFIX: u64 = 1 << 20;

fn lower_name(path: &Path) -> String {
    path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
}

fn lower_ext(path: &Path) -> String {
    path.extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
}

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Whether `line` holds one of [`PY_COMMANDS`] as a whole word, with an
/// optional version suffix, or `uv` followed by a Python subcommand.
pub(crate) fn invokes_python(line: &str) -> bool {
    let b = line.as_bytes();
    for cmd in PY_COMMANDS {
        let mut from = 0usize;
        while let Some(off) = line.get(from..).and_then(|s| s.find(cmd)) {
            let start = from.saturating_add(off);
            let mut end = start.saturating_add(cmd.len());
            from = end;
            let before_ok = start
                .checked_sub(1)
                .and_then(|i| b.get(i))
                .is_none_or(|&c| !is_word_byte(c));
            while b.get(end).is_some_and(|&c| c.is_ascii_digit() || c == b'.') {
                end = end.saturating_add(1);
            }
            let after_ok = b.get(end).is_none_or(|&c| !is_word_byte(c));
            if before_ok && after_ok {
                return true;
            }
        }
    }
    let words: Vec<&str> = line
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
        .filter(|w| !w.is_empty())
        .collect();
    words
        .windows(2)
        .any(|w| matches!(w, [a, b] if *a == "uv" && UV_SUBCOMMANDS.contains(b)))
}

/// Whether the start of a file is a shebang that runs Python.
pub(crate) fn is_python_shebang(head: &[u8]) -> bool {
    let Some(rest) = head.strip_prefix(b"#!") else {
        return false;
    };
    let line = rest.split(|&b| b == b'\n').next().unwrap_or(&[]);
    let lower = String::from_utf8_lossy(line).to_ascii_lowercase();
    ["python", "pypy", "jython", "graalpy"]
        .iter()
        .any(|n| lower.contains(n))
        || invokes_python(&lower)
}

/// Whether a file name marks Python by its extension or its name.
pub(crate) fn has_python_name(path: &Path) -> bool {
    let name = lower_name(path);
    PY_EXTENSIONS.contains(&lower_ext(path).as_str())
        || PY_NAMES.contains(&name.as_str())
        || (name.starts_with("requirements") && (name.ends_with(".txt") || name.ends_with(".in")))
}

/// The installed npm trees that `npm ci --ignore-scripts` writes. They are
/// git-ignored and never committed (the npm gate refuses any other
/// `node_modules` tree).
const INSTALLED_NPM_TREES: [&str; 2] = ["web/node_modules", "e2e/node_modules"];

/// Whether `rel` lies inside an installed npm tree. Python files and Python
/// shebangs there still fail. Only the line scan for Python invocations
/// skips them: it reads third-party JavaScript, whose language names such
/// as `"python"` (Playwright's code generator) are not invocations. Those
/// packages are pinned and reviewed through `deps/npm-allowlist.txt`, and
/// no package script runs, since installs use `--ignore-scripts`.
fn in_installed_npm_tree(rel: &Path) -> bool {
    INSTALLED_NPM_TREES.iter().any(|t| rel.starts_with(t))
}

/// Whether the invocation scan reads this file. `head` is its first bytes.
fn is_script(path: &Path, head: &[u8]) -> bool {
    SCRIPT_EXTENSIONS.contains(&lower_ext(path).as_str())
        || SCRIPT_NAMES.contains(&lower_name(path).as_str())
        || head.starts_with(b"#!")
}

/// 1-based numbers of lines outside comments that invoke Python.
pub(crate) fn invocation_lines(text: &str) -> Vec<usize> {
    text.lines()
        .enumerate()
        .filter(|(_, l)| {
            let t = l.trim_start();
            !t.starts_with('#') && !t.starts_with("//") && invokes_python(l)
        })
        .map(|(i, _)| i.saturating_add(1))
        .collect()
}

/// The scan result.
#[derive(Debug, Default)]
pub(crate) struct Scan {
    /// Regular files inspected.
    pub(crate) files: usize,
    /// Violations and scan problems.
    pub(crate) findings: Vec<Finding>,
}

/// Scans the walked files of `root` for Python.
pub(crate) fn scan(root: &Path, walk: &Walk) -> Scan {
    let mut out = Scan::default();
    for f in &walk.files {
        let rel = f.rel.display();
        if has_python_name(&f.rel) {
            out.findings.push(Finding::error(
                "python-file",
                format!("{rel} is a Python file"),
            ));
        }
        // Symbolic links and special files are judged by name only.
        if f.kind != Kind::File {
            continue;
        }
        out.files = out.files.saturating_add(1);
        let path = root.join(&f.rel);
        let head = match read_prefix(&path, SHEBANG_PREFIX as u64) {
            Ok(h) => h,
            Err(e) => {
                out.findings
                    .push(Finding::error("scan-io", format!("cannot read {rel}: {e}")));
                continue;
            }
        };
        if is_python_shebang(&head) {
            out.findings.push(Finding::error(
                "python-shebang",
                format!("{rel} starts with a Python shebang"),
            ));
            continue;
        }
        if !is_script(&f.rel, &head) || in_installed_npm_tree(&f.rel) {
            continue;
        }
        match read_prefix(&path, SCRIPT_PREFIX) {
            Ok(bytes) => {
                for line in invocation_lines(&String::from_utf8_lossy(&bytes)) {
                    out.findings.push(Finding::error(
                        "python-invocation",
                        format!("{rel}:{line} invokes a Python tool"),
                    ));
                }
            }
            Err(e) => out
                .findings
                .push(Finding::error("scan-io", format!("cannot read {rel}: {e}"))),
        }
    }
    out.findings.sort();
    out
}

fn read_prefix(path: &Path, limit: u64) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    fs::File::open(path)?.take(limit).read_to_end(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::repo::walk;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    /// A fresh, empty temporary directory, removed on drop.
    pub(crate) struct TempDir(pub(crate) PathBuf);

    impl TempDir {
        pub(crate) fn new(tag: &str) -> TempDir {
            let n = COUNTER.fetch_add(1, Ordering::SeqCst);
            let p =
                std::env::temp_dir().join(format!("deps-check-{tag}-{}-{n}", std::process::id()));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(&p).unwrap();
            TempDir(p)
        }

        pub(crate) fn write(&self, rel: &str, content: &[u8]) {
            let p = self.0.join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, content).unwrap();
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn run_scan(t: &TempDir) -> Scan {
        let root = fs::canonicalize(&t.0).unwrap();
        scan(&root, &walk(&root, &[]))
    }

    #[test]
    fn shebang_forms() {
        for yes in [
            &b"#!/usr/bin/env python3\nprint(1)"[..],
            b"#!/usr/bin/python",
            b"#! /usr/bin/env -S PYTHON -u\n",
            b"#!/opt/pypy/bin/pypy3\n",
            b"#!/usr/bin/env -S uv run --script\n",
            b"#!/usr/bin/env uvx\n",
            b"#!/usr/bin/env -S pipx run\n",
            b"#!/opt/graalpy/bin/graalpy\n",
            b"#!/usr/bin/jython\n",
        ] {
            assert!(is_python_shebang(yes), "{:?}", String::from_utf8_lossy(yes));
        }
        for no in [
            &b"#!/bin/bash\n# python is not allowed here\n"[..],
            b"#!/usr/bin/env node\n",
            b"python\n",
            b" #!/usr/bin/python\n",
            b"",
            b"#",
        ] {
            assert!(!is_python_shebang(no), "{:?}", String::from_utf8_lossy(no));
        }
    }

    #[test]
    fn invocation_words() {
        for yes in [
            "python3 - <<EOF",
            "  python -c 'print(1)'",
            "run: python3.12 tools/gen",
            "/usr/bin/python3 x",
            "pip install foo",
            "pip3 install -r reqs",
            "uv run gen",
            "uvx ruff",
            "x=$(pypy3 -V)",
            "exec(\"python3\")",
        ] {
            assert!(invokes_python(yes), "{yes}");
        }
        for no in [
            "set -o pipefail",
            "pipeline step",
            "no-Python gate",
            "uv is a unit",
            "pythonic_name_x",
            "mypython3",
        ] {
            assert!(!invokes_python(no), "{no}");
        }
    }

    /// The no-Python rule in CLAUDE.md: Python files and shebangs fail.
    /// `.git` directories and build output are skipped.
    #[test]
    fn no_python_scan_finds_files_and_shebangs() {
        let t = TempDir::new("py");
        t.write("ok.rs", b"fn main() {}\n");
        t.write("tools/run", b"#!/usr/bin/env python3\n");
        t.write(
            "tools/run.sh",
            b"#!/usr/bin/env bash\necho Python is banned\n",
        );
        t.write("deep/a/b/gen.PY", b"x = 1\n");
        t.write("stubs/x.pyi", b"");
        t.write(".git/hooks/pre-commit.py", b"");
        t.write("target/debug/build.py", b"");
        t.write("crates/x/fuzz/target/y.py", b"");
        t.write("crates/x/fuzz/corpus/z.py", b"");
        let s = run_scan(&t);
        let got: Vec<(&str, String)> = s
            .findings
            .iter()
            .map(|f| (f.code, f.message.clone()))
            .collect();
        assert_eq!(
            got,
            vec![
                ("python-file", "deep/a/b/gen.PY is a Python file".to_owned()),
                ("python-file", "stubs/x.pyi is a Python file".to_owned()),
                (
                    "python-shebang",
                    "tools/run starts with a Python shebang".to_owned()
                ),
            ]
        );
        assert_eq!(s.files, 5);
    }

    /// Regression for review finding python-scan-skips-any-target-dir
    /// (CLAUDE.md, no Python anywhere): a directory named `target` that is
    /// not build output is scanned.
    #[test]
    fn review_python_scan_skips_any_target_dir() {
        let t = TempDir::new("pytarget");
        t.write("tools/target/gen.py", b"print(1)\n");
        t.write("tools/target/run", b"#!/usr/bin/env python3\n");
        t.write("crates/x/src/target/helper.py", b"");
        let s = run_scan(&t);
        let got: Vec<&str> = s.findings.iter().map(|f| f.message.as_str()).collect();
        assert_eq!(
            got,
            vec![
                "crates/x/src/target/helper.py is a Python file",
                "tools/target/gen.py is a Python file",
                "tools/target/run starts with a Python shebang",
            ],
            "{:?}",
            s.findings
        );
    }

    fn scan_codes(t: &TempDir) -> Vec<(&'static str, String)> {
        run_scan(t)
            .findings
            .iter()
            .map(|f| (f.code, f.message.clone()))
            .collect()
    }

    /// Regression for review finding python-heuristics-gaps (CLAUDE.md):
    /// a zipapp, a notebook, inline Python in a shell script and a uv
    /// shebang all fail.
    #[test]
    fn review_python_heuristics_gaps() {
        let t = TempDir::new("pygaps");
        t.write("tools/build.pyz", b"PK");
        t.write("tools/nb.ipynb", b"{}");
        t.write(
            "tools/gen.sh",
            b"#!/usr/bin/env bash\npython3 - <<EOF\nprint(1)\nEOF\n",
        );
        t.write("tools/uvscript", b"#!/usr/bin/env -S uv run --script\n");
        t.write(
            "tools/ok.sh",
            b"#!/usr/bin/env bash\nset -o pipefail\necho no-Python\n",
        );
        let want: Vec<(&str, String)> = vec![
            ("python-file", "tools/build.pyz is a Python file".into()),
            ("python-file", "tools/nb.ipynb is a Python file".into()),
            (
                "python-invocation",
                "tools/gen.sh:2 invokes a Python tool".into(),
            ),
            (
                "python-shebang",
                "tools/uvscript starts with a Python shebang".into(),
            ),
        ];
        assert_eq!(scan_codes(&t), want);
    }

    /// Regression for review finding no-python-gate-heuristic (CLAUDE.md):
    /// Python embedded in a shell generator or a CI step, Cython, a notebook
    /// and packaging files fail.
    #[test]
    fn review_no_python_gate_heuristic() {
        let t = TempDir::new("pycompliance");
        t.write(
            "tools/rc-gen.sh",
            b"#!/bin/bash\nset -e\npython3 - <<PY\nprint('x')\nPY\n",
        );
        t.write("tools/rc-mod.pyx", b"");
        t.write("tools/rc-note.ipynb", b"{}");
        t.write(
            ".github/workflows/x.yml",
            b"jobs:\n  a:\n    steps:\n      # python3 in a comment is fine\n      - run: python3 gen\n",
        );
        t.write("pyproject.toml", b"");
        t.write("requirements-dev.txt", b"");
        let want: Vec<(&str, String)> = vec![
            ("python-file", "pyproject.toml is a Python file".into()),
            (
                "python-file",
                "requirements-dev.txt is a Python file".into(),
            ),
            ("python-file", "tools/rc-mod.pyx is a Python file".into()),
            ("python-file", "tools/rc-note.ipynb is a Python file".into()),
            (
                "python-invocation",
                ".github/workflows/x.yml:5 invokes a Python tool".into(),
            ),
            (
                "python-invocation",
                "tools/rc-gen.sh:3 invokes a Python tool".into(),
            ),
        ];
        assert_eq!(scan_codes(&t), want);
    }

    #[test]
    fn installed_npm_trees_skip_only_the_invocation_scan() {
        let t = TempDir::new("npmtree");
        t.write(
            "e2e/node_modules/pkg/lib.js",
            b"const langs = ['python'];\nexec('python3 x');\n",
        );
        t.write("web/node_modules/pkg/tool.py", b"print(1)\n");
        t.write("web/node_modules/pkg/run", b"#!/usr/bin/env python3\n");
        t.write("tools/x.sh", b"python3 - <<EOF\n");
        let codes = scan_codes(&t);
        assert!(
            !codes
                .iter()
                .any(|(c, r)| *c == "python-invocation" && r.contains("node_modules")),
            "{codes:?}"
        );
        assert!(
            codes
                .iter()
                .any(|(c, r)| *c == "python-file" && r.contains("tool.py")),
            "{codes:?}"
        );
        assert!(
            codes
                .iter()
                .any(|(c, r)| *c == "python-shebang" && r.contains("pkg/run")),
            "{codes:?}"
        );
        assert!(
            codes
                .iter()
                .any(|(c, r)| *c == "python-invocation" && r.contains("tools/x.sh")),
            "{codes:?}"
        );
    }

    #[test]
    fn symlinks_are_not_followed() {
        let t = TempDir::new("link");
        t.write("real/ok.txt", b"hello\n");
        std::os::unix::fs::symlink(&t.0, t.0.join("real/loop")).unwrap();
        std::os::unix::fs::symlink(t.0.join("real/ok.txt"), t.0.join("alias.py")).unwrap();
        let s = run_scan(&t);
        let codes: Vec<&str> = s.findings.iter().map(|f| f.code).collect();
        assert_eq!(codes, vec!["python-file"], "{:?}", s.findings);
        assert_eq!(s.files, 1);
    }

    /// The shebang test matches its definition on arbitrary input.
    #[test]
    fn shebang_detection_matches_definition() {
        fstp_prop::check("shebang_detection_matches_definition", |g| {
            let parts = [
                "#!",
                "/usr/bin/env ",
                "python",
                "PyThOn3",
                "pypy",
                "bash",
                "\n",
                " ",
                "-S ",
            ];
            let mut s = Vec::new();
            for _ in 0..g.usize_in(0..=6) {
                if g.bool() {
                    s.extend_from_slice(g.pick(&parts).as_bytes());
                } else {
                    s.extend(g.bytes(0..=3));
                }
            }
            let first = s.split(|&b| b == b'\n').next().unwrap_or(&[]).to_vec();
            let lower = String::from_utf8_lossy(&first).to_ascii_lowercase();
            let want = first.starts_with(b"#!")
                && (["python", "pypy", "jython", "graalpy"]
                    .iter()
                    .any(|n| lower.contains(n))
                    || invokes_python(&lower));
            fstp_prop::prop_assert_eq!(is_python_shebang(&s), want);
            Ok(())
        });
    }
}
