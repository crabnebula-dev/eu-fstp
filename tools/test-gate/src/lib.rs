//! CI gate over the output of `cargo test --workspace --no-fail-fast`.
//!
//! Some tests are red on purpose: each waits on a seam that a named later
//! lane closes, and none is weakened, skipped or marked expected-failure.
//! `ci/known-red.txt` lists them, one per line, with the seam and the
//! lane. Decided by Daniel on 2026-10-31. The gate fails when:
//!
//! - a test fails that the list does not name;
//! - a listed test passes, so its entry must be removed;
//! - a listed test does not run at all, so its entry is stale;
//! - a test binary starts and never prints its result, which covers a
//!   crash or an abort;
//! - the output holds a compile error, or no test binary ran;
//! - two runs of the same key disagree, so the key is ambiguous.
//!
//! A test is keyed `<binary>::<test>`. The binary is the name cargo
//! prints in `Running ... (target/<profile>/deps/<binary>-<hash>)`
//! without its hash, or `doctest:<crate>` for a doc-test run.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// The outcome of one test, as libtest prints it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// `... ok`.
    Passed,
    /// `... FAILED`.
    Failed,
    /// `... ignored`.
    Ignored,
}

/// What one cargo test run printed, read line by line.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Run {
    /// Each key and the outcomes printed for it, in order.
    pub tests: BTreeMap<String, Vec<Outcome>>,
    /// Every binary that started.
    pub binaries: BTreeSet<String>,
    /// Binaries that started and printed no `test result:` line.
    pub unfinished: BTreeSet<String>,
    /// Whether the output holds a compile error.
    pub compile_error: bool,
}

/// The longest line the gate reads. A longer line is not a libtest line.
pub const MAX_LINE: usize = 4096;

/// The binary named by a `Running` line, without its hash.
fn running_binary(line: &str) -> Option<String> {
    let rest = line.trim_start().strip_prefix("Running ")?;
    let open = rest.rfind('(')?;
    let inner = rest.get(open.checked_add(1)?..)?.strip_suffix(')')?;
    let file = inner.rsplit('/').next()?;
    let (name, hash) = file.rsplit_once('-')?;
    if name.is_empty() || hash.is_empty() || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(name.to_owned())
}

/// The crate of a `Doc-tests <crate>` line.
fn doctest_binary(line: &str) -> Option<String> {
    let name = line.trim_start().strip_prefix("Doc-tests ")?.trim();
    if name.is_empty() || name.contains(' ') {
        return None;
    }
    Some(format!("doctest:{name}"))
}

/// The test name and outcome of a `test <name> ... <outcome>` line.
fn test_line(line: &str) -> Option<(&str, Outcome)> {
    let rest = line.strip_prefix("test ")?;
    let (name, result) = rest.split_once(" ... ")?;
    if name.is_empty() || name.starts_with("result:") {
        return None;
    }
    let word = result.split([',', ' ']).next()?;
    let outcome = match word {
        "ok" => Outcome::Passed,
        "FAILED" => Outcome::Failed,
        "ignored" => Outcome::Ignored,
        _ => return None,
    };
    Some((name, outcome))
}

/// Reads the output of a cargo test run. Lines longer than [`MAX_LINE`]
/// and lines in no known form are skipped, so test output that a test
/// itself prints cannot forge a result: a forged `test` line can only
/// add an outcome, and two outcomes for one key make the key ambiguous.
pub fn read_run(output: &str) -> Run {
    let mut run = Run::default();
    let mut current: Option<String> = None;
    for line in output.lines() {
        if line.len() > MAX_LINE {
            continue;
        }
        if line.starts_with("error[E") || line.starts_with("error: could not compile") {
            run.compile_error = true;
            continue;
        }
        if let Some(bin) = running_binary(line).or_else(|| doctest_binary(line)) {
            if let Some(open) = current.take() {
                run.unfinished.insert(open);
            }
            run.binaries.insert(bin.clone());
            current = Some(bin);
            continue;
        }
        if line.starts_with("test result: ") {
            current = None;
            continue;
        }
        if let (Some(bin), Some((name, outcome))) = (current.as_ref(), test_line(line)) {
            run.tests
                .entry(format!("{bin}::{name}"))
                .or_default()
                .push(outcome);
        }
    }
    if let Some(open) = current {
        run.unfinished.insert(open);
    }
    run
}

/// One entry of the known-red list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// `<binary>::<test>`.
    pub key: String,
    /// The seam the test waits on.
    pub seam: String,
    /// The lane that closes the seam.
    pub lane: String,
}

/// A line of the known-red list that is not an entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListError {
    /// The line number, from 1.
    pub line: usize,
    /// What is wrong.
    pub reason: &'static str,
}

/// Reads the known-red list: `<binary>::<test> | <seam> | <lane>` per
/// line, with `#` comments and blank lines. Each field is non-empty, the
/// key holds `::`, and no key appears twice. A key may hold spaces, since
/// doc-test names do; no field holds `|`.
pub fn read_list(text: &str) -> Result<Vec<Entry>, Vec<ListError>> {
    let mut entries = Vec::new();
    let mut errors = Vec::new();
    let mut seen = BTreeSet::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        let n = i.saturating_add(1);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split('|').map(str::trim);
        let (Some(key), Some(seam), Some(lane), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            errors.push(ListError {
                line: n,
                reason: "an entry has exactly three fields",
            });
            continue;
        };
        if key.is_empty() || seam.is_empty() || lane.is_empty() {
            errors.push(ListError {
                line: n,
                reason: "every field is non-empty",
            });
            continue;
        }
        if !key.contains("::") {
            errors.push(ListError {
                line: n,
                reason: "the key is <binary>::<test>",
            });
            continue;
        }
        if !seen.insert(key.to_owned()) {
            errors.push(ListError {
                line: n,
                reason: "the key appears twice",
            });
            continue;
        }
        entries.push(Entry {
            key: key.to_owned(),
            seam: seam.to_owned(),
            lane: lane.to_owned(),
        });
    }
    if errors.is_empty() {
        Ok(entries)
    } else {
        Err(errors)
    }
}

/// One reason the gate fails.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Problem {
    /// The output holds a compile error.
    CompileError,
    /// No test binary ran.
    NothingRan,
    /// A binary started and printed no result.
    Unfinished(String),
    /// A test failed that the list does not name.
    NewFailure(String),
    /// A listed test passed.
    NowPassing(String),
    /// A listed test did not run.
    Stale(String),
    /// A key has more than one outcome.
    Ambiguous(String),
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Problem::CompileError => write!(f, "the output holds a compile error"),
            Problem::NothingRan => write!(f, "no test binary ran"),
            Problem::Unfinished(b) => {
                write!(f, "{b}: started and printed no result (crash or abort)")
            }
            Problem::NewFailure(k) => write!(f, "{k}: failed and is not on the known-red list"),
            Problem::NowPassing(k) => {
                write!(f, "{k}: passes now; remove it from the known-red list")
            }
            Problem::Stale(k) => write!(
                f,
                "{k}: on the known-red list but did not run; the entry is stale"
            ),
            Problem::Ambiguous(k) => write!(
                f,
                "{k}: ran more than once with different outcomes; the key is ambiguous"
            ),
        }
    }
}

/// Every reason `run` fails against `list`, sorted. Empty when it passes.
pub fn check(run: &Run, list: &[Entry]) -> Vec<Problem> {
    let mut problems = BTreeSet::new();
    if run.compile_error {
        problems.insert(Problem::CompileError);
    }
    if run.binaries.is_empty() {
        problems.insert(Problem::NothingRan);
    }
    for b in &run.unfinished {
        problems.insert(Problem::Unfinished(b.clone()));
    }
    let listed: BTreeSet<&str> = list.iter().map(|e| e.key.as_str()).collect();
    for (key, outcomes) in &run.tests {
        let failed = outcomes.contains(&Outcome::Failed);
        let passed = outcomes.contains(&Outcome::Passed);
        if failed && passed {
            problems.insert(Problem::Ambiguous(key.clone()));
            continue;
        }
        match (failed, listed.contains(key.as_str())) {
            (true, false) => {
                problems.insert(Problem::NewFailure(key.clone()));
            }
            (false, true) if passed => {
                problems.insert(Problem::NowPassing(key.clone()));
            }
            _ => {}
        }
    }
    for e in list {
        if !run.tests.contains_key(&e.key) {
            problems.insert(Problem::Stale(e.key.clone()));
        }
    }
    problems.into_iter().collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    const RUN: &str = "\
     Running tests/a.rs (target/debug/deps/a-0123abcd)

running 2 tests
test one ... ok
test two ... FAILED
test result: FAILED. 1 passed; 1 failed; 0 ignored
     Running unittests src/lib.rs (target/debug/deps/fstp_x-ffee0011)
test m::three ... ignored, needs a cluster
test result: ok. 0 passed; 0 failed; 1 ignored
   Doc-tests fstp_x
test src/lib.rs - f (line 3) ... ok
test result: ok. 1 passed
";

    fn list(text: &str) -> Vec<Entry> {
        read_list(text).unwrap()
    }

    /// The gate reads keys and outcomes per binary, doc-tests included.
    #[test]
    fn known_red_run_reads_keys_and_outcomes() {
        let run = read_run(RUN);
        assert_eq!(run.tests["a::one"], vec![Outcome::Passed]);
        assert_eq!(run.tests["a::two"], vec![Outcome::Failed]);
        assert_eq!(run.tests["fstp_x::m::three"], vec![Outcome::Ignored]);
        assert_eq!(
            run.tests["doctest:fstp_x::src/lib.rs - f (line 3)"],
            vec![Outcome::Passed]
        );
        assert!(run.unfinished.is_empty());
        assert!(!run.compile_error);
    }

    /// A listed failure passes the gate; an unlisted one fails it.
    #[test]
    fn known_red_only_listed_failures_pass() {
        let run = read_run(RUN);
        assert!(check(&run, &list("a::two | seam | lane")).is_empty());
        assert_eq!(check(&run, &[]), vec![Problem::NewFailure("a::two".into())]);
    }

    /// A listed test that passes, or that never ran, fails the gate.
    #[test]
    fn known_red_passing_and_stale_entries_fail() {
        let run = read_run(RUN);
        let got = check(
            &run,
            &list("a::two | s | l\na::one | s | l\na::gone | s | l"),
        );
        assert_eq!(
            got,
            vec![
                Problem::NowPassing("a::one".into()),
                Problem::Stale("a::gone".into())
            ]
        );
    }

    /// A binary with no result line, a compile error, an empty run and two
    /// disagreeing outcomes for one key each fail the gate.
    #[test]
    fn known_red_crash_compile_error_empty_and_ambiguous_fail() {
        let crash = read_run("     Running tests/b.rs (target/debug/deps/b-00ff)\ntest x ... ok\n");
        assert_eq!(check(&crash, &[]), vec![Problem::Unfinished("b".into())]);
        let broken = read_run("error[E0425]: cannot find value `x`\n");
        assert_eq!(
            check(&broken, &[]),
            vec![Problem::CompileError, Problem::NothingRan]
        );
        let twice = read_run(
            "     Running tests/c.rs (target/debug/deps/c-01)\ntest t ... ok\ntest t ... FAILED\ntest result: x\n",
        );
        assert_eq!(check(&twice, &[]), vec![Problem::Ambiguous("c::t".into())]);
    }

    /// Lines in no libtest form, and over-long lines, are skipped.
    #[test]
    fn known_red_skips_foreign_lines() {
        let long = format!("test {} ... FAILED", "y".repeat(MAX_LINE));
        let text = format!(
            "     Running tests/d.rs (target/debug/deps/d-0a)\nthread panicked at x\n{long}\ntest z ... maybe\ntest result: ok\n"
        );
        let run = read_run(&text);
        assert!(run.tests.is_empty());
        assert!(check(&run, &[]).is_empty());
    }

    /// The list refuses malformed, empty, spaced and repeated entries.
    #[test]
    fn known_red_list_is_strict() {
        let bad = "# c\n\nnocolons | s | l\na::b | s\na::b | | l\na|b::c | s | l\na::b | s | l\na::b | s | l | x\na::b | s | l\n";
        let errs = read_list(bad).unwrap_err();
        let lines: Vec<usize> = errs.iter().map(|e| e.line).collect();
        assert_eq!(lines, vec![3, 4, 5, 6, 8, 9]);
    }
}
