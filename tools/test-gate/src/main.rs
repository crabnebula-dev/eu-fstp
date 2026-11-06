//! Command-line entry point of test-gate:
//! `test-gate --known-red <list> [--partial [--filter <s>]... [--skip <s>]...] <cargo test output>`.
//! `--partial` gates one CI shard: `--filter` and `--skip` repeat the
//! libtest filters the shard ran with. The checks live in the library;
//! see its documentation for what they are.

#![allow(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    reason = "R-NF-02 print ban: a CI tool that reports to the terminal and never ships"
)]

use std::process::ExitCode;

use test_gate::{Outcome, Selection, check, check_partial, read_list, read_run};

const USAGE: &str = "usage: test-gate --known-red <list> [--partial [--filter <s>]... [--skip <s>]...] <cargo test output>";

/// The parsed arguments: the list, the log and, for a shard, its selection.
struct Args {
    list: String,
    log: String,
    partial: Option<Selection>,
}

fn parse_args(args: &[String]) -> Option<Args> {
    let mut it = args.iter();
    if it.next()? != "--known-red" {
        return None;
    }
    let list = it.next()?.clone();
    let mut partial: Option<Selection> = None;
    let mut log = None;
    while let Some(a) = it.next() {
        match a.as_str() {
            "--partial" if partial.is_none() => partial = Some(Selection::default()),
            "--filter" => partial.as_mut()?.filters.push(it.next()?.clone()),
            "--skip" => partial.as_mut()?.skips.push(it.next()?.clone()),
            _ if log.is_none() && !a.starts_with("--") => log = Some(a.clone()),
            _ => return None,
        }
    }
    Some(Args {
        list,
        log: log?,
        partial,
    })
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(Args {
        list: list_path,
        log: log_path,
        partial,
    }) = parse_args(&args)
    else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let read = |p: &str| std::fs::read_to_string(p).map_err(|e| format!("{p}: {e}"));
    let (list_text, log) = match (read(&list_path), read(&log_path)) {
        (Ok(l), Ok(o)) => (l, o),
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("test-gate: {e}");
            return ExitCode::from(2);
        }
    };
    let list = match read_list(&list_text) {
        Ok(l) => l,
        Err(errors) => {
            for e in errors {
                eprintln!("{list_path}:{}: {}", e.line, e.reason);
            }
            return ExitCode::FAILURE;
        }
    };
    let run = read_run(&log);
    let count = |o: Outcome| run.tests.values().filter(|v| v.contains(&o)).count();
    println!(
        "test-gate: {} binaries, {} passed, {} failed ({} on the known-red list), {} ignored",
        run.binaries.len(),
        count(Outcome::Passed),
        count(Outcome::Failed),
        list.len(),
        count(Outcome::Ignored)
    );
    let problems = match &partial {
        Some(selection) => {
            println!(
                "test-gate: partial, filters {:?}, skips {:?}",
                selection.filters, selection.skips
            );
            check_partial(&run, &list, selection)
        }
        None => check(&run, &list),
    };
    if problems.is_empty() {
        println!("test-gate: PASS");
        return ExitCode::SUCCESS;
    }
    for p in &problems {
        println!("FAIL {p}");
    }
    println!("test-gate: FAIL ({} problems)", problems.len());
    ExitCode::FAILURE
}
