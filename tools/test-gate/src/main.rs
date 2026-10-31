//! Command-line entry point of test-gate:
//! `test-gate --known-red <list> <cargo test output>`. The checks live in
//! the library; see its documentation for what they are.

use std::process::ExitCode;

use test_gate::{Outcome, check, read_list, read_run};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (list_path, log_path) = match args.as_slice() {
        [flag, list, log] if flag == "--known-red" => (list, log),
        _ => {
            eprintln!("usage: test-gate --known-red <list> <cargo test output>");
            return ExitCode::from(2);
        }
    };
    let read = |p: &str| std::fs::read_to_string(p).map_err(|e| format!("{p}: {e}"));
    let (list_text, log) = match (read(list_path), read(log_path)) {
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
    let problems = check(&run, &list);
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
