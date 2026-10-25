//! Command-line entry point of deps-check. The gates live in the library;
//! see its documentation for what they check.

use std::process::ExitCode;

fn main() -> ExitCode {
    deps_check::run()
}
