//! The `fstp-admin` binary (ADR-028). See the library documentation.

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    ExitCode::from(fstp_admin::main_with(&args))
}
