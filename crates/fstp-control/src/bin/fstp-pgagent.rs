//! The `fstp-pgagent` binary (M3 design section 2.3, ADR-011).
//!
//! It decodes the configuration named by `FSTP_PGAGENT_CONFIG` and serves
//! typed provisioning jobs from `fstp-control` through
//! `fstp_control::agent::run`, on the one tokio runtime behind `fstp_rt`,
//! until SIGTERM drains it.
//!
//! `run-job <job> [<database>]` runs one non-destructive provisioning job
//! on the local cluster and exits, for a single host with no control
//! plane (ADR-028 "Database provisioning", `fstp_control::agent::run_local`).

use std::process::ExitCode;

use fstp_control::ControlError;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.split_first() {
        Some((first, rest)) if first == "run-job" => {
            let words: Vec<&str> = rest.iter().map(String::as_str).collect();
            fstp_control::agent::run_local(&words)
        }
        Some(_) => Err(ControlError::Config("arguments")),
        None => fstp_control::agent::run(),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        // A refused configuration or argument exits with the usage
        // status. No event names it, since `LogEvent` has no variant for
        // it (R-NF-02).
        Err(ControlError::Config(_) | ControlError::Identifier) => ExitCode::from(2),
        Err(_) => ExitCode::FAILURE,
    }
}
