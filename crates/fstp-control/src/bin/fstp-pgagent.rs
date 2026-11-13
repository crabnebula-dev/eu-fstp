//! The `fstp-pgagent` binary (M3 design section 2.3, ADR-011).
//!
//! It decodes the configuration named by `FSTP_PGAGENT_CONFIG` and serves
//! typed provisioning jobs from `fstp-control` through
//! `fstp_control::agent::run`, on the one tokio runtime behind `fstp_rt`,
//! until SIGTERM drains it.

use std::process::ExitCode;

use fstp_control::ControlError;

fn main() -> ExitCode {
    match fstp_control::agent::run() {
        Ok(()) => ExitCode::SUCCESS,
        // A refused configuration exits with the usage status. No event
        // names it, since `LogEvent` has no variant for it (R-NF-02).
        Err(ControlError::Config(_)) => ExitCode::from(2),
        Err(_) => ExitCode::FAILURE,
    }
}
