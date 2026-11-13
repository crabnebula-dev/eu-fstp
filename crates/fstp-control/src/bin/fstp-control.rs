//! The `fstp-control` binary (M3 design section 2.3).
//!
//! It decodes the configuration named by `FSTP_CONTROL_CONFIG` and serves
//! the `CellToCp` listener through `fstp_control::service::run`, on the one
//! tokio runtime behind `fstp_rt`, until SIGTERM drains it.

use std::process::ExitCode;

use fstp_control::ControlError;

fn main() -> ExitCode {
    match fstp_control::service::run() {
        Ok(()) => ExitCode::SUCCESS,
        // A refused configuration exits with the usage status. No event
        // names it, since `LogEvent` has no variant for it (R-NF-02).
        Err(ControlError::Config(_)) => ExitCode::from(2),
        Err(_) => ExitCode::FAILURE,
    }
}
