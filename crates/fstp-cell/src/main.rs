//! The `fstp-cell` binary (design section 2.3).
//!
//! It decodes the configuration named by `FSTP_CELL_CONFIG` and serves the
//! cell through `fstp_cell::run`, on the one tokio runtime behind
//! `fstp_rt`, until SIGTERM drains it through `fstp_rt::Shutdown`. Until
//! the production store and witness transport land, `run` refuses after
//! the configuration decodes, and the binary logs `NotImplemented`.

use std::process::ExitCode;

use fstp_cell::CellError;

fn main() -> ExitCode {
    match fstp_cell::run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(CellError::NotImplemented(_)) => {
            // R-NF-02: a typed event, never the error text.
            let _ = fstp_obs::log_to_stderr(&fstp_obs::LogEvent::NotImplemented);
            ExitCode::FAILURE
        }
        // A refused configuration exits with the usage status. No event
        // names it, since `LogEvent` has no variant for it.
        Err(CellError::Config(_)) => ExitCode::from(2),
        Err(_) => ExitCode::FAILURE,
    }
}
