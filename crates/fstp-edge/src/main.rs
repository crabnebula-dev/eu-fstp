//! The `fstp-edge` binary (M3 design section 2.3, ADR-009 "Pilot edge
//! configuration"). It runs the pilot edge from the configuration file
//! named by `FSTP_EDGE_CONFIG` until SIGTERM or SIGINT (`fstp_edge::run`).
//!
//! It writes typed events only (R-NF-02). A refused configuration, route
//! file or credential exits with status 2, any other failure with status 1.

use std::process::ExitCode;

use fstp_edge::EdgeError;

fn main() -> ExitCode {
    match fstp_edge::run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(EdgeError::NotImplemented(_)) => {
            // R-NF-02: a typed event, never the error text.
            let _ = fstp_obs::log_to_stderr(&fstp_obs::LogEvent::NotImplemented);
            ExitCode::FAILURE
        }
        // A refused configuration exits with the usage status. No event
        // names it, since `LogEvent` has no variant for it.
        Err(EdgeError::Config(_)) => ExitCode::from(2),
        Err(_) => ExitCode::FAILURE,
    }
}
