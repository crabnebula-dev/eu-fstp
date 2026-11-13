//! The `fstp-witness` binary (M3 design section 2.3).
//!
//! It decodes the configuration named by `FSTP_WITNESS_CONFIG`, opens its
//! receipt key through its own `fstp-keyd` entry, and serves until
//! SIGTERM drains it (`fstp_witness::run`, lane F-CP).

use std::process::ExitCode;

use fstp_witness::WitnessError;

fn main() -> ExitCode {
    match fstp_witness::run() {
        Ok(()) => ExitCode::SUCCESS,
        // A refused configuration exits with the usage status. No event
        // names it, since `LogEvent` has no variant for it.
        Err(WitnessError::Config(_)) => ExitCode::from(2),
        Err(WitnessError::NotImplemented(_)) => {
            // R-NF-02: a typed event, never the error text.
            let _ = fstp_obs::log_to_stderr(&fstp_obs::LogEvent::NotImplemented);
            ExitCode::FAILURE
        }
        Err(_) => ExitCode::FAILURE,
    }
}
