//! The `fstp-cell` binary (design section 2.3, ADR-026 "Configuration").
//!
//! It decodes the configuration file named by `FSTP_CELL_CONFIG` and runs
//! one command on the one tokio runtime behind `fstp_rt`
//! (`fstp_cell::run`):
//!
//! - no argument: serve the cell until SIGTERM or SIGINT drains it;
//! - `first-admin <file>`: record the first admin's invitation and write
//!   its token once to the new file (D4);
//! - `init-keys <dir>`: create the sealed cell key file at genesis and
//!   write the public keys the witness and the vault pin into `<dir>`;
//! - `copy-key-file <out>`: copy the sealed cell key file off the host and
//!   record the copy (ADR-004 record of lane L16);
//! - `retire-key-file-copy <id>`: record that every copy of `id` is
//!   destroyed.
//!
//! It writes typed events only (R-NF-02). A refused configuration or
//! argument exits with status 2, any other failure with status 1.

use std::process::ExitCode;

use fstp_cell::CellError;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let outcome = fstp_cell::run::parse_args(&args).and_then(|c| fstp_cell::run::run_command(&c));
    match outcome {
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
