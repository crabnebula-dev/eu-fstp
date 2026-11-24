//! The `fstp-witness` binary (M3 design section 2.3).
//!
//! It decodes the configuration named by `FSTP_WITNESS_CONFIG`, opens its
//! receipt key through its own `fstp-keyd` entry, and serves until
//! SIGTERM drains it (`fstp_witness::run`, lane F-CP).
//!
//! Two operator commands work on its receipt key file (ADR-004 record of
//! lane L16): `copy-key-file <out>` copies the sealed file off the host
//! and records the copy, and `retire-key-file-copy <id>` records that
//! every copy of an id is destroyed.
//!
//! Two install commands of a self-hosted witness (ADR-028, lane L19,
//! `fstp_witness::install`): `init-keys <dir>` creates the receipt key
//! file, and `register <cell> <cell-ca.pem> <app-anchor.pub>
//! <vault-anchor.pub>` registers a cell in the file store.
//!
//! One check-only command (ADR-028 record of lane `m10/witness-copy`):
//! `check-store <dir>` loads a file store as the witness does at start.

use std::path::Path;
use std::process::ExitCode;

use fstp_witness::WitnessError;

fn command(args: &[String]) -> Result<(), WitnessError> {
    match args {
        [] => fstp_witness::run(),
        [c, out] if c == "copy-key-file" => {
            fstp_witness::key_copy::run_copy(std::path::Path::new(out))
        }
        [c, id] if c == "retire-key-file-copy" => fstp_custody::copies::CopyId::parse(id)
            .ok_or(WitnessError::Config("arguments"))
            .and_then(fstp_witness::key_copy::run_retire),
        [c, dir] if c == "init-keys" => fstp_witness::install::init_keys(Path::new(dir)),
        [c, dir] if c == "check-store" => fstp_witness::install::check_store(Path::new(dir)),
        [c, cell, ca, app, vault] if c == "register" => {
            fstp_witness::install::register(cell, Path::new(ca), Path::new(app), Path::new(vault))
        }
        _ => Err(WitnessError::Config("arguments")),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match command(&args) {
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
