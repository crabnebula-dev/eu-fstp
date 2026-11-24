//! The `fstp-vault` binary (M3 design section 2.3, ADR-026 record of lane
//! L8).
//!
//! It decodes the configuration file named by `FSTP_VAULT_CONFIG` and runs
//! one command on the one tokio runtime behind `fstp_rt`
//! (`fstp_vault::run`):
//!
//! - no argument: serve the vault until SIGTERM or SIGINT drains it;
//! - `init-keys <dir>`: create the vault keystore at genesis and write the
//!   Vault chain anchor public key the witness registers into `<dir>`;
//! - `erase-identity <account>`: erase the identity of the account on the
//!   Vault chain, with the vault stopped (ADR-004 record of lane L11).
//! - `restore-keystore [<snapshot id>]`: after a restore of the vault
//!   cluster, keep the newest keystore copy that opens, with the vault
//!   stopped (ADR-012 record of lane L17).
//! - `check-keystore <port>`: the restore drill's check that the keystore
//!   rows of a scratch cluster at `port` open; it writes nothing (ADR-012
//!   record of lane m10/backup-health).
//!
//! It writes typed events only (R-NF-02). A refused configuration or
//! argument exits with status 2, any other failure with status 1.

use std::process::ExitCode;

use fstp_vault::VaultError;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let outcome = fstp_vault::run::parse_args(&args).and_then(|c| fstp_vault::run::run_command(&c));
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(VaultError::NotImplemented(_)) => {
            // R-NF-02: a typed event, never the error text.
            let _ = fstp_obs::log_to_stderr(&fstp_obs::LogEvent::NotImplemented);
            ExitCode::FAILURE
        }
        // A refused configuration exits with the usage status. No event
        // names it, since `LogEvent` has no variant for it.
        Err(VaultError::Config(_)) => ExitCode::from(2),
        Err(_) => ExitCode::FAILURE,
    }
}
