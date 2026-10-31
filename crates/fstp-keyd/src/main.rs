//! The `fstp-keyd` binary (M3 design section 2.3, ADR-004 part 2 "File
//! custody" and "Access to `fstp-keyd`").
//!
//! It serves the key volume `/var/lib/fstp-keyd` on one socket per
//! client OS user, under `/run/fstp-keyd`:
//!
//! - `console.sock`, always, for root at the host console (mode 0600).
//! - `cell.sock`, `vault.sock` and `pgagent.sock`, each only when its
//!   variable `FSTP_KEYD_GROUP_CELL`, `FSTP_KEYD_GROUP_VAULT` or
//!   `FSTP_KEYD_GROUP_PGAGENT` names the group id of that client's OS
//!   user. The socket is handed to that group (mode 0660). The install
//!   sets the variables in the systemd unit and makes `fstp-keyd` a
//!   member of each group.
//!
//! The passphrase comes from the systemd credential
//! `fstp-keyd-passphrase`, or else from the operator through
//! `systemd-ask-password`. A refusal to start is logged as a typed
//! event, never as error text (R-NF-02). SIGTERM ends the process with
//! the default action: every write of `fstp-keyd` is fsynced before it
//! is answered, and the next start removes a stale socket.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use fstp_keyd::{ClientRole, ClientSocket, PassphraseSource};

/// The directory of the sockets.
const RUN_DIR: &str = "/run/fstp-keyd";
/// The key volume.
const KEY_VOLUME: &str = "/var/lib/fstp-keyd";

/// The variable that names the client group of `role`, if the role has
/// one. The console has none: it is for root only.
fn group_var(role: ClientRole) -> Option<&'static str> {
    match role {
        ClientRole::Cell => Some("FSTP_KEYD_GROUP_CELL"),
        ClientRole::Vault => Some("FSTP_KEYD_GROUP_VAULT"),
        ClientRole::PgAgent => Some("FSTP_KEYD_GROUP_PGAGENT"),
        ClientRole::Console => None,
    }
}

/// The sockets of this host, or `None` when a group variable is not a
/// group id.
fn layout() -> Option<Vec<ClientSocket>> {
    let mut out = Vec::new();
    for role in ClientRole::ALL {
        let path = PathBuf::from(RUN_DIR).join(format!("{}.sock", role.name()));
        match group_var(role) {
            None => out.push(ClientSocket::owner_only(&path, role)),
            Some(var) => match std::env::var(var) {
                Ok(text) => out.push(ClientSocket {
                    path,
                    role,
                    group: Some(text.trim().parse::<u32>().ok()?),
                }),
                Err(std::env::VarError::NotPresent) => {}
                Err(std::env::VarError::NotUnicode(_)) => return None,
            },
        }
    }
    Some(out)
}

fn main() -> ExitCode {
    let _ = fstp_obs::log_to_stderr(&fstp_obs::LogEvent::Started);
    let served = layout().is_some_and(|sockets| {
        fstp_keyd::serve_sockets(
            &sockets,
            Path::new(KEY_VOLUME),
            PassphraseSource::CredentialOrAsk,
        )
        .is_ok()
    });
    if served {
        ExitCode::SUCCESS
    } else {
        // R-NF-02: a typed event, never the error text. fstp-obs has
        // no keyd refusal event yet (a lead change), so the shutdown
        // event stands in.
        let _ = fstp_obs::log_to_stderr(&fstp_obs::LogEvent::ShuttingDown);
        ExitCode::FAILURE
    }
}
