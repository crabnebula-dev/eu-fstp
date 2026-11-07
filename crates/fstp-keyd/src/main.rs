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
//!
//! It starts on any host (I-81 NOTE of 2026-11-01). It logs the I-81
//! assurance of the key volume in its start event: full only on a Linux
//! ext4 or XFS volume, reduced with the reason anywhere else. In
//! development mode (`FSTP_DEPLOYMENT_MODE`) no host check stops a start:
//! a missing key volume or socket directory is replaced by a fresh
//! temporary one, and a missing passphrase by an ephemeral one, each
//! with a warning event.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use fstp_keyd::{ClientRole, ClientSocket, KeydError, PassphraseSource, VolumeOrigin};
use fstp_obs::LogEvent;
use fstp_obs::assurance::{DeploymentMode, HostCheck, deployment_mode_from_env};

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

/// The sockets of this host under `run_dir`, or `None` when a group
/// variable is not a group id.
fn layout(run_dir: &Path) -> Option<Vec<ClientSocket>> {
    let mut out = Vec::new();
    for role in ClientRole::ALL {
        let path = run_dir.join(format!("{}.sock", role.name()));
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

/// A fresh directory `leaf` under this process's temporary directory,
/// readable by its owner only.
fn temporary_dir(leaf: &str) -> Result<PathBuf, KeydError> {
    let dir = std::env::temp_dir()
        .join(format!("fstp-keyd-{}", std::process::id()))
        .join(leaf);
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder
        .create(&dir)
        .map_err(|_| KeydError::Io("the temporary directory"))?;
    Ok(dir)
}

/// `named` when it is a directory. Otherwise, in development mode only,
/// a fresh temporary directory, with the warning `check`.
fn dir_or_temporary(
    named: &str,
    leaf: &str,
    mode: DeploymentMode,
    check: HostCheck,
) -> Result<(PathBuf, bool), KeydError> {
    let path = PathBuf::from(named);
    if path.is_dir() || mode == DeploymentMode::Production {
        return Ok((path, false));
    }
    let dir = temporary_dir(leaf)?;
    let _ = fstp_obs::log_to_stderr(&LogEvent::HostCheckWarned { check });
    Ok((dir, true))
}

fn run() -> Result<(), KeydError> {
    let mode = deployment_mode_from_env().map_err(KeydError::Mode)?.mode;
    let (volume, temporary) =
        dir_or_temporary(KEY_VOLUME, "keys", mode, HostCheck::KeyVolumeTemporary)?;
    let (run_dir, _) = dir_or_temporary(RUN_DIR, "run", mode, HostCheck::SocketDirTemporary)?;
    let sockets = layout(&run_dir).ok_or(KeydError::Io("a group variable is not a group id"))?;
    let origin = if temporary {
        VolumeOrigin::Temporary
    } else {
        VolumeOrigin::Named
    };
    fstp_keyd::serve_sockets_from(&sockets, &volume, origin, PassphraseSource::CredentialOrAsk)
}

fn main() -> ExitCode {
    let _ = fstp_obs::log_to_stderr(&LogEvent::Started);
    if run().is_ok() {
        ExitCode::SUCCESS
    } else {
        // R-NF-02: a typed event, never the error text. fstp-obs has
        // no keyd refusal event yet (a lead change), so the shutdown
        // event stands in.
        let _ = fstp_obs::log_to_stderr(&LogEvent::ShuttingDown);
        ExitCode::FAILURE
    }
}
