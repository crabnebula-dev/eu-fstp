//! The `fstp-keyd` binary (M3 design section 2.3, ADR-004 part 2 "File
//! custody" and "Access to `fstp-keyd`").
//!
//! It serves the key volume `/var/lib/fstp-keyd` on one socket per
//! client OS user, under `/run/fstp-keyd`:
//!
//! - `console.sock`, always, for root at the host console (mode 0600).
//! - `cell.sock`, `vault.sock`, `pgagent.sock`, `control.sock` and
//!   `witness.sock`, each only when its variable `FSTP_KEYD_GROUP_CELL`,
//!   `FSTP_KEYD_GROUP_VAULT`, `FSTP_KEYD_GROUP_PGAGENT`,
//!   `FSTP_KEYD_GROUP_CONTROL` or `FSTP_KEYD_GROUP_WITNESS` names the group
//!   id of that client's OS user. `control.sock` serves the pilot
//!   `fstp-control` (ADR-009 "Pilot route feed"), and `witness.sock` a
//!   self-hosted `fstp-witness` (ADR-028 "Witness custody"). The socket is handed to
//!   that group (mode 0660). The install
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
//!
//! Four operator commands work on a stopped entry (ADR-004 record of
//! lane L16): `export <volume> <file>` writes an off-host sealed copy,
//! `import <file> <volume>` writes it onto a fresh volume and holds it,
//! `release <volume> app=<e> vault=<e>` ends the hold, and
//! `retire-export <volume> <id>` records that a copy is destroyed.
//!
//! With a second custodian (ADR-004 record of lane `m10/guard-key`),
//! `export` seals the copy to the entry's guard and `import` asks the
//! custodian to open it. `guard-check <volume>` exits 0 when the custodian
//! answers and nothing is owed, 3 when a rotation is owed, 6 when a fresh
//! copy is owed to the custodian, 4 when the custodian does not answer
//! and 5 when none is configured. `fetch-copy <file>` writes the
//! custodian's held copy of the entry (ADR-004 "The custodian's copy").

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use fstp_keyd::export::{self, Command};
use fstp_keyd::guard::link::{GuardSetup, setup_from_env};
use fstp_keyd::guard::{self, GuardFault};
use fstp_keyd::{ClientRole, ClientSocket, KeydError, Passphrase, PassphraseSource, VolumeOrigin};
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
        ClientRole::Control => Some("FSTP_KEYD_GROUP_CONTROL"),
        ClientRole::Witness => Some("FSTP_KEYD_GROUP_WITNESS"),
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

/// Runs one operator command on a key volume (ADR-004 record of lane
/// L16). The passphrase comes from the systemd credential, or else from
/// the operator through `systemd-ask-password`, as for a start. The
/// commands write typed events only (R-NF-02). A copy's id stands in
/// clear in bytes 26 to 41 of its header, for `retire-export`.
fn operator(command: &Command) -> Result<(), KeydError> {
    use std::io::Write as _;
    let passphrase = || Passphrase::from_credentials_or_ask();
    // ADR-004 record of lane `m10/guard-key`: the custodian of a pilot
    // entry, from the same variables and credentials as a start.
    let link = || match setup_from_env()? {
        GuardSetup::Pilot(link) => Ok(Some(link)),
        GuardSetup::None => Ok(None),
        GuardSetup::Custodian(_) => Err(KeydError::Volume(
            "a custodian's key volume is never copied or imported",
        )),
    };
    let development = deployment_mode_from_env()
        .map(|c| c.mode == DeploymentMode::Development)
        .unwrap_or(false);
    match command {
        Command::Serve | Command::GuardCheck { .. } | Command::FetchCopy { .. } => Ok(()),
        Command::Export { volume, file } => {
            let bytes = match link()? {
                Some(link) => export::export_guarded(volume, &passphrase()?, &link)?.1,
                // In production every copy is guarded (Daniel, 2026-11-23).
                // Development mode writes a plain copy (I-81 NOTE of
                // 2026-11-01), which the register reports until retired.
                None if development => export::export_volume(volume, &passphrase()?)?.1,
                None => return Err(KeydError::Guard(GuardFault::Unreachable)),
            };
            let mut out = std::fs::OpenOptions::new();
            out.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                out.mode(0o600);
            }
            let mut f = out
                .open(file)
                .map_err(|_| KeydError::Io("create the copy file"))?;
            f.write_all(&bytes)
                .and_then(|()| f.sync_all())
                .map_err(|_| KeydError::Io("write the copy file"))
        }
        Command::Import { file, volume } => {
            let meta = std::fs::metadata(file).map_err(|_| KeydError::Io("read the copy file"))?;
            if meta.len() > guard::copy::MAX_GUARDED_LEN as u64 {
                return Err(KeydError::Malformed("a copy is too long"));
            }
            let bytes = std::fs::read(file).map_err(|_| KeydError::Io("read the copy file"))?;
            // A plain copy predates the guard. Production refuses it, since
            // no guard can be destroyed for it (ADR-004, Q-F018-3, decided
            // by Daniel on 2026-11-24).
            let mode = if development {
                DeploymentMode::Development
            } else {
                DeploymentMode::Production
            };
            export::import_copy(&bytes, volume, &passphrase()?, link()?.as_ref(), mode).map(|_| ())
        }
        Command::Release { volume, current } => {
            export::release_import_guarded(volume, &passphrase()?, current, link()?)
        }
        Command::Retire { volume, id } => export::retire_export(volume, *id),
    }
}

/// The exit code of `guard-check` (ADR-028 record of lane
/// `m10/guard-key`). It reads the guard state without the volume's lock,
/// so it runs while the entry serves, and asks the custodian for the
/// current guard, which makes generation 1 at the first ask.
fn guard_check(volume: &Path) -> u8 {
    let link = match setup_from_env() {
        Ok(GuardSetup::Pilot(link)) => link,
        Ok(GuardSetup::None) => return 5,
        Ok(GuardSetup::Custodian(_)) | Err(_) => return 1,
    };
    let Ok(state) = guard::state::read_state(volume) else {
        return 1;
    };
    if link.client.public(link.entry).is_err() {
        return 4;
    }
    if state.owed.is_some() {
        3
    } else if state.copy_owed {
        6
    } else {
        0
    }
}

/// The exit code of `fetch-copy <file>` (ADR-028 record of lane
/// `m10/guard-key`, part 2): 0 when the custodian's held copy of this
/// entry is written to the new file `<file>` with mode 0600, 4 when the
/// custodian does not answer, 5 when none is configured, 7 when it holds
/// no copy, and 1 for any other failure.
fn fetch_copy(file: &Path) -> u8 {
    use std::io::Write as _;
    let link = match setup_from_env() {
        Ok(GuardSetup::Pilot(link)) => link,
        Ok(GuardSetup::None) => return 5,
        Ok(GuardSetup::Custodian(_)) | Err(_) => return 1,
    };
    let bytes = match link.client.fetch(link.entry) {
        Ok(b) => b,
        Err(GuardFault::Refused(fstp_custody::Refusal::UnknownRoot)) => return 7,
        Err(GuardFault::Refused(_)) => return 1,
        Err(GuardFault::Unreachable) => return 4,
    };
    let mut out = std::fs::OpenOptions::new();
    out.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        out.mode(0o600);
    }
    let written = out
        .open(file)
        .and_then(|mut f| f.write_all(&bytes).and_then(|()| f.sync_all()));
    if written.is_ok() { 0 } else { 1 }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = match export::parse_command(&args) {
        Ok(c) => c,
        Err(_) => return ExitCode::from(2),
    };
    if let Command::GuardCheck { volume } = &command {
        return ExitCode::from(guard_check(volume));
    }
    if let Command::FetchCopy { file } = &command {
        return ExitCode::from(fetch_copy(file));
    }
    if command != Command::Serve {
        return if operator(&command).is_ok() {
            ExitCode::SUCCESS
        } else {
            let _ = fstp_obs::log_to_stderr(&LogEvent::ShuttingDown);
            ExitCode::FAILURE
        };
    }
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
