//! The `fstp-backup` binary (M3 design section 2.3, ADR-012 record of
//! lane L10).
//!
//! It decodes the configuration file named by `FSTP_BACKUP_CONFIG` and
//! runs one command (`fstp_backup::run`):
//!
//! - `init-keys`: create the ClusterBackup key file, as root, through the
//!   `fstp-keyd` console socket;
//! - `base-backup`: one base backup, from a timer;
//! - `wal-archive <path> <name>`: `archive_command`, `%p %f`;
//! - `wal-restore <name> <path>`: `restore_command`, `%f %p`;
//! - `restore <data dir> [<backup id> <size>] [--to <unix seconds>]`: a
//!   restore, as root, to the newest point or to a time;
//! - `custodian-init`: on a second custodian, as root, create its key
//!   and request (ADR-012 record of lane L16);
//! - `custodian-escrow <request> <out>`: on the first host, as root, seal
//!   the group secret to a second custodian.
//!
//! It writes no line of its own (R-NF-02). A refused configuration or
//! argument exits with status 2, a restore whose archive ends before its
//! target with status 3, and any other failure with status 1, which is
//! also what `restore_command` returns for a file the store lacks.

use std::process::ExitCode;

use fstp_backup::BackupError;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match fstp_backup::parse_args(&args).and_then(|c| fstp_backup::run(&c)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(BackupError::Config(_)) => ExitCode::from(2),
        // ADR-012 record of lane `m10/backup-pitr`: the archive holds no
        // change after the restore target.
        Err(BackupError::TargetNotReached) => ExitCode::from(3),
        Err(_) => ExitCode::FAILURE,
    }
}
