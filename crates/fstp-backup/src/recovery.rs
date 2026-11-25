//! The recovery settings of a restored data directory and the check run
//! before it is swapped in (ADR-012 record of lane `m10/backup-pitr`).
//!
//! Every restore uses PostgreSQL archive recovery: `recovery.signal`, and
//! the settings of [`settings`] in `postgresql.auto.conf`. The root-run
//! restore has already fetched every history file and segment into
//! `pg_wal`, so `restore_command` fails cleanly and PostgreSQL reads
//! `pg_wal`. Earlier lines of the same names are removed first, since a
//! base backup taken after a restore carries them ([`rewrite_auto_conf`],
//! fuzzed with `wal_history_decode`).
//!
//! [`check`] runs PostgreSQL once on the directory with
//! `recovery_target_action = 'shutdown'`. PostgreSQL exits 0 only once it
//! has reached the target, or with no target a consistent state, and it
//! never promotes there. The promotion happens at the real start, with the
//! cluster's own `archive_command`, so the new timeline's history file
//! reaches the archive.

use std::io::{Read as _, Write as _};
use std::path::Path;
use std::process::{Command, Stdio};

use crate::BackupError;

/// The settings file PostgreSQL reads last.
pub const AUTO_CONF: &str = "postgresql.auto.conf";
/// The file that asks for archive recovery.
pub const SIGNAL: &str = "recovery.signal";
/// The largest `postgresql.auto.conf` rewritten.
pub const MAX_AUTO_CONF_LEN: usize = 1024 * 1024;
/// The OS user that runs PostgreSQL on a host (ADR-028 "PostgreSQL").
pub const PG_OS_USER: &str = "postgres";
/// What PostgreSQL logs when the archive ends before the target.
pub const NOT_REACHED: &str = "recovery ended before configured recovery target was reached";

/// The settings a restore owns. Any earlier line of these names goes.
pub const NAMES: [&str; 6] = [
    "restore_command",
    "recovery_target",
    "recovery_target_time",
    "recovery_target_timeline",
    "recovery_target_action",
    "hot_standby",
];

/// Which run the settings are for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Run {
    /// The check before the swap: stop at the target and shut down.
    Check,
    /// The real start: stop at the target, or at the end, and promote.
    Final,
}

/// `YYYY-MM-DD HH:MM:SS+00` of `unix` seconds, the spelling
/// `recovery_target_time` takes.
#[must_use]
pub fn pg_time(unix: u64) -> String {
    let a = crate::sigv4::amz_date(unix);
    let p = |r: std::ops::Range<usize>| a.get(r).unwrap_or("00").to_owned();
    format!(
        "{}-{}-{} {}:{}:{}+00",
        p(0..4),
        p(4..6),
        p(6..8),
        p(9..11),
        p(11..13),
        p(13..15)
    )
}

/// The recovery settings of `run` for `target` (Unix seconds, `None` for
/// the newest point).
#[must_use]
pub fn settings(target: Option<u64>, run: Run) -> String {
    let mut s = String::from(
        "# Written by fstp-backup restore (ADR-012 record of lane m10/backup-pitr).\n\
         restore_command = 'false'\n\
         recovery_target_timeline = 'latest'\n\
         hot_standby = 'off'\n",
    );
    match (target, run) {
        (Some(t), Run::Check) => {
            s.push_str(&format!(
                "recovery_target_time = '{}'\nrecovery_target_action = 'shutdown'\n",
                pg_time(t)
            ));
        }
        (Some(t), Run::Final) => {
            s.push_str(&format!(
                "recovery_target_time = '{}'\nrecovery_target_action = 'promote'\n",
                pg_time(t)
            ));
        }
        (None, Run::Check) => {
            s.push_str("recovery_target = 'immediate'\nrecovery_target_action = 'shutdown'\n");
        }
        (None, Run::Final) => {}
    }
    s
}

/// The name a settings line sets, if it sets one.
fn line_name(line: &str) -> Option<&str> {
    let t = line.trim_start();
    if t.is_empty() || t.starts_with('#') {
        return None;
    }
    let end = t
        .find(|c: char| c == '=' || c.is_whitespace())
        .unwrap_or(t.len());
    t.get(..end)
}

/// `existing` without any line that sets one of [`NAMES`] (in any case),
/// then `settings`. Fuzzed (`wal_history_decode`).
///
/// # Errors
///
/// [`BackupError::Malformed`] for a file over [`MAX_AUTO_CONF_LEN`] or not
/// UTF-8.
pub fn rewrite_auto_conf(existing: &[u8], settings: &str) -> Result<String, BackupError> {
    if existing.len() > MAX_AUTO_CONF_LEN {
        return Err(BackupError::Malformed("auto.conf length"));
    }
    let text =
        std::str::from_utf8(existing).map_err(|_| BackupError::Malformed("auto.conf UTF-8"))?;
    let mut out = String::with_capacity(text.len().saturating_add(settings.len()));
    for line in text.lines() {
        let owned =
            line_name(line).is_some_and(|n| NAMES.iter().any(|m| m.eq_ignore_ascii_case(n)));
        if !owned {
            out.push_str(line);
            out.push('\n');
        }
    }
    out.push_str(settings);
    Ok(out)
}

/// Writes the settings of `run` for `target` into `data_dir`, and
/// `recovery.signal`. Existing files are rewritten in place, so they keep
/// their owner.
///
/// # Errors
///
/// [`BackupError::Io`] naming the file, and the errors of
/// [`rewrite_auto_conf`].
pub fn write(data_dir: &Path, target: Option<u64>, run: Run) -> Result<(), BackupError> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let path = data_dir.join(AUTO_CONF);
    let existing = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(_) => return Err(BackupError::Io("auto.conf")),
    };
    let text = rewrite_auto_conf(&existing, &settings(target, run))?;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)
        .map_err(|_| BackupError::Io("auto.conf"))?;
    f.write_all(text.as_bytes())
        .and_then(|()| f.sync_all())
        .map_err(|_| BackupError::Io("auto.conf"))?;
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(data_dir.join(SIGNAL))
        .map_err(|_| BackupError::Io("recovery.signal"))?;
    Ok(())
}

/// Whether this process runs as root.
fn is_root() -> bool {
    Command::new("id")
        .arg("-u")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .output()
        .is_ok_and(|o| o.stdout.trim_ascii() == b"0")
}

/// A free loopback port.
fn free_port() -> Result<u16, BackupError> {
    std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .map_err(|_| BackupError::Io("free port"))
}

/// Writes `log` to `<data dir>.check.log`, mode 0600, beside the
/// directory.
fn keep_log(data_dir: &Path, log: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut name = data_dir.as_os_str().to_owned();
    name.push(".check.log");
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(std::path::PathBuf::from(name))?;
    f.write_all(log)
}

/// The check before the swap (module documentation): PostgreSQL of
/// `pg_bindir` recovers `data_dir` to `target`, or to a consistent state,
/// and shuts down. Then the final settings are written. As root, the
/// directory goes to `postgres`, which runs the check. PostgreSQL's log of
/// the run is kept in `<data dir>.check.log`.
///
/// # Errors
///
/// [`BackupError::TargetNotReached`] when the archive ends before the
/// target, [`BackupError::Tool`] (`postgres`) for any other failed run,
/// and the errors of [`write`].
pub fn check(pg_bindir: &Path, data_dir: &Path, target: Option<u64>) -> Result<(), BackupError> {
    write(data_dir, target, Run::Check)?;
    let root = is_root();
    let program = pg_bindir.join("postgres");
    let mut cmd = if root {
        let ok = Command::new("chown")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .arg("-R")
            .arg(format!("{PG_OS_USER}:{PG_OS_USER}"))
            .arg(data_dir)
            .status()
            .is_ok_and(|s| s.success());
        if !ok {
            return Err(BackupError::Tool("chown"));
        }
        let mut c = Command::new("runuser");
        c.args(["-u", PG_OS_USER, "--"]).arg(&program);
        c
    } else {
        Command::new(&program)
    };
    let port = free_port()?;
    cmd.env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .arg("-D")
        .arg(data_dir)
        .args(["-c", "listen_addresses=127.0.0.1"])
        .arg("-c")
        .arg(format!("port={port}"))
        .args(["-c", "unix_socket_directories="])
        .args([
            "-c",
            "ssl=off",
            "-c",
            "archive_mode=off",
            "-c",
            "hot_standby=off",
        ])
        .args([
            "-c",
            "logging_collector=off",
            "-c",
            "log_destination=stderr",
        ])
        .args(["-c", "lc_messages=C"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|_| BackupError::Tool("postgres"))?;
    let mut log = Vec::new();
    if let Some(mut e) = child.stderr.take() {
        let _ = e.read_to_end(&mut log);
    }
    let status = child.wait().map_err(|_| BackupError::Tool("postgres"))?;
    // PostgreSQL's own lines go to a file beside the directory, for the
    // operator. They name locations, times and settings, never row
    // content, and this process writes no line of its own (R-NF-02).
    let _ = keep_log(data_dir, &log);
    if !status.success() {
        let reached_end = log
            .windows(NOT_REACHED.len())
            .any(|w| w == NOT_REACHED.as_bytes());
        return Err(if reached_end {
            BackupError::TargetNotReached
        } else {
            BackupError::Tool("postgres")
        });
    }
    write(data_dir, target, Run::Final)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    /// ADR-012 record of lane `m10/backup-pitr`: the target time reaches
    /// PostgreSQL in UTC, the check run shuts down, the final run
    /// promotes, and with no target the check stops at consistency.
    #[test]
    fn adr012_pitr_recovery_settings_for_each_run() {
        assert_eq!(pg_time(1_795_514_400), "2026-11-24 10:00:00+00");
        assert_eq!(pg_time(0), "1970-01-01 00:00:00+00");
        let c = settings(Some(1_795_514_400), Run::Check);
        assert!(c.contains("recovery_target_time = '2026-11-24 10:00:00+00'\n"));
        assert!(c.contains("recovery_target_action = 'shutdown'\n"));
        assert!(c.contains("restore_command = 'false'\n"));
        assert!(c.contains("recovery_target_timeline = 'latest'\n"));
        let f = settings(Some(1_795_514_400), Run::Final);
        assert!(f.contains("recovery_target_action = 'promote'\n"));
        let n = settings(None, Run::Check);
        assert!(n.contains("recovery_target = 'immediate'\n"));
        let nf = settings(None, Run::Final);
        assert!(!nf.contains("recovery_target =") && !nf.contains("recovery_target_time ="));
        assert!(!nf.contains("recovery_target_action"));
    }

    /// ADR-012 record of lane `m10/backup-pitr`: a base backup taken
    /// after a restore carries the old settings. The rewrite drops every
    /// line a restore owns, in any case, and keeps the rest.
    #[test]
    fn adr012_pitr_recovery_settings_replace_earlier_ones() {
        let old = "# Do not edit this file manually!\n\
                   archive_timeout = '60'\n\
                   recovery_target_time = '2026-11-01 00:00:00+00'\n\
                   Restore_Command='false'\n  hot_standby = 'off'\n\
                   recovery_target_timeline_x = '1'\n";
        let out = rewrite_auto_conf(old.as_bytes(), &settings(None, Run::Final)).unwrap();
        assert!(out.contains("archive_timeout = '60'\n"));
        assert!(out.contains("recovery_target_timeline_x = '1'\n"));
        assert!(!out.contains("2026-11-01"));
        assert!(!out.contains("Restore_Command"));
        assert_eq!(out.matches("hot_standby").count(), 1);
        assert!(rewrite_auto_conf(&[0xff], "").is_err());
        assert!(rewrite_auto_conf(&vec![b'#'; MAX_AUTO_CONF_LEN + 1], "").is_err());
    }
}
