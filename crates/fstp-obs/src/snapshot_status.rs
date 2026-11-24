//! The keystore snapshot status file (ADR-012 record of lane L27).
//!
//! Each serving process that takes keystore snapshots, `fstp-cell` and
//! `fstp-vault`, rewrites `keystore-snapshot.status` in its credentials
//! directory after each snapshot, step 5 of a rotation included.
//! `fstp-admin status` reads it. It holds two instants and, since lane
//! m10/backup-followups (ADR-012, row "Failure reason"), the step at
//! which the last failure failed:
//!
//! ```text
//! file = "v1" SP <last verified> SP <last failed> LF
//!      / "v2" SP <last verified> SP <last failed> SP <reason> LF
//! ```
//!
//! `<reason>` is one word of [`crate::SnapshotFailure`]. A file whose last
//! failure has no reason, or that never failed, keeps the `v1` form, so
//! each state has one spelling.
//!
//! Each instant is Unix seconds in decimal, with no sign and no leading
//! zero, and `0` means never. [`decode`] admits exactly this spelling, so
//! [`encode`] of a decoded file gives back its bytes. It is fuzzed
//! (`snapshot_status_decode`, in the fuzz project of `fstp-admin`). A
//! refusal names no byte of the input (R-NF-02).
//!
//! [`due`] says when the next daily snapshot runs: a minute after the
//! start, then every [`DAILY`] seconds, and [`RETRY`] seconds after a
//! failure.

use std::io::Write as _;
use std::path::Path;

/// The file's name in a credentials directory.
pub const FILE: &str = "keystore-snapshot.status";

/// The longest file accepted, in bytes.
pub const MAX_LEN: usize = 64;

/// The latest instant accepted, 9999-12-31T23:59:59Z in Unix seconds.
pub const MAX_INSTANT: u64 = 253_402_300_799;

/// Seconds between two daily snapshots.
pub const DAILY: u64 = 24 * 3600;

/// Seconds before a failed snapshot is tried again.
pub const RETRY: u64 = 3600;

/// Seconds after a start before the first daily snapshot.
pub const FIRST: u64 = 60;

/// What the file says.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SnapshotStatus {
    /// When a snapshot last verified, in Unix seconds, if ever.
    pub last_verified: Option<u64>,
    /// When a snapshot last failed, in Unix seconds, if ever.
    pub last_failed: Option<u64>,
    /// The step at which the last failure failed, if known.
    pub reason: Option<crate::SnapshotFailure>,
}

impl SnapshotStatus {
    /// Whether the newest try failed.
    #[must_use]
    pub fn failing(&self) -> bool {
        match (self.last_failed, self.last_verified) {
            (Some(f), Some(v)) => f > v,
            (Some(_), None) => true,
            (None, _) => false,
        }
    }

    /// The status after one more try at `now`: verified when `failure` is
    /// `None`, else failed at that step.
    #[must_use]
    pub fn after(self, failure: Option<crate::SnapshotFailure>, now: u64) -> SnapshotStatus {
        if failure.is_none() {
            SnapshotStatus {
                last_verified: Some(now),
                ..self
            }
        } else {
            SnapshotStatus {
                last_failed: Some(now),
                reason: failure,
                ..self
            }
        }
    }
}

/// Why a status file was refused. It names the rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatusError(pub &'static str);

fn instant(text: &str) -> Result<Option<u64>, StatusError> {
    let bad = StatusError("instant");
    if text.is_empty()
        || text.len() > 12
        || !text.bytes().all(|b| b.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0'))
    {
        return Err(bad);
    }
    let n: u64 = text.parse().map_err(|_| bad)?;
    if n > MAX_INSTANT {
        return Err(bad);
    }
    Ok((n != 0).then_some(n))
}

/// Decodes a status file (module documentation).
///
/// # Errors
///
/// [`StatusError`] naming the rule broken.
pub fn decode(bytes: &[u8]) -> Result<SnapshotStatus, StatusError> {
    if bytes.len() > MAX_LEN {
        return Err(StatusError("length"));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| StatusError("text"))?;
    let line = text.strip_suffix('\n').ok_or(StatusError("line end"))?;
    let mut parts = line.split(' ');
    let v2 = match parts.next() {
        Some("v1") => false,
        Some("v2") => true,
        _ => return Err(StatusError("version")),
    };
    let verified = instant(parts.next().ok_or(StatusError("fields"))?)?;
    let failed = instant(parts.next().ok_or(StatusError("fields"))?)?;
    let reason = if v2 {
        let word = parts.next().ok_or(StatusError("fields"))?;
        let r = crate::SnapshotFailure::from_word(word).ok_or(StatusError("reason"))?;
        // A reason names a failure that happened.
        if failed.is_none() {
            return Err(StatusError("reason"));
        }
        Some(r)
    } else {
        None
    };
    if parts.next().is_some() {
        return Err(StatusError("fields"));
    }
    Ok(SnapshotStatus {
        last_verified: verified,
        last_failed: failed,
        reason,
    })
}

/// Encodes a status file.
#[must_use]
pub fn encode(s: &SnapshotStatus) -> String {
    let verified = s.last_verified.unwrap_or(0).min(MAX_INSTANT);
    let failed = s.last_failed.unwrap_or(0).min(MAX_INSTANT);
    match s.reason {
        Some(r) if failed != 0 => format!("v2 {verified} {failed} {}\n", r.as_str()),
        _ => format!("v1 {verified} {failed}\n"),
    }
}

/// Reads the status file of `dir`. A missing or refused file reads as
/// never.
#[must_use]
pub fn read(dir: &Path) -> SnapshotStatus {
    std::fs::read(dir.join(FILE))
        .ok()
        .and_then(|b| decode(&b).ok())
        .unwrap_or_default()
}

/// Records one try at `now` in the status file of `dir`: written to a
/// temporary file, synced and renamed over the old one, mode 0600.
///
/// # Errors
///
/// The I/O error of the write or the rename.
pub fn record(
    dir: &Path,
    failure: Option<crate::SnapshotFailure>,
    now: u64,
) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let next = read(dir).after(failure, now);
    let tmp = dir.join(format!("{FILE}.tmp"));
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(encode(&next).as_bytes())?;
    f.sync_all()?;
    std::fs::rename(&tmp, dir.join(FILE))
}

/// Whether a daily snapshot is due at `now`, for a process that started at
/// `started` and last tried at `last_try`, which verified or not.
#[must_use]
pub fn due(started: u64, last_try: Option<(u64, bool)>, now: u64) -> bool {
    match last_try {
        None => now >= started.saturating_add(FIRST),
        Some((at, true)) => now >= at.saturating_add(DAILY),
        Some((at, false)) => now >= at.saturating_add(RETRY),
    }
}

/// The current time in Unix seconds.
#[must_use]
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    const F: Option<crate::SnapshotFailure> = Some(crate::SnapshotFailure::Fetch);

    /// ADR-012 record of lane L27, row "Status file": the file round trips
    /// in one spelling, and every other spelling is refused.
    #[test]
    fn adr012_snapshot_status_file_round_trips_in_one_spelling() {
        for s in [
            SnapshotStatus::default(),
            SnapshotStatus {
                last_verified: Some(1_795_000_000),
                last_failed: None,
                reason: None,
            },
            SnapshotStatus {
                last_verified: Some(5),
                last_failed: Some(MAX_INSTANT),
                reason: None,
            },
            SnapshotStatus {
                last_verified: Some(5),
                last_failed: Some(7),
                reason: Some(crate::SnapshotFailure::Database),
            },
        ] {
            let text = encode(&s);
            assert_eq!(decode(text.as_bytes()), Ok(s));
        }
        assert_eq!(encode(&SnapshotStatus::default()), "v1 0 0\n");
        for bad in [
            "",
            "v1 0 0",
            "v1 0 0\n\n",
            "v2 0 0\n",
            "v1 00 0\n",
            "v1 +1 0\n",
            "v1 1 0 0\n",
            "v1 1\n",
            "v1  1 0\n",
            "v1 999999999999 0\n",
            "v1 1 0\r\n",
            "V1 0 0\n",
        ] {
            assert!(decode(bad.as_bytes()).is_err(), "{bad:?}");
        }
        let failing = SnapshotStatus::default().after(None, 10).after(F, 20);
        assert!(failing.failing());
        assert!(!failing.after(None, 30).failing());
        assert!(SnapshotStatus::default().after(F, 1).failing());
        assert!(!SnapshotStatus::default().failing());
    }

    /// R-NF-02, ADR-012 record of lane m10/backup-followups, row "Failure
    /// reason": a failure records its step as one word of a closed list,
    /// in the `v2` form; a file with no reason keeps the `v1` form, so each
    /// state has one spelling. A verified try keeps the last failure's
    /// reason, and an unknown word or a reason without a failure is
    /// refused.
    #[test]
    fn adr012_bf_snapshot_status_names_the_failed_step() {
        for f in crate::SnapshotFailure::ALL {
            let s = SnapshotStatus::default().after(None, 10).after(Some(f), 20);
            let text = encode(&s);
            assert_eq!(text, format!("v2 10 20 {}\n", f.as_str()));
            assert_eq!(decode(text.as_bytes()), Ok(s));
            let later = s.after(None, 30);
            assert!(!later.failing());
            assert_eq!(later.reason, Some(f));
        }
        assert_eq!(
            encode(&SnapshotStatus::default().after(None, 3)),
            "v1 3 0\n"
        );
        for bad in [
            "v2 1 2\n",
            "v2 1 2 none\n",
            "v2 1 2 Fetch\n",
            "v2 1 0 fetch\n",
            "v2 1 2 fetch x\n",
            "v1 1 2 fetch\n",
        ] {
            assert!(decode(bad.as_bytes()).is_err(), "{bad:?}");
        }
    }

    /// ADR-012 record of lane L27, row "Daily snapshot": the first a
    /// minute after the start, then daily, and an hour after a failure.
    #[test]
    fn adr012_daily_snapshot_is_due_daily_and_retried_hourly() {
        let t = 1_000_000;
        assert!(!due(t, None, t + FIRST - 1));
        assert!(due(t, None, t + FIRST));
        assert!(!due(t, Some((t, true)), t + DAILY - 1));
        assert!(due(t, Some((t, true)), t + DAILY));
        assert!(!due(t, Some((t, false)), t + RETRY - 1));
        assert!(due(t, Some((t, false)), t + RETRY));
    }

    /// ADR-012 record of lane L27: a recorded try reads back, and a
    /// failure keeps the last verified instant.
    #[test]
    fn adr012_snapshot_status_records_each_try() {
        let dir = std::env::temp_dir().join(format!(
            "fstp-obs-snapstatus-{}-{}",
            std::process::id(),
            now()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(read(&dir), SnapshotStatus::default());
        record(&dir, None, 100).unwrap();
        record(&dir, F, 200).unwrap();
        let s = read(&dir);
        assert_eq!((s.last_verified, s.last_failed), (Some(100), Some(200)));
        assert!(s.failing());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
