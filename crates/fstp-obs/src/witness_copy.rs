//! The witness copy status file (ADR-012 record of lane
//! m10/witness-copy, row "Health").
//!
//! `fstp-admin witness-copy` rewrites `witness-copy.status` in the admin
//! state directory after each run of `fstp-backup witness-archive`, and
//! `fstp-admin status` reads it. It holds one line:
//!
//! ```text
//! file    = "v1" SP last_try SP last_success SP last_failure SP outcome LF
//! outcome = "none" / "ok" / "failed"
//! ```
//!
//! Times are Unix seconds in decimal, with no sign and no leading zero,
//! and `0` means never. [`decode`] admits exactly the files [`encode`]
//! writes:
//!
//! - no run: `v1 0 0 0 none`;
//! - `last_try` is the later of the two other times;
//! - `ok` when the last run succeeded, so `last_success` equals
//!   `last_try`, and `failed` when it failed, so `last_failure` does.
//!
//! It is fuzzed (`witness_copy_status_decode`). A refusal names the rule,
//! never a byte of the input (R-NF-02).

use std::io::Write as _;
use std::path::Path;

use crate::host_status::WalArchive;

/// The file's name in the admin state directory.
pub const FILE: &str = "witness-copy.status";

/// The longest file accepted, in bytes.
pub const MAX_LEN: usize = 64;

/// The latest instant accepted, 9999-12-31T23:59:59Z in Unix seconds.
pub const MAX_INSTANT: u64 = 253_402_300_799;

/// Seconds after the last successful run before the copy is late: 10
/// minutes, ten runs of the timer. Interim, pending Daniel.
pub const LATE_AFTER: u64 = 600;

/// What the file says.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WitnessCopyStatus {
    /// When a run last ended, in Unix seconds.
    pub last_try: Option<u64>,
    /// When a run last succeeded.
    pub last_success: Option<u64>,
    /// When a run last failed.
    pub last_failure: Option<u64>,
    /// Whether the last run failed.
    pub failed: bool,
}

impl WitnessCopyStatus {
    /// The status after a run that succeeded at `now`.
    #[must_use]
    pub fn after_success(self, now: u64) -> WitnessCopyStatus {
        let now = now.min(MAX_INSTANT);
        WitnessCopyStatus {
            last_try: Some(now),
            last_success: Some(now),
            last_failure: self.last_failure.map(|t| t.min(now)),
            failed: false,
        }
    }

    /// The status after a run that failed at `now`.
    #[must_use]
    pub fn after_failure(self, now: u64) -> WitnessCopyStatus {
        let now = now.min(MAX_INSTANT);
        WitnessCopyStatus {
            last_try: Some(now),
            last_success: self.last_success.map(|t| t.min(now)),
            last_failure: Some(now),
            failed: true,
        }
    }

    /// The state at `now` (ADR-012 record of lane m10/witness-copy, row
    /// "Health"): `unknown` before the first run, `failing` after a failed
    /// run, `late` when no run succeeded in [`LATE_AFTER`] seconds, else
    /// `ok`.
    #[must_use]
    pub fn state(&self, now: u64) -> WalArchive {
        if self.last_try.is_none() {
            WalArchive::Unknown
        } else if self.failed {
            WalArchive::Failing
        } else if self
            .last_success
            .is_none_or(|t| now.saturating_sub(t) > LATE_AFTER)
        {
            WalArchive::Late
        } else {
            WalArchive::Ok
        }
    }
}

/// Why a status file was refused. It names the rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WitnessCopyStatusError(pub &'static str);

fn number(text: &str) -> Result<u64, WitnessCopyStatusError> {
    let bad = WitnessCopyStatusError("number");
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
    Ok(n)
}

/// Decodes a status file (module documentation).
///
/// # Errors
///
/// [`WitnessCopyStatusError`] naming the rule broken.
pub fn decode(bytes: &[u8]) -> Result<WitnessCopyStatus, WitnessCopyStatusError> {
    if bytes.len() > MAX_LEN {
        return Err(WitnessCopyStatusError("length"));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| WitnessCopyStatusError("text"))?;
    let line = text
        .strip_suffix('\n')
        .ok_or(WitnessCopyStatusError("line end"))?;
    let mut f = line.split(' ');
    if f.next() != Some("v1") {
        return Err(WitnessCopyStatusError("version"));
    }
    let mut next = || f.next().ok_or(WitnessCopyStatusError("fields"));
    let last_try = number(next()?)?;
    let success = number(next()?)?;
    let failure = number(next()?)?;
    let outcome = next()?;
    if f.next().is_some() {
        return Err(WitnessCopyStatusError("fields"));
    }
    let consistent = match outcome {
        "none" => last_try == 0 && success == 0 && failure == 0,
        "ok" => last_try != 0 && success == last_try && failure <= last_try,
        "failed" => last_try != 0 && failure == last_try && success <= last_try,
        _ => return Err(WitnessCopyStatusError("outcome")),
    };
    if !consistent {
        return Err(WitnessCopyStatusError("consistency"));
    }
    let opt = |n: u64| (n != 0).then_some(n);
    Ok(WitnessCopyStatus {
        last_try: opt(last_try),
        last_success: opt(success),
        last_failure: opt(failure),
        failed: outcome == "failed",
    })
}

/// Encodes a status file.
#[must_use]
pub fn encode(s: &WitnessCopyStatus) -> String {
    let outcome = match (s.last_try, s.failed) {
        (None, _) => "none",
        (Some(_), false) => "ok",
        (Some(_), true) => "failed",
    };
    format!(
        "v1 {} {} {} {outcome}\n",
        s.last_try.unwrap_or(0).min(MAX_INSTANT),
        s.last_success.unwrap_or(0).min(MAX_INSTANT),
        s.last_failure.unwrap_or(0).min(MAX_INSTANT),
    )
}

/// Reads the status file of `dir`. A missing or refused file reads as no
/// run.
#[must_use]
pub fn read(dir: &Path) -> WitnessCopyStatus {
    std::fs::read(dir.join(FILE))
        .ok()
        .and_then(|b| decode(&b).ok())
        .unwrap_or_default()
}

/// Writes `s` as the status file of `dir`: to a temporary file, synced
/// and renamed over the old one, mode 0600.
///
/// # Errors
///
/// The I/O error of the write or the rename.
pub fn write(dir: &Path, s: &WitnessCopyStatus) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::create_dir_all(dir)?;
    let tmp = dir.join(format!("{FILE}.tmp"));
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(encode(s).as_bytes())?;
    f.sync_all()?;
    std::fs::rename(&tmp, dir.join(FILE))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    /// ADR-012 record of lane m10/witness-copy, row "Health": each state
    /// round trips in one spelling, every other spelling is refused, and
    /// the rule reads unknown, failing, late and ok.
    #[test]
    fn adr012_wc_witness_copy_status_round_trips_in_one_spelling() {
        let none = WitnessCopyStatus::default();
        assert_eq!(encode(&none), "v1 0 0 0 none\n");
        let ok = none.after_success(1_795_000_000);
        assert_eq!(encode(&ok), "v1 1795000000 1795000000 0 ok\n");
        let failed = ok.after_failure(1_795_000_060);
        assert_eq!(
            encode(&failed),
            "v1 1795000060 1795000000 1795000060 failed\n"
        );
        let again = failed.after_success(1_795_000_060);
        assert_eq!(encode(&again), "v1 1795000060 1795000060 1795000060 ok\n");
        let never = none.after_failure(7);
        for s in [none, ok, failed, again, never] {
            assert_eq!(decode(encode(&s).as_bytes()), Ok(s), "{s:?}");
        }
        for bad in [
            "",
            "v1 0 0 0 none",
            "v2 0 0 0 none\n",
            "v1 0 0 0\n",
            "v1 0 0 0 none 0\n",
            "v1 1 0 0 none\n",
            "v1 0 0 0 ok\n",
            "v1 2 1 0 ok\n",
            "v1 2 2 3 ok\n",
            "v1 2 3 2 failed\n",
            "v1 2 2 1 failed\n",
            "v1 2 2 0 later\n",
            "v1 02 2 0 ok\n",
            "v1 253402300800 253402300800 0 ok\n",
            "v1  2 2 0 ok\n",
            "v1 2 2 0 ok\r\n",
        ] {
            assert!(decode(bad.as_bytes()).is_err(), "{bad:?}");
        }
        let t = 1_795_000_000;
        assert_eq!(none.state(t), WalArchive::Unknown);
        assert_eq!(ok.state(t + LATE_AFTER), WalArchive::Ok);
        assert_eq!(ok.state(t + LATE_AFTER + 1), WalArchive::Late);
        assert_eq!(failed.state(t + 60), WalArchive::Failing);
        assert_eq!(never.state(8), WalArchive::Failing);
        assert_eq!(again.state(t + 61), WalArchive::Ok);
    }

    /// ADR-012 record of lane m10/witness-copy: a written status reads
    /// back.
    #[test]
    fn adr012_wc_witness_copy_status_writes_and_reads_back() {
        let dir = std::env::temp_dir().join(format!(
            "fstp-obs-witnesscopy-{}-{}",
            std::process::id(),
            crate::snapshot_status::now()
        ));
        assert_eq!(read(&dir), WitnessCopyStatus::default());
        let s = WitnessCopyStatus::default().after_success(100);
        write(&dir, &s).unwrap();
        assert_eq!(read(&dir), s);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
