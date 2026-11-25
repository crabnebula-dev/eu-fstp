//! The restore drill status file (ADR-012 record of lane
//! m10/backup-health).
//!
//! `fstp-admin drill` rewrites `drill.status` in the admin state
//! directory after each drill, and `fstp-admin status` reads it. It holds
//! one line:
//!
//! ```text
//! file = "v1" SP last_try SP last_pass SP step SP seconds LF
//! step = "none" / "space" / "restore" / "recovery" / "database"
//!        / "keystore" / "chain" / "cleanup" / "witness"
//! ```
//!
//! `last_try` and `last_pass` are Unix seconds in decimal, with no sign
//! and no leading zero, and `0` means never. `step` is where the last try
//! failed, `none` when it passed or none ran. `seconds` is the restore
//! duration of the last passed drill, `0` when none passed. [`decode`]
//! admits exactly the files [`encode`] writes, so one state has one
//! spelling:
//!
//! - no try: `v1 0 0 none 0`;
//! - a last try that passed: `last_pass` equals `last_try`;
//! - a last try that failed: a step, and `last_pass` before `last_try` or
//!   never;
//! - `seconds` is at least 1 exactly when a drill passed.
//!
//! It is fuzzed (`drill_status_decode`). A refusal names the rule, never
//! a byte of the input (R-NF-02).

use std::io::Write as _;
use std::path::Path;

/// The file's name in the admin state directory.
pub const FILE: &str = "drill.status";

/// The longest file accepted, in bytes.
pub const MAX_LEN: usize = 64;

/// The latest instant accepted, 9999-12-31T23:59:59Z in Unix seconds.
pub const MAX_INSTANT: u64 = 253_402_300_799;

/// The longest restore duration accepted, in seconds: 115 days.
pub const MAX_SECONDS: u64 = 9_999_999;

/// Seconds after the last passed drill before the next one is due: 35
/// days, so the monthly timer has five days of slack. Interim, pending
/// Daniel.
pub const DUE_AFTER: u64 = 35 * 24 * 3600;

/// The step where a drill failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Step {
    /// The scratch location lacks room for the restored cluster.
    Space,
    /// `fstp-backup restore` failed.
    Restore,
    /// The throwaway server did not start or did not finish recovery.
    Recovery,
    /// The cell database is missing or does not answer.
    Database,
    /// The restored keystore rows do not open.
    Keystore,
    /// The restored audit chain does not verify against fetched witness
    /// copies, or the copies did not fetch (ADR-012 record of lane
    /// m10/drill-chain).
    Chain,
    /// The throwaway server did not stop, or the scratch directory did
    /// not go.
    Cleanup,
    /// The witness copies did not fetch, did not load, or are not a prefix
    /// of the live witness store (ADR-012 record of lane m10/witness-copy).
    Witness,
}

impl Step {
    /// Every step.
    pub const ALL: [Step; 8] = [
        Self::Space,
        Self::Restore,
        Self::Recovery,
        Self::Database,
        Self::Keystore,
        Self::Chain,
        Self::Cleanup,
        Self::Witness,
    ];

    /// The word in the file.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Space => "space",
            Self::Restore => "restore",
            Self::Recovery => "recovery",
            Self::Database => "database",
            Self::Keystore => "keystore",
            Self::Chain => "chain",
            Self::Cleanup => "cleanup",
            Self::Witness => "witness",
        }
    }
}

/// What the file says.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DrillStatus {
    /// When a drill last ran, in Unix seconds.
    pub last_try: Option<u64>,
    /// When a drill last passed, in Unix seconds.
    pub last_pass: Option<u64>,
    /// Where the last try failed, if it failed.
    pub failed: Option<Step>,
    /// The restore duration of the last passed drill, in seconds.
    pub seconds: Option<u64>,
}

impl DrillStatus {
    /// The status after a drill passed at `now` in `seconds`.
    #[must_use]
    pub fn after_pass(self, now: u64, seconds: u64) -> DrillStatus {
        let now = now.min(MAX_INSTANT);
        DrillStatus {
            last_try: Some(now),
            last_pass: Some(now),
            failed: None,
            seconds: Some(seconds.clamp(1, MAX_SECONDS)),
        }
    }

    /// The status after a drill failed at `now` in `step`.
    #[must_use]
    pub fn after_fail(self, now: u64, step: Step) -> DrillStatus {
        let now = now.min(MAX_INSTANT);
        DrillStatus {
            last_try: Some(now),
            last_pass: self.last_pass.map(|p| p.min(now)),
            failed: Some(step),
            seconds: self.seconds,
        }
    }

    /// Whether a drill is due at `now`: the last one failed, none passed,
    /// or the last pass is older than [`DUE_AFTER`].
    #[must_use]
    pub fn due(&self, now: u64) -> bool {
        self.failed.is_some()
            || self
                .last_pass
                .is_none_or(|p| now.saturating_sub(p) > DUE_AFTER)
    }
}

/// Why a status file was refused. It names the rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DrillStatusError(pub &'static str);

fn number(text: &str, max: u64) -> Result<u64, DrillStatusError> {
    let bad = DrillStatusError("number");
    if text.is_empty()
        || text.len() > 12
        || !text.bytes().all(|b| b.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0'))
    {
        return Err(bad);
    }
    let n: u64 = text.parse().map_err(|_| bad)?;
    if n > max {
        return Err(bad);
    }
    Ok(n)
}

/// Decodes a status file (module documentation).
///
/// # Errors
///
/// [`DrillStatusError`] naming the rule broken.
pub fn decode(bytes: &[u8]) -> Result<DrillStatus, DrillStatusError> {
    if bytes.len() > MAX_LEN {
        return Err(DrillStatusError("length"));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| DrillStatusError("text"))?;
    let line = text
        .strip_suffix('\n')
        .ok_or(DrillStatusError("line end"))?;
    let mut f = line.split(' ');
    if f.next() != Some("v1") {
        return Err(DrillStatusError("version"));
    }
    let mut next = || f.next().ok_or(DrillStatusError("fields"));
    let last_try = number(next()?, MAX_INSTANT)?;
    let last_pass = number(next()?, MAX_INSTANT)?;
    let step = next()?;
    let failed = match step {
        "none" => None,
        w => Some(
            Step::ALL
                .iter()
                .copied()
                .find(|s| s.word() == w)
                .ok_or(DrillStatusError("step"))?,
        ),
    };
    let seconds = number(next()?, MAX_SECONDS)?;
    if f.next().is_some() {
        return Err(DrillStatusError("fields"));
    }
    let consistent = match (last_try, failed) {
        (0, None) => last_pass == 0,
        (0, Some(_)) => false,
        (t, None) => last_pass == t,
        (t, Some(_)) => last_pass <= t,
    } && ((last_pass == 0) == (seconds == 0));
    if !consistent {
        return Err(DrillStatusError("consistency"));
    }
    let opt = |n: u64| (n != 0).then_some(n);
    Ok(DrillStatus {
        last_try: opt(last_try),
        last_pass: opt(last_pass),
        failed,
        seconds: opt(seconds),
    })
}

/// Encodes a status file.
#[must_use]
pub fn encode(s: &DrillStatus) -> String {
    format!(
        "v1 {} {} {} {}\n",
        s.last_try.unwrap_or(0).min(MAX_INSTANT),
        s.last_pass.unwrap_or(0).min(MAX_INSTANT),
        s.failed.map_or("none", Step::word),
        s.seconds.unwrap_or(0).min(MAX_SECONDS),
    )
}

/// Reads the status file of `dir`. A missing or refused file reads as no
/// drill.
#[must_use]
pub fn read(dir: &Path) -> DrillStatus {
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
pub fn write(dir: &Path, s: &DrillStatus) -> std::io::Result<()> {
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

/// The longest check line accepted, in bytes.
pub const MAX_CHECK_LEN: usize = 160;

/// The largest count a check line carries.
pub const MAX_COUNT: u64 = 999_999_999_999_999;

/// What `fstp-cell check-chain` and `fstp-vault check-chain` found
/// (ADR-012 record of lane m10/drill-chain, row "Check line"). They print
/// it as one line on standard output, and the drill reads it:
///
/// ```text
/// line = "v1" SP rows SP checked SP later SP oldest_later SP oldest_newer
///        SP lost SP doubt LF
/// ```
///
/// Each field is a decimal without a leading zero. The times are Unix
/// seconds, 0 exactly when their tail is empty. [`decode_chain_check`]
/// admits exactly the lines [`encode_chain_check`] writes. Fuzzed
/// (`drill_chain_check_decode`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ChainCheck {
    /// The restored rows.
    pub rows: u64,
    /// The rows up to the head in common with the witness copies.
    pub checked: u64,
    /// The receipts of the copies after the restored head.
    pub later: u64,
    /// The witness time of the oldest of them, Unix seconds.
    pub oldest_later: Option<u64>,
    /// The witness time of the oldest stored receipt of a row beyond the
    /// copies, Unix seconds.
    pub oldest_newer: Option<u64>,
    /// The windows lost in declared restores.
    pub lost: u64,
    /// The possible deletions.
    pub doubt: u64,
}

impl ChainCheck {
    /// The rows beyond the copies.
    #[must_use]
    pub fn newer(&self) -> u64 {
        self.rows.saturating_sub(self.checked)
    }
}

/// The Unix seconds of a witness time in UTC microseconds, at least 1 so
/// that 0 keeps meaning none, and at most [`MAX_INSTANT`].
#[must_use]
pub fn instant_of_micros(us: i64) -> u64 {
    u64::try_from(us.div_euclid(1_000_000))
        .unwrap_or(0)
        .clamp(1, MAX_INSTANT)
}

/// Encodes a check line ([`ChainCheck`]).
#[must_use]
pub fn encode_chain_check(c: &ChainCheck) -> String {
    let rows = c.rows.min(MAX_COUNT);
    let checked = c.checked.min(rows);
    let later = c.later.min(MAX_COUNT);
    let time = |t: Option<u64>, some: bool| {
        if some {
            t.unwrap_or(1).clamp(1, MAX_INSTANT)
        } else {
            0
        }
    };
    format!(
        "v1 {rows} {checked} {later} {} {} {} {}\n",
        time(c.oldest_later, later > 0),
        time(c.oldest_newer, checked < rows),
        c.lost.min(MAX_COUNT),
        c.doubt.min(MAX_COUNT),
    )
}

fn count_field(text: &str, max: u64) -> Result<u64, DrillStatusError> {
    let bad = DrillStatusError("number");
    if text.is_empty()
        || text.len() > 15
        || !text.bytes().all(|b| b.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0'))
    {
        return Err(bad);
    }
    let n: u64 = text.parse().map_err(|_| bad)?;
    if n > max {
        return Err(bad);
    }
    Ok(n)
}

/// Decodes a check line ([`ChainCheck`]).
///
/// # Errors
///
/// [`DrillStatusError`] naming the rule broken, never a byte of the input
/// (R-NF-02).
pub fn decode_chain_check(bytes: &[u8]) -> Result<ChainCheck, DrillStatusError> {
    if bytes.len() > MAX_CHECK_LEN {
        return Err(DrillStatusError("length"));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| DrillStatusError("text"))?;
    let line = text
        .strip_suffix('\n')
        .ok_or(DrillStatusError("line end"))?;
    let mut f = line.split(' ');
    if f.next() != Some("v1") {
        return Err(DrillStatusError("version"));
    }
    let mut next = || f.next().ok_or(DrillStatusError("fields"));
    let rows = count_field(next()?, MAX_COUNT)?;
    let checked = count_field(next()?, MAX_COUNT)?;
    let later = count_field(next()?, MAX_COUNT)?;
    let oldest_later = count_field(next()?, MAX_INSTANT)?;
    let oldest_newer = count_field(next()?, MAX_INSTANT)?;
    let lost = count_field(next()?, MAX_COUNT)?;
    let doubt = count_field(next()?, MAX_COUNT)?;
    if f.next().is_some() {
        return Err(DrillStatusError("fields"));
    }
    let consistent = checked <= rows
        && ((later > 0) == (oldest_later != 0))
        && ((checked < rows) == (oldest_newer != 0));
    if !consistent {
        return Err(DrillStatusError("consistency"));
    }
    let opt = |n: u64| (n != 0).then_some(n);
    Ok(ChainCheck {
        rows,
        checked,
        later,
        oldest_later: opt(oldest_later),
        oldest_newer: opt(oldest_newer),
        lost,
        doubt,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    /// ADR-012 record of lane m10/backup-health, row "Drill status file":
    /// each state round trips in one spelling, every other spelling is
    /// refused, and a drill is due after a failure, without a pass, or 35
    /// days after the last pass.
    #[test]
    fn adr012_bh_drill_status_round_trips_in_one_spelling() {
        let none = DrillStatus::default();
        assert_eq!(encode(&none), "v1 0 0 none 0\n");
        let passed = none.after_pass(1_795_000_000, 412);
        assert_eq!(encode(&passed), "v1 1795000000 1795000000 none 412\n");
        let failed = passed.after_fail(1_797_000_000, Step::Keystore);
        assert_eq!(encode(&failed), "v1 1797000000 1795000000 keystore 412\n");
        let never = none.after_fail(5, Step::Space);
        assert_eq!(encode(&never), "v1 5 0 space 0\n");
        for s in [
            none,
            passed,
            failed,
            never,
            failed.after_pass(1_798_000_000, 0),
        ] {
            assert_eq!(decode(encode(&s).as_bytes()), Ok(s), "{s:?}");
        }
        for step in Step::ALL {
            let s = none.after_fail(9, step);
            assert_eq!(decode(encode(&s).as_bytes()), Ok(s));
        }
        for bad in [
            "",
            "v1 0 0 none 0",
            "v1 0 0 none 0\n\n",
            "v2 0 0 none 0\n",
            "v1 0 0 none\n",
            "v1 0 0 none 0 0\n",
            "v1 00 0 none 0\n",
            "v1 1 1 none 0\n",
            "v1 2 1 none 5\n",
            "v1 0 0 space 0\n",
            "v1 1 2 space 5\n",
            "v1 1 0 space 5\n",
            "v1 1 1 none 10000000\n",
            "v1 1 1 later 3\n",
            "v1 1 1 None 3\n",
            "v1 253402300800 0 space 0\n",
            "v1  1 1 none 3\n",
            "v1 1 1 none 3\r\n",
        ] {
            assert!(decode(bad.as_bytes()).is_err(), "{bad:?}");
        }
        let day = 24 * 3600;
        assert!(none.due(1));
        assert!(!passed.due(1_795_000_000 + DUE_AFTER));
        assert!(passed.due(1_795_000_000 + DUE_AFTER + 1));
        assert!(failed.due(1_797_000_000 + day));
        assert!(never.due(6));
    }

    /// ADR-012 record of lane m10/drill-chain, rows "Check line" and
    /// "Status": the check line round trips in one spelling, every other
    /// spelling is refused, and the step `chain` has its word.
    #[test]
    fn adr012_dc_chain_check_line_round_trips_in_one_spelling() {
        let clean = ChainCheck {
            rows: 42,
            checked: 42,
            ..ChainCheck::default()
        };
        assert_eq!(encode_chain_check(&clean), "v1 42 42 0 0 0 0 0\n");
        let tails = ChainCheck {
            rows: 50,
            checked: 47,
            later: 2,
            oldest_later: Some(1_795_000_100),
            oldest_newer: Some(1_795_000_050),
            lost: 1,
            doubt: 3,
        };
        assert_eq!(
            encode_chain_check(&tails),
            "v1 50 47 2 1795000100 1795000050 1 3\n"
        );
        assert_eq!(tails.newer(), 3);
        for c in [ChainCheck::default(), clean, tails] {
            assert_eq!(decode_chain_check(encode_chain_check(&c).as_bytes()), Ok(c));
        }
        for bad in [
            "",
            "v1 1 1 0 0 0 0 0",
            "v2 1 1 0 0 0 0 0\n",
            "v1 1 1 0 0 0 0\n",
            "v1 1 1 0 0 0 0 0 0\n",
            "v1 01 1 0 0 0 0 0\n",
            "v1 1 2 0 0 0 0 0\n",
            "v1 2 1 0 0 0 0 0\n",
            "v1 1 1 0 0 5 0 0\n",
            "v1 1 1 1 0 0 0 0\n",
            "v1 1 1 0 7 0 0 0\n",
            "v1 1 1 0 253402300800 0 0 0\n",
            "v1 1000000000000000 1 0 0 1 0 0\n",
            "v1 -1 1 0 0 0 0 0\n",
            "v1  1 1 0 0 0 0 0\n",
            "v1 1 1 0 0 0 0 0\r\n",
        ] {
            assert!(decode_chain_check(bad.as_bytes()).is_err(), "{bad:?}");
        }
        assert_eq!(instant_of_micros(1_795_000_000_999_999), 1_795_000_000);
        assert_eq!(instant_of_micros(0), 1);
        assert_eq!(instant_of_micros(-5), 1);
        assert_eq!(instant_of_micros(i64::MAX), MAX_INSTANT);
        let s = DrillStatus::default().after_fail(9, Step::Chain);
        assert_eq!(encode(&s), "v1 9 0 chain 0\n");
        assert_eq!(decode(b"v1 9 0 chain 0\n"), Ok(s));
    }

    /// ADR-012 record of lane m10/backup-health: a written status reads
    /// back.
    #[test]
    fn adr012_bh_drill_status_writes_and_reads_back() {
        let dir = std::env::temp_dir().join(format!(
            "fstp-obs-drillstatus-{}-{}",
            std::process::id(),
            crate::snapshot_status::now()
        ));
        assert_eq!(read(&dir), DrillStatus::default());
        let s = DrillStatus::default().after_pass(100, 7);
        write(&dir, &s).unwrap();
        assert_eq!(read(&dir), s);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
