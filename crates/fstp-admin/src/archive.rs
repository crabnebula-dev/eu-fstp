//! The health of the WAL archive of each cluster (ADR-012 record of lane
//! m10/backup-health, decided by Daniel on 2026-11-24).
//!
//! `status` and `report` read each cluster as the superuser, through
//! [`crate::pg::psql`]. [`QUERY`] returns one line:
//!
//! ```text
//! line = archived "|" last_archived "|" failed "|" last_failed "|" oldest_waiting
//! ```
//!
//! The counts and times of `pg_stat_archiver`, and the time of the oldest
//! finished segment that still waits for its upload (the oldest `.ready`
//! file of `pg_ls_archive_statusdir()`). Times are Unix seconds, and 0
//! means never or none. [`parse_row`] accepts five unsigned decimal
//! fields, with no sign, no leading zero and nothing else. It is fuzzed
//! (`archiver_row_decode`).
//!
//! [`state`] applies the rule: `failing` when the last failure is newer
//! than the last success, `late` when a finished segment has waited more
//! than [`LATE_AFTER`] seconds, else `ok`. A waiting segment is the test
//! of drift, not the age of the last success: an idle cluster archives
//! nothing, since PostgreSQL switches a segment only after WAL was
//! written.

use fstp_obs::host_status::{MAX_INSTANT, WalArchive};

use crate::layout::{Cluster, Layout};

/// The query of one cluster's archive facts (module documentation).
pub const QUERY: &str = "SELECT a.archived_count::text || '|' \
     || coalesce(floor(extract(epoch FROM a.last_archived_time))::bigint, 0)::text || '|' \
     || a.failed_count::text || '|' \
     || coalesce(floor(extract(epoch FROM a.last_failed_time))::bigint, 0)::text || '|' \
     || coalesce((SELECT floor(extract(epoch FROM min(s.modification)))::bigint \
        FROM pg_ls_archive_statusdir() s WHERE s.name LIKE '%.ready'), 0)::text \
     FROM pg_stat_archiver a;";

/// Seconds a finished segment may wait for its upload before the archive
/// counts as late. `archive_timeout` is 60 seconds. Interim, pending
/// Daniel.
pub const LATE_AFTER: i64 = 600;

/// The archive facts of one cluster.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Archiver {
    /// Segments archived since the statistics were reset.
    pub archived: u64,
    /// When the last segment was archived, in Unix seconds.
    pub last_archived: Option<i64>,
    /// Failed attempts since the statistics were reset.
    pub failed: u64,
    /// When the last attempt failed, in Unix seconds.
    pub last_failed: Option<i64>,
    /// When the oldest segment still waiting for its upload was finished.
    pub oldest_waiting: Option<i64>,
}

fn number(field: &str) -> Option<u64> {
    if field.is_empty()
        || field.len() > 20
        || !field.bytes().all(|b| b.is_ascii_digit())
        || (field.len() > 1 && field.starts_with('0'))
    {
        return None;
    }
    field.parse().ok()
}

fn instant(field: &str) -> Option<Option<i64>> {
    let n = i64::try_from(number(field)?).ok()?;
    if n > MAX_INSTANT {
        return None;
    }
    Some((n != 0).then_some(n))
}

/// Parses the one line of [`QUERY`] (module documentation). Fuzzed
/// (`archiver_row_decode`).
#[must_use]
pub fn parse_row(line: &str) -> Option<Archiver> {
    let mut f = line.split('|');
    let a = Archiver {
        archived: number(f.next()?)?,
        last_archived: instant(f.next()?)?,
        failed: number(f.next()?)?,
        last_failed: instant(f.next()?)?,
        oldest_waiting: instant(f.next()?)?,
    };
    if f.next().is_some() {
        return None;
    }
    Some(a)
}

/// The line of `a`, as [`QUERY`] writes it.
#[must_use]
pub fn row_text(a: &Archiver) -> String {
    format!(
        "{}|{}|{}|{}|{}",
        a.archived,
        a.last_archived.unwrap_or(0),
        a.failed,
        a.last_failed.unwrap_or(0),
        a.oldest_waiting.unwrap_or(0)
    )
}

impl Archiver {
    /// Whether the last attempt failed: a failure newer than the last
    /// success, or a failure and no success.
    #[must_use]
    pub fn failing(&self) -> bool {
        match (self.last_failed, self.last_archived) {
            (Some(f), Some(a)) => f > a,
            (Some(_), None) => true,
            (None, _) => false,
        }
    }

    /// Seconds the oldest waiting segment has waited at `now`.
    #[must_use]
    pub fn waited(&self, now: i64) -> Option<i64> {
        self.oldest_waiting.map(|t| now.saturating_sub(t).max(0))
    }
}

/// The state of one cluster's archive at `now`. `None` reads as unknown.
#[must_use]
pub fn state(a: Option<&Archiver>, now: i64) -> WalArchive {
    match a {
        None => WalArchive::Unknown,
        Some(a) if a.failing() => WalArchive::Failing,
        Some(a) if a.waited(now).is_some_and(|w| w > LATE_AFTER) => WalArchive::Late,
        Some(_) => WalArchive::Ok,
    }
}

/// Reads the archive facts of `c`, or `None` when the cluster does not
/// answer or answers out of the grammar.
#[must_use]
pub fn read(layout: &Layout, c: Cluster) -> Option<Archiver> {
    let out = crate::pg::psql(layout, c, "postgres", QUERY, "the WAL archive state").ok()?;
    parse_row(&out)
}

/// The archive facts of both clusters, in [`Cluster::ALL`] order. Empty
/// facts without backups, since the archive is off then.
#[must_use]
pub fn read_all(layout: &Layout) -> Vec<(Cluster, Option<Archiver>)> {
    if layout.cfg.backup.is_none() {
        return Vec::new();
    }
    Cluster::ALL
        .iter()
        .map(|c| (*c, read(layout, *c)))
        .collect()
}

/// The host's archive state at `now`: the worse of the clusters, and
/// `unknown` without backups.
#[must_use]
pub fn host_state(all: &[(Cluster, Option<Archiver>)], now: i64) -> WalArchive {
    if all.is_empty() {
        return WalArchive::Unknown;
    }
    all.iter()
        .map(|(_, a)| state(a.as_ref(), now))
        .fold(WalArchive::Ok, WalArchive::worst)
}

/// The older of the clusters' last archived segments, if each archived
/// one.
#[must_use]
pub fn oldest_last_archived(all: &[(Cluster, Option<Archiver>)]) -> Option<i64> {
    if all.is_empty() {
        return None;
    }
    all.iter()
        .map(|(_, a)| a.and_then(|a| a.last_archived))
        .try_fold(i64::MAX, |acc, t| t.map(|t| acc.min(t)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ADR-012 record of lane m10/backup-health, row "WAL archive facts":
    /// the line has five unsigned decimal fields in one spelling, and a
    /// parsed line writes back to the same text.
    #[test]
    fn adr012_bh_archiver_row_parses_one_spelling() {
        let a = parse_row("12|1795000000|3|1794990000|0").expect("a row");
        assert_eq!(
            a,
            Archiver {
                archived: 12,
                last_archived: Some(1_795_000_000),
                failed: 3,
                last_failed: Some(1_794_990_000),
                oldest_waiting: None,
            }
        );
        assert_eq!(row_text(&a), "12|1795000000|3|1794990000|0");
        assert_eq!(parse_row("0|0|0|0|0"), Some(Archiver::default()));
        for bad in [
            "",
            "0|0|0|0",
            "0|0|0|0|0|0",
            "01|0|0|0|0",
            "+1|0|0|0|0",
            "-1|0|0|0|0",
            "1|0|0|0|0\n",
            " 1|0|0|0|0",
            "1||0|0|0",
            "1|253402300800|0|0|0",
            "1|1.5|0|0|0",
            "99999999999999999999999|0|0|0|0",
            "a|0|0|0|0",
        ] {
            assert_eq!(parse_row(bad), None, "{bad:?}");
        }
    }

    /// ADR-012 record of lane m10/backup-health, row "WAL archive rule":
    /// a failure newer than the last success is failing, a segment that
    /// waited over ten minutes is late, an idle cluster is ok, and a
    /// cluster that does not answer is unknown.
    #[test]
    fn adr012_bh_archive_rule_reads_failing_late_and_ok() {
        let now = 1_795_000_000;
        let ok = Archiver {
            archived: 5,
            last_archived: Some(now - 86_400),
            ..Archiver::default()
        };
        assert_eq!(state(Some(&ok), now), WalArchive::Ok, "idle for a day");
        let failing = Archiver {
            failed: 1,
            last_failed: Some(now - 30),
            oldest_waiting: Some(now - 60),
            ..ok
        };
        assert_eq!(state(Some(&failing), now), WalArchive::Failing);
        let never = Archiver {
            failed: 1,
            last_failed: Some(now - 30),
            ..Archiver::default()
        };
        assert_eq!(state(Some(&never), now), WalArchive::Failing);
        let recovered = Archiver {
            last_failed: Some(now - 90_000),
            failed: 1,
            ..ok
        };
        assert_eq!(state(Some(&recovered), now), WalArchive::Ok);
        let hung = Archiver {
            oldest_waiting: Some(now - LATE_AFTER - 1),
            ..ok
        };
        assert_eq!(state(Some(&hung), now), WalArchive::Late);
        let busy = Archiver {
            oldest_waiting: Some(now - LATE_AFTER),
            ..ok
        };
        assert_eq!(state(Some(&busy), now), WalArchive::Ok);
        assert_eq!(state(None, now), WalArchive::Unknown);
        let all = [
            (Cluster::App, Some(ok)),
            (
                Cluster::Vault,
                Some(Archiver {
                    last_archived: Some(now - 10),
                    ..ok
                }),
            ),
        ];
        assert_eq!(host_state(&all, now), WalArchive::Ok);
        assert_eq!(oldest_last_archived(&all), Some(now - 86_400));
        let all = [(Cluster::App, Some(hung)), (Cluster::Vault, None)];
        assert_eq!(host_state(&all, now), WalArchive::Late);
        assert_eq!(oldest_last_archived(&all), None);
        assert_eq!(host_state(&[], now), WalArchive::Unknown);
    }
}
