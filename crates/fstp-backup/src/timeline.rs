//! Timeline history files and the segment path of a restore (ADR-012
//! record of lane `m10/backup-pitr`).
//!
//! A cluster that promotes after a recovery starts a new timeline and
//! archives `<tli>.history`. PostgreSQL writes one line per ancestor:
//!
//! ```text
//! line = parent tli (decimal) TAB switch point (X/X, uppercase hex) TAB reason LF
//! ```
//!
//! The parent timeline ended at the switch point, where its child began.
//! Blank lines and lines that start with `#` are skipped. The decoder
//! admits the spelling PostgreSQL writes and nothing else: no leading
//! whitespace, no leading zeros, parents strictly increasing and below the
//! file's own timeline, switch points never decreasing. Fuzzed
//! (`wal_history_decode`). A refusal names its rule and never quotes the
//! file (R-NF-02).

use crate::{BackupError, WalName};

/// The largest history file read. Each ancestor takes one short line.
pub const MAX_HISTORY_LEN: usize = 64 * 1024;

/// One line of a history file: the parent timeline and where it ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Switch {
    /// The parent timeline.
    pub parent: u32,
    /// The WAL location at which it ended and its child began.
    pub end: u64,
}

fn bad(rule: &'static str) -> BackupError {
    BackupError::Malformed(rule)
}

fn decimal_u32(s: &str) -> Result<u32, BackupError> {
    if s.is_empty() || s.len() > 10 || (s.len() > 1 && s.starts_with('0')) {
        return Err(bad("history timeline"));
    }
    if !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad("history timeline"));
    }
    s.parse::<u32>().map_err(|_| bad("history timeline"))
}

fn hex_u32(s: &str) -> Result<u32, BackupError> {
    if s.is_empty() || s.len() > 8 || (s.len() > 1 && s.starts_with('0')) {
        return Err(bad("history switch point"));
    }
    let mut v: u32 = 0;
    for d in s.bytes() {
        let n = match d {
            b'0'..=b'9' => d.wrapping_sub(b'0'),
            b'A'..=b'F' => d.wrapping_sub(b'A').wrapping_add(10),
            _ => return Err(bad("history switch point")),
        };
        v = v.wrapping_shl(4) | u32::from(n);
    }
    Ok(v)
}

/// Parses a WAL location `X/X` in uppercase hex, as PostgreSQL prints it.
///
/// # Errors
///
/// [`BackupError::Malformed`] for any other spelling.
pub fn parse_lsn(s: &str) -> Result<u64, BackupError> {
    let (hi, lo) = s.split_once('/').ok_or(bad("history switch point"))?;
    Ok((u64::from(hex_u32(hi)?) << 32) | u64::from(hex_u32(lo)?))
}

/// Decodes the history file of timeline `own` (module documentation).
/// Fuzzed (`wal_history_decode`).
///
/// # Errors
///
/// [`BackupError::Malformed`] naming the first rule the input breaks.
pub fn decode_history(own: u32, bytes: &[u8]) -> Result<Vec<Switch>, BackupError> {
    if own < 2 {
        return Err(bad("history timeline"));
    }
    if bytes.len() > MAX_HISTORY_LEN {
        return Err(bad("history length"));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| bad("history UTF-8"))?;
    if !text.ends_with('\n') {
        return Err(bad("history line end"));
    }
    let mut out: Vec<Switch> = Vec::new();
    for line in text.split_terminator('\n') {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.chars().any(|c| c.is_control() && c != '\t') {
            return Err(bad("history line"));
        }
        let mut f = line.splitn(3, '\t');
        let (Some(tli), Some(lsn)) = (f.next(), f.next()) else {
            return Err(bad("history fields"));
        };
        let s = Switch {
            parent: decimal_u32(tli)?,
            end: parse_lsn(lsn)?,
        };
        if s.parent == 0 || s.parent >= own {
            return Err(bad("history timeline"));
        }
        if let Some(prev) = out.last() {
            if s.parent <= prev.parent {
                return Err(bad("history timeline order"));
            }
            if s.end < prev.end {
                return Err(bad("history switch point order"));
            }
        }
        out.push(s);
    }
    if out.is_empty() {
        return Err(bad("history fields"));
    }
    Ok(out)
}

/// One timeline on the path to the latest timeline: where it began and,
/// unless it is the latest, where it ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Step {
    /// The timeline.
    pub tli: u32,
    /// The location where it began, 0 for the first.
    pub begin: u64,
    /// The location where it ended, `None` for the latest.
    pub end: Option<u64>,
}

/// The path of timeline `latest`, oldest first, from its history (empty
/// for timeline 1).
#[must_use]
pub fn path(latest: u32, history: &[Switch]) -> Vec<Step> {
    let mut out = Vec::with_capacity(history.len().saturating_add(1));
    let mut begin = 0u64;
    for s in history {
        out.push(Step {
            tli: s.parent,
            begin,
            end: Some(s.end),
        });
        begin = s.end;
    }
    out.push(Step {
        tli: latest,
        begin,
        end: None,
    });
    out
}

/// Whether `path` passes through location `lsn` of timeline `tli`: the
/// latest timeline descends from that point, so a base backup that
/// started there recovers onto it.
#[must_use]
pub fn descends(path: &[Step], tli: u32, lsn: u64) -> bool {
    path.iter()
        .any(|s| s.tli == tli && s.begin <= lsn && s.end.is_none_or(|e| lsn < e))
}

/// The segment that holds location `lsn`, for segments of `size` bytes,
/// in the order of [`WalName::segment`]: the log id in the high 32 bits.
#[must_use]
pub fn segment_of(lsn: u64, size: u64) -> u64 {
    let low = (lsn & 0xFFFF_FFFF).checked_div(size).unwrap_or(0);
    ((lsn >> 32) << 32) | low
}

/// The names to try for `segment`, newest timeline first, as PostgreSQL
/// reads segments: each timeline of `path` that has begun by that
/// segment, and none older than `min_tli`, the timeline of the segment
/// before. Before the segment size is known, every timeline of the path
/// is tried: a timeline holds no segment before its beginning.
#[must_use]
pub fn candidates(path: &[Step], segment: u64, size: Option<u64>, min_tli: u32) -> Vec<WalName> {
    path.iter()
        .rev()
        .filter(|s| s.tli >= min_tli && size.is_none_or(|z| segment_of(s.begin, z) <= segment))
        .map(|s| WalName {
            timeline: s.tli,
            segment,
        })
        .collect()
}

/// The history file name of timeline `tli`.
#[must_use]
pub fn history_name(tli: u32) -> String {
    format!("{tli:08X}.history")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    const TL3: &[u8] = b"1\t0/3000148\tno recovery target specified\n\n\
        2\t0/5000060\tbefore 2026-11-24 10:00:00+00\n";

    /// ADR-012 record of lane `m10/backup-pitr`: a history file in the
    /// spelling PostgreSQL writes decodes to its switch points.
    #[test]
    fn adr012_pitr_history_decodes_what_postgresql_writes() {
        let h = decode_history(3, TL3).unwrap();
        assert_eq!(
            h,
            vec![
                Switch {
                    parent: 1,
                    end: 0x0300_0148
                },
                Switch {
                    parent: 2,
                    end: 0x0500_0060
                }
            ]
        );
        let commented = b"# a comment\n1\t1/A0\n";
        assert_eq!(
            decode_history(2, commented).unwrap(),
            vec![Switch {
                parent: 1,
                end: (1 << 32) | 0xA0
            }]
        );
        assert_eq!(history_name(10), "0000000A.history");
        assert_eq!(parse_lsn("FF/0").unwrap(), 0xFF << 32);
    }

    /// ADR-012 record of lane `m10/backup-pitr`: one spelling only.
    #[test]
    fn adr012_pitr_history_refuses_other_spellings() {
        for (own, bad) in [
            (3, &b"1\t0/3000148\n2\t0/2000000\n"[..]),
            (3, b"2\t0/3000148\n1\t0/5000000\n"),
            (2, b"2\t0/3000148\n"),
            (2, b"0\t0/3000148\n"),
            (2, b"01\t0/3000148\n"),
            (2, b"1\t0/03000148\n"),
            (2, b"1\t0/3000148a\n"),
            (2, b"1\t0x3000148\n"),
            (2, b" 1\t0/3000148\n"),
            (2, b"1 0/3000148\n"),
            (2, b"1\t0/3000148"),
            (2, b"1\t0/3000148\r\n"),
            (2, b"1\t0/123456789\n"),
            (2, b"\n# only a comment\n"),
            (2, b""),
            (1, b"1\t0/3000148\n"),
            (2, b"1\t0/3000148\tbad\x00reason\n"),
        ] {
            assert!(decode_history(own, bad).is_err(), "{bad:?}");
        }
        assert!(decode_history(2, &vec![b'#'; MAX_HISTORY_LEN + 1]).is_err());
    }

    /// ADR-012 record of lane `m10/backup-pitr`: the segment path follows
    /// the history. Before the switch segment only the parent's names are
    /// tried, from it on the child's first, and never one older than the
    /// timeline of the segment before.
    #[test]
    fn adr012_pitr_segment_path_follows_the_switch_points() {
        let mb16 = 16 << 20;
        let p = path(3, &decode_history(3, TL3).unwrap());
        assert_eq!(p.len(), 3);
        let tlis = |seg: u64, min: u32| -> Vec<u32> {
            candidates(&p, seg, Some(mb16), min)
                .iter()
                .map(|w| w.timeline)
                .collect()
        };
        assert_eq!(tlis(2, 1), vec![1]);
        assert_eq!(tlis(3, 1), vec![2, 1]);
        assert_eq!(tlis(4, 1), vec![2, 1]);
        assert_eq!(tlis(5, 1), vec![3, 2, 1]);
        assert_eq!(tlis(5, 2), vec![3, 2]);
        assert_eq!(tlis(9, 3), vec![3]);
        assert_eq!(
            candidates(&p, 5, Some(mb16), 3)[0].file_name(),
            "000000030000000000000005"
        );
        assert_eq!(
            path(1, &[]),
            vec![Step {
                tli: 1,
                begin: 0,
                end: None
            }]
        );
        assert_eq!(segment_of((2 << 32) | 0x0300_0000, mb16), (2 << 32) | 3);
    }

    /// ADR-012 record of lane `m10/backup-pitr`: the latest timeline
    /// descends from a backup taken before a switch point of its path,
    /// and not from one taken on the abandoned branch after it.
    #[test]
    fn adr012_pitr_segment_path_knows_abandoned_branches() {
        let p = path(3, &decode_history(3, TL3).unwrap());
        assert!(descends(&p, 1, 0x0200_0028));
        assert!(!descends(&p, 1, 0x0400_0028), "after timeline 1 ended");
        assert!(descends(&p, 2, 0x0400_0028));
        assert!(descends(&p, 3, 0x0900_0028));
        assert!(!descends(&p, 4, 0x0900_0028));
        assert!(descends(&path(1, &[]), 1, 0x0900_0028));
    }
}
