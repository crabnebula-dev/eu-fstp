//! WAL segment names (ADR-012 "Object names", lane F-ERASE).
//!
//! PostgreSQL names a segment with 24 uppercase hex digits: the timeline,
//! the log id and the segment within that log id, eight digits each. The
//! parser admits that one spelling only. Timeline 0 does not exist, so it
//! is refused. [`crate::WalName::segment`] holds the log id in its high 32
//! bits and the segment within it in its low 32 bits, so the order of
//! names is the order of segments for any segment size.

use crate::{BackupError, WalName};

/// The length of a segment name.
const NAME_LEN: usize = 24;

/// Eight uppercase hex digits as a u32.
fn hex8(digits: &[u8]) -> Result<u32, BackupError> {
    let mut v: u32 = 0;
    for d in digits {
        let n = match d {
            b'0'..=b'9' => d.wrapping_sub(b'0'),
            b'A'..=b'F' => d.wrapping_sub(b'A').wrapping_add(10),
            _ => return Err(BackupError::Malformed("WAL name digit")),
        };
        v = v
            .checked_mul(16)
            .ok_or(BackupError::Malformed("WAL name"))?
            | u32::from(n);
    }
    Ok(v)
}

pub(crate) fn parse(name: &str) -> Result<WalName, BackupError> {
    let b = name.as_bytes();
    if b.len() != NAME_LEN {
        return Err(BackupError::Malformed("WAL name length"));
    }
    let (t, rest) = b.split_at(8);
    let (log, seg) = rest.split_at(8);
    let timeline = hex8(t)?;
    if timeline == 0 {
        return Err(BackupError::Malformed("WAL timeline"));
    }
    let segment = (u64::from(hex8(log)?) << 32) | u64::from(hex8(seg)?);
    Ok(WalName { timeline, segment })
}

/// What `archive_command` was handed (ADR-012 record of lane L10).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArchiveName {
    /// A WAL segment.
    Segment(WalName),
    /// The history file of a timeline, `<8 hex>.history`.
    History(u32),
    /// A backup history file (`<segment>.<8 hex>.backup`) or a partial
    /// segment (`<segment>.partial`). Neither is needed for a restore, so
    /// the agent skips it with success.
    Skipped,
}

/// Parses an archive file name (module documentation and
/// [`ArchiveName`]). Fuzzed (`wal_name_parse`).
///
/// # Errors
///
/// [`BackupError::Malformed`] for any other spelling.
pub(crate) fn parse_archive(name: &str) -> Result<ArchiveName, BackupError> {
    if name.len() == NAME_LEN {
        return parse(name).map(ArchiveName::Segment);
    }
    if let Some(t) = name.strip_suffix(".history") {
        if t.len() != 8 {
            return Err(BackupError::Malformed("history name"));
        }
        let timeline = hex8(t.as_bytes())?;
        if timeline == 0 {
            return Err(BackupError::Malformed("WAL timeline"));
        }
        return Ok(ArchiveName::History(timeline));
    }
    if let Some(seg) = name.strip_suffix(".partial") {
        parse(seg)?;
        return Ok(ArchiveName::Skipped);
    }
    if let Some(rest) = name.strip_suffix(".backup") {
        let (seg, offset) = rest
            .split_once('.')
            .ok_or(BackupError::Malformed("backup history name"))?;
        parse(seg)?;
        if offset.len() != 8 {
            return Err(BackupError::Malformed("backup history name"));
        }
        hex8(offset.as_bytes())?;
        return Ok(ArchiveName::Skipped);
    }
    Err(BackupError::Malformed("archive name"))
}

/// The start segment a `backup_label` names: its line
/// `START WAL LOCATION: <lsn> (file <segment name>)`. Fuzzed
/// (`wal_name_parse`).
///
/// # Errors
///
/// [`BackupError::Malformed`] when no such line names a segment.
pub(crate) fn start_segment(label: &[u8]) -> Result<WalName, BackupError> {
    let text = std::str::from_utf8(label).map_err(|_| BackupError::Malformed("backup label"))?;
    let line = text
        .lines()
        .find(|l| l.starts_with("START WAL LOCATION: "))
        .ok_or(BackupError::Malformed("backup label"))?;
    let (_, after) = line
        .split_once("(file ")
        .ok_or(BackupError::Malformed("backup label"))?;
    let name = after
        .strip_suffix(')')
        .ok_or(BackupError::Malformed("backup label"))?;
    parse(name)
}

impl WalName {
    /// The segment after this one on the same timeline, for segments of
    /// `segment_size` bytes: a power of two from 1 MiB to 1 GiB, as
    /// PostgreSQL allows. `None` for another size or past the last one.
    #[must_use]
    pub fn next(&self, segment_size: u64) -> Option<WalName> {
        if !segment_size.is_power_of_two() || !(1 << 20..=1 << 30).contains(&segment_size) {
            return None;
        }
        let per_log = (1u64 << 32).checked_div(segment_size)?;
        let log = self.segment >> 32;
        let seg = self.segment & 0xFFFF_FFFF;
        let (log, seg) = match seg.checked_add(1)? {
            s if s < per_log => (log, s),
            _ => (log.checked_add(1).filter(|l| *l <= 0xFFFF_FFFF)?, 0),
        };
        Some(WalName {
            timeline: self.timeline,
            segment: (log << 32) | seg,
        })
    }

    /// The segment's file name, the one spelling [`crate::parse_wal_name`]
    /// admits.
    #[must_use]
    pub fn file_name(&self) -> String {
        format!(
            "{:08X}{:08X}{:08X}",
            self.timeline,
            self.segment >> 32,
            self.segment & 0xFFFF_FFFF
        )
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    /// ADR-012 "Object names": a PostgreSQL segment name parses and spells
    /// back the same, and segment order follows name order.
    #[test]
    fn adr012_wal_name_round_trips() {
        let a = parse("000000010000000A000000FF").unwrap();
        assert_eq!(a.timeline, 1);
        assert_eq!(a.segment, (0xA << 32) | 0xFF);
        assert_eq!(a.file_name(), "000000010000000A000000FF");
        let b = parse("000000010000000B00000000").unwrap();
        assert!(a < b);
    }

    /// ADR-012: one spelling only. Lowercase, short, long, signed and
    /// timeline 0 names are refused.
    #[test]
    fn adr012_wal_name_refuses_other_spellings() {
        for bad in [
            "000000010000000a000000FF",
            "00000001000000000000001",
            "0000000100000000000000010",
            "+00000010000000000000001",
            "000000000000000000000001",
            "",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    /// ADR-012 record of lane L10: segments, history files and the two
    /// skipped kinds parse, and nothing else does.
    #[test]
    fn adr012_archive_names() {
        assert_eq!(
            parse_archive("000000010000000000000003").unwrap(),
            ArchiveName::Segment(parse("000000010000000000000003").unwrap())
        );
        assert_eq!(
            parse_archive("0000000A.history").unwrap(),
            ArchiveName::History(10)
        );
        for skipped in [
            "000000010000000000000003.partial",
            "000000010000000000000003.00000028.backup",
        ] {
            assert_eq!(parse_archive(skipped).unwrap(), ArchiveName::Skipped);
        }
        for bad in [
            "00000000.history",
            "0000000a.history",
            "1.history",
            "000000010000000000000003.backup",
            "000000010000000000000003.0028.backup",
            "x.partial",
            "../000000010000000000000003",
            "000000010000000000000003/x",
        ] {
            assert!(parse_archive(bad).is_err(), "{bad}");
        }
    }

    /// ADR-012 record of lane L10: the start segment of a backup label,
    /// and the next segment wraps at the end of a log id.
    #[test]
    fn adr012_label_start_and_next_segment() {
        let label = b"START WAL LOCATION: 0/2000028 (file 000000010000000000000002)\n\
            CHECKPOINT LOCATION: 0/2000060\nBACKUP METHOD: streamed\n";
        let s = start_segment(label).unwrap();
        assert_eq!(s.file_name(), "000000010000000000000002");
        assert!(start_segment(b"CHECKPOINT LOCATION: 0/2000060\n").is_err());
        assert!(start_segment(b"START WAL LOCATION: 0/2 (file 0001)\n").is_err());
        let mb16 = 16 << 20;
        assert_eq!(
            s.next(mb16).unwrap().file_name(),
            "000000010000000000000003"
        );
        let last = parse("0000000100000000000000FF").unwrap();
        assert_eq!(
            last.next(mb16).unwrap().file_name(),
            "000000010000000100000000"
        );
        let gb = parse("000000010000000000000003").unwrap();
        assert_eq!(
            gb.next(1 << 30).unwrap().file_name(),
            "000000010000000100000000"
        );
        assert!(s.next(3 << 20).is_none());
        assert!(s.next(1 << 31).is_none());
        assert!(
            parse("00000001FFFFFFFF000000FF")
                .unwrap()
                .next(mb16)
                .is_none()
        );
    }
}
