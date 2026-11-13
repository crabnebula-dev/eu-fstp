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

impl WalName {
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
}
