//! The local base backup index (ADR-012 "Finding the newest backup",
//! record of lane L10).
//!
//! `<state_dir>/base-backups.index` holds one line per completed base
//! backup, appended after its last part is uploaded:
//!
//! ```text
//! line = cluster (32 lowercase hex) SP backup id (32 lowercase hex) SP unix seconds SP plaintext bytes LF
//! ```
//!
//! Numbers are decimal without leading zeros. The decoder admits exactly
//! this form and is fuzzed (`backup_index_decode`). A refusal names its
//! rule and never quotes the file (R-NF-02).

use std::path::Path;

use crate::BackupError;
use crate::sigv4::hex;

/// The index file's name in the state directory.
pub const INDEX_FILE: &str = "base-backups.index";
/// The largest index file read.
pub const MAX_INDEX_LEN: usize = 4 * 1024 * 1024;

/// One completed base backup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IndexEntry {
    /// The cluster.
    pub cluster: [u8; 16],
    /// The backup id.
    pub backup: [u8; 16],
    /// When it completed, in Unix seconds.
    pub at: u64,
    /// The plaintext bytes of the tar stream.
    pub size: u64,
}

fn bad(rule: &'static str) -> BackupError {
    BackupError::Index(rule)
}

/// Parses 32 lowercase hex digits.
///
/// # Errors
///
/// [`BackupError::Index`] for any other spelling.
pub fn parse_hex16(s: &str) -> Result<[u8; 16], BackupError> {
    let b = s.as_bytes();
    if b.len() != 32 {
        return Err(bad("hex"));
    }
    let mut out = [0u8; 16];
    for (slot, pair) in out.iter_mut().zip(b.chunks_exact(2)) {
        let n = |c: Option<&u8>| match c {
            Some(c @ b'0'..=b'9') => Ok(c.wrapping_sub(b'0')),
            Some(c @ b'a'..=b'f') => Ok(c.wrapping_sub(b'a').wrapping_add(10)),
            _ => Err(bad("hex")),
        };
        *slot = (n(pair.first())? << 4) | n(pair.get(1))?;
    }
    Ok(out)
}

fn decimal(s: &str) -> Result<u64, BackupError> {
    if s.is_empty() || s.len() > 20 || (s.len() > 1 && s.starts_with('0')) {
        return Err(bad("number"));
    }
    if !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad("number"));
    }
    s.parse::<u64>().map_err(|_| bad("number"))
}

/// The line of `e`.
#[must_use]
pub fn encode_line(e: &IndexEntry) -> String {
    format!(
        "{} {} {} {}\n",
        hex(&e.cluster),
        hex(&e.backup),
        e.at,
        e.size
    )
}

/// Decodes an index file. Fuzzed (`backup_index_decode`).
///
/// # Errors
///
/// [`BackupError::Index`] for a line of any other form, or a last line
/// without its line end.
pub fn decode(bytes: &[u8]) -> Result<Vec<IndexEntry>, BackupError> {
    if bytes.len() > MAX_INDEX_LEN {
        return Err(bad("length"));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| bad("UTF-8"))?;
    if !text.is_empty() && !text.ends_with('\n') {
        return Err(bad("line end"));
    }
    let mut out = Vec::new();
    for line in text.split_terminator('\n') {
        let mut f = line.split(' ');
        let (Some(c), Some(b), Some(at), Some(size), None) =
            (f.next(), f.next(), f.next(), f.next(), f.next())
        else {
            return Err(bad("fields"));
        };
        out.push(IndexEntry {
            cluster: parse_hex16(c)?,
            backup: parse_hex16(b)?,
            at: decimal(at)?,
            size: decimal(size)?,
        });
    }
    Ok(out)
}

/// The newest entry of `cluster` in the index of `state_dir`.
///
/// # Errors
///
/// [`BackupError::Index`] when the file cannot be read or decoded, and
/// [`BackupError::NotFound`] when it names no backup of `cluster`.
pub fn newest(state_dir: &Path, cluster: [u8; 16]) -> Result<IndexEntry, BackupError> {
    let bytes = std::fs::read(state_dir.join(INDEX_FILE)).map_err(|_| bad("read"))?;
    decode(&bytes)?
        .into_iter()
        .rev()
        .find(|e| e.cluster == cluster)
        .ok_or(BackupError::NotFound)
}

/// The entry of `backup` of `cluster`, if the index names it.
///
/// # Errors
///
/// As for [`newest`].
pub fn find(
    state_dir: &Path,
    cluster: [u8; 16],
    backup: [u8; 16],
) -> Result<IndexEntry, BackupError> {
    let bytes = std::fs::read(state_dir.join(INDEX_FILE)).map_err(|_| bad("read"))?;
    decode(&bytes)?
        .into_iter()
        .rev()
        .find(|e| e.cluster == cluster && e.backup == backup)
        .ok_or(BackupError::NotFound)
}

/// Appends `e` to the index of `state_dir` and syncs it.
///
/// # Errors
///
/// [`BackupError::Index`] when a step fails.
pub fn append(state_dir: &Path, e: &IndexEntry) -> Result<(), BackupError> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(state_dir.join(INDEX_FILE))
        .map_err(|_| bad("open"))?;
    f.write_all(encode_line(e).as_bytes())
        .and_then(|()| f.sync_all())
        .map_err(|_| bad("write"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    /// ADR-012 "Finding the newest backup": lines round trip, and the
    /// newest of a cluster is the last of its lines.
    #[test]
    fn adr012_index_round_trips() {
        let a = IndexEntry {
            cluster: [1; 16],
            backup: [2; 16],
            at: 1_790_000_000,
            size: 0,
        };
        let b = IndexEntry {
            cluster: [3; 16],
            backup: [4; 16],
            at: 1,
            size: 67_108_865,
        };
        let c = IndexEntry {
            backup: [5; 16],
            ..a
        };
        let text = [a, b, c].iter().map(encode_line).collect::<String>();
        assert_eq!(decode(text.as_bytes()).unwrap(), vec![a, b, c]);
        assert_eq!(decode(b"").unwrap(), vec![]);
        let dir = std::env::temp_dir().join(format!(
            "fstp-backup-index-{}",
            hex(&fstp_crypto::random_array::<8>().unwrap())
        ));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(newest(&dir, [1; 16]).is_err());
        for e in [a, b, c] {
            append(&dir, &e).unwrap();
        }
        assert_eq!(newest(&dir, [1; 16]).unwrap(), c);
        assert_eq!(find(&dir, [1; 16], [2; 16]).unwrap(), a);
        assert_eq!(newest(&dir, [9; 16]).unwrap_err(), BackupError::NotFound);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// ADR-012: one spelling only.
    #[test]
    fn adr012_index_refuses_other_spellings() {
        let good = encode_line(&IndexEntry {
            cluster: [0xab; 16],
            backup: [0xcd; 16],
            at: 7,
            size: 9,
        });
        for bad in [
            good.trim_end().to_owned(),
            good.replace(" 7 ", " 07 "),
            good.replace(" 7 ", "  7 "),
            good.replace(" 9\n", " +9\n"),
            good.replace(" 9\n", " 9 \n"),
            good.replace("ab", "AB"),
            good.replace("\n", "\r\n"),
            good.replace(" 9\n", " 99999999999999999999999\n"),
            format!("{good}\n"),
        ] {
            assert!(decode(bad.as_bytes()).is_err(), "{bad:?}");
        }
    }
}
