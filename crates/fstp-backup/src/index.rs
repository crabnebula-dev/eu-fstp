//! The local base backup index (ADR-012 "Finding the newest backup",
//! record of lane L10).
//!
//! `<state_dir>/base-backups.index` holds one line per completed base
//! backup, appended after its last part is uploaded:
//!
//! ```text
//! line = cluster (32 lowercase hex) SP backup id (32 lowercase hex) SP unix seconds SP plaintext bytes
//!        [SP part count SP (start segment | "-")] LF
//! ```
//!
//! The two last fields came with lane m10/backup-format ([`IndexLine`]):
//! the part count and the WAL start segment of the backup, or `-` when
//! it is not known. Pruning reads them. Lines of four fields, written
//! before that lane, stay readable.
//!
//! Numbers are decimal without leading zeros. The decoder admits exactly
//! this form and is fuzzed (`backup_index_decode`). A refusal names its
//! rule and never quotes the file (R-NF-02).

use std::path::Path;

use crate::sigv4::hex;
use crate::{BackupError, WalName};

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

/// One line of the index: the entry, and for a line of six fields its
/// part count and its start segment (record of lane m10/backup-format).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IndexLine {
    /// The entry.
    pub entry: IndexEntry,
    /// The part count, `None` for a line of four fields.
    pub parts: Option<u32>,
    /// The WAL start segment, when known.
    pub start: Option<WalName>,
}

/// The text of `l`: four fields when it has no part count, else six.
#[must_use]
pub fn encode_index_line(l: &IndexLine) -> String {
    let mut s = encode_line(&l.entry);
    if let Some(parts) = l.parts {
        s.pop();
        let start = l.start.map_or_else(|| "-".to_owned(), |w| w.file_name());
        s.push_str(&format!(" {parts} {start}\n"));
    }
    s
}

/// Decodes an index file into its entries. Fuzzed
/// (`backup_index_decode`).
///
/// # Errors
///
/// [`BackupError::Index`] for a line of any other form, or a last line
/// without its line end.
pub fn decode(bytes: &[u8]) -> Result<Vec<IndexEntry>, BackupError> {
    Ok(decode_lines(bytes)?.into_iter().map(|l| l.entry).collect())
}

/// Decodes an index file into its lines, of four or six fields. Fuzzed
/// (`backup_index_decode`).
///
/// # Errors
///
/// As [`decode`].
pub fn decode_lines(bytes: &[u8]) -> Result<Vec<IndexLine>, BackupError> {
    if bytes.len() > MAX_INDEX_LEN {
        return Err(bad("length"));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| bad("UTF-8"))?;
    if !text.is_empty() && !text.ends_with('\n') {
        return Err(bad("line end"));
    }
    let mut out = Vec::new();
    for line in text.split_terminator('\n') {
        let f: Vec<&str> = line.split(' ').collect();
        let (c, b, at, size) = match f.as_slice() {
            [c, b, at, size] | [c, b, at, size, _, _] => (*c, *b, *at, *size),
            _ => return Err(bad("fields")),
        };
        let entry = IndexEntry {
            cluster: parse_hex16(c)?,
            backup: parse_hex16(b)?,
            at: decimal(at)?,
            size: decimal(size)?,
        };
        let (parts, start) = match f.as_slice() {
            [_, _, _, _, parts, start] => {
                let parts = u32::try_from(decimal(parts)?)
                    .ok()
                    .filter(|p| *p != 0)
                    .ok_or(bad("part count"))?;
                let start = match *start {
                    "-" => None,
                    s => Some(crate::wal::parse(s).map_err(|_| bad("start segment"))?),
                };
                (Some(parts), start)
            }
            _ => (None, None),
        };
        out.push(IndexLine {
            entry,
            parts,
            start,
        });
    }
    Ok(out)
}

/// The lines of the index of `state_dir`, or none when it does not exist.
///
/// # Errors
///
/// [`BackupError::Index`] when the file cannot be read or decoded.
pub fn read_lines(state_dir: &Path) -> Result<Vec<IndexLine>, BackupError> {
    match std::fs::read(state_dir.join(INDEX_FILE)) {
        Ok(bytes) => decode_lines(&bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(_) => Err(bad("read")),
    }
}

/// Replaces the index of `state_dir` with `lines`, through a temporary
/// file, a sync and a rename, so a crash leaves the old or the new index.
///
/// # Errors
///
/// [`BackupError::Index`] when a step fails.
pub fn rewrite(state_dir: &Path, lines: &[IndexLine]) -> Result<(), BackupError> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let tmp = state_dir.join(format!("{INDEX_FILE}.new"));
    let _ = std::fs::remove_file(&tmp);
    let text: String = lines.iter().map(encode_index_line).collect();
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|_| bad("open"))?;
    f.write_all(text.as_bytes())
        .and_then(|()| f.sync_all())
        .map_err(|_| bad("write"))?;
    std::fs::rename(&tmp, state_dir.join(INDEX_FILE)).map_err(|_| bad("rename"))
}

/// Appends the line `l` to the index of `state_dir` and syncs it.
///
/// # Errors
///
/// [`BackupError::Index`] when a step fails.
pub fn append_line(state_dir: &Path, l: &IndexLine) -> Result<(), BackupError> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(state_dir.join(INDEX_FILE))
        .map_err(|_| bad("open"))?;
    f.write_all(encode_index_line(l).as_bytes())
        .and_then(|()| f.sync_all())
        .map_err(|_| bad("write"))
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

    /// ADR-012 record of lane m10/backup-format: lines of four and of six
    /// fields read side by side, round trip, and a rewrite keeps each form.
    /// A part count of 0, a bad start segment and five fields are refused.
    #[test]
    fn adr012_index_reads_both_line_forms() {
        let e = IndexEntry {
            cluster: [1; 16],
            backup: [2; 16],
            at: 5,
            size: 6,
        };
        let old = IndexLine {
            entry: e,
            parts: None,
            start: None,
        };
        let new = IndexLine {
            entry: IndexEntry {
                backup: [3; 16],
                ..e
            },
            parts: Some(2),
            start: Some(crate::parse_wal_name("00000001000000000000000A").unwrap()),
        };
        let unknown = IndexLine {
            parts: Some(1),
            start: None,
            ..new
        };
        let text: String = [old, new, unknown].iter().map(encode_index_line).collect();
        assert!(text.contains(" 2 00000001000000000000000A\n"));
        assert!(text.ends_with(" 1 -\n"));
        assert_eq!(
            decode_lines(text.as_bytes()).unwrap(),
            vec![old, new, unknown]
        );
        assert_eq!(decode(text.as_bytes()).unwrap().len(), 3);
        let good = encode_index_line(&new);
        for bad in [
            good.replace(" 2 0", " 0 0"),
            good.replace(" 2 0", " 02 0"),
            good.replace("0000000A", "0000000a"),
            good.replace(" 2 0", " 2  0"),
            good.replace(" 2 00000001000000000000000A", " 2"),
            good.replace("\n", " -\n"),
        ] {
            assert!(decode_lines(bad.as_bytes()).is_err(), "{bad:?}");
        }
        let dir = std::env::temp_dir().join(format!(
            "fstp-backup-index2-{}",
            hex(&fstp_crypto::random_array::<8>().unwrap())
        ));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(read_lines(&dir).unwrap().is_empty());
        append(&dir, &e).unwrap();
        append_line(&dir, &new).unwrap();
        assert_eq!(read_lines(&dir).unwrap(), vec![old, new]);
        rewrite(&dir, &[new]).unwrap();
        assert_eq!(read_lines(&dir).unwrap(), vec![new]);
        assert_eq!(newest(&dir, [1; 16]).unwrap(), new.entry);
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
