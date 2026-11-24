//! The head of a base backup's tar stream (ADR-012 record of lane
//! m10/backup-format, row "Start segment").
//!
//! `pg_basebackup -F t -D -` writes the base tar to standard output, and
//! the server sends `backup_label` as its first member. The agent reads
//! that member from the first part, to record the start segment of the
//! backup in its index line. Pruning needs it to know which WAL belongs
//! to which base backup.
//!
//! The parser takes exactly one POSIX ustar header at the very start: the
//! name `backup_label` with NUL padding, an empty prefix, a regular file
//! (type `'0'` or NUL), the magic `"ustar\0"` with version `"00"`, a size
//! in octal of at most [`MAX_LABEL_LEN`] bytes, and a header checksum that
//! matches. Anything else is refused, and the agent then records no start
//! segment. Fuzzed (`backup_tar_label_decode`).

use crate::BackupError;

/// The length of a tar header block.
pub const BLOCK: usize = 512;
/// The longest `backup_label` read.
pub const MAX_LABEL_LEN: usize = 64 * 1024;

fn bad(rule: &'static str) -> BackupError {
    BackupError::Malformed(rule)
}

/// An octal field: digits, then NUL or space padding to its end, with at
/// least one digit.
fn octal(field: &[u8]) -> Result<u64, BackupError> {
    let digits = field
        .iter()
        .position(|b| *b == 0 || *b == b' ')
        .unwrap_or(field.len());
    let (d, pad) = field.split_at(digits);
    if d.is_empty() || !pad.iter().all(|b| *b == 0 || *b == b' ') {
        return Err(bad("tar octal field"));
    }
    let mut v: u64 = 0;
    for c in d {
        if !(b'0'..=b'7').contains(c) {
            return Err(bad("tar octal field"));
        }
        v = v
            .checked_mul(8)
            .and_then(|v| v.checked_add(u64::from(c.wrapping_sub(b'0'))))
            .ok_or(bad("tar octal field"))?;
    }
    Ok(v)
}

/// The contents of `backup_label`, when `head` starts with it as its
/// first tar member (module documentation). `head` must hold the whole
/// member.
///
/// # Errors
///
/// [`BackupError::Malformed`] naming the rule broken, or
/// [`BackupError::Truncated`] when `head` ends inside the member.
pub fn backup_label(head: &[u8]) -> Result<&[u8], BackupError> {
    let h = head.get(..BLOCK).ok_or(BackupError::Truncated)?;
    let field = |a: usize, b: usize| h.get(a..b).ok_or(BackupError::Truncated);
    let name = field(0, 100)?;
    let label = b"backup_label";
    if name.get(..label.len()) != Some(&label[..])
        || !name
            .get(label.len()..)
            .is_some_and(|r| r.iter().all(|b| *b == 0))
    {
        return Err(bad("tar member name"));
    }
    if !field(345, 500)?.iter().all(|b| *b == 0) {
        return Err(bad("tar member name"));
    }
    if !matches!(field(156, 157)?, [b'0'] | [0]) {
        return Err(bad("tar member type"));
    }
    if field(257, 265)? != b"ustar\x0000" {
        return Err(bad("tar magic"));
    }
    let want = octal(field(148, 156)?)?;
    let sum: u64 = h
        .iter()
        .enumerate()
        .map(|(i, b)| {
            if (148..156).contains(&i) {
                u64::from(b' ')
            } else {
                u64::from(*b)
            }
        })
        .sum();
    if sum != want {
        return Err(bad("tar checksum"));
    }
    let size = usize::try_from(octal(field(124, 136)?)?).map_err(|_| bad("tar member size"))?;
    if size > MAX_LABEL_LEN {
        return Err(bad("tar member size"));
    }
    head.get(BLOCK..BLOCK.saturating_add(size))
        .ok_or(BackupError::Truncated)
}

/// A tar header block for a regular file `name` of `size` bytes, as
/// PostgreSQL writes one. For tests and the fuzz target's seeds.
#[must_use]
pub fn header(name: &str, size: usize) -> [u8; BLOCK] {
    let mut h = [0u8; BLOCK];
    let put = |h: &mut [u8; BLOCK], at: usize, bytes: &[u8]| {
        for (i, b) in bytes.iter().enumerate() {
            if let Some(slot) = h.get_mut(at.saturating_add(i)) {
                *slot = *b;
            }
        }
    };
    put(&mut h, 0, name.as_bytes());
    put(&mut h, 100, b"0000600\0");
    put(&mut h, 108, b"0000000\0");
    put(&mut h, 116, b"0000000\0");
    put(&mut h, 124, format!("{size:011o}\0").as_bytes());
    put(&mut h, 136, b"00000000000\0");
    put(&mut h, 148, b"        ");
    put(&mut h, 156, b"0");
    put(&mut h, 257, b"ustar\x0000");
    let sum: u64 = h.iter().map(|b| u64::from(*b)).sum();
    put(&mut h, 148, format!("{sum:06o}\0 ").as_bytes());
    h
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;

    /// ADR-012 record of lane m10/backup-format "Start segment": the
    /// first tar member `backup_label` gives its contents and the start
    /// segment. Another first member, a bad checksum, a cut member, a
    /// long label and another magic give none.
    #[test]
    fn adr012_tar_head_names_the_backup_label() {
        let label = b"START WAL LOCATION: 0/9000028 (file 000000010000000000000009)\n\
                      CHECKPOINT LOCATION: 0/9000060\n";
        let mut tar = header("backup_label", label.len()).to_vec();
        tar.extend_from_slice(label);
        tar.resize(tar.len() + 700, 0);
        assert_eq!(backup_label(&tar).unwrap(), &label[..]);
        let start = crate::backup_label_start(backup_label(&tar).unwrap()).unwrap();
        assert_eq!(start.file_name(), "000000010000000000000009");
        let mut other = header("PG_VERSION", 3).to_vec();
        other.extend_from_slice(b"16\n");
        assert!(backup_label(&other).is_err());
        let mut sum = tar.clone();
        sum[150] ^= 1;
        assert!(backup_label(&sum).is_err());
        let mut flipped = tar.clone();
        flipped[20] = 1;
        assert!(backup_label(&flipped).is_err());
        assert_eq!(
            backup_label(&tar[..BLOCK + 10]).unwrap_err(),
            BackupError::Truncated
        );
        assert!(backup_label(&tar[..100]).is_err());
        let long = header("backup_label", MAX_LABEL_LEN + 1);
        assert_eq!(
            backup_label(&[&long[..], &vec![0; MAX_LABEL_LEN + 1]].concat()).unwrap_err(),
            BackupError::Malformed("tar member size")
        );
        let mut gnu = tar.clone();
        gnu[257..265].copy_from_slice(b"ustar  \0");
        assert!(backup_label(&gnu).is_err());
    }
}
