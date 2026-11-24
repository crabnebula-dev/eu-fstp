//! The copy of the local witness store (ADR-012 record of lane
//! m10/witness-copy, decided by Daniel on 2026-11-24: backup is mission
//! critical).
//!
//! A self-hosted witness keeps one append-only file per cell and chain
//! and one registry file (`fstp_witness::file_store`). Three commands of
//! the agent of the application cluster work on that store:
//!
//! - [`Agent::witness_archive`], from a timer every minute: the whole
//!   records after the copied offset of each file, sealed as `FBC2`
//!   containers of kind 6 and sent to every store.
//! - [`Agent::witness_fetch`]: every copied file, into a new directory.
//! - [`Agent::witness_restore`]: the fetch, then each file of the store
//!   that is missing or shorter than its copy is replaced by the copy. A
//!   longer local file stays, and a file that differs stops it.
//!
//! The store's files are opaque here beyond their outer framing,
//! `be64(seq) || be32(len) || bytes`, which [`whole_records`] reads to
//! find the last whole record. A new record kind needs no change.
//!
//! The archiver's state file ([`decode_state`], fuzzed as
//! `witness_state_decode`) holds per file its number, its name, the
//! offset copied to every store, and the end of a segment in flight:
//!
//! ```text
//! state = "v1" LF line*
//! line  = file SP name SP copied SP end LF
//! ```

use std::io::{Read as _, Seek as _, Write as _};
use std::path::Path;

use fstp_crypto::hybrid_kem::HybridSecretKey;
use fstp_rt::Runtime;

use crate::agent::Agent;
use crate::sigv4::hex;
use crate::{BackupError, ObjectIdent};

/// The archiver state file in the agent's state directory.
pub const STATE_FILE: &str = "witness-copies";
/// The scratch directory of [`Agent::witness_restore`] in the state
/// directory.
pub const FETCH_DIR: &str = "witness-fetch";
/// The largest plaintext of one segment: 16 MiB.
pub const MAX_SEGMENT: usize = 16 * 1024 * 1024;
/// The most files a store may have.
pub const MAX_FILES: usize = 4096;
/// The longest state file.
pub const MAX_STATE_LEN: usize = 256 * 1024;
/// The longest file name.
pub const MAX_NAME_LEN: usize = 48;
/// The largest offset the state file holds: 10^15 bytes.
pub const MAX_OFFSET: u64 = 1_000_000_000_000_000;
/// The length of a record's frame header: `be64(seq) || be32(len)`.
const FRAME_HEADER: usize = 12;

/// Whether `name` may be a file name of the witness store: 1 to 48 bytes
/// of `a-z`, `0-9` and `-`, not starting with `-`.
#[must_use]
pub fn valid_name(name: &str) -> bool {
    (1..=MAX_NAME_LEN).contains(&name.len())
        && !name.starts_with('-')
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// The length of the longest prefix of `bytes` that holds only whole
/// records of the store's framing, `be64(seq) || be32(len) || bytes`.
#[must_use]
pub fn whole_records(bytes: &[u8]) -> usize {
    let mut at = 0usize;
    loop {
        let Some(len) = bytes
            .get(at.saturating_add(8)..at.saturating_add(FRAME_HEADER))
            .and_then(|b| <[u8; 4]>::try_from(b).ok())
            .map(u32::from_be_bytes)
            .and_then(|l| usize::try_from(l).ok())
        else {
            return at;
        };
        let end = at.saturating_add(FRAME_HEADER).saturating_add(len);
        if end > bytes.len() {
            return at;
        }
        at = end;
    }
}

/// One file of the archiver state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileState {
    /// The file number, from 0.
    pub file: u32,
    /// The file's name in the store.
    pub name: String,
    /// The offset every store holds the file up to.
    pub copied: u64,
    /// The end of a segment in flight, or `copied` when none is.
    pub end: u64,
}

/// The archiver state.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WitnessState {
    /// The files, in number order.
    pub files: Vec<FileState>,
}

fn number(text: &str) -> Result<u64, BackupError> {
    let bad = BackupError::Malformed("witness state number");
    if text.is_empty()
        || text.len() > 16
        || !text.bytes().all(|b| b.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0'))
    {
        return Err(bad);
    }
    let n: u64 = text.parse().map_err(|_| bad)?;
    if n > MAX_OFFSET {
        return Err(bad);
    }
    Ok(n)
}

/// Decodes an archiver state file in its one spelling (module
/// documentation). Fuzzed (`witness_state_decode`).
///
/// # Errors
///
/// [`BackupError::Malformed`] naming the rule broken.
pub fn decode_state(bytes: &[u8]) -> Result<WitnessState, BackupError> {
    if bytes.len() > MAX_STATE_LEN {
        return Err(BackupError::Malformed("witness state length"));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| BackupError::Malformed("witness state"))?;
    let body = text
        .strip_prefix("v1\n")
        .ok_or(BackupError::Malformed("witness state version"))?;
    let mut files: Vec<FileState> = Vec::new();
    if body.is_empty() {
        return Ok(WitnessState { files });
    }
    let body = body
        .strip_suffix('\n')
        .ok_or(BackupError::Malformed("witness state line end"))?;
    for line in body.split('\n') {
        let bad = BackupError::Malformed("witness state line");
        let mut f = line.split(' ');
        let (Some(file), Some(name), Some(copied), Some(end), None) =
            (f.next(), f.next(), f.next(), f.next(), f.next())
        else {
            return Err(bad);
        };
        let file = number(file)?;
        if file != u64::try_from(files.len()).map_err(|_| bad)? || files.len() >= MAX_FILES {
            return Err(BackupError::Malformed("witness state file number"));
        }
        if !valid_name(name) || files.iter().any(|x| x.name == name) {
            return Err(BackupError::Malformed("witness state name"));
        }
        let (copied, end) = (number(copied)?, number(end)?);
        if copied > end {
            return Err(BackupError::Malformed("witness state offsets"));
        }
        files.push(FileState {
            file: u32::try_from(file).map_err(|_| bad)?,
            name: name.to_owned(),
            copied,
            end,
        });
    }
    Ok(WitnessState { files })
}

/// Encodes an archiver state file.
#[must_use]
pub fn encode_state(s: &WitnessState) -> String {
    use std::fmt::Write as _;
    let mut out = String::from("v1\n");
    for f in &s.files {
        // Writing to a String does not fail.
        let _ = writeln!(out, "{} {} {} {}", f.file, f.name, f.copied, f.end);
    }
    out
}

/// Writes `s` as the state file of `dir`: a temporary file, synced and
/// renamed over the old one, mode 0600.
fn write_state(dir: &Path, s: &WitnessState) -> Result<(), BackupError> {
    write_replacing(dir, STATE_FILE, encode_state(s).as_bytes())
}

/// Writes `bytes` as `dir/name` through `dir/name.tmp`, synced and
/// renamed, mode 0600, then syncs the directory.
fn write_replacing(dir: &Path, name: &str, bytes: &[u8]) -> Result<(), BackupError> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let io = |_| BackupError::Io("witness write");
    std::fs::create_dir_all(dir).map_err(io)?;
    let tmp = dir.join(format!("{name}.tmp"));
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(io)?;
    f.write_all(bytes).and_then(|()| f.sync_all()).map_err(io)?;
    std::fs::rename(&tmp, dir.join(name)).map_err(io)?;
    std::fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(io)
}

/// The regular files of `store` with a valid name and at least one byte,
/// with their sizes, in name order. A missing directory has none.
fn listing(store: &Path) -> Result<Vec<(String, u64)>, BackupError> {
    let rd = match std::fs::read_dir(store) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err(BackupError::Io("witness store")),
    };
    let mut out = Vec::new();
    for e in rd {
        let e = e.map_err(|_| BackupError::Io("witness store"))?;
        let Some(name) = e.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let meta =
            std::fs::symlink_metadata(e.path()).map_err(|_| BackupError::Io("witness store"))?;
        if valid_name(&name) && meta.is_file() && meta.len() > 0 {
            out.push((name, meta.len()));
        }
    }
    out.sort();
    Ok(out)
}

/// The size of `path`, 0 when it does not exist.
fn size_of(path: &Path) -> Result<u64, BackupError> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.is_file() => Ok(m.len()),
        Ok(_) => Err(BackupError::Io("witness file")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(_) => Err(BackupError::Io("witness file")),
    }
}

/// Reads at most `len` bytes of `path` from `from`.
fn read_range(path: &Path, from: u64, len: usize) -> Result<Vec<u8>, BackupError> {
    let io = |_| BackupError::Io("witness file");
    let mut f = std::fs::File::open(path).map_err(io)?;
    f.seek(std::io::SeekFrom::Start(from)).map_err(io)?;
    let mut out = Vec::new();
    f.take(u64::try_from(len).unwrap_or(u64::MAX))
        .read_to_end(&mut out)
        .map_err(io)?;
    Ok(out)
}

/// What [`Agent::witness_restore`] did, by file name, in file order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WitnessRestored {
    /// Files that were missing or shorter, now the copy.
    pub filled: Vec<String>,
    /// Files equal to or longer than their copy, left as they were.
    pub kept: Vec<String>,
}

fn len_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

impl<R: Runtime> Agent<R> {
    /// The object name of the segment at `offset` of witness file `file`:
    /// `<cluster>/witness/<file, 8 hex>/<offset, 16 hex>`.
    #[must_use]
    pub fn witness_object(&self, file: u32, offset: u64) -> String {
        format!(
            "{}/witness/{file:08x}/{offset:016x}",
            hex(&self.key.cluster)
        )
    }

    /// Seals `bytes`, the segment at `offset` of `f`, and sends it to every
    /// store.
    async fn send_segment(
        &self,
        f: &FileState,
        offset: u64,
        bytes: &[u8],
    ) -> Result<(), BackupError> {
        let ident = ObjectIdent::Witness {
            file: f.file,
            offset,
            name: f.name.clone(),
        };
        let stores: Vec<_> = self.s3.iter().collect();
        self.seal_and_store(&ident, &self.witness_object(f.file, offset), bytes, &stores)
            .await
    }

    /// One run of the archiver over the witness store `store` (ADR-012
    /// record of lane m10/witness-copy, row "One run"). Returns the
    /// number of segments sent.
    ///
    /// # Errors
    ///
    /// [`BackupError::WitnessForeign`] when the state is missing and a
    /// store holds copies, [`BackupError::Malformed`] for a file shorter
    /// than its copies, and the errors of the read, the seal and the
    /// store. The run stops at the first one.
    pub async fn witness_archive(&self, store: &Path) -> Result<u32, BackupError> {
        let path = self.state_dir.join(STATE_FILE);
        let mut st = match std::fs::read(&path) {
            Ok(b) => decode_state(&b)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let first = self.witness_object(0, 0);
                for s in &self.s3 {
                    if s.head_object(&first).await? {
                        return Err(BackupError::WitnessForeign);
                    }
                }
                let st = WitnessState::default();
                write_state(&self.state_dir, &st)?;
                st
            }
            Err(_) => return Err(BackupError::Io("witness state")),
        };
        let mut added = false;
        for (name, _) in listing(store)? {
            if st.files.iter().any(|f| f.name == name) {
                continue;
            }
            if st.files.len() >= MAX_FILES {
                return Err(BackupError::Malformed("witness file count"));
            }
            let file = u32::try_from(st.files.len())
                .map_err(|_| BackupError::Malformed("witness file count"))?;
            st.files.push(FileState {
                file,
                name,
                copied: 0,
                end: 0,
            });
            added = true;
        }
        if added {
            write_state(&self.state_dir, &st)?;
        }
        let mut sent = 0u32;
        for i in 0..st.files.len() {
            let Some(f) = st.files.get(i).cloned() else {
                break;
            };
            let file_path = store.join(&f.name);
            let size = size_of(&file_path)?;
            if size < f.end {
                return Err(BackupError::Malformed(
                    "witness file shorter than its copies",
                ));
            }
            if f.end > f.copied {
                let len = usize::try_from(f.end.saturating_sub(f.copied))
                    .map_err(|_| BackupError::Malformed("witness segment"))?;
                let bytes = read_range(&file_path, f.copied, len)?;
                if bytes.len() != len || whole_records(&bytes) != len {
                    return Err(BackupError::Malformed("witness segment in flight"));
                }
                self.send_segment(&f, f.copied, &bytes).await?;
                sent = sent.saturating_add(1);
                if let Some(x) = st.files.get_mut(i) {
                    x.copied = f.end;
                }
                write_state(&self.state_dir, &st)?;
            }
            while let Some(f) = st.files.get(i).cloned() {
                if size <= f.copied {
                    break;
                }
                let want = usize::try_from(size.saturating_sub(f.copied))
                    .unwrap_or(usize::MAX)
                    .min(MAX_SEGMENT);
                let mut bytes = read_range(&file_path, f.copied, want)?;
                let whole = whole_records(&bytes);
                if whole == 0 {
                    if bytes.len() >= MAX_SEGMENT {
                        return Err(BackupError::Malformed("witness record length"));
                    }
                    // A record still being written waits for the next run.
                    break;
                }
                bytes.truncate(whole);
                let end = f.copied.saturating_add(len_u64(whole));
                if end > MAX_OFFSET {
                    return Err(BackupError::Malformed("witness file size"));
                }
                if let Some(x) = st.files.get_mut(i) {
                    x.end = end;
                }
                write_state(&self.state_dir, &st)?;
                self.send_segment(&f, f.copied, &bytes).await?;
                sent = sent.saturating_add(1);
                if let Some(x) = st.files.get_mut(i) {
                    x.copied = end;
                }
                write_state(&self.state_dir, &st)?;
            }
        }
        Ok(sent)
    }

    /// Fetches and opens the segment at `offset` of file `file`. With
    /// `name`, the segment must name that file; without, any valid name
    /// is taken and returned. `None` when no store holds it.
    async fn fetch_segment(
        &self,
        secret: &HybridSecretKey,
        file: u32,
        offset: u64,
        name: Option<&str>,
    ) -> Result<Option<(String, Vec<u8>)>, BackupError> {
        let seen = std::cell::RefCell::new(None::<String>);
        let got = self
            .fetch_checked(secret, &self.witness_object(file, offset), |id| match id {
                ObjectIdent::Witness {
                    file: f,
                    offset: o,
                    name: n,
                } if *f == file && *o == offset && name.is_none_or(|w| w == n) => {
                    *seen.borrow_mut() = Some(n.clone());
                    Some(true)
                }
                _ => None,
            })
            .await?;
        let Some((plain, _)) = got else {
            return Ok(None);
        };
        if plain.is_empty() {
            return Err(BackupError::Malformed("empty witness segment"));
        }
        let name = seen
            .into_inner()
            .ok_or(BackupError::Malformed("restored container"))?;
        Ok(Some((name, plain)))
    }

    /// Fetches every copied file of the witness store into `out`, which
    /// must be new or an empty directory (ADR-012 record of lane
    /// m10/witness-copy, row "Fetch"). Returns each file's name and
    /// length, in file order. No copies give no files.
    ///
    /// # Errors
    ///
    /// [`BackupError::Malformed`] for a segment that names another file,
    /// offset or name, an empty segment, or a name seen twice, and the
    /// errors of the fetch and the write.
    pub async fn witness_fetch(
        &self,
        secret: &HybridSecretKey,
        out: &Path,
    ) -> Result<Vec<(String, u64)>, BackupError> {
        use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
        let io = |_| BackupError::Io("witness fetch");
        match std::fs::read_dir(out) {
            Ok(mut rd) => {
                if rd.next().is_some() {
                    return Err(BackupError::Io("witness fetch directory not empty"));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(out)
                    .map_err(io)?;
            }
            Err(_) => return Err(BackupError::Io("witness fetch")),
        }
        let mut files: Vec<(String, u64)> = Vec::new();
        for file in 0..u32::try_from(MAX_FILES).unwrap_or(u32::MAX) {
            let Some((name, first)) = self.fetch_segment(secret, file, 0, None).await? else {
                break;
            };
            if files.iter().any(|(n, _)| *n == name) {
                return Err(BackupError::Malformed("witness file name seen twice"));
            }
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(out.join(&name))
                .map_err(io)?;
            f.write_all(&first).map_err(io)?;
            let mut offset = len_u64(first.len());
            while let Some((_, more)) = self
                .fetch_segment(secret, file, offset, Some(&name))
                .await?
            {
                f.write_all(&more).map_err(io)?;
                offset = offset.saturating_add(len_u64(more.len()));
                if offset > MAX_OFFSET {
                    return Err(BackupError::Malformed("witness file size"));
                }
            }
            f.sync_all().map_err(io)?;
            files.push((name, offset));
        }
        Ok(files)
    }

    /// Rebuilds the witness store `store` from its copies (ADR-012 record
    /// of lane m10/witness-copy, row "Rebuild"), then writes the archiver
    /// state from the copies. Nothing changes before every file is
    /// compared.
    ///
    /// # Errors
    ///
    /// [`BackupError::WitnessDiverged`] for a local file that neither
    /// extends nor is extended by its copy, and the errors of
    /// [`Agent::witness_fetch`] and the writes.
    pub async fn witness_restore(
        &self,
        secret: &HybridSecretKey,
        store: &Path,
    ) -> Result<WitnessRestored, BackupError> {
        let scratch = self.state_dir.join(FETCH_DIR);
        let _ = std::fs::remove_dir_all(&scratch);
        let r = self.restore_from(secret, store, &scratch).await;
        let _ = std::fs::remove_dir_all(&scratch);
        r
    }

    async fn restore_from(
        &self,
        secret: &HybridSecretKey,
        store: &Path,
        scratch: &Path,
    ) -> Result<WitnessRestored, BackupError> {
        let fetched = self.witness_fetch(secret, scratch).await?;
        let mut done = WitnessRestored::default();
        if fetched.is_empty() {
            return Ok(done);
        }
        let read = |p: &Path| match std::fs::read(p) {
            Ok(b) => Ok(b),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(_) => Err(BackupError::Io("witness file")),
        };
        let mut fill = Vec::new();
        for (name, _) in &fetched {
            let copy = read(&scratch.join(name))?;
            let local = read(&store.join(name))?;
            if local.starts_with(&copy) {
                done.kept.push(name.clone());
            } else if copy.starts_with(&local) {
                done.filled.push(name.clone());
                fill.push((name.clone(), copy));
            } else {
                return Err(BackupError::WitnessDiverged);
            }
        }
        {
            use std::os::unix::fs::DirBuilderExt as _;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(store)
                .map_err(|_| BackupError::Io("witness store"))?;
        }
        for (name, copy) in &fill {
            write_replacing(store, name, copy)?;
        }
        let st = WitnessState {
            files: fetched
                .iter()
                .enumerate()
                .map(|(i, (name, len))| FileState {
                    file: u32::try_from(i).unwrap_or(u32::MAX),
                    name: name.clone(),
                    copied: *len,
                    end: *len,
                })
                .collect(),
        };
        write_state(&self.state_dir, &st)?;
        Ok(done)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;

    /// ADR-012 record of lane m10/witness-copy, row "Archiver state": each
    /// state round trips in one spelling, and every other spelling is
    /// refused.
    #[test]
    fn adr012_wc_witness_state_round_trips_in_one_spelling() {
        let empty = WitnessState::default();
        assert_eq!(encode_state(&empty), "v1\n");
        let two = WitnessState {
            files: vec![
                FileState {
                    file: 0,
                    name: "chain-0102030405060708090a0b0c0d0e0f10-1".into(),
                    copied: 624,
                    end: 1248,
                },
                FileState {
                    file: 1,
                    name: "registry".into(),
                    copied: 0,
                    end: 0,
                },
            ],
        };
        let text = encode_state(&two);
        assert_eq!(
            text,
            "v1\n0 chain-0102030405060708090a0b0c0d0e0f10-1 624 1248\n1 registry 0 0\n"
        );
        for s in [&empty, &two] {
            assert_eq!(decode_state(encode_state(s).as_bytes()).unwrap(), *s);
        }
        for bad in [
            "",
            "v1",
            "v2\n",
            "v1\n\n",
            "v1\n0 registry 0 0",
            "v1\n1 registry 0 0\n",
            "v1\n0 registry 1 0\n",
            "v1\n0 registry 00 0\n",
            "v1\n0 registry 0 0 0\n",
            "v1\n0 registry 0\n",
            "v1\n0 Registry 0 0\n",
            "v1\n0 a/b 0 0\n",
            "v1\n0 registry 0 0\n1 registry 0 0\n",
            "v1\n0 registry 0 1000000000000001\n",
            "v1\n0 registry  0 0\n",
            "v1\n0 registry 0 0\r\n",
            "v1\n-0 registry 0 0\n",
        ] {
            assert!(decode_state(bad.as_bytes()).is_err(), "{bad:?}");
        }
        let long = "v1\n".to_owned() + &"x".repeat(MAX_STATE_LEN);
        assert!(decode_state(long.as_bytes()).is_err());
    }

    /// ADR-012 record of lane m10/witness-copy, row "Segments": the whole
    /// records end before a record cut in its header or its bytes.
    #[test]
    fn adr012_wc_whole_records_end_before_a_cut_record() {
        let frame = |seq: u64, len: usize| {
            let mut v = seq.to_be_bytes().to_vec();
            v.extend_from_slice(&u32::try_from(len).unwrap().to_be_bytes());
            v.extend(std::iter::repeat_n(7u8, len));
            v
        };
        let two: Vec<u8> = [frame(1, 5), frame(2, 0)].concat();
        assert_eq!(whole_records(&[]), 0);
        assert_eq!(whole_records(&two), 17 + 12);
        let third = frame(3, 40);
        for cut in 0..third.len() {
            let mut b = two.clone();
            b.extend_from_slice(&third[..cut]);
            assert_eq!(whole_records(&b), 29, "{cut}");
        }
        let mut b = two.clone();
        b.extend_from_slice(&third);
        assert_eq!(whole_records(&b), 29 + 52);
        // A length past the end, even the largest, is a cut.
        let mut huge = 9u64.to_be_bytes().to_vec();
        huge.extend_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(whole_records(&huge), 0);
        assert!(valid_name("registry"));
        assert!(valid_name("chain-0102030405060708090a0b0c0d0e0f10-2"));
        for bad in ["", "-a", "a.b", "A", "a b", "registry.tmp"] {
            assert!(!valid_name(bad), "{bad:?}");
        }
    }
}
