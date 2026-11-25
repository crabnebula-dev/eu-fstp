//! The backup agent's operations (ADR-012, record of lane L10, M3 design
//! sections 2.3 and 3.8). Each `fstp-backup` invocation runs one of them:
//!
//! - [`Agent::archive`] for `archive_command`: one WAL segment or history
//!   file, sealed and uploaded once.
//! - [`Agent::base_backup`] for the timer: `pg_basebackup` over loopback,
//!   cut into parts of [`Limits::base_part`] bytes, each sealed as its own
//!   container and uploaded. The index line is written last.
//! - [`Agent::restore_to`] for a restore as root: the parts of one base
//!   backup, checked and extracted, then every timeline history file and
//!   the archived segments from the backup's start segment along the
//!   latest timeline into `pg_wal`, and the recovery settings for a target
//!   time (ADR-012 record of lane `m10/backup-pitr`).
//! - [`Agent::restore_wal`] for `restore_command`: one segment or history
//!   file.
//!
//! Every container is an `FBC2` container ([`crate::seal_object`], record
//! of lane m10/backup-format), sealed to the ClusterBackup group public
//! key of `cluster-backup.key`: a fresh data key each, sealed through the
//! hybrid KEM (R-CR-01). It names its object and carries the writer
//! key's signature, and every restore checks both (F-043). The writer holds
//! the public key only. Opening needs the group secret, which only the
//! custody root opens ([`crate::keyfile::open`]), so a destroyed key
//! stays destroyed in every copy (I-81).

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use fstp_crypto::hybrid_kem::HybridSecretKey;
use fstp_custody::Custody;
use fstp_rt::Runtime;

use crate::config::{self, FileConfig, Retention};
use crate::index::{self, IndexEntry, IndexLine};
use crate::keyfile::{self, KeyFile};
use crate::s3::{Deleted, S3Client};
use crate::sigv4::hex;
use crate::timeline;
use crate::wal::{self, ArchiveName};
use crate::writer::{WRITER_FILE, WriterKey};
use crate::{BackupError, ObjectIdent, WalName, open_object, seal_object};

/// The plaintext of one base backup part (record of lane L10).
pub const BASE_PART: usize = 64 * 1024 * 1024;
/// The largest container this agent writes or reads: one base backup part
/// or one WAL segment of at most [`BASE_PART`] bytes.
pub const MAX_CONTAINER_LEN: usize = crate::container_len(BASE_PART);
/// The largest container sent with one `PutObject`.
pub const SINGLE_PUT_MAX: usize = 32 * 1024 * 1024;
/// The part size of a multipart upload.
pub const UPLOAD_PART: usize = 16 * 1024 * 1024;

/// The sizes the agent cuts and uploads by. Tests take smaller ones.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// The plaintext of one base backup part.
    pub base_part: usize,
    /// The largest container sent with one `PutObject`.
    pub single_put_max: usize,
    /// The part size of a multipart upload.
    pub upload_part: usize,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            base_part: BASE_PART,
            single_put_max: SINGLE_PUT_MAX,
            upload_part: UPLOAD_PART,
        }
    }
}

/// What [`Agent::archive`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Archived {
    /// It sealed and uploaded the file.
    Uploaded,
    /// The object was in the store already.
    Present,
    /// The name is one the agent skips ([`ArchiveName::Skipped`]).
    Skipped,
}

/// What [`Agent::restore`] wrote.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Restored {
    /// The base backup.
    pub backup: IndexEntry,
    /// Its parts.
    pub parts: u32,
    /// The archived segments written into `pg_wal`.
    pub segments: u32,
    /// The last of them, if any.
    pub last_segment: Option<WalName>,
    /// The latest timeline of the archive, which the restore follows.
    pub timeline: u32,
    /// The history files written into `pg_wal`.
    pub histories: u32,
}

/// One timeline history file of the archive (ADR-012 record of lane
/// `m10/backup-pitr`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct History {
    /// Its timeline.
    pub tli: u32,
    /// Its bytes, as PostgreSQL wrote them.
    pub bytes: Vec<u8>,
    /// Its decoded switch points.
    pub switches: Vec<timeline::Switch>,
}

/// The rule a base backup breaks when the latest timeline does not
/// descend from its position: it lies on a branch an earlier restore
/// abandoned.
const OFF_LATEST: &str = "base backup off the latest timeline";

/// The agent of one cluster.
pub struct Agent<R: Runtime> {
    /// The object stores, in order, never empty (ADR-012 record of lane
    /// m10/backup-format).
    pub(crate) s3: Vec<S3Client<R>>,
    pub(crate) key: KeyFile,
    writer: Option<WriterKey>,
    pub(crate) state_dir: PathBuf,
    limits: Limits,
}

impl<R: Runtime> std::fmt::Debug for Agent<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Agent")
            .field("s3", &self.s3)
            .finish_non_exhaustive()
    }
}

fn io(rule: &'static str) -> impl FnOnce(std::io::Error) -> BackupError {
    move |_| BackupError::Io(rule)
}

/// Reads until `buf` is full or the input ends. The count read.
fn fill(r: &mut impl Read, buf: &mut [u8]) -> Result<usize, BackupError> {
    let mut n = 0usize;
    while let Some(rest) = buf.get_mut(n..) {
        if rest.is_empty() {
            break;
        }
        match r.read(rest) {
            Ok(0) => break,
            Ok(k) => n = n.saturating_add(k),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(BackupError::Io("read")),
        }
    }
    Ok(n)
}

/// Writes `bytes` to a new file `path` with mode 0600 and syncs it.
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), BackupError> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(io("new file"))?;
    f.write_all(bytes)
        .and_then(|()| f.sync_all())
        .map_err(io("write"))
}

impl<R: Runtime> Agent<R> {
    /// An agent over `s3` for the cluster of the key file `key_file`,
    /// signing with the writer key file `writer_key` (F-043, F-044). A host
    /// that only restores, such as a second custodian, has no writer key and
    /// passes `None`. It can fetch and open, and every seal refuses.
    ///
    /// # Errors
    ///
    /// [`BackupError::KeyFile`] for a key file that does not decode, names
    /// another cluster, or is not bound to the writer key
    /// ([`KeyFile::check_writer`]).
    pub fn new(
        s3: S3Client<R>,
        cluster: [u8; 16],
        key_file: &[u8],
        writer_key: Option<&[u8]>,
        state_dir: &Path,
    ) -> Result<Agent<R>, BackupError> {
        let key = keyfile::decode(key_file)?;
        if key.cluster != cluster {
            return Err(BackupError::KeyFile("another cluster"));
        }
        key.public_key()?;
        key.check_binding()?;
        let writer = writer_key.map(WriterKey::decode).transpose()?;
        if let Some(w) = &writer {
            key.check_writer(w)?;
        }
        Ok(Agent {
            s3: vec![s3],
            key,
            writer,
            state_dir: state_dir.to_path_buf(),
            limits: Limits::default(),
        })
    }

    /// The agent of the configuration `cfg` on `rt`: the object store
    /// credentials and the key file from the credentials directory.
    ///
    /// # Errors
    ///
    /// [`BackupError::Config`] naming a missing or refused credential, and
    /// the errors of [`Agent::new`].
    pub fn from_config(rt: R, cfg: &FileConfig) -> Result<Agent<R>, BackupError> {
        let dir = &cfg.credentials_dir;
        let mut stores = Vec::new();
        for (n, endpoint) in std::iter::once(&cfg.object_store)
            .chain(&cfg.more_stores)
            .enumerate()
        {
            let (credentials, ca) = config::store_credentials(dir, n)?;
            stores.push(S3Client::new(
                rt.clone(),
                endpoint.clone(),
                credentials,
                ca.as_deref(),
            )?);
        }
        let mut stores = stores.into_iter();
        let s3 = stores.next().ok_or(BackupError::Config("object_store"))?;
        let key = config::read_credential(dir, keyfile::KEY_FILE)?;
        // A restore-only host holds no writer key (record of lane
        // m10/backup-format).
        let writer = match std::fs::read(dir.join(WRITER_FILE)) {
            Ok(bytes) => Some(zeroize::Zeroizing::new(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => return Err(BackupError::Config(WRITER_FILE)),
        };
        Ok(Agent::new(
            s3,
            cfg.cluster,
            &key,
            writer.as_deref().map(Vec::as_slice),
            &cfg.state_dir,
        )?
        .with_stores(stores.collect()))
    }

    /// The agent with the further object stores `more`, after the first:
    /// every container goes to every store, and a fetch tries them in order
    /// (ADR-012 record of lane m10/backup-format).
    #[must_use]
    pub fn with_stores(mut self, more: Vec<S3Client<R>>) -> Agent<R> {
        self.s3.extend(more);
        self
    }

    /// The agent with other sizes.
    #[must_use]
    pub fn with_limits(mut self, limits: Limits) -> Agent<R> {
        self.limits = limits;
        self
    }

    /// The writer key, which every seal needs.
    fn writer(&self) -> Result<&WriterKey, BackupError> {
        self.writer.as_ref().ok_or(BackupError::Config(WRITER_FILE))
    }

    /// The cluster.
    #[must_use]
    pub fn cluster(&self) -> [u8; 16] {
        self.key.cluster
    }

    /// The object name of part `part` of base backup `backup`.
    #[must_use]
    pub fn base_object(&self, backup: [u8; 16], part: u32) -> String {
        format!("{}/base/{}/{part}", hex(&self.key.cluster), hex(&backup))
    }

    /// The object name of the archive file `name`.
    #[must_use]
    pub fn wal_object(&self, name: &str) -> String {
        format!("{}/wal/{name}", hex(&self.key.cluster))
    }

    /// Seals `plaintext` as the `FBC2` container of `ident`, signed by the
    /// writer key (F-043), and stores the same bytes as `object` in each
    /// store of `stores` (ADR-012 record of lane m10/backup-format).
    pub(crate) async fn seal_and_store(
        &self,
        ident: &ObjectIdent,
        object: &str,
        plaintext: &[u8],
        stores: &[&S3Client<R>],
    ) -> Result<(), BackupError> {
        // F-044: the key file is checked before every seal.
        let writer = self.writer()?;
        self.key.check_writer(writer)?;
        let public = self.key.public_key()?;
        let sealed = seal_object(&public, writer, &self.key.group_ref(), ident, plaintext)?;
        // Every store is tried, so one refusing store does not keep the
        // copy from the others. The first error is the result.
        let mut first = None;
        for s in stores {
            if let Err(e) = s
                .store(
                    object,
                    sealed.clone(),
                    self.limits.single_put_max,
                    self.limits.upload_part,
                )
                .await
            {
                first.get_or_insert(e);
            }
        }
        first.map_or(Ok(()), Err)
    }

    /// Every store, in order.
    fn every_store(&self) -> Vec<&S3Client<R>> {
        self.s3.iter().collect()
    }

    /// `archive_command`: seals the file at `path`, handed over as `name`,
    /// and uploads it to each store that does not hold it yet. It succeeds
    /// only when every store holds it (ADR-012 record of lane
    /// m10/backup-format).
    ///
    /// # Errors
    ///
    /// [`BackupError::Malformed`] for a name of no archive kind, and the
    /// errors of the read, the seal and the store.
    pub async fn archive(&self, path: &Path, name: &str) -> Result<Archived, BackupError> {
        if wal::parse_archive(name)? == ArchiveName::Skipped {
            return Ok(Archived::Skipped);
        }
        let object = self.wal_object(name);
        // A store that does not answer counts as missing the file: the
        // upload to it then fails, and so does the archive.
        let mut missing = Vec::new();
        for s in &self.s3 {
            if !matches!(s.head_object(&object).await, Ok(true)) {
                missing.push(s);
            }
        }
        if missing.is_empty() {
            return Ok(Archived::Present);
        }
        let len = std::fs::metadata(path).map_err(io("WAL file"))?.len();
        if usize::try_from(len).map_or(true, |l| l > self.limits.base_part) {
            return Err(BackupError::Malformed("WAL file size"));
        }
        let bytes = std::fs::read(path).map_err(io("WAL file"))?;
        self.seal_and_store(
            &ObjectIdent::Wal(name.to_owned()),
            &object,
            &bytes,
            &missing,
        )
        .await?;
        Ok(Archived::Uploaded)
    }

    /// Seals the tar stream `tar` as the parts of a new base backup,
    /// uploads each, and appends the index line last.
    ///
    /// # Errors
    ///
    /// The errors of the read, the seal, the store and the index.
    pub async fn base_backup_from(&self, tar: &mut impl Read) -> Result<IndexEntry, BackupError> {
        let staged = self.stage_parts(tar).await?;
        self.record(&staged)
    }

    /// Appends the index line of a completed base backup.
    /// With its part count and start segment (record of lane
    /// m10/backup-format).
    fn record(&self, staged: &Staged) -> Result<IndexEntry, BackupError> {
        let entry = IndexEntry {
            cluster: self.key.cluster,
            backup: staged.backup,
            at: now_unix(),
            size: staged.size,
        };
        index::append_line(
            &self.state_dir,
            &IndexLine {
                entry,
                parts: Some(staged.parts),
                start: staged.start,
            },
        )?;
        Ok(entry)
    }

    /// The timer's base backup: `pg_basebackup` of the cluster of `cfg`
    /// over loopback as `fstp_repl` ([`pg_basebackup`]), sealed and
    /// uploaded by [`Agent::base_backup_from`]. The index line is written
    /// only when `pg_basebackup` succeeds.
    ///
    /// # Errors
    ///
    /// [`BackupError::Tool`] when `pg_basebackup` fails, and the errors of
    /// [`Agent::base_backup_from`].
    pub async fn base_backup(&self, cfg: &FileConfig) -> Result<IndexEntry, BackupError> {
        let mut child = pg_basebackup(cfg)?
            .spawn()
            .map_err(|_| BackupError::Tool("pg_basebackup"))?;
        let mut out = child
            .stdout
            .take()
            .ok_or(BackupError::Tool("pg_basebackup"))?;
        // The index line waits for the exit status, so the backup counts
        // only once `pg_basebackup` has succeeded.
        let staged = self.stage_parts(&mut out).await;
        drop(out);
        let status = child
            .wait()
            .map_err(|_| BackupError::Tool("pg_basebackup"))?;
        let staged = staged?;
        if !status.success() {
            return Err(BackupError::Tool("pg_basebackup"));
        }
        self.record(&staged)
    }

    /// Seals and uploads the parts of `tar` under a new backup id, without
    /// the index line. The id and the plaintext size. Each part says
    /// whether it is the last (F-043): the agent reads one byte ahead to
    /// know, since it cuts the stream as it reads.
    async fn stage_parts(&self, tar: &mut impl Read) -> Result<Staged, BackupError> {
        let backup =
            fstp_crypto::random_array::<16>().map_err(|_| BackupError::Seal("backup id"))?;
        let mut buf = vec![0u8; self.limits.base_part.max(1)];
        let mut size = 0u64;
        let mut part = 0u32;
        let mut carry: Option<u8> = None;
        let mut start = None;
        loop {
            let n = match (carry.take(), buf.split_first_mut()) {
                (Some(b), Some((first, rest))) => {
                    *first = b;
                    fill(tar, rest)?.saturating_add(1)
                }
                _ => fill(tar, &mut buf)?,
            };
            if n == buf.len() {
                let mut one = [0u8; 1];
                if fill(tar, &mut one)? == 1 {
                    carry = Some(one[0]);
                }
            }
            let last = carry.is_none();
            let body = buf.get(..n).ok_or(BackupError::Io("read"))?;
            if part == 0 {
                // The start segment, from `backup_label` at the head of
                // the tar stream, for pruning. None when it is not there.
                start = crate::tar::backup_label(body)
                    .and_then(crate::backup_label_start)
                    .ok();
            }
            let ident = ObjectIdent::Base { backup, part, last };
            self.seal_and_store(
                &ident,
                &self.base_object(backup, part),
                body,
                &self.every_store(),
            )
            .await?;
            size = size.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
            if last {
                return Ok(Staged {
                    backup,
                    size,
                    parts: part.saturating_add(1),
                    start,
                });
            }
            part = part
                .checked_add(1)
                .ok_or(BackupError::Malformed("part count"))?;
        }
    }

    /// The fetch helper of every restore (ADR-012 record of lane
    /// m10/backup-format): fetches `object`, opens it as an `FBC2`
    /// container signed by the key file's writer key, and checks that it
    /// is of this cluster and names the object `want` accepts. `want`
    /// gives the part's last flag, or `None` to refuse the object.
    ///
    /// It tries the stores in order and takes the first copy that passes.
    /// A missing object, a failed request and a refused copy fall through to
    /// the next store. When no copy passes, the answer is `None` if some
    /// store said the object is absent and no store held a refused copy.
    /// Otherwise it is the first error, so a refused copy is never taken
    /// for the end of the archive, and one dead store does not stop a
    /// restore.
    pub(crate) async fn fetch_checked(
        &self,
        secret: &HybridSecretKey,
        object: &str,
        want: impl Fn(&ObjectIdent) -> Option<bool>,
    ) -> Result<Option<(Vec<u8>, bool)>, BackupError> {
        let writer = self.key.check_binding()?;
        let mut absent = false;
        let mut refused = false;
        let mut first: Option<BackupError> = None;
        for s in &self.s3 {
            let bytes = match s.get_object(object).await {
                Ok(Some(b)) => b,
                Ok(None) => {
                    absent = true;
                    continue;
                }
                Err(e) => {
                    first.get_or_insert(e);
                    continue;
                }
            };
            let checked = open_object(secret, &writer.writer[..], &bytes).and_then(|o| {
                if o.owner != self.key.cluster {
                    return Err(BackupError::Malformed("restored container"));
                }
                let last = want(&o.ident).ok_or(BackupError::Malformed("restored container"))?;
                Ok((o.plaintext, last))
            });
            match checked {
                Ok(v) => return Ok(Some(v)),
                Err(e) => {
                    refused = true;
                    first.get_or_insert(e);
                }
            }
        }
        match first {
            Some(e) if refused || !absent => Err(e),
            _ => Ok(None),
        }
    }

    /// Fetches and opens part `part` of base backup `backup`, with its
    /// last flag. `None` when no store holds it.
    ///
    /// # Errors
    ///
    /// [`BackupError::Malformed`] for a container that is not signed by
    /// this cluster's writer key or names another object, and the errors
    /// of the fetch.
    pub async fn fetch_base_part(
        &self,
        secret: &HybridSecretKey,
        backup: [u8; 16],
        part: u32,
    ) -> Result<Option<(Vec<u8>, bool)>, BackupError> {
        let object = self.base_object(backup, part);
        self.fetch_checked(secret, &object, |id| match id {
            ObjectIdent::Base {
                backup: b,
                part: p,
                last,
            } if *b == backup && *p == part => Some(*last),
            _ => None,
        })
        .await
    }

    /// Opens the group secret through `custody` (the console socket).
    ///
    /// # Errors
    ///
    /// The errors of [`keyfile::open`].
    pub async fn open_secret<C: Custody>(
        &self,
        custody: &C,
    ) -> Result<HybridSecretKey, BackupError> {
        keyfile::open(custody, &self.key).await
    }

    /// Opens the group secret on a second custodian (ADR-012 record of
    /// lane L16): the custodian key through `custody`, then the escrow.
    ///
    /// # Errors
    ///
    /// The errors of [`crate::custodian::open`].
    pub async fn open_escrow<C: Custody>(
        &self,
        custody: &C,
        custodian_key: &[u8],
        escrow: &[u8],
    ) -> Result<HybridSecretKey, BackupError> {
        crate::custodian::open(custody, custodian_key, escrow, &self.key).await
    }

    /// Writes the plaintext of base backup `entry` to `out`, part by part.
    /// Each part must exist, be of this cluster and name its backup and
    /// number, and the last flag must stand exactly on the part where the
    /// parts add up to the entry's size (F-043).
    ///
    /// # Errors
    ///
    /// [`BackupError::NotFound`] for a missing part,
    /// [`BackupError::Malformed`] for a part of another backup or a size
    /// that does not add up, and the errors of the fetch and the write.
    pub async fn restore_base(
        &self,
        secret: &HybridSecretKey,
        entry: &IndexEntry,
        out: &mut impl Write,
    ) -> Result<u32, BackupError> {
        let mut total = 0u64;
        let mut part = 0u32;
        loop {
            let (plain, last) = self
                .fetch_base_part(secret, entry.backup, part)
                .await?
                .ok_or(BackupError::NotFound)?;
            if plain.is_empty() && entry.size != 0 {
                return Err(BackupError::Malformed("empty base backup part"));
            }
            total = total.saturating_add(u64::try_from(plain.len()).unwrap_or(u64::MAX));
            if total > entry.size || (last && total != entry.size) {
                return Err(BackupError::Malformed("base backup size"));
            }
            out.write_all(&plain).map_err(io("restore write"))?;
            part = part
                .checked_add(1)
                .ok_or(BackupError::Malformed("part count"))?;
            if last {
                return Ok(part);
            }
        }
    }

    /// Fetches and opens the archive file `name`. `None` when the store
    /// does not hold it.
    ///
    /// # Errors
    ///
    /// [`BackupError::Malformed`] for a name of no archive kind, or a
    /// container that is not signed by this cluster's writer key or names
    /// another file, and the errors of the fetch.
    pub async fn fetch_wal(
        &self,
        secret: &HybridSecretKey,
        name: &str,
    ) -> Result<Option<Vec<u8>>, BackupError> {
        if wal::parse_archive(name)? == ArchiveName::Skipped {
            return Ok(None);
        }
        let got = self
            .fetch_checked(secret, &self.wal_object(name), |id| match id {
                ObjectIdent::Wal(n) if n == name => Some(true),
                _ => None,
            })
            .await?;
        Ok(got.map(|(plain, _)| plain))
    }

    /// `restore_command`: writes the archive file `name` to `dest`.
    ///
    /// # Errors
    ///
    /// [`BackupError::NotFound`] when the store does not hold it, and the
    /// errors of [`Agent::fetch_wal`] and the write.
    pub async fn restore_wal(
        &self,
        secret: &HybridSecretKey,
        name: &str,
        dest: &Path,
    ) -> Result<(), BackupError> {
        let bytes = self
            .fetch_wal(secret, name)
            .await?
            .ok_or(BackupError::NotFound)?;
        let _ = std::fs::remove_file(dest);
        write_new(dest, &bytes)
    }

    /// Every timeline history file of the archive, from timeline 2 upwards
    /// until one is absent, with its decoded switch points (ADR-012 record
    /// of lane `m10/backup-pitr`). PostgreSQL probes for them the same way.
    ///
    /// # Errors
    ///
    /// [`BackupError::Malformed`] for a history file that does not decode,
    /// and the errors of [`Agent::fetch_wal`].
    pub async fn fetch_histories(
        &self,
        secret: &HybridSecretKey,
    ) -> Result<Vec<History>, BackupError> {
        let mut out = Vec::new();
        let mut tli = 2u32;
        while let Some(bytes) = self.fetch_wal(secret, &timeline::history_name(tli)).await? {
            let switches = timeline::decode_history(tli, &bytes)?;
            out.push(History {
                tli,
                bytes,
                switches,
            });
            tli = tli
                .checked_add(1)
                .ok_or(BackupError::Malformed("history timeline"))?;
        }
        Ok(out)
    }

    /// A restore into the new directory `data_dir` to the newest archived
    /// point: [`Agent::restore_to`] of `entry` alone, with no target.
    ///
    /// # Errors
    ///
    /// As for [`Agent::restore_to`].
    pub async fn restore(
        &self,
        secret: &HybridSecretKey,
        entry: &IndexEntry,
        data_dir: &Path,
    ) -> Result<Restored, BackupError> {
        self.restore_to(secret, std::slice::from_ref(entry), data_dir, None)
            .await
    }

    /// A restore into the new directory `data_dir` (module documentation,
    /// ADR-012 record of lane `m10/backup-pitr`): the first base backup of
    /// `entries` whose position the latest timeline descends from, its
    /// history files and segments, and the recovery settings for `target`
    /// (Unix seconds, or the newest point). A backup on a branch that an
    /// earlier restore abandoned is skipped, and the directory emptied for
    /// the next one. PostgreSQL replays the segments at its next start and
    /// promotes onto a new timeline above every archived one.
    ///
    /// # Errors
    ///
    /// [`BackupError::NotFound`] when no entry suits the latest timeline,
    /// and the errors of [`Agent::fetch_histories`] and of each attempt.
    pub async fn restore_to(
        &self,
        secret: &HybridSecretKey,
        entries: &[IndexEntry],
        data_dir: &Path,
        target: Option<u64>,
    ) -> Result<Restored, BackupError> {
        let histories = self.fetch_histories(secret).await?;
        for entry in entries {
            match self
                .restore_one(secret, entry, data_dir, &histories, target)
                .await
            {
                Err(BackupError::Malformed(OFF_LATEST)) => {
                    std::fs::remove_dir_all(data_dir).map_err(io("data directory"))?;
                }
                r => return r,
            }
        }
        Err(BackupError::NotFound)
    }

    async fn restore_one(
        &self,
        secret: &HybridSecretKey,
        entry: &IndexEntry,
        data_dir: &Path,
        histories: &[History],
        target: Option<u64>,
    ) -> Result<Restored, BackupError> {
        use std::os::unix::fs::DirBuilderExt as _;
        if entry.cluster != self.key.cluster {
            return Err(BackupError::Malformed("another cluster"));
        }
        match std::fs::read_dir(data_dir) {
            Ok(mut d) => {
                if d.next().is_some() {
                    return Err(BackupError::Io("data directory not empty"));
                }
            }
            Err(_) => std::fs::DirBuilder::new()
                .mode(0o700)
                .create(data_dir)
                .map_err(io("data directory"))?,
        }
        let mut tar = Command::new("tar")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .arg("-x")
            .arg("-f")
            .arg("-")
            .arg("-C")
            .arg(data_dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|_| BackupError::Tool("tar"))?;
        let mut stdin = tar.stdin.take().ok_or(BackupError::Tool("tar"))?;
        let written = self.restore_base(secret, entry, &mut stdin).await;
        drop(stdin);
        let status = tar.wait().map_err(|_| BackupError::Tool("tar"))?;
        let parts = written?;
        if !status.success() {
            return Err(BackupError::Tool("tar"));
        }
        let label = std::fs::read(data_dir.join("backup_label")).map_err(io("backup_label"))?;
        let (start, start_lsn) = wal::start_location(&label)?;
        // The latest timeline, as `recovery_target_timeline = 'latest'`
        // reads it, and the path to it.
        let (latest, path) = match histories.last() {
            Some(h) => (h.tli, timeline::path(h.tli, &h.switches)),
            None => (1, timeline::path(1, &[])),
        };
        if !timeline::descends(&path, start.timeline, start_lsn) {
            return Err(BackupError::Malformed(OFF_LATEST));
        }
        let pg_wal = data_dir.join("pg_wal");
        if std::fs::metadata(&pg_wal).is_err() {
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&pg_wal)
                .map_err(io("pg_wal"))?;
        }
        // Every history file, so the promoted cluster takes a timeline id
        // above all of them.
        for h in histories {
            let p = pg_wal.join(timeline::history_name(h.tli));
            let _ = std::fs::remove_file(&p);
            write_new(&p, &h.bytes)?;
        }
        let mut segments = 0u32;
        let mut last_segment = None;
        let mut size: Option<u64> = None;
        let mut min_tli = start.timeline;
        let mut next = Some(start.segment);
        while let Some(seg) = next {
            let mut found = None;
            for name in timeline::candidates(&path, seg, size, min_tli) {
                if let Some(bytes) = self.fetch_wal(secret, &name.file_name()).await? {
                    found = Some((name, bytes));
                    break;
                }
            }
            let Some((name, bytes)) = found else {
                break;
            };
            let p = pg_wal.join(name.file_name());
            let _ = std::fs::remove_file(&p);
            write_new(&p, &bytes)?;
            let len = u64::try_from(bytes.len()).unwrap_or(0);
            if size.is_some_and(|s| s != len) {
                return Err(BackupError::Malformed("WAL segment size"));
            }
            size = Some(len);
            segments = segments.saturating_add(1);
            last_segment = Some(name);
            min_tli = name.timeline;
            next = name.next(len).map(|n| n.segment);
        }
        crate::recovery::write(data_dir, target, crate::recovery::Run::Final)?;
        Ok(Restored {
            backup: *entry,
            parts,
            segments,
            last_segment,
            timeline: latest,
            histories: u32::try_from(histories.len()).unwrap_or(u32::MAX),
        })
    }
}

/// The WAL segment size pruning assumes: PostgreSQL's default, which
/// `fstp-admin setup` keeps (ADR-012 record of lane m10/backup-format).
/// With another size, the names pruning tries miss, and the WAL stays.
pub const PRUNE_SEGMENT_SIZE: u64 = 16 * 1024 * 1024;
/// The most WAL names pruning tries for one base backup. A longer range
/// is left alone.
pub const MAX_PRUNE_SEGMENTS: u64 = 1_000_000;

/// What [`Agent::prune`] did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Pruned {
    /// Base backups whose objects are gone from every store, and whose
    /// index lines were removed.
    pub removed: u32,
    /// Base backups due for pruning that a store still holds, such as
    /// under an object lock, or whose delete failed. Their lines stay,
    /// and the next prune tries again.
    pub held: u32,
    /// Base backups of the cluster that the retention keeps.
    pub kept: u32,
}

/// The names of the WAL segments from `from` up to, not including, `to`,
/// on each timeline from `from`'s to `to`'s, for segments of
/// [`PRUNE_SEGMENT_SIZE`]. Empty when the range is empty or longer than
/// [`MAX_PRUNE_SEGMENTS`] per timeline.
#[must_use]
pub fn wal_between(from: WalName, to: WalName) -> Vec<String> {
    let mut out = Vec::new();
    if to.timeline < from.timeline {
        return out;
    }
    for timeline in from.timeline..=to.timeline {
        let mut seg = WalName {
            timeline,
            segment: from.segment,
        };
        let mut names = Vec::new();
        while seg.segment < to.segment {
            if u64::try_from(names.len()).unwrap_or(u64::MAX) >= MAX_PRUNE_SEGMENTS {
                return Vec::new();
            }
            names.push(seg.file_name());
            match seg.next(PRUNE_SEGMENT_SIZE) {
                Some(n) => seg = n,
                None => break,
            }
        }
        out.extend(names);
    }
    out
}

impl<R: Runtime> Agent<R> {
    /// Deletes `object` in every store. Whether it is gone from all.
    async fn delete_everywhere(&self, object: &str) -> bool {
        let mut gone = true;
        for s in &self.s3 {
            if !matches!(s.delete_object(object).await, Ok(Deleted::Gone)) {
                gone = false;
            }
        }
        gone
    }

    /// Prunes old base backups after a successful one (ADR-012 record of
    /// lane m10/backup-format, row "Prune rule"), driven by the local
    /// index, never by a listing. The candidates are the cluster's index
    /// lines older than `keep_days` at `now` (Unix seconds) and not among
    /// the newest `keep_min`, taken from the oldest while each one is a
    /// candidate. So the newest base backup is never one. For each, the
    /// parts go from every store, then the WAL from its start segment up
    /// to the next line's start segment. Timeline history files stay. A
    /// line leaves the index only when every delete succeeded in every
    /// store. Erasure never waits on any of this (I-81).
    ///
    /// # Errors
    ///
    /// [`BackupError::Index`] when the index cannot be read or rewritten.
    /// A refused or failed delete is no error: it is counted as held.
    pub async fn prune(&self, retention: &Retention, now: u64) -> Result<Pruned, BackupError> {
        let lines = index::read_lines(&self.state_dir)?;
        let mine: Vec<usize> = lines
            .iter()
            .enumerate()
            .filter(|(_, l)| l.entry.cluster == self.key.cluster)
            .map(|(i, _)| i)
            .collect();
        let n = mine.len();
        let keep_min = usize::try_from(retention.keep_min).unwrap_or(usize::MAX);
        let max_age = u64::from(retention.keep_days).saturating_mul(86_400);
        let mut candidates = 0usize;
        for (k, &i) in mine.iter().enumerate() {
            let old = lines
                .get(i)
                .is_some_and(|l| l.entry.at.saturating_add(max_age) < now);
            if k.saturating_add(keep_min) < n && old {
                candidates = k.saturating_add(1);
            } else {
                break;
            }
        }
        let mut removed = std::collections::BTreeSet::new();
        let mut out = Pruned::default();
        for k in 0..candidates {
            let (Some(line), Some(next)) = (
                mine.get(k).and_then(|&i| lines.get(i)),
                mine.get(k.saturating_add(1)).and_then(|&i| lines.get(i)),
            ) else {
                break;
            };
            let parts = line.parts.unwrap_or_else(|| {
                let per = u64::try_from(BASE_PART).unwrap_or(u64::MAX);
                u32::try_from(line.entry.size.div_ceil(per).max(1)).unwrap_or(u32::MAX)
            });
            let mut gone = true;
            for p in 0..parts {
                gone &= self
                    .delete_everywhere(&self.base_object(line.entry.backup, p))
                    .await;
            }
            if let (Some(from), Some(to)) = (line.start, next.start) {
                for name in wal_between(from, to) {
                    gone &= self.delete_everywhere(&self.wal_object(&name)).await;
                }
            }
            if gone {
                removed.extend(mine.get(k).copied());
                out.removed = out.removed.saturating_add(1);
            } else {
                out.held = out.held.saturating_add(1);
            }
        }
        out.kept = u32::try_from(n.saturating_sub(candidates)).unwrap_or(u32::MAX);
        if !removed.is_empty() {
            let rest: Vec<IndexLine> = lines
                .iter()
                .enumerate()
                .filter(|(i, _)| !removed.contains(i))
                .map(|(_, l)| *l)
                .collect();
            index::rewrite(&self.state_dir, &rest)?;
        }
        Ok(out)
    }
}

/// What [`Agent::stage_parts`] uploaded.
struct Staged {
    backup: [u8; 16],
    size: u64,
    parts: u32,
    start: Option<WalName>,
}

/// The time in Unix seconds.
#[must_use]
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The `pg_basebackup` command of `cfg` (ADR-012 record of lane L10): the
/// tar stream on standard output, no WAL, a fast checkpoint, no manifest,
/// over loopback as `fstp_repl` with TLS verify-full, its client
/// certificate and its password. The password travels in the
/// environment, never on the command line.
///
/// # Errors
///
/// [`BackupError::Config`] naming a missing credential.
pub fn pg_basebackup(cfg: &FileConfig) -> Result<Command, BackupError> {
    let dir = &cfg.credentials_dir;
    let password = config::read_secret(dir, "repl.password")?;
    for name in ["repl.pem", "repl.key", "db-ca.pem"] {
        if std::fs::metadata(dir.join(name)).is_err() {
            return Err(BackupError::Config(match name {
                "repl.pem" => "repl.pem",
                "repl.key" => "repl.key",
                _ => "db-ca.pem",
            }));
        }
    }
    let mut cmd = Command::new(cfg.pg_bindir.join("pg_basebackup"));
    cmd.env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .env("PGPASSWORD", password)
        .env("PGSSLMODE", "verify-full")
        .env("PGSSLROOTCERT", dir.join("db-ca.pem"))
        .env("PGSSLCERT", dir.join("repl.pem"))
        .env("PGSSLKEY", dir.join("repl.key"))
        .env("PGCONNECT_TIMEOUT", "20")
        .env("PGAPPNAME", "fstp-backup")
        .arg("-h")
        .arg(cfg.database.host.to_string())
        .arg("-p")
        .arg(cfg.database.port.to_string())
        .args(["-U", "fstp_repl", "-D", "-", "-F", "t", "-X", "none"])
        .args(["-c", "fast", "-w", "--no-manifest"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    Ok(cmd)
}
