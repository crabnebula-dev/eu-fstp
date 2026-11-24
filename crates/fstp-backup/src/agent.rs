//! The backup agent's operations (ADR-012, record of lane L10, M3 design
//! sections 2.3 and 3.8). Each `fstp-backup` invocation runs one of them:
//!
//! - [`Agent::archive`] for `archive_command`: one WAL segment or history
//!   file, sealed and uploaded once.
//! - [`Agent::base_backup`] for the timer: `pg_basebackup` over loopback,
//!   cut into parts of [`Limits::base_part`] bytes, each sealed as its own
//!   container and uploaded. The index line is written last.
//! - [`Agent::restore`] for a restore as root: the parts of one base
//!   backup, checked and extracted, then the archived segments from the
//!   backup's start segment into `pg_wal`.
//! - [`Agent::restore_wal`] for `restore_command`: one segment or history
//!   file.
//!
//! Every container is sealed through [`crate::seal_container`] to the
//! ClusterBackup group public key of `cluster-backup.key`: a fresh data
//! key each, sealed through the hybrid KEM (R-CR-01). The writer holds
//! the public key only. Opening needs the group secret, which only the
//! custody root opens ([`crate::keyfile::open`]), so a destroyed key
//! stays destroyed in every copy (I-81).

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use fstp_crypto::hybrid_kem::HybridSecretKey;
use fstp_custody::Custody;
use fstp_rt::Runtime;

use crate::config::{self, FileConfig};
use crate::index::{self, IndexEntry};
use crate::keyfile::{self, KeyFile};
use crate::s3::S3Client;
use crate::sigv4::hex;
use crate::wal::{self, ArchiveName};
use crate::writer::{WRITER_FILE, WriterKey};
use crate::{BackupError, ContainerKind, WalName, open_container, seal_container};

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
}

/// The agent of one cluster.
pub struct Agent<R: Runtime> {
    s3: S3Client<R>,
    key: KeyFile,
    writer: Option<WriterKey>,
    state_dir: PathBuf,
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
            s3,
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
        let credentials = config::s3_credentials(dir)?;
        let ca = config::s3_ca(dir)?;
        let s3 = S3Client::new(rt, cfg.object_store.clone(), credentials, ca.as_deref())?;
        let key = config::read_credential(dir, keyfile::KEY_FILE)?;
        // A restore-only host holds no writer key (record of lane
        // m10/backup-format).
        let writer = match std::fs::read(dir.join(WRITER_FILE)) {
            Ok(bytes) => Some(zeroize::Zeroizing::new(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => return Err(BackupError::Config(WRITER_FILE)),
        };
        Agent::new(
            s3,
            cfg.cluster,
            &key,
            writer.as_deref().map(Vec::as_slice),
            &cfg.state_dir,
        )
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

    async fn seal_and_store(
        &self,
        kind: ContainerKind,
        part: u32,
        object: &str,
        plaintext: &[u8],
    ) -> Result<(), BackupError> {
        // F-044: the key file is checked before every seal.
        let writer = self.writer()?;
        self.key.check_writer(writer)?;
        let public = self.key.public_key()?;
        let sealed = seal_container(&public, kind, &self.key.group_ref(), part, plaintext)?;
        self.s3
            .store(
                object,
                sealed,
                self.limits.single_put_max,
                self.limits.upload_part,
            )
            .await
    }

    /// `archive_command`: seals the file at `path`, handed over as `name`,
    /// and uploads it, unless the store holds it already.
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
        if self.s3.head_object(&object).await? {
            return Ok(Archived::Present);
        }
        let len = std::fs::metadata(path).map_err(io("WAL file"))?.len();
        if usize::try_from(len).map_or(true, |l| l > self.limits.base_part) {
            return Err(BackupError::Malformed("WAL file size"));
        }
        let bytes = std::fs::read(path).map_err(io("WAL file"))?;
        self.seal_and_store(ContainerKind::WalSegment, 0, &object, &bytes)
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
        let (backup, size) = self.stage_parts(tar).await?;
        self.record(backup, size)
    }

    /// Appends the index line of a completed base backup.
    fn record(&self, backup: [u8; 16], size: u64) -> Result<IndexEntry, BackupError> {
        let entry = IndexEntry {
            cluster: self.key.cluster,
            backup,
            at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
            size,
        };
        index::append(&self.state_dir, &entry)?;
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
        let (backup, size) = staged?;
        if !status.success() {
            return Err(BackupError::Tool("pg_basebackup"));
        }
        self.record(backup, size)
    }

    /// Seals and uploads the parts of `tar` under a new backup id, without
    /// the index line. The id and the plaintext size.
    async fn stage_parts(&self, tar: &mut impl Read) -> Result<([u8; 16], u64), BackupError> {
        let backup =
            fstp_crypto::random_array::<16>().map_err(|_| BackupError::Seal("backup id"))?;
        let mut buf = vec![0u8; self.limits.base_part.max(1)];
        let mut size = 0u64;
        let mut part = 0u32;
        loop {
            let n = fill(tar, &mut buf)?;
            if n == 0 && part > 0 {
                break;
            }
            let body = buf.get(..n).ok_or(BackupError::Io("read"))?;
            let object = self.base_object(backup, part);
            self.seal_and_store(ContainerKind::BaseBackup, part, &object, body)
                .await?;
            size = size.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
            part = part
                .checked_add(1)
                .ok_or(BackupError::Malformed("part count"))?;
            if n < buf.len() {
                break;
            }
        }
        Ok((backup, size))
    }

    /// Fetches `object` and opens it under `secret`. `None` when it does
    /// not exist. The container must be of `kind`, of this cluster and
    /// part `part`.
    async fn fetch_open(
        &self,
        secret: &HybridSecretKey,
        object: &str,
        kind: ContainerKind,
        part: u32,
    ) -> Result<Option<Vec<u8>>, BackupError> {
        let Some(bytes) = self.s3.get_object(object).await? else {
            return Ok(None);
        };
        let opened = open_container(secret, &bytes)?;
        if opened.kind != kind || opened.owner != self.key.cluster || opened.part != part {
            return Err(BackupError::Malformed("restored container"));
        }
        Ok(Some(opened.plaintext))
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
    /// Each part must exist, be of this cluster and carry its number, and
    /// the parts must add up to the entry's size.
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
            let object = self.base_object(entry.backup, part);
            let plain = self
                .fetch_open(secret, &object, ContainerKind::BaseBackup, part)
                .await?
                .ok_or(BackupError::NotFound)?;
            if plain.is_empty() && entry.size != 0 {
                return Err(BackupError::Malformed("empty base backup part"));
            }
            total = total.saturating_add(u64::try_from(plain.len()).unwrap_or(u64::MAX));
            if total > entry.size {
                return Err(BackupError::Malformed("base backup size"));
            }
            out.write_all(&plain).map_err(io("restore write"))?;
            part = part
                .checked_add(1)
                .ok_or(BackupError::Malformed("part count"))?;
            if total == entry.size {
                return Ok(part);
            }
        }
    }

    /// Fetches and opens the archive file `name`. `None` when the store
    /// does not hold it.
    ///
    /// # Errors
    ///
    /// [`BackupError::Malformed`] for a name of no archive kind or a
    /// container of another kind or cluster, and the errors of the fetch.
    pub async fn fetch_wal(
        &self,
        secret: &HybridSecretKey,
        name: &str,
    ) -> Result<Option<Vec<u8>>, BackupError> {
        if wal::parse_archive(name)? == ArchiveName::Skipped {
            return Ok(None);
        }
        self.fetch_open(secret, &self.wal_object(name), ContainerKind::WalSegment, 0)
            .await
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

    /// A restore into the new directory `data_dir` (module documentation):
    /// the base backup `entry`, extracted with the host's `tar`, then each
    /// archived segment from the start segment of its `backup_label`, on
    /// that timeline, into `pg_wal`, until the next one is absent.
    /// PostgreSQL replays them at its next start.
    ///
    /// # Errors
    ///
    /// [`BackupError::Io`] when `data_dir` exists and is not empty,
    /// [`BackupError::Tool`] when `tar` fails, and the errors of
    /// [`Agent::restore_base`] and [`Agent::fetch_wal`].
    pub async fn restore(
        &self,
        secret: &HybridSecretKey,
        entry: &IndexEntry,
        data_dir: &Path,
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
        let mut next = Some(wal::start_segment(&label)?);
        let pg_wal = data_dir.join("pg_wal");
        if std::fs::metadata(&pg_wal).is_err() {
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&pg_wal)
                .map_err(io("pg_wal"))?;
        }
        let mut segments = 0u32;
        let mut last_segment = None;
        while let Some(seg) = next {
            let name = seg.file_name();
            let Some(bytes) = self.fetch_wal(secret, &name).await? else {
                break;
            };
            let path = pg_wal.join(&name);
            let _ = std::fs::remove_file(&path);
            write_new(&path, &bytes)?;
            segments = segments.saturating_add(1);
            last_segment = Some(seg);
            next = seg.next(u64::try_from(bytes.len()).unwrap_or(0));
        }
        Ok(Restored {
            backup: *entry,
            parts,
            segments,
            last_segment,
        })
    }
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
