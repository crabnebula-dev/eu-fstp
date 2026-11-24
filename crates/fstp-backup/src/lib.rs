//! The backup agent: backup container, multipart S3 client with SigV4 and
//! an XML subset parser (M3 design section 3.8, ADR-012).
//!
//! - The container decoder (lane F-CRYPTO), the container writer and
//!   opener and the WAL segment name parser (lane F-ERASE).
//! - Lane L10 `prod/backup` (ADR-012, record of lane L10): the XML subset
//!   parser ([`xml`]), SigV4 ([`sigv4`]), the S3 client ([`s3`]), the
//!   configuration file ([`config`]), the ClusterBackup key file
//!   ([`keyfile`]), the base backup index ([`index`]), the agent's
//!   operations ([`agent`]) and the command line ([`run`]).
//!
//! Each invocation of the binary runs one command and exits. The timer
//! runs `base-backup`, PostgreSQL's `archive_command` runs `wal-archive`,
//! and a root operator runs `init-keys`, `restore` and `wal-restore`.

pub mod agent;
pub mod config;
mod container;
pub mod custodian;
pub mod index;
pub mod keyfile;
mod object;
pub mod recovery;
pub mod s3;
mod seal;
pub mod sigv4;
pub mod snapshot;
pub mod tar;
pub mod timeline;
mod wal;
pub mod witness;
pub mod writer;
pub mod xml;

use std::path::PathBuf;

pub use object::{ObjectIdent, OpenedObject, open_object, seal_object};
pub use seal::{ContainerKind, GroupRef, Opened, open_container, seal_container};
pub use snapshot::{ObjectStore, SnapshotKey, SnapshotOwner, Snapshots};
pub use wal::ArchiveName;

/// Why a backup operation failed. Every variant names a rule, a part or
/// a status. None quotes input, a secret or a server's text (R-NF-02).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackupError {
    /// Kept for the tests that guarded the W0 stubs. No operation returns
    /// it since lane L10.
    NotImplemented(&'static str),
    /// The container ends before its final chunk does (ADR-012).
    Truncated,
    /// The container's data key is not an `FSK1` key sealed through the
    /// hybrid KEM on the container's chain (R-CR-01).
    KeyNotHybrid,
    /// The input breaks an ADR-012 rule. It names the rule.
    Malformed(&'static str),
    /// Sealing failed: the KEM, the AEAD or the generator. It names the
    /// part.
    Seal(&'static str),
    /// The data key or a chunk did not open under the given group secret.
    OpenFailed,
    /// An S3 response body breaks the XML subset. It names the rule.
    Xml(&'static str),
    /// The object store answered with this unexpected status.
    S3Status(u16),
    /// The object store refused with this error code.
    S3Refused(xml::S3Code),
    /// The request did not complete. It names the phase.
    Transport(&'static str),
    /// The configuration, a credential or an argument was refused. It
    /// names the member, the file or the rule.
    Config(&'static str),
    /// The key file was refused. It names the rule.
    KeyFile(&'static str),
    /// Custody refused a call. It names the call.
    Custody(&'static str),
    /// The base backup index was refused. It names the rule.
    Index(&'static str),
    /// The object or index entry does not exist.
    NotFound,
    /// A local file operation failed. It names the step.
    Io(&'static str),
    /// A host tool (`pg_basebackup`, `tar`, `postgres`) failed. It names
    /// the tool.
    Tool(&'static str),
    /// The archive ends before the restore target: it holds no change
    /// after that time (ADR-012 record of lane `m10/backup-pitr`).
    TargetNotReached,
    /// The witness archiver has no state while a store holds witness
    /// copies: they are of another host or another store (ADR-012 record
    /// of lane m10/witness-copy).
    WitnessForeign,
    /// A local witness store file neither extends nor is extended by its
    /// copy (ADR-012 record of lane m10/witness-copy).
    WitnessDiverged,
}

impl std::fmt::Display for BackupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackupError::NotImplemented(op) => write!(f, "{op} is not implemented yet"),
            BackupError::Truncated => write!(f, "the container is truncated"),
            BackupError::KeyNotHybrid => {
                write!(f, "the data key is not sealed through the hybrid KEM")
            }
            BackupError::Malformed(rule) => write!(f, "the input breaks the {rule} rule"),
            BackupError::Seal(part) => write!(f, "sealing the {part} failed"),
            BackupError::OpenFailed => write!(f, "the container does not open under this key"),
            BackupError::Xml(rule) => write!(f, "the S3 response breaks the XML {rule} rule"),
            BackupError::S3Status(s) => write!(f, "the object store answered status {s}"),
            BackupError::S3Refused(code) => write!(f, "the object store refused: {code:?}"),
            BackupError::Transport(phase) => write!(f, "the request failed: {phase}"),
            BackupError::Config(rule) => write!(f, "the configuration was refused: {rule}"),
            BackupError::KeyFile(rule) => write!(f, "the key file was refused: {rule}"),
            BackupError::Custody(call) => write!(f, "custody refused the {call} call"),
            BackupError::Index(rule) => write!(f, "the backup index was refused: {rule}"),
            BackupError::NotFound => write!(f, "not found"),
            BackupError::Io(step) => write!(f, "the file step {step} failed"),
            BackupError::Tool(tool) => write!(f, "{tool} failed"),
            BackupError::TargetNotReached => {
                write!(f, "the archive ends before the restore target")
            }
            BackupError::WitnessForeign => {
                write!(
                    f,
                    "the object store holds witness copies this host did not write"
                )
            }
            BackupError::WitnessDiverged => {
                write!(f, "the witness store differs from its copies")
            }
        }
    }
}

impl std::error::Error for BackupError {}

/// One chunk of a backup container.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Chunk {
    /// The chunk index.
    pub index: u64,
    /// Whether this is the final chunk.
    pub last: bool,
    /// The sealed chunk bytes: the 12-byte nonce, then the ciphertext and
    /// its 16-byte tag.
    pub sealed: Vec<u8>,
}

/// One element of an S3 XML response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XmlElement {
    /// The depth: the root is 1.
    pub depth: u8,
    /// The name.
    pub name: String,
    /// The text, with references decoded. Empty for an element with
    /// child elements.
    pub text: String,
}

/// A decoded S3 XML response of the subset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct S3Response {
    /// The elements, in document order.
    pub elements: Vec<XmlElement>,
}

/// A PostgreSQL WAL segment name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct WalName {
    /// The timeline.
    pub timeline: u32,
    /// The segment number.
    pub segment: u64,
}

/// The length of a container of `plaintext` bytes (ADR-012 "Container
/// format"): the header, then one chunk of 33 bytes of framing per MiB or
/// part of one, and at least one chunk.
#[must_use]
pub const fn container_len(plaintext: usize) -> usize {
    let chunk = container::CHUNK_SIZE as usize;
    let chunks = if plaintext == 0 {
        1
    } else {
        plaintext.div_ceil(chunk)
    };
    container::HEADER_LEN
        .saturating_add(plaintext)
        .saturating_add(chunks.saturating_mul(33))
}

/// Decodes a backup container, `FBC1` or `FBC2`, into its sealed chunks
/// (ADR-012, record of lane m10/backup-format). Chunk order and the final
/// flag are enforced, and the data key must be sealed through the hybrid
/// KEM (R-CR-01). An `FBC2` container must end in exactly one signature,
/// which this does not verify ([`open_object`] does). Fuzzed
/// (`backup_container_decode`).
///
/// # Errors
///
/// Returns [`BackupError::Truncated`], [`BackupError::KeyNotHybrid`] or
/// [`BackupError::Malformed`] with the first rule the input breaks.
pub fn decode_container(bytes: &[u8]) -> Result<Vec<Chunk>, BackupError> {
    container::decode(bytes)
}

/// Decodes an S3 XML response ([`xml`]). DTDs, entities, processing
/// instructions, comments and CDATA are refused. Fuzzed
/// (`s3_xml_decode`).
///
/// # Errors
///
/// [`BackupError::Xml`] with the first rule the input breaks.
pub fn decode_s3_xml(bytes: &[u8]) -> Result<S3Response, BackupError> {
    xml::decode(bytes)
}

/// Parses a WAL segment name: 24 uppercase hex digits, the timeline,
/// the log id and the segment within it ([`wal`]). Fuzzed
/// (`wal_name_parse`).
///
/// # Errors
///
/// [`BackupError::Malformed`] for any other spelling.
pub fn parse_wal_name(name: &str) -> Result<WalName, BackupError> {
    wal::parse(name)
}

/// Parses a name `archive_command` hands over: a segment, a timeline
/// history file, or a kind the agent skips. Fuzzed (`wal_name_parse`).
///
/// # Errors
///
/// [`BackupError::Malformed`] for any other spelling.
pub fn parse_archive_name(name: &str) -> Result<ArchiveName, BackupError> {
    wal::parse_archive(name)
}

/// The start segment a `backup_label` names. Fuzzed (`wal_name_parse`).
///
/// # Errors
///
/// [`BackupError::Malformed`] when no `START WAL LOCATION` line names a
/// segment.
pub fn backup_label_start(label: &[u8]) -> Result<WalName, BackupError> {
    wal::start_segment(label)
}

/// The start segment and the start location a `backup_label` names.
/// Fuzzed (`wal_name_parse`).
///
/// # Errors
///
/// [`BackupError::Malformed`] when no `START WAL LOCATION` line names
/// both.
pub fn backup_label_location(label: &[u8]) -> Result<(WalName, u64), BackupError> {
    wal::start_location(label)
}

/// What the binary was asked to do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    /// `init-keys`: create `cluster-backup.key` and
    /// `cluster-backup-writer.key` in the credentials directory.
    InitKeys,
    /// `upgrade-keys`: turn a version 1 `cluster-backup.key` into version
    /// 2 bound to a writer key (record of lane m10/backup-format). A
    /// version 2 file is left as it is.
    UpgradeKeys,
    /// `base-backup`: one base backup.
    BaseBackup,
    /// `wal-archive <path> <name>`, for `archive_command` (`%p %f`).
    WalArchive {
        /// The file.
        path: PathBuf,
        /// Its archive name.
        name: String,
    },
    /// `wal-restore <name> <path>`, for `restore_command` (`%f %p`).
    WalRestore {
        /// The archive name.
        name: String,
        /// Where to write it.
        path: PathBuf,
    },
    /// `restore <data dir> [<backup id> <size>] [--to <unix seconds>]`.
    Restore {
        /// The new data directory.
        data_dir: PathBuf,
        /// The backup id and its plaintext size, or the newest of the
        /// index that suits the target.
        backup: Option<([u8; 16], u64)>,
        /// The point in time to restore to, in Unix seconds, or the
        /// newest archived point (ADR-012 record of lane
        /// `m10/backup-pitr`).
        target: Option<u64>,
    },
    /// `custodian-init`, on a second custodian: create `custodian.key`
    /// and `custodian.pub` in the credentials directory (ADR-012 record
    /// of lane L16).
    CustodianInit,
    /// `custodian-escrow <request> <out>`, on the first host: seal the
    /// group secret to the custodian key of the request file.
    CustodianEscrow {
        /// The request file of the second custodian.
        request: PathBuf,
        /// The new escrow file.
        out: PathBuf,
    },
    /// `witness-archive <store dir>`: one run of the witness store's copy
    /// (ADR-012 record of lane m10/witness-copy).
    WitnessArchive {
        /// The witness store directory.
        store: PathBuf,
    },
    /// `witness-fetch <dir>`: every copied witness file into a new or empty
    /// directory, as root.
    WitnessFetch {
        /// The directory.
        out: PathBuf,
    },
    /// `witness-restore <store dir>`: the witness store rebuilt from its
    /// copies where it is missing or behind, as root.
    WitnessRestore {
        /// The witness store directory.
        store: PathBuf,
    },
}

/// Parses the binary's arguments, without the program name.
///
/// # Errors
///
/// [`BackupError::Config`] (`arguments`) for any other form.
pub fn parse_args(args: &[String]) -> Result<Command, BackupError> {
    let usage = BackupError::Config("arguments");
    match args {
        [c] if c == "init-keys" => Ok(Command::InitKeys),
        [c] if c == "upgrade-keys" => Ok(Command::UpgradeKeys),
        [c] if c == "base-backup" => Ok(Command::BaseBackup),
        [c, path, name] if c == "wal-archive" => Ok(Command::WalArchive {
            path: PathBuf::from(path),
            name: name.clone(),
        }),
        [c, name, path] if c == "wal-restore" => Ok(Command::WalRestore {
            name: name.clone(),
            path: PathBuf::from(path),
        }),
        [c, dir, rest @ ..] if c == "restore" => {
            // ADR-012 record of lane `m10/backup-pitr`: an optional
            // `--to <unix seconds>` after the other forms.
            let (rest, target) = match rest {
                [r @ .., flag, secs] if flag == "--to" => {
                    (r, Some(index::decimal(secs).map_err(|_| usage)?))
                }
                r => (r, None),
            };
            let backup = match rest {
                [] => None,
                [id, size] => Some((
                    index::parse_hex16(id).map_err(|_| usage)?,
                    size.parse::<u64>().map_err(|_| usage)?,
                )),
                _ => return Err(usage),
            };
            Ok(Command::Restore {
                data_dir: PathBuf::from(dir),
                backup,
                target,
            })
        }
        [c] if c == "custodian-init" => Ok(Command::CustodianInit),
        [c, request, out] if c == "custodian-escrow" => Ok(Command::CustodianEscrow {
            request: PathBuf::from(request),
            out: PathBuf::from(out),
        }),
        [c, store] if c == "witness-archive" => Ok(Command::WitnessArchive {
            store: PathBuf::from(store),
        }),
        [c, out] if c == "witness-fetch" => Ok(Command::WitnessFetch {
            out: PathBuf::from(out),
        }),
        [c, store] if c == "witness-restore" => Ok(Command::WitnessRestore {
            store: PathBuf::from(store),
        }),
        _ => Err(usage),
    }
}

/// The console custody of `cfg`, for the commands that open or create
/// the group key.
fn console(cfg: &config::FileConfig) -> Result<fstp_custody::KeydCustody, BackupError> {
    let socket = cfg
        .keyd_socket
        .as_ref()
        .ok_or(BackupError::Config("keyd_socket"))?;
    fstp_custody::KeydCustody::new(socket).map_err(|_| BackupError::Config("keyd_socket"))
}

/// Runs `command` over the configuration file of
/// [`config::CONFIG_ENV`], on one tokio runtime through `fstp-rt`
/// (ADR-002).
///
/// # Errors
///
/// The first step that fails. `wal-restore` of a file the store does not
/// hold is [`BackupError::NotFound`].
pub fn run(command: &Command) -> Result<(), BackupError> {
    use fstp_rt::tokio::TokioRuntime;
    let cfg = config::load()?;
    let rt = TokioRuntime::new_multi_thread(2).map_err(|_| BackupError::Io("runtime"))?;
    if *command == Command::InitKeys {
        let path = cfg.credentials_dir.join(keyfile::KEY_FILE);
        let wpath = cfg.credentials_dir.join(writer::WRITER_FILE);
        for p in [&path, &wpath] {
            if std::fs::symlink_metadata(p).is_ok() {
                return Err(BackupError::Config(keyfile::KEY_FILE));
            }
        }
        let custody = console(&cfg)?;
        let created = rt.block_on(keyfile::create(&custody, cfg.cluster))?;
        write_key_file(&wpath, &created.writer_key)?;
        return write_key_file(&path, &created.key_file);
    }
    if *command == Command::UpgradeKeys {
        return upgrade_keys(&rt, &cfg);
    }
    if *command == Command::CustodianInit {
        let key_path = cfg.credentials_dir.join(custodian::CUSTODIAN_KEY_FILE);
        let req_path = cfg.credentials_dir.join(custodian::REQUEST_FILE);
        for p in [&key_path, &req_path] {
            if std::fs::symlink_metadata(p).is_ok() {
                return Err(BackupError::Config(custodian::CUSTODIAN_KEY_FILE));
            }
        }
        let custody = console(&cfg)?;
        let (key, request) = rt.block_on(custodian::init(&custody, cfg.cluster))?;
        write_key_file(&key_path, &key)?;
        return write_key_file(&req_path, &request);
    }
    if let Command::CustodianEscrow { request, out } = command {
        let request = read_small(request, custodian::REQUEST_LEN)?;
        let key = keyfile::decode(&config::read_credential(
            &cfg.credentials_dir,
            keyfile::KEY_FILE,
        )?)?;
        let custody = console(&cfg)?;
        let escrow = rt.block_on(custodian::escrow(&custody, &key, &request))?;
        return write_key_file(out, &escrow);
    }
    let agent = agent::Agent::from_config(rt.clone(), &cfg)?;
    rt.block_on(async {
        match command {
            Command::InitKeys
            | Command::UpgradeKeys
            | Command::CustodianInit
            | Command::CustodianEscrow { .. } => Ok(()),
            Command::BaseBackup => {
                agent.base_backup(&cfg).await?;
                // ADR-012 record of lane m10/backup-format: pruning follows
                // a successful base backup and never fails it.
                if let Some(r) = &cfg.retention {
                    let _ = agent.prune(r, agent::now_unix()).await;
                }
                Ok(())
            }
            Command::WalArchive { path, name } => agent.archive(path, name).await.map(|_| ()),
            Command::WitnessArchive { store } => agent.witness_archive(store).await.map(|_| ()),
            Command::WitnessFetch { out } => {
                let secret = open_group_secret(&agent, &cfg).await?;
                agent.witness_fetch(&secret, out).await.map(|_| ())
            }
            Command::WitnessRestore { store } => {
                let secret = open_group_secret(&agent, &cfg).await?;
                agent.witness_restore(&secret, store).await.map(|_| ())
            }
            Command::WalRestore { name, path } => {
                let secret = open_group_secret(&agent, &cfg).await?;
                agent.restore_wal(&secret, name, path).await
            }
            Command::Restore {
                data_dir,
                backup,
                target,
            } => {
                // ADR-012 record of lane `m10/backup-pitr`: the named
                // backup, or each backup of the index that finished before
                // the target, newest first.
                let entries = match backup {
                    Some((id, size)) => vec![index::IndexEntry {
                        cluster: cfg.cluster,
                        backup: *id,
                        at: 0,
                        size: *size,
                    }],
                    None => index::before(&cfg.state_dir, cfg.cluster, *target)?,
                };
                let secret = open_group_secret(&agent, &cfg).await?;
                agent
                    .restore_to(&secret, &entries, data_dir, *target)
                    .await?;
                recovery::check(&cfg.pg_bindir, data_dir, *target)
            }
        }
    })
}

/// The group secret for a restore command, through the console socket.
/// On a second custodian, whose credentials directory holds the escrow,
/// it opens the custodian key and then the escrow (ADR-012 record of lane
/// L16). Otherwise it opens the key file under this host's root.
async fn open_group_secret<R: fstp_rt::Runtime>(
    agent: &agent::Agent<R>,
    cfg: &config::FileConfig,
) -> Result<fstp_crypto::hybrid_kem::HybridSecretKey, BackupError> {
    let custody = console(cfg)?;
    let escrow = cfg.credentials_dir.join(custodian::ESCROW_FILE);
    if std::fs::symlink_metadata(&escrow).is_err() {
        return agent.open_secret(&custody).await;
    }
    let escrow = read_small(&escrow, custodian::MAX_ESCROW_LEN)?;
    let key = config::read_credential(&cfg.credentials_dir, custodian::CUSTODIAN_KEY_FILE)?;
    agent.open_escrow(&custody, &key, &escrow).await
}

/// `upgrade-keys` (record of lane m10/backup-format): a version 2 key
/// file is left as it is. A version 1 file is opened through the console
/// socket and replaced by a version 2 file for the same group key, bound
/// to the writer key file, which is created first unless it exists. The
/// key file is replaced through a temporary file and a rename.
fn upgrade_keys(
    rt: &fstp_rt::tokio::TokioRuntime,
    cfg: &config::FileConfig,
) -> Result<(), BackupError> {
    let dir = &cfg.credentials_dir;
    let bytes = config::read_credential(dir, keyfile::KEY_FILE)?;
    let wpath = dir.join(writer::WRITER_FILE);
    let existing = match std::fs::read(&wpath) {
        Ok(w) => Some(writer::WriterKey::decode(&zeroize::Zeroizing::new(w))?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => return Err(BackupError::Config(writer::WRITER_FILE)),
    };
    if let Ok(v2) = keyfile::decode(&bytes) {
        return match &existing {
            Some(w) => v2.check_writer(w),
            None => Err(BackupError::Config(writer::WRITER_FILE)),
        };
    }
    let had_writer = existing.is_some();
    let custody = console(cfg)?;
    let created = rt.block_on(keyfile::upgrade(&custody, &bytes, existing))?;
    if !had_writer {
        write_key_file(&wpath, &created.writer_key)?;
    }
    let tmp = dir.join(format!("{}.upgrade", keyfile::KEY_FILE));
    let _ = std::fs::remove_file(&tmp);
    write_key_file(&tmp, &created.key_file)?;
    std::fs::rename(&tmp, dir.join(keyfile::KEY_FILE)).map_err(|_| BackupError::Io("key file"))
}

/// Reads a file of at most `max` bytes.
fn read_small(path: &std::path::Path, max: usize) -> Result<Vec<u8>, BackupError> {
    let meta = std::fs::metadata(path).map_err(|_| BackupError::Io("read a ceremony file"))?;
    if meta.len() > u64::try_from(max).unwrap_or(u64::MAX) {
        return Err(BackupError::KeyFile("ceremony file length"));
    }
    std::fs::read(path).map_err(|_| BackupError::Io("read a ceremony file"))
}

/// Writes a new key file with mode 0600.
fn write_key_file(path: &std::path::Path, bytes: &[u8]) -> Result<(), BackupError> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| BackupError::Io("key file"))?;
    f.write_all(bytes)
        .and_then(|()| f.sync_all())
        .map_err(|_| BackupError::Io("key file"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_owned()).collect()
    }

    /// ADR-012 records of lanes L10, L16 and m10/backup-format: the eight
    /// command forms, and no other.
    #[test]
    fn adr012_binary_takes_eight_command_forms() {
        assert_eq!(
            parse_args(&s(&["upgrade-keys"])).unwrap(),
            Command::UpgradeKeys
        );
        assert_eq!(
            parse_args(&s(&["custodian-init"])).unwrap(),
            Command::CustodianInit
        );
        assert_eq!(
            parse_args(&s(&["custodian-escrow", "/r", "/o"])).unwrap(),
            Command::CustodianEscrow {
                request: PathBuf::from("/r"),
                out: PathBuf::from("/o")
            }
        );
        assert_eq!(parse_args(&s(&["init-keys"])).unwrap(), Command::InitKeys);
        assert_eq!(
            parse_args(&s(&["base-backup"])).unwrap(),
            Command::BaseBackup
        );
        assert_eq!(
            parse_args(&s(&["wal-archive", "pg_wal/x", "000000010000000000000001"])).unwrap(),
            Command::WalArchive {
                path: PathBuf::from("pg_wal/x"),
                name: "000000010000000000000001".to_owned()
            }
        );
        assert!(matches!(
            parse_args(&s(&[
                "wal-restore",
                "00000002.history",
                "pg_wal/RECOVERYHISTORY"
            ]))
            .unwrap(),
            Command::WalRestore { .. }
        ));
        assert_eq!(
            parse_args(&s(&["restore", "/d", &"ab".repeat(16), "12"])).unwrap(),
            Command::Restore {
                data_dir: PathBuf::from("/d"),
                backup: Some(([0xab; 16], 12)),
                target: None,
            }
        );
        for bad in [
            &[][..],
            &["base-backup", "x"],
            &["wal-archive", "p"],
            &["restore", "/d", "nothex", "1"],
            &["restore", "/d", &"ab".repeat(16)],
            &["serve"],
            &["custodian-init", "x"],
            &["custodian-escrow", "/r"],
            &["upgrade-keys", "x"],
        ] {
            assert_eq!(
                parse_args(&s(bad)).unwrap_err(),
                BackupError::Config("arguments")
            );
        }
    }

    /// ADR-012 record of lane `m10/backup-pitr`: `restore` takes an
    /// optional `--to <unix seconds>` after either form, in one spelling,
    /// and the forms without it are unchanged.
    #[test]
    fn adr012_pitr_binary_takes_a_target() {
        let id = "ab".repeat(16);
        assert_eq!(
            parse_args(&s(&["restore", "/d"])).unwrap(),
            Command::Restore {
                data_dir: PathBuf::from("/d"),
                backup: None,
                target: None,
            }
        );
        assert_eq!(
            parse_args(&s(&["restore", "/d", "--to", "1795514400"])).unwrap(),
            Command::Restore {
                data_dir: PathBuf::from("/d"),
                backup: None,
                target: Some(1_795_514_400),
            }
        );
        assert_eq!(
            parse_args(&s(&["restore", "/d", &id, "12", "--to", "7"])).unwrap(),
            Command::Restore {
                data_dir: PathBuf::from("/d"),
                backup: Some(([0xab; 16], 12)),
                target: Some(7),
            }
        );
        for bad in [
            &["restore", "/d", "--to"][..],
            &["restore", "/d", "--to", "07"],
            &["restore", "/d", "--to", "+7"],
            &["restore", "/d", "--to", "2026-11-24T10:00:00Z"],
            &["restore", "/d", "--to", "7", "x"],
            &["restore", "/d", "--at", "7"],
            &["restore", "/d", &id, "--to", "7"],
        ] {
            assert_eq!(
                parse_args(&s(bad)).unwrap_err(),
                BackupError::Config("arguments"),
                "{bad:?}"
            );
        }
    }

    /// ADR-012 record of lane m10/witness-copy, row "Mechanism": the three
    /// witness commands each take one directory, and nothing else.
    #[test]
    fn adr012_wc_binary_takes_the_witness_commands() {
        let d = PathBuf::from("/s/witness");
        assert_eq!(
            parse_args(&s(&["witness-archive", "/s/witness"])).unwrap(),
            Command::WitnessArchive { store: d.clone() }
        );
        assert_eq!(
            parse_args(&s(&["witness-fetch", "/s/witness"])).unwrap(),
            Command::WitnessFetch { out: d.clone() }
        );
        assert_eq!(
            parse_args(&s(&["witness-restore", "/s/witness"])).unwrap(),
            Command::WitnessRestore { store: d }
        );
        for bad in [
            &["witness-archive"][..],
            &["witness-fetch", "/a", "/b"],
            &["witness-restore"],
        ] {
            assert_eq!(
                parse_args(&s(bad)).unwrap_err(),
                BackupError::Config("arguments"),
                "{bad:?}"
            );
        }
    }

    /// ADR-012 "Container format": the container length formula matches
    /// the writer, for an empty, a short and a two-chunk plaintext.
    #[test]
    fn adr012_container_len_matches_the_writer() {
        let sk = fstp_crypto::hybrid_kem::generate().unwrap();
        let g = GroupRef {
            owner: [1; 16],
            group: fstp_keys::GroupId([2; 16]),
            generation: 1,
        };
        for n in [0usize, 5, (1 << 20) + 3] {
            let c =
                seal_container(sk.public(), ContainerKind::WalSegment, &g, 0, &vec![7; n]).unwrap();
            assert_eq!(c.len(), container_len(n), "{n}");
        }
    }
}
