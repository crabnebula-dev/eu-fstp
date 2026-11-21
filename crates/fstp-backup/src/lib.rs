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
pub mod index;
pub mod keyfile;
pub mod s3;
mod seal;
pub mod sigv4;
mod wal;
pub mod xml;

use std::path::PathBuf;

pub use seal::{ContainerKind, GroupRef, Opened, open_container, seal_container};
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
    /// A host tool (`pg_basebackup`, `tar`) failed. It names the tool.
    Tool(&'static str),
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

/// Decodes a backup container into its sealed chunks (ADR-012). Chunk
/// order and the final flag are enforced, and the data key must be
/// sealed through the hybrid KEM (R-CR-01). Fuzzed
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

/// What the binary was asked to do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    /// `init-keys`: create `cluster-backup.key` in the credentials
    /// directory.
    InitKeys,
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
    /// `restore <data dir> [<backup id> <size>]`.
    Restore {
        /// The new data directory.
        data_dir: PathBuf,
        /// The backup id and its plaintext size, or the newest of the
        /// index.
        backup: Option<([u8; 16], u64)>,
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
        [c] if c == "base-backup" => Ok(Command::BaseBackup),
        [c, path, name] if c == "wal-archive" => Ok(Command::WalArchive {
            path: PathBuf::from(path),
            name: name.clone(),
        }),
        [c, name, path] if c == "wal-restore" => Ok(Command::WalRestore {
            name: name.clone(),
            path: PathBuf::from(path),
        }),
        [c, dir] if c == "restore" => Ok(Command::Restore {
            data_dir: PathBuf::from(dir),
            backup: None,
        }),
        [c, dir, id, size] if c == "restore" => {
            let id = index::parse_hex16(id).map_err(|_| usage)?;
            let size = size.parse::<u64>().map_err(|_| usage)?;
            Ok(Command::Restore {
                data_dir: PathBuf::from(dir),
                backup: Some((id, size)),
            })
        }
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
        if std::fs::symlink_metadata(&path).is_ok() {
            return Err(BackupError::Config(keyfile::KEY_FILE));
        }
        let custody = console(&cfg)?;
        let bytes = rt.block_on(keyfile::create(&custody, cfg.cluster))?;
        return write_key_file(&path, &bytes);
    }
    let agent = agent::Agent::from_config(rt.clone(), &cfg)?;
    rt.block_on(async {
        match command {
            Command::InitKeys => Ok(()),
            Command::BaseBackup => agent.base_backup(&cfg).await.map(|_| ()),
            Command::WalArchive { path, name } => agent.archive(path, name).await.map(|_| ()),
            Command::WalRestore { name, path } => {
                let secret = agent.open_secret(&console(&cfg)?).await?;
                agent.restore_wal(&secret, name, path).await
            }
            Command::Restore { data_dir, backup } => {
                let entry = match backup {
                    Some((id, size)) => index::IndexEntry {
                        cluster: cfg.cluster,
                        backup: *id,
                        at: 0,
                        size: *size,
                    },
                    None => index::newest(&cfg.state_dir, cfg.cluster)?,
                };
                let secret = agent.open_secret(&console(&cfg)?).await?;
                agent.restore(&secret, &entry, data_dir).await.map(|_| ())
            }
        }
    })
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

    /// ADR-012 record of lane L10: the five command forms, and no other.
    #[test]
    fn adr012_binary_takes_five_command_forms() {
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
                backup: Some(([0xab; 16], 12))
            }
        );
        for bad in [
            &[][..],
            &["base-backup", "x"],
            &["wal-archive", "p"],
            &["restore", "/d", "nothex", "1"],
            &["restore", "/d", &"ab".repeat(16)],
            &["serve"],
        ] {
            assert_eq!(
                parse_args(&s(bad)).unwrap_err(),
                BackupError::Config("arguments")
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
