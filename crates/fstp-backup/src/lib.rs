//! The backup agent: backup container, multipart S3 client with SigV4 and
//! an XML subset parser (M3 design section 3.8, ADR-012).
//!
//! Status: the container decoder (lane F-CRYPTO), the container writer and
//! opener and the WAL segment name parser (lane F-ERASE) are built. The S3
//! client, the XML subset parser and the agent run loop are W0 stubs that
//! refuse with [`BackupError::NotImplemented`] until lane W2k fills them.
//! Until then the test world plays the uploader and the object store.

mod container;
mod seal;
mod wal;

pub use seal::{ContainerKind, GroupRef, Opened, open_container, seal_container};

/// Why a backup operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackupError {
    /// The operation is a W0 stub. It names the operation.
    NotImplemented(&'static str),
    /// The container ends before its final chunk does (ADR-012).
    Truncated,
    /// The container's data key is not an `FSK1` key sealed through the
    /// hybrid KEM on the container's chain (R-CR-01).
    KeyNotHybrid,
    /// The container breaks an ADR-012 rule. It names the rule.
    Malformed(&'static str),
    /// Sealing failed: the KEM, the AEAD or the generator. It names the
    /// part.
    Seal(&'static str),
    /// The data key or a chunk did not open under the given group secret.
    OpenFailed,
}

impl std::fmt::Display for BackupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackupError::NotImplemented(op) => write!(f, "{op} is not implemented yet"),
            BackupError::Truncated => write!(f, "the container is truncated"),
            BackupError::KeyNotHybrid => {
                write!(f, "the data key is not sealed through the hybrid KEM")
            }
            BackupError::Malformed(rule) => write!(f, "the container breaks the {rule} rule"),
            BackupError::Seal(part) => write!(f, "sealing the {part} failed"),
            BackupError::OpenFailed => write!(f, "the container does not open under this key"),
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

/// A decoded S3 XML response of the subset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct S3Response {
    /// The element names and texts, in order.
    pub elements: Vec<(String, String)>,
}

/// A PostgreSQL WAL segment name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct WalName {
    /// The timeline.
    pub timeline: u32,
    /// The segment number.
    pub segment: u64,
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

/// Decodes an S3 XML response. DTDs, entities and processing instructions
/// are refused. Fuzzed (`s3_xml_decode`).
pub fn decode_s3_xml(bytes: &[u8]) -> Result<S3Response, BackupError> {
    let _ = bytes;
    Err(BackupError::NotImplemented("fstp_backup::decode_s3_xml"))
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

/// Runs one backup agent invocation.
pub fn run() -> Result<(), BackupError> {
    Err(BackupError::NotImplemented("fstp_backup::run"))
}
