//! The backup agent: backup container, multipart S3 client with SigV4 and
//! an XML subset parser (M3 design section 3.8, ADR-012).
//!
//! Status: W0 stub. Lane W2k fills the crate. Every operation refuses with
//! [`BackupError::NotImplemented`].

/// Why a backup operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackupError {
    /// The operation is a W0 stub. It names the operation.
    NotImplemented(&'static str),
}

impl std::fmt::Display for BackupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackupError::NotImplemented(op) => write!(f, "{op} is not implemented yet"),
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
    /// The sealed chunk bytes.
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

/// Decodes a backup container. Chunk order and the final flag are
/// enforced. Fuzzed (`backup_container_decode`).
pub fn decode_container(bytes: &[u8]) -> Result<Vec<Chunk>, BackupError> {
    let _ = bytes;
    Err(BackupError::NotImplemented("fstp_backup::decode_container"))
}

/// Decodes an S3 XML response. DTDs, entities and processing instructions
/// are refused. Fuzzed (`s3_xml_decode`).
pub fn decode_s3_xml(bytes: &[u8]) -> Result<S3Response, BackupError> {
    let _ = bytes;
    Err(BackupError::NotImplemented("fstp_backup::decode_s3_xml"))
}

/// Parses a WAL segment name. Fuzzed (`wal_name_parse`).
pub fn parse_wal_name(name: &str) -> Result<WalName, BackupError> {
    let _ = name;
    Err(BackupError::NotImplemented("fstp_backup::parse_wal_name"))
}

/// Runs one backup agent invocation.
pub fn run() -> Result<(), BackupError> {
    Err(BackupError::NotImplemented("fstp_backup::run"))
}
