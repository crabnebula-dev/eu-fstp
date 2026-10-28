//! File custody server for self-hosted cells (I-80, Q32, ADR-004 part 2).
//!
//! `fstp-keyd` is the only shipped crate that names [`RootMaterial`]
//! (layering rule 7). It serves wrap, unwrap, destroy and usage requests on
//! a Unix socket that only the cell and vault OS users can read.
//!
//! Status: W0 stub. Lane W2f fills the crate. Every operation refuses with
//! [`KeydError::NotImplemented`].
//!
//! Seam: [`RootMaterial`] is designed to wipe itself through zeroize.
//! zeroize is not a dependency until Daniel accepts ADR-001 A1, so the type
//! does not wipe yet (`docs/handoff/m3-base.md`).

/// The root bytes of file custody. No `Clone`, no `Debug`, and no way out
/// of this crate (I-80).
pub struct RootMaterial {
    bytes: [u8; 32],
}

impl RootMaterial {
    /// The number of root bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the material is empty. It never is.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// Why a keyd operation failed. Its display never holds key bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeydError {
    /// The operation is a W0 stub. It names the operation.
    NotImplemented(&'static str),
}

impl std::fmt::Display for KeydError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeydError::NotImplemented(op) => write!(f, "{op} is not implemented yet"),
        }
    }
}

impl std::error::Error for KeydError {}

/// A request to the server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeydRequest {
    /// Create a root.
    CreateRoot,
    /// Wrap a seal key.
    Wrap,
    /// Unwrap a seal key.
    Unwrap,
    /// Destroy a root.
    Destroy,
    /// Read the usage log.
    UsageSince,
}

/// The decoded custody file of the key volume. No `Debug`, since it holds
/// root material.
pub struct CustodyFile {
    roots: Vec<RootMaterial>,
}

impl CustodyFile {
    /// The number of roots the file holds.
    pub fn root_count(&self) -> usize {
        self.roots.len()
    }
}

/// Decodes one request frame. Fuzzed (`keyd_request_decode`).
pub fn decode_request(bytes: &[u8]) -> Result<KeydRequest, KeydError> {
    let _ = bytes;
    Err(KeydError::NotImplemented("fstp_keyd::decode_request"))
}

/// Decodes the custody file. Fuzzed (`custody_file_decode`).
pub fn decode_custody_file(bytes: &[u8]) -> Result<CustodyFile, KeydError> {
    let _ = bytes;
    Err(KeydError::NotImplemented("fstp_keyd::decode_custody_file"))
}

/// Runs the server until shutdown.
pub fn serve(socket: &std::path::Path, key_volume: &std::path::Path) -> Result<(), KeydError> {
    let _ = (socket, key_volume);
    Err(KeydError::NotImplemented("fstp_keyd::serve"))
}
