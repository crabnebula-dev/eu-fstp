//! The identity vault service: internal API, vault origin, persistence,
//! vault migrations and its own anchorer (M3 design section 6).
//!
//! The vault has no seeding path. Test facts come from `fstp-celltest`
//! only (design section 6.9, layering rule 9).
//!
//! Status: W0 stub. Lane W2d fills the crate. Every operation refuses with
//! [`VaultError::NotImplemented`].

pub mod egress;

pub use egress::VaultDestination;

use fstp_migrate::catalogue::TableSpec;

/// The tables of the vault database (`v_<cell>`). Lane W2d lists them next
/// to its migrations.
pub const CATALOGUE: &[TableSpec] = &[];

/// Why a vault operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultError {
    /// The operation is a W0 stub. It names the operation.
    NotImplemented(&'static str),
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultError::NotImplemented(op) => write!(f, "{op} is not implemented yet"),
        }
    }
}

impl std::error::Error for VaultError {}

/// A write that arrives on the vault origin (design section 6.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OriginWrite {
    /// The ticket bytes.
    pub ticket: Vec<u8>,
    /// The body bytes.
    pub body: Vec<u8>,
}

/// A stored fact body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FactBody {
    /// The fact kind.
    pub kind: u16,
    /// The canonical fields.
    pub fields: Vec<u8>,
}

/// Decodes an origin write. Fuzzed (`origin_write_decode`). The ticket
/// signature is checked before any field is used.
pub fn decode_origin_write(bytes: &[u8]) -> Result<OriginWrite, VaultError> {
    let _ = bytes;
    Err(VaultError::NotImplemented(
        "fstp_vault::decode_origin_write",
    ))
}

/// Decodes a stored fact body. Fuzzed (`fact_body_decode`).
pub fn decode_fact_body(bytes: &[u8]) -> Result<FactBody, VaultError> {
    let _ = bytes;
    Err(VaultError::NotImplemented("fstp_vault::decode_fact_body"))
}

/// Runs the vault service until shutdown.
pub fn run() -> Result<(), VaultError> {
    Err(VaultError::NotImplemented("fstp_vault::run"))
}
