//! The identity vault service: internal API, vault origin, persistence,
//! vault migrations and its own anchorer (M3 design section 6).
//!
//! - [`origin`]: the vault origin (`POST /w`, `POST /r`) and the internal
//!   API, sans I/O, over `fstp-vault-core`.
//! - [`codec`]: the origin write frame and the stored fact body.
//! - [`catalogue`] and [`MIGRATIONS`]: the vault database `v_<cell>`.
//! - [`config`]: the process configuration, with a closed member set.
//! - [`match_key`]: the identity match key of design section 6.4 (Q17).
//! - [`egress`]: the closed set of outbound destinations (B4a).
//!
//! The vault has no seeding path. Test facts come from `fstp-celltest`
//! only (design section 6.9, layering rule 9). The route tables, the
//! configuration decoder and this crate's sources name no seed route,
//! flag or file.

pub mod catalogue;
pub mod codec;
pub mod config;
pub mod egress;
pub mod origin;
pub mod store;

pub use catalogue::CATALOGUE;
pub use codec::{FactBody, OriginWrite, decode_fact_body, decode_origin_write};
pub use egress::VaultDestination;
pub use origin::{JournalEntry, OriginRefusal, Reply, Vault, Written};

/// The vault migrations, in order (design section 4.6).
pub const MIGRATIONS: &[fstp_migrate::Migration] = &[fstp_migrate::Migration::new(
    1,
    "vault",
    include_str!("../migrations/vault/0001_vault.sql"),
)];

/// Why a vault operation failed. No variant holds tenant data (R-NF-02).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultError {
    /// A part of the process that waits on another lane. It names the
    /// part.
    NotImplemented(&'static str),
    /// The input does not decode. It names what failed.
    Malformed(&'static str),
    /// The vault cannot serve the request now. It names what failed.
    Unavailable(&'static str),
    /// The database refused a second use of something single-use. It
    /// names what.
    Conflict(&'static str),
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultError::NotImplemented(op) => write!(f, "{op} is not implemented yet"),
            VaultError::Malformed(what) => write!(f, "malformed {what}"),
            VaultError::Unavailable(what) => write!(f, "{what} is unavailable"),
            VaultError::Conflict(what) => write!(f, "{what} was refused as a repeat"),
        }
    }
}

impl std::error::Error for VaultError {}

/// The length of an identity match key.
pub const MATCH_KEY_LEN: usize = 32;

/// The identity match key of `tuple` under the cell's Match key `key`:
/// `HMAC-SHA-256(Match key, canonical attribute tuple of the method)`
/// (design section 6.4, Q17). The Match key differs per cell, so keys
/// never correlate across tenants (I-20).
pub fn match_key(key: &[u8; 32], tuple: &[u8]) -> [u8; MATCH_KEY_LEN] {
    fstp_crypto::hmac_sha256(key, tuple)
}

/// Runs the vault service until shutdown.
///
/// # Errors
///
/// [`VaultError::NotImplemented`]: the process waits on the sealing calls
/// of `fstp-keys` and on custody (lane W2f), and on the vault chain writer
/// of `fstp-audit` (lane W2g). Every fact body and negotiation fact is
/// sealed at rest, so the vault does not start without them.
pub fn run() -> Result<(), VaultError> {
    Err(VaultError::NotImplemented(
        "fstp_vault::run (waits on fstp-keys sealing and custody, lane W2f, and the vault chain, lane W2g)",
    ))
}
