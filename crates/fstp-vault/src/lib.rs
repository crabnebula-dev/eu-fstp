//! The identity vault service: internal API, vault origin, persistence,
//! vault migrations and its own anchorer (M3 design section 6).
//!
//! - [`origin`]: the vault origin (`POST /w`, `POST /r`) and the internal
//!   API, sans I/O, over `fstp-vault-core`.
//! - [`codec`]: the origin write frame and the stored fact body.
//! - [`catalogue`] and [`MIGRATIONS`]: the vault database `v_<cell>`.
//! - [`start`]: the I-83 start check over the placement marker, the server
//!   certificate OU and the registered SPKI (design section 9.2).
//! - [`service`]: the run loop of the internal listener and the vault
//!   origin, over the database and the sans-IO core (lane int5).
//! - [`config`]: the process configuration, with a closed member set.
//! - [`match_key`]: the identity match key of design section 6.4 (Q17).
//! - [`egress`]: the closed set of outbound destinations (B4a).
//!
//! The vault has no seeding path. Test facts come from `fstp-celltest`
//! only (design section 6.9, layering rule 9). The route tables, the
//! configuration decoder and this crate's sources name no seed route,
//! flag or file.

pub mod catalogue;
pub mod chain;
pub mod codec;
pub mod config;
pub mod egress;
pub mod origin;
pub mod service;
pub mod start;
pub mod store;

pub use catalogue::CATALOGUE;
pub use codec::{FactBody, OriginWrite, decode_fact_body, decode_origin_write};
pub use egress::VaultDestination;
pub use origin::{JournalEntry, OriginRefusal, Reply, Vault, Written};

/// The vault migrations, in order (design sections 4.1 and 4.6). They
/// mirror the application set `fstp_pgstore::MIGRATIONS`:
///
/// 1. `meta`: `fstp_meta.placement` with kind 2 only, and the shared
///    trigger function. Provisioning writes the one placement row as the
///    migrator (design section 9.2 step 7).
/// 2. `apply_grant`: `fstp_migrate::catalogue::APPLY_GRANT_SQL`, the one
///    shared text of design section 4.1, byte for byte, then
///    `APPLY_GRANT_REVOKE_SQL`, so PUBLIC never holds EXECUTE on the
///    function after the migration commits. A test ties the file to the
///    two constants.
/// 3. `vault`: the schemas, tables and triggers of design section 4.3.
/// 4. `bank`: the bank and hardship fact kinds of M5 (I-33, R-PR-04).
/// 5. `migration_ledger`: `fstp_migrate.schema_migrations` in the runner's
///    own shape, for a set applied without the runner (I-16).
/// 6. `column_classes`: the length checks of Daniel's Q-A classes
///    (2026-11-07, design section 4.5, R-NF-08).
/// 7. `vault_chain`: the entry columns of a kind 1 row of the vault chain
///    (ADR-010 open point 5, Daniel, 2026-11-13).
pub const MIGRATIONS: &[fstp_migrate::Migration] = &[
    fstp_migrate::Migration::new(1, "meta", include_str!("../migrations/vault/0001_meta.sql")),
    fstp_migrate::Migration::new(
        2,
        "apply_grant",
        include_str!("../migrations/vault/0002_apply_grant.sql"),
    ),
    fstp_migrate::Migration::new(
        3,
        "vault",
        include_str!("../migrations/vault/0003_vault.sql"),
    ),
    fstp_migrate::Migration::new(4, "bank", include_str!("../migrations/vault/0004_bank.sql")),
    fstp_migrate::Migration::new(
        5,
        "migration_ledger",
        include_str!("../migrations/vault/0005_migration_ledger.sql"),
    ),
    fstp_migrate::Migration::new(
        6,
        "column_classes",
        include_str!("../migrations/vault/0006_column_classes.sql"),
    ),
    fstp_migrate::Migration::new(
        7,
        "vault_chain",
        include_str!("../migrations/vault/0007_vault_chain.sql"),
    ),
];

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

/// The binary's entry. It refuses: the process configuration and the
/// vault keystore that gives the sealing and anchor keys are not built.
/// [`service::serve`] is the run loop, which a world starts with the
/// parts it holds.
///
/// # Errors
///
/// [`VaultError::NotImplemented`].
pub fn run() -> Result<(), VaultError> {
    Err(VaultError::NotImplemented(
        "fstp_vault::run: the process configuration and the vault keystore; fstp_vault::service::serve is the run loop",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fstp_migrate::catalogue::{APPLY_GRANT_REVOKE_SQL, APPLY_GRANT_SQL};

    /// I-82, design section 4.6: the vault set is a valid migration list.
    #[test]
    fn i82_vault_migrations_form_a_valid_set() {
        assert!(fstp_migrate::MigrationSet::new(MIGRATIONS).is_ok());
    }

    /// I-82, design section 4.1: migration 2 is the shared function text
    /// and the shared revoke, each followed by one line break only, as in
    /// the application set.
    #[test]
    fn i82_vault_apply_grant_file_is_the_shared_text() {
        let file = include_str!("../migrations/vault/0002_apply_grant.sql");
        assert_eq!(
            file,
            format!("{APPLY_GRANT_SQL}\n{APPLY_GRANT_REVOKE_SQL}\n")
        );
    }

    /// I-82, design section 4.6: no vault migration installs an extension
    /// or defines a SECURITY DEFINER function.
    #[test]
    fn i82_vault_migrations_name_no_extension_and_no_security_definer() {
        for m in MIGRATIONS {
            let upper = m.sql.to_ascii_uppercase();
            assert!(!upper.contains("CREATE EXTENSION"), "{}", m.name);
            assert!(!upper.contains("SECURITY DEFINER"), "{}", m.name);
        }
    }

    /// I-83, design section 4.1: the vault placement table takes kind 2
    /// only, and checks the vault database grammar `v_<cell>`.
    #[test]
    fn i83_vault_placement_marker_is_kind_2() {
        let meta = include_str!("../migrations/vault/0001_meta.sql");
        assert!(meta.contains("CHECK (kind = 2)"));
        assert!(meta.contains("'^v_[0-9a-f]{32}$'"));
        assert_eq!(start::VAULT_MARKER, 2);
    }
}
