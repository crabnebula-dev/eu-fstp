//! The closed set of outbound destinations of a vault (B4a, ADR-009
//! "Outbound destinations").
//!
//! The vault's connector opens connections only to a [`VaultDestination`],
//! and the host firewall holds the same list. The vault answers its own
//! cell and the vault origin, and calls neither. A new variant needs an
//! amendment of ADR-009.
//!
//! Status: W0 stub. Lane W2d writes the connector. [`connect`] refuses
//! with [`VaultError::NotImplemented`] until then.

use crate::VaultError;

/// Where a vault may open a connection. Closed and exhaustive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultDestination {
    /// `v_<cell>` on its vault cluster.
    VaultDatabase,
    /// Its own Vault custody entry, with its own credential.
    Custody,
    /// The witness, for the Vault chain's prepares, aborts and receipts.
    Witness,
    /// The `<cell>/keystore/` object storage prefix only. Proposed by
    /// ADR-012 and pending Daniel, so no connector builds it yet.
    KeystoreSnapshots,
}

/// Opens a connection to `to`.
pub fn connect(to: &VaultDestination) -> Result<(), VaultError> {
    let _ = to;
    Err(VaultError::NotImplemented("fstp_vault::egress::connect"))
}
