//! The vault fact seeder (design section 6.9). Test only: the identifiers
//! `SeedSource` and `seed_fact` appear nowhere else, so no shipped binary
//! can write a vault fact around the vault's own write rules (layering
//! rule 9). Lane W1a.

use crate::NotImplemented;

/// Where a seeded fact claims to come from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeedSource {
    /// A synthetic verification.
    SyntheticVerification,
    /// A synthetic affiliation.
    SyntheticAffiliation,
    /// A synthetic guardian consent.
    SyntheticConsent,
}

/// Seeds one fact into a vault state through `fstp-vault-core`.
pub fn seed_fact(
    state: &mut fstp_vault_core::VaultState,
    source: SeedSource,
    body: &[u8],
) -> Result<(), NotImplemented> {
    let _ = (state, source, body);
    Err(NotImplemented::new("fstp_celltest::vault_seed::seed_fact"))
}

/// Runs the seeded vault as a process until shutdown.
pub fn run() -> Result<(), NotImplemented> {
    Err(NotImplemented::new("fstp_celltest::vault_seed::run"))
}
