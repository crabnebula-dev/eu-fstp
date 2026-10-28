//! The vault fact seeder (design section 6.9). Test only: the identifiers
//! `SeedSource` and `seed_fact` appear nowhere else, so no shipped binary
//! can write a vault fact around the vault's own write rules (layering
//! rule 9). Lane W1a.
//!
//! A seeded fact goes through `fstp_vault_core::write`, the same entry the
//! vault uses, so it becomes effective exactly as a real one does: only
//! after the cell's reaction (NOTE 4). The seeder never touches vault
//! state directly. Every seeded write is recorded with its source, so a
//! claim built on seeding can say so.
//!
//! Seams: the fact kinds and body encodings are lane W2d's, so the caller
//! passes a ready `FactWrite`. `fstp_vault_core::write` and
//! `fstp_vault::run` refuse until lane W2d lands them, and the seeder
//! passes their refusal on.

use std::fmt;

use fstp_vault_core::{CoreError, FactWrite, VaultEvent, VaultState};
use fstp_vault_proto::VaultRefusal;

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

/// Why a seeded write did not land.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeedError {
    /// The vault core refused the write, as it would refuse a real one.
    Refused(VaultRefusal),
    /// A part the seeder needs is not built yet. It names the part.
    NotImplemented(NotImplemented),
}

impl fmt::Display for SeedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SeedError::Refused(r) => write!(f, "the vault core refused the seeded fact: {r:?}"),
            SeedError::NotImplemented(e) => write!(f, "{e} (NotImplemented)"),
        }
    }
}

impl std::error::Error for SeedError {}

impl From<CoreError> for SeedError {
    fn from(e: CoreError) -> Self {
        match e {
            CoreError::Refused(r) => SeedError::Refused(r),
            CoreError::NotImplemented(op) => SeedError::NotImplemented(NotImplemented::new(op)),
        }
    }
}

/// One seeded write and its source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeededWrite {
    /// Where the fact claims to come from.
    pub source: SeedSource,
    /// The write kind.
    pub kind: u16,
    /// When it was written, in microseconds since the Unix epoch.
    pub at: i64,
}

/// Every seeded write of a test, in order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SeedLog {
    /// The writes the vault core accepted.
    pub writes: Vec<SeededWrite>,
}

/// Seeds one fact into a vault state through `fstp_vault_core::write` at
/// `now` (microseconds since the Unix epoch), and records it in `log`.
///
/// # Errors
///
/// Passes on the vault core's refusal. Nothing is logged then.
pub fn seed_fact(
    state: &mut VaultState,
    log: &mut SeedLog,
    source: SeedSource,
    write: FactWrite,
    now: i64,
) -> Result<Vec<VaultEvent>, SeedError> {
    let kind = write.kind;
    let events = fstp_vault_core::write(state, write, now)?;
    log.writes.push(SeededWrite {
        source,
        kind,
        at: now,
    });
    Ok(events)
}

/// Runs the seeded vault as a process until shutdown: the `fstp-vault`
/// library, fed by a [`SeedSource`].
///
/// # Errors
///
/// Passes on the refusal of `fstp_vault::run`, which lane W2d writes.
pub fn run() -> Result<(), NotImplemented> {
    fstp_vault::run().map_err(|e| match e {
        fstp_vault::VaultError::NotImplemented(op) => NotImplemented::new(op),
        #[allow(unreachable_patterns, reason = "fstp-vault gains variants in lane W2d")]
        _ => NotImplemented::new("fstp_vault::run failed"),
    })
}
