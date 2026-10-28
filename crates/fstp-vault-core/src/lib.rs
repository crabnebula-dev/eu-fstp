//! Vault facts, epochs, the commit protocol, query evaluation, and the
//! release and write rules (M3 design section 6.3, NOTE 4). Pure.
//!
//! No crate outside `fstp-vault` reaches this one, except the test-only
//! `fstp-celltest` (layering rule 2).
//!
//! Status: W0 stub. Lane W2d fills the crate. Every operation refuses with
//! [`CoreError::NotImplemented`]. The designed functions return
//! `VaultRefusal` as their error; the stub error wraps it.

use fstp_vault_proto::{VaultRefusal, WireAnswer};

/// The vault state of one cell.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VaultState {
    effective: u64,
}

impl VaultState {
    /// The effective epoch.
    pub fn effective(&self) -> u64 {
        self.effective
    }
}

/// A fact write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FactWrite {
    /// The write kind.
    pub kind: u16,
    /// The canonical fact body.
    pub body: Vec<u8>,
}

/// An event the vault emits after a write or an acknowledgement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VaultEvent {
    /// A provisional epoch was opened.
    Provisional {
        /// The epoch.
        epoch: u64,
    },
    /// An epoch became effective.
    Effective {
        /// The epoch.
        epoch: u64,
    },
}

/// The claims of a release ticket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseClaims {
    /// The ticket bytes.
    pub ticket: Vec<u8>,
}

/// Why a vault core operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoreError {
    /// The vault refused.
    Refused(VaultRefusal),
    /// The operation is a W0 stub. It names the operation.
    NotImplemented(&'static str),
}

/// Queues a fact write.
pub fn write(s: &mut VaultState, w: FactWrite, now: i64) -> Result<Vec<VaultEvent>, CoreError> {
    let _ = (s, w, now);
    Err(CoreError::NotImplemented("fstp_vault_core::write"))
}

/// Answers queries.
pub fn ask(
    s: &VaultState,
    queries: &[fstp_vault_proto::WireQuery],
) -> Result<Vec<WireAnswer>, CoreError> {
    let _ = (s, queries);
    Err(CoreError::NotImplemented("fstp_vault_core::ask"))
}

/// Records an acknowledgement.
pub fn ack(s: &mut VaultState, epoch: u64, ledger_seq: u64) -> Result<Vec<VaultEvent>, CoreError> {
    let _ = (s, epoch, ledger_seq);
    Err(CoreError::NotImplemented("fstp_vault_core::ack"))
}

/// Whether a release ticket may be honoured now (I-17).
pub fn release_allowed(s: &VaultState, t: &ReleaseClaims, now: i64) -> Result<(), CoreError> {
    let _ = (s, t, now);
    Err(CoreError::NotImplemented(
        "fstp_vault_core::release_allowed",
    ))
}
