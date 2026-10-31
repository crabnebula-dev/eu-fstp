//! The audit sink (I-24) and the recorder of vault answers that commit no
//! command (`overview.md` NOTE 5, design section 6.1 requirement 12).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use fstp_api_core::port::{AuditEntry, AuditSink, PortError, QueryDigest, Tx, VaultAudit};
use fstp_domain::id::VaultEpoch;

use super::lock;

/// Records every audit entry, or fails each write while set to fail.
/// Cloning shares the entries.
#[derive(Clone, Debug, Default)]
pub struct FakeAudit {
    entries: Arc<Mutex<Vec<AuditEntry>>>,
    failing: Arc<AtomicBool>,
}

impl FakeAudit {
    /// Every entry, in order.
    pub fn entries(&self) -> Vec<AuditEntry> {
        lock(&self.entries).clone()
    }

    /// Makes every later write fail with `PortError::Unavailable`, or
    /// succeed again.
    pub fn set_failing(&self, failing: bool) {
        self.failing.store(failing, Ordering::SeqCst);
    }
}

impl AuditSink for FakeAudit {
    fn record(&self, tx: &mut Tx, e: AuditEntry) -> Result<(), PortError> {
        let _ = tx;
        if self.failing.load(Ordering::SeqCst) {
            return Err(PortError::Unavailable);
        }
        lock(&self.entries).push(e);
        Ok(())
    }
}

/// One recorded vault answer: the query digest, the answer bit and the
/// epoch. It holds no identity attribute.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VaultAuditRecord {
    /// The digest of the query.
    pub query: QueryDigest,
    /// The answer bit.
    pub answer: bool,
    /// The epoch of the answer.
    pub epoch: VaultEpoch,
}

#[derive(Debug, Default)]
struct State {
    records: Vec<VaultAuditRecord>,
    failing: bool,
    refused: usize,
}

/// Records every vault answer it is given, or fails each one while set to
/// fail. Cloning shares the records.
#[derive(Clone, Debug, Default)]
pub struct FakeVaultAudit {
    state: Arc<Mutex<State>>,
}

impl FakeVaultAudit {
    /// Every record, in order.
    pub fn records(&self) -> Vec<VaultAuditRecord> {
        lock(&self.state).records.clone()
    }

    /// Makes every later `record` fail with `PortError::Unavailable`, or
    /// succeed again.
    pub fn set_failing(&self, failing: bool) {
        lock(&self.state).failing = failing;
    }

    /// How many `record` calls failed.
    pub fn refused(&self) -> usize {
        lock(&self.state).refused
    }
}

impl FakeVaultAudit {
    /// Records one answer now, as `VaultAudit::record` does. The engine
    /// port's creator environment, which is synchronous, records the
    /// answers of its SoD previews here (`overview.md` NOTE 5).
    pub fn record_now(
        &self,
        q: QueryDigest,
        answer: bool,
        epoch: VaultEpoch,
    ) -> Result<(), PortError> {
        let mut s = lock(&self.state);
        if s.failing {
            s.refused = s.refused.saturating_add(1);
            return Err(PortError::Unavailable);
        }
        s.records.push(VaultAuditRecord {
            query: q,
            answer,
            epoch,
        });
        Ok(())
    }
}

impl VaultAudit for FakeVaultAudit {
    async fn record(
        &self,
        q: QueryDigest,
        answer: bool,
        epoch: VaultEpoch,
    ) -> Result<(), PortError> {
        self.record_now(q, answer, epoch)
    }
}
