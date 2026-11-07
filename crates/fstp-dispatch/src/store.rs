//! An in-memory model of `ops.delivery` (M6 design sections 3.2 and 7,
//! T1).
//!
//! [`MemDelivery`] applies the head rules of `fstp_pgstore`
//! ([`next_step`], [`may_commit`], [`may_record`]) as `DeliveryLog` does
//! under its advisory lock, and enforces the table's constraints on each
//! insert: the message exists, the row meets its CHECKs, the primary key
//! `(outbox_id, attempt, phase)` is unique, and a message holds at most one
//! terminal row. Rows are never changed or removed.
//!
//! A test can inject a fault into the next write transaction ([`Fault`]):
//! a commit that fails, or one whose outcome is unknown and that did or
//! did not apply. So the crash tests reach every store outcome a worker
//! must survive.

use std::collections::{BTreeMap, VecDeque};

pub use fstp_pgstore::{
    CommitFacts, DELIVERY_LEASE_US, DeliveryRow, MAX_ATTEMPTS, Next, Phase, backoff_us, may_commit,
    may_record, next_step,
};

/// A fault of one write transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Fault {
    /// The commit fails and nothing is written.
    Fail,
    /// The commit's outcome is unknown to the caller. The row was written.
    UnknownApplied,
    /// The commit's outcome is unknown to the caller. Nothing was written.
    UnknownLost,
}

/// Why a write of the model did not report success.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StoreError {
    /// The commit failed. Nothing was written.
    Failed,
    /// The outcome is unknown. The row may or may not exist.
    Unknown,
    /// The row breaks a constraint of `ops.delivery`, named.
    Constraint(&'static str),
}

/// The in-memory `ops.delivery` of one cell.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct MemDelivery {
    rows: BTreeMap<[u8; 16], Vec<DeliveryRow>>,
    faults: VecDeque<Fault>,
}

impl MemDelivery {
    /// A log for the messages `outbox`, with no rows.
    pub fn new(outbox: impl IntoIterator<Item = [u8; 16]>) -> MemDelivery {
        MemDelivery {
            rows: outbox.into_iter().map(|id| (id, Vec::new())).collect(),
            faults: VecDeque::new(),
        }
    }

    /// Adds the message `outbox`, as an append inserts its `ops.outbox`
    /// row.
    pub fn add_message(&mut self, outbox: [u8; 16]) {
        self.rows.entry(outbox).or_default();
    }

    /// Queues `fault` for the next write transaction.
    pub fn inject(&mut self, fault: Fault) {
        self.faults.push_back(fault);
    }

    /// Every message, in id order.
    pub fn messages(&self) -> impl Iterator<Item = &[u8; 16]> {
        self.rows.keys()
    }

    /// The rows of `outbox`, in insert order.
    pub fn rows(&self, outbox: &[u8; 16]) -> &[DeliveryRow] {
        self.rows.get(outbox).map_or(&[], Vec::as_slice)
    }

    /// The head of `outbox`: its row with the highest (attempt, phase).
    pub fn head(&self, outbox: &[u8; 16]) -> Option<&DeliveryRow> {
        self.rows(outbox).iter().max_by_key(|r| r.order())
    }

    /// Whether `outbox` holds its terminal row.
    pub fn is_settled(&self, outbox: &[u8; 16]) -> bool {
        self.rows(outbox).iter().any(|r| r.phase.is_terminal())
    }

    /// S1 and recovery, as `DeliveryLog::claim`.
    ///
    /// # Errors
    ///
    /// An injected fault, or a broken constraint.
    pub fn claim(
        &mut self,
        outbox: [u8; 16],
        worker: [u8; 16],
        now: i64,
    ) -> Result<Next, StoreError> {
        let next = next_step(self.head(&outbox), now);
        let row = |attempt, phase, lease_until| DeliveryRow {
            outbox,
            attempt,
            phase,
            at: now,
            worker,
            lease_until,
            commit: None,
            reply_code: None,
        };
        let write = match next {
            Next::Claim { attempt } => Some(row(
                attempt,
                Phase::Claimed,
                Some(now.saturating_add(DELIVERY_LEASE_US)),
            )),
            Next::RecordInDoubt { attempt } => Some(row(attempt, Phase::InDoubt, None)),
            Next::GiveUp { attempt } => Some(row(attempt, Phase::Permanent, None)),
            Next::Busy { .. } | Next::Wait { .. } | Next::Done => None,
        };
        self.transact(write)?;
        Ok(next)
    }

    /// S4, as `DeliveryLog::commit_point`.
    ///
    /// # Errors
    ///
    /// An injected fault, or a broken constraint.
    pub fn commit_point(
        &mut self,
        outbox: [u8; 16],
        worker: [u8; 16],
        attempt: u32,
        facts: CommitFacts,
        now: i64,
    ) -> Result<bool, StoreError> {
        let ok = may_commit(self.head(&outbox), worker, attempt);
        self.transact(ok.then_some(DeliveryRow {
            outbox,
            attempt,
            phase: Phase::Committing,
            at: now,
            worker,
            lease_until: Some(now.saturating_add(DELIVERY_LEASE_US)),
            commit: Some(facts),
            reply_code: None,
        }))?;
        Ok(ok)
    }

    /// S6, as `DeliveryLog::record`.
    ///
    /// # Errors
    ///
    /// An injected fault, or a broken constraint.
    pub fn record(
        &mut self,
        outbox: [u8; 16],
        worker: [u8; 16],
        attempt: u32,
        phase: Phase,
        reply_code: Option<u16>,
        now: i64,
    ) -> Result<bool, StoreError> {
        let ok = may_record(self.head(&outbox), worker, attempt, phase);
        self.transact(ok.then_some(DeliveryRow {
            outbox,
            attempt,
            phase,
            at: now,
            worker,
            lease_until: None,
            commit: None,
            reply_code,
        }))?;
        Ok(ok)
    }

    /// One write transaction: the next injected fault, then the insert.
    fn transact(&mut self, write: Option<DeliveryRow>) -> Result<(), StoreError> {
        match self.faults.pop_front() {
            Some(Fault::Fail) => Err(StoreError::Failed),
            Some(Fault::UnknownLost) => Err(StoreError::Unknown),
            Some(Fault::UnknownApplied) => {
                if let Some(r) = write {
                    self.insert(r)?;
                }
                Err(StoreError::Unknown)
            }
            None => match write {
                Some(r) => self.insert(r),
                None => Ok(()),
            },
        }
    }

    /// Inserts `r` under the constraints of `ops.delivery`.
    pub fn insert(&mut self, r: DeliveryRow) -> Result<(), StoreError> {
        if !r.is_well_formed() {
            return Err(StoreError::Constraint("check"));
        }
        let rows = self
            .rows
            .get_mut(&r.outbox)
            .ok_or(StoreError::Constraint("foreign key"))?;
        if rows.iter().any(|x| x.order() == r.order()) {
            return Err(StoreError::Constraint("primary key"));
        }
        if r.phase.is_terminal() && rows.iter().any(|x| x.phase.is_terminal()) {
            return Err(StoreError::Constraint("one terminal row"));
        }
        rows.push(r);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(attempt: u32, phase: Phase) -> DeliveryRow {
        DeliveryRow {
            outbox: [1; 16],
            attempt,
            phase,
            at: 0,
            worker: [2; 16],
            lease_until: matches!(phase, Phase::Claimed | Phase::Committing).then_some(1),
            commit: (phase == Phase::Committing).then_some(CommitFacts {
                event: [3; 32],
                template_version: 1,
                body_digest: [4; 32],
            }),
            reply_code: None,
        }
    }

    /// I-26, M6 design section 3.2: the model refuses what the table
    /// refuses: a second terminal row, a repeated key, a row of an unknown
    /// message and a row outside its CHECKs.
    #[test]
    fn i26_model_enforces_the_delivery_constraints() {
        let mut m = MemDelivery::new([[1; 16]]);
        assert_eq!(m.insert(row(1, Phase::Committing)), Ok(()));
        assert_eq!(m.insert(row(1, Phase::InDoubt)), Ok(()));
        assert_eq!(
            m.insert(row(2, Phase::Sent)),
            Err(StoreError::Constraint("one terminal row"))
        );
        assert_eq!(
            m.insert(row(1, Phase::Committing)),
            Err(StoreError::Constraint("primary key"))
        );
        let mut orphan = row(1, Phase::Claimed);
        orphan.outbox = [9; 16];
        assert_eq!(m.insert(orphan), Err(StoreError::Constraint("foreign key")));
        let mut bad = row(3, Phase::Committing);
        bad.commit = None;
        assert_eq!(m.insert(bad), Err(StoreError::Constraint("check")));
        assert_eq!(m.head(&[1; 16]).map(|h| h.phase), Some(Phase::InDoubt));
    }

    /// M6 design section 7, T1: an injected fault fails a write, or leaves
    /// its outcome unknown with or without the row.
    #[test]
    fn i26_model_injects_store_faults() {
        let mut m = MemDelivery::new([[1; 16]]);
        m.inject(Fault::Fail);
        assert_eq!(m.claim([1; 16], [2; 16], 0), Err(StoreError::Failed));
        assert!(m.rows(&[1; 16]).is_empty());
        m.inject(Fault::UnknownLost);
        assert_eq!(m.claim([1; 16], [2; 16], 0), Err(StoreError::Unknown));
        assert!(m.rows(&[1; 16]).is_empty());
        m.inject(Fault::UnknownApplied);
        assert_eq!(m.claim([1; 16], [2; 16], 0), Err(StoreError::Unknown));
        assert_eq!(m.rows(&[1; 16]).len(), 1);
        assert_eq!(
            m.claim([1; 16], [3; 16], 1),
            Ok(Next::Busy {
                until: DELIVERY_LEASE_US
            })
        );
    }
}
