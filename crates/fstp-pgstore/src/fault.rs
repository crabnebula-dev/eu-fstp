//! A fault point a test arms on a record store (design sections 3.2 and
//! 5.3, R-NF-08, lane F-ERASE).
//!
//! An armed point aborts the next append after its rows are inserted and
//! before the witness prepare: the transaction rolls back, so the sealed
//! body of the aborted append stays in the WAL only. The append fails as
//! the store failing, and the next append runs as after any failure.
//! Production builds no point, so a production store has none
//! ([`crate::PgRecordStore::with_fault_point`]).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// A fault point shared by a test and the store it armed.
#[derive(Clone, Debug, Default)]
pub struct FaultPoint {
    armed: Arc<AtomicBool>,
    fired: Arc<AtomicU64>,
}

impl FaultPoint {
    /// Arms the point: the next append aborts once.
    pub fn arm_abort_next_append(&self) {
        self.armed.store(true, Ordering::SeqCst);
    }

    /// Whether the point is armed and has not fired yet.
    #[must_use]
    pub fn armed(&self) -> bool {
        self.armed.load(Ordering::SeqCst)
    }

    /// How many appends the point aborted.
    #[must_use]
    pub fn fired(&self) -> u64 {
        self.fired.load(Ordering::SeqCst)
    }

    /// Disarms the point if it was armed, and says whether it was.
    pub(crate) fn take(&self) -> bool {
        let was = self.armed.swap(false, Ordering::SeqCst);
        if was {
            let _ = self
                .fired
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_add(1));
        }
        was
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// R-NF-08: an armed point fires once, and counts it.
    #[test]
    fn r_nf_08_fault_point_fires_once() {
        let f = FaultPoint::default();
        assert!(!f.take());
        f.arm_abort_next_append();
        assert!(f.armed());
        assert!(f.take());
        assert!(!f.take());
        assert_eq!(f.fired(), 1);
    }
}
