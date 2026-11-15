//! A deterministic id source. Production draws ids with
//! `fstp_crypto::random_array`. The fake counts, so a replayed trace draws
//! the same ids and a model can rebuild a cell from its trace.

use std::sync::{Arc, Mutex};

use fstp_api_core::port::{Ids, PortError};

use super::lock;

/// The first id the fake draws. It sits far above the fixture's ids, so a
/// drawn id never collides with one the fixture chose.
pub const FIRST_ID: u128 = 0x4d34_0000_0000_0000;

/// A counter of ids. Cloning shares the counter.
#[derive(Clone, Debug)]
pub struct FakeIds {
    next: Arc<Mutex<u128>>,
}

impl Default for FakeIds {
    fn default() -> FakeIds {
        FakeIds {
            next: Arc::new(Mutex::new(FIRST_ID)),
        }
    }
}

impl FakeIds {
    /// How many ids were drawn.
    pub fn drawn(&self) -> u128 {
        lock(&self.next).saturating_sub(FIRST_ID)
    }

    /// Continues after the ids `from` drew, as a restarted cell draws no
    /// id twice. Every clone of `self` sees it.
    pub fn continue_from(&self, from: &FakeIds) {
        let next = *lock(&from.next);
        *lock(&self.next) = next;
    }
}

impl Ids for FakeIds {
    fn fresh(&self) -> Result<u128, PortError> {
        let mut next = lock(&self.next);
        let id = *next;
        *next = id.checked_add(1).ok_or(PortError::Unavailable)?;
        Ok(id)
    }
}
