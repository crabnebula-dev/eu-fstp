//! The controllable cell clock (design section 1.2, the `fstp-e2e-cell`
//! clock route). Time moves only when a test moves it.

use std::sync::{Arc, Mutex};

use fstp_api_core::port::Clock;
use fstp_domain::time::Timestamp;

use super::lock;

/// A clock that reads a shared instant. Cloning shares the instant.
#[derive(Clone, Debug)]
pub struct FakeClock {
    now: Arc<Mutex<Timestamp>>,
}

impl FakeClock {
    /// A clock that reads `at` until it is moved.
    pub fn new(at: Timestamp) -> FakeClock {
        FakeClock {
            now: Arc::new(Mutex::new(at)),
        }
    }

    /// Sets the instant.
    pub fn set(&self, at: Timestamp) {
        *lock(&self.now) = at;
    }

    /// Moves the instant forward by `micros`, saturating.
    pub fn advance(&self, micros: i64) {
        let mut now = lock(&self.now);
        *now = Timestamp::from_micros(now.micros().saturating_add(micros));
    }

    /// The current instant.
    pub fn read(&self) -> Timestamp {
        *lock(&self.now)
    }
}

impl Clock for FakeClock {
    fn now(&self) -> Timestamp {
        self.read()
    }
}
