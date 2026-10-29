//! Background tasks of a cell (design sections 3.5, 5.1, 8.2 and 10).
//!
//! - [`timeline`]: the system commands due at an instant, and the
//!   scheduled session ends (I-77).
//! - [`release`]: the licence refresh and the update check of a
//!   self-hosted cell (I-38, I-39).
//! - [`erasure`]: the erasure runner of design section 3.5 (I-81).
//!
//! Each task is a sans-IO core with an async runner over a [`Clock`]. A
//! task never holds a handle a request handler reaches, so no command
//! waits for one (I-39).

pub mod erasure;
pub mod release;
pub mod timeline;

use std::future::Future;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fstp_rt::Runtime;

/// One second in microseconds.
pub const SECOND_US: i64 = 1_000_000;
/// One day in microseconds.
pub const DAY_US: i64 = 86_400 * SECOND_US;

/// The time a task runs on, in UTC microseconds.
pub trait Clock: Send + Sync + 'static {
    /// The current instant.
    fn now(&self) -> i64;

    /// Completes at or after `at`.
    fn sleep_until(&self, at: i64) -> impl Future<Output = ()> + Send;
}

/// The system clock, with sleeps on the cell's runtime.
#[derive(Clone, Debug)]
pub struct SystemClock<R> {
    rt: R,
}

impl<R: Runtime> SystemClock<R> {
    /// The system clock over `rt`.
    pub fn new(rt: R) -> SystemClock<R> {
        SystemClock { rt }
    }
}

/// UTC microseconds of the system clock, saturating outside `i64`.
pub fn system_now() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_micros()).unwrap_or(i64::MAX),
        Err(e) => i64::try_from(e.duration().as_micros())
            .map(i64::saturating_neg)
            .unwrap_or(i64::MIN),
    }
}

impl<R: Runtime> Clock for SystemClock<R> {
    fn now(&self) -> i64 {
        system_now()
    }

    fn sleep_until(&self, at: i64) -> impl Future<Output = ()> + Send {
        let left = at.saturating_sub(system_now()).max(0);
        let micros = u64::try_from(left).unwrap_or(0);
        self.rt.sleep(Duration::from_micros(micros))
    }
}
