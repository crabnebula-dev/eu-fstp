//! Deadlines on futures.

use std::fmt;
use std::future::{Future, poll_fn};
use std::pin::pin;
use std::task::Poll;
use std::time::{Duration, Instant};

use crate::Runtime;

/// Error returned by [`timeout`] when the deadline passes first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Elapsed(());

impl Elapsed {
    /// Creates the error value. Runtime-independent helpers use it.
    #[must_use]
    pub fn new() -> Self {
        Self(())
    }
}

impl Default for Elapsed {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for Elapsed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("deadline elapsed")
    }
}

impl std::error::Error for Elapsed {}

impl From<Elapsed> for std::io::Error {
    fn from(e: Elapsed) -> Self {
        std::io::Error::new(std::io::ErrorKind::TimedOut, e)
    }
}

/// Runs `f` until it completes or `d` passes, whichever comes first.
///
/// `f` is polled before the timer on every wake-up, so a future that is
/// already complete wins even with a zero duration. When the deadline passes,
/// `f` is dropped before this function returns.
///
/// Whenever `f` returns `Pending`, the deadline is also checked against
/// the clock. A runtime can refuse to poll the timer after `f` used up the
/// task's budget, as tokio does. The timer alone would then never fire
/// while `f` keeps receiving data, for example a read loop on a socket
/// that a peer keeps readable.
///
/// # Errors
///
/// Returns [`Elapsed`] when the deadline passes before `f` completes.
pub async fn timeout<R: Runtime, F: Future>(
    rt: &R,
    d: Duration,
    f: F,
) -> Result<F::Output, Elapsed> {
    let deadline = Instant::now().checked_add(d);
    let mut f = pin!(f);
    let mut sleep = pin!(rt.sleep(d));
    poll_fn(|cx| {
        if let Poll::Ready(v) = f.as_mut().poll(cx) {
            return Poll::Ready(Ok(v));
        }
        if deadline.is_some_and(|t| Instant::now() >= t) {
            return Poll::Ready(Err(Elapsed::new()));
        }
        match sleep.as_mut().poll(cx) {
            Poll::Ready(()) => Poll::Ready(Err(Elapsed::new())),
            Poll::Pending => Poll::Pending,
        }
    })
    .await
}
