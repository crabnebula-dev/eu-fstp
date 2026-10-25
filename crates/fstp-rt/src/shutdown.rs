//! Graceful shutdown: stop accepting, notify tasks, await drain with a deadline.
//!
//! A server owns one [`Shutdown`]. Every task that must finish before the
//! process exits holds a [`ShutdownSignal`]. The sequence is:
//!
//! 1. [`Shutdown::trigger`] wakes every [`ShutdownSignal::notified`] future.
//!    Accept loops built on [`ShutdownSignal::run_until`] stop accepting.
//! 2. Tasks finish their current work and drop their signals.
//! 3. [`Shutdown::drained`] completes once no signal is left.
//!    [`Shutdown::shutdown`] combines all three steps with a deadline.
//!
//! Tasks still running after the deadline can be stopped with
//! [`AbortHandle`](crate::AbortHandle)s that the server kept.

use std::fmt;
use std::future::Future;
use std::pin::{Pin, pin};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use crate::{Runtime, timeout};

struct State {
    triggered: bool,
    active: usize,
    next_id: u64,
    notify_waiters: Vec<(u64, Waker)>,
    drain_waiters: Vec<(u64, Waker)>,
}

struct Inner {
    state: Mutex<State>,
}

impl Inner {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl State {
    fn take_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        id
    }
}

/// Registers or refreshes a waker under `id` in `list`.
fn register(list: &mut Vec<(u64, Waker)>, id: u64, waker: &Waker) {
    for (entry_id, entry) in list.iter_mut() {
        if *entry_id == id {
            if !entry.will_wake(waker) {
                *entry = waker.clone();
            }
            return;
        }
    }
    list.push((id, waker.clone()));
}

fn unregister(list: &mut Vec<(u64, Waker)>, id: u64) {
    list.retain(|(entry_id, _)| *entry_id != id);
}

/// The controller side of graceful shutdown.
///
/// Cloning a `Shutdown` gives another controller for the same group. Clones
/// are not participants: they never delay [`Shutdown::drained`].
#[derive(Clone)]
pub struct Shutdown {
    inner: Arc<Inner>,
}

impl Default for Shutdown {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Shutdown {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let st = self.inner.lock();
        f.debug_struct("Shutdown")
            .field("triggered", &st.triggered)
            .field("active", &st.active)
            .finish()
    }
}

impl Shutdown {
    /// Creates a new shutdown group with no participants.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                state: Mutex::new(State {
                    triggered: false,
                    active: 0,
                    next_id: 0,
                    notify_waiters: Vec::new(),
                    drain_waiters: Vec::new(),
                }),
            }),
        }
    }

    /// Creates a participant signal. Drain waits until it is dropped.
    #[must_use]
    pub fn signal(&self) -> ShutdownSignal {
        {
            let mut st = self.inner.lock();
            st.active = st.active.saturating_add(1);
        }
        ShutdownSignal {
            inner: self.inner.clone(),
        }
    }

    /// Starts shutdown and wakes every waiting signal. Idempotent.
    pub fn trigger(&self) {
        let wakers = {
            let mut st = self.inner.lock();
            if st.triggered {
                return;
            }
            st.triggered = true;
            std::mem::take(&mut st.notify_waiters)
        };
        for (_, w) in wakers {
            w.wake();
        }
    }

    /// True once [`Shutdown::trigger`] was called.
    #[must_use]
    pub fn is_triggered(&self) -> bool {
        self.inner.lock().triggered
    }

    /// Number of live participant signals.
    #[must_use]
    pub fn active(&self) -> usize {
        self.inner.lock().active
    }

    /// Completes once no participant signal is left.
    ///
    /// It does not trigger shutdown by itself.
    pub fn drained(&self) -> Drained {
        Drained {
            inner: self.inner.clone(),
            id: None,
        }
    }

    /// Triggers shutdown and waits up to `deadline` for every participant to
    /// finish.
    ///
    /// # Errors
    ///
    /// Returns [`DrainTimeout`] with the number of participants still alive
    /// when the deadline passes first.
    pub async fn shutdown<R: Runtime>(
        &self,
        rt: &R,
        deadline: Duration,
    ) -> Result<(), DrainTimeout> {
        self.trigger();
        match timeout(rt, deadline, self.drained()).await {
            Ok(()) => Ok(()),
            Err(_) => Err(DrainTimeout {
                remaining: self.active(),
            }),
        }
    }
}

/// A participant in a shutdown group.
///
/// Holding a signal delays [`Shutdown::drained`]. Cloning creates another
/// participant. Dropping it ends participation.
pub struct ShutdownSignal {
    inner: Arc<Inner>,
}

impl fmt::Debug for ShutdownSignal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShutdownSignal")
            .field("triggered", &self.is_triggered())
            .finish()
    }
}

impl Clone for ShutdownSignal {
    fn clone(&self) -> Self {
        {
            let mut st = self.inner.lock();
            st.active = st.active.saturating_add(1);
        }
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl Drop for ShutdownSignal {
    fn drop(&mut self) {
        let wakers = {
            let mut st = self.inner.lock();
            st.active = st.active.saturating_sub(1);
            if st.active == 0 {
                std::mem::take(&mut st.drain_waiters)
            } else {
                Vec::new()
            }
        };
        for (_, w) in wakers {
            w.wake();
        }
    }
}

impl ShutdownSignal {
    /// True once shutdown was triggered.
    #[must_use]
    pub fn is_triggered(&self) -> bool {
        self.inner.lock().triggered
    }

    /// Completes once shutdown is triggered.
    ///
    /// The future does not count as a participant, so it can be moved into
    /// other tasks freely.
    pub fn notified(&self) -> Notified {
        Notified {
            inner: self.inner.clone(),
            id: None,
        }
    }

    /// Runs `f` until it completes or shutdown is triggered.
    ///
    /// Returns `None` when shutdown came first; `f` is dropped then. `f` is
    /// polled only while shutdown has not been triggered, so an accept loop
    /// built on this never accepts after the trigger.
    pub async fn run_until<F: Future>(&self, f: F) -> Option<F::Output> {
        let mut f = pin!(f);
        let mut stop = pin!(self.notified());
        std::future::poll_fn(|cx| {
            if stop.as_mut().poll(cx).is_ready() {
                return Poll::Ready(None);
            }
            f.as_mut().poll(cx).map(Some)
        })
        .await
    }
}

/// Future returned by [`ShutdownSignal::notified`].
#[must_use = "futures do nothing unless polled"]
pub struct Notified {
    inner: Arc<Inner>,
    id: Option<u64>,
}

impl fmt::Debug for Notified {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Notified").finish_non_exhaustive()
    }
}

impl Future for Notified {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        let mut st = this.inner.lock();
        if st.triggered {
            return Poll::Ready(());
        }
        let id = match this.id {
            Some(id) => id,
            None => {
                let id = st.take_id();
                this.id = Some(id);
                id
            }
        };
        register(&mut st.notify_waiters, id, cx.waker());
        Poll::Pending
    }
}

impl Drop for Notified {
    fn drop(&mut self) {
        if let Some(id) = self.id {
            unregister(&mut self.inner.lock().notify_waiters, id);
        }
    }
}

/// Future returned by [`Shutdown::drained`].
#[must_use = "futures do nothing unless polled"]
pub struct Drained {
    inner: Arc<Inner>,
    id: Option<u64>,
}

impl fmt::Debug for Drained {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Drained").finish_non_exhaustive()
    }
}

impl Future for Drained {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        let mut st = this.inner.lock();
        if st.active == 0 {
            return Poll::Ready(());
        }
        let id = match this.id {
            Some(id) => id,
            None => {
                let id = st.take_id();
                this.id = Some(id);
                id
            }
        };
        register(&mut st.drain_waiters, id, cx.waker());
        Poll::Pending
    }
}

impl Drop for Drained {
    fn drop(&mut self) {
        if let Some(id) = self.id {
            unregister(&mut self.inner.lock().drain_waiters, id);
        }
    }
}

/// Error from [`Shutdown::shutdown`] when participants outlive the deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DrainTimeout {
    /// Participants still alive when the deadline passed.
    pub remaining: usize,
}

impl fmt::Display for DrainTimeout {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "shutdown deadline passed with {} task(s) still running",
            self.remaining
        )
    }
}

impl std::error::Error for DrainTimeout {}
