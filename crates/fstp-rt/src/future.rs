//! Small runtime-independent future combinators.
//!
//! These are in-house replacements for the helpers that tokio puts behind its
//! `macros` and `io-util` features, which ADR-002 leaves disabled.

use std::future::Future;
use std::pin::{Pin, pin};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, Wake, Waker};
use std::thread::{self, Thread};

/// One of two values. Returned by [`race`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Either<A, B> {
    /// The first future finished first.
    Left(A),
    /// The second future finished first.
    Right(B),
}

/// Polls two futures and returns the output of whichever finishes first.
///
/// `a` is polled before `b` on every wake-up, so `a` wins a tie. The other
/// future is dropped when the returned future completes.
pub async fn race<A: Future, B: Future>(a: A, b: B) -> Either<A::Output, B::Output> {
    let mut a = pin!(a);
    let mut b = pin!(b);
    std::future::poll_fn(|cx| {
        if let Poll::Ready(v) = a.as_mut().poll(cx) {
            return Poll::Ready(Either::Left(v));
        }
        if let Poll::Ready(v) = b.as_mut().poll(cx) {
            return Poll::Ready(Either::Right(v));
        }
        Poll::Pending
    })
    .await
}

/// Polls two futures concurrently and returns both outputs.
pub async fn join<A: Future, B: Future>(a: A, b: B) -> (A::Output, B::Output) {
    let mut a = pin!(a);
    let mut b = pin!(b);
    let mut out_a = None;
    let mut out_b = None;
    std::future::poll_fn(|cx| {
        if out_a.is_none()
            && let Poll::Ready(v) = a.as_mut().poll(cx)
        {
            out_a = Some(v);
        }
        if out_b.is_none()
            && let Poll::Ready(v) = b.as_mut().poll(cx)
        {
            out_b = Some(v);
        }
        match (out_a.take(), out_b.take()) {
            (Some(x), Some(y)) => Poll::Ready((x, y)),
            (x, y) => {
                out_a = x;
                out_b = y;
                Poll::Pending
            }
        }
    })
    .await
}

/// Yields once to the executor, then completes.
///
/// The returned future wakes itself before returning `Pending`, so other
/// tasks get a chance to run.
pub fn yield_now() -> YieldNow {
    YieldNow { yielded: false }
}

/// Future returned by [`yield_now`].
#[derive(Debug)]
#[must_use = "futures do nothing unless polled"]
pub struct YieldNow {
    yielded: bool,
}

impl Future for YieldNow {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.yielded {
            return Poll::Ready(());
        }
        self.yielded = true;
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

struct ThreadWaker {
    thread: Thread,
    notified: AtomicBool,
}

impl Wake for ThreadWaker {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.notified.store(true, Ordering::Release);
        self.thread.unpark();
    }
}

/// Runs a future to completion on the current thread.
///
/// This is a minimal executor for tests, fuzz targets and tools. It has no
/// timers and no IO driver: futures that need a runtime's reactor must run on
/// that runtime instead, for example with
/// [`TokioRuntime::block_on`](crate::tokio::TokioRuntime::block_on).
/// Calling it from inside an async task blocks that task's worker thread.
pub fn block_on<F: Future>(fut: F) -> F::Output {
    let mut fut = pin!(fut);
    let state = Arc::new(ThreadWaker {
        thread: thread::current(),
        notified: AtomicBool::new(false),
    });
    let waker = Waker::from(state.clone());
    let mut cx = Context::from_waker(&waker);
    loop {
        if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
            return v;
        }
        while !state.notified.swap(false, Ordering::AcqRel) {
            thread::park();
        }
    }
}

/// Polls `fut` with a no-op waker until it completes or `max_polls` polls
/// were made.
///
/// Returns `None` when the budget runs out. Fuzz targets use this to turn a
/// future that never terminates into a detectable failure. The future must
/// not depend on wake-ups from a reactor, since none are delivered; the
/// in-memory transports in this crate satisfy that.
pub fn poll_bounded<F: Future>(fut: F, max_polls: usize) -> Option<F::Output> {
    let mut fut = pin!(fut);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..max_polls {
        if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
            return Some(v);
        }
    }
    None
}
