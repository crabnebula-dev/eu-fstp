//! In-house task handles: awaitable, abortable, and panic-reporting.
//!
//! A runtime module spawns a [`TaskFuture`] (or runs a [`BlockingTask`]) and
//! hands the matching [`JoinHandle`] to the caller. The logic for results,
//! aborts and panics lives here once, so every runtime module behaves the same.

use std::any::Any;
use std::fmt;
use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};

/// Why a task did not produce a value.
#[derive(Clone, PartialEq, Eq)]
pub struct JoinError {
    repr: Repr,
}

#[derive(Clone, PartialEq, Eq)]
enum Repr {
    Cancelled,
    Panicked(String),
    Consumed,
}

impl JoinError {
    fn cancelled() -> Self {
        Self {
            repr: Repr::Cancelled,
        }
    }

    /// True when the task was aborted or dropped before it finished.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        matches!(self.repr, Repr::Cancelled)
    }

    /// True when the task panicked.
    #[must_use]
    pub fn is_panic(&self) -> bool {
        matches!(self.repr, Repr::Panicked(_))
    }

    /// The panic message, when the task panicked with a string payload.
    ///
    /// The message can contain data from the task. [`fmt::Display`] and
    /// [`fmt::Debug`] never print it, so that a logged `JoinError` carries no
    /// content (R-NF-02). Callers decide whether the message is safe to log.
    #[must_use]
    pub fn panic_message(&self) -> Option<&str> {
        match &self.repr {
            Repr::Panicked(msg) => Some(msg),
            _ => None,
        }
    }
}

impl fmt::Display for JoinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.repr {
            Repr::Cancelled => f.write_str("task was cancelled"),
            Repr::Panicked(_) => f.write_str("task panicked"),
            Repr::Consumed => f.write_str("join handle polled after completion"),
        }
    }
}

impl fmt::Debug for JoinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self.repr {
            Repr::Cancelled => "Cancelled",
            Repr::Panicked(_) => "Panicked",
            Repr::Consumed => "Consumed",
        };
        f.debug_struct("JoinError").field("kind", &kind).finish()
    }
}

impl std::error::Error for JoinError {}

impl From<JoinError> for std::io::Error {
    fn from(e: JoinError) -> Self {
        let kind = if e.is_cancelled() {
            std::io::ErrorKind::Interrupted
        } else {
            std::io::ErrorKind::Other
        };
        std::io::Error::new(kind, e)
    }
}

enum Slot<T> {
    Running,
    Done(Result<T, JoinError>),
    Taken,
}

struct State<T> {
    slot: Slot<T>,
    join_waker: Option<Waker>,
    task_waker: Option<Waker>,
    abort: bool,
}

struct Shared<T> {
    state: Mutex<State<T>>,
}

impl<T> Shared<T> {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                slot: Slot::Running,
                join_waker: None,
                task_waker: None,
                abort: false,
            }),
        })
    }

    fn lock(&self) -> MutexGuard<'_, State<T>> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Stores the result unless one is already stored, then wakes the joiner.
    fn complete(&self, result: Result<T, JoinError>) {
        let waker = {
            let mut st = self.lock();
            if !matches!(st.slot, Slot::Running) {
                return;
            }
            st.slot = Slot::Done(result);
            st.task_waker = None;
            st.join_waker.take()
        };
        if let Some(w) = waker {
            w.wake();
        }
    }
}

/// Object-safe view of the abort flag, so that [`AbortHandle`] needs no type
/// parameter.
trait Abortable: Send + Sync {
    fn request_abort(&self);
    fn finished(&self) -> bool;
}

impl<T: Send> Abortable for Shared<T> {
    fn request_abort(&self) {
        let waker = {
            let mut st = self.lock();
            if !matches!(st.slot, Slot::Running) {
                return;
            }
            st.abort = true;
            st.task_waker.take()
        };
        if let Some(w) = waker {
            w.wake();
        }
    }

    fn finished(&self) -> bool {
        !matches!(self.lock().slot, Slot::Running)
    }
}

/// An owned permission to await a spawned task's result.
///
/// - Awaiting it yields `Ok(value)`, or a [`JoinError`] when the task was
///   aborted, dropped by its runtime, or panicked. A panic never propagates
///   into the awaiting task.
/// - [`JoinHandle::abort`] asks the task to stop. An async task is dropped at
///   its next scheduling point. A blocking task is only prevented from
///   starting.
/// - Dropping the handle detaches the task, which keeps running.
#[must_use = "dropping a JoinHandle detaches the task"]
pub struct JoinHandle<T> {
    shared: Arc<Shared<T>>,
}

impl<T: Send + 'static> JoinHandle<T> {
    /// Requests that the task stop. Has no effect once the task finished.
    pub fn abort(&self) {
        self.shared.request_abort();
    }

    /// Returns a cloneable handle that can abort the task from elsewhere.
    pub fn abort_handle(&self) -> AbortHandle {
        AbortHandle {
            shared: self.shared.clone(),
        }
    }

    /// True once the task produced a value, panicked, or was cancelled.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.shared.finished()
    }
}

impl<T> fmt::Debug for JoinHandle<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JoinHandle").finish_non_exhaustive()
    }
}

impl<T> Future for JoinHandle<T> {
    type Output = Result<T, JoinError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut st = self.shared.lock();
        match std::mem::replace(&mut st.slot, Slot::Taken) {
            Slot::Done(result) => Poll::Ready(result),
            Slot::Taken => Poll::Ready(Err(JoinError {
                repr: Repr::Consumed,
            })),
            Slot::Running => {
                st.slot = Slot::Running;
                match &mut st.join_waker {
                    Some(w) if w.will_wake(cx.waker()) => {}
                    other => *other = Some(cx.waker().clone()),
                }
                Poll::Pending
            }
        }
    }
}

/// A cloneable handle that aborts a task.
#[derive(Clone)]
pub struct AbortHandle {
    shared: Arc<dyn Abortable>,
}

impl AbortHandle {
    /// Requests that the task stop. Has no effect once the task finished.
    pub fn abort(&self) {
        self.shared.request_abort();
    }

    /// True once the task finished in any way.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.shared.finished()
    }
}

impl fmt::Debug for AbortHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AbortHandle").finish_non_exhaustive()
    }
}

fn panic_text(payload: &(dyn Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_owned()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        String::from("non-string panic payload")
    }
}

/// The future a runtime module spawns for an async task.
///
/// It polls the user future inside `catch_unwind`, honours abort requests,
/// and reports a cancellation if the runtime drops it early.
pub(crate) struct TaskFuture<F: Future> {
    fut: Option<Pin<Box<F>>>,
    shared: Arc<Shared<F::Output>>,
}

impl<F: Future> fmt::Debug for TaskFuture<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TaskFuture").finish_non_exhaustive()
    }
}

/// Wraps `fut` for spawning and returns the wrapper with its join handle.
///
/// Runtime modules call this and then hand the [`TaskFuture`] to their
/// executor. Only runtime modules need it.
pub(crate) fn task<F>(fut: F) -> (TaskFuture<F>, JoinHandle<F::Output>)
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    let shared = Shared::new();
    (
        TaskFuture {
            fut: Some(Box::pin(fut)),
            shared: shared.clone(),
        },
        JoinHandle { shared },
    )
}

impl<F: Future> TaskFuture<F> {
    /// Drops the user future, containing any panic from its destructor.
    fn drop_inner(&mut self) {
        if let Some(fut) = self.fut.take() {
            let _ = catch_unwind(AssertUnwindSafe(move || drop(fut)));
        }
    }
}

impl<F: Future> Future for TaskFuture<F> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = &mut *self;
        if this.fut.is_none() {
            return Poll::Ready(());
        }
        let abort = {
            let mut st = this.shared.lock();
            if !st.abort {
                match &mut st.task_waker {
                    Some(w) if w.will_wake(cx.waker()) => {}
                    other => *other = Some(cx.waker().clone()),
                }
            }
            st.abort
        };
        if abort {
            this.drop_inner();
            this.shared.complete(Err(JoinError::cancelled()));
            return Poll::Ready(());
        }
        let Some(fut) = this.fut.as_mut() else {
            return Poll::Ready(());
        };
        match catch_unwind(AssertUnwindSafe(|| fut.as_mut().poll(cx))) {
            Ok(Poll::Pending) => Poll::Pending,
            Ok(Poll::Ready(value)) => {
                this.drop_inner();
                this.shared.complete(Ok(value));
                Poll::Ready(())
            }
            Err(payload) => {
                let message = panic_text(payload.as_ref());
                this.drop_inner();
                this.shared.complete(Err(JoinError {
                    repr: Repr::Panicked(message),
                }));
                Poll::Ready(())
            }
        }
    }
}

impl<F: Future> Drop for TaskFuture<F> {
    fn drop(&mut self) {
        self.drop_inner();
        // A no-op when the task already completed.
        self.shared.complete(Err(JoinError::cancelled()));
    }
}

/// A blocking closure prepared for a thread pool.
///
/// Calling [`BlockingTask::run`] executes the closure unless the task was
/// aborted first. Dropping it without running reports a cancellation.
pub(crate) struct BlockingTask<F, R> {
    f: Option<F>,
    shared: Arc<Shared<R>>,
}

impl<F, R> fmt::Debug for BlockingTask<F, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlockingTask").finish_non_exhaustive()
    }
}

/// Wraps a blocking closure and returns it with its join handle.
pub(crate) fn blocking_task<F, R>(f: F) -> (BlockingTask<F, R>, JoinHandle<R>)
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    let shared = Shared::new();
    (
        BlockingTask {
            f: Some(f),
            shared: shared.clone(),
        },
        JoinHandle { shared },
    )
}

impl<F, R> BlockingTask<F, R>
where
    F: FnOnce() -> R,
{
    /// Runs the closure on the current thread and stores its result.
    pub(crate) fn run(mut self) {
        let Some(f) = self.f.take() else {
            return;
        };
        if self.shared.lock().abort {
            self.shared.complete(Err(JoinError::cancelled()));
            return;
        }
        let result = match catch_unwind(AssertUnwindSafe(f)) {
            Ok(value) => Ok(value),
            Err(payload) => Err(JoinError {
                repr: Repr::Panicked(panic_text(payload.as_ref())),
            }),
        };
        self.shared.complete(result);
    }
}

impl<F, R> Drop for BlockingTask<F, R> {
    fn drop(&mut self) {
        self.shared.complete(Err(JoinError::cancelled()));
    }
}
