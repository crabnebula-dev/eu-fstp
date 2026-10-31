//! Termination signals behind the runtime trait (ADR-002 review note of
//! 2026-10-28).
//!
//! A service manager stops a process with SIGTERM. A binary asks its one
//! runtime for a [`TerminationListener`] through [`Signals`], then triggers
//! the existing [`Shutdown`](crate::Shutdown) when the listener reports a
//! [`Termination`]. No other crate calls `tokio::signal`.
//!
//! ```no_run
//! use std::time::Duration;
//!
//! use fstp_rt::Shutdown;
//! use fstp_rt::signal::{Signals, TerminationListener};
//! use fstp_rt::tokio::TokioRuntime;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let rt = TokioRuntime::new_multi_thread(2)?;
//! let rt2 = rt.clone();
//! rt.block_on(async move {
//!     let mut term = rt2.listen_termination()?;
//!     let shutdown = Shutdown::new();
//!     // ... spawn tasks that hold `shutdown.signal()` ...
//!     let _which = term.recv().await;
//!     let _ = shutdown.shutdown(&rt2, Duration::from_secs(30)).await;
//!     Ok::<(), fstp_rt::signal::SignalError>(())
//! })?;
//! # Ok(())
//! # }
//! ```
//!
//! On Unix the tokio implementation listens for SIGTERM and SIGINT. On any
//! other target [`Signals::listen_termination`] refuses with
//! [`SignalError::Io`] and [`io::ErrorKind::Unsupported`]. The platform
//! deploys to Linux only (ADR-005).

use std::fmt;
use std::future::Future;
use std::io;

use crate::Runtime;

/// A termination request delivered to the process.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Termination {
    /// SIGTERM, sent by a service manager.
    Terminate,
    /// SIGINT, sent from a terminal.
    Interrupt,
}

/// Why termination signals could not be set up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignalError {
    /// The operating system refused to register a handler, or the target
    /// has no termination signals (`Unsupported`).
    Io(io::ErrorKind),
}

impl fmt::Display for SignalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(kind) => write!(f, "signal handler registration failed: {kind:?}"),
        }
    }
}

impl std::error::Error for SignalError {}

/// Receives termination signals that arrived after it was created.
pub trait TerminationListener: Send + 'static {
    /// Completes with the next termination signal.
    ///
    /// Signals that arrived since the listener was created, or since the
    /// last `recv`, are not lost. Several deliveries of one signal before a
    /// `recv` may be reported once.
    fn recv(&mut self) -> impl Future<Output = Termination> + Send;
}

/// Termination signals for a runtime. Each binary uses exactly one runtime,
/// so it takes its signals from that runtime (ADR-002).
pub trait Signals: Runtime {
    /// The listener this runtime hands out.
    type Listener: TerminationListener;

    /// Registers handlers for SIGTERM and SIGINT before it returns.
    ///
    /// From then on, a termination signal no longer ends the process at
    /// once. It is queued for the listener instead. The handlers stay in
    /// place for the life of the process, even after the listener is
    /// dropped.
    ///
    /// # Errors
    ///
    /// Returns [`SignalError`] when a handler cannot be registered.
    fn listen_termination(&self) -> Result<Self::Listener, SignalError>;
}

/// The tokio [`TerminationListener`].
pub struct TokioTermination {
    #[cfg(unix)]
    terminate: ::tokio::signal::unix::Signal,
    #[cfg(unix)]
    interrupt: ::tokio::signal::unix::Signal,
}

impl fmt::Debug for TokioTermination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokioTermination").finish_non_exhaustive()
    }
}

#[cfg(unix)]
impl TerminationListener for TokioTermination {
    fn recv(&mut self) -> impl Future<Output = Termination> + Send {
        std::future::poll_fn(move |cx| {
            use std::task::Poll;
            // SIGTERM is checked first, so a service manager's request wins
            // when both are pending. A stream that reports `None` belongs to
            // a runtime that has shut down; no signal can arrive through it,
            // so it stays pending.
            if let Poll::Ready(Some(())) = self.terminate.poll_recv(cx) {
                return Poll::Ready(Termination::Terminate);
            }
            if let Poll::Ready(Some(())) = self.interrupt.poll_recv(cx) {
                return Poll::Ready(Termination::Interrupt);
            }
            Poll::Pending
        })
    }
}

#[cfg(not(unix))]
impl TerminationListener for TokioTermination {
    fn recv(&mut self) -> impl Future<Output = Termination> + Send {
        std::future::pending()
    }
}

impl Signals for crate::tokio::TokioRuntime {
    type Listener = TokioTermination;

    #[cfg(unix)]
    fn listen_termination(&self) -> Result<Self::Listener, SignalError> {
        use ::tokio::signal::unix::{SignalKind, signal};
        // tokio registers the handler at once, in the runtime's signal
        // driver. Entering the handle makes this work from any thread, not
        // only from inside a task of this runtime.
        let _guard = self.handle().enter();
        let reg = |kind| signal(kind).map_err(|e| SignalError::Io(e.kind()));
        Ok(TokioTermination {
            terminate: reg(SignalKind::terminate())?,
            interrupt: reg(SignalKind::interrupt())?,
        })
    }

    #[cfg(not(unix))]
    fn listen_termination(&self) -> Result<Self::Listener, SignalError> {
        Err(SignalError::Io(io::ErrorKind::Unsupported))
    }
}
