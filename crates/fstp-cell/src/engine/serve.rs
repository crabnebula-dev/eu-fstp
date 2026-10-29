//! Serving a cell until a termination signal drains it (design section
//! 2.3, ADR-002 review note of 2026-10-28).
//!
//! The binary registers its termination handlers through
//! `fstp_rt::signal::Signals` before it logs `Started`, so a SIGTERM that
//! arrives at once is queued, not fatal. On a signal it logs
//! `SignalReceived` and `ShuttingDown`, triggers the cell's
//! [`Shutdown`], and waits for every participant to finish within the
//! drain deadline. It then logs `Drained` or `DrainTimedOut`. Every event
//! goes to standard error through `fstp_obs` (R-NF-02).

use std::time::{Duration, Instant};

use fstp_obs::{LogEvent, Signal};
use fstp_rt::signal::{Termination, TerminationListener};
use fstp_rt::{Runtime, Shutdown};

use super::{CellEngine, CellStore, VaultClient};
use crate::CellError;

/// The default drain deadline.
pub const DRAIN_DEADLINE: Duration = Duration::from_secs(30);

/// How a served cell drains.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServeOptions {
    /// How long the drain may take before it is reported as timed out.
    pub drain: Duration,
    /// The bound of the engine's command channel.
    pub queue: usize,
}

impl Default for ServeOptions {
    fn default() -> ServeOptions {
        ServeOptions {
            drain: DRAIN_DEADLINE,
            queue: super::DEFAULT_QUEUE,
        }
    }
}

/// How a served cell ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Drain {
    /// Every participant finished within the deadline.
    Drained,
    /// The deadline passed with participants still running.
    TimedOut {
        /// How many were still running.
        remaining: usize,
    },
}

fn log(event: &LogEvent) {
    // R-NF-02: typed events only. A failed write cannot be reported
    // anywhere else, so it is dropped.
    let _ = fstp_obs::log_to_stderr(event);
}

const fn signal_of(t: Termination) -> Signal {
    match t {
        Termination::Terminate => Signal::Terminate,
        Termination::Interrupt => Signal::Interrupt,
    }
}

/// Serves one cell over `store` and `vault` until `term` reports a
/// termination signal, then drains it.
///
/// `on_started` runs once the engine serves and `Started` is logged. It
/// receives the engine and the cell's shutdown, so the caller can spawn
/// the listeners and system tasks as participants of the drain.
///
/// It returns once the drain ends, and never waits past the drain
/// deadline. After [`Drain::Drained`] the engine task has ended, and the
/// store comes back. After [`Drain::TimedOut`] a store whose engine task
/// still runs a command is not awaited: the task is aborted, as a crash
/// would end it, and `None` comes back. The store resolves that command
/// at its next start (design section 7.2).
///
/// # Errors
///
/// [`CellError::Store`] or [`CellError::Fold`] when the engine cannot
/// replay the store. [`CellError::NotImplemented`] when the engine task
/// ends without giving the store back.
pub async fn serve_until_terminated<R, L, S, V, F>(
    rt: &R,
    mut term: L,
    store: S,
    vault: V,
    opts: ServeOptions,
    on_started: F,
) -> Result<(Option<S>, Drain), CellError>
where
    R: Runtime,
    L: TerminationListener,
    S: CellStore,
    V: VaultClient,
    F: FnOnce(&CellEngine, &Shutdown),
{
    let shutdown = Shutdown::new();
    let (engine, task) = CellEngine::start(rt, store, vault, &shutdown, opts.queue)
        .await
        .map_err(|e| match e {
            super::StartError::Store(s) => CellError::Store(s),
            super::StartError::Fold(f) => CellError::Fold(f),
        })?;
    log(&LogEvent::Started);
    on_started(&engine, &shutdown);
    let which = term.recv().await;
    log(&LogEvent::SignalReceived {
        signal: signal_of(which),
    });
    let drain = drain(rt, &shutdown, opts.drain).await;
    drop(engine);
    if matches!(drain, Drain::TimedOut { .. }) && !task.is_finished() {
        // The engine is a stuck participant. Awaiting it would keep the
        // process alive past the deadline (ADR-002 review note).
        task.abort();
        return Ok((None, drain));
    }
    let store = task.await.map_err(|_| {
        CellError::NotImplemented("the engine task ended without its store (a panic)")
    })?;
    Ok((Some(store), drain))
}

/// Triggers `shutdown`, waits for the drain up to `deadline`, and logs
/// the outcome.
pub async fn drain<R: Runtime>(rt: &R, shutdown: &Shutdown, deadline: Duration) -> Drain {
    log(&LogEvent::ShuttingDown);
    let start = Instant::now();
    match shutdown.shutdown(rt, deadline).await {
        Ok(()) => {
            log(&LogEvent::Drained {
                elapsed: start.elapsed(),
            });
            Drain::Drained
        }
        Err(t) => {
            log(&LogEvent::DrainTimedOut {
                remaining: u64::try_from(t.remaining).unwrap_or(u64::MAX),
            });
            Drain::TimedOut {
                remaining: t.remaining,
            }
        }
    }
}
