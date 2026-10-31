//! Thin internal runtime trait for spawning, timers and sockets (ADR-002), with a tokio implementation.
//!
//! Protocol code in the platform is written against this crate, never against
//! a runtime crate directly. That keeps the choice between tokio and smol a
//! per-binary decision (ADR-002).
//!
//! - [`AsyncRead`], [`AsyncWrite`] and [`Connection`]: poll-based IO traits.
//! - [`IoExt`]: async helpers (`read`, `read_exact`, `write_all`, `flush`,
//!   `shutdown`, `read_to_end`) as in-house futures.
//! - [`Runtime`] and [`Listener`]: spawning, timers and TCP.
//! - [`JoinHandle`]: awaitable and abortable. A panicked task is reported as
//!   a [`JoinError`] instead of propagating.
//! - [`timeout`]: a deadline on any future.
//! - [`Shutdown`] and [`ShutdownSignal`]: graceful shutdown.
//! - [`duplex`]: an in-memory connection pair for tests and fuzzing.
//! - [`scripted`]: a transport that replays fixed peer bytes, for fuzz
//!   targets of protocol endpoints.
//! - [`future`]: `block_on`, `join`, `race`, `yield_now` and `poll_bounded`.
//! - [`signal`]: termination signals behind the runtime trait, so SIGTERM
//!   can trigger [`Shutdown`].
//! - [`tokio`]: the tokio implementation of [`Runtime`].
//!
//! This crate contains no parser. It moves opaque bytes and never interprets
//! them, so it has no fuzz target (ADR-003 covers parsers and protocol
//! decoders). Its in-memory transports, [`duplex`] and [`scripted`], are what
//! the fuzz targets of protocol crates run over.

pub mod duplex;
pub mod future;
mod io;
mod runtime;
pub mod scripted;
mod shutdown;
pub mod signal;
mod task;
mod time;
pub mod tokio;

pub use crate::io::{
    AsyncRead, AsyncWrite, Connection, Flush, IoExt, Read, ReadExact, ReadToEnd, ShutdownWrite,
    Write, WriteAll,
};
pub use crate::runtime::{Listener, Runtime};
pub use crate::shutdown::{DrainTimeout, Drained, Notified, Shutdown, ShutdownSignal};
pub use crate::task::{AbortHandle, JoinError, JoinHandle};
pub use crate::time::{Elapsed, timeout};
