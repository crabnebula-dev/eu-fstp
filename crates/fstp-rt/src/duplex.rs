//! In-memory connection pair for tests and fuzzing.
//!
//! [`duplex`] returns two connected [`DuplexStream`]s. Bytes written to one
//! are read from the other. Each direction has its own bounded buffer, so a
//! writer that outpaces its reader gets `Pending` and is woken once the reader
//! frees space. No runtime is needed: any executor can drive the pair.
//!
//! Semantics, per direction:
//!
//! - A write accepts at most the free buffer space and returns how much it
//!   accepted. With no free space it returns `Pending`.
//! - A read returns at most the buffered bytes. With nothing buffered it
//!   returns `Pending`, or `Ok(0)` once the writer shut down or was dropped.
//! - `poll_shutdown` closes the write direction. Buffered bytes stay
//!   readable, then the reader sees end of stream. A later write fails with
//!   [`io::ErrorKind::BrokenPipe`].
//! - Dropping a stream closes both of its directions. The peer reads any
//!   buffered bytes and then end of stream. Writes by the peer fail with
//!   [`io::ErrorKind::BrokenPipe`].

use std::collections::VecDeque;
use std::fmt;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};

use crate::io::{AsyncRead, AsyncWrite};

struct Pipe {
    buf: VecDeque<u8>,
    capacity: usize,
    /// The writing end shut down or was dropped.
    write_closed: bool,
    /// The reading end was dropped.
    read_closed: bool,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
}

impl Pipe {
    fn new(capacity: usize) -> Arc<Mutex<Pipe>> {
        Arc::new(Mutex::new(Pipe {
            buf: VecDeque::new(),
            capacity,
            write_closed: false,
            read_closed: false,
            read_waker: None,
            write_waker: None,
        }))
    }
}

fn lock(pipe: &Mutex<Pipe>) -> MutexGuard<'_, Pipe> {
    pipe.lock().unwrap_or_else(PoisonError::into_inner)
}

fn store(slot: &mut Option<Waker>, waker: &Waker) {
    match slot {
        Some(w) if w.will_wake(waker) => {}
        other => *other = Some(waker.clone()),
    }
}

/// One end of an in-memory connection. See the [module docs](self).
pub struct DuplexStream {
    /// Bytes flowing towards this end.
    incoming: Arc<Mutex<Pipe>>,
    /// Bytes flowing away from this end.
    outgoing: Arc<Mutex<Pipe>>,
}

impl fmt::Debug for DuplexStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DuplexStream").finish_non_exhaustive()
    }
}

/// Creates a connected pair with `capacity` bytes of buffer per direction.
///
/// A `capacity` of zero is raised to one, so that progress is always possible.
#[must_use]
pub fn duplex(capacity: usize) -> (DuplexStream, DuplexStream) {
    let capacity = capacity.max(1);
    let a_to_b = Pipe::new(capacity);
    let b_to_a = Pipe::new(capacity);
    (
        DuplexStream {
            incoming: b_to_a.clone(),
            outgoing: a_to_b.clone(),
        },
        DuplexStream {
            incoming: a_to_b,
            outgoing: b_to_a,
        },
    )
}

impl DuplexStream {
    /// Number of bytes buffered towards this end and not yet read.
    #[must_use]
    pub fn readable_len(&self) -> usize {
        lock(&self.incoming).buf.len()
    }
}

impl AsyncRead for DuplexStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut pipe = lock(&self.incoming);
        if pipe.buf.is_empty() {
            if pipe.write_closed {
                return Poll::Ready(Ok(0));
            }
            store(&mut pipe.read_waker, cx.waker());
            return Poll::Pending;
        }
        // `drain` removes its whole range even if the zip stops early, so the
        // range is limited to what fits into `buf`.
        let n = buf.len().min(pipe.buf.len());
        for (dst, src) in buf.iter_mut().zip(pipe.buf.drain(..n)) {
            *dst = src;
        }
        let waker = pipe.write_waker.take();
        drop(pipe);
        if let Some(w) = waker {
            w.wake();
        }
        Poll::Ready(Ok(n))
    }
}

impl AsyncWrite for DuplexStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut pipe = lock(&self.outgoing);
        if pipe.write_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "write after shutdown",
            )));
        }
        if pipe.read_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "peer dropped its end",
            )));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let free = pipe.capacity.saturating_sub(pipe.buf.len());
        if free == 0 {
            store(&mut pipe.write_waker, cx.waker());
            return Poll::Pending;
        }
        let n = free.min(buf.len());
        pipe.buf.extend(buf.iter().take(n));
        let waker = pipe.read_waker.take();
        drop(pipe);
        if let Some(w) = waker {
            w.wake();
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let waker = {
            let mut pipe = lock(&self.outgoing);
            pipe.write_closed = true;
            pipe.read_waker.take()
        };
        if let Some(w) = waker {
            w.wake();
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for DuplexStream {
    fn drop(&mut self) {
        let reader = {
            let mut pipe = lock(&self.outgoing);
            pipe.write_closed = true;
            pipe.read_waker.take()
        };
        let writer = {
            let mut pipe = lock(&self.incoming);
            pipe.read_closed = true;
            pipe.buf.clear();
            pipe.write_waker.take()
        };
        if let Some(w) = reader {
            w.wake();
        }
        if let Some(w) = writer {
            w.wake();
        }
    }
}
