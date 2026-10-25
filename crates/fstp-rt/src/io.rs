//! Poll-based IO traits and in-house async helpers.
//!
//! [`AsyncRead`] and [`AsyncWrite`] are the only IO abstraction that protocol
//! code sees. Runtime modules adapt their socket types to these traits, so a
//! protocol never names a runtime crate (ADR-002).

use std::future::Future;
use std::io;
use std::ops::DerefMut;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Reads bytes from a source without blocking the thread.
///
/// The contract follows `std::io::Read`, translated to polling:
///
/// - `Poll::Ready(Ok(n))` with `n > 0` means `n` bytes were placed at the
///   start of `buf`.
/// - `Poll::Ready(Ok(0))` with a non-empty `buf` means end of stream.
/// - `Poll::Pending` means no data is available yet. The implementation has
///   arranged for `cx.waker()` to be woken when that may change.
pub trait AsyncRead {
    /// Attempts to read into `buf`.
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>>;
}

/// Writes bytes to a sink without blocking the thread.
///
/// - `poll_write` returns how many bytes of `buf` were accepted. A result of
///   `Ok(0)` for a non-empty `buf` means the sink can accept no more data.
/// - `poll_flush` pushes buffered data towards the destination.
/// - `poll_shutdown` flushes and then closes the write direction. The peer
///   then reads end of stream once it has consumed all earlier data.
pub trait AsyncWrite {
    /// Attempts to write bytes from `buf`.
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>>;

    /// Attempts to flush buffered data.
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>>;

    /// Attempts to flush and close the write direction.
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>>;
}

/// A bidirectional byte stream that can move between tasks.
///
/// Every type that is [`AsyncRead`], [`AsyncWrite`], `Send`, `Unpin` and
/// `'static` is a `Connection`.
pub trait Connection: AsyncRead + AsyncWrite + Send + Unpin + 'static {}

impl<T> Connection for T where T: AsyncRead + AsyncWrite + Send + Unpin + 'static {}

impl<T: AsyncRead + Unpin + ?Sized> AsyncRead for &mut T {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut **self).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin + ?Sized> AsyncWrite for &mut T {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut **self).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut **self).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut **self).poll_shutdown(cx)
    }
}

impl<T: AsyncRead + Unpin + ?Sized> AsyncRead for Box<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut **self).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin + ?Sized> AsyncWrite for Box<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut **self).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut **self).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut **self).poll_shutdown(cx)
    }
}

impl<P> AsyncRead for Pin<P>
where
    P: DerefMut + Unpin,
    P::Target: AsyncRead,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut().as_mut().poll_read(cx, buf)
    }
}

impl<P> AsyncWrite for Pin<P>
where
    P: DerefMut + Unpin,
    P::Target: AsyncWrite,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut().as_mut().poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().as_mut().poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().as_mut().poll_shutdown(cx)
    }
}

/// Async helper methods for any `AsyncRead + AsyncWrite + Unpin` value.
///
/// Every method returns an in-house future that borrows the stream. Dropping
/// a future before it completes is safe. For [`IoExt::read_exact`] and
/// [`IoExt::write_all`], a dropped future may leave a part of the buffer
/// transferred, as with any partial IO.
pub trait IoExt: AsyncRead + AsyncWrite + Unpin {
    /// Reads some bytes into `buf` and returns how many. `Ok(0)` for a
    /// non-empty `buf` is end of stream.
    fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> Read<'a, Self> {
        Read { io: self, buf }
    }

    /// Fills `buf` completely.
    ///
    /// Fails with [`io::ErrorKind::UnexpectedEof`] when the stream ends first.
    fn read_exact<'a>(&'a mut self, buf: &'a mut [u8]) -> ReadExact<'a, Self> {
        ReadExact {
            io: self,
            buf,
            filled: 0,
        }
    }

    /// Reads until end of stream, appending to `out`.
    ///
    /// Fails with [`io::ErrorKind::InvalidData`] once more than `limit` bytes
    /// would be appended. The bytes read up to that point stay in `out`.
    fn read_to_end<'a>(&'a mut self, out: &'a mut Vec<u8>, limit: usize) -> ReadToEnd<'a, Self> {
        ReadToEnd {
            io: self,
            out,
            limit,
            read: 0,
        }
    }

    /// Writes some bytes from `buf` and returns how many were accepted.
    fn write<'a>(&'a mut self, buf: &'a [u8]) -> Write<'a, Self> {
        Write { io: self, buf }
    }

    /// Writes all of `buf`.
    ///
    /// Fails with [`io::ErrorKind::WriteZero`] when the sink stops accepting
    /// data first.
    fn write_all<'a>(&'a mut self, buf: &'a [u8]) -> WriteAll<'a, Self> {
        WriteAll { io: self, buf }
    }

    /// Flushes buffered data.
    fn flush(&mut self) -> Flush<'_, Self> {
        Flush { io: self }
    }

    /// Flushes and closes the write direction.
    fn shutdown(&mut self) -> ShutdownWrite<'_, Self> {
        ShutdownWrite { io: self }
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin + ?Sized> IoExt for T {}

/// Future returned by [`IoExt::read`].
#[derive(Debug)]
#[must_use = "futures do nothing unless polled"]
pub struct Read<'a, T: ?Sized> {
    io: &'a mut T,
    buf: &'a mut [u8],
}

impl<T: AsyncRead + Unpin + ?Sized> Future for Read<'_, T> {
    type Output = io::Result<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        Pin::new(&mut *this.io).poll_read(cx, this.buf)
    }
}

/// Future returned by [`IoExt::read_exact`].
#[derive(Debug)]
#[must_use = "futures do nothing unless polled"]
pub struct ReadExact<'a, T: ?Sized> {
    io: &'a mut T,
    buf: &'a mut [u8],
    filled: usize,
}

impl<T: AsyncRead + Unpin + ?Sized> Future for ReadExact<'_, T> {
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        loop {
            let Some(rest) = this.buf.get_mut(this.filled..) else {
                return Poll::Ready(Err(invalid_state()));
            };
            if rest.is_empty() {
                return Poll::Ready(Ok(()));
            }
            let n = match Pin::new(&mut *this.io).poll_read(cx, rest) {
                Poll::Ready(Ok(n)) => n,
                Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::Interrupted => continue,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "stream ended before the buffer was filled",
                )));
            }
            this.filled = this.filled.saturating_add(n.min(rest.len()));
        }
    }
}

/// Future returned by [`IoExt::read_to_end`].
#[derive(Debug)]
#[must_use = "futures do nothing unless polled"]
pub struct ReadToEnd<'a, T: ?Sized> {
    io: &'a mut T,
    out: &'a mut Vec<u8>,
    limit: usize,
    read: usize,
}

impl<T: AsyncRead + Unpin + ?Sized> Future for ReadToEnd<'_, T> {
    type Output = io::Result<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let mut chunk = [0u8; 8192];
        loop {
            // Read one byte past the limit so that "exactly limit" succeeds
            // and "more than limit" is detected.
            let room = this.limit.saturating_sub(this.read).saturating_add(1);
            let want = room.min(chunk.len());
            let Some(dst) = chunk.get_mut(..want) else {
                return Poll::Ready(Err(invalid_state()));
            };
            let n = match Pin::new(&mut *this.io).poll_read(cx, dst) {
                Poll::Ready(Ok(n)) => n.min(dst.len()),
                Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::Interrupted => continue,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            if n == 0 {
                return Poll::Ready(Ok(this.read));
            }
            let total = this.read.saturating_add(n);
            if total > this.limit {
                let keep = this.limit.saturating_sub(this.read);
                if let Some(part) = dst.get(..keep) {
                    this.out.extend_from_slice(part);
                }
                this.read = this.limit;
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "stream exceeds the read limit",
                )));
            }
            if let Some(part) = dst.get(..n) {
                this.out.extend_from_slice(part);
            }
            this.read = total;
        }
    }
}

/// Future returned by [`IoExt::write`].
#[derive(Debug)]
#[must_use = "futures do nothing unless polled"]
pub struct Write<'a, T: ?Sized> {
    io: &'a mut T,
    buf: &'a [u8],
}

impl<T: AsyncWrite + Unpin + ?Sized> Future for Write<'_, T> {
    type Output = io::Result<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        Pin::new(&mut *this.io).poll_write(cx, this.buf)
    }
}

/// Future returned by [`IoExt::write_all`].
#[derive(Debug)]
#[must_use = "futures do nothing unless polled"]
pub struct WriteAll<'a, T: ?Sized> {
    io: &'a mut T,
    buf: &'a [u8],
}

impl<T: AsyncWrite + Unpin + ?Sized> Future for WriteAll<'_, T> {
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        while !this.buf.is_empty() {
            let n = match Pin::new(&mut *this.io).poll_write(cx, this.buf) {
                Poll::Ready(Ok(n)) => n,
                Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::Interrupted => continue,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "sink accepted no more data",
                )));
            }
            this.buf = this.buf.get(n..).unwrap_or_default();
        }
        Poll::Ready(Ok(()))
    }
}

/// Future returned by [`IoExt::flush`].
#[derive(Debug)]
#[must_use = "futures do nothing unless polled"]
pub struct Flush<'a, T: ?Sized> {
    io: &'a mut T,
}

impl<T: AsyncWrite + Unpin + ?Sized> Future for Flush<'_, T> {
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut *self.get_mut().io).poll_flush(cx)
    }
}

/// Future returned by [`IoExt::shutdown`].
#[derive(Debug)]
#[must_use = "futures do nothing unless polled"]
pub struct ShutdownWrite<'a, T: ?Sized> {
    io: &'a mut T,
}

impl<T: AsyncWrite + Unpin + ?Sized> Future for ShutdownWrite<'_, T> {
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut *self.get_mut().io).poll_shutdown(cx)
    }
}

fn invalid_state() -> io::Error {
    io::Error::other("io helper reached an inconsistent state")
}
