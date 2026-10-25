//! tokio implementation of [`Runtime`] (ADR-002).
//!
//! All tokio-specific code lives in this module, so a smol module can sit next
//! to it later. The workspace enables only the tokio features `rt`,
//! `rt-multi-thread`, `net` and `time`. Sockets are adapted through tokio's
//! own `AsyncRead`, `AsyncWrite` and `ReadBuf`, which need no extra feature.

use std::fmt;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use ::tokio::io::{AsyncRead as TokioRead, AsyncWrite as TokioWrite, ReadBuf};
use ::tokio::runtime::{Builder, Handle};

use crate::io::{AsyncRead, AsyncWrite};
use crate::runtime::{Listener, Runtime};
use crate::task::{JoinHandle, blocking_task, task};

/// Longest host name [`Runtime::resolve`] accepts, in bytes (RFC 1035 limit).
pub const MAX_HOST_LEN: usize = 253;

struct Owner {
    rt: Option<::tokio::runtime::Runtime>,
}

impl Drop for Owner {
    fn drop(&mut self) {
        if let Some(rt) = self.rt.take() {
            // `shutdown_background` never blocks, so it is safe even when
            // the last handle is dropped on one of the runtime's own threads.
            rt.shutdown_background();
        }
    }
}

/// A [`Runtime`] backed by tokio.
///
/// Clones share one tokio runtime. The runtime shuts down when the last clone
/// created by [`TokioRuntime::new_multi_thread`] or
/// [`TokioRuntime::new_current_thread`] is dropped. A value made with
/// [`TokioRuntime::from_handle`] or [`TokioRuntime::current`] does not own
/// its runtime and must not outlive it.
#[derive(Clone)]
pub struct TokioRuntime {
    handle: Handle,
    owner: Option<Arc<Owner>>,
}

impl fmt::Debug for TokioRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokioRuntime")
            .field("owned", &self.owner.is_some())
            .finish_non_exhaustive()
    }
}

impl TokioRuntime {
    /// Starts a multi-threaded runtime with `workers` worker threads.
    ///
    /// A `workers` value of zero is raised to one.
    ///
    /// # Errors
    ///
    /// Returns the operating system error if the threads or the IO driver
    /// cannot be created.
    pub fn new_multi_thread(workers: usize) -> io::Result<Self> {
        let rt = Builder::new_multi_thread()
            .worker_threads(workers.max(1))
            .thread_name("fstp-rt-worker")
            .enable_all()
            .build()?;
        Ok(Self::owning(rt))
    }

    /// Starts a runtime that runs every task on the thread calling
    /// [`TokioRuntime::block_on`].
    ///
    /// # Errors
    ///
    /// Returns the operating system error if the IO driver cannot be created.
    pub fn new_current_thread() -> io::Result<Self> {
        let rt = Builder::new_current_thread().enable_all().build()?;
        Ok(Self::owning(rt))
    }

    fn owning(rt: ::tokio::runtime::Runtime) -> Self {
        Self {
            handle: rt.handle().clone(),
            owner: Some(Arc::new(Owner { rt: Some(rt) })),
        }
    }

    /// Wraps an existing tokio runtime handle without owning the runtime.
    ///
    /// The runtime must have its IO and time drivers enabled.
    ///
    /// The returned value and its clones must not outlive the runtime that
    /// owns `handle`. Once that runtime has shut down, spawned tasks are
    /// cancelled at once, and tokio panics when a timer from
    /// [`Runtime::sleep`] or [`timeout`](crate::timeout) is polled.
    #[must_use]
    pub fn from_handle(handle: Handle) -> Self {
        Self {
            handle,
            owner: None,
        }
    }

    /// Returns the runtime whose context the current thread is in, if any.
    ///
    /// The value does not own the runtime. As with
    /// [`TokioRuntime::from_handle`], it must not outlive it.
    #[must_use]
    pub fn current() -> Option<Self> {
        Handle::try_current().ok().map(Self::from_handle)
    }

    /// Runs `fut` to completion on this runtime, blocking the current thread.
    ///
    /// # Panics
    ///
    /// tokio panics when this is called from inside an async context, since
    /// blocking there would stall a worker thread. Call it only from plain
    /// threads such as `main` or a test function.
    pub fn block_on<F: Future>(&self, fut: F) -> F::Output {
        match self.owner.as_ref().and_then(|o| o.rt.as_ref()) {
            Some(rt) => rt.block_on(fut),
            None => self.handle.block_on(fut),
        }
    }

    /// Shuts the runtime down, waiting up to `timeout` for worker and
    /// blocking threads to stop.
    ///
    /// Returns `true` when this value was the last owner and the runtime was
    /// shut down here. Otherwise the runtime stays up for the other clones.
    /// Inside an async context the wait is skipped.
    pub fn shutdown_timeout(self, timeout: Duration) -> bool {
        let Some(owner) = self.owner else {
            return false;
        };
        let Ok(mut owner) = Arc::try_unwrap(owner) else {
            return false;
        };
        let Some(rt) = owner.rt.take() else {
            return false;
        };
        if Handle::try_current().is_ok() {
            rt.shutdown_background();
        } else {
            rt.shutdown_timeout(timeout);
        }
        true
    }

    /// The underlying tokio handle, for code inside this module's boundary.
    #[must_use]
    pub fn handle(&self) -> &Handle {
        &self.handle
    }
}

/// Polls `fut` with the runtime's context entered.
///
/// tokio looks up its reactor and timer through a thread-local context. This
/// wrapper sets that context for the duration of each poll, so the futures
/// returned by [`TokioRuntime`] work on any executor thread.
struct InRuntime<F> {
    handle: Handle,
    fut: Pin<Box<F>>,
}

impl<F: Future> InRuntime<F> {
    fn new(handle: Handle, fut: F) -> Self {
        Self {
            handle,
            fut: Box::pin(fut),
        }
    }
}

impl<F: Future> Future for InRuntime<F> {
    type Output = F::Output;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<F::Output> {
        let this = &mut *self;
        let _guard = this.handle.enter();
        this.fut.as_mut().poll(cx)
    }
}

impl Runtime for TokioRuntime {
    type Tcp = TcpStream;
    type TcpListener = TcpListener;

    fn spawn<F>(&self, f: F) -> JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let (fut, handle) = task(f);
        // The tokio handle is dropped, which detaches the tokio task. The
        // in-house handle carries result, abort and panic reporting.
        drop(self.handle.spawn(fut));
        handle
    }

    fn spawn_blocking<F, R>(&self, f: F) -> JoinHandle<R>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        let (job, handle) = blocking_task(f);
        drop(self.handle.spawn_blocking(move || job.run()));
        handle
    }

    fn sleep(&self, d: Duration) -> impl Future<Output = ()> + Send + 'static {
        let _guard = self.handle.enter();
        // tokio caps deadlines that overflow `Instant` at a far-future value.
        ::tokio::time::sleep(d)
    }

    fn connect_tcp(&self, addr: SocketAddr) -> impl Future<Output = io::Result<TcpStream>> + Send {
        InRuntime::new(self.handle.clone(), async move {
            let inner = ::tokio::net::TcpStream::connect(addr).await?;
            inner.set_nodelay(true)?;
            Ok(TcpStream { inner })
        })
    }

    fn bind_tcp(&self, addr: SocketAddr) -> impl Future<Output = io::Result<TcpListener>> + Send {
        let handle = self.handle.clone();
        InRuntime::new(self.handle.clone(), async move {
            let inner = ::tokio::net::TcpListener::bind(addr).await?;
            Ok(TcpListener { inner, handle })
        })
    }

    fn resolve(
        &self,
        host: &str,
        port: u16,
    ) -> impl Future<Output = io::Result<Vec<SocketAddr>>> + Send {
        let host = host.to_owned();
        InRuntime::new(self.handle.clone(), async move {
            if host.is_empty() || host.len() > MAX_HOST_LEN || host.contains('\0') {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "host name is empty, too long or contains NUL",
                ));
            }
            let addrs: Vec<SocketAddr> = ::tokio::net::lookup_host((host.as_str(), port))
                .await?
                .collect();
            if addrs.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "host name resolved to no addresses",
                ));
            }
            Ok(addrs)
        })
    }
}

/// A TCP connection on the tokio runtime.
///
/// `TCP_NODELAY` is set on every connection, because the platform's protocols
/// write whole messages and flush explicitly.
pub struct TcpStream {
    inner: ::tokio::net::TcpStream,
}

impl fmt::Debug for TcpStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpStream")
            .field("local", &self.inner.local_addr().ok())
            .field("peer", &self.inner.peer_addr().ok())
            .finish()
    }
}

impl TcpStream {
    /// The local address of this connection.
    ///
    /// # Errors
    ///
    /// Returns the operating system error if the address cannot be read.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    /// The remote address of this connection.
    ///
    /// # Errors
    ///
    /// Returns the operating system error if the address cannot be read.
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.inner.peer_addr()
    }

    /// Sets or clears `TCP_NODELAY`.
    ///
    /// # Errors
    ///
    /// Returns the operating system error if the option cannot be set.
    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        self.inner.set_nodelay(nodelay)
    }
}

impl AsyncRead for TcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let mut rb = ReadBuf::new(buf);
        match TokioRead::poll_read(Pin::new(&mut self.get_mut().inner), cx, &mut rb) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(rb.filled().len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        TokioWrite::poll_write(Pin::new(&mut self.get_mut().inner), cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        TokioWrite::poll_flush(Pin::new(&mut self.get_mut().inner), cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        TokioWrite::poll_shutdown(Pin::new(&mut self.get_mut().inner), cx)
    }
}

/// A TCP listener on the tokio runtime.
pub struct TcpListener {
    inner: ::tokio::net::TcpListener,
    handle: Handle,
}

impl fmt::Debug for TcpListener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpListener")
            .field("local", &self.inner.local_addr().ok())
            .finish()
    }
}

impl Listener for TcpListener {
    type Conn = TcpStream;

    /// Accepts one connection.
    ///
    /// Errors such as a full file descriptor table are returned to the
    /// caller. An accept loop decides whether to back off and retry.
    fn accept(&mut self) -> impl Future<Output = io::Result<(TcpStream, SocketAddr)>> + Send {
        let handle = self.handle.clone();
        let listener = &self.inner;
        InRuntime::new(handle, async move {
            let (inner, addr) = listener.accept().await?;
            inner.set_nodelay(true)?;
            Ok((TcpStream { inner }, addr))
        })
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}
