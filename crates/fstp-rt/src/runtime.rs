//! The internal runtime trait (ADR-002).

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use crate::io::Connection;
use crate::task::JoinHandle;

/// A bound socket that accepts connections.
pub trait Listener: Send + 'static {
    /// The connection type this listener yields.
    type Conn: Connection;

    /// Waits for the next inbound connection and returns it with the peer
    /// address.
    fn accept(&mut self) -> impl Future<Output = io::Result<(Self::Conn, SocketAddr)>> + Send;

    /// The address this listener is bound to.
    ///
    /// # Errors
    ///
    /// Returns the operating system error if the address cannot be read.
    fn local_addr(&self) -> io::Result<SocketAddr>;
}

/// Spawning, timers and sockets, independent of the runtime crate.
///
/// Protocol code is generic over `R: Runtime`. Each binary picks exactly one
/// implementation (ADR-002). This crate ships
/// [`TokioRuntime`](crate::tokio::TokioRuntime).
pub trait Runtime: Clone + Send + Sync + 'static {
    /// TCP connection type.
    type Tcp: Connection;
    /// TCP listener type.
    type TcpListener: Listener<Conn = Self::Tcp>;

    /// Runs `f` as a new task. See [`JoinHandle`] for result, abort and panic
    /// semantics.
    fn spawn<F>(&self, f: F) -> JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static;

    /// Runs a blocking closure on a thread reserved for blocking work.
    fn spawn_blocking<F, R>(&self, f: F) -> JoinHandle<R>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static;

    /// Completes after `d` has passed.
    fn sleep(&self, d: Duration) -> impl Future<Output = ()> + Send + 'static;

    /// Opens a TCP connection to `addr`.
    fn connect_tcp(&self, addr: SocketAddr) -> impl Future<Output = io::Result<Self::Tcp>> + Send;

    /// Binds a TCP listener to `addr`. Port 0 picks a free port.
    fn bind_tcp(
        &self,
        addr: SocketAddr,
    ) -> impl Future<Output = io::Result<Self::TcpListener>> + Send;

    /// Resolves `host` to socket addresses with `port`.
    ///
    /// An IP literal resolves to itself without a lookup. An empty result is
    /// an error.
    fn resolve(
        &self,
        host: &str,
        port: u16,
    ) -> impl Future<Output = io::Result<Vec<SocketAddr>>> + Send;
}
