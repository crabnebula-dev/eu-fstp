//! HTTP/1.1 server driver over any [`fstp_rt::Runtime`].
//!
//! - Optional TLS and mutual TLS through `fstp-tls` (R-NF-09). Under mutual
//!   TLS, handlers see the client certificate through
//!   [`Request::client_certificate_der`].
//! - Keep-alive and pipelining. Requests on one connection are handled in
//!   order and their responses are written in the same order.
//! - Separate deadlines for the TLS handshake, the request head, the body,
//!   idle keep-alive time and response writes. A client that sends a head
//!   slowly (slowloris) is cut off when the head deadline passes.
//! - A cap on concurrent connections. At the cap, the accept loop waits for
//!   a slot, so excess connections wait in the kernel backlog.
//! - Graceful shutdown with a drain deadline through [`fstp_rt::Shutdown`]:
//!   the listener closes, idle connections close, in-flight requests finish
//!   with `Connection: close`, and connections still open at the deadline
//!   are aborted.
//! - Bodies are buffered up to [`Limits::max_body_bytes`] before the
//!   handler runs.
//! - Errors in a request get the status from
//!   [`ParseErrorKind::status`](crate::ParseErrorKind::status) and close the
//!   connection.
//!
//! The server never logs. It reports [`ServerEvent`]s to an optional hook.
//! Events carry kinds, status codes and durations only, never header
//! values, bodies, targets or peer addresses (R-NF-02).

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant, SystemTime};

use fstp_rt::future::{Either, race};
use fstp_rt::{
    AbortHandle, Connection, DrainTimeout, IoExt, JoinHandle, Listener, Runtime, Shutdown,
    ShutdownSignal, timeout,
};
use fstp_tls::{TlsError, TlsErrorKind};

use crate::decode::{RequestDecoder, RequestEvent};
use crate::encode::{CONTINUE_RESPONSE, SerializeError, encode_response};
use crate::error::{ParseError, ParseErrorKind};
use crate::handler::Handler;
use crate::header::{HeaderName, HeaderValue};
use crate::io::{CatchUnwind, deadline_after, http_date, remaining};
use crate::limits::Limits;
use crate::message::{BodyKind, Request, Response};
use crate::method::Method;
use crate::status::StatusCode;
use crate::version::Version;

/// Which deadline passed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TimeoutPhase {
    /// The TLS handshake.
    TlsHandshake,
    /// Waiting for the first byte of a request on a kept-alive connection,
    /// or of the first request on a new connection.
    Idle,
    /// Reading a request head after its first byte.
    Header,
    /// Reading a request body.
    Body,
    /// Writing a response.
    Write,
}

/// A content-free report from the server.
///
/// No variant carries header values, bodies, request targets or peer
/// addresses (R-NF-02).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ServerEvent {
    /// A connection was accepted.
    ConnectionOpened,
    /// A connection closed after serving this many requests.
    ConnectionClosed {
        /// Requests answered on the connection.
        requests: u64,
    },
    /// Accepting a connection failed.
    AcceptFailed {
        /// The operating system error kind.
        kind: io::ErrorKind,
    },
    /// The TLS handshake failed.
    TlsHandshakeFailed {
        /// The TLS failure class, when known.
        kind: Option<TlsErrorKind>,
    },
    /// A request violated the grammar, a framing rule or a limit.
    RequestRejected {
        /// The rule that failed.
        kind: ParseErrorKind,
        /// The status sent in reply.
        status: StatusCode,
    },
    /// A deadline passed.
    Timeout {
        /// Which deadline.
        phase: TimeoutPhase,
    },
    /// A handler panicked. The client got 500.
    HandlerPanicked,
    /// A handler's response could not be serialized. The client got 500.
    SerializeFailed {
        /// Why serialization failed.
        error: SerializeError,
    },
    /// A response was written.
    ResponseSent {
        /// The request method for standard methods, or `OTHER` for
        /// extension methods, whose names a client chooses freely.
        method: &'static str,
        /// The status sent.
        status: StatusCode,
        /// Time from the end of the request to the end of the write.
        duration: Duration,
    },
}

/// A callback that receives [`ServerEvent`]s.
#[derive(Clone)]
pub struct EventHook(Arc<dyn Fn(&ServerEvent) + Send + Sync>);

impl EventHook {
    /// Wraps a callback. It runs on connection tasks, so it should be quick.
    pub fn new(f: impl Fn(&ServerEvent) + Send + Sync + 'static) -> EventHook {
        EventHook(Arc::new(f))
    }
}

impl fmt::Debug for EventHook {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EventHook")
    }
}

/// Server settings.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Parser limits for requests.
    pub limits: Limits,
    /// TLS settings. `None` serves plain TCP. A configuration built with
    /// [`fstp_tls::ServerConfig::mutual`] requires client certificates.
    pub tls: Option<fstp_tls::ServerConfig>,
    /// Deadline for the TLS handshake.
    pub tls_handshake_timeout: Duration,
    /// Deadline for a request head, from its first byte. A new connection
    /// must also deliver its first byte within this time.
    pub header_read_timeout: Duration,
    /// Deadline for a request body, from the end of the head.
    pub body_read_timeout: Duration,
    /// How long a kept-alive connection may wait for the next request.
    pub idle_timeout: Duration,
    /// Deadline for writing one response.
    pub write_timeout: Duration,
    /// Most connections served at once. Zero accepts no connection at all.
    pub max_connections: usize,
    /// Most requests on one connection before it is closed.
    pub max_requests_per_connection: u64,
    /// Size of each socket read, in bytes.
    pub read_buffer_size: usize,
    /// After an error response, how long to keep reading and discarding
    /// input, so that the client receives the response before the close.
    pub linger_timeout: Duration,
    /// Most bytes discarded while lingering.
    pub linger_max_bytes: usize,
    /// Receives [`ServerEvent`]s.
    pub on_event: Option<EventHook>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            limits: Limits::default(),
            tls: None,
            tls_handshake_timeout: Duration::from_secs(10),
            header_read_timeout: Duration::from_secs(10),
            body_read_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(60),
            write_timeout: Duration::from_secs(30),
            max_connections: 1024,
            max_requests_per_connection: 1000,
            read_buffer_size: 16 * 1024,
            linger_timeout: Duration::from_secs(2),
            linger_max_bytes: 256 * 1024,
            on_event: None,
        }
    }
}

/// Abort handles of live connection tasks.
#[derive(Default)]
struct Registry {
    handles: Mutex<Vec<AbortHandle>>,
}

impl Registry {
    fn lock(&self) -> MutexGuard<'_, Vec<AbortHandle>> {
        self.handles.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn insert(&self, h: AbortHandle) {
        let mut v = self.lock();
        v.retain(|h| !h.is_finished());
        v.push(h);
    }

    fn abort_all(&self) {
        for h in self.lock().iter() {
            h.abort();
        }
    }
}

/// A counting gate for concurrent connections.
struct Slots {
    state: Mutex<SlotState>,
}

struct SlotState {
    free: usize,
    waiter: Option<Waker>,
}

impl Slots {
    fn new(n: usize) -> Arc<Slots> {
        Arc::new(Slots {
            state: Mutex::new(SlotState {
                free: n,
                waiter: None,
            }),
        })
    }

    fn lock(&self) -> MutexGuard<'_, SlotState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    async fn acquire(self: &Arc<Self>) -> Permit {
        std::future::poll_fn(|cx: &mut Context<'_>| {
            let mut st = self.lock();
            if st.free > 0 {
                st.free = st.free.saturating_sub(1);
                Poll::Ready(Permit(self.clone()))
            } else {
                st.waiter = Some(cx.waker().clone());
                Poll::Pending
            }
        })
        .await
    }
}

/// One connection slot. Dropping it frees the slot.
struct Permit(Arc<Slots>);

impl Drop for Permit {
    fn drop(&mut self) {
        let waker = {
            let mut st = self.0.lock();
            st.free = st.free.saturating_add(1);
            st.waiter.take()
        };
        if let Some(w) = waker {
            w.wake();
        }
    }
}

struct Shared<R, H> {
    rt: R,
    config: ServerConfig,
    handler: H,
    registry: Arc<Registry>,
    slots: Arc<Slots>,
}

impl<R, H> Shared<R, H> {
    fn emit(&self, ev: ServerEvent) {
        if let Some(hook) = &self.config.on_event {
            (hook.0)(&ev);
        }
    }
}

/// An HTTP/1.1 server over any [`fstp_rt::Runtime`].
///
/// - Optional TLS and mutual TLS through `fstp-tls` (R-NF-09). Under mutual
///   TLS, handlers see the client certificate through
///   [`Request::client_certificate_der`].
/// - Keep-alive and pipelining. Requests on one connection are handled in
///   order and their responses are written in the same order.
/// - Separate deadlines for the TLS handshake, the request head, the body,
///   idle keep-alive time and response writes. A client that sends a head
///   slowly (slowloris) is cut off when the head deadline passes.
/// - A cap on concurrent connections. At the cap, the accept loop waits for
///   a slot, so excess connections wait in the kernel backlog.
/// - Graceful shutdown with a drain deadline through [`fstp_rt::Shutdown`]:
///   the listener closes, idle connections close, in-flight requests finish
///   with `Connection: close`, and connections still open at the deadline
///   are aborted.
/// - Bodies are buffered up to [`Limits::max_body_bytes`] before the
///   handler runs.
/// - Errors in a request get the status from [`ParseErrorKind::status`] and
///   close the connection.
///
/// The server never logs. It reports [`ServerEvent`]s to an optional hook.
/// Events carry kinds, status codes and durations only, never header
/// values, bodies, targets or peer addresses (R-NF-02).
pub struct Server<R: Runtime, H: Handler> {
    rt: R,
    config: ServerConfig,
    handler: H,
}

impl<R: Runtime, H: Handler> fmt::Debug for Server<R, H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Server")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl<R: Runtime, H: Handler> Server<R, H> {
    /// A server that runs on `rt` and answers requests with `handler`.
    pub fn new(rt: R, config: ServerConfig, handler: H) -> Server<R, H> {
        Server {
            rt,
            config,
            handler,
        }
    }

    /// Binds a TCP listener to `addr` and starts serving on a spawned task.
    ///
    /// # Errors
    ///
    /// Returns the operating system error when binding fails.
    pub async fn bind(self, addr: SocketAddr) -> io::Result<ServerHandle<R>> {
        let listener = self.rt.bind_tcp(addr).await?;
        self.serve(listener)
    }

    /// Starts serving connections from `listener` on a spawned task.
    ///
    /// # Errors
    ///
    /// Returns the operating system error when the listener's address
    /// cannot be read.
    pub fn serve<L: Listener>(self, listener: L) -> io::Result<ServerHandle<R>> {
        let local_addr = listener.local_addr()?;
        let shutdown = Shutdown::new();
        let signal = shutdown.signal();
        let registry = Arc::new(Registry::default());
        let shared = Arc::new(Shared {
            rt: self.rt.clone(),
            slots: Slots::new(self.config.max_connections),
            config: self.config,
            handler: self.handler,
            registry: registry.clone(),
        });
        let accept = self.rt.spawn(accept_loop(shared, listener, signal));
        Ok(ServerHandle {
            rt: self.rt,
            local_addr,
            shutdown,
            registry,
            accept,
        })
    }
}

/// Controls a running server.
///
/// Dropping the handle triggers shutdown without waiting for the drain.
pub struct ServerHandle<R: Runtime> {
    rt: R,
    local_addr: SocketAddr,
    shutdown: Shutdown,
    registry: Arc<Registry>,
    accept: JoinHandle<()>,
}

impl<R: Runtime> fmt::Debug for ServerHandle<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerHandle")
            .field("local_addr", &self.local_addr)
            .field("shutdown", &self.shutdown)
            .finish_non_exhaustive()
    }
}

impl<R: Runtime> ServerHandle<R> {
    /// The address the server listens on.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Starts shutdown without waiting.
    pub fn trigger_shutdown(&self) {
        self.shutdown.trigger();
    }

    /// Number of tasks that shutdown still waits for: the accept loop while
    /// it runs, plus one per open connection.
    #[must_use]
    pub fn active_tasks(&self) -> usize {
        self.shutdown.active()
    }

    /// Stops accepting, lets in-flight requests finish, and waits up to
    /// `deadline` for every connection to close. Connections still open at
    /// the deadline are aborted.
    ///
    /// # Errors
    ///
    /// Returns [`DrainTimeout`] with the number of tasks that were still
    /// running at the deadline.
    pub async fn shutdown(&self, deadline: Duration) -> Result<(), DrainTimeout> {
        let res = self.shutdown.shutdown(&self.rt, deadline).await;
        if res.is_err() {
            self.registry.abort_all();
            self.accept.abort();
        }
        res
    }
}

impl<R: Runtime> Drop for ServerHandle<R> {
    fn drop(&mut self) {
        self.shutdown.trigger();
    }
}

async fn accept_loop<R: Runtime, H: Handler, L: Listener>(
    shared: Arc<Shared<R, H>>,
    mut listener: L,
    signal: ShutdownSignal,
) {
    loop {
        let Some(permit) = signal.run_until(shared.slots.acquire()).await else {
            break;
        };
        let Some(accepted) = signal.run_until(listener.accept()).await else {
            break;
        };
        match accepted {
            Ok((conn, peer)) => {
                let conn_signal = signal.clone();
                let s = shared.clone();
                let task = shared.rt.spawn(async move {
                    let _permit = permit;
                    handle_connection(&s, conn, peer, &conn_signal).await;
                    drop(conn_signal);
                });
                shared.registry.insert(task.abort_handle());
            }
            Err(e) => {
                drop(permit);
                shared.emit(ServerEvent::AcceptFailed { kind: e.kind() });
                // Back off briefly, for example when file descriptors run
                // out, instead of spinning on the error.
                let pause = shared.rt.sleep(Duration::from_millis(20));
                if signal.run_until(pause).await.is_none() {
                    break;
                }
            }
        }
    }
}

async fn handle_connection<R: Runtime, H: Handler, C: Connection>(
    s: &Shared<R, H>,
    conn: C,
    peer: SocketAddr,
    signal: &ShutdownSignal,
) {
    s.emit(ServerEvent::ConnectionOpened);
    let requests = match &s.config.tls {
        None => ConnDriver::new(s, conn, peer, None, signal).run().await,
        Some(tls) => {
            let hs = timeout(
                &s.rt,
                s.config.tls_handshake_timeout,
                fstp_tls::accept(tls, conn),
            )
            .await;
            match hs {
                Ok(Ok(stream)) => {
                    let cert = stream.peer_end_entity_der().map(Arc::<[u8]>::from);
                    ConnDriver::new(s, stream, peer, cert, signal).run().await
                }
                Ok(Err(e)) => {
                    let kind = TlsError::from_io(&e).map(TlsError::kind);
                    s.emit(ServerEvent::TlsHandshakeFailed { kind });
                    0
                }
                Err(_) => {
                    s.emit(ServerEvent::Timeout {
                        phase: TimeoutPhase::TlsHandshake,
                    });
                    0
                }
            }
        }
    };
    s.emit(ServerEvent::ConnectionClosed { requests });
}

/// Why reading a request stopped.
enum ReadError {
    Parse(ParseError),
    Timeout(TimeoutPhase),
    Io,
}

/// What the connection loop does next.
enum Next {
    Continue,
    Close,
    Linger,
}

struct ConnDriver<'a, R, H, C> {
    s: &'a Shared<R, H>,
    io: C,
    decoder: RequestDecoder,
    buf: Vec<u8>,
    peer: SocketAddr,
    cert: Option<Arc<[u8]>>,
    signal: &'a ShutdownSignal,
    requests: u64,
}

/// A fixed label for a method. Extension method names are chosen by the
/// client and could carry content, so they all read as `OTHER`.
fn method_label(m: &Method) -> &'static str {
    match m.as_str() {
        "GET" => "GET",
        "HEAD" => "HEAD",
        "POST" => "POST",
        "PUT" => "PUT",
        "DELETE" => "DELETE",
        "OPTIONS" => "OPTIONS",
        "TRACE" => "TRACE",
        "PATCH" => "PATCH",
        _ => "OTHER",
    }
}

impl<'a, R: Runtime, H: Handler, C: Connection> ConnDriver<'a, R, H, C> {
    fn new(
        s: &'a Shared<R, H>,
        io: C,
        peer: SocketAddr,
        cert: Option<Arc<[u8]>>,
        signal: &'a ShutdownSignal,
    ) -> Self {
        Self {
            s,
            io,
            decoder: RequestDecoder::new(s.config.limits),
            buf: vec![0u8; s.config.read_buffer_size.max(1)],
            peer,
            cert,
            signal,
            requests: 0,
        }
    }

    /// Serves requests until the connection closes. Returns the number of
    /// requests answered.
    async fn run(mut self) -> u64 {
        let next = loop {
            match self.serve_one().await {
                Next::Continue => {}
                other => break other,
            }
        };
        match next {
            Next::Linger => self.linger_close().await,
            _ => {
                let _ = timeout(&self.s.rt, self.s.config.write_timeout, self.io.shutdown()).await;
            }
        }
        self.requests
    }

    /// Feeds one socket read into the decoder. `Ok(false)` means the
    /// deadline passed.
    ///
    /// The deadline is checked before every read. [`timeout`] polls the
    /// read first, so a read that is already ready would win over an
    /// expired timer, and a client that keeps sending would never time out.
    async fn fill(&mut self, deadline: Instant) -> Result<bool, ReadError> {
        if Instant::now() >= deadline {
            return Ok(false);
        }
        let read = timeout(&self.s.rt, remaining(deadline), self.io.read(&mut self.buf)).await;
        match read {
            Err(_) => Ok(false),
            Ok(Err(_)) => Err(ReadError::Io),
            Ok(Ok(0)) => {
                self.decoder.feed_eof();
                Ok(true)
            }
            Ok(Ok(n)) => {
                self.decoder.feed(self.buf.get(..n).unwrap_or_default());
                Ok(true)
            }
        }
    }

    async fn next_event(
        &mut self,
        deadline: Instant,
        phase: TimeoutPhase,
    ) -> Result<Option<RequestEvent>, ReadError> {
        loop {
            match self.decoder.next_event() {
                Ok(Some(ev)) => return Ok(Some(ev)),
                Ok(None) if self.decoder.is_finished() => return Ok(None),
                Ok(None) => {}
                Err(e) => return Err(ReadError::Parse(e)),
            }
            if !self.fill(deadline).await? {
                return Err(ReadError::Timeout(phase));
            }
        }
    }

    async fn write_all(&mut self, bytes: &[u8]) -> bool {
        let write = async {
            self.io.write_all(bytes).await?;
            self.io.flush().await
        };
        match timeout(&self.s.rt, self.s.config.write_timeout, write).await {
            Ok(Ok(())) => true,
            Ok(Err(_)) => false,
            Err(_) => {
                self.s.emit(ServerEvent::Timeout {
                    phase: TimeoutPhase::Write,
                });
                false
            }
        }
    }

    /// Answers a failed read. Returns what to do with the connection.
    async fn fail(&mut self, err: ReadError) -> Next {
        let resp = match err {
            ReadError::Io => return Next::Close,
            ReadError::Parse(e) => {
                let status = e.status();
                self.s.emit(ServerEvent::RequestRejected {
                    kind: e.kind(),
                    status,
                });
                if e.kind() == ParseErrorKind::UnexpectedEof {
                    // The client closed mid-request; nobody reads a reply.
                    return Next::Close;
                }
                Response::text(status, e.kind().description())
            }
            ReadError::Timeout(phase) => {
                self.s.emit(ServerEvent::Timeout { phase });
                Response::text(StatusCode::REQUEST_TIMEOUT, "request timeout")
            }
        };
        let resp = finalize(resp, false, Version::Http11);
        let mut out = Vec::new();
        if encode_response(&resp, false, &mut out).is_ok() && self.write_all(&out).await {
            Next::Linger
        } else {
            Next::Close
        }
    }

    async fn serve_one(&mut self) -> Next {
        let s = self.s;
        let cfg = &s.config;
        // Wait for the first byte of the next request.
        if self.decoder.is_idle() {
            if self.signal.is_triggered() {
                return Next::Close;
            }
            let wait = if self.requests == 0 {
                cfg.header_read_timeout
            } else {
                cfg.idle_timeout
            };
            let read = race(
                self.signal.notified(),
                timeout(&self.s.rt, wait, self.io.read(&mut self.buf)),
            )
            .await;
            match read {
                Either::Left(()) => return Next::Close,
                Either::Right(Err(_)) => {
                    self.s.emit(ServerEvent::Timeout {
                        phase: TimeoutPhase::Idle,
                    });
                    return Next::Close;
                }
                Either::Right(Ok(Err(_) | Ok(0))) => return Next::Close,
                Either::Right(Ok(Ok(n))) => {
                    self.decoder.feed(self.buf.get(..n).unwrap_or_default());
                }
            }
        }

        // Head.
        let head_deadline = deadline_after(cfg.header_read_timeout);
        let head = match self.next_event(head_deadline, TimeoutPhase::Header).await {
            Ok(Some(RequestEvent::Head(h))) => h,
            Ok(_) => return Next::Close,
            Err(e) => return self.fail(e).await,
        };

        // Body, after an interim 100 when the client waits for one.
        if head.expect_continue
            && head.body != BodyKind::Length(0)
            && self.decoder.buffered() == 0
            && !self.write_all(CONTINUE_RESPONSE).await
        {
            return Next::Close;
        }
        let body_deadline = deadline_after(cfg.body_read_timeout);
        let mut body = Vec::new();
        let trailers = loop {
            match self.next_event(body_deadline, TimeoutPhase::Body).await {
                Ok(Some(RequestEvent::Data(d))) => body.extend_from_slice(&d),
                Ok(Some(RequestEvent::End(t))) => break t,
                Ok(_) => return Next::Close,
                Err(e) => return self.fail(e).await,
            }
        };

        // Handler.
        let is_head = head.method == Method::HEAD;
        let label = method_label(&head.method);
        let keep_alive_req = head.keep_alive;
        let version = head.version;
        let mut req = Request::from_parts(*head, body, trailers);
        req.context.peer_addr = Some(self.peer);
        req.context.client_cert = self.cert.clone();
        let started = Instant::now();
        let resp = match CatchUnwind::new(self.s.handler.handle(req)).await {
            Ok(r) => r,
            Err(()) => {
                self.s.emit(ServerEvent::HandlerPanicked);
                Response::new(StatusCode::INTERNAL_SERVER_ERROR)
            }
        };

        // Response.
        self.requests = self.requests.saturating_add(1);
        let keep_alive = keep_alive_req
            && !resp.wants_close()
            && !resp.status.is_informational()
            && !self.signal.is_triggered()
            && self.requests < self.s.config.max_requests_per_connection;
        let resp = if resp.status.is_informational() {
            // A handler cannot send an interim response as the final one.
            Response::new(StatusCode::INTERNAL_SERVER_ERROR)
        } else {
            resp
        };
        let mut resp = finalize(resp, keep_alive, version);
        let mut out = Vec::new();
        let mut keep_alive = keep_alive;
        if let Err(error) = encode_response(&resp, is_head, &mut out) {
            self.s.emit(ServerEvent::SerializeFailed { error });
            keep_alive = false;
            resp = finalize(
                Response::new(StatusCode::INTERNAL_SERVER_ERROR),
                false,
                version,
            );
            out.clear();
            if encode_response(&resp, is_head, &mut out).is_err() {
                return Next::Close;
            }
        }
        if !self.write_all(&out).await {
            return Next::Close;
        }
        self.s.emit(ServerEvent::ResponseSent {
            method: label,
            status: resp.status,
            duration: started.elapsed(),
        });
        if keep_alive {
            Next::Continue
        } else {
            Next::Linger
        }
    }

    /// Closes the write direction, then reads and discards input for a
    /// bounded time, so the peer receives the response before the close.
    async fn linger_close(&mut self) {
        let s = self.s;
        let cfg = &s.config;
        let _ = timeout(&self.s.rt, cfg.write_timeout, self.io.shutdown()).await;
        let deadline = deadline_after(cfg.linger_timeout);
        let mut drained = 0usize;
        while drained < cfg.linger_max_bytes && Instant::now() < deadline {
            match timeout(&self.s.rt, remaining(deadline), self.io.read(&mut self.buf)).await {
                Ok(Ok(n)) if n > 0 => drained = drained.saturating_add(n),
                _ => break,
            }
        }
    }
}

/// Adds Date and the Connection option that matches `keep_alive`.
fn finalize(mut resp: Response, keep_alive: bool, version: Version) -> Response {
    resp.version = Version::Http11;
    if !resp.headers.contains("date")
        && let (Ok(n), Ok(v)) = (
            HeaderName::new("date"),
            HeaderValue::new(http_date(SystemTime::now())),
        )
    {
        resp.headers.append(n, v);
    }
    if !keep_alive {
        if !resp.wants_close()
            && let (Ok(n), Ok(v)) = (HeaderName::new("connection"), HeaderValue::new("close"))
        {
            resp.headers.insert(n, v);
        }
    } else if version == Version::Http10
        && let (Ok(n), Ok(v)) = (
            HeaderName::new("connection"),
            HeaderValue::new("keep-alive"),
        )
    {
        resp.headers.insert(n, v);
    }
    resp
}
