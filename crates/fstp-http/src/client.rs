//! HTTP/1.1 client driver over any [`fstp_rt::Runtime`].
//!
//! - Plain TCP for `http` URLs and TLS for `https` URLs. TLS verifies the
//!   server's chain and name (verify-full) and presents a client certificate
//!   when the TLS configuration holds one (mutual TLS, R-NF-09).
//! - Idle connections are kept per scheme, host and port and reused for
//!   later requests. A request on a reused connection that the server had
//!   already closed is retried once on a new connection, for idempotent
//!   methods only.
//! - The pool is capped per authority and in total. Expired connections
//!   on every authority are closed at each pool operation.
//! - Deadlines for connecting (TCP and TLS), writing the request, and
//!   reading the whole response.
//! - Response heads and bodies are bounded by [`Limits`].
//! - Redirects are returned to the caller, never followed.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use fstp_rt::{AsyncRead, Connection, IoExt, Runtime, timeout};

use crate::decode::{ResponseDecoder, ResponseEvent};
use crate::encode::{Framing, SerializeError, encode_request};
use crate::error::{ParseError, ParseErrorKind};
use crate::header::{HeaderName, HeaderValue};
use crate::io::{MaybeTls, deadline_after, remaining};
use crate::limits::Limits;
use crate::message::{Request, Response, ResponseHead};
use crate::method::Method;
use crate::target::Scheme;

/// Client settings.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Parser limits for responses.
    pub limits: Limits,
    /// TLS settings for `https` URLs. Build it with
    /// [`fstp_tls::ClientConfig::mutual`] to present a client certificate.
    pub tls: Option<fstp_tls::ClientConfig>,
    /// Deadline for name resolution, the TCP connect and the TLS handshake
    /// together.
    pub connect_timeout: Duration,
    /// Deadline for writing the request.
    pub request_timeout: Duration,
    /// Deadline for reading the whole response, from the end of the write.
    pub response_timeout: Duration,
    /// How long an idle connection stays in the pool.
    ///
    /// Expired connections on every authority are closed whenever a request
    /// takes a connection from the pool or returns one, and whenever
    /// [`Client::idle_connections`] counts them.
    pub idle_timeout: Duration,
    /// Most idle connections kept per scheme, host and port.
    pub max_idle_per_authority: usize,
    /// Most idle connections kept over all authorities together. Zero
    /// disables connection reuse.
    pub max_idle_total: usize,
    /// Most interim (1xx) responses skipped before the final one.
    pub max_interim_responses: usize,
    /// Size of each socket read, in bytes.
    pub read_buffer_size: usize,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            limits: Limits {
                max_body_bytes: 8 * 1024 * 1024,
                max_chunk_size: 8 * 1024 * 1024,
                ..Limits::default()
            },
            tls: None,
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(30),
            response_timeout: Duration::from_secs(60),
            idle_timeout: Duration::from_secs(30),
            max_idle_per_authority: 8,
            max_idle_total: 256,
            max_interim_responses: 8,
            read_buffer_size: 16 * 1024,
        }
    }
}

/// The step during which a client deadline passed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClientPhase {
    /// Resolving, connecting or the TLS handshake.
    Connect,
    /// Writing the request.
    Request,
    /// Reading the response.
    Response,
}

/// Why a request failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum ClientError {
    /// The request cannot be sent, for example because its target is not
    /// an absolute URL.
    InvalidRequest(&'static str),
    /// An `https` URL was requested without a TLS configuration.
    TlsNotConfigured,
    /// Name resolution failed.
    Resolve(io::Error),
    /// Every TCP connection attempt failed.
    Connect(io::Error),
    /// The TLS handshake failed. The inner error wraps an
    /// [`fstp_tls::TlsError`].
    Tls(io::Error),
    /// A deadline passed.
    Timeout(ClientPhase),
    /// Reading or writing failed.
    Io(io::Error),
    /// The response violated the grammar, a framing rule or a limit.
    Protocol(ParseError),
    /// The request could not be serialized.
    Serialize(SerializeError),
    /// More interim responses arrived than the limit allows.
    TooManyInterimResponses,
    /// The connection closed before a complete response arrived.
    ConnectionClosed,
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientError::InvalidRequest(why) => write!(f, "invalid request: {why}"),
            ClientError::TlsNotConfigured => f.write_str("https URL without a TLS configuration"),
            ClientError::Resolve(e) => write!(f, "name resolution failed: {e}"),
            ClientError::Connect(e) => write!(f, "connect failed: {e}"),
            ClientError::Tls(e) => write!(f, "TLS handshake failed: {e}"),
            ClientError::Timeout(p) => write!(f, "deadline passed during {p:?}"),
            ClientError::Io(e) => write!(f, "transport error: {e}"),
            ClientError::Protocol(e) => write!(f, "invalid response: {e}"),
            ClientError::Serialize(e) => write!(f, "{e}"),
            ClientError::TooManyInterimResponses => f.write_str("too many interim responses"),
            ClientError::ConnectionClosed => f.write_str("connection closed before the response"),
        }
    }
}

impl std::error::Error for ClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ClientError::Resolve(e)
            | ClientError::Connect(e)
            | ClientError::Tls(e)
            | ClientError::Io(e) => Some(e),
            ClientError::Protocol(e) => Some(e),
            ClientError::Serialize(e) => Some(e),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PoolKey {
    scheme: Scheme,
    host: String,
    port: u16,
}

struct ClientConn<S> {
    io: MaybeTls<S>,
    decoder: ResponseDecoder,
}

struct Idle<S> {
    conn: ClientConn<S>,
    since: Instant,
}

type Pool<S> = HashMap<PoolKey, Vec<Idle<S>>>;

/// Closes idle connections older than `idle_timeout` on every authority
/// and removes empty lists. Returns the number of idle connections left.
fn prune<S>(pool: &mut Pool<S>, idle_timeout: Duration) -> usize {
    let mut left = 0usize;
    pool.retain(|_, list| {
        list.retain(|i| i.since.elapsed() < idle_timeout);
        left = left.saturating_add(list.len());
        !list.is_empty()
    });
    left
}

struct Inner<R: Runtime> {
    rt: R,
    config: ClientConfig,
    pool: Mutex<Pool<R::Tcp>>,
    opened: AtomicU64,
}

/// An HTTP/1.1 client. Cheap to clone; clones share one connection pool.
///
/// - Plain TCP for `http` URLs and TLS for `https` URLs. TLS verifies the
///   server's chain and name (verify-full) and presents a client certificate
///   when the TLS configuration holds one (mutual TLS, R-NF-09).
/// - Idle connections are kept per scheme, host and port and reused for
///   later requests. A request on a reused connection that the server had
///   already closed is retried once on a new connection, for idempotent
///   methods only.
/// - The pool is capped per authority and in total. Expired connections
///   on every authority are closed at each pool operation.
/// - Deadlines for connecting (TCP and TLS), writing the request, and
///   reading the whole response.
/// - Response heads and bodies are bounded by [`Limits`].
/// - Redirects are returned to the caller, never followed.
pub struct Client<R: Runtime> {
    inner: Arc<Inner<R>>,
}

impl<R: Runtime> Clone for Client<R> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<R: Runtime> fmt::Debug for Client<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("config", &self.inner.config)
            .field("idle", &self.idle_connections())
            .finish_non_exhaustive()
    }
}

/// An exchange failure, with whether a retry on a new connection is safe.
struct ExchangeError {
    error: ClientError,
    /// The server closed the connection before sending any response byte.
    closed_early: bool,
}

impl From<ClientError> for ExchangeError {
    fn from(error: ClientError) -> Self {
        ExchangeError {
            error,
            closed_early: false,
        }
    }
}

/// Longest wait for a response that the server sent before it closed the
/// connection on a request still being written.
const EARLY_RESPONSE_WAIT: Duration = Duration::from_secs(1);

fn is_closed_kind(kind: io::ErrorKind) -> bool {
    matches!(
        kind,
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::UnexpectedEof
    )
}

impl<R: Runtime> Client<R> {
    /// A client that runs on `rt`.
    pub fn new(rt: R, config: ClientConfig) -> Client<R> {
        Client {
            inner: Arc::new(Inner {
                rt,
                config,
                pool: Mutex::new(HashMap::new()),
                opened: AtomicU64::new(0),
            }),
        }
    }

    /// Number of connections opened so far.
    #[must_use]
    pub fn connections_opened(&self) -> u64 {
        self.inner.opened.load(Ordering::Relaxed)
    }

    /// Number of idle connections in the pool. Counting first closes every
    /// connection that stayed idle longer than
    /// [`ClientConfig::idle_timeout`].
    #[must_use]
    pub fn idle_connections(&self) -> usize {
        prune(&mut self.lock_pool(), self.inner.config.idle_timeout)
    }

    fn lock_pool(&self) -> MutexGuard<'_, Pool<R::Tcp>> {
        self.inner
            .pool
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Sends a GET request for an absolute URL.
    ///
    /// # Errors
    ///
    /// See [`Client::send`].
    pub async fn get(&self, url: &str) -> Result<Response, ClientError> {
        let req = Request::get(url).map_err(|e| ClientError::InvalidRequest(e.description()))?;
        self.send(req).await
    }

    /// Sends `req` and returns the final response.
    ///
    /// The target must be an absolute `http` or `https` URL. The request
    /// line uses its origin form, and a Host field is derived from it unless
    /// `req` sets one. Redirect responses are returned as they are.
    ///
    /// # Errors
    ///
    /// Returns a [`ClientError`] for an invalid request, a connection or
    /// TLS failure, a deadline, or an invalid or oversized response.
    pub async fn send(&self, req: Request) -> Result<Response, ClientError> {
        let scheme = req.target.scheme().ok_or(ClientError::InvalidRequest(
            "target must be an absolute http or https URL",
        ))?;
        let authority = req
            .target
            .authority()
            .cloned()
            .ok_or(ClientError::InvalidRequest("target has no authority"))?;
        if scheme == Scheme::Https && self.inner.config.tls.is_none() {
            return Err(ClientError::TlsNotConfigured);
        }
        let key = PoolKey {
            scheme,
            host: authority.host_for_connect().to_ascii_lowercase(),
            port: authority.port().unwrap_or(scheme.default_port()),
        };
        let mut wire = req;
        if !wire.headers.contains("host") {
            let name =
                HeaderName::new("host").map_err(|_| ClientError::InvalidRequest("host header"))?;
            let value = HeaderValue::new(authority.as_str())
                .map_err(|_| ClientError::InvalidRequest("authority is not a valid Host"))?;
            wire.headers.append(name, value);
        }
        wire.target = wire.target.to_origin_form();
        let close_requested = wire.headers.has_token("connection", "close");
        let mut bytes = Vec::new();
        encode_request(&wire, Framing::ContentLength, &mut bytes)
            .map_err(ClientError::Serialize)?;
        let method = wire.method.clone();

        let mut attempt = 0u8;
        loop {
            let pooled = if attempt == 0 {
                self.take_idle(&key)
            } else {
                None
            };
            let reused = pooled.is_some();
            let mut conn = match pooled {
                Some(c) => c,
                None => self.connect(&key).await?,
            };
            match self.exchange(&mut conn, &bytes, &method).await {
                Ok((resp, reusable)) => {
                    if reusable && !close_requested {
                        self.put_idle(key, conn);
                    }
                    return Ok(resp);
                }
                Err(e) if reused && e.closed_early && method.is_idempotent() && attempt == 0 => {
                    attempt = 1;
                }
                Err(e) => return Err(e.error),
            }
        }
    }

    fn take_idle(&self, key: &PoolKey) -> Option<ClientConn<R::Tcp>> {
        let mut pool = self.lock_pool();
        prune(&mut pool, self.inner.config.idle_timeout);
        let list = pool.get_mut(key)?;
        let mut found = None;
        while let Some(mut idle) = list.pop() {
            if !is_stale(&mut idle.conn) {
                found = Some(idle.conn);
                break;
            }
        }
        if list.is_empty() {
            pool.remove(key);
        }
        found
    }

    /// Pools `conn` for reuse, or closes it when a cap is reached.
    fn put_idle(&self, key: PoolKey, conn: ClientConn<R::Tcp>) {
        let cfg = &self.inner.config;
        let mut pool = self.lock_pool();
        let total = prune(&mut pool, cfg.idle_timeout);
        let for_key = pool.get(&key).map_or(0, Vec::len);
        if total < cfg.max_idle_total && for_key < cfg.max_idle_per_authority {
            pool.entry(key).or_default().push(Idle {
                conn,
                since: Instant::now(),
            });
        }
    }

    async fn connect(&self, key: &PoolKey) -> Result<ClientConn<R::Tcp>, ClientError> {
        let inner = &self.inner;
        let cfg = &inner.config;
        let deadline = deadline_after(cfg.connect_timeout);
        let addrs = timeout(
            &inner.rt,
            remaining(deadline),
            inner.rt.resolve(&key.host, key.port),
        )
        .await
        .map_err(|_| ClientError::Timeout(ClientPhase::Connect))?
        .map_err(ClientError::Resolve)?;
        let mut last_err = None;
        let mut tcp = None;
        for addr in addrs {
            match timeout(&inner.rt, remaining(deadline), inner.rt.connect_tcp(addr)).await {
                Ok(Ok(s)) => {
                    tcp = Some(s);
                    break;
                }
                Ok(Err(e)) => last_err = Some(e),
                Err(_) => return Err(ClientError::Timeout(ClientPhase::Connect)),
            }
        }
        let tcp = tcp.ok_or_else(|| {
            ClientError::Connect(
                last_err.unwrap_or_else(|| io::Error::other("no address to connect to")),
            )
        })?;
        let io = match key.scheme {
            Scheme::Http => MaybeTls::Plain(tcp),
            Scheme::Https => {
                let tls = cfg.tls.as_ref().ok_or(ClientError::TlsNotConfigured)?;
                let stream = timeout(
                    &inner.rt,
                    remaining(deadline),
                    fstp_tls::connect(tls, &key.host, tcp),
                )
                .await
                .map_err(|_| ClientError::Timeout(ClientPhase::Connect))?
                .map_err(ClientError::Tls)?;
                MaybeTls::Tls(Box::new(stream))
            }
        };
        inner.opened.fetch_add(1, Ordering::Relaxed);
        Ok(ClientConn {
            io,
            decoder: ResponseDecoder::new(cfg.limits),
        })
    }

    async fn exchange<S: Connection>(
        &self,
        conn: &mut ClientConn<S>,
        bytes: &[u8],
        method: &Method,
    ) -> Result<(Response, bool), ExchangeError> {
        let inner = &self.inner;
        let cfg = &inner.config;
        let write = async {
            conn.io.write_all(bytes).await?;
            conn.io.flush().await
        };
        match timeout(&inner.rt, cfg.request_timeout, write).await {
            Err(_) => return Err(ClientError::Timeout(ClientPhase::Request).into()),
            Ok(Err(e)) if is_closed_kind(e.kind()) => {
                // The server may have answered before the request was fully
                // written, for example with 413, and closed the connection.
                // That response is likely already in the receive buffer.
                let wait = deadline_after(cfg.response_timeout.min(EARLY_RESPONSE_WAIT));
                return match self.read_response(conn, method, wait).await {
                    Ok((resp, _)) => Ok((resp, false)),
                    Err(early) => Err(ExchangeError {
                        closed_early: early.closed_early,
                        error: ClientError::Io(e),
                    }),
                };
            }
            Ok(Err(e)) => return Err(ClientError::Io(e).into()),
            Ok(Ok(())) => {}
        }
        let deadline = deadline_after(cfg.response_timeout);
        self.read_response(conn, method, deadline).await
    }

    /// Reads the final response to `method` until `deadline`. The flag is
    /// true when the connection can carry another request.
    async fn read_response<S: Connection>(
        &self,
        conn: &mut ClientConn<S>,
        method: &Method,
        deadline: Instant,
    ) -> Result<(Response, bool), ExchangeError> {
        let inner = &self.inner;
        let cfg = &inner.config;
        conn.decoder.expect_response_to(method.clone());
        let mut buf = vec![0u8; cfg.read_buffer_size.max(1)];
        let mut received_any = false;
        let mut eof = false;
        let mut interim = 0usize;
        let mut head: Option<Box<ResponseHead>> = None;
        let mut body = Vec::new();
        loop {
            match conn.decoder.next_event() {
                Err(e) => {
                    let closed_early = !received_any && e.kind() == ParseErrorKind::UnexpectedEof;
                    let error = if closed_early {
                        ClientError::ConnectionClosed
                    } else {
                        ClientError::Protocol(e)
                    };
                    return Err(ExchangeError {
                        error,
                        closed_early,
                    });
                }
                Ok(Some(ResponseEvent::Head(h))) => {
                    if h.status.is_informational() {
                        interim = interim.saturating_add(1);
                        if interim > cfg.max_interim_responses {
                            return Err(ClientError::TooManyInterimResponses.into());
                        }
                    }
                    head = Some(h);
                }
                Ok(Some(ResponseEvent::Data(d))) => body.extend_from_slice(&d),
                Ok(Some(ResponseEvent::End(trailers))) => {
                    let Some(h) = head.take() else {
                        return Err(ClientError::ConnectionClosed.into());
                    };
                    if h.status.is_informational() {
                        conn.decoder.expect_response_to(method.clone());
                        continue;
                    }
                    let reusable = h.keep_alive && !eof && conn.decoder.is_idle();
                    return Ok((Response::from_parts(*h, body, trailers), reusable));
                }
                Ok(None) if eof => {
                    return Err(ExchangeError {
                        error: ClientError::ConnectionClosed,
                        closed_early: !received_any,
                    });
                }
                Ok(None) => {
                    // Checked before every read: `timeout` lets a read that
                    // is already ready win over an expired timer, so a
                    // server that keeps sending would never time out.
                    if Instant::now() >= deadline {
                        return Err(ClientError::Timeout(ClientPhase::Response).into());
                    }
                    let read =
                        timeout(&inner.rt, remaining(deadline), conn.io.read(&mut buf)).await;
                    match read {
                        Err(_) => return Err(ClientError::Timeout(ClientPhase::Response).into()),
                        Ok(Err(e)) => {
                            return Err(ExchangeError {
                                closed_early: !received_any && is_closed_kind(e.kind()),
                                error: ClientError::Io(e),
                            });
                        }
                        Ok(Ok(0)) => {
                            eof = true;
                            conn.decoder.feed_eof();
                        }
                        Ok(Ok(n)) => {
                            received_any = true;
                            conn.decoder.feed(buf.get(..n).unwrap_or_default());
                        }
                    }
                }
            }
        }
    }
}

/// True when an idle connection has data or an end of stream pending,
/// which means the server closed it or sent something unexpected.
fn is_stale<S: Connection>(conn: &mut ClientConn<S>) -> bool {
    let mut cx = Context::from_waker(Waker::noop());
    let mut probe = [0u8; 1];
    !matches!(
        Pin::new(&mut conn.io).poll_read(&mut cx, &mut probe),
        Poll::Pending
    )
}
