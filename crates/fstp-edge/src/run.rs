//! The pilot edge process (ADR-009 "Pilot edge configuration" and "Pilot
//! route feed", gap G12, D1). Lane L9 `prod/edgerun`, lane L15
//! `prod/route-feed`.
//!
//! [`run`] reads the configuration file that [`CONFIG_ENV`] names, the
//! tunnel credentials and the feed public keys by fixed name. It binds
//! the public listener on one tokio runtime through `fstp-rt` (ADR-002)
//! and serves until SIGTERM or SIGINT. It starts with its signed cache of
//! the last verified table, verified again, or with no route.
//! [`poll_routes`] polls the signed route feed of `fstp-control` and swaps
//! in each newer verified table with its pins, so routes change without a
//! restart. A refused or failed poll keeps the last verified table.
//!
//! Each client connection runs, in order:
//!
//! 1. the [`Gate`]: a connection over a limit closes before any read;
//! 2. [`read_hello`] under the hello deadline, which routes by SNI or
//!    closes. No SNI, an unknown host or a malformed hello opens no
//!    tunnel (I-19);
//! 3. [`forward`] under the connection lifetime. Its tunnel comes from
//!    [`PinnedTunnelOpener`]: mutual TLS to the routed endpoint, then the
//!    pin of the server's end-entity certificate in the table current at
//!    that moment, before any byte of the client leaves the edge.
//!
//! The edge passes the client's TLS through unchanged and holds no origin
//! key (B5). Logs are typed events only (R-NF-02).

use std::collections::HashMap;
use std::future::Future;
use std::io::{self, Read as _};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use fstp_rt::tokio::TokioRuntime;
use fstp_rt::{AsyncRead, AsyncWrite, Listener as _, Runtime, Shutdown, ShutdownSignal};
use fstp_tls::{ClientConfig, TlsStream};

use crate::config::{
    CACHE_FILE, ConfigError, FEED_KEYS_FILE, Limits, MAX_CONFIG_LEN, MAX_FEED_KEYS_LEN, Pins,
    decode_config, decode_feed_keys,
};
use crate::feed::{FeedError, FeedTransport, RouteFeed, TlsFeed};
use crate::route::{CellEndpoint, LiveRoutes, PinSource, RouteTable};
use crate::splice::{EdgeError, Spliced, TlsTunnelOpener, TunnelOpener, forward, read_hello};

/// The environment variable that names the configuration file.
pub const CONFIG_ENV: &str = "FSTP_EDGE_CONFIG";

/// How long open connections may run on after SIGTERM.
pub const DRAIN: Duration = Duration::from_secs(20);

/// The largest credential file read, in bytes.
pub const MAX_CREDENTIAL_LEN: usize = 64 * 1024;

/// The worker threads of the runtime.
const WORKERS: usize = 2;

/// How long the accept loop waits after a failed accept.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(50);

/// The tunnel opener of the pilot edge: mutual TLS to the endpoint with
/// the edge's tunnel certificate, under the open deadline, then the pin
/// of the server's end-entity certificate (ADR-009 "Pilot edge
/// configuration", row "Tunnel server pin").
pub struct PinnedTunnelOpener<R: Runtime, P: PinSource = Pins> {
    inner: TlsTunnelOpener<R>,
    rt: R,
    pins: P,
    open: Duration,
}

impl<R: Runtime, P: PinSource> PinnedTunnelOpener<R, P> {
    /// An opener over `rt` that authenticates with `config`, checks each
    /// endpoint's pin in `pins`, and gives up after `open`. With
    /// [`LiveRoutes`] as `pins`, the pin comes from the table that is
    /// current when the tunnel opens (lane L15).
    pub fn new(rt: R, config: ClientConfig, pins: P, open: Duration) -> Self {
        PinnedTunnelOpener {
            inner: TlsTunnelOpener::new(rt.clone(), config),
            rt,
            pins,
            open,
        }
    }
}

impl<R: Runtime, P: PinSource> TunnelOpener for PinnedTunnelOpener<R, P> {
    type Tunnel = TlsStream<R::Tcp>;

    /// Opens the tunnel, or refuses with `PermissionDenied` when the
    /// endpoint has no pin or its server's end-entity certificate does not
    /// match it, and with `TimedOut` after the open deadline. A refused
    /// tunnel is dropped before the tunnel header is written.
    async fn open(&self, endpoint: &CellEndpoint) -> io::Result<Self::Tunnel> {
        let denied = || io::Error::from(io::ErrorKind::PermissionDenied);
        let pin = self.pins.pin_now(endpoint).ok_or_else(denied)?;
        let tunnel = fstp_rt::timeout(&self.rt, self.open, self.inner.open(endpoint))
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        let leaf = tunnel.peer_end_entity_der().ok_or_else(denied)?;
        if fstp_crypto::sha256(leaf) != pin {
            return Err(denied());
        }
        Ok(tunnel)
    }
}

/// The open connections, in all and per client IP address. The address
/// lives in memory only and is never logged (Q19).
#[derive(Debug, Default)]
struct GateState {
    open: usize,
    per_client: HashMap<IpAddr, usize>,
}

/// Admits a connection while it stays within the connection limits.
#[derive(Clone, Debug)]
pub struct Gate {
    state: Arc<Mutex<GateState>>,
    connections: usize,
    per_client: usize,
}

/// One admitted connection. Dropping it frees its place.
#[derive(Debug)]
pub struct Permit {
    state: Arc<Mutex<GateState>>,
    ip: IpAddr,
}

impl Gate {
    /// A gate with the connection limits of `limits`.
    pub fn new(limits: &Limits) -> Gate {
        Gate {
            state: Arc::new(Mutex::new(GateState::default())),
            connections: limits.connections,
            per_client: limits.per_client,
        }
    }

    /// A permit for a connection from `ip`, or `None` when it would pass
    /// either limit. An IPv4-mapped IPv6 address counts as its IPv4
    /// address.
    pub fn admit(&self, ip: IpAddr) -> Option<Permit> {
        let ip = ip.to_canonical();
        let mut st = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let mine = st.per_client.get(&ip).copied().unwrap_or(0);
        if st.open >= self.connections || mine >= self.per_client {
            return None;
        }
        st.open = st.open.saturating_add(1);
        st.per_client.insert(ip, mine.saturating_add(1));
        Some(Permit {
            state: Arc::clone(&self.state),
            ip,
        })
    }

    /// The number of open connections.
    pub fn open(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .open
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        let mut st = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        st.open = st.open.saturating_sub(1);
        let left = st
            .per_client
            .get(&self.ip)
            .copied()
            .unwrap_or(0)
            .saturating_sub(1);
        if left == 0 {
            st.per_client.remove(&self.ip);
        } else {
            st.per_client.insert(self.ip, left);
        }
    }
}

/// Serves one client connection: routes it by SNI within the hello
/// deadline, then forwards it within the connection lifetime.
///
/// # Errors
///
/// An [`EdgeError`] when the connection closes before or during the
/// splice. A deadline that passes is [`EdgeError::Io`] with `TimedOut`.
pub async fn connection<R, C, O>(
    rt: &R,
    mut client: C,
    peer: SocketAddr,
    table: &RouteTable,
    opener: &O,
    limits: &Limits,
) -> Result<Spliced, EdgeError>
where
    R: Runtime,
    C: AsyncRead + AsyncWrite + Unpin,
    O: TunnelOpener,
{
    let timed_out = || EdgeError::Io(io::Error::from(io::ErrorKind::TimedOut));
    let routed = fstp_rt::timeout(rt, limits.hello, read_hello(&mut client, table))
        .await
        .map_err(|_| timed_out())??;
    fstp_rt::timeout(rt, limits.lifetime, forward(client, peer, routed, opener))
        .await
        .map_err(|_| timed_out())?
}

/// Accepts connections on `listener` until `stop` is triggered. Each
/// connection the [`Gate`] admits runs `handle` in a task of its own,
/// which holds its permit and a participant of `stop`, so a drain waits
/// for it. A connection the gate refuses closes at once.
pub async fn accept_loop<R, H, F>(
    rt: R,
    mut listener: R::TcpListener,
    gate: Gate,
    stop: ShutdownSignal,
    handle: H,
) where
    R: Runtime,
    H: Fn(R::Tcp, SocketAddr) -> F,
    F: Future<Output = ()> + Send + 'static,
{
    loop {
        let Some(accepted) = stop.run_until(listener.accept()).await else {
            break;
        };
        let Ok((conn, peer)) = accepted else {
            rt.sleep(ACCEPT_BACKOFF).await;
            continue;
        };
        let Some(permit) = gate.admit(peer.ip()) else {
            drop(conn);
            continue;
        };
        let task = handle(conn, peer);
        let held = stop.clone();
        drop(rt.spawn(async move {
            let _permit = permit;
            let _held = held;
            task.await;
        }));
    }
}

/// Reads `path`, at most `limit` bytes. A longer file is refused under
/// `rule`, and the error never quotes a byte.
fn read_bounded(path: &Path, limit: usize, rule: &'static str) -> Result<Vec<u8>, EdgeError> {
    let refused = || EdgeError::Config(ConfigError::Invalid(rule));
    let file = std::fs::File::open(path).map_err(|_| refused())?;
    let cap = u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1);
    let mut bytes = Vec::new();
    file.take(cap)
        .read_to_end(&mut bytes)
        .map_err(|_| refused())?;
    if bytes.len() > limit {
        return Err(refused());
    }
    Ok(bytes)
}

/// The tunnel client configuration from the credentials directory:
/// `tunnel.pem` and `tunnel.key`, the edge's chain and key, and
/// `tunnel-ca.pem`, the CA of the tunnel servers (ADR-009 "Pilot edge
/// configuration", row "Credentials").
///
/// # Errors
///
/// [`EdgeError::Config`] naming the file or the credential set, never
/// their bytes.
pub fn tunnel_client(dir: &Path) -> Result<ClientConfig, EdgeError> {
    let ca = read_bounded(
        &dir.join("tunnel-ca.pem"),
        MAX_CREDENTIAL_LEN,
        "tunnel-ca.pem",
    )?;
    let chain = read_bounded(&dir.join("tunnel.pem"), MAX_CREDENTIAL_LEN, "tunnel.pem")?;
    let mut key = read_bounded(&dir.join("tunnel.key"), MAX_CREDENTIAL_LEN, "tunnel.key")?;
    let config = ClientConfig::mutual(&ca, &chain, &key)
        .map_err(|_| EdgeError::Config(ConfigError::Invalid("tunnel credentials")));
    key.fill(0);
    std::hint::black_box(&key);
    config
}

/// What a pilot edge loads at start: its configuration, its tunnel client
/// configuration (also its client side of the route feed), and the feed
/// public keys it pins.
pub struct Loaded {
    /// The configuration.
    pub config: crate::config::EdgeConfig,
    /// The tunnel client configuration from the credentials directory.
    pub tls: ClientConfig,
    /// The pinned feed public keys ([`FEED_KEYS_FILE`]).
    pub feed_keys: Vec<Vec<u8>>,
}

/// The configuration file, the tunnel credentials and the feed keys,
/// decoded and checked (ADR-009 "Pilot route feed").
///
/// # Errors
///
/// [`EdgeError::Config`] for a missing or refused file.
pub fn load(config: &Path) -> Result<Loaded, EdgeError> {
    let cfg = decode_config(&read_bounded(config, MAX_CONFIG_LEN, "config file")?)
        .map_err(EdgeError::Config)?;
    let tls = tunnel_client(&cfg.credentials_dir)?;
    let feed_keys = decode_feed_keys(&read_bounded(
        &cfg.credentials_dir.join(FEED_KEYS_FILE),
        MAX_FEED_KEYS_LEN,
        FEED_KEYS_FILE,
    )?)
    .map_err(EdgeError::Config)?;
    Ok(Loaded {
        config: cfg,
        tls,
        feed_keys,
    })
}

/// The route template the edge logs its route feed under.
pub const FEED_ROUTE: &str = "/edge/route-feed";

/// How long one poll may take.
pub const POLL_TIMEOUT: Duration = Duration::from_secs(10);

/// Polls `feed` at once and then every `every` until `stop` is triggered
/// (ADR-009 "Pilot route feed", rows "Poll interval" and "Unreachable or
/// refused feed"). A refused or failed poll keeps the table the edge
/// serves. It logs `Request` when a newer table is applied, and `Refused`
/// with the rule when a poll's outcome turns into a refusal of another
/// rule. No event names a host or an address (R-NF-02).
pub async fn poll_routes<R, T>(rt: R, feed: RouteFeed<T>, every: Duration, stop: ShutdownSignal)
where
    R: Runtime,
    T: FeedTransport,
{
    let mut last_rule: Option<&'static str> = None;
    loop {
        let before = feed.routes().version();
        let begun = Instant::now();
        let Some(outcome) = stop
            .run_until(fstp_rt::timeout(&rt, POLL_TIMEOUT, feed.poll_once()))
            .await
        else {
            break;
        };
        let outcome = outcome.unwrap_or(Err(FeedError::Io(io::ErrorKind::TimedOut)));
        match outcome {
            Ok(version) => {
                last_rule = None;
                if version != before {
                    let _ = fstp_obs::log_to_stderr(&fstp_obs::LogEvent::Request {
                        method: fstp_obs::Method::Other,
                        route: FEED_ROUTE,
                        status: 200,
                        elapsed: begun.elapsed(),
                    });
                }
            }
            Err(e) => {
                let rule = e.rule();
                if last_rule != Some(rule) {
                    let _ = fstp_obs::log_to_stderr(&fstp_obs::LogEvent::Refused {
                        method: fstp_obs::Method::Other,
                        route: FEED_ROUTE,
                        rule,
                        status: 502,
                    });
                }
                last_rule = Some(rule);
            }
        }
        if stop.run_until(rt.sleep(every)).await.is_none() {
            break;
        }
    }
}

/// Runs the pilot edge named by the configuration file in [`CONFIG_ENV`]
/// until SIGTERM or SIGINT (module documentation). It starts with no
/// route and serves the routes of the signed route feed of `fstp-control`
/// as they change, without a restart (ADR-009 "Pilot route feed").
///
/// # Errors
///
/// [`EdgeError::Config`] for a missing or refused configuration, feed key
/// file or credential, and [`EdgeError::Start`] when the runtime, the
/// signal handler or the listener does not start.
pub fn run() -> Result<(), EdgeError> {
    use fstp_rt::signal::{SignalError, Signals as _, TerminationListener as _};
    let path = std::env::var_os(CONFIG_ENV).ok_or(EdgeError::Config(ConfigError::Missing))?;
    let Loaded {
        config: cfg,
        tls,
        feed_keys,
    } = load(Path::new(&path))?;
    let rt = TokioRuntime::new_multi_thread(WORKERS).map_err(|e| EdgeError::Start(e.kind()))?;
    // Registered before the bind, so a SIGTERM during the start is queued.
    let mut term = rt
        .listen_termination()
        .map_err(|SignalError::Io(kind)| EdgeError::Start(kind))?;
    let task_rt = rt.clone();
    rt.block_on(async move {
        let listener = task_rt
            .bind_tcp(cfg.listen)
            .await
            .map_err(|e| EdgeError::Start(e.kind()))?;
        let limits = cfg.limits;
        let live = LiveRoutes::default();
        let feed = RouteFeed::new(
            TlsFeed::new(
                task_rt.clone(),
                cfg.feed.address,
                &cfg.feed.server_name,
                tls.clone(),
            )
            .with_pins(cfg.feed.cert_sha256.clone()),
            feed_keys,
            live.clone(),
        )
        .with_cache(cfg.state_dir.join(CACHE_FILE));
        // The signed cache, verified again, serves until the feed answers
        // (ADR-009 "Pilot route feed", row "Signed cache").
        if let Err(e) = feed.load_cache() {
            let _ = fstp_obs::log_to_stderr(&fstp_obs::LogEvent::Refused {
                method: fstp_obs::Method::Other,
                route: FEED_ROUTE,
                rule: e.rule(),
                status: 502,
            });
        }
        let opener = Arc::new(PinnedTunnelOpener::new(
            task_rt.clone(),
            tls,
            live.clone(),
            limits.open,
        ));
        let conn_rt = task_rt.clone();
        let handle = move |client, peer| {
            let rt = conn_rt.clone();
            // The table current when the connection arrives (TH-48).
            let table = live.current();
            let opener = Arc::clone(&opener);
            async move {
                // A closed connection is the whole answer: the edge logs
                // no host and no address per connection (R-NF-02).
                let _ = connection(&rt, client, peer, &table, &*opener, &limits).await;
            }
        };
        let shutdown = Shutdown::new();
        drop(task_rt.spawn(poll_routes(
            task_rt.clone(),
            feed,
            cfg.feed.poll,
            shutdown.signal(),
        )));
        drop(task_rt.spawn(accept_loop(
            task_rt.clone(),
            listener,
            Gate::new(&limits),
            shutdown.signal(),
            handle,
        )));
        let _ = fstp_obs::log_to_stderr(&fstp_obs::LogEvent::Started);
        let _ = term.recv().await;
        let _ = fstp_obs::log_to_stderr(&fstp_obs::LogEvent::ShuttingDown);
        let begun = Instant::now();
        let event = match shutdown.shutdown(&task_rt, DRAIN).await {
            Ok(()) => fstp_obs::LogEvent::Drained {
                elapsed: begun.elapsed(),
            },
            Err(t) => fstp_obs::LogEvent::DrainTimedOut {
                remaining: u64::try_from(t.remaining).unwrap_or(u64::MAX),
            },
        };
        let _ = fstp_obs::log_to_stderr(&event);
        Ok(())
    })
}
