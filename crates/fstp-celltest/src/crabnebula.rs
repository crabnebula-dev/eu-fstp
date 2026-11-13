//! The CrabNebula stand-in of a test world: the licence and update
//! services that a world cell reaches, run by the world (design sections
//! 10 and 14.3, I-38, I-39, lane m3/licence-update).
//!
//! Each world cell gets a stand-in of its own. It is a loopback TLS
//! listener with a server certificate for both service hosts
//! (`fstp_release::egress::LICENCE_HOST` and `UPDATE_HOST`) from a CA of
//! its own. The cell reaches it through a [`StandInTransport`], the
//! `fstp_cell::egress::CnTransport` the world hands the cell. The
//! transport runs the production exchange, `fstp_cell::egress::exchange_over`:
//! the TLS handshake with the service host as SNI and verified name, the
//! request, and the read of one answer. Only the root it trusts and the
//! address it dials are the world's.
//!
//! What the stand-in records in the world's [`EgressLog`], from the
//! cell's side, with the route cell to [`Peer::CrabNebula`]:
//!
//! - every plaintext chunk it reads, as [`Direction::Outbound`], and
//!   every chunk it writes, as [`Direction::Inbound`]. The recorder thus
//!   sits above TLS, as design section 14.3 asks;
//! - no handshake. The link is not mutually authenticated (design
//!   section 10.1), so R-NF-09 claims nothing about it;
//! - each connection attempt, as an [`Attempt`]: a refused dial by the
//!   transport, and a failed or completed handshake by the stand-in. An
//!   attempt that fails below TLS leaves no capture, so only this record
//!   shows that the cell made it (the `ATTEMPT_SEAM` of `i39_licence`).
//!
//! The services answer through the production service cores,
//! `fstp_release_svc::licence_response` and `update_response`, which
//! accept only the templates of `fstp_release::egress`. The stand-in
//! reads a request until one of the two service decoders accepts it, so
//! it holds no request parser of its own.
//!
//! The world sets a [`Mode`] per call: up, or down with one [`Fault`] of
//! design section 14.4 (T-LICENCE-OUTAGE). Readings of lane
//! m3/licence-update, Interim, pending Daniel:
//!
//! - `refused`: the transport dials a loopback port with no listener.
//! - `timed-out`: the stand-in reads the request and never answers.
//! - `failed-tls`: the stand-in presents a certificate from a CA the cell
//!   does not trust, so the handshake fails before any request byte.
//! - `garbage`: the answer is bytes that are not HTTP.
//! - `slow-body`: a correct answer whose body arrives a byte at a time.
//! - `expired-token`, `bad-signature`, `clock-skew`: a licence refresh is
//!   answered with a token past its `not_after`, signed by a key outside
//!   the pinned set, or issued 30 days ahead of the service clock. An
//!   update check is answered as when up.
//! - The update service serves synthetic metadata: the metadata magic,
//!   then zero bytes. No release signing key exists in M3, and the cell
//!   verifies no metadata before I-91 (design section 10.3).

use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use fstp_cell::egress::{CnFault, CnTransport};
use fstp_release::egress::Channel;
use fstp_release::licence::{Ed25519SigningKey, LicenceId, LicenceKind, VerifiedToken};
use fstp_release_svc::{
    HttpStatus, Issuer, LicenceRecord, LicenceRegistry, MetadataSource, TokenPolicy,
};
use fstp_rt::{AbortHandle, IoExt, Listener, Runtime};

use crate::egress::{Attempt, AttemptOutcome, Direction, EgressLog, Endpoint, Peer, Route};

/// One day in seconds.
const DAY_S: i64 = 86_400;

/// How long the stand-in waits for one handshake or one request.
const READ_TIMEOUT: Duration = Duration::from_secs(20);

/// How long a `timed-out` stand-in holds a connection open before it
/// closes it itself.
const HOLD_OPEN: Duration = Duration::from_secs(60);

/// The pause between two body bytes of a `slow-body` answer.
const SLOW_BYTE: Duration = Duration::from_millis(10);

/// How long one exchange of the transport may take, from the dial to the
/// last answer byte. As `fstp_cell::egress::SERVICE_TIMEOUT`.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(30);

/// The refresh interval and lifetime of the tokens the licence service
/// issues: refresh after 7 days, valid for 30.
const POLICY: (i64, i64) = (7 * DAY_S, 30 * DAY_S);

/// How a service fails (design section 14.4, module documentation).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Fault {
    /// The connection is refused.
    Refused,
    /// The request is read and never answered.
    TimedOut,
    /// The TLS handshake fails.
    FailedTls,
    /// The answer is not HTTP.
    Garbage,
    /// The answer's body arrives a byte at a time.
    SlowBody,
    /// The refresh answer holds an expired token.
    ExpiredToken,
    /// The refresh answer holds a token signed outside the pinned set.
    BadSignature,
    /// The refresh answer holds a token issued in the future.
    ClockSkew,
}

impl Fault {
    /// Every fault.
    pub const ALL: [Fault; 8] = [
        Fault::Refused,
        Fault::TimedOut,
        Fault::FailedTls,
        Fault::Garbage,
        Fault::SlowBody,
        Fault::ExpiredToken,
        Fault::BadSignature,
        Fault::ClockSkew,
    ];

    /// The label a cycle step names it by.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Fault::Refused => "refused",
            Fault::TimedOut => "timed-out",
            Fault::FailedTls => "failed-tls",
            Fault::Garbage => "garbage",
            Fault::SlowBody => "slow-body",
            Fault::ExpiredToken => "expired-token",
            Fault::BadSignature => "bad-signature",
            Fault::ClockSkew => "clock-skew",
        }
    }

    /// The fault labelled `label`.
    #[must_use]
    pub fn parse(label: &str) -> Option<Fault> {
        Fault::ALL.into_iter().find(|f| f.label() == label)
    }
}

/// How the services answer the next call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Both services answer through their production cores.
    Up,
    /// Both services fail with the fault.
    Down(Fault),
}

impl Mode {
    /// `up`, `success` (the W1g name of a refresh that succeeds) or a
    /// fault label.
    #[must_use]
    pub fn parse(label: &str) -> Option<Mode> {
        match label {
            "up" | "success" => Some(Mode::Up),
            other => Fault::parse(other).map(Mode::Down),
        }
    }
}

/// The time the services run on, in UTC microseconds: the clock of the
/// cell's release tasks, so tokens are issued at the instant the cell
/// checks them against.
pub type ServiceClock = Arc<dyn Fn() -> i64 + Send + Sync>;

/// What the stand-in and its transport share.
struct Shared {
    mode: Mutex<Mode>,
    /// The exchanges of the transport in flight.
    in_flight: std::sync::atomic::AtomicUsize,
    licence: LicenceId,
    key: Ed25519SigningKey,
    outsider: Ed25519SigningKey,
    clock: ServiceClock,
}

impl Shared {
    fn mode(&self) -> Mode {
        *self.mode.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn now_s(&self) -> i64 {
        (self.clock)().div_euclid(1_000_000)
    }
}

/// The licence of the stand-in's registry.
struct Registry(LicenceId);

impl LicenceRegistry for Registry {
    fn lookup(&self, licence: &LicenceId) -> Option<LicenceRecord> {
        (*licence == self.0).then_some(LicenceRecord {
            kind: LicenceKind::Noncommercial,
        })
    }
}

/// The synthetic release metadata (module documentation).
struct Metadata;

impl MetadataSource for Metadata {
    fn latest(&self, channel: Channel) -> Option<Vec<u8>> {
        let _ = channel;
        let mut m = fstp_release::metadata::METADATA_MAGIC.to_vec();
        m.resize(fstp_release::metadata::METADATA_LEN, 0);
        Some(m)
    }
}

/// What the world hands a stand-in at its start.
pub struct StandInParts {
    /// The cell the stand-in serves, as its captures name it.
    pub cell: u8,
    /// The server configuration with the certificate for both service
    /// hosts under the CA the transport trusts.
    pub server: fstp_tls::ServerConfig,
    /// A server configuration under a CA the transport does not trust
    /// (`failed-tls`).
    pub untrusted: fstp_tls::ServerConfig,
    /// The client configuration of the transport: the stand-in CA only.
    pub client: fstp_tls::ClientConfig,
    /// The licence of the cell.
    pub licence: LicenceId,
    /// The licence token key the cell pins.
    pub key: Ed25519SigningKey,
    /// The services' clock.
    pub clock: ServiceClock,
}

/// A running stand-in. Dropping it stops the listener and every
/// connection.
pub struct StandIn<R: Runtime> {
    rt: R,
    log: EgressLog,
    route: Route,
    addr: SocketAddr,
    closed: SocketAddr,
    client: fstp_tls::ClientConfig,
    shared: Arc<Shared>,
    tasks: Arc<Mutex<Vec<AbortHandle>>>,
}

impl<R: Runtime> std::fmt::Debug for StandIn<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StandIn")
            .field("addr", &self.addr)
            .field("mode", &self.shared.mode())
            .finish_non_exhaustive()
    }
}

impl<R: Runtime> Drop for StandIn<R> {
    fn drop(&mut self) {
        for t in lock(&self.tasks).drain(..) {
            t.abort();
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl<R: Runtime> StandIn<R> {
    /// The mode of the next calls.
    pub fn mode(&self) -> Mode {
        self.shared.mode()
    }

    /// How many exchanges of the transport are in flight.
    pub fn in_flight(&self) -> usize {
        self.shared
            .in_flight
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Sets the mode of the next calls.
    pub fn set_mode(&self, mode: Mode) {
        *lock(&self.shared.mode) = mode;
    }

    /// The licence token that the licence service issued for the cell at
    /// `now_s`, signed by the pinned key: the token a holder imports
    /// from the registration page (design section 10.2, Q41).
    ///
    /// # Errors
    ///
    /// The signing error, which a valid policy makes unexpected.
    pub fn first_token(&self, now_s: i64) -> Result<VerifiedToken, fstp_release::ReleaseError> {
        let t = VerifiedToken {
            licence: self.shared.licence,
            kind: LicenceKind::Noncommercial,
            issued_at: now_s,
            refresh_after: now_s.saturating_add(POLICY.0),
            not_after: now_s.saturating_add(POLICY.1),
        };
        fstp_release::licence::sign_token(&t, &self.shared.key)?;
        Ok(t)
    }

    /// The transport a cell reaches this stand-in through.
    #[must_use]
    pub fn transport(&self) -> StandInTransport<R> {
        StandInTransport {
            rt: self.rt.clone(),
            log: self.log.clone(),
            route: self.route,
            addr: self.addr,
            closed: self.closed,
            tls: self.client.clone(),
            shared: Arc::clone(&self.shared),
        }
    }
}

/// Starts a stand-in on a free loopback port, recording in `log`.
///
/// # Errors
///
/// Fails when a listener cannot bind.
pub async fn start<R: Runtime>(
    rt: R,
    log: EgressLog,
    parts: StandInParts,
) -> io::Result<StandIn<R>> {
    let loopback = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    // A port that had a listener and has none: a dial there is refused.
    let closed = {
        let probe = rt.bind_tcp(loopback).await?;
        probe.local_addr()?
    };
    let mut listener = rt.bind_tcp(loopback).await?;
    let addr = listener.local_addr()?;
    let shared = Arc::new(Shared {
        mode: Mutex::new(Mode::Up),
        in_flight: std::sync::atomic::AtomicUsize::new(0),
        licence: parts.licence,
        key: parts.key,
        outsider: Ed25519SigningKey::generate()
            .map_err(|_| io::Error::other("the outsider key"))?,
        clock: parts.clock,
    });
    let route = Route::new(Endpoint::cell(parts.cell), Peer::CrabNebula, None);
    let server = Arc::new(parts.server);
    let untrusted = Arc::new(parts.untrusted);
    let tasks: Arc<Mutex<Vec<AbortHandle>>> = Arc::new(Mutex::new(Vec::new()));
    let held = Arc::clone(&tasks);
    let inner_rt = rt.clone();
    let inner_shared = Arc::clone(&shared);
    let held_log = log.clone();
    let accept = rt.spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let mode = inner_shared.mode();
            let tls = match mode {
                Mode::Down(Fault::FailedTls) => Arc::clone(&untrusted),
                _ => Arc::clone(&server),
            };
            let conn = serve(
                inner_rt.clone(),
                held_log.clone(),
                route,
                tls,
                Arc::clone(&inner_shared),
                mode,
                tcp,
            );
            let handle = inner_rt.spawn(conn).abort_handle();
            let mut list = lock(&held);
            list.retain(|t| !t.is_finished());
            list.push(handle);
        }
    });
    lock(&tasks).push(accept.abort_handle());
    Ok(StandIn {
        rt,
        log,
        route,
        addr,
        closed,
        client: parts.client,
        shared,
        tasks,
    })
}

/// Which service a request reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Service {
    Licence,
    Update,
}

/// The service whose decoder accepts `request`, if one does.
fn service_of(request: &[u8]) -> Option<Service> {
    if fstp_release_svc::decode_refresh_request(request).is_ok() {
        Some(Service::Licence)
    } else if fstp_release_svc::decode_update_query(request).is_ok() {
        Some(Service::Update)
    } else {
        None
    }
}

/// One connection of the stand-in in `mode`.
async fn serve<R: Runtime>(
    rt: R,
    log: EgressLog,
    route: Route,
    tls: Arc<fstp_tls::ServerConfig>,
    shared: Arc<Shared>,
    mode: Mode,
    tcp: R::Tcp,
) {
    let accepted = fstp_rt::timeout(&rt, READ_TIMEOUT, fstp_tls::accept(&tls, tcp)).await;
    let Ok(Ok(mut stream)) = accepted else {
        log.record_attempt(Attempt {
            route,
            outcome: AttemptOutcome::HandshakeFailed,
        });
        return;
    };
    log.record_attempt(Attempt {
        route,
        outcome: AttemptOutcome::Connected,
    });
    let connection = log.open_connection();
    // The request, read until a service decoder accepts it.
    let mut request = Vec::new();
    let mut chunk = [0u8; 1024];
    let service = loop {
        let read = fstp_rt::timeout(&rt, READ_TIMEOUT, stream.read(&mut chunk)).await;
        let n = match read {
            Ok(Ok(n)) if n > 0 => n,
            _ => break None,
        };
        let Some(bytes) = chunk.get(..n) else {
            break None;
        };
        log.record(route, Direction::Outbound, connection, bytes);
        request.extend_from_slice(bytes);
        if let Some(s) = service_of(&request) {
            break Some(s);
        }
        if request.len() > fstp_release_svc::MAX_REQUEST_LEN {
            break None;
        }
    };
    let answer = match (mode, service) {
        (Mode::Down(Fault::TimedOut), _) => {
            // Never answers: the connection stays open until the cell
            // gives up and closes it, or the hold ends.
            let mut rest = Vec::new();
            let _ = fstp_rt::timeout(&rt, HOLD_OPEN, stream.read_to_end(&mut rest, 1 << 16)).await;
            return;
        }
        (Mode::Down(Fault::Garbage), _) => garbage(),
        (_, None) => fstp_release_svc::http_response(HttpStatus::BadRequest, &[]),
        (_, Some(Service::Update)) => fstp_release_svc::update_response(&request, &Metadata),
        (Mode::Up | Mode::Down(Fault::SlowBody), Some(Service::Licence)) => {
            licence_answer(&shared, &request, &shared.key, None)
        }
        (Mode::Down(Fault::ExpiredToken), Some(Service::Licence)) => {
            // Issued 60 days ago, so it expired 30 days ago.
            licence_answer(&shared, &request, &shared.key, Some(-60 * DAY_S))
        }
        (Mode::Down(Fault::BadSignature), Some(Service::Licence)) => {
            licence_answer(&shared, &request, &shared.outsider, None)
        }
        (Mode::Down(Fault::ClockSkew), Some(Service::Licence)) => {
            licence_answer(&shared, &request, &shared.key, Some(30 * DAY_S))
        }
        // The transport never dials the stand-in when refused, and a
        // failed handshake ends above.
        (Mode::Down(Fault::Refused | Fault::FailedTls), Some(_)) => {
            fstp_release_svc::http_response(HttpStatus::InternalServerError, &[])
        }
    };
    let slow = mode == Mode::Down(Fault::SlowBody);
    let _ = write_answer(&rt, &mut stream, &answer, slow, &log, route, connection).await;
    let _ = stream.shutdown().await;
}

/// The licence service's answer to `request`, with its tokens signed by
/// `key` and issued `shift` seconds from the service clock.
fn licence_answer(
    shared: &Shared,
    request: &[u8],
    key: &Ed25519SigningKey,
    shift: Option<i64>,
) -> Vec<u8> {
    let now = shared.now_s().saturating_add(shift.unwrap_or(0));
    let Ok(policy) = TokenPolicy::new(POLICY.0, POLICY.1) else {
        return fstp_release_svc::http_response(HttpStatus::InternalServerError, &[]);
    };
    let issuer = Issuer {
        key,
        policy,
        transition: None,
    };
    fstp_release_svc::licence_response(request, &Registry(shared.licence), &issuer, now)
}

/// Bytes that are not HTTP.
fn garbage() -> Vec<u8> {
    let mut g = vec![0u8; 64];
    if fstp_crypto::random_bytes(&mut g).is_err() {
        g.fill(0xA5);
    }
    // Never a status line, whatever the random bytes are.
    if let Some(first) = g.first_mut() {
        *first = 0;
    }
    g
}

/// Writes `answer`, recording each chunk as read by the cell. A `slow`
/// answer writes its head at once and its body a byte at a time.
async fn write_answer<R: Runtime, S: fstp_rt::Connection>(
    rt: &R,
    stream: &mut S,
    answer: &[u8],
    slow: bool,
    log: &EgressLog,
    route: Route,
    connection: u64,
) -> io::Result<()> {
    let head_len = answer
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(answer.len(), |p| p.saturating_add(4));
    let (head, body) = answer.split_at(head_len.min(answer.len()));
    stream.write_all(head).await?;
    stream.flush().await?;
    log.record(route, Direction::Inbound, connection, head);
    if slow {
        for b in body.chunks(1) {
            rt.sleep(SLOW_BYTE).await;
            stream.write_all(b).await?;
            stream.flush().await?;
            log.record(route, Direction::Inbound, connection, b);
        }
    } else {
        stream.write_all(body).await?;
        stream.flush().await?;
        log.record(route, Direction::Inbound, connection, body);
    }
    Ok(())
}

/// The `fstp_cell::egress::CnTransport` of a world cell: the production
/// exchange to the stand-in (module documentation).
#[derive(Clone)]
pub struct StandInTransport<R> {
    rt: R,
    log: EgressLog,
    route: Route,
    addr: SocketAddr,
    closed: SocketAddr,
    tls: fstp_tls::ClientConfig,
    shared: Arc<Shared>,
}

impl<R> std::fmt::Debug for StandInTransport<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StandInTransport")
            .field("addr", &self.addr)
            .finish_non_exhaustive()
    }
}

impl<R: Runtime> CnTransport for StandInTransport<R> {
    fn exchange(
        &self,
        host: &'static str,
        request: Vec<u8>,
    ) -> impl Future<Output = Result<Vec<u8>, CnFault>> + Send {
        let rt = self.rt.clone();
        let tls = self.tls.clone();
        let log = self.log.clone();
        let route = self.route;
        let addr = match self.shared.mode() {
            Mode::Down(Fault::Refused) => self.closed,
            _ => self.addr,
        };
        let shared = Arc::clone(&self.shared);
        async move {
            let _flight = InFlight::enter(shared);
            let run = async {
                let tcp = match rt.connect_tcp(addr).await {
                    Ok(t) => t,
                    Err(_) => {
                        log.record_attempt(Attempt {
                            route,
                            outcome: AttemptOutcome::Refused,
                        });
                        return Err(CnFault::Unreachable);
                    }
                };
                fstp_cell::egress::exchange_over(&tls, host, tcp, &request).await
            };
            fstp_rt::timeout(&rt, EXCHANGE_TIMEOUT, run)
                .await
                .map_err(|_| CnFault::Unreachable)?
        }
    }
}

/// One exchange in flight: counted from the transport's first poll to
/// its end or its drop, so a call the cell abandons counts no more.
struct InFlight(Arc<Shared>);

impl InFlight {
    fn enter(shared: Arc<Shared>) -> InFlight {
        shared
            .in_flight
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        InFlight(shared)
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0
            .in_flight
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}
