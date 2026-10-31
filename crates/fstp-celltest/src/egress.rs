//! The egress recorder: a test transport on `fstp_rt::duplex`, above TLS
//! (design section 14.3). Lane W1a.
//!
//! A component under test gets a [`Recorded`] stream where it would open a
//! connection. Every byte it writes or reads is recorded in plaintext,
//! with the [`Route`] (the source component and cell, the peer and the
//! peer's cell), the direction and a connection number. The recorder sits
//! above TLS, so the captures are what the component meant to send. The
//! I-16, I-19 and I-38 scans read them through [`EgressLog::store_set`] or
//! [`EgressLog::store_set_where`], which join each connection's bytes per
//! direction, so a canary split across two writes is still found.
//!
//! The route tells cell A's traffic to its own vault from cell A's
//! traffic to cell B's vault, and a vault's traffic to the witness from a
//! cell's. Store names carry it: `egress/<from>/<to>/<connection>/<dir>`,
//! for example `egress/cell-0/vault-0/1/out`.

use std::fmt;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll};

use fstp_rt::duplex::{DuplexStream, duplex};
use fstp_rt::{AsyncRead, AsyncWrite};

use crate::scan::StoreSet;

/// Where a capture went.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Peer {
    /// A vault.
    Vault,
    /// The control plane.
    ControlPlane,
    /// The witness.
    Witness,
    /// Custody.
    Custody,
    /// A CrabNebula host.
    CrabNebula,
}

impl Peer {
    /// Every peer.
    pub const ALL: [Peer; 5] = [
        Peer::Vault,
        Peer::ControlPlane,
        Peer::Witness,
        Peer::Custody,
        Peer::CrabNebula,
    ];

    /// A short lowercase label, used in store names.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Peer::Vault => "vault",
            Peer::ControlPlane => "control-plane",
            Peer::Witness => "witness",
            Peer::Custody => "custody",
            Peer::CrabNebula => "crabnebula",
        }
    }
}

/// The kind of component a capture leaves.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Component {
    /// A cell (`fstp-cell`).
    Cell,
    /// A cell's vault (`fstp-vault`).
    Vault,
    /// The control plane (`fstp-control`).
    ControlPlane,
    /// The witness (`fstp-witness`).
    Witness,
    /// The edge (`fstp-edge`).
    Edge,
    /// The backup runner (`fstp-backup`).
    Backup,
}

impl Component {
    /// A short lowercase label, used in store names.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Component::Cell => "cell",
            Component::Vault => "vault",
            Component::ControlPlane => "control-plane",
            Component::Witness => "witness",
            Component::Edge => "edge",
            Component::Backup => "backup",
        }
    }
}

/// The component a capture leaves, and its cell if it belongs to one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Endpoint {
    /// The component kind.
    pub component: Component,
    /// The cell index, or `None` for shared infrastructure.
    pub cell: Option<u8>,
}

impl Endpoint {
    /// Cell `i`.
    #[must_use]
    pub const fn cell(i: u8) -> Endpoint {
        Endpoint {
            component: Component::Cell,
            cell: Some(i),
        }
    }

    /// The vault of cell `i`.
    #[must_use]
    pub const fn vault(i: u8) -> Endpoint {
        Endpoint {
            component: Component::Vault,
            cell: Some(i),
        }
    }

    /// A component of the shared infrastructure, outside every cell.
    #[must_use]
    pub const fn shared(component: Component) -> Endpoint {
        Endpoint {
            component,
            cell: None,
        }
    }

    /// `<component>` or `<component>-<cell>`.
    #[must_use]
    pub fn label(&self) -> String {
        labelled(self.component.label(), self.cell)
    }
}

fn labelled(label: &str, cell: Option<u8>) -> String {
    match cell {
        Some(i) => format!("{label}-{i}"),
        None => label.to_owned(),
    }
}

/// The route of one recorded connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Route {
    /// The component that opened the connection.
    pub from: Endpoint,
    /// The peer it talks to.
    pub to: Peer,
    /// The peer's cell, or `None` for a peer outside every cell.
    pub to_cell: Option<u8>,
}

impl Route {
    /// The route from `from` to `to` in cell `to_cell`.
    #[must_use]
    pub const fn new(from: Endpoint, to: Peer, to_cell: Option<u8>) -> Route {
        Route { from, to, to_cell }
    }

    /// The peer's label: `<peer>` or `<peer>-<cell>`.
    #[must_use]
    pub fn to_label(&self) -> String {
        labelled(self.to.label(), self.to_cell)
    }

    /// Whether the route crosses from one cell into another cell.
    #[must_use]
    pub fn crosses_cells(&self) -> bool {
        matches!((self.from.cell, self.to_cell), (Some(a), Some(b)) if a != b)
    }
}

/// Which way the bytes went, seen from the recorded component.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Direction {
    /// Written by the component.
    Outbound,
    /// Read by the component.
    Inbound,
}

/// One plaintext capture: the bytes of one successful read or write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capture {
    /// The route of the connection.
    pub route: Route,
    /// The direction.
    pub direction: Direction,
    /// The connection, numbered from 1 in the order they were opened.
    pub connection: u64,
    /// The bytes.
    pub bytes: Vec<u8>,
}

/// Every capture of a world. Clones share one log.
#[derive(Clone, Default)]
pub struct EgressLog {
    inner: Arc<Shared>,
}

#[derive(Default)]
struct Shared {
    captures: Mutex<Vec<Capture>>,
    next_connection: AtomicU64,
}

impl fmt::Debug for EgressLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EgressLog")
            .field("captures", &self.lock().len())
            .finish_non_exhaustive()
    }
}

impl PartialEq for EgressLog {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner) || *self.lock() == *other.lock()
    }
}

impl Eq for EgressLog {}

impl EgressLog {
    /// An empty log.
    #[must_use]
    pub fn new() -> EgressLog {
        EgressLog::default()
    }

    fn lock(&self) -> MutexGuard<'_, Vec<Capture>> {
        self.inner
            .captures
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// The captures so far, in order.
    #[must_use]
    pub fn captures(&self) -> Vec<Capture> {
        self.lock().clone()
    }

    /// The peers that received at least one outbound byte.
    #[must_use]
    pub fn peers_contacted(&self) -> Vec<Peer> {
        let mut peers: Vec<Peer> = self
            .lock()
            .iter()
            .filter(|c| c.direction == Direction::Outbound && !c.bytes.is_empty())
            .map(|c| c.route.to)
            .collect();
        peers.sort();
        peers.dedup();
        peers
    }

    /// Records `bytes` for `route` on `connection`.
    pub fn record(&self, route: Route, direction: Direction, connection: u64, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        self.lock().push(Capture {
            route,
            direction,
            connection,
            bytes: bytes.to_vec(),
        });
    }

    /// Wraps `inner` so every byte through it is recorded for `route`.
    #[must_use]
    pub fn wrap<T>(&self, route: Route, inner: T) -> Recorded<T> {
        let connection = self
            .inner
            .next_connection
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        Recorded {
            inner,
            route,
            connection,
            log: self.clone(),
        }
    }

    /// A connected in-memory pair with `capacity` bytes of buffer per
    /// direction. The first end is the component's and is recorded for
    /// `route`. The second end is the peer's.
    #[must_use]
    pub fn connect(&self, route: Route, capacity: usize) -> (Recorded<DuplexStream>, DuplexStream) {
        let (component, remote) = duplex(capacity);
        (self.wrap(route, component), remote)
    }

    /// One store per connection and direction, named
    /// `egress/<from>/<to>/<connection>/<direction>`, holding the bytes in
    /// the order they passed.
    #[must_use]
    pub fn store_set(&self) -> StoreSet {
        self.store_set_where(|_| true)
    }

    /// As [`EgressLog::store_set`], for the connections whose route
    /// `keep` accepts. For example, `|r| r.from.cell == Some(0)` gives
    /// everything that left cell 0 or its vault.
    #[must_use]
    pub fn store_set_where(&self, keep: impl Fn(&Route) -> bool) -> StoreSet {
        let mut streams: Vec<((Route, u64, Direction), Vec<u8>)> = Vec::new();
        for c in self.lock().iter().filter(|c| keep(&c.route)) {
            let key = (c.route, c.connection, c.direction);
            if let Some((_, bytes)) = streams.iter_mut().find(|(k, _)| *k == key) {
                bytes.extend_from_slice(&c.bytes);
            } else {
                streams.push((key, c.bytes.clone()));
            }
        }
        let mut set = StoreSet::default();
        for ((route, connection, direction), bytes) in streams {
            let dir = match direction {
                Direction::Outbound => "out",
                Direction::Inbound => "in",
            };
            set.push(
                format!(
                    "egress/{}/{}/{connection}/{dir}",
                    route.from.label(),
                    route.to_label()
                ),
                bytes,
            );
        }
        set
    }
}

/// A stream whose reads and writes are recorded in an [`EgressLog`].
pub struct Recorded<T> {
    inner: T,
    route: Route,
    connection: u64,
    log: EgressLog,
}

impl<T> fmt::Debug for Recorded<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Recorded")
            .field("route", &self.route)
            .field("connection", &self.connection)
            .finish_non_exhaustive()
    }
}

impl<T> Recorded<T> {
    /// The peer this stream talks to.
    #[must_use]
    pub fn peer(&self) -> Peer {
        self.route.to
    }

    /// The route of this stream.
    #[must_use]
    pub fn route(&self) -> Route {
        self.route
    }

    /// The connection number in the log.
    #[must_use]
    pub fn connection(&self) -> u64 {
        self.connection
    }

    /// The wrapped stream.
    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for Recorded<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(n)) = &polled
            && let Some(read) = buf.get(..*n)
        {
            this.log
                .record(this.route, Direction::Inbound, this.connection, read);
        }
        polled
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Recorded<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &polled
            && let Some(written) = buf.get(..*n)
        {
            this.log
                .record(this.route, Direction::Outbound, this.connection, written);
        }
        polled
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
