//! The signed, versioned route table that each remote `fstp-edge` polls
//! (design section 3.7 step 3, ADR-004 "Decided by Daniel, 2026-11-15
//! (late)"). Lane m3/erase-prod.
//!
//! [`RoutePublisher`] holds the routes of every cell and a version that
//! rises with each change. It signs each version with the control-plane
//! composite key under `fstp_edge::ROUTE_TABLE_CONTEXT`, and answers each
//! edge's poll with the signed table ([`RoutePublisher::answer_poll`]).
//! Each poll reports the version the edge serves, which the publisher
//! keeps per edge.
//!
//! [`RemoteEdges`] is the erasure's [`EdgeRoutes`] for remote edges. It
//! removes the cell's routes, which publishes a new version, then waits
//! until every edge the control plane expects reports that version or a
//! newer one. Only then does step 3 finish. The in-process path through
//! `fstp_edge::LiveRoutes` stays for the test world.
//!
//! Interim, pending Daniel: an edge is named by the one subject CN of its
//! client certificate, `edge_<32 hex digits>` ([`EDGE_CN_PREFIX`]), as
//! cells are named on `CellToCp`. The set of edges is configured, not
//! discovered. The wait gives up after a configured time and fails the
//! erasure there, with no confirmation, as any failed step does.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use fstp_cp_proto::CellId;
use fstp_crypto::composite::CompositeSigningKey;
use fstp_edge::{
    ROUTE_TABLE_CONTEXT, RouteEntry, decode_poll, encode_route_table_body,
    encode_signed_route_table,
};
use fstp_rt::Runtime;

use crate::ControlError;
use crate::erase::EdgeRoutes;

/// The prefix of the subject CN of an edge's client certificate. The 32
/// lowercase hex digits of the edge id follow. Interim, pending Daniel.
pub const EDGE_CN_PREFIX: &str = "edge_";

/// How often [`RemoteEdges`] looks at the edges' reports while it waits.
pub const REPORT_CHECK: Duration = Duration::from_millis(50);

/// The id of one edge.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EdgeId(pub [u8; 16]);

impl EdgeId {
    /// The edge id the certificate `cert_der` names in its one subject CN,
    /// `edge_<32 hex digits>`, or `None`.
    pub fn of_peer(cert_der: &[u8]) -> Option<EdgeId> {
        let names = crate::exchange::peer_common_names(cert_der)?;
        let [cn] = names.as_slice() else {
            return None;
        };
        let hex = cn.strip_prefix(EDGE_CN_PREFIX)?;
        if hex.len() != 32 {
            return None;
        }
        let mut id = [0u8; 16];
        for (i, out) in id.iter_mut().enumerate() {
            let pair = hex.get(i.saturating_mul(2)..i.saturating_mul(2).saturating_add(2))?;
            if !pair
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return None;
            }
            *out = u8::from_str_radix(pair, 16).ok()?;
        }
        Some(EdgeId(id))
    }
}

struct State {
    version: u64,
    routes: BTreeMap<[u8; 16], RouteEntry>,
    signed: Vec<u8>,
    reported: BTreeMap<EdgeId, u64>,
}

/// The route table the control plane publishes, and what each edge
/// reported (module documentation).
pub struct RoutePublisher {
    signer: CompositeSigningKey,
    edges: Vec<EdgeId>,
    state: Mutex<State>,
}

impl std::fmt::Debug for RoutePublisher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoutePublisher")
            .field("edges", &self.edges.len())
            .finish_non_exhaustive()
    }
}

fn sign(
    signer: &CompositeSigningKey,
    version: u64,
    routes: &BTreeMap<[u8; 16], RouteEntry>,
) -> Result<Vec<u8>, ControlError> {
    let list: Vec<RouteEntry> = routes.values().cloned().collect();
    let body =
        encode_route_table_body(version, &list).map_err(|_| ControlError::Job("route table"))?;
    let signature = signer
        .sign_with_context(&body, ROUTE_TABLE_CONTEXT)
        .map_err(|_| ControlError::Job("the route table signature"))?;
    encode_signed_route_table(&body, &signature.to_bytes())
        .map_err(|_| ControlError::Job("route table"))
}

impl RoutePublisher {
    /// A publisher of an empty table, version 1, signed by the
    /// control-plane key `signer`, for the edges `edges`.
    ///
    /// # Errors
    ///
    /// [`ControlError::Job`] when the table cannot be signed.
    pub fn new(
        signer: CompositeSigningKey,
        edges: &[EdgeId],
    ) -> Result<RoutePublisher, ControlError> {
        let routes = BTreeMap::new();
        let signed = sign(&signer, 1, &routes)?;
        Ok(RoutePublisher {
            signer,
            edges: edges.to_vec(),
            state: Mutex::new(State {
                version: 1,
                routes,
                signed,
                reported: BTreeMap::new(),
            }),
        })
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The current version.
    pub fn version(&self) -> u64 {
        self.state().version
    }

    /// The current signed table.
    pub fn signed_table(&self) -> Vec<u8> {
        self.state().signed.clone()
    }

    /// Publishes `entry` as the route of its cell, replacing an older
    /// route of that cell, as a new version. Returns the version.
    ///
    /// # Errors
    ///
    /// [`ControlError::Job`] when the table does not encode or sign, as
    /// for a host that another cell holds. Nothing changes then.
    pub fn publish(&self, entry: RouteEntry) -> Result<u64, ControlError> {
        let mut s = self.state();
        let mut routes = s.routes.clone();
        if routes
            .iter()
            .any(|(c, r)| *c != entry.app.cell && r.host == entry.host)
        {
            return Err(ControlError::Job("a host of another cell"));
        }
        routes.insert(entry.app.cell, entry);
        self.commit(&mut s, routes)
    }

    /// Removes the routes of `cell` as a new version, and returns the
    /// number of hosts removed (2 per cell: its host and `id.<host>`) and
    /// the version without them. A cell without routes changes nothing
    /// and returns the current version.
    ///
    /// # Errors
    ///
    /// [`ControlError::Job`] when the new table cannot be signed.
    pub fn remove_cell(&self, cell: CellId) -> Result<(u16, u64), ControlError> {
        let mut s = self.state();
        let mut routes = s.routes.clone();
        if routes.remove(&cell.0).is_none() {
            return Ok((0, s.version));
        }
        let version = self.commit(&mut s, routes)?;
        Ok((2, version))
    }

    fn commit(
        &self,
        s: &mut State,
        routes: BTreeMap<[u8; 16], RouteEntry>,
    ) -> Result<u64, ControlError> {
        let version = s
            .version
            .checked_add(1)
            .ok_or(ControlError::Job("route table version"))?;
        let signed = sign(&self.signer, version, &routes)?;
        s.version = version;
        s.routes = routes;
        s.signed = signed;
        Ok(version)
    }

    /// Answers the poll `request` of the edge whose client certificate is
    /// `peer_der`: records the version the edge reports, and returns the
    /// signed table. A peer that is no configured edge, or a request that
    /// is no poll, gets no reply.
    pub fn answer_poll(&self, peer_der: &[u8], request: &[u8]) -> Option<Vec<u8>> {
        let edge = EdgeId::of_peer(peer_der).filter(|e| self.edges.contains(e))?;
        let have = decode_poll(request).ok()?;
        let mut s = self.state();
        let seen = s.reported.entry(edge).or_insert(0);
        *seen = (*seen).max(have);
        Some(s.signed.clone())
    }

    /// The version `edge` last reported, 0 before its first poll.
    pub fn reported(&self, edge: EdgeId) -> u64 {
        self.state().reported.get(&edge).copied().unwrap_or(0)
    }

    /// Whether every configured edge reported `version` or a newer one.
    pub fn every_edge_at(&self, version: u64) -> bool {
        let s = self.state();
        self.edges
            .iter()
            .all(|e| s.reported.get(e).is_some_and(|v| *v >= version))
    }
}

/// Serves the route feed on `listener` until `signal` is triggered: one
/// poll per connection over mutual TLS ([`crate::exchange::serve`]). The
/// TLS configuration requires a client certificate from the CA of the
/// edges.
pub async fn serve_route_feed<R: Runtime>(
    rt: R,
    listener: R::TcpListener,
    tls: fstp_tls::ServerConfig,
    signal: fstp_rt::ShutdownSignal,
    publisher: Arc<RoutePublisher>,
) {
    crate::exchange::serve(
        rt,
        listener,
        tls,
        fstp_edge::POLL_LEN,
        signal,
        move |peer, request| {
            let p = Arc::clone(&publisher);
            async move { p.answer_poll(&peer, &request) }
        },
    )
    .await;
}

/// The erasure's [`EdgeRoutes`] for remote edges (module documentation).
pub struct RemoteEdges<R: Runtime> {
    rt: R,
    publisher: Arc<RoutePublisher>,
    wait: Duration,
}

impl<R: Runtime> RemoteEdges<R> {
    /// Route removal through `publisher`, waiting at most `wait` for every
    /// edge to report the version without the cell's routes.
    pub fn new(rt: R, publisher: Arc<RoutePublisher>, wait: Duration) -> RemoteEdges<R> {
        RemoteEdges {
            rt,
            publisher,
            wait,
        }
    }
}

impl<R: Runtime> EdgeRoutes for RemoteEdges<R> {
    async fn remove_cell(&self, cell: CellId) -> Result<u16, ControlError> {
        let (removed, version) = self.publisher.remove_cell(cell)?;
        let started = std::time::Instant::now();
        while !self.publisher.every_edge_at(version) {
            if started.elapsed() >= self.wait {
                return Err(ControlError::Job(
                    "an edge did not report the table without the cell",
                ));
            }
            self.rt.sleep(REPORT_CHECK).await;
        }
        Ok(removed)
    }
}
