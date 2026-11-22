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
//!
//! Lane L15 (ADR-009 "Pilot route feed", decided by Daniel on 2026-11-21):
//! each route carries the pins of its two tunnel servers, and the
//! publisher builds each table through the edge's own checks before it
//! signs ([`sign_table`]). A version is `max(previous + 1, Unix time in
//! milliseconds)` ([`next_version`]). A pilot publisher resumes from its
//! state file and writes each new table there before an edge can fetch it
//! ([`RoutePublisher::resume`]).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fstp_cp_proto::CellId;
use fstp_crypto::composite::CompositeSigningKey;
use fstp_edge::{
    PinnedRoute, ROUTE_TABLE_CONTEXT, check_routes, decode_poll, encode_route_table_body,
    encode_signed_route_table, verify_route_table,
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
    routes: BTreeMap<[u8; 16], PinnedRoute>,
    signed: Vec<u8>,
    reported: BTreeMap<EdgeId, u64>,
}

/// The route table the control plane publishes, and what each edge
/// reported (module documentation).
pub struct RoutePublisher {
    signer: CompositeSigningKey,
    edges: Vec<EdgeId>,
    state: Mutex<State>,
    store: Option<PathBuf>,
}

impl std::fmt::Debug for RoutePublisher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoutePublisher")
            .field("edges", &self.edges.len())
            .finish_non_exhaustive()
    }
}

/// The version after `previous`: `max(previous + 1, Unix time in
/// milliseconds)` (ADR-009 "Pilot route feed", row "Versions"). So a
/// table written again after a lost state still rises above every
/// version an edge served, unless the host clock ran back.
///
/// # Errors
///
/// [`ControlError::Job`] when the version would pass `u64::MAX`.
pub fn next_version(previous: u64) -> Result<u64, ControlError> {
    let next = previous
        .checked_add(1)
        .ok_or(ControlError::Job("route table version"))?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    Ok(next.max(now))
}

/// Signs the table of `version` with `routes`. The routes first pass the
/// edge's own checks ([`fstp_edge::check_routes`]), so the control plane
/// never signs a table an edge refuses (ADR-009 "Pilot route feed", row
/// "Checks before signing").
///
/// # Errors
///
/// [`ControlError::Request`] naming the rule for routes an edge would
/// refuse, and [`ControlError::Job`] when the table does not sign.
pub fn sign_table(
    signer: &CompositeSigningKey,
    version: u64,
    routes: &[PinnedRoute],
) -> Result<Vec<u8>, ControlError> {
    check_routes(routes).map_err(|e| ControlError::Request(e.rule()))?;
    let body =
        encode_route_table_body(version, routes).map_err(|_| ControlError::Request("I-19"))?;
    let signature = signer
        .sign_with_context(&body, ROUTE_TABLE_CONTEXT)
        .map_err(|_| ControlError::Job("the route table signature"))?;
    encode_signed_route_table(&body, &signature.to_bytes())
        .map_err(|_| ControlError::Job("route table"))
}

fn sign(
    signer: &CompositeSigningKey,
    version: u64,
    routes: &BTreeMap<[u8; 16], PinnedRoute>,
) -> Result<Vec<u8>, ControlError> {
    let list: Vec<PinnedRoute> = routes.values().cloned().collect();
    sign_table(signer, version, &list)
}

impl RoutePublisher {
    /// A publisher of an empty table, signed by the control-plane key
    /// `signer`, for the edges `edges`. Its version comes from
    /// [`next_version`]. It keeps its table in memory only.
    ///
    /// # Errors
    ///
    /// [`ControlError::Job`] when the table cannot be signed.
    pub fn new(
        signer: CompositeSigningKey,
        edges: &[EdgeId],
    ) -> Result<RoutePublisher, ControlError> {
        let routes = BTreeMap::new();
        let version = next_version(0)?;
        let signed = sign(&signer, version, &routes)?;
        Ok(RoutePublisher {
            signer,
            edges: edges.to_vec(),
            state: Mutex::new(State {
                version,
                routes,
                signed,
                reported: BTreeMap::new(),
            }),
            store: None,
        })
    }

    /// A publisher that resumes from the signed table `signed`, the
    /// state file of a pilot (ADR-009 "Pilot route feed", row "Table
    /// state"), and writes each new table to `store` before it serves it.
    /// The table must verify under `signer`'s own public key, through the
    /// edge's own decoder and checks.
    ///
    /// # Errors
    ///
    /// [`ControlError::Config`] for a table that does not verify under
    /// the key.
    pub fn resume(
        signer: CompositeSigningKey,
        edges: &[EdgeId],
        signed: &[u8],
        store: PathBuf,
    ) -> Result<RoutePublisher, ControlError> {
        let key = signer.public_key().to_bytes().to_vec();
        let verified = verify_route_table(&[key], signed)
            .map_err(|_| ControlError::Config("route table state"))?;
        let routes = verified
            .routes
            .into_iter()
            .map(|r| (r.route.app.cell, r))
            .collect();
        Ok(RoutePublisher {
            signer,
            edges: edges.to_vec(),
            state: Mutex::new(State {
                version: verified.version,
                routes,
                signed: signed.to_vec(),
                reported: BTreeMap::new(),
            }),
            store: Some(store),
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

    /// The current routes, in ascending cell order.
    pub fn routes(&self) -> Vec<PinnedRoute> {
        self.state().routes.values().cloned().collect()
    }

    /// Publishes `entry` as the route of its cell, replacing an older
    /// route of that cell, as a new version. Returns the version.
    ///
    /// # Errors
    ///
    /// [`ControlError::Request`] for a host that another cell holds, or a
    /// table an edge would refuse, and [`ControlError::Job`] or
    /// [`ControlError::Io`] when the table does not sign or store.
    /// Nothing changes then.
    pub fn publish(&self, entry: PinnedRoute) -> Result<u64, ControlError> {
        self.publish_with(entry, &mut |_| Ok(()))
    }

    /// As [`RoutePublisher::publish`], and calls `before_store` with the
    /// new version after the table is signed and before it is stored or
    /// served. An error of `before_store` changes nothing. The pilot
    /// appends its audit record there (lane L15).
    ///
    /// # Errors
    ///
    /// As [`RoutePublisher::publish`], and the error of `before_store`.
    pub fn publish_with(
        &self,
        entry: PinnedRoute,
        before_store: &mut dyn FnMut(u64) -> Result<(), ControlError>,
    ) -> Result<u64, ControlError> {
        let mut s = self.state();
        let mut routes = s.routes.clone();
        let cell = entry.route.app.cell;
        if routes
            .iter()
            .any(|(c, r)| *c != cell && r.route.host == entry.route.host)
        {
            return Err(ControlError::Request("I-19"));
        }
        routes.insert(cell, entry);
        self.commit(&mut s, routes, before_store)
    }

    /// Removes the routes of `cell` as a new version, and returns the
    /// number of hosts removed (2 per cell: its host and `id.<host>`) and
    /// the version without them. A cell without routes changes nothing
    /// and returns the current version.
    ///
    /// # Errors
    ///
    /// [`ControlError::Job`] or [`ControlError::Io`] when the new table
    /// cannot be signed or stored.
    pub fn remove_cell(&self, cell: CellId) -> Result<(u16, u64), ControlError> {
        self.remove_cell_with(cell, &mut |_| Ok(()))
    }

    /// As [`RoutePublisher::remove_cell`], with `before_store` as for
    /// [`RoutePublisher::publish_with`]. A cell without routes calls
    /// nothing.
    ///
    /// # Errors
    ///
    /// As [`RoutePublisher::remove_cell`], and the error of `before_store`.
    pub fn remove_cell_with(
        &self,
        cell: CellId,
        before_store: &mut dyn FnMut(u64) -> Result<(), ControlError>,
    ) -> Result<(u16, u64), ControlError> {
        let mut s = self.state();
        let mut routes = s.routes.clone();
        if routes.remove(&cell.0).is_none() {
            return Ok((0, s.version));
        }
        let version = self.commit(&mut s, routes, before_store)?;
        Ok((2, version))
    }

    fn commit(
        &self,
        s: &mut State,
        routes: BTreeMap<[u8; 16], PinnedRoute>,
        before_store: &mut dyn FnMut(u64) -> Result<(), ControlError>,
    ) -> Result<u64, ControlError> {
        let version = next_version(s.version)?;
        let signed = sign(&self.signer, version, &routes)?;
        before_store(version)?;
        // The state file holds the new table before any edge can fetch it.
        if let Some(path) = &self.store {
            write_atomic(path, &signed)?;
        }
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

/// Writes `bytes` to `path` so a crash leaves the old file or the new
/// one: a new temporary file beside it with mode 0600, synced, then
/// renamed over `path`, and the directory synced.
///
/// # Errors
///
/// [`ControlError::Io`] when a step fails.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), ControlError> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let io = |e: std::io::Error| ControlError::Io(e.kind());
    let dir = path
        .parent()
        .ok_or(ControlError::Io(std::io::ErrorKind::InvalidInput))?;
    let mut tmp_name = path
        .file_name()
        .ok_or(ControlError::Io(std::io::ErrorKind::InvalidInput))?
        .to_os_string();
    tmp_name.push(".new");
    let tmp = dir.join(tmp_name);
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(io)?;
    f.write_all(bytes).map_err(io)?;
    f.sync_all().map_err(io)?;
    drop(f);
    std::fs::rename(&tmp, path).map_err(io)?;
    std::fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(io)
}
