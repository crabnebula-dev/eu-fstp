//! The route feed from `fstp-control` to a remote `fstp-edge` (design
//! section 3.7 step 3, ADR-004 "Decided by Daniel, 2026-11-15 (late)":
//! "Each `fstp-edge` polls a signed route table from `fstp-control`").
//! Lane m3/erase-prod.
//!
//! The control plane publishes one route table with a version that rises
//! with each change, signed with its composite control-plane key. Each
//! edge polls it, reports the version it serves in each poll, checks the
//! signature (I-90: both halves), and swaps the table in only when its
//! version is newer than the one it serves ([`LiveRoutes::apply`]). An
//! erasure finishes route removal once every edge reports a version
//! without the cell's routes.
//!
//! Interim, pending Daniel, the bytes:
//!
//! ```text
//! signed = body | signature len u16 | composite signature
//! body   = "FRT1" | version u64 | count u16 | route*
//! route  = cell 16 | host len u8 | host | endpoint (app) | endpoint (vault)
//! endpoint = family u8 (4 or 6) | address 4 or 16 | port u16
//!          | tls name len u8 | tls name
//! poll   = "FRP1" | version u64
//! ```
//!
//! Integers are big-endian. The signature context is
//! [`ROUTE_TABLE_CONTEXT`]. Each route names a cell's application host;
//! its vault origin `id.<host>` follows from it ([`RouteTable::add_cell`]).
//! Routes appear in ascending host order, so a table has one spelling.
//! The decoder is fuzzed (`route_table_decode`).

use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use fstp_rt::{IoExt as _, Runtime};
use fstp_tls::ClientConfig;

use crate::host::HostName;
use crate::route::{CELL_ID_LEN, CellEndpoint, LiveRoutes, RouteError, RouteKind, RouteTable};

/// The magic of a route table body.
pub const ROUTE_TABLE_MAGIC: [u8; 4] = *b"FRT1";
/// The magic of a poll.
pub const POLL_MAGIC: [u8; 4] = *b"FRP1";
/// Length of a poll.
pub const POLL_LEN: usize = 12;
/// The composite signature context of a route table.
pub const ROUTE_TABLE_CONTEXT: &[u8] = b"fstp-route-table-v1";
/// The most routes a table holds.
pub const MAX_ROUTES: usize = 4096;
/// The longest TLS name of an endpoint.
pub const MAX_TLS_NAME_LEN: usize = 253;
/// The longest signature a signed table carries.
pub const MAX_SIGNATURE_LEN: usize = 8192;
/// The longest signed route table.
pub const MAX_SIGNED_TABLE_LEN: usize = 4 * 1024 * 1024;

/// Why a route table or a poll was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeedError {
    /// The bytes break the encoding. It names the rule.
    Malformed(&'static str),
    /// The signature does not verify under any pinned control-plane key.
    BadSignature,
    /// A route breaks a rule of [`RouteTable::add_cell`].
    Route(RouteError),
    /// The poll exchange failed.
    Io(io::ErrorKind),
}

impl std::fmt::Display for FeedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FeedError::Malformed(rule) => write!(f, "route feed: {rule}"),
            FeedError::BadSignature => f.write_str("route feed: the signature does not verify"),
            FeedError::Route(e) => write!(f, "route feed: a route is refused: {e:?}"),
            FeedError::Io(k) => write!(f, "route feed: {k:?}"),
        }
    }
}

impl std::error::Error for FeedError {}

/// One route of the table: a cell's application host and both endpoints.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteEntry {
    /// The cell's application host. Its vault origin is `id.<host>`.
    pub host: HostName,
    /// The cell application's tunnel endpoint.
    pub app: CellEndpoint,
    /// The vault process's tunnel endpoint.
    pub vault: CellEndpoint,
}

/// A decoded signed route table, before its signature is checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedRouteTable {
    /// The table version.
    pub version: u64,
    /// The routes, in ascending host order.
    pub routes: Vec<RouteEntry>,
    /// The signed body.
    pub body: Vec<u8>,
    /// The composite signature over the body.
    pub signature: Vec<u8>,
}

fn malformed(rule: &'static str) -> FeedError {
    FeedError::Malformed(rule)
}

fn push_name(out: &mut Vec<u8>, name: &[u8], max: usize) -> Result<(), FeedError> {
    if name.is_empty() || name.len() > max {
        return Err(malformed("a name length out of bounds"));
    }
    out.push(u8::try_from(name.len()).map_err(|_| malformed("a name too long"))?);
    out.extend_from_slice(name);
    Ok(())
}

fn push_endpoint(out: &mut Vec<u8>, ep: &CellEndpoint) -> Result<(), FeedError> {
    match ep.address.ip() {
        IpAddr::V4(v4) => {
            out.push(4);
            out.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out.push(6);
            out.extend_from_slice(&v6.octets());
        }
    }
    out.extend_from_slice(&ep.address.port().to_be_bytes());
    push_name(out, ep.tls_name.as_bytes(), MAX_TLS_NAME_LEN)
}

/// The body of a route table of `version` with `routes`, in ascending
/// host order whatever the order of `routes`.
///
/// # Errors
///
/// [`FeedError::Malformed`] for more than [`MAX_ROUTES`] routes, a host
/// listed twice, a cell id that differs between a route's endpoints, or
/// a TLS name out of bounds.
pub fn encode_route_table_body(version: u64, routes: &[RouteEntry]) -> Result<Vec<u8>, FeedError> {
    if routes.len() > MAX_ROUTES {
        return Err(malformed("too many routes"));
    }
    let mut sorted: Vec<&RouteEntry> = routes.iter().collect();
    sorted.sort_by(|a, b| a.host.cmp(&b.host));
    if sorted
        .windows(2)
        .any(|w| matches!(w, [a, b] if a.host == b.host))
    {
        return Err(malformed("a host listed twice"));
    }
    let mut out = ROUTE_TABLE_MAGIC.to_vec();
    out.extend_from_slice(&version.to_be_bytes());
    let n = u16::try_from(sorted.len()).map_err(|_| malformed("too many routes"))?;
    out.extend_from_slice(&n.to_be_bytes());
    for r in sorted {
        if r.app.cell != r.vault.cell {
            return Err(malformed("the endpoints of a route name two cells"));
        }
        out.extend_from_slice(&r.app.cell);
        push_name(&mut out, r.host.as_bytes(), crate::host::MAX_HOST_LEN)?;
        push_endpoint(&mut out, &r.app)?;
        push_endpoint(&mut out, &r.vault)?;
    }
    Ok(out)
}

/// The signed table: `body`, the signature length and the signature.
///
/// # Errors
///
/// [`FeedError::Malformed`] for a signature above [`MAX_SIGNATURE_LEN`].
pub fn encode_signed_route_table(body: &[u8], signature: &[u8]) -> Result<Vec<u8>, FeedError> {
    if signature.len() > MAX_SIGNATURE_LEN {
        return Err(malformed("a signature too long"));
    }
    let mut out = body.to_vec();
    let n = u16::try_from(signature.len()).map_err(|_| malformed("a signature too long"))?;
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(signature);
    Ok(out)
}

struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], FeedError> {
        let (head, tail) = self
            .rest
            .split_at_checked(n)
            .ok_or(malformed("truncated"))?;
        self.rest = tail;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], FeedError> {
        self.take(N)?.try_into().map_err(|_| malformed("truncated"))
    }

    fn u8(&mut self) -> Result<u8, FeedError> {
        Ok(u8::from_be_bytes(self.array()?))
    }

    fn name(&mut self, max: usize) -> Result<&'a [u8], FeedError> {
        let n = usize::from(self.u8()?);
        if n == 0 || n > max {
            return Err(malformed("a name length out of bounds"));
        }
        self.take(n)
    }

    fn endpoint(&mut self, cell: [u8; CELL_ID_LEN]) -> Result<CellEndpoint, FeedError> {
        let ip = match self.u8()? {
            4 => IpAddr::V4(Ipv4Addr::from(self.array::<4>()?)),
            6 => IpAddr::V6(Ipv6Addr::from(self.array::<16>()?)),
            _ => return Err(malformed("an unknown address family")),
        };
        let port = u16::from_be_bytes(self.array()?);
        let name = self.name(MAX_TLS_NAME_LEN)?;
        let tls_name = std::str::from_utf8(name)
            .map_err(|_| malformed("a TLS name that is not UTF-8"))?
            .to_owned();
        Ok(CellEndpoint {
            cell,
            address: SocketAddr::new(ip, port),
            tls_name,
        })
    }
}

/// Decodes a signed route table without checking its signature. A table
/// decodes only in its one spelling: routes in ascending host order, no
/// host twice, lowercase hosts, and no byte after the signature. Fuzzed
/// (`route_table_decode`).
///
/// # Errors
///
/// [`FeedError::Malformed`] naming the rule broken.
pub fn decode_signed_route_table(bytes: &[u8]) -> Result<SignedRouteTable, FeedError> {
    if bytes.len() > MAX_SIGNED_TABLE_LEN {
        return Err(malformed("too long"));
    }
    let mut r = Reader { rest: bytes };
    if r.array::<4>()? != ROUTE_TABLE_MAGIC {
        return Err(malformed("the wrong magic"));
    }
    let version = u64::from_be_bytes(r.array()?);
    let count = usize::from(u16::from_be_bytes(r.array()?));
    if count > MAX_ROUTES {
        return Err(malformed("too many routes"));
    }
    let mut routes: Vec<RouteEntry> = Vec::with_capacity(count.min(64));
    for _ in 0..count {
        let cell = r.array::<CELL_ID_LEN>()?;
        let host = HostName::parse_lowercase(r.name(crate::host::MAX_HOST_LEN)?)
            .map_err(|_| malformed("a host that is not a lowercase host name"))?;
        if routes.last().is_some_and(|p| p.host >= host) {
            return Err(malformed("routes out of host order"));
        }
        let app = r.endpoint(cell)?;
        let vault = r.endpoint(cell)?;
        routes.push(RouteEntry { host, app, vault });
    }
    let body_len = bytes.len().saturating_sub(r.rest.len());
    let body = bytes
        .get(..body_len)
        .ok_or(malformed("truncated"))?
        .to_vec();
    let n = usize::from(u16::from_be_bytes(r.array()?));
    if n > MAX_SIGNATURE_LEN {
        return Err(malformed("a signature too long"));
    }
    let signature = r.take(n)?.to_vec();
    if !r.rest.is_empty() {
        return Err(malformed("trailing bytes"));
    }
    Ok(SignedRouteTable {
        version,
        routes,
        body,
        signature,
    })
}

/// Decodes `bytes`, checks the composite signature of its body under
/// one of `keys`, the pinned control-plane public keys (I-90: both
/// halves), and builds the table its routes name.
///
/// # Errors
///
/// The errors of [`decode_signed_route_table`],
/// [`FeedError::BadSignature`], and [`FeedError::Route`] for routes that
/// [`RouteTable::add_cell`] refuses, such as two cells on one address.
pub fn verify_route_table(keys: &[Vec<u8>], bytes: &[u8]) -> Result<(u64, RouteTable), FeedError> {
    let signed = decode_signed_route_table(bytes)?;
    let ok = keys.iter().any(|k| {
        fstp_crypto::composite::verify_with_context(
            k,
            &signed.body,
            ROUTE_TABLE_CONTEXT,
            &signed.signature,
        )
        .is_ok()
    });
    if !ok {
        return Err(FeedError::BadSignature);
    }
    let mut table = RouteTable::new();
    for r in signed.routes {
        table
            .add_cell(r.host, r.app, r.vault)
            .map_err(FeedError::Route)?;
    }
    Ok((signed.version, table))
}

/// The routes of `table`, one per cell application host, so a control
/// plane can publish what an edge holds.
pub fn routes_of(table: &RouteTable) -> Vec<RouteEntry> {
    table
        .iter()
        .filter(|(_, (_, kind))| *kind == RouteKind::Cell)
        .filter_map(|(host, (app, _))| {
            let origin = host.vault_origin().ok()?;
            let (vault, _) = table.route(&origin)?;
            Some(RouteEntry {
                host: host.clone(),
                app: app.clone(),
                vault: vault.clone(),
            })
        })
        .collect()
}

/// The poll an edge sends: the magic and the version it serves.
pub fn encode_poll(version: u64) -> [u8; POLL_LEN] {
    let mut out = [0u8; POLL_LEN];
    let (m, v) = out.split_at_mut(4);
    m.copy_from_slice(&POLL_MAGIC);
    v.copy_from_slice(&version.to_be_bytes());
    out
}

/// Decodes a poll. Fuzzed (`route_table_decode`).
///
/// # Errors
///
/// [`FeedError::Malformed`] for any input but [`POLL_LEN`] bytes with the
/// magic.
pub fn decode_poll(bytes: &[u8]) -> Result<u64, FeedError> {
    let bytes: &[u8; POLL_LEN] = bytes.try_into().map_err(|_| malformed("a poll length"))?;
    let (m, v) = bytes.split_at(4);
    if m != POLL_MAGIC {
        return Err(malformed("the wrong poll magic"));
    }
    let v: [u8; 8] = v.try_into().map_err(|_| malformed("a poll length"))?;
    Ok(u64::from_be_bytes(v))
}

/// How an edge reaches `fstp-control` for one poll.
pub trait FeedTransport {
    /// Sends `poll` and returns the reply, a signed route table.
    fn fetch(&self, poll: &[u8]) -> impl Future<Output = io::Result<Vec<u8>>>;
}

/// The mutual TLS transport of the route feed: one exchange per
/// connection, as the control-private links write it (the client writes
/// its request, closes its sending side, and reads the reply up to the
/// peer's close). The edge presents its edge certificate and pins the
/// control-plane CA.
pub struct TlsFeed<R: Runtime> {
    rt: R,
    addr: SocketAddr,
    server_name: String,
    config: ClientConfig,
}

impl<R: Runtime> TlsFeed<R> {
    /// The transport to `fstp-control` at `addr`, whose certificate must
    /// carry `server_name`, with the client `config`.
    pub fn new(rt: R, addr: SocketAddr, server_name: &str, config: ClientConfig) -> TlsFeed<R> {
        TlsFeed {
            rt,
            addr,
            server_name: server_name.to_owned(),
            config,
        }
    }
}

impl<R: Runtime> FeedTransport for TlsFeed<R> {
    async fn fetch(&self, poll: &[u8]) -> io::Result<Vec<u8>> {
        let tcp = self.rt.connect_tcp(self.addr).await?;
        let mut stream = fstp_tls::connect(&self.config, &self.server_name, tcp).await?;
        stream.write_all(poll).await?;
        stream.flush().await?;
        stream.shutdown().await?;
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply, MAX_SIGNED_TABLE_LEN).await?;
        Ok(reply)
    }
}

/// The edge's side of the route feed: it polls through a transport,
/// checks each table and applies the newer ones to its live routes.
pub struct RouteFeed<T: FeedTransport> {
    transport: T,
    keys: Vec<Vec<u8>>,
    routes: LiveRoutes,
}

impl<T: FeedTransport> RouteFeed<T> {
    /// The feed into `routes`, over `transport`, trusting the control-plane
    /// composite public keys `keys`, the current and the next one.
    pub fn new(transport: T, keys: Vec<Vec<u8>>, routes: LiveRoutes) -> RouteFeed<T> {
        RouteFeed {
            transport,
            keys,
            routes,
        }
    }

    /// The transport.
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Polls once: reports the version the edge serves, checks the table
    /// that comes back, and applies it when it is newer. It returns the
    /// version the edge serves after the poll.
    ///
    /// # Errors
    ///
    /// [`FeedError::Io`] when the exchange fails, and the errors of
    /// [`verify_route_table`]. A refused table changes nothing.
    pub async fn poll_once(&self) -> Result<u64, FeedError> {
        let reply = self
            .transport
            .fetch(&encode_poll(self.routes.version()))
            .await
            .map_err(|e| FeedError::Io(e.kind()))?;
        let (version, table) = verify_route_table(&self.keys, &reply)?;
        self.routes.apply(version, table);
        Ok(self.routes.version())
    }
}
