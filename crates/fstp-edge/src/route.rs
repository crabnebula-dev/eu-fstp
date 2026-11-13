//! The route table and the routing decision (M3 design sections 1.5 and
//! 9.4, ADR-009 "Edge and tunnel", I-19, B5, TH-48).
//!
//! `<cell host>` routes to the cell application and `id.<cell host>` to
//! the vault process of the same cell. A cell's two routes are added and
//! removed together. A host maps to exactly one cell and one kind, and in
//! M3 a cell has exactly one host.
//! The table holds verified hosts only: the control plane verifies a host
//! before it hands the route to the edge, which cannot verify it itself.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, PoisonError, RwLock};

use crate::host::{HostError, HostName};
use crate::sni::{SniError, SniOutcome, parse_client_hello_sni};

/// The length of a cell id, as `fstp-obs` labels it.
pub const CELL_ID_LEN: usize = fstp_obs::CELL_ID_LEN;

/// Where a host routes to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CellEndpoint {
    /// The cell id, for the edge's typed logs and metrics.
    pub cell: [u8; CELL_ID_LEN],
    /// The tunnel address of the cell process.
    pub address: SocketAddr,
    /// The name the tunnel's server certificate must carry.
    pub tls_name: String,
}

/// What a route serves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteKind {
    /// The cell application.
    Cell,
    /// The vault origin.
    VaultOrigin,
}

/// Why a route was not added.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteError {
    /// The cell host or its vault origin host already has a route.
    HostTaken,
    /// The vault origin host `id.<host>` is not a valid host name.
    VaultOriginHost(HostError),
    /// The two endpoints name different cells.
    CellMismatch,
    /// The application and the vault endpoint share a tunnel address, so
    /// vault origin traffic could reach the cell application.
    SameAddress,
    /// A tunnel address is already bound to another cell or kind, so one
    /// cell's connections could reach another cell's process.
    AddressTaken,
    /// The cell already has routes. In M3 a cell has one host, so cell
    /// erasure by host removes every route of the cell (TH-48).
    CellTaken,
}

/// The route table. It holds verified hosts only.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RouteTable {
    by_host: BTreeMap<HostName, (CellEndpoint, RouteKind)>,
}

impl RouteTable {
    /// An empty table.
    pub fn new() -> RouteTable {
        RouteTable::default()
    }

    /// The route of `host`, if any.
    pub fn route(&self, host: &HostName) -> Option<&(CellEndpoint, RouteKind)> {
        self.by_host.get(host)
    }

    /// The number of routes. Each cell has two.
    pub fn len(&self) -> usize {
        self.by_host.len()
    }

    /// Whether the table has no route.
    pub fn is_empty(&self) -> bool {
        self.by_host.is_empty()
    }

    /// Adds the two routes of one cell: `host` to `app` and `id.<host>` to
    /// `vault`. Either both routes are added or neither is.
    ///
    /// # Errors
    ///
    /// Returns [`RouteError::HostTaken`] when either host already has a
    /// route, so a host never maps to two cells or two kinds. Returns
    /// [`RouteError::SameAddress`] when both endpoints share an address,
    /// and [`RouteError::AddressTaken`] when an address already serves
    /// another route. Returns [`RouteError::CellTaken`] when the cell
    /// already has routes, so a cell has exactly one host and its vault
    /// origin. Addresses compare as endpoints: an IPv4-mapped IPv6
    /// address equals its IPv4 address, and IPv6 flow info and scope id
    /// are ignored. So a mistaken route feed never sends one cell's
    /// traffic, or vault origin traffic, to the wrong process.
    pub fn add_cell(
        &mut self,
        host: HostName,
        app: CellEndpoint,
        vault: CellEndpoint,
    ) -> Result<(), RouteError> {
        if app.cell != vault.cell {
            return Err(RouteError::CellMismatch);
        }
        if same_endpoint(&app.address, &vault.address) {
            return Err(RouteError::SameAddress);
        }
        let origin = host.vault_origin().map_err(RouteError::VaultOriginHost)?;
        if self.by_host.contains_key(&host) || self.by_host.contains_key(&origin) {
            return Err(RouteError::HostTaken);
        }
        let taken = |want: &CellEndpoint| {
            self.by_host
                .values()
                .any(|(ep, _)| same_endpoint(&ep.address, &want.address))
        };
        if taken(&app) || taken(&vault) {
            return Err(RouteError::AddressTaken);
        }
        if self.by_host.values().any(|(ep, _)| ep.cell == app.cell) {
            return Err(RouteError::CellTaken);
        }
        self.by_host.insert(host, (app, RouteKind::Cell));
        self.by_host.insert(origin, (vault, RouteKind::VaultOrigin));
        Ok(())
    }

    /// Removes both routes of the cell whose application host is `host`
    /// (TH-48: cell erasure removes both routes). Returns whether the cell
    /// had routes. A vault origin host alone removes nothing.
    pub fn remove_cell(&mut self, host: &HostName) -> bool {
        let is_cell = matches!(self.by_host.get(host), Some((_, RouteKind::Cell)));
        if !is_cell {
            return false;
        }
        self.by_host.remove(host);
        if let Ok(origin) = host.vault_origin() {
            self.by_host.remove(&origin);
        }
        true
    }

    /// Removes every route of cell `cell`, whatever its hosts (design
    /// section 3.7 step 3, TH-48). Returns the number of routes removed.
    pub fn remove_cell_by_id(&mut self, cell: &[u8; CELL_ID_LEN]) -> usize {
        let before = self.by_host.len();
        self.by_host.retain(|_, (ep, _)| ep.cell != *cell);
        before.saturating_sub(self.by_host.len())
    }
}

/// The route table an edge serves from, shared between the listener and
/// the route feed (design section 3.7 step 3, TH-48).
///
/// Each connection routes on the table that is current when its hello
/// arrives ([`LiveRoutes::current`]). A change builds a new table and
/// swaps it in, so a connection never sees half a change. Removing an
/// erased cell's routes makes every later hello for its hosts close as
/// [`CloseReason::UnknownHost`]. A tunnel already open runs on until
/// either end closes it.
#[derive(Clone, Debug, Default)]
pub struct LiveRoutes {
    inner: Arc<RwLock<Arc<RouteTable>>>,
}

impl LiveRoutes {
    /// Live routes that start as `table`.
    pub fn new(table: RouteTable) -> LiveRoutes {
        LiveRoutes {
            inner: Arc::new(RwLock::new(Arc::new(table))),
        }
    }

    /// The current table.
    pub fn current(&self) -> Arc<RouteTable> {
        Arc::clone(&self.inner.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// Adds the two routes of one cell, as [`RouteTable::add_cell`] does.
    ///
    /// # Errors
    ///
    /// The errors of [`RouteTable::add_cell`]. A refused change leaves
    /// the table as it was.
    pub fn add_cell(
        &self,
        host: HostName,
        app: CellEndpoint,
        vault: CellEndpoint,
    ) -> Result<(), RouteError> {
        let mut slot = self.inner.write().unwrap_or_else(PoisonError::into_inner);
        let mut next = RouteTable::clone(&slot);
        next.add_cell(host, app, vault)?;
        *slot = Arc::new(next);
        Ok(())
    }

    /// Removes every route of cell `cell`, as
    /// [`RouteTable::remove_cell_by_id`] does, and returns the number
    /// removed. Removing the routes of a cell without routes changes
    /// nothing and returns 0, so a retried removal is harmless.
    pub fn remove_cell_by_id(&self, cell: &[u8; CELL_ID_LEN]) -> usize {
        let mut slot = self.inner.write().unwrap_or_else(PoisonError::into_inner);
        let mut next = RouteTable::clone(&slot);
        let removed = next.remove_cell_by_id(cell);
        if removed > 0 {
            *slot = Arc::new(next);
        }
        removed
    }
}

/// The endpoint `addr` names, as (IP address, port). An IPv4-mapped IPv6
/// address folds to its IPv4 address. IPv6 flow info and scope id are
/// dropped, so two spellings of one listener compare equal.
fn endpoint_key(addr: &SocketAddr) -> (IpAddr, u16) {
    let ip = match addr.ip() {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 @ IpAddr::V4(_) => v4,
    };
    (ip, addr.port())
}

/// Whether `a` and `b` name the same endpoint (see [`endpoint_key`]).
fn same_endpoint(a: &SocketAddr, b: &SocketAddr) -> bool {
    endpoint_key(a) == endpoint_key(b)
}

/// Why the edge closes a connection before any tunnel opens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloseReason {
    /// The bytes are not TLS.
    NotTls,
    /// The ClientHello has no SNI.
    NoSni,
    /// The SNI names a host without a route.
    UnknownHost,
    /// The ClientHello was refused.
    Refused(SniError),
}

/// What the edge does with the first bytes of a connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision<'t> {
    /// Read more bytes first.
    NeedMore,
    /// Open a tunnel to `endpoint` and forward every byte unchanged.
    Forward {
        /// The host the ClientHello named.
        host: HostName,
        /// The route's endpoint.
        endpoint: &'t CellEndpoint,
        /// What the route serves.
        kind: RouteKind,
    },
    /// Close the connection.
    Close(CloseReason),
}

/// Routes the first bytes of a connection by their SNI. No SNI, ECH, an
/// unknown host or a malformed hello closes the connection (design
/// section 9.4).
pub fn decide<'t>(table: &'t RouteTable, buf: &[u8]) -> Decision<'t> {
    match parse_client_hello_sni(buf) {
        Ok(SniOutcome::NeedMore) => Decision::NeedMore,
        Ok(SniOutcome::NotTls) => Decision::Close(CloseReason::NotTls),
        Ok(SniOutcome::NoSni) => Decision::Close(CloseReason::NoSni),
        Err(e) => Decision::Close(CloseReason::Refused(e)),
        Ok(SniOutcome::Host(host)) => match table.route(&host) {
            Some((endpoint, kind)) => Decision::Forward {
                host,
                endpoint,
                kind: *kind,
            },
            None => Decision::Close(CloseReason::UnknownHost),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The application endpoint of cell `cell`.
    fn app(cell: u8) -> CellEndpoint {
        endpoint(cell, 8443)
    }

    /// The vault origin endpoint of cell `cell`.
    fn vault(cell: u8) -> CellEndpoint {
        endpoint(cell, 9443)
    }

    fn endpoint(cell: u8, port: u16) -> CellEndpoint {
        CellEndpoint {
            cell: [cell; CELL_ID_LEN],
            address: SocketAddr::from(([10, 0, 0, cell], port)),
            tls_name: "tunnel.cell.internal".to_owned(),
        }
    }

    /// I-19, TH-48 (design section 1.5): a cell's host routes to its
    /// application and `id.<host>` to its vault origin. A host maps to one
    /// cell and kind, and removal takes both routes.
    #[test]
    fn i19_route_table_maps_each_host_to_one_cell_and_kind() -> Result<(), HostError> {
        let mut t = RouteTable::new();
        let a = HostName::parse(b"a.example")?;
        let a_id = HostName::parse(b"id.a.example")?;
        assert_eq!(t.add_cell(a.clone(), app(1), vault(1)), Ok(()));
        assert_eq!(t.route(&a).map(|r| r.1), Some(RouteKind::Cell));
        assert_eq!(t.route(&a_id).map(|r| r.1), Some(RouteKind::VaultOrigin));
        assert_eq!(
            t.add_cell(a.clone(), app(2), vault(2)),
            Err(RouteError::HostTaken)
        );
        assert_eq!(
            t.add_cell(a_id.clone(), app(2), vault(2)),
            Err(RouteError::HostTaken)
        );
        let b = HostName::parse(b"b.example")?;
        assert_eq!(
            t.add_cell(b, app(2), vault(3)),
            Err(RouteError::CellMismatch)
        );
        assert_eq!(t.len(), 2);
        assert!(!t.remove_cell(&a_id));
        assert!(t.remove_cell(&a));
        assert!(t.is_empty());
        Ok(())
    }

    /// I-19 (design sections 1.5 and 9.4, review W5): a tunnel address
    /// serves one cell and one kind. A cell whose two endpoints share an
    /// address, or whose address already serves another cell or kind, is
    /// refused and leaves the table unchanged.
    #[test]
    fn i19_route_table_binds_each_tunnel_address_to_one_cell_and_kind() -> Result<(), HostError> {
        let mut t = RouteTable::new();
        let a = HostName::parse(b"a.example")?;
        let b = HostName::parse(b"b.example")?;
        assert_eq!(
            t.add_cell(a.clone(), app(1), app(1)),
            Err(RouteError::SameAddress)
        );
        assert!(t.is_empty());
        assert_eq!(t.add_cell(a, app(1), vault(1)), Ok(()));
        let before = t.clone();
        let mut other_app = app(1);
        other_app.cell = [2; CELL_ID_LEN];
        let mut other_vault = vault(2);
        other_vault.cell = [2; CELL_ID_LEN];
        assert_eq!(
            t.add_cell(b.clone(), other_app, other_vault),
            Err(RouteError::AddressTaken)
        );
        // Cell 1 again, with its vault address offered as an application.
        assert_eq!(
            t.add_cell(b.clone(), vault(1), endpoint(1, 7443)),
            Err(RouteError::AddressTaken)
        );
        assert_eq!(t, before);
        assert_eq!(t.add_cell(b, app(2), vault(2)), Ok(()));
        assert_eq!(t.len(), 4);
        Ok(())
    }

    /// I-19 (design sections 1.5 and 9.4, review fix round 2): tunnel
    /// addresses compare as endpoints. An IPv4-mapped IPv6 spelling, or an
    /// IPv6 address that differs only in flow info or scope id, names an
    /// address already in use and is refused.
    #[test]
    fn i19_route_table_compares_tunnel_addresses_as_endpoints() -> Result<(), HostError> {
        use std::net::{Ipv4Addr, SocketAddrV6};
        let mapped = |cell: u8, port: u16| {
            let v6 = Ipv4Addr::new(10, 0, 0, cell).to_ipv6_mapped();
            SocketAddr::V6(SocketAddrV6::new(v6, port, 0, 0))
        };
        let mut t = RouteTable::new();
        let a = HostName::parse(b"a.example")?;
        let mut a_vault = vault(1);
        a_vault.address = mapped(1, 8443);
        assert_eq!(
            t.add_cell(a.clone(), app(1), a_vault),
            Err(RouteError::SameAddress)
        );
        assert_eq!(t.add_cell(a, app(1), vault(1)), Ok(()));
        let before = t.clone();
        let b = HostName::parse(b"b.example")?;
        let mut b_app = app(2);
        b_app.address = mapped(1, 8443);
        assert_eq!(
            t.add_cell(b.clone(), b_app, vault(2)),
            Err(RouteError::AddressTaken)
        );
        let v6 = |flow: u32, scope: u32, port: u16| {
            let ip = std::net::Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
            SocketAddr::V6(SocketAddrV6::new(ip, port, flow, scope))
        };
        let mut c_app = app(3);
        c_app.address = v6(0, 0, 8443);
        let mut c_vault = vault(3);
        c_vault.address = v6(7, 3, 8443);
        let c = HostName::parse(b"c.example")?;
        assert_eq!(t.add_cell(c, c_app, c_vault), Err(RouteError::SameAddress));
        assert_eq!(t, before);
        Ok(())
    }

    /// TH-48 (design section 3.7 step 3, review fix round 2): a cell has
    /// one host in M3, so a second host for a cell in the table is
    /// refused. Erasure by cell id removes every route of the cell and
    /// leaves other cells routed.
    #[test]
    fn th48_cell_erasure_removes_every_route_of_the_cell() -> Result<(), HostError> {
        let mut t = RouteTable::new();
        let a = HostName::parse(b"a.example")?;
        let a2 = HostName::parse(b"a2.example")?;
        let b = HostName::parse(b"b.example")?;
        assert_eq!(t.add_cell(a.clone(), app(1), vault(1)), Ok(()));
        assert_eq!(
            t.add_cell(a2.clone(), app(1), vault(1)),
            Err(RouteError::AddressTaken)
        );
        assert_eq!(
            t.add_cell(a2.clone(), endpoint(1, 7443), endpoint(1, 6443)),
            Err(RouteError::CellTaken)
        );
        assert_eq!(t.add_cell(b.clone(), app(2), vault(2)), Ok(()));
        assert_eq!(t.remove_cell_by_id(&[1; CELL_ID_LEN]), 2);
        assert_eq!(t.route(&a), None);
        assert_eq!(t.route(&HostName::parse(b"id.a.example")?), None);
        assert_eq!(t.route(&a2), None);
        assert_eq!(t.route(&b).map(|r| r.1), Some(RouteKind::Cell));
        assert_eq!(t.len(), 2);
        assert_eq!(t.remove_cell_by_id(&[1; CELL_ID_LEN]), 0);
        Ok(())
    }
}
