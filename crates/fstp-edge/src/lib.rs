//! The SNI router: ClientHello SNI parser, route table, tunnel header and
//! splice (I-19, M3 design section 9.4, ADR-009).
//!
//! - [`parse_client_hello_sni`] reads the SNI of a ClientHello and nothing
//!   else, at most 16 KiB. It is in-house and fuzzed (`client_hello_sni`).
//! - [`RouteTable`] maps a verified host to one cell and one kind:
//!   `<cell host>` to the cell application, `id.<cell host>` to its vault
//!   origin (design section 1.5). [`decide`] routes the first bytes of a
//!   connection. [`LiveRoutes`] holds the table the edge serves from, and
//!   removes an erased cell's routes (design section 3.7 step 3).
//! - [`encode_tunnel_header`] and [`decode_tunnel_header`] write and read
//!   the first frame of the tunnel, with one spelling. The decoder is
//!   fuzzed (`tunnel_header_decode`), and the cell and vault call it.
//! - [`serve`] splices one client connection into one tunnel. Every byte
//!   the client sends, the ClientHello included, passes unchanged.
//! - [`RouteFeed`] polls the signed, versioned route table of
//!   `fstp-control` over [`TlsFeed`], checks its composite signature
//!   (I-90), and applies a newer version to [`LiveRoutes`]. Each poll
//!   reports the version the edge serves, so an erasure can finish route
//!   removal once every edge serves a table without the cell (design
//!   section 3.7 step 3, ADR-004 "Decided by Daniel, 2026-11-15 (late)").
//!   The table decoder is fuzzed (`route_table_decode`).
//! - [`config`] and [`run`] start a pilot edge from a configuration file
//!   and a static route file, with no control plane (ADR-009 "Pilot edge
//!   configuration", D1). Both decoders are fuzzed (`edge_config_decode`,
//!   `edge_routes_decode`).
//!
//! The edge holds no tenant TLS server and no tenant TLS key (boundary
//! rule B5). It reaches `fstp-tls` for its tunnel client only, and a
//! source scan refuses any server configuration in this crate (layering
//! rule 5).

pub mod config;
mod feed;
mod header;
mod host;
mod route;
pub mod run;
mod sni;
mod splice;

pub use crate::feed::{
    FeedError, FeedTransport, MAX_ROUTES, MAX_SIGNATURE_LEN, MAX_SIGNED_TABLE_LEN,
    MAX_TLS_NAME_LEN, POLL_LEN, POLL_MAGIC, ROUTE_TABLE_CONTEXT, ROUTE_TABLE_MAGIC, RouteEntry,
    RouteFeed, SignedRouteTable, TlsFeed, decode_poll, decode_signed_route_table, encode_poll,
    encode_route_table_body, encode_signed_route_table, routes_of, verify_route_table,
};
pub use crate::header::{
    FAMILY_IPV4, FAMILY_IPV6, HeaderError, TUNNEL_HEADER_LEN, TUNNEL_HEADER_VERSION, TunnelHeader,
    decode_tunnel_header, encode_tunnel_header,
};
pub use crate::host::{HostError, HostName, MAX_HOST_LEN, MAX_LABEL_LEN};
pub use crate::route::{
    CELL_ID_LEN, CellEndpoint, CloseReason, Decision, LiveRoutes, RouteError, RouteKind,
    RouteTable, decide,
};
pub use crate::sni::{
    HelloPart, HelloScan, MAX_HELLO_BUF, SniError, SniOutcome, parse_client_hello_sni,
};
pub use crate::splice::{
    EdgeError, Routed, Spliced, TlsTunnelOpener, TunnelOpener, forward, read_hello, serve,
};

/// Runs the pilot edge from the configuration file that
/// [`run::CONFIG_ENV`] names until SIGTERM or SIGINT ([`run::run`], ADR-009
/// "Pilot edge configuration"). It serves a static route table and never
/// polls the route feed, so it is a pilot, not a release (D1).
///
/// # Errors
///
/// As [`run::run`].
pub fn run() -> Result<(), EdgeError> {
    run::run()
}
