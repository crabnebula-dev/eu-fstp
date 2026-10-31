//! The SNI router: ClientHello SNI parser, route table, tunnel header and
//! splice (I-19, M3 design section 9.4, ADR-009).
//!
//! - [`parse_client_hello_sni`] reads the SNI of a ClientHello and nothing
//!   else, at most 16 KiB. It is in-house and fuzzed (`client_hello_sni`).
//! - [`RouteTable`] maps a verified host to one cell and one kind:
//!   `<cell host>` to the cell application, `id.<cell host>` to its vault
//!   origin (design section 1.5). [`decide`] routes the first bytes of a
//!   connection.
//! - [`encode_tunnel_header`] and [`decode_tunnel_header`] write and read
//!   the first frame of the tunnel, with one spelling. The decoder is
//!   fuzzed (`tunnel_header_decode`), and the cell and vault call it.
//! - [`serve`] splices one client connection into one tunnel. Every byte
//!   the client sends, the ClientHello included, passes unchanged.
//!
//! The edge holds no tenant TLS server and no tenant TLS key (boundary
//! rule B5). It reaches `fstp-tls` for its tunnel client only, and a
//! source scan refuses any server configuration in this crate (layering
//! rule 5).

mod header;
mod host;
mod route;
mod sni;
mod splice;

pub use crate::header::{
    FAMILY_IPV4, FAMILY_IPV6, HeaderError, TUNNEL_HEADER_LEN, TUNNEL_HEADER_VERSION, TunnelHeader,
    decode_tunnel_header, encode_tunnel_header,
};
pub use crate::host::{HostError, HostName, MAX_HOST_LEN, MAX_LABEL_LEN};
pub use crate::route::{
    CELL_ID_LEN, CellEndpoint, CloseReason, Decision, RouteError, RouteKind, RouteTable, decide,
};
pub use crate::sni::{
    HelloPart, HelloScan, MAX_HELLO_BUF, SniError, SniOutcome, parse_client_hello_sni,
};
pub use crate::splice::{
    EdgeError, Routed, Spliced, TlsTunnelOpener, TunnelOpener, read_hello, serve,
};

/// Runs the edge until shutdown.
///
/// # Errors
///
/// Returns [`EdgeError::NotImplemented`]: the route feed from the control
/// plane and the listener configuration are not designed yet, so the
/// binary refuses to start rather than route on a made-up table.
pub fn run() -> Result<(), EdgeError> {
    Err(EdgeError::NotImplemented(
        "fstp_edge::run: route feed and listener configuration",
    ))
}
