//! The SNI router: ClientHello SNI parser, route table, tunnel header and
//! splice (I-19, M3 design section 9.4, ADR-009).
//!
//! The edge holds no tenant TLS server. It reaches `fstp-tls` for its
//! tunnel client only, and a source scan refuses any server configuration
//! in this crate (layering rule 5). Bytes after the ClientHello pass
//! unchanged.
//!
//! Status: W0 stub. Lane W2i fills the crate. Every parser refuses with a
//! typed `NotImplemented` error.

use std::collections::BTreeMap;

/// The length of the tunnel header.
pub const TUNNEL_HEADER_LEN: usize = 64;

/// A host name, lowercase ASCII.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HostName(String);

impl HostName {
    /// The name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// What the parser found in the first bytes of a connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SniOutcome {
    /// More bytes are needed.
    NeedMore,
    /// The ClientHello names this host.
    Host(HostName),
    /// The ClientHello has no SNI.
    NoSni,
    /// The bytes are not TLS.
    NotTls,
}

/// Why the ClientHello parser refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SniError {
    /// The parser is a W0 stub. It names the operation.
    NotImplemented(&'static str),
}

/// Why a tunnel header did not decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderError {
    /// The codec is a W0 stub. It names the operation.
    NotImplemented(&'static str),
}

/// The header the edge sends before the spliced bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TunnelHeader {
    /// The routed host.
    pub host: HostName,
    /// The client address, bucketed for logs.
    pub client: [u8; 16],
}

/// Where a host routes to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CellEndpoint {
    /// The cell's tunnel address.
    pub address: String,
}

/// What a route serves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteKind {
    /// The cell application.
    Cell,
    /// The vault origin.
    VaultOrigin,
}

/// The route table. It holds verified hosts only.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RouteTable {
    by_host: BTreeMap<HostName, (CellEndpoint, RouteKind)>,
}

impl RouteTable {
    /// The route of `host`, if any.
    pub fn route(&self, host: &HostName) -> Option<&(CellEndpoint, RouteKind)> {
        self.by_host.get(host)
    }
}

/// Parses the SNI from the first bytes of a connection, at most 16 KiB.
/// Fuzzed (`client_hello_sni`).
pub fn parse_client_hello_sni(buf: &[u8]) -> Result<SniOutcome, SniError> {
    let _ = buf;
    Err(SniError::NotImplemented(
        "fstp_edge::parse_client_hello_sni",
    ))
}

/// Encodes a tunnel header. The designed function is infallible; the stub
/// returns a `Result` until lane W2i lands it.
pub fn encode_tunnel_header(h: &TunnelHeader) -> Result<[u8; TUNNEL_HEADER_LEN], HeaderError> {
    let _ = h;
    Err(HeaderError::NotImplemented(
        "fstp_edge::encode_tunnel_header",
    ))
}

/// Decodes a tunnel header. Fuzzed (`tunnel_header_decode`). The cell
/// calls it too.
pub fn decode_tunnel_header(b: &[u8]) -> Result<TunnelHeader, HeaderError> {
    let _ = b;
    Err(HeaderError::NotImplemented(
        "fstp_edge::decode_tunnel_header",
    ))
}

/// Runs the edge until shutdown.
pub fn run() -> Result<(), SniError> {
    Err(SniError::NotImplemented("fstp_edge::run"))
}
