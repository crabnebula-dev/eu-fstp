//! The configuration of a pilot edge and its static route file (ADR-009
//! "Pilot edge configuration", gap G12, D1). Lane L9 `prod/edgerun`.
//!
//! A pilot has no control plane, so the edge reads its routes from a file
//! at start and never polls [`crate::RouteFeed`]. Both decoders are
//! fuzzed (`edge_config_decode`, `edge_routes_decode`). A refusal names
//! its rule and never quotes the input (R-NF-02).
//!
//! # The configuration file
//!
//! ```text
//! {"credentials_dir": "/etc/fstp/edge",
//!  "limits": {"connections": 1024, "hello_seconds": 10,          optional
//!             "lifetime_seconds": 7200, "open_seconds": 10,
//!             "per_client": 64},
//!  "listen": {"public": "0.0.0.0:443"},
//!  "routes": "/etc/fstp/edge-routes.json"}
//! ```
//!
//! Each member of `limits` is optional and has the default of
//! [`Limits::default`].
//!
//! # The route file
//!
//! ```text
//! {"routes": [
//!   {"cell": "<32 lowercase hex>", "host": "grants.example.eu",
//!    "app":   {"address": "10.0.0.4:7443", "server_name": "cell.tunnel.internal",
//!              "cert_sha256": "<64 lowercase hex>"},
//!    "vault": {"address": "10.0.0.6:7446", "server_name": "vault.tunnel.internal",
//!              "cert_sha256": "<64 lowercase hex>"}}]}
//! ```
//!
//! `host` routes to `app` and `id.<host>` to `vault`
//! ([`RouteTable::add_cell`], I-19). `cert_sha256` pins the tunnel
//! server's end-entity certificate ([`Pins`]).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use fstp_json::{Object, ParseLimits, Value};

use crate::host::HostName;
use crate::route::{CELL_ID_LEN, CellEndpoint, RouteError, RouteTable, same_endpoint};

/// The largest configuration file accepted, in bytes.
pub const MAX_CONFIG_LEN: usize = 4096;

/// The largest route file accepted, in bytes.
pub const MAX_ROUTE_FILE_LEN: usize = 64 * 1024;

/// The most routes, one per cell, a route file holds.
pub const MAX_PILOT_ROUTES: usize = 64;

/// The longest path the configuration names, in bytes.
pub const MAX_PATH_LEN: usize = 1024;

/// Why a configuration or a route file was refused. No variant holds a
/// byte of the input (R-NF-02).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// No configuration was named.
    Missing,
    /// The bytes are not one JSON object within the limits.
    NotAnObject,
    /// A member is not known. Unknown members are refused, so a typo
    /// never falls back to a default.
    UnknownMember(&'static str),
    /// A required member is absent.
    MissingMember(&'static str),
    /// A member's value does not have its grammar.
    Invalid(&'static str),
    /// The route table refused a route (I-19).
    Route(RouteError),
    /// Two endpoints carry one pin.
    PinTaken,
}

/// The limits of the edge (ADR-009 "Pilot edge configuration", row
/// "Limits").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Open client connections.
    pub connections: usize,
    /// Open connections per client IP address.
    pub per_client: usize,
    /// The ClientHello deadline.
    pub hello: Duration,
    /// The tunnel open deadline, handshake and pin check included.
    pub open: Duration,
    /// The life of one connection.
    pub lifetime: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            connections: 1024,
            per_client: 64,
            hello: Duration::from_secs(10),
            open: Duration::from_secs(10),
            lifetime: Duration::from_secs(7200),
        }
    }
}

/// The configuration of one edge process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EdgeConfig {
    /// The credentials directory.
    pub credentials_dir: PathBuf,
    /// The public listener.
    pub listen: SocketAddr,
    /// The route file.
    pub routes: PathBuf,
    /// The limits.
    pub limits: Limits,
}

/// The tunnel server pins of a route file: one SHA-256 digest of an
/// end-entity certificate DER per endpoint.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Pins {
    by_endpoint: Vec<(CellEndpoint, [u8; 32])>,
}

impl Pins {
    /// The pin of `endpoint`: the one entry with its cell, its address and
    /// its server name, or `None`.
    pub fn pin_of(&self, endpoint: &CellEndpoint) -> Option<[u8; 32]> {
        self.by_endpoint
            .iter()
            .find(|(ep, _)| {
                ep.cell == endpoint.cell
                    && ep.tls_name == endpoint.tls_name
                    && same_endpoint(&ep.address, &endpoint.address)
            })
            .map(|(_, pin)| *pin)
    }

    /// The number of pins, two per cell.
    pub fn len(&self) -> usize {
        self.by_endpoint.len()
    }

    /// Whether there is no pin.
    pub fn is_empty(&self) -> bool {
        self.by_endpoint.is_empty()
    }

    fn add(&mut self, endpoint: CellEndpoint, pin: [u8; 32]) -> Result<(), ConfigError> {
        if self.by_endpoint.iter().any(|(_, p)| *p == pin) {
            return Err(ConfigError::PinTaken);
        }
        self.by_endpoint.push((endpoint, pin));
        Ok(())
    }
}

/// A decoded route file: the table and the pins of its endpoints.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PilotRoutes {
    /// The route table, verified by [`RouteTable::add_cell`].
    pub table: RouteTable,
    /// The tunnel server pins.
    pub pins: Pins,
}

const CONFIG_MEMBERS: [&str; 4] = ["credentials_dir", "limits", "listen", "routes"];
const LIMIT_MEMBERS: [&str; 5] = [
    "connections",
    "hello_seconds",
    "lifetime_seconds",
    "open_seconds",
    "per_client",
];
const ROUTE_MEMBERS: [&str; 4] = ["app", "cell", "host", "vault"];
const ENDPOINT_MEMBERS: [&str; 3] = ["address", "cert_sha256", "server_name"];

fn members(o: &Object, allowed: &[&str], rule: &'static str) -> Result<(), ConfigError> {
    if o.keys().any(|k| !allowed.contains(&k)) {
        return Err(ConfigError::UnknownMember(rule));
    }
    Ok(())
}

fn get<'a>(o: &'a Object, name: &str, rule: &'static str) -> Result<&'a Value, ConfigError> {
    o.get(name).ok_or(ConfigError::MissingMember(rule))
}

fn text<'a>(o: &'a Object, name: &str, rule: &'static str) -> Result<&'a str, ConfigError> {
    get(o, name, rule)?
        .as_str()
        .ok_or(ConfigError::Invalid(rule))
}

fn object<'a>(o: &'a Object, name: &str, rule: &'static str) -> Result<&'a Object, ConfigError> {
    get(o, name, rule)?
        .as_object()
        .ok_or(ConfigError::Invalid(rule))
}

fn path_of(s: &str, rule: &'static str) -> Result<PathBuf, ConfigError> {
    if !s.starts_with('/') || s.len() > MAX_PATH_LEN || s.contains('\0') {
        return Err(ConfigError::Invalid(rule));
    }
    Ok(PathBuf::from(s))
}

fn addr_of(s: &str, rule: &'static str) -> Result<SocketAddr, ConfigError> {
    let addr = s
        .parse::<SocketAddr>()
        .map_err(|_| ConfigError::Invalid(rule))?;
    // One spelling: the address must print as it was written.
    if addr.to_string() != s {
        return Err(ConfigError::Invalid(rule));
    }
    Ok(addr)
}

fn nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(b.wrapping_sub(b'a').wrapping_add(10)),
        _ => None,
    }
}

fn hex<const N: usize>(s: &str, rule: &'static str) -> Result<[u8; N], ConfigError> {
    let bytes = s.as_bytes();
    if bytes.len() != N.saturating_mul(2) {
        return Err(ConfigError::Invalid(rule));
    }
    let mut out = [0u8; N];
    for (slot, pair) in out.iter_mut().zip(bytes.chunks_exact(2)) {
        let [hi, lo] = pair else {
            return Err(ConfigError::Invalid(rule));
        };
        let hi = nibble(*hi).ok_or(ConfigError::Invalid(rule))?;
        let lo = nibble(*lo).ok_or(ConfigError::Invalid(rule))?;
        *slot = (hi << 4) | lo;
    }
    Ok(out)
}

/// An optional whole number in `range`, or `default`.
fn bounded(
    o: &Object,
    name: &str,
    rule: &'static str,
    range: std::ops::RangeInclusive<u64>,
    default: u64,
) -> Result<u64, ConfigError> {
    match o.get(name) {
        None => Ok(default),
        Some(v) => v
            .as_u64()
            .filter(|n| range.contains(n))
            .ok_or(ConfigError::Invalid(rule)),
    }
}

fn usize_of(n: u64, rule: &'static str) -> Result<usize, ConfigError> {
    usize::try_from(n).map_err(|_| ConfigError::Invalid(rule))
}

fn limits_of(o: &Object) -> Result<Limits, ConfigError> {
    members(o, &LIMIT_MEMBERS, "limits")?;
    let d = Limits::default();
    let secs = |name: &str, rule: &'static str, range, default: Duration| {
        bounded(o, name, rule, range, default.as_secs()).map(Duration::from_secs)
    };
    let connections = usize_of(
        bounded(
            o,
            "connections",
            "limits.connections",
            1..=65_536,
            u64::try_from(d.connections).unwrap_or(u64::MAX),
        )?,
        "limits.connections",
    )?;
    let per_client = usize_of(
        bounded(
            o,
            "per_client",
            "limits.per_client",
            1..=65_536,
            u64::try_from(d.per_client.min(connections)).unwrap_or(u64::MAX),
        )?,
        "limits.per_client",
    )?;
    if per_client > connections {
        return Err(ConfigError::Invalid("limits.per_client"));
    }
    Ok(Limits {
        connections,
        per_client,
        hello: secs("hello_seconds", "limits.hello_seconds", 1..=60, d.hello)?,
        open: secs("open_seconds", "limits.open_seconds", 1..=60, d.open)?,
        lifetime: secs(
            "lifetime_seconds",
            "limits.lifetime_seconds",
            60..=86_400,
            d.lifetime,
        )?,
    })
}

fn config_limits() -> ParseLimits {
    ParseLimits::default()
        .with_max_input_bytes(MAX_CONFIG_LEN)
        .with_max_depth(3)
        .with_max_container_len(8)
        .with_max_string_bytes(MAX_PATH_LEN)
}

/// Decodes and checks an edge configuration file (module documentation,
/// ADR-009 "Pilot edge configuration"). Fuzzed (`edge_config_decode`).
///
/// # Errors
///
/// [`ConfigError`] naming the rule broken. It never quotes the input
/// (R-NF-02).
pub fn decode_config(bytes: &[u8]) -> Result<EdgeConfig, ConfigError> {
    if bytes.len() > MAX_CONFIG_LEN {
        return Err(ConfigError::Invalid("length"));
    }
    let value =
        fstp_json::parse_with(bytes, &config_limits()).map_err(|_| ConfigError::NotAnObject)?;
    let o = value.as_object().ok_or(ConfigError::NotAnObject)?;
    members(o, &CONFIG_MEMBERS, "config")?;
    let credentials_dir = path_of(
        text(o, "credentials_dir", "credentials_dir")?,
        "credentials_dir",
    )?;
    let listen = object(o, "listen", "listen")?;
    members(listen, &["public"], "listen")?;
    let listen = addr_of(text(listen, "public", "listen.public")?, "listen.public")?;
    let routes = path_of(text(o, "routes", "routes")?, "routes")?;
    let limits = match o.get("limits") {
        None => Limits::default(),
        Some(v) => limits_of(v.as_object().ok_or(ConfigError::Invalid("limits"))?)?,
    };
    Ok(EdgeConfig {
        credentials_dir,
        listen,
        routes,
        limits,
    })
}

fn route_limits() -> ParseLimits {
    ParseLimits::default()
        .with_max_input_bytes(MAX_ROUTE_FILE_LEN)
        .with_max_depth(4)
        .with_max_container_len(MAX_PILOT_ROUTES)
        .with_max_string_bytes(crate::host::MAX_HOST_LEN)
}

fn endpoint_of(
    o: &Object,
    name: &str,
    cell: [u8; CELL_ID_LEN],
    rule: &'static str,
) -> Result<(CellEndpoint, [u8; 32]), ConfigError> {
    let e = object(o, name, rule)?;
    members(e, &ENDPOINT_MEMBERS, rule)?;
    let address = addr_of(text(e, "address", rule)?, rule)?;
    let server_name = text(e, "server_name", rule)?;
    // The name the tunnel server's certificate carries: one lowercase
    // LDH spelling, as a route host.
    HostName::parse_lowercase(server_name.as_bytes()).map_err(|_| ConfigError::Invalid(rule))?;
    let pin = hex::<32>(text(e, "cert_sha256", rule)?, rule)?;
    Ok((
        CellEndpoint {
            cell,
            address,
            tls_name: server_name.to_owned(),
        },
        pin,
    ))
}

/// Decodes and checks a route file (module documentation, ADR-009
/// "Pilot edge configuration"). Every route passes
/// [`RouteTable::add_cell`], so a host maps to one cell and one kind and
/// no tunnel address serves two routes (I-19). Fuzzed
/// (`edge_routes_decode`).
///
/// # Errors
///
/// [`ConfigError`] naming the rule broken. It never quotes the input
/// (R-NF-02).
pub fn decode_routes(bytes: &[u8]) -> Result<PilotRoutes, ConfigError> {
    if bytes.len() > MAX_ROUTE_FILE_LEN {
        return Err(ConfigError::Invalid("length"));
    }
    let value =
        fstp_json::parse_with(bytes, &route_limits()).map_err(|_| ConfigError::NotAnObject)?;
    let o = value.as_object().ok_or(ConfigError::NotAnObject)?;
    members(o, &["routes"], "route file")?;
    let list = get(o, "routes", "routes")?
        .as_array()
        .ok_or(ConfigError::Invalid("routes"))?;
    if list.is_empty() || list.len() > MAX_PILOT_ROUTES {
        return Err(ConfigError::Invalid("routes"));
    }
    let mut out = PilotRoutes::default();
    for r in list.iter() {
        let r = r.as_object().ok_or(ConfigError::Invalid("route"))?;
        members(r, &ROUTE_MEMBERS, "route")?;
        let cell = hex::<CELL_ID_LEN>(text(r, "cell", "route.cell")?, "route.cell")?;
        let host = HostName::parse_lowercase(text(r, "host", "route.host")?.as_bytes())
            .map_err(|_| ConfigError::Invalid("route.host"))?;
        let (app, app_pin) = endpoint_of(r, "app", cell, "route.app")?;
        let (vault, vault_pin) = endpoint_of(r, "vault", cell, "route.vault")?;
        out.table
            .add_cell(host, app.clone(), vault.clone())
            .map_err(ConfigError::Route)?;
        out.pins.add(app, app_pin)?;
        out.pins.add(vault, vault_pin)?;
    }
    Ok(out)
}
