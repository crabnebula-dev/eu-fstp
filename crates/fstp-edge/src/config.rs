//! The configuration of a pilot edge, the feed keys it pins, and the route
//! file grammar (ADR-009 "Pilot edge configuration" and "Pilot route
//! feed", gap G12, D1). Lane L9 `prod/edgerun`, lane L15 `prod/route-feed`.
//!
//! Daniel decided on 2026-11-21 that the pilot edge changes routes
//! without a restart: it polls the signed route feed of `fstp-control`
//! ([`crate::RouteFeed`]) and reads no route file. The route file grammar
//! stays as the input of `fstp-control route add`. The decoders are fuzzed
//! (`edge_config_decode`, `edge_routes_decode`). A refusal names its rule
//! and never quotes the input (R-NF-02).
//!
//! # The configuration file
//!
//! ```text
//! {"credentials_dir": "/etc/fstp/edge",
//!  "limits": {"connections": 1024, "hello_seconds": 10,          optional
//!             "lifetime_seconds": 7200, "open_seconds": 10,
//!             "per_client": 64},
//!  "feed": {"address": "10.0.0.2:7350", "cert_sha256": ["<64 lowercase hex>"],
//!           "poll_seconds": 5,                                     optional
//!           "server_name": "control.tunnel.internal"},
//!  "listen": {"public": "0.0.0.0:443"},
//!  "state_dir": "/var/lib/fstp-edge"}
//! ```
//!
//! Each member of `limits` is optional and has the default of
//! [`Limits::default`]. `feed.cert_sha256` pins the end-entity certificate
//! of `fstp-control`, with one or two pins (the current and the next).
//! `state_dir` holds the signed cache of the last verified table
//! ([`CACHE_FILE`]). The feed public keys sit in [`FEED_KEYS_FILE`] of the
//! credentials directory, one or two lowercase hex lines
//! ([`decode_feed_keys`]).
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

use crate::feed::{PinnedRoute, routes_of};
use crate::host::HostName;
pub use crate::route::Pins;
use crate::route::{CELL_ID_LEN, CellEndpoint, RouteError, RouteTable};

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
    /// The route feed source (lane L15).
    pub feed: FeedSource,
    /// The writable directory of the signed route table cache
    /// ([`CACHE_FILE`], Daniel, 2026-11-21).
    pub state_dir: PathBuf,
    /// The limits.
    pub limits: Limits,
}

/// Where the edge polls its routes (ADR-009 "Pilot route feed", row "Edge
/// configuration"). Lane L15.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeedSource {
    /// The feed listener of `fstp-control`.
    pub address: SocketAddr,
    /// The name its certificate must carry.
    pub server_name: String,
    /// The SHA-256 of the DER of its end-entity certificate: one or two
    /// distinct pins, the current and the next, so a renewal is staged
    /// without a restart (Daniel, 2026-11-21).
    pub cert_sha256: Vec<[u8; 32]>,
    /// The time between two polls.
    pub poll: Duration,
}

/// The most control certificate pins: the current and the next.
pub const MAX_CONTROL_PINS: usize = 2;

/// The signed route table cache in the edge's `state_dir`.
pub const CACHE_FILE: &str = "route-table.signed";

/// The default time between two polls.
pub const DEFAULT_POLL: Duration = Duration::from_secs(5);

/// The file of the feed public keys in the credentials directory.
pub const FEED_KEYS_FILE: &str = "route-feed.pub";

/// The most feed public keys the edge pins: the current and the next.
pub const MAX_FEED_KEYS: usize = 2;

/// The length of one feed public key: a composite public key.
pub const FEED_KEY_LEN: usize = fstp_crypto::composite::PUBLIC_KEY_LEN;

/// The longest feed keys file accepted, in bytes.
pub const MAX_FEED_KEYS_LEN: usize = 16 * 1024;

/// A decoded route file: the table and the pins of its endpoints.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PilotRoutes {
    /// The route table, verified by [`RouteTable::add_cell`].
    pub table: RouteTable,
    /// The tunnel server pins.
    pub pins: Pins,
}

impl PilotRoutes {
    /// The routes of the file with their pins, in ascending host order, as
    /// `fstp-control route add` publishes them (lane L15).
    pub fn entries(&self) -> Vec<PinnedRoute> {
        routes_of(&self.table)
            .into_iter()
            .filter_map(|route| {
                let app_pin = self.pins.pin_of(&route.app)?;
                let vault_pin = self.pins.pin_of(&route.vault)?;
                Some(PinnedRoute {
                    route,
                    app_pin,
                    vault_pin,
                })
            })
            .collect()
    }
}

const CONFIG_MEMBERS: [&str; 5] = ["credentials_dir", "feed", "limits", "listen", "state_dir"];
const FEED_MEMBERS: [&str; 4] = ["address", "cert_sha256", "poll_seconds", "server_name"];
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

fn feed_of(o: &Object) -> Result<FeedSource, ConfigError> {
    members(o, &FEED_MEMBERS, "feed")?;
    let address = addr_of(text(o, "address", "feed.address")?, "feed.address")?;
    let server_name = text(o, "server_name", "feed.server_name")?;
    HostName::parse_lowercase(server_name.as_bytes())
        .map_err(|_| ConfigError::Invalid("feed.server_name"))?;
    let pins = get(o, "cert_sha256", "feed.cert_sha256")?
        .as_array()
        .ok_or(ConfigError::Invalid("feed.cert_sha256"))?;
    if pins.is_empty() || pins.len() > MAX_CONTROL_PINS {
        return Err(ConfigError::Invalid("feed.cert_sha256"));
    }
    let mut cert_sha256: Vec<[u8; 32]> = Vec::new();
    for p in pins.iter() {
        let pin = hex::<32>(
            p.as_str().ok_or(ConfigError::Invalid("feed.cert_sha256"))?,
            "feed.cert_sha256",
        )?;
        if cert_sha256.contains(&pin) {
            return Err(ConfigError::Invalid("feed.cert_sha256"));
        }
        cert_sha256.push(pin);
    }
    let poll = bounded(
        o,
        "poll_seconds",
        "feed.poll_seconds",
        1..=60,
        DEFAULT_POLL.as_secs(),
    )
    .map(Duration::from_secs)?;
    Ok(FeedSource {
        address,
        server_name: server_name.to_owned(),
        cert_sha256,
        poll,
    })
}

/// Decodes the feed keys file [`FEED_KEYS_FILE`]: one or two composite
/// public keys of `fstp_crypto::composite::PUBLIC_KEY_LEN` bytes, each as
/// one line of lowercase hex ending in a newline, and no key twice
/// (ADR-009 "Pilot route feed", row "How the edge pins the control
/// plane"). Fuzzed (`edge_config_decode`).
///
/// # Errors
///
/// [`ConfigError::Invalid`] naming the file. It never quotes the input
/// (R-NF-02).
pub fn decode_feed_keys(bytes: &[u8]) -> Result<Vec<Vec<u8>>, ConfigError> {
    const RULE: &str = "route-feed.pub";
    const KEY_LEN: usize = FEED_KEY_LEN;
    if bytes.len() > MAX_FEED_KEYS_LEN {
        return Err(ConfigError::Invalid(RULE));
    }
    let body = bytes
        .strip_suffix(b"\n")
        .ok_or(ConfigError::Invalid(RULE))?;
    let mut keys: Vec<Vec<u8>> = Vec::new();
    for line in body.split(|b| *b == b'\n') {
        if keys.len() >= MAX_FEED_KEYS {
            return Err(ConfigError::Invalid(RULE));
        }
        let text = std::str::from_utf8(line).map_err(|_| ConfigError::Invalid(RULE))?;
        let key = hex::<KEY_LEN>(text, RULE)?.to_vec();
        if keys.contains(&key) {
            return Err(ConfigError::Invalid(RULE));
        }
        keys.push(key);
    }
    Ok(keys)
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
    let feed = feed_of(object(o, "feed", "feed")?)?;
    let state_dir = path_of(text(o, "state_dir", "state_dir")?, "state_dir")?;
    let limits = match o.get("limits") {
        None => Limits::default(),
        Some(v) => limits_of(v.as_object().ok_or(ConfigError::Invalid("limits"))?)?,
    };
    Ok(EdgeConfig {
        credentials_dir,
        listen,
        feed,
        state_dir,
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
        if !out.pins.add(app, app_pin) || !out.pins.add(vault, vault_pin) {
            return Err(ConfigError::PinTaken);
        }
    }
    Ok(out)
}
