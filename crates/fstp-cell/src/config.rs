//! The configuration of a cell and its decoder (design sections 1.2,
//! 10.3 and 14.4).
//!
//! No field may hold a payment account type or a debtor account (I-16,
//! `i16_config_types_hold_no_debtor_account`). The configuration names
//! exactly one cell (I-19, `i19_cell_process_serves_one_cell`).
//!
//! # Format
//!
//! One JSON object, parsed by `fstp_json`, with these members and no
//! other:
//!
//! - `cell`: 32 lowercase hex digits.
//! - `mode`: `"saas"` or `"self_hosted"`.
//! - `eudi_relying_party`: `"tenant_registration"` or `"intermediary"`,
//!   optional, `"tenant_registration"` by default. These are the W1g
//!   proposal names of `fstp-celltest` `i38_egress`. A self-hosted build
//!   refuses `"intermediary"` (P-45, `eudi-wallet.md`, I-38).
//! - `licence`: 32 lowercase hex digits. Optional for a self-hosted cell
//!   and refused for a SaaS cell, which never reaches CrabNebula (B12).
//!   A self-hosted cell starts before its holder registers, and takes
//!   the licence from the first token it imports (design section 10.2,
//!   Q41). When both name a licence, they must name the same one.
//! - `version`: `"major.minor.patch"`, the running product version.
//!
//! The member grammar is the lane W3a reading. Design section 9.5 fixes no
//! configuration grammar yet.

use fstp_cp_proto::CellId;
use fstp_release::egress::ProductVersion;
use fstp_release::licence::LicenceId;

/// How a cell is deployed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// A SaaS cell, which reaches the control plane and never CrabNebula.
    Saas,
    /// A self-hosted cell, which has no control plane and reaches
    /// CrabNebula only through `fstp_release::egress` (B12).
    SelfHosted,
}

/// How the cell acts as an EUDI relying party (P-45).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelyingParty {
    /// The tenant registers as its own relying party.
    TenantRegistration,
    /// The platform acts as an intermediary. A self-hosted build refuses
    /// it, since it would send identity data to a CrabNebula service.
    Intermediary,
}

/// The configuration of one cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CellConfig {
    /// The one cell this process serves.
    pub cell: CellId,
    /// The deployment mode.
    pub mode: Mode,
    /// The EUDI relying party mode.
    pub relying_party: RelyingParty,
    /// The licence of a self-hosted cell.
    pub licence: Option<LicenceId>,
    /// The running product version.
    pub version: ProductVersion,
}

/// Why a configuration was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// No configuration was given.
    Missing,
    /// The bytes are not one JSON object.
    NotAnObject,
    /// A member is not known. Unknown members are refused, so a typo
    /// never falls back to a default.
    UnknownMember,
    /// A required member is absent.
    MissingMember(&'static str),
    /// A member's value does not have its grammar.
    Invalid(&'static str),
    /// A self-hosted build refuses P-45 intermediary mode (I-38).
    IntermediaryWhenSelfHosted,
    /// A SaaS cell holds no licence: it never reaches CrabNebula (B12).
    LicenceWhenSaas,
}

const MEMBERS: [&str; 5] = ["cell", "mode", "eudi_relying_party", "licence", "version"];

/// The largest configuration accepted, in bytes.
pub const MAX_CONFIG_LEN: usize = 4096;

fn hex16(text: &str, member: &'static str) -> Result<[u8; 16], ConfigError> {
    let bytes = text.as_bytes();
    if bytes.len() != 32 {
        return Err(ConfigError::Invalid(member));
    }
    let mut out = [0u8; 16];
    for (i, pair) in bytes.chunks_exact(2).enumerate() {
        let hi = nibble(pair.first().copied()).ok_or(ConfigError::Invalid(member))?;
        let lo = nibble(pair.get(1).copied()).ok_or(ConfigError::Invalid(member))?;
        let slot = out.get_mut(i).ok_or(ConfigError::Invalid(member))?;
        *slot = (hi << 4) | lo;
    }
    Ok(out)
}

fn nibble(b: Option<u8>) -> Option<u8> {
    match b? {
        c @ b'0'..=b'9' => Some(c.wrapping_sub(b'0')),
        c @ b'a'..=b'f' => Some(c.wrapping_sub(b'a').wrapping_add(10)),
        _ => None,
    }
}

/// Decodes and checks a configuration.
///
/// # Errors
///
/// [`ConfigError`] for any input that is not a valid configuration. A
/// self-hosted configuration with intermediary mode is refused with
/// [`ConfigError::IntermediaryWhenSelfHosted`].
pub fn decode(bytes: &[u8]) -> Result<CellConfig, ConfigError> {
    if bytes.len() > MAX_CONFIG_LEN {
        return Err(ConfigError::Invalid("length"));
    }
    let value = fstp_json::parse(bytes).map_err(|_| ConfigError::NotAnObject)?;
    let obj = value.as_object().ok_or(ConfigError::NotAnObject)?;
    for (name, _) in obj.iter() {
        if !MEMBERS.contains(&name) {
            return Err(ConfigError::UnknownMember);
        }
    }
    let text = |name: &'static str| -> Result<Option<&str>, ConfigError> {
        match obj.get(name) {
            None => Ok(None),
            Some(v) => v.as_str().map(Some).ok_or(ConfigError::Invalid(name)),
        }
    };
    let cell = text("cell")?.ok_or(ConfigError::MissingMember("cell"))?;
    let cell = CellId(hex16(cell, "cell")?);
    let mode = match text("mode")?.ok_or(ConfigError::MissingMember("mode"))? {
        "saas" => Mode::Saas,
        "self_hosted" => Mode::SelfHosted,
        _ => return Err(ConfigError::Invalid("mode")),
    };
    let relying_party = match text("eudi_relying_party")? {
        None | Some("tenant_registration") => RelyingParty::TenantRegistration,
        Some("intermediary") => RelyingParty::Intermediary,
        Some(_) => return Err(ConfigError::Invalid("eudi_relying_party")),
    };
    let licence = text("licence")?
        .map(|t| hex16(t, "licence").map(LicenceId))
        .transpose()?;
    let version = text("version")?.ok_or(ConfigError::MissingMember("version"))?;
    let version =
        ProductVersion::parse(version.as_bytes()).ok_or(ConfigError::Invalid("version"))?;
    match (mode, relying_party, licence) {
        (Mode::SelfHosted, RelyingParty::Intermediary, _) => {
            Err(ConfigError::IntermediaryWhenSelfHosted)
        }
        (Mode::Saas, _, Some(_)) => Err(ConfigError::LicenceWhenSaas),
        _ => Ok(CellConfig {
            cell,
            mode,
            relying_party,
            licence,
            version,
        }),
    }
}

// ---------------------------------------------------------------------------
// The configuration file of `fstp-cell` (ADR-026 "Configuration", lane L4).
//
// One JSON object with a closed member set. It names every part of
// `crate::process::CellProcessParts` that is not a secret, and the
// credentials directory that holds the secrets by fixed name.
//
// ```text
// {"assets_dir": "/opt/fstp/web",                                   optional
//  "cell": "<32 hex>", "credentials_dir": "/etc/fstp/cell",
//  "checks": {"forge_hosts": ["codeberg.org"]},                       optional
//  "database": {"dbname": "c_<32 hex>", "host": "db.internal", "port": 5432},
//  "eudi_relying_party": "tenant_registration",                     optional
//  "host": "grants.example.eu",
//  "host_status": "/var/lib/fstp/status/host.json",                  optional
//  "key_file_keyd_socket": "/run/fstp-keyd/cell-keys.sock",
//  "keyd_socket": "/run/fstp-keyd/cell.sock",
//  "licence": "<32 hex>",                                          self-hosted only
//  "listen": {"health": "127.0.0.1:9090", "internal": "0.0.0.0:7444",
//             "tunnel": "0.0.0.0:7443"},
//  "mail": {"address": "127.0.0.1:2465", "relay": "smtp.example.eu",
//           "sender": "noreply@example.eu", "username": "cell"},     optional
//  "mode": "saas",
//  "object_store": {"bucket": "fstp-pilot", "endpoint": "s3.gra.io.cloud.ovh.net",
//                   "region": "gra"},                              optional
//  "registered_servers": [{"kind": "application", "spki_sha256": "<64 hex>"}],
//  "vault": {"address": "127.0.0.1:4100"},
//  "version": "0.3.0",
//  "witness": {"address": "10.0.0.5:7443", "ca_spki_sha256": "<64 hex>",
//              "server_name": "witness.internal"}}
// ```

use std::net::SocketAddr;
use std::path::PathBuf;

use fstp_json::{Object, ParseLimits, Value};

/// The largest configuration file accepted, in bytes.
pub const MAX_FILE_LEN: usize = 8192;

/// The longest path the file names, in bytes.
pub const MAX_PATH_LEN: usize = 1024;

/// The most registered server keys the file names.
pub const MAX_REGISTERED: usize = 32;

/// The most forge hosts `checks.forge_hosts` names (ADR-026 section of
/// lane `m10/checks-runner`).
pub const MAX_FORGE_HOSTS: usize = 16;

/// The most witness receipt keys `witness-receipt-keys` holds.
pub const MAX_RECEIPT_KEYS: usize = 8;

/// The longest encoded witness receipt key, in bytes.
pub const MAX_RECEIPT_KEY_LEN: usize = 4096;

const FILE_MEMBERS: [&str; 20] = [
    "assets_dir",
    "cell",
    "checks",
    "credentials_dir",
    "database",
    "eudi_relying_party",
    "host",
    "host_status",
    "key_file_keyd_socket",
    "keyd_socket",
    "licence",
    "listen",
    "mail",
    "mode",
    "object_store",
    "object_stores",
    "registered_servers",
    "shell",
    "vault",
    "version",
    "witness",
];

const CORE_MEMBERS: [&str; 5] = ["cell", "mode", "eudi_relying_party", "licence", "version"];

/// The cluster kind a server key was registered for (`cp.cluster`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerKind {
    /// An application cluster.
    Application,
    /// A vault cluster.
    Vault,
    /// A control plane cluster.
    Control,
    /// A witness cluster.
    Witness,
}

/// One registered cluster server key (design section 9.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegisteredServer {
    /// SHA-256 over the server certificate's SubjectPublicKeyInfo DER.
    pub spki_sha256: [u8; 32],
    /// The kind of cluster it was registered for.
    pub kind: ServerKind,
}

/// The cell database (design section 4.7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DatabaseConfig {
    /// The server host.
    pub host: String,
    /// The server port.
    pub port: u16,
    /// The database name: `c_<cell>`.
    pub dbname: String,
}

/// The witness of the App chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessConfig {
    /// Where it listens.
    pub address: SocketAddr,
    /// The name its server certificate carries.
    pub server_name: String,
    /// SHA-256 over the witness CA's SubjectPublicKeyInfo DER.
    pub ca_spki_sha256: [u8; 32],
}

/// The vault's internal listener. Its certificate names the address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VaultConfig {
    /// Where it listens.
    pub address: SocketAddr,
}

/// Where the cell listens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListenConfig {
    /// The tunnel listener, which the edge reaches.
    pub tunnel: SocketAddr,
    /// The internal mutual TLS listener.
    pub internal: SocketAddr,
    /// The health listener, on loopback only.
    pub health: SocketAddr,
}

/// The platform submission relay (D3, ADR-018 amendment of 2026-11-20).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MailConfig {
    /// The relay host, which its certificate must name.
    pub relay: String,
    /// The envelope and `From` sender.
    pub sender: String,
    /// The AUTH PLAIN user. The password is `mail.password`.
    pub username: String,
    /// The pinned relay address, in place of a DNS lookup (interim,
    /// pending Daniel).
    pub address: Option<SocketAddr>,
}

/// The settings of the creator shell of a configured cell (ADR-027, wave 2
/// merge). The probes take the relay host from `mail.relay` and its CA from
/// `mail-ca.pem`, so the sending domain probe checks the relay the cell
/// submits to.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ShellConfig {
    /// The DNS resolver of the sending domain probe, TCP.
    pub resolver: Option<SocketAddr>,
    /// The sending domain, a host name.
    pub sending_domain: Option<String>,
    /// The DKIM selector of the sending domain.
    pub dkim_selector: Option<String>,
    /// The `https:` address applicants create an account on.
    pub platform_url: Option<String>,
}

/// Whether `s` is a DKIM selector: dot-separated LDH labels of 1 to 63
/// bytes, at most 253 bytes.
fn is_selector(s: &str) -> bool {
    (1..=253).contains(&s.len())
        && s.split('.').all(|l| {
            (1..=63).contains(&l.len())
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

/// Whether `s` is a platform address: `https://`, a host name, and an
/// optional path of visible ASCII, at most 512 bytes.
fn is_platform_url(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("https://") else {
        return false;
    };
    let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
    s.len() <= 512 && is_host_name(host) && path.bytes().all(|b| b.is_ascii_graphic())
}

/// The settings of the payment checks runner of a configured cell
/// (ADR-026 section of lane `m10/checks-runner`, ADR-009 amendment of
/// 2026-11-24, interim, pending Daniel).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChecksConfig {
    /// The forge allowlist: the hosts whose deliverables the checks fetch,
    /// over https to public addresses only. Empty refuses every fetch, so
    /// the checks fail closed.
    pub forge_hosts: Vec<String>,
}

fn checks_of(o: &Object) -> Result<ChecksConfig, ConfigError> {
    members(o, &["forge_hosts"], "checks")?;
    let Some(list) = o.get("forge_hosts") else {
        return Ok(ChecksConfig::default());
    };
    let list = list
        .as_array()
        .ok_or(ConfigError::Invalid("checks.forge_hosts"))?;
    if list.len() > MAX_FORGE_HOSTS {
        return Err(ConfigError::Invalid("checks.forge_hosts"));
    }
    let mut forge_hosts: Vec<String> = Vec::with_capacity(list.len());
    for v in list.iter() {
        let h = v
            .as_str()
            .ok_or(ConfigError::Invalid("checks.forge_hosts"))?;
        if !is_host_name(h)
            || crate::egress::is_crabnebula_host(h)
            || forge_hosts.iter().any(|x| x == h)
        {
            return Err(ConfigError::Invalid("checks.forge_hosts"));
        }
        forge_hosts.push(h.to_owned());
    }
    Ok(ChecksConfig { forge_hosts })
}

fn shell_of(o: &Object) -> Result<ShellConfig, ConfigError> {
    members(
        o,
        &[
            "dkim_selector",
            "platform_url",
            "resolver",
            "sending_domain",
        ],
        "shell",
    )?;
    let opt = |name: &'static str| -> Result<Option<&str>, ConfigError> {
        o.get(name)
            .map(|v| v.as_str().ok_or(ConfigError::Invalid(name)))
            .transpose()
    };
    let resolver = opt("resolver")?
        .map(|s| addr_of(s, "shell.resolver"))
        .transpose()?;
    let sending_domain = opt("sending_domain")?;
    if sending_domain.is_some_and(|d| !is_host_name(d)) {
        return Err(ConfigError::Invalid("shell.sending_domain"));
    }
    let dkim_selector = opt("dkim_selector")?;
    if dkim_selector.is_some_and(|d| !is_selector(d)) {
        return Err(ConfigError::Invalid("shell.dkim_selector"));
    }
    let platform_url = opt("platform_url")?;
    if platform_url.is_some_and(|u| !is_platform_url(u)) {
        return Err(ConfigError::Invalid("shell.platform_url"));
    }
    Ok(ShellConfig {
        resolver,
        sending_domain: sending_domain.map(str::to_owned),
        dkim_selector: dkim_selector.map(str::to_owned),
        platform_url: platform_url.map(str::to_owned),
    })
}

/// The configuration file of one cell process (ADR-026).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileConfig {
    /// The core members, which name the one cell (I-19).
    pub core: CellConfig,
    /// The cell host: the relying party id and the origin host.
    pub host: String,
    /// The credentials directory.
    pub credentials_dir: PathBuf,
    /// The compiled web assets, if any.
    pub assets_dir: Option<PathBuf>,
    /// The host status file `fstp-admin` writes, which the System page
    /// reads (ADR-028 record of lane L20), if any.
    pub host_status: Option<PathBuf>,
    /// The cell database.
    pub database: DatabaseConfig,
    /// The registered cluster server keys.
    pub registered_servers: Vec<RegisteredServer>,
    /// The cell's own `fstp-keyd` socket: the App chain.
    pub keyd_socket: PathBuf,
    /// The dedicated `fstp-keyd` socket of the cell key file root.
    pub key_file_keyd_socket: PathBuf,
    /// The witness.
    pub witness: WitnessConfig,
    /// The vault.
    pub vault: VaultConfig,
    /// The listeners.
    pub listen: ListenConfig,
    /// The platform relay, if any.
    pub mail: Option<MailConfig>,
    /// The creator shell's settings (ADR-027), if any.
    pub shell: Option<ShellConfig>,
    /// The payment checks runner's settings (ADR-026 section of lane
    /// `m10/checks-runner`), if any. Absent is an empty forge allowlist.
    pub checks: Option<ChecksConfig>,
    /// The object store of the App chain's keystore snapshots, if one is
    /// configured (ADR-012 record of lane L17), in the shape `fstp-backup`
    /// uses.
    pub object_store: Option<fstp_backup::s3::Endpoint>,
    /// The further stores of `object_stores`, after the first, in order
    /// (ADR-012 record of lane m10/backup-followups, row "Every store").
    pub more_stores: Vec<fstp_backup::s3::Endpoint>,
}

fn file_limits() -> ParseLimits {
    ParseLimits::default()
        .with_max_input_bytes(MAX_FILE_LEN)
        .with_max_depth(3)
        .with_max_container_len(MAX_REGISTERED)
        .with_max_string_bytes(MAX_PATH_LEN)
}

/// Whether `name` is a host name: lowercase letters, digits and hyphens in
/// dot-separated labels of 1 to 63 bytes, at least two labels, at most 253
/// bytes, with a last label that is not all digits.
#[must_use]
pub fn is_host_name(name: &str) -> bool {
    let label_ok = |l: &str| {
        (1..=63).contains(&l.len())
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    (1..=253).contains(&name.len())
        && name.contains('.')
        && name.split('.').all(label_ok)
        && name
            .rsplit('.')
            .next()
            .is_some_and(|l| !l.bytes().all(|b| b.is_ascii_digit()))
}

fn members(o: &Object, allowed: &[&str], rule: &'static str) -> Result<(), ConfigError> {
    if o.keys().any(|k| k.is_empty() || !allowed.contains(&k)) {
        return Err(ConfigError::Invalid(rule));
    }
    Ok(())
}

fn text<'a>(o: &'a Object, name: &str, rule: &'static str) -> Result<&'a str, ConfigError> {
    o.get(name)
        .ok_or(ConfigError::MissingMember(rule))?
        .as_str()
        .ok_or(ConfigError::Invalid(rule))
}

fn object<'a>(o: &'a Object, name: &str, rule: &'static str) -> Result<&'a Object, ConfigError> {
    o.get(name)
        .ok_or(ConfigError::MissingMember(rule))?
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
    s.parse::<SocketAddr>()
        .map_err(|_| ConfigError::Invalid(rule))
}

fn hex32(s: &str, rule: &'static str) -> Result<[u8; 32], ConfigError> {
    let bytes = s.as_bytes();
    if bytes.len() != 64 {
        return Err(ConfigError::Invalid(rule));
    }
    let mut out = [0u8; 32];
    for (slot, pair) in out.iter_mut().zip(bytes.chunks_exact(2)) {
        let hi = nibble(pair.first().copied()).ok_or(ConfigError::Invalid(rule))?;
        let lo = nibble(pair.get(1).copied()).ok_or(ConfigError::Invalid(rule))?;
        *slot = (hi << 4) | lo;
    }
    Ok(out)
}

/// The lowercase hex digit of the low four bits of `n`.
fn hex_digit(n: u8) -> u8 {
    b"0123456789abcdef"
        .get(usize::from(n & 0xf))
        .copied()
        .unwrap_or(b'0')
}

/// The database name of `cell`: `c_<32 hex>` (design section 4.7).
#[must_use]
pub fn database_name(cell: &CellId) -> String {
    let mut s = String::from("c_");
    for b in cell.0 {
        s.push(char::from(hex_digit(b >> 4)));
        s.push(char::from(hex_digit(b)));
    }
    s
}

/// Decodes and checks a configuration file (module documentation,
/// ADR-026). Fuzzed (`cell_config_decode`).
///
/// # Errors
///
/// [`ConfigError`] naming the rule broken. It never quotes the input
/// (R-NF-02).
pub fn decode_file(bytes: &[u8]) -> Result<FileConfig, ConfigError> {
    if bytes.len() > MAX_FILE_LEN {
        return Err(ConfigError::Invalid("length"));
    }
    let value =
        fstp_json::parse_with(bytes, &file_limits()).map_err(|_| ConfigError::NotAnObject)?;
    let o = value.as_object().ok_or(ConfigError::NotAnObject)?;
    if o.keys().any(|k| k.is_empty() || !FILE_MEMBERS.contains(&k)) {
        return Err(ConfigError::UnknownMember);
    }
    // The core members go through the M3 decoder, so the I-38 and B12
    // rules hold for the file as for the core form.
    let mut core = Object::new();
    for name in CORE_MEMBERS {
        if let Some(v) = o.get(name) {
            core.insert(name, v.clone());
        }
    }
    let core = decode(fstp_json::to_compact(&Value::Object(core)).as_bytes())?;
    let host = text(o, "host", "host")?;
    if !is_host_name(host) {
        return Err(ConfigError::Invalid("host"));
    }
    let credentials_dir = path_of(
        text(o, "credentials_dir", "credentials_dir")?,
        "credentials_dir",
    )?;
    let assets_dir = match o.get("assets_dir") {
        None => None,
        Some(v) => Some(path_of(
            v.as_str().ok_or(ConfigError::Invalid("assets_dir"))?,
            "assets_dir",
        )?),
    };
    let host_status = match o.get("host_status") {
        None => None,
        Some(v) => Some(path_of(
            v.as_str().ok_or(ConfigError::Invalid("host_status"))?,
            "host_status",
        )?),
    };
    let db = object(o, "database", "database")?;
    members(db, &["dbname", "host", "port"], "database")?;
    let db_host = text(db, "host", "database.host")?;
    if db_host.is_empty() || db_host.len() > 253 || !db_host.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(ConfigError::Invalid("database.host"));
    }
    let port = db
        .get("port")
        .ok_or(ConfigError::MissingMember("database.port"))?
        .as_u64()
        .and_then(|p| u16::try_from(p).ok())
        .filter(|p| *p != 0)
        .ok_or(ConfigError::Invalid("database.port"))?;
    let dbname = text(db, "dbname", "database.dbname")?;
    // I-19, I-83: the one application database of the one cell. A vault
    // database `v_<cell>` or another cell's database is refused here,
    // before the start check reads the placement marker.
    if dbname != database_name(&core.cell) {
        return Err(ConfigError::Invalid("database.dbname"));
    }
    let database = DatabaseConfig {
        host: db_host.to_owned(),
        port,
        dbname: dbname.to_owned(),
    };
    let list = o
        .get("registered_servers")
        .ok_or(ConfigError::MissingMember("registered_servers"))?
        .as_array()
        .ok_or(ConfigError::Invalid("registered_servers"))?;
    if list.is_empty() || list.len() > MAX_REGISTERED {
        return Err(ConfigError::Invalid("registered_servers"));
    }
    let mut registered_servers = Vec::with_capacity(list.len());
    for item in list.iter() {
        let r = item
            .as_object()
            .ok_or(ConfigError::Invalid("registered_servers"))?;
        members(r, &["kind", "spki_sha256"], "registered_servers")?;
        let kind = match text(r, "kind", "registered_servers.kind")? {
            "application" => ServerKind::Application,
            "vault" => ServerKind::Vault,
            "control" => ServerKind::Control,
            "witness" => ServerKind::Witness,
            _ => return Err(ConfigError::Invalid("registered_servers.kind")),
        };
        let spki_sha256 = hex32(
            text(r, "spki_sha256", "registered_servers.spki_sha256")?,
            "registered_servers.spki_sha256",
        )?;
        registered_servers.push(RegisteredServer { spki_sha256, kind });
    }
    let keyd_socket = path_of(text(o, "keyd_socket", "keyd_socket")?, "keyd_socket")?;
    let key_file_keyd_socket = path_of(
        text(o, "key_file_keyd_socket", "key_file_keyd_socket")?,
        "key_file_keyd_socket",
    )?;
    // ADR-004 record of lane L4: the key file root has its own entry.
    if key_file_keyd_socket == keyd_socket {
        return Err(ConfigError::Invalid("key_file_keyd_socket"));
    }
    let w = object(o, "witness", "witness")?;
    members(w, &["address", "ca_spki_sha256", "server_name"], "witness")?;
    let server_name = text(w, "server_name", "witness.server_name")?;
    if !is_host_name(server_name) {
        return Err(ConfigError::Invalid("witness.server_name"));
    }
    let witness = WitnessConfig {
        address: addr_of(text(w, "address", "witness.address")?, "witness.address")?,
        server_name: server_name.to_owned(),
        ca_spki_sha256: hex32(
            text(w, "ca_spki_sha256", "witness.ca_spki_sha256")?,
            "witness.ca_spki_sha256",
        )?,
    };
    let v = object(o, "vault", "vault")?;
    members(v, &["address"], "vault")?;
    let vault = VaultConfig {
        address: addr_of(text(v, "address", "vault.address")?, "vault.address")?,
    };
    let l = object(o, "listen", "listen")?;
    members(l, &["health", "internal", "tunnel"], "listen")?;
    let listen = ListenConfig {
        tunnel: addr_of(text(l, "tunnel", "listen.tunnel")?, "listen.tunnel")?,
        internal: addr_of(text(l, "internal", "listen.internal")?, "listen.internal")?,
        health: addr_of(text(l, "health", "listen.health")?, "listen.health")?,
    };
    // Design section 2.3: the health listener serves loopback only.
    if !listen.health.ip().is_loopback() {
        return Err(ConfigError::Invalid("listen.health"));
    }
    let mail = match o.get("mail") {
        None => None,
        Some(m) => {
            let m = m.as_object().ok_or(ConfigError::Invalid("mail"))?;
            members(m, &["address", "relay", "sender", "username"], "mail")?;
            let relay = text(m, "relay", "mail.relay")?;
            crate::egress::MailHost::parse(relay)
                .map_err(|_| ConfigError::Invalid("mail.relay"))?;
            let sender = text(m, "sender", "mail.sender")?;
            if !fstp_smtp::command::valid_mailbox(sender) {
                return Err(ConfigError::Invalid("mail.sender"));
            }
            let username = text(m, "username", "mail.username")?;
            if fstp_smtp::client::Credentials::try_new(username, "x").is_err() {
                return Err(ConfigError::Invalid("mail.username"));
            }
            let address = match m.get("address") {
                None => None,
                Some(a) => Some(addr_of(
                    a.as_str().ok_or(ConfigError::Invalid("mail.address"))?,
                    "mail.address",
                )?),
            };
            Some(MailConfig {
                relay: relay.to_owned(),
                sender: sender.to_owned(),
                username: username.to_owned(),
                address,
            })
        }
    };
    let shell = match o.get("shell") {
        None => None,
        Some(v) => Some(shell_of(
            v.as_object().ok_or(ConfigError::Invalid("shell"))?,
        )?),
    };
    let checks = match o.get("checks") {
        None => None,
        Some(v) => Some(checks_of(
            v.as_object().ok_or(ConfigError::Invalid("checks"))?,
        )?),
    };
    // ADR-012 record of lane m10/backup-followups: `object_store`, or
    // `object_stores` in order, never both.
    let (object_store, more_stores) = match fstp_backup::config::decode_stores(o) {
        Ok(None) => (None, Vec::new()),
        Ok(Some(mut s)) => {
            let first = s.remove(0);
            (Some(first), s)
        }
        Err(_) if o.get("object_store").is_none() => {
            return Err(ConfigError::Invalid("object_stores"));
        }
        Err(_) => return Err(ConfigError::Invalid("object_store")),
    };
    Ok(FileConfig {
        core,
        host: host.to_owned(),
        credentials_dir,
        assets_dir,
        host_status,
        database,
        registered_servers,
        keyd_socket,
        key_file_keyd_socket,
        witness,
        vault,
        listen,
        mail,
        shell,
        checks,
        object_store,
        more_stores,
    })
}

/// Decodes `witness-receipt-keys`: one encoded receipt public key per
/// line, in lowercase hex, each line ended by `\n`. Fuzzed
/// (`cell_config_decode`).
///
/// # Errors
///
/// [`ConfigError::Invalid`] for no key, more than [`MAX_RECEIPT_KEYS`],
/// a key longer than [`MAX_RECEIPT_KEY_LEN`], an odd or empty line, a byte
/// that is not lowercase hex, or a last line without its end.
pub fn decode_receipt_keys(bytes: &[u8]) -> Result<Vec<Vec<u8>>, ConfigError> {
    const RULE: ConfigError = ConfigError::Invalid("witness-receipt-keys");
    let body = bytes.strip_suffix(b"\n").ok_or(RULE)?;
    let mut keys = Vec::new();
    for line in body.split(|b| *b == b'\n') {
        if line.is_empty() || line.len() % 2 != 0 || line.len() > MAX_RECEIPT_KEY_LEN * 2 {
            return Err(RULE);
        }
        if keys.len() >= MAX_RECEIPT_KEYS {
            return Err(RULE);
        }
        let mut key = Vec::with_capacity(line.len() / 2);
        for pair in line.chunks_exact(2) {
            let hi = nibble(pair.first().copied()).ok_or(RULE)?;
            let lo = nibble(pair.get(1).copied()).ok_or(RULE)?;
            key.push((hi << 4) | lo);
        }
        keys.push(key);
    }
    Ok(keys)
}

/// Encodes `keys` in the form [`decode_receipt_keys`] reads.
#[must_use]
pub fn encode_receipt_keys(keys: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for k in keys {
        for b in k {
            out.push(hex_digit(b >> 4));
            out.push(hex_digit(*b));
        }
        out.push(b'\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const CELL: &str = "000102030405060708090a0b0c0d0e0f";

    fn cfg(extra: &str) -> Vec<u8> {
        format!("{{\"cell\":\"{CELL}\",\"version\":\"0.3.0\",{extra}}}").into_bytes()
    }

    /// I-38: a self-hosted configuration with intermediary mode is refused
    /// at decode, and the same one without it decodes.
    #[test]
    fn i38_config_refuses_intermediary_mode_when_self_hosted() {
        let lic = "\"licence\":\"5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a\"";
        let bad = cfg(&format!(
            "\"mode\":\"self_hosted\",{lic},\"eudi_relying_party\":\"intermediary\""
        ));
        assert_eq!(decode(&bad), Err(ConfigError::IntermediaryWhenSelfHosted));
        let good = cfg(&format!("\"mode\":\"self_hosted\",{lic}"));
        assert_eq!(decode(&good).map(|c| c.mode), Ok(Mode::SelfHosted));
    }

    /// I-39, design section 10.2 (Q41): a self-hosted cell starts before
    /// its holder registers, so its configuration decodes without a
    /// licence. The licence comes from the first token it imports.
    #[test]
    fn i39_config_accepts_a_self_hosted_cell_before_its_first_token() {
        let c = decode(&cfg("\"mode\":\"self_hosted\""));
        assert_eq!(c.map(|c| (c.mode, c.licence)), Ok((Mode::SelfHosted, None)));
    }

    /// B12: a SaaS cell holds no licence, and an unknown member or a bad
    /// cell id is refused.
    #[test]
    fn i38_config_refuses_a_licence_on_saas_and_unknown_members() {
        let lic = "\"licence\":\"5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a\"";
        assert_eq!(
            decode(&cfg(&format!("\"mode\":\"saas\",{lic}"))),
            Err(ConfigError::LicenceWhenSaas)
        );
        assert_eq!(
            decode(&cfg("\"mode\":\"saas\",\"x\":1")),
            Err(ConfigError::UnknownMember)
        );
        assert_eq!(
            decode(b"{\"cell\":\"00\",\"mode\":\"saas\",\"version\":\"0.3.0\"}"),
            Err(ConfigError::Invalid("cell"))
        );
        assert_eq!(
            decode(&cfg("\"mode\":\"saas\"")).map(|c| c.cell.0[15]),
            Ok(15)
        );
    }
}

#[cfg(test)]
pub(crate) use file_tests::file as tests_file;

#[cfg(test)]
mod file_tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;

    const CELL: &str = "000102030405060708090a0b0c0d0e0f";

    /// A complete SaaS configuration file, with `extra` members added.
    pub(crate) fn file(extra: &str) -> String {
        let spki = "ab".repeat(32);
        format!(
            r#"{{"cell":"{CELL}","credentials_dir":"/etc/fstp/cell","database":{{"dbname":"c_{CELL}","host":"db.internal","port":5432}},"host":"grants.example.test","key_file_keyd_socket":"/run/fstp-keyd/cell-keys.sock","keyd_socket":"/run/fstp-keyd/cell.sock","listen":{{"health":"127.0.0.1:9090","internal":"0.0.0.0:7444","tunnel":"0.0.0.0:7443"}},"mode":"saas","registered_servers":[{{"kind":"application","spki_sha256":"{spki}"}}],"vault":{{"address":"127.0.0.1:4100"}},"version":"0.3.0","witness":{{"address":"10.0.0.5:7443","ca_spki_sha256":"{spki}","server_name":"witness.internal"}}{extra}}}"#
        )
    }

    /// ADR-012 record of lane L17: `object_store` is optional, absent by
    /// default, and decodes in the shape `fstp-backup` uses. A malformed
    /// one is refused by name.
    #[test]
    fn adr012_cell_config_takes_an_optional_object_store() {
        assert_eq!(decode_file(file("").as_bytes()).unwrap().object_store, None);
        let c = decode_file(
            file(r#","object_store":{"bucket":"fstp-pilot","endpoint":"s3.gra.io.cloud.ovh.net","port":8443,"region":"gra"}"#)
                .as_bytes(),
        )
        .unwrap();
        let os = c.object_store.unwrap();
        assert_eq!((os.bucket.as_str(), os.port), ("fstp-pilot", 8443));
        for bad in [
            r#","object_store":{"bucket":"fstp-pilot","region":"gra"}"#,
            r#","object_store":{"bucket":"fstp-pilot","endpoint":"s3.gra.io.cloud.ovh.net","region":"gra","x":1}"#,
            r#","object_store":"s3""#,
        ] {
            assert_eq!(
                decode_file(file(bad).as_bytes()),
                Err(ConfigError::Invalid("object_store")),
                "{bad}"
            );
        }
    }

    /// Q25, ADR-012 record of lane m10/backup-followups, row "Every store":
    /// `object_stores` lists one to three stores in order, the first in
    /// `object_store`, the rest in `more_stores`. Both members together,
    /// an empty list and four stores are refused by name.
    #[test]
    fn adr012_bf_cell_config_takes_a_list_of_stores() {
        let one = r#"{"bucket":"fstp-pilot","endpoint":"s3.gra.io.cloud.ovh.net","region":"gra"}"#;
        let two = r#"{"bucket":"fstp-copy","endpoint":"s3.fr-par.scw.cloud","region":"fr-par"}"#;
        let c =
            decode_file(file(&format!(r#","object_stores":[{one},{two}]"#)).as_bytes()).unwrap();
        assert_eq!(c.object_store.unwrap().bucket, "fstp-pilot");
        assert_eq!(c.more_stores.len(), 1);
        assert_eq!(c.more_stores[0].bucket, "fstp-copy");
        let single = decode_file(file(&format!(r#","object_store":{one}"#)).as_bytes()).unwrap();
        assert!(single.more_stores.is_empty());
        assert!(
            decode_file(file("").as_bytes())
                .unwrap()
                .more_stores
                .is_empty()
        );
        for (bad, rule) in [
            (
                format!(r#","object_store":{one},"object_stores":[{two}]"#),
                "object_store",
            ),
            (r#","object_stores":[]"#.to_owned(), "object_stores"),
            (
                format!(r#","object_stores":[{one},{one},{one},{one}]"#),
                "object_stores",
            ),
        ] {
            assert_eq!(
                decode_file(file(&bad).as_bytes()),
                Err(ConfigError::Invalid(rule)),
                "{bad}"
            );
        }
    }

    /// ADR-026: the full grammar decodes, with and without its optional
    /// members, and the core members keep their M3 meaning.
    #[test]
    fn adr026_config_file_decodes_every_member() {
        let c = decode_file(file("").as_bytes()).unwrap();
        assert_eq!(c.core.mode, Mode::Saas);
        assert_eq!(c.database.port, 5432);
        assert!(c.mail.is_none() && c.assets_dir.is_none());
        let full = file(
            r#","assets_dir":"/opt/fstp/web","mail":{"address":"127.0.0.1:2465","relay":"smtp.example.test","sender":"noreply@example.test","username":"cell"}"#,
        );
        let c = decode_file(full.as_bytes()).unwrap();
        assert_eq!(
            c.mail.unwrap().address,
            Some("127.0.0.1:2465".parse().unwrap())
        );
    }

    /// ADR-028 record of lane L20: the optional member `host_status` names
    /// the host status file by an absolute path, and anything else is
    /// refused.
    #[test]
    fn adr028_l20_config_takes_host_status() {
        assert!(
            decode_file(file("").as_bytes())
                .unwrap()
                .host_status
                .is_none()
        );
        let c = decode_file(file(r#","host_status":"/var/lib/fstp/status/host.json""#).as_bytes())
            .unwrap();
        assert_eq!(
            c.host_status,
            Some(PathBuf::from("/var/lib/fstp/status/host.json"))
        );
        for bad in [r#""status/host.json""#, "1", "null", r#""""#] {
            assert_eq!(
                decode_file(file(&format!(r#","host_status":{bad}"#)).as_bytes()).err(),
                Some(ConfigError::Invalid("host_status")),
                "{bad}"
            );
        }
    }

    /// ADR-021, ADR-026 record of lane L18 (Daniel, 2026-11-21: "Build
    /// onboarding, then drop flag"): the member `organisation_active` is
    /// gone. A file that names it is refused as an unknown member, so no
    /// configuration activates an organisation the ledger did not.
    #[test]
    fn adr021_config_refuses_organisation_active() {
        for v in ["true", "false"] {
            let f = file(&format!(r#","organisation_active":{v}"#));
            assert!(
                decode_file(f.as_bytes()).is_err(),
                "organisation_active {v}"
            );
        }
    }

    /// I-19: the file names exactly one cell. The cell member is one id,
    /// not a list, the database is that cell's own, and a second cell
    /// member is refused.
    #[test]
    fn i19_config_names_one_cell() {
        let list = file("").replace(
            &format!(r#""cell":"{CELL}""#),
            &format!(r#""cell":["{CELL}","{CELL}"]"#),
        );
        assert!(decode_file(list.as_bytes()).is_err());
        let other = file("").replace(&format!("c_{CELL}"), "c_ffffffffffffffffffffffffffffffff");
        assert_eq!(
            decode_file(other.as_bytes()),
            Err(ConfigError::Invalid("database.dbname"))
        );
        let twice = file(&format!(r#","cell":"{CELL}""#));
        assert!(decode_file(twice.as_bytes()).is_err());
        let source = include_str!("config.rs");
        let fields = source
            .split("pub struct FileConfig {")
            .nth(1)
            .and_then(|s| s.split("\n}").next())
            .unwrap();
        assert_eq!(
            fields.matches("CellId").count(),
            0,
            "FileConfig names a second cell"
        );
        assert_eq!(fields.matches("CellConfig").count(), 1);
    }

    /// I-16, design section 14.4: no type of the configuration grammar
    /// holds a payment account, a debtor account or a bank detail.
    #[test]
    fn i16_config_types_hold_no_debtor_account() {
        let source = include_str!("config.rs");
        let code = source.split("#[cfg(test)]").next().unwrap();
        let mut structs = 0;
        for block in code.split("pub struct ").skip(1) {
            structs += 1;
            let body = block.split("\n}").next().unwrap().to_ascii_lowercase();
            for word in [
                "iban", "bic", "debtor", "creditor", "account", "payment", "bank",
            ] {
                let field_types: Vec<&str> = body
                    .lines()
                    .filter(|l| l.trim_start().starts_with("pub ") && l.contains(':'))
                    .collect();
                for f in field_types {
                    assert!(!f.contains(word), "a config field holds {word}: {f}");
                }
            }
        }
        assert!(structs >= 8, "the scan saw {structs} structs");
    }

    /// I-83: the file cannot name a vault database. `v_<cell>` is
    /// refused before any connection, and the start check refuses a vault
    /// cluster's server key on the live connection
    /// (`crate::process::check_database`).
    #[test]
    fn i83_config_start_refuses_a_vault_cluster() {
        let vault = file("").replace(&format!("\"c_{CELL}\""), &format!("\"v_{CELL}\""));
        assert_eq!(
            decode_file(vault.as_bytes()),
            Err(ConfigError::Invalid("database.dbname"))
        );
        let c = decode_file(file("").as_bytes()).unwrap();
        assert_eq!(c.database.dbname, format!("c_{CELL}"));
        assert_eq!(c.registered_servers[0].kind, ServerKind::Application);
    }

    /// ADR-026: an unknown member, an empty or relative path, two equal
    /// keyd sockets, a health listener off loopback, a bad relay and a
    /// file over the limit are refused.
    #[test]
    fn adr026_config_file_refuses_what_breaks_its_rules() {
        for (bad, rule) in [
            (file(r#","x":1"#), ConfigError::UnknownMember),
            (
                file("").replace("/etc/fstp/cell", "etc/fstp/cell"),
                ConfigError::Invalid("credentials_dir"),
            ),
            (
                file("").replace("cell-keys.sock", "cell.sock"),
                ConfigError::Invalid("key_file_keyd_socket"),
            ),
            (
                file("").replace("127.0.0.1:9090", "0.0.0.0:9090"),
                ConfigError::Invalid("listen.health"),
            ),
            (
                file(r#","mail":{"relay":"10.0.0.1","sender":"a@b.test","username":"u"}"#),
                ConfigError::Invalid("mail.relay"),
            ),
            (
                file(
                    r#","mail":{"relay":"smtp.crabnebula.dev","sender":"a@b.test","username":"u"}"#,
                ),
                ConfigError::Invalid("mail.relay"),
            ),
            (
                file("").replace("\"saas\"", "\"cloud\""),
                ConfigError::Invalid("mode"),
            ),
        ] {
            assert_eq!(decode_file(bad.as_bytes()), Err(rule), "{bad}");
        }
        let long = file(&format!(r#","assets_dir":"/{}""#, "a".repeat(MAX_FILE_LEN)));
        assert!(decode_file(long.as_bytes()).is_err());
    }

    /// ADR-010 "Keys": the receipt key list round-trips and refuses an
    /// empty list, a missing line end, odd or upper-case hex and too many
    /// keys.
    #[test]
    fn adr010_receipt_key_list_round_trips() {
        let keys = vec![vec![1u8, 2, 0xfe], vec![0xab; 40]];
        let bytes = encode_receipt_keys(&keys);
        assert_eq!(decode_receipt_keys(&bytes).unwrap(), keys);
        for bad in [&b""[..], b"\n", b"0102", b"010\n", b"0A\n", b"01\n\n02\n"] {
            assert!(decode_receipt_keys(bad).is_err(), "{bad:?}");
        }
        let many = encode_receipt_keys(&vec![vec![1u8]; MAX_RECEIPT_KEYS + 1]);
        assert!(decode_receipt_keys(&many).is_err());
    }
}

#[cfg(test)]
mod shell_tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    /// The file seed of `cell_config_decode` is an accepted file, so the
    /// fuzz properties of an accepted file run from the first input.
    #[test]
    fn adr026_fuzz_seed_file_decodes() {
        let seed = include_bytes!("../fuzz/seeds/cell_config_decode/file_saas");
        assert!(decode_file(seed).unwrap().shell.is_some());
    }

    /// ADR-027, wave 2 merge: the `shell` member takes the resolver, the
    /// sending domain, the DKIM selector and the platform address, each
    /// optional, and refuses any other member or a malformed value.
    #[test]
    fn adr027_config_shell_member_decodes_and_refuses() {
        let ok = tests_file(
            r#","shell":{"dkim_selector":"fstp1","platform_url":"https://grants.example.test/apply","resolver":"10.0.0.53:53","sending_domain":"calls.example.test"}"#,
        );
        let c = decode_file(ok.as_bytes()).unwrap().shell.unwrap();
        assert_eq!(c.resolver, Some("10.0.0.53:53".parse().unwrap()));
        assert_eq!(c.dkim_selector.as_deref(), Some("fstp1"));
        let empty = decode_file(tests_file(r#","shell":{}"#).as_bytes()).unwrap();
        assert_eq!(empty.shell, Some(ShellConfig::default()));
        for (bad, rule) in [
            (r#","shell":{"x":1}"#, ConfigError::Invalid("shell")),
            (
                r#","shell":{"resolver":"dns"}"#,
                ConfigError::Invalid("shell.resolver"),
            ),
            (
                r#","shell":{"sending_domain":"Calls.Example"}"#,
                ConfigError::Invalid("shell.sending_domain"),
            ),
            (
                r#","shell":{"dkim_selector":"-bad"}"#,
                ConfigError::Invalid("shell.dkim_selector"),
            ),
            (
                r#","shell":{"platform_url":"http://grants.example.test"}"#,
                ConfigError::Invalid("shell.platform_url"),
            ),
            (r#","shell":[]"#, ConfigError::Invalid("shell")),
        ] {
            assert_eq!(decode_file(tests_file(bad).as_bytes()), Err(rule), "{bad}");
        }
    }
}

#[cfg(test)]
mod checks_tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    /// ADR-026 section of lane `m10/checks-runner`, ADR-009 amendment of
    /// 2026-11-24, I-38: `checks.forge_hosts` names at most 16 distinct
    /// host names, never a CrabNebula host. Absent, the allowlist is empty.
    #[test]
    fn adr026_config_checks_member_names_the_forge_allowlist() {
        assert_eq!(decode_file(tests_file("").as_bytes()).unwrap().checks, None);
        let ok = tests_file(r#","checks":{"forge_hosts":["codeberg.org","forge.example.test"]}"#);
        let c = decode_file(ok.as_bytes()).unwrap().checks.unwrap();
        assert_eq!(c.forge_hosts, vec!["codeberg.org", "forge.example.test"]);
        let empty = decode_file(tests_file(r#","checks":{}"#).as_bytes()).unwrap();
        assert_eq!(empty.checks, Some(ChecksConfig::default()));
        let seventeen: Vec<String> = (0..17).map(|i| format!("\"f{i}.example\"")).collect();
        let many = format!(r#","checks":{{"forge_hosts":[{}]}}"#, seventeen.join(","));
        for (bad, rule) in [
            (r#","checks":{"x":1}"#.to_owned(), "checks"),
            (r#","checks":"codeberg.org""#.to_owned(), "checks"),
            (
                r#","checks":{"forge_hosts":"codeberg.org"}"#.to_owned(),
                "checks.forge_hosts",
            ),
            (
                r#","checks":{"forge_hosts":["Codeberg.org"]}"#.to_owned(),
                "checks.forge_hosts",
            ),
            (
                r#","checks":{"forge_hosts":["https://codeberg.org"]}"#.to_owned(),
                "checks.forge_hosts",
            ),
            (
                r#","checks":{"forge_hosts":["10.0.0.1"]}"#.to_owned(),
                "checks.forge_hosts",
            ),
            (
                r#","checks":{"forge_hosts":["a.example","a.example"]}"#.to_owned(),
                "checks.forge_hosts",
            ),
            (
                r#","checks":{"forge_hosts":["updates.fstp.crabnebula.dev"]}"#.to_owned(),
                "checks.forge_hosts",
            ),
            (many, "checks.forge_hosts"),
        ] {
            assert_eq!(
                decode_file(tests_file(&bad).as_bytes()),
                Err(ConfigError::Invalid(rule)),
                "{bad}"
            );
        }
        let seed = include_bytes!("../fuzz/seeds/cell_config_decode/file_checks");
        assert_eq!(
            decode_file(seed).unwrap().checks.unwrap().forge_hosts.len(),
            2
        );
    }
}
