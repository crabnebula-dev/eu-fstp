//! The one configuration file of a host, `/etc/fstp/fstp.json` (ADR-028
//! "One configuration file").
//!
//! Readable multi-line JSON, decoded by `fstp-json`. Few members are
//! required, and every other member has a default:
//!
//! ```text
//! {
//!   "domain": "grants.example.eu",                       required
//!   "operator_email": "admin@example.eu",                required
//!   "mail": {"relay": "smtp.example.eu",                 required
//!            "username": "cell",                         required
//!            "password_file": "/etc/fstp/mail.password",
//!            "sender": "noreply@grants.example.eu",
//!            "address": "192.0.2.7:465"},
//!   "tls": {"cert": "...fullchain.pem", "key": "...privkey.pem"},
//!   "backup": {"endpoint": "s3.gra.io.cloud.ovh.net", "region": "gra",
//!              "bucket": "fstp-backups", "port": 443},
//!   "paths": {"bin": "/usr/local/bin", "share": "/usr/share/fstp",
//!             "etc": "/etc/fstp", "state": "/var/lib/fstp",
//!             "pg_bin": "/usr/lib/postgresql/16/bin", "token_dir": "/root"},
//!   "ports": {"public": 443, "base": 7440},
//!   "services": "systemd",
//!   "custody_simulator": "/path/to/fstp-custody-sim",    direct only
//!   "agreements": "1,1,1",
//!   "version": "0.3.0"
//! }
//! ```
//!
//! Every refusal names the member and the fix ([`ConfigError`]). The
//! decoder is fuzzed (`admin_config_decode`).

use std::net::SocketAddr;
use std::path::PathBuf;

use fstp_json::{Object, Value};

/// The longest configuration file.
pub const MAX_CONFIG_LEN: usize = 16 * 1024;

/// The longest path.
pub const MAX_PATH_LEN: usize = 512;

/// The cell version the cell configuration names by default.
pub const DEFAULT_VERSION: &str = "0.3.0";

/// The agreement versions `provision-tenant` records by default.
pub const DEFAULT_AGREEMENTS: &str = "1,1,1";

/// How many ports above `ports.base` the host uses.
pub const PORT_SPAN: u16 = 10;

/// How the services run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Services {
    /// One systemd unit per service (production).
    Systemd,
    /// Processes started by `fstp-admin` itself, for a development machine
    /// and the end-to-end test. Needs `FSTP_DEPLOYMENT_MODE=development`.
    Direct,
}

/// The submission relay for proof mail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mail {
    /// The relay host name.
    pub relay: String,
    /// The AUTH user.
    pub username: String,
    /// The file that holds the relay password.
    pub password_file: PathBuf,
    /// The sender address.
    pub sender: String,
    /// A pinned socket address of the relay, if any.
    pub address: Option<SocketAddr>,
    /// A pinned CA of the relay, PEM, if any.
    pub ca_file: Option<PathBuf>,
}

/// The public origin certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tls {
    /// The certificate chain, PEM, for the domain and `id.<domain>`.
    pub cert: PathBuf,
    /// Its key, PEM.
    pub key: PathBuf,
}

/// The object store for backups.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Backup {
    /// The endpoint host name.
    pub endpoint: String,
    /// The region.
    pub region: String,
    /// The bucket.
    pub bucket: String,
    /// The port.
    pub port: u16,
    /// The file that holds the access key id.
    pub access_key_file: PathBuf,
    /// The file that holds the secret access key.
    pub secret_key_file: PathBuf,
}

/// The directories of the host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Paths {
    /// Where the binaries are.
    pub bin: PathBuf,
    /// Where the web assets and migrations are installed.
    pub share: PathBuf,
    /// Where configuration and credentials go.
    pub etc: PathBuf,
    /// Where state goes: databases, custody, the witness store, backups.
    pub state: PathBuf,
    /// The PostgreSQL 16 bin directory.
    pub pg_bin: PathBuf,
    /// Where the first admin's token file goes.
    pub token_dir: PathBuf,
}

/// The decoded configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostConfig {
    /// The tenant domain.
    pub domain: String,
    /// The first admin's email address. Never printed.
    pub operator_email: String,
    /// The mail relay.
    pub mail: Mail,
    /// The public origin certificate, if the admin has one.
    pub tls: Option<Tls>,
    /// The object store, if backups are set up.
    pub backup: Option<Backup>,
    /// The directories.
    pub paths: Paths,
    /// The public port of the edge.
    pub public_port: u16,
    /// The first of [`PORT_SPAN`] loopback ports.
    pub base_port: u16,
    /// How the services run.
    pub services: Services,
    /// The custody simulator, in direct mode only.
    pub custody_simulator: Option<PathBuf>,
    /// The versions of the SaaS terms, the data processing agreement and
    /// the sub-processor list the tenant accepted, for
    /// `fstp-cell provision-tenant --agreements` (ADR-026). Default `1,1,1`.
    pub agreements: String,
    /// The cell version.
    pub version: String,
    /// The second custodian that guards the key copies, as its host and
    /// port (ADR-028 record of lane `m10/guard-key`). `fstp-admin
    /// pair-custodian` writes it.
    pub custodian: Option<(String, u16)>,
}

/// What is wrong with a member.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Problem {
    /// The file is not a JSON object.
    NotJson,
    /// The file is longer than [`MAX_CONFIG_LEN`].
    TooLong,
    /// A required member is missing.
    Missing,
    /// A member the file may not have.
    Unknown,
    /// Not a text value.
    NotText,
    /// Not a whole number in range.
    NotNumber,
    /// Not `true` or `false`.
    NotBool,
    /// Not an object.
    NotObject,
    /// Not a lowercase DNS name.
    BadHost,
    /// Not an email address.
    BadEmail,
    /// Not an absolute path, or too long.
    NotAbsolute,
    /// A port of 0, or ports that collide.
    BadPort,
    /// Not an `ip:port` socket address.
    BadAddress,
    /// Not one of the allowed words.
    BadServices,
    /// `custody_simulator` without `"services": "direct"`.
    SimulatorNeedsDirect,
    /// Not a version `x.y.z`.
    BadVersion,
    /// `tls` without both `cert` and `key`.
    TlsNeedsBoth,
    /// Not three agreement versions like `1,1,1`.
    BadAgreements,
}

/// A refused configuration: the member, as a dotted path, and what is
/// wrong with it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigError {
    /// The member, for example `mail.relay`. An unknown member's name is
    /// cut to 40 printable ASCII characters.
    pub field: String,
    /// What is wrong.
    pub problem: Problem,
}

fn err<T>(field: &str, problem: Problem) -> Result<T, ConfigError> {
    Err(ConfigError {
        field: field.to_owned(),
        problem,
    })
}

/// A member name from the file, safe to print: printable ASCII only, at
/// most 40 characters.
fn printable(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_ascii_graphic())
        .take(40)
        .collect()
}

fn closed(obj: &Object, prefix: &str, members: &[&str]) -> Result<(), ConfigError> {
    for (name, _) in obj.iter() {
        if !members.contains(&name) {
            let field = if prefix.is_empty() {
                printable(name)
            } else {
                format!("{prefix}.{}", printable(name))
            };
            return err(&field, Problem::Unknown);
        }
    }
    Ok(())
}

fn text<'a>(obj: &'a Object, name: &str, field: &str) -> Result<Option<&'a str>, ConfigError> {
    match obj.get(name) {
        None => Ok(None),
        Some(v) => match v.as_str() {
            Some(s) => Ok(Some(s)),
            None => err(field, Problem::NotText),
        },
    }
}

fn required<'a>(obj: &'a Object, name: &str, field: &str) -> Result<&'a str, ConfigError> {
    match text(obj, name, field)? {
        Some(s) => Ok(s),
        None => err(field, Problem::Missing),
    }
}

fn object<'a>(obj: &'a Object, name: &str) -> Result<Option<&'a Object>, ConfigError> {
    match obj.get(name) {
        None => Ok(None),
        Some(v) => match v.as_object() {
            Some(o) => Ok(Some(o)),
            None => err(name, Problem::NotObject),
        },
    }
}

fn port(obj: &Object, name: &str, field: &str, default: u16) -> Result<u16, ConfigError> {
    match obj.get(name) {
        None => Ok(default),
        Some(v) => match v.as_u64().and_then(|n| u16::try_from(n).ok()) {
            Some(0) => err(field, Problem::BadPort),
            Some(p) => Ok(p),
            None => err(field, Problem::NotNumber),
        },
    }
}

fn path(
    obj: Option<&Object>,
    name: &str,
    field: &str,
    default: &str,
) -> Result<PathBuf, ConfigError> {
    let given = match obj {
        Some(o) => text(o, name, field)?,
        None => None,
    };
    let p = given.unwrap_or(default);
    if p.len() > MAX_PATH_LEN || !p.starts_with('/') || p.contains('\0') || p.contains('\n') {
        return err(field, Problem::NotAbsolute);
    }
    Ok(PathBuf::from(p))
}

fn optional_path(obj: &Object, name: &str, field: &str) -> Result<Option<PathBuf>, ConfigError> {
    match text(obj, name, field)? {
        None => Ok(None),
        Some(_) => path(Some(obj), name, field, "").map(Some),
    }
}

/// Whether `name` is a lowercase DNS name of at least two labels: letters,
/// digits and hyphens, no label starting or ending with a hyphen, at most
/// 253 characters.
#[must_use]
pub fn is_host_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = name.split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
        && labels
            .last()
            .is_some_and(|l| !l.bytes().all(|b| b.is_ascii_digit()))
}

/// Whether `addr` reads as an email address: one `@`, a local part of
/// printable ASCII without spaces, and a host name after it.
#[must_use]
pub fn is_email(addr: &str) -> bool {
    let Some((local, host)) = addr.split_once('@') else {
        return false;
    };
    addr.len() <= 254
        && !local.is_empty()
        && local.len() <= 64
        && local.bytes().all(|b| b.is_ascii_graphic() && b != b'@')
        && is_host_name(&host.to_ascii_lowercase())
}

/// Whether `a` is three agreement versions: whole numbers from 1, with
/// commas and no spaces.
fn is_agreements(a: &str) -> bool {
    let parts: Vec<&str> = a.split(',').collect();
    parts.len() == 3
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.len() <= 5
                && p.bytes().all(|b| b.is_ascii_digit())
                && !p.starts_with('0')
        })
}

fn is_version(v: &str) -> bool {
    let parts: Vec<&str> = v.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit()))
}

const TOP: [&str; 13] = [
    "backup",
    "custodian",
    "custody_simulator",
    "domain",
    "mail",
    "agreements",
    "operator_email",
    "paths",
    "ports",
    "services",
    "tls",
    "version",
    "$comment",
];
const MAIL: [&str; 6] = [
    "address",
    "ca_file",
    "password_file",
    "relay",
    "sender",
    "username",
];
const TLS: [&str; 2] = ["cert", "key"];
const BACKUP: [&str; 6] = [
    "access_key_file",
    "bucket",
    "endpoint",
    "port",
    "region",
    "secret_key_file",
];
const PATHS: [&str; 6] = ["bin", "etc", "pg_bin", "share", "state", "token_dir"];
const PORTS: [&str; 2] = ["base", "public"];

/// Decodes and checks a configuration file.
///
/// # Errors
///
/// [`ConfigError`] naming the first member that is wrong.
pub fn decode(bytes: &[u8]) -> Result<HostConfig, ConfigError> {
    if bytes.len() > MAX_CONFIG_LEN {
        return err("fstp.json", Problem::TooLong);
    }
    let value: Value = match fstp_json::parse(bytes) {
        Ok(v) => v,
        Err(_) => return err("fstp.json", Problem::NotJson),
    };
    let Some(top) = value.as_object() else {
        return err("fstp.json", Problem::NotJson);
    };
    closed(top, "", &TOP)?;

    let domain = required(top, "domain", "domain")?;
    if !is_host_name(domain) {
        return err("domain", Problem::BadHost);
    }
    let operator_email = required(top, "operator_email", "operator_email")?;
    if !is_email(operator_email) {
        return err("operator_email", Problem::BadEmail);
    }

    let paths_obj = object(top, "paths")?;
    if let Some(p) = paths_obj {
        closed(p, "paths", &PATHS)?;
    }
    let paths = Paths {
        bin: path(paths_obj, "bin", "paths.bin", "/usr/local/bin")?,
        share: path(paths_obj, "share", "paths.share", "/usr/share/fstp")?,
        etc: path(paths_obj, "etc", "paths.etc", "/etc/fstp")?,
        state: path(paths_obj, "state", "paths.state", "/var/lib/fstp")?,
        pg_bin: path(
            paths_obj,
            "pg_bin",
            "paths.pg_bin",
            "/usr/lib/postgresql/16/bin",
        )?,
        token_dir: path(paths_obj, "token_dir", "paths.token_dir", "/root")?,
    };

    let Some(mail_obj) = object(top, "mail")? else {
        return err("mail", Problem::Missing);
    };
    closed(mail_obj, "mail", &MAIL)?;
    let relay = required(mail_obj, "relay", "mail.relay")?;
    if !is_host_name(relay) {
        return err("mail.relay", Problem::BadHost);
    }
    let username = required(mail_obj, "username", "mail.username")?;
    if username.is_empty()
        || username.len() > 128
        || !username.bytes().all(|b| b.is_ascii_graphic())
    {
        return err("mail.username", Problem::NotText);
    }
    let default_password = paths.etc.join("mail.password");
    let password_file = path(
        Some(mail_obj),
        "password_file",
        "mail.password_file",
        &default_password.to_string_lossy(),
    )?;
    let sender = match text(mail_obj, "sender", "mail.sender")? {
        Some(s) if is_email(s) => s.to_owned(),
        Some(_) => return err("mail.sender", Problem::BadEmail),
        None => format!("noreply@{domain}"),
    };
    let address = match text(mail_obj, "address", "mail.address")? {
        None => None,
        Some(a) => match a.parse::<SocketAddr>() {
            Ok(s) if s.port() != 0 => Some(s),
            _ => return err("mail.address", Problem::BadAddress),
        },
    };
    let ca_file = optional_path(mail_obj, "ca_file", "mail.ca_file")?;
    let mail = Mail {
        relay: relay.to_owned(),
        username: username.to_owned(),
        password_file,
        sender,
        address,
        ca_file,
    };

    let tls = match object(top, "tls")? {
        None => None,
        Some(t) => {
            closed(t, "tls", &TLS)?;
            match (
                optional_path(t, "cert", "tls.cert")?,
                optional_path(t, "key", "tls.key")?,
            ) {
                (Some(cert), Some(key)) => Some(Tls { cert, key }),
                (None, _) => return err("tls.cert", Problem::TlsNeedsBoth),
                (_, None) => return err("tls.key", Problem::TlsNeedsBoth),
            }
        }
    };

    let backup = match object(top, "backup")? {
        None => None,
        Some(b) => {
            closed(b, "backup", &BACKUP)?;
            let endpoint = required(b, "endpoint", "backup.endpoint")?;
            if !is_host_name(endpoint) {
                return err("backup.endpoint", Problem::BadHost);
            }
            let region = required(b, "region", "backup.region")?;
            if region.is_empty()
                || region.len() > 64
                || !region
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
            {
                return err("backup.region", Problem::NotText);
            }
            let bucket = required(b, "bucket", "backup.bucket")?;
            if bucket.len() < 3
                || bucket.len() > 63
                || !bucket
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'.')
            {
                return err("backup.bucket", Problem::NotText);
            }
            let ak = paths.etc.join("s3-access-key-id");
            let sk = paths.etc.join("s3-secret-access-key");
            Some(Backup {
                endpoint: endpoint.to_owned(),
                region: region.to_owned(),
                bucket: bucket.to_owned(),
                port: port(b, "port", "backup.port", 443)?,
                access_key_file: path(
                    Some(b),
                    "access_key_file",
                    "backup.access_key_file",
                    &ak.to_string_lossy(),
                )?,
                secret_key_file: path(
                    Some(b),
                    "secret_key_file",
                    "backup.secret_key_file",
                    &sk.to_string_lossy(),
                )?,
            })
        }
    };

    let ports_obj = object(top, "ports")?;
    let (public_port, base_port) = match ports_obj {
        None => (443, 7440),
        Some(p) => {
            closed(p, "ports", &PORTS)?;
            (
                port(p, "public", "ports.public", 443)?,
                port(p, "base", "ports.base", 7440)?,
            )
        }
    };
    let last = base_port.checked_add(PORT_SPAN);
    match last {
        None => return err("ports.base", Problem::BadPort),
        Some(last) if (base_port..last).contains(&public_port) => {
            return err("ports.public", Problem::BadPort);
        }
        Some(_) => {}
    }

    let services = match text(top, "services", "services")? {
        None | Some("systemd") => Services::Systemd,
        Some("direct") => Services::Direct,
        Some(_) => return err("services", Problem::BadServices),
    };
    let custody_simulator = optional_path(top, "custody_simulator", "custody_simulator")?;
    if custody_simulator.is_some() && services != Services::Direct {
        return err("custody_simulator", Problem::SimulatorNeedsDirect);
    }
    let agreements = match text(top, "agreements", "agreements")? {
        None => DEFAULT_AGREEMENTS.to_owned(),
        Some(a) if is_agreements(a) => a.to_owned(),
        Some(_) => return err("agreements", Problem::BadAgreements),
    };
    let custodian = match text(top, "custodian", "custodian")? {
        None => None,
        Some(c) => match custodian_target(c) {
            Some(t) => Some(t),
            None => return err("custodian", Problem::BadAddress),
        },
    };
    let version = match text(top, "version", "version")? {
        None => DEFAULT_VERSION.to_owned(),
        Some(v) if is_version(v) => v.to_owned(),
        Some(_) => return err("version", Problem::BadVersion),
    };
    Ok(HostConfig {
        domain: domain.to_owned(),
        operator_email: operator_email.to_owned(),
        mail,
        tls,
        backup,
        paths,
        public_port,
        base_port,
        services,
        custody_simulator,
        agreements,
        version,
        custodian,
    })
}

/// The port of the second custodian unless the member names another.
pub const CUSTODIAN_PORT: u16 = 7460;

/// The host and port of `host`, `host:port`, `ip`, `ip:port` or
/// `[v6]:port`, with [`CUSTODIAN_PORT`] by default.
#[must_use]
pub fn custodian_target(text: &str) -> Option<(String, u16)> {
    let port_of = |p: &str| p.parse::<u16>().ok().filter(|p| *p > 0);
    let (host, port) = if let Some(rest) = text.strip_prefix('[') {
        let (h, tail) = rest.split_once(']')?;
        h.parse::<std::net::Ipv6Addr>().ok()?;
        let port = match tail {
            "" => CUSTODIAN_PORT,
            t => port_of(t.strip_prefix(':')?)?,
        };
        (h, port)
    } else {
        match text.split_once(':') {
            Some((h, p)) => (h, port_of(p)?),
            None => (text, CUSTODIAN_PORT),
        }
    };
    let ok = is_host_name(host) || host.parse::<std::net::IpAddr>().is_ok();
    ok.then(|| (host.to_owned(), port))
}

/// A starting configuration with the three things every host must name
/// filled in by the admin's answers (`fstp-admin setup` asks for them when
/// no file exists yet).
#[must_use]
pub fn starter(domain: &str, operator_email: &str, relay: &str, username: &str) -> String {
    format!(
        "{{\n  \"domain\": {d},\n  \"operator_email\": {e},\n  \"mail\": {{\n    \"relay\": {r},\n    \"username\": {u}\n  }}\n}}\n",
        d = quote(domain),
        e = quote(operator_email),
        r = quote(relay),
        u = quote(username),
    )
}

/// A JSON string literal of `s`.
#[must_use]
pub fn quote(s: &str) -> String {
    Value::String(s.to_owned()).to_compact()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]

    use super::*;

    const MIN: &str = r#"{"domain":"grants.example.eu","operator_email":"admin@example.eu",
        "mail":{"relay":"smtp.example.eu","username":"cell"}}"#;

    fn with(extra: &str) -> String {
        format!(
            r#"{{"domain":"grants.example.eu","operator_email":"admin@example.eu",
            "mail":{{"relay":"smtp.example.eu","username":"cell"}},{extra}}}"#
        )
    }

    fn problem(text: &str) -> (String, Problem) {
        let e = decode(text.as_bytes()).unwrap_err();
        (e.field, e.problem)
    }

    /// ADR-028 "One configuration file": three members are enough, and the
    /// rest takes its defaults.
    #[test]
    fn adr028_three_members_are_enough() {
        let c = decode(MIN.as_bytes()).unwrap();
        assert_eq!(c.domain, "grants.example.eu");
        assert_eq!(c.mail.sender, "noreply@grants.example.eu");
        assert_eq!(
            c.mail.password_file,
            PathBuf::from("/etc/fstp/mail.password")
        );
        assert_eq!(c.paths.state, PathBuf::from("/var/lib/fstp"));
        assert_eq!(c.public_port, 443);
        assert_eq!(c.services, Services::Systemd);
        assert!(c.tls.is_none() && c.backup.is_none());
        assert_eq!(c.agreements, "1,1,1");
    }

    /// ADR-028 record of lane `m10/guard-key`: the member `custodian`
    /// names the second custodian by host or address, with port 7460 by
    /// default, and a bad one names the member. The pairing command adds
    /// it to a file without touching the rest.
    #[test]
    fn adr028_guard_config_takes_the_custodian_member() {
        let c = decode(with(r#""custodian":"c.example.eu""#).as_bytes()).unwrap();
        assert_eq!(c.custodian, Some(("c.example.eu".into(), CUSTODIAN_PORT)));
        let c = decode(with(r#""custodian":"[2001:db8::7]:9""#).as_bytes()).unwrap();
        assert_eq!(c.custodian, Some(("2001:db8::7".into(), 9)));
        assert!(
            decode(with("\"agreements\":\"1,1,1\"").as_bytes())
                .unwrap()
                .custodian
                .is_none()
        );
        for bad in ["", "c.example.eu:0", "C!", "[x]:1"] {
            assert_eq!(
                problem(&with(&format!(r#""custodian":"{bad}""#))),
                ("custodian".into(), Problem::BadAddress),
                "{bad}"
            );
        }
        let dir = std::env::temp_dir().join(format!("fstp-admin-guard-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("fstp.json");
        std::fs::write(&path, with(r#""agreements":"1,1,1""#)).unwrap();
        crate::custodian::set_member(&path, "c.example.eu:7460").unwrap();
        crate::custodian::set_member(&path, "d.example.eu:7460").unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.matches("\"custodian\"").count(), 1, "{text}");
        let c = decode(text.as_bytes()).unwrap();
        assert_eq!(c.custodian, Some(("d.example.eu".into(), 7460)));
        assert_eq!(c.agreements, "1,1,1");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// ADR-028: each refusal names the member that is wrong.
    #[test]
    fn adr028_refusals_name_the_member() {
        assert_eq!(problem("{"), ("fstp.json".into(), Problem::NotJson));
        assert_eq!(
            problem(r#"{"operator_email":"a@b.eu"}"#),
            ("domain".into(), Problem::Missing)
        );
        assert_eq!(
            problem(r#"{"domain":"Grants.EU","operator_email":"a@b.eu"}"#),
            ("domain".into(), Problem::BadHost)
        );
        assert_eq!(
            problem(r#"{"domain":"g.example.eu","operator_email":"nobody"}"#),
            ("operator_email".into(), Problem::BadEmail)
        );
        assert_eq!(
            problem(r#"{"domain":"g.example.eu","operator_email":"a@b.eu"}"#),
            ("mail".into(), Problem::Missing)
        );
        assert_eq!(
            problem(&with(r#""colour":"red""#)),
            ("colour".into(), Problem::Unknown)
        );
        assert_eq!(
            problem(&with(r#""paths":{"bin":"relative"}"#)),
            ("paths.bin".into(), Problem::NotAbsolute)
        );
        assert_eq!(
            problem(&with(r#""paths":{"color":"/x"}"#)),
            ("paths.color".into(), Problem::Unknown)
        );
        assert_eq!(
            problem(&with(r#""tls":{"cert":"/a.pem"}"#)),
            ("tls.key".into(), Problem::TlsNeedsBoth)
        );
        assert_eq!(
            problem(&with(r#""ports":{"public":7441}"#)),
            ("ports.public".into(), Problem::BadPort)
        );
        assert_eq!(
            problem(&with(r#""ports":{"base":0}"#)),
            ("ports.base".into(), Problem::BadPort)
        );
        assert_eq!(
            problem(&with(r#""custody_simulator":"/sim""#)),
            ("custody_simulator".into(), Problem::SimulatorNeedsDirect)
        );
        assert_eq!(
            problem(&with(r#""services":"docker""#)),
            ("services".into(), Problem::BadServices)
        );
        assert_eq!(
            problem(&with(
                r#""backup":{"endpoint":"s3.gra.example.net","region":"gra"}"#
            )),
            ("backup.bucket".into(), Problem::Missing)
        );
    }

    /// ADR-028, R-NF-02: an unknown member's name is cut to printable
    /// ASCII before anything prints it.
    #[test]
    fn r_nf_02_unknown_member_names_are_cut() {
        let long = "x".repeat(100);
        let (field, p) = problem(&with(&format!("\"{long}\\n\":1")));
        assert_eq!(p, Problem::Unknown);
        assert_eq!(field.len(), 40);
        assert!(field.bytes().all(|b| b.is_ascii_graphic()));
    }

    /// ADR-028: the starter file the questions write decodes.
    #[test]
    fn adr028_starter_decodes() {
        let s = starter(
            "grants.example.eu",
            "a\"b@example.eu",
            "smtp.example.eu",
            "cell",
        );
        let c = decode(s.as_bytes()).unwrap();
        assert_eq!(c.operator_email, "a\"b@example.eu");
    }
}
