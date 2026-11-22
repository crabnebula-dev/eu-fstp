//! The configuration of the vault process (design sections 1.4 and 6.1,
//! ADR-026 record of lane L8).
//!
//! It is canonical JSON (RFC 8785) with a closed member set, so the
//! decoder refuses any member it does not name. There is no member for a
//! fact source, so no configuration can feed the vault facts around its
//! write rules (design section 6.9, I-18).
//!
//! The configuration holds no secret. The credentials directory holds the
//! certificates, keys and passwords by fixed name ([`CREDENTIAL_FILES`]).
//! The database must be the vault database of the configured cell,
//! `v_<cell>`, so a cell database is refused before any connection (I-83).
//! A refusal names its rule and never quotes the input (R-NF-02).

use std::net::SocketAddr;
use std::path::PathBuf;

use fstp_json::{Object, ParseLimits, Value};
use fstp_vault_core::MAX_PINNED_KEYS;
use fstp_vault_proto::json::{self, parse_canonical};

use crate::VaultError;
use crate::service::RegisteredSpki;
use crate::start::ClusterRole;

/// The members of a configuration, in key order.
pub const CONFIG_MEMBERS: [&str; 10] = [
    "cell",
    "credentials_dir",
    "database",
    "internal_listen",
    "keyd_socket",
    "origin_host",
    "origin_listen",
    "registered_servers",
    "ticket_keys",
    "witness",
];

/// The optional members of a configuration. `assets_dir` names the
/// static pages (ADR-004 record of lane L13b). `object_store` names the
/// bucket of the keystore snapshots (ADR-012 record of lane L17), in the
/// shape `fstp-backup` uses.
pub const OPTIONAL_MEMBERS: [&str; 2] = ["assets_dir", "object_store"];

/// The members of the database part, in key order.
pub const DATABASE_MEMBERS: [&str; 3] = ["dbname", "host", "port"];

/// The members of one registered server, in key order.
pub const SERVER_MEMBERS: [&str; 2] = ["kind", "spki_sha256"];

/// The members of the witness part, in key order.
pub const WITNESS_MEMBERS: [&str; 4] = ["address", "ca_spki_sha256", "receipt_keys", "server_name"];

/// The files of the credentials directory, by fixed name (ADR-026 record
/// of lane L8, row "Secrets").
pub const CREDENTIAL_FILES: [&str; 18] = [
    "db-ca.pem",
    "vault.pem",
    "vault.key",
    "vault.password",
    "keys.pem",
    "keys.key",
    "keys.password",
    "internal.pem",
    "internal.key",
    "cell-ca.pem",
    "tunnel.pem",
    "tunnel.key",
    "tunnel-ca.pem",
    "origin.pem",
    "origin.key",
    "witness.pem",
    "witness.key",
    "witness-ca.pem",
];

/// The largest configuration file, in bytes.
pub const MAX_CONFIG_LEN: usize = 64 * 1024;

/// The longest path the configuration names.
pub const MAX_PATH_LEN: usize = 1024;

/// The most registered servers.
pub const MAX_REGISTERED: usize = 32;

/// The most witness receipt keys.
pub const MAX_RECEIPT_KEYS: usize = 8;

/// The longest witness receipt key, in bytes.
pub const MAX_RECEIPT_KEY_LEN: usize = 4096;

/// Where the vault database is. The two logins are `<dbname>_vault` and
/// `<dbname>_keys`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DatabaseConfig {
    /// The host name.
    pub host: String,
    /// The port.
    pub port: u16,
    /// The database name, `v_<cell>`.
    pub dbname: String,
}

/// Where and how the vault reaches its witness (ADR-010 "Witnesses").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessConfig {
    /// The witness address.
    pub address: SocketAddr,
    /// The SHA-256 digest of the witness CA's SubjectPublicKeyInfo.
    pub ca_spki_sha256: [u8; 32],
    /// The pinned witness receipt public keys, encoded.
    pub receipt_keys: Vec<Vec<u8>>,
    /// The name the witness server certificate carries.
    pub server_name: String,
}

/// The vault process configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultConfig {
    /// The installed static pages of the vault origin, if any (ADR-004
    /// record of lane L13b, row "Static pages"). Optional.
    pub assets_dir: Option<PathBuf>,
    /// The cell this vault belongs to.
    pub cell: [u8; 16],
    /// The directory of the role certificates and keys, readable only by
    /// the vault's OS user (design section 4.7).
    pub credentials_dir: PathBuf,
    /// The vault database.
    pub database: DatabaseConfig,
    /// The internal mTLS listener for the cell.
    pub internal_listen: SocketAddr,
    /// The socket of the vault's `fstp-keyd` entry (client role `vault`).
    pub keyd_socket: PathBuf,
    /// The vault origin host, `id.<cell host>`.
    pub origin_host: String,
    /// The vault origin listener, behind the edge tunnel.
    pub origin_listen: SocketAddr,
    /// The control plane's registration of cluster server keys.
    pub registered_servers: Vec<RegisteredSpki>,
    /// The cell's pinned ticket public keys: current and next.
    pub ticket_keys: Vec<[u8; 32]>,
    /// The witness.
    pub witness: WitnessConfig,
    /// The object store of the keystore snapshots, if one is configured
    /// (ADR-012 record of lane L17). Without one, step 5 of a rotation
    /// reads the committed rows back from the database.
    pub object_store: Option<fstp_backup::s3::Endpoint>,
}

/// The vault database name of `cell`: `v_` and 32 lowercase hex digits.
#[must_use]
pub fn vault_dbname(cell: &[u8; 16]) -> String {
    let mut s = String::from("v_");
    for b in cell {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn limits() -> ParseLimits {
    json::limits()
        .with_max_input_bytes(MAX_CONFIG_LEN)
        .with_max_container_len(MAX_REGISTERED)
}

fn bad(rule: &'static str) -> VaultError {
    VaultError::Config(rule)
}

fn obj<'a>(v: &'a Value, names: &[&str], rule: &'static str) -> Result<&'a Object, VaultError> {
    json::object(v, names, rule).map_err(|_| bad(rule))
}

fn member<'a>(o: &'a Object, name: &'static str) -> Result<&'a Value, VaultError> {
    json::member(o, name, name).map_err(|_| bad(name))
}

fn string<'a>(o: &'a Object, name: &'static str) -> Result<&'a str, VaultError> {
    json::string(o, name, name).map_err(|_| bad(name))
}

fn addr(o: &Object, name: &'static str) -> Result<SocketAddr, VaultError> {
    string(o, name)?.parse().map_err(|_| bad(name))
}

fn hex<const N: usize>(o: &Object, name: &'static str) -> Result<[u8; N], VaultError> {
    json::hex_array::<N>(string(o, name)?, name).map_err(|_| bad(name))
}

fn path(o: &Object, name: &'static str) -> Result<PathBuf, VaultError> {
    let s = string(o, name)?;
    if s.is_empty() || s.len() > MAX_PATH_LEN || !s.starts_with('/') || s.contains('\0') {
        return Err(bad(name));
    }
    Ok(PathBuf::from(s))
}

/// A lowercase DNS name, as the tunnel header carries one.
fn host(o: &Object, name: &'static str) -> Result<String, VaultError> {
    let s = string(o, name)?;
    fstp_edge::HostName::parse_lowercase(s.as_bytes()).map_err(|_| bad(name))?;
    Ok(s.to_owned())
}

fn array<'a>(o: &'a Object, name: &'static str, max: usize) -> Result<&'a [Value], VaultError> {
    let items = member(o, name)?.as_array().ok_or(bad(name))?;
    if items.is_empty() || items.len() > max {
        return Err(bad(name));
    }
    Ok(items)
}

fn registered(o: &Object) -> Result<Vec<RegisteredSpki>, VaultError> {
    const RULE: &str = "registered_servers";
    let mut out = Vec::new();
    for item in array(o, RULE, MAX_REGISTERED)? {
        let s = obj(item, &SERVER_MEMBERS, RULE)?;
        let role = match string(s, "kind")? {
            "application" => ClusterRole::Application,
            "vault" => ClusterRole::Vault,
            "control" | "witness" => ClusterRole::Other,
            _ => return Err(bad("kind")),
        };
        out.push(RegisteredSpki {
            digest: hex::<32>(s, "spki_sha256")?,
            role,
        });
    }
    Ok(out)
}

fn witness(o: &Object) -> Result<WitnessConfig, VaultError> {
    let w = obj(member(o, "witness")?, &WITNESS_MEMBERS, "witness")?;
    let mut receipt_keys = Vec::new();
    for k in array(w, "receipt_keys", MAX_RECEIPT_KEYS)? {
        let s = k.as_str().ok_or(bad("receipt_keys"))?;
        let key = json::unhex(s, "receipt_keys").map_err(|_| bad("receipt_keys"))?;
        if key.is_empty() || key.len() > MAX_RECEIPT_KEY_LEN {
            return Err(bad("receipt_keys"));
        }
        receipt_keys.push(key);
    }
    Ok(WitnessConfig {
        address: addr(w, "address")?,
        ca_spki_sha256: hex::<32>(w, "ca_spki_sha256")?,
        receipt_keys,
        server_name: host(w, "server_name")?,
    })
}

/// Decodes a configuration. One trailing line break is allowed after the
/// canonical form, as an editor writes one.
///
/// # Errors
///
/// [`VaultError::Config`] naming the rule broken, for any other member
/// set, spelling or value. It never quotes the input (R-NF-02).
pub fn decode_config(bytes: &[u8]) -> Result<VaultConfig, VaultError> {
    if bytes.len() > MAX_CONFIG_LEN {
        return Err(bad("length"));
    }
    let body = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    let v = parse_canonical(body, &limits()).map_err(|_| bad("canonical JSON"))?;
    let mut names: Vec<&str> = CONFIG_MEMBERS.to_vec();
    if let Some(o) = v.as_object() {
        names.extend(OPTIONAL_MEMBERS.iter().filter(|n| o.contains_key(n)));
    }
    let o = obj(&v, &names, "members")?;
    let has_assets = o.get("assets_dir").is_some();
    let object_store = match o.get("object_store") {
        None => None,
        Some(os) => Some(
            fstp_backup::config::decode_object_store(os.as_object().ok_or(bad("object_store"))?)
                .map_err(|_| bad("object_store"))?,
        ),
    };
    let d = obj(member(o, "database")?, &DATABASE_MEMBERS, "database")?;
    let cell = hex::<16>(o, "cell")?;
    let dbname = string(d, "dbname")?;
    // I-83: the vault names its own database only, never `c_<cell>`.
    if dbname != vault_dbname(&cell) {
        return Err(bad("dbname"));
    }
    let db_host = string(d, "host")?;
    if db_host.is_empty() || db_host.len() > MAX_PATH_LEN {
        return Err(bad("host"));
    }
    let keys = array(o, "ticket_keys", MAX_PINNED_KEYS)?;
    let mut ticket_keys = Vec::with_capacity(keys.len());
    for k in keys {
        let s = k.as_str().ok_or(bad("ticket_keys"))?;
        ticket_keys.push(json::hex_array::<32>(s, "ticket_keys").map_err(|_| bad("ticket_keys"))?);
    }
    let internal_listen = addr(o, "internal_listen")?;
    let origin_listen = addr(o, "origin_listen")?;
    let assets_dir = if has_assets {
        Some(path(o, "assets_dir")?)
    } else {
        None
    };
    Ok(VaultConfig {
        assets_dir,
        cell,
        credentials_dir: path(o, "credentials_dir")?,
        database: DatabaseConfig {
            host: db_host.to_owned(),
            port: u16::try_from(json::uint(d, "port", "port").map_err(|_| bad("port"))?)
                .map_err(|_| bad("port"))?,
            dbname: dbname.to_owned(),
        },
        internal_listen,
        keyd_socket: path(o, "keyd_socket")?,
        origin_host: host(o, "origin_host")?,
        origin_listen,
        registered_servers: registered(o)?,
        ticket_keys,
        witness: witness(o)?,
        object_store,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use super::*;

    pub(crate) const CELL: &str = "000102030405060708090a0b0c0d0e0f";

    /// A valid configuration, with `edit` applied to its text.
    pub(crate) fn text(edit: impl Fn(String) -> String) -> String {
        let receipt = "ab".repeat(1984);
        edit(format!(
            "{{\"cell\":\"{CELL}\",\"credentials_dir\":\"/etc/fstp/vault\",\"database\":{{\"dbname\":\"v_{CELL}\",\"host\":\"vdb.internal\",\"port\":5433}},\"internal_listen\":\"10.0.0.6:7445\",\"keyd_socket\":\"/run/fstp-keyd/vault.sock\",\"origin_host\":\"id.grants.example.eu\",\"origin_listen\":\"10.0.0.6:7446\",\"registered_servers\":[{{\"kind\":\"application\",\"spki_sha256\":\"{a}\"}},{{\"kind\":\"vault\",\"spki_sha256\":\"{v}\"}}],\"ticket_keys\":[\"{t}\"],\"witness\":{{\"address\":\"10.0.0.5:7443\",\"ca_spki_sha256\":\"{w}\",\"receipt_keys\":[\"{receipt}\"],\"server_name\":\"witness.internal\"}}}}",
            a = "11".repeat(32),
            v = "22".repeat(32),
            t = "33".repeat(32),
            w = "44".repeat(32),
        ))
    }

    /// ADR-012 record of lane L17: `object_store` is optional, absent by
    /// default, and decodes in the shape `fstp-backup` uses. A malformed
    /// one is refused by name.
    #[test]
    fn adr012_vault_config_takes_an_optional_object_store() {
        assert_eq!(
            decode_config(text(|s| s).as_bytes()).unwrap().object_store,
            None
        );
        let with = |os: &str| {
            text(|s| {
                s.replacen(
                    "\"origin_host\"",
                    &format!("\"object_store\":{os},\"origin_host\""),
                    1,
                )
            })
        };
        let c = decode_config(
            with(r#"{"bucket":"fstp-pilot","endpoint":"s3.gra.io.cloud.ovh.net","region":"gra"}"#)
                .as_bytes(),
        )
        .unwrap();
        let os = c.object_store.unwrap();
        assert_eq!(
            (os.bucket.as_str(), os.port, os.region.as_str()),
            ("fstp-pilot", 443, "gra")
        );
        for bad_os in [
            r#"{"bucket":"fstp-pilot","endpoint":"s3.gra.io.cloud.ovh.net"}"#,
            r#"{"bucket":"X","endpoint":"s3.gra.io.cloud.ovh.net","region":"gra"}"#,
            r#""s3""#,
        ] {
            assert_eq!(
                decode_config(with(bad_os).as_bytes()),
                Err(VaultError::Config("object_store")),
                "{bad_os}"
            );
        }
    }

    /// ADR-004 record of lane L13b, row "Static pages": `assets_dir` is
    /// optional, absent by default, and an absolute path when present.
    #[test]
    fn adr009_vault_config_takes_an_optional_assets_dir() {
        assert_eq!(
            decode_config(text(|s| s).as_bytes()).unwrap().assets_dir,
            None
        );
        let with = |p: &str| {
            text(|s| {
                s.replacen(
                    "{\"cell\"",
                    &format!("{{\"assets_dir\":\"{p}\",\"cell\""),
                    1,
                )
            })
        };
        assert_eq!(
            decode_config(with("/opt/fstp/web").as_bytes())
                .unwrap()
                .assets_dir,
            Some(PathBuf::from("/opt/fstp/web"))
        );
        assert!(decode_config(with("opt/fstp/web").as_bytes()).is_err());
    }

    /// G12, ADR-026 record of lane L8: a valid configuration decodes into
    /// every member, with one trailing line break or none.
    #[test]
    fn g12_vault_config_decodes_every_member() {
        let t = text(|s| s);
        let c = decode_config(t.as_bytes()).unwrap();
        assert_eq!(c.cell, core::array::from_fn(|i| u8::try_from(i).unwrap()));
        assert_eq!(c.database.dbname, format!("v_{CELL}"));
        assert_eq!(c.database.port, 5433);
        assert_eq!(c.credentials_dir, PathBuf::from("/etc/fstp/vault"));
        assert_eq!(c.keyd_socket, PathBuf::from("/run/fstp-keyd/vault.sock"));
        assert_eq!(c.origin_host, "id.grants.example.eu");
        assert_eq!(c.registered_servers.len(), 2);
        assert_eq!(c.registered_servers[1].role, ClusterRole::Vault);
        assert_eq!(c.ticket_keys, vec![[0x33; 32]]);
        assert_eq!(c.witness.receipt_keys, vec![vec![0xab; 1984]]);
        assert_eq!(c.witness.server_name, "witness.internal");
        let with_newline = format!("{t}\n");
        assert_eq!(decode_config(with_newline.as_bytes()).unwrap(), c);
    }

    /// G12, I-18: the decoder refuses bad input. Each case breaks one
    /// rule of the grammar, and each is refused with a rule name.
    #[test]
    fn g12_vault_config_refuses_bad_input() {
        let cases: Vec<(&str, String)> = vec![
            ("empty", String::new()),
            ("not canonical", text(|s| s.replacen(',', ", ", 1))),
            ("two line breaks", text(|s| format!("{s}\n\n"))),
            (
                "unknown member",
                text(|s| s.replacen("{\"cell\"", "{\"aaa\":1,\"cell\"", 1)),
            ),
            (
                "missing member",
                text(|s| s.replacen("\"keyd_socket\":\"/run/fstp-keyd/vault.sock\",", "", 1)),
            ),
            (
                "relative path",
                text(|s| s.replacen("\"/etc/fstp/vault\"", "\"etc/fstp\"", 1)),
            ),
            ("bad cell", text(|s| s.replacen(CELL, "zz", 1))),
            ("bad port", text(|s| s.replacen("5433", "70000", 1))),
            (
                "bad listen",
                text(|s| s.replacen("10.0.0.6:7445", "nowhere", 1)),
            ),
            (
                "bad host",
                text(|s| s.replacen("id.grants.example.eu", "ID..x", 1)),
            ),
            (
                "bad kind",
                text(|s| s.replacen("\"kind\":\"vault\"", "\"kind\":\"vaults\"", 1)),
            ),
            (
                "short digest",
                text(|s| s.replacen(&"22".repeat(32), "22", 1)),
            ),
            (
                "no ticket key",
                text(|s| s.replacen(&format!("[\"{}\"]", "33".repeat(32)), "[]", 1)),
            ),
            (
                "odd receipt key",
                text(|s| s.replacen(&"ab".repeat(1984), "abc", 1)),
            ),
            (
                "database role",
                text(|s| s.replacen("\"port\":5433", "\"port\":5433,\"role\":\"x\"", 1)),
            ),
            (
                "seed member",
                text(|s| {
                    s.replacen(
                        "\"ticket_keys\"",
                        "\"seed\":\"facts.json\",\"ticket_keys\"",
                        1,
                    )
                }),
            ),
        ];
        for (name, t) in cases {
            match decode_config(t.as_bytes()) {
                Err(VaultError::Config(_)) => {}
                other => panic!("{name}: {other:?}"),
            }
        }
        let long = vec![b' '; MAX_CONFIG_LEN + 1];
        assert_eq!(decode_config(&long), Err(VaultError::Config("length")));
    }

    /// I-83, R-NG-01, ADR-009: the vault names its own database only. A
    /// cell database `c_<cell>`, or the vault database of another cell, is
    /// refused before any connection.
    #[test]
    fn i83_vault_config_refuses_a_cell_database() {
        let cell_db = text(|s| s.replacen(&format!("v_{CELL}"), &format!("c_{CELL}"), 1));
        assert_eq!(
            decode_config(cell_db.as_bytes()),
            Err(VaultError::Config("dbname"))
        );
        let other =
            text(|s| s.replacen(&format!("v_{CELL}"), &format!("v_{}", "ff".repeat(16)), 1));
        assert_eq!(
            decode_config(other.as_bytes()),
            Err(VaultError::Config("dbname"))
        );
    }

    /// R-NF-02: a refused configuration never quotes its bytes. Each error
    /// names a fixed rule only.
    #[test]
    fn r_nf_02_vault_config_errors_never_quote_bytes() {
        let marker = "s3cr3tm4rk3r";
        let cases = [
            marker.to_owned(),
            format!("{{\"{marker}\":1}}"),
            text(|s| {
                s.replacen("vdb.internal", marker, 1)
                    .replacen(&format!("v_{CELL}"), marker, 1)
            }),
            text(|s| s.replacen("witness.internal", &format!("{marker} x"), 1)),
            text(|s| s.replacen("/etc/fstp/vault", marker, 1)),
            text(|s| s.replacen("\"application\"", &format!("\"{marker}\""), 1)),
        ];
        for c in &cases {
            let e = decode_config(c.as_bytes()).unwrap_err();
            let shown = format!("{e:?} {e}");
            assert!(!shown.contains(marker), "R-NF-02: {shown}");
        }
    }
}
