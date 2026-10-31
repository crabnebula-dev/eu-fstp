//! The configuration of the vault process (design sections 1.4 and 6.1).
//!
//! It is canonical JSON with a closed member set, so the decoder refuses
//! any member it does not name. There is no member for a fact source, so
//! no configuration can feed the vault facts around its write rules
//! (design section 6.9, I-18).

use std::net::SocketAddr;

use fstp_vault_core::MAX_PINNED_KEYS;
use fstp_vault_proto::json::{self, limits, parse_canonical};

use crate::VaultError;

/// The members of a configuration, in key order.
pub const CONFIG_MEMBERS: [&str; 6] = [
    "cell",
    "credentials_dir",
    "database",
    "internal_listen",
    "origin_listen",
    "ticket_keys",
];

/// The members of the database part, in key order.
pub const DATABASE_MEMBERS: [&str; 4] = ["dbname", "host", "port", "role"];

/// Where the vault database is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DatabaseConfig {
    /// The host name.
    pub host: String,
    /// The port.
    pub port: u16,
    /// The database role, which the client certificate names.
    pub role: String,
    /// The database name, `v_<cell>`.
    pub dbname: String,
}

/// The vault process configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultConfig {
    /// The cell this vault belongs to.
    pub cell: [u8; 16],
    /// The directory of the role certificates and keys, readable only by
    /// the vault's OS user (design section 4.7).
    pub credentials_dir: String,
    /// The vault database.
    pub database: DatabaseConfig,
    /// The internal mTLS listener for the cell.
    pub internal_listen: SocketAddr,
    /// The vault origin listener, behind the edge tunnel.
    pub origin_listen: SocketAddr,
    /// The cell's pinned ticket public keys: current and next.
    pub ticket_keys: Vec<[u8; 32]>,
}

const CONFIG: &str = "configuration";

/// Decodes a configuration.
///
/// # Errors
///
/// [`VaultError::Malformed`] for any other member set, spelling or value.
pub fn decode_config(bytes: &[u8]) -> Result<VaultConfig, VaultError> {
    let bad = |_| VaultError::Malformed(CONFIG);
    let v = parse_canonical(bytes, &limits()).map_err(bad)?;
    let o = json::object(&v, &CONFIG_MEMBERS, CONFIG).map_err(bad)?;
    let d = json::object(
        json::member(o, "database", CONFIG).map_err(bad)?,
        &DATABASE_MEMBERS,
        CONFIG,
    )
    .map_err(bad)?;
    let addr = |name: &str| -> Result<SocketAddr, VaultError> {
        json::string(o, name, CONFIG)
            .map_err(bad)?
            .parse()
            .map_err(|_| VaultError::Malformed(CONFIG))
    };
    let keys = json::member(o, "ticket_keys", CONFIG)
        .map_err(bad)?
        .as_array()
        .ok_or(VaultError::Malformed(CONFIG))?;
    if keys.is_empty() || keys.len() > MAX_PINNED_KEYS {
        return Err(VaultError::Malformed(CONFIG));
    }
    let mut ticket_keys = Vec::with_capacity(keys.len());
    for k in keys.iter() {
        let s = k.as_str().ok_or(VaultError::Malformed(CONFIG))?;
        ticket_keys.push(json::hex_array::<32>(s, CONFIG).map_err(bad)?);
    }
    Ok(VaultConfig {
        cell: json::hex_array(json::string(o, "cell", CONFIG).map_err(bad)?, CONFIG)
            .map_err(bad)?,
        credentials_dir: json::string(o, "credentials_dir", CONFIG)
            .map_err(bad)?
            .to_owned(),
        database: DatabaseConfig {
            host: json::string(d, "host", CONFIG).map_err(bad)?.to_owned(),
            port: u16::try_from(json::uint(d, "port", CONFIG).map_err(bad)?)
                .map_err(|_| VaultError::Malformed(CONFIG))?,
            role: json::string(d, "role", CONFIG).map_err(bad)?.to_owned(),
            dbname: json::string(d, "dbname", CONFIG).map_err(bad)?.to_owned(),
        },
        internal_listen: addr("internal_listen")?,
        origin_listen: addr("origin_listen")?,
        ticket_keys,
    })
}
