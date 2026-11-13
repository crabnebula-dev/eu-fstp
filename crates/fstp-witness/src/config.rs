//! The process configuration of `fstp-witness` and its receipt key file
//! (ADR-010 "Keys", open point 6, ADR-004 part 2 "Self-hosted witness
//! receipt key"). Lane F-CP.
//!
//! # Configuration
//!
//! A JSON object with a closed member set. Any other member, a missing
//! member or a member of the other mode is refused.
//!
//! ```text
//! {"credentials_dir": "...", "database": {"dbname": "witness",
//!  "host": "...", "port": 5432, "role": "witness_service"},
//!  "keyd_socket": "...", "listen": "0.0.0.0:7443", "mode": "saas"}
//! {"credentials_dir": "...", "keyd_socket": "...",
//!  "listen": "127.0.0.1:7443", "mode": "self_hosted", "store_dir": "..."}
//! ```
//!
//! A SaaS witness names its database. A self-hosted witness names its file
//! store directory instead. The credentials directory, readable only by
//! the witness's OS user, holds `server.pem` and `server.key` (the witness
//! server certificate chain and key), [`RECEIPT_KEY_FILE`], and for a SaaS
//! witness `db-ca.pem`, `db.pem`, `db.key` and `db.password` (the
//! `witness_service` login, design section 4.1).
//!
//! # Receipt key file
//!
//! Interim, pending Daniel (ADR-004 part 2):
//!
//! ```text
//! file    = magic (27) || be64(epoch) || be16(len) || custody handle
//!           || be16(len) || wrapped S(e) || nonce (12) || sealed (80)
//! magic   = "fstp-witness-receipt-key-v1"
//! wrap    = custody wrap of S(e) under the witness's own fstp-keyd entry,
//!           chain ControlPlane, AAD = magic || "controlplane" || be64(epoch)
//! sealed  = AES-256-GCM under S(e) of the 64-byte composite private key,
//!           AAD = magic || "controlplane" || purpose code 9 || be64(epoch)
//! ```
//!
//! Both decoders are fuzzed (`witness_config_decode`).

use std::net::SocketAddr;
use std::path::PathBuf;

use fstp_json::{ParseLimits, Value};

use crate::WitnessError;

/// The magic that opens a receipt key file, and labels both AADs.
pub const RECEIPT_KEY_MAGIC: &[u8; 27] = b"fstp-witness-receipt-key-v1";

/// The receipt key file in the credentials directory.
pub const RECEIPT_KEY_FILE: &str = "receipt.key";

/// The longest configuration.
pub const MAX_CONFIG_LEN: usize = 4096;

/// The longest custody handle or wrapped seal key a key file holds.
pub const MAX_KEY_FIELD_LEN: usize = 4096;

/// The length of the sealed composite private key: 64 bytes and the tag.
pub const SEALED_KEY_LEN: usize = 64 + fstp_crypto::aead::TAG_LEN;

/// The purpose code the seal binds: `Anchor`, the composite signing key
/// purpose (ADR-004 part 1 table, part 2 interim reading).
pub const RECEIPT_KEY_PURPOSE: u8 = 9;

/// Where a witness keeps its records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WitnessStore {
    /// A SaaS witness: its own database (design section 4.1).
    Database {
        /// The host.
        host: String,
        /// The port.
        port: u16,
        /// The login role, `witness_service`.
        role: String,
        /// The database name.
        dbname: String,
    },
    /// A self-hosted witness: its append-only file store.
    Files {
        /// The store directory.
        dir: PathBuf,
    },
}

/// The witness process configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessConfig {
    /// Where to listen.
    pub listen: SocketAddr,
    /// The credentials directory.
    pub credentials_dir: PathBuf,
    /// The socket of the witness's own `fstp-keyd` entry.
    pub keyd_socket: PathBuf,
    /// The store.
    pub store: WitnessStore,
}

fn bad(rule: &'static str) -> WitnessError {
    WitnessError::Config(rule)
}

fn path(v: Option<&Value>, rule: &'static str) -> Result<PathBuf, WitnessError> {
    let s = v.and_then(Value::as_str).ok_or(bad(rule))?;
    if s.is_empty() || s.contains('\0') {
        return Err(bad(rule));
    }
    Ok(PathBuf::from(s))
}

/// Decodes a configuration. Fuzzed (`witness_config_decode`).
///
/// # Errors
///
/// [`WitnessError::Config`] naming the rule broken.
pub fn decode_config(bytes: &[u8]) -> Result<WitnessConfig, WitnessError> {
    if bytes.len() > MAX_CONFIG_LEN {
        return Err(bad("too long"));
    }
    let limits = ParseLimits::default()
        .with_max_input_bytes(MAX_CONFIG_LEN)
        .with_max_depth(3)
        .with_max_container_len(8)
        .with_max_string_bytes(MAX_CONFIG_LEN);
    let value = fstp_json::parse_with(bytes, &limits).map_err(|_| bad("json"))?;
    let o = value.as_object().ok_or(bad("not an object"))?;
    let mode = o.get("mode").and_then(Value::as_str);
    let allowed: &[&str] = match mode {
        Some("saas") => &[
            "credentials_dir",
            "database",
            "keyd_socket",
            "listen",
            "mode",
        ],
        Some("self_hosted") => &[
            "credentials_dir",
            "keyd_socket",
            "listen",
            "mode",
            "store_dir",
        ],
        _ => return Err(bad("mode")),
    };
    if o.keys().any(|k| !allowed.contains(&k)) || o.len() != allowed.len() {
        return Err(bad("members"));
    }
    let listen = o
        .get("listen")
        .and_then(Value::as_str)
        .and_then(|s| s.parse::<SocketAddr>().ok())
        .ok_or(bad("listen"))?;
    let store = if mode == Some("saas") {
        let d = o
            .get("database")
            .and_then(Value::as_object)
            .ok_or(bad("database"))?;
        let names = ["dbname", "host", "port", "role"];
        if d.keys().any(|k| !names.contains(&k)) || d.len() != names.len() {
            return Err(bad("database members"));
        }
        let text = |name: &str| -> Result<String, WitnessError> {
            match d.get(name).and_then(Value::as_str) {
                Some(s) if !s.is_empty() && s.bytes().all(|b| b.is_ascii_graphic()) => {
                    Ok(s.to_owned())
                }
                _ => Err(bad("database")),
            }
        };
        WitnessStore::Database {
            host: text("host")?,
            port: d
                .get("port")
                .and_then(Value::as_u64)
                .and_then(|p| u16::try_from(p).ok())
                .filter(|p| *p != 0)
                .ok_or(bad("port"))?,
            role: text("role")?,
            dbname: text("dbname")?,
        }
    } else {
        WitnessStore::Files {
            dir: path(o.get("store_dir"), "store_dir")?,
        }
    };
    Ok(WitnessConfig {
        listen,
        credentials_dir: path(o.get("credentials_dir"), "credentials_dir")?,
        keyd_socket: path(o.get("keyd_socket"), "keyd_socket")?,
        store,
    })
}

/// A decoded receipt key file.
#[derive(Clone, PartialEq, Eq)]
pub struct ReceiptKeyFile {
    /// The root epoch of the witness's `fstp-keyd` entry.
    pub epoch: u64,
    /// The custody handle of that root.
    pub handle: Vec<u8>,
    /// `S(e)`, wrapped under the root.
    pub wrapped: Vec<u8>,
    /// The AES-256-GCM nonce of the sealed key.
    pub nonce: [u8; fstp_crypto::aead::NONCE_LEN],
    /// The sealed composite private key.
    pub sealed: Vec<u8>,
}

impl std::fmt::Debug for ReceiptKeyFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReceiptKeyFile")
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

/// The AAD of the custody wrap of `S(e)`.
#[must_use]
pub fn wrap_aad(epoch: u64) -> Vec<u8> {
    [
        &RECEIPT_KEY_MAGIC[..],
        fstp_keys::Chain::ControlPlane.name().as_bytes(),
        &epoch.to_be_bytes(),
    ]
    .concat()
}

/// The AAD of the sealed composite private key.
#[must_use]
pub fn seal_aad(epoch: u64) -> Vec<u8> {
    [
        &RECEIPT_KEY_MAGIC[..],
        fstp_keys::Chain::ControlPlane.name().as_bytes(),
        &[RECEIPT_KEY_PURPOSE],
        &epoch.to_be_bytes(),
    ]
    .concat()
}

fn put16(out: &mut Vec<u8>, field: &[u8]) -> Result<(), WitnessError> {
    if field.is_empty() || field.len() > MAX_KEY_FIELD_LEN {
        return Err(bad("key file field"));
    }
    let len = u16::try_from(field.len()).map_err(|_| bad("key file field"))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(field);
    Ok(())
}

/// Encodes a receipt key file.
///
/// # Errors
///
/// [`WitnessError::Config`] for an empty or overlong field, or a sealed
/// key of another length.
pub fn encode_receipt_key_file(f: &ReceiptKeyFile) -> Result<Vec<u8>, WitnessError> {
    if f.sealed.len() != SEALED_KEY_LEN {
        return Err(bad("sealed key length"));
    }
    let mut out = RECEIPT_KEY_MAGIC.to_vec();
    out.extend_from_slice(&f.epoch.to_be_bytes());
    put16(&mut out, &f.handle)?;
    put16(&mut out, &f.wrapped)?;
    out.extend_from_slice(&f.nonce);
    out.extend_from_slice(&f.sealed);
    Ok(out)
}

/// Decodes a receipt key file. Fuzzed (`witness_config_decode`).
///
/// # Errors
///
/// [`WitnessError::Config`] for a wrong magic, a cut or overlong field,
/// or trailing bytes.
pub fn decode_receipt_key_file(bytes: &[u8]) -> Result<ReceiptKeyFile, WitnessError> {
    let mut r = fstp_audit::codec::Reader::new(bytes);
    let e = |_| bad("key file");
    if r.take(RECEIPT_KEY_MAGIC.len()).map_err(e)? != RECEIPT_KEY_MAGIC {
        return Err(bad("key file magic"));
    }
    let epoch = r.be64().map_err(e)?;
    let field = |r: &mut fstp_audit::codec::Reader<'_>| -> Result<Vec<u8>, WitnessError> {
        let len = usize::from(r.be16().map_err(e)?);
        if len == 0 || len > MAX_KEY_FIELD_LEN {
            return Err(bad("key file field"));
        }
        Ok(r.take(len).map_err(e)?.to_vec())
    };
    let handle = field(&mut r)?;
    let wrapped = field(&mut r)?;
    let nonce = r.array::<{ fstp_crypto::aead::NONCE_LEN }>().map_err(e)?;
    let sealed = r.take(SEALED_KEY_LEN).map_err(e)?.to_vec();
    r.finish().map_err(e)?;
    Ok(ReceiptKeyFile {
        epoch,
        handle,
        wrapped,
        nonce,
        sealed,
    })
}

/// The custody root reference of a key file: the witness's own
/// `fstp-keyd` entry, chain ControlPlane, of no cell.
#[must_use]
pub fn root_of(f: &ReceiptKeyFile) -> fstp_custody::RootRef {
    fstp_custody::RootRef {
        backend: fstp_custody::BackendId::Keyd,
        cell: None,
        chain: fstp_keys::Chain::ControlPlane,
        epoch: fstp_keys::Epoch(f.epoch),
        handle: fstp_custody::CustodyHandle(f.handle.clone()),
    }
}

/// Seals `key` under `seal`, the unwrapped `S(e)` of epoch `epoch`, into
/// a key file with the custody `handle` and the wrapped `S(e)`. The
/// install runs this once, at first start (ADR-004 part 2).
///
/// # Errors
///
/// [`WitnessError::Signing`] when the key does not export or the seal
/// fails, and the errors of [`encode_receipt_key_file`].
pub fn seal_receipt_key(
    key: &fstp_crypto::composite::CompositeSigningKey,
    seal: &fstp_custody::SealKey,
    epoch: u64,
    handle: &[u8],
    wrapped: &[u8],
) -> Result<Vec<u8>, WitnessError> {
    let aead = fstp_crypto::aead::Key::from_bytes(seal.expose()).map_err(WitnessError::Signing)?;
    let secret = key.to_bytes().map_err(WitnessError::Signing)?;
    let sealed = fstp_crypto::aead::seal(&aead, &seal_aad(epoch), &secret[..])
        .map_err(WitnessError::Signing)?;
    encode_receipt_key_file(&ReceiptKeyFile {
        epoch,
        handle: handle.to_vec(),
        wrapped: wrapped.to_vec(),
        nonce: sealed.nonce,
        sealed: sealed.body,
    })
}

/// Opens the receipt key of `f` under `seal`, the `S(e)` that custody
/// unwrapped for it.
///
/// # Errors
///
/// [`WitnessError::Signing`] when the sealed key does not open or does
/// not read as a composite private key.
pub fn open_receipt_key(
    f: &ReceiptKeyFile,
    seal: &fstp_custody::SealKey,
) -> Result<fstp_crypto::composite::CompositeSigningKey, WitnessError> {
    let aead = fstp_crypto::aead::Key::from_bytes(seal.expose()).map_err(WitnessError::Signing)?;
    let secret = fstp_crypto::aead::open(&aead, &f.nonce, &seal_aad(f.epoch), &f.sealed)
        .map_err(WitnessError::Signing)?;
    fstp_crypto::composite::CompositeSigningKey::from_bytes(&secret).map_err(WitnessError::Signing)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        reason = "test code asserts on known-good values"
    )]

    use super::*;

    /// ADR-010 open point 6: each mode takes exactly its own member set.
    /// A SaaS witness names its database, a self-hosted witness its store.
    #[test]
    fn adr010_witness_config_takes_one_form_per_mode() {
        let saas = br#"{"credentials_dir":"/etc/fstp/witness","database":{"dbname":"witness","host":"db.internal","port":5432,"role":"witness_service"},"keyd_socket":"/run/fstp-keyd/witness.sock","listen":"0.0.0.0:7443","mode":"saas"}"#;
        let own = br#"{"credentials_dir":"/etc/fstp/witness","keyd_socket":"/run/fstp-keyd/witness.sock","listen":"127.0.0.1:7443","mode":"self_hosted","store_dir":"/var/lib/fstp-witness"}"#;
        assert!(matches!(
            decode_config(saas).unwrap().store,
            WitnessStore::Database { port: 5432, .. }
        ));
        assert!(matches!(
            decode_config(own).unwrap().store,
            WitnessStore::Files { .. }
        ));
        for bad in [
            &br#"{"credentials_dir":"/c","keyd_socket":"/k","listen":"127.0.0.1:1","mode":"self_hosted"}"#[..],
            br#"{"credentials_dir":"/c","keyd_socket":"/k","listen":"127.0.0.1:1","mode":"self_hosted","store_dir":"/s","database":{}}"#,
            br#"{"credentials_dir":"/c","keyd_socket":"/k","listen":"127.0.0.1:1","mode":"saas","store_dir":"/s"}"#,
            br#"{"credentials_dir":"/c","keyd_socket":"/k","listen":"nowhere","mode":"self_hosted","store_dir":"/s"}"#,
            br#"{"credentials_dir":"/c","keyd_socket":"/k","listen":"127.0.0.1:1","mode":"intermediary","store_dir":"/s"}"#,
            br#"{"credentials_dir":"/c","keyd_socket":"/k","listen":"127.0.0.1:1","mode":"self_hosted","store_dir":"/s","password":"x"}"#,
        ] {
            assert!(decode_config(bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
    }

    /// ADR-004 part 2, Q-D: a receipt key sealed under `S(e)` opens under
    /// the same `S(e)` only, and its file round-trips. A cut file, a file
    /// with a trailing byte and a file of another epoch are refused.
    #[test]
    fn adr004_receipt_key_file_round_trips_and_opens_under_its_seal_key_only() {
        let key = fstp_crypto::composite::generate().unwrap();
        let seal = fstp_custody::SealKey::generate().unwrap();
        let other = fstp_custody::SealKey::generate().unwrap();
        let file = seal_receipt_key(&key, &seal, 3, b"handle", b"wrapped").unwrap();
        let f = decode_receipt_key_file(&file).unwrap();
        assert_eq!(encode_receipt_key_file(&f).unwrap(), file);
        let opened = open_receipt_key(&f, &seal).unwrap();
        assert_eq!(opened.public_key().to_bytes(), key.public_key().to_bytes());
        assert!(open_receipt_key(&f, &other).is_err());
        let mut moved = f.clone();
        moved.epoch = 4;
        assert!(open_receipt_key(&moved, &seal).is_err(), "another epoch");
        assert!(decode_receipt_key_file(&file[..file.len() - 1]).is_err());
        let mut longer = file.clone();
        longer.push(0);
        assert!(decode_receipt_key_file(&longer).is_err());
    }
}
