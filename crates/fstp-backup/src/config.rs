//! The configuration file of `fstp-backup` and its credentials (ADR-012
//! record of lane L10, in the style of ADR-026 "Configuration").
//!
//! One JSON object in the file that [`CONFIG_ENV`] names, at most
//! [`MAX_FILE_LEN`] bytes, with these members and no other:
//!
//! - `cluster`: 32 lowercase hex digits, the cluster that owns the
//!   ClusterBackup group.
//! - `credentials_dir`, `state_dir`, `pg_bindir`: absolute paths.
//! - `database`: `host`, a loopback address literal, and `port`.
//! - `object_store`: `endpoint` (a host name), `port` (optional, 443),
//!   `region` and `bucket`. Or `object_stores`, a list of one to
//!   [`MAX_STORES`] such stores, in order (ADR-012 record of lane
//!   m10/backup-format). Exactly one of the two is given.
//! - `keyd_socket`: optional, absolute. The `fstp-keyd` console socket,
//!   for `init-keys` and the restore commands only.
//!
//! An unknown member, a member given twice or a missing required member is
//! refused, so a typo never falls back to a default. No secret is in the
//! file. The credentials directory holds them by fixed name, and each
//! command reads only the ones it needs. Fuzzed (`backup_config_decode`).
//! A refusal names its rule and never quotes the input (R-NF-02).

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use fstp_json::{Object, ParseLimits};

use crate::BackupError;
use crate::s3::Endpoint;
use crate::sigv4::Credentials;

/// The environment variable that names the configuration file.
pub const CONFIG_ENV: &str = "FSTP_BACKUP_CONFIG";
/// The largest configuration file, in bytes.
pub const MAX_FILE_LEN: usize = 4096;
/// The longest path.
pub const MAX_PATH_LEN: usize = 1024;

const MEMBERS: [&str; 8] = [
    "cluster",
    "credentials_dir",
    "state_dir",
    "pg_bindir",
    "database",
    "object_store",
    "object_stores",
    "keyd_socket",
];

/// The most object stores a configuration names (ADR-012 record of lane
/// m10/backup-format).
pub const MAX_STORES: usize = 3;

/// The loopback database login of `pg_basebackup`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DatabaseConfig {
    /// The loopback address.
    pub host: IpAddr,
    /// The port.
    pub port: u16,
}

/// A decoded configuration file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileConfig {
    /// The cluster.
    pub cluster: [u8; 16],
    /// The credentials directory.
    pub credentials_dir: PathBuf,
    /// The state directory, which holds the base backup index.
    pub state_dir: PathBuf,
    /// The PostgreSQL binaries.
    pub pg_bindir: PathBuf,
    /// The database.
    pub database: DatabaseConfig,
    /// The first object store.
    pub object_store: Endpoint,
    /// The further object stores, in order: each container goes to every
    /// store (ADR-012 record of lane m10/backup-format).
    pub more_stores: Vec<Endpoint>,
    /// The `fstp-keyd` console socket, if any.
    pub keyd_socket: Option<PathBuf>,
}

fn cfg(rule: &'static str) -> BackupError {
    BackupError::Config(rule)
}

fn limits() -> ParseLimits {
    ParseLimits::default()
        .with_max_input_bytes(MAX_FILE_LEN)
        .with_max_depth(3)
        .with_max_container_len(10)
        .with_max_string_bytes(MAX_PATH_LEN)
}

fn members(o: &Object, allowed: &[&str], rule: &'static str) -> Result<(), BackupError> {
    if o.keys().any(|k| k.is_empty() || !allowed.contains(&k)) {
        return Err(cfg(rule));
    }
    Ok(())
}

fn text<'a>(o: &'a Object, name: &str, rule: &'static str) -> Result<&'a str, BackupError> {
    o.get(name).ok_or(cfg(rule))?.as_str().ok_or(cfg(rule))
}

fn path_of(s: &str, rule: &'static str) -> Result<PathBuf, BackupError> {
    if !s.starts_with('/') || s.len() > MAX_PATH_LEN || s.contains('\0') {
        return Err(cfg(rule));
    }
    Ok(PathBuf::from(s))
}

fn port_of(
    v: Option<&fstp_json::Value>,
    default: Option<u16>,
    rule: &'static str,
) -> Result<u16, BackupError> {
    match v {
        None => default.ok_or(cfg(rule)),
        Some(v) => v
            .as_u64()
            .and_then(|p| u16::try_from(p).ok())
            .filter(|p| *p != 0)
            .ok_or(cfg(rule)),
    }
}

fn hex16(s: &str, rule: &'static str) -> Result<[u8; 16], BackupError> {
    let b = s.as_bytes();
    if b.len() != 32 {
        return Err(cfg(rule));
    }
    let mut out = [0u8; 16];
    for (slot, pair) in out.iter_mut().zip(b.chunks_exact(2)) {
        let n = |c: Option<&u8>| match c {
            Some(c @ b'0'..=b'9') => Some(c.wrapping_sub(b'0')),
            Some(c @ b'a'..=b'f') => Some(c.wrapping_sub(b'a').wrapping_add(10)),
            _ => None,
        };
        *slot = (n(pair.first()).ok_or(cfg(rule))? << 4) | n(pair.get(1)).ok_or(cfg(rule))?;
    }
    Ok(out)
}

/// Whether `name` is a host name: `localhost`, or lowercase letters,
/// digits and hyphens in dot-separated labels of 1 to 63 bytes, at most
/// 253 bytes, with a last label that is not all digits.
#[must_use]
pub fn is_host_name(name: &str) -> bool {
    if name == "localhost" {
        return true;
    }
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

/// Whether `b` is a bucket name this client addresses path-style: 3 to
/// 63 lowercase letters, digits and hyphens, starting and ending with a
/// letter or digit.
#[must_use]
pub fn is_bucket(b: &str) -> bool {
    (3..=63).contains(&b.len())
        && b.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        && !b.starts_with('-')
        && !b.ends_with('-')
}

/// Decodes and checks a configuration file (module documentation).
/// Fuzzed (`backup_config_decode`).
///
/// # Errors
///
/// [`BackupError::Config`] naming the rule broken. It never quotes the
/// input (R-NF-02).
pub fn decode_file(bytes: &[u8]) -> Result<FileConfig, BackupError> {
    if bytes.len() > MAX_FILE_LEN {
        return Err(cfg("length"));
    }
    let value = fstp_json::parse_with(bytes, &limits()).map_err(|_| cfg("JSON object"))?;
    let o = value.as_object().ok_or(cfg("JSON object"))?;
    members(o, &MEMBERS, "unknown member")?;
    let cluster = hex16(text(o, "cluster", "cluster")?, "cluster")?;
    let credentials_dir = path_of(
        text(o, "credentials_dir", "credentials_dir")?,
        "credentials_dir",
    )?;
    let state_dir = path_of(text(o, "state_dir", "state_dir")?, "state_dir")?;
    let pg_bindir = path_of(text(o, "pg_bindir", "pg_bindir")?, "pg_bindir")?;
    let db = o
        .get("database")
        .and_then(|v| v.as_object())
        .ok_or(cfg("database"))?;
    members(db, &["host", "port"], "database")?;
    let host: IpAddr = text(db, "host", "database.host")?
        .parse()
        .map_err(|_| cfg("database.host"))?;
    // ADR-005: `fstp_repl` logs in over loopback only.
    if !host.is_loopback() {
        return Err(cfg("database.host"));
    }
    let port = port_of(db.get("port"), None, "database.port")?;
    let mut stores = match (o.get("object_store"), o.get("object_stores")) {
        (Some(v), None) => vec![decode_object_store(
            v.as_object().ok_or(cfg("object_store"))?,
        )?],
        (None, Some(v)) => {
            let list = v.as_array().ok_or(cfg("object_stores"))?;
            if list.is_empty() || list.len() > MAX_STORES {
                return Err(cfg("object_stores"));
            }
            list.iter()
                .map(|s| decode_object_store(s.as_object().ok_or(cfg("object_stores"))?))
                .collect::<Result<Vec<_>, _>>()?
        }
        _ => return Err(cfg("object_store")),
    };
    let object_store = stores.remove(0);
    let more_stores = stores;
    let keyd_socket = match o.get("keyd_socket") {
        None => None,
        Some(v) => Some(path_of(
            v.as_str().ok_or(cfg("keyd_socket"))?,
            "keyd_socket",
        )?),
    };
    Ok(FileConfig {
        cluster,
        credentials_dir,
        state_dir,
        pg_bindir,
        database: DatabaseConfig { host, port },
        object_store,
        more_stores,
        keyd_socket,
    })
}

/// Decodes the `object_store` member: `endpoint` (a host name), `port`
/// (optional, 443), `region` and `bucket`, and no other. The cell and the
/// vault configurations take the same member for their keystore
/// snapshots (ADR-012 record of lane L17).
///
/// # Errors
///
/// [`BackupError::Config`] naming the rule broken.
pub fn decode_object_store(os: &Object) -> Result<Endpoint, BackupError> {
    members(
        os,
        &["endpoint", "port", "region", "bucket"],
        "object_store",
    )?;
    let endpoint = text(os, "endpoint", "object_store.endpoint")?;
    if !is_host_name(endpoint) {
        return Err(cfg("object_store.endpoint"));
    }
    let os_port = port_of(os.get("port"), Some(443), "object_store.port")?;
    let region = text(os, "region", "object_store.region")?;
    if !(1..=32).contains(&region.len())
        || !region
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(cfg("object_store.region"));
    }
    let bucket = text(os, "bucket", "object_store.bucket")?;
    if !is_bucket(bucket) {
        return Err(cfg("object_store.bucket"));
    }
    Ok(Endpoint {
        host: endpoint.to_owned(),
        port: os_port,
        region: region.to_owned(),
        bucket: bucket.to_owned(),
    })
}

/// Reads the configuration file named by [`CONFIG_ENV`].
///
/// # Errors
///
/// [`BackupError::Config`] for a missing, unreadable or refused file.
pub fn load() -> Result<FileConfig, BackupError> {
    let path = std::env::var_os(CONFIG_ENV).ok_or(cfg(CONFIG_ENV))?;
    load_from(Path::new(&path))
}

/// Reads and decodes the configuration file `path`.
///
/// # Errors
///
/// As for [`load`].
pub fn load_from(path: &Path) -> Result<FileConfig, BackupError> {
    use std::io::Read as _;
    let f = std::fs::File::open(path).map_err(|_| cfg("configuration file"))?;
    let mut bytes = Vec::new();
    f.take(
        u64::try_from(MAX_FILE_LEN)
            .unwrap_or(u64::MAX)
            .saturating_add(1),
    )
    .read_to_end(&mut bytes)
    .map_err(|_| cfg("configuration file"))?;
    decode_file(&bytes)
}

/// Reads the credential `name`. The error names the file, never its
/// bytes.
///
/// # Errors
///
/// [`BackupError::Config`] naming the file.
pub fn read_credential(dir: &Path, name: &'static str) -> Result<Vec<u8>, BackupError> {
    std::fs::read(dir.join(name)).map_err(|_| cfg(name))
}

/// Reads a one-line secret, without its line end.
///
/// # Errors
///
/// As for [`read_credential`], and for a file that is not UTF-8.
pub fn read_secret(dir: &Path, name: &'static str) -> Result<String, BackupError> {
    let text = String::from_utf8(read_credential(dir, name)?).map_err(|_| cfg(name))?;
    Ok(text.trim_end_matches(['\r', '\n']).to_owned())
}

/// The object store credentials of the credentials directory.
///
/// # Errors
///
/// [`BackupError::Config`] naming the file.
pub fn s3_credentials(dir: &Path) -> Result<Credentials, BackupError> {
    let id = read_secret(dir, "s3-access-key-id")?;
    let secret = read_secret(dir, "s3-secret-access-key")?;
    Credentials::new(&id, &secret)
}

/// The credential file names of store `n` from 1 (ADR-012 record of lane
/// m10/backup-format): access key id, secret access key and CA.
const MORE_STORE_FILES: [[&str; 3]; MAX_STORES - 1] = [
    [
        "s3-1-access-key-id",
        "s3-1-secret-access-key",
        "s3-1-ca.pem",
    ],
    [
        "s3-2-access-key-id",
        "s3-2-secret-access-key",
        "s3-2-ca.pem",
    ],
];

/// The credentials and the optional pinned CA of store `n`: store 0 takes
/// the files of the record of lane L10, store `n` from 1 takes
/// `s3-<n>-access-key-id`, `s3-<n>-secret-access-key` and optionally
/// `s3-<n>-ca.pem`.
///
/// # Errors
///
/// [`BackupError::Config`] naming the file.
pub fn store_credentials(
    dir: &Path,
    n: usize,
) -> Result<(Credentials, Option<Vec<u8>>), BackupError> {
    let Some(i) = n.checked_sub(1) else {
        return Ok((s3_credentials(dir)?, s3_ca(dir)?));
    };
    let [id, secret, ca] = *MORE_STORE_FILES.get(i).ok_or(cfg("object_stores"))?;
    let credentials = Credentials::new(&read_secret(dir, id)?, &read_secret(dir, secret)?)?;
    let ca = match std::fs::read(dir.join(ca)) {
        Ok(pem) => Some(pem),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => return Err(cfg(ca)),
    };
    Ok((credentials, ca))
}

/// The optional pinned CA of the object store.
///
/// # Errors
///
/// [`BackupError::Config`] for a file that exists and cannot be read.
pub fn s3_ca(dir: &Path) -> Result<Option<Vec<u8>>, BackupError> {
    match std::fs::read(dir.join("s3-ca.pem")) {
        Ok(pem) => Ok(Some(pem)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(cfg("s3-ca.pem")),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    pub(crate) const GOOD: &str = r#"{
      "cluster": "00112233445566778899aabbccddeeff",
      "credentials_dir": "/etc/fstp/backup",
      "state_dir": "/var/lib/fstp-backup",
      "pg_bindir": "/usr/lib/postgresql/16/bin",
      "database": {"host": "127.0.0.1", "port": 5432},
      "object_store": {"endpoint": "s3.gra.io.cloud.ovh.net", "region": "gra", "bucket": "fstp-pilot-backups"},
      "keyd_socket": "/run/fstp-keyd/console.sock"
    }"#;

    /// ADR-012 record of lane L10: the documented form decodes.
    #[test]
    fn adr012_config_decodes() {
        let c = decode_file(GOOD.as_bytes()).unwrap();
        assert_eq!(c.cluster[0], 0x00);
        assert_eq!(c.cluster[15], 0xff);
        assert_eq!(c.object_store.port, 443);
        assert_eq!(c.object_store.host_header(), "s3.gra.io.cloud.ovh.net");
        assert_eq!(c.database.port, 5432);
        assert!(c.keyd_socket.is_some());
    }

    /// ADR-012, ADR-005: unknown, missing and malformed members are
    /// refused, and the database login is loopback only.
    #[test]
    fn adr012_config_refuses_other_forms() {
        let cases = [
            ("\"keyd_socket\"", "\"keyd_sockt\""),
            ("\"127.0.0.1\"", "\"10.0.0.5\""),
            ("\"127.0.0.1\"", "\"localhost\""),
            ("\"/etc/fstp/backup\"", "\"etc/fstp/backup\""),
            (
                "00112233445566778899aabbccddeeff",
                "00112233445566778899AABBCCDDEEFF",
            ),
            ("\"fstp-pilot-backups\"", "\"Fstp_Backups\""),
            ("\"gra\"", "\"\""),
            ("\"s3.gra.io.cloud.ovh.net\"", "\"10.0.0.1\""),
            ("5432", "0"),
            (
                "\"region\": \"gra\",",
                "\"region\": \"gra\", \"secret\": \"x\",",
            ),
        ];
        for (from, to) in cases {
            let text = GOOD.replacen(from, to, 1);
            assert_ne!(text, GOOD, "{from}");
            assert!(decode_file(text.as_bytes()).is_err(), "{to}");
        }
        let missing = GOOD.replace("\"state_dir\": \"/var/lib/fstp-backup\",", "");
        assert!(decode_file(missing.as_bytes()).is_err());
        let twice = GOOD.replace("{\n", "{\n \"state_dir\": \"/x\",\n");
        assert!(decode_file(twice.as_bytes()).is_err());
        assert!(decode_file(b"[]").is_err());
        assert!(decode_file(&vec![b' '; MAX_FILE_LEN + 1]).is_err());
    }

    /// Q25, ADR-012 record of lane m10/backup-format: `object_stores` takes
    /// one to three stores in order, one entry stays valid, and the single
    /// `object_store` still reads. Both together, none, an empty list and
    /// four stores are refused.
    #[test]
    fn adr012_config_takes_a_list_of_stores() {
        let one = r#"{"endpoint": "s3.gra.io.cloud.ovh.net", "region": "gra", "bucket": "fstp-pilot-backups"}"#;
        let two = r#"{"endpoint": "s3.fr-par.scw.cloud", "port": 8443, "region": "fr-par", "bucket": "fstp-copy"}"#;
        let single = format!("\"object_store\": {one},");
        let with = |member: &str| GOOD.replacen(&single, member, 1);
        assert_ne!(with("X"), GOOD);
        let c =
            decode_file(with(&format!("\"object_stores\": [{one}, {two}],")).as_bytes()).unwrap();
        assert_eq!(c.object_store.bucket, "fstp-pilot-backups");
        assert_eq!(c.more_stores.len(), 1);
        assert_eq!(
            (c.more_stores[0].port, c.more_stores[0].region.as_str()),
            (8443, "fr-par")
        );
        let c = decode_file(with(&format!("\"object_stores\": [{one}],")).as_bytes()).unwrap();
        assert!(c.more_stores.is_empty());
        assert_eq!(c, decode_file(GOOD.as_bytes()).unwrap());
        for bad in [
            format!("{single} \"object_stores\": [{one}],"),
            String::new(),
            "\"object_stores\": [],".to_owned(),
            format!("\"object_stores\": [{one}, {one}, {one}, {one}],"),
            format!("\"object_stores\": {one},"),
            "\"object_stores\": [{\"endpoint\": \"10.0.0.1\", \"region\": \"gra\", \"bucket\": \"abc\"}],".to_owned(),
        ] {
            assert!(decode_file(with(&bad).as_bytes()).is_err(), "{bad}");
        }
    }

    /// R-NF-02: a refused configuration never quotes its bytes, and a
    /// missing credential names the file only.
    #[test]
    fn r_nf_02_config_errors_never_quote_secret_bytes() {
        let canary = "S3cr3t_canary_77f0";
        for text in [
            GOOD.replace("\"gra\"", &format!("\"{canary}\"")),
            GOOD.replace("\"cluster\"", &format!("\"{canary}\"")),
            GOOD.replace("/etc/fstp/backup", canary),
            format!("{{\"cluster\": \"{canary}\"}}"),
            canary.to_owned(),
        ] {
            let e = decode_file(text.as_bytes()).unwrap_err();
            let shown = format!("{e} {e:?}");
            assert!(!shown.contains("canary"), "{shown}");
        }
        let dir = std::env::temp_dir().join(format!(
            "fstp-backup-cfg-{}",
            sigv4_hex(&fstp_crypto::random_array::<8>().unwrap())
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("s3-access-key-id"), "AKID\n").unwrap();
        std::fs::write(
            dir.join("s3-secret-access-key"),
            format!("{canary} with space\n"),
        )
        .unwrap();
        let e = s3_credentials(&dir).unwrap_err();
        assert!(!format!("{e} {e:?}").contains("canary"));
        std::fs::write(dir.join("s3-secret-access-key"), format!("{canary}\n")).unwrap();
        let c = s3_credentials(&dir).unwrap();
        assert!(!format!("{c:?}").contains("canary"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn sigv4_hex(b: &[u8]) -> String {
        crate::sigv4::hex(b)
    }
}
