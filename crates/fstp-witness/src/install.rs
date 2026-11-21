//! The install commands of a self-hosted witness (ADR-028 "Witness key
//! commands", ADR-004 part 2 "Self-hosted witness receipt key", ADR-010
//! open point 6). Lane L19.
//!
//! - `init-keys <dir>` creates the receipt key file once, through the
//!   witness's own custody entry, and writes the receipt public key as one
//!   lowercase hex line to `<dir>/receipt.pub`. The receipt private key
//!   exists only between its generation and its seal.
//! - `register <cell> <cell-ca.pem> <app-anchor.pub> <vault-anchor.pub>`
//!   registers a cell's CA and its two anchor keys in the file store of a
//!   self-hosted witness. A repeat changes nothing. The witness must be
//!   stopped, since it reads its registry at start.
//!
//! Both read the configuration named by [`crate::CONFIG_ENV`]. They write
//! no output (R-NF-02).

use std::path::Path;

use fstp_audit::{CellId, ChainId};
use fstp_custody::{Aad, Custody as _, KeydCustody, RootLabel, SealKey};

use crate::WitnessError;
use crate::config::{self, WitnessConfig, WitnessStore};

/// The name of the public key file `init-keys` writes.
pub const RECEIPT_PUBLIC_FILE: &str = "receipt.pub";

/// The epoch of a new receipt key file.
const FIRST_EPOCH: u64 = 1;

fn load() -> Result<WitnessConfig, WitnessError> {
    let path =
        std::env::var_os(crate::CONFIG_ENV).ok_or(WitnessError::Config(crate::CONFIG_ENV))?;
    let bytes = std::fs::read(&path).map_err(|_| WitnessError::Config(crate::CONFIG_ENV))?;
    config::decode_config(&bytes)
}

fn write_new(path: &Path, bytes: &[u8], mode: u32) -> Result<(), WitnessError> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .map_err(|e| WitnessError::Io(e.kind()))?;
    f.write_all(bytes)
        .and_then(|()| f.sync_all())
        .map_err(|e| WitnessError::Io(e.kind()))
}

/// Lowercase hex of `bytes`.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// The bytes of one line of lowercase hex.
#[must_use]
pub fn unhex(t: &str) -> Option<Vec<u8>> {
    if !t.len().is_multiple_of(2) || t.is_empty() {
        return None;
    }
    let digit = |b: u8| match b {
        b'0'..=b'9' => Some(b.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(b.wrapping_sub(b'a').wrapping_add(10)),
        _ => None,
    };
    t.as_bytes()
        .chunks_exact(2)
        .map(|p| Some((digit(*p.first()?)? << 4) | digit(*p.get(1)?)?))
        .collect()
}

/// The DER of the first certificate of a PEM text.
#[must_use]
pub fn pem_der(pem: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(pem).ok()?;
    let body: String = text
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN CERTIFICATE-----"))
        .skip(1)
        .take_while(|l| !l.starts_with("-----END"))
        .collect();
    if body.is_empty() {
        return None;
    }
    fstp_pgwire::base64::decode(body.as_bytes()).ok()
}

/// `init-keys <dir>` (module documentation).
///
/// # Errors
///
/// [`WitnessError::Io`] for a key file that exists already or a file that
/// does not write, [`WitnessError::Custody`] when custody refuses.
pub fn init_keys(out: &Path) -> Result<(), WitnessError> {
    let cfg = load()?;
    let key_path = cfg.credentials_dir.join(config::RECEIPT_KEY_FILE);
    if key_path.exists() {
        return Err(WitnessError::Io(std::io::ErrorKind::AlreadyExists));
    }
    let custody =
        KeydCustody::new(&cfg.keyd_socket).map_err(|_| WitnessError::Config("keyd_socket"))?;
    let rt = fstp_rt::tokio::TokioRuntime::new_multi_thread(1)
        .map_err(|e| WitnessError::Io(e.kind()))?;
    let (handle, wrapped, seal) = rt.block_on(async {
        let root = custody
            .create_root(RootLabel {
                cell: None,
                chain: fstp_keys::Chain::ControlPlane,
                epoch: fstp_keys::Epoch(FIRST_EPOCH),
            })
            .await
            .map_err(|_| WitnessError::Custody)?;
        let seal = SealKey::generate().map_err(|_| WitnessError::Custody)?;
        let wrapped = custody
            .wrap(&root, &seal, &Aad(config::wrap_aad(FIRST_EPOCH)))
            .await
            .map_err(|_| WitnessError::Custody)?;
        Ok::<_, WitnessError>((root.handle.0, wrapped.0, seal))
    })?;
    let key = fstp_crypto::composite::generate().map_err(WitnessError::Signing)?;
    let file = config::seal_receipt_key(&key, &seal, FIRST_EPOCH, &handle, &wrapped)?;
    let public = hex(&key.public_key().to_bytes());
    drop(key);
    drop(seal);
    write_new(&key_path, &file, 0o600)?;
    write_new(
        &out.join(RECEIPT_PUBLIC_FILE),
        format!("{public}\n").as_bytes(),
        0o644,
    )
}

fn now_us() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_micros()).ok())
        .unwrap_or(0)
}

/// `register <cell> <cell-ca.pem> <app-anchor.pub> <vault-anchor.pub>`
/// (module documentation).
///
/// # Errors
///
/// [`WitnessError::Config`] for a SaaS witness or a malformed argument
/// file, [`WitnessError::Store`] when the store refuses, for example a
/// cell registered before with another CA.
pub fn register(
    cell: &str,
    ca_pem: &Path,
    app_anchor: &Path,
    vault_anchor: &Path,
) -> Result<(), WitnessError> {
    let cfg = load()?;
    let WitnessStore::Files { dir } = &cfg.store else {
        return Err(WitnessError::Config("register needs a self-hosted witness"));
    };
    let cell: [u8; 16] = unhex(cell)
        .and_then(|b| b.try_into().ok())
        .ok_or(WitnessError::Config("cell"))?;
    let read = |p: &Path, rule: &'static str| -> Result<Vec<u8>, WitnessError> {
        let text = std::fs::read_to_string(p).map_err(|_| WitnessError::Config(rule))?;
        unhex(text.trim()).ok_or(WitnessError::Config(rule))
    };
    let ca = std::fs::read(ca_pem).map_err(|_| WitnessError::Config("cell CA"))?;
    let ca = pem_der(&ca).ok_or(WitnessError::Config("cell CA"))?;
    let app = read(app_anchor, "app anchor")?;
    let vault = read(vault_anchor, "vault anchor")?;
    let mut fs = crate::file_store::FileStore::open(dir).map_err(WitnessError::Store)?;
    let at = now_us();
    fs.register_cell(CellId(cell), &ca, at)
        .map_err(WitnessError::Store)?;
    fs.register_anchor_key(CellId(cell), ChainId::App, &app, at)
        .map_err(WitnessError::Store)?;
    fs.register_anchor_key(CellId(cell), ChainId::Vault, &vault, at)
        .map_err(WitnessError::Store)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    /// ADR-028: public key files and the cell id read as lowercase hex
    /// only.
    #[test]
    fn adr028_install_reads_lowercase_hex_only() {
        assert_eq!(unhex("00ff").unwrap(), vec![0, 255]);
        assert!(unhex("0F").is_none());
        assert!(unhex("abc").is_none());
        assert!(unhex("").is_none());
        assert!(pem_der(b"no certificate").is_none());
    }
}
