//! Off-host copies of the witness receipt key file (ADR-004 record of
//! lane L16, Q-L16-3, decided by Daniel on 2026-11-21, I-81).
//!
//! `fstp-witness copy-key-file <out>` opens `receipt.key` through the
//! witness's own `fstp-keyd` entry, writes its sealed bytes to `<out>` and
//! records the copy in `receipt.copies` beside it, with a digest of the
//! receipt key ([`fstp_custody::copies`]). The copy never holds an open
//! key (I-80).
//!
//! At each start the witness compares the register with its live receipt
//! key. While a copy that is not retired holds a key the live file no
//! longer holds, as after a rotation of the receipt key, it logs reduced
//! I-81 assurance ([`report`]). `fstp-witness retire-key-file-copy <id>`
//! records that every copy of an id is destroyed.

use std::path::Path;

use fstp_crypto::composite::CompositeSigningKey;
use fstp_custody::copies::{self, CopyId};
use fstp_obs::LogEvent;
use fstp_obs::assurance::{Assurance, ReducedReason};

use crate::{WitnessError, config};

/// The copy register in the credentials directory.
pub const COPY_REGISTER: &str = "receipt.copies";

/// The digest of the receipt key `key`.
///
/// # Errors
///
/// [`WitnessError::Signing`] when the key does not export.
pub fn key_digests(key: &CompositeSigningKey) -> Result<Vec<[u8; 32]>, WitnessError> {
    let secret = key.to_bytes().map_err(WitnessError::Signing)?;
    Ok(vec![copies::key_digest("receipt", &secret[..])])
}

/// The I-81 assurance the copy register at `register` gives against the
/// live receipt key: reduced while a copy that is not retired holds
/// another key, and `None` otherwise. A key that does not export counts
/// as reduced.
#[must_use]
pub fn assurance(register: &Path, key: &CompositeSigningKey) -> Option<Assurance> {
    let reduced = match key_digests(key) {
        Ok(current) => copies::holds_replaced(register, &current),
        Err(_) => true,
    };
    reduced.then_some(Assurance::Reduced(ReducedReason::CopyHoldsReplacedKey))
}

/// Logs the reduced assurance of [`assurance`], if any, as a typed event.
pub fn report(register: &Path, key: &CompositeSigningKey) {
    if let Some(assurance) = assurance(register, key) {
        let _ = fstp_obs::log_to_stderr(&LogEvent::KeyFileAssurance {
            file: config::RECEIPT_KEY_FILE,
            assurance,
        });
    }
}

/// Copies the receipt key file of `creds`, opened under `seal`, to the
/// new file `out` as sealed, and records the copy.
///
/// # Errors
///
/// [`WitnessError::Config`] for an existing `out` or a refused register,
/// and the errors of opening the key.
pub fn copy_opened(
    creds: &Path,
    file: &[u8],
    key: &CompositeSigningKey,
    out: &Path,
) -> Result<CopyId, WitnessError> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let digests = key_digests(key)?;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(out)
        .map_err(|_| WitnessError::Config("copy file"))?;
    f.write_all(file)
        .and_then(|()| f.sync_all())
        .map_err(|e| WitnessError::Io(e.kind()))?;
    let id = copies::record_copy(&creds.join(COPY_REGISTER), digests)
        .map_err(|_| WitnessError::Config("copy register"))?;
    copies::write_id_file(out, id).map_err(|_| WitnessError::Config("copy id file"))?;
    Ok(id)
}

/// `fstp-witness copy-key-file <out>`: reads the configuration that
/// [`crate::CONFIG_ENV`] names, opens the receipt key through the
/// witness's `fstp-keyd` entry and copies the file.
///
/// # Errors
///
/// [`WitnessError::Config`] for a refused configuration or credential,
/// [`WitnessError::Custody`] when custody does not unwrap, and the errors
/// of [`copy_opened`].
pub fn run_copy(out: &Path) -> Result<(), WitnessError> {
    use fstp_custody::Custody as _;
    let path =
        std::env::var_os(crate::CONFIG_ENV).ok_or(WitnessError::Config(crate::CONFIG_ENV))?;
    let bytes = std::fs::read(&path).map_err(|_| WitnessError::Config(crate::CONFIG_ENV))?;
    let cfg = config::decode_config(&bytes)?;
    let creds = &cfg.credentials_dir;
    let raw = std::fs::read(creds.join(config::RECEIPT_KEY_FILE))
        .map_err(|_| WitnessError::Config(config::RECEIPT_KEY_FILE))?;
    let key_file = config::decode_receipt_key_file(&raw)?;
    let custody = fstp_custody::keyd::KeydCustody::new(&cfg.keyd_socket)
        .map_err(|_| WitnessError::Config("keyd_socket"))?;
    let rt = fstp_rt::tokio::TokioRuntime::new_multi_thread(1)
        .map_err(|e| WitnessError::Io(e.kind()))?;
    let seal = rt
        .block_on(custody.unwrap(
            &config::root_of(&key_file),
            &fstp_custody::WrappedSealKey(key_file.wrapped.clone()),
            &fstp_custody::Aad(config::wrap_aad(key_file.epoch)),
        ))
        .map_err(|_| WitnessError::Custody)?;
    let key = config::open_receipt_key(&key_file, &seal)?;
    copy_opened(creds, &raw, &key, out).map(|_| ())
}

/// `fstp-witness retire-key-file-copy <id>`: records that every copy of
/// `id` is destroyed.
///
/// # Errors
///
/// [`WitnessError::Config`] for a refused configuration or an id the
/// register holds no live copy of.
pub fn run_retire(id: CopyId) -> Result<(), WitnessError> {
    let path =
        std::env::var_os(crate::CONFIG_ENV).ok_or(WitnessError::Config(crate::CONFIG_ENV))?;
    let bytes = std::fs::read(&path).map_err(|_| WitnessError::Config(crate::CONFIG_ENV))?;
    let cfg = config::decode_config(&bytes)?;
    copies::retire_copy(&cfg.credentials_dir.join(COPY_REGISTER), id)
        .map_err(|_| WitnessError::Config("copy register"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    /// I-81, ADR-004 record of lane L16 (Q-L16-3): a copy of the receipt
    /// key file lowers the witness's assurance once the live key is
    /// replaced, and until the copy is retired. The copy is the sealed
    /// file, byte for byte, and the register holds no key.
    #[test]
    fn i81_witness_key_file_copy_reports_reduced_after_the_key_is_replaced() {
        let dir = std::env::temp_dir().join(format!("fstp-witness-l16-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let register = dir.join(COPY_REGISTER);
        let old = fstp_crypto::composite::generate().unwrap();
        let sealed_file = b"synthetic sealed receipt key file".to_vec();
        let id = copy_opened(&dir, &sealed_file, &old, &dir.join("copy")).unwrap();
        assert_eq!(std::fs::read(dir.join("copy")).unwrap(), sealed_file);
        assert_eq!(
            std::fs::read_to_string(dir.join("copy.id")).unwrap(),
            format!("{}\n", id.hex())
        );
        assert_eq!(assurance(&register, &old), None);
        let new = fstp_crypto::composite::generate().unwrap();
        assert_eq!(
            assurance(&register, &new),
            Some(Assurance::Reduced(ReducedReason::CopyHoldsReplacedKey))
        );
        let reg = std::fs::read(&register).unwrap();
        let secret = old.to_bytes().unwrap();
        assert!(!reg.windows(32).any(|w| secret.windows(32).any(|s| s == w)));
        copies::retire_copy(&register, id).unwrap();
        assert_eq!(assurance(&register, &new), None);
        assert!(copy_opened(&dir, &sealed_file, &old, &dir.join("copy")).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
