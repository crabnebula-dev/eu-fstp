//! The epoch files of file custody (ADR-004 part 2 "File custody").
//!
//! Each root epoch is 32 random bytes in its own file
//! `epoch-<chain>-<e>.key`, sealed with AES-256-GCM under the per-epoch
//! key `K(e)` of the key table. No ADR fixed these bytes before this
//! lane. Lane W2f writes them at first use, and their record in ADR-004
//! is with the lead.
//!
//! ```text
//! header = "FKE1" | version u8 = 1 | chain u8 | epoch u64      14 bytes
//! file   = header | nonce 12 | AES-256-GCM(K(e), aad = header, root 32)   74 bytes
//! ```

use std::path::{Path, PathBuf};

use fstp_crypto::aead;
use zeroize::Zeroizing;

use fstp_custody::{Chain, Epoch};

use crate::table::EpochKey;
use crate::{KeydError, RootMaterial};

/// The magic of an epoch file.
pub const EPOCH_MAGIC: [u8; 4] = *b"FKE1";
/// The format version.
pub const EPOCH_VERSION: u8 = 1;
/// Length of the header.
pub const EPOCH_HEADER_LEN: usize = 14;
/// Length of an epoch file.
pub const EPOCH_FILE_LEN: usize = EPOCH_HEADER_LEN + aead::NONCE_LEN + 32 + aead::TAG_LEN;

/// The file name of the epoch file of `chain` and `epoch`.
#[must_use]
pub fn file_name(chain: Chain, epoch: Epoch) -> String {
    format!("epoch-{}-{}.key", chain.name(), epoch.0)
}

/// The path of the epoch file of `chain` and `epoch` on `volume`.
#[must_use]
pub fn path(volume: &Path, chain: Chain, epoch: Epoch) -> PathBuf {
    volume.join(file_name(chain, epoch))
}

fn header(chain: Chain, epoch: Epoch) -> [u8; EPOCH_HEADER_LEN] {
    let mut out = [0u8; EPOCH_HEADER_LEN];
    let (magic, rest) = out.split_at_mut(4);
    magic.copy_from_slice(&EPOCH_MAGIC);
    let (codes, e) = rest.split_at_mut(2);
    codes.copy_from_slice(&[EPOCH_VERSION, chain.code()]);
    e.copy_from_slice(&epoch.0.to_be_bytes());
    out
}

/// Seals `root` for `chain` and `epoch` under `k`.
pub(crate) fn seal(
    k: &EpochKey,
    chain: Chain,
    epoch: Epoch,
    root: &RootMaterial,
) -> Result<Vec<u8>, KeydError> {
    let key = aead::Key::from_bytes(k.expose()).map_err(KeydError::Crypto)?;
    let hb = header(chain, epoch);
    let sealed = aead::seal(&key, &hb, root.bytes()).map_err(KeydError::Crypto)?;
    let mut out = Vec::with_capacity(EPOCH_FILE_LEN);
    out.extend_from_slice(&hb);
    out.extend_from_slice(&sealed.nonce);
    out.extend_from_slice(&sealed.body);
    Ok(out)
}

/// Opens the bytes of an epoch file for `chain` and `epoch` under `k`.
pub(crate) fn open(
    k: &EpochKey,
    chain: Chain,
    epoch: Epoch,
    bytes: &[u8],
) -> Result<RootMaterial, KeydError> {
    if bytes.len() != EPOCH_FILE_LEN {
        return Err(KeydError::Malformed("an epoch file has the wrong length"));
    }
    let hb = header(chain, epoch);
    let (head, rest) = bytes
        .split_first_chunk::<EPOCH_HEADER_LEN>()
        .ok_or(KeydError::Malformed("an epoch file is too short"))?;
    if *head != hb {
        return Err(KeydError::Malformed(
            "an epoch file names another chain or epoch",
        ));
    }
    let (nonce, body) = rest
        .split_first_chunk::<{ aead::NONCE_LEN }>()
        .ok_or(KeydError::Malformed("an epoch file is too short"))?;
    let key = aead::Key::from_bytes(k.expose()).map_err(KeydError::Crypto)?;
    let opened = aead::open(&key, nonce, &hb, body)
        .map_err(|_| KeydError::Malformed("an epoch file did not open"))?;
    let root: [u8; 32] = opened
        .as_slice()
        .try_into()
        .map_err(|_| KeydError::Malformed("an epoch file holds no 32 root bytes"))?;
    Ok(RootMaterial::from_opened(Zeroizing::new(root)))
}

/// Writes a new epoch file, fsyncs it and its directory. An older file of
/// the same name, left by a crashed create, is replaced: it never had a
/// key table entry, so nothing opens it.
pub(crate) fn write_new(
    volume: &Path,
    chain: Chain,
    epoch: Epoch,
    bytes: &[u8],
) -> Result<(), KeydError> {
    use std::io::Write as _;
    let p = path(volume, chain, epoch);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&p)
        .map_err(|_| KeydError::Io("create an epoch file"))?;
    file.write_all(bytes)
        .map_err(|_| KeydError::Io("write an epoch file"))?;
    file.sync_all()
        .map_err(|_| KeydError::Io("fsync an epoch file"))?;
    sync_dir(volume)
}

/// Reads the epoch file of `chain` and `epoch`, if it exists.
pub(crate) fn read(
    volume: &Path,
    chain: Chain,
    epoch: Epoch,
) -> Result<Option<Vec<u8>>, KeydError> {
    match std::fs::read(path(volume, chain, epoch)) {
        Ok(b) => Ok(Some(b)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(KeydError::Io("read an epoch file")),
    }
}

/// Unlinks the epoch file of `chain` and `epoch`. A missing file is
/// fine: a destroy that is retried finds it gone.
pub(crate) fn unlink(volume: &Path, chain: Chain, epoch: Epoch) -> Result<(), KeydError> {
    match std::fs::remove_file(path(volume, chain, epoch)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(KeydError::Io("unlink an epoch file")),
    }
}

/// Fsyncs the directory `dir`, so a create or an unlink in it is durable.
pub(crate) fn sync_dir(dir: &Path) -> Result<(), KeydError> {
    std::fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(|_| KeydError::Io("fsync the key directory"))
}
