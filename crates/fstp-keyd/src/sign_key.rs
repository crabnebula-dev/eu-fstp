//! The sign-key files of file custody (ADR-004 "Decided by Daniel,
//! 2026-11-15 (late)": "The key table gains a sign-key slot form beside
//! the root slots"). Lane m3/erase-prod.
//!
//! Each CA sign key is an ECDSA P-256 key pair from `fstp-crypto`, in its
//! own file `sign-<class>-<name>.key`. The PKCS#8 document of the key is
//! sealed with AES-256-GCM under a random key `K` of its own. `K` lives in
//! a sign-key slot of the key table ([`crate::table`]), as `K(e)` of a
//! root does. A destroy overwrites `K` in its slot in place, fsyncs,
//! unlinks the file, fsyncs the directory and reads back, the five steps
//! of a root destroy. The private key never leaves `fstp-keyd`: a create
//! answers with the public key, and a sign with the signature.
//!
//! ```text
//! header = "FKK1" | version u8 = 1 | class u8 | name 8          14 bytes
//! file   = header | nonce 12 | AES-256-GCM(K, aad = header, PKCS#8 document)
//! ```
//!
//! The structural decoder [`decode_sign_key_file`] is fuzzed
//! (`sign_key_file_decode`).

use std::path::{Path, PathBuf};

use fstp_crypto::aead;
use fstp_crypto::sig::EcdsaP256KeyPair;
use zeroize::Zeroizing;

use crate::KeydError;
use crate::table::{EpochKey, SignKeyName};

/// The magic of a sign-key file.
pub const SIGN_KEY_MAGIC: [u8; 4] = *b"FKK1";
/// The format version.
pub const SIGN_KEY_VERSION: u8 = 1;
/// Length of the header.
pub const SIGN_KEY_HEADER_LEN: usize = 14;
/// The longest PKCS#8 document a sign-key file holds.
pub const MAX_PKCS8_LEN: usize = 512;
/// The longest sign-key file.
pub const MAX_SIGN_KEY_FILE_LEN: usize =
    SIGN_KEY_HEADER_LEN + aead::NONCE_LEN + MAX_PKCS8_LEN + aead::TAG_LEN;

/// The file name of the sign key `name`.
#[must_use]
pub fn file_name(name: SignKeyName) -> String {
    let mut hex = String::with_capacity(16);
    for b in name.name {
        hex.push_str(&format!("{b:02x}"));
    }
    format!("sign-{}-{hex}.key", name.class)
}

/// The path of the sign-key file of `name` on `volume`.
#[must_use]
pub fn path(volume: &Path, name: SignKeyName) -> PathBuf {
    volume.join(file_name(name))
}

fn header(name: SignKeyName) -> [u8; SIGN_KEY_HEADER_LEN] {
    let mut out = [0u8; SIGN_KEY_HEADER_LEN];
    let (magic, rest) = out.split_at_mut(4);
    magic.copy_from_slice(&SIGN_KEY_MAGIC);
    let (codes, n) = rest.split_at_mut(2);
    codes.copy_from_slice(&[SIGN_KEY_VERSION, name.class]);
    n.copy_from_slice(&name.name);
    out
}

/// Decodes the structure of a sign-key file without opening it: the
/// header, then a sealed body of a PKCS#8 document of 1 to
/// [`MAX_PKCS8_LEN`] bytes. It returns the sign key the file names and the
/// length of its sealed document. Fuzzed (`sign_key_file_decode`).
///
/// # Errors
///
/// Refuses another magic, version or class, and a length out of bounds.
pub fn decode_sign_key_file(bytes: &[u8]) -> Result<(SignKeyName, usize), KeydError> {
    if bytes.len() > MAX_SIGN_KEY_FILE_LEN {
        return Err(KeydError::Malformed("a sign-key file is too long"));
    }
    let (head, rest) = bytes
        .split_first_chunk::<SIGN_KEY_HEADER_LEN>()
        .ok_or(KeydError::Malformed("a sign-key file is too short"))?;
    let (magic, h) = head
        .split_first_chunk::<4>()
        .ok_or(KeydError::Malformed("a sign-key file is too short"))?;
    if *magic != SIGN_KEY_MAGIC {
        return Err(KeydError::Malformed("a sign-key file has the wrong magic"));
    }
    let (codes, n) = h
        .split_first_chunk::<2>()
        .ok_or(KeydError::Malformed("a sign-key file is too short"))?;
    let [version, class] = *codes;
    if version != SIGN_KEY_VERSION {
        return Err(KeydError::Malformed(
            "a sign-key file has an unknown version",
        ));
    }
    let mut handle = Vec::with_capacity(9);
    handle.push(class);
    handle.extend_from_slice(n);
    let name = SignKeyName::from_handle(&handle).ok_or(KeydError::Malformed(
        "a sign-key file names an unknown class",
    ))?;
    let sealed = rest
        .len()
        .checked_sub(aead::NONCE_LEN + aead::TAG_LEN)
        .filter(|n| (1..=MAX_PKCS8_LEN).contains(n))
        .ok_or(KeydError::Malformed("a sign-key file has the wrong length"))?;
    Ok((name, sealed))
}

/// Seals the PKCS#8 document of `key` for `name` under `k`.
pub(crate) fn seal(
    k: &EpochKey,
    name: SignKeyName,
    key: &EcdsaP256KeyPair,
) -> Result<Vec<u8>, KeydError> {
    let pkcs8 = key.pkcs8_der().map_err(KeydError::Crypto)?;
    if pkcs8.is_empty() || pkcs8.len() > MAX_PKCS8_LEN {
        return Err(KeydError::Malformed("a PKCS#8 document out of bounds"));
    }
    let aead_key = aead::Key::from_bytes(k.expose()).map_err(KeydError::Crypto)?;
    let hb = header(name);
    let sealed = aead::seal(&aead_key, &hb, &pkcs8).map_err(KeydError::Crypto)?;
    let mut out = Vec::with_capacity(MAX_SIGN_KEY_FILE_LEN);
    out.extend_from_slice(&hb);
    out.extend_from_slice(&sealed.nonce);
    out.extend_from_slice(&sealed.body);
    Ok(out)
}

/// Opens the bytes of the sign-key file of `name` under `k`.
pub(crate) fn open(
    k: &EpochKey,
    name: SignKeyName,
    bytes: &[u8],
) -> Result<EcdsaP256KeyPair, KeydError> {
    let (named, _) = decode_sign_key_file(bytes)?;
    if named != name {
        return Err(KeydError::Malformed("a sign-key file names another key"));
    }
    let hb = header(name);
    let rest = bytes
        .get(SIGN_KEY_HEADER_LEN..)
        .ok_or(KeydError::Malformed("a sign-key file is too short"))?;
    let (nonce, body) = rest
        .split_first_chunk::<{ aead::NONCE_LEN }>()
        .ok_or(KeydError::Malformed("a sign-key file is too short"))?;
    let aead_key = aead::Key::from_bytes(k.expose()).map_err(KeydError::Crypto)?;
    let pkcs8 = Zeroizing::new(
        aead::open(&aead_key, nonce, &hb, body)
            .map_err(|_| KeydError::Malformed("a sign-key file did not open"))?,
    );
    EcdsaP256KeyPair::from_pkcs8(&pkcs8).map_err(KeydError::Crypto)
}

/// Writes a new sign-key file, fsyncs it and its directory. An older file
/// of the same name, left by a crashed create, is replaced: it never had
/// a live key table entry, so nothing opens it.
pub(crate) fn write_new(volume: &Path, name: SignKeyName, bytes: &[u8]) -> Result<(), KeydError> {
    use std::io::Write as _;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path(volume, name))
        .map_err(|_| KeydError::Io("create a sign-key file"))?;
    file.write_all(bytes)
        .map_err(|_| KeydError::Io("write a sign-key file"))?;
    file.sync_all()
        .map_err(|_| KeydError::Io("fsync a sign-key file"))?;
    crate::epoch::sync_dir(volume)
}

/// Reads the sign-key file of `name`, if it exists.
pub(crate) fn read(volume: &Path, name: SignKeyName) -> Result<Option<Vec<u8>>, KeydError> {
    match std::fs::read(path(volume, name)) {
        Ok(b) => Ok(Some(b)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(KeydError::Io("read a sign-key file")),
    }
}

/// Unlinks the sign-key file of `name`. A missing file is fine: a destroy
/// that is retried finds it gone.
pub(crate) fn unlink(volume: &Path, name: SignKeyName) -> Result<(), KeydError> {
    match std::fs::remove_file(path(volume, name)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(KeydError::Io("unlink a sign-key file")),
    }
}
