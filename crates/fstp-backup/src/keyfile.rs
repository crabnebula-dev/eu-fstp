//! The ClusterBackup key file `cluster-backup.key` (ADR-012 record of
//! lane L10, ADR-004, R-CR-01, I-80).
//!
//! ```text
//! file   = MAGIC (22) || cluster (16) || group (16) || be32(generation) || be64(epoch)
//!          || public key (1216)
//!          || be16(len) || custody handle || be16(len) || wrapped S
//!          || nonce (12) || sealed (2432 + 16)
//! aad    = MAGIC || cluster || group || be32(generation) || be64(epoch)
//! wrap   = custody wrap of S under the root {no cell, ClusterBackup, epoch}, AAD = aad
//! sealed = AES-256-GCM under S of the hybrid secret key, AAD = aad
//! ```
//!
//! The writer reads the public key only, so it cannot open what it wrote
//! (ADR-012 "Writer"). Opening the secret needs the custody root, which
//! the `fstp-keyd` console socket serves. The file never holds an open
//! key (I-80). The decoder admits exactly this form and is fuzzed
//! (`backup_key_file_decode`). An error names its rule and never quotes
//! the file (R-NF-02).

use fstp_crypto::aead;
use fstp_crypto::hybrid_kem::{self, HybridPublicKey, HybridSecretKey};
use fstp_custody::{
    Aad, BackendId, Chain, Custody, CustodyHandle, Epoch, RootLabel, RootRef, SealKey,
    WrappedSealKey,
};
use fstp_keys::GroupId;

use crate::{BackupError, GroupRef};

/// The magic that opens the file and labels its AAD.
pub const MAGIC: &[u8; 22] = b"fstp-cluster-backup-v1";
/// The file's name in the credentials directory.
pub const KEY_FILE: &str = "cluster-backup.key";
/// The epoch of the root at genesis.
pub const ROOT_EPOCH: u64 = 1;
/// The group generation at genesis.
pub const GENERATION: u32 = 1;
/// The longest custody handle or wrapped key the file holds.
pub const MAX_FIELD_LEN: usize = 4096;

const SEALED_LEN: usize = hybrid_kem::SECRET_KEY_LEN + aead::TAG_LEN;

fn bad(rule: &'static str) -> BackupError {
    BackupError::KeyFile(rule)
}

/// A decoded key file: the public key, references and sealed bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct KeyFile {
    /// The cluster that owns the group.
    pub cluster: [u8; 16],
    /// The group.
    pub group: [u8; 16],
    /// The group generation.
    pub generation: u32,
    /// The root epoch.
    pub epoch: u64,
    /// The group public key.
    pub public: [u8; hybrid_kem::PUBLIC_KEY_LEN],
    /// The custody handle of the root.
    pub handle: Vec<u8>,
    /// `S`, wrapped under the root.
    pub wrapped: Vec<u8>,
    /// The nonce of the sealed secret.
    pub nonce: [u8; aead::NONCE_LEN],
    /// The sealed group secret.
    pub sealed: Vec<u8>,
}

impl std::fmt::Debug for KeyFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyFile")
            .field("generation", &self.generation)
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

impl KeyFile {
    /// The AAD of the wrap and the seal.
    #[must_use]
    pub fn aad(&self) -> Vec<u8> {
        [
            &MAGIC[..],
            &self.cluster[..],
            &self.group[..],
            &self.generation.to_be_bytes(),
            &self.epoch.to_be_bytes(),
        ]
        .concat()
    }

    /// The group key the writer seals to.
    #[must_use]
    pub fn group_ref(&self) -> GroupRef {
        GroupRef {
            owner: self.cluster,
            group: GroupId(self.group),
            generation: self.generation,
        }
    }

    /// The group public key.
    ///
    /// # Errors
    ///
    /// [`BackupError::KeyFile`] when it does not decode.
    pub fn public_key(&self) -> Result<HybridPublicKey, BackupError> {
        HybridPublicKey::from_bytes(&self.public).map_err(|_| bad("public key"))
    }

    /// The custody root.
    #[must_use]
    pub fn root(&self) -> RootRef {
        RootRef {
            backend: BackendId::Keyd,
            cell: None,
            chain: Chain::ClusterBackup,
            epoch: Epoch(self.epoch),
            handle: CustodyHandle(self.handle.clone()),
        }
    }
}

fn put16(out: &mut Vec<u8>, field: &[u8]) -> Result<(), BackupError> {
    if field.is_empty() || field.len() > MAX_FIELD_LEN {
        return Err(bad("field length"));
    }
    let len = u16::try_from(field.len()).map_err(|_| bad("field length"))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(field);
    Ok(())
}

/// Encodes a key file.
///
/// # Errors
///
/// [`BackupError::KeyFile`] for an empty or overlong field or a sealed
/// secret of another length.
pub fn encode(f: &KeyFile) -> Result<Vec<u8>, BackupError> {
    if f.sealed.len() != SEALED_LEN {
        return Err(bad("sealed length"));
    }
    let mut out = f.aad();
    out.extend_from_slice(&f.public);
    put16(&mut out, &f.handle)?;
    put16(&mut out, &f.wrapped)?;
    out.extend_from_slice(&f.nonce);
    out.extend_from_slice(&f.sealed);
    Ok(out)
}

struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], BackupError> {
        let (head, tail) = self.rest.split_at_checked(n).ok_or(bad("truncated"))?;
        self.rest = tail;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], BackupError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    fn field(&mut self) -> Result<Vec<u8>, BackupError> {
        let len = usize::from(u16::from_be_bytes(self.array()?));
        if len == 0 || len > MAX_FIELD_LEN {
            return Err(bad("field length"));
        }
        Ok(self.take(len)?.to_vec())
    }
}

/// Decodes a key file. Fuzzed (`backup_key_file_decode`).
///
/// # Errors
///
/// [`BackupError::KeyFile`] for a wrong magic, a cut or overlong field,
/// a generation or epoch of 0, or trailing bytes.
pub fn decode(bytes: &[u8]) -> Result<KeyFile, BackupError> {
    let mut r = Reader { rest: bytes };
    if r.take(MAGIC.len())? != MAGIC {
        return Err(bad("magic"));
    }
    let cluster = r.array::<16>()?;
    let group = r.array::<16>()?;
    let generation = u32::from_be_bytes(r.array()?);
    let epoch = u64::from_be_bytes(r.array()?);
    if generation == 0 || epoch == 0 {
        return Err(bad("generation or epoch"));
    }
    let public = r.array::<{ hybrid_kem::PUBLIC_KEY_LEN }>()?;
    let handle = r.field()?;
    let wrapped = r.field()?;
    let nonce = r.array::<{ aead::NONCE_LEN }>()?;
    let sealed = r.take(SEALED_LEN)?.to_vec();
    if !r.rest.is_empty() {
        return Err(bad("trailing bytes"));
    }
    Ok(KeyFile {
        cluster,
        group,
        generation,
        epoch,
        public,
        handle,
        wrapped,
        nonce,
        sealed,
    })
}

/// Genesis (`fstp-backup init-keys`): draws the group key pair and a
/// group id, creates the root through `custody`, wraps a fresh `S` under
/// it and seals the group secret under `S`.
///
/// # Errors
///
/// [`BackupError::Custody`] when custody refuses, and
/// [`BackupError::Seal`] when a draw or the seal fails.
pub async fn create<C: Custody>(custody: &C, cluster: [u8; 16]) -> Result<Vec<u8>, BackupError> {
    let secret = hybrid_kem::generate().map_err(|_| BackupError::Seal("group key"))?;
    let group = fstp_crypto::random_array::<16>().map_err(|_| BackupError::Seal("group id"))?;
    let root = custody
        .create_root(RootLabel {
            cell: None,
            chain: Chain::ClusterBackup,
            epoch: Epoch(ROOT_EPOCH),
        })
        .await
        .map_err(|_| BackupError::Custody("create root"))?;
    let mut file = KeyFile {
        cluster,
        group,
        generation: GENERATION,
        epoch: ROOT_EPOCH,
        public: secret.public().to_bytes(),
        handle: root.handle.0.clone(),
        wrapped: Vec::new(),
        nonce: [0; aead::NONCE_LEN],
        sealed: Vec::new(),
    };
    let seal = SealKey::generate().map_err(|_| BackupError::Seal("seal key"))?;
    let aad = file.aad();
    let wrapped = custody
        .wrap(&root, &seal, &Aad(aad.clone()))
        .await
        .map_err(|_| BackupError::Custody("wrap"))?;
    file.wrapped = wrapped.0;
    let key = aead::Key::from_bytes(seal.expose()).map_err(|_| BackupError::Seal("seal key"))?;
    let plain = secret.to_bytes();
    let sealed = aead::seal(&key, &aad, &plain[..]).map_err(|_| BackupError::Seal("group key"))?;
    file.nonce = sealed.nonce;
    file.sealed = sealed.body;
    encode(&file)
}

/// Opens the group secret of `f` through `custody`. The secret's public
/// half must be the file's public key.
///
/// # Errors
///
/// [`BackupError::Custody`] when custody refuses the unwrap, and
/// [`BackupError::KeyFile`] when the secret does not open or does not
/// match.
pub async fn open<C: Custody>(custody: &C, f: &KeyFile) -> Result<HybridSecretKey, BackupError> {
    let aad = f.aad();
    let seal = custody
        .unwrap(
            &f.root(),
            &WrappedSealKey(f.wrapped.clone()),
            &Aad(aad.clone()),
        )
        .await
        .map_err(|_| BackupError::Custody("unwrap"))?;
    let key = aead::Key::from_bytes(seal.expose()).map_err(|_| bad("seal key"))?;
    let plain = aead::open(&key, &f.nonce, &aad, &f.sealed).map_err(|_| bad("open"))?;
    let secret = HybridSecretKey::from_bytes(&plain).map_err(|_| bad("secret key"))?;
    if secret.public().to_bytes() != f.public {
        return Err(bad("public key mismatch"));
    }
    Ok(secret)
}
