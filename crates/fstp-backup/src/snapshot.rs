//! Keystore snapshots of the cell and the vault (ADR-012 record of lane
//! L17, ADR-004 record of lane L17, I-81, R-NF-08).
//!
//! Each process seals its own keystore image into one container and
//! uploads it to `<cell>/keystore/<snapshot id>` through the S3 subset.
//! The snapshot id is the container id. `fstp-cell` seals to the
//! CellBackup group of `cell-snapshot.key` (kind 3), `fstp-vault` to the
//! VaultBackup group of `vault-snapshot.key` (kind 5). Each writer holds
//! only its group's public key while it seals. Opening a fetched snapshot
//! needs the group secret, which custody unwraps through the snapshot
//! root of the process's own entry.
//!
//! After a snapshot verifies, the process writes its id, exactly 16
//! bytes, to `<cell>/keystore/latest-app` or `<cell>/keystore/latest-vault`,
//! since the subset has no listing call. [`decode_pointer`] admits exactly
//! 16 bytes, and the fuzz target `backup_container_decode` runs it.
//!
//! An error names a rule, a status or a step. None quotes a byte of the
//! object or a secret (R-NF-02).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use fstp_crypto::hybrid_kem::HybridSecretKey;
use fstp_custody::Custody;
use fstp_rt::Runtime;

use crate::BackupError;
use crate::container::decode_header;
use crate::keyfile::{self, FileKind, KeyFile};
use crate::s3::S3Client;
use crate::seal::{ContainerKind, open_container, seal_container};

/// The prefix under a cell of every keystore snapshot object.
pub const PREFIX: &str = "keystore";

/// The process a snapshot belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapshotOwner {
    /// `fstp-cell`, the App chain keystore in `c_<cell>`.
    App,
    /// `fstp-vault`, the Vault chain keystore in `v_<cell>`.
    Vault,
}

impl SnapshotOwner {
    /// The container kind of its snapshots.
    #[must_use]
    pub const fn kind(self) -> ContainerKind {
        match self {
            SnapshotOwner::App => ContainerKind::KeystoreSnapshot,
            SnapshotOwner::Vault => ContainerKind::VaultKeystoreSnapshot,
        }
    }

    /// The kind of its snapshot key file.
    #[must_use]
    pub const fn file_kind(self) -> FileKind {
        match self {
            SnapshotOwner::App => FileKind::CellSnapshot,
            SnapshotOwner::Vault => FileKind::VaultSnapshot,
        }
    }

    /// The name of its snapshot key file in its credentials directory.
    #[must_use]
    pub const fn key_file_name(self) -> &'static str {
        match self {
            SnapshotOwner::App => keyfile::CELL_SNAPSHOT_KEY_FILE,
            SnapshotOwner::Vault => keyfile::VAULT_SNAPSHOT_KEY_FILE,
        }
    }

    const fn pointer(self) -> &'static str {
        match self {
            SnapshotOwner::App => "latest-app",
            SnapshotOwner::Vault => "latest-vault",
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    crate::sigv4::hex(bytes)
}

/// The object name of snapshot `id` of `cell`: `<cell>/keystore/<id>`, in
/// lowercase hex.
#[must_use]
pub fn object_name(cell: [u8; 16], id: [u8; 16]) -> String {
    format!("{}/{PREFIX}/{}", hex(&cell), hex(&id))
}

/// The object name of the pointer to the newest verified snapshot of
/// `owner`.
#[must_use]
pub fn pointer_name(cell: [u8; 16], owner: SnapshotOwner) -> String {
    format!("{}/{PREFIX}/{}", hex(&cell), owner.pointer())
}

/// Decodes a pointer: exactly 16 bytes, the snapshot id.
///
/// # Errors
///
/// [`BackupError::Malformed`] for any other length.
pub fn decode_pointer(bytes: &[u8]) -> Result<[u8; 16], BackupError> {
    bytes
        .try_into()
        .map_err(|_| BackupError::Malformed("snapshot pointer"))
}

/// A boxed future of an [`ObjectStore`] call.
pub type StoreFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, BackupError>> + Send + 'a>>;

/// The two calls a snapshot writer makes on its object store: store an
/// object and fetch one. The S3 client of this crate implements it, and so
/// may a test double.
pub trait ObjectStore: Send + Sync {
    /// Stores `body` as `key`.
    fn put<'a>(&'a self, key: &'a str, body: Vec<u8>) -> StoreFuture<'a, ()>;
    /// Fetches `key`, or `None` when it does not exist.
    fn get<'a>(&'a self, key: &'a str) -> StoreFuture<'a, Option<Vec<u8>>>;
}

impl<R: Runtime + Send + Sync> ObjectStore for S3Client<R> {
    fn put<'a>(&'a self, key: &'a str, body: Vec<u8>) -> StoreFuture<'a, ()> {
        Box::pin(self.store(
            key,
            body,
            crate::agent::SINGLE_PUT_MAX,
            crate::agent::UPLOAD_PART,
        ))
    }

    fn get<'a>(&'a self, key: &'a str) -> StoreFuture<'a, Option<Vec<u8>>> {
        Box::pin(self.get_object(key))
    }
}

/// A process's snapshot key file, checked to be of its kind and its cell.
#[derive(Clone, Debug)]
pub struct SnapshotKey {
    file: KeyFile,
    owner: SnapshotOwner,
}

impl SnapshotKey {
    /// Creates the snapshot key file of `owner` for `cell` through
    /// `custody`, and returns its bytes. It creates the root
    /// `{cell, CellBackup or VaultBackup, epoch 1}` and no other.
    ///
    /// # Errors
    ///
    /// As [`keyfile::create_kind`].
    pub async fn create<C: Custody>(
        custody: &C,
        cell: [u8; 16],
        owner: SnapshotOwner,
    ) -> Result<Vec<u8>, BackupError> {
        keyfile::create_kind(custody, cell, owner.file_kind()).await
    }

    /// Decodes the snapshot key file of `owner` for `cell`.
    ///
    /// # Errors
    ///
    /// [`BackupError::KeyFile`] for a file of another kind or cell.
    pub fn decode(
        bytes: &[u8],
        cell: [u8; 16],
        owner: SnapshotOwner,
    ) -> Result<SnapshotKey, BackupError> {
        let file = keyfile::decode_kind(bytes, owner.file_kind())?;
        if file.cluster != cell {
            return Err(BackupError::KeyFile("cell"));
        }
        Ok(SnapshotKey { file, owner })
    }

    /// The decoded key file.
    #[must_use]
    pub fn file(&self) -> &KeyFile {
        &self.file
    }

    /// The process it belongs to.
    #[must_use]
    pub fn owner(&self) -> SnapshotOwner {
        self.owner
    }

    /// The cell.
    #[must_use]
    pub fn cell(&self) -> [u8; 16] {
        self.file.cluster
    }

    /// Opens the group secret through `custody`.
    ///
    /// # Errors
    ///
    /// As [`keyfile::open`].
    pub async fn open_secret<C: Custody>(
        &self,
        custody: &C,
    ) -> Result<HybridSecretKey, BackupError> {
        keyfile::open(custody, &self.file).await
    }
}

/// The snapshot writer and reader of one process.
#[derive(Clone)]
pub struct Snapshots {
    store: Arc<dyn ObjectStore>,
    key: SnapshotKey,
}

impl std::fmt::Debug for Snapshots {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Snapshots")
            .field("owner", &self.key.owner)
            .finish_non_exhaustive()
    }
}

impl Snapshots {
    /// A writer over `store` with `key`.
    #[must_use]
    pub fn new(store: Arc<dyn ObjectStore>, key: SnapshotKey) -> Snapshots {
        Snapshots { store, key }
    }

    /// The snapshot key.
    #[must_use]
    pub fn key(&self) -> &SnapshotKey {
        &self.key
    }

    /// Seals `image` into one container to the snapshot group's public key
    /// and uploads it. Returns the snapshot id.
    ///
    /// # Errors
    ///
    /// The seal's or the upload's failure.
    pub async fn upload(&self, image: &[u8]) -> Result<[u8; 16], BackupError> {
        let public = self.key.file.public_key()?;
        let bytes = seal_container(
            &public,
            self.key.owner.kind(),
            &self.key.file.group_ref(),
            0,
            image,
        )?;
        let id = decode_header(&bytes)?.container;
        self.store
            .put(&object_name(self.key.cell(), id), bytes)
            .await?;
        Ok(id)
    }

    /// Fetches snapshot `id` and opens it through `custody`: the container
    /// must be of this process's kind and cell, carry the id, and be part
    /// 0. Returns the image.
    ///
    /// # Errors
    ///
    /// [`BackupError::NotFound`] for a missing object, the opener's
    /// refusal, and [`BackupError::Malformed`] for a container of another
    /// kind, cell or id.
    pub async fn fetch<C: Custody>(
        &self,
        custody: &C,
        id: [u8; 16],
    ) -> Result<Vec<u8>, BackupError> {
        let bytes = self
            .store
            .get(&object_name(self.key.cell(), id))
            .await?
            .ok_or(BackupError::NotFound)?;
        let secret = self.key.open_secret(custody).await?;
        let opened = open_container(&secret, &bytes)?;
        if opened.kind != self.key.owner.kind() {
            return Err(BackupError::Malformed("snapshot kind"));
        }
        if opened.owner != self.key.cell() || opened.container != id || opened.part != 0 {
            return Err(BackupError::Malformed("snapshot name"));
        }
        Ok(opened.plaintext)
    }

    /// Writes `id` as the newest verified snapshot of this process.
    ///
    /// # Errors
    ///
    /// The upload's failure.
    pub async fn publish(&self, id: [u8; 16]) -> Result<(), BackupError> {
        self.store
            .put(&pointer_name(self.key.cell(), self.key.owner), id.to_vec())
            .await
    }

    /// The newest verified snapshot of this process, if one was published.
    ///
    /// # Errors
    ///
    /// The fetch's failure, and [`decode_pointer`]'s refusal.
    pub async fn latest(&self) -> Result<Option<[u8; 16]>, BackupError> {
        match self
            .store
            .get(&pointer_name(self.key.cell(), self.key.owner))
            .await?
        {
            None => Ok(None),
            Some(b) => decode_pointer(&b).map(Some),
        }
    }
}
