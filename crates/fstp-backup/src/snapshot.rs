//! Keystore snapshots of the cell and the vault (ADR-012 records of lanes
//! L17 and m10/backup-followups, ADR-004 record of lane L17, I-81,
//! R-NF-08, F-043).
//!
//! Each process seals its own keystore image into one `FBC2` container
//! and uploads it to `<cell>/keystore/<snapshot id>` in every configured
//! object store. `fstp-cell` seals to the CellBackup group of
//! `cell-snapshot.key` (kind 3), `fstp-vault` to the VaultBackup group of
//! `vault-snapshot.key` (kind 5). The container names its snapshot id and
//! carries the composite signature of the process's snapshot writer key,
//! which the version 2 key file seals beside the group secret. So the
//! writer key opens only through the process's own custody entry, for
//! each upload and each pointer write.
//!
//! After a snapshot verifies, the process writes a signed pointer to
//! `<cell>/keystore/latest-app` or `<cell>/keystore/latest-vault`, since
//! the subset has no listing call:
//!
//! ```text
//! pointer = "FKP1" | version u8 = 1 | kind u8 | cell 16 | snapshot id 16
//!           | signature 3373 over the 38 bytes before it,
//!             context "fstp-backup-snapshot-pointer-v1"
//! ```
//!
//! [`decode_pointer`] admits exactly this form, and the fuzz target
//! `backup_container_decode` runs it. A 16-byte version 1 pointer names
//! no snapshot, since nothing authenticates it.
//!
//! A fetch takes the first store whose copy verifies and opens. An error
//! names a rule, a status or a step. None quotes a byte of the object or a
//! secret (R-NF-02).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use fstp_crypto::hybrid_kem::HybridSecretKey;
use fstp_custody::Custody;
use fstp_rt::Runtime;

use crate::BackupError;
use crate::keyfile::{self, FileKind, KeyFile};
use crate::object::{ObjectIdent, open_object, seal_object};
use crate::s3::S3Client;
use crate::seal::ContainerKind;
use crate::writer::{self, SIGNATURE_LEN};

/// The prefix under a cell of every keystore snapshot object.
pub const PREFIX: &str = "keystore";
/// The magic of a version 2 pointer.
pub const POINTER_MAGIC: [u8; 4] = *b"FKP1";
/// The version of a pointer.
pub const POINTER_VERSION: u8 = 1;
/// The length of the signed part of a pointer.
pub const POINTER_BODY_LEN: usize = 4 + 1 + 1 + 16 + 16;
/// The length of a version 2 pointer.
pub const POINTER_LEN: usize = POINTER_BODY_LEN + SIGNATURE_LEN;
/// The length of a version 1 pointer, which names no snapshot.
pub const POINTER_V1_LEN: usize = 16;

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

    /// The kind of its snapshot key file, version 2.
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

    /// The object identity of its snapshot `id`.
    #[must_use]
    pub const fn ident(self, id: [u8; 16]) -> ObjectIdent {
        match self {
            SnapshotOwner::App => ObjectIdent::AppSnapshot(id),
            SnapshotOwner::Vault => ObjectIdent::VaultSnapshot(id),
        }
    }

    /// The owner of a container kind, if it is a snapshot kind.
    #[must_use]
    pub const fn of_kind(kind: ContainerKind) -> Option<SnapshotOwner> {
        match kind {
            ContainerKind::KeystoreSnapshot => Some(SnapshotOwner::App),
            ContainerKind::VaultKeystoreSnapshot => Some(SnapshotOwner::Vault),
            _ => None,
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

/// A decoded version 2 pointer. Its signature is not yet verified.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pointer<'a> {
    /// The process whose snapshot it names.
    pub owner: SnapshotOwner,
    /// The cell.
    pub cell: [u8; 16],
    /// The snapshot id.
    pub id: [u8; 16],
    /// The signed bytes.
    pub body: &'a [u8],
    /// The writer's composite signature over [`Pointer::body`].
    pub signature: &'a [u8],
}

/// Encodes the signed part of a pointer.
#[must_use]
pub fn pointer_body(owner: SnapshotOwner, cell: [u8; 16], id: [u8; 16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(POINTER_LEN);
    out.extend_from_slice(&POINTER_MAGIC);
    out.push(POINTER_VERSION);
    out.push(owner.kind().code());
    out.extend_from_slice(&cell);
    out.extend_from_slice(&id);
    out
}

/// Decodes a version 2 pointer, in one spelling. Fuzzed
/// (`backup_container_decode`).
///
/// # Errors
///
/// [`BackupError::Malformed`] for any other length, magic, version or
/// kind.
pub fn decode_pointer(bytes: &[u8]) -> Result<Pointer<'_>, BackupError> {
    let bad = BackupError::Malformed("snapshot pointer");
    if bytes.len() != POINTER_LEN {
        return Err(bad);
    }
    let (body, signature) = bytes.split_at_checked(POINTER_BODY_LEN).ok_or(bad)?;
    let (magic, rest) = body.split_first_chunk::<4>().ok_or(bad)?;
    let (&[version, kind], rest) = rest.split_first_chunk::<2>().ok_or(bad)?;
    if *magic != POINTER_MAGIC || version != POINTER_VERSION {
        return Err(bad);
    }
    let owner = ContainerKind::from_code(kind)
        .and_then(SnapshotOwner::of_kind)
        .ok_or(bad)?;
    let (cell, id) = rest.split_first_chunk::<16>().ok_or(bad)?;
    let id: [u8; 16] = id.try_into().map_err(|_| bad)?;
    Ok(Pointer {
        owner,
        cell: *cell,
        id,
        body,
        signature,
    })
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

/// The S3 clients of `endpoints`, in order, with the credentials of the
/// credentials directory `dir`: store 0 takes `s3-access-key-id`,
/// `s3-secret-access-key` and optionally `s3-ca.pem`, store `n` from 1
/// takes `s3-<n>-access-key-id`, `s3-<n>-secret-access-key` and
/// optionally `s3-<n>-ca.pem` (ADR-012 record of lane
/// m10/backup-followups, row "Every store").
///
/// # Errors
///
/// [`BackupError::Config`] naming a credential file or the list.
pub fn s3_stores<R: Runtime + Send + Sync + 'static>(
    rt: &R,
    dir: &std::path::Path,
    endpoints: &[crate::s3::Endpoint],
) -> Result<Vec<Arc<dyn ObjectStore>>, BackupError> {
    if endpoints.is_empty() || endpoints.len() > crate::config::MAX_STORES {
        return Err(BackupError::Config("object_stores"));
    }
    endpoints
        .iter()
        .enumerate()
        .map(|(n, e)| {
            let (credentials, ca) = crate::config::store_credentials(dir, n)?;
            let client = S3Client::new(rt.clone(), e.clone(), credentials, ca.as_deref())?;
            Ok(Arc::new(client) as Arc<dyn ObjectStore>)
        })
        .collect()
}

/// Fetches `key` from `stores` in order and returns the first copy that
/// `check` accepts (ADR-012 record of lane m10/backup-format, row "Fetch
/// from the stores"). A missing object, a failed request and a refused
/// copy fall through to the next store. When no copy passes, the answer
/// is `None` if some store said the object is absent and no store held a
/// refused copy. Otherwise it is the first error.
///
/// # Errors
///
/// The first error, as above.
pub(crate) async fn first_good<T>(
    stores: &[&dyn ObjectStore],
    key: &str,
    mut check: impl FnMut(Vec<u8>) -> Result<T, BackupError>,
) -> Result<Option<T>, BackupError> {
    let mut absent = false;
    let mut refused = false;
    let mut first: Option<BackupError> = None;
    for s in stores {
        let bytes = match s.get(key).await {
            Ok(Some(b)) => b,
            Ok(None) => {
                absent = true;
                continue;
            }
            Err(e) => {
                first.get_or_insert(e);
                continue;
            }
        };
        match check(bytes) {
            Ok(v) => return Ok(Some(v)),
            Err(e) => {
                refused = true;
                first.get_or_insert(e);
            }
        }
    }
    match first {
        Some(e) if refused || !absent => Err(e),
        _ => Ok(None),
    }
}

/// A process's snapshot key file, checked to be of its kind and its cell.
#[derive(Clone, Debug)]
pub struct SnapshotKey {
    file: KeyFile,
    owner: SnapshotOwner,
}

impl SnapshotKey {
    /// Creates the version 2 snapshot key file of `owner` for `cell`
    /// through `custody`, with its writer key sealed inside, and returns
    /// its bytes. It creates the root `{cell, CellBackup or VaultBackup,
    /// epoch 1}` and no other.
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

    /// Whether `bytes` is a version 1 snapshot key file of `owner`, which
    /// [`SnapshotKey::upgrade`] turns into version 2.
    #[must_use]
    pub fn is_version_1(bytes: &[u8], owner: SnapshotOwner) -> bool {
        owner
            .file_kind()
            .snapshot_v1()
            .is_some_and(|k| keyfile::decode_kind(bytes, k).is_ok())
    }

    /// Upgrades the version 1 snapshot key file `v1` of `owner` for `cell`
    /// through `custody` (ADR-012 record of lane m10/backup-followups, row
    /// "Upgrade"): same root, group and group key, a fresh writer key.
    /// Returns the version 2 bytes.
    ///
    /// # Errors
    ///
    /// [`BackupError::KeyFile`] for a file of another kind or cell, and
    /// the errors of [`keyfile::upgrade_snapshot`].
    pub async fn upgrade<C: Custody>(
        custody: &C,
        v1: &[u8],
        cell: [u8; 16],
        owner: SnapshotOwner,
    ) -> Result<Vec<u8>, BackupError> {
        let old = owner
            .file_kind()
            .snapshot_v1()
            .ok_or(BackupError::KeyFile("kind"))?;
        if keyfile::decode_kind(v1, old)?.cluster != cell {
            return Err(BackupError::KeyFile("cell"));
        }
        keyfile::upgrade_snapshot(custody, v1, owner.file_kind()).await
    }

    /// Decodes the version 2 snapshot key file of `owner` for `cell`, and
    /// checks its binding signature.
    ///
    /// # Errors
    ///
    /// [`BackupError::KeyFile`] for a file of another kind, version or
    /// cell, or a binding that does not verify.
    pub fn decode(
        bytes: &[u8],
        cell: [u8; 16],
        owner: SnapshotOwner,
    ) -> Result<SnapshotKey, BackupError> {
        let file = keyfile::decode_kind(bytes, owner.file_kind())?;
        if file.cluster != cell {
            return Err(BackupError::KeyFile("cell"));
        }
        file.check_binding()?;
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

    /// The writer public key, which every container and pointer of this
    /// process verifies under.
    fn writer_public(&self) -> Result<&[u8], BackupError> {
        self.file
            .writer_public()
            .map(|w| &w[..])
            .ok_or(BackupError::KeyFile("binding"))
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

/// The snapshot writer and reader of one process, over every configured
/// object store.
#[derive(Clone)]
pub struct Snapshots {
    stores: Vec<Arc<dyn ObjectStore>>,
    key: SnapshotKey,
}

impl std::fmt::Debug for Snapshots {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Snapshots")
            .field("owner", &self.key.owner)
            .field("stores", &self.stores.len())
            .finish_non_exhaustive()
    }
}

impl Snapshots {
    /// A writer over the one store `store` with `key`.
    #[must_use]
    pub fn new(store: Arc<dyn ObjectStore>, key: SnapshotKey) -> Snapshots {
        Snapshots {
            stores: vec![store],
            key,
        }
    }

    /// A writer over every store of `stores`, in order, with `key` (ADR-012
    /// record of lane m10/backup-followups, row "Every store").
    ///
    /// # Errors
    ///
    /// [`BackupError::Config`] for an empty list or more than
    /// [`crate::config::MAX_STORES`].
    pub fn with_stores(
        stores: Vec<Arc<dyn ObjectStore>>,
        key: SnapshotKey,
    ) -> Result<Snapshots, BackupError> {
        if stores.is_empty() || stores.len() > crate::config::MAX_STORES {
            return Err(BackupError::Config("object_stores"));
        }
        Ok(Snapshots { stores, key })
    }

    /// The snapshot key.
    #[must_use]
    pub fn key(&self) -> &SnapshotKey {
        &self.key
    }

    fn stores(&self) -> Vec<&dyn ObjectStore> {
        self.stores
            .iter()
            .map(|s| &**s as &dyn ObjectStore)
            .collect()
    }

    async fn put_everywhere(&self, name: &str, bytes: &[u8]) -> Result<(), BackupError> {
        for s in &self.stores {
            s.put(name, bytes.to_vec()).await?;
        }
        Ok(())
    }

    /// Draws a snapshot id, seals `image` into one `FBC2` container of it
    /// to the snapshot group's public key, signs it with the writer key
    /// that `custody` opens, and uploads it to every store. Returns the
    /// snapshot id once every store holds it.
    ///
    /// # Errors
    ///
    /// The custody, seal or upload failure.
    pub async fn upload<C: Custody>(
        &self,
        custody: &C,
        image: &[u8],
    ) -> Result<[u8; 16], BackupError> {
        let writer = keyfile::open_writer(custody, &self.key.file).await?;
        let public = self.key.file.public_key()?;
        let id = fstp_crypto::random_array::<16>().map_err(|_| BackupError::Seal("snapshot id"))?;
        let bytes = seal_object(
            &public,
            &writer,
            &self.key.file.group_ref(),
            &self.key.owner.ident(id),
            image,
        )?;
        self.put_everywhere(&object_name(self.key.cell(), id), &bytes)
            .await?;
        Ok(id)
    }

    /// Fetches snapshot `id` from the first store whose copy verifies and
    /// opens through `custody`: the writer signature verifies under the
    /// key file's writer public key, then the container must be of this
    /// process's kind and cell and name `id`. Returns the image.
    ///
    /// # Errors
    ///
    /// [`BackupError::NotFound`] when every store that answered lacks it,
    /// and otherwise the first refusal: [`BackupError::Malformed`] for a
    /// container of another kind, cell, id or writer, and the opener's.
    pub async fn fetch<C: Custody>(
        &self,
        custody: &C,
        id: [u8; 16],
    ) -> Result<Vec<u8>, BackupError> {
        let secret = self.key.open_secret(custody).await?;
        let writer = self.key.writer_public()?;
        let want = self.key.owner.ident(id);
        let cell = self.key.cell();
        let got = first_good(&self.stores(), &object_name(cell, id), |bytes| {
            let o = open_object(&secret, writer, &bytes)?;
            if o.ident.kind() != want.kind() {
                return Err(BackupError::Malformed("snapshot kind"));
            }
            if o.owner != cell || o.ident != want {
                return Err(BackupError::Malformed("snapshot name"));
            }
            Ok(o.plaintext)
        })
        .await?;
        got.ok_or(BackupError::NotFound)
    }

    /// Writes a pointer to `id` as the newest verified snapshot of this
    /// process, signed with the writer key that `custody` opens, to every
    /// store.
    ///
    /// # Errors
    ///
    /// The custody, signature or upload failure.
    pub async fn publish<C: Custody>(&self, custody: &C, id: [u8; 16]) -> Result<(), BackupError> {
        let writer = keyfile::open_writer(custody, &self.key.file).await?;
        let mut bytes = pointer_body(self.key.owner, self.key.cell(), id);
        let signature = writer.sign_pointer(&bytes)?;
        bytes.extend_from_slice(&signature);
        self.put_everywhere(&pointer_name(self.key.cell(), self.key.owner), &bytes)
            .await
    }

    /// The newest verified snapshot of this process, from the first store
    /// whose pointer verifies under the writer public key and names this
    /// process and cell. A version 1 pointer names none.
    ///
    /// # Errors
    ///
    /// The first refusal when no store holds a pointer that verifies and
    /// some store holds one that does not, or the fetch's failure.
    pub async fn latest(&self) -> Result<Option<[u8; 16]>, BackupError> {
        let writer = self.key.writer_public()?;
        let (owner, cell) = (self.key.owner, self.key.cell());
        let got = first_good(&self.stores(), &pointer_name(cell, owner), |bytes| {
            if bytes.len() == POINTER_V1_LEN {
                return Ok(None);
            }
            let p = decode_pointer(&bytes)?;
            if !writer::pointer_signature_verifies(writer, p.body, p.signature) {
                return Err(BackupError::Malformed("pointer signature"));
            }
            if p.owner != owner || p.cell != cell {
                return Err(BackupError::Malformed("snapshot pointer"));
            }
            Ok(Some(p.id))
        })
        .await?;
        Ok(got.flatten())
    }
}

/// Reads the snapshot key file of `owner` for `cell` at `path` (ADR-004
/// record of lane L17, row "Genesis"; ADR-012 record of lane
/// m10/backup-followups, row "Upgrade"). A missing file is created through
/// `custody` and written with mode 0600. A version 1 file is upgraded
/// through `custody` and replaced through a temporary file, a sync and a
/// rename, so a crash leaves the old file or the new one. Either way the
/// process's own entry does it, with no operator step.
///
/// # Errors
///
/// [`BackupError::Custody`] when custody refuses, [`BackupError::Io`]
/// for a file step, and [`BackupError::KeyFile`] for a file that does not
/// decode as version 1 or 2 of `owner` and `cell`.
pub async fn load_key<C: Custody>(
    custody: &C,
    path: &std::path::Path,
    cell: [u8; 16],
    owner: SnapshotOwner,
) -> Result<SnapshotKey, BackupError> {
    let bytes = match std::fs::read(path) {
        Ok(b) if SnapshotKey::is_version_1(&b, owner) => {
            let new = SnapshotKey::upgrade(custody, &b, cell, owner).await?;
            let tmp = path.with_extension("key.upgrade");
            let _ = std::fs::remove_file(&tmp);
            write_file(&tmp, &new)?;
            std::fs::rename(&tmp, path).map_err(|_| BackupError::Io("snapshot key file"))?;
            new
        }
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let b = SnapshotKey::create(custody, cell, owner).await?;
            write_file(path, &b)?;
            b
        }
        Err(_) => return Err(BackupError::Io("snapshot key file")),
    };
    SnapshotKey::decode(&bytes, cell, owner)
}

/// Writes a new file with mode 0600 and syncs it.
fn write_file(path: &std::path::Path, bytes: &[u8]) -> Result<(), BackupError> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| BackupError::Io("snapshot key file"))?;
    f.write_all(bytes)
        .and_then(|()| f.sync_all())
        .map_err(|_| BackupError::Io("snapshot key file"))
}
