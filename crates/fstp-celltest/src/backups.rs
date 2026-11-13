//! Backups of a test world: base backups, WAL archives and keystore
//! snapshots, sealed through `fstp-backup`, and the restore of each copy
//! (design sections 3.5, 3.8 and 14.4, ADR-012, I-80, I-81, R-CR-01).
//! Lane F-ERASE.
//!
//! What runs here and what it stands in for. Interim, pending Daniel:
//!
//! - **Object store.** No connector may build the object storage
//!   destinations yet (ADR-012 "Writer and upload", `KeystoreSnapshots`
//!   pending). So the world keeps the uploaded objects in a directory of
//!   its own, under the ADR-012 object names, and [`World::stores`] reads
//!   them as `objects/<name>`.
//! - **Base backup** (`base-backup`). Each self-operated cluster of the
//!   world is copied with `pg_basebackup` over loopback as its
//!   replication role `fstp_repl` (G22), with its WAL streamed. Each of
//!   its two files, `base.tar` and `pg_wal.tar`, is sealed as one
//!   ClusterBackup container (kind 1), named
//!   `<cluster>/base/<backup id>/<file>/0`. ADR-012 names no file level,
//!   so that level is this lane's reading. The cell's keystore
//!   is held in memory by its owner until W2e moves it into the
//!   `keystore` tables, so the step also takes the cell's keystore
//!   snapshot: the rows that the tables would hold in the copy.
//! - **WAL archive** (`wal-archive`). The harness plays `archive_command`.
//!   It reads each cluster's current WAL segment, then switches to the
//!   next one, and seals the segment as a ClusterBackup container (kind
//!   2) named by `fstp_backup::parse_wal_name`. A segment already
//!   archived is not archived twice.
//! - **Keystore snapshot** (`keystore-snapshot`, and after each erasure
//!   batch of `erase-text`). The image of the cell's App chain keystore
//!   (`fstp_cell::tasks::erasure::snapshot`) is sealed to the cell's
//!   CellBackup group key (kind 3). It holds wrapped and sealed rows
//!   only, never a root or an open key (I-80).
//! - **ClusterBackup chain.** `fstp-control` holds it (ADR-004). No world
//!   part runs the control plane, so the harness holds one group key per
//!   cluster in the test process. Its custody is not modelled.
//! - **CellBackup chain.** `fstp-cell` holds it (ADR-004), but no cell
//!   code writes snapshots yet. The harness keeps it per cell through the
//!   cell's own custody: a root `R(e)` there, a seal key wrapped under it,
//!   and the group secret sealed under that seal key.
//! - **`rotate-chain`** is the yearly re-wrap of the CellBackup chain
//!   (design section 3.1): a new root and seal key, the group secret
//!   resealed under it, and the old root destroyed.
//! - **`erase-text`** stores a text that stays live, then erases the
//!   oldest live text that an earlier `erase-text` stored. The first one
//!   stores a second text and erases that. So a backup taken between two
//!   steps holds the sealed key of a text the next step erases (I-81).
//!   Each text is `salt (32) || text`, as `blob.text` holds it (ADR-007),
//!   with a text salt canary as the salt and a proposal text canary as
//!   the text. Every text of a cell shares one group, so an erasure
//!   reseals its live siblings (design section 3.5 step 2).
//! - **Restore** ([`World::restored_copies`]). Each object is opened
//!   alone, as a restore would read it. The opened bytes of a base backup
//!   or a WAL segment are the files a restore writes. No server is
//!   started over them. An opened snapshot gives its image. The live
//!   store comes last.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};

use fstp_backup::{ContainerKind, GroupRef, open_container, seal_container};
use fstp_cell::tasks::erasure::snapshot::{
    KeystoreImage, decode_image, encode_image, open_text, root_ref, seal_key_aad, wrapped_of,
};
use fstp_crypto::aead;
use fstp_crypto::hybrid_kem::{self, HybridPublicKey, HybridSecretKey};
use fstp_custody::{Aad, Custody, RootLabel, RootRef, SealKey, WrappedSealKey};
use fstp_keys::{CellId, Chain, Epoch, GroupId};
use fstp_rt::future::block_on;

use crate::canary::{Canary, CanaryKind};
use crate::scan::StoreSet;
use crate::world::{CellHandle, ClusterHandle, World, WorldCustody, WorldError};

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn err(what: &str, e: &dyn std::fmt::Display) -> WorldError {
    WorldError::Store(format!("backups: {what}: {e}"))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn random16(what: &str) -> Result<[u8; 16], WorldError> {
    fstp_crypto::random_array::<16>().map_err(|e| err(what, &e))
}

// ---------------------------------------------------------------------------
// The object store.

/// The uploaded objects of one world, in a directory of their own, which
/// goes with the world.
#[derive(Debug)]
struct ObjectStore {
    dir: PathBuf,
    names: Mutex<Vec<String>>,
}

impl ObjectStore {
    fn new() -> Result<ObjectStore, WorldError> {
        let dir = std::env::temp_dir().join(format!(
            "fstp-objects-{}-{}",
            std::process::id(),
            hex(&random16("an object store id")?)
        ));
        std::fs::create_dir_all(&dir).map_err(|e| err("the object store", &e))?;
        Ok(ObjectStore {
            dir,
            names: Mutex::new(Vec::new()),
        })
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name.replace('/', "_"))
    }

    /// Stores `bytes` as `name`, unless an object of that name exists.
    fn put(&self, name: &str, bytes: &[u8]) -> Result<(), WorldError> {
        let mut names = lock(&self.names);
        if names.iter().any(|n| n == name) {
            return Ok(());
        }
        std::fs::write(self.path(name), bytes).map_err(|e| err("an object", &e))?;
        names.push(name.to_owned());
        Ok(())
    }

    fn all(&self) -> Result<Vec<(String, Vec<u8>)>, WorldError> {
        lock(&self.names)
            .iter()
            .map(|n| {
                std::fs::read(self.path(n))
                    .map(|b| (n.clone(), b))
                    .map_err(|e| err("an object", &e))
            })
            .collect()
    }
}

impl Drop for ObjectStore {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

// ---------------------------------------------------------------------------
// The ClusterBackup group keys, which `fstp-control` would hold.

/// The ClusterBackup group key of one cluster.
struct ClusterKey {
    owner: [u8; 16],
    group: GroupId,
    secret: HybridSecretKey,
}

/// The group key of cluster `name`, made on first use. The clusters are
/// shared by every world of the process, so the keys are too.
fn cluster_key(name: &str) -> Result<&'static ClusterKey, WorldError> {
    type Keys = Mutex<BTreeMap<String, &'static ClusterKey>>;
    static KEYS: OnceLock<Keys> = OnceLock::new();
    let mut keys = lock(KEYS.get_or_init(Keys::default));
    if let Some(k) = keys.get(name) {
        return Ok(k);
    }
    let key: &'static ClusterKey = Box::leak(Box::new(ClusterKey {
        owner: crate::world::cluster_id(name)?,
        group: GroupId(random16("a group id")?),
        secret: hybrid_kem::generate().map_err(|e| err("a group key", &e))?,
    }));
    keys.insert(name.to_owned(), key);
    Ok(key)
}

/// The generation of every ClusterBackup group key here.
const CLUSTER_GENERATION: u32 = 1;

// ---------------------------------------------------------------------------
// The CellBackup chain of one cell.

/// The AAD label of a CellBackup seal key wrapped under its root.
const BACKUP_SEAL_AAD: &[u8] = b"fstp-cellbackup-seal-key-v1";
/// The AAD label of the CellBackup group secret under a seal key.
const BACKUP_GROUP_AAD: &[u8] = b"fstp-cellbackup-group-v1";
/// The generation of every CellBackup group key here. The yearly
/// rotation re-wraps it and keeps the group key.
const BACKUP_GENERATION: u32 = 1;

struct BackupChain {
    epoch: u64,
    root: RootRef,
    wrapped: WrappedSealKey,
    group: GroupId,
    public: HybridPublicKey,
    nonce: [u8; aead::NONCE_LEN],
    body: Vec<u8>,
}

fn seal_aad(cell: [u8; 16], epoch: u64) -> Aad {
    let mut aad = BACKUP_SEAL_AAD.to_vec();
    aad.extend_from_slice(&cell);
    aad.push(Chain::CellBackup.code());
    aad.extend_from_slice(&epoch.to_be_bytes());
    Aad(aad)
}

fn group_aad(cell: [u8; 16], group: GroupId, epoch: u64) -> Vec<u8> {
    let mut aad = BACKUP_GROUP_AAD.to_vec();
    aad.extend_from_slice(&cell);
    aad.extend_from_slice(&group.0);
    aad.extend_from_slice(&BACKUP_GENERATION.to_be_bytes());
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad
}

/// A new root of epoch `epoch` and a fresh seal key wrapped under it.
fn new_root(
    custody: &WorldCustody,
    cell: [u8; 16],
    epoch: u64,
) -> Result<(RootRef, WrappedSealKey, SealKey), WorldError> {
    let root = block_on(custody.create_root(RootLabel {
        cell: Some(CellId(cell)),
        chain: Chain::CellBackup,
        epoch: Epoch(epoch),
    }))
    .map_err(|e| err("a CellBackup root", &e))?;
    let s = SealKey::generate().map_err(|e| err("a seal key", &e))?;
    let wrapped = block_on(custody.wrap(&root, &s, &seal_aad(cell, epoch)))
        .map_err(|e| err("the CellBackup wrap", &e))?;
    Ok((root, wrapped, s))
}

fn seal_secret(
    s: &SealKey,
    cell: [u8; 16],
    group: GroupId,
    epoch: u64,
    secret: &HybridSecretKey,
) -> Result<aead::Sealed, WorldError> {
    let key = aead::Key::from_bytes(s.expose()).map_err(|e| err("a seal key", &e))?;
    aead::seal(&key, &group_aad(cell, group, epoch), &secret.to_bytes()[..])
        .map_err(|e| err("the CellBackup group secret", &e))
}

impl BackupChain {
    fn genesis(custody: &WorldCustody, cell: [u8; 16]) -> Result<BackupChain, WorldError> {
        let (root, wrapped, s) = new_root(custody, cell, 0)?;
        let group = GroupId(random16("a group id")?);
        let secret = hybrid_kem::generate().map_err(|e| err("a group key", &e))?;
        let sealed = seal_secret(&s, cell, group, 0, &secret)?;
        Ok(BackupChain {
            epoch: 0,
            root,
            wrapped,
            group,
            public: secret.public().clone(),
            nonce: sealed.nonce,
            body: sealed.body,
        })
    }

    /// The group secret, through custody: refused once the root is gone.
    fn secret(
        &self,
        custody: &WorldCustody,
        cell: [u8; 16],
    ) -> Result<HybridSecretKey, WorldError> {
        let s = block_on(custody.unwrap(&self.root, &self.wrapped, &seal_aad(cell, self.epoch)))
            .map_err(|e| err("the CellBackup unwrap", &e))?;
        let key = aead::Key::from_bytes(s.expose()).map_err(|e| err("a seal key", &e))?;
        let bytes = aead::open(
            &key,
            &self.nonce,
            &group_aad(cell, self.group, self.epoch),
            &self.body,
        )
        .map_err(|e| err("the CellBackup group secret", &e))?;
        HybridSecretKey::from_bytes(&bytes).map_err(|e| err("the CellBackup group secret", &e))
    }

    /// The yearly re-wrap: a new root and seal key, the group secret
    /// resealed under it, then the old root destroyed.
    fn rotate(&mut self, custody: &WorldCustody, cell: [u8; 16]) -> Result<(), WorldError> {
        let secret = self.secret(custody, cell)?;
        let epoch = self
            .epoch
            .checked_add(1)
            .ok_or_else(|| err("the CellBackup epoch", &"overflow"))?;
        let (root, wrapped, s) = new_root(custody, cell, epoch)?;
        let sealed = seal_secret(&s, cell, self.group, epoch, &secret)?;
        let old = std::mem::replace(&mut self.root, root);
        self.wrapped = wrapped;
        self.epoch = epoch;
        self.nonce = sealed.nonce;
        self.body = sealed.body;
        block_on(custody.destroy(&old)).map_err(|e| err("the CellBackup destroy", &e))?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The state of one cell.

/// One text that `erase-text` stored.
#[derive(Clone, Debug)]
struct StoredText {
    id: [u8; 16],
    salt: Canary,
    text: Canary,
}

#[derive(Default)]
struct State {
    chain: Option<BackupChain>,
    group: Option<[u8; 16]>,
    texts: Vec<StoredText>,
}

/// What a cell's backups reach of its world: the object store and the
/// world's clusters.
#[derive(Debug)]
struct WorldPart {
    store: Arc<ObjectStore>,
    clusters: Vec<(String, &'static fstp_pgtest::PgServer)>,
}

/// The backups and stored texts of one cell (module documentation), and
/// the fault point of its record store (R-NF-08).
#[derive(Default)]
pub struct CellBackups {
    state: Mutex<State>,
    world: OnceLock<WorldPart>,
    fault: fstp_pgstore::FaultPoint,
    retried: std::sync::atomic::AtomicU64,
}

impl CellBackups {
    /// The fault point of the cell's record store, which the cell starts
    /// with (`fstp_cell::process::StartOptions::fault_point`).
    pub(crate) fn fault(&self) -> &fstp_pgstore::FaultPoint {
        &self.fault
    }

    /// Counts one command that the cycle sent again after the fault point
    /// aborted its append.
    pub(crate) fn note_retry(&self) {
        let _ = self.retried.fetch_update(
            std::sync::atomic::Ordering::SeqCst,
            std::sync::atomic::Ordering::SeqCst,
            |n| n.checked_add(1),
        );
    }

    /// How many aborted commands the cycle sent again.
    pub(crate) fn retried(&self) -> u64 {
        self.retried.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl std::fmt::Debug for CellBackups {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CellBackups").finish_non_exhaustive()
    }
}

/// Gives the started `cells` of a world their object store and the
/// world's self-operated clusters.
pub(crate) fn attach(cells: &[CellHandle], clusters: &[ClusterHandle]) -> Result<(), WorldError> {
    let store = Arc::new(ObjectStore::new()?);
    let agent: Vec<(String, &'static fstp_pgtest::PgServer)> = clusters
        .iter()
        .filter(|c| crate::world::is_agent_kind(c.kind()))
        .map(|c| (c.name().to_owned(), c.server()))
        .collect();
    for c in cells {
        let _ = c.backups.world.set(WorldPart {
            store: Arc::clone(&store),
            clusters: agent.clone(),
        });
    }
    Ok(())
}

fn world_part(cell: &CellHandle) -> Result<&WorldPart, WorldError> {
    cell.backups
        .world
        .get()
        .ok_or_else(|| err("the cell", &"has no world part"))
}

// ---------------------------------------------------------------------------
// The steps.

/// `keystore-snapshot`: the image of the cell's App chain keystore,
/// sealed to its CellBackup group key and stored as
/// `<cell>/keystore/<snapshot id>`.
///
/// # Errors
///
/// Fails when the keystore cannot be read or a seal fails.
pub(crate) fn keystore_snapshot(cell: &CellHandle) -> Result<(), WorldError> {
    let image = live_image(cell)?;
    let bytes = encode_image(&image).map_err(|e| err("the keystore image", &e))?;
    let custody = cell.custody()?;
    let mut state = lock(&cell.backups.state);
    if state.chain.is_none() {
        state.chain = Some(BackupChain::genesis(&custody, cell.id())?);
    }
    let chain = state
        .chain
        .as_ref()
        .ok_or_else(|| err("the CellBackup chain", &"missing"))?;
    let group = GroupRef {
        owner: cell.id(),
        group: chain.group,
        generation: BACKUP_GENERATION,
    };
    let sealed = seal_container(
        &chain.public,
        ContainerKind::KeystoreSnapshot,
        &group,
        0,
        &bytes,
    )
    .map_err(|e| err("the snapshot container", &e))?;
    let name = format!(
        "{}/keystore/{}",
        hex(&cell.id()),
        hex(&random16("a snapshot id")?)
    );
    world_part(cell)?.store.put(&name, &sealed)
}

/// `base-backup`: a `pg_basebackup` of each self-operated cluster, each
/// file sealed as `<cluster>/base/<backup id>/<file>/0`, then the cell's keystore snapshot
/// (module documentation).
///
/// # Errors
///
/// Fails when a cluster has no replication role, `pg_basebackup` fails,
/// or a seal fails.
pub(crate) fn base_backup(cell: &CellHandle) -> Result<(), WorldError> {
    let part = world_part(cell)?;
    for (name, server) in &part.clusters {
        let login = crate::world::replication_of(name)?
            .ok_or_else(|| err(name, &"has no replication role"))?;
        let files = server
            .base_backup_files(&login)
            .map_err(|e| err("pg_basebackup", &e))?;
        let key = cluster_key(name)?;
        let group = GroupRef {
            owner: key.owner,
            group: key.group,
            generation: CLUSTER_GENERATION,
        };
        let id = hex(&random16("a backup id")?);
        for (file, bytes) in files {
            let sealed = seal_container(
                key.secret.public(),
                ContainerKind::BaseBackup,
                &group,
                0,
                &bytes,
            )
            .map_err(|e| err("a base backup container", &e))?;
            let object = format!("{}/base/{id}/{file}/0", hex(&key.owner));
            part.store.put(&object, &sealed)?;
        }
    }
    keystore_snapshot(cell)
}

/// `wal-archive`: each cluster's current WAL segment, read and then
/// switched, sealed as `<cluster>/wal/<segment name>`.
///
/// # Errors
///
/// Fails when the segment cannot be read, its name does not parse, or a
/// seal fails.
pub(crate) fn wal_archive(cell: &CellHandle) -> Result<(), WorldError> {
    let part = world_part(cell)?;
    for (name, server) in &part.clusters {
        let segment = server
            .psql("postgres", "SELECT pg_walfile_name(pg_current_wal_lsn())")
            .map_err(|e| err("the current WAL segment", &e))?;
        let wal = fstp_backup::parse_wal_name(&segment).map_err(|e| err("a WAL name", &e))?;
        let bytes = std::fs::read(server.dir().join("data/pg_wal").join(wal.file_name()))
            .map_err(|e| err("a WAL segment", &e))?;
        server
            .psql("postgres", "SELECT pg_switch_wal()")
            .map_err(|e| err("pg_switch_wal", &e))?;
        let key = cluster_key(name)?;
        let group = GroupRef {
            owner: key.owner,
            group: key.group,
            generation: CLUSTER_GENERATION,
        };
        let sealed = seal_container(
            key.secret.public(),
            ContainerKind::WalSegment,
            &group,
            0,
            &bytes,
        )
        .map_err(|e| err("a WAL container", &e))?;
        part.store.put(
            &format!("{}/wal/{}", hex(&key.owner), wal.file_name()),
            &sealed,
        )?;
    }
    Ok(())
}

/// `rotate-chain`: the yearly re-wrap of the cell's CellBackup chain
/// (module documentation). A chain that does not exist yet is created
/// first, so the step always destroys one root.
///
/// # Errors
///
/// Fails when custody refuses a call.
pub(crate) fn rotate_chain(cell: &CellHandle) -> Result<(), WorldError> {
    let custody = cell.custody()?;
    let mut state = lock(&cell.backups.state);
    if state.chain.is_none() {
        state.chain = Some(BackupChain::genesis(&custody, cell.id())?);
    }
    match state.chain.as_mut() {
        Some(chain) => chain.rotate(&custody, cell.id()),
        None => Err(err("the CellBackup chain", &"missing")),
    }
}

/// The texts `erase-text` stores and the one it erases: their ids, in
/// the order the ledger takes `PutText`.
pub(crate) struct TextErasure {
    /// The texts stored now.
    pub(crate) put: Vec<[u8; 16]>,
    /// The text to erase.
    pub(crate) erase: [u8; 16],
}

/// Stores the texts of one `erase-text` step through the cell's erasure
/// task and names the text to erase (module documentation).
///
/// # Errors
///
/// Fails when the erasure task refuses the group or a text.
pub(crate) fn prepare_text_erasure(cell: &CellHandle) -> Result<TextErasure, WorldError> {
    let erasure = cell.erasure()?;
    let erased = erasure.erased();
    let mut state = lock(&cell.backups.state);
    let group = match state.group {
        Some(g) => g,
        None => {
            let g = random16("a text group")?;
            cell.block_on(erasure.add_group(g))?
                .map_err(|e| err("the text group", &e))?;
            state.group = Some(g);
            g
        }
    };
    let victim = state
        .texts
        .iter()
        .find(|t| !erased.contains(&t.id))
        .map(|t| t.id);
    let count = if victim.is_some() { 1 } else { 2 };
    let mut put = Vec::new();
    for _ in 0..count {
        let salt = Canary::generate(cell.index(), CanaryKind::TextSalt)
            .map_err(|e| err("a salt canary", &e))?;
        let text = Canary::generate(cell.index(), CanaryKind::ProposalText)
            .map_err(|e| err("a text canary", &e))?;
        let id = random16("a text id")?;
        let mut bytes = salt.secret_bytes().to_vec();
        bytes.extend_from_slice(text.text().as_bytes());
        cell.block_on(erasure.put_text(group, id, bytes))?
            .map_err(|e| err("a text", &e))?;
        state.texts.push(StoredText { id, salt, text });
        put.push(id);
    }
    let erase = match (victim, put.last()) {
        (Some(v), _) | (None, Some(&v)) => v,
        (None, None) => return Err(err("erase-text", &"stored no text")),
    };
    Ok(TextErasure { put, erase })
}

/// The live image of the cell's keystore.
fn live_image(cell: &CellHandle) -> Result<KeystoreImage, WorldError> {
    let erasure = cell.erasure()?;
    cell.block_on(erasure.keystore())?
        .ok_or_else(|| err("the keystore", &"the erasure task is not running"))?
        .image()
        .map_err(|e| err("the keystore image", &e))
}

// ---------------------------------------------------------------------------
// Copies and their trial.

/// What [`World::try_every_text`] found. The counts show it tried
/// something.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TextTrial {
    /// The (copy, erased text) pairs tried.
    pub erased_tried: usize,
    /// The (copy, live text) pairs tried.
    pub live_tried: usize,
    /// The erased texts that opened, by copy.
    pub erased_opened: Vec<String>,
    /// The live texts that did not open, by copy.
    pub live_failed: Vec<String>,
}

/// The prefix of a keystore image in a copy's store set.
pub const KEYSTORE_PREFIX: &str = "keystore/";

impl World {
    /// Every object the world's backups uploaded, by ADR-012 object name,
    /// in upload order (lane F-ERASE).
    ///
    /// # Errors
    ///
    /// Fails when an object cannot be read.
    pub fn backup_objects(&self) -> Result<Vec<(String, Vec<u8>)>, WorldError> {
        match self.cell(0).and_then(|c| c.backups.world.get()) {
            Some(part) => part.store.all(),
            None => Ok(Vec::new()),
        }
    }

    /// Every backup copy, each restored alone (module documentation), and
    /// the live store last. A copy of a base backup or a WAL segment holds
    /// its opened bytes as `restored/<object>`. A copy of a keystore
    /// snapshot holds its image as `keystore/<cell>/<object>`. The live
    /// store is [`World::stores`] with the live image of each cell as
    /// `keystore/<cell>/live`.
    ///
    /// # Errors
    ///
    /// Fails when an object does not open under the key that sealed it.
    pub fn restored_copies(&self) -> Result<Vec<StoreSet>, WorldError> {
        let mut out = Vec::new();
        for (name, bytes) in self.backup_objects()? {
            let mut set = StoreSet::default();
            if name.contains("/keystore/") {
                let cell = self
                    .cells()
                    .find(|c| name.starts_with(&hex(&c.id())))
                    .ok_or_else(|| err("a snapshot", &"names no cell of the world"))?;
                let secret = {
                    let state = lock(&cell.backups.state);
                    let chain = state
                        .chain
                        .as_ref()
                        .ok_or_else(|| err("the CellBackup chain", &"missing"))?;
                    chain.secret(&cell.custody()?, cell.id())?
                };
                let opened = open_container(&secret, &bytes).map_err(|e| err("a snapshot", &e))?;
                set.push(
                    format!("{KEYSTORE_PREFIX}{}/{name}", hex(&cell.id())),
                    opened.plaintext,
                );
            } else {
                let cluster = name.split('/').next().unwrap_or_default();
                let key = self
                    .clusters()
                    .iter()
                    .filter_map(|c| cluster_key(c.name()).ok())
                    .find(|k| hex(&k.owner) == cluster)
                    .ok_or_else(|| err("an object", &"names no cluster of the world"))?;
                let opened =
                    open_container(&key.secret, &bytes).map_err(|e| err("a cluster object", &e))?;
                set.push(format!("restored/{name}"), opened.plaintext);
            }
            out.push(set);
        }
        let mut live = self.stores()?;
        for c in self.cells() {
            let image = encode_image(&live_image(c)?).map_err(|e| err("an image", &e))?;
            live.push(format!("{KEYSTORE_PREFIX}{}/live", hex(&c.id())), image);
        }
        out.push(live);
        Ok(out)
    }

    /// Tries every text of every keystore image in `copies` with every
    /// wrapped key of that copy and of the live keystore, each unwrapped
    /// under every live custody root of the cell (I-81, design section
    /// 3.5). Key rows follow the restore rule of ADR-012: the live
    /// keystore's rows first, then the copy's own. A text the cell erased
    /// counts as erased, every other text as live.
    ///
    /// # Errors
    ///
    /// Fails when an image does not decode or a keystore cannot be read.
    pub fn try_every_text(&self, copies: &[StoreSet]) -> Result<TextTrial, WorldError> {
        let mut trial = TextTrial::default();
        let mut lives = BTreeMap::new();
        for c in self.cells() {
            lives.insert(c.id(), (c, live_image(c)?, c.erasure()?.erased()));
        }
        for (i, copy) in copies.iter().enumerate() {
            for (name, bytes) in &copy.stores {
                if !name.starts_with(KEYSTORE_PREFIX) {
                    continue;
                }
                let image = decode_image(bytes).map_err(|e| err("an image", &e))?;
                let (cell, live, erased) = lives
                    .get(&image.cell)
                    .ok_or_else(|| err("an image", &"names no cell of the world"))?;
                let rows = [live, &image];
                let seal_keys = unwrap_every_root(&cell.custody()?, image.cell, &rows);
                for text in &image.texts {
                    let opened = open_text(image.cell, &rows, &seal_keys, text).is_some();
                    let at = format!("copy {i} {name} text {}", hex(&text.id));
                    if erased.contains(&text.id) {
                        trial.erased_tried = trial.erased_tried.saturating_add(1);
                        if opened {
                            trial.erased_opened.push(at);
                        }
                    } else {
                        trial.live_tried = trial.live_tried.saturating_add(1);
                        if !opened {
                            trial.live_failed.push(at);
                        }
                    }
                }
            }
        }
        Ok(trial)
    }

    /// The canaries of `kind` in the texts `erase-text` stored, of the
    /// erased texts or of the live ones (lane F-ERASE). The text salt
    /// and proposal text kinds have canaries. Other kinds give none.
    ///
    /// # Errors
    ///
    /// Fails when a cell's erasure task cannot be reached.
    pub fn text_canaries(&self, kind: CanaryKind, erased: bool) -> Result<Vec<Canary>, WorldError> {
        let mut out = Vec::new();
        for c in self.cells() {
            let gone = c.erasure()?.erased();
            for t in &lock(&c.backups.state).texts {
                if gone.contains(&t.id) != erased {
                    continue;
                }
                match kind {
                    CanaryKind::TextSalt => out.push(t.salt.clone()),
                    CanaryKind::ProposalText => out.push(t.text.clone()),
                    _ => {}
                }
            }
        }
        Ok(out)
    }

    fn cells(&self) -> impl Iterator<Item = &CellHandle> {
        (0..=u8::MAX).map_while(|i| self.cell(i))
    }
}

/// Every seal key that a root row of `rows` gives under any live custody
/// root of `custody`.
fn unwrap_every_root(
    custody: &WorldCustody,
    cell: [u8; 16],
    rows: &[&KeystoreImage],
) -> Vec<SealKey> {
    let live = custody.live_handles();
    let mut out = Vec::new();
    for img in rows {
        for row in &img.roots {
            let aad = seal_key_aad(cell, row.epoch);
            let wrapped = wrapped_of(row);
            for handle in &live {
                let mut root = root_ref(cell, row);
                root.handle = fstp_custody::CustodyHandle(handle.clone());
                if let Ok(s) = block_on(custody.unwrap(&root, &wrapped, &aad)) {
                    out.push(s);
                }
            }
        }
    }
    out
}
