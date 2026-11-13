//! The erasure runner of the App chain (design sections 3.4 and 3.5,
//! I-81, R-KY-02, ADR-004 part 2 and "Reconciliation", ADR-007).
//!
//! The planner is `fstp_keys::erasure`. The runner is its shell. It holds
//! the keystore of the chain, calls custody, and records its key records
//! through the engine under the system task `ErasureRunner`.
//!
//! # One batch, from epoch `e` to `e + 1`
//!
//! Each call of [`ErasureRunner::step`] does the work of one
//! [`ErasureEvent`], so a crash can fall between any two of them:
//!
//! 1. [`ErasureEvent::RequestRecorded`]: requests recorded in the ledger
//!    (`TextErasureRequested`) join the chain state, which is durable from
//!    here. The texts cannot be opened from the ledger request on
//!    ([`open_text`]).
//! 2. [`ErasureEvent::GroupsRotated`]: each affected group gets a new
//!    generation, and every surviving sibling is resealed to it.
//! 3. [`ErasureEvent::RootCreated`] and [`ErasureEvent::SealKeyWrapped`]:
//!    `R(e+1)` is created in custody and a fresh `S(e+1)` wrapped under
//!    it. The new root's reference is kept at once, so a restart reuses it
//!    rather than leave an orphan root. [`ErasureEvent::GroupsResealed`]:
//!    every live group secret is resealed under `S(e+1)`.
//! 4. [`ErasureEvent::Committed`]: the new rows are committed at once.
//! 5. [`ErasureEvent::SnapshotTaken`] and
//!    [`ErasureEvent::SnapshotVerified`]: a keystore snapshot is taken,
//!    and a scratch copy opens a sample of live keys under `R(e+1)`.
//! 6. [`ErasureEvent::RootDestroyed`]: `R(e)` is destroyed in custody and
//!    its receipt digest kept. `S(e)` and the old group secrets are
//!    dropped, which wipes them.
//! 7. [`ErasureEvent::CompletionRecorded`]: `KeyEpochDestroyed` is
//!    appended with the receipt digest.
//!
//! Every custody call first appends a `RecordKeyOp` ledger record with
//! its request id (ADR-004 "Reconciliation", Daniel 2026-10-29). A call
//! whose record cannot be appended is never made.
//!
//! # Durability
//!
//! [`Keystore`] holds what survives a crash: the rows, the chain state at
//! its last durable point and the reference of a root created for a batch
//! not yet committed. Until the PostgreSQL keystore tables of lane W2e
//! land it is held in memory by its owner. Steps 2 and 3 live in process
//! memory until the commit, so a restart before the commit starts the
//! batch again from step 2 (`ChainState::restart`).
//!
//! # Reading against `fstp-cell-core`
//!
//! `fstp_cell_core` decides `EraseTexts` as `ErasureRequested` and
//! `TextsErased` in one batch, so the erasure-log entry shows
//! `completed_at` at the request (decide.rs, "In M3 the erasure completes
//! in the same batch"). Design section 3.5 reports completion only at
//! step 7. `KeyCommand` has no command that records `TextsErased` with
//! `KeyEpochDestroyed`. That change belongs to lane W2c.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use fstp_cell_core::gate::{self, Action};
use fstp_cell_core::{CellCommand, CellState, KeyCommand, SystemTask, system_command_id};
use fstp_crypto::aead;
use fstp_crypto::hybrid_kem::{self, HybridSecretKey};
use fstp_custody::{Aad, Custody, RootLabel, RootRef, SealKey, WrappedSealKey};
use fstp_domain::time::Timestamp;
use fstp_json::{Object, Value};
use fstp_keys::envelope::{self, DataKey, SealContext, SealedBlob, SealedKey};
use fstp_keys::erasure::{self as plan, ChainState, Step};
use fstp_keys::{CellId, Chain, DekId, Epoch, GroupId, ObjectId, Purpose};
use fstp_rt::ShutdownSignal;
use fstp_rt::future::{Either, race, yield_now};

use super::Clock;
use crate::CellError;
use crate::engine::chan::{self, Receiver, ReplyTx, Sender};
use crate::engine::{CellEngine, EngineError};

/// The AAD label of a wrapped seal key.
pub const SEAL_KEY_AAD: &[u8] = b"fstp-seal-key-v1";
/// The AAD label of a group secret sealed under a seal key.
pub const GROUP_SECRET_AAD: &[u8] = b"fstp-group-secret-v1";

/// One unit of the runner's work, in design order (design section 3.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErasureEvent {
    /// Step 1: requests joined the chain state.
    RequestRecorded,
    /// Step 2: the affected groups were rotated.
    GroupsRotated,
    /// Step 3: `R(epoch)` was created in custody.
    RootCreated {
        /// The new epoch.
        epoch: u64,
    },
    /// Step 3: `S(epoch)` was wrapped under `R(epoch)`.
    SealKeyWrapped {
        /// The new epoch.
        epoch: u64,
    },
    /// Step 3: every live group secret was resealed under `S(epoch)`.
    GroupsResealed {
        /// The new epoch.
        epoch: u64,
    },
    /// Step 4: the new rows of `epoch` were committed.
    Committed {
        /// The new epoch.
        epoch: u64,
    },
    /// Step 5: a keystore snapshot was taken.
    SnapshotTaken {
        /// The new epoch.
        epoch: u64,
    },
    /// Step 5: the snapshot opened a sample of live keys.
    SnapshotVerified {
        /// The new epoch.
        epoch: u64,
    },
    /// Step 6: `R(epoch)` was destroyed and its receipt kept.
    RootDestroyed {
        /// The old epoch.
        epoch: u64,
    },
    /// Step 7: `KeyEpochDestroyed` of `epoch` was appended.
    CompletionRecorded {
        /// The old epoch.
        epoch: u64,
    },
}

/// One stored text: its data key and its sealed body.
#[derive(Clone)]
struct TextRow {
    dek: DekId,
    blob: SealedBlob,
}

/// One root epoch: its custody reference and its wrapped seal key.
#[derive(Clone)]
struct RootRow {
    root: RootRef,
    wrapped: WrappedSealKey,
}

/// A group secret sealed under the seal key of `epoch`.
#[derive(Clone)]
struct GroupRow {
    epoch: u64,
    nonce: [u8; aead::NONCE_LEN],
    body: Vec<u8>,
}

/// The durable key state of one chain: what survives a crash.
#[derive(Clone)]
pub struct Keystore {
    cell: CellId,
    chain_state: ChainState,
    roots: BTreeMap<u64, RootRow>,
    receipts: BTreeMap<u64, [u8; 32]>,
    groups: BTreeMap<(GroupId, u32), GroupRow>,
    keys: BTreeMap<DekId, (GroupId, u32, SealedKey)>,
    texts: BTreeMap<[u8; 16], TextRow>,
    /// A root created for the batch in flight, before its commit.
    pending_root: Option<RootRow>,
    /// Requests already joined, by text.
    requested: BTreeSet<[u8; 16]>,
}

impl std::fmt::Debug for Keystore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keystore")
            .field("epoch", &self.chain_state.epoch())
            .field("roots", &self.roots.keys().collect::<Vec<_>>())
            .field("texts", &self.texts.len())
            .finish_non_exhaustive()
    }
}

impl Keystore {
    /// The current root epoch.
    pub fn epoch(&self) -> u64 {
        self.chain_state.epoch().0
    }

    /// The custody receipt digest of each destroyed epoch.
    pub fn receipts(&self) -> &BTreeMap<u64, [u8; 32]> {
        &self.receipts
    }

    /// The epochs whose root this keystore still references.
    pub fn live_roots(&self) -> Vec<u64> {
        self.roots
            .keys()
            .copied()
            .filter(|e| !self.receipts.contains_key(e))
            .collect()
    }

    /// Start-up, first half (design section 3.4): unwraps the current
    /// `S(e)` through custody. The chain cannot be written before `S(e)`
    /// is open, so its `RecordKeyOp` follows once the engine runs
    /// ([`ErasureRunner::from_open`], ADR-004 "Reconciliation").
    ///
    /// # Errors
    ///
    /// [`CellError::Custody`] when custody refuses or cannot be reached.
    pub async fn unwrap_current<C: Custody>(&self, custody: &C) -> Result<SealKey, CellError> {
        let epoch = self.chain_state.epoch().0;
        let row = self
            .roots
            .get(&epoch)
            .ok_or(keys_err("no root of the current epoch"))?;
        custody
            .unwrap(&row.root, &row.wrapped, &seal_aad(self.cell, epoch))
            .await
            .map_err(CellError::Custody)
    }

    /// Start-up, second half: opens every current group secret under
    /// `s` into process memory.
    ///
    /// # Errors
    ///
    /// [`CellError::Keys`] when a group secret does not open.
    pub fn open_groups(&self, s: &SealKey) -> Result<OpenGroups, CellError> {
        let mut secrets = BTreeMap::new();
        for ((g, generation), row) in &self.groups {
            if self.chain_state.generation(*g) == Some(*generation) {
                secrets.insert(
                    (*g, *generation),
                    open_group(s, self.cell, *g, *generation, row)?,
                );
            }
        }
        Ok(OpenGroups(secrets))
    }
}

/// The group secrets of a keystore, open in process memory. They wipe on
/// drop.
pub struct OpenGroups(BTreeMap<(GroupId, u32), HybridSecretKey>);

impl OpenGroups {
    /// How many group secrets are open.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether no group secret is open.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Why a text did not open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenRefusal {
    /// Its erasure was requested or completed: it resolves to its
    /// erasure-log entry, never to the text (design section 3.4).
    Erased,
    /// The cell holds no such text.
    Unknown,
    /// The key chain refused.
    Keys,
}

fn keys_err(step: &'static str) -> CellError {
    CellError::Keys(step)
}

fn ctx_for(cell: CellId, group: GroupId, generation: u32, object: [u8; 16]) -> SealContext {
    SealContext {
        cell,
        chain: Chain::App,
        purpose: Purpose::Text,
        group,
        generation,
        object: ObjectId(object),
    }
}

fn group_aad(cell: CellId, group: GroupId, generation: u32, epoch: u64) -> Vec<u8> {
    let mut aad = GROUP_SECRET_AAD.to_vec();
    aad.extend_from_slice(&cell.0);
    aad.push(Chain::App.code());
    aad.extend_from_slice(&group.0);
    aad.extend_from_slice(&generation.to_be_bytes());
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad
}

fn seal_aad(cell: CellId, epoch: u64) -> Aad {
    let mut aad = SEAL_KEY_AAD.to_vec();
    aad.extend_from_slice(&cell.0);
    aad.push(Chain::App.code());
    aad.extend_from_slice(&epoch.to_be_bytes());
    Aad(aad)
}

fn seal_group(
    s: &SealKey,
    cell: CellId,
    group: GroupId,
    generation: u32,
    epoch: u64,
    sk: &HybridSecretKey,
) -> Result<GroupRow, CellError> {
    let key = aead::Key::from_bytes(s.expose()).map_err(|_| keys_err("seal key"))?;
    let sealed = aead::seal(
        &key,
        &group_aad(cell, group, generation, epoch),
        &sk.to_bytes()[..],
    )
    .map_err(|_| keys_err("group secret seal"))?;
    Ok(GroupRow {
        epoch,
        nonce: sealed.nonce,
        body: sealed.body,
    })
}

fn open_group(
    s: &SealKey,
    cell: CellId,
    group: GroupId,
    generation: u32,
    row: &GroupRow,
) -> Result<HybridSecretKey, CellError> {
    let key = aead::Key::from_bytes(s.expose()).map_err(|_| keys_err("seal key"))?;
    let bytes = aead::open(
        &key,
        &row.nonce,
        &group_aad(cell, group, generation, row.epoch),
        &row.body,
    )
    .map_err(|_| keys_err("group secret open"))?;
    HybridSecretKey::from_bytes(&bytes).map_err(|_| keys_err("group secret decode"))
}

/// The canonical `RecordKeyOp` body of a custody call.
fn key_op_body(call: &str, epoch: u64, request: [u8; 16]) -> Result<Vec<u8>, CellError> {
    let mut hex = String::with_capacity(32);
    for b in request {
        hex.push_str(&format!("{b:02x}"));
    }
    let members = vec![
        ("call".to_owned(), Value::String(call.to_owned())),
        ("chain".to_owned(), Value::String("app".to_owned())),
        (
            "epoch".to_owned(),
            Value::Number(fstp_json::Number::from(epoch)),
        ),
        ("request".to_owned(), Value::String(hex)),
    ];
    let obj = Object::from_members(members).map_err(|_| keys_err("key op body"))?;
    fstp_json::to_canonical(&Value::Object(obj))
        .map(String::into_bytes)
        .map_err(|_| keys_err("key op body"))
}

/// What the runner holds in process memory: the open secrets and the
/// work of steps 2 and 3 before their commit.
struct Work {
    /// `S(e)` of the current epoch.
    current: SealKey,
    /// The open group secrets of the committed state.
    secrets: BTreeMap<(GroupId, u32), HybridSecretKey>,
    /// Step 2: the new generations and their resealed keys.
    new_groups: BTreeMap<(GroupId, u32), HybridSecretKey>,
    resealed: BTreeMap<DekId, (GroupId, u32, SealedKey)>,
    /// Step 3: the new root, seal key and resealed group rows.
    new_root: Option<RootRow>,
    new_seal: Option<SealKey>,
    rows: BTreeMap<(GroupId, u32), GroupRow>,
    /// Step 5: the snapshot taken.
    snapshot: Option<Keystore>,
}

/// The erasure runner of one cell's App chain.
pub struct ErasureRunner<C> {
    custody: C,
    engine: CellEngine,
    store: Keystore,
    /// The working chain state: the durable one plus steps not yet durable.
    chain: ChainState,
    work: Work,
    events: Vec<ErasureEvent>,
    erased: Vec<[u8; 16]>,
}

impl<C> std::fmt::Debug for ErasureRunner<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ErasureRunner")
            .field("store", &self.store)
            .field("events", &self.events)
            .finish_non_exhaustive()
    }
}

/// A fresh request id for a custody call.
fn request_id() -> Result<[u8; 16], CellError> {
    let mut id = [0u8; 16];
    fstp_crypto::random_bytes(&mut id).map_err(|_| keys_err("request id"))?;
    Ok(id)
}

impl<C: Custody> ErasureRunner<C> {
    /// Creates the chain at epoch 0 for `cell`: root `R(0)` in custody and
    /// a fresh `S(0)` wrapped under it, each custody call recorded first.
    ///
    /// # Errors
    ///
    /// A refused key record, or a custody failure.
    pub async fn genesis(
        custody: C,
        engine: CellEngine,
        cell: [u8; 16],
    ) -> Result<ErasureRunner<C>, CellError> {
        let cell = CellId(cell);
        let mut runner = ErasureRunner {
            custody,
            engine,
            store: Keystore {
                cell,
                chain_state: ChainState::genesis(Epoch(0)),
                roots: BTreeMap::new(),
                receipts: BTreeMap::new(),
                groups: BTreeMap::new(),
                keys: BTreeMap::new(),
                texts: BTreeMap::new(),
                pending_root: None,
                requested: BTreeSet::new(),
            },
            chain: ChainState::genesis(Epoch(0)),
            work: Work::new(SealKey::generate().map_err(CellError::Custody)?),
            events: Vec::new(),
            erased: Vec::new(),
        };
        let root = runner.create_root(0).await?;
        let wrapped = runner.wrap(&root, &runner.work.current, 0).await?;
        runner.store.roots.insert(0, RootRow { root, wrapped });
        Ok(runner)
    }

    /// Resumes after a crash from the durable `store`. It unwraps the
    /// current seal key through custody and opens the group secrets
    /// (design section 3.4).
    ///
    /// # Errors
    ///
    /// A refused key record, a custody failure, or a keystore that does
    /// not open.
    pub async fn resume(
        custody: C,
        engine: CellEngine,
        store: Keystore,
    ) -> Result<ErasureRunner<C>, CellError> {
        let epoch = store.chain_state.epoch().0;
        let row = store
            .roots
            .get(&epoch)
            .cloned()
            .ok_or(keys_err("no root of the current epoch"))?;
        let chain = store.chain_state.restart();
        let mut runner = ErasureRunner {
            custody,
            engine,
            store,
            chain,
            work: Work::new(SealKey::from_bytes([0; 32])),
            events: Vec::new(),
            erased: Vec::new(),
        };
        let s = runner.unwrap(&row, epoch).await?;
        runner.work.current = s;
        runner.open_secrets()?;
        Ok(runner)
    }

    /// The runner after a start-up that opened `seal` and `groups` from
    /// `store`. It records the deferred `RecordKeyOp` of the start-up
    /// unwrap first (ADR-004 "Reconciliation").
    ///
    /// # Errors
    ///
    /// A refused key record.
    pub async fn from_open(
        custody: C,
        engine: CellEngine,
        store: Keystore,
        seal: SealKey,
        groups: OpenGroups,
    ) -> Result<ErasureRunner<C>, CellError> {
        let chain = store.chain_state.restart();
        let epoch = store.chain_state.epoch().0;
        let mut work = Work::new(seal);
        work.secrets = groups.0;
        let runner = ErasureRunner {
            custody,
            engine,
            store,
            chain,
            work,
            events: Vec::new(),
            erased: Vec::new(),
        };
        runner.record_call("unwrap", epoch).await?;
        Ok(runner)
    }

    /// The durable keystore, for a restart.
    pub fn keystore(&self) -> &Keystore {
        &self.store
    }

    /// The texts whose erasure this runner completed, in order.
    pub fn erased(&self) -> &[[u8; 16]] {
        &self.erased
    }

    /// Every event so far, in order.
    pub fn events(&self) -> &[ErasureEvent] {
        &self.events
    }

    /// The custody backend.
    pub fn custody(&self) -> &C {
        &self.custody
    }

    fn open_secrets(&mut self) -> Result<(), CellError> {
        let mut secrets = BTreeMap::new();
        for ((g, generation), row) in &self.store.groups {
            if self.store.chain_state.generation(*g) == Some(*generation) {
                let sk = open_group(&self.work.current, self.store.cell, *g, *generation, row)?;
                secrets.insert((*g, *generation), sk);
            }
        }
        self.work.secrets = secrets;
        Ok(())
    }

    /// Appends one key record through the engine.
    async fn record(&self, cmd: KeyCommand, id: [u8; 16]) -> Result<(), CellError> {
        let state = self.engine.state();
        let admitted = gate::admit_system(
            &state,
            Action::Command(CellCommand::Key(cmd)),
            SystemTask::ErasureRunner,
            id,
            state
                .now_floor()
                .max(Timestamp::from_micros(self.engine.now())),
        )
        .map_err(|_| keys_err("key record admission"))?;
        match self.engine.execute(admitted).await {
            Ok(_) => Ok(()),
            Err(EngineError::ShuttingDown | EngineError::Stopped) => {
                Err(keys_err("the engine is not running"))
            }
            Err(EngineError::Exec(_)) => Err(keys_err("key record refused")),
        }
    }

    /// Records a custody call before it is made (ADR-004).
    async fn record_call(&self, call: &str, epoch: u64) -> Result<(), CellError> {
        let request = request_id()?;
        let op = key_op_body(call, epoch, request)?;
        let mut suffix = [0u8; 8];
        for (d, s) in suffix.iter_mut().zip(request.iter()) {
            *d = *s;
        }
        self.record(KeyCommand::RecordKeyOp { op }, system_command_id(suffix))
            .await
    }

    async fn create_root(&self, epoch: u64) -> Result<RootRef, CellError> {
        self.record_call("create_root", epoch).await?;
        self.custody
            .create_root(RootLabel {
                cell: Some(fstp_custody::CellId(self.store.cell.0)),
                chain: Chain::App,
                epoch: Epoch(epoch),
            })
            .await
            .map_err(CellError::Custody)
    }

    async fn wrap(
        &self,
        root: &RootRef,
        s: &SealKey,
        epoch: u64,
    ) -> Result<WrappedSealKey, CellError> {
        self.record_call("wrap", epoch).await?;
        self.custody
            .wrap(root, s, &seal_aad(self.store.cell, epoch))
            .await
            .map_err(CellError::Custody)
    }

    async fn unwrap(&self, row: &RootRow, epoch: u64) -> Result<SealKey, CellError> {
        self.record_call("unwrap", epoch).await?;
        self.custody
            .unwrap(&row.root, &row.wrapped, &seal_aad(self.store.cell, epoch))
            .await
            .map_err(CellError::Custody)
    }

    /// Adds an empty text group at generation 1. Allowed while no batch
    /// runs or after its commit (`fstp_keys::erasure`).
    ///
    /// # Errors
    ///
    /// The planner's refusal, or a failed seal.
    pub fn add_group(&mut self, group: [u8; 16]) -> Result<(), CellError> {
        let g = GroupId(group);
        let mut chain = self.chain.clone();
        chain
            .add_group_for(g, Purpose::Text)
            .map_err(|_| keys_err("group admission"))?;
        let sk = hybrid_kem::generate().map_err(|_| keys_err("group key"))?;
        let epoch = self.store.chain_state.epoch().0;
        let row = seal_group(&self.work.current, self.store.cell, g, 1, epoch, &sk)?;
        self.store.groups.insert((g, 1), row);
        self.store
            .chain_state
            .add_group_for(g, Purpose::Text)
            .map_err(|_| keys_err("group admission"))?;
        self.chain = chain;
        self.work.secrets.insert((g, 1), sk);
        Ok(())
    }

    /// Stores `text` under a fresh data key in `group`, as text `id`
    /// (design section 5.6).
    ///
    /// # Errors
    ///
    /// An unknown group, a planner refusal, or a failed seal.
    pub fn put_text(
        &mut self,
        group: [u8; 16],
        id: [u8; 16],
        text: &[u8],
    ) -> Result<(), CellError> {
        let g = GroupId(group);
        let generation = self
            .store
            .chain_state
            .generation(g)
            .ok_or(keys_err("unknown group"))?;
        let sk = self
            .work
            .secrets
            .get(&(g, generation))
            .ok_or(keys_err("group secret not open"))?;
        let dek = DekId(id);
        let mut chain = self.chain.clone();
        chain.admit(g, dek).map_err(|_| keys_err("key admission"))?;
        let data_key = DataKey::generate().map_err(|_| keys_err("data key"))?;
        let ctx = ctx_for(self.store.cell, g, generation, id);
        let blob = envelope::seal_blob(&data_key, &ctx, text).map_err(|_| keys_err("text seal"))?;
        let sealed = envelope::seal_key(sk.public(), &data_key, &ctx)
            .map_err(|_| keys_err("data key seal"))?;
        self.store
            .chain_state
            .admit(g, dek)
            .map_err(|_| keys_err("key admission"))?;
        self.chain = chain;
        self.store.keys.insert(dek, (g, generation, sealed));
        self.store.texts.insert(id, TextRow { dek, blob });
        Ok(())
    }

    /// Opens text `id` for `state`, or refuses it (design section 3.4).
    ///
    /// # Errors
    ///
    /// [`OpenRefusal::Erased`] from the moment its erasure request is in
    /// the ledger, before the planner runs.
    pub fn open_text(
        &self,
        state: &CellState,
        id: [u8; 16],
    ) -> Result<impl std::ops::Deref<Target = Vec<u8>> + use<C>, OpenRefusal> {
        if state.erasure(id).is_some()
            || state.text(id) == Some(fstp_cell_core::state::TextStatus::Erased)
        {
            return Err(OpenRefusal::Erased);
        }
        let row = self.store.texts.get(&id).ok_or(OpenRefusal::Unknown)?;
        if self.chain.refused_for_open(row.dek) {
            return Err(OpenRefusal::Erased);
        }
        let (g, generation, sealed) = self.store.keys.get(&row.dek).ok_or(OpenRefusal::Unknown)?;
        let sk = self
            .work
            .secrets
            .get(&(*g, *generation))
            .ok_or(OpenRefusal::Keys)?;
        let ctx = ctx_for(self.store.cell, *g, *generation, id);
        let dk = envelope::open_key(sk, sealed, &ctx).map_err(|_| OpenRefusal::Keys)?;
        envelope::open_blob(&dk, &ctx, &row.blob).map_err(|_| OpenRefusal::Keys)
    }

    /// Whether the runner has work: a request not yet joined, or a batch
    /// in flight.
    pub fn busy(&self) -> Result<bool, CellError> {
        Ok(!self.new_requests().is_empty()
            || plan::next(&self.chain)
                .map_err(|_| keys_err("planner"))?
                .is_some())
    }

    fn new_requests(&self) -> Vec<[u8; 16]> {
        let state = self.engine.state();
        self.store
            .texts
            .keys()
            .copied()
            .filter(|id| !self.store.requested.contains(id) && state.erasure(*id).is_some())
            .collect()
    }

    /// Runs steps until the chain is idle.
    ///
    /// # Errors
    ///
    /// The first failing step. The runner keeps its state, so a later
    /// call retries that step.
    pub async fn run_until_idle(&mut self) -> Result<(), CellError> {
        while self.step().await?.is_some() {}
        Ok(())
    }

    /// Does the work of one event and gives it, or `None` when idle.
    ///
    /// # Errors
    ///
    /// The step's failure. Nothing is half applied: a retry does the same
    /// step again.
    pub async fn step(&mut self) -> Result<Option<ErasureEvent>, CellError> {
        let fresh = self.new_requests();
        if !fresh.is_empty() {
            let seq = self.engine.state().head().raw();
            let mut durable = self.store.chain_state.clone();
            let mut chain = self.chain.clone();
            for id in &fresh {
                let dek = self
                    .store
                    .texts
                    .get(id)
                    .map(|t| t.dek)
                    .ok_or(keys_err("unknown text"))?;
                durable
                    .request(dek, seq)
                    .map_err(|_| keys_err("erasure request"))?;
                chain
                    .request(dek, seq)
                    .map_err(|_| keys_err("erasure request"))?;
            }
            self.store.chain_state = durable;
            self.chain = chain;
            self.store.requested.extend(fresh);
            return Ok(Some(self.emit(ErasureEvent::RequestRecorded)));
        }
        let Some(next) = plan::next(&self.chain).map_err(|_| keys_err("planner"))? else {
            return Ok(None);
        };
        let event = match next {
            Step::NewGroups { .. } | Step::Reseal { .. } => self.rotate()?,
            Step::NewEpoch(e) => self.new_epoch(e).await?,
            Step::RewrapGroups(e) => self.rewrap(e)?,
            Step::Commit(e) => self.commit(e)?,
            Step::Snapshot(e) => self.snapshot(e)?,
            Step::VerifySnapshot(e) => self.verify_snapshot(e).await?,
            Step::DestroyRoot(e) => self.destroy(e).await?,
            Step::Complete { epoch, .. } => self.complete(epoch).await?,
        };
        Ok(Some(self.emit(event)))
    }

    fn emit(&mut self, e: ErasureEvent) -> ErasureEvent {
        self.events.push(e);
        e
    }

    fn apply(&mut self, done: &Step) -> Result<(), CellError> {
        plan::apply(&mut self.chain, done).map_err(|_| keys_err("planner step"))
    }

    /// Step 2: every `NewGroups` and `Reseal` step of the batch.
    fn rotate(&mut self) -> Result<ErasureEvent, CellError> {
        let mut chain = self.chain.clone();
        let mut new_groups = BTreeMap::new();
        let mut resealed = BTreeMap::new();
        while let Some(step) = plan::next(&chain).map_err(|_| keys_err("planner"))? {
            match &step {
                Step::NewGroups { groups } => {
                    for g in groups {
                        let generation = chain
                            .generation(*g)
                            .and_then(|n| n.checked_add(1))
                            .ok_or(keys_err("generation"))?;
                        let sk = hybrid_kem::generate().map_err(|_| keys_err("group key"))?;
                        new_groups.insert((*g, generation), sk);
                    }
                }
                Step::Reseal { group, keep } => {
                    let old = chain.generation(*group).ok_or(keys_err("generation"))?;
                    let new = old.checked_add(1).ok_or(keys_err("generation"))?;
                    let old_sk = self
                        .work
                        .secrets
                        .get(&(*group, old))
                        .ok_or(keys_err("group secret not open"))?;
                    let new_sk = new_groups
                        .get(&(*group, new))
                        .ok_or(keys_err("new generation missing"))?;
                    for dek in keep {
                        let (_, _, sealed) = self
                            .store
                            .keys
                            .get(dek)
                            .ok_or(keys_err("unknown data key"))?;
                        let dk = envelope::open_key(
                            old_sk,
                            sealed,
                            &ctx_for(self.store.cell, *group, old, dek.0),
                        )
                        .map_err(|_| keys_err("data key open"))?;
                        let again = envelope::seal_key(
                            new_sk.public(),
                            &dk,
                            &ctx_for(self.store.cell, *group, new, dek.0),
                        )
                        .map_err(|_| keys_err("data key seal"))?;
                        resealed.insert(*dek, (*group, new, again));
                    }
                }
                _ => break,
            }
            plan::apply(&mut chain, &step).map_err(|_| keys_err("planner step"))?;
        }
        self.chain = chain;
        self.work.new_groups = new_groups;
        self.work.resealed = resealed;
        Ok(ErasureEvent::GroupsRotated)
    }

    /// Step 3, first half and second half: create `R(e)` once, then wrap
    /// a fresh `S(e)` under it.
    async fn new_epoch(&mut self, e: Epoch) -> Result<ErasureEvent, CellError> {
        if self.work.new_root.is_none() {
            let row = match self.store.pending_root.clone() {
                // A root created before a restart is reused, so no root
                // is left orphaned in custody.
                Some(row) if row.root.epoch == e => row,
                _ => {
                    let root = self.create_root(e.0).await?;
                    let row = RootRow {
                        root,
                        wrapped: WrappedSealKey(Vec::new()),
                    };
                    self.store.pending_root = Some(row.clone());
                    self.work.new_root = Some(row);
                    return Ok(ErasureEvent::RootCreated { epoch: e.0 });
                }
            };
            self.work.new_root = Some(row);
        }
        let root = self
            .work
            .new_root
            .as_ref()
            .map(|r| r.root.clone())
            .ok_or(keys_err("new root"))?;
        let s = SealKey::generate().map_err(CellError::Custody)?;
        let wrapped = self.wrap(&root, &s, e.0).await?;
        self.work.new_root = Some(RootRow { root, wrapped });
        self.work.new_seal = Some(s);
        self.apply(&Step::NewEpoch(e))?;
        Ok(ErasureEvent::SealKeyWrapped { epoch: e.0 })
    }

    /// Step 3, the reseal of every live group secret under `S(e)`.
    fn rewrap(&mut self, e: Epoch) -> Result<ErasureEvent, CellError> {
        let s = self
            .work
            .new_seal
            .as_ref()
            .ok_or(keys_err("new seal key"))?;
        let mut rows = BTreeMap::new();
        for ((g, generation), sk) in &self.work.secrets {
            let replaced = self.work.new_groups.keys().any(|(ng, _)| ng == g);
            if !replaced {
                rows.insert(
                    (*g, *generation),
                    seal_group(s, self.store.cell, *g, *generation, e.0, sk)?,
                );
            }
        }
        for ((g, generation), sk) in &self.work.new_groups {
            rows.insert(
                (*g, *generation),
                seal_group(s, self.store.cell, *g, *generation, e.0, sk)?,
            );
        }
        self.work.rows = rows;
        self.apply(&Step::RewrapGroups(e))?;
        Ok(ErasureEvent::GroupsResealed { epoch: e.0 })
    }

    /// Step 4: commits the new rows and the chain state at once.
    fn commit(&mut self, e: Epoch) -> Result<ErasureEvent, CellError> {
        let root = self.work.new_root.clone().ok_or(keys_err("new root"))?;
        let seal = self.work.new_seal.take().ok_or(keys_err("new seal key"))?;
        let mut chain = self.chain.clone();
        plan::apply(&mut chain, &Step::Commit(e)).map_err(|_| keys_err("planner step"))?;
        let mut store = self.store.clone();
        store.roots.insert(e.0, root);
        for (k, row) in std::mem::take(&mut self.work.rows) {
            store.groups.insert(k, row);
        }
        for (dek, v) in std::mem::take(&mut self.work.resealed) {
            store.keys.insert(dek, v);
        }
        for dek in chain.running_batch() {
            store.keys.remove(&dek);
        }
        store.pending_root = None;
        store.chain_state = chain.clone();
        self.store = store;
        self.chain = chain;
        let old = std::mem::replace(&mut self.work.current, seal);
        drop(old);
        let mut secrets = std::mem::take(&mut self.work.secrets);
        for (k, sk) in std::mem::take(&mut self.work.new_groups) {
            secrets.retain(|(g, _), _| *g != k.0);
            secrets.insert(k, sk);
        }
        self.work.secrets = secrets;
        self.work.new_root = None;
        Ok(ErasureEvent::Committed { epoch: e.0 })
    }

    /// Step 5: a snapshot of the committed keystore.
    fn snapshot(&mut self, e: Epoch) -> Result<ErasureEvent, CellError> {
        self.work.snapshot = Some(self.store.clone());
        self.apply_durable(&Step::Snapshot(e))?;
        Ok(ErasureEvent::SnapshotTaken { epoch: e.0 })
    }

    /// Step 5: a scratch restore of the snapshot opens a sample of live
    /// keys under `R(e)`.
    async fn verify_snapshot(&mut self, e: Epoch) -> Result<ErasureEvent, CellError> {
        let snap = match self.work.snapshot.clone() {
            Some(s) => s,
            None => self.store.clone(),
        };
        let row = snap
            .roots
            .get(&e.0)
            .cloned()
            .ok_or(keys_err("snapshot root"))?;
        let s = self.unwrap(&row, e.0).await?;
        for (dek, (g, generation, sealed)) in snap.keys.iter().take(1) {
            let grow = snap
                .groups
                .get(&(*g, *generation))
                .ok_or(keys_err("snapshot group"))?;
            let sk = open_group(&s, snap.cell, *g, *generation, grow)?;
            envelope::open_key(&sk, sealed, &ctx_for(snap.cell, *g, *generation, dek.0))
                .map_err(|_| keys_err("snapshot sample"))?;
        }
        self.apply_durable(&Step::VerifySnapshot(e))?;
        Ok(ErasureEvent::SnapshotVerified { epoch: e.0 })
    }

    /// Step 6: destroys `R(e)` and keeps the digest of its receipt.
    async fn destroy(&mut self, e: Epoch) -> Result<ErasureEvent, CellError> {
        let row = self
            .store
            .roots
            .get(&e.0)
            .cloned()
            .ok_or(keys_err("old root"))?;
        self.record_call("destroy", e.0).await?;
        let receipt = self
            .custody
            .destroy(&row.root)
            .await
            .map_err(CellError::Custody)?;
        let digest = fstp_crypto::sha256(&receipt.0);
        let mut chain = self.chain.clone();
        plan::apply_destroy(&mut chain, e, digest).map_err(|_| keys_err("planner step"))?;
        self.store.receipts.insert(e.0, digest);
        self.store.chain_state = chain.clone();
        self.chain = chain;
        self.work.snapshot = None;
        Ok(ErasureEvent::RootDestroyed { epoch: e.0 })
    }

    /// Step 7: appends `KeyEpochDestroyed` of the old epoch.
    async fn complete(&mut self, new: Epoch) -> Result<ErasureEvent, CellError> {
        let old = new.0.checked_sub(1).ok_or(keys_err("epoch"))?;
        let receipt = *self.store.receipts.get(&old).ok_or(keys_err("receipt"))?;
        let mut suffix = *b"epoch\0\0\0";
        let tail = u32::try_from(old)
            .map_err(|_| keys_err("epoch"))?
            .to_be_bytes();
        for (d, s) in suffix.iter_mut().skip(4).zip(tail.iter()) {
            *d = *s;
        }
        self.record(
            KeyCommand::RecordEpochDestroyed {
                epoch: old,
                receipt,
            },
            system_command_id(suffix),
        )
        .await?;
        let step = plan::next(&self.chain)
            .map_err(|_| keys_err("planner"))?
            .ok_or(keys_err("planner"))?;
        if let Step::Complete { erased, .. } = &step {
            self.erased.extend(erased.iter().map(|d| d.0));
        }
        self.apply_durable(&step)?;
        Ok(ErasureEvent::CompletionRecorded { epoch: old })
    }

    fn apply_durable(&mut self, step: &Step) -> Result<(), CellError> {
        let mut chain = self.chain.clone();
        plan::apply(&mut chain, step).map_err(|_| keys_err("planner step"))?;
        self.store.chain_state = chain.clone();
        self.chain = chain;
        Ok(())
    }
}

impl Work {
    fn new(current: SealKey) -> Work {
        Work {
            current,
            secrets: BTreeMap::new(),
            new_groups: BTreeMap::new(),
            resealed: BTreeMap::new(),
            new_root: None,
            new_seal: None,
            rows: BTreeMap::new(),
            snapshot: None,
        }
    }
}

// ---------------------------------------------------------------------------
// The erasure task of a started cell.
// ---------------------------------------------------------------------------

/// How long the erasure task waits for new work when it is idle, and
/// before it retries a step that failed. Interim reading of lane W3a:
/// design section 3.5 has an erasure complete in seconds, with no batch
/// waiting for a timer, so the wait is short.
pub const ERASURE_TICK: Duration = Duration::from_millis(200);

/// The bound of the request channel of the erasure task.
pub const ERASURE_QUEUE: usize = 64;

/// An open text, wiped on drop.
pub type Plaintext = Box<dyn std::ops::Deref<Target = Vec<u8>> + Send>;

/// A request to the erasure task.
enum Request {
    AddGroup {
        group: [u8; 16],
        reply: ReplyTx<Result<(), CellError>>,
    },
    PutText {
        group: [u8; 16],
        id: [u8; 16],
        text: Vec<u8>,
        reply: ReplyTx<Result<(), CellError>>,
    },
    OpenText {
        id: [u8; 16],
        reply: ReplyTx<Result<Plaintext, OpenRefusal>>,
    },
    Keystore {
        reply: ReplyTx<Keystore>,
    },
}

impl Request {
    /// Answers a request the task can no longer serve.
    fn refuse(self) {
        let gone = keys_err("the erasure task is not running");
        match self {
            Request::AddGroup { reply, .. } | Request::PutText { reply, .. } => {
                reply.send(Err(gone));
            }
            Request::OpenText { reply, .. } => reply.send(Err(OpenRefusal::Keys)),
            // Dropping the slot answers `None`.
            Request::Keystore { reply } => drop(reply),
        }
    }
}

#[derive(Debug, Default)]
struct Progress {
    events: Vec<ErasureEvent>,
    erased: Vec<[u8; 16]>,
}

/// A handle on the erasure task of a started cell (design section 3.5).
/// The task owns the runner, and with it the keys of the chain. A route
/// reaches the texts only through this handle, and the task serves each
/// request between two steps of a batch. Cloning gives another handle on
/// the same task.
#[derive(Clone)]
pub struct ErasureHandle {
    tx: Sender<Request>,
    progress: Arc<Mutex<Progress>>,
}

impl std::fmt::Debug for ErasureHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ErasureHandle").finish_non_exhaustive()
    }
}

impl ErasureHandle {
    fn progress(&self) -> MutexGuard<'_, Progress> {
        self.progress.lock().unwrap_or_else(PoisonError::into_inner)
    }

    async fn ask<T>(&self, make: impl FnOnce(ReplyTx<T>) -> Request) -> Option<T> {
        let (reply, rx) = chan::reply();
        if let Err(req) = self.tx.send(make(reply)).await {
            req.refuse();
            return None;
        }
        rx.recv().await
    }

    /// Adds an empty text group ([`ErasureRunner::add_group`]).
    ///
    /// # Errors
    ///
    /// The runner's refusal, or [`CellError::Keys`] once the task ended.
    pub async fn add_group(&self, group: [u8; 16]) -> Result<(), CellError> {
        self.ask(|reply| Request::AddGroup { group, reply })
            .await
            .unwrap_or(Err(keys_err("the erasure task is not running")))
    }

    /// Stores `text` as text `id` in `group` ([`ErasureRunner::put_text`]).
    ///
    /// # Errors
    ///
    /// The runner's refusal, or [`CellError::Keys`] once the task ended.
    pub async fn put_text(
        &self,
        group: [u8; 16],
        id: [u8; 16],
        text: Vec<u8>,
    ) -> Result<(), CellError> {
        self.ask(|reply| Request::PutText {
            group,
            id,
            text,
            reply,
        })
        .await
        .unwrap_or(Err(keys_err("the erasure task is not running")))
    }

    /// Opens text `id` against the engine's current state
    /// ([`ErasureRunner::open_text`]).
    ///
    /// # Errors
    ///
    /// The runner's [`OpenRefusal`], or [`OpenRefusal::Keys`] once the
    /// task ended.
    pub async fn open_text(&self, id: [u8; 16]) -> Result<Plaintext, OpenRefusal> {
        self.ask(|reply| Request::OpenText { id, reply })
            .await
            .unwrap_or(Err(OpenRefusal::Keys))
    }

    /// A copy of the durable keystore, or `None` once the task ended.
    pub async fn keystore(&self) -> Option<Keystore> {
        self.ask(|reply| Request::Keystore { reply }).await
    }

    /// Every event of the task so far, in order.
    pub fn events(&self) -> Vec<ErasureEvent> {
        self.progress().events.clone()
    }

    /// The texts whose erasure the task completed, in order.
    pub fn erased(&self) -> Vec<[u8; 16]> {
        self.progress().erased.clone()
    }
}

/// What woke the erasure task.
enum Wake {
    Request(Option<Request>),
    Stop,
    Tick,
}

/// The erasure task over `runner`: a handle on it, and the future to
/// spawn. The task runs each erasure batch to its end as soon as its
/// request is in the ledger, one step at a time, and serves the handle's
/// requests between steps. It stops between two steps once `stop` is
/// triggered. Every step is crash safe, so a batch resumes at the next
/// start (design section 3.5). The future holds `stop`, so the task is a
/// participant of the drain (ADR-002).
pub fn task<C: Custody + Send + Sync + 'static, K: Clock>(
    runner: ErasureRunner<C>,
    clock: K,
    stop: ShutdownSignal,
) -> (ErasureHandle, impl Future<Output = ()> + Send) {
    let (tx, rx) = chan::channel(ERASURE_QUEUE);
    let progress = Arc::new(Mutex::new(Progress::default()));
    let handle = ErasureHandle {
        tx,
        progress: Arc::clone(&progress),
    };
    (handle, run_task(runner, rx, clock, stop, progress))
}

async fn run_task<C: Custody + Send + Sync + 'static, K: Clock>(
    mut runner: ErasureRunner<C>,
    mut rx: Receiver<Request>,
    clock: K,
    stop: ShutdownSignal,
    progress: Arc<Mutex<Progress>>,
) {
    let tick = i64::try_from(ERASURE_TICK.as_micros()).unwrap_or(i64::MAX);
    let mut closed = false;
    let mut cooling = false;
    loop {
        if stop.is_triggered() {
            break;
        }
        let work = !cooling && matches!(runner.busy(), Ok(true));
        let woke = if work {
            if closed {
                Wake::Tick
            } else {
                // Serve a request already queued, then do the next step.
                match race(rx.recv(), yield_now()).await {
                    Either::Left(r) => Wake::Request(r),
                    Either::Right(()) => Wake::Tick,
                }
            }
        } else {
            let until = clock.now().saturating_add(tick);
            if closed {
                match race(stop.notified(), clock.sleep_until(until)).await {
                    Either::Left(()) => Wake::Stop,
                    Either::Right(()) => Wake::Tick,
                }
            } else {
                match race(rx.recv(), race(stop.notified(), clock.sleep_until(until))).await {
                    Either::Left(r) => Wake::Request(r),
                    Either::Right(Either::Left(())) => Wake::Stop,
                    Either::Right(Either::Right(())) => Wake::Tick,
                }
            }
        };
        match woke {
            Wake::Stop => break,
            Wake::Request(None) => closed = true,
            Wake::Request(Some(req)) => serve(&mut runner, req),
            Wake::Tick if work => {
                // A failed step keeps the runner's state, so it is
                // retried after one tick (`ErasureRunner::step`).
                cooling = runner.step().await.is_err();
            }
            Wake::Tick => cooling = false,
        }
        publish(&runner, &progress);
    }
    rx.close();
    for req in rx.drain() {
        req.refuse();
    }
    publish(&runner, &progress);
    drop(stop);
}

fn serve<C: Custody>(runner: &mut ErasureRunner<C>, req: Request) {
    match req {
        Request::AddGroup { group, reply } => reply.send(runner.add_group(group)),
        Request::PutText {
            group,
            id,
            text,
            reply,
        } => reply.send(runner.put_text(group, id, &text)),
        Request::OpenText { id, reply } => {
            let state = runner.engine.state();
            let opened = runner
                .open_text(&state, id)
                .map(|t| Box::new(t) as Plaintext);
            reply.send(opened);
        }
        Request::Keystore { reply } => reply.send(runner.keystore().clone()),
    }
}

fn publish<C>(runner: &ErasureRunner<C>, progress: &Mutex<Progress>) {
    let mut p = progress.lock().unwrap_or_else(PoisonError::into_inner);
    if p.events.len() != runner.events.len() {
        p.events.clone_from(&runner.events);
    }
    if p.erased.len() != runner.erased.len() {
        p.erased.clone_from(&runner.erased);
    }
}
