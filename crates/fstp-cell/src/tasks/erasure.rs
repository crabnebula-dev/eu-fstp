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
//! whose record cannot be appended is never made. The call then carries
//! the same request id to custody (`fstp_custody::with_request`), so the
//! backend usage log names it. The body is `fstp_keys::keyop`, and
//! [`key_op_of_body`] reads it back.
//!
//! The start-up `unwrap` of `S(e)` is the one exception: its request id
//! is kept in the keystore before the call ([`Keystore::unwrap_current`]),
//! and [`ErasureRunner::from_open`] writes its record with that id once
//! the engine runs.
//!
//! # Durability
//!
//! [`Keystore`] holds what survives a crash: the rows, the chain state at
//! its last durable point and the reference of a root created for a batch
//! not yet committed. Since lane L3 (ADR-004, decided by Daniel on
//! 2026-11-20) it writes through to the keystore tables ([`tables`]), and
//! a start loads it from them. Steps 2 and 3 live in process
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

use fstp_api_core::port::{DisplayNameSet, ErasureCause};
use fstp_cell_core::gate::{self, Action};
use fstp_cell_core::{CellCommand, CellState, KeyCommand, SystemTask, system_command_id};
use fstp_crypto::aead;
use fstp_crypto::composite::{self, CompositeSigningKey};
use fstp_crypto::hybrid_kem::{self, HybridSecretKey};
use fstp_custody::{
    Aad, Custody, RequestId, RootLabel, RootRef, SealKey, WrappedSealKey, with_request,
};
use fstp_domain::time::Timestamp;
use fstp_keys::envelope::{self, DataKey, SealContext, SealedBlob, SealedKey};
use fstp_keys::erasure::{self as plan, ChainState, Step};
use fstp_keys::keyop::{self, KeyCall, KeyOp};
use fstp_keys::{CellId, Chain, DekId, Epoch, GroupId, ObjectId, Purpose};
use fstp_rt::ShutdownSignal;
use fstp_rt::future::{Either, race, yield_now};

pub mod restore;
pub mod rows_image;
pub mod snapshot;
pub mod tables;

pub use tables::{KeystoreSink, NoSink, SinkFuture};

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

/// One stored text: its data key, the group generation its body was
/// sealed under, and its sealed body. The body's seal context keeps that
/// generation after the data key is resealed to a later one (design
/// section 3.5 step 2), so a live sibling of an erased text still opens.
#[derive(Clone)]
struct TextRow {
    dek: DekId,
    generation: u32,
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
    /// The group public key, as `keystore.group_key` holds it. Empty in
    /// a row read from a keystore image, which holds none.
    public: Vec<u8>,
}

/// A composite level 2 signing key of one purpose, sealed under the seal
/// key of `epoch` (ADR-004 "Signing keys", M9 decision CD4).
#[derive(Clone)]
struct SignerRow {
    /// The generation: 1 at creation, one more at each rotation.
    generation: u32,
    epoch: u64,
    nonce: [u8; aead::NONCE_LEN],
    body: Vec<u8>,
    /// The composite public key, `mldsaPK || tradPK`.
    public: Vec<u8>,
    /// When the generation was created, in microseconds since the epoch.
    created_us: i64,
}

/// The purposes whose composite level 2 key the keystore creates and
/// rotates. The `Anchor` key is still handed in by the caller
/// (`crate::process::CellKeys`), so it is not here.
pub const SIGNER_PURPOSES: [Purpose; 1] = [Purpose::NoticeCompanion];

/// How long one generation of a level 2 signing key serves before it is
/// due for replacement: 365 days, the yearly rotation of ADR-004.
pub const SIGNER_LIFETIME_US: i64 = 365 * 24 * 60 * 60 * 1_000_000;

/// The AAD label of a level 2 signing key sealed under a seal key.
pub const SIGNER_AAD: &[u8] = b"fstp-level2-signer-v1";

/// The HKDF label of the HMAC key of a keyed digest group (design
/// sections 3.1 and 3.5, G24). The info is this label and the purpose
/// code.
///
/// Interim reading of lane m3/login-m2http, pending Daniel: the runner
/// holds every level 2 group as a hybrid group secret, sealed under the
/// seal key and replaced by a new generation in each batch that affects
/// it. So the `Lookup` group is such a group, and its HMAC key is derived
/// from its secret. A batch that erases a login email then replaces the
/// key with the group (design section 3.5, decision 27), and the old key
/// dies with the old root.
pub const KEYED_DIGEST_LABEL: &[u8] = b"fstp-keyed-digest-v1";

/// The normalised form of a login email that the keyed index digests:
/// ASCII lower case, as the in-memory backend reads it. Interim, pending
/// Daniel (Q22): the design names a normalised address but no rule.
pub fn normalise_email(email: &str) -> String {
    email.to_ascii_lowercase()
}

/// The keyed login email index (design section 4.2, Q22): the account of
/// each live login email by `HMAC-SHA-256(Lookup, normalised address)`,
/// and the text that holds each address, sealed like every text.
///
/// Since lane L3 the index lives in `keystore.login_digest` and
/// `keystore.login_text`, written with the rest of the keystore.
#[derive(Clone, Default)]
struct LoginIndex {
    /// The keyed digest group of purpose `Lookup`, once a login email
    /// exists. Its subjects are the data keys of the login email texts.
    lookup: Option<GroupId>,
    /// The text group that new login emails join.
    group: Option<GroupId>,
    /// The text of each account's login email.
    texts: BTreeMap<u128, [u8; 16]>,
    /// The account of each keyed digest.
    digests: BTreeMap<[u8; 32], u128>,
}

/// One account's display name in the index (SA-11 amendment, ADR-004
/// section "Written by lane L26"): the text that holds it and its keyed
/// fingerprint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DisplayRow {
    text: [u8; 16],
    fingerprint: [u8; 32],
}

/// The display name index (SA-11 amendment, lane L26): each account's
/// name text and fingerprint, and the account of each fingerprint. The
/// fingerprint key is derived from the `Lookup` key ([`display_key`]), and
/// each name's text is a subject of the `Lookup` group, so a batch that
/// erases a name replaces the key and recomputes every live fingerprint.
/// It lives in `keystore.display_name`, written with the rest of the
/// keystore.
#[derive(Clone, Default)]
struct DisplayIndex {
    names: BTreeMap<u128, DisplayRow>,
    owners: BTreeMap<[u8; 32], u128>,
}

impl DisplayIndex {
    /// The index of `names`, with its owners derived from them.
    fn of(names: BTreeMap<u128, DisplayRow>) -> DisplayIndex {
        let owners = names.iter().map(|(a, r)| (r.fingerprint, *a)).collect();
        DisplayIndex { names, owners }
    }
}

/// The display name fingerprint key of the `Lookup` key `lookup`:
/// HKDF-SHA256 with an empty salt and
/// `fstp_api_core::display_name::FINGERPRINT_KEY_LABEL` (ADR-004 "Chains",
/// decided by Daniel on 2026-11-21), as
/// `fstp_api_core::display_name::fingerprint_key` derives it. The key is
/// derived straight into its heap allocation, so no copy of it is left on
/// the stack (I-80).
pub fn display_key(lookup: &SealKey) -> Result<SealKey, CellError> {
    let mut out = fstp_custody::zeroed_key_box();
    fstp_crypto::kdf::hkdf_sha256(
        &[],
        lookup.expose(),
        fstp_api_core::display_name::FINGERPRINT_KEY_LABEL,
        &mut out[..],
    )
    .map_err(|_| keys_err("display name key"))?;
    Ok(SealKey::from_box(out))
}

/// What [`ErasureRunner::set_login_email`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoginEmailSet {
    /// The address is now the account's login email.
    Set,
    /// The address is the login email of another account already.
    Taken,
}

/// The HMAC key of the keyed digest group whose secret is `sk`.
fn digest_key(sk: &HybridSecretKey, purpose: Purpose) -> Result<SealKey, CellError> {
    let mut info = KEYED_DIGEST_LABEL.to_vec();
    info.push(purpose.code());
    // The key is derived straight into its heap allocation, so no copy
    // of it is left on the stack (I-80).
    let mut out = fstp_custody::zeroed_key_box();
    fstp_crypto::kdf::hkdf_sha256(&[], &sk.to_bytes()[..], &info, &mut out[..])
        .map_err(|_| keys_err("keyed digest key"))?;
    Ok(SealKey::from_box(out))
}

/// The keyed digest of the normalised `address` under `key`.
fn keyed_digest(key: &SealKey, address: &[u8]) -> [u8; 32] {
    fstp_crypto::hmac_sha256(key.expose(), address)
}

/// The erasure log of the cell (ADR-007 section "Built by lane L33"): every
/// entry of the ledger's state, oldest request first, then by text id. A
/// ledger text's entry comes from `EraseTexts`, a keystore text's from
/// `KeystoreErasureRequested`, and the destroyed epoch of either from
/// `ErasuresCompleted`.
pub fn erasure_log(state: &CellState) -> Vec<([u8; 16], fstp_cell_core::state::ErasureEntry)> {
    let mut out: Vec<_> = state.erasures().collect();
    out.sort_by_key(|(id, e)| (e.requested_at, *id));
    out
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
    /// The current composite signing key of each purpose of
    /// [`SIGNER_PURPOSES`] the cell created.
    signers: BTreeMap<Purpose, SignerRow>,
    /// The public keys of replaced generations, kept so earlier
    /// signatures stay verifiable.
    retired: BTreeMap<(Purpose, u32), Vec<u8>>,
    /// A root created for the batch in flight, before its commit.
    pending_root: Option<RootRow>,
    /// Requests already joined, by text.
    requested: BTreeSet<[u8; 16]>,
    /// The keyed login email index.
    logins: LoginIndex,
    /// The display name index (SA-11 amendment, lane L26).
    displays: DisplayIndex,
    /// The request id of the start-up `unwrap` of `S(e)`, kept before
    /// the call until its deferred `RecordKeyOp` is written (ADR-004
    /// "Reconciliation", the start-up exception).
    startup_unwrap: Option<RequestId>,
    /// The write-through to the keystore tables ([`tables`], lane L3).
    persist: tables::Persist,
    /// The keystore snapshot writer the runner of this keystore takes,
    /// with the directory of its status file (ADR-012 records of lanes
    /// L17 and L27). It holds no key row.
    snapshots: Option<(fstp_backup::Snapshots, Option<std::path::PathBuf>)>,
}

impl std::fmt::Debug for Keystore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keystore")
            .field("epoch", &self.epoch())
            .field("roots", &self.roots.keys().collect::<Vec<_>>())
            .field("texts", &self.texts.len())
            .finish_non_exhaustive()
    }
}

impl Keystore {
    /// Hands `snapshots` to the runner that opens this keystore at start,
    /// with the directory of the snapshot status file (ADR-012 records of
    /// lanes L17 and L27).
    #[must_use]
    pub fn with_snapshots(
        mut self,
        snapshots: fstp_backup::Snapshots,
        status_dir: Option<std::path::PathBuf>,
    ) -> Keystore {
        self.snapshots = Some((snapshots, status_dir));
        self
    }

    /// The current root epoch.
    pub fn epoch(&self) -> u64 {
        // A loaded keystore names its epoch beside its sealed chain state
        // until the state opens (`tables`).
        match (&self.persist.sealed, self.persist.closed) {
            (Some((e, _)), true) => *e,
            _ => self.chain_state.epoch().0,
        }
    }

    /// The custody receipt digest of each destroyed epoch.
    pub fn receipts(&self) -> &BTreeMap<u64, [u8; 32]> {
        &self.receipts
    }

    /// The keyed digests of the login email index, in order. They are
    /// what an index table row would hold (design section 4.2).
    pub fn login_digests(&self) -> Vec<[u8; 32]> {
        self.logins.digests.keys().copied().collect()
    }

    /// The text that holds the login email of `account`, if any. An
    /// account erasure names it in its `EraseTexts` (ADR-007).
    pub fn login_text(&self, account: fstp_domain::id::AccountId) -> Option<[u8; 16]> {
        self.logins.texts.get(&account.raw()).copied()
    }

    /// The text that holds the display name of `account`, if any (SA-11,
    /// lane L26). An account erasure names it in its `EraseTexts`
    /// (ADR-007).
    pub fn display_text(&self, account: fstp_domain::id::AccountId) -> Option<[u8; 16]> {
        self.displays.names.get(&account.raw()).map(|r| r.text)
    }

    /// The keyed fingerprint of the display name of `account`, if any
    /// (SA-11 amendment, lane L26).
    pub fn display_fingerprint(&self, account: fstp_domain::id::AccountId) -> Option<[u8; 32]> {
        self.displays
            .names
            .get(&account.raw())
            .map(|r| r.fingerprint)
    }

    /// Every display name fingerprint, in order: what
    /// `keystore.display_name` holds (SA-11 amendment, lane L26).
    pub fn display_fingerprints(&self) -> Vec<[u8; 32]> {
        self.displays.owners.keys().copied().collect()
    }

    /// The epochs whose root this keystore still references.
    pub fn live_roots(&self) -> Vec<u64> {
        self.roots
            .keys()
            .copied()
            .filter(|e| !self.receipts.contains_key(e))
            .collect()
    }

    /// Every public key of the signing key of `purpose`, by generation,
    /// the current one last. Empty when the cell created none.
    pub fn signer_public_keys(&self, purpose: Purpose) -> Vec<(u32, Vec<u8>)> {
        let mut out: Vec<(u32, Vec<u8>)> = self
            .retired
            .iter()
            .filter(|((p, _), _)| *p == purpose)
            .map(|((_, g), k)| (*g, k.clone()))
            .collect();
        if let Some(row) = self.signers.get(&purpose) {
            out.push((row.generation, row.public.clone()));
        }
        out
    }

    /// Whether the current signing key of `purpose` has served
    /// [`SIGNER_LIFETIME_US`] at `now_us` and is due for rotation. A
    /// purpose with no key is not due.
    pub fn signer_due(&self, purpose: Purpose, now_us: i64) -> bool {
        self.signers
            .get(&purpose)
            .is_some_and(|r| now_us.saturating_sub(r.created_us) >= SIGNER_LIFETIME_US)
    }

    /// Start-up, first half (design section 3.4): unwraps the current
    /// `S(e)` through custody. The chain cannot be written before `S(e)`
    /// is open, so its `RecordKeyOp` follows once the engine runs
    /// ([`ErasureRunner::from_open`], ADR-004 "Reconciliation"). The
    /// call's request id is kept in the keystore before the call, as the
    /// operational row of the start-up exception, and the deferred record
    /// carries the same id.
    ///
    /// # Errors
    ///
    /// [`CellError::Custody`] when custody refuses or cannot be reached.
    pub async fn unwrap_current<C: Custody>(&mut self, custody: &C) -> Result<SealKey, CellError> {
        let epoch = self.epoch();
        let request = request_id()?;
        self.startup_unwrap = Some(request);
        // The request id is durable before the call (ADR-004
        // "Reconciliation"). A keystore in memory only writes nothing.
        self.persist.dirty.meta = true;
        self.flush(None).await?;
        let row = self
            .roots
            .get(&epoch)
            .ok_or(keys_err("no root of the current epoch"))?;
        let aad = seal_aad(self.cell, epoch);
        with_request(request, || custody.unwrap(&row.root, &row.wrapped, &aad))
            .await
            .map_err(CellError::Custody)
    }

    /// The custody reference of every root the keystore holds a row for,
    /// by epoch. The reconciliation reads each root's usage log through
    /// it (`Custody::usage_since`, ADR-004 "Reconciliation").
    pub fn root_refs(&self) -> Vec<RootRef> {
        self.roots.values().map(|r| r.root.clone()).collect()
    }

    /// The request id of the start-up `unwrap` whose `RecordKeyOp` is
    /// still owed, if any.
    pub fn startup_unwrap(&self) -> Option<RequestId> {
        self.startup_unwrap
    }

    /// Start-up, second half: opens every current group secret under
    /// `s` into process memory.
    ///
    /// # Errors
    ///
    /// [`CellError::Keys`] when a group secret does not open.
    pub fn open_groups(&mut self, s: &SealKey) -> Result<OpenGroups, CellError> {
        // A keystore loaded from its tables opens its chain state first.
        self.open_chain_state(s)?;
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
        public: sk.public().to_bytes().to_vec(),
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

fn signer_aad(cell: CellId, purpose: Purpose, generation: u32, epoch: u64) -> Vec<u8> {
    let mut aad = SIGNER_AAD.to_vec();
    aad.extend_from_slice(&cell.0);
    aad.push(Chain::App.code());
    aad.push(purpose.code());
    aad.extend_from_slice(&generation.to_be_bytes());
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad
}

/// Seals `key`, generation `generation` of `purpose`, under `s` of `epoch`.
fn seal_signer(
    s: &SealKey,
    cell: CellId,
    purpose: Purpose,
    generation: u32,
    epoch: u64,
    key: &CompositeSigningKey,
    created_us: i64,
) -> Result<SignerRow, CellError> {
    let aead_key = aead::Key::from_bytes(s.expose()).map_err(|_| keys_err("seal key"))?;
    let secret = key.to_bytes().map_err(|_| keys_err("signing key export"))?;
    let sealed = aead::seal(
        &aead_key,
        &signer_aad(cell, purpose, generation, epoch),
        &secret[..],
    )
    .map_err(|_| keys_err("signing key seal"))?;
    Ok(SignerRow {
        generation,
        epoch,
        nonce: sealed.nonce,
        body: sealed.body,
        public: key.public_key().to_bytes().to_vec(),
        created_us,
    })
}

/// Opens the signing key of `row` under `s`, and checks it is the key
/// whose public key the row names.
fn open_signer(
    s: &SealKey,
    cell: CellId,
    purpose: Purpose,
    row: &SignerRow,
) -> Result<CompositeSigningKey, CellError> {
    let aead_key = aead::Key::from_bytes(s.expose()).map_err(|_| keys_err("seal key"))?;
    let secret = aead::open(
        &aead_key,
        &row.nonce,
        &signer_aad(cell, purpose, row.generation, row.epoch),
        &row.body,
    )
    .map_err(|_| keys_err("signing key open"))?;
    let key =
        CompositeSigningKey::from_bytes(&secret).map_err(|_| keys_err("signing key decode"))?;
    if key.public_key().to_bytes()[..] != row.public[..] {
        return Err(keys_err("signing key mismatch"));
    }
    Ok(key)
}

/// Opens every current signing key of `store` under `s`.
fn open_signers(
    s: &SealKey,
    store: &Keystore,
) -> Result<BTreeMap<Purpose, CompositeSigningKey>, CellError> {
    let mut out = BTreeMap::new();
    for (purpose, row) in &store.signers {
        out.insert(*purpose, open_signer(s, store.cell, *purpose, row)?);
    }
    Ok(out)
}

/// A second handle on `key`, for a caller outside the runner.
fn copy_signer(key: &CompositeSigningKey) -> Result<CompositeSigningKey, CellError> {
    let secret = key.to_bytes().map_err(|_| keys_err("signing key export"))?;
    CompositeSigningKey::from_bytes(&secret[..]).map_err(|_| keys_err("signing key decode"))
}

/// The canonical `RecordKeyOp` body of a custody call of the App chain
/// (`fstp_keys::keyop`).
fn key_op_body(call: KeyCall, epoch: u64, request: RequestId) -> Result<Vec<u8>, CellError> {
    keyop::encode(&KeyOp {
        call,
        chain: Chain::App,
        epoch: Epoch(epoch),
        request: request.0,
    })
    .map_err(|_| keys_err("key op body"))
}

/// The `KeyOp` a `RecordKeyOp` body holds (ADR-004 "Reconciliation").
/// The daily reconciliation reads these from the App chain and matches
/// them with the custody usage log (`fstp_custody::usage::reconcile`).
///
/// # Errors
///
/// [`CellError::Keys`] for a body that is not the canonical form.
pub fn key_op_of_body(body: &[u8]) -> Result<KeyOp, CellError> {
    keyop::decode(body).map_err(|_| keys_err("key op body"))
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
    /// Step 5: the snapshot uploaded, not yet verified.
    snapshot_id: Option<[u8; 16]>,
    /// The open composite signing keys of the committed state.
    signers: BTreeMap<Purpose, CompositeSigningKey>,
    /// Step 3: the signing keys resealed under the new seal key.
    signer_rows: BTreeMap<Purpose, SignerRow>,
    /// Step 2: the login email index under the new `Lookup` key, when
    /// the batch erases a login email.
    new_logins: Option<BTreeMap<[u8; 32], u128>>,
    /// Step 2: the display name fingerprints under the new `Lookup` key,
    /// by account, when the batch replaces `Lookup` (lane L26).
    new_displays: Option<BTreeMap<u128, [u8; 32]>>,
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
    /// The keystore snapshot writer of step 5, when an object store is
    /// configured (ADR-012 record of lane L17). Without one, step 5 keeps
    /// an in-memory copy of the committed keystore.
    snapshots: Option<fstp_backup::Snapshots>,
    /// The directory of the snapshot status file (ADR-012 record of lane
    /// L27): the credentials directory of a serving cell.
    snapshot_status: Option<std::path::PathBuf>,
    /// When the runner started and its last daily snapshot, in Unix
    /// seconds, and whether that verified (ADR-012 record of lane L27).
    daily_started: u64,
    daily_last: Option<(u64, bool)>,
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
fn request_id() -> Result<RequestId, CellError> {
    RequestId::generate().map_err(|_| keys_err("request id"))
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
                signers: BTreeMap::new(),
                retired: BTreeMap::new(),
                pending_root: None,
                requested: BTreeSet::new(),
                logins: LoginIndex::default(),
                displays: DisplayIndex::default(),
                startup_unwrap: None,
                persist: tables::Persist::default(),
                snapshots: None,
            },
            chain: ChainState::genesis(Epoch(0)),
            work: Work::new(SealKey::generate().map_err(CellError::Custody)?),
            events: Vec::new(),
            erased: Vec::new(),
            snapshots: None,
            snapshot_status: None,
            daily_started: fstp_obs::snapshot_status::now(),
            daily_last: None,
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
            snapshots: None,
            snapshot_status: None,
            daily_started: fstp_obs::snapshot_status::now(),
            daily_last: None,
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
    /// A refused key record, or a signing key that does not open.
    pub async fn from_open(
        custody: C,
        engine: CellEngine,
        store: Keystore,
        seal: SealKey,
        groups: OpenGroups,
    ) -> Result<ErasureRunner<C>, CellError> {
        let mut store = store;
        let request = store
            .startup_unwrap
            .take()
            .ok_or(keys_err("no start-up unwrap request id"))?;
        store.persist.dirty.meta = true;
        let chain = store.chain_state.restart();
        let epoch = store.chain_state.epoch().0;
        let (snapshots, snapshot_status) = match store.snapshots.take() {
            Some((s, d)) => (Some(s), d),
            None => (None, None),
        };
        let mut work = Work::new(seal);
        work.secrets = groups.0;
        work.signers = open_signers(&work.current, &store)?;
        let mut runner = ErasureRunner {
            custody,
            engine,
            store,
            chain,
            work,
            events: Vec::new(),
            erased: Vec::new(),
            snapshots,
            snapshot_status,
            daily_started: fstp_obs::snapshot_status::now(),
            daily_last: None,
        };
        runner
            .record_call_as(KeyCall::Unwrap, epoch, request)
            .await?;
        // ADR-007 (Daniel, 2026-11-23, decision 2; lane L39): the sealed
        // row of every completed document erasure is deleted again, so a
        // crash between `ErasuresCompleted` and its flush loses nothing. A
        // row deleted before deletes nothing.
        let documents: Vec<[u8; 16]> = runner
            .engine
            .state()
            .erasures()
            .filter(|(_, e)| {
                e.kind == fstp_cell_core::ERASURE_KIND_DOCUMENT && e.destroyed_epoch.is_some()
            })
            .map(|(id, _)| id)
            .collect();
        runner.store.persist.dirty.blobs.extend(documents);
        // F-017: so are the rows of every completed workspace erasure.
        let workspaces: Vec<[u8; 16]> = runner
            .engine
            .state()
            .erasures()
            .filter(|(_, e)| {
                e.kind == fstp_cell_core::ERASURE_KIND_WORKSPACE && e.destroyed_epoch.is_some()
            })
            .map(|(id, _)| id)
            .collect();
        runner.store.persist.dirty.workspaces.extend(workspaces);
        // The owed record is written, so its request id leaves the row.
        runner.flush().await?;
        Ok(runner)
    }

    /// The durable keystore, for a restart.
    pub fn keystore(&self) -> &Keystore {
        &self.store
    }

    /// Makes the keystore write through `sink` and writes it whole
    /// (`tables`). A cell process does this once, after genesis.
    ///
    /// # Errors
    ///
    /// [`CellError::Keys`] when the sink refuses the write.
    pub async fn persist_to(
        &mut self,
        sink: std::sync::Arc<dyn KeystoreSink>,
    ) -> Result<(), CellError> {
        self.store.attach(sink);
        self.flush().await
    }

    /// Writes the keystore's marked rows (`tables`), sealing a changed
    /// chain state under the current seal key.
    async fn flush(&mut self) -> Result<(), CellError> {
        self.store.flush(Some(&self.work.current)).await
    }

    /// The texts whose erasure this runner completed, in order.
    pub fn erased(&self) -> &[[u8; 16]] {
        &self.erased
    }

    /// Every event so far, in order.
    pub fn events(&self) -> &[ErasureEvent] {
        &self.events
    }

    /// Takes step 5's snapshots through `snapshots` from now on (ADR-012
    /// record of lane L17).
    #[must_use]
    pub fn with_snapshots(mut self, snapshots: fstp_backup::Snapshots) -> Self {
        self.snapshots = Some(snapshots);
        self
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
        self.work.signers = open_signers(&self.work.current, &self.store)?;
        Ok(())
    }

    /// Whether a batch holds a new seal key not yet committed. A signing
    /// key sealed now would miss the batch's reseal, so none is created or
    /// rotated then.
    fn sealing(&self) -> bool {
        self.work.new_seal.is_some()
    }

    /// Makes generation `generation` of the signing key of `purpose`,
    /// sealed under the current seal key, and returns its public key.
    ///
    /// The key record `call` (`create_signer` or `rotate_signer`) is
    /// appended first, as for a custody call, although none is made
    /// (ADR-004, decided by Daniel on 2026-11-15). A refused purpose or a
    /// resealing batch appends nothing.
    async fn make_signer(
        &mut self,
        purpose: Purpose,
        generation: u32,
        call: KeyCall,
    ) -> Result<Vec<u8>, CellError> {
        if !SIGNER_PURPOSES.contains(&purpose) {
            return Err(keys_err("no level 2 signing key of this purpose"));
        }
        if self.sealing() {
            return Err(keys_err("a batch is resealing the keystore"));
        }
        let epoch = self.store.chain_state.epoch().0;
        self.record_call(call, epoch).await?;
        let key = composite::generate().map_err(|_| keys_err("signing key"))?;
        let row = seal_signer(
            &self.work.current,
            self.store.cell,
            purpose,
            generation,
            epoch,
            &key,
            super::system_now(),
        )?;
        self.store
            .persist
            .dirty
            .signers
            .insert((purpose, generation));
        let public = row.public.clone();
        if let Some(old) = self.store.signers.insert(purpose, row) {
            self.store
                .persist
                .dirty
                .signers
                .insert((purpose, old.generation));
            self.store
                .retired
                .insert((purpose, old.generation), old.public);
        }
        self.work.signers.insert(purpose, key);
        Ok(public)
    }

    /// Creates the composite level 2 signing key of `purpose` at
    /// generation 1, unless one exists, and returns its public key. The key
    /// is sealed under the chain's seal key, which custody wraps under the
    /// root, so it is resealed at each new epoch (ADR-004, M9 decision
    /// CD4). Only the purposes of [`SIGNER_PURPOSES`] are held. Creating
    /// the key appends a `create_signer` key record.
    ///
    /// # Errors
    ///
    /// Another purpose, a batch that is resealing, a key record the
    /// engine refused, or a failed seal.
    pub async fn ensure_signer(&mut self, purpose: Purpose) -> Result<Vec<u8>, CellError> {
        if let Some(row) = self.store.signers.get(&purpose) {
            return Ok(row.public.clone());
        }
        self.make_signer(purpose, 1, KeyCall::CreateSigner).await
    }

    /// Replaces the signing key of `purpose` with a new generation and
    /// returns its public key. The replaced public key stays in
    /// [`Keystore::signer_public_keys`], and its secret is dropped. The
    /// rotation appends a `rotate_signer` key record.
    ///
    /// # Errors
    ///
    /// No key of `purpose` yet, a batch that is resealing, a key record
    /// the engine refused, or a failed seal.
    pub async fn rotate_signer(&mut self, purpose: Purpose) -> Result<Vec<u8>, CellError> {
        let generation = self
            .store
            .signers
            .get(&purpose)
            .and_then(|r| r.generation.checked_add(1))
            .ok_or(keys_err("no signing key to rotate"))?;
        self.make_signer(purpose, generation, KeyCall::RotateSigner)
            .await
    }

    /// A handle on the current signing key of `purpose`, as custody of the
    /// cell hands it out. `fstp_contract::notice_companion` takes it with
    /// its purpose and refuses any other (D6).
    ///
    /// # Errors
    ///
    /// No key of `purpose`.
    pub fn signer(&self, purpose: Purpose) -> Result<CompositeSigningKey, CellError> {
        let key = self
            .work
            .signers
            .get(&purpose)
            .ok_or(keys_err("no signing key of this purpose"))?;
        copy_signer(key)
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

    /// Records a custody call before it is made, and gives the request id
    /// the call then carries to custody (ADR-004 "Reconciliation").
    async fn record_call(&self, call: KeyCall, epoch: u64) -> Result<RequestId, CellError> {
        let request = request_id()?;
        self.record_call_as(call, epoch, request).await?;
        Ok(request)
    }

    /// Records a custody call under `request`.
    async fn record_call_as(
        &self,
        call: KeyCall,
        epoch: u64,
        request: RequestId,
    ) -> Result<(), CellError> {
        let op = key_op_body(call, epoch, request)?;
        let mut suffix = [0u8; 8];
        for (d, s) in suffix.iter_mut().zip(request.0.iter()) {
            *d = *s;
        }
        self.record(KeyCommand::RecordKeyOp { op }, system_command_id(suffix))
            .await
    }

    async fn create_root(&self, epoch: u64) -> Result<RootRef, CellError> {
        let request = self.record_call(KeyCall::CreateRoot, epoch).await?;
        let label = RootLabel {
            cell: Some(fstp_custody::CellId(self.store.cell.0)),
            chain: Chain::App,
            epoch: Epoch(epoch),
        };
        with_request(request, || self.custody.create_root(label))
            .await
            .map_err(CellError::Custody)
    }

    async fn wrap(
        &self,
        root: &RootRef,
        s: &SealKey,
        epoch: u64,
    ) -> Result<WrappedSealKey, CellError> {
        let request = self.record_call(KeyCall::Wrap, epoch).await?;
        let aad = seal_aad(self.store.cell, epoch);
        with_request(request, || self.custody.wrap(root, s, &aad))
            .await
            .map_err(CellError::Custody)
    }

    async fn unwrap(&self, row: &RootRow, epoch: u64) -> Result<SealKey, CellError> {
        let request = self.record_call(KeyCall::Unwrap, epoch).await?;
        let aad = seal_aad(self.store.cell, epoch);
        with_request(request, || {
            self.custody.unwrap(&row.root, &row.wrapped, &aad)
        })
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
        self.store.persist.dirty.groups.insert((g, 1));
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
        self.store.texts.insert(
            id,
            TextRow {
                dek,
                generation,
                blob,
            },
        );
        self.store.persist.dirty.keys.insert(dek);
        self.store.persist.dirty.texts.insert(id);
        Ok(())
    }

    /// Seals `bytes` as document `id` under a fresh data key of the
    /// existing group `group`, and returns the sealed blob in its stored
    /// form (`doc.blob.envelope`, ADR-026 record of lane L5). The data key
    /// is kept like a text's, so erasing the group erases the document.
    /// The blob's context names generation 0, so a later re-seal of the
    /// data key at another generation still opens it.
    ///
    /// # Errors
    ///
    /// An unknown group, a planner refusal, or a failed seal.
    pub fn seal_document(
        &mut self,
        group: [u8; 16],
        id: [u8; 16],
        bytes: &[u8],
    ) -> Result<Vec<u8>, CellError> {
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
        let blob = envelope::seal_blob(&data_key, &ctx_for(self.store.cell, g, 0, id), bytes)
            .map_err(|_| keys_err("document seal"))?;
        let stored = envelope::encode_sealed_blob(&blob).map_err(|_| keys_err("document form"))?;
        let ctx = ctx_for(self.store.cell, g, generation, id);
        let sealed = envelope::seal_key(sk.public(), &data_key, &ctx)
            .map_err(|_| keys_err("data key seal"))?;
        self.store
            .chain_state
            .admit(g, dek)
            .map_err(|_| keys_err("key admission"))?;
        self.chain = chain;
        self.store.keys.insert(dek, (g, generation, sealed));
        self.store.persist.dirty.keys.insert(dek);
        Ok(stored)
    }

    /// Opens the sealed document `stored` of data key `id`
    /// ([`ErasureRunner::seal_document`]), or refuses it once its key is
    /// erased.
    ///
    /// # Errors
    ///
    /// [`OpenRefusal`] as for a text.
    pub fn open_document(
        &self,
        id: [u8; 16],
        stored: &[u8],
    ) -> Result<impl std::ops::Deref<Target = Vec<u8>> + use<C>, OpenRefusal> {
        let dek = DekId(id);
        // ADR-007 section "Built by lane L37": refused from the moment its
        // erasure request is in the ledger, before the planner runs.
        if self.chain.refused_for_open(dek) || self.engine.state().erasure(id).is_some() {
            return Err(OpenRefusal::Erased);
        }
        let (g, generation, sealed) = self.store.keys.get(&dek).ok_or(OpenRefusal::Unknown)?;
        let sk = self
            .work
            .secrets
            .get(&(*g, *generation))
            .ok_or(OpenRefusal::Keys)?;
        let ctx = ctx_for(self.store.cell, *g, *generation, id);
        let dk = envelope::open_key(sk, sealed, &ctx).map_err(|_| OpenRefusal::Keys)?;
        let blob = envelope::decode_sealed_blob(stored).map_err(|_| OpenRefusal::Keys)?;
        envelope::open_blob(&dk, &ctx_for(self.store.cell, *g, 0, id), &blob)
            .map_err(|_| OpenRefusal::Keys)
    }

    /// Requests the erasure of document `id`, the data key id under which
    /// [`ErasureRunner::seal_document`] sealed it, with `cause` as `by`
    /// asked (ADR-007 section "Built by lane L37", R-KY-02, I-81).
    ///
    /// The ledger record `KeystoreErasureRequested` with the document kind
    /// is the durable trigger: the next step joins the key to the chain
    /// state, and step 7 completes the entry with the destroyed epoch. A
    /// command id fixed per document and the check of an entry already in
    /// the log make a repeated call append nothing twice. The document
    /// opens no more once the record is in.
    ///
    /// # Errors
    ///
    /// An id that names no document key of this runner, an id whose entry
    /// is not a document's, or a refused record.
    pub async fn erase_document(
        &mut self,
        id: [u8; 16],
        cause: u16,
        by: fstp_domain::id::AccountId,
        reason: Option<[u8; 16]>,
    ) -> Result<(), CellError> {
        if let Some(e) = self.engine.state().erasure(id) {
            return if e.kind == fstp_cell_core::ERASURE_KIND_DOCUMENT {
                Ok(())
            } else {
                Err(keys_err("not a document"))
            };
        }
        if self.store.texts.contains_key(&id) || !self.store.keys.contains_key(&DekId(id)) {
            return Err(keys_err("unknown document"));
        }
        let mut suffix = [b'q'; 8];
        for (d, s) in suffix.iter_mut().skip(1).zip(id.iter()) {
            *d = *s;
        }
        self.record(
            KeyCommand::RecordKeystoreErasure {
                ids: vec![id],
                cause,
                by,
                kind: fstp_cell_core::ERASURE_KIND_DOCUMENT,
                reason,
            },
            system_command_id(suffix),
        )
        .await
    }

    /// Whether the workspace of `proposal` is under erasure or erased: the
    /// ledger has an entry for its key, or the chain state holds a request
    /// for it.
    fn workspace_erased(&self, proposal: [u8; 16]) -> bool {
        self.engine.state().erasure(proposal).is_some() || self.chain.is_requested(DekId(proposal))
    }

    /// Seals `bytes` as a workspace value of `proposal` under the
    /// proposal's own workspace key, and returns the stored form, an
    /// `FSB1` blob (F-017, ADR-026 section "Written by the M10 fix lane").
    ///
    /// The key's id is the proposal id. The first seal of a proposal
    /// creates the key in a group of its own, as for a document. A batch
    /// before its commit is first run to its commit, since no group may be
    /// added then. Each seal draws a fresh random nonce. The blob's
    /// context names generation 0 and the proposal as its object, so a
    /// value of another proposal does not open, and a later reseal of the
    /// key at another generation still opens it.
    ///
    /// The caller writes the rows before it hands the value out
    /// (`durable`), so the key is durable before any row names it.
    ///
    /// # Errors
    ///
    /// A workspace under erasure or erased, a value over
    /// [`fstp_pgstore::MAX_WORKSPACE_SEALED`], a step of the batch in
    /// flight that fails, a planner refusal, or a failed seal.
    pub async fn seal_workspace(
        &mut self,
        proposal: [u8; 16],
        bytes: &[u8],
    ) -> Result<Vec<u8>, CellError> {
        if self.workspace_erased(proposal) {
            return Err(keys_err("the workspace is erased"));
        }
        if bytes.len() > fstp_pgstore::MAX_WORKSPACE_SEALED.saturating_sub(envelope::MIN_BLOB_LEN) {
            return Err(keys_err("a workspace value over its limit"));
        }
        let dek = DekId(proposal);
        if self.store.texts.contains_key(&proposal) {
            return Err(keys_err("a text holds this id"));
        }
        let data_key = match self.store.keys.get(&dek) {
            Some((g, generation, sealed)) => {
                let sk = self
                    .work
                    .secrets
                    .get(&(*g, *generation))
                    .ok_or(keys_err("group secret not open"))?;
                let ctx = ctx_for(self.store.cell, *g, *generation, proposal);
                envelope::open_key(sk, sealed, &ctx).map_err(|_| keys_err("workspace key"))?
            }
            None => {
                while self.resealing() {
                    if self.step().await?.is_none() {
                        break;
                    }
                }
                if self.resealing() {
                    return Err(keys_err("a batch is resealing the keystore"));
                }
                let group = fstp_crypto::random_array::<16>().map_err(|_| keys_err("group id"))?;
                self.add_group(group)?;
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
                let mut chain = self.chain.clone();
                chain.admit(g, dek).map_err(|_| keys_err("key admission"))?;
                let data_key = DataKey::generate().map_err(|_| keys_err("data key"))?;
                let ctx = ctx_for(self.store.cell, g, generation, proposal);
                let sealed = envelope::seal_key(sk.public(), &data_key, &ctx)
                    .map_err(|_| keys_err("data key seal"))?;
                self.store
                    .chain_state
                    .admit(g, dek)
                    .map_err(|_| keys_err("key admission"))?;
                self.chain = chain;
                self.store.keys.insert(dek, (g, generation, sealed));
                self.store.persist.dirty.keys.insert(dek);
                data_key
            }
        };
        let g = self
            .store
            .keys
            .get(&dek)
            .map(|(g, _, _)| *g)
            .ok_or(keys_err("workspace key"))?;
        let blob = envelope::seal_blob(&data_key, &ctx_for(self.store.cell, g, 0, proposal), bytes)
            .map_err(|_| keys_err("workspace seal"))?;
        envelope::encode_sealed_blob(&blob).map_err(|_| keys_err("workspace form"))
    }

    /// Opens the stored workspace value `stored` of `proposal`
    /// ([`ErasureRunner::seal_workspace`]), or refuses it from the moment
    /// the workspace's erasure request is in the ledger (F-017).
    ///
    /// # Errors
    ///
    /// [`OpenRefusal`] as for a document.
    pub fn open_workspace(
        &self,
        proposal: [u8; 16],
        stored: &[u8],
    ) -> Result<impl std::ops::Deref<Target = Vec<u8>> + use<C>, OpenRefusal> {
        if self.workspace_erased(proposal) {
            return Err(OpenRefusal::Erased);
        }
        if self.store.texts.contains_key(&proposal) {
            return Err(OpenRefusal::Unknown);
        }
        self.open_document(proposal, stored)
    }

    /// Requests the erasure of the workspace of `proposal` with `cause` as
    /// `by` asked (F-017, ADR-026 section "Written by the M10 fix lane").
    /// `false` when the proposal has no workspace key, so nothing of it is
    /// stored under one.
    ///
    /// The ledger record `KeystoreErasureRequested` of the workspace kind
    /// is the durable trigger, as for a document: from it on nothing seals
    /// or opens the workspace, the next step joins the key to the chain
    /// state, and step 7 completes the entry with the destroyed epoch. The
    /// rows leave in the keystore batch after that. A command id fixed per
    /// proposal and the check of an entry already in the log make a
    /// repeated call append nothing twice.
    ///
    /// # Errors
    ///
    /// An id whose entry is not a workspace's, or a refused record.
    pub async fn erase_workspace(
        &mut self,
        proposal: [u8; 16],
        cause: u16,
        by: fstp_domain::id::AccountId,
    ) -> Result<bool, CellError> {
        if let Some(e) = self.engine.state().erasure(proposal) {
            return if e.kind == fstp_cell_core::ERASURE_KIND_WORKSPACE {
                Ok(true)
            } else {
                Err(keys_err("not a workspace"))
            };
        }
        if self.store.texts.contains_key(&proposal)
            || !self.store.keys.contains_key(&DekId(proposal))
        {
            return Ok(false);
        }
        let mut suffix = [b'w'; 8];
        for (d, s) in suffix.iter_mut().skip(1).zip(proposal.iter()) {
            *d = *s;
        }
        self.record(
            KeyCommand::RecordKeystoreErasure {
                ids: vec![proposal],
                cause,
                by,
                kind: fstp_cell_core::ERASURE_KIND_WORKSPACE,
                reason: None,
            },
            system_command_id(suffix),
        )
        .await?;
        Ok(true)
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
        let body = ctx_for(self.store.cell, *g, row.generation, id);
        envelope::open_blob(&dk, &body, &row.blob).map_err(|_| OpenRefusal::Keys)
    }

    /// The HMAC key of the `Lookup` group at its committed generation, if
    /// the group exists.
    fn lookup_key(&self) -> Result<Option<SealKey>, CellError> {
        let Some(g) = self.store.logins.lookup else {
            return Ok(None);
        };
        let generation = self
            .store
            .chain_state
            .generation(g)
            .ok_or(keys_err("unknown lookup group"))?;
        let sk = self
            .work
            .secrets
            .get(&(g, generation))
            .ok_or(keys_err("lookup group secret not open"))?;
        digest_key(sk, Purpose::Lookup).map(Some)
    }

    /// The delivery body digest key, derived from the `Lookup` key with
    /// `crate::tasks::dispatch::digest_key` (m4-design section 15.0 row
    /// "Delivery body digest key", ADR-026 record of lane L5). `None`
    /// while the cell has no `Lookup` group. The `Lookup` key never leaves
    /// the runner.
    fn delivery_digest_key(&self) -> Result<Option<fstp_dispatch::DigestKey>, CellError> {
        let Some(k) = self.lookup_key()? else {
            return Ok(None);
        };
        crate::tasks::dispatch::digest_key(k.expose())
            .map(Some)
            .map_err(|_| keys_err("delivery digest key"))
    }

    /// Creates the `Lookup` keyed digest group at generation 1 (design
    /// section 3.1), sealed under the current seal key.
    fn add_lookup_group(&mut self) -> Result<GroupId, CellError> {
        let g = GroupId(fstp_crypto::random_array::<16>().map_err(|_| keys_err("group id"))?);
        let mut chain = self.chain.clone();
        chain
            .add_digest_group(g, &[])
            .map_err(|_| keys_err("lookup group admission"))?;
        let sk = hybrid_kem::generate().map_err(|_| keys_err("group key"))?;
        let epoch = self.store.chain_state.epoch().0;
        let row = seal_group(&self.work.current, self.store.cell, g, 1, epoch, &sk)?;
        self.store
            .chain_state
            .add_digest_group(g, &[])
            .map_err(|_| keys_err("lookup group admission"))?;
        self.chain = chain;
        self.store.groups.insert((g, 1), row);
        self.work.secrets.insert((g, 1), sk);
        self.store.logins.lookup = Some(g);
        self.store.persist.dirty.groups.insert((g, 1));
        self.store.persist.dirty.meta = true;
        Ok(g)
    }

    /// Stores `text` as text `id` in the login email group, and opens a
    /// new group when there is none or it is full.
    fn put_login_text(&mut self, id: [u8; 16], text: &[u8]) -> Result<(), CellError> {
        if let Some(g) = self.store.logins.group
            && self.put_text(g.0, id, text).is_ok()
        {
            return Ok(());
        }
        let g = fstp_crypto::random_array::<16>().map_err(|_| keys_err("group id"))?;
        self.add_group(g)?;
        self.store.logins.group = Some(GroupId(g));
        self.store.persist.dirty.meta = true;
        self.put_text(g, id, text)
    }

    /// Makes `email` the login email of `account` (design section 4.2,
    /// Q22, decision 27): the normalised address is sealed as a text of
    /// its own, and its keyed digest under the `Lookup` key maps to the
    /// account. The text's data key is a subject of the `Lookup` group,
    /// so a batch that erases it replaces the key (design section 3.5).
    /// The address is never kept in clear.
    ///
    /// An address that is another account's login email already is
    /// [`LoginEmailSet::Taken`], and nothing changes. The same address
    /// for the same account changes nothing either.
    ///
    /// # Errors
    ///
    /// An account that has another login email (no change of address is
    /// built), a batch that holds a login group frozen, or a failed seal.
    pub fn set_login_email(
        &mut self,
        account: fstp_domain::id::AccountId,
        email: &str,
    ) -> Result<LoginEmailSet, CellError> {
        let address = normalise_email(email);
        // Before a batch commits, its groups take no key and no new group
        // is added, so nothing here is half applied. The caller retries.
        if matches!(
            self.chain.phase(),
            plan::Phase::Planned | plan::Phase::Resealed
        ) {
            return Err(keys_err("a batch is resealing the keystore"));
        }
        let lookup = match self.store.logins.lookup {
            Some(g) => g,
            None => self.add_lookup_group()?,
        };
        let key = self.lookup_key()?.ok_or(keys_err("no lookup key"))?;
        let digest = keyed_digest(&key, address.as_bytes());
        match self.store.logins.digests.get(&digest) {
            Some(a) if *a == account.raw() => return Ok(LoginEmailSet::Set),
            Some(_) => return Ok(LoginEmailSet::Taken),
            None => {}
        }
        if self.store.logins.texts.contains_key(&account.raw()) {
            return Err(keys_err("the account has a login email"));
        }
        let id = fstp_crypto::random_array::<16>().map_err(|_| keys_err("text id"))?;
        self.put_login_text(id, address.as_bytes())?;
        let mut chain = self.chain.clone();
        chain
            .add_digest_subject(lookup, DekId(id))
            .map_err(|_| keys_err("lookup subject"))?;
        self.store
            .chain_state
            .add_digest_subject(lookup, DekId(id))
            .map_err(|_| keys_err("lookup subject"))?;
        self.chain = chain;
        self.store.logins.texts.insert(account.raw(), id);
        self.store.logins.digests.insert(digest, account.raw());
        self.store.persist.dirty.logins.insert(account.raw());
        self.store.persist.dirty.digests.insert(digest);
        Ok(LoginEmailSet::Set)
    }

    /// The account whose login email is `email`, through the keyed index.
    ///
    /// # Errors
    ///
    /// A key chain that does not open.
    pub fn login_account(
        &self,
        email: &str,
    ) -> Result<Option<fstp_domain::id::AccountId>, CellError> {
        let Some(key) = self.lookup_key()? else {
            return Ok(None);
        };
        let digest = keyed_digest(&key, normalise_email(email).as_bytes());
        Ok(self
            .store
            .logins
            .digests
            .get(&digest)
            .map(|a| fstp_domain::id::AccountId::from_raw(*a)))
    }

    /// The login email of `account`, opened from its text, or `None` when
    /// the account has none or its text is under erasure.
    ///
    /// # Errors
    ///
    /// A key chain that does not open.
    pub fn login_email(
        &self,
        state: &CellState,
        account: fstp_domain::id::AccountId,
    ) -> Result<Option<String>, CellError> {
        let Some(id) = self.store.logins.texts.get(&account.raw()) else {
            return Ok(None);
        };
        match self.open_text(state, *id) {
            Ok(t) => String::from_utf8(t.to_vec())
                .map(Some)
                .map_err(|_| keys_err("login email text")),
            Err(OpenRefusal::Erased | OpenRefusal::Unknown) => Ok(None),
            Err(OpenRefusal::Keys) => Err(keys_err("login email open")),
        }
    }

    /// Step 2 of a batch that erases a login email (design section 3.5,
    /// G24): the keyed digest of every live login email under the new
    /// `Lookup` generation `sk`. Erased addresses get no digest.
    fn recompute_logins(
        &self,
        batch: &BTreeSet<DekId>,
        sk: &HybridSecretKey,
    ) -> Result<BTreeMap<[u8; 32], u128>, CellError> {
        let key = digest_key(sk, Purpose::Lookup)?;
        let mut out = BTreeMap::new();
        for (account, id) in &self.store.logins.texts {
            if batch.contains(&DekId(*id)) {
                continue;
            }
            let row = self.store.texts.get(id).ok_or(keys_err("login text"))?;
            let (g, generation, sealed) = self
                .store
                .keys
                .get(&row.dek)
                .ok_or(keys_err("login text key"))?;
            let gsk = self
                .work
                .secrets
                .get(&(*g, *generation))
                .ok_or(keys_err("group secret not open"))?;
            let ctx = ctx_for(self.store.cell, *g, *generation, *id);
            let dk = envelope::open_key(gsk, sealed, &ctx).map_err(|_| keys_err("login key"))?;
            let body = ctx_for(self.store.cell, *g, row.generation, *id);
            let address =
                envelope::open_blob(&dk, &body, &row.blob).map_err(|_| keys_err("login text"))?;
            out.insert(keyed_digest(&key, &address), *account);
        }
        Ok(out)
    }

    /// Opens the live text `id` with no ledger check, for a recompute of
    /// step 2: its data key under its committed group generation.
    fn open_stored(
        &self,
        id: &[u8; 16],
    ) -> Result<impl std::ops::Deref<Target = Vec<u8>> + use<C>, CellError> {
        let row = self.store.texts.get(id).ok_or(keys_err("indexed text"))?;
        let (g, generation, sealed) = self
            .store
            .keys
            .get(&row.dek)
            .ok_or(keys_err("indexed text key"))?;
        let gsk = self
            .work
            .secrets
            .get(&(*g, *generation))
            .ok_or(keys_err("group secret not open"))?;
        let ctx = ctx_for(self.store.cell, *g, *generation, *id);
        let dk = envelope::open_key(gsk, sealed, &ctx).map_err(|_| keys_err("indexed key"))?;
        let body = ctx_for(self.store.cell, *g, row.generation, *id);
        envelope::open_blob(&dk, &body, &row.blob).map_err(|_| keys_err("indexed text"))
    }

    /// Step 2 of a batch that replaces `Lookup` (SA-11 amendment, ADR-004
    /// section "Written by lane L26"): the fingerprint of every live
    /// display name under the fingerprint key of the new `Lookup`
    /// generation `sk`, by account. Names the batch erases get none.
    fn recompute_displays(
        &self,
        batch: &BTreeSet<DekId>,
        sk: &HybridSecretKey,
    ) -> Result<BTreeMap<u128, [u8; 32]>, CellError> {
        let key = display_key(&digest_key(sk, Purpose::Lookup)?)?;
        let mut out = BTreeMap::new();
        for (account, row) in &self.store.displays.names {
            let dek = self
                .store
                .texts
                .get(&row.text)
                .map(|t| t.dek)
                .ok_or(keys_err("display name text"))?;
            if batch.contains(&dek) {
                continue;
            }
            let plain = self.open_stored(&row.text)?;
            let name = std::str::from_utf8(&plain).map_err(|_| keys_err("display name text"))?;
            out.insert(
                *account,
                fstp_api_core::display_name::fingerprint(key.expose(), name),
            );
        }
        Ok(out)
    }

    /// Whether a batch is before its commit, so no group, key or `Lookup`
    /// subject may be added.
    fn resealing(&self) -> bool {
        matches!(
            self.chain.phase(),
            plan::Phase::Planned | plan::Phase::Resealed
        )
    }

    /// Sets the display name of `account` to `name`, or clears it with
    /// `None` (SA-11, SA-11 amendment, ADR-004 section "Written by lane
    /// L26"). The API core checked the name first.
    ///
    /// - A batch before its commit is first run to its commit, so the
    ///   person is not refused for a batch in flight.
    /// - A name whose fingerprint another account holds is
    ///   [`DisplayNameSet::Taken`], and nothing changes. The account's own
    ///   name again, byte for byte, changes nothing either.
    /// - Otherwise the name is sealed as a text of its own in a group of
    ///   its own, its data key joins the `Lookup` group's subjects, and its
    ///   fingerprint maps to the account. The replaced or cleared name's
    ///   fingerprint leaves the index at once, and its text gets an
    ///   erasure request in the chain state, which starts its batch.
    ///
    /// The caller writes the rows before it answers (`durable`).
    ///
    /// # Errors
    ///
    /// A step of the batch in flight that fails, a planner refusal, or a
    /// failed seal.
    pub async fn set_display_name(
        &mut self,
        account: fstp_domain::id::AccountId,
        name: Option<&str>,
    ) -> Result<DisplayNameSet, CellError> {
        while self.resealing() {
            if self.step().await?.is_none() {
                break;
            }
        }
        if self.resealing() {
            return Err(keys_err("a batch is resealing the keystore"));
        }
        let a = account.raw();
        let current = self.store.displays.names.get(&a).copied();
        let new = match name {
            None => None,
            Some(name) => {
                let lookup = match self.store.logins.lookup {
                    Some(g) => g,
                    None => self.add_lookup_group()?,
                };
                let key = display_key(&self.lookup_key()?.ok_or(keys_err("no lookup key"))?)?;
                let fingerprint = fstp_api_core::display_name::fingerprint(key.expose(), name);
                if self
                    .store
                    .displays
                    .owners
                    .get(&fingerprint)
                    .is_some_and(|owner| *owner != a)
                {
                    return Ok(DisplayNameSet::Taken);
                }
                if let Some(row) = current
                    && row.fingerprint == fingerprint
                    && self.open_stored(&row.text)?.as_slice() == name.as_bytes()
                {
                    return Ok(DisplayNameSet::Set);
                }
                Some((name, lookup, fingerprint))
            }
        };
        if current.is_none() && new.is_none() {
            return Ok(DisplayNameSet::Set);
        }
        let mut added = None;
        if let Some((name, lookup, fingerprint)) = new {
            let group = fstp_crypto::random_array::<16>().map_err(|_| keys_err("group id"))?;
            let id = fstp_crypto::random_array::<16>().map_err(|_| keys_err("text id"))?;
            self.add_group(group)?;
            self.put_text(group, id, name.as_bytes())?;
            let mut chain = self.chain.clone();
            chain
                .add_digest_subject(lookup, DekId(id))
                .map_err(|_| keys_err("lookup subject"))?;
            self.store
                .chain_state
                .add_digest_subject(lookup, DekId(id))
                .map_err(|_| keys_err("lookup subject"))?;
            self.chain = chain;
            added = Some(DisplayRow {
                text: id,
                fingerprint,
            });
        }
        if let Some(old) = current {
            // ADR-007 section "Built by lane L33": the erasure log names the
            // request, with the account as its authoriser and the kind of a
            // display name, before the chain state takes it. A fixed id per
            // text makes a retry append nothing twice.
            let mut suffix = [b'r'; 8];
            for (d, s) in suffix.iter_mut().skip(1).zip(old.text.iter()) {
                *d = *s;
            }
            self.record(
                KeyCommand::RecordKeystoreErasure {
                    ids: vec![old.text],
                    cause: ErasureCause::ErasureRequest.code(),
                    by: account,
                    kind: fstp_cell_core::ERASURE_KIND_DISPLAY_NAME,
                    reason: None,
                },
                system_command_id(suffix),
            )
            .await?;
            // The replaced or cleared name is erased at once (ADR-007,
            // SA-11): its request joins the chain state directly.
            let dek = self
                .store
                .texts
                .get(&old.text)
                .map(|t| t.dek)
                .ok_or(keys_err("display name text"))?;
            let seq = self.engine.state().head().raw();
            let mut durable = self.store.chain_state.clone();
            durable
                .request(dek, seq)
                .map_err(|_| keys_err("erasure request"))?;
            let mut chain = self.chain.clone();
            chain
                .request(dek, seq)
                .map_err(|_| keys_err("erasure request"))?;
            self.store.chain_state = durable;
            self.chain = chain;
            self.store.requested.insert(old.text);
            self.store.persist.dirty.requested.insert(old.text);
            self.store.displays.owners.remove(&old.fingerprint);
            self.store.displays.names.remove(&a);
        }
        if let Some(row) = added {
            self.store.displays.names.insert(a, row);
            self.store.displays.owners.insert(row.fingerprint, a);
        }
        self.store.persist.dirty.displays.insert(a);
        Ok(DisplayNameSet::Set)
    }

    /// The display names of those of `accounts` that have one, opened
    /// from their texts (SA-11). A name whose text is under erasure is
    /// left out. The caller checked the read's clearance first.
    ///
    /// # Errors
    ///
    /// A key chain that does not open.
    pub fn display_names(
        &self,
        state: &CellState,
        accounts: &[fstp_domain::id::AccountId],
    ) -> Result<BTreeMap<fstp_domain::id::AccountId, String>, CellError> {
        let mut out = BTreeMap::new();
        for account in accounts {
            let Some(row) = self.store.displays.names.get(&account.raw()) else {
                continue;
            };
            match self.open_text(state, row.text) {
                Ok(t) => {
                    let name =
                        String::from_utf8(t.to_vec()).map_err(|_| keys_err("display name text"))?;
                    out.insert(*account, name);
                }
                Err(OpenRefusal::Erased | OpenRefusal::Unknown) => {}
                Err(OpenRefusal::Keys) => return Err(keys_err("display name open")),
            }
        }
        Ok(out)
    }

    /// Whether the runner has work: a request not yet joined, or a batch
    /// in flight.
    pub fn busy(&self) -> Result<bool, CellError> {
        Ok(!self.new_requests().is_empty()
            || plan::next(&self.chain)
                .map_err(|_| keys_err("planner"))?
                .is_some())
    }

    /// The ids whose erasure request is in the ledger and not yet in the
    /// chain state: the ledger's texts, and the documents of the erasure
    /// log (ADR-007 section "Built by lane L37"). A text's and a
    /// document's data key id is its id.
    fn new_requests(&self) -> Vec<[u8; 16]> {
        let state = self.engine.state();
        let texts = self
            .store
            .texts
            .keys()
            .copied()
            .filter(|id| !self.store.requested.contains(id) && state.erasure(*id).is_some());
        // A workspace's key id is its proposal id (F-017), as a document's
        // is its data key id.
        let documents = state
            .erasures()
            .filter(|(id, e)| {
                (e.kind == fstp_cell_core::ERASURE_KIND_DOCUMENT
                    || e.kind == fstp_cell_core::ERASURE_KIND_WORKSPACE)
                    && !self.store.requested.contains(id)
                    && !self.store.texts.contains_key(id)
                    && self.store.keys.contains_key(&DekId(*id))
            })
            .map(|(id, _)| id);
        texts.chain(documents).collect()
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
        // Rows a failed flush left marked are written before any further
        // step, so no step and no custody call follows a step that is not
        // durable (`tables`). The step's own rows are written after it.
        self.flush().await?;
        let event = self.step_once().await?;
        self.flush().await?;
        Ok(event)
    }

    async fn step_once(&mut self) -> Result<Option<ErasureEvent>, CellError> {
        let fresh = self.new_requests();
        if !fresh.is_empty() {
            let seq = self.engine.state().head().raw();
            let mut durable = self.store.chain_state.clone();
            let mut chain = self.chain.clone();
            for id in &fresh {
                // A document's data key id is its id (lane L37).
                let dek = match self.store.texts.get(id) {
                    Some(t) => t.dek,
                    None if self.store.keys.contains_key(&DekId(*id)) => DekId(*id),
                    None => return Err(keys_err("unknown text")),
                };
                durable
                    .request(dek, seq)
                    .map_err(|_| keys_err("erasure request"))?;
                chain
                    .request(dek, seq)
                    .map_err(|_| keys_err("erasure request"))?;
            }
            self.store.chain_state = durable;
            self.chain = chain;
            self.store
                .persist
                .dirty
                .requested
                .extend(fresh.iter().copied());
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
            Step::Snapshot(e) => self.snapshot(e).await?,
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
        // G24, decision 27: a batch that erases a login email affects the
        // `Lookup` group, which takes a new generation and so a new key.
        // Every live login email is digested again under it.
        // SA-11 amendment, ADR-004 (lane L26): every live display name takes
        // its fingerprint under the new key too.
        let (new_logins, new_displays) = match self.store.logins.lookup {
            Some(lookup) => match new_groups.iter().find(|((g, _), _)| *g == lookup) {
                Some((_, sk)) => {
                    let batch = self.chain.running_batch();
                    (
                        Some(self.recompute_logins(&batch, sk)?),
                        Some(self.recompute_displays(&batch, sk)?),
                    )
                }
                None => (None, None),
            },
            None => (None, None),
        };
        self.chain = chain;
        self.work.new_logins = new_logins;
        self.work.new_displays = new_displays;
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
                    self.store.persist.dirty.roots.insert(e.0);
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
        // The level 2 signing keys are resealed under `S(e)` with the
        // group secrets (ADR-004: "Re-sealed under each new epoch").
        let mut signer_rows = BTreeMap::new();
        for (purpose, key) in &self.work.signers {
            let old = self
                .store
                .signers
                .get(purpose)
                .ok_or(keys_err("signing key row"))?;
            signer_rows.insert(
                *purpose,
                seal_signer(
                    s,
                    self.store.cell,
                    *purpose,
                    old.generation,
                    e.0,
                    key,
                    old.created_us,
                )?,
            );
        }
        self.work.rows = rows;
        self.work.signer_rows = signer_rows;
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
        // Every row below is marked, so the flush after this step writes
        // the commit in one transaction (`tables`).
        store.roots.insert(e.0, root);
        store.persist.dirty.roots.insert(e.0);
        for (k, row) in std::mem::take(&mut self.work.rows) {
            store.groups.insert(k, row);
            store.persist.dirty.groups.insert(k);
        }
        for (purpose, row) in std::mem::take(&mut self.work.signer_rows) {
            store
                .persist
                .dirty
                .signers
                .insert((purpose, row.generation));
            store.signers.insert(purpose, row);
        }
        for (dek, v) in std::mem::take(&mut self.work.resealed) {
            store.keys.insert(dek, v);
            store.persist.dirty.keys.insert(dek);
        }
        let batch = chain.running_batch();
        for dek in &batch {
            store.keys.remove(dek);
            store.persist.dirty.keys.insert(*dek);
        }
        for (account, id) in &store.logins.texts {
            if batch.contains(&DekId(*id)) {
                store.persist.dirty.logins.insert(*account);
            }
        }
        // The erased login emails leave the index, and the live ones take
        // their digests under the new `Lookup` key (G24).
        store
            .logins
            .texts
            .retain(|_, id| !batch.contains(&DekId(*id)));
        if let Some(digests) = self.work.new_logins.take() {
            store
                .persist
                .dirty
                .digests
                .extend(store.logins.digests.keys().chain(digests.keys()).copied());
            store.logins.digests = digests;
        }
        // SA-11 amendment, ADR-004 (lane L26): an erased display name leaves
        // the index, and every live one takes its fingerprint under the new
        // `Lookup` key.
        let erased: Vec<u128> = store
            .displays
            .names
            .iter()
            .filter(|(_, r)| {
                store
                    .texts
                    .get(&r.text)
                    .is_some_and(|t| batch.contains(&t.dek))
            })
            .map(|(a, _)| *a)
            .collect();
        for a in &erased {
            store.displays.names.remove(a);
            store.persist.dirty.displays.insert(*a);
        }
        if let Some(fingerprints) = self.work.new_displays.take() {
            for (a, fingerprint) in fingerprints {
                if let Some(r) = store.displays.names.get_mut(&a) {
                    r.fingerprint = fingerprint;
                    store.persist.dirty.displays.insert(a);
                }
            }
        }
        store.displays = DisplayIndex::of(std::mem::take(&mut store.displays.names));
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

    /// Step 5: a snapshot of the committed keystore. With an object store
    /// its tables' rows are sealed to the cell's snapshot key and uploaded
    /// (ADR-012 records of lanes L17 and L27). Without one the runner keeps
    /// an in-memory copy.
    async fn snapshot(&mut self, e: Epoch) -> Result<ErasureEvent, CellError> {
        self.take_snapshot().await?;
        self.apply_durable(&Step::Snapshot(e))?;
        Ok(ErasureEvent::SnapshotTaken { epoch: e.0 })
    }

    /// Seals and uploads the keystore's table rows, and returns the
    /// snapshot id.
    async fn upload_rows(&self, s: &fstp_backup::Snapshots) -> Result<[u8; 16], CellError> {
        let rows = self.store.table_rows(&self.work.current)?;
        let image =
            rows_image::encode(self.store.cell.0, &rows).map_err(|_| keys_err("snapshot image"))?;
        s.upload(&self.custody, &image)
            .await
            .map_err(|_| keys_err("snapshot upload"))
    }

    async fn take_snapshot(&mut self) -> Result<(), CellError> {
        if let Some(s) = self.snapshots.clone() {
            self.work.snapshot_id = Some(self.upload_rows(&s).await?);
        }
        self.work.snapshot = Some(self.store.clone());
        Ok(())
    }

    /// Fetches snapshot `id`, loads its rows as a keystore, and opens
    /// every current key of epoch `e` under `R(e)` through custody
    /// ([`restore::open_loaded`]). Then the pointer names it.
    async fn check_fetched(
        &self,
        s: &fstp_backup::Snapshots,
        id: [u8; 16],
        e: Epoch,
    ) -> Result<(), CellError> {
        let bytes = s
            .fetch(&self.custody, id)
            .await
            .map_err(|_| keys_err("snapshot fetch"))?;
        let (cell, rows) = rows_image::decode(&bytes).map_err(|_| keys_err("snapshot image"))?;
        if cell != self.store.cell.0 {
            return Err(keys_err("snapshot cell"));
        }
        let mut ks = Keystore::from_rows(cell, rows, Arc::new(NoSink))?;
        if ks.epoch() != e.0 {
            return Err(keys_err("snapshot epoch"));
        }
        let row = ks
            .roots
            .get(&e.0)
            .cloned()
            .ok_or(keys_err("snapshot root"))?;
        let seal = self.unwrap(&row, e.0).await?;
        restore::open_loaded(&mut ks, &seal)?;
        s.publish(&self.custody, id)
            .await
            .map_err(|_| keys_err("snapshot pointer"))
    }

    /// Records one snapshot try: the status file and one typed event
    /// (ADR-012 record of lane L27).
    fn note(&self, trigger: fstp_obs::SnapshotTrigger, verified: bool) {
        if let Some(d) = &self.snapshot_status {
            let _ =
                fstp_obs::snapshot_status::record(d, verified, fstp_obs::snapshot_status::now());
        }
        let _ = fstp_obs::log_to_stderr(&fstp_obs::LogEvent::KeystoreSnapshot {
            chain: fstp_obs::SnapshotChain::App,
            trigger,
            verified,
        });
    }

    /// Step 5: a scratch restore of the snapshot opens a sample of live
    /// keys under `R(e)`. With an object store the snapshot is fetched
    /// back, opened with the cell's snapshot key and loaded as a keystore,
    /// and every current key of it opens under `R(e)` (ADR-012 records of
    /// lanes L17 and L27). A snapshot that is missing or does not open
    /// fails the step, so `R(e-1)` lives, and the next attempt uploads a
    /// fresh one.
    async fn verify_snapshot(&mut self, e: Epoch) -> Result<ErasureEvent, CellError> {
        if let Some(s) = self.snapshots.clone() {
            let id = match self.work.snapshot_id.take() {
                Some(id) => id,
                None => {
                    self.take_snapshot().await?;
                    self.work.snapshot_id.take().ok_or(keys_err("snapshot"))?
                }
            };
            let checked = self.check_fetched(&s, id, e).await;
            self.note(fstp_obs::SnapshotTrigger::Rotation, checked.is_ok());
            checked?;
        }
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
        // Every signing key opens from the snapshot too.
        for (purpose, row) in &snap.signers {
            open_signer(&s, snap.cell, *purpose, row)?;
        }
        self.apply_durable(&Step::VerifySnapshot(e))?;
        Ok(ErasureEvent::SnapshotVerified { epoch: e.0 })
    }

    /// The daily snapshot (ADR-012 record of lane L27, row "Daily
    /// snapshot"): with no batch running, the keystore's rows are sealed,
    /// uploaded, fetched back and opened under the current root, and the
    /// pointer names them. Nothing is rotated or destroyed. The try is
    /// recorded in the status file and as an event. Returns whether it
    /// verified.
    ///
    /// # Errors
    ///
    /// [`CellError::Keys`] with no object store, or while a batch runs.
    pub async fn daily_snapshot(&mut self) -> Result<bool, CellError> {
        let s = self.snapshots.clone().ok_or(keys_err("no object store"))?;
        if self.busy()? {
            return Err(keys_err("an erasure batch runs"));
        }
        let e = Epoch(self.store.epoch());
        let checked = async {
            let id = self.upload_rows(&s).await?;
            self.check_fetched(&s, id, e).await
        }
        .await;
        let ok = checked.is_ok();
        self.note(fstp_obs::SnapshotTrigger::Daily, ok);
        self.daily_last = Some((fstp_obs::snapshot_status::now(), ok));
        Ok(ok)
    }

    /// Whether a daily snapshot is due now: an object store is configured
    /// and the schedule of `fstp_obs::snapshot_status::due` says so.
    pub fn daily_due(&self) -> bool {
        self.snapshots.is_some()
            && fstp_obs::snapshot_status::due(
                self.daily_started,
                self.daily_last,
                fstp_obs::snapshot_status::now(),
            )
    }

    /// Writes the snapshot status file into `dir` after each snapshot
    /// from now on (ADR-012 record of lane L27, row "Status file").
    #[must_use]
    pub fn with_snapshot_status(mut self, dir: std::path::PathBuf) -> Self {
        self.snapshot_status = Some(dir);
        self
    }

    /// Step 6: destroys `R(e)` and keeps the digest of its receipt.
    async fn destroy(&mut self, e: Epoch) -> Result<ErasureEvent, CellError> {
        let row = self
            .store
            .roots
            .get(&e.0)
            .cloned()
            .ok_or(keys_err("old root"))?;
        let request = self.record_call(KeyCall::Destroy, e.0).await?;
        let receipt = with_request(request, || self.custody.destroy(&row.root))
            .await
            .map_err(CellError::Custody)?;
        let digest = fstp_crypto::sha256(&receipt.0);
        let mut chain = self.chain.clone();
        plan::apply_destroy(&mut chain, e, digest).map_err(|_| keys_err("planner step"))?;
        self.store.receipts.insert(e.0, digest);
        self.store.persist.dirty.roots.insert(e.0);
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
            let (documents, workspaces) = self.record_completions(old, erased).await?;
            // ADR-007 (Daniel, 2026-11-23, decision 2; lane L39): the
            // sealed rows of the documents whose completion is now in the
            // ledger go in the flush after this step, never before. So do
            // the rows of the workspaces (F-017).
            self.store.persist.dirty.blobs.extend(documents);
            self.store.persist.dirty.workspaces.extend(workspaces);
            self.erased.extend(erased.iter().map(|d| d.0));
        }
        self.apply_durable(&step)?;
        Ok(ErasureEvent::CompletionRecorded { epoch: old })
    }

    /// Step 7, the erasure log (ADR-007 section "Built by lane L33", I-81):
    /// the destruction of epoch `old` completed the erasure of every text
    /// whose data key is in `erased` and that the log names. At most
    /// `MAX_TEXT_IDS` texts go in one record, each record under a fixed id
    /// of the epoch and its place, so a step repeated after a crash
    /// appends nothing twice.
    ///
    /// It gives the data key ids of the completed documents, whose sealed
    /// rows the next flush deletes (lane L39), and the proposals of the
    /// completed workspaces, whose rows it deletes too (F-017).
    async fn record_completions(
        &self,
        old: u64,
        erased: &[DekId],
    ) -> Result<(Vec<[u8; 16]>, Vec<[u8; 16]>), CellError> {
        let erased: BTreeSet<DekId> = erased.iter().copied().collect();
        let state = self.engine.state();
        let texts = self
            .store
            .texts
            .iter()
            .filter(|(id, t)| erased.contains(&t.dek) && state.erasure(**id).is_some())
            .map(|(id, _)| *id);
        // ADR-007 section "Built by lane L37": a document's entry is named
        // by its data key id, and a workspace's by its proposal id, which
        // is its key id (F-017).
        let kind_of = |d: &DekId| state.erasure(d.0).map(|e| e.kind);
        let documents = erased
            .iter()
            .filter(|d| kind_of(d) == Some(fstp_cell_core::ERASURE_KIND_DOCUMENT))
            .map(|d| d.0);
        let workspaces = erased
            .iter()
            .filter(|d| kind_of(d) == Some(fstp_cell_core::ERASURE_KIND_WORKSPACE))
            .map(|d| d.0);
        let completed_documents: Vec<[u8; 16]> = documents.clone().collect();
        let completed_workspaces: Vec<[u8; 16]> = workspaces.clone().collect();
        let ids: Vec<[u8; 16]> = texts
            .chain(documents)
            .chain(workspaces)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let epoch = u32::try_from(old)
            .map_err(|_| keys_err("epoch"))?
            .to_be_bytes();
        for (n, chunk) in ids.chunks(fstp_cell_core::codec::MAX_TEXT_IDS).enumerate() {
            let place = u16::try_from(n)
                .map_err(|_| keys_err("completion records"))?
                .to_be_bytes();
            let suffix = [
                b'd', b'n', place[0], place[1], epoch[0], epoch[1], epoch[2], epoch[3],
            ];
            self.record(
                KeyCommand::RecordErasuresCompleted {
                    epoch: old,
                    ids: chunk.to_vec(),
                },
                system_command_id(suffix),
            )
            .await?;
        }
        Ok((completed_documents, completed_workspaces))
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
            snapshot_id: None,
            signers: BTreeMap::new(),
            signer_rows: BTreeMap::new(),
            new_logins: None,
            new_displays: None,
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
    SealDocument {
        group: [u8; 16],
        id: [u8; 16],
        bytes: Vec<u8>,
        reply: ReplyTx<Result<Vec<u8>, CellError>>,
    },
    OpenDocument {
        id: [u8; 16],
        stored: Vec<u8>,
        reply: ReplyTx<Result<Plaintext, OpenRefusal>>,
    },
    EraseDocument {
        id: [u8; 16],
        cause: u16,
        by: fstp_domain::id::AccountId,
        reason: Option<[u8; 16]>,
        reply: ReplyTx<Result<(), CellError>>,
    },
    SealWorkspace {
        proposal: [u8; 16],
        bytes: Vec<u8>,
        reply: ReplyTx<Result<Vec<u8>, CellError>>,
    },
    OpenWorkspace {
        proposal: [u8; 16],
        stored: Vec<u8>,
        reply: ReplyTx<Result<Plaintext, OpenRefusal>>,
    },
    EraseWorkspace {
        proposal: [u8; 16],
        cause: u16,
        by: fstp_domain::id::AccountId,
        reply: ReplyTx<Result<bool, CellError>>,
    },
    Keystore {
        reply: ReplyTx<Keystore>,
    },
    Signer {
        purpose: Purpose,
        reply: ReplyTx<Result<CompositeSigningKey, CellError>>,
    },
    RotateSigner {
        purpose: Purpose,
        reply: ReplyTx<Result<Vec<u8>, CellError>>,
    },
    SetLoginEmail {
        account: fstp_domain::id::AccountId,
        email: String,
        reply: ReplyTx<Result<LoginEmailSet, CellError>>,
    },
    LoginAccount {
        email: String,
        reply: ReplyTx<Result<Option<fstp_domain::id::AccountId>, CellError>>,
    },
    LoginEmail {
        account: fstp_domain::id::AccountId,
        reply: ReplyTx<Result<Option<String>, CellError>>,
    },
    DeliveryDigestKey {
        reply: ReplyTx<Result<Option<fstp_dispatch::DigestKey>, CellError>>,
    },
    SetDisplayName {
        account: fstp_domain::id::AccountId,
        name: Option<String>,
        reply: ReplyTx<Result<DisplayNameSet, CellError>>,
    },
    DisplayNames {
        accounts: Vec<fstp_domain::id::AccountId>,
        reply: ReplyTx<DisplayNamesReply>,
    },
}

/// The reply of [`ErasureHandle::display_names`].
type DisplayNamesReply = Result<BTreeMap<fstp_domain::id::AccountId, String>, CellError>;

impl Request {
    /// Answers a request the task can no longer serve.
    fn refuse(self) {
        let gone = keys_err("the erasure task is not running");
        match self {
            Request::AddGroup { reply, .. } | Request::PutText { reply, .. } => {
                reply.send(Err(gone));
            }
            Request::OpenText { reply, .. } => reply.send(Err(OpenRefusal::Keys)),
            Request::SealDocument { reply, .. } => {
                reply.send(Err(keys_err("the erasure task is not running")))
            }
            Request::OpenDocument { reply, .. } => reply.send(Err(OpenRefusal::Keys)),
            Request::EraseDocument { reply, .. } => reply.send(Err(gone)),
            Request::SealWorkspace { reply, .. } => {
                reply.send(Err(keys_err("the erasure task is not running")))
            }
            Request::OpenWorkspace { reply, .. } => reply.send(Err(OpenRefusal::Keys)),
            Request::EraseWorkspace { reply, .. } => {
                reply.send(Err(keys_err("the erasure task is not running")))
            }
            Request::Signer { reply, .. } => reply.send(Err(gone)),
            Request::RotateSigner { reply, .. } => reply.send(Err(gone)),
            Request::SetLoginEmail { reply, .. } => reply.send(Err(gone)),
            Request::LoginAccount { reply, .. } => reply.send(Err(gone)),
            Request::LoginEmail { reply, .. } => reply.send(Err(gone)),
            Request::DeliveryDigestKey { reply } => reply.send(Err(gone)),
            Request::SetDisplayName { reply, .. } => {
                reply.send(Err(keys_err("the erasure task is not running")))
            }
            Request::DisplayNames { reply, .. } => {
                reply.send(Err(keys_err("the erasure task is not running")))
            }
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

    /// Seals `bytes` as document `id` in `group`
    /// ([`ErasureRunner::seal_document`]): the stored envelope, once its
    /// data key is durable.
    ///
    /// # Errors
    ///
    /// The runner's refusal, or [`CellError::Keys`] once the task ended.
    pub async fn seal_document(
        &self,
        group: [u8; 16],
        id: [u8; 16],
        bytes: Vec<u8>,
    ) -> Result<Vec<u8>, CellError> {
        self.ask(|reply| Request::SealDocument {
            group,
            id,
            bytes,
            reply,
        })
        .await
        .unwrap_or(Err(keys_err("the erasure task is not running")))
    }

    /// Opens the stored document envelope `stored` of data key `id`
    /// ([`ErasureRunner::open_document`]).
    ///
    /// # Errors
    ///
    /// The runner's [`OpenRefusal`], or [`OpenRefusal::Keys`] once the
    /// task ended.
    pub async fn open_document(
        &self,
        id: [u8; 16],
        stored: Vec<u8>,
    ) -> Result<Plaintext, OpenRefusal> {
        self.ask(|reply| Request::OpenDocument { id, stored, reply })
            .await
            .unwrap_or(Err(OpenRefusal::Keys))
    }

    /// Requests the erasure of document `id` with `cause` as `by` asked
    /// ([`ErasureRunner::erase_document`], ADR-007 section "Built by lane
    /// L37"). The task then runs the batch that destroys its key.
    ///
    /// # Errors
    ///
    /// The runner's refusal, or [`CellError::Keys`] once the task ended.
    pub async fn erase_document(
        &self,
        id: [u8; 16],
        cause: u16,
        by: fstp_domain::id::AccountId,
        reason: Option<[u8; 16]>,
    ) -> Result<(), CellError> {
        self.ask(|reply| Request::EraseDocument {
            id,
            cause,
            by,
            reason,
            reply,
        })
        .await
        .unwrap_or(Err(keys_err("the erasure task is not running")))
    }

    /// Seals `bytes` as a workspace value of `proposal` under its own
    /// workspace key ([`ErasureRunner::seal_workspace`], F-017): the stored
    /// form, once the key is durable.
    ///
    /// # Errors
    ///
    /// The runner's refusal, or [`CellError::Keys`] once the task ended.
    pub async fn seal_workspace(
        &self,
        proposal: [u8; 16],
        bytes: Vec<u8>,
    ) -> Result<Vec<u8>, CellError> {
        self.ask(|reply| Request::SealWorkspace {
            proposal,
            bytes,
            reply,
        })
        .await
        .unwrap_or(Err(keys_err("the erasure task is not running")))
    }

    /// Opens the stored workspace value `stored` of `proposal`
    /// ([`ErasureRunner::open_workspace`], F-017).
    ///
    /// # Errors
    ///
    /// The runner's [`OpenRefusal`], or [`OpenRefusal::Keys`] once the
    /// task ended.
    pub async fn open_workspace(
        &self,
        proposal: [u8; 16],
        stored: Vec<u8>,
    ) -> Result<Plaintext, OpenRefusal> {
        self.ask(|reply| Request::OpenWorkspace {
            proposal,
            stored,
            reply,
        })
        .await
        .unwrap_or(Err(OpenRefusal::Keys))
    }

    /// Requests the erasure of the workspace of `proposal` with `cause` as
    /// `by` asked ([`ErasureRunner::erase_workspace`], F-017). `false` when
    /// the proposal has no workspace key. The task then runs the batch that
    /// destroys the key, and deletes the rows after it.
    ///
    /// # Errors
    ///
    /// The runner's refusal, or [`CellError::Keys`] once the task ended.
    pub async fn erase_workspace(
        &self,
        proposal: [u8; 16],
        cause: u16,
        by: fstp_domain::id::AccountId,
    ) -> Result<bool, CellError> {
        self.ask(|reply| Request::EraseWorkspace {
            proposal,
            cause,
            by,
            reply,
        })
        .await
        .unwrap_or(Err(keys_err("the erasure task is not running")))
    }

    /// A copy of the durable keystore, or `None` once the task ended.
    pub async fn keystore(&self) -> Option<Keystore> {
        self.ask(|reply| Request::Keystore { reply }).await
    }

    /// The current signing key of `purpose`, created at its first use
    /// ([`ErasureRunner::ensure_signer`], [`ErasureRunner::signer`]). The
    /// notice companion key comes from here (M9 decision CD4).
    ///
    /// # Errors
    ///
    /// The runner's refusal, or [`CellError::Keys`] once the task ended.
    pub async fn signer(&self, purpose: Purpose) -> Result<CompositeSigningKey, CellError> {
        self.ask(|reply| Request::Signer { purpose, reply })
            .await
            .unwrap_or(Err(keys_err("the erasure task is not running")))
    }

    /// Replaces the signing key of `purpose` with a new generation
    /// ([`ErasureRunner::rotate_signer`]) and gives its public key.
    ///
    /// # Errors
    ///
    /// The runner's refusal, or [`CellError::Keys`] once the task ended.
    pub async fn rotate_signer(&self, purpose: Purpose) -> Result<Vec<u8>, CellError> {
        self.ask(|reply| Request::RotateSigner { purpose, reply })
            .await
            .unwrap_or(Err(keys_err("the erasure task is not running")))
    }

    /// Makes `email` the login email of `account`
    /// ([`ErasureRunner::set_login_email`]).
    ///
    /// # Errors
    ///
    /// The runner's refusal, or [`CellError::Keys`] once the task ended.
    pub async fn set_login_email(
        &self,
        account: fstp_domain::id::AccountId,
        email: String,
    ) -> Result<LoginEmailSet, CellError> {
        self.ask(|reply| Request::SetLoginEmail {
            account,
            email,
            reply,
        })
        .await
        .unwrap_or(Err(keys_err("the erasure task is not running")))
    }

    /// The account whose login email is `email`
    /// ([`ErasureRunner::login_account`]).
    ///
    /// # Errors
    ///
    /// The runner's refusal, or [`CellError::Keys`] once the task ended.
    pub async fn login_account(
        &self,
        email: String,
    ) -> Result<Option<fstp_domain::id::AccountId>, CellError> {
        self.ask(|reply| Request::LoginAccount { email, reply })
            .await
            .unwrap_or(Err(keys_err("the erasure task is not running")))
    }

    /// The login email of `account` ([`ErasureRunner::login_email`]).
    ///
    /// # Errors
    ///
    /// The runner's refusal, or [`CellError::Keys`] once the task ended.
    pub async fn login_email(
        &self,
        account: fstp_domain::id::AccountId,
    ) -> Result<Option<String>, CellError> {
        self.ask(|reply| Request::LoginEmail { account, reply })
            .await
            .unwrap_or(Err(keys_err("the erasure task is not running")))
    }

    /// The delivery body digest key of the App chain `Lookup` key, or
    /// `None` while the cell has no `Lookup` group (ADR-026 record of lane
    /// L5). The `Lookup` key itself never leaves the task.
    ///
    /// # Errors
    ///
    /// The runner's refusal, or [`CellError::Keys`] once the task ended.
    pub async fn delivery_digest_key(&self) -> Result<Option<fstp_dispatch::DigestKey>, CellError> {
        self.ask(|reply| Request::DeliveryDigestKey { reply })
            .await
            .unwrap_or(Err(keys_err("the erasure task is not running")))
    }

    /// Sets or clears the display name of `account`
    /// ([`ErasureRunner::set_display_name`], SA-11, lane L26).
    ///
    /// # Errors
    ///
    /// The runner's refusal, or [`CellError::Keys`] once the task ended.
    pub async fn set_display_name(
        &self,
        account: fstp_domain::id::AccountId,
        name: Option<String>,
    ) -> Result<DisplayNameSet, CellError> {
        self.ask(|reply| Request::SetDisplayName {
            account,
            name,
            reply,
        })
        .await
        .unwrap_or(Err(keys_err("the erasure task is not running")))
    }

    /// The display names of those of `accounts` that have one
    /// ([`ErasureRunner::display_names`], SA-11, lane L26). The caller
    /// checks the read's clearance first.
    ///
    /// # Errors
    ///
    /// The runner's refusal, or [`CellError::Keys`] once the task ended.
    pub async fn display_names(
        &self,
        accounts: Vec<fstp_domain::id::AccountId>,
    ) -> Result<BTreeMap<fstp_domain::id::AccountId, String>, CellError> {
        self.ask(|reply| Request::DisplayNames { accounts, reply })
            .await
            .unwrap_or(Err(keys_err("the erasure task is not running")))
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
            Wake::Request(Some(req)) => serve(&mut runner, req).await,
            Wake::Tick if work => {
                // A failed step keeps the runner's state, so it is
                // retried after one tick (`ErasureRunner::step`).
                cooling = runner.step().await.is_err();
            }
            Wake::Tick => {
                cooling = false;
                // ADR-012 record of lane L27: the daily snapshot, only while
                // no batch runs. It records its own outcome.
                if runner.daily_due() {
                    let _ = runner.daily_snapshot().await;
                }
            }
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

/// `done` once the runner's rows are durable: a change whose flush fails
/// is refused, and the next flush writes it (`tables`).
async fn durable<C: Custody, T>(
    runner: &mut ErasureRunner<C>,
    done: Result<T, CellError>,
) -> Result<T, CellError> {
    let flushed = runner.flush().await;
    let out = done?;
    flushed?;
    Ok(out)
}

async fn serve<C: Custody>(runner: &mut ErasureRunner<C>, req: Request) {
    match req {
        Request::AddGroup { group, reply } => {
            let done = runner.add_group(group);
            reply.send(durable(runner, done).await);
        }
        Request::PutText {
            group,
            id,
            text,
            reply,
        } => {
            let done = runner.put_text(group, id, &text);
            reply.send(durable(runner, done).await);
        }
        Request::OpenText { id, reply } => {
            let state = runner.engine.state();
            let opened = runner
                .open_text(&state, id)
                .map(|t| Box::new(t) as Plaintext);
            reply.send(opened);
        }
        Request::SealDocument {
            group,
            id,
            bytes,
            reply,
        } => {
            let done = runner.seal_document(group, id, &bytes);
            reply.send(durable(runner, done).await);
        }
        Request::OpenDocument { id, stored, reply } => {
            let opened = runner
                .open_document(id, &stored)
                .map(|t| Box::new(t) as Plaintext);
            reply.send(opened);
        }
        Request::EraseDocument {
            id,
            cause,
            by,
            reason,
            reply,
        } => {
            let done = runner.erase_document(id, cause, by, reason).await;
            reply.send(durable(runner, done).await);
        }
        Request::SealWorkspace {
            proposal,
            bytes,
            reply,
        } => {
            let done = runner.seal_workspace(proposal, &bytes).await;
            reply.send(durable(runner, done).await);
        }
        Request::OpenWorkspace {
            proposal,
            stored,
            reply,
        } => {
            let opened = runner
                .open_workspace(proposal, &stored)
                .map(|t| Box::new(t) as Plaintext);
            reply.send(opened);
        }
        Request::EraseWorkspace {
            proposal,
            cause,
            by,
            reply,
        } => {
            let done = runner.erase_workspace(proposal, cause, by).await;
            reply.send(durable(runner, done).await);
        }
        Request::Keystore { reply } => reply.send(runner.keystore().clone()),
        Request::Signer { purpose, reply } => {
            let made = runner.ensure_signer(purpose).await;
            let made = durable(runner, made).await;
            reply.send(made.and_then(|_| runner.signer(purpose)));
        }
        Request::RotateSigner { purpose, reply } => {
            let done = runner.rotate_signer(purpose).await;
            reply.send(durable(runner, done).await);
        }
        Request::SetLoginEmail {
            account,
            email,
            reply,
        } => {
            let done = runner.set_login_email(account, &email);
            reply.send(durable(runner, done).await);
        }
        Request::LoginAccount { email, reply } => reply.send(runner.login_account(&email)),
        Request::LoginEmail { account, reply } => {
            let state = runner.engine.state();
            reply.send(runner.login_email(&state, account));
        }
        Request::DeliveryDigestKey { reply } => reply.send(runner.delivery_digest_key()),
        Request::SetDisplayName {
            account,
            name,
            reply,
        } => {
            let done = runner.set_display_name(account, name.as_deref()).await;
            reply.send(durable(runner, done).await);
        }
        Request::DisplayNames { accounts, reply } => {
            let state = runner.engine.state();
            reply.send(runner.display_names(&state, &accounts));
        }
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
