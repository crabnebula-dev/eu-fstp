//! The reference key hierarchy, sealed formats and erasure plan (I-75,
//! I-80, I-81, R-ID-03, R-SW-02, R-CR-01). Lane W1d owns this file.
//!
//! Written from ADR-004 parts 1 and 2, ADR-012 and design section 3. It
//! shares only the type names `Chain` and `Purpose` with `fstp-keys`, and
//! no logic: the production crates were W0 stubs when it was written. It
//! holds five parts.
//!
//! - **The symbolic hierarchy** ([`Row`], [`closure`]). Rows are what a
//!   keystore, a WAL segment, a backup or a snapshot can hold. Custody
//!   roots are the only keys that are not rows. The closure is what an
//!   attacker opens from a set of rows and the live custody roots. It is
//!   the judge of M-SHRED (I-81).
//! - **The reference planner** ([`RefPlan`], [`RefStep`]). It follows the
//!   seven steps of ADR-004 "Erasure construction" in order. M-SHRED runs
//!   it as its reference backend, and its [`Defect`] twins are the teeth.
//! - **The sealed key format** of ADR-004 part 1 ([`RefSealedKey`],
//!   [`seal_key`], [`open_key`]), over the hybrid KEM oracle of
//!   [`crate::reference::hybrid`].
//! - **The backup container** of ADR-012 ([`RefContainerHeader`],
//!   [`seal_container`], [`decode_container`]). ADR-012 marks these bytes
//!   as interim, pending Daniel, and so is this part of the reference.
//!   ADR-012 also leaves open which key seals a vault keystore snapshot.
//!   The reference follows its first draft, the CellBackup chain only, and
//!   that reading is interim, pending Daniel, too.
//! - **Cell erasure** ([`cell_erasure_destroys`]): the custody keys that
//!   design section 3.7 and ADR-004 part 2 destroy for one cell.
//!
//! **Sealed blobs: a seam, not a part.** Design section 3.2 names
//! `SealedBlob` and a `BlobHeader`, but no ADR fixes the blob header bytes
//! yet. Lane W2f records them in ADR-004 at first use, and this reference
//! then follows that record, as [`purpose_code`] does for the purpose
//! table. Until then the reference has no blob format, so no test compares
//! production blobs against guessed bytes ([`SEALED_BLOB_SEAM`]).
//!
//! AES-256-GCM goes through `fstp_crypto::aead`, because the ADR-004 nonce
//! rule refuses every other AEAD entry point in the workspace, test code
//! included. HKDF is the HMAC evaluation of the hybrid reference.

use std::collections::BTreeSet;

use fstp_keys::{Chain, Purpose};

use crate::reference::hybrid::{
    self as h, CIPHERTEXT_LEN, MLKEM_CT_LEN, OracleError, PUBLIC_KEY_LEN, RefKeyPair,
};

// ---------------------------------------------------------------------------
// The symbolic hierarchy.

/// A custody root instance. Every `create_root` call makes a new one, so
/// a retried creation never shares an id with the first attempt.
pub type RootId = u8;
/// A group secret instance (level 2). Each new generation, and each retry
/// of one, is a new instance.
pub type SecretId = u8;
/// A data key (level 3) of the universe.
pub type KeyIx = u8;
/// A key group of the universe.
pub type GroupIx = u8;

/// One stored row, as a keystore, a WAL segment, a backup or a snapshot
/// can hold it (ADR-004 part 2, "Hierarchy as built").
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Row {
    /// The epoch seal key `S(e)` that goes with custody root `root`,
    /// wrapped by that root (`keystore.root`).
    WrappedSeal {
        /// The custody root that wraps it.
        root: RootId,
    },
    /// The group secret instance `secret`, sealed under the epoch seal key
    /// of `under` (`keystore.group_key`).
    GroupSecret {
        /// The group secret instance.
        secret: SecretId,
        /// The root whose epoch seal key seals it.
        under: RootId,
    },
    /// The data key `dek`, sealed to the group secret instance `secret`
    /// through the hybrid KEM (`keystore.data_key`).
    DataKey {
        /// The data key.
        dek: KeyIx,
        /// The group secret instance it is sealed to.
        secret: SecretId,
    },
}

/// What an attacker opens from a set of rows and the live custody roots.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Closure {
    /// The epoch seal keys it unwraps, by root.
    pub seal_keys: BTreeSet<RootId>,
    /// The group secret instances it opens.
    pub secrets: BTreeSet<SecretId>,
    /// The data keys it opens.
    pub deks: BTreeSet<KeyIx>,
}

/// The closure of `rows` under the custody roots in `live_roots`.
///
/// A live root unwraps its own epoch seal key wherever a wrapped copy is.
/// An epoch seal key opens every group secret sealed under it. A group
/// secret opens every data key sealed to it. The hierarchy has no other
/// edge, so one pass per level reaches the fixed point.
pub fn closure<'a>(
    rows: impl IntoIterator<Item = &'a Row>,
    live_roots: &BTreeSet<RootId>,
) -> Closure {
    let rows: Vec<&Row> = rows.into_iter().collect();
    let mut out = Closure::default();
    for row in &rows {
        if let Row::WrappedSeal { root } = row
            && live_roots.contains(root)
        {
            out.seal_keys.insert(*root);
        }
    }
    for row in &rows {
        if let Row::GroupSecret { secret, under } = row
            && out.seal_keys.contains(under)
        {
            out.secrets.insert(*secret);
        }
    }
    for row in &rows {
        if let Row::DataKey { dek, secret } = row
            && out.secrets.contains(secret)
        {
            out.deks.insert(*dek);
        }
    }
    out
}

/// Whether `dek` opens from `rows` under `live_roots`.
pub fn opens<'a>(
    rows: impl IntoIterator<Item = &'a Row>,
    live_roots: &BTreeSet<RootId>,
    dek: KeyIx,
) -> bool {
    closure(rows, live_roots).deks.contains(&dek)
}

/// The group layout of a universe: the data keys of each group, in group
/// order. Groups and keys are numbered from zero.
///
/// A group with no data keys and a non-empty subject list is a keyed
/// digest group (design section 3.5, G24): a `Lookup`, `CredLookup` or
/// `Match` key. Its group secret is the HMAC key itself. Its subjects are
/// the data keys whose plaintext it digests, such as an account's sealed
/// login email. ADR-004 part 2 replaces the group in every rotation that
/// erases one of its subjects.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Layout {
    /// The keys of each group.
    pub groups: Vec<Vec<KeyIx>>,
    /// The digest subjects of each group, by group index. A missing entry
    /// or an empty one means the group digests nothing.
    pub subjects: Vec<Vec<KeyIx>>,
}

impl Layout {
    /// The M-SHRED universe (design section 14.2): two groups of two data
    /// keys each, `g0 = {k0, k1}` and `g1 = {k2, k3}`. Beside them is one
    /// keyed digest group `g2` with no data keys, whose subjects are `k0`
    /// and `k2` (G24): for example the `Lookup` key over two login emails.
    pub fn m_shred() -> Layout {
        Layout {
            groups: vec![vec![0, 1], vec![2, 3], Vec::new()],
            subjects: vec![Vec::new(), Vec::new(), vec![0, 2]],
        }
    }

    /// One `Document` group with one data key (ADR-004 part 2, "Chains":
    /// "A `Document` group holds one"), beside one group of two other
    /// vault keys (R-ID-03).
    pub fn document() -> Layout {
        Layout {
            groups: vec![vec![0], vec![1, 2]],
            subjects: Vec::new(),
        }
    }

    /// Every data key, in order.
    pub fn keys(&self) -> Vec<KeyIx> {
        self.groups.iter().flatten().copied().collect()
    }

    /// The digest subjects of group `g`: empty for a group of data keys.
    pub fn subjects_of(&self, g: GroupIx) -> &[KeyIx] {
        self.subjects
            .get(usize::from(g))
            .map_or(&[][..], Vec::as_slice)
    }

    /// Whether group `g` is a keyed digest group.
    pub fn is_digest(&self, g: GroupIx) -> bool {
        !self.subjects_of(g).is_empty()
    }

    /// The number of groups, as a group index bound.
    pub fn group_count(&self) -> GroupIx {
        GroupIx::try_from(self.groups.len()).unwrap_or(GroupIx::MAX)
    }

    /// The group of `dek` at genesis.
    pub fn group_of(&self, dek: KeyIx) -> Option<GroupIx> {
        self.groups
            .iter()
            .position(|g| g.contains(&dek))
            .and_then(|i| GroupIx::try_from(i).ok())
    }
}

// ---------------------------------------------------------------------------
// The reference planner.

/// One step of an erasure run, in the reference's own small ids. It
/// mirrors `fstp_keys::erasure::Step` one to one.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RefStep {
    /// Step 2: create generation `gen + 1` of each affected group.
    NewGroups(Vec<GroupIx>),
    /// Step 2: seal the surviving siblings of `group` to its new
    /// generation, at most 256 per step.
    Reseal {
        /// The affected group.
        group: GroupIx,
        /// The keys that stay.
        keep: Vec<KeyIx>,
    },
    /// Step 3: create `R(e+1)` in custody, draw `S(e+1)` and wrap it.
    NewEpoch(u64),
    /// Step 3: re-seal every live group secret of the chain under `S(e+1)`.
    RewrapGroups(u64),
    /// Step 4: commit the new rows in one transaction.
    Commit(u64),
    /// Step 5: take a keystore snapshot under the new epoch.
    Snapshot(u64),
    /// Step 5: verify that snapshot under `R(e+1)`.
    VerifySnapshot(u64),
    /// Step 6: destroy the old root epoch in custody and keep the receipt.
    DestroyRoot(u64),
    /// Step 7: record completion, after the receipt.
    Complete {
        /// The new epoch.
        epoch: u64,
        /// The erased keys.
        erased: Vec<KeyIx>,
    },
}

impl RefStep {
    /// Whether the step calls custody (create or destroy a root).
    pub fn calls_custody(&self) -> bool {
        matches!(self, RefStep::NewEpoch(_) | RefStep::DestroyRoot(_))
    }

    /// Whether a crash after the step keeps its effect on the planner
    /// state. Steps 2 and 3 become durable only with the commit of step 4
    /// ("Commit the new rows in one transaction"). Every later step stores
    /// its phase as it completes.
    pub fn is_durable(&self) -> bool {
        matches!(
            self,
            RefStep::Commit(_)
                | RefStep::Snapshot(_)
                | RefStep::VerifySnapshot(_)
                | RefStep::DestroyRoot(_)
                | RefStep::Complete { .. }
        )
    }
}

/// A seeded planner defect, for the M-SHRED teeth (design section 14.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Defect {
    /// The affected groups keep their generation: no `NewGroups`, no
    /// `Reseal`, and the old generation is re-wrapped under `S(e+1)`.
    GroupNotRotated,
    /// The old epoch is destroyed before the commit of the new one.
    DestroyBeforeCommit,
    /// Completion is recorded before the destroy receipt.
    CompleteBeforeReceipt,
    /// A request that arrives while a run is in flight is ignored, so it
    /// never joins the next run (ADR-004 part 2 coalescing).
    DropsMidRunRequest,
    /// A restart forgets the queued requests ("A crash at any step loses
    /// nothing", ADR-004 part 2).
    ForgetsQueueOnRestart,
    /// `Reseal` drops only the smallest erased key of its group and seals
    /// every other erased key of that group to the new generation.
    ResealsAllButOneErased,
    /// A keyed digest group is not replaced when a rotation erases one of
    /// its subjects (design section 3.5, G24).
    DigestNotRotated,
}

/// The running batch of the reference planner.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RefRun {
    /// The keys being erased.
    pub batch: BTreeSet<KeyIx>,
    /// The planned steps, in order.
    pub steps: Vec<RefStep>,
    /// How many of them are done.
    pub done: usize,
}

/// The state of the reference planner for one chain.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RefPlan {
    /// The committed root epoch.
    pub epoch: u64,
    /// The live members of each group.
    pub members: Vec<BTreeSet<KeyIx>>,
    /// The live digest subjects of each group (G24). Empty for a group of
    /// data keys.
    pub subjects: Vec<BTreeSet<KeyIx>>,
    /// The committed generation of each group.
    pub generations: Vec<u32>,
    /// Requests recorded and waiting for the next run (they join the
    /// next batch, ADR-004 part 2).
    pub queued: BTreeSet<KeyIx>,
    /// The running batch, if any.
    pub run: Option<RefRun>,
    /// The seeded defect, if this is a teeth twin.
    pub defect: Option<Defect>,
}

/// Why the reference planner refused a step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanError(pub String);

impl RefPlan {
    /// A fresh chain at epoch 1 (ADR-004 "Provisioning creates epoch 1"),
    /// with every group at generation 1.
    pub fn genesis(layout: &Layout, defect: Option<Defect>) -> RefPlan {
        RefPlan {
            epoch: 1,
            members: layout
                .groups
                .iter()
                .map(|g| g.iter().copied().collect())
                .collect(),
            subjects: (0..layout.group_count())
                .map(|g| layout.subjects_of(g).iter().copied().collect())
                .collect(),
            generations: vec![1; layout.groups.len()],
            queued: BTreeSet::new(),
            run: None,
            defect,
        }
    }

    /// Step 1: record an erasure request and the intent row. The key is
    /// refused for open from here on.
    ///
    /// "Each erasure request starts a rotation of its chain at once"
    /// (ADR-004 part 2), so a request on an idle chain fixes its batch
    /// here, in the intent row. A request while a rotation runs joins the
    /// next one, which the completion of the running one starts. So every
    /// batch is fixed at a durable point, and a crash never changes the
    /// batch of a run in flight.
    pub fn request(&self, dek: KeyIx) -> Result<RefPlan, PlanError> {
        let known = self.members.iter().any(|m| m.contains(&dek));
        let running = self.run.as_ref().is_some_and(|r| r.batch.contains(&dek));
        if !known && !running && !self.queued.contains(&dek) {
            return Err(PlanError(format!("k{dek} is not a live data key")));
        }
        let mut next = self.clone();
        if self.run.is_some() && self.defect == Some(Defect::DropsMidRunRequest) {
            return Ok(next);
        }
        if !running {
            next.queued.insert(dek);
        }
        if next.run.is_none() {
            next.start_queued();
        }
        Ok(next)
    }

    /// Starts a run over the queued requests, if any.
    fn start_queued(&mut self) {
        let steps = self.plan_erasure(&self.queued);
        if !steps.is_empty() {
            self.run = Some(RefRun {
                batch: std::mem::take(&mut self.queued),
                steps,
                done: 0,
            });
        }
    }

    /// Whether a run that erases `batch` replaces group `g`: the group
    /// holds a key of the batch, or it is a keyed digest group with a
    /// subject in the batch (design section 3.5, G24).
    fn affected(&self, g: usize, batch: &BTreeSet<KeyIx>) -> bool {
        let holds = self.members.get(g).is_some_and(|m| !m.is_disjoint(batch));
        let digests = self.defect != Some(Defect::DigestNotRotated)
            && self.subjects.get(g).is_some_and(|s| !s.is_disjoint(batch));
        holds || digests
    }

    /// The keys `Reseal` keeps in group `g` for `batch`: its members that
    /// the batch does not erase. A keyed digest group keeps none, since it
    /// holds no data key. Its new HMAC key is recomputed over the live
    /// subjects by the shell, not resealed.
    fn keep(&self, g: GroupIx, batch: &BTreeSet<KeyIx>) -> Vec<KeyIx> {
        let Some(members) = self.members.get(usize::from(g)) else {
            return Vec::new();
        };
        let mut keep: BTreeSet<KeyIx> = members.difference(batch).copied().collect();
        if self.defect == Some(Defect::ResealsAllButOneErased) {
            keep.extend(members.intersection(batch).skip(1).copied());
        }
        keep.into_iter().collect()
    }

    /// The steps of a run that erases `batch`, from this state.
    pub fn plan_erasure(&self, batch: &BTreeSet<KeyIx>) -> Vec<RefStep> {
        if batch.is_empty() {
            return Vec::new();
        }
        let affected: Vec<GroupIx> = (0..self.members.len())
            .filter(|g| self.affected(*g, batch))
            .filter_map(|g| GroupIx::try_from(g).ok())
            .collect();
        let old = self.epoch;
        let new = old.saturating_add(1);
        let mut steps = Vec::new();
        if self.defect != Some(Defect::GroupNotRotated) {
            steps.push(RefStep::NewGroups(affected.clone()));
            for g in &affected {
                steps.push(RefStep::Reseal {
                    group: *g,
                    keep: self.keep(*g, batch),
                });
            }
        }
        steps.push(RefStep::NewEpoch(new));
        steps.push(RefStep::RewrapGroups(new));
        if self.defect == Some(Defect::DestroyBeforeCommit) {
            steps.push(RefStep::DestroyRoot(old));
        }
        steps.push(RefStep::Commit(new));
        steps.push(RefStep::Snapshot(new));
        steps.push(RefStep::VerifySnapshot(new));
        let complete = RefStep::Complete {
            epoch: new,
            erased: batch.iter().copied().collect(),
        };
        match self.defect {
            Some(Defect::DestroyBeforeCommit) => steps.push(complete),
            Some(Defect::CompleteBeforeReceipt) => {
                steps.push(complete);
                steps.push(RefStep::DestroyRoot(old));
            }
            _ => {
                steps.push(RefStep::DestroyRoot(old));
                steps.push(complete);
            }
        }
        steps
    }

    /// The next step of the running batch, if any.
    pub fn next(&self) -> Option<RefStep> {
        self.run
            .as_ref()
            .and_then(|run| run.steps.get(run.done).cloned())
    }

    /// The state to resume from after a process restart, given the state
    /// stored at the last durable point. Steps 2 and 3 live in process
    /// memory until the commit of step 4, so a run stored before its
    /// commit starts again from step 2, with the same batch.
    pub fn restart(&self) -> RefPlan {
        let mut next = self.clone();
        if self.defect == Some(Defect::ForgetsQueueOnRestart) {
            next.queued.clear();
        }
        if let Some(run) = next.run.as_mut() {
            let commit = run
                .steps
                .iter()
                .position(|s| matches!(s, RefStep::Commit(_)))
                .unwrap_or(0);
            if run.done <= commit {
                run.done = 0;
            }
        }
        next
    }

    /// Folds a completed step into the state. The completion of a run
    /// starts the next one over the requests queued meanwhile.
    pub fn apply(&self, done: &RefStep) -> Result<RefPlan, PlanError> {
        let mut next = self.clone();
        let Some(run) = next.run.as_mut() else {
            return Err(PlanError(format!("{done:?} with no run")));
        };
        if run.steps.get(run.done) != Some(done) {
            return Err(PlanError(format!(
                "{done:?} is not the next step {:?}",
                run.steps.get(run.done)
            )));
        }
        run.done = run.done.saturating_add(1);
        let batch = run.batch.clone();
        let finished = run.done >= run.steps.len();
        if let RefStep::Commit(e) = done {
            let affected: Vec<bool> = (0..self.members.len())
                .map(|g| self.affected(g, &batch))
                .collect();
            next.epoch = *e;
            let groups = next
                .members
                .iter_mut()
                .zip(next.subjects.iter_mut())
                .zip(next.generations.iter_mut());
            for (((members, subjects), generation), hit) in groups.zip(affected) {
                if hit {
                    *generation = generation.saturating_add(1);
                    members.retain(|k| !batch.contains(k));
                    subjects.retain(|k| !batch.contains(k));
                }
            }
        }
        if finished {
            next.run = None;
            next.start_queued();
        }
        Ok(next)
    }
}

// ---------------------------------------------------------------------------
// The sealed key format (ADR-004 part 1, "Sealed key format").

/// The magic of a sealed key.
pub const KEY_MAGIC: &[u8; 4] = b"FSK1";
/// The magic of a seal context.
pub const CTX_MAGIC: &[u8; 4] = b"FSC1";
/// The format version.
pub const FORMAT_VERSION: u8 = 1;
/// The `kem` code of the ADR-004 combiner.
pub const KEM_HYBRID: u16 = 1;
/// The `aead` code of AES-256-GCM.
pub const AEAD_AES_256_GCM: u16 = 1;
/// The KDF label of the key-encryption key.
pub const SEAL_INFO: &[u8; 12] = b"fstp-seal-v1";
/// Length of a sealed key header.
pub const HEADER_LEN: usize = 30;
/// Length of a seal context.
pub const CTX_LEN: usize = 58;
/// Length of the wrapped data key: 32 bytes and the 16-byte tag.
pub const WRAPPED_LEN: usize = 48;
/// Length of a nonce.
pub const NONCE_LEN: usize = 12;
/// Length of a sealed key.
pub const SEALED_KEY_LEN: usize = HEADER_LEN + CIPHERTEXT_LEN + NONCE_LEN + WRAPPED_LEN;

/// The ADR-004 chain code: App 1, Vault 2, CellBackup 3, ClusterBackup 4,
/// ControlPlane 5.
pub const fn chain_code(chain: Chain) -> u8 {
    match chain {
        Chain::App => 1,
        Chain::Vault => 2,
        Chain::CellBackup => 3,
        Chain::ClusterBackup => 4,
        Chain::ControlPlane => 5,
    }
}

/// The ADR-004 purpose code of `purpose`.
///
/// ADR-004 says "Purpose codes come from `fstp_keys::Purpose`. Record at
/// first use: the purpose code table, which is frozen once written." The
/// table is not recorded yet, so the reference knows no code and answers
/// `None`. Every check that needs a code then fails with the missing
/// record, never with a guessed value. The lane that records the table
/// copies it here.
pub const fn purpose_code(purpose: Purpose) -> Option<u8> {
    let _ = purpose;
    None
}

/// The header of a sealed key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RefHeader {
    /// The format version.
    pub version: u8,
    /// The KEM code.
    pub kem: u16,
    /// The AEAD code.
    pub aead: u16,
    /// The chain code.
    pub chain: u8,
    /// The group id.
    pub group: [u8; 16],
    /// The group generation.
    pub generation: u32,
}

impl RefHeader {
    /// The header ADR-004 writes for `ctx`.
    pub fn for_context(ctx: &RefContext) -> RefHeader {
        RefHeader {
            version: FORMAT_VERSION,
            kem: KEM_HYBRID,
            aead: AEAD_AES_256_GCM,
            chain: ctx.chain,
            group: ctx.group,
            generation: ctx.generation,
        }
    }

    /// The 30 header bytes.
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = Vec::with_capacity(HEADER_LEN);
        out.extend_from_slice(KEY_MAGIC);
        out.push(self.version);
        out.extend_from_slice(&self.kem.to_be_bytes());
        out.extend_from_slice(&self.aead.to_be_bytes());
        out.push(self.chain);
        out.extend_from_slice(&self.group);
        out.extend_from_slice(&self.generation.to_be_bytes());
        fixed(&out)
    }
}

/// The seal context `ctx`. It is not stored: the caller supplies it from
/// the row that names the key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RefContext {
    /// The owner: the cell id, the cluster id or the environment id.
    pub owner: [u8; 16],
    /// The chain code.
    pub chain: u8,
    /// The purpose code.
    pub purpose: u8,
    /// The group id.
    pub group: [u8; 16],
    /// The group generation.
    pub generation: u32,
    /// The object: the data key id.
    pub object: [u8; 16],
}

impl RefContext {
    /// The 58 context bytes.
    pub fn encode(&self) -> [u8; CTX_LEN] {
        let mut out = Vec::with_capacity(CTX_LEN);
        out.extend_from_slice(CTX_MAGIC);
        out.extend_from_slice(&self.owner);
        out.push(self.chain);
        out.push(self.purpose);
        out.extend_from_slice(&self.group);
        out.extend_from_slice(&self.generation.to_be_bytes());
        out.extend_from_slice(&self.object);
        fixed(&out)
    }
}

/// A decoded sealed key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefSealedKey {
    /// The header.
    pub header: RefHeader,
    /// The sender's ephemeral X25519 public key `E`.
    pub e: [u8; 32],
    /// The ML-KEM-768 ciphertext `ct_M`.
    pub ct_m: Vec<u8>,
    /// The AES-256-GCM nonce.
    pub nonce: [u8; NONCE_LEN],
    /// The wrapped data key and its tag.
    pub wrapped: [u8; WRAPPED_LEN],
}

/// Copies `src` into a fixed array. The callers only pass slices of the
/// right length, and a shorter one leaves trailing zeros.
fn fixed<const N: usize>(src: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    for (d, s) in out.iter_mut().zip(src) {
        *d = *s;
    }
    out
}

/// A cursor over input bytes that never reads past the end.
struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, tail) = self.rest.split_at_checked(n)?;
        self.rest = tail;
        Some(head)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).and_then(|b| b.first().copied())
    }

    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes(fixed(b)))
    }

    fn u32(&mut self) -> Option<u32> {
        self.take(4).map(|b| u32::from_be_bytes(fixed(b)))
    }

    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N).map(fixed)
    }
}

/// Decodes a sealed key as ADR-004 says: exactly 1210 bytes, the magic,
/// version 1, known codes. Any other input is refused.
pub fn decode_sealed_key(bytes: &[u8]) -> Option<RefSealedKey> {
    if bytes.len() != SEALED_KEY_LEN {
        return None;
    }
    let mut r = Reader { rest: bytes };
    if r.take(4)? != KEY_MAGIC {
        return None;
    }
    let header = RefHeader {
        version: r.u8()?,
        kem: r.u16()?,
        aead: r.u16()?,
        chain: r.u8()?,
        group: r.array()?,
        generation: r.u32()?,
    };
    if header.version != FORMAT_VERSION
        || header.kem != KEM_HYBRID
        || header.aead != AEAD_AES_256_GCM
        || !(1..=5).contains(&header.chain)
    {
        return None;
    }
    let e = r.array()?;
    let ct_m = r.take(MLKEM_CT_LEN)?.to_vec();
    let nonce = r.array()?;
    let wrapped = r.array()?;
    r.rest.is_empty().then_some(RefSealedKey {
        header,
        e,
        ct_m,
        nonce,
        wrapped,
    })
}

/// Encodes a sealed key in its one spelling.
pub fn encode_sealed_key(k: &RefSealedKey) -> Vec<u8> {
    let mut out = Vec::with_capacity(SEALED_KEY_LEN);
    out.extend_from_slice(&k.header.encode());
    out.extend_from_slice(&k.e);
    out.extend_from_slice(&k.ct_m);
    out.extend_from_slice(&k.nonce);
    out.extend_from_slice(&k.wrapped);
    out
}

/// The key-encryption key: HKDF-SHA-256 with an empty salt over `ss`,
/// info `"fstp-seal-v1" || header`, 32 bytes.
pub fn kek(ss: &[u8; 32], header: &[u8; HEADER_LEN]) -> Option<[u8; 32]> {
    let prk = h::hkdf_extract(&[], ss);
    let mut info = SEAL_INFO.to_vec();
    info.extend_from_slice(header);
    h::hkdf_expand(&prk, &info, 32).map(|v| fixed(&v))
}

/// The AAD of the wrapped data key: header then context.
pub fn key_aad(header: &[u8; HEADER_LEN], ctx: &RefContext) -> Vec<u8> {
    let mut aad = header.to_vec();
    aad.extend_from_slice(&ctx.encode());
    aad
}

/// Seals the data key `dek` to the hybrid public key `pk` in the FSK1
/// format, through the oracle KEM.
///
/// # Errors
///
/// Refuses when the oracle or the AEAD fails.
pub fn seal_key(
    pk: &[u8; PUBLIC_KEY_LEN],
    dek: &[u8; 32],
    ctx: &RefContext,
) -> Result<Vec<u8>, OracleError> {
    let (ct, ss) = h::encapsulate(pk)?;
    let header = RefHeader::for_context(ctx);
    let hb = header.encode();
    let k = kek(&ss, &hb).ok_or(OracleError("kek derivation"))?;
    let key = fstp_crypto::aead::Key::from_bytes(&k).map_err(|_| OracleError("kek import"))?;
    let sealed = fstp_crypto::aead::seal(&key, &key_aad(&hb, ctx), dek)
        .map_err(|_| OracleError("wrap the data key"))?;
    let (e, ct_m) = ct.split_at_checked(32).ok_or(OracleError("ciphertext"))?;
    Ok(encode_sealed_key(&RefSealedKey {
        header,
        e: fixed(e),
        ct_m: ct_m.to_vec(),
        nonce: sealed.nonce,
        wrapped: fixed(&sealed.body),
    }))
}

/// Opens a sealed key with the oracle key pair `kp`. The header's chain,
/// group and generation are compared with `ctx` before any
/// decapsulation, as ADR-004 says.
///
/// # Errors
///
/// Refuses a malformed key, a context mismatch and a failed open.
pub fn open_key(kp: &RefKeyPair, bytes: &[u8], ctx: &RefContext) -> Result<[u8; 32], OracleError> {
    let k = decode_sealed_key(bytes).ok_or(OracleError("sealed key decode"))?;
    if k.header.chain != ctx.chain
        || k.header.group != ctx.group
        || k.header.generation != ctx.generation
    {
        return Err(OracleError("sealed key header does not match the context"));
    }
    let mut ct = [0u8; CIPHERTEXT_LEN];
    for (d, s) in ct.iter_mut().zip(k.e.iter().chain(k.ct_m.iter())) {
        *d = *s;
    }
    let ss = kp.decapsulate(&ct)?;
    let hb = k.header.encode();
    let kk = kek(&ss, &hb).ok_or(OracleError("kek derivation"))?;
    let key = fstp_crypto::aead::Key::from_bytes(&kk).map_err(|_| OracleError("kek import"))?;
    let opened = fstp_crypto::aead::open(&key, &k.nonce, &key_aad(&hb, ctx), &k.wrapped)
        .map_err(|_| OracleError("wrapped data key did not open"))?;
    if opened.len() != 32 {
        return Err(OracleError("data key length"));
    }
    Ok(fixed(&opened))
}

// ---------------------------------------------------------------------------
// Sealed blobs (design section 3.2): a seam.

/// Why the reference has no sealed blob format. Design section 3.2 names
/// `SealedBlob { header: BlobHeader, nonce, body }`, but no ADR fixes the
/// `BlobHeader` bytes. Record at first use: lane W2f records them in
/// ADR-004, and this reference then follows that record.
pub const SEALED_BLOB_SEAM: &str = "fstp_celltest::reference::keys: no ADR fixes the BlobHeader bytes of a sealed blob (design section 3.2); lane W2f records them in ADR-004 at first use";

// ---------------------------------------------------------------------------
// The backup container (ADR-012 "Container format"). Interim, pending
// Daniel, as ADR-012 marks these bytes.

/// The magic of a backup container.
pub const CONTAINER_MAGIC: &[u8; 4] = b"FBC1";
/// Length of a container header.
pub const CONTAINER_HEADER_LEN: usize = 1259;
/// The only chunk size version 1 accepts: 1 MiB.
pub const CHUNK_SIZE: u32 = 1_048_576;
/// Container kind: a base backup file.
pub const KIND_BASE_BACKUP: u8 = 1;
/// Container kind: a WAL segment.
pub const KIND_WAL_SEGMENT: u8 = 2;
/// Container kind: a keystore snapshot.
pub const KIND_KEYSTORE_SNAPSHOT: u8 = 3;

/// A container header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefContainerHeader {
    /// The format version.
    pub version: u8,
    /// The AEAD code.
    pub aead: u16,
    /// The kind: 1 base backup, 2 WAL segment, 3 keystore snapshot.
    pub kind: u8,
    /// The chain code: CellBackup 3 or ClusterBackup 4.
    pub chain: u8,
    /// The owner: the cluster id or the cell id.
    pub owner: [u8; 16],
    /// The container id, also the data key id.
    pub container: [u8; 16],
    /// The part number.
    pub part: u32,
    /// The chunk size.
    pub chunk_size: u32,
    /// The data key in the FSK1 form, sealed to the chain's group key.
    pub sealed_key: Vec<u8>,
}

impl RefContainerHeader {
    /// The 1259 header bytes. A sealed key of the wrong length is padded
    /// or cut, which the decoder then refuses.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CONTAINER_HEADER_LEN);
        out.extend_from_slice(CONTAINER_MAGIC);
        out.push(self.version);
        out.extend_from_slice(&self.aead.to_be_bytes());
        out.push(self.kind);
        out.push(self.chain);
        out.extend_from_slice(&self.owner);
        out.extend_from_slice(&self.container);
        out.extend_from_slice(&self.part.to_be_bytes());
        out.extend_from_slice(&self.chunk_size.to_be_bytes());
        let key: [u8; SEALED_KEY_LEN] = fixed(&self.sealed_key);
        out.extend_from_slice(&key);
        out
    }

    /// Whether the data key is sealed through the hybrid KEM: an FSK1 key
    /// with the combiner's `kem` code, on the container's own chain
    /// (R-CR-01).
    pub fn key_is_hybrid(&self) -> bool {
        decode_sealed_key(&self.sealed_key)
            .is_some_and(|k| k.header.kem == KEM_HYBRID && k.header.chain == self.chain)
    }
}

/// One sealed chunk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefChunk {
    /// Whether this is the final chunk.
    pub last: bool,
    /// The nonce.
    pub nonce: [u8; NONCE_LEN],
    /// The ciphertext and its tag.
    pub body: Vec<u8>,
}

/// The AAD of chunk `index`: header, index, final flag.
pub fn chunk_aad(header: &[u8], index: u64, last: bool) -> Vec<u8> {
    let mut aad = header.to_vec();
    aad.extend_from_slice(&index.to_be_bytes());
    aad.push(u8::from(last));
    aad
}

/// Seals `plaintext` into a container under the data key `dek`, in
/// chunks of the header's chunk size. An empty plaintext gives one empty
/// final chunk.
///
/// # Errors
///
/// Refuses a chunk size of zero and an AEAD failure.
pub fn seal_container(
    header: &RefContainerHeader,
    dek: &[u8; 32],
    plaintext: &[u8],
) -> Result<Vec<u8>, OracleError> {
    let size = usize::try_from(header.chunk_size).map_err(|_| OracleError("chunk size"))?;
    if size == 0 {
        return Err(OracleError("chunk size"));
    }
    let key = fstp_crypto::aead::Key::from_bytes(dek).map_err(|_| OracleError("data key"))?;
    let hb = header.encode();
    let mut parts: Vec<&[u8]> = plaintext.chunks(size).collect();
    if parts.is_empty() {
        parts.push(&[]);
    }
    let count = parts.len();
    let mut out = hb.clone();
    for (i, part) in parts.into_iter().enumerate() {
        let last = i.saturating_add(1) == count;
        let index = u64::try_from(i).map_err(|_| OracleError("chunk index"))?;
        let sealed = fstp_crypto::aead::seal(&key, &chunk_aad(&hb, index, last), part)
            .map_err(|_| OracleError("chunk seal"))?;
        let len = u32::try_from(part.len()).map_err(|_| OracleError("chunk length"))?;
        out.push(u8::from(last));
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&sealed.nonce);
        out.extend_from_slice(&sealed.body);
    }
    Ok(out)
}

/// Decodes a container under the rules of ADR-012: version 1, AEAD 1, a
/// known kind and chain, chunk size 1 MiB, a non-final chunk of exactly
/// the chunk size, exactly one final chunk and nothing after it.
///
/// ADR-012 says "Decoder: one spelling only", but its rules admit two
/// spellings of a plaintext that is a whole number of chunks: the last
/// full chunk is final, or an empty final chunk follows it. The reference
/// takes the first as the one spelling, which [`seal_container`] writes.
/// So an empty final chunk is refused unless it is chunk 0, the spelling
/// of an empty plaintext. This reading is the reference's own until
/// ADR-012 records it (interim, pending Daniel).
///
/// The reference also refuses a data key that is not an FSK1 key of the
/// container's chain. ADR-012 says the field "is the data key in the
/// 1210-byte `FSK1` form", and R-CR-01 needs that form, so a container
/// whose key is sealed any other way never decodes.
pub fn decode_container(bytes: &[u8]) -> Option<(RefContainerHeader, Vec<RefChunk>)> {
    let mut r = Reader { rest: bytes };
    if r.take(4)? != CONTAINER_MAGIC {
        return None;
    }
    let header = RefContainerHeader {
        version: r.u8()?,
        aead: r.u16()?,
        kind: r.u8()?,
        chain: r.u8()?,
        owner: r.array()?,
        container: r.array()?,
        part: r.u32()?,
        chunk_size: r.u32()?,
        sealed_key: r.take(SEALED_KEY_LEN)?.to_vec(),
    };
    if header.version != FORMAT_VERSION
        || header.aead != AEAD_AES_256_GCM
        || !(1..=3).contains(&header.kind)
        || !(3..=4).contains(&header.chain)
        || header.chunk_size != CHUNK_SIZE
        || !header.key_is_hybrid()
    {
        return None;
    }
    let mut chunks = Vec::new();
    loop {
        let last = match r.u8()? {
            0 => false,
            1 => true,
            _ => return None,
        };
        let len = r.u32()?;
        if len > header.chunk_size || (!last && len != header.chunk_size) {
            return None;
        }
        if last && len == 0 && !chunks.is_empty() {
            return None;
        }
        let nonce = r.array()?;
        let body_len = usize::try_from(len).ok()?.checked_add(16)?;
        let body = r.take(body_len)?.to_vec();
        chunks.push(RefChunk { last, nonce, body });
        if last {
            break;
        }
    }
    r.rest.is_empty().then_some((header, chunks))
}

/// Opens a container under the data key `dek`.
pub fn open_container(bytes: &[u8], dek: &[u8; 32]) -> Option<Vec<u8>> {
    let (header, chunks) = decode_container(bytes)?;
    let hb = header.encode();
    let key = fstp_crypto::aead::Key::from_bytes(dek).ok()?;
    let mut out = Vec::new();
    for (i, c) in chunks.iter().enumerate() {
        let index = u64::try_from(i).ok()?;
        let pt = fstp_crypto::aead::open(&key, &c.nonce, &chunk_aad(&hb, index, c.last), &c.body)
            .ok()?;
        out.extend_from_slice(&pt);
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// The key volume of file custody (design section 3.3, Q32 A).

/// Linux `statfs` magic numbers of filesystems a key volume may use. The
/// rule is an allowlist: [`key_volume_accepted`] refuses every other
/// value, so an unknown copy-on-write, FUSE or network filesystem is
/// refused too. ADR-004 part 2 names only what `fstp-keyd` refuses
/// (btrfs, ZFS, overlayfs, network filesystems). The allowlist is the
/// reference's reading of that rule, since a denylist cannot name every
/// such filesystem.
///
/// The values were written from memory, as `EXT4_SUPER_MAGIC` and
/// `XFS_SUPER_MAGIC` of `linux/magic.h`. Record at first use: lane W2f
/// checks each against the kernel headers of the CI image and records the
/// list in ADR-004.
pub const ACCEPTED_VOLUMES: [(&str, u64); 2] = [("ext4", 0xef53), ("xfs", 0x5846_5342)];

/// Whether `fstp-keyd` accepts a key volume whose `statfs` type is
/// `magic`: only the filesystems of [`ACCEPTED_VOLUMES`].
pub fn key_volume_accepted(magic: u64) -> bool {
    ACCEPTED_VOLUMES.iter().any(|(_, m)| *m == magic)
}

/// Filesystems a key volume must not use, as examples for the tests. The
/// rule itself is the allowlist [`ACCEPTED_VOLUMES`], so this list need
/// not be complete. It holds the copy-on-write filesystems (btrfs, ZFS,
/// bcachefs), overlayfs, FUSE (sshfs, s3fs) and network filesystems.
///
/// The values were written from memory. All but ZFS are the `*_MAGIC`
/// values of the Linux `linux/magic.h` header. ZFS is not in the kernel
/// tree, so its value is `ZFS_SUPER_MAGIC` of the OpenZFS sources, not of
/// `linux/magic.h`. Record at first use: lane W2f checks each against the
/// kernel headers of the CI image and the OpenZFS sources, and records
/// them in ADR-004.
pub const REFUSED_VOLUMES: [(&str, u64); 12] = [
    ("btrfs", 0x9123_683e),
    ("zfs", 0x2fc1_2fc1),
    ("bcachefs", 0xca45_1a4e),
    ("overlayfs", 0x794c_7630),
    ("fuse", 0x6573_5546),
    ("nfs", 0x6969),
    ("smb", 0x517b),
    ("cifs", 0xff53_4d42),
    ("smb2", 0xfe53_4d42),
    ("ceph", 0x00c3_6400),
    ("afs", 0x5346_414f),
    ("9p", 0x0102_1997),
];

// ---------------------------------------------------------------------------
// Cell erasure (design section 3.7, ADR-004 part 2, R-SW-02).

/// One custody key that a cell erasure destroys.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CellCustodyKey {
    /// A live root instance of one of the cell's chains.
    Root {
        /// The chain.
        chain: Chain,
        /// The root instance.
        root: RootId,
    },
    /// The cell CA signing key.
    CellCa,
}

/// The chains a cell erasure destroys (design section 3.7 step 1).
pub const CELL_CHAINS: [Chain; 3] = [Chain::App, Chain::Vault, Chain::CellBackup];

/// The custody keys a cell erasure destroys, given the live root
/// instances of each chain. ADR-004 part 2: cell erasure "destroys the
/// cell CA key together with every live root epoch of the cell's App,
/// Vault and CellBackup chains", and the confirmation lists every destroy
/// receipt. So the list is the cell CA key and every live root of those
/// three chains: every epoch of a chain caught mid-rotation, and every
/// orphan root of a crashed rotation. A root of any other chain is not
/// the cell's and is never listed.
pub fn cell_erasure_destroys(live: &[(Chain, BTreeSet<RootId>)]) -> BTreeSet<CellCustodyKey> {
    let mut out = BTreeSet::from([CellCustodyKey::CellCa]);
    for (chain, roots) in live {
        if CELL_CHAINS.contains(chain) {
            out.extend(roots.iter().map(|root| CellCustodyKey::Root {
                chain: *chain,
                root: *root,
            }));
        }
    }
    out
}
