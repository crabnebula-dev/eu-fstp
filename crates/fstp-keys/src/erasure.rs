//! The erasure planner (M3 design section 3.5, I-81, R-KY-02, ADR-004
//! part 2 "Erasure construction", ADR-007). Pure.
//!
//! One rotation on a chain, from epoch `e` to `e + 1`, runs the seven
//! steps of ADR-004 part 2:
//!
//! 1. [`ChainState::request`] records a request. The key is refused for
//!    open from here on. A request on an idle chain starts a rotation at
//!    once. A request while a rotation runs joins the next one.
//! 2. [`Step::NewGroups`] and one [`Step::Reseal`] per affected group.
//! 3. [`Step::NewEpoch`] and [`Step::RewrapGroups`].
//! 4. [`Step::Commit`].
//! 5. [`Step::Snapshot`] and [`Step::VerifySnapshot`].
//! 6. [`Step::DestroyRoot`] of the old epoch.
//! 7. [`Step::Complete`], only after the destroy.
//!
//! A group is affected when it holds a key of the batch, or when it is a
//! keyed digest group (`Lookup`, `CredLookup` or `Match`) with a subject
//! in the batch (G24).
//!
//! The shell persists the state at the durable points: each request and
//! each step from `Commit` on. Steps 2 and 3 become durable only with the
//! commit, so [`ChainState::restart`] resumes a run stored before its
//! commit from its first step, with the same batch.
//!
//! # Admissions while a rotation runs
//!
//! New text and document keys keep flowing while a rotation runs, so a
//! busy chain is never starved of writes. The rule:
//!
//! - A data key or digest subject joins a group the running batch does
//!   not affect at any phase. That group keeps its generation, and
//!   `RewrapGroups` re-seals its secret under the new epoch anyway.
//! - It joins an affected group only after `Commit`, into the group's new
//!   generation. Before `Commit`, the `Reseal` keep lists are fixed, so a
//!   key added then would stay sealed to the generation that dies with
//!   the old root. It is refused with [`KeyFoldError::RunInFlight`].
//! - A new group is added only while idle or after `Commit`. Before
//!   `Commit`, its secret would be sealed under the old epoch, which
//!   step 6 destroys.
//!
//! # Purposes
//!
//! A group added with [`ChainState::add_group_for`] carries its purpose
//! (ADR-004 part 2 "Chains"). A `Document` group holds one data key. The
//! `Ledger` group never takes part in an erasure, so a request for a
//! ledger key is refused with [`KeyFoldError::NotErasable`].
//!
//! `plan_erasure` and `next` keep the `Result` of the W0 stub, so the
//! callers in `fstp-celltest` compile unchanged. Neither ever returns an
//! error for a state this module built, except `plan_erasure` for a key
//! the chain does not hold. Design section 3.5 gives them infallible
//! signatures, which is a deviation recorded in the lane report.

use std::collections::{BTreeMap, BTreeSet};

use crate::hierarchy::{DekId, Epoch, GroupId, Purpose};

/// The most data keys one group holds (ADR-004 part 2 "Chains").
pub const GROUP_LIMIT: usize = 256;

/// The most data keys one `Document` group holds (ADR-004 part 2
/// "Chains": "A `Document` group holds one").
pub const DOCUMENT_GROUP_LIMIT: usize = 1;

/// The most keys one `Reseal` step names (design section 3.5).
pub const RESEAL_BATCH: usize = 256;

/// The receipt digest that [`apply`] records for a [`Step::DestroyRoot`]
/// when the shell has not handed the planner the custody receipt digest.
/// The shell calls [`apply_destroy`] with the real digest instead.
pub const NO_RECEIPT_DIGEST: [u8; 32] = [0u8; 32];

/// What a group holds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum GroupKind {
    /// Data keys sealed to the group key (`Text`, `Document`, and the
    /// like).
    #[default]
    DataKeys,
    /// A keyed digest key over the plaintext of its subjects (`Lookup`,
    /// `CredLookup`, `Match`). It holds no data key.
    KeyedDigest,
}

/// The state of one key group.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GroupState {
    /// The committed group generation.
    pub generation: u32,
    /// The data keys sealed in the group.
    pub members: BTreeSet<DekId>,
    /// What the group holds.
    pub kind: GroupKind,
    /// The data keys whose plaintext a keyed digest group digests. Empty
    /// for a data key group.
    pub subjects: BTreeSet<DekId>,
    /// The purpose of the group, when it was added with one.
    pub purpose: Option<Purpose>,
}

impl GroupState {
    /// The most data keys the group may hold.
    #[must_use]
    pub fn limit(&self) -> usize {
        match self.purpose {
            Some(Purpose::Document) => DOCUMENT_GROUP_LIMIT,
            _ => GROUP_LIMIT,
        }
    }
}

/// A recorded erasure request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErasureRequest {
    /// The ledger sequence of the request.
    pub requested_at_seq: u64,
}

/// The state of one root epoch (ADR-004 part 2 "Epochs").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootState {
    /// The current root.
    Active,
    /// The root being replaced, from the commit of its successor until
    /// its destroy.
    Retiring,
    /// A destroyed root, with its custody receipt digest.
    Destroyed([u8; 32]),
}

/// Where an erasure run stands.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Phase {
    /// No erasure is running.
    #[default]
    Idle,
    /// A plan exists, and its steps 2 and 3 are in progress.
    Planned,
    /// Every affected group is resealed and every group secret re-wrapped
    /// under the new epoch, in process memory.
    Resealed,
    /// The new epoch is committed.
    Committed,
    /// A snapshot under the new epoch is verified.
    SnapshotVerified,
    /// The old root is destroyed.
    Destroyed,
}

/// The running rotation.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Run {
    /// The keys it erases.
    batch: BTreeSet<DekId>,
    /// Its steps, in order.
    steps: Vec<Step>,
    /// How many steps are done.
    done: usize,
}

/// The key state of one chain.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChainState {
    epoch: Epoch,
    groups: BTreeMap<GroupId, GroupState>,
    destroying: BTreeMap<DekId, ErasureRequest>,
    roots: BTreeMap<Epoch, RootState>,
    phase: Phase,
    run: Option<Run>,
}

/// One step of an erasure run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// Create generation `gen + 1` of each affected group.
    NewGroups {
        /// The affected groups.
        groups: Vec<GroupId>,
    },
    /// Seal the surviving siblings of a group to its new generation, in
    /// batches of at most 256.
    Reseal {
        /// The group.
        group: GroupId,
        /// The keys that stay.
        keep: Vec<DekId>,
    },
    /// Create the new root epoch in custody, draw its seal key and wrap
    /// it.
    NewEpoch(Epoch),
    /// Re-seal every live group secret of the chain under the new epoch.
    RewrapGroups(Epoch),
    /// Commit the new rows in one transaction.
    Commit(Epoch),
    /// Take a keystore snapshot under the new epoch.
    Snapshot(Epoch),
    /// Verify that snapshot.
    VerifySnapshot(Epoch),
    /// Destroy the old root in custody and keep the receipt.
    DestroyRoot(Epoch),
    /// Record completion after the destroy receipt.
    Complete {
        /// The new epoch.
        epoch: Epoch,
        /// The erased keys.
        erased: Vec<DekId>,
    },
}

/// The plan for one batch of erasure requests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErasurePlan {
    /// The steps in order.
    pub steps: Vec<Step>,
}

/// Why the key fold refused a call. A refused call leaves the state
/// unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyFoldError {
    /// Kept for the W0 callers that match on it. No call here returns it.
    NotImplemented(&'static str),
    /// No erasure run is in flight, so no step can fold in.
    NoRun,
    /// The step is not the next step of the running erasure.
    NotNext,
    /// The group is not on this chain.
    UnknownGroup,
    /// A group with this id already exists.
    GroupExists,
    /// The data key is not a live data key of this chain.
    UnknownDataKey,
    /// The data key already belongs to a group, or is under erasure.
    AlreadyAdmitted,
    /// The group holds as many data keys as it may: [`GROUP_LIMIT`], or
    /// [`DOCUMENT_GROUP_LIMIT`] for a `Document` group.
    GroupFull,
    /// The group is a keyed digest group where a data key group is
    /// needed, or the reverse.
    WrongGroupKind,
    /// The running erasure has not committed yet, and the call would add
    /// a group, or a key to a group the batch affects. So a run never
    /// misses a key it must re-seal or re-wrap.
    RunInFlight,
    /// The key is in the `Ledger` group, which never takes part in an
    /// erasure (ADR-004 part 2 "Chains").
    NotErasable,
    /// An epoch or generation counter would overflow.
    Overflow,
}

impl std::fmt::Display for KeyFoldError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            KeyFoldError::NotImplemented(op) => op,
            KeyFoldError::NoRun => "no erasure run is in flight",
            KeyFoldError::NotNext => "the step is not the next step of the run",
            KeyFoldError::UnknownGroup => "the group is not on this chain",
            KeyFoldError::GroupExists => "the group already exists",
            KeyFoldError::UnknownDataKey => "the data key is not a live key of this chain",
            KeyFoldError::AlreadyAdmitted => "the data key already belongs to a group",
            KeyFoldError::GroupFull => "the group holds the most data keys it may",
            KeyFoldError::WrongGroupKind => "the group is of the wrong kind",
            KeyFoldError::RunInFlight => "an erasure run that affects this has not committed",
            KeyFoldError::NotErasable => "the key is in the ledger group, which is never erased",
            KeyFoldError::Overflow => "an epoch or generation counter would overflow",
        };
        f.write_str(s)
    }
}

impl std::error::Error for KeyFoldError {}

impl ChainState {
    /// The state of a fresh chain whose first root has epoch `epoch`
    /// (ADR-004 part 2: provisioning creates epoch 1).
    #[must_use]
    pub fn genesis(epoch: Epoch) -> ChainState {
        ChainState {
            epoch,
            roots: BTreeMap::from([(epoch, RootState::Active)]),
            ..ChainState::default()
        }
    }

    /// The current root epoch.
    #[must_use]
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Where an erasure run stands.
    #[must_use]
    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// The number of groups, data keys under erasure and roots.
    #[must_use]
    pub fn sizes(&self) -> (usize, usize, usize) {
        (self.groups.len(), self.destroying.len(), self.roots.len())
    }

    /// The committed generation of `group`, if the chain holds it.
    #[must_use]
    pub fn generation(&self, group: GroupId) -> Option<u32> {
        self.groups.get(&group).map(|g| g.generation)
    }

    /// The state of `group`, if the chain holds it.
    #[must_use]
    pub fn group(&self, group: GroupId) -> Option<&GroupState> {
        self.groups.get(&group)
    }

    /// The state of root epoch `epoch`, if the chain knows it.
    #[must_use]
    pub fn root_state(&self, epoch: Epoch) -> Option<RootState> {
        self.roots.get(&epoch).copied()
    }

    /// The group that holds the live data key `dek`, if any.
    #[must_use]
    pub fn group_of(&self, dek: DekId) -> Option<GroupId> {
        self.groups
            .iter()
            .find(|(_, g)| g.members.contains(&dek))
            .map(|(id, _)| *id)
    }

    /// Whether the in-memory index refuses to open `dek` (design section
    /// 3.4). It refuses a key under erasure from its request on, and any
    /// key that is no live data key of the chain.
    #[must_use]
    pub fn refused_for_open(&self, dek: DekId) -> bool {
        self.destroying.contains_key(&dek) || self.group_of(dek).is_none()
    }

    /// Whether `dek` has a recorded erasure request that is not complete.
    #[must_use]
    pub fn is_requested(&self, dek: DekId) -> bool {
        self.destroying.contains_key(&dek)
    }

    /// The keys of the running batch, empty when idle.
    #[must_use]
    pub fn running_batch(&self) -> BTreeSet<DekId> {
        self.run
            .as_ref()
            .map(|r| r.batch.clone())
            .unwrap_or_default()
    }

    /// Adds a data key group at generation 1, with no purpose recorded.
    ///
    /// # Errors
    ///
    /// Refuses while a run that has not committed is in flight, and
    /// refuses an existing group.
    pub fn add_group(&mut self, group: GroupId) -> Result<(), KeyFoldError> {
        self.insert_group(group, GroupKind::DataKeys, BTreeSet::new(), None)
    }

    /// Adds a data key group of `purpose` at generation 1. A `Document`
    /// group then holds one data key, and a key of the `Ledger` group is
    /// never erased (ADR-004 part 2 "Chains").
    ///
    /// # Errors
    ///
    /// As [`ChainState::add_group`], and refuses a keyed digest purpose
    /// (`Lookup`, `CredLookup`, `Match`) with
    /// [`KeyFoldError::WrongGroupKind`]: those groups hold no data keys.
    pub fn add_group_for(&mut self, group: GroupId, purpose: Purpose) -> Result<(), KeyFoldError> {
        if purpose.is_keyed_digest() {
            return Err(KeyFoldError::WrongGroupKind);
        }
        self.insert_group(group, GroupKind::DataKeys, BTreeSet::new(), Some(purpose))
    }

    /// Adds a keyed digest group (`Lookup`, `CredLookup` or `Match`) at
    /// generation 1, which digests the plaintext of `subjects` (G24).
    ///
    /// # Errors
    ///
    /// Refuses while a run that has not committed is in flight, an
    /// existing group, and a subject that is no live data key of the
    /// chain.
    pub fn add_digest_group(
        &mut self,
        group: GroupId,
        subjects: &[DekId],
    ) -> Result<(), KeyFoldError> {
        let mut set = BTreeSet::new();
        for s in subjects {
            if self.refused_for_open(*s) {
                return Err(KeyFoldError::UnknownDataKey);
            }
            set.insert(*s);
        }
        self.insert_group(group, GroupKind::KeyedDigest, set, None)
    }

    fn insert_group(
        &mut self,
        group: GroupId,
        kind: GroupKind,
        subjects: BTreeSet<DekId>,
        purpose: Option<Purpose>,
    ) -> Result<(), KeyFoldError> {
        if self.before_commit() {
            return Err(KeyFoldError::RunInFlight);
        }
        if self.groups.contains_key(&group) {
            return Err(KeyFoldError::GroupExists);
        }
        self.groups.insert(
            group,
            GroupState {
                generation: 1,
                members: BTreeSet::new(),
                kind,
                subjects,
                purpose,
            },
        );
        Ok(())
    }

    /// Whether a run is in flight and has not reached its `Commit`.
    fn before_commit(&self) -> bool {
        self.run.is_some() && matches!(self.phase, Phase::Planned | Phase::Resealed)
    }

    /// Whether `g` takes part in the running batch and that batch has not
    /// committed, so no key may join it yet.
    fn frozen(&self, g: &GroupState) -> bool {
        self.before_commit()
            && self
                .run
                .as_ref()
                .is_some_and(|r| ChainState::affected(g, &r.batch))
    }

    /// Admits the data key `dek` to the current generation of the data
    /// key group `group`. While a rotation runs, a group the batch does
    /// not affect admits at any phase, and an affected group admits from
    /// the `Commit` on, into its new generation.
    ///
    /// # Errors
    ///
    /// Refuses an affected group before the running batch commits, an
    /// unknown group, a keyed digest group, a full group, and a key that
    /// already belongs to a group or is under erasure.
    pub fn admit(&mut self, group: GroupId, dek: DekId) -> Result<(), KeyFoldError> {
        if self.destroying.contains_key(&dek) || self.group_of(dek).is_some() {
            return Err(KeyFoldError::AlreadyAdmitted);
        }
        let g = self.groups.get(&group).ok_or(KeyFoldError::UnknownGroup)?;
        if g.kind != GroupKind::DataKeys {
            return Err(KeyFoldError::WrongGroupKind);
        }
        if self.frozen(g) {
            return Err(KeyFoldError::RunInFlight);
        }
        if g.members.len() >= g.limit() {
            return Err(KeyFoldError::GroupFull);
        }
        let g = self
            .groups
            .get_mut(&group)
            .ok_or(KeyFoldError::UnknownGroup)?;
        g.members.insert(dek);
        Ok(())
    }

    /// Adds the live data key `dek` to the subjects of the keyed digest
    /// group `group`, as a new account's email joins the `Lookup` index.
    /// The rule of [`ChainState::admit`] applies while a rotation runs.
    ///
    /// # Errors
    ///
    /// Refuses an affected group before the running batch commits, an
    /// unknown group, a data key group, and a key that is no live data
    /// key of the chain.
    pub fn add_digest_subject(&mut self, group: GroupId, dek: DekId) -> Result<(), KeyFoldError> {
        if self.refused_for_open(dek) {
            return Err(KeyFoldError::UnknownDataKey);
        }
        let g = self.groups.get(&group).ok_or(KeyFoldError::UnknownGroup)?;
        if g.kind != GroupKind::KeyedDigest {
            return Err(KeyFoldError::WrongGroupKind);
        }
        if self.frozen(g) {
            return Err(KeyFoldError::RunInFlight);
        }
        let g = self
            .groups
            .get_mut(&group)
            .ok_or(KeyFoldError::UnknownGroup)?;
        g.subjects.insert(dek);
        Ok(())
    }

    /// Step 1: records an erasure request for `dek` at ledger sequence
    /// `seq`. The key is refused for open from here on. On an idle chain
    /// the request starts a rotation at once. While a rotation runs, it
    /// joins the next one. A second request for a key under erasure
    /// changes nothing.
    ///
    /// # Errors
    ///
    /// Refuses a key that is no live data key of the chain, and a key of
    /// the `Ledger` group with [`KeyFoldError::NotErasable`].
    pub fn request(&mut self, dek: DekId, seq: u64) -> Result<(), KeyFoldError> {
        if self.destroying.contains_key(&dek) {
            return Ok(());
        }
        let group = self.group_of(dek).ok_or(KeyFoldError::UnknownDataKey)?;
        if self.is_ledger(group) {
            return Err(KeyFoldError::NotErasable);
        }
        let mut next = self.clone();
        next.destroying.insert(
            dek,
            ErasureRequest {
                requested_at_seq: seq,
            },
        );
        if next.run.is_none() {
            next.start_queued()?;
        }
        *self = next;
        Ok(())
    }

    /// The state to resume from after a process restart, given the state
    /// stored at the last durable point. Steps 2 and 3 live in process
    /// memory until the commit, so a run stored before its commit starts
    /// again from its first step, with the same batch.
    #[must_use]
    pub fn restart(&self) -> ChainState {
        let mut next = self.clone();
        if let Some(run) = next.run.as_mut() {
            let commit = run
                .steps
                .iter()
                .position(|s| matches!(s, Step::Commit(_)))
                .unwrap_or(0);
            if run.done <= commit {
                run.done = 0;
                next.phase = Phase::Planned;
            }
        }
        next
    }

    /// The requested keys that wait for the next run.
    fn queued(&self) -> BTreeSet<DekId> {
        let running = self.running_batch();
        self.destroying
            .keys()
            .filter(|k| !running.contains(k))
            .copied()
            .collect()
    }

    /// Starts a run over the queued requests, if any.
    fn start_queued(&mut self) -> Result<(), KeyFoldError> {
        let batch = self.queued();
        let plan = plan_erasure(self, &batch)?;
        if plan.steps.is_empty() {
            self.run = None;
            self.phase = Phase::Idle;
        } else {
            self.run = Some(Run {
                batch,
                steps: plan.steps,
                done: 0,
            });
            self.phase = Phase::Planned;
        }
        Ok(())
    }

    /// Whether `group` is the `Ledger` group.
    fn is_ledger(&self, group: GroupId) -> bool {
        self.groups
            .get(&group)
            .is_some_and(|g| g.purpose == Some(Purpose::Ledger))
    }

    /// Whether group `g` is affected by a run that erases `batch`.
    fn affected(g: &GroupState, batch: &BTreeSet<DekId>) -> bool {
        !g.members.is_disjoint(batch) || !g.subjects.is_disjoint(batch)
    }

    /// Folds the commit of `epoch` for `batch`: the new epoch becomes
    /// active, the old one retires, and every affected group moves to its
    /// next generation without the erased keys.
    fn commit(&mut self, epoch: Epoch, batch: &BTreeSet<DekId>) -> Result<(), KeyFoldError> {
        for g in self.groups.values_mut() {
            if ChainState::affected(g, batch) {
                g.generation = g.generation.checked_add(1).ok_or(KeyFoldError::Overflow)?;
                g.members.retain(|k| !batch.contains(k));
                g.subjects.retain(|k| !batch.contains(k));
            }
        }
        let old = self.epoch;
        self.roots.insert(old, RootState::Retiring);
        self.roots.insert(epoch, RootState::Active);
        self.epoch = epoch;
        Ok(())
    }
}

/// Plans the erasure of `batch` from the committed state `s`: the steps
/// of ADR-004 part 2 for one rotation from the current epoch. An empty
/// batch plans no step.
///
/// # Errors
///
/// Refuses a key that is no data key of the chain, a key of the `Ledger`
/// group, and an epoch that would overflow.
pub fn plan_erasure(s: &ChainState, batch: &BTreeSet<DekId>) -> Result<ErasurePlan, KeyFoldError> {
    if batch.is_empty() {
        return Ok(ErasurePlan { steps: Vec::new() });
    }
    for k in batch {
        let group = s.group_of(*k).ok_or(KeyFoldError::UnknownDataKey)?;
        if s.is_ledger(group) {
            return Err(KeyFoldError::NotErasable);
        }
    }
    let old = s.epoch;
    let new = Epoch(old.0.checked_add(1).ok_or(KeyFoldError::Overflow)?);
    let affected: Vec<(GroupId, &GroupState)> = s
        .groups
        .iter()
        .filter(|(_, g)| ChainState::affected(g, batch))
        .map(|(id, g)| (*id, g))
        .collect();
    let mut steps = vec![Step::NewGroups {
        groups: affected.iter().map(|(id, _)| *id).collect(),
    }];
    for (id, g) in &affected {
        let keep: Vec<DekId> = g.members.difference(batch).copied().collect();
        if keep.is_empty() {
            steps.push(Step::Reseal {
                group: *id,
                keep: Vec::new(),
            });
        }
        for chunk in keep.chunks(RESEAL_BATCH) {
            steps.push(Step::Reseal {
                group: *id,
                keep: chunk.to_vec(),
            });
        }
    }
    steps.extend([
        Step::NewEpoch(new),
        Step::RewrapGroups(new),
        Step::Commit(new),
        Step::Snapshot(new),
        Step::VerifySnapshot(new),
        Step::DestroyRoot(old),
        Step::Complete {
            epoch: new,
            erased: batch.iter().copied().collect(),
        },
    ]);
    Ok(ErasurePlan { steps })
}

/// The next step of the running erasure, or `None` when the chain is
/// idle.
///
/// # Errors
///
/// Never fails. The `Result` keeps the W0 signature.
pub fn next(s: &ChainState) -> Result<Option<Step>, KeyFoldError> {
    Ok(s.run.as_ref().and_then(|r| r.steps.get(r.done).cloned()))
}

/// Folds a completed step into the state. Only the step [`next`] gives
/// folds in. Any other step is refused, and a refused step leaves the
/// state unchanged. The completion of a run starts the next one over the
/// requests that arrived meanwhile.
///
/// A [`Step::DestroyRoot`] folded here records [`NO_RECEIPT_DIGEST`].
/// The shell uses [`apply_destroy`], which records the custody receipt
/// digest.
///
/// # Errors
///
/// Returns [`KeyFoldError::NoRun`] on an idle chain and
/// [`KeyFoldError::NotNext`] for any step other than the next one.
pub fn apply(s: &mut ChainState, done: &Step) -> Result<(), KeyFoldError> {
    apply_with_receipt(s, done, NO_RECEIPT_DIGEST)
}

/// Folds the destroy of root epoch `epoch` with the digest of its custody
/// receipt (step 6). `Step::DestroyRoot(epoch)` must be the next step.
///
/// # Errors
///
/// As [`apply`].
pub fn apply_destroy(
    s: &mut ChainState,
    epoch: Epoch,
    receipt_digest: [u8; 32],
) -> Result<(), KeyFoldError> {
    apply_with_receipt(s, &Step::DestroyRoot(epoch), receipt_digest)
}

fn apply_with_receipt(
    s: &mut ChainState,
    done: &Step,
    receipt_digest: [u8; 32],
) -> Result<(), KeyFoldError> {
    let mut next = s.clone();
    let Some(run) = next.run.as_mut() else {
        return Err(KeyFoldError::NoRun);
    };
    if run.steps.get(run.done) != Some(done) {
        return Err(KeyFoldError::NotNext);
    }
    run.done = run.done.checked_add(1).ok_or(KeyFoldError::Overflow)?;
    let finished = run.done >= run.steps.len();
    let batch = run.batch.clone();
    match done {
        Step::NewGroups { .. } | Step::Reseal { .. } | Step::NewEpoch(_) => {}
        Step::RewrapGroups(_) => next.phase = Phase::Resealed,
        Step::Commit(e) => {
            next.commit(*e, &batch)?;
            next.phase = Phase::Committed;
        }
        Step::Snapshot(_) => {}
        Step::VerifySnapshot(_) => next.phase = Phase::SnapshotVerified,
        Step::DestroyRoot(e) => {
            next.roots.insert(*e, RootState::Destroyed(receipt_digest));
            next.phase = Phase::Destroyed;
        }
        Step::Complete { erased, .. } => {
            for k in erased {
                next.destroying.remove(k);
            }
        }
    }
    if finished {
        next.run = None;
        next.phase = Phase::Idle;
        next.start_queued()?;
    }
    *s = next;
    Ok(())
}
