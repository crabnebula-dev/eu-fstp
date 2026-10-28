//! The erasure planner (M3 design section 3.5, I-81, ADR-007). Pure.
//!
//! Status: W0 stub. The state types and the step list follow the design.
//! `plan_erasure`, `next` and `apply` refuse with
//! [`KeyFoldError::NotImplemented`]. The designed signatures of
//! `plan_erasure` and `next` are infallible. They return a `Result` here
//! until lane W2f restores them, so a stub never answers "nothing to do".

use std::collections::{BTreeMap, BTreeSet};

use crate::hierarchy::{DekId, Epoch, GroupId};

/// The state of one key group.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GroupState {
    /// The group generation.
    pub generation: u32,
    /// The data keys sealed in the group.
    pub members: BTreeSet<DekId>,
}

/// A request to erase data keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErasureRequest {
    /// The ledger sequence of the request.
    pub requested_at_seq: u64,
}

/// The state of one root epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootState {
    /// The current root.
    Active,
    /// A root being replaced.
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
    /// A plan exists.
    Planned,
    /// Groups are resealed.
    Resealed,
    /// The new epoch is committed.
    Committed,
    /// A snapshot under the new epoch is verified.
    SnapshotVerified,
    /// The old root is destroyed.
    Destroyed,
}

/// The key state of one chain.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChainState {
    epoch: Epoch,
    groups: BTreeMap<GroupId, GroupState>,
    destroying: BTreeMap<DekId, ErasureRequest>,
    roots: BTreeMap<Epoch, RootState>,
    phase: Phase,
}

impl ChainState {
    /// The state of a fresh chain whose first root has epoch `epoch`.
    pub fn genesis(epoch: Epoch) -> ChainState {
        ChainState {
            epoch,
            roots: BTreeMap::from([(epoch, RootState::Active)]),
            ..ChainState::default()
        }
    }

    /// The current root epoch.
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Where an erasure run stands.
    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// The number of groups, data keys under erasure and roots.
    pub fn sizes(&self) -> (usize, usize, usize) {
        (self.groups.len(), self.destroying.len(), self.roots.len())
    }
}

/// One step of an erasure run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// Create new groups.
    NewGroups {
        /// The new groups.
        groups: Vec<GroupId>,
    },
    /// Reseal a group without the erased keys, in batches of at most 256.
    Reseal {
        /// The group.
        group: GroupId,
        /// The keys that stay.
        keep: Vec<DekId>,
    },
    /// Create a new root epoch.
    NewEpoch(Epoch),
    /// Rewrap every group under the new epoch.
    RewrapGroups(Epoch),
    /// Commit the new epoch.
    Commit(Epoch),
    /// Take a snapshot under the new epoch.
    Snapshot(Epoch),
    /// Verify that snapshot.
    VerifySnapshot(Epoch),
    /// Destroy the old root in custody.
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

/// Why the key fold refused a step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyFoldError {
    /// The planner is a W0 stub. It names the operation.
    NotImplemented(&'static str),
}

/// Plans the erasure of `batch`.
pub fn plan_erasure(s: &ChainState, batch: &BTreeSet<DekId>) -> Result<ErasurePlan, KeyFoldError> {
    let _ = (s, batch);
    Err(KeyFoldError::NotImplemented(
        "fstp_keys::erasure::plan_erasure",
    ))
}

/// The next step of the running erasure, if any.
pub fn next(s: &ChainState) -> Result<Option<Step>, KeyFoldError> {
    let _ = s;
    Err(KeyFoldError::NotImplemented("fstp_keys::erasure::next"))
}

/// Folds a completed step into the state.
pub fn apply(s: &mut ChainState, done: &Step) -> Result<(), KeyFoldError> {
    let _ = (s, done);
    Err(KeyFoldError::NotImplemented("fstp_keys::erasure::apply"))
}
