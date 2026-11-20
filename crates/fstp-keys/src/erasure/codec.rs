//! The stored form of a [`ChainState`]: the chain state row of the cell
//! keystore (`keystore.chain`, ADR-004 "Decided by Daniel, 2026-11-20").
//! Lane L3 `prod/keystore-pg`.
//!
//! The chain state is the planner's whole view of a chain: its epoch,
//! groups with their members and subjects, the erasure requests, the root
//! states, the phase and the running batch with its steps. A restart reads
//! it back and resumes through [`ChainState::restart`]. It holds ids,
//! counters and receipt digests only, and no key material.
//!
//! Interim, pending Daniel: the bytes are this lane's own.
//!
//! ```text
//! state   = "FKC1" | version u8 = 1 | epoch u64 | phase u8
//!           | n u32 | group* | n u32 | request* | n u32 | root*
//!           | run u8 (0 none, 1 some) | [run]
//! group   = id 16 | generation u32 | kind u8 | purpose u8 (0 none)
//!           | n u32 | member 16* | n u32 | subject 16*
//! request = dek 16 | seq u64
//! root    = epoch u64 | state u8 | [receipt digest 32, when state = 3]
//! run     = n u32 | dek 16* | n u32 | step* | done u32
//! step    = 1 | n u32 | group 16*          NewGroups
//!         | 2 | group 16 | n u32 | dek 16* Reseal
//!         | 3..8 | epoch u64                NewEpoch, RewrapGroups, Commit,
//!                                          Snapshot, VerifySnapshot,
//!                                          DestroyRoot
//!         | 9 | epoch u64 | n u32 | dek 16* Complete
//! ```
//!
//! Integers are big-endian. Groups, members, subjects, requests, roots and
//! the batch are in strictly increasing order, so the decoder admits one
//! spelling only. The lists inside a step keep the planner's order, and
//! the round trip of [`encode`] pins them. `done` is at most the number of
//! steps. Bytes after the run are refused. Fuzzed (`chain_state_decode`).

use std::collections::{BTreeMap, BTreeSet};

use super::{ChainState, ErasureRequest, GroupKind, GroupState, Phase, RootState, Run, Step};
use crate::hierarchy::{DekId, Epoch, GroupId, Purpose};

/// The magic of a stored chain state.
pub const STATE_MAGIC: [u8; 4] = *b"FKC1";
/// The only version.
pub const STATE_VERSION: u8 = 1;
/// The longest stored chain state the decoder reads: 64 MiB.
pub const MAX_STATE_LEN: usize = 64 * 1024 * 1024;

/// Why a stored chain state did not decode. It names the rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateError {
    /// The input ends early.
    Truncated,
    /// The input breaks the named rule.
    Malformed(&'static str),
}

impl std::fmt::Display for StateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StateError::Truncated => f.write_str("the stored chain state is truncated"),
            StateError::Malformed(rule) => {
                write!(f, "the stored chain state breaks the {rule} rule")
            }
        }
    }
}

impl std::error::Error for StateError {}

const fn phase_code(p: Phase) -> u8 {
    match p {
        Phase::Idle => 0,
        Phase::Planned => 1,
        Phase::Resealed => 2,
        Phase::Committed => 3,
        Phase::SnapshotVerified => 4,
        Phase::Destroyed => 5,
    }
}

fn phase_of(code: u8) -> Option<Phase> {
    match code {
        0 => Some(Phase::Idle),
        1 => Some(Phase::Planned),
        2 => Some(Phase::Resealed),
        3 => Some(Phase::Committed),
        4 => Some(Phase::SnapshotVerified),
        5 => Some(Phase::Destroyed),
        _ => None,
    }
}

fn count(n: usize) -> Result<[u8; 4], StateError> {
    u32::try_from(n)
        .map(u32::to_be_bytes)
        .map_err(|_| StateError::Malformed("count"))
}

fn put_ids<'a>(
    out: &mut Vec<u8>,
    ids: impl ExactSizeIterator<Item = &'a [u8; 16]>,
) -> Result<(), StateError> {
    out.extend_from_slice(&count(ids.len())?);
    for id in ids {
        out.extend_from_slice(id);
    }
    Ok(())
}

fn put_step(out: &mut Vec<u8>, step: &Step) -> Result<(), StateError> {
    match step {
        Step::NewGroups { groups } => {
            out.push(1);
            put_ids(out, groups.iter().map(|g| &g.0))?;
        }
        Step::Reseal { group, keep } => {
            out.push(2);
            out.extend_from_slice(&group.0);
            put_ids(out, keep.iter().map(|d| &d.0))?;
        }
        Step::NewEpoch(e) => {
            out.push(3);
            out.extend_from_slice(&e.0.to_be_bytes());
        }
        Step::RewrapGroups(e) => {
            out.push(4);
            out.extend_from_slice(&e.0.to_be_bytes());
        }
        Step::Commit(e) => {
            out.push(5);
            out.extend_from_slice(&e.0.to_be_bytes());
        }
        Step::Snapshot(e) => {
            out.push(6);
            out.extend_from_slice(&e.0.to_be_bytes());
        }
        Step::VerifySnapshot(e) => {
            out.push(7);
            out.extend_from_slice(&e.0.to_be_bytes());
        }
        Step::DestroyRoot(e) => {
            out.push(8);
            out.extend_from_slice(&e.0.to_be_bytes());
        }
        Step::Complete { epoch, erased } => {
            out.push(9);
            out.extend_from_slice(&epoch.0.to_be_bytes());
            put_ids(out, erased.iter().map(|d| &d.0))?;
        }
    }
    Ok(())
}

/// Encodes `state` in the one spelling [`decode`] admits.
///
/// # Errors
///
/// [`StateError::Malformed`] for a count above `u32` or a state longer
/// than [`MAX_STATE_LEN`].
pub fn encode(state: &ChainState) -> Result<Vec<u8>, StateError> {
    let mut out = STATE_MAGIC.to_vec();
    out.push(STATE_VERSION);
    out.extend_from_slice(&state.epoch.0.to_be_bytes());
    out.push(phase_code(state.phase));
    out.extend_from_slice(&count(state.groups.len())?);
    for (id, g) in &state.groups {
        out.extend_from_slice(&id.0);
        out.extend_from_slice(&g.generation.to_be_bytes());
        out.push(match g.kind {
            GroupKind::DataKeys => 0,
            GroupKind::KeyedDigest => 1,
        });
        out.push(g.purpose.map_or(0, Purpose::code));
        put_ids(&mut out, g.members.iter().map(|d| &d.0))?;
        put_ids(&mut out, g.subjects.iter().map(|d| &d.0))?;
    }
    out.extend_from_slice(&count(state.destroying.len())?);
    for (dek, r) in &state.destroying {
        out.extend_from_slice(&dek.0);
        out.extend_from_slice(&r.requested_at_seq.to_be_bytes());
    }
    out.extend_from_slice(&count(state.roots.len())?);
    for (epoch, r) in &state.roots {
        out.extend_from_slice(&epoch.0.to_be_bytes());
        match r {
            RootState::Active => out.push(1),
            RootState::Retiring => out.push(2),
            RootState::Destroyed(d) => {
                out.push(3);
                out.extend_from_slice(d);
            }
        }
    }
    match &state.run {
        None => out.push(0),
        Some(run) => {
            out.push(1);
            put_ids(&mut out, run.batch.iter().map(|d| &d.0))?;
            out.extend_from_slice(&count(run.steps.len())?);
            for s in &run.steps {
                put_step(&mut out, s)?;
            }
            out.extend_from_slice(&count(run.done)?);
        }
    }
    if out.len() > MAX_STATE_LEN {
        return Err(StateError::Malformed("length"));
    }
    Ok(out)
}

/// A cursor that never reads past the end.
struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], StateError> {
        let (head, tail) = self.rest.split_at_checked(n).ok_or(StateError::Truncated)?;
        self.rest = tail;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], StateError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, StateError> {
        let [b] = self.array::<1>()?;
        Ok(b)
    }

    fn u32(&mut self) -> Result<u32, StateError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, StateError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    /// A count of items, each at least `min` bytes long, checked against
    /// what is left so a count never asks for more than the input holds.
    fn count(&mut self, min: usize) -> Result<usize, StateError> {
        let n = usize::try_from(self.u32()?).map_err(|_| StateError::Malformed("count"))?;
        if n.checked_mul(min).is_none_or(|need| need > self.rest.len()) {
            return Err(StateError::Truncated);
        }
        Ok(n)
    }

    /// A list of ids in the stored order.
    fn ids(&mut self) -> Result<Vec<[u8; 16]>, StateError> {
        let n = self.count(16)?;
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(self.array::<16>()?);
        }
        Ok(out)
    }

    /// A set of ids in strictly increasing order.
    fn id_set(&mut self) -> Result<BTreeSet<DekId>, StateError> {
        let mut prev = None;
        let mut out = BTreeSet::new();
        for id in self.ids()? {
            ascending(&mut prev, id)?;
            out.insert(DekId(id));
        }
        Ok(out)
    }

    fn step(&mut self) -> Result<Step, StateError> {
        let tag = self.u8()?;
        let step = match tag {
            1 => Step::NewGroups {
                groups: self.ids()?.into_iter().map(GroupId).collect(),
            },
            2 => {
                let group = GroupId(self.array()?);
                Step::Reseal {
                    group,
                    keep: self.ids()?.into_iter().map(DekId).collect(),
                }
            }
            3..=8 => {
                let e = Epoch(self.u64()?);
                match tag {
                    3 => Step::NewEpoch(e),
                    4 => Step::RewrapGroups(e),
                    5 => Step::Commit(e),
                    6 => Step::Snapshot(e),
                    7 => Step::VerifySnapshot(e),
                    _ => Step::DestroyRoot(e),
                }
            }
            9 => {
                let epoch = Epoch(self.u64()?);
                Step::Complete {
                    epoch,
                    erased: self.ids()?.into_iter().map(DekId).collect(),
                }
            }
            _ => return Err(StateError::Malformed("step tag")),
        };
        Ok(step)
    }
}

/// Fails unless `next` is strictly above the previous key.
fn ascending<K: Ord + Copy>(prev: &mut Option<K>, next: K) -> Result<(), StateError> {
    if prev.is_some_and(|p| p >= next) {
        return Err(StateError::Malformed("order"));
    }
    *prev = Some(next);
    Ok(())
}

/// Decodes a stored chain state (module documentation). Fuzzed
/// (`chain_state_decode`).
///
/// # Errors
///
/// [`StateError::Truncated`] when the input ends early, and
/// [`StateError::Malformed`] with the first other rule it breaks.
pub fn decode(bytes: &[u8]) -> Result<ChainState, StateError> {
    if bytes.len() > MAX_STATE_LEN {
        return Err(StateError::Malformed("length"));
    }
    let mut r = Reader { rest: bytes };
    if r.array::<4>()? != STATE_MAGIC {
        return Err(StateError::Malformed("magic"));
    }
    if r.u8()? != STATE_VERSION {
        return Err(StateError::Malformed("version"));
    }
    let epoch = Epoch(r.u64()?);
    let phase = phase_of(r.u8()?).ok_or(StateError::Malformed("phase"))?;
    let mut groups = BTreeMap::new();
    let mut prev = None;
    for _ in 0..r.count(30)? {
        let id = r.array::<16>()?;
        ascending(&mut prev, id)?;
        let generation = r.u32()?;
        let kind = match r.u8()? {
            0 => GroupKind::DataKeys,
            1 => GroupKind::KeyedDigest,
            _ => return Err(StateError::Malformed("group kind")),
        };
        let purpose = match r.u8()? {
            0 => None,
            c => Some(Purpose::from_code(c).ok_or(StateError::Malformed("purpose"))?),
        };
        let members = r.id_set()?;
        let subjects = r.id_set()?;
        groups.insert(
            GroupId(id),
            GroupState {
                generation,
                members,
                kind,
                subjects,
                purpose,
            },
        );
    }
    let mut destroying = BTreeMap::new();
    let mut prev = None;
    for _ in 0..r.count(24)? {
        let dek = r.array::<16>()?;
        ascending(&mut prev, dek)?;
        let requested_at_seq = r.u64()?;
        destroying.insert(DekId(dek), ErasureRequest { requested_at_seq });
    }
    let mut roots = BTreeMap::new();
    let mut prev = None;
    for _ in 0..r.count(9)? {
        let e = r.u64()?;
        ascending(&mut prev, e)?;
        let state = match r.u8()? {
            1 => RootState::Active,
            2 => RootState::Retiring,
            3 => RootState::Destroyed(r.array()?),
            _ => return Err(StateError::Malformed("root state")),
        };
        roots.insert(Epoch(e), state);
    }
    let run = match r.u8()? {
        0 => None,
        1 => {
            let batch = r.id_set()?;
            let n = r.count(9)?;
            let mut steps = Vec::with_capacity(n);
            for _ in 0..n {
                steps.push(r.step()?);
            }
            let done = usize::try_from(r.u32()?).map_err(|_| StateError::Malformed("done"))?;
            if done > steps.len() {
                return Err(StateError::Malformed("done"));
            }
            Some(Run { batch, steps, done })
        }
        _ => return Err(StateError::Malformed("run flag")),
    };
    if !r.rest.is_empty() {
        return Err(StateError::Malformed("bytes after the run"));
    }
    Ok(ChainState {
        epoch,
        groups,
        destroying,
        roots,
        phase,
        run,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;
    use crate::erasure::{apply, next};

    fn busy() -> ChainState {
        let mut s = ChainState::genesis(Epoch(0));
        s.add_group_for(GroupId([1; 16]), Purpose::Text).unwrap();
        s.add_group(GroupId([2; 16])).unwrap();
        for i in 1..5u8 {
            s.admit(GroupId([1; 16]), DekId([i; 16])).unwrap();
        }
        s.admit(GroupId([2; 16]), DekId([9; 16])).unwrap();
        s.add_digest_group(GroupId([3; 16]), &[DekId([9; 16])])
            .unwrap();
        s.request(DekId([2; 16]), 7).unwrap();
        s
    }

    /// ADR-004 (2026-11-20), I-81: a chain state round trips at every step
    /// of an erasure, and every strict prefix is refused.
    #[test]
    fn adr004_chain_state_round_trips_through_every_step() {
        let mut s = busy();
        loop {
            let bytes = encode(&s).unwrap();
            assert_eq!(decode(&bytes).unwrap(), s);
            assert_eq!(decode(&bytes).unwrap().restart(), s.restart());
            for cut in 0..bytes.len() {
                assert!(decode(&bytes[..cut]).is_err(), "{cut}");
            }
            let mut more = bytes.clone();
            more.push(0);
            assert!(decode(&more).is_err());
            let Some(step) = next(&s).unwrap() else {
                break;
            };
            apply(&mut s, &step).unwrap();
        }
        assert_eq!(s.epoch(), Epoch(1));
    }

    /// One spelling only: an unknown phase, purpose, root state or step
    /// tag, and ids out of order, are refused.
    #[test]
    fn adr004_chain_state_refuses_other_spellings() {
        let bytes = encode(&busy()).unwrap();
        let mut b = bytes.clone();
        b[13] = 9;
        assert_eq!(decode(&b), Err(StateError::Malformed("phase")));
        // The first group's purpose octet: magic 4, version 1, epoch 8,
        // phase 1, count 4, id 16, generation 4, kind 1.
        let mut b = bytes.clone();
        b[39] = 200;
        assert_eq!(decode(&b), Err(StateError::Malformed("purpose")));
        // The first two members of group 1 swapped.
        let mut b = bytes;
        let at = 44;
        let (x, y) = (b[at..at + 16].to_vec(), b[at + 16..at + 32].to_vec());
        b[at..at + 16].copy_from_slice(&y);
        b[at + 16..at + 32].copy_from_slice(&x);
        assert_eq!(decode(&b), Err(StateError::Malformed("order")));
    }
}
