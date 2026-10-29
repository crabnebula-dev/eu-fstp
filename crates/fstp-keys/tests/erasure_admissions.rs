//! Admissions while a rotation runs, and group purposes (design section
//! 3.5, ADR-004 part 2 "Chains" and "Erasure construction", I-81).
//!
//! New text and document keys keep flowing while a rotation runs. A key
//! may join a group the running batch does not affect at any phase, and
//! an affected group only from the `Commit` on. The property below plays
//! the shell M-SHRED style: it tracks the group generation each data key
//! is sealed to, re-seals the `keep` lists of each `Reseal` step, and
//! checks after every move that each member of each group is sealed to
//! that group's committed generation. A key sealed to a generation that
//! dies with the old root would be lost, which I-81 never allows for a
//! key that was not erased.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code"
)]

use std::collections::{BTreeMap, BTreeSet};

use fstp_keys::erasure::{ChainState, KeyFoldError, Phase, Step, apply, apply_destroy, next};
use fstp_keys::{DekId, Epoch, GroupId, Purpose};
use fstp_prop::{Gen, prop_assert, prop_assert_eq};

fn group(n: u8) -> GroupId {
    GroupId([n; 16])
}

fn dek(n: u8) -> DekId {
    let mut id = [0u8; 16];
    id[0] = 0xd0;
    id[1] = n;
    DekId(id)
}

/// The shell's view: the generation each data key is sealed to, and the
/// generation each `Reseal` sealed a kept key to before the commit.
#[derive(Default)]
struct Shell {
    sealed: BTreeMap<DekId, u32>,
    pending: BTreeMap<DekId, u32>,
}

impl Shell {
    /// Runs the next step of `s`, as the shell would, and folds it.
    fn step(&mut self, s: &mut ChainState) -> Result<bool, String> {
        let Some(step) = next(s).map_err(|e| e.to_string())? else {
            return Ok(false);
        };
        match &step {
            Step::Reseal { group, keep } => {
                let generation = s.generation(*group).ok_or("reseal of an unknown group")?;
                for k in keep {
                    self.pending.insert(*k, generation + 1);
                }
            }
            Step::DestroyRoot(e) => {
                apply_destroy(s, *e, [0xab; 32]).map_err(|e| e.to_string())?;
                return Ok(true);
            }
            _ => {}
        }
        apply(s, &step).map_err(|e| e.to_string())?;
        if matches!(step, Step::Commit(_)) {
            self.sealed.append(&mut self.pending);
        }
        Ok(true)
    }

    /// Every member of every group is sealed to that group's committed
    /// generation.
    fn check(&self, s: &ChainState, groups: &[GroupId]) -> Result<(), String> {
        for g in groups {
            let Some(state) = s.group(*g) else {
                continue;
            };
            for k in &state.members {
                prop_assert_eq!(
                    self.sealed.get(k).copied(),
                    Some(state.generation),
                    "a live key of {g:?} is sealed to another generation"
                );
            }
        }
        Ok(())
    }
}

/// I-81, design section 3.5: under any interleaving of admissions,
/// requests, steps and restarts, every live data key stays sealed to its
/// group's committed generation, an admission is refused only for a
/// group that the running batch affects before its commit, and every
/// request completes once the chain drains.
#[test]
fn i81_admissions_interleaved_with_rotations_stay_sealed_to_live_generations() {
    fstp_prop::check(
        "i81_admissions_interleaved_with_rotations_stay_sealed_to_live_generations",
        |g: &mut Gen| {
            let groups: Vec<GroupId> = (0..3).map(group).collect();
            let mut s = ChainState::genesis(Epoch(1));
            let mut shell = Shell::default();
            let mut fresh = 0u8;
            let mut requested = BTreeSet::new();
            for gid in &groups {
                s.add_group(*gid).map_err(|e| e.to_string())?;
                for _ in 0..2 {
                    s.admit(*gid, dek(fresh)).map_err(|e| e.to_string())?;
                    shell.sealed.insert(dek(fresh), 1);
                    fresh += 1;
                }
            }
            let moves = g.usize_in(0..=60);
            for _ in 0..moves {
                match g.usize_in(0..=9) {
                    0..=2 => {
                        let gid = *g.pick(&groups);
                        let k = dek(fresh);
                        fresh = fresh.wrapping_add(1);
                        let generation = s.generation(gid).ok_or("no group")?;
                        match s.admit(gid, k) {
                            Ok(()) => {
                                shell.sealed.insert(k, generation);
                            }
                            Err(KeyFoldError::RunInFlight) => {
                                let batch = s.running_batch();
                                let members = &s.group(gid).ok_or("no group")?.members;
                                prop_assert!(
                                    matches!(s.phase(), Phase::Planned | Phase::Resealed),
                                    "refused at phase {:?}",
                                    s.phase()
                                );
                                prop_assert!(
                                    !members.is_disjoint(&batch),
                                    "refused for a group the batch does not affect"
                                );
                            }
                            Err(e) => return Err(format!("admit refused: {e}")),
                        }
                    }
                    3 | 4 => {
                        let live: Vec<DekId> = groups
                            .iter()
                            .filter_map(|gid| s.group(*gid))
                            .flat_map(|st| st.members.iter().copied())
                            .collect();
                        if !live.is_empty() {
                            let k = *g.pick(&live);
                            s.request(k, 0).map_err(|e| e.to_string())?;
                            requested.insert(k);
                        }
                    }
                    5 => {
                        // A crash: the shell resumes from the stored state,
                        // and a run before its commit starts again.
                        s = s.restart();
                        if matches!(s.phase(), Phase::Planned) {
                            shell.pending.clear();
                        }
                    }
                    _ => {
                        shell.step(&mut s)?;
                    }
                }
                shell.check(&s, &groups)?;
            }
            let mut budget = 10_000;
            while shell.step(&mut s)? {
                shell.check(&s, &groups)?;
                budget -= 1;
                prop_assert!(budget > 0, "the chain never drained");
            }
            prop_assert_eq!(s.phase(), Phase::Idle);
            for k in &requested {
                prop_assert!(!s.is_requested(*k), "a request never completed");
                prop_assert!(s.group_of(*k).is_none(), "an erased key is still live");
            }
            Ok(())
        },
    );
}

/// The universe of the deterministic tests: `g1 = {k0, k1}` and
/// `g2 = {k2}`, with a request for `k0` that starts a rotation.
fn rotating() -> ChainState {
    let mut s = ChainState::genesis(Epoch(1));
    s.add_group(group(1)).unwrap();
    s.add_group(group(2)).unwrap();
    s.admit(group(1), dek(0)).unwrap();
    s.admit(group(1), dek(1)).unwrap();
    s.admit(group(2), dek(2)).unwrap();
    s.request(dek(0), 1).unwrap();
    s
}

/// Folds steps until the next one is a `Commit`, then folds it too when
/// `commit` is true.
fn run_to_commit(s: &mut ChainState, commit: bool) {
    loop {
        let step = next(s).unwrap().unwrap();
        let is_commit = matches!(step, Step::Commit(_));
        if is_commit && !commit {
            return;
        }
        apply(s, &step).unwrap();
        if is_commit {
            return;
        }
    }
}

/// I-81, design section 3.5: an affected group admits no key before the
/// running batch commits, and admits into its new generation after.
#[test]
fn i81_affected_group_admits_only_after_commit() {
    let mut s = rotating();
    assert_eq!(s.admit(group(1), dek(9)), Err(KeyFoldError::RunInFlight));
    run_to_commit(&mut s, false);
    assert_eq!(s.admit(group(1), dek(9)), Err(KeyFoldError::RunInFlight));
    run_to_commit(&mut s, true);
    assert_eq!(s.phase(), Phase::Committed);
    assert_eq!(s.admit(group(1), dek(9)), Ok(()));
    assert_eq!(s.generation(group(1)), Some(2));
}

/// I-81, design section 3.5: a new group waits for the running batch to
/// commit, since its secret would otherwise be sealed under the epoch
/// that step 6 destroys. After the commit it is added at once.
#[test]
fn i81_new_group_waits_for_the_commit() {
    let mut s = rotating();
    assert_eq!(s.add_group(group(7)), Err(KeyFoldError::RunInFlight));
    assert_eq!(
        s.add_digest_group(group(8), &[dek(2)]),
        Err(KeyFoldError::RunInFlight)
    );
    run_to_commit(&mut s, true);
    assert_eq!(s.add_group(group(7)), Ok(()));
    assert_eq!(s.add_digest_group(group(8), &[dek(2)]), Ok(()));
}

/// ADR-004 part 2 "Chains": "A `Document` group holds one" data key.
#[test]
fn adr004_document_group_holds_one_data_key() {
    let mut s = ChainState::genesis(Epoch(1));
    s.add_group_for(group(1), Purpose::Document).unwrap();
    assert_eq!(s.admit(group(1), dek(0)), Ok(()));
    assert_eq!(s.admit(group(1), dek(1)), Err(KeyFoldError::GroupFull));
}

/// ADR-004 part 2 "Chains": "The `Ledger` group never takes part in an
/// erasure." A request for a ledger key is refused and starts no
/// rotation. A keyed digest purpose is no data key group.
#[test]
fn adr004_ledger_key_is_never_erased() {
    let mut s = ChainState::genesis(Epoch(1));
    s.add_group_for(group(1), Purpose::Ledger).unwrap();
    s.admit(group(1), dek(0)).unwrap();
    assert_eq!(s.request(dek(0), 1), Err(KeyFoldError::NotErasable));
    assert_eq!(s.phase(), Phase::Idle);
    assert!(!s.refused_for_open(dek(0)), "the ledger key was closed");
    assert_eq!(
        s.add_group_for(group(2), Purpose::Lookup),
        Err(KeyFoldError::WrongGroupKind)
    );
}
