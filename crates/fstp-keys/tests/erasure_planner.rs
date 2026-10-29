//! The erasure planner of `fstp_keys::erasure` (design section 3.5,
//! ADR-004 part 2 "Erasure construction", I-81, R-KY-02, G24).
//!
//! The universe is the one of M-SHRED (design section 14.2): data key
//! groups `g0 = {k0, k1}` and `g1 = {k2, k3}`, and a keyed digest group
//! `g2` whose subjects are `k0` and `k2`. M-SHRED in `fstp-celltest`
//! checks the planner against an attacker over every interleaving. These
//! are the crate's own unit and property tests of the same calls.
//!
//! The universe is built through the helpers of `common`, which call the
//! admissions of lane W2f (`ChainState::add_group`, `admit` and
//! `add_digest_group`), its request call and its state accessors.
//! Admissions while a rotation runs, and group purposes, are tested in
//! `erasure_admissions.rs`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code"
)]

mod common;

use std::collections::BTreeSet;

use common::{
    DATA_GROUPS, DIGEST_GROUP, Fail, KEYS, add_group, admit, adr004_steps, affected, apply_step,
    dek_id, dek_ids, drive, expect_refused, gen_batch, generation, group_id, next_step, plan,
    refused_for_open, request, root_state, universe,
};
use fstp_keys::erasure::{ChainState, Phase, RootState, Step};
use fstp_keys::{DekId, Epoch, GroupId};
use fstp_prop::{Gen, prop_assert, prop_assert_eq};

/// The universe with one request for key `k` recorded at sequence 1.
fn requested(k: u8) -> Result<ChainState, Fail> {
    let mut s = universe()?;
    request(&mut s, dek_id(k), 1)?;
    Ok(s)
}

/// I-81, ADR-004 part 2 "Epochs": a fresh chain is idle at its first
/// epoch, and its planner has nothing to do.
#[test]
fn i81_fresh_chain_is_idle_with_nothing_to_do() {
    let s = ChainState::genesis(Epoch(1));
    assert_eq!(s.epoch(), Epoch(1));
    assert_eq!(s.phase(), Phase::Idle);
    assert_eq!(next_step(&s), Ok(None), "a fresh chain has work to do");
}

/// I-81: an empty batch plans no step. No rotation runs without a
/// request, so no custody root is created or destroyed for nothing.
#[test]
fn i81_empty_batch_plans_no_step() {
    let s = ChainState::genesis(Epoch(1));
    assert_eq!(plan(&s, &BTreeSet::new()), Ok(Vec::new()));
}

/// Every step kind, at generated epochs and ids.
fn gen_step(g: &mut Gen) -> Step {
    let e = Epoch(g.u64_in(0..=8));
    let gid = group_id(g.u8_in(0..=3));
    let keys: Vec<DekId> = g.vec(0..=3, |g| dek_id(g.u8_in(0..=4)));
    match g.usize_in(0..=8) {
        0 => Step::NewGroups { groups: vec![gid] },
        1 => Step::Reseal {
            group: gid,
            keep: keys,
        },
        2 => Step::NewEpoch(e),
        3 => Step::RewrapGroups(e),
        4 => Step::Commit(e),
        5 => Step::Snapshot(e),
        6 => Step::VerifySnapshot(e),
        7 => Step::DestroyRoot(e),
        _ => Step::Complete {
            epoch: e,
            erased: keys,
        },
    }
}

/// I-81, ADR-004 part 2: no run is in flight on a fresh chain, so `apply`
/// refuses every step there and leaves the state as it was. A destroy or
/// a completion that no plan asked for never folds in.
#[test]
fn i81_apply_on_an_idle_chain_refuses_every_step() {
    fstp_prop::check(
        "i81_apply_on_an_idle_chain_refuses_every_step",
        |g: &mut Gen| {
            let before = ChainState::genesis(Epoch(1));
            let step = gen_step(g);
            g.note("step", &step);
            let mut s = before.clone();
            expect_refused(apply_step(&mut s, &step), "a step on an idle chain")?;
            prop_assert!(s == before, "a refused step changed the state");
            Ok(())
        },
    );
}

/// I-81, R-KY-02, ADR-004 part 2 steps 2 to 7: the plan for a batch opens
/// with `NewGroups` of every affected group and one `Reseal` per affected
/// group, keeping its survivors. Then come `NewEpoch`, `RewrapGroups`,
/// `Commit`, `Snapshot` and `VerifySnapshot` of the new epoch. It ends
/// with `DestroyRoot` of the old epoch and `Complete` naming the batch.
/// The digest group is affected when the batch holds one of its
/// subjects (G24).
#[test]
fn i81_plan_matches_the_adr004_step_list() {
    fstp_prop::check("i81_plan_matches_the_adr004_step_list", |g: &mut Gen| {
        let s = universe()?;
        let batch = gen_batch(g);
        g.note("batch", &batch);
        prop_assert_eq!(plan(&s, &dek_ids(&batch))?, adr004_steps(1, &batch));
        Ok(())
    });
}

/// I-81, design section 3.5 "Keyed digests" (G24): erasing a subject of
/// the digest group replaces that group in the same rotation. Erasing a
/// key that is no subject of it leaves it alone.
#[test]
fn i81_erased_digest_subject_replaces_its_digest_group() {
    let s = universe().unwrap_or_else(|e| panic!("{e}"));
    let digest = group_id(DIGEST_GROUP.0);
    let groups_of = |k: u8| -> Vec<GroupId> {
        let steps = plan(&s, &BTreeSet::from([dek_id(k)])).unwrap_or_else(|e| panic!("{e}"));
        match steps.first() {
            Some(Step::NewGroups { groups }) => groups.clone(),
            other => panic!("the plan for k{k} starts with {other:?}"),
        }
    };
    for subject in DIGEST_GROUP.1 {
        assert!(
            groups_of(subject).contains(&digest),
            "erasing subject k{subject} keeps the old digest key"
        );
    }
    for k in KEYS.into_iter().filter(|k| !DIGEST_GROUP.1.contains(k)) {
        assert!(
            !groups_of(k).contains(&digest),
            "erasing k{k}, no subject, replaced the digest key"
        );
    }
}

/// I-81, ADR-004 part 2: "Each erasure request starts a rotation of its
/// chain at once. No timer and no minimum interval apply." After one
/// request on an idle chain, the planner leaves `Idle` and its next step
/// is the first step of the plan for that key.
#[test]
fn i81_request_on_an_idle_chain_starts_a_rotation_at_once() {
    let s = requested(1).unwrap_or_else(|e| panic!("{e}"));
    assert_ne!(s.phase(), Phase::Idle, "the request left the chain idle");
    let first = adr004_steps(1, &BTreeSet::from([1])).into_iter().next();
    assert_eq!(next_step(&s), Ok(first));
}

/// I-81: driving `next` and `apply` from a request runs exactly the
/// ADR-004 steps for that key, then goes idle.
#[test]
fn i81_next_and_apply_run_the_adr004_steps_of_the_request() {
    fstp_prop::check(
        "i81_next_and_apply_run_the_adr004_steps_of_the_request",
        |g: &mut Gen| {
            let k = *g.pick(&KEYS);
            let mut s = requested(k)?;
            let ran = drive(&mut s)?;
            prop_assert_eq!(ran, adr004_steps(1, &BTreeSet::from([k])));
            prop_assert_eq!(s.phase(), Phase::Idle);
            Ok(())
        },
    );
}

/// I-81, ADR-004 part 2: a completed rotation moves the chain to epoch 2.
/// Every affected group is at its next generation, every other group
/// keeps its own, and no erasure request is left.
#[test]
fn i81_rotation_advances_the_epoch_and_the_affected_generations() {
    fstp_prop::check(
        "i81_rotation_advances_the_epoch_and_the_affected_generations",
        |g: &mut Gen| {
            let k = *g.pick(&KEYS);
            let mut s = requested(k)?;
            let groups: Vec<u8> = DATA_GROUPS
                .iter()
                .map(|(id, _)| *id)
                .chain([DIGEST_GROUP.0])
                .collect();
            let mut before = Vec::new();
            for id in &groups {
                before.push(generation(&s, group_id(*id))?);
            }
            drive(&mut s)?;
            prop_assert_eq!(s.epoch(), Epoch(2));
            prop_assert_eq!(s.sizes().1, 0, "requests left after completion");
            let hit = affected(&BTreeSet::from([k]));
            for (id, old) in groups.iter().zip(before) {
                let want = if hit.contains(id) { old + 1 } else { old };
                prop_assert_eq!(generation(&s, group_id(*id))?, want, "generation of g{id}");
            }
            Ok(())
        },
    );
}

/// I-81, ADR-004 part 2 "Epochs": after a rotation from epoch 1 to 2,
/// epoch 1 is `Destroyed` with its receipt and epoch 2 is `Active`.
#[test]
fn i81_rotation_destroys_the_old_root_and_activates_the_new_one() {
    let mut s = requested(0).unwrap_or_else(|e| panic!("{e}"));
    drive(&mut s).unwrap_or_else(|e| panic!("{e}"));
    let old = root_state(&s, Epoch(1)).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        matches!(old, Some(RootState::Destroyed(_))),
        "epoch 1 after the rotation: {old:?}"
    );
    let new = root_state(&s, Epoch(2)).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(new, Some(RootState::Active), "epoch 2 after the rotation");
}

/// I-81, design section 3.4, ADR-004 part 2 step 1: "The keys cannot be
/// opened from here on." The in-memory index refuses the requested key
/// from the request on, and refuses none of the others.
#[test]
fn i81_requested_key_is_refused_for_open_at_once() {
    let s = requested(1).unwrap_or_else(|e| panic!("{e}"));
    for k in KEYS {
        let refused = refused_for_open(&s, dek_id(k)).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            refused,
            k == 1,
            "open refusal of k{k} after a request for k1"
        );
    }
}

/// I-81: a request for a key the chain does not hold is refused. A typo
/// in an id must not start a rotation that erases nothing.
#[test]
fn i81_request_refuses_a_key_the_chain_does_not_hold() {
    let mut s = universe().unwrap_or_else(|e| panic!("{e}"));
    let before = s.clone();
    let r = request(&mut s, dek_id(9), 1);
    assert!(matches!(r, Err(Fail::Refused(_))), "an unknown key: {r:?}");
    assert!(s == before, "a refused request changed the state");
}

/// The `Complete` steps of `ran`, as (epoch, erased keys).
fn completions(ran: &[Step]) -> Vec<(Epoch, Vec<DekId>)> {
    ran.iter()
        .filter_map(|s| match s {
            Step::Complete { epoch, erased } => Some((*epoch, erased.clone())),
            _ => None,
        })
        .collect()
}

/// I-81, ADR-004 part 2: "Requests that arrive while a rotation of the
/// same chain runs join the next rotation, which starts as soon as the
/// running one ends." Two requests made mid run share that next
/// rotation, and nothing waits for a timer.
#[test]
fn i81_requests_during_a_run_join_the_next_rotation() {
    let mut s = requested(0).unwrap_or_else(|e| panic!("{e}"));
    let first = next_step(&s)
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|| panic!("no step after a request"));
    apply_step(&mut s, &first).unwrap_or_else(|e| panic!("{e}"));
    request(&mut s, dek_id(1), 2).unwrap_or_else(|e| panic!("{e}"));
    request(&mut s, dek_id(3), 3).unwrap_or_else(|e| panic!("{e}"));
    let mut ran = vec![first];
    ran.extend(drive(&mut s).unwrap_or_else(|e| panic!("{e}")));
    assert_eq!(
        completions(&ran),
        vec![
            (Epoch(2), vec![dek_id(0)]),
            (Epoch(3), vec![dek_id(1), dek_id(3)]),
        ],
        "the rotations that ran: {ran:?}"
    );
    assert_eq!(s.epoch(), Epoch(3));
    assert_eq!(s.phase(), Phase::Idle);
}

/// Every step the pool for refusal tests draws from, for the universe at
/// epochs 1 to 3.
fn step_pool() -> Vec<Step> {
    let mut pool = Vec::new();
    for e in 1..=3 {
        pool.extend([
            Step::NewEpoch(Epoch(e)),
            Step::RewrapGroups(Epoch(e)),
            Step::Commit(Epoch(e)),
            Step::Snapshot(Epoch(e)),
            Step::VerifySnapshot(Epoch(e)),
            Step::DestroyRoot(Epoch(e)),
            Step::Complete {
                epoch: Epoch(e),
                erased: vec![dek_id(0)],
            },
        ]);
    }
    for (g, _) in DATA_GROUPS {
        pool.push(Step::NewGroups {
            groups: vec![group_id(g)],
        });
        pool.push(Step::Reseal {
            group: group_id(g),
            keep: Vec::new(),
        });
    }
    pool
}

/// I-81, ADR-004 part 2: `apply` folds only the step `next` gives. Any
/// other step is refused at any point of a run and leaves the state
/// unchanged. So the shell cannot skip the commit, the snapshot check or
/// the destroy.
#[test]
fn i81_apply_refuses_a_step_that_is_not_next() {
    let pool = step_pool();
    fstp_prop::check(
        "i81_apply_refuses_a_step_that_is_not_next",
        |g: &mut Gen| {
            let k = *g.pick(&KEYS);
            let mut s = requested(k)?;
            let prefix = g.usize_in(0..=12);
            for _ in 0..prefix {
                let Some(step) = next_step(&s)? else { break };
                apply_step(&mut s, &step)?;
            }
            let want = next_step(&s)?;
            let others: Vec<&Step> = pool.iter().filter(|p| Some(*p) != want.as_ref()).collect();
            let wrong = (*g.pick(&others)).clone();
            g.note("next", &want);
            g.note("applied instead", &wrong);
            let before = s.clone();
            expect_refused(apply_step(&mut s, &wrong), "a step that is not next")?;
            prop_assert!(s == before, "a refused step changed the state");
            Ok(())
        },
    );
}

/// I-81, ADR-004 part 2: "An erasure is reported complete only at step 7,
/// after the destroy receipt." Whenever `next` gives `Complete`, the
/// old root epoch is already `Destroyed`, and the phase says so.
#[test]
fn i81_completion_comes_only_after_the_old_root_is_destroyed() {
    fstp_prop::check(
        "i81_completion_comes_only_after_the_old_root_is_destroyed",
        |g: &mut Gen| {
            let k = *g.pick(&KEYS);
            let mut s = requested(k)?;
            let mut seen = false;
            while let Some(step) = next_step(&s)? {
                if let Step::Complete { epoch, .. } = &step {
                    seen = true;
                    let old = Epoch(epoch.0 - 1);
                    let state = root_state(&s, old)?;
                    prop_assert!(
                        matches!(state, Some(RootState::Destroyed(_))),
                        "Complete({epoch:?}) while epoch {old:?} is {state:?}"
                    );
                    prop_assert_eq!(s.phase(), Phase::Destroyed, "phase before Complete");
                }
                apply_step(&mut s, &step)?;
            }
            prop_assert!(seen, "the run never completed");
            Ok(())
        },
    );
}

/// The position of a phase in the order design section 3.5 lists.
fn rank(p: Phase) -> u8 {
    match p {
        Phase::Idle => 0,
        Phase::Planned => 1,
        Phase::Resealed => 2,
        Phase::Committed => 3,
        Phase::SnapshotVerified => 4,
        Phase::Destroyed => 5,
    }
}

/// I-81, design section 3.5: one run passes through the phases in their
/// listed order and never back. It reaches `Committed`, then
/// `SnapshotVerified`, then `Destroyed`, and ends `Idle`.
#[test]
fn i81_phases_follow_the_designed_order() {
    fstp_prop::check("i81_phases_follow_the_designed_order", |g: &mut Gen| {
        let k = *g.pick(&KEYS);
        let mut s = requested(k)?;
        let mut phases = vec![s.phase()];
        while let Some(step) = next_step(&s)? {
            apply_step(&mut s, &step)?;
            phases.push(s.phase());
        }
        g.note("phases", &phases);
        prop_assert_eq!(
            phases.last().copied(),
            Some(Phase::Idle),
            "the run ends idle"
        );
        let during = &phases[..phases.len() - 1];
        prop_assert!(
            during.windows(2).all(|w| rank(w[0]) <= rank(w[1])),
            "a phase went back during the run"
        );
        for p in [Phase::Committed, Phase::SnapshotVerified, Phase::Destroyed] {
            prop_assert!(during.contains(&p), "the run skipped {p:?}");
        }
        Ok(())
    });
}

/// I-81, ADR-004 part 2: "A crash at any step loses nothing. The pure
/// planner resumes from the stored phase." A run resumed from the state
/// stored after any step ends in the same state as a run without a
/// crash. The planner keeps no state outside `ChainState`.
#[test]
fn i81_erasure_resumes_from_every_stored_state() {
    fstp_prop::check(
        "i81_erasure_resumes_from_every_stored_state",
        |g: &mut Gen| {
            let k = *g.pick(&KEYS);
            let mut s = requested(k)?;
            let mut stored = vec![s.clone()];
            while let Some(step) = next_step(&s)? {
                apply_step(&mut s, &step)?;
                stored.push(s.clone());
            }
            let at = g.usize_in(0..=stored.len() - 1);
            let mut resumed = stored[at].clone();
            drive(&mut resumed)?;
            g.note("resumed after step", &at);
            prop_assert!(resumed == s, "the resumed run ended elsewhere");
            Ok(())
        },
    );
}

/// I-81, ADR-004 part 2: under any interleaving of requests and steps,
/// every requested key is erased by exactly one rotation, rotations run
/// on consecutive epochs, and the chain ends idle with no request left.
#[test]
fn i81_every_request_completes_once_under_any_interleaving() {
    fstp_prop::check(
        "i81_every_request_completes_once_under_any_interleaving",
        |g: &mut Gen| {
            let mut s = universe()?;
            let mut order: Vec<u8> = KEYS.to_vec();
            g.shuffle(&mut order);
            let count = g.usize_in(1..=order.len());
            let wanted: BTreeSet<u8> = order[..count].iter().copied().collect();
            let mut ran = Vec::new();
            for (seq, k) in order[..count].iter().enumerate() {
                request(&mut s, dek_id(*k), seq as u64 + 1)?;
                for _ in 0..g.usize_in(0..=6) {
                    let Some(step) = next_step(&s)? else { break };
                    apply_step(&mut s, &step)?;
                    ran.push(step);
                }
            }
            ran.extend(drive(&mut s)?);
            let done = completions(&ran);
            let mut erased: Vec<DekId> = done.iter().flat_map(|(_, ks)| ks.clone()).collect();
            erased.sort();
            let want: Vec<DekId> = wanted.iter().map(|k| dek_id(*k)).collect();
            prop_assert_eq!(erased, want, "keys erased");
            for (i, (e, _)) in done.iter().enumerate() {
                prop_assert_eq!(*e, Epoch(i as u64 + 2), "epoch of rotation {i}");
            }
            prop_assert_eq!(s.epoch(), Epoch(done.len() as u64 + 1));
            prop_assert_eq!(s.phase(), Phase::Idle);
            prop_assert_eq!(s.sizes().1, 0, "requests left");
            Ok(())
        },
    );
}

/// The most data keys a group holds (ADR-004 part 2 "Chains").
const GROUP_LIMIT: u16 = 256;

/// I-81, ADR-004 part 2: "Groups that hold data keys hold at most 256 of
/// them." The 257th admission to one group is refused, which keeps every
/// rotation to at most 255 hybrid re-seals per group.
#[test]
fn i81_group_holds_at_most_256_data_keys() {
    let mut s = ChainState::genesis(Epoch(1));
    let gid = GroupId([0x40; 16]);
    add_group(&mut s, gid).unwrap_or_else(|e| panic!("{e}"));
    for i in 0..GROUP_LIMIT {
        let mut id = [0x50; 16];
        id[..2].copy_from_slice(&i.to_be_bytes());
        admit(&mut s, gid, DekId(id)).unwrap_or_else(|e| panic!("admission {i}: {e}"));
    }
    let r = admit(&mut s, gid, DekId([0x60; 16]));
    assert!(matches!(r, Err(Fail::Refused(_))), "the 257th key: {r:?}");
}

/// I-81: a data key belongs to one group. Admitting it to a second group
/// is refused, since a copy sealed to a group the plan does not rotate
/// would survive its erasure.
#[test]
fn i81_data_key_belongs_to_one_group() {
    let mut s = universe().unwrap_or_else(|e| panic!("{e}"));
    let before = s.clone();
    let r = admit(&mut s, group_id(1), dek_id(0));
    assert!(
        matches!(r, Err(Fail::Refused(_))),
        "k0 admitted to g1: {r:?}"
    );
    assert!(s == before, "a refused admission changed the state");
}
