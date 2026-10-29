//! Fuzz target `erasure_plan_sequence` of `fstp-keys` (TH-26, H-05, M3 design section 15).
//!
//! Design checks: random step sequences keep the M-SHRED predicates.
//!
//! The chain starts as the M-SHRED universe: data key groups `g0 = {k0,
//! k1}` and `g1 = {k2, k3}`, and a keyed digest group `g2` over `k0` and
//! `k2`. The input then drives five kinds of operation: plan a batch,
//! apply the step `next` gives, apply an arbitrary step, record an
//! erasure request, and admit a group or a key. After each one the
//! target checks what holds on every state.
//!
//! - The epoch never goes back.
//! - `apply` folds only the step `next` gives. Any other step is refused
//!   and leaves the state unchanged. So does every refused request or
//!   admission.
//! - A recorded request makes its key refused for open at once, and a
//!   request on an idle chain starts a run at once.
//! - A plan for an empty batch is empty. A plan for any other batch ends
//!   with `Complete` naming the batch at the next epoch, after `Commit`
//!   of that epoch and `DestroyRoot` of the current one. No `Reseal`
//!   keeps a key of the batch.
//! - Whenever `next` gives `Complete`, the old root is destroyed.

#![no_main]

use std::collections::BTreeSet;

use fstp_keys::erasure::{ChainState, Phase, RootState, Step, apply, next, plan_erasure};
use fstp_keys::{DekId, Epoch, GroupId};
use libfuzzer_sys::fuzz_target;

fn dek(i: u8) -> DekId {
    DekId([0x20_u8.wrapping_add(i); 16])
}

fn group(i: u8) -> GroupId {
    GroupId([0x10_u8.wrapping_add(i); 16])
}

/// The M-SHRED universe at epoch 1.
fn universe() -> ChainState {
    let mut s = ChainState::genesis(Epoch(1));
    for (g, keys) in [(0u8, [0u8, 1]), (1, [2, 3])] {
        assert!(s.add_group(group(g)).is_ok(), "add g{g}");
        for k in keys {
            assert!(s.admit(group(g), dek(k)).is_ok(), "admit k{k}");
        }
    }
    assert!(
        s.add_digest_group(group(2), &[dek(0), dek(2)]).is_ok(),
        "add the digest group"
    );
    s
}

/// An arbitrary step from two input bytes.
fn step_from(kind: u8, arg: u8) -> Step {
    let e = Epoch(u64::from(arg % 8));
    let g = group(arg % 4);
    match kind % 9 {
        0 => Step::NewGroups { groups: vec![g] },
        1 => Step::Reseal {
            group: g,
            keep: vec![dek(arg % 8)],
        },
        2 => Step::NewEpoch(e),
        3 => Step::RewrapGroups(e),
        4 => Step::Commit(e),
        5 => Step::Snapshot(e),
        6 => Step::VerifySnapshot(e),
        7 => Step::DestroyRoot(e),
        _ => Step::Complete {
            epoch: e,
            erased: vec![dek(arg % 8)],
        },
    }
}

fn position(steps: &[Step], want: &Step) -> Option<usize> {
    steps.iter().position(|s| s == want)
}

/// The plan checks of the module comment.
fn check_plan(state: &ChainState, batch: &BTreeSet<DekId>, steps: &[Step]) {
    if batch.is_empty() {
        assert!(steps.is_empty(), "a plan for an empty batch: {steps:?}");
        return;
    }
    let old = state.epoch();
    let new = Epoch(old.0.saturating_add(1));
    let complete = Step::Complete {
        epoch: new,
        erased: batch.iter().copied().collect(),
    };
    assert_eq!(
        steps.last(),
        Some(&complete),
        "the plan does not end with Complete"
    );
    let commit = position(steps, &Step::Commit(new));
    let destroy = position(steps, &Step::DestroyRoot(old));
    assert!(commit.is_some(), "no Commit({new:?}) in {steps:?}");
    assert!(destroy.is_some(), "no DestroyRoot({old:?}) in {steps:?}");
    assert!(commit < destroy, "DestroyRoot before Commit in {steps:?}");
    for s in steps {
        if let Step::Reseal { keep, .. } = s {
            assert!(
                keep.iter().all(|k| !batch.contains(k)),
                "a Reseal keeps an erased key: {s:?}"
            );
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut state = universe();
    let mut input = data.iter().copied().take(256);
    while let Some(op) = input.next() {
        let before = state.epoch();
        let saved = state.clone();
        match op % 5 {
            0 => {
                let mask = input.next().unwrap_or(0);
                let batch: BTreeSet<DekId> =
                    (0..8u8).filter(|i| mask & (1 << i) != 0).map(dek).collect();
                if let Ok(plan) = plan_erasure(&state, &batch) {
                    check_plan(&state, &batch, &plan.steps);
                }
            }
            1 => {
                if let Ok(Some(step)) = next(&state) {
                    if let Step::Complete { epoch, .. } = &step {
                        let old = Epoch(epoch.0.saturating_sub(1));
                        assert!(
                            matches!(state.root_state(old), Some(RootState::Destroyed(_))),
                            "Complete before the old root is destroyed"
                        );
                    }
                    assert!(
                        apply(&mut state, &step).is_ok(),
                        "next gave a step apply refuses"
                    );
                }
            }
            2 => {
                let step = step_from(input.next().unwrap_or(0), input.next().unwrap_or(0));
                let expected = next(&state);
                let applied = apply(&mut state, &step);
                if let Ok(want) = expected
                    && want.as_ref() != Some(&step)
                {
                    assert!(applied.is_err(), "applied {step:?} while next is {want:?}");
                }
                if applied.is_err() {
                    assert!(state == saved, "a refused step changed the state");
                }
            }
            3 => {
                let k = dek(input.next().unwrap_or(0) % 8);
                let idle = state.phase() == Phase::Idle;
                match state.request(k, 1) {
                    Ok(()) => {
                        assert!(state.refused_for_open(k), "a requested key still opens");
                        if idle && !saved.is_requested(k) {
                            assert_ne!(state.phase(), Phase::Idle, "a request left the chain idle");
                        }
                    }
                    Err(_) => assert!(state == saved, "a refused request changed the state"),
                }
            }
            _ => {
                let arg = input.next().unwrap_or(0);
                let r = if arg & 1 == 0 {
                    state.add_group(group(arg % 8))
                } else {
                    state.admit(group(arg % 4), dek(arg % 16))
                };
                if r.is_err() {
                    assert!(state == saved, "a refused admission changed the state");
                }
            }
        }
        assert!(state.epoch() >= before, "the epoch went back");
    }
    let shown = format!("{:?}", next(&state));
    assert!(!shown.is_empty());
});
