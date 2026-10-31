//! I-81: destroying a root or data key makes the protected data
//! unrecoverable, including from backups (design section 14.4,
//! T-ID-SHRED). The model and the pure planner tests.
//!
//! Lane W1d wrote these tests before the production code. They are red
//! until `fstp_keys::erasure` (lane W2f) and the M-SHRED tripwire count
//! (lane W4) land. The reference twins are green once the count is
//! recorded.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::BTreeSet;

use fstp_celltest::mc::shred_model::{
    Env, Mutant, Production, Reference, ShredAction, ShredBackend, ShredModel, breaches, drain,
    ids, production_plan, properties, walk,
};
use fstp_celltest::mc::tripwires::{M_SHRED, NOT_MEASURED, tripwire};
use fstp_celltest::reference::keys::{Defect, RefStep, closure};
use fstp_domain_testkit::harness::teeth::expect_violation;
use fstp_mc::{Config, check, explore};

// ---------------------------------------------------------------------------
// Helpers.

fn bound() -> Config {
    assert_ne!(
        M_SHRED, NOT_MEASURED,
        "the M-SHRED tripwire is not recorded yet (lane W4); \
         i81_m_shred_tripwire_records_the_measured_count gives the count"
    );
    Config::default()
        .with_stop_when_decided(false)
        .with_max_states(tripwire(M_SHRED))
}

fn passes<B: ShredBackend>(backend: B) {
    let model = ShredModel::new(backend);
    let props = properties(&model);
    let outcome = check(&model, &props, &bound());
    assert!(
        outcome.exhaustive,
        "M-SHRED did not finish under its tripwire:\n{outcome}"
    );
    if let Err(e) = outcome.require_all_passed() {
        panic!("{e}\n{outcome}");
    }
}

fn caught(defect: Defect, id: &str) {
    let model = ShredModel::new(Mutant(defect));
    let props = properties(&model);
    let outcome = check(&model, &props, &bound());
    if let Err(e) = expect_violation(&outcome, id) {
        panic!("{e}\n{outcome}");
    }
}

fn production() -> Production {
    Production::new().unwrap_or_else(|e| panic!("M-SHRED production backend: {e} (NotImplemented)"))
}

/// The steps a fault-free run of one request for `k0` takes.
fn one_run<B: ShredBackend>(m: &ShredModel<B>) -> Vec<RefStep> {
    let start = walk(m, &[ShredAction::Request]).unwrap_or_else(|e| panic!("{e}"));
    let states = drain(m, start.last().unwrap(), 64).unwrap_or_else(|e| panic!("{e}"));
    let mut steps = Vec::new();
    let mut prev = start.last().unwrap().clone();
    for s in states {
        let step = m
            .backend()
            .next(prev.plan.as_ref().unwrap())
            .unwrap()
            .unwrap();
        steps.push(step);
        prev = s;
    }
    steps
}

/// I-81 and no-data-loss along a run of `k0`'s erasure with a crash after
/// `k` steps, or right after the custody call of step `k`, and then a
/// resumed run to the end.
fn crash_run<B: ShredBackend>(
    m: &ShredModel<B>,
    k: usize,
    after_custody: bool,
) -> Result<(), String> {
    let mut script = vec![ShredAction::Request];
    script.extend(std::iter::repeat_n(ShredAction::Step, k));
    script.push(if after_custody {
        ShredAction::StepThenCrash
    } else {
        ShredAction::Crash
    });
    let mut states = walk(m, &script)?;
    let tail = drain(m, states.last().unwrap(), 64)?;
    states.extend(tail);
    let found = breaches(&states, m.layout());
    if !found.is_empty() {
        return Err(format!("{found:#?}"));
    }
    let end = &states.last().unwrap().env;
    if end.erased != BTreeSet::from([0]) {
        return Err(format!("the resumed run erased {:?}, not k0", end.erased));
    }
    Ok(())
}

fn resumes_at_every_step<B: ShredBackend>(m: &ShredModel<B>) {
    let steps = one_run(m);
    assert!(!steps.is_empty(), "the run took no step");
    let mut failures = Vec::new();
    for (k, step) in steps.iter().enumerate() {
        if let Err(e) = crash_run(m, k, false) {
            failures.push(format!("crash before step {k} ({step:?}): {e}"));
        }
        if step.calls_custody()
            && let Err(e) = crash_run(m, k, true)
        {
            failures.push(format!("crash after the custody call of {step:?}: {e}"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// The completion-after-receipt check along a run of `k0`'s erasure with
/// a custody fault armed before step `k`. The fault must fire: some
/// custody call of the run takes it, or the case tests nothing.
fn fault_run<B: ShredBackend>(
    m: &ShredModel<B>,
    k: usize,
    fault: ShredAction,
) -> Result<(), String> {
    let mut script = vec![ShredAction::Request];
    script.extend(std::iter::repeat_n(ShredAction::Step, k));
    script.push(fault);
    let mut states = walk(m, &script)?;
    let tail = drain(m, states.last().unwrap(), 64)?;
    states.extend(tail);
    let found = breaches(&states, m.layout());
    if !found.is_empty() {
        return Err(format!("{found:#?}"));
    }
    if !states.last().unwrap().env.fault_fired {
        return Err("the armed custody fault never fired".to_owned());
    }
    match states.last().unwrap().env.completions.as_slice() {
        [c] if c.erased == vec![0] => Ok(()),
        other => Err(format!("completions {other:?}")),
    }
}

fn completion_after_receipt<B: ShredBackend>(m: &ShredModel<B>) {
    let steps = one_run(m);
    assert!(!steps.is_empty(), "the run took no step");
    let last_custody = steps
        .iter()
        .rposition(RefStep::calls_custody)
        .expect("the run makes no custody call");
    let mut failures = Vec::new();
    for k in 0..=last_custody {
        for fault in [ShredAction::CustodyFails, ShredAction::CustodyReplyLost] {
            if let Err(e) = fault_run(m, k, fault) {
                failures.push(format!("{fault:?} before step {k}: {e}"));
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

// ---------------------------------------------------------------------------
// M-SHRED.

/// I-81, M-SHRED over production: `fstp_keys::erasure`.
#[test]
fn i81_m_shred() {
    passes(production());
}

/// I-81, M-SHRED over the reference planner: every property and witness
/// holds.
#[test]
fn i81_m_shred_on_the_reference() {
    passes(Reference);
}

/// I-81, design section 14.1: the recorded tripwire count is the measured
/// state count of M-SHRED over the reference.
#[test]
fn i81_m_shred_tripwire_records_the_measured_count() {
    let space = explore(&ShredModel::new(Reference), &Config::default());
    assert!(
        space.exhaustive,
        "M-SHRED over the reference did not finish"
    );
    assert_eq!(
        M_SHRED,
        space.len(),
        "record the measured M-SHRED count {} in fstp_celltest::mc::tripwires (lane W4)",
        space.len()
    );
}

// ---------------------------------------------------------------------------
// Teeth (design section 14.2).

/// I-81 teeth: a planner that re-wraps the affected group's old
/// generation under the new epoch, instead of rotating the group, leaves
/// the erased key openable. M-SHRED reports I-81.
#[test]
fn i81_teeth_group_not_rotated_is_caught() {
    caught(Defect::GroupNotRotated, ids::I81);
}

/// I-81 teeth: a planner that destroys the old epoch before the new rows
/// commit loses every live key. M-SHRED reports no-data-loss.
#[test]
fn i81_teeth_destroy_before_commit_loses_data_is_caught() {
    caught(Defect::DestroyBeforeCommit, ids::NO_DATA_LOSS);
}

/// I-81 teeth: a planner that records completion before the destroy
/// receipt reports a key erased while its epoch lives. M-SHRED reports
/// completion-after-receipt.
#[test]
fn i81_teeth_completion_before_receipt_is_caught() {
    caught(Defect::CompleteBeforeReceipt, ids::COMPLETION_AFTER_RECEIPT);
}

/// I-81 teeth: the same defect also breaks I-81 itself, since the erased
/// key opens under the old root.
#[test]
fn i81_teeth_completion_before_receipt_breaks_i81() {
    caught(Defect::CompleteBeforeReceipt, ids::I81);
}

/// I-81, environment requirement of M-SHRED: a crash after `NewEpoch`
/// leaves a custody root that re-wrapped every live group secret. If
/// `DestroyRoot` destroys only the committed root of its epoch, that
/// orphan keeps a later erased key openable, even under the reference
/// planner. So the shell must destroy every root of the epoch, found
/// through the `KeyOp` records of ADR-004 "Reconciliation".
#[test]
fn i81_orphan_root_of_a_crashed_rotation_must_die_with_its_epoch() {
    let model = ShredModel::new(Reference).with_orphans_surviving();
    let props = properties(&model);
    let outcome = check(&model, &props, &bound());
    if let Err(e) = expect_violation(&outcome, ids::I81) {
        panic!("{e}\n{outcome}");
    }
}

// ---------------------------------------------------------------------------
// The pure planner, in scripted runs.

/// I-81, ADR-004 "An erasure is reported complete only at step 7, after
/// the destroy receipt". A custody call fails, or its reply is lost,
/// before some step. Production then records the one completion only after
/// the old epoch's receipt, and loses no live key.
#[test]
fn i81_completion_recorded_only_after_destroy_receipt() {
    completion_after_receipt(&ShredModel::new(production()));
}

/// I-81: the reference twin of
/// `i81_completion_recorded_only_after_destroy_receipt`.
#[test]
fn i81_completion_recorded_only_after_destroy_receipt_on_the_reference() {
    completion_after_receipt(&ShredModel::new(Reference));
}

/// I-81, ADR-004 "A crash at any step loses nothing. The pure planner
/// resumes from the stored phase": production resumes after a crash
/// before every step, and right after every custody call, then erases
/// `k0` with no breach of I-81 or no-data-loss on the way.
#[test]
fn i81_erasure_resumes_after_crash_at_every_step() {
    resumes_at_every_step(&ShredModel::new(production()));
}

/// I-81: the reference twin of
/// `i81_erasure_resumes_after_crash_at_every_step`.
#[test]
fn i81_erasure_resumes_after_crash_at_every_step_on_the_reference() {
    resumes_at_every_step(&ShredModel::new(Reference));
}

/// I-81 teeth for the scripted runs: the destroy-before-commit planner
/// fails the crash and resume check.
#[test]
fn i81_teeth_scripted_crash_run_sees_destroy_before_commit() {
    let m = ShredModel::new(Mutant(Defect::DestroyBeforeCommit));
    let steps = one_run(&m);
    let failed = (0..steps.len()).any(|k| crash_run(&m, k, false).is_err());
    assert!(failed, "no scripted crash run caught the defect");
}

/// I-81, design section 3.5: `plan_erasure` lists the steps `next`
/// takes, in order, for one fault-free run of `k0`'s erasure.
#[test]
fn i81_plan_erasure_lists_the_steps_next_takes() {
    let m = ShredModel::new(production());
    let start = walk(&m, &[ShredAction::Request]).unwrap_or_else(|e| panic!("{e}"));
    let planned = production_plan(
        start.last().unwrap().plan.as_ref().unwrap(),
        &BTreeSet::from([0]),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(planned, one_run(&m));
}

/// I-81, design section 3.5: production's steps for one erasure of `k0`
/// equal the reference's: new generations of `g0` and the digest group
/// `g2`, `k1` resealed, a new
/// epoch, re-wrap, commit, snapshot, verify, destroy, completion.
#[test]
fn i81_production_steps_match_reference_steps() {
    let prod = one_run(&ShredModel::new(production()));
    let reference = one_run(&ShredModel::new(Reference));
    assert_eq!(prod, reference);
}

/// I-81, design section 3.5: the reference run for `k0` is the seven
/// steps of ADR-004 in order. Step 2 also replaces the digest group `g2`,
/// whose subject `k0` is (G24), and reseals no key into it. A self-check
/// of the reference.
#[test]
fn i81_reference_run_follows_the_adr_004_order() {
    let steps = one_run(&ShredModel::new(Reference));
    assert_eq!(
        steps,
        vec![
            RefStep::NewGroups(vec![0, 2]),
            RefStep::Reseal {
                group: 0,
                keep: vec![1]
            },
            RefStep::Reseal {
                group: 2,
                keep: vec![]
            },
            RefStep::NewEpoch(2),
            RefStep::RewrapGroups(2),
            RefStep::Commit(2),
            RefStep::Snapshot(2),
            RefStep::VerifySnapshot(2),
            RefStep::DestroyRoot(1),
            RefStep::Complete {
                epoch: 2,
                erased: vec![0]
            },
        ]
    );
}

// ---------------------------------------------------------------------------
// Progress, sibling batches and keyed digests (fix round 1).

/// I-81 teeth for `requests-complete`: a planner that ignores a request
/// arriving while a run is in flight never erases that key. ADR-004 part
/// 2 has such requests "join the next rotation". M-SHRED reports it.
#[test]
fn i81_teeth_dropped_mid_run_request_is_caught() {
    caught(Defect::DropsMidRunRequest, ids::REQUESTS_COMPLETE);
}

/// I-81 teeth for `requests-complete`: a planner whose restart forgets
/// the queued requests breaks "A crash at any step loses nothing"
/// (ADR-004 part 2). M-SHRED reports it.
#[test]
fn i81_teeth_queue_lost_on_restart_is_caught() {
    caught(Defect::ForgetsQueueOnRestart, ids::REQUESTS_COMPLETE);
}

/// I-81 teeth: a planner whose `Reseal` drops only the first erased key
/// of a group seals the other erased siblings to the new generation. The
/// second request order puts `k2` and `k3` of `g1` in one batch, so
/// M-SHRED reports I-81.
#[test]
fn i81_teeth_reseal_keeps_a_second_erased_sibling_is_caught() {
    caught(Defect::ResealsAllButOneErased, ids::I81);
}

/// I-81 teeth (design section 3.5, G24): a planner that keeps the digest
/// group when a rotation erases one of its subjects re-wraps the old
/// digest key under the new epoch. That key still digests the erased
/// subject, so M-SHRED reports I-81.
#[test]
fn i81_teeth_digest_key_not_rotated_is_caught() {
    caught(Defect::DigestNotRotated, ids::I81);
}

/// The digest key instances of `env` that digested `k` and open from
/// every row ever written under the live roots.
fn open_digest_keys(env: &Env, k: u8) -> BTreeSet<u8> {
    let open = closure(env.written.iter(), &env.live_roots());
    env.digest_keys_of(k)
        .into_iter()
        .filter(|s| open.secrets.contains(s))
        .collect()
}

/// I-81 (design section 3.5, G24) along one erasure of `k0`: the old
/// digest key, which digested `k0`, opens until `DestroyRoot` runs and
/// never after. The new digest key opens from the live store and has not
/// digested `k0`.
fn old_digest_key_dies<B: ShredBackend>(m: &ShredModel<B>) {
    let start = walk(m, &[ShredAction::Request]).unwrap_or_else(|e| panic!("{e}"));
    let first = start.last().unwrap().clone();
    let states = drain(m, &first, 64).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        !open_digest_keys(&first.env, 0).is_empty(),
        "no digest key of k0 opens before the erasure: the check below tests nothing"
    );
    let mut prev = first;
    for s in &states {
        let step = m.backend().next(prev.plan.as_ref().unwrap()).unwrap();
        let destroyed = prev.env.receipts.contains(&1) || step == Some(RefStep::DestroyRoot(1));
        let open = open_digest_keys(&s.env, 0);
        if destroyed {
            assert!(
                open.is_empty(),
                "after {step:?} digest keys {open:?} of k0 open"
            );
        }
        prev = s.clone();
    }
    let end = &prev.env;
    assert_eq!(end.erased, BTreeSet::from([0]));
    let current = end.current[2];
    let live = closure(end.live.iter(), &end.live_roots());
    assert!(
        live.secrets.contains(&current),
        "the new digest key does not open"
    );
    assert!(
        !end.digest_knows[usize::from(current)].contains(&0),
        "the new digest key digested the erased k0"
    );
}

/// I-81, design section 3.5 (G24): over production `fstp_keys::erasure`,
/// the old digest key dies with its epoch.
#[test]
fn i81_old_digest_key_dies_with_its_epoch() {
    old_digest_key_dies(&ShredModel::new(production()));
}

/// I-81: the reference twin of `i81_old_digest_key_dies_with_its_epoch`.
#[test]
fn i81_old_digest_key_dies_with_its_epoch_on_the_reference() {
    old_digest_key_dies(&ShredModel::new(Reference));
}

/// I-81, M-SHRED witness fidelity: a custody fault armed after the last
/// custody call of a run never fires, so its completion is no recovery
/// from a fault. The `witness-custody-fault-recovers` state is not
/// reached on that path.
#[test]
fn i81_fault_witness_needs_a_fired_fault() {
    let m = ShredModel::new(Reference);
    let steps = one_run(&m);
    let destroy = steps
        .iter()
        .position(|s| matches!(s, RefStep::DestroyRoot(_)))
        .unwrap();
    let mut script = vec![ShredAction::Request];
    script.extend(std::iter::repeat_n(ShredAction::Step, destroy + 1));
    script.push(ShredAction::CustodyFails);
    script.push(ShredAction::Step);
    let states = walk(&m, &script).unwrap_or_else(|e| panic!("{e}"));
    let end = &states.last().unwrap().env;
    assert_eq!(end.erased, BTreeSet::from([0]), "the run did not complete");
    assert!(
        !end.fault_fired,
        "the fault fired with no custody call left"
    );
    assert!(
        !end.recovered_after_fault,
        "the fault witness holds with no fault fired"
    );
}
