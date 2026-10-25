//! Self-tests of the teeth helpers (`docs/handoff/m2-design.md` section 6.1).
//!
//! - A teeth test injects records that a broken engine would emit, through
//!   the public structural `apply`, and asserts that the property fails.
//!   No production hook exists.
//! - An over-denial mutant drops a legal action, and the test asserts that
//!   a `reachable` property becomes unreachable.
//! - A teeth assertion must itself fail when the injected fault goes
//!   undetected, or a broken property could pass its teeth test.
//!
//! API this file is written against, in
//! `fstp_domain_testkit::harness::teeth`: `inject(state, seq, at, record)`,
//! `expect_violation(outcome, id)`, `expect_unreachable(outcome, id)`,
//! `expect_prop_failure(outcome, id)`, `names_property(message, id)`,
//! `inject_entry(ledger, state, at, command, record)`,
//! `replace_record(ledger, seq, record)`, `Injecting::new(&model, fault)` with
//! actions `Mutant::Model(_)` and `Mutant::Fault`, and
//! `Dropping::new(&model, drop)`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_domain::engine::{FoldError, apply};
use fstp_domain::id::{ContentDigest, VaultEpoch};
use fstp_domain::oracle::QueryKind;
use fstp_domain::record::Record;
use fstp_domain::state::State;
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::harness::prop::{append_only, ledger_step};
use fstp_domain_testkit::harness::teeth::{
    Dropping, InjectError, Injecting, Mutant, expect_prop_failure, expect_unreachable,
    expect_violation, inject, inject_entry, names_property, replace_record,
};
use fstp_engine::EngineState;
use fstp_ledger::{Entry, Seq};
use fstp_mc::{Config, Model, Property, check};
use fstp_prop::{Config as PropConfig, Gen, StateMachine, prop_assert, run, run_machine};

/// A record whose fold is structural today.
fn vault_outcome() -> Record {
    Record::VaultOutcome {
        kind: QueryKind::HasConflict,
        digest: ContentDigest::from_bytes([3; 32]),
        holds: true,
        epoch: VaultEpoch::GENESIS,
    }
}

// ---------------------------------------------------------------------------
// Injection through apply
// ---------------------------------------------------------------------------

/// Design 6.1: an injected record reaches the public structural `apply`.
/// The state after injection equals the state that `apply` itself gives,
/// and the record's time becomes the time floor.
#[test]
fn harness_teeth_injection_reaches_the_structural_apply() {
    let mut injected = State::genesis();
    let at = Timestamp::from_micros(42);
    assert_eq!(
        inject(&mut injected, Seq::from_raw(1), at, &vault_outcome()),
        Ok(())
    );
    let mut applied = State::genesis();
    apply(&mut applied, Seq::from_raw(1), at, &vault_outcome()).expect("apply");
    assert_eq!(injected, applied);
    assert_eq!(injected.now_floor(), at);
}

/// Design 6.1: injection reports the fold's refusal and leaves the state
/// unchanged. A record earlier than the time floor is refused.
#[test]
fn harness_teeth_injection_reports_the_fold_refusal() {
    let mut state = State::genesis();
    inject(
        &mut state,
        Seq::from_raw(1),
        Timestamp::from_micros(42),
        &vault_outcome(),
    )
    .expect("first injection");
    let before = state.clone();
    assert_eq!(
        inject(
            &mut state,
            Seq::from_raw(2),
            Timestamp::from_micros(41),
            &vault_outcome()
        ),
        Err(FoldError::TimeBackwards)
    );
    assert_eq!(state, before);
}

// ---------------------------------------------------------------------------
// Fault injection in models
// ---------------------------------------------------------------------------

/// A counter from 0 to 3. Its invariant is that it never passes 3.
struct Counter;

#[derive(Clone, Debug)]
struct Inc;

impl Model for Counter {
    type State = u8;
    type Action = Inc;

    fn init(&self) -> Vec<u8> {
        vec![0]
    }

    fn actions(&self, _: &u8, actions: &mut Vec<Inc>) {
        actions.push(Inc);
    }

    fn step(&self, s: &u8, _: &Inc) -> Option<u8> {
        (*s < 3).then(|| s + 1)
    }
}

fn props<'a, M: Model<State = u8>>() -> Vec<Property<'a, M>> {
    vec![
        Property::always("I-toy", |s: &u8| *s <= 3),
        Property::reachable("top", |s: &u8| *s == 3),
    ]
}

fn full() -> Config {
    Config::default().with_stop_when_decided(false)
}

/// Design 6.1: a fault that breaks the invariant is injected, the checker
/// finds the violation, and the teeth assertion passes.
#[test]
fn harness_teeth_expect_violation_passes_when_the_fault_is_caught() {
    let model = Injecting::new(&Counter, |_: &u8| Some(99));
    let outcome = check(&model, &props(), &full());
    assert_eq!(expect_violation(&outcome, "I-toy"), Ok(()));
}

/// Design 6.1: when the injected fault is not detected, the teeth
/// assertion fails. Here the fault leaves the state unchanged, so the
/// invariant is verified and `expect_violation` must report an error.
#[test]
fn harness_teeth_expect_violation_fails_when_the_fault_is_not_detected() {
    let model = Injecting::new(&Counter, |s: &u8| Some(*s));
    let outcome = check(&model, &props(), &full());
    assert!(outcome.exhaustive);
    assert!(expect_violation(&outcome, "I-toy").is_err());
    assert!(expect_violation(&outcome, "no-such-property").is_err());
}

/// Design 6.1: the injected fault is an extra action, and the model's own
/// actions stay enabled beside it.
#[test]
fn harness_teeth_injecting_keeps_the_model_actions() {
    let model = Injecting::new(&Counter, |_: &u8| Some(99));
    let mut actions = Vec::new();
    model.actions(&0, &mut actions);
    assert!(actions.iter().any(|a| matches!(a, Mutant::Model(Inc))));
    assert!(actions.iter().any(|a| matches!(a, Mutant::Fault)));
    assert_eq!(model.step(&0, &Mutant::Model(Inc)), Some(1));
    assert_eq!(model.step(&0, &Mutant::Fault), Some(99));
}

// ---------------------------------------------------------------------------
// Over-denial mutants
// ---------------------------------------------------------------------------

/// Design 6.1: dropping the only legal action makes the witness
/// unreachable, and the over-denial assertion passes.
#[test]
fn harness_teeth_over_denial_mutant_makes_the_witness_unreachable() {
    let model = Dropping::new(&Counter, |_: &Inc| true);
    let outcome = check(&model, &props(), &full());
    assert_eq!(expect_unreachable(&outcome, "top"), Ok(()));
}

/// Design 6.1: on the unmutated model the witness is reached, so the
/// over-denial assertion fails.
#[test]
fn harness_teeth_expect_unreachable_fails_on_the_unmutated_model() {
    let model = Dropping::new(&Counter, |_: &Inc| false);
    let outcome = check(&model, &props(), &full());
    assert!(expect_unreachable(&outcome, "top").is_err());
    assert!(expect_unreachable(&outcome, "no-such-property").is_err());
}

// ---------------------------------------------------------------------------
// fstp-prop teeth
// ---------------------------------------------------------------------------

/// Design 6.1: a property that fails under the injected fault passes the
/// teeth assertion.
#[test]
fn harness_teeth_expect_prop_failure_accepts_a_failing_property() {
    let outcome = run(
        "harness_teeth_fault_detected",
        PropConfig::default().with_cases(64),
        |g| {
            let x = g.u8();
            prop_assert!(x < 3, "I-toy: x reached {x}");
            Ok(())
        },
    );
    assert_eq!(expect_prop_failure(&outcome, "I-toy"), Ok(()));
    assert!(expect_prop_failure(&outcome, "I-23").is_err());
    assert!(expect_prop_failure(&outcome, "I-to").is_err());
}

/// Design 6.1: a property that passes despite the injected fault fails the
/// teeth assertion.
#[test]
fn harness_teeth_expect_prop_failure_rejects_a_passing_property() {
    let outcome = run(
        "harness_teeth_fault_undetected",
        PropConfig::default().with_cases(16),
        |g| {
            let _ = g.u8();
            Ok(())
        },
    );
    assert!(expect_prop_failure(&outcome, "I-toy").is_err());
}

/// Design 6.1: a failure names a property only by its whole id followed by
/// a colon, so a teeth test for one id is never passed by another.
#[test]
fn harness_teeth_names_property_matches_whole_ids() {
    assert!(names_property("I-23: the ledger shrank", "I-23"));
    assert!(names_property(
        "invariant failed after step 2 (Step): I-14: above the cap",
        "I-14"
    ));
    assert!(!names_property("I-23: the ledger shrank", "I-2"));
    assert!(!names_property("XI-23: no", "I-23"));
    assert!(!names_property("I-23 without a colon", "I-23"));
    assert!(!names_property("anything: at all", ""));
}

// ---------------------------------------------------------------------------
// Ledger-consistent injection
// ---------------------------------------------------------------------------

fn envelope(holds: bool) -> fstp_engine::Record {
    fstp_engine::Record::Core(Record::VaultOutcome {
        kind: QueryKind::HasConflict,
        digest: ContentDigest::from_bytes([3; 32]),
        holds,
        epoch: VaultEpoch::GENESIS,
    })
}

/// Design 6.1 and I-23: an injected entry goes into the ledger with the
/// next sequence number and into the state in the same call, so the I-23
/// ledger checks still pass after it.
#[test]
fn i23_teeth_inject_entry_keeps_replay_equal_to_state() {
    let mut ledger = Vec::new();
    let mut state = EngineState::genesis();
    for n in 1..=3u64 {
        let previous = ledger.clone();
        let seq = inject_entry(
            &mut ledger,
            &mut state,
            Timestamp::from_micros(10 * n as i64),
            [n as u8; 16],
            envelope(n % 2 == 0),
        )
        .expect("structural fold");
        assert_eq!(seq, Seq::from_raw(n));
        assert_eq!(ledger_step(&previous, &ledger, &state), Ok(()));
    }
    assert_eq!(ledger[2].at, 30);
    assert_eq!(ledger[2].command, [3; 16]);
}

/// Design 6.1: when the fold refuses the injected record, neither the
/// ledger nor the state changes.
#[test]
fn harness_teeth_inject_entry_refused_changes_nothing() {
    let mut ledger = Vec::new();
    let mut state = EngineState::genesis();
    inject_entry(
        &mut ledger,
        &mut state,
        Timestamp::from_micros(42),
        [1; 16],
        envelope(true),
    )
    .expect("first injection");
    let (before_ledger, before_state) = (ledger.clone(), state.clone());
    let r = inject_entry(
        &mut ledger,
        &mut state,
        Timestamp::from_micros(41),
        [2; 16],
        envelope(true),
    );
    assert_eq!(r, Err(InjectError::Fold(FoldError::TimeBackwards)));
    assert_eq!(ledger, before_ledger);
    assert_eq!(state, before_state);
}

/// Design 6.1 and I-23: the "changed past entry" fault keeps the envelope
/// of the entry and changes its record, and the append-only check catches it.
#[test]
fn i23_teeth_changed_past_entry_is_caught() {
    let mut ledger = Vec::new();
    let mut state = EngineState::genesis();
    for n in 1..=2u8 {
        inject_entry(
            &mut ledger,
            &mut state,
            Timestamp::from_micros(i64::from(n)),
            [n; 16],
            envelope(true),
        )
        .expect("structural fold");
    }
    let previous = ledger.clone();
    let old = replace_record(&mut ledger, Seq::from_raw(1), envelope(false));
    assert_eq!(old, Some(envelope(true)));
    assert_eq!(ledger[0].seq, previous[0].seq);
    assert_eq!(ledger[0].command, previous[0].command);
    let message = append_only(&previous, &ledger).expect_err("the change passed");
    assert!(names_property(&message, "I-23"), "{message}");
    assert_eq!(
        replace_record(&mut ledger, Seq::from_raw(9), envelope(true)),
        None
    );
}

/// A machine whose model ledger and state stay consistent: it injects
/// through `inject_entry`. The target property `I-toy` says no injected
/// outcome holds, and the fault injects one that does.
struct CaughtTeeth;

struct Sut {
    previous: Vec<Entry<fstp_engine::Record>>,
    ledger: Vec<Entry<fstp_engine::Record>>,
    state: EngineState,
}

#[derive(Debug)]
struct Step;

impl StateMachine for CaughtTeeth {
    type Model = ();
    type Sut = Sut;
    type Command = Step;
    type Output = ();

    fn init_model(&self) {}

    fn init_sut(&self) -> Sut {
        Sut {
            previous: Vec::new(),
            ledger: Vec::new(),
            state: EngineState::genesis(),
        }
    }

    fn command(&self, _: &mut Gen, _: &()) -> Step {
        Step
    }

    fn run(&self, sut: &mut Sut, _: &Step) {
        sut.previous = sut.ledger.clone();
        let n = sut.ledger.len() as u8;
        inject_entry(
            &mut sut.ledger,
            &mut sut.state,
            Timestamp::from_micros(1),
            [n; 16],
            envelope(true),
        )
        .expect("structural fold");
    }

    fn next_state(&self, _: &mut (), _: &Step) {}

    fn invariant(&self, _: &(), sut: &Sut) -> Result<(), String> {
        ledger_step(&sut.previous, &sut.ledger, &sut.state)?;
        let holding = sut.ledger.iter().any(|e| {
            matches!(
                e.record,
                fstp_engine::Record::Core(Record::VaultOutcome { holds: true, .. })
            )
        });
        if holding {
            return Err("I-toy: an injected outcome holds".to_owned());
        }
        Ok(())
    }
}

/// Design 6.1: with ledger-consistent injection the I-23 checks pass, so
/// the target property is what catches the fault, and the teeth assertion
/// for that id passes. The same run does not pass a teeth test for I-23.
#[test]
fn harness_teeth_machine_fault_is_caught_by_the_target_property() {
    let outcome = run_machine(
        "harness_teeth_machine_fault_is_caught_by_the_target_property",
        PropConfig::default().with_cases(8),
        &CaughtTeeth,
    );
    assert_eq!(expect_prop_failure(&outcome, "I-toy"), Ok(()));
    assert!(expect_prop_failure(&outcome, "I-23").is_err());
}
