//! Review reproducers: usability of the harness for later lanes (design sections 6.1 and 10).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_domain::id::{ContentDigest, VaultEpoch};
use fstp_domain::oracle::QueryKind;
use fstp_domain::record::Record as CoreRecord;
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::harness::prop::ledger_step;
use fstp_domain_testkit::harness::teeth::{expect_prop_failure, inject_envelope};
use fstp_engine::{EngineState, Record};
use fstp_ledger::{Entry, Seq};
use fstp_prop::{Config as PropConfig, Gen, StateMachine, run_machine};

/// A system under test as a W3 to W5 machine holds it: a ledger, the
/// previous read of it and the engine state.
struct Sut {
    previous: Vec<Entry<Record>>,
    ledger: Vec<Entry<Record>>,
    state: EngineState,
    steps: u64,
}

#[derive(Debug)]
struct Step;

/// A teeth machine. Each step injects a record that a broken engine would
/// emit through `inject_envelope`, as design 6.1 describes. The target
/// predicate stands for a broken invariant check that misses the fault, so
/// it always passes. The invariant also runs the I-23 ledger step, as every
/// machine must.
struct VacuousTeeth;

impl StateMachine for VacuousTeeth {
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
            steps: 0,
        }
    }

    fn command(&self, _: &mut Gen, _: &()) -> Step {
        Step
    }

    fn run(&self, sut: &mut Sut, _: &Step) {
        sut.previous = sut.ledger.clone();
        sut.steps += 1;
        let record = Record::Core(CoreRecord::VaultOutcome {
            kind: QueryKind::HasConflict,
            digest: ContentDigest::from_bytes([3; 32]),
            holds: true,
            epoch: VaultEpoch::GENESIS,
        });
        inject_envelope(
            &mut sut.state,
            Seq::from_raw(sut.steps),
            Timestamp::from_micros(1),
            &record,
        )
        .expect("structural fold");
    }

    fn next_state(&self, _: &mut (), _: &Step) {}

    fn invariant(&self, _: &(), sut: &Sut) -> Result<(), String> {
        ledger_step(&sut.previous, &sut.ledger, &sut.state)?;
        // The target predicate under test. It is broken and never fires.
        Ok(())
    }
}

/// Design 6.1 Teeth: a teeth test must fail when the target property misses
/// the injected fault. `inject_envelope` folds into the state only, never
/// into the ledger, and every machine checks `replay(ledger) == state`. So
/// the I-23 check fires on every injection. `expect_prop_failure` cannot
/// name the property that must catch the fault, so it accepts that I-23
/// failure, and the teeth test passes although the target predicate is
/// vacuous. The assertion now takes the target id, `I-toy` here, and a
/// failure that names only I-23 is reported as undetected.
#[test]
fn review_prop_teeth_pass_on_the_i23_replay_check_alone() {
    let outcome = run_machine(
        "review_prop_teeth_pass_on_the_i23_replay_check_alone",
        PropConfig::default().with_cases(8),
        &VacuousTeeth,
    );
    let message = outcome.failure().map(|f| f.message.clone());
    assert!(
        message.as_deref().is_some_and(|m| m.contains("I-23")),
        "setup: the I-23 replay check should be what fails, got {message:?}"
    );
    assert!(
        expect_prop_failure(&outcome, "I-toy").is_err(),
        "teeth passed although only the I-23 replay check fired: {message:?}"
    );
}
