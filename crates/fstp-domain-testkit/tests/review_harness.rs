//! Review reproducers for the fstp-mc adapters (design section 6.1).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain_testkit::harness::mc::check_exhaustive;
use fstp_mc::{Model, Property};

/// A model in which every action is refused: only the initial state exists.
/// It stands for an engine that refuses everything.
struct RefusesEverything;

#[derive(Clone, Debug)]
struct Act;

impl Model for RefusesEverything {
    type State = u8;
    type Action = Act;

    fn init(&self) -> Vec<u8> {
        vec![0]
    }

    fn actions(&self, _: &u8, actions: &mut Vec<Act>) {
        actions.push(Act);
    }

    fn step(&self, _: &u8, _: &Act) -> Option<u8> {
        None
    }

    fn is_terminal(&self, _: &u8) -> bool {
        true
    }
}

/// Design 6.1 "No vacuous models": every model has `reachable` witnesses,
/// so an engine that refuses everything fails. `check_exhaustive` is the
/// adapter every model run goes through, yet it passes a property list with
/// no `reachable` witness at all, over a model that refuses everything.
#[test]
fn review_check_exhaustive_requires_a_reachable_witness() {
    let props = vec![Property::<RefusesEverything>::always("I-toy", |s| *s == 0)];
    let r = check_exhaustive(&RefusesEverything, &props, 1);
    assert!(
        r.is_err(),
        "a run with no reachable witness over a model that refuses everything passed"
    );
}
