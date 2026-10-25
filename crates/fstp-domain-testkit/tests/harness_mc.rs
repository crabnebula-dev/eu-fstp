//! Self-tests of the fstp-mc adapters (`docs/handoff/m2-design.md` section 6.1).
//!
//! - Every model run is exhaustive, with `stop_when_decided(false)`, and
//!   every property must pass, including the `reachable` witnesses.
//! - `max_states` is a tripwire at twice the measured state count, so a
//!   model that grows past it fails visibly.
//! - Symmetry reduction is enabled only with a self-test that compares
//!   every verdict with and without it.
//!
//! The models here are toys, so the tests do not depend on any domain lane.
//!
//! API this file is written against, in `fstp_domain_testkit::harness::mc`:
//! `tripwire(measured)`, `check_exhaustive(model, properties, measured)`,
//! `Unreduced(&model)` and
//! `symmetry_selftest(model, reduced_properties, full_properties, config)`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_domain_testkit::harness::mc::{Unreduced, check_exhaustive, symmetry_selftest, tripwire};
use fstp_mc::{Config, Model, Property};
use fstp_prop::{check, prop_assert, prop_assert_eq};

// ---------------------------------------------------------------------------
// Toy models
// ---------------------------------------------------------------------------

/// A counter from 0 to `limit`: exactly `limit + 1` states.
struct Counter {
    limit: u8,
}

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
        (*s < self.limit).then(|| s + 1)
    }

    fn is_terminal(&self, s: &u8) -> bool {
        *s == self.limit
    }
}

fn counter_properties<'a>(limit: u8) -> Vec<Property<'a, Counter>> {
    vec![
        Property::always("bounded", move |s| *s <= limit),
        Property::reachable("top", move |s| *s == limit),
        Property::deadlock_free("no-deadlock"),
    ]
}

/// Which `canonicalize` the pair model uses.
#[derive(Clone, Copy, Debug)]
enum Canon {
    /// Sorts the pair. Sound for properties symmetric in the two tokens.
    Sorted,
    /// Maps every state to the initial one. Never sound.
    Collapse,
}

/// Two interchangeable tokens, each counting from 0 to 2.
struct Pair {
    canon: Canon,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Side {
    Left,
    Right,
}

impl Model for Pair {
    type State = (u8, u8);
    type Action = Side;

    fn init(&self) -> Vec<(u8, u8)> {
        vec![(0, 0)]
    }

    fn actions(&self, _: &(u8, u8), actions: &mut Vec<Side>) {
        actions.extend([Side::Left, Side::Right]);
    }

    fn step(&self, &(l, r): &(u8, u8), side: &Side) -> Option<(u8, u8)> {
        match side {
            Side::Left => (l < 2).then_some((l + 1, r)),
            Side::Right => (r < 2).then_some((l, r + 1)),
        }
    }

    fn is_terminal(&self, s: &(u8, u8)) -> bool {
        *s == (2, 2)
    }

    fn canonicalize(&self, &(l, r): &(u8, u8)) -> (u8, u8) {
        match self.canon {
            Canon::Sorted => (l.min(r), l.max(r)),
            Canon::Collapse => (0, 0),
        }
    }
}

/// Properties symmetric in the two tokens, for any model over pair states.
fn symmetric_properties<'a, M>() -> Vec<Property<'a, M>>
where
    M: Model<State = (u8, u8), Action = Side>,
{
    vec![
        Property::always("sum-at-most-4", |&(l, r): &(u8, u8)| l + r <= 4),
        Property::reachable("both-at-2", |s: &(u8, u8)| *s == (2, 2)),
        Property::transition(
            "one-unit-per-step",
            |&(a, b): &(u8, u8), _: &Side, &(c, d): &(u8, u8)| c + d == a + b + 1,
        ),
        Property::deadlock_free("no-deadlock"),
    ]
}

/// Adds a property that is not symmetric: the left token never leads.
fn with_asymmetric_property<'a, M>() -> Vec<Property<'a, M>>
where
    M: Model<State = (u8, u8), Action = Side>,
{
    let mut props = symmetric_properties::<M>();
    props.push(Property::always(
        "left-never-leads",
        |&(l, r): &(u8, u8)| l <= r,
    ));
    props
}

fn full_config() -> Config {
    Config::default().with_stop_when_decided(false)
}

// ---------------------------------------------------------------------------
// Tripwire
// ---------------------------------------------------------------------------

/// Design 6.1: the tripwire configuration runs exhaustively with every
/// verdict decided, unbounded in depth, and stores at most twice the
/// measured count. Doubling saturates instead of overflowing.
#[test]
fn harness_tripwire_config_is_twice_the_measured_count() {
    let c = tripwire(7);
    assert_eq!(c.max_states, 14);
    assert!(!c.stop_when_decided);
    assert_eq!(c.max_depth, usize::MAX);
    assert_eq!(tripwire(usize::MAX).max_states, usize::MAX);
}

/// Design 6.1: an exhaustive check fails a run whose state count exceeds
/// twice the measured count, and passes every run within it. A passing run
/// is exhaustive and reports the true state count.
#[test]
fn harness_tripwire_fails_exactly_when_states_exceed_twice_measured() {
    check(
        "harness_tripwire_fails_exactly_when_states_exceed_twice_measured",
        |g| {
            let limit = g.u8_in(0..=40);
            let measured = g.usize_in(1..=40);
            let states = usize::from(limit) + 1;
            let model = Counter { limit };
            let result = check_exhaustive(&model, &counter_properties(limit), measured);
            let within = states <= 2 * measured;
            g.note("states", &states);
            g.note("measured", &measured);
            prop_assert_eq!(result.is_ok(), within);
            if let Ok(outcome) = result {
                prop_assert!(outcome.exhaustive, "a passing run was not exhaustive");
                prop_assert_eq!(outcome.stats.states, states);
            }
            Ok(())
        },
    );
}

/// Design 6.1: an exhaustive check fails when an invariant is violated,
/// even within the tripwire.
#[test]
fn harness_check_exhaustive_fails_on_a_violated_property() {
    let model = Counter { limit: 3 };
    let props = vec![
        Property::<Counter>::always("never-three", |s| *s != 3),
        Property::<Counter>::reachable("top", |s| *s == 3),
    ];
    let message = check_exhaustive(&model, &props, 4).expect_err("the violation passed");
    assert!(message.contains("never-three"), "{message}");
}

/// Design 6.1 "No vacuous models": a property list without a `reachable`
/// witness fails, even over a model whose invariants all hold. The
/// symmetry self-test applies the same rule.
#[test]
fn harness_check_exhaustive_requires_a_reachable_witness() {
    let model = Counter { limit: 3 };
    let props = vec![Property::<Counter>::always("bounded", |s| *s <= 3)];
    let message = check_exhaustive(&model, &props, 4).expect_err("no witness passed");
    assert!(message.contains("reachable witnesses"), "{message}");
    let pair = Pair {
        canon: Canon::Sorted,
    };
    let reduced = vec![Property::<Pair>::always(
        "sum-at-most-4",
        |&(l, r): &(u8, u8)| l + r <= 4,
    )];
    let full = vec![Property::<Unreduced<'_, Pair>>::always(
        "sum-at-most-4",
        |&(l, r): &(u8, u8)| l + r <= 4,
    )];
    assert!(symmetry_selftest(&pair, &reduced, &full, &full_config()).is_err());
}

/// Design 6.1: an exhaustive check fails when a `reachable` witness is
/// unreachable, so a model that does nothing cannot pass vacuously.
#[test]
fn harness_check_exhaustive_fails_on_an_unreachable_witness() {
    let model = Counter { limit: 3 };
    let props = vec![Property::<Counter>::reachable("four", |s| *s == 4)];
    assert!(check_exhaustive(&model, &props, 4).is_err());
}

/// Design 6.1: an exhaustive check passes a model whose properties all
/// hold and whose witnesses are reached.
#[test]
fn harness_check_exhaustive_passes_a_sound_model() {
    let model = Counter { limit: 3 };
    let outcome = check_exhaustive(&model, &counter_properties(3), 4).expect("passes");
    assert!(outcome.exhaustive);
    assert_eq!(outcome.stats.states, 4);
}

// ---------------------------------------------------------------------------
// Symmetry self-test
// ---------------------------------------------------------------------------

/// Design 6.1: a sound reduction gives the same verdict for every property
/// with and without symmetry, so the self-test passes.
#[test]
fn harness_symmetry_selftest_accepts_a_sound_reduction() {
    let model = Pair {
        canon: Canon::Sorted,
    };
    let result = symmetry_selftest(
        &model,
        &symmetric_properties::<Pair>(),
        &symmetric_properties::<Unreduced<'_, Pair>>(),
        &full_config(),
    );
    assert_eq!(result, Ok(()));
}

/// Design 6.1: a `canonicalize` that merges states of different classes
/// hides the `both-at-2` witness, and the self-test reports it.
#[test]
fn harness_symmetry_selftest_detects_a_verdict_changing_canonicalize() {
    let model = Pair {
        canon: Canon::Collapse,
    };
    let result = symmetry_selftest(
        &model,
        &symmetric_properties::<Pair>(),
        &symmetric_properties::<Unreduced<'_, Pair>>(),
        &full_config(),
    );
    assert!(result.is_err(), "the collapsed model passed");
}

/// Design 6.1: a property that is not symmetric is violated without the
/// reduction and verified with it. The self-test reports the difference.
#[test]
fn harness_symmetry_selftest_detects_an_asymmetric_property() {
    let model = Pair {
        canon: Canon::Sorted,
    };
    let result = symmetry_selftest(
        &model,
        &with_asymmetric_property::<Pair>(),
        &with_asymmetric_property::<Unreduced<'_, Pair>>(),
        &full_config(),
    );
    let message = result.expect_err("the asymmetric property passed");
    assert!(
        message.contains("left-never-leads"),
        "the report does not name the property: {message}"
    );
}
