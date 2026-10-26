//! fstp-mc adapters, tripwires and the symmetry self-test helper (design section 6.1).
//!
//! - [`tripwire`] is the configuration of every model run: exhaustive, with
//!   `stop_when_decided(false)`, and a state bound at twice the measured
//!   count, so a model that grows past it fails visibly.
//! - [`check_exhaustive`] runs a model under its tripwire. It passes only
//!   when the property list holds a `reachable` witness, the run is
//!   exhaustive and every property passed, including every witness.
//! - [`Unreduced`] is a model with symmetry reduction turned off.
//!   [`symmetry_selftest`] compares every verdict with and without the
//!   reduction. A model enables symmetry only together with that self-test.

use fstp_mc::{Config, Model, Outcome, Property, PropertyKind, check};

/// The run configuration for a model whose measured state count is
/// `measured`: unbounded depth, every verdict decided, and at most twice
/// the measured count of states. Doubling saturates.
pub fn tripwire(measured: usize) -> Config {
    Config::default()
        .with_stop_when_decided(false)
        .with_max_depth(usize::MAX)
        .with_max_states(measured.saturating_mul(2))
}

/// Fails unless `properties` holds at least one `reachable` witness, so
/// that a model that refuses everything cannot pass (design section 6.1,
/// "No vacuous models").
pub fn require_witness<M: Model>(properties: &[Property<'_, M>]) -> Result<(), String> {
    if properties
        .iter()
        .any(|p| p.kind() == PropertyKind::Reachable)
    {
        Ok(())
    } else {
        Err(
            "every model has reachable witnesses: the property list holds no reachable property"
                .to_owned(),
        )
    }
}

/// Runs `model` exhaustively under [`tripwire`] for `measured` states.
///
/// Fails when `properties` holds no `reachable` witness, see
/// [`require_witness`]. Fails with the full report when the run is not
/// exhaustive, which includes a state count above the tripwire, or when
/// any property did not pass. Otherwise returns the outcome.
pub fn check_exhaustive<M: Model>(
    model: &M,
    properties: &[Property<'_, M>],
    measured: usize,
) -> Result<Outcome<M::State, M::Action>, String> {
    require_witness(properties)?;
    let config = tripwire(measured);
    let outcome = check(model, properties, &config);
    if !outcome.exhaustive {
        return Err(format!(
            "the run is not exhaustive under the tripwire of {} states (measured {measured}); \
             split the model before relaxing the bound\n{outcome}",
            config.max_states
        ));
    }
    outcome.require_all_passed()?;
    Ok(outcome)
}

/// `M` with symmetry reduction turned off: every method delegates to `M`,
/// except [`Model::canonicalize`], which is the identity.
pub struct Unreduced<'a, M>(pub &'a M);

impl<M: Model> Model for Unreduced<'_, M> {
    type State = M::State;
    type Action = M::Action;

    fn init(&self) -> Vec<M::State> {
        self.0.init()
    }

    fn actions(&self, state: &M::State, actions: &mut Vec<M::Action>) {
        self.0.actions(state, actions);
    }

    fn step(&self, state: &M::State, action: &M::Action) -> Option<M::State> {
        self.0.step(state, action)
    }

    fn is_terminal(&self, state: &M::State) -> bool {
        self.0.is_terminal(state)
    }
}

/// Checks that symmetry reduction changes no verdict (design section 6.1).
///
/// `reduced` are the properties checked on `model` with its
/// `canonicalize`, and `full` the same properties, in the same order, on
/// [`Unreduced`]. Both runs use `config` and must be exhaustive. Every
/// property must get the same verdict kind in both runs. The error names
/// each property whose verdict differs. Both lists must hold a `reachable`
/// witness, see [`require_witness`].
pub fn symmetry_selftest<'m, M: Model>(
    model: &'m M,
    reduced: &[Property<'_, M>],
    full: &[Property<'_, Unreduced<'m, M>>],
    config: &Config,
) -> Result<(), String> {
    require_witness(reduced)?;
    require_witness(full)?;
    let with = check(model, reduced, config);
    let without = check(&Unreduced(model), full, config);
    if !with.exhaustive || !without.exhaustive {
        return Err(format!(
            "the symmetry self-test needs exhaustive runs (reduced: {}, full: {})",
            with.exhaustive, without.exhaustive
        ));
    }
    let ids_with: Vec<&str> = with.results.iter().map(|r| r.id.as_str()).collect();
    let ids_without: Vec<&str> = without.results.iter().map(|r| r.id.as_str()).collect();
    if ids_with != ids_without {
        return Err(format!(
            "the two property lists differ: reduced {ids_with:?}, full {ids_without:?}"
        ));
    }
    let differences: Vec<String> = with
        .results
        .iter()
        .zip(&without.results)
        .filter(|(a, b)| a.verdict.label() != b.verdict.label())
        .map(|(a, b)| {
            format!(
                "{}: {} with symmetry, {} without",
                a.id,
                a.verdict.label(),
                b.verdict.label()
            )
        })
        .collect();
    if differences.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "symmetry reduction changes verdicts:\n{}",
            differences.join("\n")
        ))
    }
}
