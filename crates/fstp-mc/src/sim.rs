//! Seeded bounded random walks for state spaces too large to exhaust.

use crate::model::Model;
use crate::outcome::{Mode, Outcome, Stats};
use crate::property::{Property, Tracker};
use crate::rng::SplitMix64;
use crate::trace::{Step, Trace};

/// Settings for [`simulate`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SimConfig {
    /// Seed of the walk generator. The same seed gives the same walks.
    pub seed: u64,
    /// Number of walks.
    pub walks: usize,
    /// Maximum number of steps per walk. A walk also ends in a state with
    /// no enabled action.
    pub max_steps: usize,
    /// Stop once every property has a definite verdict. Default: true.
    pub stop_when_decided: bool,
}

impl Default for SimConfig {
    fn default() -> SimConfig {
        SimConfig {
            seed: 0,
            walks: 1000,
            max_steps: 1000,
            stop_when_decided: true,
        }
    }
}

impl SimConfig {
    /// Sets [`SimConfig::seed`].
    pub fn with_seed(mut self, seed: u64) -> SimConfig {
        self.seed = seed;
        self
    }

    /// Sets [`SimConfig::walks`].
    pub fn with_walks(mut self, walks: usize) -> SimConfig {
        self.walks = walks;
        self
    }

    /// Sets [`SimConfig::max_steps`].
    pub fn with_max_steps(mut self, max_steps: usize) -> SimConfig {
        self.max_steps = max_steps;
        self
    }

    /// Sets [`SimConfig::stop_when_decided`].
    pub fn with_stop_when_decided(mut self, stop: bool) -> SimConfig {
        self.stop_when_decided = stop;
        self
    }
}

/// Checks `properties` along seeded random walks through `model`.
///
/// This mode is for state spaces too large to exhaust. It is never
/// exhaustive: the outcome has `exhaustive: false` and [`Mode::Simulation`],
/// and no property is ever reported as verified or unreachable. A violation
/// or witness it reports is real, and its trace replays on the model.
///
/// Each walk starts in an initial state picked at random. At every state it
/// checks the always and reachable properties, checks every enabled
/// transition against the transition properties, and checks for deadlock.
/// It then follows one enabled transition picked uniformly at random.
/// Traces have their cycles removed, but they are not shortest traces.
/// States are not canonicalized, so traces are concrete executions.
pub fn simulate<M: Model>(
    model: &M,
    properties: &[Property<'_, M>],
    config: &SimConfig,
) -> Outcome<M::State, M::Action> {
    let mut tracker = Tracker::new(properties);
    let mut rng = SplitMix64::new(config.seed);
    let mut stats = Stats::default();
    let mut walks_done = 0usize;
    let mut stopped_early = false;
    let inits = model.init();
    let mut actions: Vec<M::Action> = Vec::new();
    let mut succs: Vec<(M::Action, M::State)> = Vec::new();

    if !inits.is_empty() {
        for _ in 0..config.walks {
            if config.stop_when_decided && tracker.all_decided() {
                stopped_early = true;
                break;
            }
            let Some(start) = inits.get(rng.index(inits.len())) else {
                break;
            };
            walks_done = walks_done.saturating_add(1);
            let mut walk: Trace<M::State, M::Action> = Trace::new(start.clone());
            stats.states = stats.states.saturating_add(1);
            tracker.check_state(&walk.init, || walk.without_cycles());

            for _ in 0..config.max_steps {
                let cur = walk.last_state();
                actions.clear();
                model.actions(cur, &mut actions);
                let check_transitions = tracker.wants_transitions();
                for action in actions.drain(..) {
                    let Some(next) = model.step(cur, &action) else {
                        continue;
                    };
                    stats.transitions = stats.transitions.saturating_add(1);
                    if check_transitions {
                        tracker.check_transition(cur, &action, &next, || walk.without_cycles());
                    }
                    succs.push((action, next));
                }
                if succs.is_empty() {
                    if tracker.wants_deadlock() && !model.is_terminal(cur) {
                        tracker.check_deadlock(|| walk.without_cycles());
                    }
                    break;
                }
                let pick = rng.index(succs.len());
                let chosen = if pick < succs.len() {
                    succs.swap_remove(pick)
                } else {
                    break;
                };
                succs.clear();
                let (action, state) = chosen;
                walk.steps.push(Step { action, state });
                stats.states = stats.states.saturating_add(1);
                stats.max_depth = stats.max_depth.max(walk.len());
                tracker.check_state(walk.last_state(), || walk.without_cycles());
            }
            succs.clear();
        }
    }

    Outcome {
        mode: Mode::Simulation {
            seed: config.seed,
            walks: walks_done,
            max_steps: config.max_steps,
        },
        stats,
        exhaustive: false,
        depth_bound_hit: false,
        state_bound_hit: false,
        stopped_early,
        results: tracker.finish(false),
    }
}
