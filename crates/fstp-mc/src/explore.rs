//! Bounded breadth-first exploration.

use crate::model::Model;
use crate::outcome::{Mode, Outcome, Stats};
use crate::property::{Property, Tracker};
use crate::table::{IndexTable, Probe, hash_state};
use crate::trace::{Step, Trace};

/// Default for [`Config::max_states`].
pub const DEFAULT_MAX_STATES: usize = 1 << 20;

/// Bounds and options for [`check`] and [`explore`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    /// Maximum depth of a stored state, counted in actions from an initial
    /// state. Stored states at this depth are still expanded, so their
    /// transitions are checked, and a transition counterexample can have
    /// `max_depth + 1` steps. A new successor beyond the bound is dropped
    /// and the run is not exhaustive. Default: unbounded.
    pub max_depth: usize,
    /// Maximum number of distinct states stored. A new state beyond the
    /// bound is dropped and the run is not exhaustive. States already stored
    /// are still expanded. Default: [`DEFAULT_MAX_STATES`].
    pub max_states: usize,
    /// Stop exploring once every property has a definite verdict: violated,
    /// or reached for reachable properties. A run that stops early is not
    /// exhaustive. Has no effect without properties. Default: true.
    pub stop_when_decided: bool,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            max_depth: usize::MAX,
            max_states: DEFAULT_MAX_STATES,
            stop_when_decided: true,
        }
    }
}

impl Config {
    /// Sets [`Config::max_depth`].
    pub fn with_max_depth(mut self, max_depth: usize) -> Config {
        self.max_depth = max_depth;
        self
    }

    /// Sets [`Config::max_states`].
    pub fn with_max_states(mut self, max_states: usize) -> Config {
        self.max_states = max_states;
        self
    }

    /// Sets [`Config::stop_when_decided`].
    pub fn with_stop_when_decided(mut self, stop: bool) -> Config {
        self.stop_when_decided = stop;
        self
    }
}

/// A stored state with its breadth-first parent link.
struct Node<S, A> {
    state: S,
    hash: u64,
    parent: Option<(usize, A)>,
    depth: usize,
}

/// The visited set. Nodes are appended in discovery order, which is
/// breadth-first order, so the vector doubles as the work queue. Every
/// parent index is smaller than its child's index.
struct Store<S, A> {
    nodes: Vec<Node<S, A>>,
    index: IndexTable,
}

impl<S: Clone + Eq, A: Clone> Store<S, A> {
    fn new() -> Self {
        Store {
            nodes: Vec::new(),
            index: IndexTable::new(),
        }
    }

    fn find(&self, state: &S, hash: u64) -> Probe {
        let nodes = &self.nodes;
        self.index.probe(hash, |i| {
            nodes
                .get(i)
                .is_some_and(|n| n.hash == hash && n.state == *state)
        })
    }

    fn lookup(&self, state: &S, hash: u64) -> Option<usize> {
        match self.find(state, hash) {
            Probe::Found(i) => Some(i),
            Probe::Vacant(_) => None,
        }
    }

    /// Appends a node known to be absent and indexes it. `slot` is the
    /// vacant slot a lookup of the node's state returned. Returns the index.
    fn insert(&mut self, slot: usize, node: Node<S, A>) -> usize {
        let idx = self.nodes.len();
        let slot = if self.index.needs_growth() {
            self.index.grow(self.nodes.iter().map(|n| n.hash));
            match self.find(&node.state, node.hash) {
                Probe::Vacant(s) => s,
                Probe::Found(_) => usize::MAX,
            }
        } else {
            slot
        };
        self.index.insert_at(slot, idx);
        self.nodes.push(node);
        idx
    }

    /// Builds the trace from an initial state to node `idx` by following
    /// parent links. Returns `None` only for an index out of range.
    fn trace_to(&self, idx: usize) -> Option<Trace<S, A>> {
        let mut cur = self.nodes.get(idx)?;
        let mut rev: Vec<Step<S, A>> = Vec::with_capacity(cur.depth);
        // Parent indices strictly decrease, so this ends within len steps.
        for _ in 0..self.nodes.len() {
            let Some((p, action)) = &cur.parent else {
                break;
            };
            let Some(parent) = self.nodes.get(*p) else {
                break;
            };
            rev.push(Step {
                action: action.clone(),
                state: cur.state.clone(),
            });
            cur = parent;
        }
        rev.reverse();
        Some(Trace {
            init: cur.state.clone(),
            steps: rev,
        })
    }

    /// Like [`Store::trace_to`], falling back to a trace of the node's own
    /// state if the parent chain were broken. Used where an index is known
    /// to be valid.
    fn trace_or_state(&self, idx: usize, state: &S) -> Trace<S, A> {
        self.trace_to(idx)
            .unwrap_or_else(|| Trace::new(state.clone()))
    }
}

/// Bound flags and counters of one breadth-first run.
struct Run<S, A> {
    store: Store<S, A>,
    stats: Stats,
    exhaustive: bool,
    depth_bound_hit: bool,
    state_bound_hit: bool,
    stopped_early: bool,
}

fn bfs<M: Model>(
    model: &M,
    tracker: &mut Tracker<'_, '_, M>,
    config: &Config,
) -> Run<M::State, M::Action> {
    let mut store: Store<M::State, M::Action> = Store::new();
    let mut stats = Stats::default();
    let mut depth_bound_hit = false;
    let mut state_bound_hit = false;
    let mut stopped_early = false;

    for s in model.init() {
        let canon = model.canonicalize(&s);
        let hash = hash_state(&canon);
        let Probe::Vacant(slot) = store.find(&canon, hash) else {
            continue;
        };
        if store.nodes.len() >= config.max_states {
            state_bound_hit = true;
            continue;
        }
        let node = Node {
            state: canon,
            hash,
            parent: None,
            depth: 0,
        };
        let idx = store.insert(slot, node);
        if let Some(node) = store.nodes.get(idx) {
            tracker.check_state(&node.state, || store.trace_or_state(idx, &node.state));
        }
    }

    let mut actions: Vec<M::Action> = Vec::new();
    let mut succs: Vec<(M::Action, M::State)> = Vec::new();
    let mut cursor = 0usize;
    while let Some(node) = store.nodes.get(cursor) {
        if config.stop_when_decided && tracker.all_decided() {
            stopped_early = true;
            break;
        }
        let depth = node.depth;
        actions.clear();
        model.actions(&node.state, &mut actions);
        let check_transitions = tracker.wants_transitions();
        for action in actions.drain(..) {
            let Some(next) = model.step(&node.state, &action) else {
                continue;
            };
            stats.transitions = stats.transitions.saturating_add(1);
            if check_transitions {
                tracker.check_transition(&node.state, &action, &next, || {
                    store.trace_or_state(cursor, &node.state)
                });
            }
            succs.push((action, next));
        }
        if succs.is_empty() && tracker.wants_deadlock() && !model.is_terminal(&node.state) {
            tracker.check_deadlock(|| store.trace_or_state(cursor, &node.state));
        }

        let next_depth = depth.saturating_add(1);
        for (action, next) in succs.drain(..) {
            let canon = model.canonicalize(&next);
            drop(next);
            let hash = hash_state(&canon);
            let Probe::Vacant(slot) = store.find(&canon, hash) else {
                continue;
            };
            if next_depth > config.max_depth {
                depth_bound_hit = true;
                continue;
            }
            if store.nodes.len() >= config.max_states {
                state_bound_hit = true;
                continue;
            }
            let node = Node {
                state: canon,
                hash,
                parent: Some((cursor, action)),
                depth: next_depth,
            };
            let idx = store.insert(slot, node);
            stats.max_depth = stats.max_depth.max(next_depth);
            if let Some(node) = store.nodes.get(idx) {
                tracker.check_state(&node.state, || store.trace_or_state(idx, &node.state));
            }
        }
        cursor = cursor.saturating_add(1);
    }

    stats.states = store.nodes.len();
    let exhaustive = !stopped_early && !depth_bound_hit && !state_bound_hit;
    Run {
        store,
        stats,
        exhaustive,
        depth_bound_hit,
        state_bound_hit,
        stopped_early,
    }
}

/// Checks `properties` on `model` by breadth-first exploration.
///
/// The first violation found for a property has a shortest trace, because
/// states are explored in order of depth. Exploration stops at the bounds in
/// `config`. A bounded run reports `exhaustive: false` and never reports a
/// property as verified. Never panics, unless model or property code does.
///
/// Results are deterministic: they depend only on the model, the properties
/// and the configuration, never on hash values.
pub fn check<M: Model>(
    model: &M,
    properties: &[Property<'_, M>],
    config: &Config,
) -> Outcome<M::State, M::Action> {
    let mut tracker = Tracker::new(properties);
    let run = bfs(model, &mut tracker, config);
    Outcome {
        mode: Mode::Exhaustive {
            max_depth: config.max_depth,
            max_states: config.max_states,
        },
        stats: run.stats,
        exhaustive: run.exhaustive,
        depth_bound_hit: run.depth_bound_hit,
        state_bound_hit: run.state_bound_hit,
        stopped_early: run.stopped_early,
        results: tracker.finish(run.exhaustive),
    }
}

/// Explores `model` breadth-first within the bounds of `config` and returns
/// the stored state space.
///
/// Use it to enumerate reachable states, for example to generate an
/// authorisation matrix over every reachable state.
pub fn explore<M: Model>(model: &M, config: &Config) -> StateSpace<M::State, M::Action> {
    let mut tracker = Tracker::new(&[]);
    let run = bfs(model, &mut tracker, config);
    StateSpace {
        store: run.store,
        stats: run.stats,
        exhaustive: run.exhaustive,
        depth_bound_hit: run.depth_bound_hit,
        state_bound_hit: run.state_bound_hit,
    }
}

/// The states stored by [`explore`], in breadth-first discovery order.
///
/// States are stored in canonical form ([`Model::canonicalize`]). Each state
/// has a depth, which is the length of a shortest path to it, and a parent
/// link that rebuilds that path.
pub struct StateSpace<S, A> {
    store: Store<S, A>,
    /// Counters for the run.
    pub stats: Stats,
    /// True when every reachable state was stored.
    pub exhaustive: bool,
    /// True when a successor that is not stored was dropped because its depth
    /// along the current path exceeds the depth bound. Such a successor may
    /// also have been dropped earlier by the state bound.
    pub depth_bound_hit: bool,
    /// True when a new state was dropped because the state bound was reached.
    pub state_bound_hit: bool,
}

impl<S, A> StateSpace<S, A> {
    /// Returns the number of stored states.
    pub fn len(&self) -> usize {
        self.store.nodes.len()
    }

    /// Returns true when no state is stored.
    pub fn is_empty(&self) -> bool {
        self.store.nodes.is_empty()
    }

    /// Returns the state at `index` in discovery order.
    pub fn state(&self, index: usize) -> Option<&S> {
        self.store.nodes.get(index).map(|n| &n.state)
    }

    /// Returns the depth of the state at `index`: the length of a shortest
    /// path to it from an initial state.
    pub fn depth(&self, index: usize) -> Option<usize> {
        self.store.nodes.get(index).map(|n| n.depth)
    }

    /// Returns the parent index and the action that first reached the state
    /// at `index`, or `None` for an initial state or an index out of range.
    pub fn parent(&self, index: usize) -> Option<(usize, &A)> {
        let node = self.store.nodes.get(index)?;
        node.parent.as_ref().map(|(p, a)| (*p, a))
    }

    /// Returns every stored state in discovery order.
    pub fn states(&self) -> impl Iterator<Item = &S> {
        self.store.nodes.iter().map(|n| &n.state)
    }
}

impl<S: Clone + Eq + core::hash::Hash, A: Clone> StateSpace<S, A> {
    /// Returns the index of `state`, compared with the stored canonical forms.
    pub fn find(&self, state: &S) -> Option<usize> {
        self.store.lookup(state, hash_state(state))
    }

    /// Returns true when `state` is stored, compared with canonical forms.
    pub fn contains(&self, state: &S) -> bool {
        self.find(state).is_some()
    }

    /// Returns a shortest trace from an initial state to the state at `index`.
    pub fn trace_to(&self, index: usize) -> Option<Trace<S, A>> {
        self.store.trace_to(index)
    }
}

impl<S: core::fmt::Debug, A> core::fmt::Debug for StateSpace<S, A> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StateSpace")
            .field("states", &self.store.nodes.len())
            .field("stats", &self.stats)
            .field("exhaustive", &self.exhaustive)
            .field("depth_bound_hit", &self.depth_bound_hit)
            .field("state_bound_hit", &self.state_bound_hit)
            .finish()
    }
}
