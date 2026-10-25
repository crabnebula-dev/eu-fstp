//! Explicit directed graphs as models, and differential checks against
//! reference graph algorithms.
//!
//! The self-tests and the `random_graph` and `symmetric_graph` fuzz targets
//! share this module. A [`GraphModel`] is a finite directed graph whose nodes
//! are states and whose edges are actions. Disabled edges exercise guards:
//! their step returns `None`. Optional node classes exercise
//! [`Model::canonicalize`], and optional terminal nodes exercise
//! [`Model::is_terminal`]. [`check_against_reference`] runs the checker on a
//! [`GraphCase`] and compares every observable result with a plain
//! depth-first search and a plain breadth-first search written independently
//! of the checker.

use core::fmt;
use std::collections::BTreeMap;

use crate::explore::{Config, StateSpace, check, explore};
use crate::model::Model;
use crate::outcome::{Outcome, Verdict};
use crate::property::Property;
use crate::sim::{SimConfig, simulate};
use crate::trace::Trace;

/// An outgoing edge of a [`GraphModel`] node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Edge {
    /// The target node.
    pub to: usize,
    /// False for an edge whose guard is always false: it is listed as an
    /// action but never taken.
    pub enabled: bool,
}

/// An error building a [`GraphModel`] or decoding a [`GraphCase`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GraphError {
    /// An edge or initial node refers to a node that does not exist.
    NodeOutOfRange {
        /// The offending node.
        node: usize,
        /// The number of nodes.
        node_count: usize,
    },
    /// The graph has more nodes than the limits allow.
    TooManyNodes {
        /// The requested node count.
        node_count: usize,
        /// The limit.
        max_nodes: usize,
    },
    /// The graph has more edges than the limits allow.
    TooManyEdges {
        /// The limit.
        max_edges: usize,
    },
    /// The graph has more initial nodes than the limits allow.
    TooManyInitial {
        /// The limit.
        max_init: usize,
    },
    /// The limits are unusable, for example a zero node limit.
    InvalidLimits,
}

impl fmt::Display for GraphError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GraphError::NodeOutOfRange { node, node_count } => {
                write!(f, "node {node} out of range for {node_count} nodes")
            }
            GraphError::TooManyNodes {
                node_count,
                max_nodes,
            } => write!(f, "{node_count} nodes exceed the limit of {max_nodes}"),
            GraphError::TooManyEdges { max_edges } => {
                write!(f, "edges exceed the limit of {max_edges}")
            }
            GraphError::TooManyInitial { max_init } => {
                write!(f, "initial nodes exceed the limit of {max_init}")
            }
            GraphError::InvalidLimits => f.write_str("invalid graph limits"),
        }
    }
}

impl std::error::Error for GraphError {}

/// Hard upper bound on the node count of a [`GraphModel`], whatever
/// [`GraphLimits::max_nodes`] says. It bounds the adjacency allocation, so a
/// permissive limit can never make [`GraphModel::new`] panic or abort.
pub const MAX_GRAPH_NODES: usize = 1 << 16;

/// Size limits for [`GraphModel::new`] and [`GraphCase::from_bytes`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GraphLimits {
    /// Maximum number of nodes, at least 1. [`GraphModel::new`] caps it at
    /// [`MAX_GRAPH_NODES`], and decoding from bytes caps it at 256.
    pub max_nodes: usize,
    /// Maximum number of edges.
    pub max_edges: usize,
    /// Maximum number of initial nodes, before duplicates are removed.
    pub max_init: usize,
}

impl Default for GraphLimits {
    fn default() -> GraphLimits {
        GraphLimits {
            max_nodes: 64,
            max_edges: 512,
            max_init: 4,
        }
    }
}

/// A finite directed graph used as a [`Model`].
///
/// States are node numbers. The actions of a node are the indices of its
/// outgoing edges, in insertion order.
///
/// Nodes may be grouped into classes ([`GraphModel::with_classes`]).
/// [`Model::canonicalize`] then maps each node to the smallest node of its
/// class. A grouping need not meet the soundness requirement of
/// [`Model::canonicalize`]. The checker then explores a quotient graph, and
/// the reference searches here compute that same quotient. Nodes may also be
/// declared terminal ([`GraphModel::with_terminal`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GraphModel {
    init: Vec<usize>,
    adj: Vec<Vec<Edge>>,
    /// Canonical form of each node. Empty means the identity.
    canon: Vec<usize>,
    /// Whether each node is terminal. Empty means none is.
    terminal: Vec<bool>,
}

impl GraphModel {
    /// Builds a graph with `node_count` nodes, the given initial nodes and
    /// edges `(from, to, enabled)`. Checks every node against the count and
    /// the sizes against `limits`. The node count may not exceed
    /// [`MAX_GRAPH_NODES`] either. The graph has no classes and no terminal
    /// nodes.
    pub fn new(
        node_count: usize,
        init: Vec<usize>,
        edges: &[(usize, usize, bool)],
        limits: &GraphLimits,
    ) -> Result<GraphModel, GraphError> {
        let max_nodes = limits.max_nodes.min(MAX_GRAPH_NODES);
        if node_count > max_nodes {
            return Err(GraphError::TooManyNodes {
                node_count,
                max_nodes,
            });
        }
        if edges.len() > limits.max_edges {
            return Err(GraphError::TooManyEdges {
                max_edges: limits.max_edges,
            });
        }
        if init.len() > limits.max_init {
            return Err(GraphError::TooManyInitial {
                max_init: limits.max_init,
            });
        }
        let out_of_range = |node: usize| GraphError::NodeOutOfRange { node, node_count };
        if let Some(&bad) = init.iter().find(|&&v| v >= node_count) {
            return Err(out_of_range(bad));
        }
        let mut adj: Vec<Vec<Edge>> = vec![Vec::new(); node_count];
        for &(from, to, enabled) in edges {
            if to >= node_count {
                return Err(out_of_range(to));
            }
            let list = adj.get_mut(from).ok_or_else(|| out_of_range(from))?;
            list.push(Edge { to, enabled });
        }
        Ok(GraphModel {
            init,
            adj,
            canon: Vec::new(),
            terminal: Vec::new(),
        })
    }

    /// Returns the graph with its nodes grouped into classes.
    ///
    /// `class_of[v]` is the class key of node `v`. Nodes with equal keys form
    /// a class, and a node beyond the end of `class_of` is alone in its class.
    /// The canonical form of a node is the smallest node of its class, so
    /// canonicalizing twice changes nothing. Replaces any earlier grouping.
    pub fn with_classes(mut self, class_of: &[usize]) -> GraphModel {
        let mut first: BTreeMap<usize, usize> = BTreeMap::new();
        self.canon = (0..self.node_count())
            .map(|v| match class_of.get(v) {
                Some(&key) => *first.entry(key).or_insert(v),
                None => v,
            })
            .collect();
        self
    }

    /// Returns the graph with exactly the given nodes declared terminal.
    /// Fails when a node does not exist.
    pub fn with_terminal(mut self, nodes: &[usize]) -> Result<GraphModel, GraphError> {
        let node_count = self.node_count();
        let mut terminal = vec![false; node_count];
        for &node in nodes {
            let slot = terminal
                .get_mut(node)
                .ok_or(GraphError::NodeOutOfRange { node, node_count })?;
            *slot = true;
        }
        self.terminal = terminal;
        Ok(self)
    }

    /// Returns the canonical form of `node`: the smallest node of its class.
    pub fn canonical(&self, node: usize) -> usize {
        self.canon.get(node).copied().unwrap_or(node)
    }

    /// Returns whether `node` is declared terminal.
    pub fn is_terminal_node(&self, node: usize) -> bool {
        self.terminal.get(node).copied().unwrap_or(false)
    }

    /// Returns the number of nodes.
    pub fn node_count(&self) -> usize {
        self.adj.len()
    }

    /// Returns the initial nodes, in order, with any duplicates.
    pub fn init_nodes(&self) -> &[usize] {
        &self.init
    }

    /// Returns the outgoing edges of `node`, or an empty slice if it does not exist.
    pub fn edges(&self, node: usize) -> &[Edge] {
        self.adj.get(node).map_or(&[], |v| v.as_slice())
    }

    /// Iterates over the targets of the enabled edges of `node`, in order.
    fn enabled_targets(&self, node: usize) -> impl Iterator<Item = usize> + '_ {
        self.edges(node).iter().filter(|e| e.enabled).map(|e| e.to)
    }
}

impl Model for GraphModel {
    type State = usize;
    type Action = usize;

    fn init(&self) -> Vec<usize> {
        self.init.clone()
    }

    fn actions(&self, state: &usize, actions: &mut Vec<usize>) {
        actions.extend(0..self.edges(*state).len());
    }

    fn step(&self, state: &usize, action: &usize) -> Option<usize> {
        let edge = self.edges(*state).get(*action)?;
        edge.enabled.then_some(edge.to)
    }

    fn is_terminal(&self, state: &usize) -> bool {
        self.is_terminal_node(*state)
    }

    fn canonicalize(&self, state: &usize) -> usize {
        self.canonical(*state)
    }
}

/// A graph with a target node, bounds for a bounded run and a seed for a
/// simulation: the input of [`check_against_reference`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GraphCase {
    /// The graph.
    pub model: GraphModel,
    /// The node whose distance the counterexample length must match.
    pub target: usize,
    /// Depth bound for the bounded run.
    pub max_depth: usize,
    /// State bound for the bounded run.
    pub max_states: usize,
    /// Seed for the simulation run.
    pub seed: u64,
}

impl GraphCase {
    /// Decodes a case from arbitrary bytes. Every byte string decodes; a
    /// missing header byte reads as 0. Fails only for unusable limits.
    ///
    /// Layout: node count, initial count, initial nodes, target, depth bound,
    /// state bound and seed, one byte each. Then each pair of bytes adds an
    /// edge until the bytes or the edge limit run out. The high bit of an
    /// edge's second byte disables it.
    pub fn from_bytes(data: &[u8], limits: &GraphLimits) -> Result<GraphCase, GraphError> {
        let max_nodes = limits.max_nodes.min(256);
        if max_nodes == 0 {
            return Err(GraphError::InvalidLimits);
        }
        let modulo = |a: u8, m: usize| usize::from(a).checked_rem(m).unwrap_or(0);
        let mut bytes = data.iter().copied();
        let mut header = || bytes.next().unwrap_or(0);
        let n = modulo(header(), max_nodes).saturating_add(1);
        let init_count = modulo(header(), limits.max_init.saturating_add(1));
        let mut init = Vec::with_capacity(init_count);
        for _ in 0..init_count {
            init.push(modulo(header(), n));
        }
        let target = modulo(header(), n);
        let depth_byte = header();
        let max_depth = if depth_byte & 0x80 != 0 {
            usize::MAX
        } else {
            usize::from(depth_byte & 0x0f)
        };
        let states_byte = header();
        let max_states = if states_byte & 0x80 != 0 {
            usize::MAX
        } else {
            modulo(states_byte & 0x7f, n.saturating_add(2))
        };
        let seed = u64::from(header());
        let mut edges = Vec::new();
        let mut rest = bytes;
        while edges.len() < limits.max_edges {
            let (Some(from), Some(to)) = (rest.next(), rest.next()) else {
                break;
            };
            edges.push((modulo(from, n), modulo(to & 0x7f, n), to & 0x80 == 0));
        }
        let model = GraphModel::new(n, init, &edges, limits)?;
        Ok(GraphCase {
            model,
            target,
            max_depth,
            max_states,
            seed,
        })
    }

    /// Decodes a case with node classes and terminal nodes from arbitrary
    /// bytes. Every byte string decodes. Fails only for unusable limits.
    ///
    /// The first byte gives the length `k` of a block of node bytes that
    /// follows it, and the bytes after the block decode as in
    /// [`GraphCase::from_bytes`]. Node `v` reads block byte `v` when there is
    /// one. Its low seven bits modulo the node count give the class key, and
    /// its high bit makes the node terminal. A node without a block byte is
    /// alone in its class and is not terminal.
    pub fn from_bytes_symmetric(
        data: &[u8],
        limits: &GraphLimits,
    ) -> Result<GraphCase, GraphError> {
        let (k, rest) = match data.split_first() {
            Some((&k, rest)) => (usize::from(k), rest),
            None => (0, data),
        };
        let (block, rest) = rest
            .split_at_checked(k.min(rest.len()))
            .unwrap_or((&[], rest));
        let mut case = GraphCase::from_bytes(rest, limits)?;
        let n = case.model.node_count();
        let block = block.get(..n.min(block.len())).unwrap_or(block);
        let keys: Vec<usize> = block
            .iter()
            .map(|&b| usize::from(b & 0x7f).checked_rem(n).unwrap_or(0))
            .collect();
        let terminal: Vec<usize> = (0..block.len())
            .filter(|&v| block.get(v).is_some_and(|&b| b & 0x80 != 0))
            .collect();
        case.model = case.model.with_classes(&keys).with_terminal(&terminal)?;
        Ok(case)
    }
}

/// The result of the reference breadth-first search.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reference {
    /// Reachable nodes in breadth-first discovery order: initial nodes in
    /// order without duplicates, then successors by edge order.
    pub order: Vec<usize>,
    /// Shortest distance from an initial node, `None` when unreachable.
    pub dist: Vec<Option<usize>>,
}

/// Plain multi-source breadth-first search over enabled edges, on canonical
/// forms.
///
/// It starts from the canonical forms of the initial nodes. It expands each
/// canonical node by its own enabled edges and maps every target to its
/// canonical form. This is the quotient graph that the checker explores. A
/// graph without classes gives the plain search.
pub fn reference_bfs(model: &GraphModel) -> Reference {
    bfs_with(model, |v| model.canonical(v))
}

/// Plain multi-source breadth-first search over enabled edges on concrete
/// nodes, ignoring classes. A simulation walks concrete states, so its
/// traces are compared with this search.
pub fn reference_bfs_concrete(model: &GraphModel) -> Reference {
    bfs_with(model, |v| v)
}

/// Breadth-first search where `canon` maps each discovered node to the
/// node that is stored and expanded.
fn bfs_with(model: &GraphModel, canon: impl Fn(usize) -> usize) -> Reference {
    let n = model.node_count();
    let mut dist: Vec<Option<usize>> = vec![None; n];
    let mut order = Vec::new();
    for &v in model.init_nodes() {
        let c = canon(v);
        if let Some(d @ None) = dist.get_mut(c) {
            *d = Some(0);
            order.push(c);
        }
    }
    let mut head = 0;
    while let Some(&u) = order.get(head) {
        head = head.saturating_add(1);
        let du = dist.get(u).copied().flatten().unwrap_or(0);
        for v in model.enabled_targets(u) {
            let c = canon(v);
            if let Some(d @ None) = dist.get_mut(c) {
                *d = Some(du.saturating_add(1));
                order.push(c);
            }
        }
    }
    Reference { order, dist }
}

/// Plain depth-first search over enabled edges with an explicit stack, on
/// canonical forms like [`reference_bfs`]. Returns, per node, whether it is
/// a reachable canonical node.
pub fn reference_dfs(model: &GraphModel) -> Vec<bool> {
    let mut seen = vec![false; model.node_count()];
    let mut stack: Vec<usize> = model
        .init_nodes()
        .iter()
        .map(|&v| model.canonical(v))
        .collect();
    while let Some(u) = stack.pop() {
        match seen.get_mut(u) {
            Some(s) if !*s => *s = true,
            _ => continue,
        }
        stack.extend(model.enabled_targets(u).map(|v| model.canonical(v)));
    }
    seen
}

/// Returns whether `node` deadlocks: it has no enabled edge and is not terminal.
fn deadlocks(model: &GraphModel, node: usize) -> bool {
    model.enabled_targets(node).next().is_none() && !model.is_terminal_node(node)
}

macro_rules! ensure {
    ($cond:expr, $($fmt:tt)+) => {
        if !$cond {
            return Err(format!($($fmt)+));
        }
    };
}

const ALWAYS: &str = "target-never-reached";
const REACH: &str = "target-reachable";
const DEADLOCK: &str = "deadlock-free";
const EDGE: &str = "no-edge-into-target";

fn properties<'a>(target: usize) -> [Property<'a, GraphModel>; 4] {
    [
        Property::always(ALWAYS, move |&s| s != target),
        Property::reachable(REACH, move |&s| s == target),
        Property::deadlock_free(DEADLOCK),
        Property::transition(EDGE, move |_, _, &t| t != target),
    ]
}

/// Expected trace lengths, from the reference search restricted to `stored`.
struct Expected {
    target: Option<usize>,
    deadlock: Option<usize>,
    edge: Option<usize>,
}

fn expected(model: &GraphModel, r: &Reference, stored: &[usize], target: usize) -> Expected {
    let dist = |v: usize| r.dist.get(v).copied().flatten();
    let target_d = if stored.contains(&target) {
        dist(target)
    } else {
        None
    };
    let deadlock = stored
        .iter()
        .filter(|&&u| deadlocks(model, u))
        .filter_map(|&u| dist(u))
        .min();
    let edge = stored
        .iter()
        .filter(|&&u| model.enabled_targets(u).any(|v| v == target))
        .filter_map(|&u| dist(u).map(|d| d.saturating_add(1)))
        .min();
    Expected {
        target: target_d,
        deadlock,
        edge,
    }
}

fn check_trace(
    model: &GraphModel,
    what: &str,
    trace: &Trace<usize, usize>,
    len: Option<usize>,
    ends: impl Fn(usize) -> bool,
) -> Result<(), String> {
    trace
        .replay(model)
        .map_err(|e| format!("{what}: trace does not replay: {e}\n{trace}"))?;
    ensure!(
        ends(*trace.last_state()),
        "{what}: trace ends in the wrong state\n{trace}"
    );
    if let Some(len) = len {
        ensure!(
            trace.len() == len,
            "{what}: trace has {} steps, the reference says {len}\n{trace}",
            trace.len()
        );
    }
    Ok(())
}

/// Checks one verdict against the expected trace length, or against no
/// trace when `expect` is `None`. `mode` says what the run may claim.
fn check_verdict(
    model: &GraphModel,
    outcome: &Outcome<usize, usize>,
    id: &str,
    expect: Option<usize>,
    mode: Expect,
    ends: impl Fn(usize) -> bool,
) -> Result<(), String> {
    let Some(verdict) = outcome.verdict(id) else {
        return Err(format!("no verdict for {id}"));
    };
    let is_reach = id == REACH;
    let exhaustive = mode == Expect::Exhaustive;
    let trace = match (verdict, is_reach) {
        (Verdict::Violated(v), false) => Some(&v.trace),
        (Verdict::Reached(t), true) => Some(t),
        _ => None,
    };
    match (trace, expect) {
        (Some(trace), Some(len)) if mode == Expect::Simulation => {
            check_trace(model, id, trace, None, ends)?;
            ensure!(
                trace.len() >= len,
                "{id}: trace of {} steps is shorter than the shortest path {len}",
                trace.len()
            );
            Ok(())
        }
        (Some(trace), Some(len)) => check_trace(model, id, trace, Some(len), ends),
        (None, _) if mode == Expect::Simulation && verdict.is_unknown() => Ok(()),
        (None, None) if exhaustive && !is_reach && *verdict == Verdict::Verified => Ok(()),
        (None, None) if exhaustive && is_reach && *verdict == Verdict::Unreachable => Ok(()),
        (None, None) if mode == Expect::Bounded && verdict.is_unknown() => Ok(()),
        _ => Err(format!(
            "{id}: verdict {} but the reference expects {expect:?} ({mode:?})\n{outcome}",
            verdict.label()
        )),
    }
}

/// What a run may claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Expect {
    /// Exhaustive: exact lengths, undecided means verified or unreachable.
    Exhaustive,
    /// Bounded and not exhaustive: exact lengths, undecided means unknown.
    Bounded,
    /// Simulation: lengths are lower bounds, anything may stay unknown.
    Simulation,
}

/// Checks the verdicts of the four properties from [`properties`].
fn check_verdicts(
    model: &GraphModel,
    outcome: &Outcome<usize, usize>,
    want: &Expected,
    target: usize,
    mode: Expect,
) -> Result<(), String> {
    let at_target = |s: usize| s == target;
    let dead = |s: usize| deadlocks(model, s);
    check_verdict(model, outcome, ALWAYS, want.target, mode, at_target)?;
    check_verdict(model, outcome, REACH, want.target, mode, at_target)?;
    check_verdict(model, outcome, DEADLOCK, want.deadlock, mode, dead)?;
    check_verdict(model, outcome, EDGE, want.edge, mode, at_target)
}

fn check_space(
    model: &GraphModel,
    r: &Reference,
    space: &StateSpace<usize, usize>,
    expected_order: &[usize],
    label: &str,
) -> Result<(), String> {
    let got: Vec<usize> = space.states().copied().collect();
    ensure!(
        got == expected_order,
        "{label}: stored states {got:?} differ from the reference order {expected_order:?}"
    );
    let mut transitions = 0usize;
    for (i, &v) in got.iter().enumerate() {
        let want = r.dist.get(v).copied().flatten();
        ensure!(
            space.depth(i) == want,
            "{label}: node {v} has depth {:?}, the reference distance is {want:?}",
            space.depth(i)
        );
        ensure!(space.find(&v) == Some(i), "{label}: find({v}) is wrong");
        let Some(trace) = space.trace_to(i) else {
            return Err(format!("{label}: no trace to node {v}"));
        };
        check_trace(model, label, &trace, want, |s| s == v)?;
        transitions = transitions.saturating_add(model.enabled_targets(v).count());
    }
    ensure!(
        space.stats.transitions == transitions,
        "{label}: {} transitions counted, {transitions} expected",
        space.stats.transitions
    );
    ensure!(
        space.stats.states == got.len(),
        "{label}: stats.states is {}, {} stored",
        space.stats.states,
        got.len()
    );
    let deepest = got
        .iter()
        .filter_map(|&v| r.dist.get(v).copied().flatten())
        .max()
        .unwrap_or(0);
    ensure!(
        space.stats.max_depth == deepest,
        "{label}: max depth {} but the deepest stored node is at {deepest}",
        space.stats.max_depth
    );
    Ok(())
}

/// Runs the checker on `case` and compares it with the reference searches.
///
/// The checker explores canonical forms, so steps 1 to 5 compare it with the
/// reference searches on canonical forms. Terminal nodes never count as
/// deadlocks. Checks, in order:
///
/// 1. The reference depth-first and breadth-first searches agree.
/// 2. An unbounded [`explore`] stores exactly the reachable nodes, in
///    breadth-first order, each at its shortest distance, and is exhaustive.
///    Every parent trace replays and has the shortest length.
/// 3. An unbounded [`check`] gives the reference verdicts. Counterexample
///    and witness lengths equal the reference shortest distances.
/// 4. A bounded run stores the reference order cut by both bounds, and is
///    exhaustive exactly when no bound removed a reachable node. Its
///    verdicts follow the stored nodes, and undecided ones are unknown.
/// 5. Two identical runs give identical outcomes.
/// 6. A simulation never verifies, and every trace it reports replays and
///    is no shorter than the distance in the concrete graph.
pub fn check_against_reference(case: &GraphCase) -> Result<(), String> {
    let model = &case.model;
    let target = case.target;
    let r = reference_bfs(model);
    let dfs = reference_dfs(model);

    // 1. The two reference searches agree.
    for (v, &seen) in dfs.iter().enumerate() {
        let by_bfs = r.dist.get(v).copied().flatten().is_some();
        ensure!(seen == by_bfs, "reference DFS and BFS disagree on node {v}");
    }
    let reach_count = dfs.iter().filter(|&&s| s).count();
    let dist = |v: usize| r.dist.get(v).copied().flatten();
    let ecc = r.order.iter().filter_map(|&v| dist(v)).max().unwrap_or(0);

    // 2. Unbounded exploration.
    let full_cfg = Config::default().with_max_states(usize::MAX);
    let space = explore(model, &full_cfg);
    ensure!(space.exhaustive, "unbounded exploration is not exhaustive");
    ensure!(
        !space.depth_bound_hit && !space.state_bound_hit,
        "unbounded exploration hit a bound"
    );
    ensure!(
        space.len() == reach_count,
        "checker found {} states, reference DFS {reach_count}",
        space.len()
    );
    check_space(model, &r, &space, &r.order, "unbounded")?;
    ensure!(
        space.stats.max_depth == ecc,
        "max depth {} but the reference eccentricity is {ecc}",
        space.stats.max_depth
    );

    // 3. Unbounded check, with and without the early stop.
    let props = properties(target);
    let want = expected(model, &r, &r.order, target);
    for stop in [false, true] {
        let outcome = check(model, &props, &full_cfg.with_stop_when_decided(stop));
        let exhaustive = outcome.exhaustive;
        ensure!(
            exhaustive || (stop && outcome.stopped_early),
            "unbounded check is not exhaustive\n{outcome}"
        );
        let mode = if exhaustive {
            Expect::Exhaustive
        } else {
            Expect::Bounded
        };
        check_verdicts(model, &outcome, &want, target, mode)?;
    }

    // 4. Bounded exploration and check.
    let bounded_cfg = Config {
        max_depth: case.max_depth,
        max_states: case.max_states,
        stop_when_decided: false,
    };
    let within_depth: Vec<usize> = r
        .order
        .iter()
        .copied()
        .filter(|&v| dist(v).is_some_and(|d| d <= case.max_depth))
        .collect();
    let stored: Vec<usize> = within_depth.iter().copied().take(case.max_states).collect();
    let bounded = explore(model, &bounded_cfg);
    check_space(model, &r, &bounded, &stored, "bounded")?;
    let want_exhaustive = ecc <= case.max_depth && reach_count <= case.max_states;
    ensure!(
        bounded.exhaustive == want_exhaustive,
        "bounded exhaustive flag is {}, expected {want_exhaustive}",
        bounded.exhaustive
    );
    ensure!(
        bounded.state_bound_hit == (within_depth.len() > case.max_states),
        "state bound flag is {}",
        bounded.state_bound_hit
    );
    // A stored node at the depth bound with an enabled edge to a node that
    // is not stored. That node lies one step beyond the bound, or the state
    // bound dropped it earlier; either way this edge is cut by the depth bound.
    let depth_drop = stored.iter().any(|&u| {
        dist(u) == Some(case.max_depth)
            && model
                .enabled_targets(u)
                .any(|v| !stored.contains(&model.canonical(v)))
    });
    ensure!(
        bounded.depth_bound_hit == depth_drop,
        "depth bound flag is {}, expected {depth_drop}",
        bounded.depth_bound_hit
    );
    let outcome = check(model, &props, &bounded_cfg);
    ensure!(
        outcome.exhaustive == want_exhaustive,
        "bounded check exhaustive flag differs from exploration"
    );
    ensure!(
        outcome.stats == bounded.stats,
        "bounded check and exploration statistics differ"
    );
    if !want_exhaustive {
        ensure!(
            outcome
                .results
                .iter()
                .all(|res| res.verdict != Verdict::Verified),
            "a non-exhaustive run verified a property\n{outcome}"
        );
    }
    let want_b = expected(model, &r, &stored, target);
    let mode = if want_exhaustive {
        Expect::Exhaustive
    } else {
        Expect::Bounded
    };
    check_verdicts(model, &outcome, &want_b, target, mode)?;

    // 5. Determinism.
    let again = check(model, &props, &bounded_cfg);
    ensure!(again == outcome, "two identical runs differ");
    ensure!(
        again.to_string() == outcome.to_string(),
        "two identical runs print differently"
    );

    // 6. Simulation. It walks concrete states, so the concrete search gives
    // the lower bounds.
    let concrete = reference_bfs_concrete(model);
    let want_concrete = expected(model, &concrete, &concrete.order, target);
    let sim_cfg = SimConfig {
        seed: case.seed,
        walks: 8,
        max_steps: model.node_count().saturating_mul(2),
        stop_when_decided: false,
    };
    let sim = simulate(model, &props, &sim_cfg);
    ensure!(!sim.exhaustive, "a simulation claimed to be exhaustive");
    ensure!(
        sim.results
            .iter()
            .all(|res| !matches!(res.verdict, Verdict::Verified | Verdict::Unreachable)),
        "a simulation verified a property\n{sim}"
    );
    let sim_again = simulate(model, &props, &sim_cfg);
    ensure!(sim_again == sim, "two identical simulations differ");
    check_verdicts(model, &sim, &want_concrete, target, Expect::Simulation)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_out_of_range_nodes() {
        let limits = GraphLimits::default();
        assert_eq!(
            GraphModel::new(2, vec![2], &[], &limits),
            Err(GraphError::NodeOutOfRange {
                node: 2,
                node_count: 2
            })
        );
        assert!(GraphModel::new(2, vec![0], &[(0, 5, true)], &limits).is_err());
        assert!(GraphModel::new(2, vec![0], &[(5, 0, true)], &limits).is_err());
        assert!(GraphModel::new(65, vec![0], &[], &limits).is_err());
        let open = GraphLimits {
            max_nodes: usize::MAX,
            ..limits
        };
        assert_eq!(
            GraphModel::new(MAX_GRAPH_NODES + 1, vec![], &[], &open),
            Err(GraphError::TooManyNodes {
                node_count: MAX_GRAPH_NODES + 1,
                max_nodes: MAX_GRAPH_NODES
            })
        );
        assert_eq!(
            GraphModel::new(MAX_GRAPH_NODES, vec![], &[], &open).map(|g| g.node_count()),
            Ok(MAX_GRAPH_NODES)
        );
    }

    #[test]
    fn classes_and_terminal_nodes() {
        let limits = GraphLimits::default();
        let g = GraphModel::new(5, vec![4], &[(4, 3, true), (3, 0, true)], &limits)
            .unwrap()
            .with_classes(&[9, 7, 9, 7])
            .with_terminal(&[1])
            .unwrap();
        let canon: Vec<usize> = (0..5).map(|v| g.canonical(v)).collect();
        assert_eq!(canon, [0, 1, 0, 1, 4]);
        assert_eq!(g.canonicalize(&3), 1);
        assert!(g.is_terminal(&1));
        assert!(!g.is_terminal(&3));
        assert!(g.clone().with_terminal(&[5]).is_err());
        // From 4, the edge to 3 lands on its canonical form 1, whose own
        // edges are expanded: none, so 1 is reached but 0 is not.
        let r = reference_bfs(&g);
        assert_eq!(r.order, vec![4, 1]);
        assert_eq!(reference_dfs(&g), vec![false, true, false, false, true]);
        assert_eq!(reference_bfs_concrete(&g).order, vec![4, 3, 0]);
    }

    #[test]
    fn from_bytes_symmetric_decodes_every_input() {
        let limits = GraphLimits::default();
        for data in [
            &b""[..],
            b"\x00",
            b"\x03\x81\x01",
            b"\xff\xff\xff\xff\xff\xff\xff\xff\xff",
        ] {
            let case = GraphCase::from_bytes_symmetric(data, &limits).unwrap();
            assert!(case.model.node_count() >= 1);
            assert!(case.target < case.model.node_count());
            check_against_reference(&case).unwrap();
        }
        // Block of two bytes: node 0 is terminal, node 1 shares its class.
        // Then three nodes with no initial nodes.
        let case = GraphCase::from_bytes_symmetric(b"\x02\x80\x03\x02", &limits).unwrap();
        assert_eq!(case.model.node_count(), 3);
        assert!(case.model.is_terminal_node(0));
        assert!(!case.model.is_terminal_node(1));
        assert_eq!(case.model.canonical(1), 0);
        assert_eq!(case.model.canonical(2), 2);
    }

    #[test]
    fn from_bytes_decodes_every_input() {
        let limits = GraphLimits::default();
        for data in [&b""[..], b"\x00", b"\xff\xff\xff\xff\xff\xff\xff\xff\xff"] {
            let case = GraphCase::from_bytes(data, &limits).unwrap();
            assert!(case.model.node_count() >= 1);
            assert!(case.target < case.model.node_count());
        }
        let bad = GraphLimits {
            max_nodes: 0,
            ..limits
        };
        assert_eq!(
            GraphCase::from_bytes(b"", &bad),
            Err(GraphError::InvalidLimits)
        );
    }

    #[test]
    fn reference_on_a_small_graph() {
        let limits = GraphLimits::default();
        // 0 -> 1 -> 2, 0 -> 2 disabled, 3 unreachable.
        let g = GraphModel::new(
            4,
            vec![0, 0],
            &[(0, 1, true), (0, 2, false), (1, 2, true), (3, 0, true)],
            &limits,
        )
        .unwrap();
        let r = reference_bfs(&g);
        assert_eq!(r.order, vec![0, 1, 2]);
        assert_eq!(r.dist, vec![Some(0), Some(1), Some(2), None]);
        assert_eq!(reference_dfs(&g), vec![true, true, true, false]);
        for target in 0..4 {
            for (max_depth, max_states) in [(usize::MAX, usize::MAX), (1, 9), (9, 2), (0, 0)] {
                let case = GraphCase {
                    model: g.clone(),
                    target,
                    max_depth,
                    max_states,
                    seed: 3,
                };
                check_against_reference(&case).unwrap();
            }
        }
    }
}
