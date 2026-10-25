//! Self-tests of the model checker (M1 exit criterion "harnesses self-tested").
//!
//! Each test runs the checker on a model with a known answer, derived by hand
//! or by an independent reference search, and checks the outcome exactly:
//! verdicts, shortest trace lengths, state counts, depths and bound flags.

// Models and helpers here sit outside #[test] functions, where the workspace
// test exemptions (clippy.toml) do not reach. Panics, indexing and arithmetic
// in this file are model code over small known ranges or report test
// failures, which is their purpose.
#![allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::{HashMap, VecDeque};

use fstp_mc::graph::{GraphCase, GraphLimits, GraphModel, check_against_reference};
use fstp_mc::{
    Config, Mode, Model, Outcome, Property, PropertyKind, SimConfig, Trace, Verdict, check,
    explore, simulate,
};
use fstp_prop::{Config as PropConfig, check_with};

// ---------------------------------------------------------------------------
// Helpers

/// Independent breadth-first search with std collections. Returns the number
/// of reachable (canonical) states and the greatest shortest distance.
fn reference_bfs<M: Model>(model: &M) -> (usize, usize) {
    let mut depth: HashMap<M::State, usize> = HashMap::new();
    let mut queue = VecDeque::new();
    for s in model.init() {
        let c = model.canonicalize(&s);
        if !depth.contains_key(&c) {
            depth.insert(c.clone(), 0);
            queue.push_back(c);
        }
    }
    while let Some(s) = queue.pop_front() {
        let d = depth[&s];
        let mut actions = Vec::new();
        model.actions(&s, &mut actions);
        for a in actions {
            if let Some(t) = model.step(&s, &a) {
                let t = model.canonicalize(&t);
                if !depth.contains_key(&t) {
                    depth.insert(t.clone(), d + 1);
                    queue.push_back(t);
                }
            }
        }
    }
    let max = depth.values().copied().max().unwrap_or(0);
    (depth.len(), max)
}

fn verdict<'o, S, A>(outcome: &'o Outcome<S, A>, id: &str) -> &'o Verdict<S, A> {
    match outcome.verdict(id) {
        Some(v) => v,
        None => panic!("no verdict for {id}"),
    }
}

/// Returns the counterexample of a violated property, or panics with the report.
fn violation_trace<'o, S, A>(outcome: &'o Outcome<S, A>, id: &str) -> &'o Trace<S, A>
where
    S: std::fmt::Debug,
    A: std::fmt::Debug,
{
    match verdict(outcome, id) {
        Verdict::Violated(v) => &v.trace,
        _ => panic!("expected {id} to be violated\n{outcome}"),
    }
}

fn witness_trace<'o, S, A>(outcome: &'o Outcome<S, A>, id: &str) -> &'o Trace<S, A>
where
    S: std::fmt::Debug,
    A: std::fmt::Debug,
{
    match verdict(outcome, id) {
        Verdict::Reached(t) => t,
        _ => panic!("expected {id} to be reached\n{outcome}"),
    }
}

fn action_names<S, A: std::fmt::Debug>(trace: &Trace<S, A>) -> Vec<String> {
    trace.actions().map(|a| format!("{a:?}")).collect()
}

fn full() -> Config {
    Config::default().with_stop_when_decided(false)
}

// ---------------------------------------------------------------------------
// 1. Die Hard water jugs

struct Jugs;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Pour {
    FillSmall,
    FillBig,
    EmptySmall,
    EmptyBig,
    SmallToBig,
    BigToSmall,
}

impl Model for Jugs {
    /// (small, big) in gallons; capacities 3 and 5.
    type State = (u8, u8);
    type Action = Pour;

    fn init(&self) -> Vec<(u8, u8)> {
        vec![(0, 0)]
    }

    fn actions(&self, _: &(u8, u8), actions: &mut Vec<Pour>) {
        actions.extend([
            Pour::FillSmall,
            Pour::FillBig,
            Pour::EmptySmall,
            Pour::EmptyBig,
            Pour::SmallToBig,
            Pour::BigToSmall,
        ]);
    }

    fn step(&self, &(small, big): &(u8, u8), pour: &Pour) -> Option<(u8, u8)> {
        let next = match pour {
            Pour::FillSmall => (3, big),
            Pour::FillBig => (small, 5),
            Pour::EmptySmall => (0, big),
            Pour::EmptyBig => (small, 0),
            Pour::SmallToBig => {
                let moved = small.min(5 - big);
                (small - moved, big + moved)
            }
            Pour::BigToSmall => {
                let moved = big.min(3 - small);
                (small + moved, big - moved)
            }
        };
        (next != (small, big)).then_some(next)
    }
}

/// The 4-gallon state is reachable, and "never 4 gallons" fails with a
/// shortest trace of exactly 6 steps.
///
/// The 6-step solution fills the big jug, pours into the small one, empties
/// the small one, pours the remaining 2 gallons across, refills the big jug
/// and tops up the small one, which leaves 4 in the big jug. The other
/// route starts by filling the small jug and takes 8 steps.
#[test]
fn selftest_die_hard_four_gallons_shortest_trace_is_six() {
    let props = [
        Property::<Jugs>::reachable("four-reachable", |&(_, big)| big == 4),
        Property::<Jugs>::always("never-four", |&(_, big)| big != 4),
        Property::<Jugs>::deadlock_free("no-deadlock"),
    ];
    let outcome = check(&Jugs, &props, &full());
    assert!(outcome.exhaustive, "{outcome}");
    // Reachable states are those with at least one jug empty or full: 16.
    assert_eq!(outcome.stats.states, 16);
    assert_eq!(reference_bfs(&Jugs).0, 16);

    let witness = witness_trace(&outcome, "four-reachable");
    assert_eq!(witness.len(), 6);
    let trace = violation_trace(&outcome, "never-four");
    assert_eq!(trace.len(), 6);
    assert_eq!(trace, witness);
    assert_eq!(
        action_names(trace),
        [
            "FillBig",
            "BigToSmall",
            "EmptySmall",
            "BigToSmall",
            "FillBig",
            "BigToSmall"
        ]
    );
    let states: Vec<(u8, u8)> = trace.states().copied().collect();
    assert_eq!(
        states,
        [(0, 0), (0, 5), (3, 2), (0, 2), (2, 0), (2, 5), (3, 4)]
    );
    trace.replay(&Jugs).unwrap();
    assert_eq!(verdict(&outcome, "no-deadlock"), &Verdict::Verified);
}

// ---------------------------------------------------------------------------
// 2. Mutual exclusion: Peterson and a naive check-then-set protocol

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Peterson {
    /// 0 idle, 1 flag raised, 2 waiting, 3 critical.
    pc: [u8; 2],
    flag: [bool; 2],
    turn: usize,
}

struct PetersonModel;

impl Model for PetersonModel {
    type State = Peterson;
    /// The process that moves.
    type Action = usize;

    fn init(&self) -> Vec<Peterson> {
        vec![Peterson {
            pc: [0, 0],
            flag: [false, false],
            turn: 0,
        }]
    }

    fn actions(&self, _: &Peterson, actions: &mut Vec<usize>) {
        actions.extend([0, 1]);
    }

    fn step(&self, s: &Peterson, &i: &usize) -> Option<Peterson> {
        let j = 1 - i;
        let mut t = s.clone();
        match s.pc[i] {
            0 => {
                t.flag[i] = true;
                t.pc[i] = 1;
            }
            1 => {
                t.turn = j;
                t.pc[i] = 2;
            }
            2 => {
                if s.flag[j] && s.turn == j {
                    return None;
                }
                t.pc[i] = 3;
            }
            _ => {
                t.flag[i] = false;
                t.pc[i] = 0;
            }
        }
        Some(t)
    }
}

/// Peterson's algorithm for two processes keeps mutual exclusion in every
/// reachable state. The run is exhaustive, each critical section is
/// reachable, and no state deadlocks.
#[test]
fn selftest_peterson_mutual_exclusion_verifies() {
    let props = [
        Property::<PetersonModel>::always("mutual-exclusion", |s| !(s.pc[0] == 3 && s.pc[1] == 3)),
        Property::<PetersonModel>::reachable("p0-critical", |s| s.pc[0] == 3),
        Property::<PetersonModel>::reachable("p1-critical", |s| s.pc[1] == 3),
        Property::<PetersonModel>::deadlock_free("no-deadlock"),
    ];
    let outcome = check(&PetersonModel, &props, &full());
    assert!(outcome.exhaustive, "{outcome}");
    assert!(outcome.all_passed(), "{outcome}");
    outcome.require_all_passed().unwrap();
    assert_eq!(verdict(&outcome, "mutual-exclusion"), &Verdict::Verified);
    // Process 0 needs three steps to enter: raise flag, yield turn, enter.
    assert_eq!(witness_trace(&outcome, "p0-critical").len(), 3);
    let (states, depth) = reference_bfs(&PetersonModel);
    assert_eq!(outcome.stats.states, states);
    assert_eq!(outcome.stats.max_depth, depth);
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Naive {
    /// 0 idle, 1 checked the other flag, 2 critical.
    pc: [u8; 2],
    flag: [bool; 2],
}

struct NaiveMutex;

impl Model for NaiveMutex {
    type State = Naive;
    type Action = usize;

    fn init(&self) -> Vec<Naive> {
        vec![Naive {
            pc: [0, 0],
            flag: [false, false],
        }]
    }

    fn actions(&self, _: &Naive, actions: &mut Vec<usize>) {
        actions.extend([0, 1]);
    }

    fn step(&self, s: &Naive, &i: &usize) -> Option<Naive> {
        let j = 1 - i;
        let mut t = s.clone();
        match s.pc[i] {
            // Check: wait until the other flag is down.
            0 => {
                if s.flag[j] {
                    return None;
                }
                t.pc[i] = 1;
            }
            // Set: raise the own flag and enter the critical section.
            1 => {
                t.flag[i] = true;
                t.pc[i] = 2;
            }
            // Exit.
            _ => {
                t.flag[i] = false;
                t.pc[i] = 0;
            }
        }
        Some(t)
    }
}

/// A check-flag-then-set mutex violates mutual exclusion, and the checker
/// returns a shortest trace of exactly 4 steps.
///
/// Derivation: a process needs two steps to reach its critical section from
/// idle, a check and a set. Both processes in their critical sections need
/// at least 2 + 2 = 4 steps. Four suffice: both processes check while both
/// flags are down, then both set. No trace is shorter.
///
/// With actions ordered process 0 then process 1, breadth-first search first
/// reaches the violation by: P0 check, P1 check, P0 set, P1 set.
#[test]
fn selftest_naive_mutex_violation_has_shortest_trace_of_four() {
    let props = [Property::<NaiveMutex>::always("mutual-exclusion", |s| {
        !(s.pc[0] == 2 && s.pc[1] == 2)
    })];
    let outcome = check(&NaiveMutex, &props, &full());
    let trace = violation_trace(&outcome, "mutual-exclusion");
    assert_eq!(trace.len(), 4, "{outcome}");
    assert_eq!(trace.actions().copied().collect::<Vec<_>>(), [0, 1, 0, 1]);
    assert_eq!(trace.last_state().pc, [2, 2]);
    trace.replay(&NaiveMutex).unwrap();
    assert!(outcome.has_failures());
    assert!(outcome.require_no_failures().is_err());
}

// ---------------------------------------------------------------------------
// 3. Wrapping counter

struct Counter {
    bits: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Inc;

impl Model for Counter {
    type State = u64;
    type Action = Inc;

    fn init(&self) -> Vec<u64> {
        vec![0]
    }

    fn actions(&self, _: &u64, actions: &mut Vec<Inc>) {
        actions.push(Inc);
    }

    fn step(&self, &v: &u64, _: &Inc) -> Option<u64> {
        Some((v + 1) & ((1u64 << self.bits) - 1))
    }
}

/// An n-bit wrapping counter has exactly 2^n reachable states, depth
/// 2^n - 1 and 2^n transitions, for several n. A depth bound of exactly
/// 2^n - 1 still gives an exhaustive run; one less does not.
#[test]
fn selftest_wrapping_counter_has_two_to_the_n_states() {
    for bits in [1u32, 2, 3, 4, 5, 8, 10, 12] {
        let model = Counter { bits };
        let size = 1usize << bits;
        let props = [
            Property::<Counter>::deadlock_free("no-deadlock"),
            Property::<Counter>::always("in-range", move |&v| v < size as u64),
        ];
        let outcome = check(&model, &props, &full());
        assert!(outcome.exhaustive, "bits {bits}: {outcome}");
        assert_eq!(outcome.stats.states, size, "bits {bits}");
        assert_eq!(outcome.stats.max_depth, size - 1, "bits {bits}");
        assert_eq!(outcome.stats.transitions, size, "bits {bits}");
        assert!(outcome.all_passed(), "{outcome}");

        let exact = check(&model, &props, &full().with_max_depth(size - 1));
        assert!(exact.exhaustive, "bits {bits}: {exact}");
        assert!(!exact.depth_bound_hit);

        let short = check(&model, &props, &full().with_max_depth(size - 2));
        assert!(!short.exhaustive, "bits {bits}");
        assert!(short.depth_bound_hit);
        assert_eq!(short.stats.states, size - 1);
        assert!(short.results.iter().all(|r| r.verdict.is_unknown()));

        let space = explore(&model, &full());
        assert_eq!(space.len(), size);
        assert_eq!(space.depth(size - 1), Some(size - 1));
        assert_eq!(space.find(&(size as u64 - 1)), Some(size - 1));
    }
}

// ---------------------------------------------------------------------------
// 4. Bounds never claim verification

/// With `max_states` below the state space size, the run is not exhaustive
/// and no property is reported as verified or unreachable. A property that
/// holds is unknown. A witness found within the bound is still reported,
/// because it is a real trace.
#[test]
fn selftest_state_bound_is_non_exhaustive_and_verifies_nothing() {
    let model = Counter { bits: 6 };
    let props = [
        Property::<Counter>::always("in-range", |&v| v < 64),
        Property::<Counter>::transition("increments", |&a, _, &b| b == (a + 1) % 64),
        Property::<Counter>::deadlock_free("no-deadlock"),
        Property::<Counter>::reachable("reaches-63", |&v| v == 63),
        Property::<Counter>::reachable("reaches-3", |&v| v == 3),
        Property::<Counter>::reachable("reaches-99", |&v| v == 99),
    ];
    for max_states in [0usize, 1, 10, 63] {
        let outcome = check(&model, &props, &full().with_max_states(max_states));
        assert!(!outcome.exhaustive, "{outcome}");
        assert!(outcome.state_bound_hit);
        assert_eq!(outcome.stats.states, max_states);
        for r in &outcome.results {
            assert!(
                !matches!(r.verdict, Verdict::Verified | Verdict::Unreachable),
                "{} reported {} in a bounded run",
                r.id,
                r.verdict.label()
            );
        }
        assert!(verdict(&outcome, "in-range").is_unknown());
        assert!(verdict(&outcome, "reaches-63").is_unknown());
        assert!(verdict(&outcome, "reaches-99").is_unknown());
        assert!(!outcome.all_passed());
        assert!(outcome.require_no_failures().is_ok());
        assert!(outcome.to_string().contains("exhaustive: NO"));
        if max_states > 3 {
            assert_eq!(witness_trace(&outcome, "reaches-3").len(), 3);
        }
    }
    // A bound equal to the state space size drops nothing.
    let outcome = check(&model, &props, &full().with_max_states(64));
    assert!(outcome.exhaustive, "{outcome}");
    assert_eq!(verdict(&outcome, "in-range"), &Verdict::Verified);
    assert_eq!(verdict(&outcome, "reaches-99"), &Verdict::Unreachable);
}

// ---------------------------------------------------------------------------
// 5. Deadlock detection

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Locks {
    /// 0 start, 1 holds first lock, 2 holds both, 3 done.
    pc: [u8; 2],
    /// Lock owner per lock (A, B).
    owner: [Option<usize>; 2],
}

struct TwoLocks {
    /// Both processes take A then B. Otherwise process 1 takes B then A.
    ordered: bool,
    /// Declare "both done" as terminal.
    terminal_done: bool,
}

impl TwoLocks {
    fn order(&self, i: usize) -> [usize; 2] {
        if i == 1 && !self.ordered {
            [1, 0]
        } else {
            [0, 1]
        }
    }
}

impl Model for TwoLocks {
    type State = Locks;
    type Action = usize;

    fn init(&self) -> Vec<Locks> {
        vec![Locks {
            pc: [0, 0],
            owner: [None, None],
        }]
    }

    fn actions(&self, _: &Locks, actions: &mut Vec<usize>) {
        actions.extend([0, 1]);
    }

    fn step(&self, s: &Locks, &i: &usize) -> Option<Locks> {
        let [first, second] = self.order(i);
        let mut t = s.clone();
        match s.pc[i] {
            0 | 1 => {
                let lock = if s.pc[i] == 0 { first } else { second };
                if s.owner[lock].is_some() {
                    return None;
                }
                t.owner[lock] = Some(i);
                t.pc[i] += 1;
            }
            2 => {
                t.owner = t.owner.map(|o| o.filter(|&p| p != i));
                t.pc[i] = 3;
            }
            _ => return None,
        }
        Some(t)
    }

    fn is_terminal(&self, s: &Locks) -> bool {
        self.terminal_done && s.pc == [3, 3]
    }
}

/// Deadlock detection finds the classic deadlock when two processes take
/// two locks in opposite orders: after one step each, each holds the lock
/// the other needs. Declaring terminal states does not hide it.
///
/// With a consistent lock order the only state without an enabled action is
/// "both done". It counts as a deadlock until it is declared terminal; then
/// the model is verified deadlock-free.
#[test]
fn selftest_deadlock_two_locks() {
    let props = [Property::<TwoLocks>::deadlock_free("deadlock-free")];
    for terminal_done in [false, true] {
        let model = TwoLocks {
            ordered: false,
            terminal_done,
        };
        let outcome = check(&model, &props, &full());
        let trace = violation_trace(&outcome, "deadlock-free");
        assert_eq!(trace.len(), 2, "{outcome}");
        assert_eq!(trace.last_state().owner, [Some(0), Some(1)]);
        assert_eq!(trace.last_state().pc, [1, 1]);
        trace.replay(&model).unwrap();
    }

    let not_declared = TwoLocks {
        ordered: true,
        terminal_done: false,
    };
    let outcome = check(&not_declared, &props, &full());
    let trace = violation_trace(&outcome, "deadlock-free");
    assert_eq!(trace.last_state().pc, [3, 3], "{outcome}");
    // Each process needs three steps (A, B, release): six in total.
    assert_eq!(trace.len(), 6);

    let declared = TwoLocks {
        ordered: true,
        terminal_done: true,
    };
    let outcome = check(&declared, &props, &full());
    assert!(outcome.exhaustive, "{outcome}");
    assert_eq!(verdict(&outcome, "deadlock-free"), &Verdict::Verified);
}

// ---------------------------------------------------------------------------
// 6. Transition properties

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Door {
    Open,
    Closed,
    Locked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DoorAction {
    Open,
    Close,
    Lock,
    Unlock,
    Kick,
}

struct DoorModel {
    /// Allows the forbidden transition Locked to Open.
    kick: bool,
}

impl Model for DoorModel {
    type State = Door;
    type Action = DoorAction;

    fn init(&self) -> Vec<Door> {
        vec![Door::Closed]
    }

    fn actions(&self, _: &Door, actions: &mut Vec<DoorAction>) {
        actions.extend([
            DoorAction::Open,
            DoorAction::Close,
            DoorAction::Lock,
            DoorAction::Unlock,
            DoorAction::Kick,
        ]);
    }

    fn step(&self, s: &Door, a: &DoorAction) -> Option<Door> {
        match (s, a) {
            (Door::Closed, DoorAction::Open) => Some(Door::Open),
            (Door::Open, DoorAction::Close) => Some(Door::Closed),
            (Door::Closed, DoorAction::Lock) => Some(Door::Locked),
            (Door::Locked, DoorAction::Unlock) => Some(Door::Closed),
            (Door::Locked, DoorAction::Kick) if self.kick => Some(Door::Open),
            _ => None,
        }
    }
}

/// A transition property catches a forbidden transition that no state
/// predicate can express: every state is legal, but Locked must never go
/// straight to Open. The shortest counterexample is Lock then Kick. Without
/// the faulty action the property is verified.
#[test]
fn selftest_transition_property_catches_forbidden_transition() {
    let props = [
        Property::<DoorModel>::transition_with("open-only-from-closed", |before, _, after| {
            if *after == Door::Open && *before != Door::Closed {
                Err(format!("{before:?} went straight to Open"))
            } else {
                Ok(())
            }
        }),
        Property::<DoorModel>::always("any-state", |_| true),
    ];
    let outcome = check(&DoorModel { kick: true }, &props, &full());
    let Some(Verdict::Violated(v)) = outcome.verdict("open-only-from-closed") else {
        panic!("not violated\n{outcome}");
    };
    assert_eq!(v.trace.len(), 2);
    assert_eq!(action_names(&v.trace), ["Lock", "Kick"]);
    assert_eq!(*v.trace.last_state(), Door::Open);
    assert_eq!(v.detail.as_deref(), Some("Locked went straight to Open"));
    v.trace.replay(&DoorModel { kick: true }).unwrap();
    assert_eq!(verdict(&outcome, "any-state"), &Verdict::Verified);
    assert_eq!(
        outcome.result("open-only-from-closed").map(|r| r.kind),
        Some(PropertyKind::Transition)
    );

    let fixed = check(&DoorModel { kick: false }, &props, &full());
    assert!(fixed.all_passed(), "{fixed}");
}

// ---------------------------------------------------------------------------
// 7. Differential test against reference graph searches

/// On random small directed graphs, the reachable set equals a reference
/// depth-first search, and the counterexample length to a random target
/// equals the reference breadth-first distance. `check_against_reference`
/// also covers bounded runs, flags, transition and deadlock verdicts,
/// determinism and simulation soundness.
#[test]
fn selftest_differential_random_graphs_match_reference() {
    let cfg = PropConfig::default().with_cases(1000);
    check_with("mc_differential_random_graphs", cfg, |g| {
        let n = g.usize_in(1..=10);
        let init = g.vec(0..=3, |g| g.usize_in(0..=n - 1));
        let edges = g.vec(0..=30, |g| {
            let from = g.usize_in(0..=n - 1);
            let to = g.usize_in(0..=n - 1);
            let enabled = g.weighted(&[1, 4]) == 1;
            (from, to, enabled)
        });
        let target = g.usize_in(0..=n - 1);
        let max_depth = g.option(|g| g.usize_in(0..=10)).unwrap_or(usize::MAX);
        let max_states = g.option(|g| g.usize_in(0..=12)).unwrap_or(usize::MAX);
        let seed = g.u64();
        let limits = GraphLimits {
            max_nodes: 10,
            max_edges: 30,
            max_init: 3,
        };
        let model = GraphModel::new(n, init, &edges, &limits).map_err(|e| e.to_string())?;
        g.note("model", &model);
        let case = GraphCase {
            model,
            target,
            max_depth,
            max_states,
            seed,
        };
        check_against_reference(&case)
    });
}

/// The same differential check over inputs decoded from bytes, which is what
/// the `random_graph` fuzz target runs.
#[test]
fn selftest_differential_from_bytes() {
    check_with(
        "mc_differential_from_bytes",
        PropConfig::default().with_cases(500),
        |g| {
            let data = g.bytes(0..=80);
            let case =
                GraphCase::from_bytes(&data, &GraphLimits::default()).map_err(|e| e.to_string())?;
            check_against_reference(&case)
        },
    );
}

/// The differential check on graphs with node classes and terminal nodes,
/// which drive `Model::canonicalize` and `Model::is_terminal`. The reference
/// searches use the same canonical forms, so any grouping is a valid test.
/// Terminal nodes must never count as deadlocks.
#[test]
fn selftest_differential_symmetric_graphs_match_reference() {
    let cfg = PropConfig::default().with_cases(1000);
    check_with("mc_differential_symmetric_graphs", cfg, |g| {
        let n = g.usize_in(1..=10);
        let init = g.vec(0..=3, |g| g.usize_in(0..=n - 1));
        let edges = g.vec(0..=30, |g| {
            let from = g.usize_in(0..=n - 1);
            let to = g.usize_in(0..=n - 1);
            let enabled = g.weighted(&[1, 4]) == 1;
            (from, to, enabled)
        });
        let classes = g.vec(0..=n, |g| g.usize_in(0..=3));
        let terminal = g.vec(0..=3, |g| g.usize_in(0..=n - 1));
        let target = g.usize_in(0..=n - 1);
        let max_depth = g.option(|g| g.usize_in(0..=10)).unwrap_or(usize::MAX);
        let max_states = g.option(|g| g.usize_in(0..=12)).unwrap_or(usize::MAX);
        let seed = g.u64();
        let limits = GraphLimits {
            max_nodes: 10,
            max_edges: 30,
            max_init: 3,
        };
        let model = GraphModel::new(n, init, &edges, &limits)
            .and_then(|m| m.with_classes(&classes).with_terminal(&terminal))
            .map_err(|e| e.to_string())?;
        g.note("model", &model);
        let case = GraphCase {
            model,
            target,
            max_depth,
            max_states,
            seed,
        };
        check_against_reference(&case)
    });
}

/// The symmetric differential check over inputs decoded from bytes, which
/// is what the `symmetric_graph` fuzz target runs.
#[test]
fn selftest_differential_symmetric_from_bytes() {
    check_with(
        "mc_differential_symmetric_from_bytes",
        PropConfig::default().with_cases(500),
        |g| {
            let data = g.bytes(0..=90);
            let case = GraphCase::from_bytes_symmetric(&data, &GraphLimits::default())
                .map_err(|e| e.to_string())?;
            check_against_reference(&case)
        },
    );
}

// ---------------------------------------------------------------------------
// 8. Determinism

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Move {
    Right,
    Up,
    Diagonal,
}

/// A grid with many shortest paths to each cell, so a careless tie-break
/// would show up as different traces.
struct Grid {
    size: u8,
}

impl Model for Grid {
    type State = (u8, u8);
    type Action = Move;

    fn init(&self) -> Vec<(u8, u8)> {
        vec![(0, 0)]
    }

    fn actions(&self, _: &(u8, u8), actions: &mut Vec<Move>) {
        actions.extend([Move::Right, Move::Up, Move::Diagonal]);
    }

    fn step(&self, &(x, y): &(u8, u8), m: &Move) -> Option<(u8, u8)> {
        let next = match m {
            Move::Right => (x + 1, y),
            Move::Up => (x, y + 1),
            Move::Diagonal => (x + 1, y + 1),
        };
        (next.0 < self.size && next.1 < self.size).then_some(next)
    }
}

/// Two runs give identical outcomes and traces, for exhaustive checks and
/// for simulations with the same seed. The grid trace is the one breadth
/// first search with the given action order must produce.
#[test]
fn selftest_runs_are_deterministic() {
    let grid = Grid { size: 30 };
    let props = [
        Property::<Grid>::always("not-far-corner", |&(x, y)| (x, y) != (29, 17)),
        Property::<Grid>::reachable("corner", |&s| s == (29, 29)),
    ];
    let first = check(&grid, &props, &full());
    let second = check(&grid, &props, &full());
    assert_eq!(first, second);
    assert_eq!(first.to_string(), second.to_string());
    let trace = violation_trace(&first, "not-far-corner");
    // 29 moves right and 17 up need at least 29 moves; 17 diagonals and 12
    // rights achieve it.
    assert_eq!(trace.len(), 29);
    trace.replay(&grid).unwrap();

    for model_run in 0..2 {
        let a = check(
            &NaiveMutex,
            &[Property::always("mx", |s: &Naive| s.pc != [2, 2])],
            &full(),
        );
        let b = check(
            &NaiveMutex,
            &[Property::always("mx", |s: &Naive| s.pc != [2, 2])],
            &full(),
        );
        assert_eq!(a, b, "run {model_run}");
    }

    let sim_cfg = SimConfig::default()
        .with_seed(7)
        .with_walks(50)
        .with_max_steps(60);
    let s1 = simulate(&grid, &props, &sim_cfg);
    let s2 = simulate(&grid, &props, &sim_cfg);
    assert_eq!(s1, s2);
    assert_eq!(s1.to_string(), s2.to_string());
}

// ---------------------------------------------------------------------------
// Further self-tests

/// N interchangeable switches; symmetry reduction sorts the vector.
struct Switches {
    n: usize,
    reduce: bool,
}

impl Model for Switches {
    type State = Vec<bool>;
    type Action = usize;

    fn init(&self) -> Vec<Vec<bool>> {
        vec![vec![false; self.n]]
    }

    fn actions(&self, _: &Vec<bool>, actions: &mut Vec<usize>) {
        actions.extend(0..self.n);
    }

    fn step(&self, s: &Vec<bool>, &i: &usize) -> Option<Vec<bool>> {
        let mut t = s.clone();
        t[i] = !t[i];
        Some(t)
    }

    fn canonicalize(&self, s: &Vec<bool>) -> Vec<bool> {
        let mut t = s.clone();
        if self.reduce {
            t.sort_unstable();
        }
        t
    }
}

/// Symmetry reduction explores one state per class (n + 1 instead of 2^n)
/// and gives the same verdicts and shortest trace lengths. Its traces
/// replay up to symmetry.
#[test]
fn selftest_symmetry_reduction_preserves_verdicts() {
    for n in [1usize, 3, 6, 10] {
        let props = [
            Property::<Switches>::always("not-all-on", |s| !s.iter().all(|&b| b)),
            Property::<Switches>::reachable("half-on", move |s| {
                s.iter().filter(|&&b| b).count() == n / 2
            }),
            Property::<Switches>::deadlock_free("no-deadlock"),
        ];
        let plain = Switches { n, reduce: false };
        let reduced = Switches { n, reduce: true };
        let a = check(&plain, &props, &full());
        let b = check(&reduced, &props, &full());
        assert_eq!(a.stats.states, 1 << n);
        assert_eq!(b.stats.states, n + 1);
        for (ra, rb) in a.results.iter().zip(&b.results) {
            assert_eq!(ra.verdict.label(), rb.verdict.label());
            assert_eq!(
                ra.verdict.trace().map(Trace::len),
                rb.verdict.trace().map(Trace::len)
            );
        }
        let t = violation_trace(&b, "not-all-on");
        assert_eq!(t.len(), n);
        t.replay(&reduced).unwrap();
    }
}

/// A random simulation finds the Die Hard violation, its trace replays and is
/// no shorter than the shortest, and the outcome is clearly labelled as not
/// exhaustive. A property that holds stays unknown, never verified.
#[test]
fn selftest_simulation_is_labelled_non_exhaustive() {
    let props = [
        Property::<Jugs>::always("never-four", |&(_, big)| big != 4),
        Property::<Jugs>::deadlock_free("no-deadlock"),
        Property::<Jugs>::reachable("nine-gallons-total", |&(s, b)| s + b == 9),
    ];
    let cfg = SimConfig::default()
        .with_seed(1)
        .with_walks(200)
        .with_max_steps(50);
    let outcome = simulate(&Jugs, &props, &cfg);
    assert!(!outcome.exhaustive);
    assert!(matches!(outcome.mode, Mode::Simulation { seed: 1, .. }));
    let trace = violation_trace(&outcome, "never-four");
    assert!(trace.len() >= 6);
    trace.replay(&Jugs).unwrap();
    let states: Vec<_> = trace.states().collect();
    let mut dedup = states.clone();
    dedup.sort();
    dedup.dedup();
    assert_eq!(dedup.len(), states.len(), "trace has a cycle");
    assert!(verdict(&outcome, "no-deadlock").is_unknown());
    assert!(verdict(&outcome, "nine-gallons-total").is_unknown());
    let text = outcome.to_string();
    assert!(text.contains("NOT exhaustive"), "{text}");
    assert!(text.contains("nothing is verified"), "{text}");
}

/// A simulation checks transitions and deadlocks too.
#[test]
fn selftest_simulation_finds_transition_and_deadlock_violations() {
    let props = [Property::<DoorModel>::transition(
        "open-only-from-closed",
        |b, _, a| *a != Door::Open || *b == Door::Closed,
    )];
    let outcome = simulate(&DoorModel { kick: true }, &props, &SimConfig::default());
    let trace = violation_trace(&outcome, "open-only-from-closed");
    trace.replay(&DoorModel { kick: true }).unwrap();
    assert_eq!(*trace.last_state(), Door::Open);
    assert!(outcome.stopped_early);

    let model = TwoLocks {
        ordered: false,
        terminal_done: true,
    };
    let props = [Property::<TwoLocks>::deadlock_free("deadlock-free")];
    let outcome = simulate(&model, &props, &SimConfig::default());
    let trace = violation_trace(&outcome, "deadlock-free");
    trace.replay(&model).unwrap();
    assert_eq!(trace.last_state().pc, [1, 1]);
}

/// A reachable property no state satisfies is unreachable after an
/// exhaustive run. This flags a vacuous model, where every safety property
/// would hold trivially.
#[test]
fn selftest_reachable_detects_vacuous_model() {
    let props = [
        Property::<Jugs>::always("never-four", |&(_, big)| big != 4),
        Property::<Jugs>::reachable("six-in-big", |&(_, big)| big == 6),
    ];
    let outcome = check(&Jugs, &props, &full());
    assert_eq!(verdict(&outcome, "six-in-big"), &Verdict::Unreachable);
    assert!(outcome.has_failures());
    assert_eq!(outcome.failures().count(), 2);
    let report = outcome.to_string();
    assert!(
        report.contains("[UNREACHABLE] six-in-big (reachable)"),
        "{report}"
    );
}

/// By default exploration stops once every property is decided. The
/// verdicts are the same, and the run reports that it is not exhaustive.
#[test]
fn selftest_stop_when_decided() {
    let props = [Property::<Counter>::reachable("reaches-5", |&v| v == 5)];
    let model = Counter { bits: 10 };
    let early = check(&model, &props, &Config::default());
    assert!(early.stopped_early);
    assert!(!early.exhaustive);
    assert!(early.stats.states < 1024);
    assert_eq!(witness_trace(&early, "reaches-5").len(), 5);
    let late = check(&model, &props, &full());
    assert!(late.exhaustive);
    assert_eq!(late.stats.states, 1024);
    assert_eq!(witness_trace(&late, "reaches-5").len(), 5);
    // Without properties nothing is ever decided, so the run completes.
    assert_eq!(check(&model, &[], &Config::default()).stats.states, 1024);
}

/// A violation in an initial state has a trace with no steps, and duplicate
/// initial states are explored once.
#[test]
fn selftest_initial_states() {
    struct Starts;
    impl Model for Starts {
        type State = u8;
        type Action = ();
        fn init(&self) -> Vec<u8> {
            vec![3, 1, 3, 2, 1]
        }
        fn actions(&self, _: &u8, _: &mut Vec<()>) {}
        fn step(&self, _: &u8, _: &()) -> Option<u8> {
            None
        }
        fn is_terminal(&self, _: &u8) -> bool {
            true
        }
    }
    let props = [
        Property::<Starts>::always("not-two", |&s| s != 2),
        Property::<Starts>::deadlock_free("no-deadlock"),
    ];
    let outcome = check(&Starts, &props, &full());
    assert_eq!(outcome.stats.states, 3);
    let trace = violation_trace(&outcome, "not-two");
    assert!(trace.is_empty());
    assert_eq!(trace.init, 2);
    assert_eq!(verdict(&outcome, "no-deadlock"), &Verdict::Verified);
    let space = explore(&Starts, &full());
    assert_eq!(space.states().copied().collect::<Vec<_>>(), [3, 1, 2]);
}

/// A model without initial states has no reachable state: safety properties
/// hold vacuously and every reachable property is unreachable.
#[test]
fn selftest_empty_model() {
    struct Empty;
    impl Model for Empty {
        type State = u8;
        type Action = u8;
        fn init(&self) -> Vec<u8> {
            Vec::new()
        }
        fn actions(&self, _: &u8, _: &mut Vec<u8>) {}
        fn step(&self, _: &u8, _: &u8) -> Option<u8> {
            None
        }
    }
    let props = [
        Property::<Empty>::always("anything", |_| false),
        Property::<Empty>::reachable("something", |_| true),
    ];
    let outcome = check(&Empty, &props, &full());
    assert!(outcome.exhaustive);
    assert_eq!(outcome.stats.states, 0);
    assert_eq!(verdict(&outcome, "anything"), &Verdict::Verified);
    assert_eq!(verdict(&outcome, "something"), &Verdict::Unreachable);
    let sim = simulate(&Empty, &props, &SimConfig::default());
    assert!(sim.results.iter().all(|r| r.verdict.is_unknown()));
}

/// The report names each property with its identifier and kind, and prints
/// the counterexample one state and one action per line.
#[test]
fn selftest_report_is_readable() {
    let props = [
        Property::<NaiveMutex>::always_with("mutual-exclusion", |s| {
            if s.pc == [2, 2] {
                Err("both processes are critical".to_owned())
            } else {
                Ok(())
            }
        }),
        Property::<NaiveMutex>::deadlock_free("no-deadlock"),
    ];
    let outcome = check(&NaiveMutex, &props, &full());
    let report = outcome.to_string();
    let expected_head = "[VIOLATED] mutual-exclusion (always): counterexample of 4 steps\n\
         detail: both processes are critical\n\
         initial state: Naive { pc: [0, 0], flag: [false, false] }\n\
         step 1: 0\n  state: Naive { pc: [1, 0], flag: [false, false] }\n\
         step 2: 1\n  state: Naive { pc: [1, 1], flag: [false, false] }\n\
         step 3: 0\n  state: Naive { pc: [2, 1], flag: [true, false] }\n\
         step 4: 1\n  state: Naive { pc: [2, 2], flag: [true, true] }\n";
    assert!(report.contains(expected_head), "{report}");
    assert!(
        report.starts_with("fstp-mc breadth-first check: "),
        "{report}"
    );
    assert!(report.contains("exhaustive: yes"), "{report}");
    assert!(
        report.contains("[VERIFIED] no-deadlock (deadlock freedom)"),
        "{report}"
    );
    // The alternate form pretty-prints states.
    let pretty = format!("{outcome:#}");
    assert!(pretty.contains("    pc: [\n"), "{pretty}");
}

/// A state whose hash ignores its value, so every state collides.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Colliding(u16);

impl std::hash::Hash for Colliding {
    fn hash<H: std::hash::Hasher>(&self, _: &mut H) {}
}

struct CollidingCounter;

impl Model for CollidingCounter {
    type State = Colliding;
    type Action = Inc;

    fn init(&self) -> Vec<Colliding> {
        vec![Colliding(0)]
    }

    fn actions(&self, _: &Colliding, actions: &mut Vec<Inc>) {
        actions.push(Inc);
    }

    fn step(&self, s: &Colliding, _: &Inc) -> Option<Colliding> {
        Some(Colliding((s.0 + 1) % 300))
    }
}

/// The visited set stores full states, so hash collisions never merge
/// distinct states. A checker keyed on hashes or fingerprints alone would
/// see one state here instead of 300.
#[test]
fn selftest_hash_collisions_never_merge_states() {
    let props = [
        Property::<CollidingCounter>::reachable("reaches-299", |s| s.0 == 299),
        Property::<CollidingCounter>::always("below-300", |s| s.0 < 300),
    ];
    let outcome = check(&CollidingCounter, &props, &full());
    assert!(outcome.exhaustive, "{outcome}");
    assert_eq!(outcome.stats.states, 300);
    assert_eq!(outcome.stats.max_depth, 299);
    assert_eq!(witness_trace(&outcome, "reaches-299").len(), 299);
    assert_eq!(verdict(&outcome, "below-300"), &Verdict::Verified);
}
