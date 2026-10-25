//! Regression tests for the M1 review findings on the model checker.

// The replay helper sits outside #[test] functions, where the workspace test
// exemptions (clippy.toml) do not reach. Its panic reports a test failure,
// which is its purpose.
#![allow(clippy::panic)]

use fstp_mc::graph::{GraphError, GraphLimits, GraphModel, MAX_GRAPH_NODES};
use fstp_mc::{Step, Trace};

/// Builds a trace from an initial node and `(action, state)` steps.
fn trace(init: usize, steps: &[(usize, usize)]) -> Trace<usize, usize> {
    Trace {
        init,
        steps: steps
            .iter()
            .map(|&(action, state)| Step { action, state })
            .collect(),
    }
}

/// Returns the replay error of `t`, failing the test if it replays.
fn replay_error(t: &Trace<usize, usize>, model: &GraphModel) -> String {
    match t.replay(model) {
        Ok(()) => panic!("trace replays but must not:\n{t}"),
        Err(e) => e,
    }
}

/// `Trace::replay` is the oracle that self-tests and fuzz targets use to
/// prove a counterexample is a real execution. It rejects a disabled
/// action, an action that does not exist, a recorded state that differs from
/// the successor and a start that is not initial.
#[test]
fn review_mc_replay_oracle_untested() {
    // 0 -> 1 enabled (action 0), 0 -> 2 disabled (action 1), 1 -> 2 (action 0).
    let g = GraphModel::new(
        3,
        vec![0],
        &[(0, 1, true), (0, 2, false), (1, 2, true)],
        &GraphLimits::default(),
    )
    .unwrap();
    assert_eq!(trace(0, &[]).replay(&g), Ok(()));
    assert_eq!(trace(0, &[(0, 1), (0, 2)]).replay(&g), Ok(()));

    let e = replay_error(&trace(0, &[(1, 2)]), &g);
    assert_eq!(e, "step 1: action 1 is not enabled in 0");
    let e = replay_error(&trace(0, &[(0, 1), (5, 2)]), &g);
    assert_eq!(e, "step 2: action 5 is not enabled in 1");
    let e = replay_error(&trace(0, &[(0, 2)]), &g);
    assert_eq!(e, "step 1: action 0 leads to 1, but the trace records 2");
    let e = replay_error(&trace(0, &[(0, 1), (0, 1)]), &g);
    assert_eq!(e, "step 2: action 0 leads to 2, but the trace records 1");
    let e = replay_error(&trace(1, &[(0, 2)]), &g);
    assert_eq!(e, "initial state 1 is not an initial state of the model");
}

/// With non-identity canonicalization, a recorded state may be the
/// successor or its canonical form, and the start may be an initial state or
/// its canonical form. Any other state is rejected, and replay continues
/// from the recorded state.
#[test]
fn review_mc_replay_oracle_untested_canonical() {
    // Nodes 1 and 2 form a class with canonical form 1. Initial node 2.
    // Edges: 2 -> 3 (action 0 of node 2), 1 -> 0 (action 0 of node 1),
    // 3 -> 2 (action 0 of node 3).
    let g = GraphModel::new(
        4,
        vec![2],
        &[(2, 3, true), (1, 0, true), (3, 2, true)],
        &GraphLimits::default(),
    )
    .unwrap()
    .with_classes(&[0, 5, 5, 3]);
    assert_eq!(g.canonical(2), 1);

    // The concrete start and its canonical form are both initial.
    assert_eq!(trace(2, &[(0, 3)]).replay(&g), Ok(()));
    assert_eq!(trace(1, &[(0, 0)]).replay(&g), Ok(()));
    let e = replay_error(&trace(3, &[]), &g);
    assert_eq!(e, "initial state 3 is not an initial state of the model");

    // From 3, action 0 leads to 2. The trace may record 2 or its canonical
    // form 1, never 0. The next step starts from the recorded state.
    assert_eq!(trace(2, &[(0, 3), (0, 2), (0, 3)]).replay(&g), Ok(()));
    assert_eq!(trace(2, &[(0, 3), (0, 1), (0, 0)]).replay(&g), Ok(()));
    let e = replay_error(&trace(2, &[(0, 3), (0, 0)]), &g);
    assert_eq!(e, "step 2: action 0 leads to 2, but the trace records 0");
    // After recording 1, the edges of 1 apply, not those of 2.
    let e = replay_error(&trace(2, &[(0, 3), (0, 1), (0, 3)]), &g);
    assert_eq!(e, "step 3: action 0 leads to 0, but the trace records 3");
}

/// `GraphModel::new` with permissive limits returns an error instead of
/// panicking or aborting on a huge node count (TH-26).
#[test]
fn review_mc_graph_new_capacity_panic() {
    let limits = GraphLimits {
        max_nodes: usize::MAX,
        max_edges: 0,
        max_init: 0,
    };
    let result = std::panic::catch_unwind(|| GraphModel::new(usize::MAX / 8, vec![], &[], &limits));
    let result = result.expect("GraphModel::new must not panic");
    assert_eq!(
        result,
        Err(GraphError::TooManyNodes {
            node_count: usize::MAX / 8,
            max_nodes: MAX_GRAPH_NODES
        })
    );
    assert!(GraphModel::new(usize::MAX, vec![], &[], &limits).is_err());
}
