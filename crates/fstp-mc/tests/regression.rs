//! Regression inputs found by the `random_graph` and `symmetric_graph` fuzz
//! targets (TH-26, H-05), and a run of the committed seeds through the same
//! differential checks.

// The seed helper sits outside #[test] functions, where the workspace test
// exemptions (clippy.toml) do not reach. Its panics and unwraps report test
// failures, which is their purpose.
#![allow(clippy::panic, clippy::unwrap_used, clippy::arithmetic_side_effects)]

use fstp_mc::graph::{GraphCase, GraphLimits, check_against_reference};

/// The limits the fuzz target uses.
fn fuzz_limits() -> GraphLimits {
    GraphLimits {
        max_nodes: 64,
        max_edges: 512,
        max_init: 4,
    }
}

/// Decodes `data` as the `random_graph` target does and runs the differential check.
fn run(data: &[u8]) -> Result<(), String> {
    let case = GraphCase::from_bytes(data, &fuzz_limits()).map_err(|e| e.to_string())?;
    check_against_reference(&case).map_err(|message| format!("{message}\ncase: {case:?}"))
}

/// Decodes `data` as the `symmetric_graph` target does and runs the differential check.
fn run_symmetric(data: &[u8]) -> Result<(), String> {
    let case = GraphCase::from_bytes_symmetric(data, &fuzz_limits()).map_err(|e| e.to_string())?;
    check_against_reference(&case).map_err(|message| format!("{message}\ncase: {case:?}"))
}

/// Runs every committed seed of `target` through `check`. Returns the count.
fn run_seeds(target: &str, check: fn(&[u8]) -> Result<(), String>) -> usize {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fuzz/seeds")
        .join(target);
    let mut count = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let data = std::fs::read(&path).unwrap();
        if let Err(e) = check(&data) {
            panic!("seed {} fails: {e}", path.display());
        }
        count += 1;
    }
    count
}

/// Initial nodes 1 and 0, a state bound of 1 and a depth bound of 0. Node 0
/// is dropped by the state bound, then reached again from node 1 one step
/// beyond the depth bound, which also sets the depth flag. The reference
/// expected the flag only for nodes at exactly one past the bound. The
/// reference was wrong; the checker and its documentation now state the
/// flag's meaning precisely.
#[test]
fn th26_regression_depth_flag_after_state_bound() {
    run(&[
        0x30, 0x04, 0x01, 0x00, 0x03, 0x18, 0x00, 0x00, 0x01, 0x01, 0x00, 0x80, 0x00, 0x00, 0x00,
        0x18, 0x00, 0x03, 0x80, 0x80, 0x01, 0x00, 0x01,
    ])
    .unwrap();
}

/// Every committed seed of the `random_graph` target passes the differential check.
#[test]
fn fuzz_seeds_pass_differential_check() {
    let count = run_seeds("random_graph", run);
    assert!(count >= 5, "only {count} random_graph seeds");
}

/// Every committed seed of the `symmetric_graph` target passes the
/// differential check with classes and terminal nodes. The `random_graph`
/// seeds decode as symmetric cases too and pass as well.
#[test]
fn fuzz_seeds_pass_symmetric_check() {
    let count = run_seeds("symmetric_graph", run_symmetric);
    assert!(count >= 5, "only {count} symmetric_graph seeds");
    run_seeds("random_graph", run_symmetric);
}
