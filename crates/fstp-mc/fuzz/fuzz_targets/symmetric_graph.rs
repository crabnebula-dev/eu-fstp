//! Fuzz target for symmetry reduction and terminal states in the model
//! checker, against reference graph searches (M1 exit criterion "each
//! component fuzzed").
//!
//! The input bytes decode into a directed graph with guarded edges, node
//! classes and terminal nodes (`GraphCase::from_bytes_symmetric`, which
//! accepts every byte string). The classes drive `Model::canonicalize`, and
//! the terminal nodes drive `Model::is_terminal`. `check_against_reference`
//! then compares the checker with independent searches over the same
//! canonical forms. Stored states, depths, verdicts and trace lengths must
//! match, terminal nodes must never count as deadlocks, every trace must
//! replay, and simulations must agree with the concrete graph.

#![no_main]

use fstp_mc::graph::{GraphCase, GraphLimits, check_against_reference};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = GraphLimits {
        max_nodes: 64,
        max_edges: 512,
        max_init: 4,
    };
    let case = match GraphCase::from_bytes_symmetric(data, &limits) {
        Ok(case) => case,
        Err(e) => panic!("valid limits rejected: {e}"),
    };
    if let Err(message) = check_against_reference(&case) {
        panic!("checker disagrees with the reference: {message}\ncase: {case:?}");
    }
});
