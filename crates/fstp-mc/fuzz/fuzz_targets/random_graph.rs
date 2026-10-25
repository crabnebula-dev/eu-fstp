//! Fuzz target for the model checker against reference graph searches
//! (M1 exit criterion "each component fuzzed").
//!
//! The input bytes decode into a directed graph with guarded edges, initial
//! nodes, a target node, bounds and a simulation seed
//! (`GraphCase::from_bytes`, which accepts every byte string). The target
//! then asserts more than "no panic": `check_against_reference` compares the
//! checker with an independent depth-first and breadth-first search. The
//! reachable set must match, counterexample lengths must equal shortest
//! distances, bounded runs must report their bounds and never verify, runs
//! must be deterministic, and every reported trace must replay.

#![no_main]

use fstp_mc::graph::{GraphCase, GraphLimits, check_against_reference};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = GraphLimits {
        max_nodes: 64,
        max_edges: 512,
        max_init: 4,
    };
    let case = match GraphCase::from_bytes(data, &limits) {
        Ok(case) => case,
        Err(e) => panic!("valid limits rejected: {e}"),
    };
    if let Err(message) = check_against_reference(&case) {
        panic!("checker disagrees with the reference: {message}\ncase: {case:?}");
    }
});
