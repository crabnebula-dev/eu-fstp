//! I-95, R-JV-02: the shipped proposal journey definition equals the domain core's transition table.
//!
//! This is the reference half of the drift test (`SPEC/12-journey-ui.md`
//! section 13). It reads the shipped file as a plain JSON value through
//! `fstp-json` and compares it with `StateTag::ALL` and `TRANSITIONS`
//! through `fstp_domain_testkit::reference::journey`, never through the
//! production parser. The production half, in `crates/fstp-journey/tests/`,
//! runs the same comparison through the production parser and drift check.
//!
//! Red until the journey lane ships `crates/fstp-journey/definitions/proposal.v1.json`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use fstp_domain::rules::{StateTag, TRANSITIONS};
use fstp_domain_testkit::reference::journey::{
    self, DEFINITION_PATH, Graph, JOURNEY_DEF_VERSION, PROPOSAL_GRAPH, SIDE_TRACKS, state_named,
};
use fstp_json::Value;

/// The shipped definition, parsed by the in-house codec.
fn shipped() -> Value {
    let path = format!("{}/../../{DEFINITION_PATH}", env!("CARGO_MANIFEST_DIR"));
    let bytes = std::fs::read(&path).unwrap_or_else(|e| {
        panic!("I-95: the journey definition {DEFINITION_PATH} cannot be read: {e}")
    });
    fstp_json::parse(&bytes)
        .unwrap_or_else(|e| panic!("I-95: {DEFINITION_PATH} is not I-JSON: {e}"))
}

/// I-95, R-JV-02: no node, edge or WITHDRAWN rule differs between the
/// shipped definition and the domain table, in either direction.
#[test]
fn i95_journey_graph_equals_the_state_machine() {
    let def = shipped();
    let drift = journey::drift(&def, &StateTag::ALL, TRANSITIONS)
        .unwrap_or_else(|e| panic!("I-95: the definition cannot be read: {e}"));
    let report: Vec<String> = drift.iter().map(ToString::to_string).collect();
    assert!(
        drift.is_empty(),
        "I-95: the journey graph drifted from the state machine:\n{}",
        report.join("\n")
    );
}

/// I-95: the graph of the shipped definition has exactly 16 nodes, 20
/// edges and one WITHDRAWN rule, the counts of the split table.
#[test]
fn i95_journey_graph_has_the_table_counts() {
    let graph = Graph::from_definition(&shipped()).unwrap();
    let domain = Graph::from_domain(&StateTag::ALL, TRANSITIONS);
    assert_eq!(graph.nodes.len(), 16, "I-95: one node per state");
    assert_eq!(
        graph.edges.len(),
        domain.edges.len(),
        "I-95: one edge per row"
    );
    assert_eq!(
        domain.edges.len(),
        20,
        "I-95: 21 rows, one of them WITHDRAWN"
    );
    assert_eq!(graph.any_rules.len(), 1, "I-95: one WITHDRAWN rule");
    assert!(graph.duplicates.is_empty(), "I-95: {:?}", graph.duplicates);
}

/// I-95, section 5.3: the definition is format version 1 of the proposal
/// graph and lists the section 9 side tracks.
#[test]
fn i95_definition_names_the_proposal_graph_and_version() {
    let def = shipped();
    assert_eq!(
        def.get("journey_def_version").and_then(Value::as_u64),
        Some(JOURNEY_DEF_VERSION),
        "I-95: journey_def_version"
    );
    assert_eq!(
        def.get("graph").and_then(Value::as_str),
        Some(PROPOSAL_GRAPH),
        "I-95: graph"
    );
    let tracks: BTreeSet<&str> = def
        .get("side_tracks")
        .and_then(Value::as_array)
        .expect("side_tracks is an array")
        .iter()
        .map(|t| t.as_str().expect("a side track is a string"))
        .collect();
    assert_eq!(
        tracks,
        SIDE_TRACKS.into_iter().collect::<BTreeSet<_>>(),
        "I-95: side tracks of section 9"
    );
}

/// I-95, section 5.3: each edge's label key is `journey.edge.<from>_<to>`
/// over its own endpoints, so copy follows the row the edge maps to.
#[test]
fn i95_edge_label_keys_follow_their_rows() {
    let keys = journey::edge_keys(&shipped()).unwrap();
    assert!(!keys.is_empty(), "I-95: the definition has edges");
    for (id, (from, to, label_key)) in keys {
        let (Some(f), Some(t)) = (state_named(&from), state_named(&to)) else {
            panic!("I-95: edge {id} names {from} to {to}, which are not both states");
        };
        assert_eq!(
            label_key,
            journey::edge_label_key(f, t),
            "I-95: label key of edge {id}"
        );
    }
}
