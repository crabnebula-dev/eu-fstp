//! I-95, R-JV-02: the shipped proposal journey definition equals the domain core's transition table.
//!
//! This is the production half of the drift test (`SPEC/12-journey-ui.md`
//! section 13, ADR-015). The shipped definition goes through the
//! production parser and the production drift check, against
//! `StateTag::ALL` and `TRANSITIONS`. The parser's view must also equal an
//! independent reading of the same bytes by the testkit reference, so a
//! parser that drops or changes an entry cannot hide drift. The reference
//! half runs in `crates/fstp-domain-testkit/tests/`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use fstp_domain::rules::{StateTag, TRANSITIONS};
use fstp_domain_testkit::reference::journey::{self, DEFINITION_PATH, Graph};
use fstp_journey::drift::{check, drift};

/// I-95, R-JV-02: the production drift check finds no node, edge or
/// WITHDRAWN rule that differs, in either direction.
#[test]
fn i95_journey_graph_equals_the_state_machine() {
    let def = support::shipped();
    let found = drift(&def, &StateTag::ALL, TRANSITIONS);
    let report: Vec<String> = found.iter().map(ToString::to_string).collect();
    assert!(
        found.is_empty(),
        "I-95: the journey graph drifted from the state machine:\n{}",
        report.join("\n")
    );
    assert!(check(&def).is_ok(), "I-95: check disagrees with drift");
}

/// I-95: the production parser reads the same graph as the reference, and
/// that graph has no drift under the reference comparison either.
#[test]
fn i95_parser_reads_the_same_graph_as_the_reference() {
    let production = support::production_graph(&support::shipped());
    let reference = Graph::from_definition(&support::shipped_value()).unwrap();
    assert_eq!(production, reference, "I-95: parser and reference disagree");
    let found = journey::diff(
        &Graph::from_domain(&StateTag::ALL, TRANSITIONS),
        &production,
    );
    assert!(found.is_empty(), "I-95: {found:?}");
}

/// I-95: the bytes the platform loads are the definition file in the
/// repository, so the drift test checks what ships.
#[test]
fn i95_shipped_bytes_are_the_definition_file() {
    let path = format!("{}/../../{DEFINITION_PATH}", env!("CARGO_MANIFEST_DIR"));
    let file = std::fs::read(&path).unwrap_or_else(|e| panic!("I-95: {path}: {e}"));
    assert!(
        file == fstp_journey::PROPOSAL_V1,
        "I-95: PROPOSAL_V1 is not {DEFINITION_PATH}"
    );
}

/// I-95, section 5.3: the parsed definition is format version 1 of the
/// proposal graph.
#[test]
fn i95_definition_is_version_one_of_the_proposal_graph() {
    let def = support::shipped();
    assert_eq!(def.version(), 1, "I-95: journey_def_version");
    assert_eq!(def.graph(), "proposal", "I-95: graph");
}
