//! I-95, R-JV-02 teeth: the production drift check catches a node, edge or WITHDRAWN rule changed on one side only.
//!
//! - Definition side: each case of
//!   `reference::journey::definition_mutations` changes a copy of the
//!   shipped definition. The copy is serialised, parsed again by the
//!   production parser, and the drift report must name the changed id. A
//!   case that introduces a node id that is no domain state may instead be
//!   refused by the parser, since either way the build fails.
//! - Domain side: each case of `reference::journey::domain_mutations`
//!   changes a copy of the state list or the transition table, and the
//!   drift report against the unchanged shipped definition must name the
//!   changed id.
//!
//! Every case is also checked against the reference comparison, so a case
//! that stops changing anything fails here rather than passing quietly.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use fstp_domain::rules::{StateTag, TRANSITIONS};
use fstp_domain_testkit::reference::journey::{
    self, definition_mutations, domain_mutations, mutate,
};
use fstp_journey::drift::{check, drift};

/// I-95, R-JV-02 teeth: an edge or node added, removed, renamed or
/// retargeted in the definition only is caught and named, and so is each
/// change to the WITHDRAWN rule.
#[test]
fn i95_teeth_an_added_or_removed_edge_is_caught() {
    let base = support::shipped_value();
    let cases = definition_mutations();
    assert!(
        cases.len() >= 15,
        "I-95: {} definition-side cases",
        cases.len()
    );
    for case in cases {
        let changed = mutate(&base, &case.mutation).unwrap();
        let by_reference = journey::drift(&changed, &StateTag::ALL, TRANSITIONS).unwrap();
        assert!(
            by_reference.iter().any(|d| d.id() == case.names),
            "I-95 teeth: {}: the case changes nothing the reference sees",
            case.name
        );
        match support::reparse(&changed) {
            Ok(def) => {
                let found = drift(&def, &StateTag::ALL, TRANSITIONS);
                let report: Vec<String> = found.iter().map(ToString::to_string).collect();
                assert!(
                    report.iter().any(|line| line.contains(case.names)),
                    "I-95 teeth: {}: drift did not name {}: {report:?}",
                    case.name,
                    case.names
                );
                assert!(
                    check(&def).is_err(),
                    "I-95 teeth: {}: check passed",
                    case.name
                );
            }
            Err(e) => assert!(
                case.unknown_state,
                "I-95 teeth: {}: the parser refused a well-formed definition: {e}",
                case.name
            ),
        }
    }
}

/// I-95, R-JV-02 teeth: a row or state added, removed or changed in the
/// domain table only is caught and named, and so is each change to the
/// WITHDRAWN row.
#[test]
fn i95_teeth_a_domain_side_change_is_caught() {
    let def = support::shipped();
    let value = support::shipped_value();
    let cases = domain_mutations(&StateTag::ALL, TRANSITIONS);
    assert!(cases.len() >= 10, "I-95: {} domain-side cases", cases.len());
    for case in cases {
        let by_reference = journey::drift(&value, &case.states, &case.table).unwrap();
        assert!(
            by_reference.iter().any(|d| d.id() == case.names),
            "I-95 teeth: {}: the case changes nothing the reference sees",
            case.name
        );
        let found = drift(&def, &case.states, &case.table);
        assert!(
            found.iter().any(|d| d.id() == case.names),
            "I-95 teeth: {}: the production drift did not name {}: {found:?}",
            case.name,
            case.names
        );
    }
}
