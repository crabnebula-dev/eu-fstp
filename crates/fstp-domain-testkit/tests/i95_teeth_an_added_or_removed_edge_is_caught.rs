//! I-95, R-JV-02 teeth: a node, edge or WITHDRAWN rule changed on one side only is caught.
//!
//! The reference comparison of `fstp_domain_testkit::reference::journey`
//! must name the changed node, edge or rule for every one-sided change:
//!
//! - definition side: an edge or node added, removed, renamed or
//!   retargeted, an actor or terminal flag changed, and the WITHDRAWN rule
//!   removed, renamed, retargeted, given another actor, joined by a second
//!   rule, or given other source states through the graph;
//! - domain side: a row added, removed, retargeted or given another actor,
//!   the WITHDRAWN row opened in GRANTED, closed in DEFERRED, retargeted,
//!   given another actor or removed, and a state removed.
//!
//! The generated cases run on a definition built from the domain table, so
//! the reference's teeth hold before any file ships. The shipped cases run
//! on a copy of the shipped file and stay red until it exists. The
//! production drift check gets the same cases in `crates/fstp-journey/tests/`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::rules::{StateTag, TRANSITIONS};
use fstp_domain_testkit::reference::journey::{
    self, DEFINITION_PATH, Difference, definition_mutations, domain_mutations,
    generated_definition, mutate,
};
use fstp_json::Value;

fn shipped() -> Value {
    let path = format!("{}/../../{DEFINITION_PATH}", env!("CARGO_MANIFEST_DIR"));
    let bytes = std::fs::read(&path).unwrap_or_else(|e| {
        panic!("I-95: the journey definition {DEFINITION_PATH} cannot be read: {e}")
    });
    fstp_json::parse(&bytes)
        .unwrap_or_else(|e| panic!("I-95: {DEFINITION_PATH} is not I-JSON: {e}"))
}

/// Every definition-side case must be caught on `base` with its id named.
fn definition_side_is_caught(base: &Value) -> Result<(), String> {
    let clean = journey::drift(base, &StateTag::ALL, TRANSITIONS)?;
    if !clean.is_empty() {
        return Err(format!("I-95: the unchanged definition drifts: {clean:?}"));
    }
    for case in definition_mutations() {
        let changed = mutate(base, &case.mutation)?;
        // The change must survive a round trip through the codec, as a file would.
        let bytes = changed.to_compact();
        let reparsed = fstp_json::parse(bytes.as_bytes())
            .map_err(|e| format!("I-95: {}: the changed copy is not I-JSON: {e}", case.name))?;
        let found = journey::drift(&reparsed, &StateTag::ALL, TRANSITIONS)?;
        check_named(case.name, case.names, &found)?;
    }
    Ok(())
}

/// Every domain-side case must be caught against `def` with its id named.
fn domain_side_is_caught(def: &Value) -> Result<(), String> {
    let cases = domain_mutations(&StateTag::ALL, TRANSITIONS);
    if cases.len() < 10 {
        return Err(format!("I-95: only {} domain-side cases", cases.len()));
    }
    for case in cases {
        let found = journey::drift(def, &case.states, &case.table)?;
        check_named(case.name, &case.names, &found)?;
    }
    Ok(())
}

fn check_named(name: &str, id: &str, found: &[Difference]) -> Result<(), String> {
    if found.iter().any(|d| d.id() == id) {
        Ok(())
    } else {
        Err(format!(
            "I-95 teeth: {name}: drift did not name {id}, found {found:?}"
        ))
    }
}

/// I-95: the generated definition equals the domain table, so the cases
/// below start from no drift.
#[test]
fn i95_teeth_generated_definition_has_no_drift() {
    let def = generated_definition(&StateTag::ALL, TRANSITIONS);
    let found = journey::drift(&def, &StateTag::ALL, TRANSITIONS).unwrap();
    assert!(found.is_empty(), "I-95: {found:?}");
}

/// I-95, R-JV-02 teeth: every definition-side change to the generated
/// definition is caught, including each change to the WITHDRAWN rule.
#[test]
fn i95_teeth_an_added_or_removed_edge_is_caught() {
    let def = generated_definition(&StateTag::ALL, TRANSITIONS);
    definition_side_is_caught(&def).unwrap();
}

/// I-95, R-JV-02 teeth: every domain-side change is caught against the
/// generated definition, including each change to the WITHDRAWN row.
#[test]
fn i95_teeth_a_domain_side_change_is_caught() {
    let def = generated_definition(&StateTag::ALL, TRANSITIONS);
    domain_side_is_caught(&def).unwrap();
}

/// I-95, R-JV-02 teeth: every definition-side change to a copy of the
/// shipped definition is caught. Red until the file ships.
#[test]
fn i95_teeth_a_change_to_a_copy_of_the_shipped_definition_is_caught() {
    definition_side_is_caught(&shipped()).unwrap();
}

/// I-95, R-JV-02 teeth: every domain-side change is caught against the
/// shipped definition. Red until the file ships.
#[test]
fn i95_teeth_a_domain_side_change_is_caught_against_the_shipped_definition() {
    domain_side_is_caught(&shipped()).unwrap();
}
