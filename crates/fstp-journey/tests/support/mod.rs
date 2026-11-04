//! Shared helpers for the journey definition tests (I-95, R-JV-01, R-JV-02).
//!
//! The tests are written before the production code, against this API of
//! the journey crate (lane j1 report, design API):
//!
//! - `fstp_journey::PROPOSAL_V1: &[u8]`, the bytes of
//!   `definitions/proposal.v1.json`;
//! - `fstp_journey::definition::{parse, Definition, Node, Edge, AnyRule,
//!   DefinitionError, DefinitionErrorKind}`;
//! - `fstp_journey::drift::{drift, check, Drift}`.
//!
//! Helpers return values or panic with a message. Only tests use them.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain_testkit::reference::journey::{EdgeShape, Graph};
use fstp_journey::definition::{Definition, DefinitionError, DefinitionErrorKind, parse};
use fstp_json::{Array, Object, Value};

/// The shipped definition as a plain JSON value, read by the in-house codec.
pub(crate) fn shipped_value() -> Value {
    fstp_json::parse(fstp_journey::PROPOSAL_V1).expect("I-95: the shipped definition is I-JSON")
}

/// The shipped definition through the production parser.
pub(crate) fn shipped() -> Definition {
    parse(fstp_journey::PROPOSAL_V1)
        .unwrap_or_else(|e| panic!("I-95: the shipped definition is refused: {e}"))
}

/// Serialises a changed value as a file would hold it and parses it.
pub(crate) fn reparse(v: &Value) -> Result<Definition, DefinitionError> {
    parse(v.to_compact().as_bytes())
}

/// Asserts that `bytes` are refused with one of `want`.
pub(crate) fn refused(bytes: &[u8], want: &[DefinitionErrorKind], what: &str) {
    match parse(bytes) {
        Ok(_) => panic!("I-95: {what}: the parser accepted it"),
        Err(e) => assert!(
            want.contains(&e.kind()),
            "I-95: {what}: refused as {:?} ({e}), expected one of {want:?}",
            e.kind()
        ),
    }
}

/// Asserts that a changed value is refused with one of `want`.
pub(crate) fn refused_value(v: &Value, want: &[DefinitionErrorKind], what: &str) {
    refused(v.to_compact().as_bytes(), want, what);
}

/// The top-level object.
pub(crate) fn top(v: &mut Value) -> &mut Object {
    v.as_object_mut().expect("the definition is an object")
}

/// A top-level array member.
pub(crate) fn list<'a>(v: &'a mut Value, member: &str) -> &'a mut Array {
    top(v)
        .get_mut(member)
        .and_then(Value::as_array_mut)
        .unwrap_or_else(|| panic!("member {member} is an array"))
}

/// The first entry of a top-level array member, as an object.
pub(crate) fn first<'a>(v: &'a mut Value, member: &str) -> &'a mut Object {
    list(v, member)
        .first_mut()
        .and_then(Value::as_object_mut)
        .unwrap_or_else(|| panic!("member {member} has an object entry"))
}

/// The entry of a top-level array member with this id, as an object.
pub(crate) fn by_id<'a>(v: &'a mut Value, member: &str, id: &str) -> &'a mut Object {
    list(v, member)
        .iter_mut()
        .find(|e| e.get("id").and_then(Value::as_str) == Some(id))
        .and_then(Value::as_object_mut)
        .unwrap_or_else(|| panic!("member {member} has an entry {id}"))
}

/// The production parser's view of a definition, as a reference graph.
pub(crate) fn production_graph(def: &Definition) -> Graph {
    let nodes: Vec<(String, bool)> = def
        .nodes()
        .iter()
        .map(|n| (n.id.clone(), n.terminal))
        .collect();
    let edges: Vec<(String, EdgeShape)> = def
        .edges()
        .iter()
        .map(|e| {
            let shape = EdgeShape {
                from: e.from.clone(),
                to: e.to.clone(),
                actor_role: e.actor_role.clone(),
            };
            (e.id.clone(), shape)
        })
        .collect();
    let any: Vec<(String, String, String)> = def
        .any_nonterminal_before_granted()
        .iter()
        .map(|r| (r.id.clone(), r.to.clone(), r.actor_role.clone()))
        .collect();
    Graph::from_parts(&nodes, &edges, &any)
}
