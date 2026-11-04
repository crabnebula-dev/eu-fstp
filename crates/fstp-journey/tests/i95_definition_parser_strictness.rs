//! I-95, ADR-015: the journey definition parser refuses every definition outside the section 5.3 shape.
//!
//! The parser reads the definition only through the in-house `fstp-json`
//! codec. Each test starts from the shipped definition, which must parse,
//! changes one thing, and expects a refusal of the right kind:
//!
//! - an unknown member at any level (`UnknownMember`);
//! - a format version other than the integer 1 (`UnsupportedVersion`, or
//!   `WrongType` for a value that is no integer);
//! - a missing member (`MissingMember`) or a member of the wrong type
//!   (`WrongType`);
//! - two nodes, two edges or two rules with one id, or an edge and a rule
//!   sharing one id (`DuplicateId`);
//! - an edge or a rule naming a node the definition lacks (`UnknownNode`);
//! - text that is not I-JSON, such as a repeated member name (`Json`).
//!
//! Reading taken here: every member that the section 5.3 example shows is
//! required, and nothing else is allowed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use fstp_journey::definition::DefinitionErrorKind as K;
use fstp_json::Value;

use support::{by_id, first, list, refused, refused_value, shipped_value, top};

/// I-95: the unchanged shipped definition parses, so each refusal below
/// comes from its own change.
#[test]
fn i95_parser_accepts_the_shipped_definition() {
    let def = support::shipped();
    assert!(!def.nodes().is_empty() && !def.edges().is_empty());
    assert_eq!(def.any_nonterminal_before_granted().len(), 1);
    assert!(
        support::reparse(&shipped_value()).is_ok(),
        "I-95: round trip"
    );
}

/// I-95: an unknown member is refused at the top level, in a node, in an
/// edge and in the WITHDRAWN rule.
#[test]
fn i95_parser_refuses_unknown_members() {
    let mut v = shipped_value();
    top(&mut v).insert("colour", Value::from("blue"));
    refused_value(&v, &[K::UnknownMember], "an unknown top-level member");

    for member in ["nodes", "edges", "any_nonterminal_before_granted"] {
        let mut v = shipped_value();
        first(&mut v, member).insert("colour", Value::from("blue"));
        refused_value(
            &v,
            &[K::UnknownMember],
            &format!("an unknown member in {member}"),
        );
    }
}

/// I-95: a format version other than the integer 1 is refused, and so is
/// a missing version.
#[test]
fn i95_parser_refuses_a_wrong_version() {
    let integers = ["0", "2"];
    let others = [
        "18446744073709551617",
        "-1",
        "\"1\"",
        "1.0",
        "1e0",
        "null",
        "true",
    ];
    for (lexemes, want) in [
        (&integers[..], &[K::UnsupportedVersion][..]),
        (&others[..], &[K::UnsupportedVersion, K::WrongType][..]),
    ] {
        for lexeme in lexemes {
            let mut v = shipped_value();
            let version = fstp_json::parse(lexeme.as_bytes()).unwrap();
            top(&mut v).insert("journey_def_version", version);
            refused_value(&v, want, &format!("journey_def_version {lexeme}"));
        }
    }
    let mut v = shipped_value();
    top(&mut v).remove("journey_def_version");
    refused_value(&v, &[K::MissingMember], "no journey_def_version");
}

/// I-95: two nodes, two edges or two rules with one id are refused, and so
/// is an edge whose id is the WITHDRAWN rule's.
#[test]
fn i95_parser_refuses_duplicate_ids() {
    for member in ["nodes", "edges", "any_nonterminal_before_granted"] {
        let mut v = shipped_value();
        let copy = Value::from(first(&mut v, member).clone());
        list(&mut v, member).push(copy);
        refused_value(&v, &[K::DuplicateId], &format!("a repeated id in {member}"));
    }

    let mut v = shipped_value();
    first(&mut v, "edges").insert("id", Value::from("T-ANY-WITHDRAWN"));
    refused_value(
        &v,
        &[K::DuplicateId],
        "an edge with the WITHDRAWN rule's id",
    );
}

/// I-95: an edge or rule that names a node the definition lacks is refused.
#[test]
fn i95_parser_refuses_edges_naming_unknown_nodes() {
    for member in ["from", "to"] {
        let mut v = shipped_value();
        first(&mut v, "edges").insert(member, Value::from("NOWHERE"));
        refused_value(&v, &[K::UnknownNode], &format!("an edge {member} NOWHERE"));
    }

    let mut v = shipped_value();
    first(&mut v, "any_nonterminal_before_granted").insert("to", Value::from("NOWHERE"));
    refused_value(&v, &[K::UnknownNode], "the WITHDRAWN rule to NOWHERE");

    // Removing a node that edges name leaves those edges dangling.
    let mut v = shipped_value();
    list(&mut v, "nodes").retain(|n| n.get("id").and_then(Value::as_str) != Some("RANKED"));
    refused_value(
        &v,
        &[K::UnknownNode],
        "edges naming the removed node RANKED",
    );

    // The WITHDRAWN rule names WITHDRAWN, so removing that node is refused too.
    let mut v = shipped_value();
    list(&mut v, "nodes").retain(|n| n.get("id").and_then(Value::as_str) != Some("WITHDRAWN"));
    refused_value(
        &v,
        &[K::UnknownNode],
        "the rule naming the removed node WITHDRAWN",
    );
}

/// I-95: every member of the section 5.3 shape is required.
#[test]
fn i95_parser_refuses_missing_members() {
    let top_members = [
        "journey_def_version",
        "graph",
        "nodes",
        "edges",
        "any_nonterminal_before_granted",
        "side_tracks",
    ];
    for member in top_members {
        let mut v = shipped_value();
        top(&mut v).remove(member);
        refused_value(&v, &[K::MissingMember], &format!("no {member}"));
    }
    let entries: [(&str, &[&str]); 3] = [
        (
            "nodes",
            &[
                "id",
                "kind",
                "terminal",
                "label_key",
                "help_key",
                "policy_refs",
            ],
        ),
        ("edges", &["id", "from", "to", "actor_role", "label_key"]),
        (
            "any_nonterminal_before_granted",
            &["id", "to", "actor_role"],
        ),
    ];
    for (list_name, members) in entries {
        for member in members {
            let mut v = shipped_value();
            first(&mut v, list_name).remove(member);
            refused_value(
                &v,
                &[K::MissingMember],
                &format!("{list_name} without {member}"),
            );
        }
    }
}

/// I-95: a member of the wrong JSON type is refused.
#[test]
fn i95_parser_refuses_wrong_types() {
    refused(b"[]", &[K::WrongType], "a top-level array");

    let mut v = shipped_value();
    top(&mut v).insert("nodes", Value::from(fstp_json::Object::new()));
    refused_value(&v, &[K::WrongType], "nodes as an object");

    let mut v = shipped_value();
    by_id(&mut v, "nodes", "DRAFT").insert("terminal", Value::from("false"));
    refused_value(&v, &[K::WrongType], "terminal as a string");

    let mut v = shipped_value();
    by_id(&mut v, "edges", "T-DRAFT-SUBMITTED").insert("to", Value::from(1u64));
    refused_value(&v, &[K::WrongType], "an edge target as a number");

    let mut v = shipped_value();
    top(&mut v).insert("graph", Value::Null);
    refused_value(&v, &[K::WrongType], "graph as null");
}

/// I-95: text that is not I-JSON is refused by the codec, including a
/// repeated member name, which a lenient parser would let through.
#[test]
fn i95_parser_refuses_text_that_is_not_i_json() {
    let text = shipped_value().to_compact();
    let body = text.strip_prefix('{').expect("an object");
    let repeated = format!("{{\"graph\":\"proposal\",{body}");
    refused(repeated.as_bytes(), &[K::Json], "a repeated member name");

    let trailing = format!("{},", text.strip_suffix('}').expect("an object"));
    refused(
        format!("{trailing}}}").as_bytes(),
        &[K::Json],
        "a trailing comma",
    );

    let mut bom = vec![0xEF, 0xBB, 0xBF];
    bom.extend_from_slice(text.as_bytes());
    refused(&bom, &[K::Json], "a byte order mark");

    refused(&[0x7B, 0xFF, 0x7D], &[K::Json], "invalid UTF-8");
    refused(b"", &[K::Json], "empty input");
}
