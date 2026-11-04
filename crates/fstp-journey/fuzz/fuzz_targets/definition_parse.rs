//! Fuzz target `definition_parse` of `fstp-journey` (I-95, ADR-015, ADR-003).
//!
//! It feeds arbitrary bytes to the journey definition parser. No input may
//! panic, and the result must be the same twice. An accepted definition
//! must keep the parser's promises: the checksum is the SHA-256 of the
//! bytes, the version is 1, ids are unique, and every edge and rule names a
//! node of the definition. The drift check then runs on it, and `check`
//! must agree with `drift`. Each reported drift names its id.

#![no_main]

use std::collections::BTreeSet;

use fstp_domain::rules::{StateTag, TRANSITIONS};
use fstp_journey::definition::{FORMAT_VERSION, parse};
use fstp_journey::drift::{check, drift};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let first = parse(data);
    assert_eq!(first, parse(data), "parse is not deterministic");
    let def = match first {
        Ok(def) => def,
        Err(e) => {
            assert!(!e.to_string().is_empty(), "empty error text");
            return;
        }
    };
    assert_eq!(def.checksum(), &fstp_crypto::sha256(data), "checksum");
    assert_eq!(def.version(), FORMAT_VERSION, "version");

    let nodes: BTreeSet<&str> = def.nodes().iter().map(|n| n.id.as_str()).collect();
    assert_eq!(nodes.len(), def.nodes().len(), "repeated node id accepted");
    let mut transitions = BTreeSet::new();
    for e in def.edges() {
        assert!(nodes.contains(e.from.as_str()), "edge from no node");
        assert!(nodes.contains(e.to.as_str()), "edge to no node");
        assert!(
            transitions.insert(e.id.as_str()),
            "repeated edge id accepted"
        );
    }
    for r in def.any_nonterminal_before_granted() {
        assert!(nodes.contains(r.to.as_str()), "rule to no node");
        assert!(
            transitions.insert(r.id.as_str()),
            "repeated rule id accepted"
        );
    }

    let found = drift(&def, &StateTag::ALL, TRANSITIONS);
    assert_eq!(
        check(&def).is_ok(),
        found.is_empty(),
        "check disagrees with drift"
    );
    for d in &found {
        assert!(d.to_string().contains(d.id()), "drift text omits its id");
    }
});
