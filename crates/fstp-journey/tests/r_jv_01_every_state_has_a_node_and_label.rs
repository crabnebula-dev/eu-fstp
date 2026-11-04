//! R-JV-01, I-96, O-55: every one of the 16 proposal states has a node with a plain-first label key in the parsed definition.
//!
//! The production parser's nodes cover `StateTag::ALL` exactly. Each node's
//! label key is `journey.node.<state>` and its help key
//! `journey.help.<state>`. Each label key is a row of Catalogue 1 of
//! `docs/design/07-vocabulary-pack.md` for the same formal state, with a
//! plain label, the platform default pack under O-55 as amended. The route
//! response check of R-JV-01's acceptance criterion follows with the
//! projector and API.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::collections::BTreeMap;

use fstp_domain::rules::StateTag;
use fstp_domain_testkit::reference::journey::{node_catalogue, node_help_key, node_label_key};

/// R-JV-01, I-96, O-55: one node per state, with section 5.3 keys that the
/// plain pack defines for that formal state.
#[test]
fn r_jv_01_every_state_has_a_node_and_label() {
    let def = support::shipped();
    let path = format!(
        "{}/../../docs/design/07-vocabulary-pack.md",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let catalogue = node_catalogue(&text).unwrap();
    let mut nodes = BTreeMap::new();
    for n in def.nodes() {
        assert!(
            nodes.insert(n.id.as_str(), n).is_none(),
            "R-JV-01: node {} twice",
            n.id
        );
    }
    assert_eq!(
        nodes.len(),
        StateTag::ALL.len(),
        "R-JV-01: one node per state"
    );
    for state in StateTag::ALL {
        let name = state.spec_name();
        let node = nodes
            .get(name)
            .unwrap_or_else(|| panic!("R-JV-01: state {name} has no node"));
        assert_eq!(node.label_key, node_label_key(state), "R-JV-01: {name}");
        assert_eq!(node.help_key, node_help_key(state), "R-JV-01: {name}");
        let row = catalogue
            .get(&node.label_key)
            .unwrap_or_else(|| panic!("R-JV-01: no plain label for {}", node.label_key));
        assert_eq!(
            row.formal, name,
            "I-96: {} names another state",
            node.label_key
        );
        assert!(
            !row.plain.is_empty(),
            "O-55: {} has no plain label",
            node.label_key
        );
    }
}
