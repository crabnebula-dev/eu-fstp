//! R-JV-01, I-96, O-55: every one of the 16 proposal states has a journey node with a plain-first label key.
//!
//! R-JV-01's acceptance criterion is the route response for each state.
//! The route response is built from the definition's nodes, so this
//! checks the source first. Every state of `StateTag::ALL` has exactly one
//! node in the shipped definition, with the label key
//! `journey.node.<state>` and the help key `journey.help.<state>`. Each
//! label key is a row of Catalogue 1 of `docs/design/07-vocabulary-pack.md`
//! whose formal state is that state and whose plain label, the platform
//! default pack under O-55 as amended, is not empty.
//!
//! The shipped-file test stays red until the journey lane ships
//! `crates/fstp-journey/definitions/proposal.v1.json`. The catalogue test
//! runs today. The production half, in `crates/fstp-journey/tests/`, runs
//! the same check on the production parser's nodes.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use fstp_domain::rules::StateTag;
use fstp_domain_testkit::reference::journey::{
    self, DEFINITION_PATH, node_catalogue, node_help_key, node_label_key,
};

fn repo_file(rel: &str) -> Vec<u8> {
    let path = format!("{}/../../{rel}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("R-JV-01: {rel} cannot be read: {e}"))
}

fn catalogue() -> std::collections::BTreeMap<String, journey::CatalogueRow> {
    let text = String::from_utf8(repo_file("docs/design/07-vocabulary-pack.md")).unwrap();
    node_catalogue(&text).unwrap()
}

/// R-JV-01, I-96, O-55: each of the 16 states has one node whose label and
/// help keys follow section 5.3, and whose label key the plain pack defines
/// for that formal state.
#[test]
fn r_jv_01_every_state_has_a_node_and_label() {
    let def = fstp_json::parse(&repo_file(DEFINITION_PATH))
        .unwrap_or_else(|e| panic!("R-JV-01: {DEFINITION_PATH} is not I-JSON: {e}"));
    let nodes = journey::node_keys(&def).unwrap();
    let catalogue = catalogue();
    assert_eq!(StateTag::ALL.len(), 16);
    for state in StateTag::ALL {
        let name = state.spec_name();
        let (label_key, help_key) = nodes
            .get(name)
            .unwrap_or_else(|| panic!("R-JV-01: state {name} has no node"));
        assert_eq!(
            *label_key,
            node_label_key(state),
            "R-JV-01: label key of {name}"
        );
        assert_eq!(
            *help_key,
            node_help_key(state),
            "R-JV-01: help key of {name}"
        );
        let row = catalogue
            .get(label_key)
            .unwrap_or_else(|| panic!("R-JV-01: the plain pack has no label for {label_key}"));
        assert_eq!(
            row.formal, name,
            "I-96: {label_key} names another formal state"
        );
        assert!(
            !row.plain.is_empty(),
            "O-55: {label_key} has no plain label"
        );
    }
    let states: BTreeSet<&str> = StateTag::ALL.iter().map(|s| s.spec_name()).collect();
    let extra: Vec<&String> = nodes
        .keys()
        .filter(|k| !states.contains(k.as_str()))
        .collect();
    assert!(
        extra.is_empty(),
        "R-JV-01: nodes without a state: {extra:?}"
    );
}

/// R-JV-01, O-55: the plain pack's node catalogue has one row per state,
/// keyed `journey.node.<state>`, with a plain label and a Voyage label.
#[test]
fn r_jv_01_the_plain_catalogue_names_every_state() {
    let catalogue = catalogue();
    assert_eq!(catalogue.len(), 16, "R-JV-01: {:?}", catalogue.keys());
    for state in StateTag::ALL {
        let key = node_label_key(state);
        let row = catalogue
            .get(&key)
            .unwrap_or_else(|| panic!("R-JV-01: the catalogue has no row {key}"));
        assert_eq!(row.formal, state.spec_name(), "I-96: formal state of {key}");
        assert!(!row.plain.is_empty(), "O-55: {key} has no plain label");
        assert!(!row.voyage.is_empty(), "O-55: {key} has no Voyage label");
    }
}
