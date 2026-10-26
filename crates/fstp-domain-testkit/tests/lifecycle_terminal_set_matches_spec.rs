//! Conformance: the terminal states match the spec, and no terminal state has an exit (design 6.4, NOTE 10).
//!
//! - The spec check reads `SPEC/02-domain/state-machine.md` at test time.
//!   The states its States table marks "Terminal" equal `StateTag::TERMINAL`
//!   and the review reference's list, and no row of its Transitions table
//!   leaves a terminal state.
//! - The model check runs M-LIFECYCLE from DRAFT, built from genesis. Its
//!   transition property says that a terminal state is never left. Its
//!   witnesses reach INELIGIBLE, NOT_SELECTED, DECLINED and WITHDRAWN.
//!   COMPLETED and TERMINATED come with lane L-MONEY.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use fstp_domain::rules::{StateTag, TRANSITIONS};
use fstp_domain_testkit::r#gen::roster::Backend;
use fstp_domain_testkit::harness::mc::check_exhaustive;
use fstp_domain_testkit::mc::life_model::LifeModel;
use fstp_domain_testkit::mc::lifecycle_model::{
    M_LIFECYCLE_REFERENCE_STATES, M_LIFECYCLE_STATES, lifecycle_config, terminal_properties,
};

fn spec() -> String {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../SPEC/02-domain/state-machine.md"
    );
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("reading {path}: {e}"))
}

/// The table rows of the section headed `heading`, as trimmed cells.
fn rows(doc: &str, heading: &str) -> Vec<Vec<String>> {
    doc.lines()
        .skip_while(|l| l.trim() != heading)
        .skip(1)
        .take_while(|l| !l.starts_with("## "))
        .filter(|l| l.starts_with('|') && !l.contains("---"))
        .map(|l| {
            l.trim_matches('|')
                .split('|')
                .map(|c| c.trim().to_owned())
                .collect()
        })
        .skip(1)
        .collect()
}

/// NOTE 10, R-SB-03: the spec's terminal states are exactly `StateTag::TERMINAL`
/// and the reference's, and no transition row leaves one.
#[test]
fn lifecycle_terminal_set_matches_spec() {
    let doc = spec();
    let spec_terminal: BTreeSet<String> = rows(&doc, "## States")
        .into_iter()
        .filter(|r| r.get(1).is_some_and(|m| m.contains("Terminal")))
        .filter_map(|r| r.first().cloned())
        .collect();
    let production: BTreeSet<String> = StateTag::TERMINAL
        .iter()
        .map(|s| s.spec_name().to_owned())
        .collect();
    let reference: BTreeSet<String> = fstp_domain_testkit::reference::review::TERMINAL
        .iter()
        .map(|s| s.spec_name().to_owned())
        .collect();
    assert_eq!(
        spec_terminal.len(),
        6,
        "the states table marks six terminal states"
    );
    assert_eq!(
        production, spec_terminal,
        "StateTag::TERMINAL against the spec"
    );
    assert_eq!(
        reference, spec_terminal,
        "the reference list against the spec"
    );
    for r in rows(&doc, "## Transitions") {
        let from = r.first().cloned().unwrap_or_default();
        assert!(
            !spec_terminal.contains(&from),
            "NOTE 10: the spec row {r:?} leaves the terminal state {from}"
        );
    }
    for rule in TRANSITIONS {
        assert!(
            rule.from.iter().all(|s| !s.is_terminal()),
            "NOTE 10: {:?} leaves a terminal state",
            rule.row
        );
    }
}

fn model(backend: Backend, measured: usize) {
    let model = LifeModel::new(lifecycle_config(), backend)
        .unwrap_or_else(|e| panic!("M-LIFECYCLE start from genesis: {e}"));
    if let Err(e) = check_exhaustive(&model, &terminal_properties::<LifeModel>(), measured) {
        panic!("{e}");
    }
}

/// NOTE 10: on M-LIFECYCLE no terminal state is ever left, and each
/// terminal state up to NEGOTIATION is reached.
#[test]
fn lifecycle_m_lifecycle_terminal_states_have_no_exit() {
    model(Backend::Production, M_LIFECYCLE_STATES);
}

/// NOTE 10: the model passes on the references alone.
#[test]
fn lifecycle_m_lifecycle_terminal_states_have_no_exit_reference() {
    model(Backend::Reference, M_LIFECYCLE_REFERENCE_STATES);
}
