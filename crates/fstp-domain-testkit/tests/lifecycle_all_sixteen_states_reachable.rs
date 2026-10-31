//! Conformance: every one of the sixteen proposal states is reachable on M-CONFORMANCE (design 6.3 and 6.4).
//!
//! One proposal of a minor lead with a verified guardian consent runs from
//! DRAFT, built from genesis by production commands, through every row of
//! `SPEC/02-domain/state-machine.md`: intake and knock-out, stage 1,
//! stage 2 with "no questions", questions, expiry and re-entry into call
//! 2, the cut-off, IRC review with validation, concern, decline and the
//! System's deferral after a concern once call 2 is published,
//! negotiation with the amount, the grant facts, consent withdrawal and
//! the decline, execution, milestone closure, completion, termination and
//! withdrawal. Every command is compared with the references in both
//! directions. Each state of the spec's States table must be reached.
//! Terminal states are never left, no decision row is recorded by the
//! System (R-LA-03), and every reachable state has an enabled action.
//! The run is exhaustive, with a tripwire at twice the measured count.
//! `lifecycle_terminal_set_matches_spec` checks the terminal set itself.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    reason = "R-NF-02 print ban: test-only code that never ships, so it may print"
)]

use std::collections::BTreeSet;

use fstp_domain::rules::StateTag;
use fstp_domain_testkit::harness::mc::check_exhaustive;
use fstp_domain_testkit::mc::conformance::{
    ConformanceModel, M_CONFORMANCE_STATES, conformance_properties, r_la_03_properties,
};

fn spec_states() -> BTreeSet<String> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../SPEC/02-domain/state-machine.md"
    );
    let doc = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("reading {path}: {e}"));
    doc.lines()
        .skip_while(|l| l.trim() != "## States")
        .skip(1)
        .take_while(|l| !l.starts_with("## "))
        .filter(|l| l.starts_with('|') && !l.contains("---"))
        .skip(1)
        .filter_map(|l| {
            l.trim_matches('|')
                .split('|')
                .next()
                .map(|c| c.trim().to_owned())
        })
        .collect()
}

/// Conformance, R-AU-01, NOTE 10: the model's witnesses cover exactly the
/// sixteen states of the spec's States table.
#[test]
fn lifecycle_all_sixteen_states_are_the_spec_states() {
    let spec = spec_states();
    let ours: BTreeSet<String> = StateTag::ALL
        .iter()
        .map(|s| s.spec_name().to_owned())
        .collect();
    assert_eq!(spec.len(), 16, "the States table lists sixteen states");
    assert_eq!(ours, spec, "StateTag::ALL against the spec's States table");
}

/// Conformance, R-AU-01, NOTE 10: every one of the sixteen states is
/// reachable from genesis, with production and the references agreeing
/// on every command, no terminal state left and no deadlock.
#[test]
fn lifecycle_all_sixteen_states_reachable() {
    let model = ConformanceModel::new(true)
        .unwrap_or_else(|e| panic!("M-CONFORMANCE start from genesis: {e}"));
    match check_exhaustive(
        &model,
        &conformance_properties::<ConformanceModel>(),
        M_CONFORMANCE_STATES,
    ) {
        Ok(o) => eprintln!("M-CONFORMANCE: {} states", o.stats.states),
        Err(e) => panic!("{e}"),
    }
}

/// R-LA-03, NOTE 13: over the whole lifecycle, including the rows after
/// NEGOTIATION, no decision row is recorded with the System as actor.
/// Only the rows driven by a timer or a date are the System's.
#[test]
fn r_la_03_no_decision_row_recorded_by_the_system_over_the_whole_lifecycle() {
    let model = ConformanceModel::new(true)
        .unwrap_or_else(|e| panic!("M-CONFORMANCE start from genesis: {e}"));
    if let Err(e) = check_exhaustive(
        &model,
        &r_la_03_properties::<ConformanceModel>(),
        M_CONFORMANCE_STATES,
    ) {
        panic!("{e}");
    }
}
