//! I-66: the check catalogue (M4 design section 3.2, `CHECKS`).
//!
//! The seeded-failure property covers every production check only when
//! the production catalogue equals the reference catalogue, name for name
//! and severity for severity. A second test reads the design table at
//! test time and checks the reference against it, so neither side drifts
//! from the design.
//!
//! The production test is red until lane W2a lands `fstp_creator::CHECKS`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use fstp_api_testkit::mc::activate_model::production;
use fstp_api_testkit::reference::creator::{RefCheck, RefSeverity};

fn reference() -> BTreeSet<(String, RefSeverity)> {
    RefCheck::ALL
        .into_iter()
        .map(|c| (c.name().to_owned(), c.severity()))
        .collect()
}

/// The rows of the check table in `docs/handoff/m4-design.md` section
/// 3.2: each name with its severity.
fn design_table() -> BTreeSet<(String, RefSeverity)> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/handoff/m4-design.md"
    );
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let start = text
        .find("| Check | Source | Severity | M4 implementation |")
        .unwrap_or_else(|| panic!("{path}: the check table header is missing"));
    let mut rows = BTreeSet::new();
    for line in text.get(start..).unwrap_or_default().lines().skip(2) {
        if !line.starts_with('|') {
            break;
        }
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        let (Some(names), Some(severity)) = (cells.get(1), cells.get(3)) else {
            panic!("{path}: a short row {line:?}");
        };
        let severity = if severity.starts_with("Failure") {
            RefSeverity::Failure
        } else if severity.starts_with("Warning") {
            RefSeverity::Warning
        } else {
            panic!("{path}: unknown severity {severity:?} in {line:?}");
        };
        for name in names.split(',') {
            let name = name.trim().trim_matches('`');
            rows.insert((name.to_owned(), severity));
        }
    }
    rows
}

/// I-66: the production catalogue equals the reference, so the seeded
/// property reaches every production check of severity Failure.
#[test]
fn i66_check_catalogue_matches_the_reference() {
    let got: BTreeSet<(String, RefSeverity)> = production::catalogue()
        .unwrap_or_else(|e| panic!("production: {e}"))
        .into_iter()
        .collect();
    assert_eq!(got, reference());
}

/// I-66: the reference catalogue equals the design table of section 3.2.
#[test]
fn i66_check_catalogue_reference_matches_the_design_table() {
    assert_eq!(reference(), design_table());
}
