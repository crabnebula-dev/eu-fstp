//! ADR-029 "Conformance": every line of the vendored
//! `NormalizationTest.txt` for NFC and NFD (UAX #15, section "Conformance
//! Testing").

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing)]

mod common;

use std::collections::BTreeSet;

use common::text;
use fstp_unorm::{nfc, nfd};

/// ADR-029: for every line, `c2 == NFC(c1) == NFC(c2) == NFC(c3)`,
/// `c4 == NFC(c4) == NFC(c5)`, `c3 == NFD(c1) == NFD(c2) == NFD(c3)` and
/// `c5 == NFD(c4) == NFD(c5)`.
#[test]
fn adr029_normalization_test_nfc_and_nfd() {
    let cases = unorm_gen::normalization_test(&common::ucd_dir()).unwrap();
    assert!(cases.len() > 19_000, "only {} cases", cases.len());
    let mut failures = Vec::new();
    for (i, case) in cases.iter().enumerate() {
        let [c1, c2, c3, c4, c5] = case.columns.each_ref().map(|c| text(c));
        let checks = [
            (nfc(&c1) == c2, "NFC(c1)"),
            (nfc(&c2) == c2, "NFC(c2)"),
            (nfc(&c3) == c2, "NFC(c3)"),
            (nfc(&c4) == c4, "NFC(c4)"),
            (nfc(&c5) == c4, "NFC(c5)"),
            (nfd(&c1) == c3, "NFD(c1)"),
            (nfd(&c2) == c3, "NFD(c2)"),
            (nfd(&c3) == c3, "NFD(c3)"),
            (nfd(&c4) == c5, "NFD(c4)"),
            (nfd(&c5) == c5, "NFD(c5)"),
        ];
        for (ok, what) in checks {
            if !ok {
                failures.push(format!(
                    "case {i} (part {}): {what} of {:?}",
                    case.part, case.columns[0]
                ));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} failures, first: {:?}",
        failures.len(),
        &failures[..failures.len().min(10)]
    );
}

/// ADR-029: every code point that Part 1 does not list is its own NFC and
/// NFD.
#[test]
fn adr029_code_points_outside_part1_are_invariant() {
    let cases = unorm_gen::normalization_test(&common::ucd_dir()).unwrap();
    let listed: BTreeSet<u32> = cases
        .iter()
        .filter(|c| c.part == 1)
        .map(|c| c.columns[0][0])
        .collect();
    assert!(listed.len() > 10_000);
    let mut bad = Vec::new();
    for c in common::every_char() {
        if listed.contains(&u32::from(c)) {
            continue;
        }
        let s = c.to_string();
        if nfc(&s) != s || nfd(&s) != s {
            bad.push(u32::from(c));
        }
    }
    assert!(
        bad.is_empty(),
        "{} code points change: {:X?}",
        bad.len(),
        &bad[..bad.len().min(10)]
    );
}
