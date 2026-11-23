//! ADR-036 section 8 (Daniel, 2026-11-23, "everything v2"): programmes pin
//! horizon-europe profile v2, and a programme on v1 moves to v2 (P-53,
//! R-RP-01, L-08).
//!
//! - The successor table names v1 as replaced by v2, and a successor keeps
//!   the outputs, fields and reporting periods of the version it replaces,
//!   so the move changes no report content.
//! - A pin follows the table to its current version.
//! - The funding card reads the programme's pin moved to its current
//!   version, so a v1 and a v2 pin both show the approved sentence.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_report::profile::{SUCCESSORS, approved_acknowledgement_at, current_version, shipped};

/// ADR-036 section 8: every successor keeps the outputs, fields, reporting
/// periods and visibility element keys of the version it replaces.
#[test]
fn adr036_q2_successor_keeps_outputs_fields_and_periods() {
    assert!(
        SUCCESSORS.contains(&("horizon-europe", 1, 2)),
        "v1 is replaced by v2"
    );
    for (id, from, to) in SUCCESSORS {
        let old = shipped(id, *from).unwrap();
        let new = shipped(id, *to).unwrap();
        assert!(to > from, "{id}: a successor is newer");
        assert_eq!(old.outputs(), new.outputs(), "{id} {from} to {to}: outputs");
        assert_eq!(
            old.reporting_periods(),
            new.reporting_periods(),
            "{id} {from} to {to}: periods"
        );
        let keys = |p: &fstp_report::FunderProfile| {
            p.visibility_elements()
                .iter()
                .map(|e| e.key().to_owned())
                .collect::<Vec<_>>()
        };
        assert_eq!(keys(&old), keys(&new), "{id} {from} to {to}: elements");
    }
}

/// ADR-036 section 8, P-53: a pin follows the successor table to its
/// current version; a current or unknown pin stays as it is.
#[test]
fn adr036_q2_pin_moves_to_its_current_version() {
    assert_eq!(current_version("horizon-europe", 1), 2);
    assert_eq!(current_version("horizon-europe", 2), 2);
    assert_eq!(current_version("tenant-he", 1), 1);
    assert_eq!(current_version("horizon-europe", 9), 9);
}

/// ADR-036 sections 4 and 8, L-08: the card reads the programme's own pin
/// moved to its current version. v1 and v2 pins both show the approved
/// sentence; a tenant-owned or unknown pin shows none.
#[test]
fn adr036_q2_card_reads_the_pin_moved_to_v2() {
    let v2 = approved_acknowledgement_at("horizon-europe", 2).unwrap();
    let v1 = approved_acknowledgement_at("horizon-europe", 1).unwrap();
    assert_eq!(v1.reference(), v2.reference());
    assert!(approved_acknowledgement_at("tenant-he", 1).is_none());
    assert!(approved_acknowledgement_at("horizon-europe", 9).is_none());
    assert!(approved_acknowledgement_at("", 1).is_none());
}
