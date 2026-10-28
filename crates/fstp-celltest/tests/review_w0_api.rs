//! Reviewer reproducers for lane W0 of M3, design fidelity lens.
//!
//! W0 builds every new crate as a skeleton "whose public API matches the
//! design", so the W1 verification lanes can write their tests against
//! stubs first (`docs/handoff/m3-design.md` section 19). These tests read
//! the stub sources and look for the designed items that W1 tests name.
//! A missing item would otherwise surface only as a compile error in a
//! later lane.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};

fn crate_src(krate: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(krate)
        .join("src")
}

fn collect(dir: &Path, out: &mut String) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    let mut paths: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
    paths.sort();
    for p in paths {
        if p.is_dir() {
            collect(&p, out);
        } else if p.extension().is_some_and(|e| e == "rs") {
            out.push_str(&fs::read_to_string(&p).unwrap());
            out.push('\n');
        }
    }
}

/// Every `.rs` file under a crate's `src/`, concatenated.
fn sources(krate: &str) -> String {
    let mut out = String::new();
    collect(&crate_src(krate), &mut out);
    assert!(!out.is_empty(), "no sources for {krate}");
    out
}

/// I-78, design section 5.4 step 3: the gate classifies an action through
/// `HighRiskAction::of(&action)`. M-STEPUP and the I-78 route sweep need it.
#[test]
fn review_i78_high_risk_action_of_exists() {
    let src = fs::read_to_string(crate_src("fstp-cell-core").join("gate.rs")).unwrap();
    assert!(
        src.contains("fn of("),
        "fstp_cell_core::gate::HighRiskAction::of is missing (design section 5.4)"
    );
}

/// I-82, design sections 0.4, 4.1, 9.2 and 14.2 (M-PLACE): the grant rows
/// come only from `fstp_control::pg::cell_role_plan`.
#[test]
fn review_i82_cell_role_plan_exists() {
    let src = sources("fstp-control");
    assert!(
        src.contains("pub mod pg") && src.contains("fn cell_role_plan"),
        "fstp_control::pg::cell_role_plan is missing (design sections 4.1 and 9.2)"
    );
}

/// I-82, design section 9.3: the isolation auditor reads the privilege
/// graph through `fstp_control::isolation_audit::privilege_graph`.
#[test]
fn review_i82_isolation_auditor_exists() {
    let src = sources("fstp-control");
    assert!(
        src.contains("pub mod isolation_audit") && src.contains("fn privilege_graph"),
        "fstp_control::isolation_audit::privilege_graph is missing (design section 9.3)"
    );
}

/// I-16, I-38, B4, design sections 1.2 and 14.4, ADR-009 "Outbound
/// destinations": the cell's closed egress enum `Destination`, which
/// `i16_cell_egress_has_no_payment_destination` enumerates.
#[test]
fn review_i16_cell_destination_enum_exists() {
    let src = sources("fstp-cell");
    assert!(
        src.contains("pub enum Destination"),
        "fstp-cell has no closed `Destination` enum (ADR-009, design section 1.2 B4)"
    );
}

/// B4a, design sections 1.2 and 6.1, ADR-009: the vault's closed egress
/// enum `VaultDestination`.
#[test]
fn review_b4a_vault_destination_enum_exists() {
    let src = sources("fstp-vault");
    assert!(
        src.contains("pub enum VaultDestination"),
        "fstp-vault has no closed `VaultDestination` enum (ADR-009, design section 1.2 B4a)"
    );
}

/// I-16, design section 14.4: `i16_config_types_hold_no_debtor_account`
/// inspects `CellConfig` and `ControlConfig`.
#[test]
fn review_i16_config_types_exist() {
    let cell = sources("fstp-cell");
    let control = sources("fstp-control");
    assert!(
        cell.contains("pub struct CellConfig") && control.contains("pub struct ControlConfig"),
        "CellConfig or ControlConfig is missing (design section 14.4, I-16)"
    );
}

/// I-82, design section 4.1: the cell database roles are `migrator`,
/// `writer`, `app`, `keys`, `auditor` and `vault` (the `apply_grant` suffix
/// grammar). The closed `fstp_cp_proto::RoleName` carries the role of a
/// `RoleCredential`, so it must name those roles and no other.
#[test]
fn review_i82_role_name_matches_the_designed_roles() {
    let src = fs::read_to_string(crate_src("fstp-cp-proto").join("types.rs")).unwrap();
    let start = src.find("pub enum RoleName {").unwrap();
    let body = &src[start..];
    let end = body.find("\n}").unwrap();
    let variants: Vec<&str> = body[..end]
        .lines()
        .skip(1)
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("//"))
        .map(|l| l.trim_end_matches(','))
        .collect();
    let mut actual = variants.clone();
    actual.sort_unstable();
    let mut expected = vec!["App", "Auditor", "Keys", "Migrator", "Vault", "Writer"];
    expected.sort_unstable();
    assert_eq!(
        actual, expected,
        "RoleName does not match the role suffixes of design section 4.1"
    );
}
