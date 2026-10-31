//! I-78: the high-risk table reviewed row by row against the spec and the
//! M2 domain (`docs/handoff/m3-design.md` section 8.4, ADR-008 "High-risk
//! table", lane W0).
//!
//! The spec rows are read from `SPEC/03-architecture/authentication.md` at
//! run time, so the table is checked against the text it cites. The domain
//! side is `fstp_domain::CommandKind::high_risk()` at the M2 base commit
//! (`367b7be`, recorded in `docs/handoff/m3-base.md`).
//!
//! API these tests expect in `fstp_cell_core::gate`:
//!
//! - `HighRiskAction`, a closed enum with `Debug`;
//! - `HIGH_RISK_TABLE: &[HighRiskEntry]`, where `HighRiskEntry` has the
//!   public fields `action: HighRiskAction`, `command: &'static str` (the
//!   variant name of the command or action it covers) and
//!   `spec_row: &'static str` (the Action cell of the `authentication.md`
//!   row, verbatim);
//! - `STRICT_ADDITIONS: &[StrictAddition]`, where `StrictAddition` has the
//!   public fields `command: &'static str` and `source: &'static str` (the
//!   spec row it reads strictly, verbatim).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::path::Path;

use fstp_cell_core::gate::{HIGH_RISK_TABLE, STRICT_ADDITIONS};
use fstp_domain::CommandKind;

const ROLE_ROW: &str =
    "Granting or changing a role in the Drafting, Judging or Operations groups, or tenant admin";
const EXPORT_ROW: &str =
    "Tenant export, vault export, and any download containing identity attributes";
const DEVICE_ROW: &str = "Adding a passkey, linking a device, or signing in the desktop client";
const LOGIN_ROW: &str = "Changing the account email address or login methods";
const BANK_ROW: &str = "Changing bank details";
const PAYMENT_ROW: &str = "Approving or releasing a payment";
const PUBLIC_ROW: &str = "Activating a programme or publishing a call";
const TEMPLATE_ROW: &str = "Publishing a template to other tenants";
const BREAK_GLASS_ROW: &str = "Approving break-glass access";
const RECOVERY_ROW: &str = "Approving an account recovery";

/// Design section 8.4 and ADR-008, transcribed: action variant, command,
/// source row. `GrantTenantAdmin`, `EndTenantAdmin`, `ApproveSelfGrant` and
/// `SetLoginPolicy` are cell commands (design section 5.1). The export,
/// device, email, bank, template and break-glass entries name actions of
/// later milestones or of `fstp-auth`, by their variant names.
const DESIGN_TABLE: [(&str, &str, &str); 25] = [
    ("ManagementRoleChange", "GrantRole", ROLE_ROW),
    ("ManagementRoleChange", "EndRole", ROLE_ROW),
    ("ManagementRoleChange", "ReinstateBinding", ROLE_ROW),
    ("ManagementRoleChange", "GrantTenantAdmin", ROLE_ROW),
    ("ManagementRoleChange", "EndTenantAdmin", ROLE_ROW),
    ("ManagementRoleChange", "ApproveSelfGrant", ROLE_ROW),
    ("ManagementRoleChange", "Assign", ROLE_ROW),
    ("ManagementRoleChange", "Unassign", ROLE_ROW),
    ("TenantExport", "TenantExport", EXPORT_ROW),
    ("VaultExport", "VaultExport", EXPORT_ROW),
    ("IdentityDownload", "IdentityDownload", EXPORT_ROW),
    ("AddPasskey", "AddPasskey", DEVICE_ROW),
    ("LinkDevice", "LinkDevice", DEVICE_ROW),
    ("DesktopSignIn", "DesktopSignIn", DEVICE_ROW),
    ("ChangeEmail", "ChangeEmail", LOGIN_ROW),
    ("ChangeLoginMethods", "ChangeLoginMethods", LOGIN_ROW),
    ("ChangeLoginMethods", "SetLoginPolicy", LOGIN_ROW),
    ("ChangeBankDetails", "ChangeBankDetails", BANK_ROW),
    ("ApprovePayment", "ApprovePayment", PAYMENT_ROW),
    ("ReleasePayment", "ReleasePayment", PAYMENT_ROW),
    ("ActivateProgramme", "CreateProgramme", PUBLIC_ROW),
    ("PublishCall", "PublishCall", PUBLIC_ROW),
    ("PublishTemplate", "PublishTemplate", TEMPLATE_ROW),
    ("ApproveBreakGlass", "ApproveBreakGlass", BREAK_GLASS_ROW),
    ("ApproveRecovery", "ApproveRecovery", RECOVERY_ROW),
];

/// The strict additions, interim pending Daniel (Q38), with their source
/// rows (ADR-008 "High-risk table").
const STRICT: [(&str, &str); 4] = [
    ("Assign", ROLE_ROW),
    ("Unassign", ROLE_ROW),
    ("ApproveSelfGrant", ROLE_ROW),
    ("SetLoginPolicy", LOGIN_ROW),
];

/// The kinds `CommandKind::high_risk()` marks at the M2 base commit.
const M2_BASE_HIGH_RISK: [&str; 7] = [
    "CreateProgramme",
    "GrantRole",
    "EndRole",
    "ReinstateBinding",
    "ApprovePayment",
    "ReleasePayment",
    "PublishCall",
];

/// The Action cells of the high-risk table in `authentication.md`.
fn spec_rows() -> Vec<String> {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../SPEC/03-architecture/authentication.md");
    let text = std::fs::read_to_string(&path).unwrap();
    let mut rows = Vec::new();
    let mut in_section = false;
    let mut in_table = false;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with("## ") {
            if in_section {
                break;
            }
            in_section = t == "## High-risk actions and step-up (I-78)";
            continue;
        }
        if !in_section {
            continue;
        }
        if t.starts_with('|') {
            in_table = true;
            let cell = t
                .trim_matches('|')
                .split('|')
                .next()
                .unwrap_or_default()
                .trim()
                .to_owned();
            rows.push(cell);
        } else if in_table {
            break;
        }
    }
    // Drop the header row and the separator row.
    rows.into_iter().skip(2).collect()
}

/// The domain kinds that `high_risk()` marks, by name.
fn domain_high_risk() -> BTreeSet<String> {
    CommandKind::ALL
        .iter()
        .filter(|k| k.high_risk())
        .map(|k| format!("{k:?}"))
        .collect()
}

/// Every domain kind, by name.
fn domain_kinds() -> BTreeSet<String> {
    CommandKind::ALL.iter().map(|k| format!("{k:?}")).collect()
}

/// I-78: the transcription above holds the spec table exactly, so a spec
/// change shows up here before any table check passes on stale rows.
#[test]
fn i78_spec_high_risk_table_matches_the_transcription() {
    let expected: Vec<String> = [
        ROLE_ROW,
        EXPORT_ROW,
        DEVICE_ROW,
        LOGIN_ROW,
        BANK_ROW,
        PAYMENT_ROW,
        PUBLIC_ROW,
        TEMPLATE_ROW,
        BREAK_GLASS_ROW,
        RECOVERY_ROW,
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    assert_eq!(spec_rows(), expected);
}

/// I-78, section 0.5: the domain's high-risk kinds at the M2 base commit
/// are the seven the design re-derived. A change in `fstp-domain` must be
/// re-reviewed against the table.
#[test]
fn i78_domain_high_risk_kinds_match_the_m2_base() {
    let expected: BTreeSet<String> = M2_BASE_HIGH_RISK.iter().map(|s| (*s).to_owned()).collect();
    assert_eq!(domain_high_risk(), expected);
}

/// I-78, design section 8.4: `HIGH_RISK_TABLE` equals the reviewed
/// transcription row for row, and each row cites its spec text verbatim.
#[test]
fn i78_high_risk_table_matches_spec_and_domain() {
    let actual: BTreeSet<(String, String, String)> = HIGH_RISK_TABLE
        .iter()
        .map(|e| {
            (
                format!("{:?}", e.action),
                e.command.to_owned(),
                e.spec_row.to_owned(),
            )
        })
        .collect();
    let expected: BTreeSet<(String, String, String)> = DESIGN_TABLE
        .iter()
        .map(|(a, c, r)| ((*a).to_owned(), (*c).to_owned(), (*r).to_owned()))
        .collect();
    assert_eq!(actual, expected);
    assert_eq!(
        HIGH_RISK_TABLE.len(),
        DESIGN_TABLE.len(),
        "a command appears twice"
    );
}

/// I-78: every entry cites the Action cell of a row of the
/// `authentication.md` table, verbatim.
#[test]
fn i78_high_risk_table_cites_only_spec_rows() {
    let rows: BTreeSet<String> = spec_rows().into_iter().collect();
    for e in HIGH_RISK_TABLE {
        assert!(
            rows.contains(e.spec_row),
            "{} cites `{}`, which is not a spec row",
            e.command,
            e.spec_row
        );
    }
}

/// I-78: every row of the `authentication.md` table has an entry.
#[test]
fn i78_high_risk_table_covers_every_spec_row() {
    let cited: BTreeSet<&str> = HIGH_RISK_TABLE.iter().map(|e| e.spec_row).collect();
    for row in spec_rows() {
        assert!(cited.contains(row.as_str()), "no entry for `{row}`");
    }
}

/// I-78, ADR-008: every domain kind that `high_risk()` marks is in the
/// table.
#[test]
fn i78_high_risk_table_holds_every_domain_high_risk_kind() {
    let commands: BTreeSet<&str> = HIGH_RISK_TABLE.iter().map(|e| e.command).collect();
    for kind in domain_high_risk() {
        assert!(commands.contains(kind.as_str()), "{kind} is missing");
    }
}

/// I-78, ADR-008: an entry that names a domain kind the domain does not
/// mark high-risk sits on `STRICT_ADDITIONS`, so no addition is silent.
#[test]
fn i78_high_risk_table_adds_no_domain_kind_silently() {
    let strict: BTreeSet<&str> = STRICT_ADDITIONS.iter().map(|s| s.command).collect();
    let marked = domain_high_risk();
    let kinds = domain_kinds();
    for e in HIGH_RISK_TABLE {
        if kinds.contains(e.command) && !marked.contains(e.command) {
            assert!(
                strict.contains(e.command),
                "{} is not high-risk in the domain and not a strict addition",
                e.command
            );
        }
    }
}

/// I-78, Q38 interim (ADR-008): `STRICT_ADDITIONS` is exactly `Assign`,
/// `Unassign`, `ApproveSelfGrant` and `SetLoginPolicy`, each with its
/// source row. `ApproveRecovery` is not among them, since the spec now
/// lists it (Q15, decided 2026-10-28).
#[test]
fn i78_strict_additions_are_the_q38_interim_list() {
    let actual: BTreeSet<(String, String)> = STRICT_ADDITIONS
        .iter()
        .map(|s| (s.command.to_owned(), s.source.to_owned()))
        .collect();
    let expected: BTreeSet<(String, String)> = STRICT
        .iter()
        .map(|(c, r)| ((*c).to_owned(), (*r).to_owned()))
        .collect();
    assert_eq!(actual, expected);
}

/// I-78: each strict addition is also a table entry citing the same row.
#[test]
fn i78_strict_additions_are_table_entries() {
    for s in STRICT_ADDITIONS {
        assert!(
            HIGH_RISK_TABLE
                .iter()
                .any(|e| e.command == s.command && e.spec_row == s.source),
            "{} is a strict addition without a matching entry",
            s.command
        );
    }
}

/// I-78, I-79, Q15: approving a recovery cites its own spec row.
#[test]
fn i78_approve_recovery_cites_its_own_spec_row() {
    let e = HIGH_RISK_TABLE
        .iter()
        .find(|e| e.command == "ApproveRecovery")
        .unwrap();
    assert_eq!(e.spec_row, RECOVERY_ROW);
}
