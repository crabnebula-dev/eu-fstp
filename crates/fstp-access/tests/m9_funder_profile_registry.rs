//! R-RP-01, I-44, I-85, I-86 (M9 design section 2.2, decision FD11 taken
//! up in M9 finish): the read `programme.funder_profile.view` in the
//! registry.
//!
//! - It is a read of the programme, open in every state, for the
//!   programme's manager and its auditor. The Financial signatory reads it
//!   through the tenant fold in dispatch, as `report.list` does (NOTE 5).
//! - It is web only (I-85). Its reply names the pinned profile, its
//!   version and digest, its outputs and its visibility element keys, and
//!   nothing that names an account or an amount (I-86).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_access::{OpKind, ReadKind, ReadRule, RoleOrApplicant, op, read_rule, reply};
use fstp_domain::roles::Role;

/// R-RP-01: the view is the report readers' read of one programme.
#[test]
fn r_rp_01_funder_profile_view_is_the_report_readers_read() {
    let (rule, _) = read_rule(ReadKind::GetFunderProfile).expect("a rule");
    assert_eq!(
        rule,
        ReadRule::AnyOf(&[ReadRule::Holder(Role::ProgrammeManager), ReadRule::Auditor])
    );
    assert_eq!(read_rule(ReadKind::ListReports).map(|(r, _)| r), Some(rule));
    let spec = op("programme.funder_profile.view").expect("in the registry");
    assert_eq!(spec.kind, OpKind::Read(ReadKind::GetFunderProfile));
    assert_eq!(
        spec.route.map(|(_, p)| p),
        Some("/programmes/{programme}/funder-profile")
    );
    assert_eq!(
        spec.acting,
        &[
            RoleOrApplicant::Role(Role::ProgrammeManager),
            RoleOrApplicant::Role(Role::Auditor),
            RoleOrApplicant::Role(Role::FinancialSignatory),
        ]
    );
    assert!(spec.tool.is_none(), "I-85: the view has a tool");
}

/// I-86, R-RP-01: the reply names the profile and its parts, and nothing
/// that names an account, an amount or a bank detail.
#[test]
fn i86_funder_profile_view_reply_names_no_account_or_amount() {
    let text = format!(
        "{:?}",
        reply("programme.funder_profile.view").expect("a shape")
    );
    for member in [
        "\"programme\"",
        "\"profile\"",
        "\"version\"",
        "\"digest\"",
        "\"outputs\"",
        "\"visibility_elements\"",
    ] {
        assert!(text.contains(member), "lacks {member}: {text}");
    }
    for leak in ["account", "amount", "bank", "email"] {
        assert!(!text.contains(leak), "the view names {leak}: {text}");
    }
}
