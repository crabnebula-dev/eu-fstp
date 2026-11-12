//! R-RP-03, R-AC-01, D11, I-85, I-86 (lane m5/report-programmes): the
//! programmes whose funder reports the caller reads, `report.programmes`.
//!
//! The Financial signatory approves funder reports (R-RP-03, Q3) but holds
//! a tenant-wide role (NOTE 5), so no binding names a programme for it.
//! This read lists the programmes `report.list` admits the caller to, by id
//! and name only. Its rule admits a programme manager or an auditor of any
//! programme. The dispatch admits a Financial signatory of the tenant fold
//! beside the rule, as it does for `report.list`. An applicant and a
//! reviewer are refused (R-AC-01). Web only, as `report.list` is.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_access::{OpKind, ReadKind, ReadRule, op, read_rule, reply};
use fstp_domain::StateTag;
use fstp_domain::roles::Role;

/// R-RP-03, D11: the read has one rule, a programme manager or an
/// auditor of any programme, open in all 16 states.
#[test]
fn r_rp_03_d11_report_programmes_rule_is_managers_and_auditors_anywhere() {
    let (rule, open) = read_rule(ReadKind::ListReportProgrammes).expect("a rule");
    assert_eq!(
        rule,
        ReadRule::AnyOf(&[
            ReadRule::HolderAnywhere(Role::ProgrammeManager),
            ReadRule::HolderAnywhere(Role::Auditor),
        ])
    );
    for s in StateTag::ALL {
        assert!(
            open.contains(&s),
            "D11: report.programmes is unjudged in {s:?}"
        );
    }
    assert!(ReadKind::ALL.contains(&ReadKind::ListReportProgrammes));
}

/// R-RP-03, I-85: the read sits at its route, has no MCP tool, and is
/// neither high risk nor binding.
#[test]
fn r_rp_03_i85_report_programmes_is_a_web_only_read() {
    let spec = op("report.programmes").expect("in the registry");
    assert_eq!(spec.kind, OpKind::Read(ReadKind::ListReportProgrammes));
    assert_eq!(spec.route.map(|(_, p)| p), Some("/me/report-programmes"));
    assert!(spec.tool.is_none(), "I-85: report.programmes has a tool");
    assert!(!spec.high_risk && !spec.binding);
}

/// R-RP-03, I-86: the reply names each programme by id and name, and
/// nothing about any account, report or proposal.
#[test]
fn r_rp_03_i86_report_programmes_reply_is_ids_and_names_only() {
    let text = format!("{:?}", reply("report.programmes").expect("a shape"));
    assert!(
        text.contains("\"id\"") && text.contains("\"name\""),
        "{text}"
    );
    let lower = text.to_lowercase();
    for word in [
        "account", "email", "report", "proposal", "amount", "bank", "evidence",
    ] {
        assert!(
            !lower.contains(word),
            "I-86: report.programmes names {word}: {text}"
        );
    }
}
