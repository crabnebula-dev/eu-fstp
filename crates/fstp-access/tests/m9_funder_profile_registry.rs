//! R-RP-01, I-44, I-85, I-86 (M9 design section 2.2, decision FD11 taken
//! up in M9 finish, widened by Daniel on 2026-11-15 late): the read
//! `programme.funder_profile.view` in the registry.
//!
//! - It is a read of the programme, open in every state, for every
//!   Drafting, Judging and Operations role of the programme, read-only
//!   (Daniel, 2026-11-15 late). The tenant admin reads it through its
//!   rule, and the tenant-wide Financial and Legal signatories through
//!   the tenant fold in dispatch, as `report.list` does (NOTE 5).
//! - It is web only (I-85). Its reply names the pinned profile, its
//!   version and digest, its outputs and its visibility element keys, and
//!   nothing that names an account or an amount (I-86).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_access::{OpKind, ReadKind, ReadRule, RoleOrApplicant, op, read_rule, reply};
use fstp_domain::roles::{Group, Role};

/// R-RP-01 (Daniel, 2026-11-15 late): every Drafting, Judging and
/// Operations role of the programme reads its funder profile, and no
/// Receiving role does.
#[test]
fn r_rp_01_every_programme_staff_role_reads_the_funder_profile() {
    let (rule, _) = read_rule(ReadKind::GetFunderProfile).expect("a rule");
    assert_eq!(rule, ReadRule::PROFILE_READER);
    let ReadRule::AnyOf(parts) = rule else {
        panic!("the profile rule is a union: {rule:?}");
    };
    for role in Role::ALL {
        let named = parts.contains(&ReadRule::Holder(role))
            || (role == Role::Auditor && parts.contains(&ReadRule::Auditor))
            || (role == Role::TenantAdmin && parts.contains(&ReadRule::TenantAdmin));
        let staff = role.group() != Group::Receiving;
        // The tenant-wide signatories are judged in the tenant fold.
        if role.tenant_wide_signatory() {
            assert!(!named, "{role:?} holds no programme binding");
            continue;
        }
        assert_eq!(named, staff, "{role:?}");
    }
    let spec = op("programme.funder_profile.view").expect("in the registry");
    assert_eq!(spec.kind, OpKind::Read(ReadKind::GetFunderProfile));
    assert_eq!(
        spec.route.map(|(_, p)| p),
        Some("/programmes/{programme}/funder-profile")
    );
    for role in Role::ALL {
        let acting = spec.acting.contains(&RoleOrApplicant::Role(role));
        assert_eq!(acting, role.group() != Group::Receiving, "{role:?}");
    }
    assert!(spec.tool.is_none(), "I-85: the view has a tool");
}

/// R-RP-01: the funder reports stay with their own readers. Widening the
/// profile read widens no report read.
#[test]
fn r_rp_01_report_readers_are_unchanged() {
    assert_eq!(
        read_rule(ReadKind::ListReports).map(|(r, _)| r),
        Some(ReadRule::AnyOf(&[
            ReadRule::Holder(Role::ProgrammeManager),
            ReadRule::Auditor
        ]))
    );
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
