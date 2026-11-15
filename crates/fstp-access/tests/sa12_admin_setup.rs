//! SA-12 (Daniel, 2026-11-15 night): tenant admins help set up
//! programmes, in the registry, the read rules and the SA-09 page table.
//!
//! - Every programme set-up operation of the programme manager and the
//!   call drafter acts as a tenant admin too.
//! - `import.resolve` stays the programme manager's: I-65 names "a named
//!   programme manager", and an invariant outranks SA-12.
//! - The approval and publication of calls stay the programme
//!   manager's (R-PC-03), and the approval of activation stays a tenant
//!   admin's outside the builder set (I-67).
//! - Every set-up page opens for a tenant admin: each read it needs
//!   admits one.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_access::{OpKind, PageNeed, ReadRule, RoleOrApplicant, op, page_of, read_rule};
use fstp_domain::roles::Role;

const ADMIN: RoleOrApplicant = RoleOrApplicant::Role(Role::TenantAdmin);

/// Whether `rule` admits a tenant admin, whatever its bindings.
fn admits_admin(rule: ReadRule) -> bool {
    match rule {
        ReadRule::TenantAdmin => true,
        ReadRule::AnyOf(rules) => rules.iter().any(|r| admits_admin(*r)),
        _ => false,
    }
}

/// SA-12: the set-up operations act as a tenant admin, beside the roles
/// that held them before.
#[test]
fn sa12_set_up_operations_act_as_tenant_admin() {
    for name in [
        "creator.apply_start",
        "creator.save_fields",
        "creator.accept_narrative",
        "creator.edit_narrative",
        "creator.acknowledge",
        "creator.request_activation",
        "creator.invite",
        "creator.withdraw_invitation",
        "creator.save_as_template",
        "import.upload",
        "import.remove",
        "call.draft",
        "call.edit",
    ] {
        let o = op(name).unwrap_or_else(|| panic!("no {name}"));
        assert!(o.acting.contains(&ADMIN), "SA-12: {name} {:?}", o.acting);
        assert!(
            o.acting
                .iter()
                .any(|r| *r != ADMIN && *r != RoleOrApplicant::Applicant),
            "{name} keeps its Drafting role: {:?}",
            o.acting
        );
    }
    let draft = op("call.draft").unwrap();
    assert!(
        draft
            .acting
            .contains(&RoleOrApplicant::Role(Role::CallDrafter))
    );
    assert!(
        draft
            .acting
            .contains(&RoleOrApplicant::Role(Role::ProgrammeManager))
    );
}

/// I-65, R-PC-03, I-67: the resolution of an imported value and the
/// approval and publication of a call are still no tenant admin's. The
/// approval of activation stays a tenant admin's alone.
#[test]
fn sa12_i65_r_pc_03_resolution_and_call_approval_are_unchanged() {
    for name in ["import.resolve", "call.approve", "call.publish"] {
        let o = op(name).unwrap();
        assert_eq!(
            o.acting,
            &[RoleOrApplicant::Role(Role::ProgrammeManager)],
            "{name}"
        );
    }
    for name in ["creator.approve_activation", "creator.override_activation"] {
        assert_eq!(op(name).unwrap().acting, &[ADMIN], "{name}");
    }
}

/// SA-12: a tenant admin reads the programme's call list, so the calls it
/// drafts are reachable. The board, which counts proposals, is unchanged.
#[test]
fn sa12_call_list_is_read_by_tenant_admins() {
    let OpKind::Read(kind) = op("call.list").unwrap().kind else {
        panic!("call.list is a read");
    };
    let (rule, _) = read_rule(kind).unwrap();
    assert!(admits_admin(rule), "{rule:?}");
    assert!(op("call.list").unwrap().acting.contains(&ADMIN));
    let OpKind::Read(board) = op("call.board").unwrap().kind else {
        panic!("call.board is a read");
    };
    let (rule, _) = read_rule(board).unwrap();
    assert!(!admits_admin(rule), "{rule:?}");
}

/// SA-12, SA-09: every set-up page of a programme opens for a tenant
/// admin, since every read it needs admits one: the creator start and
/// steps, the imports, the Programme editor and its approval, Guide and
/// knock-out pages, the "Create a programme" stages and the people page.
#[test]
fn sa12_sa09_set_up_pages_open_for_tenant_admins() {
    let mut pages = vec![
        "/app/creator/new".to_owned(),
        "/app/setup/new".to_owned(),
        "/app/programmes/7/creator/start".to_owned(),
        "/app/programmes/7/creator/imports".to_owned(),
        "/app/programmes/7/studio".to_owned(),
        "/app/programmes/7/studio/approval".to_owned(),
        "/app/programmes/7/studio/guide".to_owned(),
        "/app/programmes/7/studio/knock-outs".to_owned(),
        "/app/programmes/7/setup/progress".to_owned(),
        "/app/programmes/7/people".to_owned(),
    ];
    for step in fstp_access::CREATOR_STEPS {
        pages.push(format!("/app/programmes/7/creator/{step}"));
    }
    for stage in fstp_access::SETUP_STAGES {
        pages.push(format!("/app/programmes/7/setup/{stage}"));
    }
    for path in pages {
        let (row, _) = page_of(&path).unwrap_or_else(|| panic!("no page row for {path}"));
        let PageNeed::Reads(reads) = row.need else {
            panic!("{path} needs no read: {:?}", row.need);
        };
        let opened = reads.iter().any(|name| {
            let o = op(name).unwrap_or_else(|| panic!("no read {name}"));
            let OpKind::Read(kind) = o.kind else {
                return false;
            };
            read_rule(kind).is_some_and(|(rule, _)| admits_admin(rule)) && o.acting.contains(&ADMIN)
        });
        assert!(
            opened,
            "SA-12: {path} stays closed to a tenant admin ({reads:?})"
        );
    }
}
