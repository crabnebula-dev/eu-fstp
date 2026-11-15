//! SA-11 (Daniel, 2026-11-15, night): the team and member pages, with
//! display names, in the registry.
//!
//! - `team.list` lists every Drafting, Judging and Operations role of a
//!   programme, open invitations included. Tenant admins and the
//!   programme's manager read it, as they read the invitations.
//! - `admin.members` lists every member account of the organisation with
//!   its roles across programmes. Tenant admins read it.
//! - `me.display_name` and `me.set_display_name`: an account reads, sets
//!   and clears its own display name.
//! - All four are web only (I-86): they name emails and display names,
//!   which are personal data, so no MCP tool reaches them.
//! - Each page has its SA-09 row, gated on its read.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_access::{
    Classification, Method, OpKind, PageNeed, PortKind, ReadKind, ReadRule, RoleOrApplicant, Shape,
    TEAM_ROLES, op, page_of, read_rule, reply, role_wire_name,
};
use fstp_domain::StateTag;
use fstp_domain::roles::{Group, Role};

/// SA-11: the team page's readers are the programme's manager and every
/// tenant admin, the readers of the programme's invitations.
#[test]
fn sa11_team_read_rule_is_the_manager_and_the_tenant_admins() {
    assert_eq!(
        ReadRule::TEAM_READER,
        ReadRule::AnyOf(&[ReadRule::DraftManager, ReadRule::TenantAdmin])
    );
    let (rule, open) = read_rule(ReadKind::ListTeam).expect("a rule");
    assert_eq!(rule, ReadRule::TEAM_READER);
    let (invitations, _) = read_rule(ReadKind::ListInvitations).expect("a rule");
    assert_eq!(rule, invitations, "SA-11: the invitation readers");
    for s in StateTag::ALL {
        assert!(open.contains(&s), "team.list is closed in {s:?}");
    }
}

/// SA-11: the member page is the tenant admins' alone, in every state.
#[test]
fn sa11_members_read_rule_is_the_tenant_admins() {
    let (rule, open) = read_rule(ReadKind::ListMembers).expect("a rule");
    assert_eq!(rule, ReadRule::TenantAdmin);
    for s in StateTag::ALL {
        assert!(open.contains(&s), "admin.members is closed in {s:?}");
    }
}

/// SA-11, I-86: an account reads its own display name only.
#[test]
fn sa11_display_name_read_is_the_callers_own() {
    let (rule, _) = read_rule(ReadKind::GetMyDisplayName).expect("a rule");
    assert_eq!(rule, ReadRule::Own);
}

/// SA-11, I-86: the four operations, their routes and their actors. None
/// has a tool, none is high-risk or binding, and each is personal data.
#[test]
fn sa11_i86_operations_are_web_only_personal_reads_and_one_command() {
    let manager_or_admin = [
        RoleOrApplicant::Role(Role::ProgrammeManager),
        RoleOrApplicant::Role(Role::TenantAdmin),
    ];
    let team = op("team.list").expect("team.list");
    assert_eq!(team.kind, OpKind::Read(ReadKind::ListTeam));
    assert_eq!(
        team.route,
        Some((Method::Get, "/programmes/{programme}/team"))
    );
    assert_eq!(team.acting, &manager_or_admin);
    let members = op("admin.members").expect("admin.members");
    assert_eq!(members.kind, OpKind::Read(ReadKind::ListMembers));
    assert_eq!(members.route, Some((Method::Get, "/admin/members")));
    assert_eq!(members.acting, &[RoleOrApplicant::Role(Role::TenantAdmin)]);
    let own = op("me.display_name").expect("me.display_name");
    assert_eq!(own.kind, OpKind::Read(ReadKind::GetMyDisplayName));
    assert_eq!(own.route, Some((Method::Get, "/me/display-name")));
    let set = op("me.set_display_name").expect("me.set_display_name");
    assert_eq!(set.kind, OpKind::M3Port(PortKind::SetDisplayName));
    assert_eq!(set.route, Some((Method::Post, "/me/display-name")));
    for spec in [team, members, own, set] {
        assert!(spec.tool.is_none(), "I-86: {} has a tool", spec.name);
        assert!(!spec.high_risk, "{} is high-risk", spec.name);
        assert!(!spec.binding, "{} is binding", spec.name);
        assert_eq!(
            spec.classification,
            Classification::Personal,
            "{}",
            spec.name
        );
    }
}

/// SA-11: the team rows name a role outside the Receiving group only, so
/// no applicant and no applicant team is ever listed.
#[test]
fn sa11_team_roles_are_every_role_outside_receiving() {
    let want: Vec<&str> = Role::ALL
        .iter()
        .filter(|r| r.group() != Group::Receiving)
        .map(|r| role_wire_name(*r))
        .collect();
    assert_eq!(TEAM_ROLES, want.as_slice());
    for name in ["applicant", "applicant_team_member", "guardian"] {
        assert!(!TEAM_ROLES.contains(&name), "SA-11: {name} is listed");
    }
}

/// The enum of strings a member names, as its shape says.
fn enum_of(shape: &Shape, path: &[&str]) -> &'static [&'static str] {
    let mut s = *shape;
    for name in path {
        s = match s {
            Shape::Object(members) => {
                members
                    .iter()
                    .find(|m| m.name == *name)
                    .unwrap_or_else(|| panic!("no member {name}"))
                    .shape
            }
            Shape::Array(inner) => match *inner {
                Shape::Object(members) => {
                    members
                        .iter()
                        .find(|m| m.name == *name)
                        .unwrap_or_else(|| panic!("no member {name}"))
                        .shape
                }
                other => panic!("{name} under {other:?}"),
            },
            other => panic!("{name} under {other:?}"),
        };
    }
    match s {
        Shape::Enum(values) => values,
        Shape::Array(inner) => match *inner {
            Shape::Enum(values) => values,
            other => panic!("not an enum: {other:?}"),
        },
        other => panic!("not an enum: {other:?}"),
    }
}

/// SA-11: each read has its reply shape. A row names its role among the
/// team roles, its status among the six the amendment names, and the
/// actions are grant, end, reinstate and invite.
#[test]
fn sa11_replies_name_the_team_roles_statuses_and_actions() {
    let statuses = [
        "invited",
        "accepted",
        "verified",
        "active",
        "suspended",
        "ended",
    ];
    let actions = ["grant", "end", "reinstate", "invite"];
    let team = reply("team.list").expect("team.list reply");
    assert_eq!(enum_of(team, &["rows", "role"]), TEAM_ROLES);
    assert_eq!(enum_of(team, &["rows", "status"]), statuses);
    assert_eq!(enum_of(team, &["actions"]), actions);
    let members = reply("admin.members").expect("admin.members reply");
    assert_eq!(enum_of(members, &["members", "roles", "role"]), TEAM_ROLES);
    assert_eq!(enum_of(members, &["members", "roles", "status"]), statuses);
    assert_eq!(enum_of(members, &["actions"]), actions);
    let own = reply("me.display_name").expect("me.display_name reply");
    assert!(
        matches!(own, Shape::Object(m) if m.len() == 1 && m[0].name == "display_name"),
        "{own:?}"
    );
}

/// SA-09, SA-11: the team page is gated on `team.list` with the page's
/// programme, and the member page on `admin.members`.
#[test]
fn sa09_sa11_pages_are_gated_on_their_reads() {
    let (row, params) = page_of("/app/programmes/3/team").expect("the team page");
    assert_eq!(row.pattern, "/app/programmes/{programme}/team");
    assert_eq!(row.need, PageNeed::Reads(&["team.list"]));
    assert_eq!(params, vec![("programme", "3".to_owned())]);
    let (row, _) = page_of("/app/admin/members").expect("the member page");
    assert_eq!(row.pattern, "/app/admin/members");
    assert_eq!(row.need, PageNeed::Reads(&["admin.members"]));
}
