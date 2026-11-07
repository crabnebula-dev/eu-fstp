//! The branding operations of M9 lane B1 (M9 design section 2.2; I-70,
//! R-LG-03, I-78, I-85).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_access::{Method, OpKind, SessionNeed, Shape, TenantKind, op, reply};
use fstp_domain::roles::Role;

/// R-LG-03, I-78, I-85: `tenant.branding.set` is a tenant admin's
/// high-risk operation. It needs a phishing-resistant session and a fresh
/// step-up, and it has no tool, so it is web only.
#[test]
fn r_lg_03_branding_set_needs_step_up() {
    let o = op("tenant.branding.set").expect("tenant.branding.set");
    assert_eq!(o.kind, OpKind::Tenant(TenantKind::SetBranding));
    assert!(o.high_risk);
    assert_eq!(o.session, SessionNeed::PhishingResistant);
    assert!(o.tool.is_none());
    assert_eq!(o.route, Some((Method::Put, "/admin/branding")));
    assert_eq!(o.acting.len(), 1);
    assert!(matches!(
        o.acting.first(),
        Some(fstp_access::RoleOrApplicant::Role(Role::TenantAdmin))
    ));
}

/// I-70: `tenant.branding.check` returns the failing pairs and saves
/// nothing, so it needs no step-up. Its reply lists pairs by name only.
#[test]
fn i70_branding_check_lists_pairs_and_saves_nothing() {
    let o = op("tenant.branding.check").expect("tenant.branding.check");
    assert_eq!(o.kind, OpKind::Tenant(TenantKind::CheckBranding));
    assert!(!o.high_risk);
    assert!(o.tool.is_none());
    assert_eq!(o.route, Some((Method::Post, "/admin/branding/check")));
    let Some(Shape::Object(members)) = reply("tenant.branding.check") else {
        panic!("tenant.branding.check has an object reply");
    };
    let names: Vec<&str> = members.iter().map(|m| m.name).collect();
    assert_eq!(names, ["accepted", "failing"]);
    assert!(reply("tenant.branding.set").is_none());
}
