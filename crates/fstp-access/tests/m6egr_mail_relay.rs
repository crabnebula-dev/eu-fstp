//! The mail relay operation of M6 lane L6-EGR (ADR-018 proposed; R-LG-03,
//! I-78, I-85).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_access::{Method, OpKind, SessionNeed, TenantKind, op};
use fstp_domain::roles::Role;

/// R-LG-03, I-78, I-85: `tenant.set_mail_relay` is a tenant admin's
/// high-risk operation. It needs a phishing-resistant session and a fresh
/// step-up, and it has no tool, so it is web only.
#[test]
fn r_lg_03_set_mail_relay_needs_step_up() {
    let o = op("tenant.set_mail_relay").expect("tenant.set_mail_relay");
    assert_eq!(o.kind, OpKind::Tenant(TenantKind::SetMailRelay));
    assert!(o.high_risk);
    assert_eq!(o.session, SessionNeed::PhishingResistant);
    assert!(o.tool.is_none());
    assert_eq!(o.route, Some((Method::Put, "/admin/settings/mail-relay")));
    assert_eq!(o.acting.len(), 1);
    assert!(matches!(
        o.acting.first(),
        Some(fstp_access::RoleOrApplicant::Role(Role::TenantAdmin))
    ));
}
