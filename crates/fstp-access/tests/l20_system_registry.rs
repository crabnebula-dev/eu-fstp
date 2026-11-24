//! ADR-028 record of lane L20 (Daniel, 2026-11-21, usability rule): the
//! System page of the tenant admins in the registry.
//!
//! - `tenant.system` reads the facts of the page: the vault, outgoing mail
//!   and the host status file. Tenant admins read it, in every state.
//! - It is a plain read: no tool, no step-up, nothing binding, and it
//!   holds no personal data.
//! - Its reply shape holds instants, flags, counts and closed words only
//!   (R-NF-02).
//! - The page has its SA-09 row, gated on the read.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_access::{
    Classification, HOST_NEXT, Method, OpKind, PART_STATES, PageNeed, ReadKind, ReadRule,
    RoleOrApplicant, Shape, op, page_of, read_rule, reply,
};
use fstp_domain::StateTag;
use fstp_domain::roles::Role;

/// ADR-028 record of lane L20: the read is the tenant admins' alone, in
/// every state, and the page is gated on it.
#[test]
fn adr028_l20_system_read_is_tenant_admin_only() {
    let (rule, open) = read_rule(ReadKind::GetSystemStatus).expect("a rule");
    assert_eq!(rule, ReadRule::TenantAdmin);
    for s in StateTag::ALL {
        assert!(open.contains(&s), "tenant.system is closed in {s:?}");
    }
    let spec = op("tenant.system").expect("tenant.system");
    assert_eq!(spec.kind, OpKind::Read(ReadKind::GetSystemStatus));
    assert_eq!(spec.route, Some((Method::Get, "/admin/system")));
    assert_eq!(spec.acting, &[RoleOrApplicant::Role(Role::TenantAdmin)]);
    assert!(spec.tool.is_none(), "no MCP tool");
    assert!(!spec.high_risk && !spec.binding);
    assert_ne!(spec.classification, Classification::Personal);
    let (row, params) = page_of("/app/admin/system").expect("the System page");
    assert_eq!(row.pattern, "/app/admin/system");
    assert_eq!(row.need, PageNeed::Reads(&["tenant.system"]));
    assert!(params.is_empty());
}

fn no_string(s: &Shape) -> bool {
    match s {
        Shape::String => false,
        Shape::Array(inner) | Shape::Nullable(inner) => no_string(inner),
        Shape::Object(members) => members.iter().all(|m| no_string(&m.shape)),
        _ => true,
    }
}

/// R-NF-02, ADR-028 record of lane L20: the reply names no free string.
/// Its words are those of the host status file.
#[test]
fn r_nf_02_system_reply_holds_no_free_text() {
    let shape = reply("tenant.system").expect("a reply shape");
    assert!(no_string(shape), "{shape:?}");
    assert_eq!(PART_STATES, &["running", "unhealthy", "stopped"]);
    let words: Vec<&str> = fstp_obs_words();
    assert_eq!(HOST_NEXT, words.as_slice());
}

/// The words of `fstp_obs::host_status::Next`, spelled out here, since
/// `fstp-access` does not depend on `fstp-obs`. `fstp-cell`'s test
/// `adr028_l20_host_status_read_states` ties the two lists.
fn fstp_obs_words() -> Vec<&'static str> {
    vec![
        "run_setup",
        "start_service",
        "custodian",
        "pair_custodian",
        "renew_route",
        "renew",
        "public_certificate",
        "configure_backups",
        "wal_archive",
        "backup",
        "custodian_copy",
        "keystore_snapshot",
        "web_admins",
        "verify_admins",
        "copy_keys",
        "nothing",
    ]
}
