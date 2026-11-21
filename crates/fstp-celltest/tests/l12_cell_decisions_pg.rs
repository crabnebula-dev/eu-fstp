//! Tenant provisioning and the first admin's login email on the production
//! cell over PostgreSQL (ADR-026 "Tenant provisioning" and "First admin
//! email", decided by Daniel on 2026-11-21; ADR-026 record of lane L12).
//!
//! `fstp-cell provision-tenant` and `fstp-cell first-admin --email` run
//! `RunningCell::provision_tenant` and `RunningCell::first_admin_invitation`
//! on a cell started on loopback. These tests call the same two methods on
//! a world cell. The world issued its own first-admin invitation at start,
//! so each test first lets that one expire unused. Every account and
//! address is synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_celltest::mc::auth_model::http::{AuthClient, FIRST_ADMIN, one_cell_world};
use fstp_celltest::reference::auth::RefMethod;
use fstp_celltest::world::{CellHandle, HttpRequest};
use fstp_domain::id::AccountId;

/// The agreement versions of the synthetic tenant (Q22).
const AGREED: fstp_engine::AgreementVersions = fstp_engine::AgreementVersions {
    saas_terms: 1,
    dpa: 1,
    sub_processors: 1,
};

/// Moves the cell clock past the lifetime of the world's own first-admin
/// invitation, which nobody used.
fn expire_world_invitation(cell: &CellHandle) {
    let now = cell.clock().now();
    cell.clock()
        .set(now + fstp_auth::ceremony::INVITATION_US + 1_000_000);
}

/// The tenant part's first admin, if the ledger holds a tenant part.
fn tenant_first_admin(cell: &CellHandle) -> Option<AccountId> {
    cell.cell_engine()
        .unwrap()
        .state()
        .engine()
        .tenant
        .provisioning()
        .map(|p| p.first_admin)
}

/// `POST {path} {email}` with no session, as a browser sends it. The
/// reply is uniform: 202 whether or not anything was sent.
fn ask(cell: &CellHandle, path: &str, email: &str) {
    let r = cell
        .request(
            &HttpRequest::new("POST", path)
                .header("host", cell.host())
                .header("origin", format!("https://{}", cell.host()))
                .header("content-type", "application/json")
                .body(format!(r#"{{"email":"{email}"}}"#).into_bytes()),
        )
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        r.status,
        202,
        "{path}: {}",
        String::from_utf8_lossy(&r.body)
    );
}

/// ADR-021, ADR-026 "Tenant provisioning" (decided by Daniel on
/// 2026-11-21): provisioning records the tenant part once, so the ADR-021
/// gate reads a real tenant part. It is not active until onboarding and
/// activation run. A second provisioning is refused and appends nothing.
/// The first-admin invitation that follows invites exactly the
/// provisioned first admin.
#[test]
fn adr021_provision_tenant_records_the_tenant_part_on_pg() {
    let world = one_cell_world().unwrap_or_else(|e| panic!("{e}"));
    let cell = world.cell(0).unwrap();
    expire_world_invitation(cell);
    assert_eq!(
        tenant_first_admin(cell),
        None,
        "a tenant part before provisioning"
    );
    let first = cell
        .with_running(async |c| c.provision_tenant(Some(AGREED)).await)
        .unwrap()
        .unwrap_or_else(|e| panic!("the provisioning: {e}"));
    assert_eq!(tenant_first_admin(cell), Some(first));
    let state = cell.cell_engine().unwrap().state();
    let part = &state.engine().tenant;
    assert_eq!(part.agreements(), Some(AGREED));
    assert!(
        part.state().is_some_and(|t| !t.is_active()),
        "ADR-021: a provisioned organisation is active before its activation"
    );
    let head = state.head();
    assert!(
        cell.with_running(async |c| c.provision_tenant(Some(AGREED)).await)
            .unwrap()
            .is_err(),
        "a second provisioning"
    );
    assert_eq!(cell.cell_engine().unwrap().state().head(), head);
    cell.with_running(async |c| c.first_admin_invitation(None).await)
        .unwrap()
        .unwrap_or_else(|e| panic!("the first-admin invitation: {e}"));
    let s = cell.cell_engine().unwrap().state();
    assert!(
        s.auth().first_admin_invited(first),
        "the invitation does not invite the provisioned first admin"
    );
}

/// ADR-026 "First admin email" (decided by Daniel on 2026-11-21) and its
/// record of lane L12, I-79, Q35: `first-admin --email` records the
/// address as the first admin's login email, sealed and fingerprinted
/// under the `Lookup` key, so the keyed index finds the invited account.
///
/// Before the enrolment, the address opens nothing: a magic link request
/// and a recovery request both answer 202, and no proof mail leaves. Only
/// both token halves enrol the first admin. After the enrolment, recovery
/// by email opens a case and its proof reaches the address from day one.
#[test]
fn i79_first_admin_email_works_after_enrolment_only_on_pg() {
    let world = one_cell_world().unwrap_or_else(|e| panic!("{e}"));
    let cell = world.cell(0).unwrap();
    expire_world_invitation(cell);
    let first = cell
        .with_running(async |c| c.provision_tenant(Some(AGREED)).await)
        .unwrap()
        .unwrap();
    // The world's synthetic login email of its first admin.
    let email = cell.login_email(FIRST_ADMIN);
    let token = cell
        .with_running(async |c| c.first_admin_invitation(Some(&email)).await)
        .unwrap()
        .unwrap_or_else(|e| panic!("the first-admin invitation: {e}"));
    let found = cell
        .with_running(async |c| c.erasure().login_account(email.clone()).await)
        .unwrap()
        .unwrap();
    assert_eq!(
        found,
        Some(first),
        "the keyed index does not find the first admin"
    );
    // Before the enrolment: nothing leaves.
    let before = cell.mail().count();
    ask(cell, "/auth/magic/request", &email);
    ask(cell, "/auth/recovery", &email);
    let sent: Vec<_> = cell
        .mail()
        .captured()
        .into_iter()
        .skip(before)
        .filter(|m| m.to == email)
        .collect();
    assert!(
        sent.is_empty(),
        "I-79, Q35: the first admin's address opened a link or a case before the enrolment"
    );
    // Both halves enrol the first admin.
    let mut joined = token.first.to_vec();
    joined.extend_from_slice(&token.second.expect("a SaaS token has two halves"));
    let client = AuthClient::new(cell);
    assert!(
        client.enrol_invited(FIRST_ADMIN, first, &joined).unwrap(),
        "the first admin's enrolment"
    );
    assert!(
        client
            .login(FIRST_ADMIN, RefMethod::Passkey)
            .unwrap()
            .is_some()
    );
    // From day one, recovery by email opens a case and mails its proof.
    let case = client.recovery(FIRST_ADMIN).unwrap();
    assert!(
        case.is_some(),
        "I-79: recovery by email did not reach the first admin's address"
    );
}
