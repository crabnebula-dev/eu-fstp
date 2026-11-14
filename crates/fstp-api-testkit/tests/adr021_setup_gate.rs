//! ADR-021: the setup gate. Until a second tenant admin approves the
//! activation of the organisation (SoD-18), the cell refuses every
//! command, read and grant outside tenant onboarding, under the rule
//! `ADR-021`. Only tenant admins act, and they grant only the roles
//! onboarding needs: the second tenant admin and the Financial and Legal
//! signatories (SoD-14, SoD-15). Every account keeps its own sessions and
//! passkeys (R-LG-04).
//!
//! Each test drives the one dispatch of a fake cell through
//! `decode_route`, in the world of `signatories/mod.rs`: A1 and A2 are
//! verified tenant admins, S1 a verified account that takes both
//! signatory roles, and OUTSIDER a verified account with no role.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod signatories;

use fstp_api_core::decode::{Method, decode_route};
use fstp_api_core::{ApiError, Credential, Op, OpResult};
use fstp_api_testkit::fake::{FakeCell, WebLogin};
use signatories::{
    A1, A2, FINANCIAL, LEGAL, OUTSIDER, S1, active, approve, assert_rule, complete, done, login,
    member, onboarded, request, request_id, state, stepped, text,
};

/// The rule every refusal of the gate names.
const SETUP: &str = "ADR-021";

fn get(path: &str) -> Result<Op, ApiError> {
    decode_route(Method::Get, path, b"")
}

fn post(path: &str, body: &str) -> Result<Op, ApiError> {
    decode_route(Method::Post, path, body.as_bytes())
}

/// `creator.open_draft`: a command outside onboarding.
fn open_draft() -> Result<Op, ApiError> {
    post("/programmes", "{}")
}

/// `creator.invite` of a programme manager on `p`: a grant outside
/// onboarding.
fn invite_manager(p: &str) -> Result<Op, ApiError> {
    post(
        &format!("/programmes/{p}/invitations"),
        r#"{"email":"invitee@matrix.invalid","role":"programme_manager"}"#,
    )
}

/// `roles.grant` of an Auditor on `p`: a grant outside onboarding.
fn grant_auditor(p: &str) -> Result<Op, ApiError> {
    post(
        &format!("/programmes/{p}/roles"),
        &format!(
            r#"{{"account":"{}","role":"Auditor","start":"1793350800000000"}}"#,
            OUTSIDER.raw()
        ),
    )
}

/// `tenant.invite_admin`: the grant of the second tenant admin.
fn invite_admin() -> Result<Op, ApiError> {
    post("/admin/admins", r#"{"email":"third-admin@matrix.invalid"}"#)
}

fn anonymous(c: &FakeCell, op: Result<Op, ApiError>) -> Result<OpResult, ApiError> {
    c.call(Credential::None, op)
}

/// An onboarded cell with both signatory roles held by S1 and onboarding
/// completed by A1, so only the activation is missing.
fn complete_not_active() -> (FakeCell, WebLogin, WebLogin) {
    let (c, l1, l2) = onboarded(&[(S1, FINANCIAL), (S1, LEGAL)]);
    let _ = done(c.web(&l1, complete()), "tenant.complete by A1");
    assert_ne!(state(&c, &l1), "active", "SoD-18: not yet approved");
    (c, l1, l2)
}

/// ADR-021, SoD-18: before activation a command, a read and an account
/// with no role are refused under `ADR-021`. Onboarding itself goes on.
#[test]
fn adr021_sod18_before_activation_everything_outside_onboarding_is_refused() {
    let (c, l1, _l2) = complete_not_active();
    let outsider = login(&c, OUTSIDER);
    let signatory = login(&c, S1);
    // A tenant admin's command outside onboarding.
    assert_rule(
        &stepped(&c, &l1, &open_draft),
        SETUP,
        "creator.open_draft by A1",
    );
    // A tenant admin's read outside onboarding.
    assert_rule(&c.web(&l1, get("/me/mailbox")), SETUP, "me.mailbox by A1");
    assert_rule(
        &c.web(&l1, get("/me/proposals")),
        SETUP,
        "proposal.list_own by A1",
    );
    // An account with no role, and a signatory, read nothing.
    for (who, l) in [("OUTSIDER", &outsider), ("S1", &signatory)] {
        for path in ["/me/roles", "/me/proposals", "/me/mailbox", "/calls"] {
            assert_rule(&c.web(l, get(path)), SETUP, &format!("{path} by {who}"));
        }
        assert_rule(
            &c.web(l, get("/admin/activation")),
            SETUP,
            &format!("tenant.get_activation by {who}"),
        );
    }
    // An anonymous visitor finds no open calls.
    assert_rule(
        &anonymous(&c, get("/calls")),
        SETUP,
        "calls.list_open, anonymous",
    );
    // Onboarding goes on for the admins.
    let roles = done(c.web(&l1, get("/me/roles")), "me.roles by A1");
    assert_ne!(
        member(&roles, "tenant_admin"),
        fstp_json::Value::Null,
        "{roles:?}"
    );
    let _ = done(
        c.web(&l1, get("/admin/activation")),
        "tenant.get_activation by A1",
    );
    // R-LG-04: every account sees its own sessions.
    let _ = done(
        c.web(&outsider, get("/me/sessions")),
        "me.sessions by OUTSIDER",
    );
}

/// ADR-021, SoD-14, SoD-15: before activation a tenant admin grants the
/// roles onboarding needs, the second admin and the signatories, and no
/// other role.
#[test]
fn adr021_sod14_sod15_before_activation_only_onboarding_grants_pass() {
    let (c, l1, _l2) = complete_not_active();
    let _ = done(stepped(&c, &l1, &invite_admin), "tenant.invite_admin by A1");
    // The signatory grants of `onboarded` completed; another one does too.
    let _ = done(
        stepped(&c, &l1, &|| signatories::grant(A2, FINANCIAL)),
        "tenant.grant_signatory by A1",
    );
    for p in ["1", "77"] {
        assert_rule(
            &stepped(&c, &l1, &|| grant_auditor(p)),
            SETUP,
            "roles.grant by A1",
        );
        assert_rule(
            &stepped(&c, &l1, &|| invite_manager(p)),
            SETUP,
            "creator.invite by A1",
        );
    }
}

/// ADR-021, SoD-18: once A2 approves A1's request, the same command, the
/// same reads and the same grant pass.
#[test]
fn adr021_sod18_after_activation_the_same_command_and_grant_pass() {
    let (c, l1, l2) = complete_not_active();
    let _ = done(request(&c, &l1), "the activation request by A1");
    // An open request does not activate the organisation.
    assert_rule(&stepped(&c, &l1, &open_draft), SETUP, "with a request open");
    let id = request_id(&c, &l1);
    let _ = done(approve(&c, &l2, &id), "the approval by A2");
    assert_eq!(state(&c, &l1), "active");
    let draft = done(stepped(&c, &l1, &open_draft), "creator.open_draft by A1");
    let p = text(&draft, "programme");
    let _ = done(
        stepped(&c, &l1, &|| invite_manager(&p)),
        "creator.invite by A1",
    );
    let outsider = login(&c, OUTSIDER);
    for path in ["/me/roles", "/me/proposals", "/me/mailbox", "/calls"] {
        let _ = done(c.web(&outsider, get(path)), &format!("{path} by OUTSIDER"));
    }
    let _ = done(anonymous(&c, get("/calls")), "calls.list_open, anonymous");
}

/// ADR-021: the gate reopens nothing it should not. After activation the
/// rules of each operation judge it again, so an account with no role is
/// refused the activation read as before, under its own rule.
#[test]
fn adr021_after_activation_each_operation_is_judged_by_its_own_rules() {
    let (c, _l1, _l2) = active(&[(S1, FINANCIAL), (S1, LEGAL)]);
    let outsider = login(&c, OUTSIDER);
    match c.web(&outsider, get("/admin/activation")) {
        Err(ApiError::Refused { rule, .. }) => assert_ne!(rule, SETUP),
        other => panic!("tenant.get_activation by OUTSIDER: {other:?}"),
    }
}
