//! Lane m4/api-gaps (Daniel, 2026-11-15): the three operations the
//! authorisation matrices found unwired, each through `ApiCore::dispatch`
//! on a matrix world.
//!
//! - `me.add_passkey` registers through the cell's passkey ceremony
//!   (`fstp_auth::ceremony`, `fstp-webauthn`), reached by the sessions
//!   admin port (R-LG-04, I-77, I-78).
//! - `agents.consent` approves a consent of the `fstp-oauth` authorize
//!   flow by its handle (ADR-013, I-78).
//! - A tenant admin's self-grant records a grant awaiting approval, which
//!   `admin.approvals` lists and `admin.approve_self_grant` approves by
//!   id, by another tenant admin only (SoD-07).
//!
//! Every account and text is synthetic.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]

use super::*;
use crate::reference::authz::Policy;

const POST: ApiMethod = ApiMethod::Post;
const GET: ApiMethod = ApiMethod::Get;

/// The world of `state`, its cell clock at the world's instant, as a
/// matrix cell runs it.
fn world(state: StateProfile, variant: Variant) -> Built {
    let w = build(WorldKey {
        state,
        policy: Policy::SUPERSAFE,
        variant,
    })
    .unwrap_or_else(|e| panic!("world {state:?}: {e}"));
    w.ports.clock.set(Timestamp::from_micros(w.now));
    w
}

fn active() -> Built {
    world(StateProfile::ProgrammeActive, Variant::Main)
}

/// One call of `path` in `login`'s session, with no step-up answered.
fn once(
    w: &Built,
    login: &WebLogin,
    method: ApiMethod,
    path: &str,
    body: &Value,
) -> Result<OpResult, ApiError> {
    let bytes = match body {
        Value::Null => Vec::new(),
        v => v.to_compact().into_bytes(),
    };
    let op = decode_web(method, path, &bytes)?;
    block_on(w.core.dispatch(
        Credential::SessionCookie(login.cookie.clone()),
        &RequestHead::new(),
        op,
    ))
}

/// One call that answers its step-up challenge once, freshly.
fn stepped(
    w: &Built,
    login: &WebLogin,
    method: ApiMethod,
    path: &str,
    body: &Value,
) -> Result<OpResult, ApiError> {
    let r = once(w, login, method, path, body);
    let Ok(OpResult::StepUpRequired(ch)) = &r else {
        return r;
    };
    w.ports.step_up.approve(login.session, ch.action).unwrap();
    once(w, login, method, path, body)
}

fn observed(r: &Result<OpResult, ApiError>) -> Observed {
    observed_of_result(r).unwrap_or_else(|e| panic!("{e:?}"))
}

fn refused(rule: &str) -> Observed {
    Observed::Refused(Some(rule.to_owned()))
}

fn body_json(r: Result<OpResult, ApiError>) -> Value {
    match r {
        Ok(OpResult::Done { body, .. }) => body.to_json(),
        other => panic!("not done: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// me.add_passkey
// ---------------------------------------------------------------------------

/// R-LG-04, I-78, `authentication.md` (adding a passkey is high-risk): a
/// passkey session with a fresh step-up adds a passkey whose registration
/// the cell's ceremony verifies through `fstp-webauthn`. The challenge of
/// the options is single use, so the same registration is refused again
/// under `Input`.
#[test]
fn r_lg_04_i78_me_add_passkey_registers_through_the_cell_ceremony() {
    let w = active();
    let login = w.ports.sessions.login(PM, LoginMethod::Passkey);
    let body = passkey_body(&w, Some(login.session.raw())).unwrap();
    let r = stepped(&w, &login, POST, "/me/passkeys", &body);
    assert_eq!(observed(&r), Observed::Completed, "{r:?}");
    assert_eq!(
        w.ports.sessions.passkeys_of(PM).len(),
        1,
        "one passkey added"
    );
    let again = stepped(&w, &login, POST, "/me/passkeys", &body);
    assert_eq!(
        observed(&again),
        refused("Input"),
        "a challenge is used once"
    );
    assert_eq!(w.ports.sessions.passkeys_of(PM).len(), 1);
}

/// I-77, I-78, R-LG-04: a magic-link session adds no passkey, a passkey
/// session needs a fresh step-up first, and a registration over another
/// session's challenge is refused under `Input` with nothing registered.
#[test]
fn i77_i78_me_add_passkey_refusals() {
    let w = active();
    let magic = w.ports.sessions.login(LEAD, LoginMethod::MagicLink);
    let body = passkey_body(&w, Some(magic.session.raw())).unwrap();
    assert_eq!(
        observed(&once(&w, &magic, POST, "/me/passkeys", &body)),
        refused("I-77")
    );
    let login = w.ports.sessions.login(PM, LoginMethod::Passkey);
    let body = passkey_body(&w, Some(login.session.raw())).unwrap();
    assert_eq!(
        observed(&once(&w, &login, POST, "/me/passkeys", &body)),
        Observed::StepUpRequired
    );
    let other = w.ports.sessions.login(PM, LoginMethod::Passkey);
    let foreign = passkey_body(&w, Some(other.session.raw())).unwrap();
    assert_eq!(
        observed(&stepped(&w, &login, POST, "/me/passkeys", &foreign)),
        refused("Input"),
        "a challenge of another session"
    );
    assert!(w.ports.sessions.passkeys_of(PM).is_empty());
}

// ---------------------------------------------------------------------------
// agents.consent
// ---------------------------------------------------------------------------

/// ADR-013 (Consent, Strength), I-78: the user approves a consent of the
/// authorize flow by its handle, with a fresh step-up. The client gets a
/// code at its redirect URI with `iss`, and the code redeems to a token
/// whose grant names the user's account and the passkey method of the
/// consenting session. The handle approves once.
#[test]
fn adr013_i78_agents_consent_approves_the_authorize_flow_consent() {
    let w = active();
    let login = w.ports.sessions.login(PM, LoginMethod::Passkey);
    let start = w
        .ports
        .tokens
        .begin_consent(Timestamp::from_micros(w.now))
        .unwrap();
    let body = obj(vec![("consent", s(&start.handle))]);
    let reply = body_json(stepped(&w, &login, POST, "/oauth/consent", &body));
    let redirect = str_member(&reply, "redirect").unwrap();
    assert!(redirect.starts_with(&start.redirect_uri), "{redirect}");
    assert!(redirect.contains("iss="), "RFC 9207: {redirect}");
    let grant = w
        .ports
        .tokens
        .redeem(&start, &redirect, Timestamp::from_micros(w.now))
        .unwrap();
    assert_eq!(u128::from(grant.account.raw()), PM.raw());
    assert_eq!(grant.consent_method, fstp_oauth::LoginMethod::Passkey);
    assert_eq!(
        observed(&stepped(&w, &login, POST, "/oauth/consent", &body)),
        refused("Input"),
        "a consent is approved once"
    );
}

/// ADR-013, I-77, I-78: a magic-link session connects no agent, a passkey
/// session needs a fresh step-up, and a handle the server never issued is
/// refused under `Input`.
#[test]
fn adr013_i77_i78_agents_consent_refusals() {
    let w = active();
    let start = w
        .ports
        .tokens
        .begin_consent(Timestamp::from_micros(w.now))
        .unwrap();
    let body = obj(vec![("consent", s(&start.handle))]);
    let magic = w.ports.sessions.login(LEAD, LoginMethod::MagicLink);
    assert_eq!(
        observed(&once(&w, &magic, POST, "/oauth/consent", &body)),
        Observed::Refused(Some("I-77".to_owned()))
    );
    let login = w.ports.sessions.login(PM, LoginMethod::Passkey);
    assert_eq!(
        observed(&once(&w, &login, POST, "/oauth/consent", &body)),
        Observed::StepUpRequired
    );
    let unknown = obj(vec![("consent", s(&"A".repeat(43)))]);
    assert_eq!(
        observed(&stepped(&w, &login, POST, "/oauth/consent", &unknown)),
        refused("Input")
    );
}

// ---------------------------------------------------------------------------
// admin.approve_self_grant
// ---------------------------------------------------------------------------

/// SoD-07 (Daniel, 2026-11-15): a tenant admin's grant to their own
/// account records a grant awaiting approval and answers its id.
/// `admin.approvals` lists it with the grantee, programme, role and
/// dates, approvable by the other admin only. The other admin approves it
/// by id with a step-up, after which it leaves the inbox, and a second
/// approval is refused.
#[test]
fn sod_07_self_grant_awaits_a_second_admin_and_is_approved_by_id() {
    let w = active();
    let p = w.targets.programme.unwrap().raw();
    let builder = w.ports.sessions.login(ADMIN_BUILDER, LoginMethod::Passkey);
    let plain = w.ports.sessions.login(ADMIN_PLAIN, LoginMethod::Passkey);
    let start = w.now + DAY;
    let end = w.now + 30 * DAY;
    let grant = obj(vec![
        ("account", dec(ADMIN_BUILDER.raw())),
        ("role", s("Auditor")),
        ("start", dec(u128::try_from(start).unwrap())),
        ("end", dec(u128::try_from(end).unwrap())),
    ]);
    let reply = body_json(stepped(
        &w,
        &builder,
        POST,
        &format!("/programmes/{p}/roles"),
        &grant,
    ));
    let approval = str_member(&reply, "approval").unwrap();
    let rows = |login: &WebLogin| -> Vec<Value> {
        let v = body_json(once(&w, login, GET, "/admin/approvals", &Value::Null));
        v.as_object()
            .and_then(|o| o.get("approvals"))
            .and_then(Value::as_array)
            .unwrap()
            .iter()
            .filter(|r| str_member(r, "approval").as_deref() == Some(approval.as_str()))
            .cloned()
            .collect()
    };
    let seen = rows(&plain);
    assert_eq!(seen.len(), 1, "{seen:?}");
    let row = &seen[0];
    assert_eq!(
        str_member(row, "approval").as_deref(),
        Some(approval.as_str())
    );
    assert_eq!(str_member(row, "programme"), Some(p.to_string()));
    assert_eq!(str_member(row, "role").as_deref(), Some("Auditor"));
    assert_eq!(str_member(row, "start"), Some(start.to_string()));
    assert_eq!(str_member(row, "end"), Some(end.to_string()));
    assert_eq!(
        row.as_object().and_then(|o| o.get("approvable")),
        Some(&Value::Bool(true))
    );
    let own = rows(&builder);
    assert_eq!(
        own[0].as_object().and_then(|o| o.get("approvable")),
        Some(&Value::Bool(false)),
        "the grantee never approves their own grant"
    );
    let path = format!("/admin/approvals/{approval}");
    assert_eq!(
        observed(&stepped(&w, &builder, POST, &path, &obj(vec![]))),
        refused("SoD-07"),
        "SoD-07: the grantee is no second admin"
    );
    let r = stepped(&w, &plain, POST, &path, &obj(vec![]));
    assert_eq!(observed(&r), Observed::Completed, "{r:?}");
    assert!(
        rows(&plain).is_empty(),
        "an approved grant leaves the inbox"
    );
    assert_eq!(
        observed(&stepped(&w, &plain, POST, &path, &obj(vec![]))),
        refused("SoD-07"),
        "an approval is given once"
    );
}

/// SoD-07, I-78: an approval needs a fresh step-up before anything is
/// looked up, an id that names no pending grant is refused under `Input`
/// after it, a caller outside the admin set is refused as an actor, and a
/// sole tenant admin has no second admin to be.
#[test]
fn sod_07_i78_approve_self_grant_refusals() {
    let w = active();
    let plain = w.ports.sessions.login(ADMIN_PLAIN, LoginMethod::Passkey);
    let unknown = "/admin/approvals/987654321";
    assert_eq!(
        observed(&once(&w, &plain, POST, unknown, &obj(vec![]))),
        Observed::StepUpRequired
    );
    assert_eq!(
        observed(&stepped(&w, &plain, POST, unknown, &obj(vec![]))),
        Observed::NotFound("Input".to_owned())
    );
    let pm = w.ports.sessions.login(PM, LoginMethod::Passkey);
    assert_eq!(
        observed(&stepped(&w, &pm, POST, unknown, &obj(vec![]))),
        refused("actor")
    );
    let sole = world(
        StateProfile::Onboarding(OnboardStep::Administrators),
        Variant::Sole,
    );
    let login = sole.ports.sessions.login(ADMIN_SOLE, LoginMethod::Passkey);
    assert_eq!(
        observed(&stepped(&sole, &login, POST, unknown, &obj(vec![]))),
        refused("SoD-07")
    );
}

/// SoD-07: a grant to another account is no self-grant, so it binds at
/// once and leaves no pending record.
#[test]
fn sod_07_only_a_self_grant_awaits_approval() {
    let w = active();
    let p = w.targets.programme.unwrap().raw();
    let pending = |w: &Built| {
        w.ports
            .engine
            .state()
            .tenant
            .state()
            .map(|ts| ts.pending_self_grants().len())
    };
    let before = pending(&w);
    let builder = w.ports.sessions.login(ADMIN_BUILDER, LoginMethod::Passkey);
    let other = obj(vec![
        ("account", dec(UNBOUND.raw())),
        ("role", s("Auditor")),
        ("start", dec(u128::try_from(w.now).unwrap())),
    ]);
    let reply = body_json(stepped(
        &w,
        &builder,
        POST,
        &format!("/programmes/{p}/roles"),
        &other,
    ));
    assert_eq!(str_member(&reply, "approval"), None, "{reply:?}");
    assert_eq!(pending(&w), before);
}
