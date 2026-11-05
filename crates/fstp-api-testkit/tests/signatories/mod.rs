//! Shared parts of the signatory and organisation activation tests (lane
//! m4/roles; SA-01, SA-02, SoD-07, SoD-14 to SoD-18, NOTE 5, I-78).
//!
//! Every test drives the one dispatch of a cell of fake ports
//! ([`FakeCell`]) through `decode_route`, as the onboarding pages do. The
//! world is a fresh self-hosted cell, built as in
//! `m4wt_tenant_dispatch.rs`: A1 is the first tenant admin, and A2 joined
//! through `AdminInvited` and `AdminAdded`. A1, A2 and S1 are verified,
//! and S2 is not.
//!
//! # The wire this lane pins (interim, pending Daniel)
//!
//! The spec names the rules but no routes. These follow the tenant routes
//! of design section 3.5 and SA-01 backend item 7.
//!
//! - `GET /admin/signatories` (`tenant.list_signatories`): `{"signatories":
//!   [{"account", "role", "handle"}]}`. A row names no programme (NOTE 5).
//! - `POST /admin/signatories` with `{"account", "role"}`
//!   (`tenant.grant_signatory`). High-risk (I-78).
//! - `DELETE /admin/signatories/{role}/{account}`
//!   (`tenant.end_signatory`). High-risk (I-78).
//! - `GET /admin/activation` (`tenant.get_activation`): `{"state",
//!   "request", "requested_by", "approved_by"}`. The state is
//!   `not_requested`, `requested` or `active`.
//! - `POST /admin/activation` with `{}` (`tenant.request_activation`).
//! - `POST /admin/activation/approval` with `{"request"}`
//!   (`tenant.approve_activation`). The request is the id the activation
//!   read shows.
//!
//! Role keys are the wire names of `role_wire_name`:
//! `financial_signatory` and `legal_signatory`. Every refusal names its
//! rule: `SoD-07`, `SoD-14`, `SoD-15`, `SoD-17` or `SoD-18`.
//!
//! # Readings this lane pins (interim, pending Daniel)
//!
//! - SoD-14 and SoD-15 are checked at the request and again at the
//!   approval, against the holders at that instant. A refusal names the
//!   missing role's rule, even where the Administrators step is not
//!   validated for the same reason.
//! - The Administrators step validates only with at least one holder of
//!   each signatory role (`programme-creator.md`, onboarding table).
//! - An open request stays open until it is approved. The approval names
//!   it, and an approval naming another request is refused.
//! - The organisation is active from the approval on. A request that is
//!   not approved leaves it not active, so SoD-17 does not bind yet.

#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "a shared test module: each test binary uses part of it"
)]

use std::collections::BTreeSet;

use fstp_api_core::decode::{Method, decode_route};
use fstp_api_core::port::LoginMethod;
use fstp_api_core::{ApiError, ErrorCode, Op, OpResult};
use fstp_api_testkit::fake::cell::{Class, class};
use fstp_api_testkit::fake::fixture::{self, World};
use fstp_api_testkit::fake::{FakeCell, WebLogin};
use fstp_domain::id::AccountId;
use fstp_domain_testkit::vault::{GroundTruth, IdentityTag};
use fstp_engine::{Record, record_from_json_at};
use fstp_json::{Object, ToJson, Value, parse};
use fstp_ledger::{MemStore, RecordStore};
use fstp_tenant::{InvitationId, TenantRecord, TokenDigest, encode_record};

/// The first tenant admin, who requests activation.
pub(crate) const A1: AccountId = AccountId::from_raw(0x0a01);
/// The second tenant admin, who approves it.
pub(crate) const A2: AccountId = AccountId::from_raw(0x0a02);
/// A verified account outside the admin set, who signs for the tenant.
pub(crate) const S1: AccountId = AccountId::from_raw(0x0b01);
/// An unverified account outside the admin set.
pub(crate) const S2: AccountId = AccountId::from_raw(0x0b02);
/// An account outside the admin set that holds no role.
pub(crate) const OUTSIDER: AccountId = AccountId::from_raw(0x0a99);
/// The invitation A2 joined through.
const INVITATION: InvitationId = InvitationId::from_raw(0x1a2);
/// The data protection contact the Organisation step saves.
const CONTACT: &str = "Synthetic data protection contact, e2e test tenant.";

/// The Financial signatory key.
pub(crate) const FINANCIAL: &str = "financial_signatory";
/// The Legal signatory key.
pub(crate) const LEGAL: &str = "legal_signatory";
/// Both signatory keys.
pub(crate) const BOTH: [&str; 2] = [FINANCIAL, LEGAL];

/// The rule a missing holder of `role` breaks.
pub(crate) fn missing_rule(role: &str) -> &'static str {
    if role == FINANCIAL {
        "SoD-14"
    } else {
        "SoD-15"
    }
}

// ---------------------------------------------------------------------------
// The world
// ---------------------------------------------------------------------------

fn provisioned(first_admin: AccountId) -> Value {
    let mut o = Object::new();
    o.insert("cell", Value::from("self_hosted"));
    o.insert("first_admin", Value::from(first_admin.raw().to_string()));
    o.insert("kind", Value::from("TenantProvisioned"));
    Value::Object(o)
}

fn record(inner: Value) -> Record {
    let mut o = Object::new();
    o.insert("onboarding", inner);
    let stored = Value::Object(o);
    record_from_json_at(1, &stored).unwrap_or_else(|e| {
        panic!("I-23: the engine does not decode a stored tenant envelope ({e:?}): {stored:?}")
    })
}

fn tenant(r: &TenantRecord) -> Record {
    let bytes = encode_record(r).expect("the tenant codec encodes every record");
    record(parse(&bytes).expect("the tenant codec writes JSON"))
}

fn append(store: &mut MemStore<Record>, n: u8, records: Vec<Record>) {
    let head = store.head();
    let mut command = [0x7e; 16];
    command[15] = n;
    store
        .append(head, 1_000_000, command, records)
        .unwrap_or_else(|e| panic!("the setup entry {n} was refused: {e:?}"));
}

/// A fresh self-hosted cell with A1 and A2 as verified tenant admins, S1
/// verified and S2 not. No step is saved and no signatory role is held.
pub(crate) fn fresh() -> FakeCell {
    let mut truth = GroundTruth::new();
    for (a, n) in [
        (A1, 0xa1),
        (A2, 0xa2),
        (S1, 0xb1),
        (S2, 0xb2),
        (OUTSIDER, 0xa9),
    ] {
        truth.set_identity(a, IdentityTag::new(n));
    }
    for a in [A1, A2, S1, OUTSIDER] {
        truth.verify(a);
    }
    let mut store = MemStore::new();
    append(&mut store, 1, vec![record(provisioned(A1))]);
    append(
        &mut store,
        2,
        vec![tenant(&TenantRecord::AdminInvited {
            invitation: INVITATION,
            invitee: A2,
            token_digest: TokenDigest::from_bytes([0xd2; 32]),
            by: A1,
        })],
    );
    append(
        &mut store,
        3,
        vec![tenant(&TenantRecord::AdminAdded {
            account: A2,
            invitation: INVITATION,
        })],
    );
    let world = World {
        store,
        truth,
        start: fixture::START,
        admins: [A1].into_iter().collect(),
    };
    FakeCell::from_world(&world).unwrap_or_else(|e| panic!("the fake cell: {e}"))
}

/// A web login of `a` with a passkey.
pub(crate) fn login(c: &FakeCell, a: AccountId) -> WebLogin {
    c.login(a, LoginMethod::Passkey)
}

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

/// A request builder, so a test can send the same request again.
pub(crate) type OpFn = Box<dyn Fn() -> Result<Op, ApiError>>;

fn get_step(step: &str) -> Result<Op, ApiError> {
    decode_route(Method::Get, &format!("/admin/onboarding/{step}"), b"")
}

fn save_step(step: &str, base: &str, values: &str) -> Result<Op, ApiError> {
    let body = format!(r#"{{"base":"{base}","values":{values}}}"#);
    decode_route(
        Method::Put,
        &format!("/admin/onboarding/{step}"),
        body.as_bytes(),
    )
}

fn set(path: &str, value: &str) -> Result<Op, ApiError> {
    let body = format!(r#"{{"value":{value}}}"#);
    decode_route(Method::Put, path, body.as_bytes())
}

/// `tenant.complete`, the single-step completion of before SoD-18.
pub(crate) fn complete() -> Result<Op, ApiError> {
    decode_route(Method::Post, "/admin/onboarding/complete", b"{}")
}

/// `tenant.list_signatories`.
pub(crate) fn list_signatories() -> Result<Op, ApiError> {
    decode_route(Method::Get, "/admin/signatories", b"")
}

/// `tenant.grant_signatory` of `role` to `account`.
pub(crate) fn grant(account: AccountId, role: &str) -> Result<Op, ApiError> {
    let body = format!(r#"{{"account":"{}","role":"{role}"}}"#, account.raw());
    decode_route(Method::Post, "/admin/signatories", body.as_bytes())
}

/// `tenant.end_signatory` of `account`'s binding of `role`.
pub(crate) fn end(account: AccountId, role: &str) -> Result<Op, ApiError> {
    decode_route(
        Method::Delete,
        &format!("/admin/signatories/{role}/{}", account.raw()),
        b"",
    )
}

/// `tenant.get_activation`.
pub(crate) fn get_activation() -> Result<Op, ApiError> {
    decode_route(Method::Get, "/admin/activation", b"")
}

/// `tenant.request_activation`.
pub(crate) fn request_activation() -> Result<Op, ApiError> {
    decode_route(Method::Post, "/admin/activation", b"{}")
}

/// `tenant.approve_activation` of the request `request`.
pub(crate) fn approve_activation(request: &str) -> Result<Op, ApiError> {
    let body = format!(r#"{{"request":"{request}"}}"#);
    decode_route(Method::Post, "/admin/activation/approval", body.as_bytes())
}

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

/// The JSON body of a completed call. Any other result fails the test.
pub(crate) fn done(r: Result<OpResult, ApiError>, what: &str) -> Value {
    match r {
        Ok(OpResult::Done { body, .. }) => body.to_json(),
        Err(ApiError::NotImplemented(m)) => panic!("{what}: not implemented: {m}"),
        other => panic!("{what}: {other:?}"),
    }
}

/// The member `k` of `v`, or `Null` when absent.
pub(crate) fn member(v: &Value, k: &str) -> Value {
    v.as_object()
        .and_then(|o| o.get(k))
        .cloned()
        .unwrap_or(Value::Null)
}

/// The text member `k` of `v`. Any other member fails the test.
pub(crate) fn text(v: &Value, k: &str) -> String {
    match member(v, k) {
        Value::String(s) => s,
        other => panic!("member {k} is not text in {v:?}: {other:?}"),
    }
}

/// Asserts that `r` is a refusal that names `rule`. A refusal of the
/// route itself fails the test: the operation does not exist yet.
pub(crate) fn assert_rule(r: &Result<OpResult, ApiError>, rule: &str, what: &str) {
    match r {
        Err(ApiError::Refused { rule: got, .. }) if *got == rule => {}
        Err(ApiError::Refused { rule: "route", .. }) => {
            panic!("{what}: the route does not exist: {r:?}")
        }
        other => panic!("{what}: wanted a refusal naming {rule}, got {other:?}"),
    }
}

/// Asserts that `r` is a refusal of an existing operation, whatever rule
/// it names.
pub(crate) fn assert_refused(r: &Result<OpResult, ApiError>, what: &str) {
    match r {
        Err(ApiError::Refused { rule: "route", .. }) => {
            panic!("{what}: the route does not exist: {r:?}")
        }
        Err(ApiError::Refused { .. }) => {}
        other => panic!("{what}: wanted a refusal, got {other:?}"),
    }
}

/// How many commands the engine appended.
pub(crate) fn appended(c: &FakeCell) -> usize {
    c.ports.engine.appended().len()
}

/// How many step-up ceremonies were begun.
pub(crate) fn begun(c: &FakeCell) -> usize {
    c.ports.step_up.begun().len()
}

/// Runs `op`, and when it asks for a step-up, completes the ceremony for
/// exactly the challenged digest and sends it again.
pub(crate) fn stepped(
    c: &FakeCell,
    l: &WebLogin,
    op: &dyn Fn() -> Result<Op, ApiError>,
) -> Result<OpResult, ApiError> {
    match c.web(l, op()) {
        Ok(OpResult::StepUpRequired(ch)) => {
            c.ports.step_up.approve(l.session, ch.action).unwrap();
            c.web(l, op())
        }
        other => other,
    }
}

/// Whether `r` completed.
pub(crate) fn completed(r: &Result<OpResult, ApiError>) -> bool {
    class(r) == Class::Done
}

/// Whether `r` asked for a step-up.
pub(crate) fn wants_step_up(r: &Result<OpResult, ApiError>) -> bool {
    class(r) == Class::StepUpRequired
}

/// Whether `r` was refused for a weak login (I-77).
pub(crate) fn weak_login(r: &Result<OpResult, ApiError>) -> bool {
    class(r) == Class::Refused(ErrorCode::LoginStrength)
}

// ---------------------------------------------------------------------------
// Walks
// ---------------------------------------------------------------------------

/// The valid values of each step of a self-hosted walk before
/// Administrators, in order. Payments needs P-20 first.
fn walk_values() -> Vec<(&'static str, String)> {
    vec![
        (
            "organisation",
            format!(
                r#"{{"data_protection_contact":"{CONTACT}","signatories":["{}"]}}"#,
                A1.raw()
            ),
        ),
        ("branding", r#"{"package":"default"}"#.to_owned()),
        (
            "domains_and_email",
            r#"{"sending_domain":"mail.e2e.invalid"}"#.to_owned(),
        ),
        (
            "identity",
            r#"{"p18":["document_upload","eudi_wallet"],"p45":"tenant_registration"}"#.to_owned(),
        ),
        (
            "inference",
            r#"{"fallbacks":[],"primary":"placeholder-model","provider":"placeholder"}"#.to_owned(),
        ),
        (
            "payments",
            r#"{"bank_interface":"not_connected"}"#.to_owned(),
        ),
        (
            "channels",
            r#"{"matrix_homeserver":null,"whatsapp":false}"#.to_owned(),
        ),
    ]
}

/// The step read of `step`.
pub(crate) fn step_view(c: &FakeCell, l: &WebLogin, step: &str) -> Value {
    done(c.web(l, get_step(step)), &format!("tenant.get_step {step}"))
}

/// Saves `step` with `values` against the current revision.
fn save(c: &FakeCell, l: &WebLogin, step: &str, values: &str) -> Value {
    let base = text(&step_view(c, l, step), "revision");
    done(
        c.web(l, save_step(step, &base, values)),
        &format!("the save of {step}"),
    )
}

/// Walks the cell through every step before Administrators as A1,
/// setting P-20 with its step-up before Payments. Each step validates.
pub(crate) fn walk_to_administrators(c: &FakeCell, l: &WebLogin) {
    for (step, values) in walk_values() {
        if step == "payments" {
            let _ = done(
                stepped(c, l, &|| {
                    set("/admin/settings/payment-mode", r#""record_only""#)
                }),
                "P-20 before Payments",
            );
        }
        let v = save(c, l, step, &values);
        assert_eq!(text(&v, "outcome"), "validated", "R-TN-01: {step}: {v:?}");
    }
}

/// Saves the Administrators step with A1 and A2, and returns the save's
/// outcome.
pub(crate) fn save_administrators(c: &FakeCell, l: &WebLogin) -> String {
    let admins = format!(r#"{{"admins":["{}","{}"]}}"#, A1.raw(), A2.raw());
    text(&save(c, l, "administrators", &admins), "outcome")
}

/// Grants `role` to `account` as `l`, with its step-up. It must complete.
pub(crate) fn granted(c: &FakeCell, l: &WebLogin, account: AccountId, role: &str) {
    let _ = done(
        stepped(c, l, &|| grant(account, role)),
        &format!("the grant of {role} to {}", account.raw()),
    );
}

/// Ends `account`'s binding of `role` as `l`, with its step-up.
pub(crate) fn ending(
    c: &FakeCell,
    l: &WebLogin,
    account: AccountId,
    role: &str,
) -> Result<OpResult, ApiError> {
    stepped(c, l, &|| end(account, role))
}

/// A cell walked to Administrators by A1, with `holders` granted by A1
/// and the Administrators step saved. Returns the cell, A1's login and
/// A2's login.
pub(crate) fn onboarded(holders: &[(AccountId, &str)]) -> (FakeCell, WebLogin, WebLogin) {
    let c = fresh();
    let l1 = login(&c, A1);
    let l2 = login(&c, A2);
    walk_to_administrators(&c, &l1);
    for (account, role) in holders {
        granted(&c, &l1, *account, role);
    }
    let _ = save_administrators(&c, &l1);
    (c, l1, l2)
}

/// The activation read as `l`.
pub(crate) fn activation(c: &FakeCell, l: &WebLogin) -> Value {
    done(c.web(l, get_activation()), "tenant.get_activation")
}

/// The activation state as `l` reads it.
pub(crate) fn state(c: &FakeCell, l: &WebLogin) -> String {
    text(&activation(c, l), "state")
}

/// The open request id as `l` reads it.
pub(crate) fn request_id(c: &FakeCell, l: &WebLogin) -> String {
    text(&activation(c, l), "request")
}

/// Requests activation as `l`, with a step-up if one is asked for.
pub(crate) fn request(c: &FakeCell, l: &WebLogin) -> Result<OpResult, ApiError> {
    stepped(c, l, &request_activation)
}

/// Approves the request `id` as `l`, with a step-up if one is asked for.
pub(crate) fn approve(c: &FakeCell, l: &WebLogin, id: &str) -> Result<OpResult, ApiError> {
    let id = id.to_owned();
    stepped(c, l, &move || approve_activation(&id))
}

/// An onboarded cell with `holders`, whose activation A1 requested and A2
/// approved. Returns the cell, A1's login and A2's login.
pub(crate) fn active(holders: &[(AccountId, &str)]) -> (FakeCell, WebLogin, WebLogin) {
    let (c, l1, l2) = onboarded(holders);
    let _ = done(request(&c, &l1), "the activation request by A1");
    let id = request_id(&c, &l1);
    let _ = done(approve(&c, &l2, &id), "the approval by A2");
    assert_eq!(state(&c, &l1), "active", "SoD-18: the approved activation");
    (c, l1, l2)
}

/// The signatory rows as `l` reads them: account and role key.
pub(crate) fn holders(c: &FakeCell, l: &WebLogin) -> BTreeSet<(String, String)> {
    let v = done(c.web(l, list_signatories()), "tenant.list_signatories");
    let Value::Array(rows) = member(&v, "signatories") else {
        panic!("SA-01: the signatory list has no array: {v:?}");
    };
    rows.iter()
        .map(|r| (text(r, "account"), text(r, "role")))
        .collect()
}

/// The signatory row of `account` holding `role`, as the list shows it.
pub(crate) fn row(account: AccountId, role: &str) -> (String, String) {
    (account.raw().to_string(), role.to_owned())
}
