//! Review reproducers for lane m4tenant (spec fidelity lens). Each test
//! fails against the lane's working tree and passes once its defect is
//! fixed. The worlds are those of `m4wt_tenant_dispatch.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_api_core::decode::{Method, decode_route};
use fstp_api_core::meta::Scope;
use fstp_api_core::port::LoginMethod;
use fstp_api_core::{ApiError, ErrorCode, Op, OpResult};
use fstp_api_testkit::fake::cell::{Class, class};
use fstp_api_testkit::fake::fixture::{self, ADMIN, AGENT, OWNER, World};
use fstp_api_testkit::fake::requests;
use fstp_api_testkit::fake::{FakeCell, WebLogin};
use fstp_domain::id::AccountId;
use fstp_domain_testkit::vault::{GroundTruth, IdentityTag};
use fstp_engine::{Record, record_from_json_at};
use fstp_json::{Object, ToJson, Value, parse};
use fstp_ledger::{MemStore, RecordStore};
use fstp_tenant::{InvitationId, TenantRecord, TokenDigest, encode_record};

const A1: AccountId = AccountId::from_raw(0x0a01);
const A2: AccountId = AccountId::from_raw(0x0a02);
const INVITATION: InvitationId = InvitationId::from_raw(0x1a2);
const CONTACT: &str = "Synthetic data protection contact, e2e test tenant.";

fn provisioned(first_admin: AccountId, cell: &str) -> Value {
    let mut o = Object::new();
    o.insert("cell", Value::from(cell));
    o.insert("first_admin", Value::from(first_admin.raw().to_string()));
    o.insert("kind", Value::from("TenantProvisioned"));
    Value::Object(o)
}

/// The engine record of a tenant inner value, under the engine's tenant
/// member (fix round 1 moved it from `tenant` to `onboarding`).
fn record(inner: Value) -> Record {
    let mut o = Object::new();
    o.insert(fstp_engine::EnvelopeKind::Tenant.member(), inner);
    record_from_json_at(1, &Value::Object(o)).unwrap()
}

fn tenant(r: &TenantRecord) -> Record {
    record(parse(&encode_record(r).unwrap()).unwrap())
}

fn append(store: &mut MemStore<Record>, at: i64, n: u8, records: Vec<Record>) {
    let head = store.head();
    let mut command = [0x7e; 16];
    command[15] = n;
    store.append(head, at, command, records).unwrap();
}

/// A self-hosted cell whose first admin is A1. When `with_a2`, A2 joined
/// through the ledger records only and is verified. The attested set of
/// the M3 port names A1 alone.
fn fresh(with_a2: bool) -> FakeCell {
    let mut truth = GroundTruth::new();
    for (a, n) in [(A1, 0xa1), (A2, 0xa2)] {
        truth.set_identity(a, IdentityTag::new(n));
        truth.verify(a);
    }
    let mut store = MemStore::new();
    append(
        &mut store,
        1_000_000,
        1,
        vec![record(provisioned(A1, "self_hosted"))],
    );
    if with_a2 {
        append(
            &mut store,
            1_000_000,
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
            1_000_000,
            3,
            vec![tenant(&TenantRecord::AdminAdded {
                account: A2,
                invitation: INVITATION,
            })],
        );
    }
    let world = World {
        store,
        truth,
        start: fixture::START,
        admins: [A1].into_iter().collect(),
    };
    FakeCell::from_world(&world).unwrap()
}

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

fn done(r: Result<OpResult, ApiError>, what: &str) -> Value {
    match r {
        Ok(OpResult::Done { body, .. }) => body.to_json(),
        other => panic!("{what}: {other:?}"),
    }
}

fn text<'a>(v: &'a Value, k: &str) -> &'a str {
    v.as_object()
        .and_then(|o| o.get(k))
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("no text member {k} in {v:?}"))
}

fn login(c: &FakeCell, a: AccountId) -> WebLogin {
    c.login(a, LoginMethod::Passkey)
}

fn base(c: &FakeCell, l: &WebLogin, step: &str) -> String {
    text(&done(c.web(l, get_step(step)), "get_step"), "revision").to_owned()
}

fn save_validated(c: &FakeCell, l: &WebLogin, step: &str, values: &str) {
    let b = base(c, l, step);
    let v = done(c.web(l, save_step(step, &b, values)), step);
    assert_eq!(text(&v, "outcome"), "validated", "{step}: {v:?}");
}

fn organisation() -> String {
    format!(
        r#"{{"data_protection_contact":"{CONTACT}","signatories":["{}"]}}"#,
        A1.raw()
    )
}

/// Q31 A (design 3.5: "The admin set is recorded in the cell ledger"):
/// an admin who joined through the ledger runs a tenant command. The
/// tenant arm's own `admin()` also demands the attested set of the M3
/// port, so A2 is refused `R-AC-01`.
#[test]
fn review_q31_ledger_admin_runs_a_tenant_command() {
    let c = fresh(true);
    let l1 = login(&c, A1);
    let l2 = login(&c, A2);
    let b = base(&c, &l1, "organisation");
    let r = c.web(&l2, save_step("organisation", &b, &organisation()));
    assert!(
        matches!(r, Ok(OpResult::Done { .. })),
        "Q31 A: a ledger admin's step save was refused: {r:?}"
    );
}

/// Design 3.5: "The Inference step also records an
/// `InferenceConfigRecorded` entry ... `call.publish` takes `config` and
/// `config_model` from this record." A validated Inference save leaves
/// the tenant part with no inference record, so publication can only
/// read the port's side state.
#[test]
fn review_inference_step_records_the_inference_config() {
    let c = fresh(false);
    let l = login(&c, A1);
    save_validated(&c, &l, "organisation", &organisation());
    save_validated(&c, &l, "branding", r#"{"package":"default"}"#);
    save_validated(
        &c,
        &l,
        "domains_and_email",
        r#"{"sending_domain":"mail.e2e.invalid"}"#,
    );
    save_validated(
        &c,
        &l,
        "identity",
        r#"{"p18":["document_upload","eudi_wallet"],"p45":"tenant_registration"}"#,
    );
    save_validated(
        &c,
        &l,
        "inference",
        r#"{"fallbacks":[],"primary":"placeholder-model","provider":"placeholder"}"#,
    );
    let state = c.ports.engine.state();
    let ts = state.tenant.state().unwrap();
    assert!(
        ts.publication_config().is_some(),
        "design 3.5: no InferenceConfigRecorded after a validated Inference step"
    );
}

/// Q22 ("The cell keeps the data protection contact"), R-TN-01 ("save
/// and return at any point"): the contact text is kept only in the API
/// core's memory, never through the cell's text store. A restarted core
/// then fails every read of the Organisation step.
#[test]
fn review_contact_text_is_kept_by_the_cell_text_store() {
    let c = fresh(false);
    let l = login(&c, A1);
    save_validated(&c, &l, "organisation", &organisation());
    assert!(
        !c.ports.texts.is_empty(),
        "Q22: the data protection contact reached no durable text store"
    );
}

/// Design 3.5 ("Every change is a ledger record"), P-74: the ledger's P-74
/// governs the MCP server. After `tenant.set_mcp` disables it, the
/// settings read shows it off, yet a tool call is still served because
/// dispatch reads `ports.mcp_settings()`.
#[test]
fn review_p74_ledger_setting_governs_mcp_calls() {
    let mut world = fixture::pending_world().unwrap();
    let at = fstp_domain_testkit::r#gen::roster::T0.micros();
    append(
        &mut world.store,
        at,
        1,
        vec![record(provisioned(ADMIN, "saas"))],
    );
    let c = FakeCell::from_world(&world).unwrap();
    let l = login(&c, ADMIN);
    let op = || {
        decode_route(
            Method::Put,
            "/admin/settings/mcp",
            br#"{"value":{"enabled":false,"public_tools":true,"roles":null}}"#,
        )
    };
    let r = match c.web(&l, op()) {
        Ok(OpResult::StepUpRequired(ch)) => {
            c.ports.step_up.approve(l.session, ch.action).unwrap();
            c.web(&l, op())
        }
        other => other,
    };
    let _ = done(r, "tenant.set_mcp");
    let token = c.token(OWNER, AGENT, [Scope::CallsRead], LoginMethod::Passkey);
    let after = c.mcp(&token, requests::list_open_calls_mcp());
    assert_eq!(class(&after), Class::Refused(ErrorCode::P74), "{after:?}");
}
