//! `tenant.branding.check` and `tenant.branding.set` through the one
//! dispatch (M9 design section 2.2, lane B1; I-68, I-70, I-78, R-LG-03).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code asserts on known-good values"
)]

use fstp_api_core::decode::{Method, decode_route};
use fstp_api_core::port::LoginMethod;
use fstp_api_core::{ApiError, Op, OpResult};
use fstp_api_testkit::fake::FakeCell;
use fstp_api_testkit::fake::fixture::{self, World};
use fstp_domain::id::AccountId;
use fstp_domain_testkit::vault::{GroundTruth, IdentityTag};
use fstp_engine::{Record, record_from_json_at};
use fstp_json::{Object, ToJson, Value};
use fstp_ledger::{MemStore, RecordStore};

const A1: AccountId = AccountId::from_raw(0x0a01);
const OUTSIDER: AccountId = AccountId::from_raw(0x0a99);

const PLATFORM: &str = r##"{"dark":{"brand":"#3b82f6","brand-hover":"#60a5fa","brand-text":"#93c5fd","focus":"#60a5fa","on-brand":"#0f172a"},"light":{"brand":"#2563eb","brand-hover":"#1d4ed8","brand-text":"#1e40af","focus":"#2563eb","on-brand":"#ffffff"},"name":"Harbour Fund","typography":"system"}"##;

/// A SaaS cell whose only tenant admin is A1.
fn cell() -> FakeCell {
    let mut truth = GroundTruth::new();
    truth.set_identity(A1, IdentityTag::new(0xa1));
    truth.set_identity(OUTSIDER, IdentityTag::new(0xa9));
    truth.verify(A1);
    let mut o = Object::new();
    o.insert("cell", Value::from("saas"));
    o.insert("first_admin", Value::from(A1.raw().to_string()));
    o.insert("kind", Value::from("TenantProvisioned"));
    let mut env = Object::new();
    env.insert("onboarding", Value::Object(o));
    let rec: Record = record_from_json_at(1, &Value::Object(env)).unwrap();
    let mut store = MemStore::new();
    let head = store.head();
    store
        .append(head, 1_000_000, [0x7e; 16], vec![rec])
        .unwrap();
    let world = World {
        store,
        truth,
        start: fixture::START,
        admins: [A1].into_iter().collect(),
    };
    FakeCell::from_world(&world).unwrap()
}

fn check(tokens: &str) -> Result<Op, ApiError> {
    let body = format!(r#"{{"tokens":{tokens}}}"#);
    decode_route(Method::Post, "/admin/branding/check", body.as_bytes())
}

fn set(tokens: &str) -> Result<Op, ApiError> {
    let body = format!(r#"{{"tokens":{tokens}}}"#);
    decode_route(Method::Put, "/admin/branding", body.as_bytes())
}

fn failing() -> String {
    PLATFORM.replace(
        "#2563eb\",\"brand-hover\":\"#1d4ed8",
        "#ffeb3b\",\"brand-hover\":\"#1d4ed8",
    )
}

fn branding(c: &FakeCell) -> Option<String> {
    let s = c.ports.engine.state();
    s.tenant
        .state()
        .and_then(|t| t.branding().map(|(b, _)| fstp_brand::canonical(b)))
}

/// I-70: the check lists the failing pairs by name and saves nothing.
#[test]
fn i70_branding_check_lists_failing_pairs_and_saves_nothing() {
    let c = cell();
    let l = c.login(A1, LoginMethod::Passkey);
    let ok = match c.web(&l, check(PLATFORM)) {
        Ok(OpResult::Done { body, .. }) => body.to_json(),
        other => panic!("check: {other:?}"),
    };
    assert_eq!(ok.get("accepted"), Some(&Value::Bool(true)));
    let bad = match c.web(&l, check(&failing())) {
        Ok(OpResult::Done { body, .. }) => body.to_json(),
        other => panic!("check: {other:?}"),
    };
    assert_eq!(bad.get("accepted"), Some(&Value::Bool(false)));
    let names: Vec<&str> = bad
        .get("failing")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    assert_eq!(names, ["light.on-brand/brand"]);
    assert!(c.ports.engine.appended().is_empty());
    assert_eq!(branding(&c), None);
}

/// I-78, R-LG-03: the set asks for a step-up bound to its digest and
/// appends nothing before it. With the proof it records the tokens.
#[test]
fn i78_branding_set_needs_a_step_up() {
    let c = cell();
    let l = c.login(A1, LoginMethod::Passkey);
    let ch = match c.web(&l, set(PLATFORM)) {
        Ok(OpResult::StepUpRequired(ch)) => ch,
        other => panic!("I-78: set without a proof: {other:?}"),
    };
    assert!(c.ports.engine.appended().is_empty());
    c.ports.step_up.approve(l.session, ch.action).unwrap();
    match c.web(&l, set(PLATFORM)) {
        Ok(OpResult::Done { .. }) => {}
        other => panic!("set with its proof: {other:?}"),
    }
    assert_eq!(c.ports.engine.appended().len(), 1);
    assert_eq!(branding(&c).as_deref(), Some(PLATFORM));
}

/// I-70: a set with a failing pair is refused under I-70 before any
/// step-up, and nothing is recorded. An outsider is refused as an actor.
#[test]
fn i70_branding_set_with_a_failing_pair_is_refused() {
    let c = cell();
    let l = c.login(A1, LoginMethod::Passkey);
    match c.web(&l, set(&failing())) {
        Err(ApiError::Refused { rule, .. }) => assert_eq!(rule, "I-70"),
        other => panic!("I-70: {other:?}"),
    }
    assert!(c.ports.engine.appended().is_empty());
    let o = c.login(OUTSIDER, LoginMethod::Passkey);
    assert!(matches!(
        c.web(&o, set(PLATFORM)),
        Err(ApiError::Refused { .. })
    ));
    assert_eq!(branding(&c), None);
}
