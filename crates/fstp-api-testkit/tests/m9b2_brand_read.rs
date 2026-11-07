//! The current branding read and the CSS it yields (M9 lane B2; I-68).

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
use fstp_json::{Object, Value};
use fstp_ledger::{MemStore, RecordStore};

const A1: AccountId = AccountId::from_raw(0x0a01);

const PLATFORM: &str = r##"{"dark":{"brand":"#3b82f6","brand-hover":"#60a5fa","brand-text":"#93c5fd","focus":"#60a5fa","on-brand":"#0f172a"},"light":{"brand":"#2563eb","brand-hover":"#1d4ed8","brand-text":"#1e40af","focus":"#2563eb","on-brand":"#ffffff"},"name":"Harbour Fund","typography":"system"}"##;

/// A SaaS cell whose only tenant admin is A1.
fn cell() -> FakeCell {
    let mut truth = GroundTruth::new();
    truth.set_identity(A1, IdentityTag::new(0xa1));
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

fn set(tokens: &str) -> Result<Op, ApiError> {
    let body = format!(r#"{{"tokens":{tokens}}}"#);
    decode_route(Method::Put, "/admin/branding", body.as_bytes())
}

/// I-68: with no branding set the core reports none. After a set, it
/// reports the digest of the canonical tokens and exactly the CSS
/// generated from them.
#[test]
fn i68_current_brand_is_the_css_of_the_set_tokens() {
    let c = cell();
    assert_eq!(c.core().brand(), None);
    let l = c.login(A1, LoginMethod::Passkey);
    let ch = match c.web(&l, set(PLATFORM)) {
        Ok(OpResult::StepUpRequired(ch)) => ch,
        other => panic!("set without a proof: {other:?}"),
    };
    c.ports.step_up.approve(l.session, ch.action).unwrap();
    assert!(matches!(
        c.web(&l, set(PLATFORM)),
        Ok(OpResult::Done { .. })
    ));
    let brand = c.core().brand().expect("a brand after the set");
    let tokens = fstp_brand::parse(PLATFORM.as_bytes()).unwrap();
    assert_eq!(brand.css, fstp_brand::css(&tokens));
    assert_eq!(brand.digest.len(), 64);
    assert!(brand.digest.bytes().all(|b| b.is_ascii_hexdigit()));
    assert!(!brand.css.contains("Harbour"));
}
