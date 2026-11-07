//! `tenant.terminology.set` through the one dispatch (M9 design section 2.2,
//! lane T1; I-72, I-78, I-85, R-LG-03, O-55).

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
const OUTSIDER: AccountId = AccountId::from_raw(0x0a99);

const GOOD: &str = r#"{"labels":{"vocab.call":"Subgrant call"},"voyage_on":true}"#;

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

fn set(body: &str) -> Result<Op, ApiError> {
    decode_route(Method::Put, "/admin/terminology", body.as_bytes())
}

fn terminology(c: &FakeCell) -> Option<(Vec<(String, String)>, bool)> {
    let s = c.ports.engine.state();
    s.tenant.state().and_then(|t| {
        t.terminology().map(|x| {
            (
                x.labels
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect(),
                x.voyage_on,
            )
        })
    })
}

/// I-78, R-LG-03: the set asks for a step-up and appends nothing before it.
/// With the proof it records the labels and the Voyage switch.
#[test]
fn i78_terminology_set_needs_a_step_up() {
    let c = cell();
    let l = c.login(A1, LoginMethod::Passkey);
    let ch = match c.web(&l, set(GOOD)) {
        Ok(OpResult::StepUpRequired(ch)) => ch,
        other => panic!("I-78: set without a proof: {other:?}"),
    };
    assert!(c.ports.engine.appended().is_empty());
    c.ports.step_up.approve(l.session, ch.action).unwrap();
    match c.web(&l, set(GOOD)) {
        Ok(OpResult::Done { .. }) => {}
        other => panic!("set with its proof: {other:?}"),
    }
    assert_eq!(c.ports.engine.appended().len(), 1);
    assert_eq!(
        terminology(&c),
        Some((
            vec![("vocab.call".to_owned(), "Subgrant call".to_owned())],
            true
        ))
    );
}

/// I-72: a body that names approved wording, a key outside the closed list,
/// changed fixed wording or markup is refused, and nothing is recorded. An
/// outsider is refused as an actor.
#[test]
fn i72_terminology_set_refuses_approved_keys_and_fixed_wording() {
    let c = cell();
    for body in [
        r#"{"labels":{"contract.body":"x"},"voyage_on":false}"#,
        r#"{"labels":{"footer.privacy_notice":"x"},"voyage_on":false}"#,
        r#"{"labels":{"journey.node.declined":"Sunk"},"voyage_on":false}"#,
        r#"{"labels":{"vocab.call":"<b>x</b>"},"voyage_on":false}"#,
        r#"{"labels":{"vocab.call":"x"}}"#,
        r#"{"labels":{"vocab.call":"x"},"voyage_on":false,"extra":1}"#,
    ] {
        assert!(set(body).is_err(), "I-72: {body}");
    }
    assert!(c.ports.engine.appended().is_empty());
    let o = c.login(OUTSIDER, LoginMethod::Passkey);
    assert!(matches!(
        c.web(&o, set(GOOD)),
        Err(ApiError::Refused { .. })
    ));
    assert_eq!(terminology(&c), None);
}
