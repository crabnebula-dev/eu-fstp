//! Tenant copies of funder profiles through the one dispatch (Daniel,
//! 2026-11-15 late: "The platform ships versioned profiles. A tenant may
//! copy one into a tenant-owned profile and edit it."; R-RP-01, I-44,
//! I-78, R-LG-03).

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

const COPY: &str = r#"{"from_profile":"horizon-europe","from_version":"1","id":"tenant-he"}"#;

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

fn copy(body: &str) -> Result<Op, ApiError> {
    decode_route(
        Method::Post,
        "/admin/funder-profiles/copies",
        body.as_bytes(),
    )
}

fn save(body: &str) -> Result<Op, ApiError> {
    decode_route(Method::Put, "/admin/funder-profiles", body.as_bytes())
}

/// Runs `op` as A1 with a fresh step-up, and gives its outcome.
fn stepped(c: &FakeCell, op: impl Fn() -> Result<Op, ApiError>) -> Result<OpResult, ApiError> {
    let l = c.login(A1, LoginMethod::Passkey);
    match c.web(&l, op()) {
        Ok(OpResult::StepUpRequired(ch)) => {
            c.ports.step_up.approve(l.session, ch.action).unwrap();
            c.web(&l, op())
        }
        other => other,
    }
}

/// One recorded version: id, version and source.
type Version = (String, u16, Option<(String, u16)>);

fn versions(c: &FakeCell) -> Vec<Version> {
    let s = c.ports.engine.state();
    s.tenant
        .state()
        .map(|t| {
            t.funder_profiles()
                .map(|p| (p.id.clone(), p.version, p.source.clone()))
                .collect()
        })
        .unwrap_or_default()
}

/// R-RP-01, I-78: a copy of the shipped profile becomes version 1 of a
/// tenant profile, naming its source, after a step-up. An edit becomes
/// version 2. Each version names its own id and version, with its refs
/// moved under its id; the cell parsed it before it was recorded.
#[test]
fn r_rp_01_copy_then_edit_a_tenant_profile() {
    let c = cell();
    let l = c.login(A1, LoginMethod::Passkey);
    assert!(matches!(
        c.web(&l, copy(COPY)),
        Ok(OpResult::StepUpRequired(_))
    ));
    assert!(
        c.ports.engine.appended().is_empty(),
        "I-78: nothing before the proof"
    );
    assert!(matches!(
        stepped(&c, || copy(COPY)),
        Ok(OpResult::Done { .. })
    ));
    let v1 = {
        let s = c.ports.engine.state();
        s.tenant
            .state()
            .unwrap()
            .funder_profile("tenant-he", 1)
            .unwrap()
            .text
            .clone()
    };
    assert!(
        v1.contains("\"id\":\"tenant-he\"") && v1.contains("\"version\":1"),
        "{v1}"
    );
    assert!(
        v1.contains("tenant-he/") && !v1.contains("horizon-europe/"),
        "{v1}"
    );
    let edited = v1.replace("Call budget", "Budget of the call");
    let body = format!("{{\"id\":\"tenant-he\",\"profile\":{edited}}}");
    assert!(matches!(
        stepped(&c, || save(&body)),
        Ok(OpResult::Done { .. })
    ));
    assert_eq!(
        versions(&c),
        vec![
            (
                "tenant-he".to_owned(),
                1,
                Some(("horizon-europe".to_owned(), 1))
            ),
            ("tenant-he".to_owned(), 2, None),
        ]
    );
}

/// R-RP-01, I-44: a shipped id, a profile field that is no ledger fold,
/// a missing source and an outsider are refused, and nothing is recorded.
#[test]
fn r_rp_01_tenant_profile_refusals() {
    let c = cell();
    for body in [
        r#"{"from_profile":"horizon-europe","from_version":"1","id":"horizon-europe"}"#,
        r#"{"from_profile":"horizon-europe","from_version":"01","id":"tenant-he"}"#,
        r#"{"from_profile":"horizon-europe","id":"tenant-he"}"#,
    ] {
        assert!(
            copy(body).is_err() || !matches!(stepped(&c, || copy(body)), Ok(OpResult::Done { .. })),
            "{body}"
        );
    }
    let missing = r#"{"from_profile":"horizon-europe","from_version":"9","id":"tenant-he"}"#;
    assert!(!matches!(
        stepped(&c, || copy(missing)),
        Ok(OpResult::Done { .. })
    ));
    let he = std::str::from_utf8(include_bytes!(
        "../../fstp-report/profiles/horizon-europe/profile.v1.json"
    ))
    .unwrap();
    let literal = he.replacen("\"figure\": \"call_budget\"", "\"figure\": 1000", 1);
    let body = format!("{{\"id\":\"tenant-he\",\"profile\":{literal}}}");
    assert!(
        !matches!(stepped(&c, || save(&body)), Ok(OpResult::Done { .. })),
        "I-44"
    );
    assert!(versions(&c).is_empty());
    let o = c.login(OUTSIDER, LoginMethod::Passkey);
    assert!(matches!(
        c.web(&o, copy(COPY)),
        Err(ApiError::Refused { .. })
    ));
    assert!(versions(&c).is_empty());
}
