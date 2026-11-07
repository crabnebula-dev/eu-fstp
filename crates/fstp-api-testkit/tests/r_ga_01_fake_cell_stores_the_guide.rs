//! The fake cell stores the Guide at publication, and the tenant may
//! override the Guide's data protection texts (R-GA-01, I-53, I-78;
//! Daniel's answer of 2026-11-06 in section 15.0 of the M4 design).
//!
//! The ledger is the Guide world of `r_ga_support.rs` before the
//! publication of call 1. A cell of fake ports replays it. Its creator
//! environment reads the programme's artefacts from the SuperSAFE
//! fixture, as the e2e cell does for a programme whose creator draft
//! is not complete. Every value is synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "r_ga_support.rs"]
mod support;

use std::collections::BTreeSet;

use fstp_api_core::decode::{Method, decode_route};
use fstp_api_core::port::LoginMethod;
use fstp_api_core::{ApiError, Credential, ErrorCode, OpResult};
use fstp_api_testkit::fake::FakeCell;
use fstp_api_testkit::fake::fixture::World as CellWorld;
use fstp_domain::command::{Ctx, Via};
use fstp_domain::id::{AccountId, CommandId};
use fstp_domain_testkit::r#gen::roster::{T0, sod_truth};
use fstp_domain_testkit::vault::IdentityTag;
use fstp_engine::{Record, record_from_json_at};
use fstp_json::{Object, ToJson, Value};
use fstp_ledger::{MemStore, RecordStore};
use fstp_tenant::{PLATFORM_DATA_PROTECTION_SUMMARY, PLATFORM_PRIVACY_STATEMENT_URL};
use support::{GUIDE_CALL, GuideEnv, publish_step, world_with};

/// The tenant admin of the cell.
const A1: AccountId = AccountId::from_raw(0x0a01);
/// The tenant's own data protection summary. Synthetic, not a notice.
const TENANT_SUMMARY: &str =
    "Synthetic tenant data protection summary. It is not a privacy notice.";
/// The tenant's own privacy statement address.
const TENANT_PRIVACY: &str = "https://privacy.tenant.example/statement";

/// The interim provisioning record of the tenant part (Q31 A), stored as
/// the engine's tenant member.
fn provisioned() -> Record {
    let mut inner = Object::new();
    inner.insert("cell", Value::from("self_hosted"));
    inner.insert("first_admin", Value::from(A1.raw().to_string()));
    inner.insert("kind", Value::from("TenantProvisioned"));
    let mut o = Object::new();
    o.insert("onboarding", Value::Object(inner));
    record_from_json_at(1, &Value::Object(o)).unwrap_or_else(|e| panic!("{e:?}"))
}

/// A cell over the Guide world before the publication of call 1, with a
/// tenant part whose first admin is A1 when `tenant` holds. Its creator
/// environment reads the SuperSAFE fixture's artefacts.
fn cell(tenant: bool) -> FakeCell {
    let w = world_with(GuideEnv::supersafe(), false);
    let mut store: MemStore<Record> = w.engine.store().clone();
    let mut truth = sod_truth();
    truth.set_identity(A1, IdentityTag::new(0xa1));
    truth.verify(A1);
    if tenant {
        let head = store.head();
        store
            .append(head, T0.micros(), [0x7e; 16], vec![provisioned()])
            .unwrap_or_else(|e| panic!("{e:?}"));
    }
    let world = CellWorld {
        store,
        truth,
        start: T0,
        admins: [A1].into_iter().collect::<BTreeSet<_>>(),
    };
    let c = FakeCell::from_world(&world).unwrap_or_else(|e| panic!("{e}"));
    let fixture = fstp_programme::supersafe_fixture().unwrap_or_else(|e| panic!("{e:?}"));
    c.ports.engine.set_guide_spec(fixture.spec);
    c
}

/// Publishes call 1 on the cell's engine, as its programme manager.
fn publish(c: &FakeCell) -> Result<fstp_ledger::Seq, fstp_engine::ExecError> {
    let step = publish_step(GUIDE_CALL);
    let ctx = Ctx {
        now: T0,
        actor: step.actor,
        command: CommandId::from_bytes([0x9a; 16]),
        via: Via::Web,
        tenant_admin: step.flags.tenant_admin,
        second_tenant_admin: step.flags.second_admin,
        binds_tenant_admin: step.flags.binds_tenant_admin,
    };
    c.ports
        .engine
        .environment(fstp_engine::Command::Core(step.cmd), ctx)
}

/// The page `calls.guide` answers for call 1, read anonymously.
fn calls_guide(c: &FakeCell) -> String {
    let op = decode_route(
        Method::Get,
        &format!("/calls/{}/guide", GUIDE_CALL.raw()),
        b"",
    );
    match c.call(Credential::None, op) {
        Ok(OpResult::Done { body, .. }) => body
            .to_json()
            .get("html")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("no html member"))
            .to_owned(),
        other => panic!("calls.guide: {other:?}"),
    }
}

/// The `tenant.set_guide_notice` request with `summary` and `url`.
fn set_notice(summary: &str, url: &str) -> Result<fstp_api_core::Op, ApiError> {
    let mut o = Object::new();
    o.insert("privacy_statement_url", Value::from(url));
    o.insert("summary", Value::from(summary));
    let body = fstp_json::to_canonical(&Value::Object(o)).unwrap_or_else(|e| panic!("{e:?}"));
    decode_route(Method::Put, "/admin/settings/guide-notice", body.as_bytes())
}

/// R-GA-01, I-53: publishing a call in a fake cell stores its Guide in
/// the publication entry, and `calls.guide` serves that page. With no
/// tenant override, the Guide shows the platform default data
/// protection texts.
#[test]
fn r_ga_01_fake_cell_publication_stores_the_guide_with_the_platform_default() {
    let c = cell(false);
    publish(&c).unwrap_or_else(|e| panic!("the publication is refused: {e:?}"));
    let state = c.ports.engine.state();
    let stored = fstp_domain::programme::stored_guide(&state.core, GUIDE_CALL)
        .unwrap_or_else(|| panic!("R-GA-01: no Guide was stored at publication"))
        .clone();
    assert!(stored.page().contains(PLATFORM_DATA_PROTECTION_SUMMARY));
    assert!(stored.page().contains(PLATFORM_PRIVACY_STATEMENT_URL));
    assert_eq!(calls_guide(&c), stored.page(), "I-53: the stored page");
}

/// R-GA-01, I-78 (2026-11-06): a tenant admin's override of the Guide's
/// data protection texts is high-risk. Without a proof it prompts a
/// step-up and appends nothing. With one it is recorded, and the Guide
/// stored at the next publication shows the tenant's texts, not the
/// platform default.
#[test]
fn r_ga_01_i78_tenant_override_needs_a_step_up_and_replaces_the_default() {
    let c = cell(true);
    let l = c.login(A1, LoginMethod::Passkey);
    let op = || set_notice(TENANT_SUMMARY, TENANT_PRIVACY);
    let ch = match c.web(&l, op()) {
        Ok(OpResult::StepUpRequired(ch)) => ch,
        other => panic!("I-78: the override without a proof: {other:?}"),
    };
    assert!(c.ports.engine.appended().is_empty(), "I-78: appended");
    c.ports.step_up.approve(l.session, ch.action).unwrap();
    match c.web(&l, op()) {
        Ok(OpResult::Done { .. }) => {}
        other => panic!("R-GA-01: the override with its proof: {other:?}"),
    }
    assert_eq!(c.ports.engine.appended().len(), 1);
    publish(&c).unwrap_or_else(|e| panic!("the publication is refused: {e:?}"));
    let page = calls_guide(&c);
    assert!(page.contains(TENANT_SUMMARY), "R-GA-01: the tenant summary");
    assert!(page.contains(TENANT_PRIVACY), "R-GA-01: the tenant address");
    assert!(!page.contains(PLATFORM_DATA_PROTECTION_SUMMARY));
    assert!(!page.contains(PLATFORM_PRIVACY_STATEMENT_URL));
}

/// R-GA-01: only an `https:` privacy statement address stands in the
/// Guide. An `http:` address is refused by the tenant rules, naming
/// R-GA-01, before any step-up, and nothing is appended.
#[test]
fn r_ga_01_http_privacy_address_is_refused_before_step_up() {
    let c = cell(true);
    let l = c.login(A1, LoginMethod::Passkey);
    let got = c.web(
        &l,
        set_notice(TENANT_SUMMARY, "http://privacy.tenant.example/statement"),
    );
    match got {
        Err(ApiError::Refused { code, rule, .. }) => {
            assert_eq!(code, ErrorCode::Refused);
            assert_eq!(rule, "R-GA-01");
        }
        other => panic!("R-GA-01: an http address: {other:?}"),
    }
    assert!(c.ports.step_up.begun().is_empty(), "a step-up was begun");
    assert!(c.ports.engine.appended().is_empty());
}
