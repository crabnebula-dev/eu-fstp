//! The engine's tenant side inside the cell envelope (M4 design sections
//! 3.5 and 4.2, ADR-007, I-23, I-78; lane m4tenant, fix round 1).
//!
//! The engine stores its tenant records and commands under the member
//! `onboarding`. M3's own tenant family keeps `tenant`. These tests pin
//! both apart, and check that the cell's step-up digest form exists for
//! an engine tenant command. The property suites of `adr007_cell_codec`
//! draw the `onboarding` member too.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_cell_core::codec::{
    decode_cell_command, decode_cell_record, encode_cell_command, encode_cell_record,
    try_encode_cell_command,
};
use fstp_cell_core::{CellCommand, CellRecord};
use fstp_json::{Object, Value, parse};

fn provisioning() -> Value {
    let mut p = Object::new();
    p.insert("cell", Value::from("saas"));
    p.insert("first_admin", Value::from("2561"));
    p.insert("kind", Value::from("TenantProvisioned"));
    Value::Object(p)
}

fn wrap(member: &str, inner: Value) -> Value {
    let mut o = Object::new();
    o.insert(member, inner);
    Value::Object(o)
}

/// I-23, ADR-007: the engine's tenant member is one no cell family uses,
/// so an M3 tenant record and an engine tenant record never share bytes.
#[test]
fn i23_engine_tenant_member_is_not_the_cell_tenant_member() {
    let member = fstp_engine::EnvelopeKind::Tenant.member();
    assert_eq!(member, "onboarding");
    let engine = fstp_engine::record_from_json_at(1, &wrap(member, provisioning())).unwrap();
    let bytes = encode_cell_record(&CellRecord::Engine(engine));
    let v = parse(&bytes).unwrap();
    assert!(v.as_object().unwrap().get("tenant").is_none(), "{v:?}");
    // An engine tenant body under M3's member is not an engine record.
    let m3 = fstp_json::to_canonical(&wrap("tenant", provisioning())).unwrap();
    assert!(
        !matches!(decode_cell_record(m3.as_bytes()), Ok(CellRecord::Engine(_))),
        "an engine tenant body decoded as an engine record under `tenant`"
    );
}

/// I-78, design section 8.4: an engine tenant command round-trips through
/// the cell codec, so its step-up digest form exists and names it alone.
#[test]
fn i78_engine_tenant_command_has_a_cell_digest_form() {
    let command = parse(
        br#"{"base":"5","kind":"SaveStep","step":"inference","values":{"fallbacks":[],"primary":"model-a","provider":"placeholder"}}"#,
    )
    .unwrap();
    let mut probe = Object::new();
    probe.insert("check", Value::from("sending_domain"));
    probe.insert("domain", Value::from("mail.e2e.invalid"));
    probe.insert("outcome", Value::from("passed"));
    let mut o = Object::new();
    o.insert("command", command);
    o.insert("inference_config", Value::from("9"));
    o.insert("probes", Value::Array(vec![Value::Object(probe)].into()));
    let req = fstp_engine::tenant::request_from_json(&Value::Object(o)).unwrap();
    let cmd = CellCommand::Engine(fstp_engine::Command::Tenant(req));
    let bytes = encode_cell_command(&cmd);
    assert_eq!(decode_cell_command(&bytes).as_ref(), Ok(&cmd));
    assert_eq!(try_encode_cell_command(&cmd), Some(bytes));
}
