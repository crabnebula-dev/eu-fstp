//! Review reproducer for lane m4tenant (spec fidelity lens). The engine
//! stored its tenant records under the envelope member `tenant`, which
//! M3's cell envelope already uses for `CellRecord::Tenant`. So a cell
//! ledger that held an engine tenant record did not replay.
//!
//! Fix round 1: the engine's tenant side moved to the member
//! `onboarding`, which no cell family uses, and the cell codec routes it.
//! The reproducer builds its record under the engine's own member, which
//! is the only change to it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_cell_core::CellRecord;
use fstp_cell_core::codec::{decode_cell_record, encode_cell_record};
use fstp_json::{Object, Value};

/// ADR-007 (structural replay), design 4.2: an engine tenant record that
/// the cell appends decodes back to itself, never as an M3 tenant record.
#[test]
fn review_engine_tenant_record_replays_through_the_cell_codec() {
    let mut p = Object::new();
    p.insert("cell", Value::from("self_hosted"));
    p.insert("first_admin", Value::from("2561"));
    p.insert("kind", Value::from("TenantProvisioned"));
    let mut o = Object::new();
    o.insert(fstp_engine::EnvelopeKind::Tenant.member(), Value::Object(p));
    let engine = fstp_engine::record_from_json_at(1, &Value::Object(o)).unwrap();
    let record = CellRecord::Engine(engine);
    let bytes = encode_cell_record(&record);
    let back = decode_cell_record(&bytes);
    assert_eq!(
        back.as_ref().ok(),
        Some(&record),
        "the cell does not replay its own engine tenant record: {back:?}"
    );
}
