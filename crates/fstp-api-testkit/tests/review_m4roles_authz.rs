//! Independent review of lane m4/roles, lens: invariants and
//! authorisation. Each test reproduces one finding and is red until the
//! production code is fixed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_api_core::ApiError;
use fstp_api_core::port::LoginMethod;
use fstp_api_testkit::fake::fixture::{self, ADMIN, ADMIN_2, LEAD, PX, World, new_member};
use fstp_api_testkit::fake::{FakeCell, requests};
use fstp_domain::id::AccountId;
use fstp_domain::time::Timestamp;
use fstp_engine::{Record, record_from_json_at};
use fstp_json::{Object, Value, parse};
use fstp_ledger::{MemStore, RecordStore};
use fstp_tenant::{InvitationId, SignatoryRole, TenantRecord, TokenDigest, encode_record};

// ---------------------------------------------------------------------------
// SoD-03: a signatory holder takes a Receiving binding
// ---------------------------------------------------------------------------

fn tenant_record(inner: Value) -> Record {
    let mut o = Object::new();
    o.insert("onboarding", inner);
    record_from_json_at(1, &Value::Object(o)).unwrap()
}

fn tenant(r: &TenantRecord) -> Record {
    tenant_record(parse(&encode_record(r).unwrap()).unwrap())
}

fn provisioned(first: AccountId) -> Record {
    let mut o = Object::new();
    o.insert("cell", Value::from("self_hosted"));
    o.insert("first_admin", Value::from(first.raw().to_string()));
    o.insert("kind", Value::from("TenantProvisioned"));
    tenant_record(Value::Object(o))
}

fn put(store: &mut MemStore<Record>, n: u8, at: i64, records: Vec<Record>) {
    let head = store.head();
    let mut command = [0x5e; 16];
    command[15] = n;
    store
        .append(head, at, command, records)
        .unwrap_or_else(|e| panic!("setup entry {n}: {e:?}"));
}

/// SoD-03: "Operations roles cannot combine with Receiving in the same
/// programme." Financial signatory is an Operations role that acts in
/// every programme of the tenant (NOTE 5), as tenant admin does, and the
/// grant path refuses a holder of a Receiving binding. The reverse order
/// is open: once `new_member(0)` holds Financial signatory, the lead adds
/// it to proposal PX as a team member (a Receiving binding), and the core
/// accepts it, since nothing tells the core of tenant-wide holders.
#[test]
fn review_sod03_signatory_holder_cannot_take_a_receiving_binding() {
    let signatory = new_member(0);
    let mut world: World = fixture::pending_world().unwrap();
    let at = fixture::START.micros().saturating_sub(1_000);
    let invitation = InvitationId::from_raw(0x5e1);
    put(&mut world.store, 1, at, vec![provisioned(ADMIN)]);
    put(
        &mut world.store,
        2,
        at,
        vec![tenant(&TenantRecord::AdminInvited {
            invitation,
            invitee: ADMIN_2,
            token_digest: TokenDigest::from_bytes([0x5e; 32]),
            by: ADMIN,
        })],
    );
    put(
        &mut world.store,
        3,
        at,
        vec![tenant(&TenantRecord::AdminAdded {
            account: ADMIN_2,
            invitation,
        })],
    );
    put(
        &mut world.store,
        4,
        at,
        vec![tenant(&TenantRecord::SignatoryGranted {
            role: SignatoryRole::Financial,
            account: signatory,
            by: ADMIN,
            at: Timestamp::from_micros(at),
        })],
    );
    let c = FakeCell::from_world(&world).unwrap_or_else(|e| panic!("the fake cell: {e}"));
    let lead = c.login(LEAD, LoginMethod::Passkey);
    let r = c.web(&lead, requests::add_member_web(PX, signatory));
    assert!(
        matches!(&r, Err(ApiError::Refused { rule, .. }) if *rule == "SoD-03"),
        "SoD-03: a Financial signatory took a Receiving binding: {r:?}"
    );
}
