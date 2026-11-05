//! I-93, R-JV-03, R-AC-01, roles-and-sod.md NOTE 5: the journey reads
//! refuse the Financial and Legal signatories.
//!
//! Section 7.2 of `SPEC/12-journey-ui.md` names neither signatory, and
//! both bind tenant-wide with no programme. The interim reading of design
//! section 15.0 (lane j2) is fail closed: the read rule itself refuses
//! them. The test tells this apart from the I-21 state gate, which
//! refuses an admitted staff reader of a draft: the signatory gets the
//! rule's refusal, R-AC-01, and the programme manager gets I-21.
//!
//! The world is the I-85 world with the tenant onboarded and one
//! synthetic account holding both signatory roles. Every account is
//! synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_api_core::decode::{Method, decode_route};
use fstp_api_core::port::LoginMethod;
use fstp_api_core::{ApiError, OpResult};
use fstp_api_testkit::fake::FakeCell;
use fstp_api_testkit::fake::fixture::{self, ADMIN, ADMIN_2, OWNER, PX, World, new_member};
use fstp_domain::id::AccountId;
use fstp_domain::time::Timestamp;
use fstp_engine::{Record, record_from_json_at};
use fstp_json::{Object, ToJson, Value, parse};
use fstp_ledger::{MemStore, RecordStore};
use fstp_tenant::{InvitationId, SignatoryRole, TenantRecord, TokenDigest, encode_record};

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
    let mut command = [0x5f; 16];
    command[15] = n;
    store
        .append(head, at, command, records)
        .unwrap_or_else(|e| panic!("setup entry {n}: {e:?}"));
}

/// The I-85 world, onboarded by two admins, where `signatory` holds both
/// Financial and Legal signatory (SoD-16).
fn cell_with_signatory(signatory: AccountId) -> FakeCell {
    let mut world: World = fixture::pending_world().unwrap();
    let at = fixture::START.micros().saturating_sub(1_000);
    let invitation = InvitationId::from_raw(0x5f1);
    put(&mut world.store, 1, at, vec![provisioned(ADMIN)]);
    put(
        &mut world.store,
        2,
        at,
        vec![tenant(&TenantRecord::AdminInvited {
            invitation,
            invitee: ADMIN_2,
            token_digest: TokenDigest::from_bytes([0x5f; 32]),
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
    for (n, role) in [(4, SignatoryRole::Financial), (5, SignatoryRole::Legal)] {
        put(
            &mut world.store,
            n,
            at,
            vec![tenant(&TenantRecord::SignatoryGranted {
                role,
                account: signatory,
                by: ADMIN,
                at: Timestamp::from_micros(at),
            })],
        );
    }
    FakeCell::from_world(&world).unwrap_or_else(|e| panic!("the fake cell: {e}"))
}

/// The refusal rule of `account` reading `read` of PX.
fn refusal(c: &FakeCell, account: AccountId, read: &str) -> &'static str {
    let login = c.login(account, LoginMethod::Passkey);
    let path = format!("/proposals/{}/{read}", PX.raw());
    match c.web(&login, decode_route(Method::Get, &path, b"")) {
        Err(ApiError::Refused { rule, .. }) => rule,
        other => panic!("proposal.{read} for {account:?} must be refused: {other:?}"),
    }
}

/// I-93, R-JV-03, R-AC-01, NOTE 5: a holder of both signatory roles is
/// refused `proposal.journey` and `proposal.diary` by the read rule, not
/// by the I-21 state gate that refuses the programme manager.
#[test]
fn i93_r_jv_03_journey_reads_refuse_the_signatories() {
    let signatory = new_member(0);
    let c = cell_with_signatory(signatory);
    // The world holds both grants: the admin's signatory list names them.
    let admin = c.login(ADMIN, LoginMethod::Passkey);
    let list = match c.web(&admin, decode_route(Method::Get, "/admin/signatories", b"")) {
        Ok(OpResult::Done { body, .. }) => body.to_json().to_compact(),
        other => panic!("tenant.list_signatories: {other:?}"),
    };
    let account = signatory.raw().to_string();
    for role in ["financial_signatory", "legal_signatory"] {
        let row = format!(r#"{{"account":"{account}","role":"{role}""#);
        assert!(list.contains(&row), "the {role} grant is missing: {list}");
    }
    for read in ["journey", "diary"] {
        assert_eq!(
            refusal(&c, OWNER, read),
            "I-21",
            "the programme manager of a draft, proposal.{read}"
        );
        assert_eq!(
            refusal(&c, signatory, read),
            "R-AC-01",
            "NOTE 5: a signatory is no journey reader, proposal.{read}"
        );
    }
}
