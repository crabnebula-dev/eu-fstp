//! SoD-03 and NOTE 5 for the tenant-wide signatory roles (M4 design
//! section 15.0, "Roles lane questions", answered by Daniel on
//! 2026-11-06).
//!
//! - (b) The domain core refuses a Receiving binding (applicant lead,
//!   team member, guardian) to an account that holds Financial signatory
//!   or Legal signatory in the same tenant, naming SoD-03. The reverse
//!   holds too: a signatory role is refused to a holder of a Receiving
//!   binding, naming SoD-03.
//! - (c) `me.roles` names the signatory roles of the caller, so a holder
//!   finds their work from the home page. Nobody else sees them.
//!
//! Each test drives the one dispatch of a cell of fake ports over the
//! I-85 world, with the tenant provisioned, a second tenant admin and
//! the signatory grants appended to its ledger. Every account is
//! synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_api_core::decode::{Method, decode_route};
use fstp_api_core::port::LoginMethod;
use fstp_api_core::{ApiError, Op, OpResult};
use fstp_api_testkit::fake::fixture::{
    self, ADMIN, ADMIN_2, CALL_OPEN, LEAD, OWNER, PX, World, new_member,
};
use fstp_api_testkit::fake::{FakeCell, WebLogin, requests};
use fstp_domain::id::AccountId;
use fstp_domain::time::Timestamp;
use fstp_engine::{Record, record_from_json_at};
use fstp_json::{Object, ToJson, Value, parse};
use fstp_ledger::{MemStore, RecordStore};
use fstp_tenant::{InvitationId, SignatoryRole, TenantRecord, TokenDigest, encode_record};

/// Holds Financial signatory only.
const FIN: AccountId = AccountId::from_raw(0x5f01);
/// Holds Legal signatory only.
const LEG: AccountId = AccountId::from_raw(0x5f02);
/// Holds both signatory roles (SoD-16).
const BOTH: AccountId = AccountId::from_raw(0x5f03);

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
    let mut command = [0x5d; 16];
    command[15] = n;
    store
        .append(head, at, command, records)
        .unwrap_or_else(|e| panic!("setup entry {n}: {e:?}"));
}

/// The I-85 world with ADMIN and ADMIN_2 as tenant admins, FIN holding
/// Financial signatory, LEG Legal signatory and BOTH both roles.
fn cell() -> FakeCell {
    let mut world: World = fixture::pending_world().unwrap();
    let at = fixture::START.micros().saturating_sub(1_000);
    let invitation = InvitationId::from_raw(0x5d1);
    put(&mut world.store, 1, at, vec![provisioned(ADMIN)]);
    put(
        &mut world.store,
        2,
        at,
        vec![tenant(&TenantRecord::AdminInvited {
            invitation,
            invitee: ADMIN_2,
            token_digest: TokenDigest::from_bytes([0x5d; 32]),
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
    let grants = [
        (SignatoryRole::Financial, FIN),
        (SignatoryRole::Legal, LEG),
        (SignatoryRole::Financial, BOTH),
        (SignatoryRole::Legal, BOTH),
    ];
    for (n, (role, account)) in (4u8..).zip(grants) {
        put(
            &mut world.store,
            n,
            at,
            vec![tenant(&TenantRecord::SignatoryGranted {
                role,
                account,
                by: ADMIN,
                at: Timestamp::from_micros(at),
            })],
        );
    }
    FakeCell::from_world(&world).unwrap_or_else(|e| panic!("the fake cell: {e}"))
}

fn login(c: &FakeCell, a: AccountId) -> WebLogin {
    c.login(a, LoginMethod::Passkey)
}

/// How many commands the engine appended.
fn entries(c: &FakeCell) -> usize {
    c.ports.engine.appended().len()
}

fn refused_with(r: &Result<OpResult, ApiError>, want: &str) -> bool {
    matches!(r, Err(ApiError::Refused { rule, .. }) if *rule == want)
}

/// Runs `op`, and when it asks for a step-up, completes the ceremony for
/// exactly the challenged digest and sends it again.
fn stepped(
    c: &FakeCell,
    l: &WebLogin,
    op: &dyn Fn() -> Result<Op, ApiError>,
) -> Result<OpResult, ApiError> {
    match c.web(l, op()) {
        Ok(OpResult::StepUpRequired(ch)) => {
            c.ports.step_up.approve(l.session, ch.action).unwrap();
            c.web(l, op())
        }
        other => other,
    }
}

fn add_guardian(account: AccountId) -> Result<Op, ApiError> {
    decode_route(
        Method::Post,
        &format!("/proposals/{}/guardian", PX.raw()),
        format!(r#"{{"account":"{}"}}"#, account.raw()).as_bytes(),
    )
}

fn create_draft() -> Result<Op, ApiError> {
    decode_route(
        Method::Post,
        &format!("/calls/{}/proposals", CALL_OPEN.raw()),
        b"{}",
    )
}

fn grant(account: AccountId, role: &str) -> Result<Op, ApiError> {
    decode_route(
        Method::Post,
        "/admin/signatories",
        format!(r#"{{"account":"{}","role":"{role}"}}"#, account.raw()).as_bytes(),
    )
}

// ---------------------------------------------------------------------------
// SoD-03, (b): a signatory holder takes no Receiving binding
// ---------------------------------------------------------------------------

/// SoD-03, NOTE 5: the lead cannot add a holder of either signatory role
/// to the team. The refusal names SoD-03 and appends nothing.
#[test]
fn sod03_note5_a_signatory_holder_is_refused_a_team_member_binding() {
    let c = cell();
    let lead = login(&c, LEAD);
    for s in [FIN, LEG, BOTH] {
        let before = entries(&c);
        let r = c.web(&lead, requests::add_member_web(PX, s));
        assert!(
            refused_with(&r, "SoD-03"),
            "SoD-03: {s:?} joined the team: {r:?}"
        );
        assert_eq!(entries(&c), before, "SoD-03: {s:?} appended");
    }
}

/// SoD-03, NOTE 5: the lead cannot name a holder of either signatory
/// role as guardian. The refusal names SoD-03 and appends nothing.
#[test]
fn sod03_note5_a_signatory_holder_is_refused_a_guardian_binding() {
    let c = cell();
    let lead = login(&c, LEAD);
    for s in [FIN, LEG, BOTH] {
        let before = entries(&c);
        let r = c.web(&lead, add_guardian(s));
        assert!(
            refused_with(&r, "SoD-03"),
            "SoD-03: {s:?} became guardian: {r:?}"
        );
        assert_eq!(entries(&c), before, "SoD-03: {s:?} appended");
    }
}

/// SoD-03, NOTE 5: a holder of either signatory role cannot open a draft
/// proposal, which would bind them as applicant lead.
#[test]
fn sod03_note5_a_signatory_holder_is_refused_an_applicant_binding() {
    let c = cell();
    for s in [FIN, LEG, BOTH] {
        let l = login(&c, s);
        let before = entries(&c);
        let r = c.web(&l, create_draft());
        assert!(
            refused_with(&r, "SoD-03"),
            "SoD-03: {s:?} opened a draft: {r:?}"
        );
        assert_eq!(entries(&c), before, "SoD-03: {s:?} appended");
    }
}

/// SoD-03: the refusal has teeth. An account outside the admin set and
/// the signatory holders joins the same team.
#[test]
fn sod03_note5_an_account_without_a_signatory_role_joins_the_team() {
    let c = cell();
    let lead = login(&c, LEAD);
    let r = c.web(&lead, requests::add_member_web(PX, new_member(7)));
    assert!(
        matches!(r, Ok(OpResult::Done { .. })),
        "a plain account was refused: {r:?}"
    );
}

// ---------------------------------------------------------------------------
// SoD-03, (b) reversed: a Receiving holder takes no signatory role
// ---------------------------------------------------------------------------

/// SoD-03, NOTE 5: the lead of PX holds a Receiving binding, so a tenant
/// admin cannot grant them either signatory role. The refusal names
/// SoD-03 and the lead holds no signatory role after it.
#[test]
fn sod03_note5_a_receiving_holder_is_refused_either_signatory_role() {
    let c = cell();
    let admin = login(&c, ADMIN);
    for role in ["financial_signatory", "legal_signatory"] {
        let before = entries(&c);
        let r = stepped(&c, &admin, &|| grant(LEAD, role));
        assert!(
            refused_with(&r, "SoD-03"),
            "SoD-03: the lead was granted {role}: {r:?}"
        );
        assert_eq!(entries(&c), before, "SoD-03: the grant of {role} appended");
    }
    assert_eq!(signatories_of(&c, LEAD), Vec::<String>::new());
}

// ---------------------------------------------------------------------------
// (c): me.roles names the caller's signatory roles
// ---------------------------------------------------------------------------

/// The `signatories` member of the caller's `me.roles` reply.
fn signatories_of(c: &FakeCell, a: AccountId) -> Vec<String> {
    let l = login(c, a);
    let body = match c.web(&l, decode_route(Method::Get, "/me/roles", b"")) {
        Ok(OpResult::Done { body, .. }) => body.to_json(),
        other => panic!("me.roles of {a:?}: {other:?}"),
    };
    match body.get("signatories") {
        Some(Value::Array(xs)) => xs
            .iter()
            .map(|x| x.as_str().unwrap_or_else(|| panic!("{x:?}")).to_owned())
            .collect(),
        other => panic!("me.roles of {a:?} has no signatories array: {other:?}"),
    }
}

/// NOTE 5, I-86: `me.roles` names each signatory role the caller holds,
/// Financial first, and only those.
#[test]
fn note5_i86_me_roles_lists_the_callers_signatory_roles() {
    let c = cell();
    assert_eq!(signatories_of(&c, FIN), ["financial_signatory"]);
    assert_eq!(signatories_of(&c, LEG), ["legal_signatory"]);
    assert_eq!(
        signatories_of(&c, BOTH),
        ["financial_signatory", "legal_signatory"]
    );
}

/// I-86: a caller who holds no signatory role sees none, whoever else
/// holds one.
#[test]
fn note5_i86_me_roles_lists_no_signatory_role_for_others() {
    let c = cell();
    for who in [ADMIN, ADMIN_2, LEAD, OWNER, new_member(8)] {
        assert_eq!(signatories_of(&c, who), Vec::<String>::new(), "{who:?}");
    }
}
