//! Tenant operations through `ApiCore::dispatch` (M4 design sections 2.2
//! J0, 3.5, 3.6 and 3.7; R-TN-01, R-LG-03, SoD-07, I-77, I-78, Q31, Q42,
//! P-74).
//!
//! Lane m4tenant, test author. Each test drives the one dispatch on a
//! cell of fake ports ([`FakeCell`]), through the adapter-facing decoder
//! `decode_route`, with the bodies the onboarding pages send
//! (`web/src/onboarding`). The engine port runs the production driver, so
//! every tenant command is decided by `fstp_tenant::decide` and folded by
//! the engine.
//!
//! Until the engine has a tenant envelope, the setup of every world fails
//! at the decode of its provisioning record, naming I-23. Until dispatch
//! serves the tenant operations, they answer `not_implemented`, and each
//! test refuses that answer.
//!
//! # Worlds
//!
//! - A fresh cell: its ledger holds only the provisioning record of the
//!   first tenant admin A1 (Q31 A, interim reading of this lane; see
//!   `crates/fstp-engine/tests/m4_tenant_envelope.rs`). The attested admin
//!   set of the M3 port holds A1 only. A2, when present, joined through
//!   ledger records only (`AdminInvited`, `AdminAdded`), as the M3
//!   enrolment of an invited admin appends them.
//! - The I-85 world of `fake::fixture`, with a provisioning record for its
//!   admin appended, for the P-74 tests that need programme staff and
//!   their MCP tools.
//!
//! The Agreements step needs the control plane's answer (Q22), which the
//! fake ports have no source for, so the walks run in a self-hosted cell,
//! which skips that step.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use fstp_api_core::decode::{Method, decode_route};
use fstp_api_core::meta::Scope;
use fstp_api_core::port::{LoginMethod, ProbeKind, ProbeOutcome};
use fstp_api_core::{ApiError, ErrorCode, Op, OpResult};
use fstp_api_testkit::fake::cell::{Class, class};
use fstp_api_testkit::fake::fixture::{self, ADMIN, AGENT, CALL_PUBLISH, OWNER, World};
use fstp_api_testkit::fake::requests;
use fstp_api_testkit::fake::{FakeCell, WebLogin};
use fstp_domain::id::AccountId;
use fstp_domain_testkit::vault::{GroundTruth, IdentityTag};
use fstp_engine::{Record, record_from_json_at};
use fstp_json::{Object, ToJson, Value, parse};
use fstp_ledger::{MemStore, RecordStore};
use fstp_tenant::{InvitationId, TenantRecord, TokenDigest, encode_record};

/// The first tenant admin.
const A1: AccountId = AccountId::from_raw(0x0a01);
/// The second tenant admin.
const A2: AccountId = AccountId::from_raw(0x0a02);
/// An account outside the tenant admin set.
const OUTSIDER: AccountId = AccountId::from_raw(0x0a99);
/// An account outside the admin set that holds both signatory roles once
/// [`grant_signatories`] ran (SoD-14, SoD-15, NOTE 5).
const SIGNATORY: AccountId = AccountId::from_raw(0x0b01);
/// The invitation A2 joined through.
const INVITATION: InvitationId = InvitationId::from_raw(0x1a2);
/// The data protection contact the Organisation step saves.
const CONTACT: &str = "Synthetic data protection contact, e2e test tenant.";

// ---------------------------------------------------------------------------
// Worlds
// ---------------------------------------------------------------------------

/// The interim provisioning record of the tenant part (Q31 A).
fn provisioned(first_admin: AccountId, cell: &str) -> Value {
    let mut o = Object::new();
    o.insert("cell", Value::from(cell));
    o.insert("first_admin", Value::from(first_admin.raw().to_string()));
    o.insert("kind", Value::from("TenantProvisioned"));
    Value::Object(o)
}

/// The engine record stored as `{"onboarding": inner}`, the engine's
/// tenant member (M3's cell envelope keeps `tenant`). It fails the test,
/// naming I-23, while the engine has no tenant envelope.
fn record(inner: Value) -> Record {
    let mut o = Object::new();
    o.insert("onboarding", inner);
    let stored = Value::Object(o);
    record_from_json_at(1, &stored).unwrap_or_else(|e| {
        panic!("I-23: the engine does not decode a stored tenant envelope ({e:?}): {stored:?}")
    })
}

fn tenant(r: &TenantRecord) -> Record {
    let bytes = encode_record(r).expect("the tenant codec encodes every record");
    record(parse(&bytes).expect("the tenant codec writes JSON"))
}

/// Appends `records` as one entry at `at`.
fn append(store: &mut MemStore<Record>, at: i64, n: u8, records: Vec<Record>) {
    let head = store.head();
    let mut command = [0x7e; 16];
    command[15] = n;
    store
        .append(head, at, command, records)
        .unwrap_or_else(|e| panic!("the setup entry {n} was refused: {e:?}"));
}

/// How far A2 has come in a fresh cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Second {
    /// No second admin.
    None,
    /// A1 invited A2, who has not joined.
    Invited,
    /// A2 joined, and the vault holds A2 verified or not.
    Added { verified: bool },
}

/// A fresh cell of kind `cell` ("saas" or "self_hosted") whose first
/// admin is A1, with A2 as `second`. Every account has its own synthetic
/// identity. A1 and the outsider are verified.
fn fresh(cell: &str, second: Second) -> FakeCell {
    let mut truth = GroundTruth::new();
    for (a, n) in [(A1, 0xa1), (A2, 0xa2), (OUTSIDER, 0xa9)] {
        truth.set_identity(a, IdentityTag::new(n));
    }
    truth.verify(A1);
    truth.verify(OUTSIDER);
    if second == (Second::Added { verified: true }) {
        truth.verify(A2);
    }
    let mut store = MemStore::new();
    append(
        &mut store,
        1_000_000,
        1,
        vec![record(provisioned(A1, cell))],
    );
    if second != Second::None {
        append(
            &mut store,
            1_000_000,
            2,
            vec![tenant(&TenantRecord::AdminInvited {
                invitation: INVITATION,
                invitee: A2,
                token_digest: TokenDigest::from_bytes([0xd2; 32]),
                by: A1,
            })],
        );
    }
    if matches!(second, Second::Added { .. }) {
        append(
            &mut store,
            1_000_000,
            3,
            vec![tenant(&TenantRecord::AdminAdded {
                account: A2,
                invitation: INVITATION,
            })],
        );
    }
    let world = World {
        store,
        truth,
        start: fixture::START,
        admins: [A1].into_iter().collect(),
    };
    FakeCell::from_world(&world).unwrap_or_else(|e| panic!("the fake cell: {e}"))
}

/// The I-85 world, with the provisioning record of its tenant admin
/// appended, and the agreement versions the control plane recorded.
///
/// Once the ledger holds the tenant part, publication reads its
/// configuration from the ledger alone (design 3.5, fix round 1). So the
/// admin then walks onboarding to a validated Inference step whose
/// primary is the fixture's P-21 primary, as a real tenant does before
/// its first publication.
fn staffed() -> FakeCell {
    let mut world = fixture::pending_world().unwrap_or_else(|e| panic!("the I-85 world: {e}"));
    let at = fstp_domain_testkit::r#gen::roster::T0.micros();
    let mut prov = provisioned(ADMIN, "saas");
    if let Some(o) = prov.as_object_mut() {
        o.insert(
            "agreements",
            json(r#"{"dpa":"1","saas_terms":"1","sub_processors":"1"}"#),
        );
    }
    append(&mut world.store, at, 1, vec![record(prov)]);
    let c = FakeCell::from_world(&world).unwrap_or_else(|e| panic!("the fake cell: {e}"));
    let l = login(&c, ADMIN);
    let model = fstp_domain_testkit::r#gen::policy::MODEL_A;
    let steps = [
        (
            "organisation",
            format!(
                r#"{{"data_protection_contact":"{CONTACT}","signatories":["{}"]}}"#,
                ADMIN.raw()
            ),
        ),
        (
            "agreements",
            r#"{"dpa":"1","saas_terms":"1","sub_processors":"1"}"#.to_owned(),
        ),
        ("branding", r#"{"package":"default"}"#.to_owned()),
        (
            "domains_and_email",
            r#"{"sending_domain":"mail.e2e.invalid"}"#.to_owned(),
        ),
        (
            "identity",
            r#"{"p18":["document_upload","eudi_wallet"],"p45":"tenant_registration"}"#.to_owned(),
        ),
        (
            "inference",
            format!(r#"{{"fallbacks":[],"primary":"{model}","provider":"placeholder"}}"#),
        ),
    ];
    for (step, values) in steps {
        save_validated(&c, &l, step, &values);
    }
    c
}

// ---------------------------------------------------------------------------
// Requests, as the onboarding pages send them
// ---------------------------------------------------------------------------

type OpFn = Box<dyn Fn() -> Result<Op, ApiError>>;

fn get_step(step: &str) -> Result<Op, ApiError> {
    decode_route(Method::Get, &format!("/admin/onboarding/{step}"), b"")
}

fn save_step(step: &str, base: &str, values: &str) -> Result<Op, ApiError> {
    let body = format!(r#"{{"base":"{base}","values":{values}}}"#);
    decode_route(
        Method::Put,
        &format!("/admin/onboarding/{step}"),
        body.as_bytes(),
    )
}

fn complete() -> Result<Op, ApiError> {
    decode_route(Method::Post, "/admin/onboarding/complete", b"{}")
}

fn settings() -> Result<Op, ApiError> {
    decode_route(Method::Get, "/admin/settings", b"")
}

fn list_admins() -> Result<Op, ApiError> {
    decode_route(Method::Get, "/admin/admins", b"")
}

fn invite(email: &str) -> Result<Op, ApiError> {
    let body = format!(r#"{{"email":"{email}"}}"#);
    decode_route(Method::Post, "/admin/admins", body.as_bytes())
}

fn set(path: &str, value: &str) -> Result<Op, ApiError> {
    let body = format!(r#"{{"value":{value}}}"#);
    decode_route(Method::Put, path, body.as_bytes())
}

fn approve_self_grant(approval: u128) -> Result<Op, ApiError> {
    decode_route(Method::Post, &format!("/admin/approvals/{approval}"), b"{}")
}

/// One tenant setting: its route, its key in `tenant.settings`, a valid
/// new value and that value as the settings read shows it.
struct Setting {
    op: &'static str,
    path: &'static str,
    key: &'static str,
    value: &'static str,
}

fn every_setting() -> Vec<Setting> {
    vec![
        Setting {
            op: "tenant.set_payment_mode",
            path: "/admin/settings/payment-mode",
            key: "p20",
            value: r#""record_only""#,
        },
        Setting {
            op: "tenant.set_template_licence",
            path: "/admin/settings/template-licence",
            key: "p69",
            value: r#""MIT""#,
        },
        Setting {
            op: "tenant.set_login_methods",
            path: "/admin/settings/login-methods",
            key: "p70",
            value: r#"["eudi_wallet","passkey"]"#,
        },
        Setting {
            op: "tenant.set_step_up_freshness",
            path: "/admin/settings/step-up-freshness",
            key: "p71",
            value: r#""60000000""#,
        },
        Setting {
            op: "tenant.set_session_lifetimes",
            path: "/admin/settings/session-lifetimes",
            key: "p72",
            value: r#"{"absolute_us":"3600000000","idle_us":"600000000"}"#,
        },
        Setting {
            op: "tenant.set_mcp",
            path: "/admin/settings/mcp",
            key: "p74",
            value: r#"{"enabled":false,"public_tools":false,"roles":null}"#,
        },
    ]
}

/// The valid values of each step of a self-hosted walk, in order. The
/// Payments step needs P-20 first ([`walk_to`]).
fn walk_values() -> Vec<(&'static str, String)> {
    vec![
        (
            "organisation",
            format!(
                r#"{{"data_protection_contact":"{CONTACT}","signatories":["{}"]}}"#,
                A1.raw()
            ),
        ),
        ("branding", r#"{"package":"default"}"#.to_owned()),
        (
            "domains_and_email",
            r#"{"sending_domain":"mail.e2e.invalid"}"#.to_owned(),
        ),
        (
            "identity",
            r#"{"p18":["document_upload","eudi_wallet"],"p45":"tenant_registration"}"#.to_owned(),
        ),
        (
            "inference",
            r#"{"fallbacks":[],"primary":"placeholder-model","provider":"placeholder"}"#.to_owned(),
        ),
        (
            "payments",
            r#"{"bank_interface":"not_connected"}"#.to_owned(),
        ),
        (
            "channels",
            r#"{"matrix_homeserver":null,"whatsapp":false}"#.to_owned(),
        ),
    ]
}

/// Every onboarding step, in the order of the onboarding table.
const STEPS: [&str; 9] = [
    "organisation",
    "agreements",
    "branding",
    "domains_and_email",
    "identity",
    "inference",
    "payments",
    "channels",
    "administrators",
];

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

/// The JSON body of a completed call. Any other result fails the test.
fn done(r: Result<OpResult, ApiError>, what: &str) -> Value {
    match r {
        Ok(OpResult::Done { body, .. }) => body.to_json(),
        Err(ApiError::NotImplemented(m)) => panic!("{what}: not implemented: {m}"),
        other => panic!("{what}: {other:?}"),
    }
}

fn member<'a>(v: &'a Value, k: &str) -> &'a Value {
    v.as_object()
        .and_then(|o| o.get(k))
        .unwrap_or_else(|| panic!("no member {k} in {v:?}"))
}

fn text<'a>(v: &'a Value, k: &str) -> &'a str {
    member(v, k)
        .as_str()
        .unwrap_or_else(|| panic!("member {k} is not text in {v:?}"))
}

/// The JSON of `s`.
fn json(s: &str) -> Value {
    parse(s.as_bytes()).unwrap()
}

/// Asserts that `r` is a refusal, not a stub, a completion or a prompt.
fn assert_refused(r: &Result<OpResult, ApiError>, what: &str) {
    let k = class(r);
    assert!(
        matches!(k, Class::Refused(_)),
        "{what}: wanted a refusal, got {k:?}: {r:?}"
    );
}

/// How many commands the engine appended.
fn appended(c: &FakeCell) -> usize {
    c.ports.engine.appended().len()
}

fn login(c: &FakeCell, a: AccountId) -> WebLogin {
    c.login(a, LoginMethod::Passkey)
}

/// Runs `op` with a step-up when it asks for one: the user completes the
/// ceremony for exactly the challenged digest, and the call is sent
/// again.
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

/// The step read of `step` by `l`.
fn step_view(c: &FakeCell, l: &WebLogin, step: &str) -> Value {
    done(c.web(l, get_step(step)), &format!("tenant.get_step {step}"))
}

/// The revision a save of `step` names as its base, from the step read.
fn base(c: &FakeCell, l: &WebLogin, step: &str) -> String {
    text(&step_view(c, l, step), "revision").to_owned()
}

/// Saves `step` with `values` against the current revision.
fn save(c: &FakeCell, l: &WebLogin, step: &str, values: &str) -> Result<OpResult, ApiError> {
    let b = base(c, l, step);
    c.web(l, save_step(step, &b, values))
}

/// Saves `step` and expects it validated.
fn save_validated(c: &FakeCell, l: &WebLogin, step: &str, values: &str) {
    let v = done(
        save(c, l, step, values),
        &format!("R-TN-01: the save of {step}"),
    );
    assert_eq!(text(&v, "outcome"), "validated", "R-TN-01: {step}: {v:?}");
    assert_eq!(text(&v, "status"), "validated", "R-TN-01: {step}: {v:?}");
}

/// Walks a self-hosted cell through every step before Administrators,
/// setting P-20 with its step-up before Payments, as the onboarding pages
/// do.
fn walk_to_administrators(c: &FakeCell, l: &WebLogin) {
    for (step, values) in walk_values() {
        if step == "payments" {
            let _ = done(
                stepped(c, l, &|| {
                    set("/admin/settings/payment-mode", r#""record_only""#)
                }),
                "R-TN-01: P-20 before Payments",
            );
        }
        save_validated(c, l, step, &values);
    }
}

fn admins_value() -> String {
    format!(r#"{{"admins":["{}","{}"]}}"#, A1.raw(), A2.raw())
}

/// Grants Financial signatory and Legal signatory to [`SIGNATORY`] as `l`,
/// each with its step-up (I-78). The Administrators step validates only
/// with a holder of each (SoD-14, SoD-15).
fn grant_signatories(c: &FakeCell, l: &WebLogin) {
    for role in ["financial_signatory", "legal_signatory"] {
        let body = format!(r#"{{"account":"{}","role":"{role}"}}"#, SIGNATORY.raw());
        let _ = done(
            stepped(c, l, &|| {
                decode_route(Method::Post, "/admin/signatories", body.as_bytes())
            }),
            &format!("SoD-14, SoD-15: the grant of {role}"),
        );
    }
}

// ---------------------------------------------------------------------------
// tenant.get_step and tenant.save_step (R-TN-01)
// ---------------------------------------------------------------------------

/// R-TN-01: `tenant.get_step` shows each step with its status, in order.
/// In a fresh self-hosted cell Organisation is open, Agreements is
/// skipped and every later step is locked. In a SaaS cell Agreements is
/// locked. Each read names the revision a save takes as its base, and an
/// unsaved step has no values and no outcome.
#[test]
fn r_tn_01_get_step_shows_each_step_in_order() {
    for (cell, agreements) in [("self_hosted", "skipped"), ("saas", "locked")] {
        let c = fresh(cell, Second::None);
        let l = login(&c, A1);
        for step in STEPS {
            let v = step_view(&c, &l, step);
            assert_eq!(text(&v, "step"), step);
            let want = match step {
                "organisation" => "open",
                "agreements" => agreements,
                _ => "locked",
            };
            assert_eq!(text(&v, "status"), want, "R-TN-01: {cell}, {step}");
            let rev = text(&v, "revision");
            assert!(
                !rev.is_empty() && rev.bytes().all(|b| b.is_ascii_digit()),
                "R-TN-01: the revision {rev:?} is not a decimal"
            );
            // The page contract reads an absent member as null.
            for k in ["values", "outcome"] {
                let m = v.as_object().and_then(|o| o.get(k));
                assert!(
                    m.is_none_or(|m| *m == Value::Null),
                    "R-TN-01: an unsaved {step} has {k} {m:?}"
                );
            }
        }
        assert_eq!(appended(&c), 0, "a read appends nothing");
    }
}

/// R-TN-01: a valid save validates its step and opens the next. The save
/// appends one entry, moves the revision on and keeps the values, so the
/// tenant can return to them. The data protection contact reads back as
/// the text the tenant typed.
#[test]
fn r_tn_01_save_step_validates_and_opens_the_next_step() {
    let c = fresh("self_hosted", Second::None);
    let l = login(&c, A1);
    let before = base(&c, &l, "organisation");
    let (_, values) = walk_values().into_iter().next().unwrap();
    save_validated(&c, &l, "organisation", &values);
    assert_eq!(appended(&c), 1, "R-TN-01: one save, one entry");
    let v = step_view(&c, &l, "organisation");
    assert_eq!(text(&v, "status"), "validated");
    assert_eq!(text(&v, "outcome"), "validated");
    assert_ne!(
        text(&v, "revision"),
        before,
        "R-TN-01: the revision did not move"
    );
    let saved = member(&v, "values");
    assert_eq!(text(saved, "data_protection_contact"), CONTACT);
    assert_eq!(
        member(saved, "signatories"),
        &json(&format!(r#"["{}"]"#, A1.raw()))
    );
    assert_eq!(text(&step_view(&c, &l, "branding"), "status"), "open");
    assert_eq!(
        text(&step_view(&c, &l, "domains_and_email"), "status"),
        "locked"
    );
}

/// R-TN-01: each step validates before the next opens. A save of a
/// locked step is refused before it appends, and the step stays locked.
#[test]
fn r_tn_01_save_of_a_locked_step_is_refused() {
    let c = fresh("self_hosted", Second::None);
    let l = login(&c, A1);
    let (_, identity) = walk_values().into_iter().nth(3).unwrap();
    let r = save(&c, &l, "identity", &identity);
    assert_refused(&r, "R-TN-01: a save of a locked step");
    assert_eq!(appended(&c), 0);
    assert_eq!(text(&step_view(&c, &l, "identity"), "status"), "locked");
}

/// R-TN-01, design 3.5: a save names the revision it was edited against.
/// A second save against the same, now stale, revision is refused and
/// appends nothing.
#[test]
fn r_tn_01_save_against_a_stale_revision_is_refused() {
    let c = fresh("self_hosted", Second::None);
    let l = login(&c, A1);
    let (_, values) = walk_values().into_iter().next().unwrap();
    let stale = base(&c, &l, "organisation");
    let _ = done(
        c.web(&l, save_step("organisation", &stale, &values)),
        "R-TN-01: the first save",
    );
    let r = c.web(&l, save_step("organisation", &stale, &values));
    assert_refused(&r, "R-TN-01: a save against a stale revision");
    assert_eq!(appended(&c), 1);
}

/// R-TN-01: the tenant can save and return at any point. A save whose
/// values fail the step is kept with its outcome, so the step reads as
/// saved with its values, and the next step stays locked.
#[test]
fn r_tn_01_failed_save_keeps_the_values_and_names_the_outcome() {
    let c = fresh("self_hosted", Second::None);
    let l = login(&c, A1);
    let values = format!(r#"{{"data_protection_contact":"{CONTACT}","signatories":[]}}"#);
    let v = done(
        save(&c, &l, "organisation", &values),
        "R-TN-01: a failed save",
    );
    assert_eq!(text(&v, "outcome"), "invalid_values", "{v:?}");
    assert_eq!(text(&v, "status"), "saved", "{v:?}");
    assert_eq!(appended(&c), 1, "R-TN-01: the failed save is kept");
    let view = step_view(&c, &l, "organisation");
    assert_eq!(text(&view, "status"), "saved");
    assert_eq!(text(&view, "outcome"), "invalid_values");
    assert_eq!(
        text(member(&view, "values"), "data_protection_contact"),
        CONTACT
    );
    assert_eq!(text(&step_view(&c, &l, "branding"), "status"), "locked");
}

/// Q5: a step whose check runs through the prober validates only when
/// the probe passes. A failed probe of the sending domain saves the step
/// with the outcome `probe_failed`, and the next step stays locked.
#[test]
fn q5_failed_probe_does_not_validate_the_step() {
    let c = fresh("self_hosted", Second::None);
    let l = login(&c, A1);
    let values = walk_values();
    for (step, v) in values.iter().take(2) {
        save_validated(&c, &l, step, v);
    }
    c.ports
        .prober
        .set(ProbeKind::SendingDomain, ProbeOutcome::Fail);
    let (step, v) = &values[2];
    let r = done(save(&c, &l, step, v), "Q5: a save with a failed probe");
    assert_eq!(text(&r, "outcome"), "probe_failed", "{r:?}");
    assert_ne!(text(&r, "status"), "validated");
    assert_eq!(text(&step_view(&c, &l, "identity"), "status"), "locked");
    assert!(
        c.ports.prober.seen().contains(&ProbeKind::SendingDomain),
        "Q5: the sending domain was not probed"
    );
}

// ---------------------------------------------------------------------------
// tenant.complete and the Administrators step (SoD-07)
// ---------------------------------------------------------------------------

/// R-TN-01, SoD-07, design 2.2 J0: a self-hosted tenant walks every step
/// in order. With A2 joined and verified, Administrators validates and
/// onboarding completes. Every step then reads validated, or skipped
/// where the cell skips it.
#[test]
fn r_tn_01_walk_completes_with_two_verified_admins() {
    let c = fresh("self_hosted", Second::Added { verified: true });
    let l = login(&c, A1);
    walk_to_administrators(&c, &l);
    grant_signatories(&c, &l);
    save_validated(&c, &l, "administrators", &admins_value());
    let before = appended(&c);
    let _ = done(c.web(&l, complete()), "R-TN-01: completion");
    assert_eq!(
        appended(&c),
        before + 1,
        "R-TN-01: completion appends one entry"
    );
    for step in STEPS {
        let want = if step == "agreements" {
            "skipped"
        } else {
            "validated"
        };
        assert_eq!(text(&step_view(&c, &l, step), "status"), want, "{step}");
    }
}

/// SoD-07: at least two tenant admins. With A1 alone, the Administrators
/// step saves with `too_few_admins` and onboarding does not complete.
#[test]
fn sod07_one_admin_neither_validates_administrators_nor_completes() {
    let c = fresh("self_hosted", Second::None);
    let l = login(&c, A1);
    walk_to_administrators(&c, &l);
    let one = format!(r#"{{"admins":["{}"]}}"#, A1.raw());
    let v = done(
        save(&c, &l, "administrators", &one),
        "SoD-07: Administrators",
    );
    assert_eq!(text(&v, "outcome"), "too_few_admins", "{v:?}");
    let before = appended(&c);
    assert_refused(&c.web(&l, complete()), "SoD-07: completion with one admin");
    assert_eq!(appended(&c), before);
}

/// SoD-07, Q2: onboarding completes only when every tenant admin verified
/// their identity through the vault. With A2 joined but unverified, the
/// completion is refused and appends nothing.
#[test]
fn sod07_completion_needs_every_admin_verified() {
    let c = fresh("self_hosted", Second::Added { verified: false });
    let l = login(&c, A1);
    walk_to_administrators(&c, &l);
    grant_signatories(&c, &l);
    save_validated(&c, &l, "administrators", &admins_value());
    let before = appended(&c);
    assert_refused(
        &c.web(&l, complete()),
        "SoD-07: completion with an unverified admin",
    );
    assert_eq!(appended(&c), before);
}

/// R-TN-01: onboarding completes only once every step validated. A
/// completion in a fresh cell is refused and appends nothing.
#[test]
fn r_tn_01_completion_before_every_step_is_refused() {
    let c = fresh("self_hosted", Second::Added { verified: true });
    let l = login(&c, A1);
    assert_refused(&c.web(&l, complete()), "R-TN-01: an early completion");
    assert_eq!(appended(&c), 0);
}

// ---------------------------------------------------------------------------
// tenant.settings and the tenant.set_* operations (R-LG-03, I-78)
// ---------------------------------------------------------------------------

/// R-LG-03, design 3.5: the settings read shows every tenant setting in
/// the codec form, at the Default column of `policy-parameters.md` before
/// any change. P-20 has no default.
#[test]
fn r_lg_03_settings_read_shows_the_spec_defaults() {
    let c = fresh("saas", Second::None);
    let l = login(&c, A1);
    let v = done(c.web(&l, settings()), "tenant.settings");
    assert_eq!(member(&v, "p20"), &Value::Null);
    assert_eq!(text(&v, "p69"), "CC-BY-4.0");
    assert_eq!(member(&v, "p70"), &json(r#"["passkey"]"#));
    assert_eq!(text(&v, "p71"), "300000000");
    assert_eq!(
        member(&v, "p72"),
        &json(r#"{"absolute_us":"43200000000","idle_us":"1800000000"}"#)
    );
    assert_eq!(
        member(&v, "p74"),
        &json(r#"{"enabled":true,"public_tools":true,"roles":null}"#)
    );
}

/// I-78, R-LG-03: every tenant setting change is high-risk (design 3.5,
/// strict reading). Without a proof the change prompts a step-up bound to
/// its digest and appends nothing. A proof for another digest does not
/// count. With a proof for its digest the change completes and the
/// settings read shows it. The proof is consumed, so the same request
/// prompts again.
#[test]
fn i78_every_tenant_setting_change_needs_a_digest_bound_step_up() {
    for s in every_setting() {
        let c = fresh("saas", Second::None);
        let l = login(&c, A1);
        let op = || set(s.path, s.value);
        let ch = match c.web(&l, op()) {
            Ok(OpResult::StepUpRequired(ch)) => ch,
            other => panic!("I-78: {} without a proof: {other:?}", s.op),
        };
        assert_eq!(
            appended(&c),
            0,
            "I-78: {} appended before its step-up",
            s.op
        );
        c.ports
            .step_up
            .approve(l.session, fstp_api_core::ActionDigest([0x5a; 32]))
            .unwrap();
        assert!(
            matches!(c.web(&l, op()), Ok(OpResult::StepUpRequired(_))),
            "I-78: {} accepted a proof for another digest",
            s.op
        );
        c.ports.step_up.approve(l.session, ch.action).unwrap();
        let _ = done(c.web(&l, op()), &format!("I-78: {} with its proof", s.op));
        assert_eq!(appended(&c), 1, "I-78: {} appended once", s.op);
        let v = done(c.web(&l, settings()), "tenant.settings");
        assert_eq!(member(&v, s.key), &json(s.value), "R-LG-03: {}", s.op);
        assert!(
            matches!(c.web(&l, op()), Ok(OpResult::StepUpRequired(_))),
            "I-78: {} reused a consumed proof",
            s.op
        );
        assert_eq!(appended(&c), 1);
    }
}

/// Design 3.7 step 5: a dry run refuses before any step-up prompt. A
/// setting the tenant rules refuse, such as a P-71 longer than its
/// default or a P-70 without passkeys, is refused with no step-up begun
/// and nothing appended.
#[test]
fn r_lg_03_invalid_setting_is_refused_before_step_up() {
    for (path, value) in [
        ("/admin/settings/step-up-freshness", r#""600000000""#),
        ("/admin/settings/login-methods", r#"["eudi_wallet"]"#),
        ("/admin/settings/template-licence", r#""-MIT""#),
        (
            "/admin/settings/session-lifetimes",
            r#"{"absolute_us":"86400000000","idle_us":"1800000000"}"#,
        ),
    ] {
        let c = fresh("saas", Second::None);
        let l = login(&c, A1);
        assert_refused(
            &c.web(&l, set(path, value)),
            &format!("R-LG-03: {path} {value}"),
        );
        assert!(
            c.ports.step_up.begun().is_empty(),
            "design 3.7 step 5: a step-up was begun for a refused setting"
        );
        assert_eq!(appended(&c), 0);
    }
}

// ---------------------------------------------------------------------------
// tenant.invite_admin, admin.approve_self_grant (I-78, I-77, SoD-07)
// ---------------------------------------------------------------------------

/// I-78, R-LG-03: inviting a tenant admin grants tenant admin, so it is
/// high-risk (`authentication.md`). Without a proof it prompts a step-up
/// bound to its digest and appends nothing. With the proof it appends the
/// invitation. The invitee is not an admin until they join (Q31), so the
/// admin list still holds A1 alone.
#[test]
fn i78_inviting_a_tenant_admin_needs_a_digest_bound_step_up() {
    let c = fresh("self_hosted", Second::None);
    let l = login(&c, A1);
    let op = || invite("a2@e2e.invalid");
    let ch = match c.web(&l, op()) {
        Ok(OpResult::StepUpRequired(ch)) => ch,
        other => panic!("I-78: an invitation without a proof: {other:?}"),
    };
    assert_eq!(appended(&c), 0);
    c.ports.step_up.approve(l.session, ch.action).unwrap();
    let _ = done(c.web(&l, op()), "I-78: the invitation with its proof");
    assert_eq!(appended(&c), 1, "I-78: the invitation appended once");
    let admins = done(c.web(&l, list_admins()), "tenant.list_admins");
    let rows = member(&admins, "admins").as_array().unwrap();
    assert_eq!(
        rows.len(),
        1,
        "Q31: an invitee is listed as an admin: {admins:?}"
    );
}

/// SoD-07 (fix round 1): while no record lists pending self-grants, an
/// approval id names no self-grant the cell knows of. It is refused as
/// not found under `Input`, never as if a SoD-07 rule had been checked,
/// and no step-up is begun.
#[test]
fn sod07_approval_of_an_unknown_self_grant_is_not_found() {
    let c = fresh("self_hosted", Second::Added { verified: true });
    let l = login(&c, A1);
    let r = c.web(&l, approve_self_grant(7));
    match &r {
        Err(ApiError::Refused { code, rule, .. }) => {
            assert_eq!(*code, ErrorCode::NotFound, "{r:?}");
            assert_eq!(*rule, "Input", "{r:?}");
        }
        other => panic!("SoD-07: an unknown approval gave {other:?}"),
    }
    assert!(c.ports.step_up.begun().is_empty());
    assert_eq!(appended(&c), 0);
}

/// I-78, SoD-07: approving another admin's self-grant is high-risk. It
/// reaches the tenant dispatch, and without a step-up it never completes
/// and appends nothing.
#[test]
fn i78_self_grant_approval_never_runs_without_step_up() {
    let c = fresh("self_hosted", Second::Added { verified: true });
    let l = login(&c, A1);
    let r = c.web(&l, approve_self_grant(7));
    let k = class(&r);
    assert!(
        !matches!(k, Class::Stub | Class::Done),
        "I-78: admin.approve_self_grant without a proof gave {k:?}: {r:?}"
    );
    assert_eq!(appended(&c), 0);
}

/// I-77: every high-risk tenant operation needs a phishing-resistant
/// session. A magic-link session of the first admin is refused, with no
/// step-up begun and nothing appended.
#[test]
fn i77_high_risk_tenant_operations_refuse_a_weak_session() {
    let c = fresh("saas", Second::None);
    let weak = c.login(A1, LoginMethod::MagicLink);
    let mut ops: Vec<(String, OpFn)> = every_setting()
        .into_iter()
        .map(|s| {
            let (path, value) = (s.path, s.value);
            (s.op.to_owned(), Box::new(move || set(path, value)) as OpFn)
        })
        .collect();
    ops.push((
        "tenant.invite_admin".to_owned(),
        Box::new(|| invite("a2@e2e.invalid")),
    ));
    ops.push((
        "admin.approve_self_grant".to_owned(),
        Box::new(|| approve_self_grant(7)),
    ));
    for (name, op) in ops {
        let r = c.web(&weak, op());
        assert_eq!(
            class(&r),
            Class::Refused(ErrorCode::LoginStrength),
            "I-77: {name} through a magic-link session: {r:?}"
        );
    }
    assert!(c.ports.step_up.begun().is_empty());
    assert_eq!(appended(&c), 0);
}

// ---------------------------------------------------------------------------
// The tenant admin set (Q31)
// ---------------------------------------------------------------------------

/// Every tenant operation of the registry, with a valid request.
fn every_tenant_op() -> Vec<(String, OpFn)> {
    let mut ops: Vec<(String, OpFn)> = vec![
        (
            "tenant.get_step".to_owned(),
            Box::new(|| get_step("organisation")),
        ),
        (
            "tenant.save_step".to_owned(),
            Box::new(|| {
                let (_, v) = walk_values().into_iter().next().unwrap();
                save_step("organisation", "0", &v)
            }),
        ),
        ("tenant.complete".to_owned(), Box::new(complete)),
        ("tenant.settings".to_owned(), Box::new(settings)),
        ("tenant.list_admins".to_owned(), Box::new(list_admins)),
        (
            "tenant.invite_admin".to_owned(),
            Box::new(|| invite("x@e2e.invalid")),
        ),
        (
            "admin.approve_self_grant".to_owned(),
            Box::new(|| approve_self_grant(7)),
        ),
        // Lane m4/roles: the signatory roles and the activation (SA-01,
        // SA-02).
        (
            "tenant.list_signatories".to_owned(),
            Box::new(|| decode_route(Method::Get, "/admin/signatories", b"")),
        ),
        (
            "tenant.grant_signatory".to_owned(),
            Box::new(|| {
                let body = format!(r#"{{"account":"{}","role":"legal_signatory"}}"#, A2.raw());
                decode_route(Method::Post, "/admin/signatories", body.as_bytes())
            }),
        ),
        (
            "tenant.end_signatory".to_owned(),
            Box::new(|| {
                let path = format!("/admin/signatories/legal_signatory/{}", A2.raw());
                decode_route(Method::Delete, &path, b"")
            }),
        ),
        (
            "tenant.get_activation".to_owned(),
            Box::new(|| decode_route(Method::Get, "/admin/activation", b"")),
        ),
        (
            "tenant.request_activation".to_owned(),
            Box::new(|| decode_route(Method::Post, "/admin/activation", b"{}")),
        ),
        (
            "tenant.approve_activation".to_owned(),
            Box::new(|| {
                decode_route(
                    Method::Post,
                    "/admin/activation/approval",
                    br#"{"request":"7"}"#,
                )
            }),
        ),
    ];
    for s in every_setting() {
        let (path, value) = (s.path, s.value);
        ops.push((s.op.to_owned(), Box::new(move || set(path, value))));
    }
    ops
}

/// Q31, SoD-07: only a tenant admin of the ledger's admin set may run a
/// tenant operation. An account outside it is refused every one, with no
/// step-up begun and nothing appended.
#[test]
fn q31_every_tenant_operation_refuses_an_account_outside_the_admin_set() {
    let c = fresh("self_hosted", Second::None);
    let l = login(&c, OUTSIDER);
    for (name, op) in every_tenant_op() {
        assert_refused(&c.web(&l, op()), &format!("Q31: {name} by an outsider"));
    }
    assert!(c.ports.step_up.begun().is_empty());
    assert_eq!(appended(&c), 0);
}

/// Q31 A: the admin set lives in the ledger. The Administrators step
/// lists each admin once with a display handle, never an email, and
/// whether the vault verified them. An invitee who has not joined is not
/// listed.
#[test]
fn q31_admin_list_reads_the_ledger_admin_set() {
    let rows = |second: Second| {
        let c = fresh("self_hosted", second);
        let l = login(&c, A1);
        let v = done(c.web(&l, list_admins()), "tenant.list_admins");
        member(&v, "admins").as_array().unwrap().clone()
    };
    let one = rows(Second::Invited);
    assert_eq!(one.len(), 1, "Q31: {one:?}");
    assert_eq!(text(&one[0], "account"), A1.raw().to_string());
    assert_eq!(member(&one[0], "verified"), &Value::Bool(true));

    let two = rows(Second::Added { verified: false });
    let accounts: BTreeSet<String> = two.iter().map(|r| text(r, "account").to_owned()).collect();
    assert_eq!(
        accounts,
        [A1, A2].iter().map(|a| a.raw().to_string()).collect(),
        "Q31: {two:?}"
    );
    for r in &two {
        let handle = text(r, "handle");
        assert!(
            !handle.is_empty() && !handle.contains('@'),
            "R-CF-03: {handle}"
        );
        let verified = text(r, "account") == A1.raw().to_string();
        assert_eq!(member(r, "verified"), &Value::Bool(verified), "Q2: {r:?}");
    }
}

/// Q31 A: an admin who joined through the ledger is a tenant admin for
/// dispatch, although the attested set of the M3 port does not name
/// them. An invitee who has not joined is not one.
#[test]
fn q31_ledger_admin_set_gates_tenant_operations() {
    let joined = fresh("self_hosted", Second::Added { verified: true });
    let l2 = login(&joined, A2);
    let _ = done(
        joined.web(&l2, settings()),
        "Q31: a joined admin reads the tenant settings",
    );
    let invited = fresh("self_hosted", Second::Invited);
    let l2 = login(&invited, A2);
    assert_refused(
        &invited.web(&l2, settings()),
        "Q31: an invitee reads the tenant settings",
    );
    let (_, v) = walk_values().into_iter().next().unwrap();
    assert_refused(
        &invited.web(&l2, save_step("organisation", "0", &v)),
        "Q31: an invitee saves a step",
    );
    assert_eq!(appended(&invited), 0);
}

// ---------------------------------------------------------------------------
// P-74 through dispatch (Q42)
// ---------------------------------------------------------------------------

/// Changes P-74 to `value` as the I-85 world's tenant admin, with step-up.
fn set_p74(c: &FakeCell, value: &str) {
    let l = login(c, ADMIN);
    let _ = done(
        stepped(c, &l, &|| set("/admin/settings/mcp", value)),
        "P-74: tenant.set_mcp",
    );
}

/// P-74, design 3.6: when the tenant disables the MCP server, every tool
/// call is refused with `P-74`. The same call was served before the
/// change.
#[test]
fn p74_disabled_mcp_server_refuses_every_tool_call() {
    let c = staffed();
    let token = c.token(OWNER, AGENT, [Scope::CallsRead], LoginMethod::Passkey);
    let before = c.mcp(&token, requests::list_open_calls_mcp());
    assert_eq!(class(&before), Class::Done, "P-74 on: {before:?}");
    set_p74(&c, r#"{"enabled":false,"public_tools":true,"roles":null}"#);
    let after = c.mcp(&token, requests::list_open_calls_mcp());
    assert_eq!(
        class(&after),
        Class::Refused(ErrorCode::P74),
        "P-74 off: {after:?}"
    );
}

/// Q42 (interim A), P-74: an MCP operation is refused when any role
/// through which it can act is outside the roles P-74 allows. The
/// programme manager's publication tool is refused when P-74 allows
/// applicants only, and prepared when P-74 allows programme managers.
#[test]
fn q42_p74_role_limit_refuses_an_op_acting_under_a_disallowed_role() {
    for (roles, want) in [
        (r#"["Applicant"]"#, Class::Refused(ErrorCode::P74)),
        (r#"["Programme manager"]"#, Class::Pending),
    ] {
        let c = staffed();
        set_p74(
            &c,
            &format!(r#"{{"enabled":true,"public_tools":true,"roles":{roles}}}"#),
        );
        let token = c.token(
            OWNER,
            AGENT,
            [Scope::CallsDraft, Scope::CallsRead],
            LoginMethod::Passkey,
        );
        let r = c.mcp(&token, requests::publish_mcp(CALL_PUBLISH));
        assert_eq!(class(&r), want, "Q42: P-74 roles {roles}: {r:?}");
    }
}
