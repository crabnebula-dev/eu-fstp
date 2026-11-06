//! The creator reads and replies the Planning Studio needs, and the Q35
//! activation checks at dispatch (lane mcreator, M4 design sections 3.2
//! and 3.7, section 15.0 answers of 2026-11-06).
//!
//! Every test drives `ApiCore::dispatch` on a cell of fake ports
//! ([`FakeCell`]) through the adapter-facing decoders. The engine port
//! runs the production domain and creator, so every refusal is decided by
//! the real guards.
//!
//! - R-PG-04: `creator.impact` lists the calls a change reaches, through
//!   `fstp_programme::impact`, instead of answering `not_implemented` for
//!   a programme with calls.
//! - I-66, Q35 A: a vault that answers no to `classes_defined` or to
//!   `proximity_lists_declared` at the approval keeps the programme a
//!   draft. The approval recomputes the report, so the fresh failure, or
//!   the fresh unacknowledged warning, refuses it.
//! - I-78: the approval asks for a fresh step-up (section 15.0).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_api_core::decode::{Method, decode_route};
use fstp_api_core::port::LoginMethod;
use fstp_api_core::{ApiError, Op, OpResult};
use fstp_api_testkit::fake::creator_requests as rq;
use fstp_api_testkit::fake::fixture::{ADMIN, ADMIN_2, LEAD, OTHER, OWNER, P1, P2};
use fstp_api_testkit::fake::{FakeCell, WebLogin};
use fstp_domain::id::{AccountId, BindingId, CallId, CommandId, ProgrammeId};
use fstp_domain::programme::{CallStatus, ProgrammeStatus, programme_status};
use fstp_domain::roles::Role;
use fstp_domain_testkit::r#gen::roster;
use fstp_engine::Command;
use fstp_json::{ToJson, Value};

fn cell() -> FakeCell {
    FakeCell::new().unwrap_or_else(|e| panic!("the fake cell: {e}"))
}

fn login(c: &FakeCell, account: AccountId) -> WebLogin {
    c.login(account, LoginMethod::Passkey)
}

/// The JSON body of a completed call, or why it did not complete.
fn done(r: Result<OpResult, ApiError>, what: &str) -> Result<Value, String> {
    match r {
        Ok(OpResult::Done { body, .. }) => Ok(body.to_json()),
        other => Err(format!("{what} gave {other:?}")),
    }
}

/// Calls `op` through the web, running a step-up ceremony once if asked.
fn stepped(
    c: &FakeCell,
    l: &WebLogin,
    op: impl Fn() -> Result<Op, ApiError>,
) -> Result<OpResult, ApiError> {
    match c.web(l, op()) {
        Ok(OpResult::StepUpRequired(ch)) => {
            let _ = c.ports.step_up.approve(l.session, ch.action);
            c.web(l, op())
        }
        other => other,
    }
}

fn str_of(v: &Value, k: &str) -> Result<String, String> {
    v.get(k)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("no string member {k:?} in {}", v.to_compact()))
}

fn list_of(v: &Value, k: &str) -> Result<Vec<Value>, String> {
    v.get(k)
        .and_then(Value::as_array)
        .map(|a| a.iter().cloned().collect())
        .ok_or_else(|| format!("no array member {k:?} in {}", v.to_compact()))
}

/// The refusal rule of `r`, if it is a refusal.
fn rule(r: &Result<OpResult, ApiError>) -> Option<&'static str> {
    match r {
        Err(ApiError::Refused { rule, .. }) => Some(*rule),
        _ => None,
    }
}

/// The calls of a `creator.impact` reply.
fn impact_calls(v: &Value) -> Result<Vec<String>, String> {
    list_of(v, "calls")?
        .iter()
        .map(|r| str_of(r, "call"))
        .collect()
}

// ---------------------------------------------------------------------------
// R-PG-04
// ---------------------------------------------------------------------------

/// R-PG-04, I-12: after activation the impact read lists the calls a
/// change reaches. In P1 calls 1 and 2 are approved and not published,
/// so they freeze every change at publication. Call 3 is published, and
/// a change of a live parameter reaches it at its next decision. Call 4
/// is in P2 and never listed for P1.
#[test]
fn r_pg_04_impact_lists_the_calls_of_the_programme_a_change_reaches() {
    let c = cell();
    let owner = login(&c, OWNER);
    let p1 = done(c.web(&owner, rq::impact(P1)), "creator.impact of P1")
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        impact_calls(&p1).unwrap_or_else(|e| panic!("{e}")),
        ["1", "2", "3"]
    );
    let p2 = done(c.web(&owner, rq::impact(P2)), "creator.impact of P2")
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(impact_calls(&p2).unwrap_or_else(|e| panic!("{e}")), ["4"]);
    let r = c.web(&login(&c, LEAD), rq::impact(P1));
    assert!(r.is_err(), "the applicant read the impact: {r:?}");
}

// ---------------------------------------------------------------------------
// I-66, Q35 A
// ---------------------------------------------------------------------------

/// A requested SuperSAFE draft and the logins that act on it.
struct Requested {
    p: ProgrammeId,
    admin2: WebLogin,
}

/// The revision of draft `p` as `l` reads it.
fn revision(c: &FakeCell, l: &WebLogin, p: ProgrammeId) -> Result<String, String> {
    str_of(
        &done(c.web(l, rq::get_draft(p)), "creator.get_draft")?,
        "revision",
    )
}

/// A1 opens a draft, grants M1 its manager role through the engine port
/// as a change of the world, and M1 applies the SuperSAFE start, accepts
/// every narrative, fills the synthetic gaps, acknowledges every warning
/// and requests activation, as journey J1 does.
fn requested(c: &FakeCell) -> Result<Requested, String> {
    let admin = login(c, ADMIN);
    let opened = match stepped(c, &admin, rq::open_draft) {
        Ok(OpResult::Done { body, .. }) => body.to_json(),
        other => return Err(format!("creator.open_draft gave {other:?}")),
    };
    let p = ProgrammeId::from_raw(
        str_of(&opened, "programme")?
            .parse()
            .map_err(|_| "the programme id".to_owned())?,
    );
    let now = c.ports.clock.read();
    let step = roster::grant(
        BindingId::from_raw(91_001),
        OWNER,
        p,
        Role::ProgrammeManager,
        now,
    );
    c.ports
        .engine
        .environment(
            Command::Core(step.cmd.clone()),
            step.ctx(now, CommandId::from_bytes(*b"mcreator-lane:01")),
        )
        .map_err(|e| format!("the manager grant: {e:?}"))?;
    let owner = login(c, OWNER);
    let base = revision(c, &owner, p)?;
    done(
        c.web(&owner, rq::apply_start(p, &base, rq::supersafe_start())),
        "creator.apply_start",
    )?;
    loop {
        let draft = done(c.web(&owner, rq::get_draft(p)), "creator.get_draft")?;
        let key = draft
            .get("pending_narratives")
            .and_then(Value::as_object)
            .and_then(|o| o.keys().next().map(str::to_owned));
        let Some(key) = key else { break };
        let base = str_of(&draft, "revision")?;
        done(
            c.web(&owner, rq::accept_narrative(p, &key, &base)),
            "creator.accept_narrative",
        )?;
    }
    fill_gaps(c, &owner, p)?;
    let report = done(c.web(&owner, rq::get_report(p)), "creator.get_report")?;
    let mut failures = Vec::new();
    for r in list_of(&report, "results")? {
        let check = str_of(&r, "check")?;
        match str_of(&r, "severity")?.as_str() {
            "failure" => failures.push(check),
            _ if r.get("acknowledged").and_then(Value::as_bool) == Some(true) => {}
            _ => {
                let key = r
                    .get("key")
                    .and_then(Value::as_str)
                    .map_or_else(|| check.clone(), str::to_owned);
                let rev = revision(c, &owner, p)?;
                done(
                    c.web(&owner, rq::acknowledge(p, &rev, &key)),
                    "creator.acknowledge",
                )?;
            }
        }
    }
    if !failures.is_empty() {
        return Err(format!("the draft is not clean: {failures:?}"));
    }
    let rev = revision(c, &owner, p)?;
    done(
        c.web(&owner, rq::request_activation(p, &rev)),
        "creator.request_activation",
    )?;
    Ok(Requested {
        p,
        admin2: login(c, ADMIN_2),
    })
}

/// M1 saves each field the report names as unset from the synthetic
/// SuperSAFE spec, as journey J1 fills the template's gaps.
fn fill_gaps(c: &FakeCell, owner: &WebLogin, p: ProgrammeId) -> Result<(), String> {
    let report = done(c.web(owner, rq::get_report(p)), "creator.get_report")?;
    let spec = fstp_api_testkit::fake::draft_cell::synthetic_spec()?;
    let mut fields: Vec<(String, Value)> = Vec::new();
    for r in list_of(&report, "results")? {
        if r.get("check").and_then(Value::as_str) != Some("FieldUnset") {
            continue;
        }
        let key = str_of(&r, "field")?;
        let id = fstp_programme::FieldId::from_key(&key).ok_or_else(|| format!("{key:?}"))?;
        let value = spec
            .get(id)
            .as_set()
            .cloned()
            .ok_or_else(|| format!("the synthetic spec leaves {key:?} unset"))?;
        let json = fstp_json::parse(fstp_programme::encode_field_value(&value).as_bytes())
            .map_err(|e| format!("{key:?}: {e:?}"))?;
        fields.push((key, json));
    }
    if fields.is_empty() {
        return Ok(());
    }
    let base = revision(c, owner, p)?;
    let edits: Vec<(&str, Value)> = fields
        .iter()
        .map(|(k, v)| (k.as_str(), v.clone()))
        .collect();
    done(
        c.web(owner, rq::save_fields(p, &base, &edits)),
        "creator.save_fields",
    )
    .map(|_| ())
}

/// A2's approval of `d` at its current revision, with a step-up.
fn approve(c: &FakeCell, d: &Requested) -> Result<OpResult, ApiError> {
    let rev = revision(c, &d.admin2, d.p).unwrap_or_else(|e| panic!("{e}"));
    stepped(c, &d.admin2, || rq::approve_activation(d.p, &rev))
}

/// I-66, I-04, Q35 A: when the vault answers no to `classes_defined` at
/// the approval, `ExclusionClassUnknown` fails and the approval is
/// refused with I-66. The programme stays a draft. With the vault's yes
/// the same approval activates it.
#[test]
fn i66_q35_classes_not_defined_at_approval_refuses_activation() {
    let c = cell();
    let d = requested(&c).unwrap_or_else(|e| panic!("the requested draft: {e}"));
    c.ports.vault.set_q35(false, true);
    let r = approve(&c, &d);
    assert_eq!(rule(&r), Some("I-66"), "{r:?}");
    assert_eq!(
        programme_status(&c.ports.engine.state().core, d.p),
        Some(ProgrammeStatus::Draft)
    );
    c.ports.vault.set_q35(true, true);
    done(approve(&c, &d), "the approval with the vault's yes").unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        programme_status(&c.ports.engine.state().core, d.p),
        Some(ProgrammeStatus::Active)
    );
}

/// I-66, I-35, P-38, Q35 A: when the vault answers no to
/// `proximity_lists_declared` at the approval, `ProximityListMissing` is
/// a fresh warning no one acknowledged, so the approval is refused with
/// I-66 and the programme stays a draft.
#[test]
fn i66_q35_proximity_lists_not_declared_at_approval_refuses_activation() {
    let c = cell();
    let d = requested(&c).unwrap_or_else(|e| panic!("the requested draft: {e}"));
    c.ports.vault.set_q35(true, false);
    let r = approve(&c, &d);
    assert_eq!(rule(&r), Some("I-66"), "{r:?}");
    assert_eq!(
        programme_status(&c.ports.engine.state().core, d.p),
        Some(ProgrammeStatus::Draft)
    );
}

/// I-78, I-66, section 15.0 (2026-11-06): approving a programme's
/// activation is high-risk. Without a fresh step-up the approval asks for
/// one and the programme stays a draft. The same approval completes once
/// the step-up is approved.
#[test]
fn i78_activation_approval_without_a_fresh_step_up_is_refused() {
    let c = cell();
    let d = requested(&c).unwrap_or_else(|e| panic!("the requested draft: {e}"));
    let rev = revision(&c, &d.admin2, d.p).unwrap_or_else(|e| panic!("{e}"));
    let r = c.web(&d.admin2, rq::approve_activation(d.p, &rev));
    assert!(
        matches!(r, Ok(OpResult::StepUpRequired(_))),
        "the approval without a step-up gave {r:?}"
    );
    assert_eq!(
        programme_status(&c.ports.engine.state().core, d.p),
        Some(ProgrammeStatus::Draft)
    );
    done(approve(&c, &d), "the approval with a step-up").unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        programme_status(&c.ports.engine.state().core, d.p),
        Some(ProgrammeStatus::Active)
    );
}

// ---------------------------------------------------------------------------
// R-PC-02, R-PC-03: the Studio's call reads
// ---------------------------------------------------------------------------

/// `call.draft` through the web: `POST /programmes/{p}/calls`.
fn draft_call(p: ProgrammeId) -> Result<Op, ApiError> {
    let body = fstp_json::parse(
        br#"{"opens":"1000000000000","deadline":"2000000000000","deadline_zone":"Europe/Brussels","currency":"EUR","budget":"400000.00","text":"SYNTHETIC STUDIO CALL TEXT"}"#,
    )
    .map(|v| v.to_compact().into_bytes())
    .unwrap_or_default();
    decode_route(
        Method::Post,
        &format!("/programmes/{}/calls", p.raw()),
        &body,
    )
}

/// `call.list` through the web: `GET /programmes/{p}/calls`.
fn list_calls(p: ProgrammeId) -> Result<Op, ApiError> {
    decode_route(Method::Get, &format!("/programmes/{}/calls", p.raw()), &[])
}

/// `call.approve` through the web: `POST /calls/{c}/approval`.
fn approve_call(c: &str) -> Result<Op, ApiError> {
    decode_route(Method::Post, &format!("/calls/{c}/approval"), b"{}")
}

/// The row of `call` in a `call.list` reply: its status and `may_approve`.
fn call_row(v: &Value, call: &str) -> Result<(String, bool), String> {
    let rows = v
        .as_array()
        .ok_or_else(|| format!("not a list: {}", v.to_compact()))?;
    let row = rows
        .iter()
        .find(|r| r.get("call").and_then(Value::as_str) == Some(call))
        .ok_or_else(|| format!("no call {call} in {}", v.to_compact()))?;
    let may = row
        .get("may_approve")
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("no may_approve in {}", row.to_compact()))?;
    Ok((str_of(row, "status")?, may))
}

/// R-PC-02, lane mcreator: `call.draft` answers the id of the call it
/// drew, and the call is then a draft of the programme.
#[test]
fn r_pc_02_call_draft_returns_the_new_call_id() {
    let c = cell();
    let drafter = login(&c, OTHER);
    let v = done(c.web(&drafter, draft_call(P1)), "call.draft").unwrap_or_else(|e| panic!("{e}"));
    let id = str_of(&v, "call").unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(v.get("accepted").and_then(Value::as_bool), Some(true));
    let raw: u128 = id.parse().unwrap_or_else(|_| panic!("not an id: {id}"));
    let view = c
        .ports
        .engine
        .state()
        .core
        .calls()
        .get(CallId::from_raw(raw))
        .map(|v| (v.programme(), v.status()));
    assert_eq!(view, Some((P1, CallStatus::Draft)));
}

/// R-PC-03, lane mcreator: the staff list of a programme's calls gives
/// each call's state, and `may_approve` is false to a drafter of the
/// call, false on a call that is no longer a draft, and true to a
/// programme manager outside the drafters, whose approval then succeeds.
#[test]
fn r_pc_03_staff_calls_read_gives_may_approve_false_to_a_drafter() {
    let c = cell();
    let owner = login(&c, OWNER);
    let drafter = login(&c, OTHER);
    let mine =
        done(c.web(&owner, draft_call(P2)), "call.draft in P2").unwrap_or_else(|e| panic!("{e}"));
    let mine = str_of(&mine, "call").unwrap_or_else(|e| panic!("{e}"));
    let p2 =
        done(c.web(&owner, list_calls(P2)), "call.list of P2").unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        call_row(&p2, &mine).unwrap_or_else(|e| panic!("{e}")),
        ("draft".to_owned(), false),
        "the drafting manager"
    );
    assert_eq!(
        call_row(&p2, "4").unwrap_or_else(|e| panic!("{e}")),
        ("approved".to_owned(), false),
        "an approved call"
    );
    let theirs =
        done(c.web(&drafter, draft_call(P1)), "call.draft in P1").unwrap_or_else(|e| panic!("{e}"));
    let theirs = str_of(&theirs, "call").unwrap_or_else(|e| panic!("{e}"));
    let as_drafter = done(c.web(&drafter, list_calls(P1)), "call.list by the drafter")
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        call_row(&as_drafter, &theirs).unwrap_or_else(|e| panic!("{e}")),
        ("draft".to_owned(), false),
        "the call drafter"
    );
    let p1 =
        done(c.web(&owner, list_calls(P1)), "call.list of P1").unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        call_row(&p1, "3").unwrap_or_else(|e| panic!("{e}")),
        ("published".to_owned(), false)
    );
    assert_eq!(
        call_row(&p1, &theirs).unwrap_or_else(|e| panic!("{e}")),
        ("draft".to_owned(), true),
        "a manager outside the drafters"
    );
    done(c.web(&owner, approve_call(&theirs)), "call.approve").unwrap_or_else(|e| panic!("{e}"));
    let r = c.web(&login(&c, LEAD), list_calls(P1));
    assert!(r.is_err(), "the applicant read the calls: {r:?}");
}
