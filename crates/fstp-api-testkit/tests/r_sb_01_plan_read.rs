//! The team reads back the plan it recorded (`proposal.get_plan`, R-SB-01,
//! ADR-006; Daniel, 2026-11-15, night: "if i wrote it i should be able
//! to read it"; lane m4/author-reads).
//!
//! The read gives the head of the proposal's plan chain, read-only: its
//! id, its origin, its tasks with each milestone's amount and days, and
//! the total the cell summed. The work plan text is held outside the
//! domain. The plan record names it by its reference beside its digest
//! (ADR-007; Daniel, 2026-11-16: "fix now", so the text reads back after
//! restarts and in seeded scenes). The read gives the stored text, says
//! when it was erased, and leaves it out for a plan that names none,
//! never showing an empty or a changed text in its place.
//!
//! Every account and text is synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_api_core::decode::{Method, decode_route};
use fstp_api_core::model::ReadModel;
use fstp_api_core::port::LoginMethod;
use fstp_api_core::{ApiError, OpResult};
use fstp_api_testkit::fake::FakeCell;
use fstp_api_testkit::fake::cell::{Class, class};
use fstp_api_testkit::fake::fixture::{CALL_OPEN, LEAD, OTHER, PX, px_plan};
use fstp_json::{Object, ToJson, Value};

fn cell() -> FakeCell {
    FakeCell::new().unwrap_or_else(|e| panic!("the fake cell: {e}"))
}

fn object(members: Vec<(&str, Value)>) -> Value {
    let mut o = Object::new();
    for (k, v) in members {
        let _ = o.insert(k, v);
    }
    Value::Object(o)
}

/// The page form of `proposal.record_plan`: one task with one milestone
/// of `amount` EUR, and the work plan text `text`.
fn plan_page_form(amount: &str, text: &str) -> Vec<u8> {
    let milestone = object(vec![
        ("amount", Value::from(amount)),
        ("start", Value::from("1970-01-02")),
        ("due", Value::from("1970-06-30")),
    ]);
    let task = object(vec![(
        "milestones",
        Value::Array(fstp_json::Array::from(vec![milestone])),
    )]);
    object(vec![
        ("description", Value::from(text)),
        ("tasks", Value::Array(fstp_json::Array::from(vec![task]))),
    ])
    .to_compact()
    .into_bytes()
}

/// A new draft of LEAD in the open call, through the page.
fn new_draft(c: &FakeCell) -> u128 {
    let lead = c.login(LEAD, LoginMethod::Passkey);
    let r = c.web(
        &lead,
        decode_route(
            Method::Post,
            &format!("/calls/{}/proposals", CALL_OPEN.raw()),
            b"{}",
        ),
    );
    match r {
        Ok(OpResult::Done {
            body: ReadModel::Created(ids),
            ..
        }) => ids.iter().find(|(n, _)| *n == "proposal").unwrap().1,
        other => panic!("proposal.create gave {other:?}"),
    }
}

/// Records a plan of `p` through the page, as LEAD.
fn record(c: &FakeCell, p: u128, amount: &str, text: &str) {
    let lead = c.login(LEAD, LoginMethod::Passkey);
    let r = c.web(
        &lead,
        decode_route(
            Method::Put,
            &format!("/proposals/{p}/plan"),
            &plan_page_form(amount, text),
        ),
    );
    assert_eq!(class(&r), Class::Done, "the plan: {r:?}");
}

/// `proposal.get_plan` of `p` as `account`.
fn read(c: &FakeCell, account: fstp_domain::id::AccountId, p: u128) -> Result<OpResult, ApiError> {
    let login = c.login(account, LoginMethod::Passkey);
    c.web(
        &login,
        decode_route(Method::Get, &format!("/proposals/{p}/plan"), &[]),
    )
}

/// The reply body of a completed read, as the API sends it.
fn body(r: Result<OpResult, ApiError>) -> Value {
    match r {
        Ok(OpResult::Done { body, .. }) => body.to_json(),
        other => panic!("proposal.get_plan gave {other:?}"),
    }
}

/// The `plan` member of a reply.
fn plan_of(v: &Value) -> &Object {
    v.as_object()
        .and_then(|o| o.get("plan"))
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("no plan in {}", v.to_compact()))
}

/// R-SB-01, ADR-006, lane m4/author-reads: the lead reads back the plan
/// recorded through the page, read-only, with its tasks, each
/// milestone's amount and days, the total the cell summed and the work
/// plan text. A later version replaces it as the head of the chain.
#[test]
fn r_sb_01_lead_reads_back_the_plan_recorded_through_the_page() {
    let c = cell();
    let p = new_draft(&c);
    record(&c, p, "1000.00", "SYNTHETIC WORK PLAN A");
    record(&c, p, "2500.50", "SYNTHETIC WORK PLAN <b>B</b>");
    let v = body(read(&c, LEAD, p));
    let plan = plan_of(&v);
    let mut keys: Vec<&str> = plan.keys().collect();
    keys.sort_unstable();
    assert_eq!(keys, ["origin", "plan", "tasks", "text", "total"]);
    assert_eq!(
        plan.get("origin").and_then(Value::as_str),
        Some("submitted")
    );
    assert_eq!(plan.get("total").and_then(Value::as_str), Some("2500.50"));
    assert_eq!(
        plan.get("text").and_then(Value::as_str),
        Some("SYNTHETIC WORK PLAN <b>B</b>"),
        "the text of the head version, as typed"
    );
    let tasks = plan.get("tasks").and_then(Value::as_array).unwrap();
    assert_eq!(tasks.len(), 1);
    let milestones = tasks[0]
        .as_object()
        .and_then(|t| t.get("milestones"))
        .and_then(Value::as_array)
        .unwrap();
    assert_eq!(milestones.len(), 1);
    let m = milestones[0].as_object().unwrap();
    assert_eq!(m.get("amount").and_then(Value::as_str), Some("2500.50"));
    assert_eq!(m.get("start").and_then(Value::as_str), Some("1970-01-02"));
    assert_eq!(m.get("due").and_then(Value::as_str), Some("1970-06-30"));
}

/// R-SB-01, ADR-007 (Daniel, 2026-11-16: the plan text must read back
/// after a restart): the plan record names its stored text, so a
/// restarted cell, whose API core holds nothing in memory, reads back the
/// structure, the total and the work plan text. This test pinned the
/// omission of the text before that decision.
#[test]
fn r_sb_01_plan_read_after_a_restart_reads_the_text_back() {
    let c = cell();
    let p = new_draft(&c);
    record(&c, p, "1000.00", "SYNTHETIC WORK PLAN");
    let again = c.restarted().unwrap();
    let v = body(read(&again, LEAD, p));
    let plan = plan_of(&v);
    assert_eq!(plan.get("total").and_then(Value::as_str), Some("1000.00"));
    assert_eq!(
        plan.get("text").and_then(Value::as_str),
        Some("SYNTHETIC WORK PLAN"),
        "the text the plan names, read through the text store"
    );
    assert_eq!(plan.get("text_erased"), None);
}

/// R-SB-01, ADR-007: a plan seeded into the ledger in the form recorded
/// before plans named their text reads with its structure and no text,
/// and is not taken for an erased one. A draft with no plan reads as
/// `{"plan": null}`.
#[test]
fn r_sb_01_plan_read_of_a_seeded_plan_and_of_a_draft_with_none() {
    let c = cell();
    let v = body(read(&c, LEAD, PX.raw()));
    let plan = plan_of(&v);
    assert_eq!(
        plan.get("plan").and_then(Value::as_str),
        Some(px_plan().raw().to_string().as_str())
    );
    assert_eq!(plan.get("text"), None);
    assert_eq!(plan.get("text_erased"), None);
    let p = new_draft(&c);
    let v = body(read(&c, LEAD, p));
    assert_eq!(v.to_compact(), r#"{"plan":null}"#);
}

/// R-AC-01, I-21: a caller with no Receiving binding on X is refused the
/// plan read.
#[test]
fn r_ac_01_plan_read_refuses_outsiders() {
    let c = cell();
    let r = read(&c, OTHER, PX.raw());
    assert!(
        matches!(r, Err(ApiError::Refused { .. })),
        "an outsider read the plan: {r:?}"
    );
}

/// Erases every text of `p` in the text store, as a tenant admin's
/// request does once the API core checked it (ADR-007).
fn erase_texts_of(c: &FakeCell, p: u128) {
    use fstp_api_core::port::{ErasureCause, StepUpProof, StepUpRef, TextStore as _};
    let at = c.ports.clock.read();
    let proof = StepUpProof {
        step_up: StepUpRef(1),
        action: fstp_api_core::ActionDigest([0; 32]),
    };
    fstp_rt::future::block_on(c.ports.texts.request_erasure(
        fstp_api_testkit::fake::fixture::ADMIN,
        ErasureCause::ErasureRequest,
        fstp_domain::id::ProposalId::from_raw(p),
        at,
        proof,
    ))
    .expect("the store erases the proposal's texts");
}

/// R-SB-01, ADR-007 ("after erasure, a `TextRef` resolves to the text's
/// entry in the erasure log, never to the text"): once the plan's text
/// is erased, the read says so with the day of the request. It never
/// gives the text, not even from the memory of the process that stored
/// it, and never reads as a text the cell does not hold. After a restart
/// it reads the same.
#[test]
fn r_sb_01_adr007_erased_plan_text_reads_as_erased() {
    let c = cell();
    let p = new_draft(&c);
    record(&c, p, "1000.00", "SYNTHETIC WORK PLAN TO ERASE");
    erase_texts_of(&c, p);
    let day = {
        let v = body(read(&c, LEAD, p));
        let plan = plan_of(&v);
        assert_eq!(plan.get("text"), None, "an erased text was shown");
        assert!(
            !v.to_compact().contains("SYNTHETIC WORK PLAN TO ERASE"),
            "the erased text leaked: {}",
            v.to_compact()
        );
        assert_eq!(plan.get("total").and_then(Value::as_str), Some("1000.00"));
        plan.get("text_erased")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("the erasure is not named: {}", v.to_compact()))
            .to_owned()
    };
    assert_eq!(day.len(), 10, "a UTC day: {day}");
    let again = c.restarted().unwrap();
    let v = body(read(&again, LEAD, p));
    let plan = plan_of(&v);
    assert_eq!(plan.get("text"), None);
    assert_eq!(
        plan.get("text_erased").and_then(Value::as_str),
        Some(day.as_str())
    );
}

/// R-SB-01, R-AC-01, ADR-007 (Daniel, 2026-11-15: "if i wrote it i should
/// be able to read it"): a text store that keeps no erasure log, as the
/// production cell's does today, still gives the team its plan text,
/// read from the store itself. Once the store no longer holds the text,
/// the read fails closed, even though the process that stored it still
/// remembers it.
#[test]
fn r_sb_01_adr007_store_without_log_serves_the_plan_from_the_store() {
    let c = cell();
    let p = new_draft(&c);
    record(&c, p, "1000.00", "SYNTHETIC WORK PLAN WITHOUT LOG");
    c.ports.texts.without_log();
    let v = body(read(&c, LEAD, p));
    let plan = plan_of(&v);
    assert_eq!(
        plan.get("text").and_then(Value::as_str),
        Some("SYNTHETIC WORK PLAN WITHOUT LOG")
    );
    // The store no longer holds the text (an erasure without a log).
    for r in 0..64u128 {
        if c.ports
            .texts
            .peek(fstp_api_core::port::TextRef(r))
            .is_some_and(|b| b.ends_with(b"SYNTHETIC WORK PLAN WITHOUT LOG"))
        {
            c.ports.texts.forget(fstp_api_core::port::TextRef(r));
        }
    }
    let after = read(&c, LEAD, p);
    let shown = format!("{after:?}");
    assert!(
        !shown.contains("SYNTHETIC WORK PLAN WITHOUT LOG"),
        "a copy held in the process was served: {shown}"
    );
    assert!(after.is_err(), "the read fails closed: {shown}");
}
