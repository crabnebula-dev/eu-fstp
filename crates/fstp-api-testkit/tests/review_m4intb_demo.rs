//! Review of lane m4int-b (the demo): reproducers of the findings.
//!
//! Each test drives `ApiCore::dispatch` on the fake cell of the I-85
//! world, through the adapter-facing decoders, and fails against the
//! lane's code.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_api_core::decode::{Method, decode_route, decode_tool};
use fstp_api_core::meta::Scope;
use fstp_api_core::model::ReadModel;
use fstp_api_core::port::{LoginMethod, api_core};
use fstp_api_core::{Credential, OpResult, RequestHead};
use fstp_api_testkit::fake::cell::{Class, class};
use fstp_api_testkit::fake::fixture::{AGENT_2, CALL_OPEN, LEAD, PX, px_plan};
use fstp_api_testkit::fake::{FakeCell, requests};
use fstp_domain::id::{PlanVersionId, ProposalId};
use fstp_engine::Command;
use fstp_json::{Object, Value};
use fstp_rt::future::block_on;

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

/// The page form of `proposal.record_plan`: one milestone of `amount`
/// EUR.
fn plan_page_form(amount: &str) -> Vec<u8> {
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
        ("description", Value::from("SYNTHETIC WORK PLAN")),
        ("tasks", Value::Array(fstp_json::Array::from(vec![task]))),
    ])
    .to_compact()
    .into_bytes()
}

/// The latest `RecordPlanVersion` the engine appended.
fn last_recorded_plan(c: &FakeCell) -> PlanVersionId {
    c.ports
        .engine
        .appended()
        .iter()
        .rev()
        .find_map(|e| match &e.cmd {
            Command::Core(fstp_domain::Command::RecordPlanVersion { plan, .. }) => Some(*plan),
            _ => None,
        })
        .expect("a recorded plan")
}

/// I-85, P-77, design section 3.7 step 6: a confirmation executes the
/// action the user was shown. A submission prepared through MCP without
/// a `plan` member is completed with whatever plan is latest at
/// confirmation time (`Derive::LatestPlan`), so a plan the agent records
/// after the preparation is submitted under the digest of the earlier
/// action. The confirmed submission must name the plan current when the
/// action was prepared, or the confirmation must be refused.
#[test]
fn review_i85_confirmed_submission_binds_the_plan_shown() {
    let c = cell();
    let lead = c.login(LEAD, LoginMethod::Passkey);
    let token = c.token(
        LEAD,
        AGENT_2,
        [
            Scope::ProposalsRead,
            Scope::ProposalsDraft,
            Scope::ProposalsBinding,
        ],
        LoginMethod::Passkey,
    );

    // A new draft through the page, so that every plan of it passes
    // through this core.
    let r = c.web(
        &lead,
        decode_route(
            Method::Post,
            &format!("/calls/{}/proposals", CALL_OPEN.raw()),
            b"{}",
        ),
    );
    let p = match r {
        Ok(OpResult::Done {
            body: ReadModel::Created(ids),
            ..
        }) => ProposalId::from_raw(ids.iter().find(|(n, _)| *n == "proposal").unwrap().1),
        other => panic!("proposal.create gave {other:?}"),
    };

    // Plan A, through the page.
    let r = c.web(
        &lead,
        decode_route(
            Method::Put,
            &format!("/proposals/{}/plan", p.raw()),
            &plan_page_form("1000.00"),
        ),
    );
    assert_eq!(class(&r), Class::Done, "plan A: {r:?}");
    let plan_a = last_recorded_plan(&c);

    // The agent prepares the submission without naming a plan: P1 is
    // "draft only", so it waits for the user's confirmation.
    let ethics = object(vec![
        ("issues_declared", Value::Bool(false)),
        ("text", Value::from("SYNTHETIC ETHICS TEXT")),
    ]);
    let submit = object(vec![
        ("proposal", Value::from(p.raw().to_string())),
        ("ethics", ethics),
        ("notice", Value::Number(fstp_json::Number::from(1u32))),
    ]);
    let r = c.mcp(
        &token,
        decode_tool("fstp_submit_proposal", &submit.to_compact().into_bytes()),
    );
    assert_eq!(class(&r), Class::Pending, "the prepared submission: {r:?}");

    // The agent then records plan B, a draft action P-77 allows.
    let r = c.mcp(
        &token,
        decode_tool("fstp_record_plan_version", &{
            let mut v =
                fstp_json::parse_str(std::str::from_utf8(&plan_page_form("9000.00")).unwrap())
                    .unwrap();
            if let Value::Object(o) = &mut v {
                let _ = o.insert("proposal", Value::from(p.raw().to_string()));
            }
            v.to_compact().into_bytes()
        }),
    );
    assert_eq!(class(&r), Class::Done, "plan B through MCP: {r:?}");
    let plan_b = last_recorded_plan(&c);
    assert_ne!(plan_a, plan_b);

    // The user confirms the action shown, with its digest.
    let mine = c.pending(&lead).unwrap();
    assert_eq!(mine.len(), 1, "{mine:?}");
    let shown = &mine[0];
    let r = c.web(&lead, requests::pending_confirm(shown.id, &shown.digest));
    let submitted = c.ports.engine.appended().iter().find_map(|e| match &e.cmd {
        Command::Core(fstp_domain::Command::Submit { plan, .. }) => Some(*plan),
        _ => None,
    });
    assert!(
        submitted.is_none() || submitted == Some(plan_a),
        "the confirmation of the action shown (request {}) submitted plan {:?}, \
         recorded after the preparation, instead of plan {:?}: {r:?}",
        shown.request,
        submitted,
        plan_a,
    );
}

/// R-SB-01, I-84, design section 3.7: the submission of the page form
/// takes "the proposal's latest recorded plan". PX has a plan recorded in
/// the ledger (`px_plan`), so the submission must name it. The core reads
/// the latest plan from its own memory of the commands it executed
/// (`journal.rs`), which holds no plan recorded before it started, and
/// refuses with R-SB-01.
///
/// Corrected in fix round 1 of lane m4int-b. The full fix needs a public
/// read accessor of the domain for a proposal's plans (lane W1b), which
/// is outside the lane's files. Until it lands, the finding's own interim
/// applies: the core fails closed with `NotImplemented` on a proposal
/// whose history it does not hold. So the test accepts the submission of
/// the ledger plan, or that fail-closed answer with nothing appended. It
/// still refuses the wrong R-SB-01 refusal, and any other plan.
#[test]
fn review_r_sb_01_page_submission_takes_the_ledger_plan() {
    let c = cell();
    let lead = c.login(LEAD, LoginMethod::Passkey);
    let body = object(vec![
        ("ethics", Value::from("none")),
        ("notice_version", Value::from("1")),
    ]);
    let r = c.web(
        &lead,
        decode_route(
            Method::Post,
            &format!("/proposals/{}/submission", PX.raw()),
            &body.to_compact().into_bytes(),
        ),
    );
    let submitted = c.ports.engine.appended().iter().find_map(|e| match &e.cmd {
        Command::Core(fstp_domain::Command::Submit { plan, .. }) => Some(*plan),
        _ => None,
    });
    match class(&r) {
        Class::Done => assert_eq!(submitted, Some(px_plan())),
        Class::Stub => assert_eq!(submitted, None, "a fail-closed answer appends nothing"),
        other => {
            panic!("the page submission of a proposal with a recorded plan gave {other:?}: {r:?}")
        }
    }
}

/// I-21, design section 4.1: the team's private draft lives in the
/// sealed `workspace` store, not in the memory of one API core. A second
/// core over the same ports (a restart, or a second cell process) must
/// read the draft the team saved. The lane's `content.rs` keeps it in
/// process memory, so the second core reads an empty workspace.
///
/// Corrected in fix round 1 of lane m4int-b. The full fix needs a
/// workspace port and a read clearance in `port.rs`, which the lead owns.
/// Until they land, the finding's own interim applies: a core that does
/// not hold the workspace fails closed with `NotImplemented`. So the test
/// accepts the saved draft, or that fail-closed answer, and still refuses
/// the empty draft the lane's code showed.
#[test]
fn review_i21_saved_workspace_survives_a_new_core() {
    let c = cell();
    let lead = c.login(LEAD, LoginMethod::Passkey);
    let path = format!("/proposals/{}/workspace", PX.raw());
    let body = object(vec![
        ("narrative", Value::from("SYNTHETIC NARRATIVE")),
        ("summary", Value::from("SYNTHETIC SUMMARY")),
        ("title", Value::from("SYNTHETIC TITLE")),
    ]);
    let r = c.web(
        &lead,
        decode_route(Method::Put, &path, &body.to_compact().into_bytes()),
    );
    assert_eq!(class(&r), Class::Done, "the save: {r:?}");

    let second = api_core(c.ports.clone());
    let op = decode_route(Method::Get, &path, &[]).unwrap();
    let r = block_on(second.dispatch(
        Credential::SessionCookie(lead.cookie.clone()),
        &RequestHead::new(),
        op,
    ));
    match r {
        Ok(OpResult::Done {
            body: ReadModel::Workspace(w),
            ..
        }) => assert_eq!(
            w.title, "SYNTHETIC TITLE",
            "the saved draft is lost to a second core"
        ),
        Err(fstp_api_core::ApiError::NotImplemented(_)) => {}
        other => panic!("proposal.get_workspace gave {other:?}"),
    }
}
