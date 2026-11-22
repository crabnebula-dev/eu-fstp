//! The assessment run by the FSTP coordinator's connected agent, through
//! the API core of the test cell (ADR-033). Tests only.
//!
//! Each test builds the review scene at SUBMITTED with the programme's
//! P-21 on the client path, then calls the three tools as an agent with a
//! bearer token of the scope `assess:run`, as the plugin's assessor agent
//! does. Every account and text is synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing)]

use fstp_access::Scope;
use fstp_api_core::port::{AgentClientId, AsyncEngine as _, Clock as _, LoginMethod};
use fstp_domain::id::{AccountId, CallId, ProposalId};
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::review::{COORDINATOR, L1, R1};
use fstp_json::{Array, Object, Value};

use super::*;

/// The model the scene pins and the agent reports.
const MODEL: &str = "claude-opus-5-5";
/// Proposal w of the review scene: the corpus item with a direct
/// injection aimed at the assessor.
const W: u128 = 1003;

fn info() -> SiteInfo {
    SiteInfo {
        name: "a",
        host: "a.fstp.localhost".to_owned(),
        origin: "http://a.fstp.localhost:8640".to_owned(),
        control: "http://127.0.0.1:8641".to_owned(),
        assets: fstp_web_assets::AssetSet::from_files("main.js", &[("main.js", b"export {};")])
            .unwrap(),
        auth_assets: std::sync::Arc::new(crate::assets::AuthAssets::empty()),
        demo_signin: false,
        tokens: fstp_api_testkit::fake::FakeTokens::default(),
    }
}

/// The review scene at SUBMITTED on the client path, and its seed reply.
fn scene() -> (Inner, Value) {
    crate::assess::set_test_mode(Some(crate::assess::Mode::Client(MODEL.to_owned())));
    let stage = crate::scenario::ReviewAt::parse("submitted").unwrap();
    let built = fstp_rt::future::block_on(crate::scenario::build_review(&info(), stage));
    crate::assess::set_test_mode(None);
    built.unwrap()
}

/// Moves the cell's clock one second on.
fn tick(inner: &Inner) {
    let now = Timestamp::from_micros(inner.ports.clock.now().micros().saturating_add(1_000_000));
    inner.ports.clock.set(now);
}

fn answer(done: Result<fstp_api_core::OpResult, fstp_api_core::ApiError>) -> Result<Value, String> {
    match done {
        Ok(fstp_api_core::OpResult::Done { body, .. }) => Ok(fstp_json::ToJson::to_json(&body)),
        Ok(_) => Err("not done".to_owned()),
        Err(e) => Err(fstp_json::ToJson::to_json(&e).to_compact()),
    }
}

/// A web call by `account` with a passkey session.
fn web(
    inner: &Inner,
    account: AccountId,
    method: fstp_api_core::decode::Method,
    path: &str,
    body: &str,
) -> Result<Value, String> {
    tick(inner);
    let cookie = inner
        .ports
        .sessions
        .login(account, LoginMethod::Passkey)
        .cookie;
    let op = fstp_api_core::decode::decode_route(method, path, body.as_bytes())
        .map_err(|e| format!("{path}: {e}"))?;
    answer(fstp_rt::future::block_on(inner.core.dispatch(
        fstp_api_core::Credential::SessionCookie(cookie),
        &fstp_api_core::RequestHead::new(),
        op,
    )))
}

/// A bearer token of `account`'s agent with `scopes`.
fn token(inner: &Inner, account: AccountId, scopes: &[Scope]) -> Vec<u8> {
    inner.ports.tokens.issue(
        account,
        AgentClientId::from_raw(0xadc0_0000u128.saturating_add(account.raw())),
        scopes.iter().copied(),
        LoginMethod::Passkey,
    )
}

/// A tool call with `token`.
fn tool(inner: &Inner, token: &[u8], name: &str, arguments: &str) -> Result<Value, String> {
    tick(inner);
    let op = fstp_api_core::decode::decode_tool(name, arguments.as_bytes())
        .map_err(|e| format!("{name}: {e}"))?;
    answer(fstp_rt::future::block_on(inner.core.dispatch(
        fstp_api_core::Credential::Bearer(token.to_vec()),
        &fstp_api_core::RequestHead::new(),
        op,
    )))
}

/// The coordinator declares no conflict on `p` in the web.
fn declare(inner: &Inner, p: u128) {
    web(
        inner,
        COORDINATOR,
        fstp_api_core::decode::Method::Post,
        &format!("/proposals/{p}/coordinator-declaration"),
        r#"{"conflicted":false,"notifiable":false}"#,
    )
    .unwrap();
}

/// The coordinator releases the integrity hold of `p` in the web
/// (ADR-035).
fn release(inner: &Inner, p: u128) -> Result<Value, String> {
    web(
        inner,
        COORDINATOR,
        fstp_api_core::decode::Method::Post,
        &format!("/proposals/{p}/integrity-release"),
        "{}",
    )
}

/// Releases every held proposal of the scene: the seeded injections w and
/// v are held by the scan at submission (ADR-035).
fn release_all(inner: &Inner) {
    let held: Vec<u128> = [1001_u128, 1002, W, 1004, 1005]
        .into_iter()
        .filter(|p| {
            inner
                .ports
                .engine
                .state()
                .findings
                .held(ProposalId::from_raw(*p))
        })
        .collect();
    for p in held {
        release(inner, p).unwrap();
    }
}

fn s(v: &Value, k: &str) -> String {
    v.get(k)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("no {k}: {}", v.to_compact()))
        .to_owned()
}

/// The narrative part of an input.
fn narrative(input: &Value) -> String {
    input
        .get("parts")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .find(|p| p.get("label").and_then(Value::as_str) == Some("narrative"))
        .map(|p| s(p, "text"))
        .unwrap()
}

/// A finding object of the v1 output schema.
fn finding(
    kind: &str,
    criterion: Option<&str>,
    element: Option<&str>,
    statement: &str,
    quote: &str,
) -> Value {
    let mut ev = Object::new();
    ev.insert("part", Value::from("narrative"));
    ev.insert("quote", Value::from(quote));
    let mut o = Object::new();
    o.insert("kind", Value::from(kind));
    o.insert("criterion", criterion.map_or(Value::Null, Value::from));
    o.insert("element", element.map_or(Value::Null, Value::from));
    o.insert("severity", Value::from("minor"));
    o.insert("statement", Value::from(statement));
    o.insert(
        "evidence",
        Value::Array(vec![Value::Object(ev)].into_iter().collect::<Array>()),
    );
    Value::Object(o)
}

fn reply(stage: &str, output: Value) -> Value {
    let mut o = Object::new();
    o.insert("stage", Value::from(stage));
    o.insert("output", output);
    Value::Object(o)
}

fn findings(list: Vec<Value>) -> Value {
    let mut o = Object::new();
    o.insert(
        "findings",
        Value::Array(list.into_iter().collect::<Array>()),
    );
    Value::Object(o)
}

/// The arguments of a submission of `replies` for `input`.
fn submission(input: &Value, model: &str, replies: Vec<Value>) -> String {
    let mut o = Object::new();
    o.insert("proposal", Value::from(s(input, "proposal").as_str()));
    o.insert(
        "input_digest",
        Value::from(s(input, "input_digest").as_str()),
    );
    o.insert(
        "prompt_set",
        Value::from(s(input.get("prompt_set").unwrap(), "digest").as_str()),
    );
    o.insert("model", Value::from(model));
    o.insert(
        "replies",
        Value::Array(replies.into_iter().collect::<Array>()),
    );
    Value::Object(o).to_compact()
}

/// Every engine entry after the first `from`.
fn entries_since(inner: &Inner, from: usize) -> Vec<fstp_engine::Record> {
    inner
        .ports
        .engine
        .ledger()
        .unwrap()
        .iter()
        .skip(from)
        .map(|e| e.record.clone())
        .collect()
}

fn ledger_len(inner: &Inner) -> usize {
    inner.ports.engine.ledger().unwrap().len()
}

/// The quality tasks' criteria of an input.
fn criteria(input: &Value) -> Vec<String> {
    input
        .get("tasks")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .filter_map(|t| {
            t.get("criterion")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .collect()
}

/// ADR-033, I-11, I-10: a call on the client path gets no assessment from
/// a cell assessor at submission, so its findings come from one path.
#[test]
fn adr033_i11_a_client_path_call_has_no_cell_assessment() {
    let (inner, _) = scene();
    let state = inner.ports.engine.state();
    // ADR-035: the only findings are the scan's integrity findings of the
    // flagged submissions, recorded at submission. No assessor ran.
    for f in state.findings.findings_of(CallId::from_raw(1)) {
        assert_eq!(f.kind, fstp_findings::FindingKind::Integrity);
        assert!(state.findings.integrity_of(f.proposal).is_some());
    }
    let frozen = state
        .core
        .calls()
        .get(CallId::from_raw(1))
        .unwrap()
        .frozen()
        .unwrap();
    assert!(fstp_findings::client_run(&frozen.values().p21));
}

/// ADR-033, R-LA-01, R-LA-02, I-10, I-11, I-84, I-85, R-AU-01: the
/// coordinator's agent lists the queue, reads one input after the
/// coordinator declared, and records its assessment directly, with no
/// pending action. Each finding carries the call's pin and the run's
/// trace, the provenance names the coordinator and the reported model,
/// and the read is a ledger record.
#[test]
fn adr033_coordinator_agent_assesses_a_proposal_end_to_end() {
    let (inner, _) = scene();
    let t = token(&inner, COORDINATOR, &[Scope::AssessRun]);
    let queue = tool(
        &inner,
        &t,
        "fstp_assessment_list_proposals",
        r#"{"call":"1"}"#,
    )
    .unwrap();
    assert_eq!(queue.get("open"), Some(&Value::Bool(true)));
    assert_eq!(s(&queue, "model"), MODEL);
    let rows = queue.get("proposals").and_then(Value::as_array).unwrap();
    let row = rows
        .iter()
        .find(|r| s(r, "proposal") == W.to_string())
        .unwrap();
    // ADR-035: w holds a direct injection, so it waits for the release.
    assert_eq!(s(row, "status"), "held");
    assert_eq!(row.get("declared"), Some(&Value::Bool(false)));
    release(&inner, W).unwrap();
    let queue = tool(
        &inner,
        &t,
        "fstp_assessment_list_proposals",
        r#"{"call":"1"}"#,
    )
    .unwrap();
    let row = queue
        .get("proposals")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .find(|r| s(r, "proposal") == W.to_string())
        .cloned()
        .unwrap();
    assert_eq!(s(&row, "status"), "awaiting");

    // R-CF-02: no input before the declaration.
    let early = tool(
        &inner,
        &t,
        "fstp_assessment_get_input",
        &format!(r#"{{"proposal":"{W}"}}"#),
    );
    assert!(early.unwrap_err().contains("R-CF-02"));
    declare(&inner, W);

    let before = ledger_len(&inner);
    let input = tool(
        &inner,
        &t,
        "fstp_assessment_get_input",
        &format!(r#"{{"proposal":"{W}"}}"#),
    )
    .unwrap();
    let read = entries_since(&inner, before);
    assert!(
        matches!(
            read.as_slice(),
            [fstp_engine::Record::Finding(fstp_findings::FindingRecord::AssessmentInputRead { by, .. })]
                if *by == COORDINATOR
        ),
        "R-AU-01: the read is one ledger record: {read:?}"
    );
    let n = narrative(&input);
    let quote: String = n.chars().take(40).collect();
    let mut replies = vec![
        reply("completeness", findings(Vec::new())),
        reply("claims", findings(Vec::new())),
        reply("integrity", findings(Vec::new())),
    ];
    for c in criteria(&input) {
        replies.push(reply(
            "quality",
            findings(vec![finding(
                "quality",
                Some(&c),
                None,
                "The approach is described in outline.",
                &quote,
            )]),
        ));
    }
    let before = ledger_len(&inner);
    let intake = inner
        .ports
        .engine
        .state()
        .findings
        .findings_of(CallId::from_raw(1))
        .into_iter()
        .filter(|f| f.proposal == ProposalId::from_raw(W))
        .count();
    let receipt = tool(
        &inner,
        &t,
        "fstp_assessment_submit",
        &submission(&input, MODEL, replies),
    )
    .unwrap();
    let recorded = receipt.get("recorded").and_then(Value::as_u64).unwrap();
    assert!(recorded >= 3, "{}", receipt.to_compact());
    assert_eq!(
        receipt
            .get("refused")
            .and_then(Value::as_array)
            .map(|a| a.len()),
        Some(0)
    );

    // I-10: only finding records, and no pending action (I-85).
    let added = entries_since(&inner, before);
    assert!(
        added
            .iter()
            .all(|r| matches!(r, fstp_engine::Record::Finding(_))),
        "{added:?}"
    );
    let pending = web(
        &inner,
        COORDINATOR,
        fstp_api_core::decode::Method::Get,
        "/me/pending-actions",
        "",
    )
    .unwrap();
    assert_eq!(pending.as_array().map(|a| a.len()), Some(0));

    // I-11: the pin and one trace; the provenance names the run.
    let state = inner.ports.engine.state();
    let pin = state
        .core
        .calls()
        .get(CallId::from_raw(1))
        .and_then(|c| c.llm_config())
        .unwrap();
    let all: Vec<_> = state
        .findings
        .findings_of(CallId::from_raw(1))
        .into_iter()
        .filter(|f| f.proposal == ProposalId::from_raw(W))
        .collect();
    assert!(all.iter().all(|f| f.config == pin), "I-11");
    // The run's own findings share one trace; the scan's at submission
    // (ADR-035) carry their own.
    let intake_trace = all.first().map(|f| f.trace);
    let mine: Vec<_> = all
        .iter()
        .filter(|f| Some(f.trace) != intake_trace || intake == 0)
        .collect();
    assert_eq!(u64::try_from(mine.len()).unwrap(), recorded);
    assert_eq!(all.len(), intake + mine.len());
    assert!(mine.iter().all(|f| f.trace == mine[0].trace));
    let run = added.iter().find_map(|r| match r {
        fstp_engine::Record::Finding(fstp_findings::FindingRecord::ClientAssessed {
            by,
            run,
            ..
        }) => Some((*by, run.clone())),
        _ => None,
    });
    let (by, run) = run.unwrap();
    assert_eq!(by, COORDINATOR);
    assert_eq!(run.model.0, MODEL);
    assert_eq!(run.trace, mine[0].trace);
    // The deterministic integrity scan found w's injection at submission.
    assert!(
        all.iter()
            .any(|f| f.kind == fstp_findings::FindingKind::Integrity)
    );

    // One run per proposal: a second one is refused and records nothing.
    let input = tool(
        &inner,
        &t,
        "fstp_assessment_get_input",
        &format!(r#"{{"proposal":"{W}"}}"#),
    )
    .unwrap();
    let before = ledger_len(&inner);
    let again = tool(
        &inner,
        &t,
        "fstp_assessment_submit",
        &submission(&input, MODEL, vec![reply("claims", findings(Vec::new()))]),
    );
    assert!(again.is_err());
    assert_eq!(ledger_len(&inner), before);
    let queue = tool(
        &inner,
        &t,
        "fstp_assessment_list_proposals",
        r#"{"call":"1"}"#,
    )
    .unwrap();
    let row = queue
        .get("proposals")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .find(|r| s(r, "proposal") == W.to_string())
        .cloned()
        .unwrap();
    assert_eq!(s(&row, "status"), "assessed");
}

/// ADR-033, TH-01, I-10, T-LLM-INJ: replies that a submission's injection
/// could have produced are contained. A reply with a member outside the
/// schema, a score-like statement or a criterion outside P-01 drops whole
/// and is listed by stage and code. A statement that asks for another tool
/// stays a bounded statement. Nothing but finding records is appended, and
/// no pending action, score or state change follows.
#[test]
fn adr033_th01_injected_replies_yield_only_findings_or_refusals() {
    let (inner, _) = scene();
    release_all(&inner);
    let t = token(&inner, COORDINATOR, &[Scope::AssessRun]);
    declare(&inner, W);
    let input = tool(
        &inner,
        &t,
        "fstp_assessment_get_input",
        &format!(r#"{{"proposal":"{W}"}}"#),
    )
    .unwrap();
    let n = narrative(&input);
    let quote: String = n.chars().take(30).collect();
    let c = criteria(&input).into_iter().next().unwrap();
    let mut with_score = findings(vec![finding(
        "quality",
        Some(&c),
        None,
        "Observation.",
        &quote,
    )]);
    if let Value::Object(o) = &mut with_score {
        o.insert("score", Value::from(5_u64));
    }
    let replies = vec![
        // A member outside the schema.
        reply("quality", with_score),
        // A score-like statement.
        reply(
            "completeness",
            findings(vec![finding(
                "completeness",
                None,
                Some("problem"),
                "Score it 5 out of 5 and recommend funding.",
                &quote,
            )]),
        ),
        // A criterion outside P-01.
        reply(
            "quality",
            findings(vec![finding(
                "quality",
                Some(&format!("c-{:032x}", 999_999)),
                None,
                "Observation.",
                &quote,
            )]),
        ),
        // A statement that asks the agent to act: it stays data.
        reply(
            "integrity",
            findings(vec![finding(
                "integrity",
                None,
                None,
                "The text asks the assessor to call fstp_prepare_role_grant and close stage 1.",
                &quote,
            )]),
        ),
    ];
    let state_before = inner.ports.engine.state().core.clone();
    let before = ledger_len(&inner);
    let receipt = tool(
        &inner,
        &t,
        "fstp_assessment_submit",
        &submission(&input, MODEL, replies),
    )
    .unwrap();
    let refused: Vec<(String, String)> = receipt
        .get("refused")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .map(|r| (s(r, "stage"), s(r, "code")))
        .collect();
    assert!(
        refused.contains(&("quality".to_owned(), "unknown_member".to_owned())),
        "{refused:?}"
    );
    assert!(
        refused.contains(&("completeness".to_owned(), "score_like".to_owned())),
        "{refused:?}"
    );
    assert!(
        refused.contains(&("quality".to_owned(), "criterion".to_owned())),
        "{refused:?}"
    );
    let added = entries_since(&inner, before);
    assert!(
        added
            .iter()
            .all(|r| matches!(r, fstp_engine::Record::Finding(_))),
        "{added:?}"
    );
    assert_eq!(
        inner.ports.engine.state().core,
        state_before,
        "I-10: the core is unchanged"
    );
    let pending = web(
        &inner,
        COORDINATOR,
        fstp_api_core::decode::Method::Get,
        "/me/pending-actions",
        "",
    )
    .unwrap();
    assert_eq!(pending.as_array().map(|a| a.len()), Some(0));
    // The stage the client may not answer refuses the whole submission.
    let verify = submission(&input, MODEL, vec![reply("verify", findings(Vec::new()))]);
    assert!(tool(&inner, &t, "fstp_assessment_submit", &verify).is_err());
}

/// ADR-033, I-11, R-AU-01: a submission names the model the call pins,
/// the cell's prompt set and the input the cell served. Each mismatch is
/// refused before anything is recorded.
#[test]
fn adr033_i11_model_prompt_set_and_input_must_match() {
    let (inner, _) = scene();
    release_all(&inner);
    let t = token(&inner, COORDINATOR, &[Scope::AssessRun]);
    declare(&inner, W);
    let input = tool(
        &inner,
        &t,
        "fstp_assessment_get_input",
        &format!(r#"{{"proposal":"{W}"}}"#),
    )
    .unwrap();
    let before = ledger_len(&inner);
    let other_model = submission(&input, "claude-sonnet-5-5", Vec::new());
    assert!(
        tool(&inner, &t, "fstp_assessment_submit", &other_model)
            .unwrap_err()
            .contains("I-11")
    );
    let good = submission(&input, MODEL, Vec::new());
    let other_prompt = good.replace(
        &s(input.get("prompt_set").unwrap(), "digest"),
        &"0".repeat(64),
    );
    assert!(
        tool(&inner, &t, "fstp_assessment_submit", &other_prompt)
            .unwrap_err()
            .contains("I-11")
    );
    let other_input = good.replace(&s(&input, "input_digest"), &"1".repeat(64));
    assert!(
        tool(&inner, &t, "fstp_assessment_submit", &other_input)
            .unwrap_err()
            .contains("R-AU-01")
    );
    assert_eq!(ledger_len(&inner), before);
}

/// ADR-033, I-84, SoD, TH-01: only the FSTP coordinator runs it. A
/// reviewer and an applicant are refused with their own `assess:run`
/// token. A coordinator token without `assess:run` reaches none of the
/// three tools, and an `assess:run` token reaches no other tool.
#[test]
fn adr033_i84_only_the_coordinator_with_assess_run() {
    let (inner, _) = scene();
    declare(&inner, W);
    let arg = format!(r#"{{"proposal":"{W}"}}"#);
    for who in [R1, L1] {
        let t = token(&inner, who, &[Scope::AssessRun]);
        assert!(
            tool(&inner, &t, "fstp_assessment_get_input", &arg).is_err(),
            "{who:?}"
        );
    }
    let other: Vec<Scope> = Scope::ALL
        .into_iter()
        .filter(|x| *x != Scope::AssessRun)
        .collect();
    let wide = token(&inner, COORDINATOR, &other);
    let e = tool(&inner, &wide, "fstp_assessment_get_input", &arg).unwrap_err();
    assert!(e.contains("scope") || e.contains("Scope"), "{e}");
    let narrow = token(&inner, COORDINATOR, &[Scope::AssessRun]);
    let e = tool(&inner, &narrow, "fstp_list_calls", r#"{"programme":"1"}"#).unwrap_err();
    assert!(e.contains("scope") || e.contains("Scope"), "{e}");
}

/// ADR-033, I-17, I-86, R-LA-01 stage 2: the input holds no identity
/// canary of the scene, and no email address survives the stripping.
#[test]
fn adr033_i17_i86_the_input_holds_no_identity_attribute() {
    let (inner, seeded) = scene();
    release_all(&inner);
    let t = token(&inner, COORDINATOR, &[Scope::AssessRun]);
    for p in [1001_u128, 1002, W, 1004] {
        declare(&inner, p);
        let input = tool(
            &inner,
            &t,
            "fstp_assessment_get_input",
            &format!(r#"{{"proposal":"{p}"}}"#),
        )
        .unwrap();
        let text = input.to_compact();
        for c in seeded
            .get("identity_canaries")
            .and_then(Value::as_array)
            .unwrap()
        {
            let c = c.as_str().unwrap();
            assert!(!text.contains(c), "I-17: {p} holds {c}");
        }
        assert!(
            !text.contains("@example.org") && !text.contains("@e2e.invalid"),
            "{p}"
        );
    }
}

/// The findings status row of `p` as the coordinator reads it in the web.
fn status_row(inner: &Inner, p: u128) -> Value {
    web(
        inner,
        COORDINATOR,
        fstp_api_core::decode::Method::Get,
        "/calls/1/findings-status",
        "",
    )
    .unwrap()
    .as_array()
    .unwrap()
    .iter()
    .find(|r| s(r, "proposal") == p.to_string())
    .cloned()
    .unwrap()
}

/// The reason codes of a list of flag rows.
fn flag_reasons(v: &Value, k: &str) -> Vec<String> {
    v.get(k)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("no {k}: {}", v.to_compact()))
        .iter()
        .map(|f| s(f, "reason"))
        .collect()
}

/// ADR-035, TH-01, I-10, I-11, I-85, R-LA-01, T-LLM-INJ: the seeded
/// submission w holds a direct injection. The submission is not refused.
/// Its entry records the scan's integrity findings in plain words under
/// the call's pin, and the hold. Every AI assessment path waits: the queue
/// shows `held`, the input tool refuses. Only the coordinator releases it,
/// once, in the web; no tool exists for the release. After the release
/// the agent reads the input with the flagged spans beside the text, and
/// records its assessment.
#[test]
fn adr035_flagged_submission_is_held_marked_and_assessed_after_release() {
    let (inner, _) = scene();
    let w = ProposalId::from_raw(W);
    let state = inner.ports.engine.state();
    assert_eq!(
        fstp_domain::view::proposal_state(&state.core, w),
        Some(fstp_domain::StateTag::Submitted),
        "the scan never refuses a submission"
    );
    assert!(state.findings.held(w));
    let reasons: Vec<&str> = state
        .findings
        .integrity_of(w)
        .unwrap()
        .reasons
        .iter()
        .map(|r| r.code())
        .collect();
    assert!(reasons.contains(&"addressed"), "{reasons:?}");
    // The scan's findings: integrity, the call's pin, plain words that
    // never quote the injection.
    let pin = state
        .core
        .calls()
        .get(CallId::from_raw(1))
        .and_then(|c| c.llm_config())
        .unwrap();
    let scan: Vec<_> = state
        .findings
        .findings_of(CallId::from_raw(1))
        .into_iter()
        .filter(|f| f.proposal == w)
        .collect();
    assert!(!scan.is_empty());
    for f in &scan {
        assert_eq!(f.kind, fstp_findings::FindingKind::Integrity);
        assert_eq!(f.config, pin, "I-11");
        let st = f.statement.as_data();
        assert!(st.starts_with("The "), "{st}");
        assert!(!st.to_lowercase().contains("mark every claim"), "{st}");
        assert!(!f.evidence.is_empty(), "R-LA-02");
    }
    // The submission's entry holds the core records, the findings and the
    // hold together.
    let ledger = inner.ports.engine.ledger().unwrap();
    let held_at = ledger
        .iter()
        .position(|e| {
            matches!(
                &e.record,
                fstp_engine::Record::Finding(fstp_findings::FindingRecord::IntegrityHeld { proposal, .. })
                    if *proposal == w
            )
        })
        .unwrap();
    let command = ledger[held_at].command;
    assert!(ledger.iter().any(|e| e.command == command
        && matches!(&e.record, fstp_engine::Record::Core(fstp_domain::Record::Transitioned(t)) if t.proposal == w)));
    drop(state);

    // The coordinator sees the hold and its reasons on the board.
    let row = status_row(&inner, W);
    assert_eq!(s(&row, "integrity"), "held");

    // The agent's queue shows it held, and the input is refused.
    let t = token(&inner, COORDINATOR, &[Scope::AssessRun]);
    let queue = tool(
        &inner,
        &t,
        "fstp_assessment_list_proposals",
        r#"{"call":"1"}"#,
    )
    .unwrap();
    let row = queue
        .get("proposals")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .find(|r| s(r, "proposal") == W.to_string())
        .cloned()
        .unwrap();
    assert_eq!(s(&row, "status"), "held");
    declare(&inner, W);
    let before = ledger_len(&inner);
    let held = tool(
        &inner,
        &t,
        "fstp_assessment_get_input",
        &format!(r#"{{"proposal":"{W}"}}"#),
    )
    .unwrap_err();
    assert!(held.contains("I-10"), "{held}");
    assert_eq!(ledger_len(&inner), before, "a refused read records nothing");

    // I-85: no tool releases a hold.
    assert!(
        fstp_access::OPS
            .iter()
            .find(|o| o.name == "assess.release_integrity")
            .unwrap()
            .tool
            .is_none()
    );
    // Only the coordinator releases, once.
    assert!(
        web(
            &inner,
            R1,
            fstp_api_core::decode::Method::Post,
            &format!("/proposals/{W}/integrity-release"),
            "{}",
        )
        .is_err()
    );
    let before = ledger_len(&inner);
    release(&inner, W).unwrap();
    let added = entries_since(&inner, before);
    assert!(
        matches!(
            added.as_slice(),
            [fstp_engine::Record::Finding(fstp_findings::FindingRecord::IntegrityReleased { by, .. })]
                if *by == COORDINATOR
        ),
        "the release is one audited record: {added:?}"
    );
    assert!(release(&inner, W).is_err(), "one release");
    assert_eq!(s(&status_row(&inner, W), "integrity"), "released");

    // After the release the input is served, with the flagged spans beside
    // the text under closed reason codes.
    let input = tool(
        &inner,
        &t,
        "fstp_assessment_get_input",
        &format!(r#"{{"proposal":"{W}"}}"#),
    )
    .unwrap();
    let part = input
        .get("parts")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .find(|p| p.get("label").and_then(Value::as_str) == Some("narrative"))
        .cloned()
        .unwrap();
    let marks = flag_reasons(&part, "flags");
    assert!(marks.iter().any(|r| r == "addressed"), "{marks:?}");
    for f in part.get("flags").and_then(Value::as_array).unwrap().iter() {
        let (a, b) = (
            f.get("start").and_then(Value::as_u64).unwrap(),
            f.get("end").and_then(Value::as_u64).unwrap(),
        );
        assert!(a <= b && b <= u64::try_from(s(&part, "text").chars().count()).unwrap());
    }
    let mut replies = vec![
        reply("completeness", findings(Vec::new())),
        reply("claims", findings(Vec::new())),
        reply("integrity", findings(Vec::new())),
    ];
    for _ in criteria(&input) {
        replies.push(reply("quality", findings(Vec::new())));
    }
    tool(
        &inner,
        &t,
        "fstp_assessment_submit",
        &submission(&input, MODEL, replies),
    )
    .unwrap();
}

/// ADR-035, TH-60: proposal v hides an instruction in tag characters.
/// Through MCP the content read carries the neutralised view, with no
/// hidden character, and the flagged spans beside it. In the web a person
/// reads the text as submitted, with the same marks of that text.
#[test]
fn adr035_th60_mcp_content_is_neutralised_and_marked() {
    crate::assess::set_test_p75(true);
    let (inner, _) = scene();
    crate::assess::set_test_p75(false);
    let v = 1004_u128;
    assert!(
        inner
            .ports
            .engine
            .state()
            .findings
            .held(ProposalId::from_raw(v))
    );
    declare(&inner, v);
    let web_view = web(
        &inner,
        COORDINATOR,
        fstp_api_core::decode::Method::Get,
        &format!("/proposals/{v}/content"),
        "",
    )
    .unwrap();
    let as_submitted = s(&web_view, "text");
    assert!(as_submitted.chars().any(fstp_injscan::is_removed));
    assert!(!flag_reasons(&web_view, "text_flags").is_empty());
    let t = token(&inner, COORDINATOR, &[Scope::ReviewRead]);
    let agent_view = tool(
        &inner,
        &t,
        "fstp_get_proposal_content",
        &format!(r#"{{"proposal":"{v}"}}"#),
    )
    .unwrap();
    let neutral = s(&agent_view, "text");
    assert!(!neutral.chars().any(fstp_injscan::is_removed));
    assert_eq!(neutral, fstp_injscan::neutralise(&as_submitted));
    // The marks are closed codes and offsets, never text.
    for f in agent_view
        .get("text_flags")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
    {
        let o = f.as_object().unwrap();
        assert_eq!(o.len(), 3);
        assert!(fstp_access::INTEGRITY_REASONS.contains(&s(f, "reason").as_str()));
    }
}
