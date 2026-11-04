//! Dispatch tests of the creator, bridge and import operations of journey
//! J1 (M4 design sections 2.2, 3.2, 3.3, 3.7 and 8.4; lane m4wire).
//!
//! The test author of lane m4wire wrote them before the dispatch exists.
//! Each test drives `ApiCore::dispatch` on a [`FakeCell`] through the
//! adapter-facing decoders of [`creator_requests`], and reads what the
//! ports saw: the commands the engine port executed, the step-up proofs
//! and the reply bodies. Each names the requirement or invariant it
//! checks.
//!
//! The world is the I-85 world of [`fixture`]. Tenant admin A1 is
//! [`ADMIN`] and opens the draft, so A1 is a builder. A1 then grants the
//! programme manager role on the draft to M1, [`OWNER`], through the
//! engine port as a change of the world around the cell. M1 builds the
//! draft through dispatch. Tenant admin A2, [`ADMIN_2`], approves.
//!
//! Reply bodies are checked against the shapes the creator pages read in
//! `web/src/creator/model.ts` and `web/src/people/model.ts` (lane W4a),
//! the page contract of design section 3.9. Refusals are checked against
//! design section 3.7: the code and the rule text only, such as
//! `{"code":"refused","rule":"I-67"}`.
//!
//! Red now for one of these reasons, each named in the failure:
//!
//! - dispatch answers `not_implemented` for every creator, bridge and
//!   import operation (lane m4wire production);
//! - the fake engine runs the `DomainDecider`, whose `NoEnvironment`
//!   supplies no shell fact, so creator commands fail closed (lane m4wire
//!   production, `fake/engine.rs`);
//! - `fstp_creator::decide_creator` refuses `OpenDraft` and the saves at
//!   its `fstp-programme` seams until lane m4creator merges;
//! - the Guide checks and the legal wording fail closed until lane
//!   m4guide merges, so no SuperSAFE draft reaches a clean report.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_api_core::decode::Method;
use fstp_api_core::meta::Scope;
use fstp_api_core::port::{AsyncEngine, ExecError, ExecMeta, LoginMethod, OpName};
use fstp_api_core::{ActionDigest, ApiError, ErrorCode, Op, OpResult};
use fstp_creator::{
    CHECKS, CreatorCommand, DraftRevision, Invitee, Provenance, Severity, StartingPoint,
    ValueDigest,
};
use fstp_domain::Via;
use fstp_domain::command::{Actor, Ctx};
use fstp_domain::id::{
    BindingId, CommandId, ContentDigest, DecisionId, PolicyVersionId, ProgrammeId,
};
use fstp_domain::policy::{FunderProfileRef, OpaqueValue};
use fstp_domain::programme::{ProgrammeStatus, programme_status};
use fstp_domain::refusal::RuleRef;
use fstp_domain::roles::Role;
use fstp_domain_testkit::r#gen::roster;
use fstp_engine::Command;
use fstp_json::{ToJson, Value};
use fstp_ledger::Seq;
use fstp_rt::future::block_on;

use super::cell::{Class, class};
use super::creator_requests as rq;
use super::fixture::{ADMIN, ADMIN_2, AGENT, LEAD, OWNER, P1, P2};
use super::step_up::P71_MICROS;
use super::{FakeCell, WebLogin};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn cell() -> FakeCell {
    FakeCell::new().unwrap_or_else(|e| panic!("the fake cell: {e}"))
}

/// A passkey login of `account`.
fn login(c: &FakeCell, account: fstp_domain::id::AccountId) -> WebLogin {
    c.login(account, LoginMethod::Passkey)
}

/// Calls `op` through the web. A `StepUpRequired` answer is followed by
/// the ceremony in the same session, then by the call again, once, as the
/// page's step-up dialog does (ADR-014 "Step-up").
fn stepped(
    c: &FakeCell,
    l: &WebLogin,
    op: impl Fn() -> Result<Op, ApiError>,
) -> Result<OpResult, String> {
    match c.web(l, op()) {
        Ok(OpResult::StepUpRequired(ch)) => {
            c.ports
                .step_up
                .approve(l.session, ch.action)
                .map_err(|e| format!("the step-up ceremony: {e:?}"))?;
            c.web(l, op()).map_err(|e| format!("{e:?}"))
        }
        other => other.map_err(|e| format!("{e:?}")),
    }
}

/// The JSON body of a completed call, or why it did not complete.
fn done(r: Result<OpResult, ApiError>, what: &str) -> Result<Value, String> {
    match r {
        Ok(OpResult::Done { body, .. }) => Ok(body.to_json()),
        other => Err(format!("{what} gave {other:?}")),
    }
}

/// The JSON body of a completed result of [`stepped`].
fn done_stepped(r: Result<OpResult, String>, what: &str) -> Result<Value, String> {
    match r {
        Ok(OpResult::Done { body, .. }) => Ok(body.to_json()),
        other => Err(format!("{what} gave {other:?}")),
    }
}

/// The string member `k` of `v`.
fn str_of(v: &Value, k: &str) -> Result<String, String> {
    v.get(k)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("no string member {k:?} in {}", v.to_compact()))
}

/// The array member `k` of `v`.
fn list_of<'a>(v: &'a Value, k: &str) -> Result<&'a [Value], String> {
    v.get(k)
        .and_then(Value::as_array)
        .map(|a| &a[..])
        .ok_or_else(|| format!("no array member {k:?} in {}", v.to_compact()))
}

/// The refusal rule of `r`, if it is a refusal.
fn rule(r: &Result<OpResult, ApiError>) -> Option<&'static str> {
    match r {
        Err(ApiError::Refused { rule, .. }) => Some(*rule),
        _ => None,
    }
}

/// Whether `r` is a strict-decoder refusal of a matched route.
fn bad_request(r: &Result<Op, ApiError>) -> bool {
    matches!(
        r,
        Err(ApiError::Refused {
            code: ErrorCode::BadRequest,
            ..
        })
    )
}

/// The operation a decode gave, or a description of the error.
fn decoded(r: &Result<Op, ApiError>) -> Result<&'static str, String> {
    match r {
        Ok(op) => Ok(op.name()),
        Err(e) => Err(format!("{e:?}")),
    }
}

/// Every creator command the engine port executed, with its context and
/// metadata, appended or not.
fn creator_executions(c: &FakeCell) -> Vec<(CreatorCommand, Ctx, ExecMeta, bool)> {
    c.ports
        .engine
        .executions()
        .into_iter()
        .filter_map(|e| match e.cmd {
            Command::Creator(cmd) => Some((cmd, e.ctx, e.meta, e.result.is_ok())),
            _ => None,
        })
        .collect()
}

/// Every creator command the engine port appended.
fn creator_appended(c: &FakeCell) -> Vec<(CreatorCommand, Ctx, ExecMeta)> {
    creator_executions(c)
        .into_iter()
        .filter(|(_, _, _, ok)| *ok)
        .map(|(cmd, ctx, meta, _)| (cmd, ctx, meta))
        .collect()
}

/// The last appended creator command.
fn last_creator(c: &FakeCell) -> Result<(CreatorCommand, Ctx, ExecMeta), String> {
    creator_appended(c)
        .pop()
        .ok_or_else(|| "the engine port appended no creator command".to_owned())
}

/// The command id of the `n`-th change of the world in these tests.
fn world_command(n: u32) -> CommandId {
    let mut b = *b"creator-wire:\0\0\0";
    let (_, tail) = b.split_at_mut(13);
    tail.copy_from_slice(&n.to_be_bytes()[1..]);
    CommandId::from_bytes(b)
}

/// The draft head of `p` in the engine port's state.
fn head(c: &FakeCell, p: ProgrammeId) -> Option<DraftRevision> {
    c.ports.engine.state().creator.head(p)
}

/// A draft with its people (module documentation).
struct Draft {
    p: ProgrammeId,
    admin: WebLogin,
    admin2: WebLogin,
    owner: WebLogin,
}

/// A1 opens a draft through dispatch, with the step-up.
fn open(c: &FakeCell) -> Result<(ProgrammeId, WebLogin), String> {
    let admin = login(c, ADMIN);
    let body = done_stepped(stepped(c, &admin, rq::open_draft), "creator.open_draft")?;
    let id = str_of(&body, "programme")?;
    let raw: u128 = id
        .parse()
        .map_err(|_| format!("the programme member {id:?} is not a decimal id"))?;
    Ok((ProgrammeId::from_raw(raw), admin))
}

/// A1 grants the programme manager role on draft `p` to `account`, through
/// the engine port: a change of the world around the cell (D3, SoD-09).
fn grant_manager(
    c: &FakeCell,
    p: ProgrammeId,
    account: fstp_domain::id::AccountId,
    n: u32,
) -> Result<(), String> {
    let now = c.ports.clock.read();
    let binding = BindingId::from_raw(90_000u128.saturating_add(u128::from(n)));
    let step = roster::grant(binding, account, p, Role::ProgrammeManager, now);
    c.ports
        .engine
        .environment(
            Command::Core(step.cmd.clone()),
            step.ctx(now, world_command(n)),
        )
        .map(|_| ())
        .map_err(|e| format!("the grant of the programme manager on the draft: {e:?}"))
}

/// A draft opened by A1 with M1 as its programme manager.
fn opened(c: &FakeCell) -> Result<Draft, String> {
    let (p, _opening) = open(c)?;
    // The k-th draft of the cell takes the k-th grant, so a second draft
    // in one cell draws a fresh binding and command id.
    let n = u32::try_from(c.ports.engine.state().creator.drafts().count()).unwrap_or(1);
    grant_manager(c, p, OWNER, n)?;
    Ok(Draft {
        p,
        // A1 signs in again after the opening, so the step-up of
        // `creator.open_draft` stays in the opening session and a test
        // reads only what A1 does next.
        admin: login(c, ADMIN),
        admin2: login(c, ADMIN_2),
        owner: login(c, OWNER),
    })
}

/// `creator.get_draft` of `p` by `l`.
fn draft_of(c: &FakeCell, l: &WebLogin, p: ProgrammeId) -> Result<Value, String> {
    done(c.web(l, rq::get_draft(p)), "creator.get_draft")
}

/// The revision string of the draft `p` as `l` reads it.
fn revision(c: &FakeCell, l: &WebLogin, p: ProgrammeId) -> Result<String, String> {
    str_of(&draft_of(c, l, p)?, "revision")
}

/// `creator.get_report` of `p` by `l`.
fn report_of(c: &FakeCell, l: &WebLogin, p: ProgrammeId) -> Result<Value, String> {
    done(c.web(l, rq::get_report(p)), "creator.get_report")
}

/// M1 applies the SuperSAFE template start to `d`.
fn start_supersafe(c: &FakeCell, d: &Draft) -> Result<(), String> {
    let base = revision(c, &d.owner, d.p)?;
    done(
        c.web(&d.owner, rq::apply_start(d.p, &base, rq::supersafe_start())),
        "creator.apply_start",
    )
    .map(|_| ())
}

/// The keys of the draft's template narratives not yet accepted.
fn pending_narratives(draft: &Value) -> Vec<String> {
    draft
        .get("pending_narratives")
        .and_then(Value::as_object)
        .map(|o| o.keys().map(str::to_owned).collect())
        .unwrap_or_default()
}

/// M1 accepts every pending template narrative of `d`, one at a time
/// (TH-49).
fn accept_all_narratives(c: &FakeCell, d: &Draft) -> Result<(), String> {
    loop {
        let draft = draft_of(c, &d.owner, d.p)?;
        let Some(key) = pending_narratives(&draft).into_iter().next() else {
            return Ok(());
        };
        let base = str_of(&draft, "revision")?;
        done(
            c.web(&d.owner, rq::accept_narrative(d.p, &key, &base)),
            "creator.accept_narrative",
        )?;
    }
}

/// A SuperSAFE draft with every narrative accepted.
fn built(c: &FakeCell) -> Result<Draft, String> {
    let d = opened(c)?;
    start_supersafe(c, &d)?;
    accept_all_narratives(c, &d)?;
    Ok(d)
}

/// The results of a report body.
fn results(report: &Value) -> Result<Vec<(String, String, bool, String)>, String> {
    let mut out = Vec::new();
    for r in list_of(report, "results")? {
        let check = str_of(r, "check")?;
        let severity = str_of(r, "severity")?;
        let acknowledged = r
            .get("acknowledged")
            .and_then(Value::as_bool)
            .ok_or_else(|| format!("no acknowledged member in {}", r.to_compact()))?;
        let key = r
            .get("key")
            .and_then(Value::as_str)
            .map_or_else(|| check.clone(), str::to_owned);
        out.push((check, severity, acknowledged, key));
    }
    Ok(out)
}

/// M1 saves, through dispatch, the value of every field the report names
/// as unset, from the synthetic SuperSAFE spec (`draft_cell::synthetic_spec`).
/// The shipped template leaves each value the spec does not give as a gap,
/// marked `synthetic` in the fixture (design 3.1, "Synthetic
/// placeholders"), and leaves the inline P-09 wording to a save as stored
/// text (ADR-007). So a template start alone is never clean, and the
/// programme manager fills the gaps as in journey J1.
fn fill_gaps(c: &FakeCell, d: &Draft) -> Result<(), String> {
    let report = report_of(c, &d.owner, d.p)?;
    let spec = super::draft_cell::synthetic_spec()?;
    let mut fields: Vec<(String, Value)> = Vec::new();
    for r in list_of(&report, "results")? {
        if r.get("check").and_then(Value::as_str) != Some("FieldUnset") {
            continue;
        }
        let key = str_of(r, "field")?;
        let id = fstp_programme::FieldId::from_key(&key)
            .ok_or_else(|| format!("no field of key {key:?}"))?;
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
    let base = revision(c, &d.owner, d.p)?;
    let edits: Vec<(&str, Value)> = fields
        .iter()
        .map(|(k, v)| (k.as_str(), v.clone()))
        .collect();
    done(
        c.web(&d.owner, rq::save_fields(d.p, &base, &edits)),
        "creator.save_fields of the synthetic gaps",
    )
    .map(|_| ())
}

/// A built draft with its synthetic gaps saved ([`fill_gaps`]), every
/// warning acknowledged by M1 and activation requested by M1. It fails,
/// naming the checks, when the report holds a failure.
fn requested(c: &FakeCell) -> Result<Draft, String> {
    let d = built(c)?;
    fill_gaps(c, &d)?;
    let report = report_of(c, &d.owner, d.p)?;
    let rows = results(&report)?;
    let failures: Vec<&str> = rows
        .iter()
        .filter(|r| r.1 == "failure")
        .map(|r| r.0.as_str())
        .collect();
    if !failures.is_empty() {
        return Err(format!(
            "the SuperSAFE draft is not clean in this cell, failures: {failures:?}"
        ));
    }
    for (_, _, acknowledged, key) in rows.iter().filter(|r| r.1 == "warning") {
        if *acknowledged {
            continue;
        }
        let rev = revision(c, &d.owner, d.p)?;
        done(
            c.web(&d.owner, rq::acknowledge(d.p, &rev, key)),
            "creator.acknowledge",
        )?;
    }
    let rev = revision(c, &d.owner, d.p)?;
    done(
        c.web(&d.owner, rq::request_activation(d.p, &rev)),
        "creator.request_activation",
    )?;
    Ok(d)
}

/// The rows of the approval inbox as `l` reads it.
fn approvals(c: &FakeCell, l: &WebLogin) -> Result<Vec<Value>, String> {
    let body = done(c.web(l, rq::approvals()), "admin.approvals")?;
    Ok(list_of(&body, "approvals")?.to_vec())
}

/// The activation row of `p` in `rows`.
fn activation_row(rows: &[Value], p: ProgrammeId) -> Result<Value, String> {
    let want = p.raw().to_string();
    rows.iter()
        .find(|r| {
            r.get("kind").and_then(Value::as_str) == Some("activation")
                && r.get("programme").and_then(Value::as_str) == Some(want.as_str())
        })
        .cloned()
        .ok_or_else(|| format!("no activation row for programme {want}"))
}

// ---------------------------------------------------------------------------
// Decoders (design section 3.7 step 1)
// ---------------------------------------------------------------------------

/// R-PG-01, R-PG-02, design sections 2.2 and 3.7 step 1: each creator,
/// bridge and import route of journey J1 decodes to its operation. The
/// preview route takes the preview kinds `guide`, `public` and `contract`
/// as its segment, and the narrative route a field key.
#[test]
fn r_pg_01_creator_and_import_routes_decode_to_their_operations() {
    let p = ProgrammeId::from_raw(5);
    let cases: Vec<(Result<Op, ApiError>, &str)> = vec![
        (rq::open_draft(), "creator.open_draft"),
        (rq::list_programmes(), "creator.list_programmes"),
        (rq::list_templates(), "creator.list_templates"),
        (rq::get_draft(p), "creator.get_draft"),
        (rq::get_report(p), "creator.get_report"),
        (rq::preview(p, "guide"), "creator.preview"),
        (rq::preview(p, "public"), "creator.preview"),
        (rq::preview(p, "contract"), "creator.preview"),
        (rq::impact(p), "creator.impact"),
        (rq::invitations(p), "creator.invitations"),
        (
            rq::invite(p, "m2@e2e.invalid", "programme_manager", None),
            "creator.invite",
        ),
        (
            rq::withdraw_invitation(p, "7"),
            "creator.withdraw_invitation",
        ),
        (rq::save_as_template(p), "creator.save_as_template"),
        (
            rq::import_upload(p, "text/markdown", "SYNTHETIC ANNEX"),
            "import.upload",
        ),
        (rq::import_list(p), "import.list"),
        (rq::approvals(), "admin.approvals"),
    ];
    for (r, want) in &cases {
        assert_eq!(decoded(r), Ok(*want), "the route of {want}");
    }
}

/// I-84, design section 3.7 step 1: `creator.open_draft` takes no body
/// member. The server draws the programme and the policy version, so a
/// client-chosen id is refused as a bad request, as is an unknown member.
#[test]
fn i84_open_draft_decoder_refuses_client_ids_and_unknown_members() {
    assert_eq!(decoded(&rq::open_draft()), Ok("creator.open_draft"));
    for (json, what) in [
        (r#"{"programme":"9"}"#, "a client-chosen programme"),
        (r#"{"version":"3"}"#, "a client-chosen policy version"),
        (r#"{"x":1}"#, "an unknown member"),
    ] {
        let r = rq::raw(Method::Post, "/programmes", json);
        assert!(bad_request(&r), "{what}: got {:?}", decoded(&r));
    }
}

/// I-84, SoD-09, design section 3.7 step 1: `creator.invite` takes the
/// email, a role key of the invitation form and an optional canonical
/// organisation id. The server draws the invitation. An unknown role key,
/// a client-chosen invitation, a missing email, a non-canonical
/// organisation and an unknown member are refused as bad requests.
#[test]
fn i84_invite_decoder_is_strict() {
    let p = ProgrammeId::from_raw(5);
    assert_eq!(
        decoded(&rq::invite(
            p,
            "r1@e2e.invalid",
            "committee_member",
            Some("3")
        )),
        Ok("creator.invite")
    );
    let path = "/programmes/5/invitations";
    for (json, what) in [
        (
            r#"{"email":"r1@e2e.invalid","role":"superuser"}"#,
            "an unknown role key",
        ),
        (
            r#"{"email":"r1@e2e.invalid","role":"programme_manager","invitation":"9"}"#,
            "a client-chosen invitation",
        ),
        (r#"{"role":"programme_manager"}"#, "no email"),
        (
            r#"{"email":"r1@e2e.invalid","role":"committee_member","organisation":"03"}"#,
            "a non-canonical organisation",
        ),
        (
            r#"{"email":"r1@e2e.invalid","role":"committee_member","organisation":3}"#,
            "an organisation as a JSON number",
        ),
        (
            r#"{"email":"r1@e2e.invalid","role":"programme_manager","x":true}"#,
            "an unknown member",
        ),
    ] {
        let r = rq::raw(Method::Post, path, json);
        assert!(bad_request(&r), "{what}: got {:?}", decoded(&r));
    }
}

/// I-65, I-84, Q24, design sections 3.3 and 3.7 step 1: `import.upload`
/// takes the media type, `text/plain` or `text/markdown` only, and the
/// text. The server draws the document. Another media type, a missing
/// text, a client-chosen document id and an unknown member are refused
/// as bad requests.
#[test]
fn i65_import_upload_decoder_is_strict() {
    let p = ProgrammeId::from_raw(5);
    assert_eq!(
        decoded(&rq::import_upload(p, "text/plain", "SYNTHETIC ANNEX")),
        Ok("import.upload")
    );
    let path = "/programmes/5/imports";
    for (json, what) in [
        (r#"{"media":"text/html","text":"T"}"#, "text/html"),
        (r#"{"media":"application/pdf","text":"T"}"#, "a PDF"),
        (r#"{"media":"text/plain"}"#, "no text"),
        (
            r#"{"media":"text/plain","text":"T","document":"4"}"#,
            "a client-chosen document",
        ),
        (
            r#"{"media":"text/plain","text":"T","x":1}"#,
            "an unknown member",
        ),
    ] {
        let r = rq::raw(Method::Post, path, json);
        assert!(bad_request(&r), "{what}: got {:?}", decoded(&r));
    }
}

/// R-PG-05, Q17, design section 3.7 step 1: `creator.save_as_template`
/// takes no body member. The server draws the template, so a
/// client-chosen template id is refused as a bad request.
#[test]
fn r_pg_05_save_as_template_decoder_refuses_a_client_template_id() {
    let p = ProgrammeId::from_raw(5);
    assert_eq!(
        decoded(&rq::save_as_template(p)),
        Ok("creator.save_as_template")
    );
    let r = rq::raw(
        Method::Post,
        "/programmes/5/templates",
        r#"{"template":"1"}"#,
    );
    assert!(bad_request(&r), "got {:?}", decoded(&r));
}

/// R-PG-01, design section 3.7 step 1: a preview names one of the three
/// previews of J1. Any other segment is refused, as a bad request or as
/// a route that does not exist.
#[test]
fn r_pg_01_preview_decoder_refuses_unknown_previews() {
    let r = rq::preview(ProgrammeId::from_raw(5), "budget");
    assert!(
        matches!(
            r,
            Err(ApiError::Refused {
                code: ErrorCode::BadRequest | ErrorCode::NotFound,
                ..
            })
        ),
        "got {:?}",
        decoded(&r)
    );
}

// ---------------------------------------------------------------------------
// I-85: high-risk creator commands through MCP
// ---------------------------------------------------------------------------

/// I-85, design section 3.6 `i85_every_high_risk_tool_is_prepare_only`:
/// every high-risk creator, bridge or import operation of the registry is
/// a creator command that `CreatorCommand::high_risk` names, and has no
/// tool unless it is a prepare-only one. So no MCP tool runs one.
#[test]
fn i85_high_risk_creator_operations_have_no_running_tool() {
    use fstp_access::{CreatorKind, OPS, OpKind};
    let mut high: Vec<&str> = Vec::new();
    for spec in OPS {
        let in_lane = matches!(
            spec.kind,
            OpKind::Creator(_) | OpKind::Bridge(_) | OpKind::Import(_)
        );
        if !in_lane || !spec.high_risk {
            continue;
        }
        high.push(spec.name);
        assert!(
            matches!(
                spec.kind,
                OpKind::Creator(CreatorKind::OpenDraft | CreatorKind::ApproveActivation)
            ),
            "{} is high-risk but is not a high-risk creator command",
            spec.name
        );
        assert!(
            spec.tool.is_none_or(|t| t.prepare_only),
            "{} has a tool that runs",
            spec.name
        );
    }
    high.sort_unstable();
    assert_eq!(high, ["creator.approve_activation", "creator.open_draft"]);
}

/// I-85, I-78, design sections 3.6 and 3.7 step 3: opening a draft
/// through MCP is never run. A bearer request on its web route, from a
/// tenant admin's phishing-resistant token with every creator scope, is
/// refused with `Deny(NotExposed)`. No step-up is begun, no pending
/// action is stored, and the engine port executes nothing.
#[test]
fn i85_open_draft_through_mcp_is_not_exposed_and_never_runs() {
    let c = cell();
    let token = c.token(
        ADMIN,
        AGENT,
        [Scope::CreatorDraft, Scope::CallsDraft, Scope::CallsRead],
        LoginMethod::Passkey,
    );
    let r = c.mcp(&token, rq::open_draft());
    assert_eq!(
        class(&r),
        Class::Refused(ErrorCode::NotExposed),
        "creator.open_draft through MCP: {r:?}"
    );
    assert!(c.ports.engine.executions().is_empty(), "the engine ran");
    assert!(c.ports.step_up.begun().is_empty(), "a step-up was begun");
    let pending = c
        .pending(&login(&c, ADMIN))
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        pending.is_empty(),
        "a pending action was stored: {pending:?}"
    );
}

/// I-85, I-78, design sections 3.6 and 3.7 step 3: approving an
/// activation through MCP is never run. For a requested draft, the
/// approver's bearer request is refused with `Deny(NotExposed)`. No
/// step-up is begun, no pending action is stored, the engine port
/// executes no approval, and the draft stays a draft.
#[test]
fn i85_approve_activation_through_mcp_is_not_exposed_and_never_runs() {
    let c = cell();
    let d = requested(&c).unwrap_or_else(|e| panic!("the requested draft: {e}"));
    let rev = revision(&c, &d.admin2, d.p).unwrap_or_else(|e| panic!("{e}"));
    let begun = c.ports.step_up.begun().len();
    let token = c.token(
        ADMIN_2,
        AGENT,
        [Scope::CreatorDraft, Scope::CallsDraft, Scope::CallsRead],
        LoginMethod::Passkey,
    );
    let r = c.mcp(&token, rq::approve_activation(d.p, &rev));
    assert_eq!(
        class(&r),
        Class::Refused(ErrorCode::NotExposed),
        "creator.approve_activation through MCP: {r:?}"
    );
    assert_eq!(c.ports.step_up.begun().len(), begun, "a step-up was begun");
    assert!(
        !creator_executions(&c)
            .iter()
            .any(|(cmd, ..)| matches!(cmd, CreatorCommand::ApproveActivation { .. })),
        "the engine ran an approval"
    );
    let pending = c.pending(&d.admin2).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        pending.is_empty(),
        "a pending action was stored: {pending:?}"
    );
    assert_eq!(
        programme_status(&c.ports.engine.state().core, d.p),
        Some(ProgrammeStatus::Draft)
    );
}

/// I-85 bypass twin, design section 8.4
/// `i85_domain_refuses_high_risk_via_mcp_when_dispatch_is_bypassed`: the
/// engine port refuses both high-risk creator commands with
/// `RuleRef::I85` when they arrive through `Via::Mcp` around dispatch,
/// and appends nothing. Through the web the same commands are not
/// refused with I-85.
#[test]
fn i85_engine_refuses_high_risk_creator_commands_via_mcp() {
    let c = cell();
    let now = c.ports.clock.read();
    let profile = FunderProfileRef(
        OpaqueValue::from_value(&Value::String("horizon-europe/1".to_owned()))
            .unwrap_or_else(|e| panic!("{e:?}")),
    );
    let cmds = [
        CreatorCommand::OpenDraft {
            programme: ProgrammeId::from_raw(8_501),
            version: PolicyVersionId::from_raw(8_501),
            profile,
        },
        CreatorCommand::ApproveActivation {
            programme: P1,
            revision: DraftRevision::new(1, Seq::from_raw(1)),
            decision: DecisionId::from_raw(8_502),
        },
    ];
    let run = |cmd: &CreatorCommand, via: Via, n: u32| {
        let ctx = Ctx {
            now,
            actor: Actor::Account(ADMIN_2),
            command: world_command(n),
            via,
            tenant_admin: true,
            second_tenant_admin: None,
            binds_tenant_admin: false,
        };
        let meta = ExecMeta {
            via,
            session: None,
            agent: (via == Via::Mcp).then_some(AGENT),
            op: OpName("bypass-twin"),
            request: ActionDigest([0x85; 32]),
            step_up: None,
            pending: None,
            second_tenant_admin: None,
        };
        block_on(
            c.ports
                .engine
                .execute(Command::Creator(cmd.clone()), ctx, meta),
        )
    };
    let i85 = |r: &Result<Seq, ExecError>| matches!(r, Err(ExecError::Refused(x)) if x.rule == RuleRef::I85);
    let head = c.ports.engine.head();
    for (cmd, n) in cmds.iter().zip([8_501u32, 8_502]) {
        assert!(cmd.high_risk(), "{cmd:?} is high-risk");
        let r = run(cmd, Via::Mcp, n);
        assert!(i85(&r), "{cmd:?} through MCP gave {r:?}");
    }
    assert_eq!(c.ports.engine.head(), head, "the bypass appended");
    for (cmd, n) in cmds.iter().zip([8_511u32, 8_512]) {
        let r = run(cmd, Via::Web, n);
        assert!(!i85(&r), "{cmd:?} through the web was refused with I-85");
    }
}

// ---------------------------------------------------------------------------
// Opening a draft (I-78, R-LG-03, R-PG-01)
// ---------------------------------------------------------------------------

/// I-78, R-LG-03, R-PG-01, Q10, design sections 3.2 and 3.7 steps 5 to
/// 8: a tenant admin opens a draft through the web only after a fresh
/// step-up. The first call gives `StepUpRequired` and executes nothing.
/// After the ceremony the call completes with `{programme}`, the id the
/// server drew. The engine port appended one `CreatorCommand::OpenDraft`
/// of that programme by the admin through the web, carrying the proof
/// taken, and the programme is a draft.
#[test]
fn i78_r_pg_01_open_draft_needs_step_up_then_builds_open_draft() {
    let c = cell();
    let admin = login(&c, ADMIN);
    let first = c.web(&admin, rq::open_draft());
    let Ok(OpResult::StepUpRequired(ch)) = &first else {
        panic!("creator.open_draft without a proof gave {first:?}");
    };
    assert!(
        creator_executions(&c).is_empty(),
        "executed before the step-up"
    );
    c.ports
        .step_up
        .approve(admin.session, ch.action)
        .unwrap_or_else(|e| panic!("{e:?}"));
    let body = done(c.web(&admin, rq::open_draft()), "creator.open_draft")
        .unwrap_or_else(|e| panic!("{e}"));
    let id = str_of(&body, "programme").unwrap_or_else(|e| panic!("{e}"));
    let (cmd, ctx, meta) = last_creator(&c).unwrap_or_else(|e| panic!("{e}"));
    let CreatorCommand::OpenDraft { programme, .. } = cmd else {
        panic!("the engine port appended {cmd:?}");
    };
    assert_eq!(
        programme.raw().to_string(),
        id,
        "the reply names the drawn id"
    );
    assert!(programme != P1 && programme != P2, "a new programme");
    assert_eq!(ctx.actor, Actor::Account(ADMIN));
    assert_eq!(ctx.via, Via::Web);
    let taken = c.ports.step_up.taken();
    assert_eq!(taken.len(), 1, "{taken:?}");
    assert_eq!(meta.step_up, Some(taken[0].proof.step_up));
    assert_eq!(meta.request, ch.action, "the proof is bound to the request");
    assert_eq!(
        programme_status(&c.ports.engine.state().core, programme),
        Some(ProgrammeStatus::Draft)
    );
    assert!(c.ports.engine.state().drafted(programme));
}

/// R-PG-01, I-78, design section 3.7 step 5: a programme manager who is
/// no tenant admin cannot open a draft. The dry run refuses before any
/// step-up prompt, the refusal names the actor rule only, and nothing
/// executes.
#[test]
fn r_pg_01_open_draft_by_a_non_admin_is_refused_before_step_up() {
    let c = cell();
    let owner = login(&c, OWNER);
    let r = c.web(&owner, rq::open_draft());
    assert!(class(&r).refused(), "creator.open_draft by M1 gave {r:?}");
    assert_eq!(rule(&r), Some("actor"), "{r:?}");
    assert!(c.ports.step_up.begun().is_empty(), "a step-up was begun");
    assert!(creator_executions(&c).is_empty(), "the engine ran");
}

// ---------------------------------------------------------------------------
// The creator start page reads (R-PG-02)
// ---------------------------------------------------------------------------

/// R-PG-02, I-19, design section 3.6: the clone sources are the tenant's
/// programmes. A tenant admin reads `{programmes: [{id, name}]}` holding
/// P1 and P2. An applicant with no staff role is refused.
#[test]
fn r_pg_02_list_programmes_lists_the_tenant_programmes() {
    let c = cell();
    let body = done(
        c.web(&login(&c, ADMIN), rq::list_programmes()),
        "creator.list_programmes",
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let rows = list_of(&body, "programmes").unwrap_or_else(|e| panic!("{e}"));
    let ids: Vec<String> = rows
        .iter()
        .map(|r| {
            assert!(r.get("name").and_then(Value::as_str).is_some(), "{r:?}");
            str_of(r, "id").unwrap_or_else(|e| panic!("{e}"))
        })
        .collect();
    for p in [P1, P2] {
        assert!(ids.contains(&p.raw().to_string()), "{p:?} missing: {ids:?}");
    }
    let r = c.web(&login(&c, LEAD), rq::list_programmes());
    assert!(class(&r).refused(), "the applicant read the list: {r:?}");
}

/// R-PG-02, design sections 3.1 and 3.2: the template catalogue offers
/// the shipped SuperSAFE template, id 1 at version 1, as
/// `{templates: [{id, version, name}]}`.
#[test]
fn r_pg_02_list_templates_offers_the_shipped_supersafe_template() {
    let c = cell();
    let body = done(
        c.web(&login(&c, ADMIN), rq::list_templates()),
        "creator.list_templates",
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let rows = list_of(&body, "templates").unwrap_or_else(|e| panic!("{e}"));
    let supersafe = rows
        .iter()
        .find(|r| r.get("id").and_then(Value::as_str) == Some("1"))
        .unwrap_or_else(|| panic!("no template 1 in {}", body.to_compact()));
    assert_eq!(supersafe.get("version").and_then(Value::as_u64), Some(1));
    assert!(supersafe.get("name").and_then(Value::as_str).is_some());
}

// ---------------------------------------------------------------------------
// Draft reads and saves (R-PG-01, R-PG-02, I-65, TH-49)
// ---------------------------------------------------------------------------

/// R-PG-01, design sections 3.2 and 3.6: the draft read gives
/// `{spec, revision, status}` with status `draft`, to the opener and to
/// the draft's programme manager. An applicant is refused.
#[test]
fn r_pg_01_get_draft_reads_spec_revision_and_status() {
    let c = cell();
    let d = opened(&c).unwrap_or_else(|e| panic!("{e}"));
    for l in [&d.admin, &d.owner] {
        let v = draft_of(&c, l, d.p).unwrap_or_else(|e| panic!("{e}"));
        assert!(v.get("spec").and_then(Value::as_object).is_some(), "{v:?}");
        assert!(str_of(&v, "revision").is_ok(), "{v:?}");
        assert_eq!(v.get("status").and_then(Value::as_str), Some("draft"));
    }
    let r = c.web(&login(&c, LEAD), rq::get_draft(d.p));
    assert!(class(&r).refused(), "the applicant read the draft: {r:?}");
}

/// R-PG-02, design section 3.2: M1 applies the SuperSAFE template. The
/// engine port appends `ApplyStart` with the template start and the
/// revision M1 read as its base, by M1 through the web.
#[test]
fn r_pg_02_apply_start_template_builds_apply_start() {
    let c = cell();
    let d = opened(&c).unwrap_or_else(|e| panic!("{e}"));
    let before = head(&c, d.p).unwrap_or_else(|| panic!("no draft head"));
    start_supersafe(&c, &d).unwrap_or_else(|e| panic!("{e}"));
    let (cmd, ctx, _) = last_creator(&c).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        cmd,
        CreatorCommand::ApplyStart {
            programme: d.p,
            base: before,
            start: StartingPoint::Template {
                template: fstp_creator::TemplateId::from_raw(1),
                version: 1,
            },
        }
    );
    assert_eq!(ctx.actor, Actor::Account(OWNER));
    assert_eq!(ctx.via, Via::Web);
}

/// R-PG-02, design section 3.2 "`base` must equal the current
/// `DraftRevision`": a start against a revision that is no longer the
/// head is refused naming the input rule, and a tenant admin without the
/// programme manager binding is refused naming the actor rule. Neither
/// appends.
#[test]
fn r_pg_02_apply_start_refuses_a_stale_base_and_a_non_manager() {
    let c = cell();
    let d = opened(&c).unwrap_or_else(|e| panic!("{e}"));
    let stale = revision(&c, &d.owner, d.p).unwrap_or_else(|e| panic!("{e}"));
    start_supersafe(&c, &d).unwrap_or_else(|e| panic!("{e}"));
    let appended = creator_appended(&c).len();
    let r = c.web(
        &d.owner,
        rq::apply_start(d.p, &stale, rq::supersafe_start()),
    );
    assert!(class(&r).refused(), "the stale start gave {r:?}");
    assert_eq!(rule(&r), Some("Input"), "{r:?}");
    let fresh = revision(&c, &d.admin, d.p).unwrap_or_else(|e| panic!("{e}"));
    let r = c.web(
        &d.admin,
        rq::apply_start(d.p, &fresh, rq::supersafe_start()),
    );
    assert!(class(&r).refused(), "the admin's start gave {r:?}");
    assert_eq!(rule(&r), Some("actor"), "{r:?}");
    assert_eq!(
        creator_appended(&c).len(),
        appended,
        "a refused start appended"
    );
}

/// The P-05 field key of the spec JSON (`e2e/creator/contract.ts`).
const P05: &str = "money.p05_recipient_cap";

/// R-PG-01, I-65, design section 3.2 `FieldEdit`: M1 saves P-05 as the
/// ADR-006 string `"50000.00"`. The engine port appends one `SaveFields`
/// at the head M1 read, with the field of the key, the value its strict
/// decoder gives, manual provenance, and the shell's digest: SHA-256 of
/// the value's canonical text, through `fstp-crypto`.
#[test]
fn r_pg_01_save_fields_builds_field_edits_with_the_shell_sha256() {
    let c = cell();
    let d = built(&c).unwrap_or_else(|e| panic!("{e}"));
    let base = revision(&c, &d.owner, d.p).unwrap_or_else(|e| panic!("{e}"));
    let before = head(&c, d.p).unwrap_or_else(|| panic!("no draft head"));
    done(
        c.web(
            &d.owner,
            rq::save_fields(d.p, &base, &[(P05, rq::s("50000.00"))]),
        ),
        "creator.save_fields",
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let (cmd, ctx, _) = last_creator(&c).unwrap_or_else(|e| panic!("{e}"));
    let field = fstp_programme::FieldId::from_key(P05).unwrap_or_else(|| panic!("no P-05 key"));
    let value = fstp_programme::decode_field_value(field, br#""50000.00""#)
        .unwrap_or_else(|e| panic!("{e:?}"));
    let canonical = fstp_programme::encode_field_value(&value);
    let digest = ValueDigest::new(ContentDigest::from_bytes(fstp_crypto::sha256(
        canonical.as_bytes(),
    )));
    let CreatorCommand::SaveFields {
        programme,
        base: got_base,
        fields,
    } = cmd
    else {
        panic!("the engine port appended {cmd:?}");
    };
    assert_eq!(programme, d.p);
    assert_eq!(got_base, before);
    assert_eq!(fields.len(), 1, "{fields:?}");
    assert_eq!(fields[0].field, field);
    assert_eq!(fields[0].value, value);
    assert_eq!(
        fields[0].digest, digest,
        "the digest is SHA-256 of the canonical text"
    );
    assert_eq!(fields[0].provenance, Provenance::Manual);
    assert_eq!(ctx.actor, Actor::Account(OWNER));
}

/// ADR-006, I-84, design section 3.7 step 1: the save decoder is strict.
/// An amount sent as a JSON number, a value that is not an ADR-006
/// string, an unknown field key, an empty field list, a missing base and
/// an unknown member are refused as bad requests, before any dispatch.
#[test]
fn adr006_save_fields_decoder_is_strict() {
    let c = cell();
    let d = opened(&c).unwrap_or_else(|e| panic!("{e}"));
    let base = revision(&c, &d.owner, d.p).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        decoded(&rq::save_fields(d.p, &base, &[(P05, rq::s("50000.00"))])),
        Ok("creator.save_fields")
    );
    let number: Value = fstp_json::parse(b"50000").unwrap_or_else(|e| panic!("{e:?}"));
    for (r, what) in [
        (
            rq::save_fields(d.p, &base, &[(P05, number)]),
            "an amount as a JSON number",
        ),
        (
            rq::save_fields(d.p, &base, &[(P05, rq::s("50000.5"))]),
            "an amount outside the EUR scale",
        ),
        (
            rq::save_fields(d.p, &base, &[("money.no_such_field", rq::s("1.00"))]),
            "an unknown field key",
        ),
        (rq::save_fields(d.p, &base, &[]), "no field"),
        (
            rq::raw(
                Method::Put,
                &format!("/programmes/{}/draft/fields", d.p.raw()),
                r#"{"fields":[{"field":"money.p05_recipient_cap","value":"1.00"}]}"#,
            ),
            "no base",
        ),
        (
            rq::raw(
                Method::Put,
                &format!("/programmes/{}/draft/fields", d.p.raw()),
                &format!(
                    r#"{{"base":{},"fields":[],"x":1}}"#,
                    Value::String(base.clone()).to_compact()
                ),
            ),
            "an unknown member",
        ),
    ] {
        assert!(bad_request(&r), "{what}: got {:?}", decoded(&r));
    }
}

/// I-84, R-MC-02, design sections 3.6 and 3.7 step 3: the save is the one
/// creator write with a tool. M1's agent with `creator:draft` saves
/// through `fstp_creator_save_fields`, and the engine port appends the
/// save with `Via::Mcp`. A token without the scope is refused with
/// `Deny(Scope)` and appends nothing.
#[test]
fn i84_save_fields_through_mcp_runs_with_via_mcp() {
    let c = cell();
    let d = built(&c).unwrap_or_else(|e| panic!("{e}"));
    let none = c.token(OWNER, AGENT, [Scope::CallsRead], LoginMethod::Passkey);
    let base = revision(&c, &d.owner, d.p).unwrap_or_else(|e| panic!("{e}"));
    let appended = creator_appended(&c).len();
    let r = c.mcp(
        &none,
        rq::save_fields_tool(d.p, &base, &[(P05, rq::s("40000.00"))]),
    );
    assert_eq!(class(&r), Class::Refused(ErrorCode::Scope), "{r:?}");
    assert_eq!(creator_appended(&c).len(), appended);
    let token = c.token(OWNER, AGENT, [Scope::CreatorDraft], LoginMethod::Passkey);
    done(
        c.mcp(
            &token,
            rq::save_fields_tool(d.p, &base, &[(P05, rq::s("40000.00"))]),
        ),
        "fstp_creator_save_fields",
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let (cmd, ctx, meta) = last_creator(&c).unwrap_or_else(|e| panic!("{e}"));
    assert!(matches!(cmd, CreatorCommand::SaveFields { .. }), "{cmd:?}");
    assert_eq!(ctx.via, Via::Mcp);
    assert_eq!(meta.agent, Some(AGENT));
}

/// TH-49, R-PG-02, design section 3.2 `AcceptNarrative`: template text is
/// never applied silently. After the SuperSAFE start the draft read lists
/// pending narratives. M1 accepts one, and the engine port appends
/// `AcceptNarrative` of that field at the head M1 read. The narrative is
/// no longer pending.
#[test]
fn th49_accept_narrative_builds_accept_narrative() {
    let c = cell();
    let d = opened(&c).unwrap_or_else(|e| panic!("{e}"));
    start_supersafe(&c, &d).unwrap_or_else(|e| panic!("{e}"));
    let draft = draft_of(&c, &d.owner, d.p).unwrap_or_else(|e| panic!("{e}"));
    let keys = pending_narratives(&draft);
    let key = keys
        .first()
        .cloned()
        .unwrap_or_else(|| panic!("no pending narrative after the template start"));
    let base = str_of(&draft, "revision").unwrap_or_else(|e| panic!("{e}"));
    let before = head(&c, d.p).unwrap_or_else(|| panic!("no draft head"));
    done(
        c.web(&d.owner, rq::accept_narrative(d.p, &key, &base)),
        "creator.accept_narrative",
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let (cmd, ..) = last_creator(&c).unwrap_or_else(|e| panic!("{e}"));
    let field = fstp_programme::FieldId::from_key(&key)
        .unwrap_or_else(|| panic!("the pending key {key:?} names no field"));
    assert_eq!(
        cmd,
        CreatorCommand::AcceptNarrative {
            programme: d.p,
            base: before,
            field,
        }
    );
    let after = draft_of(&c, &d.owner, d.p).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        !pending_narratives(&after).contains(&key),
        "{key} is still pending"
    );
}

// ---------------------------------------------------------------------------
// People (R-PG-01 step 9, SoD-09)
// ---------------------------------------------------------------------------

/// R-PG-01, SoD-09, ADR-007, design sections 3.2 and 3.7 step 1: M1
/// invites a second programme manager by email. The engine port appends
/// `Invite` with a drawn invitation id, the role, no organisation, and
/// the email as a pending invitee whose contact is a text reference. The
/// text store holds the email, so the ledger body holds none. The
/// invitation read then lists `{id, email, role, state, sod}` with the
/// drawn id, the role key and the state `invited`.
#[test]
fn r_pg_01_invite_builds_invite_with_a_drawn_id_and_a_stored_contact() {
    let c = cell();
    let d = opened(&c).unwrap_or_else(|e| panic!("{e}"));
    let email = "m2@e2e.invalid";
    done(
        c.web(&d.owner, rq::invite(d.p, email, "programme_manager", None)),
        "creator.invite",
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let (cmd, ..) = last_creator(&c).unwrap_or_else(|e| panic!("{e}"));
    let CreatorCommand::Invite {
        programme,
        invitation,
        role,
        invitee,
        organisation,
    } = cmd
    else {
        panic!("the engine port appended {cmd:?}");
    };
    assert_eq!(programme, d.p);
    assert_eq!(role, Role::ProgrammeManager);
    assert_eq!(organisation, None);
    let Invitee::Pending { contact } = invitee else {
        panic!("an email invitee is pending: {invitee:?}");
    };
    // ADR-007: the stored text is the salt, then the email, and the
    // contact's digest is keyed with that salt.
    let stored = c
        .ports
        .texts
        .peek(fstp_api_core::port::TextRef(contact.id().raw()))
        .unwrap_or_else(|| panic!("the contact text is not stored"));
    let (salt, text) = fstp_api_core::salted::split(&stored)
        .unwrap_or_else(|| panic!("the contact text holds no salt"));
    assert_eq!(text, email.as_bytes(), "the contact text");
    assert!(
        fstp_api_core::salted::verify(&salt, text, &contact.digest().bytes()),
        "the contact digest is keyed with the stored salt"
    );
    let body = done(c.web(&d.owner, rq::invitations(d.p)), "creator.invitations")
        .unwrap_or_else(|e| panic!("{e}"));
    let rows = list_of(&body, "invitations").unwrap_or_else(|e| panic!("{e}"));
    let row = rows
        .iter()
        .find(|r| r.get("id").and_then(Value::as_str) == Some(&invitation.raw().to_string()))
        .unwrap_or_else(|| panic!("the invitation is not listed: {}", body.to_compact()));
    assert_eq!(row.get("email").and_then(Value::as_str), Some(email));
    assert_eq!(
        row.get("role").and_then(Value::as_str),
        Some("programme_manager")
    );
    assert_eq!(row.get("state").and_then(Value::as_str), Some("invited"));
    assert!(row.get("sod").and_then(Value::as_str).is_some(), "{row:?}");
}

/// R-PG-01, design section 3.2 `WithdrawInvitation`: M1 withdraws the
/// invitation the server drew, and the engine port appends
/// `WithdrawInvitation` of that id. The invitation read no longer lists
/// it as live.
#[test]
fn r_pg_01_withdraw_invitation_builds_withdraw_invitation() {
    let c = cell();
    let d = opened(&c).unwrap_or_else(|e| panic!("{e}"));
    done(
        c.web(
            &d.owner,
            rq::invite(d.p, "d1@e2e.invalid", "call_drafter", None),
        ),
        "creator.invite",
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let (cmd, ..) = last_creator(&c).unwrap_or_else(|e| panic!("{e}"));
    let CreatorCommand::Invite { invitation, .. } = cmd else {
        panic!("the engine port appended {cmd:?}");
    };
    let id = invitation.raw().to_string();
    done(
        c.web(&d.owner, rq::withdraw_invitation(d.p, &id)),
        "creator.withdraw_invitation",
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let (cmd, ..) = last_creator(&c).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        cmd,
        CreatorCommand::WithdrawInvitation {
            programme: d.p,
            invitation,
        }
    );
    let body = done(c.web(&d.owner, rq::invitations(d.p)), "creator.invitations")
        .unwrap_or_else(|e| panic!("{e}"));
    let rows = list_of(&body, "invitations").unwrap_or_else(|e| panic!("{e}"));
    assert!(
        !rows
            .iter()
            .any(|r| r.get("id").and_then(Value::as_str) == Some(id.as_str())),
        "the withdrawn invitation is still listed"
    );
}

// ---------------------------------------------------------------------------
// Report, acknowledgements, previews and templates (I-66, R-PG-01)
// ---------------------------------------------------------------------------

/// I-66, R-PG-01, design section 3.2 "Validation": the report of an
/// opened draft with no start is at the draft's revision, names only
/// checks of the catalogue `CHECKS` with their catalogue severity, and
/// holds at least one failure.
#[test]
fn i66_r_pg_01_report_names_catalogue_checks_at_the_draft_revision() {
    let c = cell();
    let d = opened(&c).unwrap_or_else(|e| panic!("{e}"));
    let rev = revision(&c, &d.owner, d.p).unwrap_or_else(|e| panic!("{e}"));
    let report = report_of(&c, &d.owner, d.p).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(str_of(&report, "revision").as_deref(), Ok(rev.as_str()));
    let rows = results(&report).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        rows.iter().any(|r| r.1 == "failure"),
        "no failure: {rows:?}"
    );
    for (check, severity, ..) in &rows {
        let spec = CHECKS
            .iter()
            .find(|s| format!("{:?}", s.id) == *check)
            .unwrap_or_else(|| panic!("{check} is not in the catalogue"));
        let want = match spec.severity {
            Severity::Failure => "failure",
            Severity::Warning => "warning",
        };
        assert_eq!(severity, want, "the severity of {check}");
    }
}

/// I-66, R-PG-03, design sections 3.2 and 3.7: requesting activation of a
/// draft whose report holds a failure is refused with the rule text
/// `I-66` only. Nothing is appended, and the report still names the
/// failing check.
#[test]
fn i66_request_activation_with_a_failure_is_refused_naming_i66() {
    let c = cell();
    let d = opened(&c).unwrap_or_else(|e| panic!("{e}"));
    let rev = revision(&c, &d.owner, d.p).unwrap_or_else(|e| panic!("{e}"));
    let appended = creator_appended(&c).len();
    let r = c.web(&d.owner, rq::request_activation(d.p, &rev));
    assert_eq!(class(&r), Class::Refused(ErrorCode::Refused), "{r:?}");
    assert_eq!(rule(&r), Some("I-66"), "{r:?}");
    assert_eq!(creator_appended(&c).len(), appended);
    let report = report_of(&c, &d.owner, d.p).unwrap_or_else(|e| panic!("{e}"));
    let rows = results(&report).unwrap_or_else(|e| panic!("{e}"));
    assert!(rows.iter().any(|r| r.1 == "failure"), "{rows:?}");
}

/// I-66, design section 3.2 "Bound to a revision": M1 acknowledges a
/// warning of the report. The engine port appends `AcknowledgeWarning` at
/// the revision M1 read for that warning's check, and the report then
/// shows it acknowledged. Acknowledging a failure is refused with the rule
/// text `I-66` and appends nothing.
#[test]
fn i66_acknowledge_builds_acknowledge_warning_and_refuses_a_failure() {
    let c = cell();
    let d = built(&c).unwrap_or_else(|e| panic!("{e}"));
    let report = report_of(&c, &d.owner, d.p).unwrap_or_else(|e| panic!("{e}"));
    let rows = results(&report).unwrap_or_else(|e| panic!("{e}"));
    let warning = rows
        .iter()
        .find(|r| r.1 == "warning" && !r.2)
        .cloned()
        .unwrap_or_else(|| panic!("no unacknowledged warning: {rows:?}"));
    let rev = str_of(&report, "revision").unwrap_or_else(|e| panic!("{e}"));
    let before = head(&c, d.p).unwrap_or_else(|| panic!("no draft head"));
    done(
        c.web(&d.owner, rq::acknowledge(d.p, &rev, &warning.3)),
        "creator.acknowledge",
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let (cmd, ..) = last_creator(&c).unwrap_or_else(|e| panic!("{e}"));
    let CreatorCommand::AcknowledgeWarning {
        programme,
        revision: at,
        warning: key,
    } = cmd
    else {
        panic!("the engine port appended {cmd:?}");
    };
    assert_eq!(programme, d.p);
    assert_eq!(at, before);
    assert_eq!(format!("{:?}", key.check), warning.0);
    let again = report_of(&c, &d.owner, d.p).unwrap_or_else(|e| panic!("{e}"));
    let rows = results(&again).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        rows.iter().any(|r| r.3 == warning.3 && r.2),
        "the warning is not acknowledged: {rows:?}"
    );
    let unclean = opened(&c).unwrap_or_else(|e| panic!("{e}"));
    let report = report_of(&c, &unclean.owner, unclean.p).unwrap_or_else(|e| panic!("{e}"));
    let rows = results(&report).unwrap_or_else(|e| panic!("{e}"));
    let failure = rows
        .iter()
        .find(|r| r.1 == "failure")
        .cloned()
        .unwrap_or_else(|| panic!("no failure: {rows:?}"));
    let rev = str_of(&report, "revision").unwrap_or_else(|e| panic!("{e}"));
    let appended = creator_appended(&c).len();
    let r = c.web(&unclean.owner, rq::acknowledge(unclean.p, &rev, &failure.3));
    match &r {
        // The decoder may already know that the key names a failure.
        Err(ApiError::Refused {
            code: ErrorCode::BadRequest,
            ..
        }) => {}
        other => assert_eq!(rule(other), Some("I-66"), "{other:?}"),
    }
    assert_eq!(creator_appended(&c).len(), appended);
}

/// R-PG-01, R-GA-01, design section 2.2 J1: the Guide, public page and
/// contract previews of a built draft read as text blocks,
/// `{blocks: [{kind, text}]}` or `{text}`, each non-empty.
#[test]
fn r_pg_01_previews_read_as_text() {
    let c = cell();
    let d = built(&c).unwrap_or_else(|e| panic!("{e}"));
    for kind in ["guide", "public", "contract"] {
        let v = done(c.web(&d.owner, rq::preview(d.p, kind)), "creator.preview")
            .unwrap_or_else(|e| panic!("{kind}: {e}"));
        let text = v.get("text").and_then(Value::as_str).map(str::to_owned);
        let blocks = v.get("blocks").and_then(Value::as_array).map(|b| b.len());
        assert!(
            text.is_some_and(|t| !t.is_empty()) || blocks.is_some_and(|n| n > 0),
            "the {kind} preview: {}",
            v.to_compact()
        );
    }
}

/// R-PG-04, design section 3.6: the impact read of a draft completes with
/// an object for its programme manager and is refused to an applicant.
#[test]
fn r_pg_04_impact_reads_for_the_manager_only() {
    let c = cell();
    let d = built(&c).unwrap_or_else(|e| panic!("{e}"));
    let v =
        done(c.web(&d.owner, rq::impact(d.p)), "creator.impact").unwrap_or_else(|e| panic!("{e}"));
    assert!(v.as_object().is_some(), "{}", v.to_compact());
    let r = c.web(&login(&c, LEAD), rq::impact(d.p));
    assert!(class(&r).refused(), "the applicant read the impact: {r:?}");
}

/// R-PG-05, Q17, design section 3.2 `SaveAsTenantTemplate`: M1 saves the
/// built draft as a tenant-private template. The engine port appends
/// `SaveAsTenantTemplate` with a drawn template id, which the catalogue
/// then lists beside the shipped template.
#[test]
fn r_pg_05_save_as_template_builds_save_as_tenant_template() {
    let c = cell();
    let d = built(&c).unwrap_or_else(|e| panic!("{e}"));
    done(
        c.web(&d.owner, rq::save_as_template(d.p)),
        "creator.save_as_template",
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let (cmd, ..) = last_creator(&c).unwrap_or_else(|e| panic!("{e}"));
    let CreatorCommand::SaveAsTenantTemplate {
        programme,
        template,
    } = cmd
    else {
        panic!("the engine port appended {cmd:?}");
    };
    assert_eq!(programme, d.p);
    assert_ne!(template.raw(), 1, "the shipped template id is not drawn");
    let body = done(
        c.web(&d.owner, rq::list_templates()),
        "creator.list_templates",
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let rows = list_of(&body, "templates").unwrap_or_else(|e| panic!("{e}"));
    let id = template.raw().to_string();
    assert!(
        rows.iter()
            .any(|r| r.get("id").and_then(Value::as_str) == Some(id.as_str())),
        "the tenant template is not listed: {}",
        body.to_compact()
    );
}

// ---------------------------------------------------------------------------
// Import (I-65)
// ---------------------------------------------------------------------------

/// A synthetic annex: untrusted text with values a proposer can find.
const ANNEX: &str = "SYNTHETIC ANNEX. NOT A REAL FUNDING DOCUMENT.\n\
Action number: 101000001\n\
Maximum per recipient: EUR 400000.00\n";

/// I-65, design section 3.3: M1 uploads a Markdown annex. The engine port
/// executes one `ImportCommand::RegisterDocument` of the draft, uploaded
/// by M1, as Markdown, with the length of the text. No creator command
/// and no field save follow from the upload. The import list then reads
/// as `{proposals: [...]}`.
#[test]
fn i65_import_upload_builds_register_document() {
    let c = cell();
    let d = built(&c).unwrap_or_else(|e| panic!("{e}"));
    let creators = creator_appended(&c).len();
    done(
        c.web(&d.owner, rq::import_upload(d.p, "text/markdown", ANNEX)),
        "import.upload",
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let registered: Vec<fstp_import::ImportDocument> = c
        .ports
        .engine
        .appended()
        .into_iter()
        .filter_map(|e| match e.cmd {
            Command::Import(fstp_import::ImportCommand::RegisterDocument(doc)) => Some(doc),
            _ => None,
        })
        .collect();
    assert_eq!(registered.len(), 1, "{registered:?}");
    let doc = &registered[0];
    assert_eq!(doc.programme.raw(), d.p.raw());
    assert_eq!(doc.uploaded_by.raw(), OWNER.raw());
    assert_eq!(doc.media, fstp_import::ImportMedia::TextMarkdown);
    assert_eq!(
        usize::try_from(doc.text_bytes).ok(),
        Some(ANNEX.len()),
        "the normalised text is the annex"
    );
    assert_eq!(
        creator_appended(&c).len(),
        creators,
        "the upload saved a field"
    );
    let v = done(c.web(&d.owner, rq::import_list(d.p)), "import.list")
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(list_of(&v, "proposals").is_ok(), "{}", v.to_compact());
}

/// I-65, design section 3.3 `resolve_import`: after an upload, M1
/// confirms one proposal that is not flagged, naming the digest the list
/// showed. The engine port appends one `BridgeCommand::ResolveImport` of
/// that proposal with the shown digest, the confirmation of the value
/// with the shell's SHA-256 of its normal text, and the base M1 read. A
/// forged shown digest and a resolution by a tenant admin without the
/// programme manager binding are refused naming `I-65`, and append
/// nothing.
#[test]
fn i65_import_resolve_builds_resolve_import_with_the_shell_sha256() {
    let c = cell();
    let d = built(&c).unwrap_or_else(|e| panic!("{e}"));
    done(
        c.web(&d.owner, rq::import_upload(d.p, "text/markdown", ANNEX)),
        "import.upload",
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let v = done(c.web(&d.owner, rq::import_list(d.p)), "import.list")
        .unwrap_or_else(|e| panic!("{e}"));
    let rows = list_of(&v, "proposals").unwrap_or_else(|e| panic!("{e}"));
    let row = rows
        .iter()
        .find(|r| r.get("flagged").and_then(Value::as_bool) == Some(false))
        .cloned()
        .unwrap_or_else(|| {
            panic!(
                "the cell's proposer proposed no unflagged value: {}",
                v.to_compact()
            )
        });
    let id = str_of(&row, "id").unwrap_or_else(|e| panic!("{e}"));
    let shown = str_of(&row, "digest").unwrap_or_else(|e| panic!("{e}"));
    let value = row
        .get("value")
        .cloned()
        .unwrap_or_else(|| panic!("no value: {row:?}"));
    let bridged = |c: &FakeCell| {
        c.ports
            .engine
            .appended()
            .into_iter()
            .filter_map(|e| match e.cmd {
                Command::Bridge(b) => Some(b),
                _ => None,
            })
            .collect::<Vec<_>>()
    };
    let base = revision(&c, &d.owner, d.p).unwrap_or_else(|e| panic!("{e}"));
    let forged = "0".repeat(shown.len().max(64));
    let r = c.web(
        &d.owner,
        rq::import_resolve(d.p, &id, &base, &forged, rq::confirm(value.clone()), false),
    );
    assert!(class(&r).refused(), "a forged digest gave {r:?}");
    assert_eq!(rule(&r), Some("I-65"), "{r:?}");
    let r = c.web(
        &d.admin,
        rq::import_resolve(d.p, &id, &base, &shown, rq::confirm(value.clone()), false),
    );
    assert!(class(&r).refused(), "the admin's resolution gave {r:?}");
    assert_eq!(rule(&r), Some("I-65"), "{r:?}");
    assert!(bridged(&c).is_empty(), "a refused resolution appended");
    let before = head(&c, d.p).unwrap_or_else(|| panic!("no draft head"));
    done(
        c.web(
            &d.owner,
            rq::import_resolve(d.p, &id, &base, &shown, rq::confirm(value.clone()), false),
        ),
        "import.resolve",
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let got = bridged(&c);
    assert_eq!(got.len(), 1, "{got:?}");
    let fstp_engine::BridgeCommand::ResolveImport {
        programme,
        proposal,
        shown: shown_digest,
        resolution,
        conflict_acknowledged,
        base: at,
    } = &got[0];
    assert_eq!(*programme, d.p);
    assert_eq!(proposal.raw().to_string(), id);
    let hex: String = shown_digest
        .bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(hex, shown, "the shown digest is the listed one");
    assert!(!conflict_acknowledged);
    assert_eq!(*at, before);
    let untrusted = fstp_import::UntrustedValue::new(&value).unwrap_or_else(|e| panic!("{e:?}"));
    let digest =
        fstp_import::ValueDigest::from_bytes(fstp_crypto::sha256(untrusted.as_data().as_bytes()));
    assert_eq!(
        *resolution,
        fstp_import::ClientResolution::Confirm {
            value: untrusted,
            digest,
        }
    );
}

// ---------------------------------------------------------------------------
// Approval (I-67, I-78, R-PG-03)
// ---------------------------------------------------------------------------

/// I-67, R-PG-03, Q1, design sections 2.2 J1 and 8.4
/// (`web/e2e/creator/second_person.spec.ts`): the approval inbox lists the
/// requested activation. It never offers the approval to a builder: A1,
/// who opened the draft and granted its binding, reads the row with
/// `approvable: false`. A2, outside the builder set, reads it with
/// `approvable: true`.
#[test]
fn i67_approval_inbox_never_offers_approval_to_a_builder() {
    let c = cell();
    let d = requested(&c).unwrap_or_else(|e| panic!("the requested draft: {e}"));
    let builders = c
        .ports
        .engine
        .state()
        .creator
        .draft(d.p)
        .map(|x| x.builders().clone())
        .unwrap_or_default();
    assert!(builders.contains(&ADMIN), "A1 is a builder: {builders:?}");
    assert!(
        !builders.contains(&ADMIN_2),
        "A2 is no builder: {builders:?}"
    );
    let a1 = activation_row(
        &approvals(&c, &d.admin).unwrap_or_else(|e| panic!("{e}")),
        d.p,
    )
    .unwrap_or_else(|e| panic!("A1: {e}"));
    assert_eq!(
        a1.get("approvable").and_then(Value::as_bool),
        Some(false),
        "the builder is offered the approval: {}",
        a1.to_compact()
    );
    let a2 = activation_row(
        &approvals(&c, &d.admin2).unwrap_or_else(|e| panic!("{e}")),
        d.p,
    )
    .unwrap_or_else(|e| panic!("A2: {e}"));
    assert_eq!(
        a2.get("approvable").and_then(Value::as_bool),
        Some(true),
        "the second person is not offered the approval: {}",
        a2.to_compact()
    );
}

/// I-67, design sections 3.2 and 3.7 step 5: a builder's forged approval
/// is refused with the rule text `I-67` by the dry run, before any
/// step-up prompt. No step-up is begun in the builder's session, nothing
/// is appended, and the draft stays a draft.
#[test]
fn i67_builder_approval_is_refused_before_any_step_up() {
    let c = cell();
    let d = requested(&c).unwrap_or_else(|e| panic!("the requested draft: {e}"));
    let rev = revision(&c, &d.admin, d.p).unwrap_or_else(|e| panic!("{e}"));
    let r = c.web(&d.admin, rq::approve_activation(d.p, &rev));
    assert_eq!(class(&r), Class::Refused(ErrorCode::Refused), "{r:?}");
    assert_eq!(rule(&r), Some("I-67"), "{r:?}");
    assert!(
        !c.ports
            .step_up
            .begun()
            .iter()
            .any(|(s, _)| *s == d.admin.session),
        "a step-up was begun for the builder"
    );
    assert!(
        !creator_appended(&c)
            .iter()
            .any(|(cmd, ..)| matches!(cmd, CreatorCommand::ApproveActivation { .. })),
        "the builder's approval appended"
    );
    assert_eq!(
        programme_status(&c.ports.engine.state().core, d.p),
        Some(ProgrammeStatus::Draft)
    );
}

/// I-78, R-LG-03, I-66, I-67, R-PG-03, design sections 3.2 and 3.7 step
/// 7: A2 approves the activation only with a fresh step-up bound to the
/// request digest. Without a proof, with a proof for another digest, and
/// with a proof exactly P-71 old, the call gives `StepUpRequired` bound
/// to the same digest and executes no approval. With a fresh proof the
/// engine port appends `ApproveActivation` of the requested revision by
/// A2 through the web, carrying the proof taken, and the programme is
/// active.
#[test]
fn i78_approve_activation_needs_a_fresh_digest_bound_step_up() {
    let c = cell();
    let d = requested(&c).unwrap_or_else(|e| panic!("the requested draft: {e}"));
    let rev = revision(&c, &d.admin2, d.p).unwrap_or_else(|e| panic!("{e}"));
    let at = head(&c, d.p).unwrap_or_else(|| panic!("no draft head"));
    let approve = || rq::approve_activation(d.p, &rev);
    let approvals_run = |c: &FakeCell| {
        creator_executions(c)
            .iter()
            .filter(|(cmd, ..)| matches!(cmd, CreatorCommand::ApproveActivation { .. }))
            .count()
    };
    let challenge = |r: &Result<OpResult, ApiError>, what: &str| match r {
        Ok(OpResult::StepUpRequired(ch)) => ch.action,
        other => panic!("{what}: {other:?}"),
    };
    let digest = challenge(&c.web(&d.admin2, approve()), "no proof");
    assert_eq!(approvals_run(&c), 0, "executed without a proof");
    c.ports
        .step_up
        .approve(d.admin2.session, ActionDigest([0x5a; 32]))
        .unwrap_or_else(|e| panic!("{e:?}"));
    let again = challenge(&c.web(&d.admin2, approve()), "a proof for another digest");
    assert_eq!(again, digest, "the challenge is bound to the request");
    assert_eq!(approvals_run(&c), 0, "executed with another digest's proof");
    c.ports
        .step_up
        .approve(d.admin2.session, digest)
        .unwrap_or_else(|e| panic!("{e:?}"));
    c.ports.clock.advance(P71_MICROS);
    let stale = challenge(&c.web(&d.admin2, approve()), "a proof P-71 old");
    assert_eq!(stale, digest);
    assert_eq!(approvals_run(&c), 0, "executed with a stale proof");
    c.ports
        .step_up
        .approve(d.admin2.session, digest)
        .unwrap_or_else(|e| panic!("{e:?}"));
    done(c.web(&d.admin2, approve()), "the fresh approval").unwrap_or_else(|e| panic!("{e}"));
    let (cmd, ctx, meta) = last_creator(&c).unwrap_or_else(|e| panic!("{e}"));
    let CreatorCommand::ApproveActivation {
        programme,
        revision: approved,
        ..
    } = cmd
    else {
        panic!("the engine port appended {cmd:?}");
    };
    assert_eq!(programme, d.p);
    assert_eq!(approved, at, "the approval names the revision A2 read");
    assert_eq!(ctx.actor, Actor::Account(ADMIN_2));
    assert_eq!(ctx.via, Via::Web);
    let taken = c.ports.step_up.taken();
    let last = taken.last().unwrap_or_else(|| panic!("no proof was taken"));
    assert_eq!(meta.step_up, Some(last.proof.step_up));
    assert_eq!(last.proof.action, digest);
    assert_eq!(meta.request, digest);
    assert_eq!(
        programme_status(&c.ports.engine.state().core, d.p),
        Some(ProgrammeStatus::Active)
    );
}
