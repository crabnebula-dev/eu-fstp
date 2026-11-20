//! The setup tools of the ADR-013 amendment of 2026-11-20 (Daniel) through
//! the one dispatch: an agent prepares, and a person confirms in the
//! platform (I-84, I-85, I-86, I-66, I-67, I-78).
//!
//! Each test drives a fake cell of the world of `signatories/mod.rs`,
//! onboarded and activated (ADR-021). A1 and A2 are its verified tenant
//! admins. A1's agent holds every scope.
//!
//! - A prepare-only tool of a creator command and of a tenant command
//!   gives a pending action and appends nothing. A1 confirms it in the
//!   platform. A high-risk one needs a step-up bound to the stored digest.
//!   The appended entry names the pending action and the agent.
//! - A prepare-only tool on an operation that is not high-risk needs no
//!   step-up at the confirmation, as its web route needs none.
//! - The dry run and the gates of the web route run before an action is
//!   stored: a request for activation of a draft whose report is not clean
//!   is refused under I-66, and nothing is stored.
//! - No tool reaches the I-67 approval or override of an activation.
//! - Daniel's decision of 2026-11-20 on P-75 and P-77: a save through MCP
//!   that sets or clears either one, alone or mixed with other fields, and
//!   a start from a template, give a pending action. A save of other
//!   fields, a blank start and the web route execute. The confirmation
//!   asks no step-up and applies once.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::arithmetic_side_effects)]

mod signatories;

use fstp_api_core::decode::decode_tool;
use fstp_api_core::meta::Scope;
use fstp_api_core::port::LoginMethod;
use fstp_api_core::{ApiError, Op, OpResult};
use fstp_api_testkit::fake::FakeCell;
use fstp_api_testkit::fake::WebLogin;
use fstp_api_testkit::fake::fixture::AGENT;
use fstp_api_testkit::fake::requests;
use fstp_domain::Via;
use fstp_json::{ToJson, Value};
use signatories::{A1, FINANCIAL, LEGAL, S1, active, appended, done, text};

/// Brand tokens that pass I-70, from `m9b1_branding_dispatch.rs`.
const PLATFORM: &str = r##"{"dark":{"brand":"#3b82f6","brand-hover":"#60a5fa","brand-text":"#93c5fd","focus":"#60a5fa","on-brand":"#0f172a"},"light":{"brand":"#2563eb","brand-hover":"#1d4ed8","brand-text":"#1e40af","focus":"#2563eb","on-brand":"#ffffff"},"name":"Harbour Fund","typography":"system"}"##;

/// A tool call through MCP with `args` as its JSON arguments.
fn tool(name: &str, args: &str) -> Result<Op, ApiError> {
    decode_tool(name, args.as_bytes())
}

/// An activated cell, A1's login and A1's agent token with every scope.
fn cell() -> (FakeCell, WebLogin, Vec<u8>) {
    let (c, l1, _) = active(&[(S1, FINANCIAL), (S1, LEGAL)]);
    let token = c.token(A1, AGENT, Scope::ALL, LoginMethod::Passkey);
    (c, l1, token)
}

/// The pending action of `r`, which must be one.
fn pending(r: Result<OpResult, ApiError>, what: &str) -> fstp_api_core::PendingReceipt {
    match r {
        Ok(OpResult::Pending(p)) => p,
        other => panic!("I-85: {what} gave {other:?}, not a pending action"),
    }
}

/// Confirms the open pending action `id` as `login`, taking a step-up when
/// one is asked for, and checks the step-up is bound to the stored digest.
/// Returns the result and whether a step-up was asked for.
fn confirm(
    c: &FakeCell,
    login: &WebLogin,
    id: fstp_api_core::port::PendingId,
) -> (Result<OpResult, ApiError>, bool) {
    let list = c.pending(login).unwrap();
    let view = list
        .iter()
        .find(|v| v.id == id)
        .expect("the action is listed");
    match c.web(login, requests::pending_confirm(id, &view.digest)) {
        Ok(OpResult::StepUpRequired(ch)) => {
            assert_eq!(ch.action, view.digest, "I-78: the step-up binds the digest");
            c.ports.step_up.approve(login.session, ch.action).unwrap();
            (
                c.web(login, requests::pending_confirm(id, &view.digest)),
                true,
            )
        }
        other => (other, false),
    }
}

/// Opens a draft through A1's agent and A1's confirmation, and returns its
/// programme id.
fn prepared_draft(c: &FakeCell, l1: &WebLogin, token: &[u8]) -> String {
    let before = appended(c);
    let p = pending(
        c.mcp(token, tool("fstp_prepare_programme_draft", "{}")),
        "fstp_prepare_programme_draft",
    );
    assert_eq!(appended(c), before, "I-85: preparing appends nothing");
    let (r, stepped) = confirm(c, l1, p.id);
    assert!(stepped, "I-78: creating a programme needs a step-up");
    let v = done(r, "the confirmation of the prepared draft");
    assert_eq!(appended(c), before + 1, "one entry once confirmed");
    let e = c.ports.engine.appended().last().cloned().unwrap();
    assert_eq!(e.meta.op.0, "creator.open_draft");
    assert_eq!(e.meta.via, Via::Web, "I-85: completed through the web");
    assert_eq!(e.meta.pending, Some(p.id), "the entry names the action");
    assert_eq!(e.meta.agent, Some(AGENT), "the entry names the agent");
    assert!(e.meta.step_up.is_some(), "I-78: with its step-up");
    text(&v, "programme")
}

/// I-85, I-78, ADR-013 amendment of 2026-11-20: a prepared programme draft,
/// a creator command and high-risk, completes only once A1 confirms it in
/// the platform with a step-up bound to the stored digest. A second
/// confirmation is refused.
#[test]
fn i85_adr013_prepared_programme_draft_needs_platform_step_up() {
    let (c, l1, token) = cell();
    let _ = prepared_draft(&c, &l1, &token);
    let id = c.pending(&l1).unwrap().first().map(|v| (v.id, v.digest));
    let (id, digest) = id.expect("the confirmed action stays listed");
    let again = c.web(&l1, requests::pending_confirm(id, &digest));
    assert!(
        matches!(again, Err(ApiError::Refused { .. })),
        "I-85: a confirmed action confirms once: {again:?}"
    );
}

/// I-85, I-86, ADR-013 amendment of 2026-11-20: the prepared invitation of a
/// programme manager, not high-risk but inviting a person, gives a pending
/// action whose receipt holds no email. A1 confirms it in the platform,
/// with no step-up since its web route asks none.
#[test]
fn i85_i86_adr013_prepared_invitation_completes_only_in_the_platform() {
    let (c, l1, token) = cell();
    let programme = prepared_draft(&c, &l1, &token);
    let before = appended(&c);
    let args = format!(
        r#"{{"programme":"{programme}","email":"invitee@matrix.invalid","role":"programme_manager"}}"#
    );
    let p = pending(
        c.mcp(&token, tool("fstp_prepare_invitation", &args)),
        "fstp_prepare_invitation",
    );
    let receipt = p.to_json().to_compact();
    assert!(
        !receipt.contains('@'),
        "I-86: the receipt names the email: {receipt}"
    );
    assert_eq!(appended(&c), before, "I-85: preparing invites nobody");
    let (r, stepped) = confirm(&c, &l1, p.id);
    assert!(!stepped, "the invitation asks no step-up on the web");
    let _ = done(r, "the confirmation of the prepared invitation");
    assert_eq!(appended(&c), before + 1);
    let e = c.ports.engine.appended().last().cloned().unwrap();
    assert_eq!(e.meta.op.0, "creator.invite");
    assert_eq!(e.meta.via, Via::Web);
    assert_eq!(e.meta.pending, Some(p.id));
}

/// I-66, I-85, ADR-013 amendment of 2026-11-20: the dry run and the I-66
/// gate of the web route run before an action is stored. A fresh draft's
/// report is not clean, so its prepared activation request is refused and
/// nothing is stored or appended.
#[test]
fn i66_adr013_prepared_activation_request_of_an_unclean_draft_is_refused() {
    let (c, l1, token) = cell();
    let programme = prepared_draft(&c, &l1, &token);
    let listed = c.pending(&l1).unwrap().len();
    let before = appended(&c);
    let view = done(
        c.web(
            &l1,
            fstp_api_testkit::fake::creator_requests::raw(
                fstp_api_core::decode::Method::Get,
                &format!("/programmes/{programme}/draft"),
                "",
            ),
        ),
        "creator.get_draft",
    );
    let revision = signatories::member(&view, "revision");
    let args = format!(
        r#"{{"programme":"{programme}","revision":{}}}"#,
        revision.to_compact()
    );
    let r = c.mcp(&token, tool("fstp_prepare_activation_request", &args));
    assert!(
        matches!(r, Err(ApiError::Refused { rule: "I-66", .. })),
        "I-66: an unclean draft's request was {r:?}"
    );
    assert_eq!(c.pending(&l1).unwrap().len(), listed, "nothing is stored");
    assert_eq!(appended(&c), before, "nothing is appended");
}

/// I-85, I-78, ADR-013 amendment of 2026-11-20: prepared interface labels, a
/// tenant command and high-risk, give a pending action and change nothing.
/// A1 confirms them in the platform with a step-up, and only then are the
/// labels recorded, through the web.
#[test]
fn i85_adr013_prepared_terminology_needs_platform_step_up() {
    let (c, l1, token) = cell();
    let before = appended(&c);
    let p = pending(
        c.mcp(
            &token,
            tool(
                "fstp_prepare_terminology",
                r#"{"labels":{"vocab.call":"Subgrant call"},"voyage_on":true}"#,
            ),
        ),
        "fstp_prepare_terminology",
    );
    assert_eq!(appended(&c), before, "I-85: preparing records nothing");
    let (r, stepped) = confirm(&c, &l1, p.id);
    assert!(stepped, "I-78: the labels need a step-up");
    let _ = done(r, "the confirmation of the prepared labels");
    assert_eq!(appended(&c), before + 1);
    let e = c.ports.engine.appended().last().cloned().unwrap();
    assert_eq!(e.meta.op.0, "tenant.terminology.set");
    assert_eq!(e.meta.via, Via::Web);
    assert_eq!(e.meta.pending, Some(p.id));
    assert!(e.meta.step_up.is_some());
}

/// I-84, ADR-013 amendment of 2026-11-20: the brand check executes through
/// MCP and records nothing, as on the web.
#[test]
fn i84_adr013_brand_check_executes_and_records_nothing() {
    let (c, _, token) = cell();
    let before = appended(&c);
    let r = c.mcp(
        &token,
        tool(
            "fstp_tenant_check_branding",
            &format!(r#"{{"tokens":{PLATFORM}}}"#),
        ),
    );
    assert!(
        matches!(r, Ok(OpResult::Done { seq: None, .. })),
        "the check executes and is never prepared: {r:?}"
    );
    assert_eq!(appended(&c), before, "the check records nothing");
}

/// I-67, I-66, ADR-013 amendment of 2026-11-20: no tool approves or
/// overrides the activation of a programme, so an agent acting for a
/// builder or an approver cannot reach either.
#[test]
fn i67_adr013_no_tool_reaches_an_activation_approval() {
    for name in [
        "fstp_prepare_activation_approval",
        "fstp_approve_activation",
        "fstp_prepare_activation_override",
        "fstp_creator_approve_activation",
    ] {
        assert!(tool(name, "{}").is_err(), "{name} decodes as a tool");
    }
    for t in fstp_api_core::meta::tools() {
        let op = fstp_access::OPS
            .iter()
            .find(|o| o.tool.is_some_and(|x| x.name == t.name))
            .unwrap();
        assert!(
            !matches!(
                op.kind,
                fstp_access::OpKind::Creator(
                    fstp_access::CreatorKind::ApproveActivation
                        | fstp_access::CreatorKind::OverrideActivation
                )
            ),
            "{} reaches {}",
            t.name,
            op.name
        );
    }
}

/// The `<step>.<member>` key of P-75 (`fstp_programme::FieldId::key`).
const P75: &str = "evaluation.p75_agent_content_reads";
/// The key of P-77.
const P77: &str = "evaluation.p77_mcp_binding_actions";
/// The key of P-28, a policy field that neither P-75 nor P-77 governs.
const P28: &str = "evaluation.p28_rubric_bands";

/// A draft A1 opens through the web with a step-up, and its programme
/// id.
fn web_draft(c: &FakeCell, l1: &WebLogin) -> String {
    let v = done(
        signatories::stepped(c, l1, &fstp_api_testkit::fake::creator_requests::open_draft),
        "creator.open_draft",
    );
    text(&v, "programme")
}

/// The programme id `p` names.
fn programme_id(p: &str) -> fstp_domain::id::ProgrammeId {
    fstp_domain::id::ProgrammeId::from_raw(p.parse().unwrap())
}

/// The head revision of draft `p`, as `creator.get_draft` shows it.
fn head(c: &FakeCell, l1: &WebLogin, p: &str) -> String {
    let view = done(
        c.web(
            l1,
            fstp_api_testkit::fake::creator_requests::get_draft(programme_id(p)),
        ),
        "creator.get_draft",
    );
    text(&view, "revision")
}

/// The fields draft `p` holds.
fn held(c: &FakeCell, p: &str) -> std::collections::BTreeSet<fstp_programme::FieldId> {
    c.ports
        .engine
        .state()
        .creator
        .draft(programme_id(p))
        .map(|d| d.set_fields())
        .unwrap_or_default()
}

/// The field id of a key.
fn field(key: &str) -> fstp_programme::FieldId {
    fstp_programme::FieldId::from_key(key).unwrap()
}

/// `fstp_creator_save_fields` on draft `p` at `base`, with `fields` as
/// `[{field, value}]` JSON and an optional `clear` JSON array.
fn save_tool(p: &str, base: &str, fields: &str, clear: Option<&str>) -> Result<Op, ApiError> {
    let clear = clear.map(|c| format!(r#","clear":{c}"#)).unwrap_or_default();
    tool(
        "fstp_creator_save_fields",
        &format!(r#"{{"programme":"{p}","base":"{base}","fields":{fields}{clear}}}"#),
    )
}

/// `fstp_creator_apply_start` on draft `p` at `base` with `start` JSON.
fn start_tool(p: &str, base: &str, start: &str) -> Result<Op, ApiError> {
    tool(
        "fstp_creator_apply_start",
        &format!(r#"{{"programme":"{p}","base":"{base}","start":{start}}}"#),
    )
}

/// The confirmed pending action's appended entry: `op` through the web,
/// naming the action and the agent, with no step-up (decision 2 of
/// 2026-11-20: the operation is not high-risk).
fn confirmed_without_step_up(
    c: &FakeCell,
    l1: &WebLogin,
    p: &fstp_api_core::PendingReceipt,
    op: &str,
) {
    let before = appended(c);
    let (r, stepped) = confirm(c, l1, p.id);
    assert!(!stepped, "{op} asks no step-up on the web, so none here");
    let _ = done(r, "the confirmation");
    assert_eq!(appended(c), before + 1, "one entry once confirmed");
    let e = c.ports.engine.appended().last().cloned().unwrap();
    assert_eq!(e.meta.op.0, op);
    assert_eq!(e.meta.via, Via::Web, "I-85: completed through the web");
    assert_eq!(e.meta.pending, Some(p.id), "the entry names the action");
    assert_eq!(e.meta.agent, Some(AGENT), "the entry names the agent");
    assert!(e.meta.step_up.is_none());
}

/// P-75, I-85, ADR-013 decision of Daniel of 2026-11-20: a save of P-75
/// through MCP gives a pending action and changes nothing. A1 confirms it
/// in the platform without a step-up, and only then does the draft hold
/// P-75.
#[test]
fn p75_i85_save_through_mcp_is_pending_until_confirmed() {
    let (c, l1, token) = cell();
    let p = web_draft(&c, &l1);
    let base = head(&c, &l1, &p);
    let before = appended(&c);
    let receipt = pending(
        c.mcp(
            &token,
            save_tool(&p, &base, &format!(r#"[{{"field":"{P75}","value":true}}]"#), None),
        ),
        "a save of P-75 through MCP",
    );
    assert_eq!(appended(&c), before, "I-85: preparing saves nothing");
    assert!(!held(&c, &p).contains(&field(P75)), "P-75 changed");
    assert_eq!(head(&c, &l1, &p), base, "the draft revision moved");
    confirmed_without_step_up(&c, &l1, &receipt, "creator.save_fields");
    assert!(held(&c, &p).contains(&field(P75)), "the confirmed save holds");
}

/// P-77, I-85, ADR-013 decision of Daniel of 2026-11-20: a save of P-77
/// through MCP gives a pending action and changes nothing until A1
/// confirms it in the platform.
#[test]
fn p77_i85_save_through_mcp_is_pending_until_confirmed() {
    let (c, l1, token) = cell();
    let p = web_draft(&c, &l1);
    let base = head(&c, &l1, &p);
    let before = appended(&c);
    let receipt = pending(
        c.mcp(
            &token,
            save_tool(
                &p,
                &base,
                &format!(r#"[{{"field":"{P77}","value":"allowed"}}]"#),
                None,
            ),
        ),
        "a save of P-77 through MCP",
    );
    assert_eq!(appended(&c), before, "I-85: preparing saves nothing");
    assert!(!held(&c, &p).contains(&field(P77)), "P-77 changed");
    confirmed_without_step_up(&c, &l1, &receipt, "creator.save_fields");
    assert!(held(&c, &p).contains(&field(P77)), "the confirmed save holds");
}

/// P-75, P-77, I-85, ADR-013 decision of Daniel of 2026-11-20: a save that
/// mixes P-77 with another field is prepared as a whole. Neither field
/// changes until A1 confirms, and the confirmation saves both.
#[test]
fn p77_i85_mixed_save_through_mcp_is_pending_as_a_whole() {
    let (c, l1, token) = cell();
    let p = web_draft(&c, &l1);
    let base = head(&c, &l1, &p);
    let before = appended(&c);
    let fields =
        format!(r#"[{{"field":"{P28}","value":false}},{{"field":"{P77}","value":"draft_only"}}]"#);
    let receipt = pending(
        c.mcp(&token, save_tool(&p, &base, &fields, None)),
        "a mixed save through MCP",
    );
    assert_eq!(appended(&c), before, "I-85: no part of the save executes");
    let fields_held = held(&c, &p);
    assert!(!fields_held.contains(&field(P28)), "P-28 was saved alone");
    assert!(!fields_held.contains(&field(P77)), "P-77 changed");
    confirmed_without_step_up(&c, &l1, &receipt, "creator.save_fields");
    let fields_held = held(&c, &p);
    assert!(fields_held.contains(&field(P28)) && fields_held.contains(&field(P77)));
}

/// P-77, I-85, ADR-013 decision of Daniel of 2026-11-20: a clear of P-77
/// through MCP removes the value the draft holds, so it is prepared too.
#[test]
fn p77_i85_clear_through_mcp_is_pending_until_confirmed() {
    let (c, l1, token) = cell();
    let p = web_draft(&c, &l1);
    let base = head(&c, &l1, &p);
    let _ = done(
        c.web(
            &l1,
            fstp_api_testkit::fake::creator_requests::save_fields(
                programme_id(&p),
                &base,
                &[(P77, Value::String("draft_only".to_owned()))],
            ),
        ),
        "the web save of P-77",
    );
    let base = head(&c, &l1, &p);
    let before = appended(&c);
    let receipt = pending(
        c.mcp(
            &token,
            save_tool(&p, &base, "[]", Some(&format!(r#"["{P77}"]"#))),
        ),
        "a clear of P-77 through MCP",
    );
    assert_eq!(appended(&c), before, "I-85: preparing clears nothing");
    assert!(held(&c, &p).contains(&field(P77)), "P-77 was cleared");
    confirmed_without_step_up(&c, &l1, &receipt, "creator.save_fields");
    assert!(!held(&c, &p).contains(&field(P77)), "the confirmed clear holds");
}

/// I-84, P-75, P-77, ADR-013 decision of Daniel of 2026-11-20: a save of
/// other fields through MCP still executes, with `Via::Mcp`.
#[test]
fn i84_p75_p77_save_of_other_fields_through_mcp_executes() {
    let (c, l1, token) = cell();
    let p = web_draft(&c, &l1);
    let base = head(&c, &l1, &p);
    let before = appended(&c);
    let _ = done(
        c.mcp(
            &token,
            save_tool(&p, &base, &format!(r#"[{{"field":"{P28}","value":true}}]"#), None),
        ),
        "a save of P-28 through MCP",
    );
    assert_eq!(appended(&c), before + 1);
    let e = c.ports.engine.appended().last().cloned().unwrap();
    assert_eq!(e.meta.op.0, "creator.save_fields");
    assert_eq!(e.meta.via, Via::Mcp);
    assert_eq!(e.meta.pending, None);
    assert!(held(&c, &p).contains(&field(P28)));
}

/// I-84, P-75, ADR-013 decision of Daniel of 2026-11-20: the web route
/// saves P-75 directly, as before. Only the MCP channel prepares it.
#[test]
fn i84_p75_web_save_executes_directly() {
    let (c, l1, _) = cell();
    let p = web_draft(&c, &l1);
    let base = head(&c, &l1, &p);
    let before = appended(&c);
    let _ = done(
        c.web(
            &l1,
            fstp_api_testkit::fake::creator_requests::save_fields(
                programme_id(&p),
                &base,
                &[(P75, Value::Bool(true))],
            ),
        ),
        "the web save of P-75",
    );
    assert_eq!(appended(&c), before + 1);
    let e = c.ports.engine.appended().last().cloned().unwrap();
    assert_eq!(e.meta.via, Via::Web);
    assert_eq!(e.meta.pending, None);
    assert!(held(&c, &p).contains(&field(P75)));
}

/// I-85, P-75, P-77, ADR-013 decision of Daniel of 2026-11-20: the pending
/// save applies once. A second confirmation is refused and appends
/// nothing, and the confirmed action is no longer open.
#[test]
fn p75_i85_confirmation_applies_the_save_once() {
    let (c, l1, token) = cell();
    let p = web_draft(&c, &l1);
    let base = head(&c, &l1, &p);
    let receipt = pending(
        c.mcp(
            &token,
            save_tool(&p, &base, &format!(r#"[{{"field":"{P75}","value":false}}]"#), None),
        ),
        "a save of P-75 through MCP",
    );
    confirmed_without_step_up(&c, &l1, &receipt, "creator.save_fields");
    let after = appended(&c);
    let digest = c
        .pending(&l1)
        .unwrap()
        .into_iter()
        .find(|v| v.id == receipt.id)
        .map(|v| v.digest)
        .expect("the confirmed action stays listed");
    let again = c.web(&l1, requests::pending_confirm(receipt.id, &digest));
    assert!(
        matches!(again, Err(ApiError::Refused { .. })),
        "I-85: a confirmed action confirms once: {again:?}"
    );
    assert_eq!(appended(&c), after, "the second confirmation saved again");
}

/// P-75, P-77, I-85, ADR-013 decision of Daniel of 2026-11-20: a start from
/// a template through MCP applies the template's P-75 and P-77, so it is
/// prepared and changes nothing until A1 confirms it. A blank start
/// applies neither and executes.
#[test]
fn p75_p77_i85_template_start_through_mcp_is_pending_and_blank_executes() {
    let (c, l1, token) = cell();
    let p = web_draft(&c, &l1);
    let base = head(&c, &l1, &p);
    let before = appended(&c);
    let template = fstp_api_testkit::fake::creator_requests::supersafe_start().to_compact();
    let receipt = pending(
        c.mcp(&token, start_tool(&p, &base, &template)),
        "a template start through MCP",
    );
    assert_eq!(appended(&c), before, "I-85: preparing applies nothing");
    let fields_held = held(&c, &p);
    assert!(!fields_held.contains(&field(P75)) && !fields_held.contains(&field(P77)));
    confirmed_without_step_up(&c, &l1, &receipt, "creator.apply_start");
    let fields_held = held(&c, &p);
    assert!(fields_held.contains(&field(P75)) && fields_held.contains(&field(P77)));

    let q = web_draft(&c, &l1);
    let base = head(&c, &l1, &q);
    let before = appended(&c);
    let _ = done(
        c.mcp(&token, start_tool(&q, &base, r#"{"kind":"blank"}"#)),
        "a blank start through MCP",
    );
    assert_eq!(appended(&c), before + 1);
    let e = c.ports.engine.appended().last().cloned().unwrap();
    assert_eq!(e.meta.op.0, "creator.apply_start");
    assert_eq!(e.meta.via, Via::Mcp);
}
