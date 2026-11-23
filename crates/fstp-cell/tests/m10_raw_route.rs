//! M10 findings F-039 and F-040 (lane H-01): the raw command route
//! `POST /api/v1/commands` of a production cell serves break-glass
//! approval only (ADR-026 D8 as amended by Daniel on 2026-11-23).
//!
//! Before the amendment the route ran every command the gate admitted.
//! The gate asks a step-up for the commands of its own table only, and
//! the controls of the API core (setup gate, probes, report digests,
//! assessment checks, erasure scope, rate limits) never ran on it. Each
//! test drives the production front over the in-memory backend, as a
//! production build serves it: without the test-only wide form.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_cell::routes::memory::{DEFAULT_NOW_US, LocalCell};
use fstp_cell_core::CellCommand;
use fstp_cell_core::ops::OpsCommand;
use fstp_cell_core::tenant::{TenantCommand, TenantLoginPolicy};
use fstp_cell_core::text::TextCommand;
use fstp_domain::id::{
    BindingId, CallId, ContentDigest, DecisionId, ProgrammeId, ProposalId, TextId, TextRef,
};
use fstp_domain::time::Timestamp;
use fstp_http::{Method, Request, RequestTarget, Response};
use fstp_obs::LogEvent;

const CELL: [u8; 16] = [0xC9; 16];
const HOST: &str = "tenant-raw.fstp.test";

/// The cell as a production build serves it.
fn cell() -> LocalCell {
    LocalCell::start_production(CELL, HOST).unwrap()
}

fn request(path: &str, cookie: &[u8], body: &[u8]) -> Request {
    let mut req = Request::new(Method::POST, RequestTarget::origin(path).unwrap())
        .try_with_header("host", HOST)
        .unwrap()
        .try_with_header("origin", format!("https://{HOST}"))
        .unwrap()
        .try_with_header("cookie", cookie.to_vec())
        .unwrap()
        .try_with_header("content-type", "application/json")
        .unwrap();
    req.body = body.to_vec();
    req
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The request body of `c`. A `CreateDraft` names no `minor` member in a
/// request (I-18), so the encoded member is left out.
fn command_body(c: &CellCommand, id: [u8; 16], stepup: Option<[u8; 16]>) -> Vec<u8> {
    let command = String::from_utf8(fstp_cell_core::encode_cell_command(c))
        .unwrap()
        .replace(",\"minor\":true", "");
    let stepup = stepup.map_or(String::new(), |s| format!(",\"stepup\":\"{}\"", hex(&s)));
    format!(
        "{{\"command\":{command},\"command_id\":\"{}\"{stepup}}}",
        hex(&id)
    )
    .into_bytes()
}

fn text(r: &Response) -> String {
    String::from_utf8_lossy(&r.body).into_owned()
}

fn text_ref(n: u128) -> TextRef {
    TextRef::new(TextId::from_raw(n), ContentDigest::from_bytes([0x11; 32]))
}

fn break_glass(request: [u8; 16]) -> CellCommand {
    CellCommand::Ops(OpsCommand::ApproveBreakGlass {
        request,
        staff: fstp_auth::recovery::StaffRef([0x57; 16]),
        scope: vec![fstp_auth::breakglass::BreakGlassRead::Content],
        until: Timestamp::from_micros(DEFAULT_NOW_US + 3_600_000_000),
    })
}

/// A command of each envelope the raw route decodes, each with its name.
/// None is break-glass approval. Synthetic ids only.
fn others() -> Vec<(&'static str, CellCommand)> {
    use fstp_domain::command::Command as Core;
    vec![
        (
            "core CreateDraft",
            CellCommand::Engine(fstp_engine::Command::Core(Core::CreateDraft {
                proposal: ProposalId::from_raw(3),
                call: CallId::from_raw(2),
                binding: BindingId::from_raw(1),
                minor: true,
            })),
        ),
        (
            "core UnmaskParty",
            CellCommand::Engine(fstp_engine::Command::Core(Core::UnmaskParty {
                programme: ProgrammeId::from_raw(1),
                subject: fstp_domain::unmask::UnmaskSubject::Binding(BindingId::from_raw(1)),
                purpose: text_ref(9),
            })),
        ),
        (
            "onboarding SetGuideNotice",
            CellCommand::Engine(fstp_engine::Command::Tenant(
                fstp_engine::TenantRequest::new(fstp_tenant::TenantCommand::SetGuideNotice {
                    notice: None,
                }),
            )),
        ),
        (
            "creator OverrideActivation",
            CellCommand::Engine(fstp_engine::Command::Creator(
                fstp_creator::CreatorCommand::OverrideActivation {
                    programme: ProgrammeId::from_raw(1),
                    revision: fstp_creator::DraftRevision::new(1, fstp_ledger::Seq::from_raw(1)),
                    decision: DecisionId::from_raw(1),
                    reason: text_ref(1),
                },
            )),
        ),
        (
            "tenant SetLoginPolicy",
            CellCommand::Tenant(TenantCommand::SetLoginPolicy {
                policy: TenantLoginPolicy::default().encode(),
            }),
        ),
        (
            "text EraseTexts",
            CellCommand::Text(TextCommand::EraseTexts {
                ids: vec![[1; 16]],
                cause: 1,
            }),
        ),
        (
            "ops EndBreakGlass",
            CellCommand::Ops(OpsCommand::EndBreakGlass { grant: [2; 16] }),
        ),
        (
            "release IssueWriteTicket",
            CellCommand::Release(fstp_cell_core::release::ReleaseCommand::IssueWriteTicket {
                kind: 1,
            }),
        ),
    ]
}

/// The rule of the last refusal the front logged, if the last event is one.
fn last_rule(c: &LocalCell) -> Option<&'static str> {
    match c.logs().last() {
        Some(LogEvent::Refused { rule, .. }) => Some(*rule),
        _ => None,
    }
}

/// F-039, F-040, I-78, ADR-026 D8 as amended 2026-11-23: a production
/// cell's raw command route refuses every command but break-glass
/// approval. A tenant admin's passkey session sends one command of each
/// envelope, with and without a step-up id. Each is refused with 403 under
/// the rule `ADR-026` before the gate runs, so nothing is appended and no
/// step-up is asked for.
#[test]
fn m10_f039_f040_raw_route_refuses_every_command_but_break_glass_approval() {
    let c = cell();
    let admin = c.admin_session().unwrap();
    let before = c.backend().records().len();
    for (name, command) in others() {
        for stepup in [None, Some([0x5A; 16])] {
            let r = c.serve(request(
                "/api/v1/commands",
                &admin,
                &command_body(&command, [0x31; 16], stepup),
            ));
            assert_eq!(
                r.status.as_u16(),
                403,
                "F-039: {name} answered {}",
                text(&r)
            );
            assert_eq!(text(&r), r#"{"error":"command"}"#, "{name}");
            assert_eq!(last_rule(&c), Some("ADR-026"), "{name}");
            assert_eq!(
                c.backend().records().len(),
                before,
                "F-040: {name} appended a record"
            );
        }
    }
}

/// F-039, I-78, TH-56: the high-risk tenant and creator commands the gate
/// table does not name are refused on the raw route of a production cell,
/// so a plain session never runs them there without a step-up. The step-up
/// options of the same command are never needed.
#[test]
fn m10_f039_i78_raw_route_refuses_high_risk_tenant_and_creator_commands() {
    let c = cell();
    let admin = c.admin_session().unwrap();
    let before = c.backend().records().len();
    let high: Vec<_> = others()
        .into_iter()
        .filter(|(n, _)| n.starts_with("onboarding") || n.starts_with("creator"))
        .collect();
    assert_eq!(high.len(), 2);
    for (name, command) in high {
        let r = c.serve(request(
            "/api/v1/commands",
            &admin,
            &command_body(&command, [0x32; 16], None),
        ));
        assert_eq!(r.status.as_u16(), 403, "I-78: {name} answered {}", text(&r));
        assert_eq!(last_rule(&c), Some("ADR-026"), "{name}");
    }
    assert_eq!(c.backend().records().len(), before);
}

/// ADR-026 D8 as amended, SoD-08, I-78: break-glass approval, which only
/// this route approves, still reaches the gate. Without a step-up the gate
/// refuses it under I-78. With the step-up the ledger granted for its
/// digest, it records `BreakGlassApproved`.
#[test]
fn m10_f039_raw_route_still_approves_break_glass_with_its_step_up() {
    let c = cell();
    let admin = c.admin_session().unwrap();
    let approve = break_glass([0x42; 16]);
    let id = [0x33; 16];
    let bare = c.serve(request(
        "/api/v1/commands",
        &admin,
        &command_body(&approve, id, None),
    ));
    assert_ne!(bare.status.as_u16(), 200, "{}", text(&bare));
    assert_eq!(last_rule(&c), Some("I-78"), "{}", text(&bare));

    let options = c.serve(request(
        "/auth/stepup/options",
        &admin,
        &command_body(&approve, id, None),
    ));
    assert_eq!(options.status.as_u16(), 200, "{}", text(&options));
    let v = fstp_json::parse(&options.body).unwrap();
    let challenge = v
        .get("challenge_id")
        .and_then(fstp_json::Value::as_str)
        .unwrap()
        .to_owned();
    let challenge: [u8; 16] = (0..16)
        .map(|i| u8::from_str_radix(&challenge[2 * i..2 * i + 2], 16).unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let granted = c.serve(c.admin_stepup_request(&admin, challenge).unwrap());
    assert_eq!(granted.status.as_u16(), 200, "{}", text(&granted));
    let r = c.serve(request(
        "/api/v1/commands",
        &admin,
        &command_body(&approve, id, Some(challenge)),
    ));
    assert_eq!(r.status.as_u16(), 200, "{}", text(&r));
    let state = fstp_rt::future::block_on(fstp_cell::routes::Backend::state(c.backend())).unwrap();
    assert!(state.break_glass_known([0x42; 16]), "no BreakGlassApproved");
}
