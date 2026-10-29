//! Flows through the cell routes that the route sweep does not reach
//! (I-18, I-19, I-78, R-LG-04, ADR-008). Lane W3a, agent one, production
//! side. Each test drives the production front over the in-memory backend
//! (`fstp_cell::routes::memory::LocalCell`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_cell::http::decode_command_body;
use fstp_cell::routes::memory::LocalCell;
use fstp_cell::routes::{CHALLENGE_US, MAGIC_LINK_US};
use fstp_cell_core::CellCommand;
use fstp_cell_core::tenant::{TenantCommand, TenantLoginPolicy};
use fstp_domain::id::{BindingId, CallId, ProposalId};
use fstp_domain::time::Timestamp;
use fstp_http::{Method, Request, RequestTarget, Response};

const CELL: [u8; 16] = [0xC3; 16];
const HOST: &str = "tenant-c.fstp.test";

fn cell() -> LocalCell {
    LocalCell::start(CELL, HOST).unwrap()
}

fn request(method: &str, path: &str, cookie: Option<&[u8]>, body: Option<&[u8]>) -> Request {
    let m = Method::from_bytes(method.as_bytes()).unwrap();
    let mut req = Request::new(m, RequestTarget::origin(path).unwrap())
        .try_with_header("host", HOST)
        .unwrap();
    if matches!(method, "POST" | "DELETE") {
        req = req
            .try_with_header("origin", format!("https://{HOST}"))
            .unwrap();
    }
    if let Some(c) = cookie {
        req = req.try_with_header("cookie", c.to_vec()).unwrap();
    }
    if let Some(b) = body {
        req = req
            .try_with_header("content-type", "application/json")
            .unwrap();
        req.body = b.to_vec();
    }
    req
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn command_body(c: &CellCommand, id: [u8; 16]) -> Vec<u8> {
    let command = String::from_utf8(fstp_cell_core::encode_cell_command(c)).unwrap();
    format!("{{\"command\":{command},\"command_id\":\"{}\"}}", hex(&id)).into_bytes()
}

fn status(r: &Response) -> u16 {
    r.status.as_u16()
}

/// I-18, NOTE 14: a `CreateDraft` in a request names no `minor` member, and
/// the route decodes it minor-flagged. The same command with the member is
/// refused, whatever its value.
#[test]
fn i18_create_draft_from_a_request_is_always_minor_flagged() {
    let draft = |minor| {
        CellCommand::Engine(fstp_engine::Command::Core(
            fstp_domain::command::Command::CreateDraft {
                proposal: ProposalId::from_raw(3),
                call: CallId::from_raw(2),
                binding: BindingId::from_raw(1),
                minor,
            },
        ))
    };
    for minor in [true, false] {
        let with = command_body(&draft(minor), [1; 16]);
        assert!(decode_command_body(&with).is_err(), "minor {minor} decoded");
    }
    let text = String::from_utf8(command_body(&draft(true), [1; 16])).unwrap();
    let without = text.replace(",\"minor\":true", "");
    assert_ne!(without, text, "the encoded draft names no minor member");
    let got = decode_command_body(without.as_bytes()).unwrap();
    assert_eq!(got.command.map(|c| *c), Some(draft(true)));
}

/// I-78, design section 8.4: a high-risk command through
/// `POST /api/v1/commands` without a step-up is refused by the gate (403),
/// for a tenant admin's passkey session.
#[test]
fn i78_commands_route_refuses_a_high_risk_command_without_a_step_up() {
    let c = cell();
    let cookie = c.admin_session().unwrap();
    let policy = TenantLoginPolicy {
        p71_us: Some(60_000_000),
        p72_idle_us: None,
        p72_absolute_us: None,
    };
    let command = CellCommand::Tenant(TenantCommand::SetLoginPolicy {
        policy: policy.encode(),
    });
    let body = command_body(&command, [2; 16]);
    let resp = c.serve(request(
        "POST",
        "/api/v1/commands",
        Some(&cookie),
        Some(&body),
    ));
    assert_eq!(status(&resp), 403);
    let last = c.logs().last().copied();
    assert!(
        matches!(
            last,
            Some(fstp_obs::LogEvent::Refused {
                route: "/api/v1/commands",
                rule: "I-78",
                status: 403,
                ..
            })
        ),
        "{last:?}"
    );
}

/// ADR-008 "Challenges": a login challenge is single use. Replaying the
/// exact request of a successful login is refused (401), and so is a
/// challenge id the cell never issued.
#[test]
fn adr008_login_challenge_is_single_use() {
    let c = cell();
    let login = c.admin_login_request().unwrap();
    assert_eq!(status(&c.serve(login.clone())), 200);
    assert_eq!(
        status(&c.serve(login)),
        401,
        "a replayed login was accepted"
    );
    // A login body naming a challenge id that was never issued.
    let body = format!(
        "{{\"authenticator_data\":\"00\",\"challenge_id\":\"{}\",\"client_data_json\":\"00\",\"credential_id\":\"00\",\"signature\":\"00\"}}",
        hex(&[9; 16])
    );
    let resp = c.serve(request(
        "POST",
        "/auth/passkey/login",
        None,
        Some(body.as_bytes()),
    ));
    assert_eq!(status(&resp), 401);
}

/// ADR-008 "Magic links": a magic link starts one session only, and an
/// expired link starts none.
#[test]
fn adr008_magic_link_is_single_use_and_expires() {
    let c = cell();
    assert!(c.applicant_session().is_ok());
    let (_, token) = *c.backend().outbox().last().unwrap();
    let body = format!("{{\"token\":\"{}\"}}", hex(&token));
    let again = c.serve(request(
        "POST",
        "/auth/magic/consume",
        None,
        Some(body.as_bytes()),
    ));
    assert_eq!(status(&again), 401, "a consumed link was accepted");

    let email = format!("{{\"email\":\"{}\"}}", c.applicant_email());
    let asked = c.serve(request(
        "POST",
        "/auth/magic/request",
        None,
        Some(email.as_bytes()),
    ));
    assert_eq!(status(&asked), 202);
    let (_, token) = *c.backend().outbox().last().unwrap();
    let late = fstp_cell::routes::memory::DEFAULT_NOW_US + MAGIC_LINK_US + 1;
    c.backend().set_now(Timestamp::from_micros(late));
    let body = format!("{{\"token\":\"{}\"}}", hex(&token));
    let expired = c.serve(request(
        "POST",
        "/auth/magic/consume",
        None,
        Some(body.as_bytes()),
    ));
    assert_eq!(status(&expired), 401, "an expired link was accepted");
}

/// ADR-008 "Challenges": a login challenge older than its lifetime is
/// refused even with a valid assertion.
#[test]
fn adr008_stale_login_challenge_is_refused() {
    let c = cell();
    let options = c.serve(request(
        "POST",
        "/auth/passkey/login/options",
        None,
        Some(b"{}"),
    ));
    assert_eq!(status(&options), 200);
    let late = fstp_cell::routes::memory::DEFAULT_NOW_US + CHALLENGE_US + 1;
    c.backend().set_now(Timestamp::from_micros(late));
    // The software login draws a new challenge, which is fresh, so it
    // still succeeds. The stale one is refused when named.
    let reply = fstp_json::parse(&options.body).unwrap();
    let id = reply.get("challenge_id").and_then(|v| v.as_str()).unwrap();
    let body = format!(
        "{{\"authenticator_data\":\"00\",\"challenge_id\":\"{id}\",\"client_data_json\":\"00\",\"credential_id\":\"00\",\"signature\":\"00\"}}"
    );
    let resp = c.serve(request(
        "POST",
        "/auth/passkey/login",
        None,
        Some(body.as_bytes()),
    ));
    assert_eq!(status(&resp), 401);
    assert!(c.admin_session().is_ok());
}

/// I-19, ADR-009: the tunnel front answers its own host only. Another
/// host, even a cell's sibling, gets 421 and reaches no route.
#[test]
fn i19_tunnel_refuses_another_host() {
    let c = cell();
    for host in ["tenant-d.fstp.test", "id.tenant-c.fstp.test"] {
        let req = Request::new(
            Method::GET,
            RequestTarget::origin("/auth/sessions").unwrap(),
        )
        .try_with_header("host", host)
        .unwrap();
        assert_eq!(status(&c.serve(req)), 421, "{host}");
    }
    let doubled = Request::new(
        Method::GET,
        RequestTarget::origin("/auth/sessions").unwrap(),
    )
    .try_with_header("host", HOST)
    .and_then(|r| r.try_with_header("host", HOST))
    .unwrap();
    assert_eq!(status(&c.serve(doubled)), 421);
}

/// R-LG-04: `GET /auth/sessions` lists the caller's own sessions only.
/// The admin's two sessions are listed to the admin, and the applicant's
/// list holds none of them.
#[test]
fn r_lg_04_sessions_list_only_the_accounts_own() {
    let c = cell();
    let first = c.admin_session().unwrap();
    let _second = c.admin_session().unwrap();
    let applicant = c.applicant_session().unwrap();
    let list = |cookie: &[u8]| {
        let resp = c.serve(request("GET", "/auth/sessions", Some(cookie), None));
        assert_eq!(status(&resp), 200);
        let v = fstp_json::parse(&resp.body).unwrap();
        v.get("sessions")
            .and_then(|s| s.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|s| s.get("id").and_then(|i| i.as_str()).map(str::to_owned))
                    .collect::<Vec<_>>()
            })
            .unwrap()
    };
    let admin = list(&first);
    let mine = list(&applicant);
    assert_eq!(admin.len(), 2);
    assert_eq!(mine.len(), 1);
    assert!(admin.iter().all(|id| !mine.contains(id)));
}

/// I-78, design section 8.4: a step-up challenge is issued only to a
/// passkey session and only for a high-risk command.
#[test]
fn i78_stepup_options_need_a_passkey_session_and_a_high_risk_command() {
    let c = cell();
    let admin = c.admin_session().unwrap();
    let applicant = c.applicant_session().unwrap();
    let policy = TenantLoginPolicy::default();
    let high = CellCommand::Tenant(TenantCommand::SetLoginPolicy {
        policy: policy.encode(),
    });
    let low = CellCommand::Engine(fstp_engine::Command::Core(
        fstp_domain::command::Command::ReadContent {
            proposal: ProposalId::from_raw(1),
        },
    ));
    let body = |cmd: &CellCommand| command_body(cmd, [5; 16]);
    let ask = |cookie: &[u8], b: &[u8]| {
        status(&c.serve(request(
            "POST",
            "/auth/stepup/options",
            Some(cookie),
            Some(b),
        )))
    };
    assert_eq!(ask(&admin, &body(&high)), 200);
    assert_eq!(ask(&applicant, &body(&high)), 403);
    assert_eq!(ask(&admin, &body(&low)), 400);
}

/// The challenge id of a step-up options reply.
fn challenge_id_of(resp: &Response) -> [u8; 16] {
    let text = std::str::from_utf8(&resp.body).unwrap();
    let (_, rest) = text.split_once("\"challenge_id\":\"").unwrap();
    let (hex, _) = rest.split_once('"').unwrap();
    fstp_cell::http::body::hex_array::<16>(hex).unwrap()
}

/// An assertion body naming `challenge` that no credential verifies.
fn bogus_assertion(challenge: [u8; 16]) -> Vec<u8> {
    format!(
        "{{\"authenticator_data\":\"00\",\"challenge_id\":\"{}\",\
         \"client_data_json\":\"00\",\"credential_id\":\"00\",\"signature\":\"00\"}}",
        hex(&challenge)
    )
    .into_bytes()
}

/// I-78, ADR-008, design section 4.2: a step-up challenge ends only by
/// the `auth_log.stepup_consumed` row of its consumption. Naming it from
/// another session at `POST /auth/stepup`, or at the passkey login, is
/// refused and leaves the challenge in place, so no request burns it.
#[test]
fn i78_stepup_challenge_is_not_consumed_by_a_refused_request() {
    let c = cell();
    let owner = c.admin_session().unwrap();
    let other = c.admin_session().unwrap();
    let high = CellCommand::Tenant(TenantCommand::SetLoginPolicy {
        policy: TenantLoginPolicy::default().encode(),
    });
    let options = c.serve(request(
        "POST",
        "/auth/stepup/options",
        Some(&owner),
        Some(&command_body(&high, [6; 16])),
    ));
    assert_eq!(status(&options), 200);
    let id = challenge_id_of(&options);
    let still_there = || {
        fstp_rt::future::block_on(fstp_cell::routes::Backend::challenge(c.backend(), id))
            .unwrap()
            .is_some()
    };
    let assertion = bogus_assertion(id);
    let from_other = c.serve(request(
        "POST",
        "/auth/stepup",
        Some(&other),
        Some(&assertion),
    ));
    assert_eq!(status(&from_other), 403);
    assert!(
        still_there(),
        "another session's request burnt the challenge"
    );
    let at_login = c.serve(request(
        "POST",
        "/auth/passkey/login",
        None,
        Some(&assertion),
    ));
    assert_eq!(status(&at_login), 401);
    assert!(still_there(), "the login route burnt a step-up challenge");
    let from_owner = c.serve(request(
        "POST",
        "/auth/stepup",
        Some(&owner),
        Some(&assertion),
    ));
    assert_eq!(status(&from_owner), 403);
    assert!(still_there(), "a refused assertion consumed the challenge");
}
