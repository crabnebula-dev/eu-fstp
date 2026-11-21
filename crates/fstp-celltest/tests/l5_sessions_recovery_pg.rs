//! The production cell's session admin and recovery ports over PostgreSQL
//! (ADR-026 record of lane L5, R-LG-04, I-77, I-78, I-79, H-21).
//!
//! A one-cell world mounts the web adapter over the cell's own `ApiCore`.
//! Each port is compared with the `/auth` route it stands for: the
//! sessions an account lists, the session it ends, and the recovery a
//! second tenant admin approves with a passkey step-up. The completion
//! stays on its route, which ends every earlier session.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_celltest::mc::auth_model::RosterChange;
use fstp_celltest::mc::auth_model::http::{AuthClient, Cookie};
use fstp_celltest::reference::auth::RefMethod;
use fstp_celltest::world::{
    CellHandle, DbMode, HttpReply, HttpRequest, VaultLayout, World, WorldSpec,
};
use fstp_domain::roles::Role;
use fstp_domain_testkit::r#gen::roster::{A, ADMIN, ADMIN_2};
use fstp_json::Value;

fn world() -> World {
    World::start_with_api(WorldSpec {
        cells: 1,
        mode: DbMode::Shared,
        vault_layout: VaultLayout::SeparateCluster,
        self_hosted: false,
        process_mode: false,
    })
    .unwrap_or_else(|e| panic!("{e}"))
}

fn json(r: &HttpReply) -> Value {
    fstp_json::parse(&r.body).unwrap_or(Value::Null)
}

fn text(r: &HttpReply) -> String {
    String::from_utf8_lossy(&r.body).into_owned()
}

fn send(cell: &CellHandle, req: HttpRequest) -> HttpReply {
    cell.request(&req.header("host", cell.host()))
        .unwrap_or_else(|e| panic!("{e}"))
}

/// A call of the web API in the session `cookie`.
fn web(cell: &CellHandle, method: &str, path: &str, cookie: &Cookie, body: &str) -> HttpReply {
    let mut r = HttpRequest::new(method, path)
        .header("cookie", cookie.0.clone())
        .header("accept", "application/json");
    if method != "GET" {
        r = r
            .header("origin", format!("https://{}", cell.host()))
            .header("x-fstp-request", "1")
            .header("content-type", "application/json")
            .body(body.as_bytes().to_vec());
    }
    send(cell, r)
}

/// The passkey ceremony of a `step_up_required` answer `first`, then the
/// same request once more.
fn with_step_up(
    client: &AuthClient<'_>,
    first: &HttpReply,
    again: impl Fn() -> HttpReply,
    cookie: &Cookie,
) -> HttpReply {
    let v = json(first);
    let ch = v
        .get("challenge")
        .unwrap_or_else(|| panic!("no challenge: {}", text(first)));
    let id = ch.get("challenge_id").and_then(Value::as_str).unwrap();
    let bytes = ch
        .get("public_key")
        .and_then(|p| p.get("challenge"))
        .and_then(Value::as_str)
        .unwrap();
    let challenge: [u8; 32] = fstp_oauth::decode_base64url(bytes.as_bytes())
        .unwrap()
        .as_bytes()
        .try_into()
        .unwrap();
    assert!(
        client.prove_api_step_up(cookie, id, challenge).unwrap(),
        "I-78: the passkey step-up was refused"
    );
    again()
}

/// A route session id, 32 hex digits, as the API core spells it: the
/// decimal of its 16 bytes, big-endian.
fn decimal_of_hex(h: &str) -> String {
    u128::from_str_radix(h, 16).unwrap().to_string()
}

/// The ids and methods `GET /auth/sessions` lists for `cookie`, in the API
/// core's spelling.
fn route_sessions(client: &AuthClient<'_>, cookie: &Cookie) -> Vec<(String, String)> {
    let body = client
        .sessions(cookie)
        .unwrap()
        .expect("GET /auth/sessions");
    let v = fstp_json::parse(&body).unwrap();
    let mut out: Vec<(String, String)> = v
        .get("sessions")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .map(|s| {
            (
                decimal_of_hex(s.get("id").and_then(Value::as_str).unwrap()),
                s.get("method").and_then(Value::as_str).unwrap().to_owned(),
            )
        })
        .collect();
    out.sort();
    out
}

/// The ids and methods `me.sessions` lists for `cookie`.
fn api_sessions(cell: &CellHandle, cookie: &Cookie) -> Vec<(String, String)> {
    let r = web(cell, "GET", "/api/v1/me/sessions", cookie, "");
    assert_eq!(r.status, 200, "me.sessions: {}", text(&r));
    let v = json(&r);
    let list = v
        .as_array()
        .cloned()
        .or_else(|| v.get("sessions").and_then(Value::as_array).cloned())
        .unwrap_or_else(|| panic!("no sessions: {}", text(&r)));
    let mut out: Vec<(String, String)> = list
        .iter()
        .map(|s| {
            (
                s.get("session").and_then(Value::as_str).unwrap().to_owned(),
                s.get("method").and_then(Value::as_str).unwrap().to_owned(),
            )
        })
        .collect();
    out.sort();
    out
}

/// R-LG-04 (ADR-026 record of lane L5): `me.sessions` lists exactly the
/// live sessions `GET /auth/sessions` lists, and `me.end_session` ends
/// one of the caller's own sessions as `DELETE /auth/sessions/{id}` does:
/// the ended session is refused from then on, and the other one lives.
/// A session of another account is never ended through the caller.
#[test]
fn r_lg_04_session_admin_matches_the_auth_routes() {
    let world = world();
    let cell = world.cell(0).unwrap();
    let client = AuthClient::new(cell);
    assert!(client.enrol(A).unwrap(), "a enrols");
    let one = client.login(A, RefMethod::Passkey).unwrap().unwrap();
    let two = client.login(A, RefMethod::Passkey).unwrap().unwrap();
    let listed = api_sessions(cell, &one);
    assert_eq!(listed, route_sessions(&client, &one), "R-LG-04: the lists");
    assert!(listed.len() >= 2, "{listed:?}");
    // The admin's session never ends a's.
    let admin = client.admin_session().expect("the admin session");
    let target = current(cell, &two);
    assert!(listed.iter().any(|(id, _)| *id == target), "{listed:?}");
    let foreign = web(
        cell,
        "POST",
        &format!("/api/v1/me/sessions/{target}/end"),
        &admin,
        "{}",
    );
    assert_ne!(foreign.status, 200, "R-LG-04: {}", text(&foreign));
    assert!(client.admitted(&two).unwrap(), "R-LG-04: a's session ended");
    let ended = web(
        cell,
        "POST",
        &format!("/api/v1/me/sessions/{target}/end"),
        &one,
        "{}",
    );
    assert_eq!(ended.status, 200, "me.end_session: {}", text(&ended));
    assert!(client.admitted(&one).unwrap(), "the caller's session ended");
    assert!(
        !client.admitted(&two).unwrap(),
        "R-LG-04: the session lives"
    );
    let after = api_sessions(cell, &one);
    assert_eq!(after, route_sessions(&client, &one));
    assert!(!after.iter().any(|(id, _)| *id == target), "{after:?}");
}

/// The API core's id of the session of `cookie`, which `GET /auth/sessions`
/// marks as current.
fn current(cell: &CellHandle, cookie: &Cookie) -> String {
    let r = send(
        cell,
        HttpRequest::new("GET", "/auth/sessions").header("cookie", cookie.0.clone()),
    );
    let v = json(&r);
    let id = v
        .get("sessions")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .find(|s| s.get("current").and_then(Value::as_bool) == Some(true))
        .and_then(|s| s.get("id").and_then(Value::as_str))
        .unwrap()
        .to_owned();
    decimal_of_hex(&id)
}

/// I-78, I-79, H-21 (ADR-026 record of lane L5): a second tenant admin
/// approves a's recovery through `admin.approve_recovery`. Without a
/// passkey step-up nothing is approved. With one, the approval commits as
/// the route's does, the holder receives a fresh enrolment token by mail,
/// and the completion on its route ends every earlier session of a.
#[test]
fn i79_api_recovery_approval_needs_a_step_up_and_completes() {
    let world = world();
    let cell = world.cell(0).unwrap();
    let client = AuthClient::new(cell);
    for who in [ADMIN, ADMIN_2, A] {
        assert!(client.enrol(who).unwrap(), "{who:?} enrols");
    }
    let admin = client.login(ADMIN, RefMethod::Passkey).unwrap().unwrap();
    assert!(
        client
            .roster(
                &admin,
                RosterChange::Grant {
                    account: A,
                    role: Role::CommitteeMember,
                    until: None,
                },
            )
            .unwrap(),
        "the committee grant to a"
    );
    assert!(
        client
            .roster(&admin, RosterChange::GrantAdmin { account: ADMIN_2 })
            .unwrap(),
        "the tenant admin grant to admin2"
    );
    let admin2 = client.login(ADMIN_2, RefMethod::Passkey).unwrap().unwrap();
    let old = client.login(A, RefMethod::Passkey).unwrap().unwrap();
    let case = client.recovery(A).unwrap().expect("a recovery case");
    assert!(client.recovery_email(&case).unwrap(), "the email proof");
    let id = u128::from_be_bytes(case.0.as_slice().try_into().unwrap());
    let path = format!("/api/v1/admin/recoveries/{id}/approval");
    let mails = cell.mail().count();
    let first = web(cell, "POST", &path, &admin2, "{}");
    assert_eq!(
        json(&first).get("code").and_then(Value::as_str),
        Some("step_up_required"),
        "I-78: an approval without a step-up: {}",
        text(&first)
    );
    assert_eq!(
        cell.mail().count(),
        mails,
        "I-78: approved without a step-up"
    );
    let done = with_step_up(
        &client,
        &first,
        || web(cell, "POST", &path, &admin2, "{}"),
        &admin2,
    );
    assert_eq!(done.status, 200, "admin.approve_recovery: {}", text(&done));
    assert!(
        cell.mail().count() > mails,
        "the holder received no enrolment token"
    );
    let fresh = client
        .recovery_complete(&case)
        .unwrap()
        .expect("I-79: the approved recovery did not complete");
    assert!(
        !client.admitted(&old).unwrap(),
        "I-79: an earlier session survived"
    );
    assert!(client.admitted(&fresh).unwrap());
}
