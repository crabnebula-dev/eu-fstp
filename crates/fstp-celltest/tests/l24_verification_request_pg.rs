//! The verification request on the production cell over PostgreSQL
//! (ADR-008 and ADR-026 record of lane L24, decided by Daniel on
//! 2026-11-22: "Request, staff record it").
//!
//! A person presses "Start verification": `me.begin_verification` goes
//! through the production cell's API core to its vault port, which
//! records `VerificationRequested` and answers the person's own identity
//! page. The tenant admin then sees the open request in the list of
//! people to verify. Every account is synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_celltest::mc::auth_model::http::{AuthClient, Cookie, FIRST_ADMIN};
use fstp_celltest::reference::auth::RefMethod;
use fstp_celltest::world::{
    CellHandle, DbMode, HttpReply, HttpRequest, VaultLayout, World, WorldSpec,
};
use fstp_domain::id::AccountId;
use fstp_json::Value;

/// The model account of the person who asks.
const PERSON: AccountId = AccountId::from_raw(72_001);

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

/// A web call in the session `cookie`, as `web/src/core/api.ts` sends it.
fn web(cell: &CellHandle, method: &str, path: &str, cookie: &Cookie, body: &str) -> HttpReply {
    let mut r = HttpRequest::new(method, path)
        .header("host", cell.host())
        .header("cookie", cookie.0.clone())
        .header("accept", "application/json");
    if method != "GET" {
        r = r
            .header("origin", format!("https://{}", cell.host()))
            .header("x-fstp-request", "1")
            .header("content-type", "application/json")
            .body(body.as_bytes().to_vec());
    }
    cell.request(&r).unwrap_or_else(|e| panic!("{e}"))
}

fn json(r: &HttpReply) -> Value {
    fstp_json::parse(&r.body).unwrap_or(Value::Null)
}

/// I-17, ADR-008 and ADR-026 record of lane L24 (decided by Daniel on
/// 2026-11-22): "Start verification" succeeds on the production cell. It
/// records one open request with no identity data, and answers the
/// person's own identity page. Pressing it again records nothing more.
/// The tenant admin's list of people to verify shows the request; the
/// person's own session may not read that list.
#[test]
fn adr008_begin_verification_records_a_request_on_the_production_cell() {
    let world = world();
    let cell = world.cell(0).unwrap();
    let client = AuthClient::new(cell);
    assert!(client.enrol(FIRST_ADMIN).unwrap());
    assert!(client.enrol(PERSON).unwrap());
    let id = client.cell_account(PERSON).unwrap();
    let person = client
        .login(PERSON, RefMethod::Passkey)
        .unwrap()
        .expect("the person's session");
    let r = web(cell, "POST", "/api/v1/me/verification", &person, "{}");
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(
        json(&r).get("redirect").and_then(Value::as_str),
        Some("/app/me/identity"),
        "the reply is not the person's identity page"
    );
    let state = || cell.cell_engine().unwrap().state();
    assert!(state().verification_requested(id));
    assert_eq!(state().verification_requests().count(), 1);
    let again = web(cell, "POST", "/api/v1/me/verification", &person, "{}");
    assert_eq!(again.status, 200);
    assert_eq!(state().verification_requests().count(), 1);
    assert!(
        !String::from_utf8_lossy(&r.body).contains("vault"),
        "I-17: the reply names the vault"
    );

    let mine = web(cell, "GET", "/api/v1/verification-people", &person, "");
    assert_eq!(
        mine.status, 403,
        "the person reads the list of people to verify"
    );
    let admin = client.admin_session().expect("the admin session");
    let list = web(cell, "GET", "/api/v1/verification-people", &admin, "");
    assert_eq!(list.status, 200);
    let people = json(&list);
    let rows = people.get("people").and_then(Value::as_array).unwrap();
    let row = rows
        .iter()
        .find(|p| p.get("account").and_then(Value::as_str) == Some(id.raw().to_string().as_str()))
        .unwrap_or_else(|| panic!("the request is not listed: {people:?}"));
    assert_eq!(row.get("requested").and_then(Value::as_bool), Some(true));
    assert!(row.get("proposal").is_some_and(Value::is_null));
}

/// The `status` of `me.get_verification` in the session `cookie`.
fn status(cell: &CellHandle, cookie: &Cookie) -> String {
    let r = web(cell, "GET", "/api/v1/me/verification", cookie, "");
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    json(&r)
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// ADR-026 record of lane L24, rows "Applicant status" and "Open
/// request" (lead readings of 2026-11-22): the person's status reads
/// "pending" from the ledger while the request is open, also long after
/// the API core's in-memory hour. Once the vault confirms the check, the
/// timeline task closes the request and the status reads "verified".
#[test]
fn adr008_status_reads_the_durable_request_until_the_vault_confirms() {
    let world = world();
    let cell = world.cell(0).unwrap();
    let client = AuthClient::new(cell);
    assert!(client.enrol(FIRST_ADMIN).unwrap());
    assert!(client.enrol(PERSON).unwrap());
    let id = client.cell_account(PERSON).unwrap();
    let person = client
        .login(PERSON, RefMethod::Passkey)
        .unwrap()
        .expect("the person's session");
    assert_eq!(status(cell, &person), "unverified");
    let r = web(cell, "POST", "/api/v1/me/verification", &person, "{}");
    assert_eq!(r.status, 200);
    let state = || cell.cell_engine().unwrap().state();
    // Three hours later, past the in-memory hour.
    cell.clock().set(cell.clock().now() + 3 * 3_600_000_000);
    cell.timeline_tick().unwrap();
    assert!(
        state().verification_requested(id),
        "an unverified request closed"
    );
    let person = client
        .login(PERSON, RefMethod::Passkey)
        .unwrap()
        .expect("a fresh session");
    assert_eq!(
        status(cell, &person),
        "pending",
        "the durable request is not read"
    );
    cell.seed_verification(id, b"l24-person-synthetic")
        .unwrap_or_else(|e| panic!("the verification: {e}"));
    for _ in 0..3 {
        cell.timeline_tick().unwrap();
        if !state().verification_requested(id) {
            break;
        }
    }
    assert!(
        !state().verification_requested(id),
        "the vault's confirmation left the request open"
    );
    assert_eq!(status(cell, &person), "verified");
}
