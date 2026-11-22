//! The erasure log of the production cell over PostgreSQL (ADR-007 section
//! "Built by lane L33", R-KY-02, I-81, I-24). Lane L33.
//!
//! A one-cell world mounts the web adapter over the cell's own `ApiCore`.
//! The first admin replaces its display name. The erasure log then names
//! the old name's text, as a display name, with the cause and the request
//! instant, and the erasure runner completes the entry with the root epoch
//! whose destruction killed its key. `admin.erasures`, the cell's
//! `GET /api/v1/erasures` and the System page read it, and it survives a
//! restart. No reply names the name. Every name is synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_celltest::mc::auth_model::http::{AuthClient, Cookie, FIRST_ADMIN};
use fstp_celltest::world::{
    CellHandle, DbMode, HttpReply, HttpRequest, VaultLayout, World, WorldSpec,
};
use fstp_json::Value;

const OLD: &str = "Synthetic Logged Name";
const NEW: &str = "Synthetic Renamed";

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
    cell.request(&r.header("host", cell.host()))
        .unwrap_or_else(|e| panic!("{e}"))
}

fn set(cell: &CellHandle, cookie: &Cookie, name: &str) {
    let body = format!(
        r#"{{"display_name":{}}}"#,
        Value::String(name.to_owned()).to_compact()
    );
    let r = web(cell, "POST", "/api/v1/me/display-name", cookie, &body);
    assert_eq!(r.status, 200, "me.set_display_name: {}", text(&r));
}

/// The `admin.erasures` rows.
fn rows(cell: &CellHandle, cookie: &Cookie) -> Vec<Value> {
    let r = web(cell, "GET", "/api/v1/admin/erasures", cookie, "");
    assert_eq!(r.status, 200, "admin.erasures: {}", text(&r));
    assert!(!text(&r).contains("Synthetic"), "a reply names a name");
    json(&r)
        .get("erasures")
        .and_then(Value::as_array)
        .map(|a| a.iter().cloned().collect())
        .unwrap_or_default()
}

fn member<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v.get(k).and_then(Value::as_str)
}

/// The rows once the erasure runner completed every entry.
fn completed(cell: &CellHandle, cookie: &Cookie) -> Vec<Value> {
    for _ in 0..100 {
        let r = rows(cell, cookie);
        if !r.is_empty() && r.iter().all(|e| member(e, "destroyed_epoch").is_some()) {
            return r;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    panic!(
        "R-KY-02: the erasure never completed: {:?}",
        rows(cell, cookie)
    );
}

/// R-KY-02, I-81, ADR-007 (lane L33): on the production cell a replaced
/// display name is an entry of the erasure log, completed by the root
/// epoch whose destruction killed its key. `admin.erasures`, the cell's
/// erasure route and the System page read it, and it survives a restart.
#[test]
fn r_ky_02_i81_production_cell_keeps_an_erasure_log() {
    let world = world();
    let cell = world.cell(0).unwrap();
    let client = AuthClient::new(cell);
    assert!(client.enrol(FIRST_ADMIN).unwrap(), "the first admin enrols");
    let admin = client.admin_session().expect("the admin session");
    assert!(rows(cell, &admin).is_empty(), "no erasure yet");
    set(cell, &admin, OLD);
    set(cell, &admin, NEW);
    let log = completed(cell, &admin);
    assert_eq!(log.len(), 1, "{log:?}");
    let e = &log[0];
    assert_eq!(member(e, "kind"), Some("display_name"));
    assert_eq!(member(e, "cause"), Some("erasure_request"));
    assert!(member(e, "requested_at").is_some());
    assert!(member(e, "completed_at").is_some(), "R-KY-02: completed");
    let epoch = member(e, "destroyed_epoch").unwrap().to_owned();
    // The cell's own route reads the same log: a tenant admin sees it.
    let r = web(cell, "GET", "/api/v1/erasures", &admin, "");
    assert_eq!(r.status, 200, "GET /api/v1/erasures: {}", text(&r));
    let listed = json(&r)
        .get("erasures")
        .and_then(Value::as_array)
        .map_or(0, |a| a.len());
    assert_eq!(listed, 1, "{}", text(&r));
    // The System page's key copy check reads the log.
    let r = web(cell, "GET", "/api/v1/admin/system", &admin, "");
    assert_eq!(r.status, 200, "tenant.system: {}", text(&r));
    assert!(
        json(&r)
            .get("last_cell_erasure")
            .and_then(Value::as_str)
            .is_some(),
        "the System page names the cell erasure: {}",
        text(&r)
    );
    // I-24: the log is the ledger's, so a restart keeps it.
    cell.restart().unwrap_or_else(|e| panic!("{e}"));
    let admin = client
        .login(
            FIRST_ADMIN,
            fstp_celltest::reference::auth::RefMethod::Passkey,
        )
        .unwrap()
        .expect("the admin session");
    let again = rows(cell, &admin);
    assert_eq!(again.len(), 1);
    assert_eq!(member(&again[0], "destroyed_epoch"), Some(epoch.as_str()));
}
