//! SA-11 and its amendment on the production cell over PostgreSQL (ADR-004
//! section "Written by lane L26", I-27, P-11, R-CR-01). Lane L26.
//!
//! A one-cell world mounts the web adapter over the cell's own `ApiCore`.
//! The first admin and a second account set display names through
//! `/api/v1/me/display-name`. A name another account holds, in any case,
//! spacing or look-alike spelling, is refused under `SA-11-unique`, and
//! the reply names no account. A replaced name is free at once. The names
//! are sealed at rest, read back on the account page, and survive a
//! restart. The member page answers a tenant admin only. Every name is synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_celltest::mc::auth_model::http::{AuthClient, Cookie, FIRST_ADMIN};
use fstp_celltest::reference::auth::RefMethod;
use fstp_celltest::world::{
    CellHandle, DbMode, HttpReply, HttpRequest, VaultLayout, World, WorldSpec,
};
use fstp_domain::id::AccountId;
use fstp_json::Value;

/// The model id of the second account, apart from every other test's.
const MEMBER: AccountId = AccountId::from_raw(26_001);

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

/// `me.set_display_name` with `name`.
fn set(cell: &CellHandle, cookie: &Cookie, name: &str) -> HttpReply {
    let body = format!(
        r#"{{"display_name":{}}}"#,
        Value::String(name.to_owned()).to_compact()
    );
    web(cell, "POST", "/api/v1/me/display-name", cookie, &body)
}

/// `me.display_name`: the caller's own name.
fn own(cell: &CellHandle, cookie: &Cookie) -> Option<String> {
    let r = web(cell, "GET", "/api/v1/me/display-name", cookie, "");
    assert_eq!(r.status, 200, "me.display_name: {}", text(&r));
    json(&r)
        .get("display_name")
        .and_then(Value::as_str)
        .map(str::to_owned)
}

/// The rows of `sql` as the superuser reads them, one value a line.
fn rows(world: &World, sql: &str) -> Vec<String> {
    world
        .app_superuser_sql(0, sql)
        .unwrap_or_else(|e| panic!("{sql}: {e}"))
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// SA-11, SA-11 amendment, ADR-004 (lane L26), R-CR-01, I-23: on the
/// production cell `me.set_display_name` succeeds, a name another account
/// holds is refused under `SA-11-unique` in any case, spacing or
/// look-alike spelling, a replaced name is free at once, the names are
/// sealed at rest, and they survive a restart.
#[test]
fn sa11_production_cell_sets_unique_display_names() {
    let world = world();
    let cell = world.cell(0).unwrap();
    let client = AuthClient::new(cell);
    assert!(client.enrol(FIRST_ADMIN).unwrap(), "the first admin enrols");
    assert!(client.enrol(MEMBER).unwrap(), "the second account enrols");
    let admin = client.admin_session().expect("the admin session");
    let member = client
        .login(MEMBER, RefMethod::Passkey)
        .unwrap()
        .expect("the second account's session");

    let r = set(cell, &admin, "Synthetic Admin Name");
    assert_eq!(r.status, 200, "SA-11: me.set_display_name: {}", text(&r));
    assert_eq!(own(cell, &admin).as_deref(), Some("Synthetic Admin Name"));

    for taken in [
        "Synthetic Admin Name",
        "synthetic  ADMIN name",
        "Synthetic Ad\u{200d}min Name",
    ] {
        let r = set(cell, &member, taken);
        assert_ne!(r.status, 200, "SA-11 amendment: {taken:?} was set");
        let body = text(&r);
        assert!(body.contains("SA-11-unique"), "the rule: {body}");
        assert!(!body.contains("Synthetic Admin"), "the reply names a name");
    }
    assert_eq!(own(cell, &member), None);
    let r = set(cell, &member, "Synthetic Member Name");
    assert_eq!(r.status, 200, "{}", text(&r));

    // A replaced name is free at once.
    let r = set(cell, &admin, "Synthetic Admin Renamed");
    assert_eq!(r.status, 200, "{}", text(&r));
    let r = set(cell, &member, "synthetic admin name");
    assert_eq!(r.status, 200, "the replaced name is free: {}", text(&r));
    assert_eq!(own(cell, &member).as_deref(), Some("synthetic admin name"));

    // The member page answers a tenant admin and no one else (SA-11,
    // I-17). These accounts hold no role, so it lists none of them.
    let r = web(cell, "GET", "/api/v1/admin/members", &admin, "");
    assert_eq!(r.status, 200, "admin.members: {}", text(&r));
    let r = web(cell, "GET", "/api/v1/admin/members", &member, "");
    assert_ne!(r.status, 200, "admin.members by a member");
    assert!(
        !text(&r).contains("Synthetic Admin"),
        "a refusal shows a name"
    );

    // R-CR-01: two index rows, and no name in clear in a keystore row.
    let n = rows(&world, "SELECT count(*) FROM keystore.display_name");
    assert_eq!(n, vec!["2".to_owned()], "keystore.display_name");
    let sealed = rows(
        &world,
        "SELECT encode(envelope, 'hex') FROM keystore.text \
         UNION ALL SELECT encode(fingerprint, 'hex') FROM keystore.display_name",
    )
    .join("\n");
    for name in [
        "Synthetic Admin Renamed",
        "synthetic admin name",
        "Synthetic Member",
    ] {
        assert!(
            !sealed.contains(&hex(name.as_bytes())),
            "R-CR-01: {name} in clear"
        );
    }

    // I-23: the names and their uniqueness survive a restart.
    cell.restart().unwrap_or_else(|e| panic!("{e}"));
    let admin = client.admin_session().expect("the admin session");
    let member = client
        .login(MEMBER, RefMethod::Passkey)
        .unwrap()
        .expect("the second account's session");
    assert_eq!(
        own(cell, &admin).as_deref(),
        Some("Synthetic Admin Renamed")
    );
    assert_eq!(own(cell, &member).as_deref(), Some("synthetic admin name"));
    let r = set(cell, &member, "SYNTHETIC ADMIN RENAMED");
    assert!(text(&r).contains("SA-11-unique"), "{}", text(&r));
    // A clear answers and frees the name.
    let r = web(
        cell,
        "POST",
        "/api/v1/me/display-name",
        &admin,
        r#"{"display_name":null}"#,
    );
    assert_eq!(r.status, 200, "{}", text(&r));
    assert_eq!(own(cell, &admin), None);
    let r = set(cell, &member, "Synthetic Admin Renamed");
    assert_eq!(r.status, 200, "{}", text(&r));
}
