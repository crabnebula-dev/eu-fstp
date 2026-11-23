//! What erases a stored document on the production cell over PostgreSQL
//! (ADR-007 section "Decided by Daniel on 2026-11-23", lane L39; R-KY-02,
//! I-81, I-24, I-97, R-CF-03).
//!
//! A one-cell world mounts the web adapter over the cell's own `ApiCore`.
//! The first admin uploads a synthetic import document. A tenant admin
//! erases it from the erasure page with a reason: no step-up, the log
//! names the cause, the authoriser kind and the reason, the key dies, and
//! the sealed `doc.blob` row is deleted. The retention sweep erases no
//! import document while the SPEC sets no period for it. Every document,
//! reason and id is synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_cell::tasks::retention::{self, DocumentRetention, KIND_IMPORT_DOCUMENT};
use fstp_celltest::mc::auth_model::http::{AuthClient, Cookie, FIRST_ADMIN};
use fstp_celltest::world::{
    CellHandle, DbMode, HttpReply, HttpRequest, VaultLayout, World, WorldSpec,
};
use fstp_json::Value;

/// A synthetic import document. No real data.
const ANNEX: &str = "SYNTHETIC ANNEX L39\n\nThe synthetic programme funds synthetic work.\n";

/// A synthetic reason.
const REASON: &str = "Synthetic reason L39: uploaded to the wrong programme";

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

fn stepped(client: &AuthClient<'_>, path: &str, cookie: &Cookie, body: &str) -> HttpReply {
    let cell = client.cell();
    let first = web(cell, "POST", path, cookie, body);
    let v = json(&first);
    if v.get("code").and_then(Value::as_str) != Some("step_up_required") {
        return first;
    }
    let ch = v.get("challenge").unwrap();
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
    assert!(client.prove_api_step_up(cookie, id, challenge).unwrap());
    web(cell, "POST", path, cookie, body)
}

fn member<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v.get(k).and_then(Value::as_str)
}

/// The `admin.erasures` reply.
fn erasures(cell: &CellHandle, cookie: &Cookie) -> Value {
    let r = web(cell, "GET", "/api/v1/admin/erasures", cookie, "");
    assert_eq!(r.status, 200, "admin.erasures: {}", text(&r));
    assert!(
        !text(&r).contains("SYNTHETIC ANNEX"),
        "a reply names content"
    );
    json(&r)
}

fn list(v: &Value, k: &str) -> Vec<Value> {
    v.get(k)
        .and_then(Value::as_array)
        .map(|a| a.iter().cloned().collect())
        .unwrap_or_default()
}

/// The log once every entry is completed.
fn completed(cell: &CellHandle, cookie: &Cookie) -> Vec<Value> {
    for _ in 0..100 {
        let r = list(&erasures(cell, cookie), "erasures");
        if !r.is_empty() && r.iter().all(|e| member(e, "destroyed_epoch").is_some()) {
            return r;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    panic!("R-KY-02: the erasure never completed");
}

fn blob_rows(world: &World) -> usize {
    world
        .app_superuser_sql(0, "SELECT dek::text FROM doc.blob")
        .unwrap_or_else(|e| panic!("{e}"))
        .lines()
        .filter(|l| !l.trim().is_empty())
        .count()
}

/// The first admin with a programme and one uploaded import document.
fn uploaded(world: &World) -> (AuthClient<'_>, Cookie, String) {
    let cell = world.cell(0).unwrap();
    let client = AuthClient::new(cell);
    assert!(client.enrol(FIRST_ADMIN).unwrap(), "the first admin enrols");
    let admin = client.admin_session().expect("the admin session");
    let opened = stepped(
        &client,
        "/api/v1/programmes",
        &admin,
        r#"{"name":"Synthetic programme"}"#,
    );
    assert_eq!(opened.status, 200, "creator.open_draft: {}", text(&opened));
    let p: String = member(&json(&opened), "programme").unwrap().to_owned();
    let body = format!(
        r#"{{"media":"text/markdown","text":{}}}"#,
        Value::String(ANNEX.to_owned()).to_compact()
    );
    let up = stepped(
        &client,
        &format!("/api/v1/programmes/{p}/imports"),
        &admin,
        &body,
    );
    assert_eq!(up.status, 200, "import.upload: {}", text(&up));
    assert_eq!(blob_rows(world), 1);
    let docs = list(&erasures(cell, &admin), "documents");
    assert_eq!(docs.len(), 1, "{docs:?}");
    assert_eq!(member(&docs[0], "programme"), Some(p.as_str()));
    assert_eq!(member(&docs[0], "media"), Some("text/markdown"));
    assert_eq!(docs[0].get("erased").and_then(Value::as_bool), Some(false));
    let id = member(&docs[0], "document").unwrap().to_owned();
    (client, admin, id)
}

/// ADR-007 (Daniel, 2026-11-23, decisions 1c, 2 and 3; lane L39),
/// R-KY-02, I-81, I-24: a tenant admin erases an import document from the
/// erasure page with a reason and no step-up. A missing reason is
/// refused. The log entry names the document kind, the cause, an account
/// as authoriser (never which one, R-CF-03) and the reason resolved for
/// the admin (I-97). Once the key died the `doc.blob` row is gone, the
/// entry stays, a repeat is a no-op, and a restart keeps both.
#[test]
fn adr007_l39_admin_erases_an_import_document_with_a_reason() {
    let world = world();
    let cell = world.cell(0).unwrap();
    let (client, admin, doc) = uploaded(&world);
    let path = format!("/api/v1/admin/documents/{doc}/erasure");
    let reason = format!(
        r#"{{"reason":{}}}"#,
        Value::String(REASON.to_owned()).to_compact()
    );
    for bad in [r#"{"reason":""}"#, r#"{"reason":"   "}"#, "{}"] {
        let r = web(cell, "POST", &path, &admin, bad);
        assert_eq!(r.status, 400, "{bad}: {}", text(&r));
    }
    assert!(list(&erasures(cell, &admin), "erasures").is_empty());
    let unknown = web(
        cell,
        "POST",
        "/api/v1/admin/documents/12345/erasure",
        &admin,
        &reason,
    );
    assert_ne!(unknown.status, 200, "an unknown document");
    let done = web(cell, "POST", &path, &admin, &reason);
    assert_eq!(done.status, 200, "no step-up: {}", text(&done));
    let rows = completed(cell, &admin);
    assert_eq!(rows.len(), 1, "{rows:?}");
    let e = &rows[0];
    assert_eq!(member(e, "kind"), Some("document"));
    assert_eq!(member(e, "cause"), Some("erasure_request"));
    assert_eq!(member(e, "authoriser"), Some("account"));
    assert_eq!(member(e, "reason"), Some(REASON));
    let epoch = member(e, "destroyed_epoch").unwrap().to_owned();
    // Decision 2: the sealed row is deleted after the key died.
    for _ in 0..100 {
        if blob_rows(&world) == 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert_eq!(blob_rows(&world), 0, "the sealed row is gone");
    let docs = list(&erasures(cell, &admin), "documents");
    assert_eq!(docs[0].get("erased").and_then(Value::as_bool), Some(true));
    // A repeat is a no-op.
    let again = web(cell, "POST", &path, &admin, &reason);
    assert_eq!(again.status, 200, "a repeat: {}", text(&again));
    assert_eq!(list(&erasures(cell, &admin), "erasures").len(), 1);
    // I-24: the entry is the ledger's, so a restart keeps it.
    cell.restart().unwrap_or_else(|e| panic!("{e}"));
    let admin = client
        .login(
            FIRST_ADMIN,
            fstp_celltest::reference::auth::RefMethod::Passkey,
        )
        .unwrap()
        .expect("the admin session");
    let after = list(&erasures(cell, &admin), "erasures");
    assert_eq!(after.len(), 1);
    assert_eq!(member(&after[0], "destroyed_epoch"), Some(epoch.as_str()));
    assert_eq!(member(&after[0], "reason"), Some(REASON));
    assert_eq!(blob_rows(&world), 0, "I-81: still gone");
}

/// ADR-007 (Daniel, 2026-11-23, decisions 1b and 3; lane L39), P-41: the
/// production rule table erases no import document, since the SPEC sets
/// no period for one (`TODO(legal)`). With a synthetic period the same
/// sweep erases it with the cause `retention_expiry` and names the
/// system as authoriser, and its row is deleted once the key died.
#[test]
fn adr007_l39_retention_sweep_erases_no_import_document() {
    let world = world();
    let cell = world.cell(0).unwrap();
    let (_client, admin, _doc) = uploaded(&world);
    let far = i64::MAX / 2;
    let n = cell
        .with_running(async |c| {
            let store = c.api_store().unwrap();
            retention::sweep_once(&store, c.erasure(), retention::rule, far).await
        })
        .unwrap()
        .unwrap();
    assert_eq!(n, 0, "no period, no erasure");
    assert!(list(&erasures(cell, &admin), "erasures").is_empty());
    assert_eq!(blob_rows(&world), 1);
    let synthetic = |kind: i16| {
        if kind == KIND_IMPORT_DOCUMENT {
            DocumentRetention::After { micros: 0 }
        } else {
            retention::rule(kind)
        }
    };
    let n = cell
        .with_running(async |c| {
            let store = c.api_store().unwrap();
            retention::sweep_once(&store, c.erasure(), synthetic, far).await
        })
        .unwrap()
        .unwrap();
    assert_eq!(n, 1);
    let rows = completed(cell, &admin);
    assert_eq!(member(&rows[0], "cause"), Some("retention_expiry"));
    assert_eq!(member(&rows[0], "authoriser"), Some("system"));
    assert_eq!(rows[0].get("reason"), Some(&Value::Null));
    for _ in 0..100 {
        if blob_rows(&world) == 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert_eq!(blob_rows(&world), 0, "the sealed row is gone");
}
