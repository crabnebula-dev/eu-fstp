//! Document erasures in the production cell's erasure log over PostgreSQL
//! (ADR-007 section "Built by lane L37", R-KY-02, I-81, I-24). Lane L37.
//!
//! A one-cell world mounts the web adapter over the cell's own `ApiCore`.
//! The first admin uploads a synthetic import document. The erasure task
//! then erases it by its data key id. The document opens no more, and
//! `admin.erasures` lists an entry of the document kind, completed by the
//! root epoch whose destruction killed its key. The entry survives a
//! restart. Every document and id is synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_celltest::mc::auth_model::http::{AuthClient, Cookie, FIRST_ADMIN};
use fstp_celltest::world::{
    CellHandle, DbMode, HttpReply, HttpRequest, VaultLayout, World, WorldSpec,
};
use fstp_domain::id::AccountId;
use fstp_json::Value;

/// A synthetic import document. No real data.
const ANNEX: &str = "SYNTHETIC ANNEX L37\n\nThe synthetic programme funds synthetic work.\n";

/// The synthetic authoriser the erasure names.
const BY: AccountId = AccountId::from_raw(0x0137_0001);

/// The closed code of an erasure request (ADR-007 causes).
const ERASURE_REQUEST: u16 = 2;

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

fn unhex(h: &str) -> Vec<u8> {
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
        .collect()
}

/// The `admin.erasures` rows.
fn log(cell: &CellHandle, cookie: &Cookie) -> Vec<Value> {
    let r = web(cell, "GET", "/api/v1/admin/erasures", cookie, "");
    assert_eq!(r.status, 200, "admin.erasures: {}", text(&r));
    assert!(
        !text(&r).contains("SYNTHETIC ANNEX"),
        "a reply names content"
    );
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
        let r = log(cell, cookie);
        if !r.is_empty() && r.iter().all(|e| member(e, "destroyed_epoch").is_some()) {
            return r;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    panic!(
        "R-KY-02: the erasure never completed: {:?}",
        log(cell, cookie)
    );
}

/// Whether the stored document of data key `dek` still opens.
fn opens(cell: &CellHandle, dek: [u8; 16], envelope: &[u8]) -> bool {
    cell.with_running(async |c| {
        c.erasure()
            .open_document(dek, envelope.to_vec())
            .await
            .is_ok()
    })
    .unwrap()
}

/// R-KY-02, I-81, ADR-007 (lane L37): on the production cell a document
/// erasure is an entry of the erasure log of its own kind, named by the
/// document's data key id. The document opens no more, the entry is
/// completed by the root epoch whose destruction killed its key, a second
/// request adds nothing, and a restart keeps the entry (I-24).
#[test]
fn r_ky_02_i81_production_cell_logs_a_document_erasure() {
    let world = world();
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
    let p: u128 = json(&opened)
        .get("programme")
        .and_then(Value::as_str)
        .and_then(|s| s.parse().ok())
        .unwrap();
    let path = format!("/api/v1/programmes/{p}/imports");
    let body = format!(
        r#"{{"media":"text/markdown","text":{}}}"#,
        Value::String(ANNEX.to_owned()).to_compact()
    );
    let up = stepped(&client, &path, &admin, &body);
    assert_eq!(up.status, 200, "import.upload: {}", text(&up));
    let got = world
        .app_superuser_sql(
            0,
            "SELECT dek::text || ':' || encode(envelope, 'hex') FROM doc.blob",
        )
        .unwrap_or_else(|e| panic!("{e}"));
    let got: Vec<&str> = got
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    assert_eq!(got.len(), 1, "one blob row: {got:?}");
    let (dek, envelope) = got[0].split_once(':').unwrap();
    let dek: [u8; 16] = unhex(&dek.replace('-', "")).try_into().unwrap();
    let envelope = unhex(envelope);
    assert!(opens(cell, dek, &envelope), "the document opens before");
    assert!(log(cell, &admin).is_empty(), "no erasure yet");

    let erase = || {
        cell.with_running(async |c| c.erasure().erase_document(dek, ERASURE_REQUEST, BY, None).await)
            .unwrap()
    };
    erase().unwrap_or_else(|e| panic!("the document erasure: {e}"));
    assert!(
        !opens(cell, dek, &envelope),
        "I-81: the document opens from the request on"
    );
    let rows = completed(cell, &admin);
    assert_eq!(rows.len(), 1, "{rows:?}");
    let e = &rows[0];
    assert_eq!(member(e, "kind"), Some("document"));
    assert_eq!(member(e, "cause"), Some("erasure_request"));
    let id = u128::from_be_bytes(dek).to_string();
    assert_eq!(member(e, "text"), Some(id.as_str()), "named by its key id");
    assert!(member(e, "completed_at").is_some(), "R-KY-02: completed");
    let epoch = member(e, "destroyed_epoch").unwrap().to_owned();
    // A second request adds nothing.
    erase().unwrap_or_else(|e| panic!("a repeated request: {e}"));
    assert_eq!(log(cell, &admin).len(), 1, "one entry per document");
    // A text id is no document.
    let wrong = cell
        .with_running(async |c| {
            c.erasure()
                .erase_document([0x37; 16], ERASURE_REQUEST, BY, None)
                .await
        })
        .unwrap();
    assert!(wrong.is_err(), "an unknown document");
    // An import is stored after a fresh salt, so the same document can be
    // uploaded again, as a new blob under a new key.
    let again = stepped(&client, &path, &admin, &body);
    assert_eq!(again.status, 200, "import.upload again: {}", text(&again));
    // ADR-007 (Daniel, 2026-11-23, decision 2; lane L39): the erased
    // document's sealed row is deleted once its key died, so only the new
    // one is left.
    let deks = || {
        world
            .app_superuser_sql(0, "SELECT replace(dek::text, '-', '') FROM doc.blob")
            .unwrap_or_else(|e| panic!("{e}"))
            .lines()
            .map(|l| l.trim().to_owned())
            .filter(|l| !l.is_empty())
            .collect::<Vec<_>>()
    };
    for _ in 0..100 {
        if deks().len() == 1 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let left = deks();
    assert_eq!(left.len(), 1, "{left:?}");
    let erased: String = dek.iter().map(|b| format!("{b:02x}")).collect();
    assert_ne!(left[0], erased, "the erased row is gone");
    // I-24: the entry is the ledger's, so a restart keeps it.
    cell.restart().unwrap_or_else(|e| panic!("{e}"));
    let admin = client
        .login(
            FIRST_ADMIN,
            fstp_celltest::reference::auth::RefMethod::Passkey,
        )
        .unwrap()
        .expect("the admin session");
    let again = log(cell, &admin);
    assert_eq!(again.len(), 1);
    assert_eq!(member(&again[0], "kind"), Some("document"));
    assert_eq!(member(&again[0], "destroyed_epoch"), Some(epoch.as_str()));
    assert!(!opens(cell, dek, &envelope), "I-81: still erased");
}
