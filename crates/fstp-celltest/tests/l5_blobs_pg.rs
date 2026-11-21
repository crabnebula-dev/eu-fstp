//! The production cell's blob store over PostgreSQL (ADR-026 record of
//! lane L5, R-PG-02, R-CR-01, I-30, ADR-004 "Application sealed values").
//!
//! A one-cell world mounts the web adapter over the cell's own `ApiCore`.
//! The first admin opens a draft and uploads a synthetic import document
//! through `/api/v1`. The blob store keeps it in `doc.blob` under the
//! SHA-256 of its stored bytes, sealed under a data key of its own. After
//! a restart the same row opens, through the cell's keystore, to the
//! uploaded bytes with their owner.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_celltest::mc::auth_model::http::{AuthClient, Cookie, FIRST_ADMIN};
use fstp_celltest::world::{
    CellHandle, DbMode, HttpReply, HttpRequest, VaultLayout, World, WorldSpec,
};
use fstp_json::Value;

/// A synthetic import document. No real data.
const ANNEX: &str = "SYNTHETIC ANNEX L5\n\nThe synthetic programme funds synthetic work.\n";

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

fn unhex(h: &str) -> Vec<u8> {
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
        .collect()
}

/// R-PG-02, R-CR-01, I-30: an upload through `/api/v1` stores one
/// `doc.blob` row of kind 5. Its envelope is a sealed blob of
/// `fstp_keys::envelope` (`FSB1`, nonce at offset 7) that holds no byte of
/// the document in clear, and its digest is the SHA-256 of the stored
/// bytes. After a restart the row opens through the cell's keystore to
/// the document of its programme, so the blob round-trips.
#[test]
fn r_cr_01_blob_round_trips_and_is_sealed_at_rest() {
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
    let got = rows(
        &world,
        "SELECT encode(digest, 'hex') || ':' || kind || ':' || dek::text \
         || ':' || encode(envelope, 'hex') FROM doc.blob",
    );
    assert_eq!(got.len(), 1, "R-PG-02: one blob row: {got:?}");
    let parts: Vec<&str> = got[0].split(':').collect();
    assert_eq!(parts[1], "5", "the kind of an import document");
    let digest: [u8; 32] = unhex(parts[0]).try_into().unwrap();
    let dek: [u8; 16] = unhex(&parts[2].replace('-', "")).try_into().unwrap();
    let envelope = unhex(parts[3]);
    assert!(
        envelope.starts_with(b"FSB1\x01"),
        "R-CR-01: not a sealed blob"
    );
    for needle in [
        ANNEX.as_bytes(),
        b"SYNTHETIC ANNEX".as_slice(),
        b"synthetic work",
    ] {
        assert!(
            !envelope.windows(needle.len()).any(|w| w == needle),
            "R-CR-01: the document in clear at rest"
        );
    }
    cell.restart().unwrap_or_else(|e| panic!("{e}"));
    let plain = cell
        .with_running(async |c| {
            let (stored_dek, stored) = c
                .api_store()
                .unwrap()
                .document(digest)
                .await
                .unwrap()
                .expect("I-23: the blob row after a restart");
            assert_eq!(stored_dek, dek);
            c.erasure()
                .open_document(dek, stored)
                .await
                .map(|p| p.to_vec())
                .unwrap_or_else(|e| panic!("the blob does not open: {e:?}"))
        })
        .unwrap();
    let mut owner = b"fstpblb1\x01".to_vec();
    owner.extend_from_slice(&p.to_be_bytes());
    assert!(plain.starts_with(&owner), "the blob's owner");
    let stored = &plain[owner.len()..];
    assert_eq!(fstp_crypto::sha256(stored), digest, "I-30: its address");
    let s = String::from_utf8_lossy(stored);
    assert!(s.contains("SYNTHETIC ANNEX L5"), "the round trip: {s}");
}
