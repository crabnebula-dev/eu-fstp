//! Review reproducers, round 2 (design sections 14.1, 14.3 and 14.4).
//! Written by the independent adversarial reviewer. Each test runs on the
//! `fstp-pgtest` fixture server, which needs no minted certificate, and
//! goes through `fstp_celltest::world::cluster_stores`, the function
//! `World::stores` uses for each cluster.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_celltest::canary::{Canary, CanaryKind};
use fstp_celltest::scan::{CellDump, PublicConstants, StoreSet, scan, shared_identifiers};
use fstp_celltest::world::cluster_stores;

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64(bytes: &[u8]) -> String {
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(B64[((n >> (18 - 6 * i)) & 0x3f) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// The stores of the fixture cluster whose names start with `prefix`.
fn stores_named(prefix: &str) -> StoreSet {
    let server = fstp_pgtest::PgServer::shared().unwrap();
    let all = cluster_stores("fixture", server).unwrap();
    StoreSet {
        stores: all
            .stores
            .into_iter()
            .filter(|(name, _)| name.starts_with(prefix))
            .collect(),
    }
}

/// Design sections 14.1 and 14.3. A long `jsonb` document holds a PEM-like
/// base64 body, wrapped at 64 characters. The JSON text carries each line
/// break as the escape `\n`. PostgreSQL compresses the value, so only the
/// logical dump shows it. COPY text format then escapes the backslash
/// again, so the dump holds `\\n`. One JSON unescape leaves a literal
/// `\n` between the base64 lines, and the canary is never found.
#[test]
fn review_dump_finds_wrapped_base64_in_a_compressed_jsonb_value() {
    let server = fstp_pgtest::PgServer::shared().unwrap();
    let db = server.fresh_database().unwrap();
    let canary = Canary::generate(1, CanaryKind::Document).unwrap();
    let mut body = b"synthetic attachment header bytes 0123456789 ".to_vec();
    body.extend_from_slice(canary.text().as_bytes());
    body.extend_from_slice(b" synthetic attachment trailer bytes");
    let encoded = base64(&body);
    let wrapped: Vec<String> = encoded
        .as_bytes()
        .chunks(64)
        .map(|l| String::from_utf8(l.to_vec()).unwrap())
        .collect();
    // The JSON text: each line break is the two characters `\n`.
    let pem = wrapped.join("\\n");
    let filler = "The applicant attaches the signed letter of support. ".repeat(80);
    server
        .psql(
            &db.dbname,
            &format!(
                "CREATE TABLE attachment (doc jsonb);\n\
                 INSERT INTO attachment VALUES \
                 ('{{\"note\":\"{filler}\",\"body\":\"{pem}\"}}');\n\
                 CHECKPOINT;"
            ),
        )
        .unwrap();
    // Control: the value is stored compressed, so the raw files cannot
    // show it, and the jsonb text holds the base64 lines.
    let method = server
        .psql(
            &db.dbname,
            "SELECT pg_column_compression(doc) FROM attachment",
        )
        .unwrap();
    assert_eq!(method, "pglz");
    let stores = stores_named(&format!("fixture/dump/{}", db.dbname));
    assert_eq!(stores.stores.len(), 1, "no dump store for the database");
    let report = scan(&stores, std::slice::from_ref(&canary)).unwrap();
    assert!(
        !report.is_clean(),
        "wrapped base64 inside a compressed jsonb value is missed in the dump"
    );
}

/// Design section 14.4, I-20 control on real stores. Two cell databases
/// with the same schema and different random digests share no identifier.
/// `CellDump::from_stores` reads every base64url-alphabet run of 22 or
/// more characters as an identifier. Every dump holds the same SQL
/// preamble (`standard_conforming_strings`, `idle_in_transaction_session_timeout`)
/// and the same table and column names. Those runs decode to equal byte
/// strings in both cells, so `shared_identifiers` is never empty and an
/// I-20 test cannot pass on a correct cell.
#[test]
fn review_cell_dumps_of_distinct_cells_share_no_identifier() {
    let server = fstp_pgtest::PgServer::shared().unwrap();
    let mut names = Vec::new();
    for _ in 0..2 {
        let db = server.fresh_database().unwrap();
        server
            .psql(
                &db.dbname,
                "CREATE TABLE account_lookup_digest_by_email (digest bytea);\n\
                 INSERT INTO account_lookup_digest_by_email \
                 VALUES (decode(md5(random()::text) || md5(random()::text), 'hex'));",
            )
            .unwrap();
        names.push(db.dbname);
    }
    let a = CellDump::from_stores(&stores_named(&format!("fixture/dump/{}", names[0])));
    let b = CellDump::from_stores(&stores_named(&format!("fixture/dump/{}", names[1])));
    assert!(!a.identifiers.is_empty() && !b.identifiers.is_empty());
    let shared = shared_identifiers(&a, &b, &PublicConstants::default()).unwrap();
    let shown: Vec<String> = shared
        .iter()
        .map(|id| String::from_utf8_lossy(id).into_owned())
        .collect();
    assert!(
        shared.is_empty(),
        "two distinct cells share {} identifiers: {shown:?}",
        shared.len()
    );
}
