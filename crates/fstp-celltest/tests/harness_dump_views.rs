//! The scanner and the identifier extractor over real logical dumps (M3
//! design sections 14.1, 14.3 and 14.4, lane W1a). Written by the W1a
//! implementer in fix round 2, after review.
//!
//! Each test runs on the `fstp-pgtest` fixture server and reads the stores
//! that `fstp_celltest::world::cluster_stores` gives, the function
//! `World::stores` uses for each cluster. The encoders here are written
//! independently of `fstp_celltest::scan`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_celltest::canary::{Canary, CanaryKind};
use fstp_celltest::scan::{CellDump, PublicConstants, StoreSet, scan, shared_identifiers};
use fstp_celltest::world::cluster_stores;
use fstp_pgtest::PgServer;
use fstp_prop::{Config, Gen, check_with};

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn base64(bytes: &[u8], alphabet: &[u8; 64]) -> String {
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
                out.push(char::from(alphabet[((n >> (18 - 6 * i)) & 0x3f) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn hex(bytes: &[u8], upper: bool) -> String {
    let digits: &[u8; 16] = if upper {
        b"0123456789ABCDEF"
    } else {
        b"0123456789abcdef"
    };
    bytes
        .iter()
        .flat_map(|b| [digits[usize::from(b >> 4)], digits[usize::from(b & 15)]])
        .map(char::from)
        .collect()
}

/// The column type a body is stored in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Column {
    Jsonb,
    Json,
    Text,
    Bytea,
}

/// How a canary body is encoded before it is stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Encoding {
    /// Base64 wrapped at 64 or 76 characters.
    Base64Wrapped,
    /// Base64url without line breaks.
    Base64Url,
    /// Lowercase or uppercase hex.
    Hex,
    /// UTF-16LE. Text columns cannot hold a NUL, so only `bytea` stores
    /// the bytes, and `json` stores them as `\u0000` escapes.
    Utf16le,
}

const COLUMNS: [Column; 4] = [Column::Jsonb, Column::Json, Column::Text, Column::Bytea];

fn encodings_for(column: Column) -> &'static [Encoding] {
    match column {
        Column::Jsonb | Column::Text => {
            &[Encoding::Base64Wrapped, Encoding::Base64Url, Encoding::Hex]
        }
        Column::Json | Column::Bytea => &[
            Encoding::Base64Wrapped,
            Encoding::Base64Url,
            Encoding::Hex,
            Encoding::Utf16le,
        ],
    }
}

fn gen_canary(g: &mut Gen) -> Canary {
    let kinds = CanaryKind::ALL;
    let kind = *g.pick(&kinds);
    let mut nonce = [0u8; 16];
    for b in &mut nonce {
        *b = g.u8();
    }
    Canary {
        cell: g.u8(),
        kind,
        nonce,
    }
}

/// The SQL literal that stores `body` in `column`, over 2 kB and
/// compressible, so PostgreSQL compresses it.
fn value_sql(g: &mut Gen, column: Column, encoding: Encoding, body: &[u8]) -> String {
    let filler = "The applicant attaches the signed letter of support. ".repeat(60);
    // In a JSON string a line break is the escape `\n` (two characters).
    // A text value holds that escape or a real line feed.
    let text_break = *g.pick(&["\\n", "\n"]);
    let encoded = match encoding {
        Encoding::Base64Wrapped => {
            let width = *g.pick(&[64usize, 76]);
            let text = base64(body, B64);
            let brk = match column {
                Column::Bytea => "\r\n",
                Column::Jsonb | Column::Json => "\\n",
                Column::Text => text_break,
            };
            text.as_bytes()
                .chunks(width)
                .map(|l| String::from_utf8(l.to_vec()).unwrap())
                .collect::<Vec<_>>()
                .join(brk)
        }
        Encoding::Base64Url => base64(body, B64URL),
        Encoding::Hex => hex(body, g.bool()),
        Encoding::Utf16le => match column {
            Column::Json => body
                .iter()
                .map(|b| format!("{}\\u0000", char::from(*b)))
                .collect(),
            Column::Bytea | Column::Jsonb | Column::Text => String::new(),
        },
    };
    match column {
        Column::Jsonb | Column::Json => {
            format!("'{{\"note\":\"{filler}\",\"body\":\"{encoded}\"}}'")
        }
        Column::Text => format!("'{filler}{encoded}{filler}'"),
        Column::Bytea => {
            let mut bytes = filler.clone().into_bytes();
            match encoding {
                Encoding::Utf16le => bytes.extend(body.iter().flat_map(|b| [*b, 0])),
                Encoding::Base64Wrapped | Encoding::Base64Url | Encoding::Hex => {
                    bytes.extend_from_slice(encoded.as_bytes());
                }
            }
            bytes.extend_from_slice(filler.as_bytes());
            format!("decode('{}', 'hex')", hex(&bytes, false))
        }
    }
}

fn column_sql(column: Column) -> &'static str {
    match column {
        Column::Jsonb => "jsonb",
        Column::Json => "json",
        Column::Text => "text",
        Column::Bytea => "bytea",
    }
}

/// The stores of the fixture cluster named exactly `name`.
fn store_named(server: &PgServer, name: &str) -> StoreSet {
    let all = cluster_stores("fixture", server).unwrap();
    StoreSet {
        stores: all.stores.into_iter().filter(|(n, _)| n == name).collect(),
    }
}

/// Design sections 14.1 and 14.3: a canary body in base64 (wrapped, with
/// JSON `\n` escapes or real line breaks), base64url, hex or UTF-16LE,
/// stored compressed in a `jsonb`, `json`, `text` or `bytea` column, is
/// found in the database's logical dump store.
fn finds_encoded_bodies_in_compressed_columns(g: &mut Gen) -> Result<(), String> {
    let server = PgServer::shared().map_err(|e| e.to_string())?;
    let canary = gen_canary(g);
    let column = *g.pick(&COLUMNS);
    let encoding = *g.pick(encodings_for(column));
    let mut body = b"synthetic attachment header ".to_vec();
    body.extend((0..g.usize_in(0..=2)).map(|_| b'x'));
    body.extend_from_slice(canary.text().as_bytes());
    body.extend_from_slice(b" synthetic attachment trailer");
    let value = value_sql(g, column, encoding, &body);
    g.note("case", &(column, encoding));
    let db = server.fresh_database().map_err(|e| e.to_string())?;
    server
        .psql(
            &db.dbname,
            &format!(
                "CREATE TABLE attachment (v {});\n\
                 INSERT INTO attachment VALUES ({value});",
                column_sql(column)
            ),
        )
        .map_err(|e| e.to_string())?;
    let method = server
        .psql(
            &db.dbname,
            "SELECT pg_column_compression(v) FROM attachment",
        )
        .map_err(|e| e.to_string())?;
    if method != "pglz" {
        return Err(format!("the value is not compressed ({method:?})"));
    }
    // The dump store `cluster_stores` adds for this database. Building the
    // whole cluster store set per case would read every other database too.
    let mut stores = StoreSet::default();
    stores.push(
        format!("fixture/dump/{}", db.dbname),
        server.dump_data(&db.dbname).map_err(|e| e.to_string())?,
    );
    let report = scan(&stores, std::slice::from_ref(&canary)).map_err(|e| format!("{e:?}"))?;
    if report.is_clean() {
        Err(format!(
            "missed a {encoding:?} body in a compressed {column:?} value"
        ))
    } else {
        Ok(())
    }
}

/// I-17, I-19 instrument, design sections 14.1 and 14.3. A compressed value
/// is visible whole only in the logical dump, whose COPY format escapes
/// each backslash again and writes `bytea` as hex.
#[test]
fn harness_dump_i17_i19_finds_encoded_bodies_in_compressed_columns() {
    check_with(
        "harness_dump_i17_i19_finds_encoded_bodies_in_compressed_columns",
        Config::default().with_cases(16).with_env(),
        finds_encoded_bodies_in_compressed_columns,
    );
}

/// The oid of database `dbname`.
fn oid_of(server: &PgServer, dbname: &str) -> String {
    server
        .psql(
            "postgres",
            &format!("SELECT oid FROM pg_database WHERE datname = '{dbname}'"),
        )
        .unwrap()
}

/// The schema both cells and both baseline cells get, and one row with
/// random keys and a constant state when `row` holds.
fn cell_database(server: &PgServer, row: bool) -> String {
    let db = server.fresh_database().unwrap();
    let insert = if row {
        "INSERT INTO account_lookup_digest_by_email VALUES \
         (decode(md5(random()::text) || md5(random()::text), 'hex'), \
          encode(decode(md5(random()::text), 'hex'), 'base64'), \
          'committee_member_role_grant_pending');"
    } else {
        ""
    };
    server
        .psql(
            &db.dbname,
            &format!(
                "CREATE TABLE account_lookup_digest_by_email \
                 (digest bytea, token text, state text);\n{insert}"
            ),
        )
        .unwrap();
    db.dbname
}

/// The stores of database `name` alone in `all`: its relation files when
/// `raw` holds, and its dump.
fn database_stores(server: &PgServer, all: &StoreSet, name: &str, raw: bool) -> StoreSet {
    let base = format!("fixture/data/base/{}/", oid_of(server, name));
    let dump = format!("fixture/dump/{name}");
    StoreSet {
        stores: all
            .stores
            .iter()
            .filter(|(n, _)| *n == dump || (raw && n.starts_with(&base)))
            .cloned()
            .collect(),
    }
}

/// I-20 control, design section 14.4: two cell databases with the same
/// schema, the same constant state and different random keys share no
/// identifier. Their dumps share none with no allow list. Their relation
/// files, which each hold a copy of the system catalogs, share none
/// beyond the baseline of two fresh cells with the same schema. The teeth
/// twin below stores one key in both and must find it.
#[test]
fn harness_dump_i20_control_distinct_cells_share_no_identifier() {
    let server = PgServer::shared().unwrap();
    let cells = [cell_database(server, true), cell_database(server, true)];
    let fresh = [cell_database(server, false), cell_database(server, false)];
    let all = cluster_stores("fixture", server).unwrap();
    let dump =
        |name: &str, raw: bool| CellDump::from_stores(&database_stores(server, &all, name, raw));
    let shown = |ids: &std::collections::BTreeSet<Vec<u8>>| -> Vec<String> {
        ids.iter()
            .map(|id| String::from_utf8_lossy(id).into_owned())
            .collect()
    };
    let (a, b) = (dump(&cells[0], false), dump(&cells[1], false));
    let in_dumps = shared_identifiers(&a, &b, &PublicConstants::default()).unwrap();
    let baseline = PublicConstants::baseline(&dump(&fresh[0], true), &dump(&fresh[1], true));
    let (ra, rb) = (dump(&cells[0], true), dump(&cells[1], true));
    let in_files = shared_identifiers(&ra, &rb, &baseline).unwrap();
    assert_eq!(
        (
            a.identifiers.is_empty() || b.identifiers.is_empty(),
            shown(&in_dumps),
            shown(&in_files)
        ),
        (false, Vec::<String>::new(), Vec::<String>::new())
    );
}

/// I-20 teeth, design section 14.4: one random key stored as `bytea` in
/// one cell's dump and as base64 text in another's is a shared identifier.
#[test]
fn harness_dump_i20_teeth_shared_key_across_dumps_is_caught() {
    let server = PgServer::shared().unwrap();
    let key: Vec<u8> = (0u8..32)
        .map(|i| i.wrapping_mul(37).wrapping_add(11))
        .collect();
    let (da, db) = (
        server.fresh_database().unwrap(),
        server.fresh_database().unwrap(),
    );
    server
        .psql(
            &da.dbname,
            &format!(
                "CREATE TABLE k (v bytea);\nINSERT INTO k VALUES (decode('{}', 'hex'));",
                hex(&key, false)
            ),
        )
        .unwrap();
    server
        .psql(
            &db.dbname,
            &format!(
                "CREATE TABLE k (v jsonb);\nINSERT INTO k VALUES ('{{\"k\":\"{}\"}}');",
                base64(&key, B64)
            ),
        )
        .unwrap();
    let all = cluster_stores("fixture", server).unwrap();
    let dump = |name: &str| StoreSet {
        stores: all
            .stores
            .iter()
            .filter(|(n, _)| *n == format!("fixture/dump/{name}"))
            .cloned()
            .collect(),
    };
    let shared = shared_identifiers(
        &CellDump::from_stores(&dump(&da.dbname)),
        &CellDump::from_stores(&dump(&db.dbname)),
        &PublicConstants::default(),
    )
    .unwrap();
    assert!(shared.contains(&key), "{shared:?}");
}

/// Design section 14.3: a canary in a populated materialized view is in
/// the database's dump store, although `pg_dump --data-only` leaves view
/// contents out. A view created `WITH NO DATA` does not stop the dump.
#[test]
fn harness_dump_i19_includes_materialized_view_rows() {
    let server = PgServer::shared().unwrap();
    let canary = Canary::generate(2, CanaryKind::Name).unwrap();
    let db = server.fresh_database().unwrap();
    server
        .psql(
            &db.dbname,
            &format!(
                "CREATE MATERIALIZED VIEW digest AS SELECT '{}'::text AS v;\n\
                 CREATE MATERIALIZED VIEW later AS SELECT 1 AS n WITH NO DATA;",
                canary.text()
            ),
        )
        .unwrap();
    let stores = store_named(server, &format!("fixture/dump/{}", db.dbname));
    let report = scan(&stores, std::slice::from_ref(&canary)).unwrap();
    assert_eq!(report.hits.len(), 1, "{:?}", report.hits);
}
