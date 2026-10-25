//! The configurable ledger schema (P4) without a server.
//!
//! - Hostile schema names, with quotes, semicolons and other SQL syntax,
//!   are rejected by validation before any SQL runs.
//! - A valid name reaches the server only as a bind parameter. It never
//!   appears in SQL text.
//! - Validation agrees with a reference model on generated names.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use fstp_migrate::{
    Database, Error, LedgerSchema, LedgerSchemaError, MAX_LEDGER_SCHEMA_LEN, Migration,
    MigrationSet,
};
use fstp_pgwire::{Row, ToSql, TransactionStatus, Type};
use fstp_prop::{Config, Gen, check_with, prop_assert, prop_assert_eq};

const LIST: &[Migration] = &[Migration::new(1, "create_t", "CREATE TABLE t (id int)")];

/// One statement the runner sent: its SQL text and the parameters that
/// encode as `text`.
#[derive(Debug)]
struct Sent {
    sql: &'static str,
    text_params: Vec<String>,
}

/// A [`Database`] that records every statement and answers with no rows.
#[derive(Default)]
struct Recorder {
    sent: Vec<Sent>,
}

impl Recorder {
    fn record(&mut self, sql: &'static str, params: &[&(dyn ToSql + Sync)]) {
        let text_params = params
            .iter()
            .filter(|p| p.accepts(Type::TEXT))
            .map(|p| {
                let mut out = Vec::new();
                p.to_sql(Type::TEXT, &mut out).unwrap();
                String::from_utf8(out).unwrap()
            })
            .collect();
        self.sent.push(Sent { sql, text_params });
    }
}

impl Database for Recorder {
    fn execute(
        &mut self,
        sql: &'static str,
        params: &[&(dyn ToSql + Sync)],
    ) -> impl Future<Output = Result<u64, fstp_pgwire::Error>> + Send {
        self.record(sql, params);
        std::future::ready(Ok(0))
    }

    fn query(
        &mut self,
        sql: &'static str,
        params: &[&(dyn ToSql + Sync)],
    ) -> impl Future<Output = Result<Vec<Row>, fstp_pgwire::Error>> + Send {
        self.record(sql, params);
        std::future::ready(Ok(Vec::new()))
    }

    fn transaction_status(&self) -> TransactionStatus {
        TransactionStatus::Idle
    }

    fn parameter(&self, name: &str) -> Option<&str> {
        (name == "standard_conforming_strings").then_some("on")
    }
}

/// Drives a future whose every await is ready at once.
fn run_ready<F: Future>(f: F) -> F::Output {
    let mut f = pin!(f);
    match f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(out) => out,
        Poll::Pending => panic!("the recorder never blocks"),
    }
}

/// P4 (revised): schema names that carry quotes, semicolons, comments,
/// other SQL syntax, upper case, or reserved prefixes are rejected by
/// validation. A [`MigrationSet`] therefore cannot hold one, and no SQL
/// runs. The error never echoes the name.
#[test]
fn p4_hostile_ledger_schema_names_are_rejected_before_any_sql() {
    let long = "a".repeat(MAX_LEDGER_SCHEMA_LEN + 1);
    let hostile: &[&str] = &[
        "x\"; DROP SCHEMA public CASCADE; --",
        "x\"\"y",
        "x'; DROP TABLE accounts; --",
        "x; DROP SCHEMA public CASCADE",
        "fstp_migrate;",
        "fstp_migrate\"",
        "\"fstp_migrate\"",
        "a$$b",
        "a$1",
        "a%Ib",
        "a--b",
        "a/*b*/",
        "a\nb",
        "a\0b",
        "a b",
        "a.b",
        "public.x",
        "Fstp_Migrate",
        "\u{ff46}stp",
        "1abc",
        "",
        long.as_str(),
        "pg_temp",
        "pg_catalog",
        "pg_toast",
        "information_schema",
    ];
    let base = MigrationSet::new(LIST).unwrap();
    let mut db = Recorder::default();
    for name in hostile {
        match LedgerSchema::new(name) {
            Ok(schema) => {
                let set = base.clone().with_ledger_schema(schema);
                let _ = run_ready(set.apply(&mut db));
                panic!("{name:?} was accepted");
            }
            Err(e) => {
                let syntax = name
                    .bytes()
                    .any(|b| !b.is_ascii_alphanumeric() && b != b'_');
                if name.len() > 3 && syntax {
                    assert!(!e.to_string().contains(name), "{name:?}: {e}");
                }
            }
        }
    }
    assert!(db.sent.is_empty(), "{:?}", db.sent);
}

/// P4 (revised): a valid ledger schema name travels only as a bind
/// parameter. No statement of `verify` or `apply` holds it, or any
/// schema name, in its SQL text.
#[test]
fn p4_schema_name_is_only_a_bind_parameter() {
    let name = "zz_ledger_marker";
    let set = MigrationSet::new(LIST)
        .unwrap()
        .with_ledger_schema(LedgerSchema::new(name).unwrap());
    let mut db = Recorder::default();
    let status = run_ready(set.verify(&mut db)).unwrap();
    assert!(!status.ledger_exists);
    // The recorder returns no rows, so apply stops at the first query that
    // needs one. By then it has probed, created and read the ledger.
    let err = run_ready(set.apply(&mut db)).unwrap_err();
    assert!(matches!(err, Error::NoRow { .. }), "{err}");

    assert!(db.sent.len() > 10, "{:?}", db.sent);
    for sent in &db.sent {
        assert!(!sent.sql.contains(name), "{}", sent.sql);
        assert!(!sent.sql.contains("fstp_migrate"), "{}", sent.sql);
    }
    let with_name: Vec<&str> = db
        .sent
        .iter()
        .filter(|s| s.text_params.iter().any(|p| p == name))
        .map(|s| s.sql)
        .collect();
    // verify probes once; apply probes, sets the schema for the two
    // CREATE blocks, and sets it again to read the ledger.
    assert_eq!(with_name.len(), 5, "{with_name:#?}");
    let blocks = db.sent.iter().filter(|s| s.sql.starts_with("DO ")).count();
    assert_eq!(blocks, 3, "{:#?}", db.sent);
    // Each DO block follows the statement that sets its schema.
    for pair in db.sent.windows(2) {
        if pair[1].sql.starts_with("DO ") {
            assert!(
                pair[0].text_params.iter().any(|p| p == name),
                "{}",
                pair[0].sql
            );
        }
    }
}

fn reference(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b.len() <= MAX_LEDGER_SCHEMA_LEN
        && (b[0].is_ascii_lowercase() || b[0] == b'_')
        && b[1..]
            .iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
        && !name.starts_with("pg_")
        && name != "information_schema"
}

/// P4 (revised): [`LedgerSchema::new`] accepts exactly the names of the
/// reference rule `[a-z_][a-z0-9_]*`, at most 63 bytes, not `pg_*` and not
/// `information_schema`, and keeps an accepted name unchanged.
#[test]
fn p4_ledger_schema_validation_matches_reference() {
    const ALPHABET: &[char] = &[
        'a', 'g', 'p', 'z', '_', '0', '9', 'A', 'Z', '"', '\'', ';', ' ', '.', '-', '$', '%', '\0',
        '\n', '\u{e9}', '\u{2028}',
    ];
    check_with(
        "p4_ledger_schema_validation_matches_reference",
        Config::from_env(),
        |g: &mut Gen| {
            let name: String = match g.weighted(&[3, 1, 1, 1]) {
                0 => g.vec(0..=70, |g| *g.pick(ALPHABET)).into_iter().collect(),
                1 => format!(
                    "pg_{}",
                    g.vec(0..=4, |g| *g.pick(ALPHABET))
                        .into_iter()
                        .collect::<String>()
                ),
                2 => g.string(0..=8),
                _ => "a".repeat(g.usize_in(60..=66)),
            };
            g.note("name", &name);
            let got = LedgerSchema::new(&name);
            prop_assert_eq!(got.is_ok(), reference(&name));
            match got {
                Ok(schema) => prop_assert_eq!(schema.as_str(), name.as_str()),
                Err(LedgerSchemaError::Empty) => prop_assert!(name.is_empty()),
                Err(LedgerSchemaError::TooLong { len }) => {
                    prop_assert!(len == name.len() && len > MAX_LEDGER_SCHEMA_LEN);
                }
                Err(LedgerSchemaError::InvalidByte { offset }) => {
                    prop_assert!(offset < name.len());
                }
                Err(LedgerSchemaError::Reserved) => {
                    prop_assert!(name.starts_with("pg_") || name == "information_schema");
                }
                Err(other) => return Err(format!("unexpected error {other:?}")),
            }
            Ok(())
        },
    );
}
