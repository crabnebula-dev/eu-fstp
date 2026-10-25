//! `fstp-migrate` against a real PostgreSQL server from `fstp-pgtest`
//! (test plan, "Database" layer: migrations forward-only; R-NF-06).
//!
//! Every test gets a fresh database on one shared server per test binary.
//! The migration files under `migrations/` are synthetic fixtures.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use std::collections::BTreeMap;
use std::sync::Barrier;

use common::{Pg, block_on, connect, fresh, relation_exists, rt, scalar_i64, scalar_text, tls};
use fstp_migrate::{
    Database, Error, LEDGER_SCHEMA, LEDGER_TABLE, LedgerProblem, Migration, MigrationSet, Status,
};
use fstp_pgwire::{Session, TransactionStatus};

const ACCOUNTS: &str = include_str!("migrations/base/0001_create_accounts.sql");
const ACCOUNTS_EDITED: &str = include_str!("migrations/base/0001_create_accounts_edited.sql");
const TRICKY: &str = include_str!("migrations/base/0002_tricky_sql.sql");
const SEED: &str = include_str!("migrations/base/0003_seed_accounts.sql");
const STATUS: &str = include_str!("migrations/base/0004_add_account_status.sql");
const BROKEN: &str = include_str!("migrations/base/0004_broken.sql");

const M1: Migration = Migration::new(1, "create_accounts", ACCOUNTS);
const M2: Migration = Migration::new(2, "tricky_sql", TRICKY);
const M3: Migration = Migration::new(3, "seed_accounts", SEED);
const M4: Migration = Migration::new(4, "add_account_status", STATUS);

/// The first release: three migrations.
const RELEASE_1: &[Migration] = &[M1, M2, M3];
/// The second release adds a fourth migration.
const RELEASE_2: &[Migration] = &[M1, M2, M3, M4];
/// An older binary that knows only two migrations.
const OLDER: &[Migration] = &[M1, M2];
/// The first migration edited after it was applied.
const EDITED: &[Migration] = &[
    Migration::new(1, "create_accounts", ACCOUNTS_EDITED),
    M2,
    M3,
    M4,
];
/// A release whose fourth migration fails at its third statement.
const WITH_BROKEN: &[Migration] = &[M1, M2, M3, Migration::new(4, "add_account_status", BROKEN)];

const CONCURRENT: &[Migration] = &[
    Migration::new(
        1,
        "create_runs",
        include_str!("migrations/concurrent/0001_create_runs.sql"),
    ),
    Migration::new(
        2,
        "second",
        include_str!("migrations/concurrent/0002_second.sql"),
    ),
    Migration::new(
        3,
        "third",
        include_str!("migrations/concurrent/0003_third.sql"),
    ),
    Migration::new(
        4,
        "fourth",
        include_str!("migrations/concurrent/0004_fourth.sql"),
    ),
];

fn set(list: &[Migration]) -> MigrationSet {
    MigrationSet::new(list).unwrap_or_else(|e| panic!("invalid fixture list: {e}"))
}

fn apply(db: &mut Pg, list: &[Migration]) -> Result<fstp_migrate::ApplyReport, Error> {
    block_on(set(list).apply(db))
}

fn verify(db: &mut Pg, list: &[Migration]) -> Result<Status, Error> {
    block_on(set(list).verify(db))
}

fn versions(report: &fstp_migrate::ApplyReport) -> Vec<u32> {
    report.applied.iter().map(|m| m.version).collect()
}

fn ledger_versions(db: &mut Pg) -> Vec<i64> {
    block_on(db.query(
        "SELECT version FROM fstp_migrate.schema_migrations ORDER BY version",
        &[],
    ))
    .unwrap()
    .iter()
    .map(|r| r.get(0).unwrap())
    .collect()
}

fn problems(e: &Error) -> Vec<LedgerProblem> {
    match e.inconsistency() {
        Some(i) => i.problems().to_vec(),
        None => panic!("expected an inconsistent ledger, got: {e}"),
    }
}

/// Forward-only (test plan, Database layer): migrations apply in order
/// from an empty database, and the ledger records each one with the
/// SHA-256 of its file and its statement count.
#[test]
fn forward_only_apply_from_empty_database() {
    let mut db = connect(&fresh());
    let status = verify(&mut db, RELEASE_1).unwrap();
    assert!(!status.ledger_exists);
    assert!(status.applied.is_empty());
    let plan: Vec<u32> = block_on(set(RELEASE_1).plan(&mut db))
        .unwrap()
        .iter()
        .map(|m| m.version)
        .collect();
    assert_eq!(plan, vec![1, 2, 3]);
    assert!(
        !relation_exists(&mut db, LEDGER_TABLE),
        "verify and plan change nothing"
    );

    let report = apply(&mut db, RELEASE_1).unwrap();
    assert_eq!(versions(&report), vec![1, 2, 3]);
    assert_eq!(report.version, 3);

    let status = verify(&mut db, RELEASE_1).unwrap();
    assert!(status.ledger_exists);
    assert!(status.pending.is_empty());
    let recorded: Vec<(i64, &str, Vec<u8>, i32)> = status
        .applied
        .iter()
        .map(|r| {
            (
                r.version,
                r.name.as_str(),
                r.checksum.clone(),
                r.statement_count,
            )
        })
        .collect();
    assert_eq!(
        recorded,
        vec![
            (
                1,
                "create_accounts",
                fstp_crypto::sha256(ACCOUNTS.as_bytes()).to_vec(),
                2
            ),
            (
                2,
                "tricky_sql",
                fstp_crypto::sha256(TRICKY.as_bytes()).to_vec(),
                6
            ),
            (
                3,
                "seed_accounts",
                fstp_crypto::sha256(SEED.as_bytes()).to_vec(),
                2
            ),
        ]
    );
    assert!(status.applied.iter().all(|r| r.applied_at.is_finite()));
    assert_eq!(db.transaction_status(), TransactionStatus::Idle);
}

/// Statement splitting on real PostgreSQL. These split correctly and
/// behave as written:
///
/// - functions with dollar-quoted bodies holding semicolons and quotes;
/// - a `BEGIN ATOMIC` body;
/// - a rule with several actions;
/// - a quoted identifier with `;` and `""`;
/// - a `DO` block.
#[test]
fn tricky_sql_splits_and_runs() {
    let mut db = connect(&fresh());
    apply(&mut db, RELEASE_1).unwrap();
    assert_eq!(
        scalar_text(&mut db, "SELECT greeting('x')"),
        "it's; \"quoted\" $$;$$ x'; done"
    );
    assert_eq!(scalar_i64(&mut db, "SELECT add_one(41)::int8"), 42);
    assert_eq!(
        scalar_text(
            &mut db,
            "SELECT string_agg(DISTINCT note, '|' ORDER BY note) FROM events"
        ),
        "account;added|second';rule"
    );
    assert_eq!(
        scalar_text(&mut db, "SELECT \"col\"\"quote\" FROM \"odd;name\""),
        "x;y"
    );
    assert_eq!(
        scalar_text(&mut db, "SELECT handle FROM accounts WHERE id = 2"),
        "bob's"
    );
}

/// The server lexes these constructs as the splitter does:
///
/// - an escape string continued over a newline and a comment keeps
///   backslash escapes;
/// - `U&`, `B` and `X` strings quote like standard strings;
/// - a standard string continues over a newline;
/// - a tagged dollar quote holds a semicolon;
/// - parenthesised subqueries stay in their statement.
#[test]
fn server_agrees_with_lexical_edge_cases() {
    const LIST: &[Migration] = &[Migration::new(
        1,
        "lexical_edges",
        "CREATE TABLE lex (id int PRIMARY KEY, v text);\n\
         INSERT INTO lex VALUES (1, E'a'\n  -- comment; '\n'\\'; b');\n\
         INSERT INTO lex VALUES (2, U&'d\\0061t;' || B'01'::text || X'1F'::text);\n\
         INSERT INTO lex VALUES (3, 'c'\n'd;');\n\
         INSERT INTO lex SELECT 4, $q$;$q$ WHERE (SELECT 1 WHERE true) = 1;\n\
         INSERT INTO lex VALUES (5, (SELECT $$x$$ || 1::text))",
    )];
    let mut db = connect(&fresh());
    let report = apply(&mut db, LIST).unwrap();
    assert_eq!(report.applied[0].statements, 6);
    assert_eq!(
        scalar_text(&mut db, "SELECT string_agg(v, '|' ORDER BY id) FROM lex"),
        "a'; b|dat;0100011111|cd;|;|x1"
    );
}

/// Forward-only (test plan, Database layer): running again applies
/// nothing and leaves the ledger as it was.
#[test]
fn forward_only_rerun_is_idempotent() {
    let mut db = connect(&fresh());
    apply(&mut db, RELEASE_1).unwrap();
    let before = verify(&mut db, RELEASE_1).unwrap();
    let again = apply(&mut db, RELEASE_1).unwrap();
    assert!(again.applied.is_empty());
    assert_eq!(again.version, 3);
    let after = verify(&mut db, RELEASE_1).unwrap();
    assert_eq!(
        before, after,
        "the ledger, applied_at included, is unchanged"
    );
    assert_eq!(scalar_i64(&mut db, "SELECT count(*) FROM accounts"), 2);
}

/// Forward-only (test plan, Database layer): an applied migration whose
/// file changed, even only in a comment, is refused by apply, verify and
/// plan, and nothing further is applied.
#[test]
fn forward_only_changed_migration_is_refused() {
    let mut db = connect(&fresh());
    apply(&mut db, RELEASE_1).unwrap();
    let expected = vec![LedgerProblem::ChecksumMismatch {
        version: 1,
        name: "create_accounts".into(),
    }];
    assert_eq!(problems(&apply(&mut db, EDITED).unwrap_err()), expected);
    assert_eq!(problems(&verify(&mut db, EDITED).unwrap_err()), expected);
    assert_eq!(
        problems(&block_on(set(EDITED).plan(&mut db)).unwrap_err()),
        expected
    );
    assert_eq!(ledger_versions(&mut db), vec![1, 2, 3]);
    assert_eq!(
        scalar_i64(
            &mut db,
            "SELECT count(*) FROM information_schema.columns \
             WHERE table_name = 'accounts' AND column_name = 'status'"
        ),
        0,
        "migration 4 was not applied"
    );
}

/// Forward-only (test plan, Database layer): a ledger whose checksum was
/// tampered with in the database is refused.
#[test]
fn forward_only_tampered_ledger_checksum_is_refused() {
    let mut db = connect(&fresh());
    apply(&mut db, RELEASE_1).unwrap();
    block_on(db.execute(
        "UPDATE fstp_migrate.schema_migrations SET checksum = sha256(checksum) WHERE version = 2",
        &[],
    ))
    .unwrap();
    let err = apply(&mut db, RELEASE_2).unwrap_err();
    assert_eq!(
        problems(&err),
        vec![LedgerProblem::ChecksumMismatch {
            version: 2,
            name: "tricky_sql".into()
        }]
    );
    assert!(err.to_string().contains("forward-only"));
    assert_eq!(ledger_versions(&mut db), vec![1, 2, 3]);
}

/// Forward-only (test plan, Database layer): a database ahead of the
/// binary is refused.
#[test]
fn forward_only_database_ahead_is_refused() {
    let mut db = connect(&fresh());
    apply(&mut db, RELEASE_1).unwrap();
    let expected = vec![LedgerProblem::UnknownVersion { version: 3 }];
    assert_eq!(problems(&apply(&mut db, OLDER).unwrap_err()), expected);
    assert_eq!(problems(&verify(&mut db, OLDER).unwrap_err()), expected);
}

/// Forward-only (test plan, Database layer): applied versions must be a
/// prefix of the embedded list.
#[test]
fn forward_only_gap_in_ledger_is_refused() {
    let mut db = connect(&fresh());
    apply(&mut db, RELEASE_1).unwrap();
    block_on(db.execute(
        "DELETE FROM fstp_migrate.schema_migrations WHERE version = 2",
        &[],
    ))
    .unwrap();
    assert_eq!(
        problems(&apply(&mut db, RELEASE_2).unwrap_err()),
        vec![LedgerProblem::Missing { version: 2 }]
    );
}

/// R-NF-06: a failing statement in the middle of a migration leaves no
/// partial change and the version unapplied, while earlier migrations stay
/// applied. The corrected release then applies cleanly.
#[test]
fn r_nf_06_failing_statement_leaves_no_partial_change() {
    let mut db = connect(&fresh());
    let err = apply(&mut db, WITH_BROKEN).unwrap_err();
    match &err {
        Error::Statement {
            version: 4,
            name: "add_account_status",
            statement: 3,
            line: 3,
            ..
        } => {}
        other => panic!("unexpected error: {other}"),
    }
    assert_eq!(err.code(), Some("42P01"));
    assert_eq!(db.transaction_status(), TransactionStatus::Idle);
    assert!(!relation_exists(&mut db, "broken_partial"));
    assert!(!relation_exists(&mut db, "broken_after"));
    assert_eq!(ledger_versions(&mut db), vec![1, 2, 3]);
    assert_eq!(scalar_i64(&mut db, "SELECT count(*) FROM accounts"), 2);
    let pending: Vec<u32> = block_on(set(WITH_BROKEN).plan(&mut db))
        .unwrap()
        .iter()
        .map(|m| m.version)
        .collect();
    assert_eq!(pending, vec![4]);

    let report = apply(&mut db, RELEASE_2).unwrap();
    assert_eq!(versions(&report), vec![4]);
}

/// R-NF-06: an update that adds a migration applies it on top of existing
/// data without losing any.
#[test]
fn r_nf_06_upgrade_keeps_existing_data() {
    let mut db = connect(&fresh());
    apply(&mut db, RELEASE_1).unwrap();
    block_on(db.execute("INSERT INTO accounts (id, handle) VALUES (3, 'carol')", &[])).unwrap();
    let events = scalar_i64(&mut db, "SELECT count(*) FROM events");
    let report = apply(&mut db, RELEASE_2).unwrap();
    assert_eq!(versions(&report), vec![4]);
    assert_eq!(report.version, 4);
    assert_eq!(
        scalar_text(
            &mut db,
            "SELECT string_agg(id || ':' || handle || ':' || status, ',' ORDER BY id) FROM accounts"
        ),
        "1:alice;one:legacy,2:bob's:active,3:carol:active"
    );
    assert_eq!(scalar_i64(&mut db, "SELECT count(*) FROM events"), events);
}

/// Forward-only (test plan, Database layer): concurrent runners apply each
/// migration exactly once. Four runners start together on four
/// connections; the first migration holds its transaction open for 300 ms
/// so that they overlap.
#[test]
fn forward_only_concurrent_runners_apply_each_migration_once() {
    concurrent_runners(None);
}

/// As above, with `REPEATABLE READ` as every session's default isolation
/// level. The runner's explicit `READ COMMITTED` keeps the reread under
/// the lock fresh.
#[test]
fn forward_only_concurrent_runners_ignore_default_isolation() {
    concurrent_runners(Some(
        "SET default_transaction_isolation = 'repeatable read'",
    ));
}

fn concurrent_runners(session_setup: Option<&'static str>) {
    let cfg = fresh();
    let migrations = set(CONCURRENT);
    let runners = 4;
    let barrier = Barrier::new(runners);
    let reports: Vec<fstp_migrate::ApplyReport> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..runners)
            .map(|_| {
                let (cfg, migrations, barrier) = (&cfg, &migrations, &barrier);
                s.spawn(move || {
                    let mut db = connect(cfg);
                    if let Some(sql) = session_setup {
                        block_on(db.execute(sql, &[])).unwrap();
                    }
                    barrier.wait();
                    block_on(migrations.apply(&mut db)).unwrap()
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let mut applied: Vec<u32> = reports.iter().flat_map(versions).collect();
    applied.sort_unstable();
    assert_eq!(
        applied,
        vec![1, 2, 3, 4],
        "each version applied by one runner"
    );
    assert!(reports.iter().all(|r| r.version == 4));

    let mut db = connect(&cfg);
    let rows = block_on(db.query(
        "SELECT migration, count(*)::int8 FROM runs GROUP BY migration ORDER BY migration",
        &[],
    ))
    .unwrap();
    let counts: BTreeMap<i32, i64> = rows
        .iter()
        .map(|r| (r.get(0).unwrap(), r.get(1).unwrap()))
        .collect();
    assert_eq!(counts, BTreeMap::from([(1, 1), (2, 1), (3, 1), (4, 1)]));
    assert_eq!(ledger_versions(&mut db), vec![1, 2, 3, 4]);
}

/// A migration that changes `search_path` or `standard_conforming_strings`,
/// even with `SET LOCAL`, is rolled back: the ledger row would otherwise
/// land in another schema, or later files would be split under other
/// quoting rules.
#[test]
fn session_setting_changes_are_refused() {
    const CASES: &[(&[Migration], &str)] = &[
        (
            &[Migration::new(
                1,
                "set_path",
                "CREATE TABLE side_effect (id int);\nSET search_path TO pg_catalog;",
            )],
            "search_path",
        ),
        (
            &[Migration::new(
                1,
                "set_local_path",
                "CREATE TABLE side_effect (id int);\nSET LOCAL search_path TO pg_catalog;",
            )],
            "search_path",
        ),
        (
            &[Migration::new(
                1,
                "set_scs",
                "CREATE TABLE side_effect (id int);\nSET standard_conforming_strings = off;",
            )],
            "standard_conforming_strings",
        ),
    ];
    for (list, expected) in CASES {
        let mut db = connect(&fresh());
        let path = scalar_text(&mut db, "SELECT current_setting('search_path')");
        match apply(&mut db, list).unwrap_err() {
            Error::SessionChanged { setting, .. } => assert_eq!(setting, *expected),
            other => panic!("unexpected error: {other}"),
        }
        assert!(!relation_exists(&mut db, "side_effect"));
        assert!(!relation_exists(&mut db, LEDGER_TABLE));
        assert_eq!(
            scalar_text(&mut db, "SELECT current_setting('search_path')"),
            path
        );
        assert_eq!(db.parameter("standard_conforming_strings"), Some("on"));
    }
}

/// The splitter assumes `standard_conforming_strings = on`, so the runner
/// refuses a session where it is off and applies nothing.
#[test]
fn standard_conforming_strings_off_is_refused() {
    let mut db = connect(&fresh());
    block_on(db.execute("SET standard_conforming_strings = off", &[])).unwrap();
    assert!(matches!(
        apply(&mut db, RELEASE_1),
        Err(Error::StandardConformingStringsOff)
    ));
    assert!(!relation_exists(&mut db, LEDGER_TABLE));
    block_on(db.execute("RESET standard_conforming_strings", &[])).unwrap();
    assert_eq!(versions(&apply(&mut db, RELEASE_1).unwrap()), vec![1, 2, 3]);
}

/// Statements that cannot run inside a transaction block are unsupported
/// in M1. One that validation does not catch by keyword is rejected by the
/// server with SQLSTATE 25001, and the migration rolls back.
#[test]
fn non_transactional_statement_is_rolled_back() {
    const LIST: &[Migration] = &[Migration::new(
        1,
        "cluster_all",
        "CREATE TABLE before_cluster (id int);\nCLUSTER;",
    )];
    let mut db = connect(&fresh());
    let err = apply(&mut db, LIST).unwrap_err();
    assert!(
        matches!(
            err,
            Error::NotTransactional {
                version: 1,
                statement: 2,
                line: 2,
                ..
            }
        ),
        "unexpected error: {err}"
    );
    assert_eq!(err.code(), Some("25001"));
    assert!(!relation_exists(&mut db, "before_cluster"));
}

/// A deferred constraint that fails at commit rolls the migration back.
#[test]
fn failure_at_commit_rolls_back() {
    const LIST: &[Migration] = &[Migration::new(
        1,
        "deferred_fk",
        "CREATE TABLE parent (id int PRIMARY KEY);\n\
         CREATE TABLE child (pid int REFERENCES parent DEFERRABLE INITIALLY DEFERRED);\n\
         INSERT INTO child VALUES (1);",
    )];
    let mut db = connect(&fresh());
    let err = apply(&mut db, LIST).unwrap_err();
    assert!(
        matches!(err, Error::Commit { version: 1, .. }),
        "unexpected error: {err}"
    );
    assert_eq!(err.code(), Some("23503"));
    assert_eq!(db.transaction_status(), TransactionStatus::Idle);
    assert!(!relation_exists(&mut db, "parent"));
    assert!(!relation_exists(&mut db, LEDGER_TABLE));
}

/// The runner owns the transaction, so it refuses a connection that is
/// already inside one.
#[test]
fn an_open_transaction_is_refused() {
    let mut db = connect(&fresh());
    block_on(db.execute("BEGIN", &[])).unwrap();
    assert!(matches!(
        apply(&mut db, RELEASE_1),
        Err(Error::TransactionOpen)
    ));
    assert!(matches!(
        verify(&mut db, RELEASE_1),
        Err(Error::TransactionOpen)
    ));
    block_on(db.execute("ROLLBACK", &[])).unwrap();
    assert!(apply(&mut db, RELEASE_1).is_ok());
}

/// `fstp_pgwire::Session` implements `Database` without an adapter.
#[test]
fn session_implements_database() {
    use fstp_rt::{Runtime, tokio::TokioRuntime};

    let cfg = fresh();
    let mut session: Session = block_on(async {
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], cfg.port()));
        let tcp = <TokioRuntime as Runtime>::connect_tcp(rt(), addr)
            .await
            .unwrap();
        let tls_stream = fstp_pgwire::tls_handshake(tcp, &tls(), cfg.server_name())
            .await
            .unwrap();
        let cert = tls_stream.peer_end_entity_der().unwrap().to_vec();
        Session::startup(Box::new(tls_stream), &cfg, Some(&cert))
            .await
            .unwrap()
    });
    let report = block_on(set(RELEASE_1).apply(&mut session)).unwrap();
    assert_eq!(versions(&report), vec![1, 2, 3]);
    let status = block_on(set(RELEASE_2).verify(&mut session)).unwrap();
    assert_eq!(
        status.pending.iter().map(|m| m.version).collect::<Vec<_>>(),
        vec![4]
    );
}

/// `fstp_pgwire::Client` implements `Database` in this crate, so callers
/// need no adapter.
#[test]
fn client_implements_database() {
    fn assert_database<D: Database>() {}
    assert_database::<Pg>();
}

/// Review finding `ledger-located-via-search-path` (forward-only, test
/// plan Database layer). A later session that resolves names differently
/// still finds the ledger and re-applies nothing. Here a migration changes
/// the database's default `search_path`, which only later sessions see, and
/// an operator session sets yet another `search_path`.
#[test]
fn review_ledger_located_via_search_path() {
    const LIST: &[Migration] = &[
        Migration::new(
            1,
            "create_notes",
            "CREATE TABLE notes (id int);\nINSERT INTO notes VALUES (1);",
        ),
        Migration::new(
            2,
            "move_to_app_schema",
            "CREATE SCHEMA IF NOT EXISTS app;\n\
             DO $$ BEGIN EXECUTE format('ALTER DATABASE %I SET search_path = app', \
             current_database()); END $$;",
        ),
    ];
    let cfg = fresh();
    let mut db = connect(&cfg);
    assert_eq!(versions(&apply(&mut db, LIST).unwrap()), vec![1, 2]);

    // The next deployment opens a new session, whose search_path is `app`.
    let mut next = connect(&cfg);
    assert_eq!(
        scalar_text(&mut next, "SELECT current_setting('search_path')"),
        "app"
    );
    let status = verify(&mut next, LIST).unwrap();
    assert!(status.ledger_exists);
    assert!(status.pending.is_empty(), "{:?}", status.pending);
    assert!(apply(&mut next, LIST).unwrap().applied.is_empty());

    // An operator session with another search_path changes nothing either.
    block_on(next.execute("CREATE SCHEMA other", &[])).unwrap();
    let mut operator = connect(&cfg);
    block_on(operator.execute("SET search_path = other", &[])).unwrap();
    assert!(apply(&mut operator, LIST).unwrap().applied.is_empty());
    assert_eq!(
        scalar_i64(
            &mut operator,
            "SELECT count(*) FROM pg_class WHERE relname = 'notes' AND relkind = 'r'"
        ),
        1,
        "migration 1 ran once"
    );
    assert_eq!(
        scalar_i64(&mut operator, "SELECT count(*) FROM public.notes"),
        1
    );
    // One ledger, in its own schema, whatever the search_path (P4).
    assert_eq!(
        scalar_text(
            &mut operator,
            "SELECT string_agg(n.nspname || '.' || c.relname, ',') FROM pg_class c \
             JOIN pg_namespace n ON n.oid = c.relnamespace \
             WHERE c.relname LIKE '%schema_migrations'"
        ),
        LEDGER_TABLE
    );
    assert!(LEDGER_TABLE.starts_with(LEDGER_SCHEMA));
}

/// Review finding `temp-table-shadows-ledger` (forward-only). A temporary
/// table named like the ledger cannot capture the runner's ledger row, so
/// the next session sees the migration as applied.
#[test]
fn review_temp_table_shadows_ledger() {
    const LIST: &[Migration] = &[Migration::new(
        1,
        "backfill",
        "CREATE TABLE IF NOT EXISTS public.items (id int);\n\
         INSERT INTO public.items VALUES (1);\n\
         CREATE TEMP TABLE fstp_schema_migrations (version bigint, name text, checksum bytea, \
         statement_count int, applied_at timestamptz DEFAULT now());\n\
         CREATE TEMP TABLE schema_migrations (version bigint, name text, checksum bytea, \
         statement_count int, applied_at timestamptz DEFAULT now());",
    )];
    let cfg = fresh();
    let mut db = connect(&cfg);
    assert_eq!(versions(&apply(&mut db, LIST).unwrap()), vec![1]);
    drop(db);
    let mut next = connect(&cfg);
    assert!(verify(&mut next, LIST).unwrap().pending.is_empty());
    assert!(apply(&mut next, LIST).unwrap().applied.is_empty());
    assert_eq!(
        scalar_i64(&mut next, "SELECT count(*) FROM public.items"),
        1
    );
}

/// Review finding `errors-carry-row-values` (R-NF-02). A data migration
/// that fails on one row does not put the row's value into the error's
/// Display or Debug output, and a syntax error does not put SQL text
/// there.
#[test]
fn review_errors_carry_row_values() {
    const CAST: &[Migration] = &[
        Migration::new(
            1,
            "people",
            "CREATE TABLE people (contact text);\n\
             INSERT INTO people VALUES ('42'), ('jane.doe@example.org');",
        ),
        Migration::new(
            2,
            "contact_to_int",
            "ALTER TABLE people ALTER COLUMN contact TYPE int USING contact::int;",
        ),
    ];
    let mut db = connect(&fresh());
    let err = apply(&mut db, CAST).unwrap_err();
    let shown = format!("{err} / {err:?}");
    assert!(!shown.contains("jane.doe"), "{shown}");
    assert!(shown.contains("22P02"), "{shown}");
    // The message stays reachable through the documented accessor.
    assert!(
        err.server_message()
            .is_some_and(|m| m.contains("jane.doe@example.org"))
    );
    assert!(
        matches!(
            err,
            Error::Statement {
                version: 2,
                name: "contact_to_int",
                statement: 1,
                line: 1,
                ..
            }
        ),
        "{shown}"
    );

    const TYPO: &[Migration] = &[Migration::new(
        1,
        "typo",
        "INSERT INTO nowhere VALUES ('secret-token-123') ON CONFLICT DO NOTHNG;",
    )];
    let mut db = connect(&fresh());
    let err = apply(&mut db, TYPO).unwrap_err();
    let shown = format!("{err} / {err:?}");
    assert!(!shown.contains("NOTHNG"), "{shown}");
    assert!(!shown.contains("secret-token"), "{shown}");
    assert_eq!(err.code(), Some("42601"));
}

/// Review finding `begin-atomic-reserved-labels` (TH-26). Inside a
/// `BEGIN ATOMIC` body, `END` and `CASE` can be column labels, bare
/// labels or qualified column names, and `begin atomic` can be a column
/// with a label. The splitter reads them as the server does.
#[test]
fn review_begin_atomic_reserved_labels() {
    const SQL: &str = "CREATE FUNCTION span() RETURNS int LANGUAGE sql\n\
         BEGIN ATOMIC\n  SELECT 2 AS end;\nEND;\n\
         CREATE FUNCTION last_end() RETURNS int LANGUAGE sql\n\
         BEGIN ATOMIC\n  SELECT r.end FROM (SELECT 7 AS \"end\") r;\nEND;\n\
         CREATE FUNCTION kind() RETURNS int LANGUAGE sql BEGIN ATOMIC SELECT 3 AS case; END;\n\
         CREATE FUNCTION bare_end() RETURNS int LANGUAGE sql BEGIN ATOMIC SELECT 4 end; END;\n\
         CREATE FUNCTION bare_case() RETURNS int LANGUAGE sql\n\
         BEGIN ATOMIC SELECT CASE WHEN true THEN 5 END case; END;\n\
         CREATE FUNCTION col_begin() RETURNS int LANGUAGE sql\n\
         BEGIN ATOMIC SELECT t.begin atomic FROM (SELECT 6 AS begin) t; END;\n\
         CREATE FUNCTION empty_proc() RETURNS void LANGUAGE sql BEGIN ATOMIC END;\n\
         CREATE TABLE after_fn (id int);\n\
         SELECT 1 AS end";
    const LIST: &[Migration] = &[Migration::new(1, "reserved_labels", SQL)];
    let mut db = connect(&fresh());
    let report = apply(&mut db, LIST).unwrap();
    assert_eq!(report.applied[0].statements, 9);
    for (sql, want) in [
        ("SELECT span()::int8", 2),
        ("SELECT last_end()::int8", 7),
        ("SELECT kind()::int8", 3),
        ("SELECT bare_end()::int8", 4),
        ("SELECT bare_case()::int8", 5),
        ("SELECT col_begin()::int8", 6),
    ] {
        assert_eq!(scalar_i64(&mut db, sql), want, "{sql}");
    }
    assert!(relation_exists(&mut db, "after_fn"));
}

/// Review finding `scs-checked-only-around-migration`. A statement that
/// turns `standard_conforming_strings` off, directly or through dynamic
/// SQL, stops the migration before the next statement reaches the server.
/// The splitter read that statement with the setting on, so it must not
/// run. Here it would be a hidden `COPY ... TO STDOUT`.
#[test]
fn review_scs_checked_only_around_migration() {
    for (name, sql) in [
        (
            "scs_set_local",
            "SET LOCAL standard_conforming_strings = off;\n\
             COPY (SELECT 'a\\'' ) TO STDOUT --');",
        ),
        (
            "scs_set_config",
            "DO $$ BEGIN PERFORM set_config('standard_conforming_strings', 'off', true); \
             END $$;\nCOPY (SELECT 'a\\'' ) TO STDOUT --');",
        ),
    ] {
        let sql: &'static str = Box::leak(sql.to_owned().into_boxed_str());
        let name: &'static str = Box::leak(name.to_owned().into_boxed_str());
        let list = [Migration::new(1, name, sql)];
        let mut db = connect(&fresh());
        let err = apply(&mut db, &list).unwrap_err();
        assert!(
            matches!(
                err,
                Error::SessionChanged {
                    version: 1,
                    setting: "standard_conforming_strings",
                    ..
                }
            ),
            "{name}: {err}"
        );
        assert_eq!(db.transaction_status(), TransactionStatus::Idle);
        assert_eq!(db.parameter("standard_conforming_strings"), Some("on"));
        assert_eq!(scalar_i64(&mut db, "SELECT 1::int8"), 1, "{name}");
    }
}

/// Review finding `lexer-param-and-vtab-disagree` (TH-26). PostgreSQL 16
/// rejects a vertical tab outside strings and comments, so a file that
/// holds one fails as a whole instead of running with the tab trimmed.
#[test]
fn review_lexer_param_and_vtab_disagree() {
    const LIST: &[Migration] = &[Migration::new(
        1,
        "vertical_tab",
        "CREATE TABLE vt (id int);\x0b",
    )];
    let mut db = connect(&fresh());
    let err = match MigrationSet::new(LIST) {
        Ok(set) => block_on(set.apply(&mut db)).map(|_| ()).unwrap_err(),
        Err(e) => panic!("validation failed: {e}"),
    };
    assert_eq!(err.code(), Some("42601"), "{err}");
    assert!(!relation_exists(&mut db, "vt"));
}
