//! ADR-011, I-82: `Client::execute_rendered_ddl`, the one entry point whose
//! SQL text is not `&'static str`. `fstp-pgagent` runs the DDL it renders
//! from typed slots through it.
//!
//! The tests run against a real PostgreSQL server as the superuser, as
//! the agent does. They check that `CREATE DATABASE` runs (it cannot run
//! in a transaction block), that a DO block runs, that two statements in
//! one text are refused, that a server error keeps its SQLSTATE and
//! leaves the connection usable, and that an open transaction refuses
//! the call.

#![cfg(feature = "rendered-ddl")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{block_on, config_with, connect, role_tls, server};
use fstp_pgtest::Role;
use fstp_pgwire::ErrorKind;

fn superuser() -> common::PgClient {
    let db = server()
        .fresh_database_as(Role::Superuser)
        .unwrap_or_else(|e| panic!("{e}"));
    connect(&config_with(&db, role_tls(Role::Superuser)))
}

/// ADR-011: `CREATE DATABASE` runs through the entry point, and running
/// it again reports SQLSTATE `42P04`, which the agent reads as done.
#[test]
fn adr011_rendered_create_database_runs_outside_a_transaction() {
    let mut c = superuser();
    let name = format!("\"c_{}\"", "ab".repeat(16));
    let sql = format!("CREATE DATABASE {name}");
    let tag = block_on(c.execute_rendered_ddl(&sql)).unwrap();
    assert_eq!(tag, "CREATE DATABASE");
    let again = block_on(c.execute_rendered_ddl(&sql)).unwrap_err();
    assert_eq!(again.code(), Some("42P04"));
    assert!(!c.is_broken());
    let drop = format!("DROP DATABASE {name}");
    block_on(c.execute_rendered_ddl(&drop)).unwrap();
}

/// ADR-011: a DO block runs, and a text with two statements is refused
/// by the server's parser, so one call runs at most one statement.
#[test]
fn adr011_rendered_ddl_runs_one_statement_only() {
    let mut c = superuser();
    let tag = block_on(c.execute_rendered_ddl(
        "DO $x$ BEGIN PERFORM pg_catalog.set_config('fstp.t', 'a', true); END $x$",
    ))
    .unwrap();
    assert_eq!(tag, "DO");
    let two = block_on(c.execute_rendered_ddl("SELECT 1; SELECT 2")).unwrap_err();
    assert_eq!(two.code(), Some("42601"));
    assert!(!c.is_broken());
    let empty = block_on(c.execute_rendered_ddl("  ")).unwrap_err();
    assert_eq!(empty.kind(), ErrorKind::Config);
}

/// R-NF-02, ADR-011: a refused statement's error carries its SQLSTATE and
/// never the SQL text, and the connection stays usable.
#[test]
fn r_nf_02_rendered_ddl_error_hides_the_sql() {
    let mut c = superuser();
    let e =
        block_on(c.execute_rendered_ddl("ALTER ROLE \"no_such_role_secret\" NOLOGIN")).unwrap_err();
    assert_eq!(e.code(), Some("42704"));
    let shown = format!("{e} {e:?}");
    assert!(!shown.contains("no_such_role_secret"), "{shown}");
    let row = block_on(c.query_one("SELECT 1::int4", &[])).unwrap();
    let one: i32 = row.get(0).unwrap();
    assert_eq!(one, 1);
}

/// ADR-011: rendered DDL never runs inside an open transaction, since
/// `CREATE DATABASE` cannot. A dropped transaction is rolled back first,
/// so a statement that refuses a transaction block still runs.
#[test]
fn adr011_rendered_ddl_runs_after_a_dropped_transaction_is_rolled_back() {
    let mut c = superuser();
    block_on(async {
        let tx = c.transaction().await.unwrap();
        drop(tx);
    });
    let sql = format!("CREATE DATABASE \"v_{}\"", "cd".repeat(16));
    block_on(c.execute_rendered_ddl(&sql)).unwrap();
    let drop = format!("DROP DATABASE \"v_{}\"", "cd".repeat(16));
    block_on(c.execute_rendered_ddl(&drop)).unwrap();
}
