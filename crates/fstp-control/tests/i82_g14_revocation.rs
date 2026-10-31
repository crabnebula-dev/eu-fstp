//! I-82, G14, design section 4.1, ADR-011 `ApplyRevocations`: the
//! cross-database statistics views and the functions behind them.
//!
//! `pg_stat_database`, `pg_stat_activity` and similar views show every
//! database's activity to every role. Design section 4.1 revokes them from
//! PUBLIC on every cluster. Daniel decided on 2026-10-29 that EXECUTE on
//! the `pg_stat_get_*` functions behind each revoked view is revoked from
//! PUBLIC too, since they return the same rows. A test checks that
//! `fstp-pgwire` sessions still work.
//!
//! The views are the three that the T-DB-ISO sweep of lane W1f probes
//! (`G14_VIEWS` in `fstp-celltest/tests/t_db_iso_i82.rs`). The functions
//! are read from the server, never from memory: every `pg_stat_get_*` name
//! in each view's definition, with every overload of it in `pg_catalog`.
//! Privileges on `pg_catalog` objects are kept per database, so every
//! database that takes connections is checked, `template1` included. A
//! database created later copies `template1`.
//!
//! The oracle tests check that an unrevoked server is caught, that a
//! reference revocation passes, and that an `fstp-pgwire` session of a
//! role without superuser works under it. The production tests run the
//! jobs of `fstp_control::pgagent` through [`apply_production_revocations`].
//!
//! No view definition names the `pg_stat_get_backend_*` functions, yet
//! together they list every session of every database. `pg_locks` and
//! `pg_prepared_xacts` show every database's locks and prepared
//! transactions. The production revocation closes these too. This is a
//! wider reading of G14 than the views' own functions, pending Daniel's
//! confirmation. The last section checks them with its own oracle.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use std::collections::BTreeSet;
use std::sync::OnceLock;
use std::time::Duration;

use common::database_name;
use fstp_control::pg::{CellDatabase, cell_role_plan};
use fstp_cp_proto::CellId;
use fstp_pgtest::{PgServer, Role};
use fstp_pgwire::{Client, ClientTls, Config, Password};
use fstp_rt::tokio::TokioRuntime;

/// The cross-database statistics views G14 revokes from PUBLIC.
const G14_VIEWS: [&str; 3] = [
    "pg_stat_database",
    "pg_stat_database_conflicts",
    "pg_stat_activity",
];

fn rt() -> &'static TokioRuntime {
    static RT: OnceLock<TokioRuntime> = OnceLock::new();
    RT.get_or_init(|| TokioRuntime::new_multi_thread(2).unwrap())
}

/// A private server, so no revocation reaches another test's databases.
fn private_server() -> PgServer {
    PgServer::start().unwrap_or_else(|e| panic!("{e}"))
}

fn psql(server: &PgServer, db: &str, sql: &str) -> String {
    server
        .psql(db, sql)
        .unwrap_or_else(|e| panic!("{db}: {sql}: {e}"))
}

/// Every database of `server` that takes connections.
fn connectable_databases(server: &PgServer) -> Vec<String> {
    psql(
        server,
        "postgres",
        "SELECT datname FROM pg_database WHERE datallowconn ORDER BY 1",
    )
    .lines()
    .filter(|l| !l.is_empty())
    .map(str::to_owned)
    .collect()
}

/// The `pg_stat_get_*` names in `text`.
fn stat_function_names(text: &str) -> BTreeSet<String> {
    const PREFIX: &str = "pg_stat_get_";
    let mut out = BTreeSet::new();
    let mut rest = text;
    while let Some(at) = rest.find(PREFIX) {
        let tail = &rest[at..];
        let len = tail
            .bytes()
            .take_while(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_')
            .count();
        out.insert(tail[..len].to_owned());
        rest = &tail[len..];
    }
    out
}

/// The functions behind `view`, as `regprocedure` text, read from `db`.
fn functions_behind(server: &PgServer, db: &str, view: &str) -> BTreeSet<String> {
    let def = psql(
        server,
        db,
        &format!("SELECT pg_get_viewdef('pg_catalog.{view}'::regclass)"),
    );
    let mut out = BTreeSet::new();
    for name in stat_function_names(&def) {
        let sigs = psql(
            server,
            db,
            &format!(
                "SELECT p.oid::regprocedure::text FROM pg_proc p \
                 WHERE p.proname = '{name}' AND p.pronamespace = 'pg_catalog'::regnamespace"
            ),
        );
        out.extend(sigs.lines().filter(|l| !l.is_empty()).map(str::to_owned));
    }
    assert!(
        !out.is_empty(),
        "{db}: no pg_stat_get_* function behind {view}"
    );
    out
}

/// Every function behind a G14 view.
fn g14_functions(server: &PgServer, db: &str) -> BTreeSet<String> {
    G14_VIEWS
        .iter()
        .flat_map(|v| functions_behind(server, db, v))
        .collect()
}

fn sql_array(items: impl IntoIterator<Item = String>) -> String {
    let quoted: Vec<String> = items.into_iter().map(|s| format!("'{s}'")).collect();
    format!("ARRAY[{}]::text[]", quoted.join(", "))
}

/// The G14 paths still open to PUBLIC in `db`, one line each.
fn g14_open(server: &PgServer, db: &str) -> Vec<String> {
    let views = sql_array(G14_VIEWS.iter().map(|v| format!("pg_catalog.{v}")));
    let functions = sql_array(g14_functions(server, db));
    let sql = format!(
        "SELECT 'PUBLIC can SELECT ' || v FROM unnest({views}) v \
         WHERE has_table_privilege('public', v::regclass, 'SELECT') \
         UNION ALL \
         SELECT 'PUBLIC can EXECUTE ' || f FROM unnest({functions}) f \
         WHERE has_function_privilege('public', f::regprocedure, 'EXECUTE') \
         ORDER BY 1"
    );
    psql(server, db, &sql)
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| format!("{db}: {l}"))
        .collect()
}

/// The G14 paths open in every database of `server` that takes
/// connections.
fn g14_open_everywhere(server: &PgServer) -> Vec<String> {
    connectable_databases(server)
        .iter()
        .flat_map(|db| g14_open(server, db))
        .collect()
}

/// The reference revocation of G14 in `db`, as design section 4.1 and
/// Daniel's 2026-10-29 answer state it. Test oracle only.
fn reference_revoke(server: &PgServer, db: &str) {
    let views: Vec<String> = G14_VIEWS
        .iter()
        .map(|v| format!("pg_catalog.{v}"))
        .collect();
    let functions: Vec<String> = g14_functions(server, db).into_iter().collect();
    psql(
        server,
        db,
        &format!(
            "REVOKE SELECT ON {} FROM PUBLIC;\nREVOKE EXECUTE ON FUNCTION {} FROM PUBLIC;",
            views.join(", "),
            functions.join(", ")
        ),
    );
}

/// Applies the production G14 revocations of `cell`'s plan to `server`,
/// as `fstp-pgagent` runs `HardenCluster` once per cluster and
/// `ApplyRevocations` once per database of the plan.
///
/// Lane W2h wired the production call here: the statements come from
/// `fstp_control::pgagent::job_statements`, and psql stands in for the
/// agent's superuser session in each statement's target database.
fn apply_production_revocations(server: &PgServer, cell: CellId) -> Result<(), String> {
    use fstp_control::pg::Revocation;
    use fstp_control::pgagent::{DbIdent, PgagentJob, job_statements};
    let plan = cell_role_plan(cell).map_err(|e| format!("cell_role_plan: {e}"))?;
    let mut jobs = vec![PgagentJob::HardenCluster];
    for db in [CellDatabase::App, CellDatabase::Vault] {
        if plan
            .revocations
            .contains(&Revocation::StatisticsFromPublic(db))
        {
            jobs.push(PgagentJob::ApplyRevocations(DbIdent::new(db, cell)));
        }
    }
    for job in &jobs {
        for s in job_statements(job).map_err(|e| format!("{job:?}: {e}"))? {
            server
                .psql(&s.target.database_name(), &s.sql)
                .map_err(|e| format!("{job:?}: {e}"))?;
        }
    }
    Ok(())
}

/// Creates both databases of `cell` on `server`, as `CreateCellDatabases`
/// does before the revocations run.
fn create_cell_databases(server: &PgServer, cell: CellId) {
    for db in [CellDatabase::App, CellDatabase::Vault] {
        psql(
            server,
            "postgres",
            &format!("CREATE DATABASE {}", database_name(db, cell)),
        );
    }
}

/// An `fstp-pgwire` session as `fstp_app`, a role without superuser or
/// `pg_read_all_stats`, on a fresh database it owns.
fn app_session(server: &PgServer) -> Client<TokioRuntime> {
    let db = server.fresh_database_as(Role::App).unwrap();
    let tls = ClientTls::new(
        db.server_ca_pem,
        Role::App.client_cert_pem(),
        Role::App.client_key_pem(),
    )
    .unwrap();
    let cfg = Config::new(
        db.host.clone(),
        db.port,
        Role::App.name(),
        Password::new(server.password(Role::App)).unwrap(),
        db.dbname.clone(),
        tls,
    )
    .unwrap()
    .connect_timeout(Some(Duration::from_secs(20)));
    rt().block_on(Client::connect(rt(), &cfg))
        .unwrap_or_else(|e| panic!("the fstp-pgwire session did not start: {e}"))
}

/// The session runs plain and parameterised statements, and the server
/// refuses it every G14 view and the function behind `pg_stat_activity`
/// with SQLSTATE 42501.
fn session_works_and_g14_is_shut(server: &PgServer) {
    let mut c = app_session(server);
    let one: i64 = rt()
        .block_on(c.query_one("SELECT 1::int8", &[]))
        .unwrap()
        .get(0)
        .unwrap();
    assert_eq!(one, 1);
    let echo: String = rt()
        .block_on(c.query_one("SELECT $1::text", &[&"fstp"]))
        .unwrap()
        .get(0)
        .unwrap();
    assert_eq!(echo, "fstp");
    let probes: [&'static str; 4] = [
        "SELECT count(*)::int8 FROM pg_catalog.pg_stat_database",
        "SELECT count(*)::int8 FROM pg_catalog.pg_stat_database_conflicts",
        "SELECT count(*)::int8 FROM pg_catalog.pg_stat_activity",
        "SELECT count(*)::int8 FROM pg_catalog.pg_stat_get_activity(NULL)",
    ];
    for sql in probes {
        match rt().block_on(c.query_one(sql, &[])) {
            Ok(_) => panic!("{sql} ran for a role without superuser"),
            Err(e) => assert_eq!(e.code(), Some("42501"), "{sql}: {e}"),
        }
    }
    // The session survives the refusals.
    let after: i64 = rt()
        .block_on(c.query_one("SELECT 2::int8", &[]))
        .unwrap()
        .get(0)
        .unwrap();
    assert_eq!(after, 2);
}

// ---------------------------------------------------------------------------
// The oracle.

/// I-82, G14 teeth: on a server without the revocation the oracle reports
/// every G14 view and at least one function behind each, in every
/// database. The function behind `pg_stat_activity` is
/// `pg_stat_get_activity(integer)`, which the session probe calls.
#[test]
fn i82_g14_teeth_unrevoked_server_is_caught() {
    let s = private_server();
    let open = g14_open_everywhere(&s);
    for db in connectable_databases(&s) {
        for view in G14_VIEWS {
            let line = format!("{db}: PUBLIC can SELECT pg_catalog.{view}");
            assert!(open.contains(&line), "{line} missing from {open:#?}");
            let behind = functions_behind(&s, &db, view);
            assert!(
                behind
                    .iter()
                    .any(|f| open.contains(&format!("{db}: PUBLIC can EXECUTE {f}"))),
                "{db}: no open function behind {view}: {open:#?}"
            );
        }
    }
    let activity = functions_behind(&s, "postgres", "pg_stat_activity");
    assert!(
        activity.contains("pg_stat_get_activity(integer)"),
        "{activity:?}"
    );
}

/// I-82, G14: after the reference revocation in every database, the oracle
/// reports nothing, so it does not over-report.
#[test]
fn i82_g14_reference_revocation_closes_views_and_functions() {
    let s = private_server();
    for db in connectable_databases(&s) {
        reference_revoke(&s, &db);
    }
    let open = g14_open_everywhere(&s);
    assert!(open.is_empty(), "{open:#?}");
}

/// I-82, G14, design section 4.1: `fstp-pgwire` sessions of a role without
/// superuser still work under the reference revocation, and the server
/// refuses that role every revoked view and function.
#[test]
fn i82_g14_pgwire_sessions_work_under_the_reference_revocation() {
    let s = private_server();
    for db in connectable_databases(&s) {
        reference_revoke(&s, &db);
    }
    session_works_and_g14_is_shut(&s);
}

// ---------------------------------------------------------------------------
// Production.

/// I-82, G14, ADR-011 `ApplyRevocations`: after the production revocations
/// of a cell's plan, no G14 view or function behind one is open to PUBLIC
/// in any database that takes connections: `postgres`, `template1` and the
/// cell's own two databases.
#[test]
fn i82_g14_production_revocation_closes_every_database() {
    let s = private_server();
    let cell = CellId([0x5c; 16]);
    create_cell_databases(&s, cell);
    apply_production_revocations(&s, cell).unwrap_or_else(|e| panic!("{e}"));
    let dbs = connectable_databases(&s);
    for want in [
        "postgres".to_owned(),
        "template1".to_owned(),
        database_name(CellDatabase::App, cell),
        database_name(CellDatabase::Vault, cell),
    ] {
        assert!(dbs.contains(&want), "{want} is missing from {dbs:?}");
    }
    let open = g14_open_everywhere(&s);
    assert!(open.is_empty(), "{open:#?}");
}

/// I-82, G14, design section 4.1: `fstp-pgwire` sessions still work after
/// the production revocations, and a database created afterwards, as the
/// next cell's would be, inherits them.
#[test]
fn i82_g14_pgwire_sessions_work_after_the_production_revocation() {
    let s = private_server();
    let cell = CellId([0x5d; 16]);
    create_cell_databases(&s, cell);
    apply_production_revocations(&s, cell).unwrap_or_else(|e| panic!("{e}"));
    session_works_and_g14_is_shut(&s);
}

// ---------------------------------------------------------------------------
// The paths that no view definition names.

/// The other G14 paths still open to PUBLIC in `db`, one line each: the
/// `pg_stat_get_backend_*` functions, which together list every session of
/// every database, and `pg_locks` and `pg_prepared_xacts` with the
/// functions behind them. Each function is read from `pg_proc`, every
/// overload included.
fn other_g14_open(server: &PgServer, db: &str) -> Vec<String> {
    let sql = "SELECT 'PUBLIC can SELECT ' || v FROM unnest(ARRAY['pg_catalog.pg_locks', \
               'pg_catalog.pg_prepared_xacts']::text[]) v \
               WHERE has_table_privilege('public', v::regclass, 'SELECT') \
               UNION ALL \
               SELECT 'PUBLIC can EXECUTE ' || p.oid::regprocedure::text FROM pg_proc p \
               WHERE p.pronamespace = 'pg_catalog'::regnamespace \
               AND (p.proname LIKE 'pg\\_stat\\_get\\_backend\\_%' \
               OR p.proname IN ('pg_lock_status', 'pg_prepared_xact')) \
               AND has_function_privilege('public', p.oid, 'EXECUTE') ORDER BY 1";
    psql(server, db, sql)
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| format!("{db}: {l}"))
        .collect()
}

/// I-82, G14 teeth: on a server without the revocation, the oracle for the
/// paths no view names reports `pg_locks`, `pg_prepared_xacts`, their two
/// functions and the backend functions that list sessions, in every
/// database.
#[test]
fn i82_g14_teeth_backend_and_lock_paths_are_caught() {
    let s = private_server();
    for db in connectable_databases(&s) {
        let open = other_g14_open(&s, &db);
        for want in [
            "PUBLIC can SELECT pg_catalog.pg_locks",
            "PUBLIC can SELECT pg_catalog.pg_prepared_xacts",
            "PUBLIC can EXECUTE pg_lock_status()",
            "PUBLIC can EXECUTE pg_prepared_xact()",
            "PUBLIC can EXECUTE pg_stat_get_backend_idset()",
            "PUBLIC can EXECUTE pg_stat_get_backend_dbid(integer)",
            "PUBLIC can EXECUTE pg_stat_get_backend_userid(integer)",
            "PUBLIC can EXECUTE pg_stat_get_backend_activity_start(integer)",
        ] {
            let line = format!("{db}: {want}");
            assert!(open.contains(&line), "{line} missing from {open:#?}");
        }
    }
}

/// I-82, G14 (Daniel, 2026-10-29, "since they return the same rows"):
/// after the production revocations, PUBLIC can use no backend function,
/// and neither `pg_locks` nor `pg_prepared_xacts` nor the functions behind
/// them, in any database that takes connections.
#[test]
fn i82_g14_production_revocation_closes_backend_and_lock_paths() {
    let s = private_server();
    let cell = CellId([0x5e; 16]);
    create_cell_databases(&s, cell);
    apply_production_revocations(&s, cell).unwrap_or_else(|e| panic!("{e}"));
    let open: Vec<String> = connectable_databases(&s)
        .iter()
        .flat_map(|db| other_g14_open(&s, db))
        .collect();
    assert!(open.is_empty(), "{open:#?}");
}

/// I-82, G14, design section 4.1: after the production revocations, an
/// `fstp-pgwire` session of a role without superuser is refused the
/// backend, lock and prepared-transaction paths with SQLSTATE 42501. Its
/// own advisory locks, which the PostgreSQL store takes, still work.
#[test]
fn i82_g14_pgwire_session_is_refused_backend_and_lock_paths() {
    let s = private_server();
    let cell = CellId([0x5f; 16]);
    create_cell_databases(&s, cell);
    apply_production_revocations(&s, cell).unwrap_or_else(|e| panic!("{e}"));
    let mut c = app_session(&s);
    let probes: [&'static str; 5] = [
        "SELECT count(*)::int8 FROM pg_catalog.pg_locks",
        "SELECT count(*)::int8 FROM pg_catalog.pg_lock_status()",
        "SELECT count(*)::int8 FROM pg_catalog.pg_prepared_xacts",
        "SELECT count(*)::int8 FROM pg_catalog.pg_stat_get_backend_idset()",
        "SELECT pg_catalog.pg_stat_get_backend_dbid(1)::int8",
    ];
    for sql in probes {
        match rt().block_on(c.query_one(sql, &[])) {
            Ok(_) => panic!("{sql} ran for a role without superuser"),
            Err(e) => assert_eq!(e.code(), Some("42501"), "{sql}: {e}"),
        }
    }
    let locked: bool = rt()
        .block_on(c.query_one("SELECT pg_catalog.pg_try_advisory_lock(7)", &[]))
        .unwrap()
        .get(0)
        .unwrap();
    assert!(locked);
    let echo: String = rt()
        .block_on(c.query_one("SELECT $1::text", &[&"fstp"]))
        .unwrap()
        .get(0)
        .unwrap();
    assert_eq!(echo, "fstp");
}
