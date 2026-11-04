//! Review reproducers for I-82 and G14 (design sections 4.1 and 9.3).
//!
//! Each test fails against the lane's code and passes once the defect is
//! fixed. They run the production jobs on a real PostgreSQL 16 server,
//! with psql standing in for the agent's superuser session.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::OnceLock;
use std::time::Duration;

use fstp_control::isolation_audit::{privilege_graph, read_catalogue};
use fstp_control::pg::CellDatabase;
use fstp_control::pgagent::{DbIdent, G14_REVOKE_SQL, PgagentJob, job_statements};
use fstp_cp_proto::CellId;
use fstp_pgtest::{PgServer, Role};
use fstp_pgwire::{Client, ClientTls, Config, Password};
use fstp_rt::tokio::TokioRuntime;

fn rt() -> &'static TokioRuntime {
    static RT: OnceLock<TokioRuntime> = OnceLock::new();
    RT.get_or_init(|| TokioRuntime::new_multi_thread(2).unwrap())
}

fn run(server: &PgServer, job: &PgagentJob) {
    for s in job_statements(job).unwrap() {
        match server.psql(&s.target.database_name(), &s.sql) {
            Ok(_) => {}
            Err(e) if s.done_if_duplicate_database && e.to_string().contains("already exists") => {}
            Err(e) => panic!("{job:?}: {e}"),
        }
    }
}

/// The application database of a cell after the production step 4 jobs.
fn hardened_cell_database(server: &PgServer) -> String {
    let d = DbIdent::new(CellDatabase::App, CellId([0x7d; 16]));
    run(server, &PgagentJob::HardenCluster);
    run(server, &PgagentJob::CreateCellDatabase(d));
    run(server, &PgagentJob::CreateRoles(d));
    run(server, &PgagentJob::ApplyRevocations(d));
    d.name()
}

/// I-82, G14 (Daniel, 2026-10-29): after the production revocation, the
/// `pg_stat_get_backend_*` functions still give PUBLIC every session of
/// every database (database, role, start times), the same rows that
/// revoking `pg_stat_activity` closes. No view names them, so the
/// view-definition scan in `G14_REVOKE_SQL` never revokes them.
#[test]
fn review_g14_backend_functions_stay_open_to_public() {
    let server = PgServer::start().unwrap();
    let db = hardened_cell_database(&server);
    let open = server
        .psql(
            &db,
            "SELECT p.oid::regprocedure::text FROM pg_catalog.pg_proc p \
             WHERE p.pronamespace = 'pg_catalog'::regnamespace \
             AND p.proname IN ('pg_stat_get_backend_idset', 'pg_stat_get_backend_dbid', \
             'pg_stat_get_backend_userid', 'pg_stat_get_backend_activity_start') \
             AND has_function_privilege('public', p.oid, 'EXECUTE') ORDER BY 1",
        )
        .unwrap();
    let open: Vec<&str> = open.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(
        open,
        Vec::<&str>::new(),
        "PUBLIC can still list every database's sessions in {db}"
    );
}

/// I-82, G14: after the production revocation, PUBLIC still reads
/// `pg_locks`, which shows the locks of every database's sessions.
#[test]
fn review_g14_pg_locks_stays_open_to_public() {
    let server = PgServer::start().unwrap();
    let db = hardened_cell_database(&server);
    let open = server
        .psql(
            &db,
            "SELECT has_table_privilege('public', 'pg_catalog.pg_locks', 'SELECT')",
        )
        .unwrap();
    assert_eq!(
        open.trim(),
        "f",
        "PUBLIC can still read every database's locks in {db}"
    );
}

/// I-82, design section 9.3, ADR-011 `PrivilegeAudit`: the auditor reads
/// view grants. A G14 view granted back to PUBLIC must change what the
/// auditor reports. Today `read_catalogue` reads no view grant, so the
/// graph before and after the seeded grant is the same.
#[test]
fn review_auditor_sees_a_regranted_g14_view() {
    let server = PgServer::start().unwrap();
    let params = server.fresh_database().unwrap();
    server.psql(&params.dbname, G14_REVOKE_SQL).unwrap();
    let tls = ClientTls::new(
        params.server_ca_pem,
        Role::Superuser.client_cert_pem(),
        Role::Superuser.client_key_pem(),
    )
    .unwrap();
    let cfg = Config::new(
        params.host.clone(),
        params.port,
        Role::Superuser.name(),
        Password::new(server.password(Role::Superuser)).unwrap(),
        params.dbname.clone(),
        tls,
    )
    .unwrap()
    .connect_timeout(Some(Duration::from_secs(20)));
    let mut c = rt().block_on(Client::connect(rt(), &cfg)).unwrap();
    let before = privilege_graph(&rt().block_on(read_catalogue(&mut c)).unwrap()).unwrap();
    server
        .psql(
            &params.dbname,
            "GRANT SELECT ON pg_catalog.pg_stat_activity TO PUBLIC",
        )
        .unwrap();
    let after = privilege_graph(&rt().block_on(read_catalogue(&mut c)).unwrap()).unwrap();
    assert_ne!(
        before, after,
        "the auditor does not see pg_stat_activity granted back to PUBLIC"
    );
}
