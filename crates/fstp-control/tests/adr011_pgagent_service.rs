//! ADR-011, I-82, I-83, R-NF-09: the `fstp-pgagent` service against a real
//! PostgreSQL 16 server, over its mutual TLS listener.
//!
//! `fstp-control`'s side of the link sends typed jobs through
//! `fstp_control::agent::send_job`, with a client certificate from a test
//! control-plane CA. The agent runs each job as `fstp_super` through
//! `fstp_pgwire::Client::execute_rendered_ddl`. The tests then read the
//! server's own catalogue and check it against `cell_role_plan`:
//!
//! - the jobs of design section 9.2 steps 4 and 7 grant exactly the
//!   plan's rows, run again without error, and `WriteHba` loads one line
//!   per planned role into `pg_hba_file_rules`;
//! - a job for the other cluster kind, a destructive job and a peer that
//!   is not `fstp-control` are refused before any SQL runs;
//! - an agent whose server presents another kind's OU refuses to work on
//!   it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::OnceLock;

use fstp_control::agent::{AgentParts, JobOutcome, JobRefusal, PgLogin, send_job, serve};
use fstp_control::pg::{CellDatabase, CellSubnet, cell_role_plan, database_name, role_name};
use fstp_control::pgagent::{DbIdent, PgagentJob};
use fstp_control::placement::{Cluster, ClusterId, ClusterKind, Placement};
use fstp_control::provision::{database_jobs, grant_jobs};
use fstp_cp_proto::{CellId, RoleName};
use fstp_pgtest::certs::ClusterCa;
use fstp_pgtest::{PgServer, Role};
use fstp_rt::tokio::TokioRuntime;
use fstp_rt::{Listener, Runtime, Shutdown};

fn rt() -> &'static TokioRuntime {
    static RT: OnceLock<TokioRuntime> = OnceLock::new();
    RT.get_or_init(|| TokioRuntime::new_multi_thread(2).unwrap())
}

/// The test control-plane CA, and the certificates it issues.
struct Pki {
    ca: ClusterCa,
}

fn pki() -> &'static Pki {
    static PKI: OnceLock<Pki> = OnceLock::new();
    PKI.get_or_init(|| Pki {
        ca: ClusterCa::generate("fstp test control plane CA").unwrap(),
    })
}

/// The application server of these tests, with `application` as its OU.
fn server() -> &'static PgServer {
    PgServer::shared_named("agentapp", "application").unwrap_or_else(|e| panic!("{e}"))
}

/// The server's `pg_hba.conf` path, as it reports it.
fn hba_file(server: &PgServer) -> String {
    server.psql("postgres", "SHOW hba_file").unwrap()
}

/// Starts an agent of `kind` for `server` on a free loopback port, and
/// returns its address. The agent runs for the rest of the test binary.
fn start_agent(server: &'static PgServer, kind: ClusterKind) -> SocketAddr {
    let login = server.fresh_database_as(Role::Superuser).unwrap();
    // The harness issues server certificates with a cluster kind OU only.
    let issued = pki().ca.issue_server("control").unwrap();
    let parts = AgentParts {
        cluster_kind: kind,
        cell_subnet: CellSubnet::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 32).unwrap(),
        hba_file: hba_file(server),
        listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        control_ca_pem: pki().ca.cert_pem().to_vec(),
        cert_pem: issued.cert_pem,
        key_pem: issued.key_pem,
        pg: PgLogin {
            port: login.port,
            server_ca_pem: login.server_ca_pem.to_vec(),
            client_cert_pem: login.client_cert_pem.to_vec(),
            client_key_pem: login.client_key_pem.to_vec(),
            password: login.password.clone(),
        },
    };
    let listener = rt().block_on(rt().bind_tcp(parts.listen)).unwrap();
    let addr = listener.local_addr().unwrap();
    // The shutdown lives as long as the test binary, so the agent serves
    // until the process ends.
    let shutdown: &'static Shutdown = Box::leak(Box::new(Shutdown::new()));
    let signal = shutdown.signal();
    drop(rt().spawn(async move {
        serve(rt().clone(), &parts, listener, signal).await.unwrap();
    }));
    addr
}

fn app_agent() -> SocketAddr {
    static ADDR: OnceLock<SocketAddr> = OnceLock::new();
    *ADDR.get_or_init(|| start_agent(server(), ClusterKind::Application))
}

/// The client TLS of `fstp-control` towards the agent: it trusts the
/// control-plane CA, which issued the agent's certificate, and presents a
/// certificate whose CN is `cn`, issued by `ca`.
fn control_tls(ca: &ClusterCa, cn: &str) -> fstp_tls::ClientConfig {
    let me = ca.issue_role(cn).unwrap();
    fstp_tls::ClientConfig::mutual(pki().ca.cert_pem(), &me.cert_pem, &me.key_pem).unwrap()
}

fn send(addr: SocketAddr, tls: &fstp_tls::ClientConfig, job: &PgagentJob) -> JobOutcome {
    rt().block_on(send_job(rt(), addr, "localhost", tls, job))
        .unwrap_or_else(|e| panic!("{job:?}: {e}"))
}

fn placement() -> Placement {
    Placement::new(
        &Cluster {
            id: ClusterId([1; 16]),
            kind: ClusterKind::Application,
        },
        &Cluster {
            id: ClusterId([2; 16]),
            kind: ClusterKind::Vault,
        },
    )
    .unwrap()
}

/// The `.sql` files of the application migration set, in order.
fn app_migrations() -> Vec<PathBuf> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../fstp-pgstore/migrations/app");
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "sql"))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no migrations in {}", dir.display());
    files
}

fn lines(server: &PgServer, db: &str, sql: &str) -> BTreeSet<String> {
    server
        .psql(db, sql)
        .unwrap_or_else(|e| panic!("{sql}: {e}"))
        .lines()
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Provisions the application database of `cell` through the agent: the
/// jobs of step 4, the migrations as the migrator (psql stands in for the
/// cell's migrator, only when `migrate` is set), the grants of step 7,
/// then `WriteHba`.
fn provision_app_through_agent(cell: CellId, migrate: bool) {
    let addr = app_agent();
    let tls = control_tls(&pki().ca, "fstp_control");
    let p = placement();
    let (app, _) = p.clusters();
    for (cluster, job) in database_jobs(cell, &p) {
        if cluster == app {
            assert_eq!(send(addr, &tls, &job), JobOutcome::Done, "{job:?}");
        }
    }
    let db = database_name(CellDatabase::App, cell);
    let migrator = role_name(CellDatabase::App, cell, RoleName::Migrator).unwrap();
    for file in app_migrations().into_iter().filter(|_| migrate) {
        let sql = std::fs::read_to_string(&file).unwrap();
        server()
            .psql(&db, &format!("SET ROLE \"{migrator}\";\n{sql}"))
            .unwrap_or_else(|e| panic!("{}: {e}", file.display()));
    }
    for (cluster, job) in grant_jobs(cell, &p) {
        if cluster == app {
            assert_eq!(send(addr, &tls, &job), JobOutcome::Done, "{job:?}");
        }
    }
    assert_eq!(send(addr, &tls, &PgagentJob::WriteHba), JobOutcome::Done);
}

/// I-82, ADR-011, design sections 4.1 and 9.2: jobs sent over the agent's
/// mutual TLS link leave the cell's table privileges, database privileges
/// and `pg_hba` lines exactly as `cell_role_plan` states them. PUBLIC
/// holds nothing on the database. Every job runs again without error.
#[test]
fn i82_pgagent_applies_the_role_plan_over_mutual_tls() {
    let cell = CellId([0xa7; 16]);
    provision_app_through_agent(cell, true);
    let server = server();
    let db = database_name(CellDatabase::App, cell);
    let plan = cell_role_plan(cell).unwrap();
    let hex = fstp_control::pg::cell_hex(cell);
    let migrator = role_name(CellDatabase::App, cell, RoleName::Migrator).unwrap();

    let want: BTreeSet<String> = plan
        .grants
        .iter()
        .filter(|g| g.database == CellDatabase::App)
        .flat_map(|g| {
            let role = role_name(CellDatabase::App, cell, g.role).unwrap();
            g.privileges
                .iter()
                .map(move |p| format!("{role}|{}|{}", g.object, p.keyword()))
        })
        .collect();
    let got = lines(
        server,
        &db,
        &format!(
            "SELECT r.rolname || '|' || n.nspname || '.' || c.relname || '|' || a.privilege_type \
             FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
             CROSS JOIN LATERAL aclexplode(c.relacl) a JOIN pg_roles r ON r.oid = a.grantee \
             WHERE r.rolname LIKE 'c\\_{hex}\\_%' AND r.rolname <> '{migrator}'"
        ),
    );
    assert_eq!(got, want, "table privileges differ from the plan");

    let want_db: BTreeSet<String> = plan
        .database_privileges
        .iter()
        .filter(|p| p.database == CellDatabase::App)
        .map(|p| {
            format!(
                "{}|{}",
                role_name(CellDatabase::App, cell, p.role).unwrap(),
                p.privilege.keyword()
            )
        })
        .collect();
    let got_db = lines(
        server,
        "postgres",
        &format!(
            "SELECT CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE r.rolname END || '|' || a.privilege_type \
             FROM pg_database d CROSS JOIN LATERAL aclexplode(d.datacl) a \
             LEFT JOIN pg_roles r ON r.oid = a.grantee \
             WHERE d.datname = '{db}' AND a.grantee <> d.datdba"
        ),
    );
    assert_eq!(got_db, want_db, "database privileges differ from the plan");

    let want_hba: BTreeSet<String> = plan
        .hba
        .iter()
        .filter(|h| h.database == CellDatabase::App)
        .map(|h| {
            format!(
                "{db}|{}|127.0.0.1|255.255.255.255|scram-sha-256|clientcert=verify-full",
                role_name(CellDatabase::App, cell, h.role).unwrap()
            )
        })
        .collect();
    let got_hba = lines(
        server,
        "postgres",
        &format!(
            "SELECT array_to_string(database, ',') || '|' || array_to_string(user_name, ',') \
             || '|' || address || '|' || netmask || '|' || auth_method || '|' \
             || array_to_string(options, ',') FROM pg_hba_file_rules \
             WHERE type = 'hostssl' AND '{db}' = ANY(database) AND error IS NULL"
        ),
    );
    assert_eq!(got_hba, want_hba, "pg_hba lines differ from the plan");
    let errors = server
        .psql(
            "postgres",
            "SELECT count(*) FROM pg_hba_file_rules WHERE error IS NOT NULL",
        )
        .unwrap();
    assert_eq!(errors, "0");

    // ADR-011: every job is idempotent.
    let before = got;
    provision_app_through_agent(cell, false);
    let again = lines(
        server,
        &db,
        &format!(
            "SELECT r.rolname || '|' || n.nspname || '.' || c.relname || '|' || a.privilege_type \
             FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
             CROSS JOIN LATERAL aclexplode(c.relacl) a JOIN pg_roles r ON r.oid = a.grantee \
             WHERE r.rolname LIKE 'c\\_{hex}\\_%' AND r.rolname <> '{migrator}'"
        ),
    );
    assert_eq!(again, before);
}

/// I-83, ADR-011: an agent on an application cluster refuses a vault
/// database job before any SQL runs, so the vault database never exists
/// there.
#[test]
fn i83_pgagent_refuses_a_vault_job_on_an_application_cluster() {
    let cell = CellId([0xb3; 16]);
    let tls = control_tls(&pki().ca, "fstp_control");
    let job = PgagentJob::CreateCellDatabase(DbIdent::new(CellDatabase::Vault, cell));
    assert_eq!(
        send(app_agent(), &tls, &job),
        JobOutcome::Refused(JobRefusal::ClusterKind)
    );
    let db = database_name(CellDatabase::Vault, cell);
    let found = server()
        .psql(
            "postgres",
            &format!("SELECT count(*) FROM pg_database WHERE datname = '{db}'"),
        )
        .unwrap();
    assert_eq!(found, "0");
}

/// ADR-011 "Two-operator approval": destructive jobs are refused until the
/// two-operator check exists, and the audit job is refused as not built,
/// since its rows have no transport yet.
#[test]
fn adr011_pgagent_refuses_destructive_jobs() {
    let cell = CellId([0xc4; 16]);
    let tls = control_tls(&pki().ca, "fstp_control");
    let d = DbIdent::new(CellDatabase::App, cell);
    for job in [
        PgagentJob::DropCellDatabase(d),
        PgagentJob::DropRoles(d),
        PgagentJob::SetNoLogin(fstp_control::pgagent::RoleIdent::new(d, RoleName::App).unwrap()),
    ] {
        assert_eq!(
            send(app_agent(), &tls, &job),
            JobOutcome::Refused(JobRefusal::ApprovalRequired),
            "{job:?}"
        );
    }
    assert_eq!(
        send(app_agent(), &tls, &PgagentJob::PrivilegeAudit),
        JobOutcome::Refused(JobRefusal::NotBuilt)
    );
}

/// R-NF-09, ADR-011: the agent answers only `fstp-control`. A cell's
/// certificate from the same CA gets no reply, a certificate from another
/// CA fails the handshake, and a client without a certificate fails it
/// too. None of them runs a job.
#[test]
fn r_nf_09_pgagent_accepts_only_fstp_control_from_the_control_ca() {
    let addr = app_agent();
    let cell = CellId([0xd5; 16]);
    let job = PgagentJob::CreateCellDatabase(DbIdent::new(CellDatabase::App, cell));
    let as_cell = control_tls(&pki().ca, &format!("cell_{}", "d5".repeat(16)));
    let rogue_ca = ClusterCa::generate("rogue CA").unwrap();
    let rogue = control_tls(&rogue_ca, "fstp_control");
    let anonymous = fstp_tls::ClientConfig::new(pki().ca.cert_pem()).unwrap();
    for tls in [&as_cell, &rogue, &anonymous] {
        let r = rt().block_on(send_job(rt(), addr, "localhost", tls, &job));
        assert!(r.is_err(), "{r:?}");
    }
    let db = database_name(CellDatabase::App, cell);
    let found = server()
        .psql(
            "postgres",
            &format!("SELECT count(*) FROM pg_database WHERE datname = '{db}'"),
        )
        .unwrap();
    assert_eq!(found, "0");
}

/// I-83, design section 1.3: an agent configured as a vault agent refuses
/// a server whose certificate OU says `application`, so it never creates a
/// vault database on an application cluster even when misconfigured.
#[test]
fn i83_pgagent_refuses_a_server_of_another_kind() {
    let addr = start_agent(server(), ClusterKind::Vault);
    let tls = control_tls(&pki().ca, "fstp_control");
    let cell = CellId([0xe6; 16]);
    let job = PgagentJob::CreateCellDatabase(DbIdent::new(CellDatabase::Vault, cell));
    assert_eq!(send(addr, &tls, &job), JobOutcome::Failed);
    let db = database_name(CellDatabase::Vault, cell);
    let found = server()
        .psql(
            "postgres",
            &format!("SELECT count(*) FROM pg_database WHERE datname = '{db}'"),
        )
        .unwrap();
    assert_eq!(found, "0");
}
