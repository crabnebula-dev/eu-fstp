//! I-82, design sections 4.1, 9.2 and 9.3, ADR-011: the provisioning jobs
//! and the isolation auditor against a real PostgreSQL 16 server.
//!
//! The jobs of `fstp_control::provision` run as `fstp-pgagent` would run
//! them, with psql standing in for the agent's superuser session. The
//! application migrations of `fstp-pgstore` run as the cell's migrator in
//! between. The tests then read the server's own catalogue:
//!
//! - every table privilege of every cell role equals the plan's grant
//!   rows, and nothing else;
//! - every database privilege of the cell's database equals the plan's
//!   rows, with nothing for PUBLIC;
//! - no cell role can create an extension;
//! - the jobs run again without error;
//! - the auditor's `fstp-pgwire` reader returns the rows psql reads, and
//!   its graph shows a seeded cross-cell grant.
//!
//! Lane W2h implementer.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;

use fstp_control::isolation_audit::{privilege_graph, read_catalogue};
use fstp_control::pg::{CellDatabase, Privilege, cell_role_plan, database_name, role_name};
use fstp_control::pgagent::{PgagentJob, job_statements};
use fstp_control::placement::{Cluster, ClusterId, ClusterKind, Placement};
use fstp_control::provision::{database_jobs, grant_jobs};
use fstp_cp_proto::{CellId, RoleName};
use fstp_pgtest::{PgServer, Role};
use fstp_pgwire::{Client, ClientTls, Config, Password};
use fstp_rt::tokio::TokioRuntime;

fn rt() -> &'static TokioRuntime {
    static RT: OnceLock<TokioRuntime> = OnceLock::new();
    RT.get_or_init(|| TokioRuntime::new_multi_thread(2).unwrap())
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

/// Runs `job` on `server` as the agent would. A `CREATE DATABASE` whose
/// database exists already counts as done.
fn run(server: &PgServer, job: &PgagentJob) {
    for s in job_statements(job).unwrap_or_else(|e| panic!("{job:?}: {e}")) {
        match server.psql(&s.target.database_name(), &s.sql) {
            Ok(_) => {}
            Err(e) if s.done_if_duplicate_database && e.to_string().contains("already exists") => {}
            Err(e) => panic!("{job:?}: {}: {e}", s.sql),
        }
    }
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

/// Provisions the application database of `cell` on `server`: the jobs of
/// step 4, `HardenCluster` first among them, the migrations as the
/// migrator, then the grants of step 7.
fn provision_app(server: &PgServer, cell: CellId) {
    let p = placement();
    let (app, _) = p.clusters();
    for (cluster, job) in database_jobs(cell, &p) {
        if cluster == app {
            run(server, &job);
        }
    }
    let db = database_name(CellDatabase::App, cell);
    let migrator = role_name(CellDatabase::App, cell, RoleName::Migrator).unwrap();
    for file in app_migrations() {
        let sql = std::fs::read_to_string(&file).unwrap();
        server
            .psql(&db, &format!("SET ROLE \"{migrator}\";\n{sql}"))
            .unwrap_or_else(|e| panic!("{}: {e}", file.display()));
    }
    for (cluster, job) in grant_jobs(cell, &p) {
        if cluster == app {
            run(server, &job);
        }
    }
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

/// I-82, design section 4.1, ADR-011: after the provisioning jobs and the
/// migrations, the table privileges of the cell's roles are exactly the
/// plan's application grant rows, and the database privileges are
/// exactly the plan's rows. PUBLIC holds nothing on the database.
#[test]
fn i82_provisioning_jobs_grant_exactly_the_plan() {
    let server = PgServer::start().unwrap();
    let cell = CellId([0x3e; 16]);
    provision_app(&server, cell);
    let db = database_name(CellDatabase::App, cell);
    let plan = cell_role_plan(cell).unwrap();

    let keyword = |p: Privilege| match p {
        Privilege::Select => "SELECT",
        Privilege::Insert => "INSERT",
        Privilege::Update => "UPDATE",
        Privilege::Delete => "DELETE",
    };
    let want: BTreeSet<String> = plan
        .grants
        .iter()
        .filter(|g| g.database == CellDatabase::App)
        .flat_map(|g| {
            let role = role_name(CellDatabase::App, cell, g.role).unwrap();
            g.privileges
                .iter()
                .map(move |p| format!("{role}|{}|{}", g.object, keyword(*p)))
        })
        .collect();
    let got = lines(
        &server,
        &db,
        &format!(
            "SELECT r.rolname || '|' || n.nspname || '.' || c.relname || '|' || a.privilege_type \
             FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
             CROSS JOIN LATERAL aclexplode(c.relacl) a JOIN pg_roles r ON r.oid = a.grantee \
             WHERE r.rolname LIKE 'c\\_{}\\_%' AND r.rolname <> '{}'",
            fstp_control::pg::cell_hex(cell),
            role_name(CellDatabase::App, cell, RoleName::Migrator).unwrap()
        ),
    );
    assert_eq!(
        got.difference(&want).collect::<Vec<_>>(),
        Vec::<&String>::new(),
        "granted beyond the plan"
    );
    assert_eq!(
        want.difference(&got).collect::<Vec<_>>(),
        Vec::<&String>::new(),
        "planned but not granted"
    );

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
        &server,
        "postgres",
        &format!(
            "SELECT CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE r.rolname END || '|' || a.privilege_type \
             FROM pg_database d CROSS JOIN LATERAL aclexplode(d.datacl) a \
             LEFT JOIN pg_roles r ON r.oid = a.grantee \
             WHERE d.datname = '{db}' AND a.grantee <> d.datdba"
        ),
    );
    assert_eq!(got_db, want_db);
}

/// I-82, design section 4.1: no cell role can create an extension in its
/// database, the migrator included, though it holds CREATE there.
#[test]
fn i82_extension_guard_refuses_create_extension() {
    let server = PgServer::start().unwrap();
    let cell = CellId([0x4f; 16]);
    provision_app(&server, cell);
    let db = database_name(CellDatabase::App, cell);
    for role in [RoleName::Migrator, RoleName::App] {
        let name = role_name(CellDatabase::App, cell, role).unwrap();
        let err = server
            .psql(
                &db,
                &format!("SET ROLE \"{name}\";\nCREATE EXTENSION pg_trgm;"),
            )
            .expect_err("a cell role created an extension");
        // The guard fires before the privilege check, so every role meets
        // it, the migrator with its CREATE privilege included.
        assert!(
            err.to_string().contains("extensions are refused"),
            "{role:?}: {err}"
        );
    }
    let ext = lines(&server, &db, "SELECT extname FROM pg_extension");
    assert_eq!(ext, BTreeSet::from(["plpgsql".to_owned()]));
}

/// ADR-011: every job is idempotent. The provisioning jobs run a second
/// time without error and leave the same grants.
#[test]
fn adr011_provisioning_jobs_run_again() {
    let server = PgServer::start().unwrap();
    let cell = CellId([0x5a; 16]);
    provision_app(&server, cell);
    let db = database_name(CellDatabase::App, cell);
    let grants = "SELECT count(*) FROM pg_class c CROSS JOIN LATERAL aclexplode(c.relacl) a";
    let before = lines(&server, &db, grants);
    let p = placement();
    let (app, _) = p.clusters();
    for (cluster, job) in database_jobs(cell, &p)
        .into_iter()
        .chain(grant_jobs(cell, &p))
    {
        if cluster == app {
            run(&server, &job);
        }
    }
    assert_eq!(lines(&server, &db, grants), before);
}

fn superuser_session(server: &PgServer) -> Client<TokioRuntime> {
    let db = server.fresh_database().unwrap();
    let tls = ClientTls::new(
        db.server_ca_pem,
        Role::Superuser.client_cert_pem(),
        Role::Superuser.client_key_pem(),
    )
    .unwrap();
    let cfg = Config::new(
        db.host.clone(),
        db.port,
        Role::Superuser.name(),
        Password::new(server.password(Role::Superuser)).unwrap(),
        db.dbname.clone(),
        tls,
    )
    .unwrap()
    .connect_timeout(Some(Duration::from_secs(20)));
    rt().block_on(Client::connect(rt(), &cfg))
        .unwrap_or_else(|e| panic!("the superuser session did not start: {e}"))
}

/// I-82, design section 9.3: the auditor's `fstp-pgwire` reader returns
/// the roles, memberships and database grants that psql reads, and the
/// graph of what it reads shows a seeded CONNECT grant from one cell's
/// role on another cell's database.
#[test]
fn i82_catalogue_reader_matches_the_server_and_finds_a_seeded_grant() {
    let server = PgServer::start().unwrap();
    let (a, b) = (CellId([0x61; 16]), CellId([0x62; 16]));
    provision_app(&server, a);
    provision_app(&server, b);
    let a_app = role_name(CellDatabase::App, a, RoleName::App).unwrap();
    let b_db = database_name(CellDatabase::App, b);
    let mut c = superuser_session(&server);

    let rows = rt().block_on(read_catalogue(&mut c)).unwrap();
    let roles: BTreeSet<String> = rows
        .catalogue
        .roles
        .iter()
        .map(|r| r.name.clone())
        .collect();
    assert_eq!(
        roles,
        lines(&server, "postgres", "SELECT rolname FROM pg_roles")
    );
    let grants: BTreeSet<String> = rows
        .catalogue
        .database_grants
        .iter()
        .map(|g| format!("{}|{}|{}", g.database, g.grantee, g.privilege))
        .collect();
    let want = lines(
        &server,
        "postgres",
        "SELECT d.datname || '|' || CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE g.rolname END \
         || '|' || a.privilege_type FROM pg_database d \
         CROSS JOIN LATERAL aclexplode(coalesce(d.datacl, acldefault('d', d.datdba))) a \
         LEFT JOIN pg_roles g ON g.oid = a.grantee",
    );
    assert_eq!(grants, want);
    assert!(!rows.catalogue.hba.is_empty(), "no pg_hba rule was read");
    let superusers: Vec<&str> = rows
        .catalogue
        .roles
        .iter()
        .filter(|r| r.superuser)
        .map(|r| r.name.as_str())
        .collect();
    assert!(!superusers.is_empty());

    let reaches = |g: &fstp_control::isolation_audit::PrivilegeGraph| {
        g.edges.iter().any(|e| e.from == a_app && e.to == b_db)
    };
    assert!(!reaches(&privilege_graph(&rows).unwrap()));
    server
        .psql(
            "postgres",
            &format!("GRANT CONNECT ON DATABASE \"{b_db}\" TO \"{a_app}\""),
        )
        .unwrap();
    let after = rt().block_on(read_catalogue(&mut c)).unwrap();
    assert!(reaches(&privilege_graph(&after).unwrap()));
}

/// A superuser `fstp-pgwire` session on the database `dbname`.
fn superuser_session_on(server: &PgServer, dbname: &str) -> Client<TokioRuntime> {
    let params = server.fresh_database().unwrap();
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
        dbname.to_owned(),
        tls,
    )
    .unwrap()
    .connect_timeout(Some(Duration::from_secs(20)));
    rt().block_on(Client::connect(rt(), &cfg))
        .unwrap_or_else(|e| panic!("the superuser session on {dbname} did not start: {e}"))
}

/// I-82, design sections 4.1 and 9.3, G14: after provisioning, the
/// auditor finds no G14 view or function open to PUBLIC in the cell's
/// database, in `postgres` or in `template1`. A view and a function
/// granted back then appear as their own edges.
#[test]
fn i82_auditor_reports_open_g14_objects_by_name() {
    let server = PgServer::start().unwrap();
    let cell = CellId([0x63; 16]);
    provision_app(&server, cell);
    let db = database_name(CellDatabase::App, cell);
    for name in [db.as_str(), "postgres", "template1"] {
        let mut c = superuser_session_on(&server, name);
        let open = rt()
            .block_on(fstp_control::isolation_audit::read_open_g14(&mut c))
            .unwrap();
        assert_eq!(open, Vec::new(), "{name}");
    }
    server
        .psql(
            &db,
            "GRANT SELECT ON pg_catalog.pg_locks TO PUBLIC;\n\
             GRANT EXECUTE ON FUNCTION pg_catalog.pg_stat_get_backend_idset() TO PUBLIC;",
        )
        .unwrap();
    let mut c = superuser_session_on(&server, &db);
    let rows = rt().block_on(read_catalogue(&mut c)).unwrap();
    let graph = privilege_graph(&rows).unwrap();
    for (to, via) in [
        (format!("view:{db}.pg_locks"), "SELECT"),
        (
            format!("function:{db}.pg_stat_get_backend_idset()"),
            "EXECUTE",
        ),
    ] {
        assert!(
            graph
                .edges
                .iter()
                .any(|e| e.from == "PUBLIC" && e.to == to && e.via == via),
            "no edge PUBLIC -> {to}: {:#?}",
            rows.open_g14
        );
    }
    assert_eq!(rows.open_g14.len(), 2, "{:#?}", rows.open_g14);
}

/// I-82, design section 4.1: after provisioning, PUBLIC holds no
/// privilege on `postgres`, `template1` or `template0`.
#[test]
fn i82_provisioning_revokes_public_on_the_initdb_databases() {
    let server = PgServer::start().unwrap();
    provision_app(&server, CellId([0x64; 16]));
    let open = lines(
        &server,
        "postgres",
        "SELECT d.datname || '|' || a.privilege_type FROM pg_database d \
         CROSS JOIN LATERAL aclexplode(coalesce(d.datacl, acldefault('d', d.datdba))) a \
         WHERE a.grantee = 0 AND d.datname IN ('postgres', 'template1', 'template0')",
    );
    assert_eq!(open, BTreeSet::new());
}

/// I-82, design section 9.3: the auditor reads each database's owner, so
/// a role that owns a database reaches it even with no ACL entry.
#[test]
fn i82_auditor_shows_the_owner_of_a_database() {
    let server = PgServer::start().unwrap();
    let (a, b) = (CellId([0x65; 16]), CellId([0x66; 16]));
    provision_app(&server, a);
    provision_app(&server, b);
    let a_app = role_name(CellDatabase::App, a, RoleName::App).unwrap();
    let b_db = database_name(CellDatabase::App, b);
    let owned = |rows: &fstp_control::isolation_audit::AuditRows| {
        privilege_graph(rows)
            .unwrap()
            .edges
            .iter()
            .any(|e| e.from == a_app && e.to == b_db && e.via == "owner")
    };
    let mut c = superuser_session(&server);
    assert!(!owned(&rt().block_on(read_catalogue(&mut c)).unwrap()));
    server
        .psql(
            "postgres",
            &format!(
                "ALTER DATABASE \"{b_db}\" OWNER TO \"{a_app}\";\n\
                 REVOKE ALL ON DATABASE \"{b_db}\" FROM \"{a_app}\";"
            ),
        )
        .unwrap();
    assert!(owned(&rt().block_on(read_catalogue(&mut c)).unwrap()));
}

/// I-82, design section 4.1, ADR-011 `CreateRoles`: a role of a plan name
/// that exists already with elevated attributes loses them when the job
/// runs.
#[test]
fn i82_create_roles_strips_attributes_of_an_existing_role() {
    let server = PgServer::start().unwrap();
    let cell = CellId([0x67; 16]);
    let app = role_name(CellDatabase::App, cell, RoleName::App).unwrap();
    server
        .psql(
            "postgres",
            &format!(
                "CREATE ROLE \"{app}\" SUPERUSER CREATEDB CREATEROLE REPLICATION BYPASSRLS NOINHERIT"
            ),
        )
        .unwrap();
    provision_app(&server, cell);
    let attrs = lines(
        &server,
        "postgres",
        &format!(
            "SELECT rolsuper::text || rolcreatedb::text || rolcreaterole::text || \
             rolreplication::text || rolbypassrls::text || rolinherit::text \
             FROM pg_roles WHERE rolname = '{app}'"
        ),
    );
    assert_eq!(
        attrs,
        BTreeSet::from(["falsefalsefalsefalsefalsetrue".to_owned()])
    );
}

/// I-82, design section 4.1, ADR-011 `CreateRoles`: a role of a plan name
/// that holds a membership, or has a member, is refused, and the job
/// fails.
#[test]
fn i82_create_roles_refuses_a_role_with_a_membership() {
    let server = PgServer::start().unwrap();
    let cell = CellId([0x68; 16]);
    let writer = role_name(CellDatabase::App, cell, RoleName::Writer).unwrap();
    let keys = role_name(CellDatabase::App, cell, RoleName::Keys).unwrap();
    let d = fstp_control::pgagent::DbIdent::new(CellDatabase::App, cell);
    for seed in [
        format!("CREATE ROLE \"{writer}\" NOLOGIN; GRANT pg_read_all_stats TO \"{writer}\";"),
        format!(
            "DROP ROLE \"{writer}\"; CREATE ROLE \"{keys}\" NOLOGIN; \
             CREATE ROLE fstp_intruder NOLOGIN; GRANT \"{keys}\" TO fstp_intruder;"
        ),
    ] {
        server.psql("postgres", &seed).unwrap();
        let refused = job_statements(&PgagentJob::CreateRoles(d))
            .unwrap()
            .iter()
            .map(|s| server.psql(&s.target.database_name(), &s.sql))
            .find_map(Result::err)
            .unwrap_or_else(|| panic!("CreateRoles accepted a membership after {seed}"));
        assert!(
            refused.to_string().contains("membership outside the plan"),
            "{refused}"
        );
    }
}
