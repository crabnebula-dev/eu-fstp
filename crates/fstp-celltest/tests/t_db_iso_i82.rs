//! T-DB-ISO for I-82: no database role can read across databases of
//! different cells (design section 14.4, ADR-005, B7).
//!
//! Every login role of cells A, B and C, on shared and on dedicated
//! servers, is taken over as an attacker who holds its credentials would
//! hold them: the test sets a known password and mints a certificate for
//! the role from its own cluster CA. No privilege changes. The role then
//! tries every other cell's database on every self-operated cluster, and
//! from its own database every escape path of design section 14.4:
//! `dblink` and `postgres_fdw`, `pg_read_file`, `COPY ... PROGRAM`,
//! `lo_import` and other sessions' query text in `pg_stat_activity`. It
//! also tries `SET ROLE` to a role with an attribute that design section
//! 4.1 denies, and the cross-database statistics views that G14 revokes.
//!
//! Lane W1f wrote these tests before the production code. They are red
//! until the cell runtime (lane W3a) provisions cells through the control
//! plane (lane W2h).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_celltest::mc::place_model::db::{self, Credential};
use fstp_celltest::world::{ClusterHandle, ClusterKind, DbMode, VaultLayout, World, WorldSpec};

fn world(mode: DbMode) -> World {
    World::start(WorldSpec {
        cells: 3,
        mode,
        vault_layout: VaultLayout::SeparateCluster,
        self_hosted: false,
        process_mode: false,
    })
    .unwrap_or_else(|e| panic!("the world did not start: {e}"))
}

fn ca_pem(c: &ClusterHandle) -> Vec<u8> {
    c.server()
        .cluster_ca()
        .expect("a world cluster has its own cluster CA")
        .cert_pem()
        .to_vec()
}

/// The escape paths a role must not take from its own database, each with
/// a statement that prints a row only when the path is open.
///
/// - COPY FROM a server file needs a table, and every cell database
///   revokes TEMPORARY. The probe therefore tests the effective right:
///   membership of `pg_read_server_files`, directly or through other
///   roles, which a superuser also has.
/// - `dblink` and `postgres_fdw` are untrusted, so only a superuser
///   installs them. Each probe also reports the extension when it is
///   already installed, since design section 4.1 requires it absent.
/// - A trusted extension, such as `pgcrypto`, installs for any role with
///   CREATE on the database. The probe rolls it back.
/// - The query-text probe needs another role's session. The sweep holds
///   one open on every cluster while it probes ([`HeldSession`]).
/// - A member of a role can `SET ROLE` to it, since PostgreSQL 16 gives a
///   grant the SET option by default. The probe reports every role the
///   current role can become that holds an attribute design section 4.1
///   denies, itself included.
/// - G14: the cross-database statistics views of [`G14_VIEWS`] are
///   revoked from PUBLIC. Each probe reports a row of another database or
///   another session. A refused SELECT prints nothing, so the path is
///   shut.
const ESCAPES: [(&str, &str); 14] = [
    (
        "COPY FROM a server file",
        "SELECT 'opened' WHERE pg_has_role(current_user, 'pg_read_server_files', 'MEMBER')",
    ),
    (
        "dblink",
        "CREATE EXTENSION IF NOT EXISTS dblink; \
         SELECT 'opened' FROM pg_extension WHERE extname = 'dblink'",
    ),
    (
        "postgres_fdw",
        "CREATE EXTENSION IF NOT EXISTS postgres_fdw; \
         SELECT 'opened' FROM pg_extension WHERE extname = 'postgres_fdw'",
    ),
    (
        "a trusted extension",
        "BEGIN; CREATE EXTENSION pgcrypto; ROLLBACK; SELECT 'opened'",
    ),
    (
        "an installed extension",
        "SELECT string_agg(extname, ',') FROM pg_extension WHERE extname <> 'plpgsql'",
    ),
    (
        "pg_read_file",
        "SELECT length(pg_read_file('postgresql.conf'))",
    ),
    (
        "COPY PROGRAM",
        "COPY (SELECT 1) TO PROGRAM 'true'; SELECT 'opened'",
    ),
    ("lo_import", "SELECT lo_import('/etc/hosts')"),
    (
        "pg_read_all_stats",
        "SELECT 'opened' WHERE pg_has_role(current_user, 'pg_read_all_stats', 'MEMBER')",
    ),
    (
        "other sessions' query text",
        "SELECT 1 FROM pg_stat_activity WHERE pid <> pg_backend_pid() \
         AND usename IS DISTINCT FROM current_user \
         AND query NOT IN ('', '<insufficient privilege>') LIMIT 1",
    ),
    (
        "SET ROLE to an elevated role",
        "SELECT string_agg(r.rolname, ',') FROM pg_roles r \
         WHERE pg_has_role(current_user, r.oid, 'SET') \
         AND (r.rolsuper OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication \
         OR r.rolbypassrls)",
    ),
    (
        "pg_stat_database",
        "SELECT 'opened' FROM pg_stat_database \
         WHERE datname IS DISTINCT FROM current_database() LIMIT 1",
    ),
    (
        "pg_stat_database_conflicts",
        "SELECT 'opened' FROM pg_stat_database_conflicts \
         WHERE datname IS DISTINCT FROM current_database() LIMIT 1",
    ),
    (
        "pg_stat_activity",
        "SELECT 'opened' FROM pg_stat_activity WHERE pid <> pg_backend_pid() LIMIT 1",
    ),
];

/// The cross-database statistics views that G14 revokes from PUBLIC
/// (design section 4.1), each with an ESCAPES probe of its name.
/// `pg_stat_ssl` and `pg_stat_gssapi` are not listed: in PostgreSQL 16
/// they show no row of another role's session to a role without
/// `pg_read_all_stats`, which the `pg_read_all_stats` probe covers.
///
/// Open question, raised by lane W1f: design section 4.1 names the views
/// only. The functions behind them, such as `pg_stat_get_activity` and
/// `pg_stat_get_db_xact_commit`, stay executable by PUBLIC and show the
/// same rows. Whether G14 revokes them too is Daniel's call.
const G14_VIEWS: [&str; 3] = [
    "pg_stat_database",
    "pg_stat_database_conflicts",
    "pg_stat_activity",
];

/// The G14 revocation that the role plan applies on every cluster, run in
/// `dbname`. A database copies the ACLs of its template, so the teeth run
/// it in `template1` before any cell database exists.
fn revoke_g14(server: &fstp_pgtest::PgServer, dbname: &str) {
    let views: Vec<String> = G14_VIEWS
        .iter()
        .map(|v| format!("pg_catalog.{v}"))
        .collect();
    server
        .psql(
            dbname,
            &format!("REVOKE SELECT ON {} FROM PUBLIC", views.join(", ")),
        )
        .unwrap();
}

/// A superuser session held open on one server, running a long query, so
/// that the query-text probe always has another role's session to read.
/// Dropping it ends the session.
struct HeldSession {
    server: &'static fstp_pgtest::PgServer,
    name: String,
    thread: Option<std::thread::JoinHandle<()>>,
}

static HELD: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

impl HeldSession {
    /// Opens the session and waits until `pg_stat_activity` shows it.
    fn open(server: &'static fstp_pgtest::PgServer) -> HeldSession {
        let n = HELD.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let name = format!("w1f_held_{}_{n}", std::process::id());
        let sql = format!("SET application_name = '{name}';\nSELECT pg_sleep(600);");
        let thread = std::thread::spawn(move || {
            // Ended by `drop`, so the error of the terminated session is
            // the expected outcome.
            let _ = server.psql("postgres", &sql);
        });
        let seen = format!(
            "SELECT count(*) FROM pg_stat_activity \
             WHERE application_name = '{name}' AND query LIKE '%pg_sleep%'"
        );
        let mut visible = false;
        for _ in 0..400 {
            if server.psql("postgres", &seen).is_ok_and(|n| n != "0") {
                visible = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        assert!(visible, "the held session {name} never showed");
        HeldSession {
            server,
            name,
            thread: Some(thread),
        }
    }
}

impl Drop for HeldSession {
    fn drop(&mut self) {
        let _ = self.server.psql(
            "postgres",
            &format!(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
                 WHERE application_name = '{}'",
                self.name
            ),
        );
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// The application and vault clusters of `w`.
fn cell_clusters(w: &World) -> Vec<&ClusterHandle> {
    w.clusters()
        .iter()
        .filter(|c| matches!(c.kind(), ClusterKind::Application | ClusterKind::Vault))
        .collect()
}

/// Runs the T-DB-ISO sweep over `clusters`, which hold `expected` cells,
/// and returns every breach, one line each. It also returns a breach when
/// a role cannot reach its own database, so the sweep is never vacuous.
fn sweep(clusters: &[&ClusterHandle], expected: usize) -> Vec<String> {
    let mut targets: Vec<(&ClusterHandle, String)> = Vec::new();
    for c in clusters {
        for d in db::databases(c.server()).unwrap() {
            if db::cell_of(&d).is_some() {
                targets.push((c, d));
            }
        }
    }
    let cells: std::collections::BTreeSet<&str> =
        targets.iter().filter_map(|(_, d)| db::cell_of(d)).collect();
    let mut breaches = Vec::new();
    if cells.len() != expected {
        breaches.push(format!("expected {expected} cells, found {cells:?}"));
    }
    let _held: Vec<HeldSession> = clusters
        .iter()
        .map(|c| HeldSession::open(c.server()))
        .collect();
    for home in clusters {
        let roles = db::cell_login_roles(home.server()).unwrap();
        if roles.is_empty() {
            breaches.push(format!("{} holds no cell login role", home.name()));
        }
        for role in roles {
            let own = db::cell_of(&role).unwrap().to_owned();
            let cred: Credential = db::take_over(home.server(), &role).unwrap();
            let mut reached_own = false;
            for (c, d) in &targets {
                let ca = ca_pem(c);
                let got = db::run_as(c.server(), &ca, &cred, true, d, "SELECT 1");
                let same_cell = db::cell_of(d) == Some(own.as_str());
                if !same_cell {
                    if let Ok(out) = got {
                        breaches.push(format!("{role} read {d} on {}: {out}", c.name()));
                    }
                    continue;
                }
                if got.is_err() {
                    continue;
                }
                reached_own = true;
                for (path, sql) in ESCAPES {
                    // An empty answer means no row: the path stayed shut.
                    if let Ok(out) = db::run_as(c.server(), &ca, &cred, true, d, sql)
                        && !out.is_empty()
                    {
                        breaches.push(format!("{role} took the {path} path from {d}: {out:?}"));
                    }
                }
            }
            if !reached_own {
                breaches.push(format!("{role} reaches no database of its own cell"));
            }
        }
    }
    breaches
}

/// I-82, T-DB-ISO, shared servers: every login role of three cells is
/// refused on every other cell's database, and takes no escape path from
/// its own.
#[test]
fn t_db_iso_i82_every_role_refused_on_foreign_cell_database() {
    let w = world(DbMode::Shared);
    let breaches = sweep(&cell_clusters(&w), 3);
    assert!(breaches.is_empty(), "{breaches:#?}");
}

/// I-82, T-DB-ISO, dedicated servers: the same sweep over cells with
/// clusters of their own.
#[test]
fn t_db_iso_i82_every_role_refused_on_foreign_cell_database_dedicated() {
    let w = world(DbMode::Dedicated);
    let breaches = sweep(&cell_clusters(&w), 3);
    assert!(breaches.is_empty(), "{breaches:#?}");
}

// ---------------------------------------------------------------------------
// Teeth for the sweep, over synthetic cells on a server of their own.

/// A fresh random cell hex.
fn random_hex() -> String {
    let mut raw = [0u8; 16];
    fstp_crypto::random_bytes(&mut raw).unwrap();
    fstp_celltest::mc::place_model::cell_hex(fstp_cp_proto::CellId(raw))
}

/// A named application cluster that only these teeth tests use, so a
/// seeded leak never reaches a world's cluster. It carries the G14
/// revocation, as the role plan applies it, so a clean cell takes no path.
fn teeth_cluster(name: &str) -> ClusterHandle {
    let c = ClusterHandle::start_named(ClusterKind::Application, name).unwrap();
    for dbname in ["template1", "postgres"] {
        revoke_g14(c.server(), dbname);
    }
    c
}

/// I-82 teeth, G14: on a cluster without the revocation a clean cell reads
/// the other cell's row of every [`G14_VIEWS`] view, and the sweep reports
/// each. So the revocation of [`teeth_cluster`] is what keeps the clean
/// cells of the other teeth clean.
#[test]
fn t_db_iso_i82_teeth_g14_views_without_the_revocation_are_caught() {
    let c = ClusterHandle::start_named(ClusterKind::Application, "w1f_teeth_g14").unwrap();
    let a = random_hex();
    synthetic_cell(&c, &a, &[]);
    let breaches = sweep(&[&c], 1);
    let mut missed = Vec::new();
    for view in G14_VIEWS {
        let want = format!("c_{a}_app took the {view} path");
        if !breaches.iter().any(|b| b.starts_with(&want)) {
            missed.push(want);
        }
    }
    assert!(missed.is_empty(), "missed {missed:#?} in {breaches:#?}");
}

/// Cell `hex` on `c`: its app role, and its database with CONNECT and a
/// `pg_hba` line for each of `roles`.
fn synthetic_cell(c: &ClusterHandle, hex: &str, extra_roles: &[&str]) {
    let role = format!("c_{hex}_app");
    c.server().create_login_role(&role).unwrap();
    let mut roles = vec![role.as_str()];
    roles.extend_from_slice(extra_roles);
    c.server()
        .create_database_for(&format!("c_{hex}"), &roles)
        .unwrap();
}

/// I-82 teeth: a CONNECT grant and a `pg_hba` line that let cell A's role
/// into cell B's database are reported by the sweep. Two clean cells give
/// no breach, so the sweep is not reporting everything.
#[test]
fn t_db_iso_i82_teeth_seeded_cross_cell_login_is_caught() {
    let c = teeth_cluster("w1f_teeth_login");
    let (a, b) = (random_hex(), random_hex());
    synthetic_cell(&c, &a, &[]);
    let clean = sweep(&[&c], 1);
    assert!(clean.is_empty(), "one clean cell gave breaches: {clean:#?}");
    let leaked = format!("c_{a}_app");
    synthetic_cell(&c, &b, &[&leaked]);
    let breaches = sweep(&[&c], 2);
    let want = format!("{leaked} read c_{b} on {}", c.name());
    assert!(
        breaches.iter().any(|x| x.starts_with(&want)),
        "the seeded login was not caught: {breaches:#?}"
    );
}

/// I-82 teeth: an EXECUTE grant on `pg_read_file` opens the server file
/// path, and the sweep reports it.
#[test]
fn t_db_iso_i82_teeth_seeded_server_file_read_is_caught() {
    let c = teeth_cluster("w1f_teeth_files");
    let a = random_hex();
    synthetic_cell(&c, &a, &[]);
    c.server()
        .psql(
            &format!("c_{a}"),
            &format!("GRANT EXECUTE ON FUNCTION pg_read_file(text) TO c_{a}_app"),
        )
        .unwrap();
    let breaches = sweep(&[&c], 1);
    assert!(
        breaches
            .iter()
            .any(|x| x.starts_with(&format!("c_{a}_app took the pg_read_file path"))),
        "the seeded file read was not caught: {breaches:#?}"
    );
}

/// The seeds of the escape teeth: each path, with the superuser SQL that
/// opens it for role `{role}` in database `{db}`. The teeth cluster
/// carries the G14 revocation, so the query-text seed grants SELECT on
/// `pg_stat_activity` too, and each G14 seed grants its view back.
const SEEDS: [(&str, &str, &str); 12] = [
    (
        "COPY FROM a server file",
        "postgres",
        "GRANT pg_read_server_files TO {role}",
    ),
    ("dblink", "{db}", "CREATE EXTENSION dblink"),
    ("postgres_fdw", "{db}", "CREATE EXTENSION postgres_fdw"),
    (
        "a trusted extension",
        "postgres",
        "GRANT CREATE ON DATABASE {db} TO {role}",
    ),
    (
        "COPY PROGRAM",
        "postgres",
        "GRANT pg_execute_server_program TO {role}",
    ),
    (
        "lo_import",
        "{db}",
        "GRANT EXECUTE ON FUNCTION lo_import(text) TO {role}",
    ),
    (
        "pg_read_all_stats",
        "postgres",
        "GRANT pg_read_all_stats TO {role}",
    ),
    (
        "other sessions' query text",
        "{db}",
        "GRANT pg_read_all_stats TO {role};\n\
         GRANT SELECT ON pg_catalog.pg_stat_activity TO {role}",
    ),
    (
        "SET ROLE to an elevated role",
        "postgres",
        "CREATE ROLE w1f_su_{db} SUPERUSER NOLOGIN;\nGRANT w1f_su_{db} TO {role}",
    ),
    (
        "pg_stat_database",
        "{db}",
        "GRANT SELECT ON pg_catalog.pg_stat_database TO {role}",
    ),
    (
        "pg_stat_database_conflicts",
        "{db}",
        "GRANT SELECT ON pg_catalog.pg_stat_database_conflicts TO {role}",
    ),
    (
        "pg_stat_activity",
        "{db}",
        "GRANT SELECT ON pg_catalog.pg_stat_activity TO {role}",
    ),
];

/// I-82 teeth, design section 14.1: each escape probe fires. One synthetic
/// cell per seed gets the one grant or extension that opens its path, and
/// the sweep reports that path for that cell's role. A clean cell on the
/// same cluster takes no path.
#[test]
fn t_db_iso_i82_teeth_every_escape_probe_fires() {
    let c = teeth_cluster("w1f_teeth_escapes");
    let clean = random_hex();
    synthetic_cell(&c, &clean, &[]);
    let mut seeded = Vec::new();
    for (path, db, sql) in SEEDS {
        let hex = random_hex();
        synthetic_cell(&c, &hex, &[]);
        let (role, dbn) = (format!("c_{hex}_app"), format!("c_{hex}"));
        let on = db.replace("{db}", &dbn);
        c.server()
            .psql(&on, &sql.replace("{role}", &role).replace("{db}", &dbn))
            .unwrap();
        seeded.push((path, role));
    }
    let breaches = sweep(&[&c], SEEDS.len() + 1);
    let mut missed = Vec::new();
    for (path, role) in &seeded {
        let want = format!("{role} took the {path} path");
        if !breaches.iter().any(|b| b.starts_with(&want)) {
            missed.push(want);
        }
    }
    assert!(missed.is_empty(), "missed {missed:#?} in {breaches:#?}");
    let dirty: Vec<&String> = breaches
        .iter()
        .filter(|b| b.starts_with(&format!("c_{clean}_app ")))
        .collect();
    assert!(dirty.is_empty(), "the clean cell took a path: {dirty:#?}");
}
