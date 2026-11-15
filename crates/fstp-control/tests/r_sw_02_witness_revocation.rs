//! R-SW-02, design section 3.7 step 2, ADR-004 "Decided by Daniel,
//! 2026-11-15 (late)": the cell erasure revokes the cell at the SaaS
//! witness through `fstp_control::erase::WitnessRegistry`, which logs in
//! as `witness_migrator` and appends the revocation record beside
//! `witness.cell_ca`. Lane m3/erase-prod.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, Ordering};

use fstp_control::erase::{WitnessCredentials, WitnessRegistry};
use fstp_cp_proto::CellId;
use fstp_pgtest::PgServer;
use fstp_pgwire::{ClientTls, Config, Password};
use fstp_rt::tokio::TokioRuntime;

fn rt() -> &'static TokioRuntime {
    static RT: OnceLock<TokioRuntime> = OnceLock::new();
    RT.get_or_init(|| TokioRuntime::new_multi_thread(2).unwrap())
}

static NEXT: AtomicU32 = AtomicU32::new(0);

/// A migrated witness database and the pgwire login of its migrator.
fn witness_database() -> (&'static PgServer, String, Config) {
    let server = PgServer::shared_named("erasewitness", "witness").unwrap();
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let dbname = format!("witness_e{n}_{}", std::process::id());
    let migrator = format!("wmig_e{n}_{}", std::process::id());
    let login = server.create_login_role(&migrator).unwrap();
    server
        .create_database_for(&dbname, &[migrator.as_str()])
        .unwrap();
    server
        .psql(
            "postgres",
            &format!("GRANT CREATE ON DATABASE {dbname} TO {migrator}"),
        )
        .unwrap();
    for m in fstp_witness::MIGRATIONS {
        server
            .psql(&dbname, &format!("SET ROLE {migrator};\n{}", m.sql))
            .unwrap();
    }
    let p = login.conn_params(server, &dbname);
    let tls = ClientTls::new(p.server_ca_pem, p.client_cert_pem, p.client_key_pem).unwrap();
    let config = Config::new(
        p.host.clone(),
        p.port,
        p.user.as_str(),
        Password::new(p.password.as_str()).unwrap(),
        p.dbname.clone(),
        tls,
    )
    .unwrap();
    (server, dbname, config)
}

/// R-SW-02, ADR-004 (2026-11-15 late): `WitnessRegistry` revokes a
/// registered cell with one revocation row. The CA row stays, a second
/// revocation changes nothing, and the cell cannot register again.
#[test]
fn r_sw_02_witness_registry_appends_the_revocation_beside_cell_ca() {
    let (server, dbname, login) = witness_database();
    let cell = CellId([0x91; 16]);
    server
        .psql(
            &dbname,
            &fstp_witness::store::registration_sql(fstp_audit::CellId(cell.0), b"ca", &[], 1),
        )
        .unwrap();
    let registry = WitnessRegistry::new(rt().clone(), login);
    rt().block_on(registry.revoke_cell(cell)).unwrap();
    rt().block_on(registry.revoke_cell(cell)).unwrap();
    let rows = server
        .psql(
            &dbname,
            "SELECT (SELECT count(*) FROM witness.cell_ca) || '|' || \
             (SELECT count(*) FROM witness.cell_revocation)",
        )
        .unwrap();
    assert_eq!(rows, "1|1");
    assert!(
        server
            .psql(
                &dbname,
                &fstp_witness::store::registration_sql(fstp_audit::CellId(cell.0), b"ca", &[], 2),
            )
            .is_err(),
        "the revoked cell registered again"
    );
}

/// R-SW-02 teeth: the revocation of a cell the witness never registered
/// fails, so the erasure stops instead of reporting a revocation that
/// pinned nothing.
#[test]
fn r_sw_02_witness_registry_refuses_an_unknown_cell() {
    let (_server, _dbname, login) = witness_database();
    let registry = WitnessRegistry::new(rt().clone(), login);
    assert!(
        rt().block_on(registry.revoke_cell(CellId([0x92; 16])))
            .is_err()
    );
}
