//! The vault database's placement marker and grant function over a real
//! PostgreSQL server from `fstp-pgtest` (design sections 4.1, 4.6 and
//! 9.2, I-82, I-83).
//!
//! Each test creates its own database named `v_<random hex>`, the vault
//! database grammar of design section 4.1, and applies the vault set with
//! the `fstp-migrate` runner, as `fstp_vault::store::migrate` does.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code asserts on known-good values"
)]

use std::sync::OnceLock;
use std::time::Duration;

use fstp_pgtest::{PgServer, Role, tls as certs};
use fstp_pgwire::{Client, ClientTls, Config, Password};
use fstp_rt::tokio::TokioRuntime;
use fstp_vault::start::{VAULT_MARKER, placement_marker};
use fstp_vault::store;

type Pg = Client<TokioRuntime>;

fn rt() -> &'static TokioRuntime {
    static RT: OnceLock<TokioRuntime> = OnceLock::new();
    RT.get_or_init(|| TokioRuntime::new_multi_thread(2).unwrap())
}

fn block_on<F: Future>(f: F) -> F::Output {
    rt().block_on(f)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A fresh, migrated database `v_<cell>` for a random cell, and the cell.
fn vault_db() -> (Pg, [u8; 16]) {
    let server = PgServer::shared().unwrap_or_else(|e| panic!("{e}"));
    let cell = fstp_crypto::random_array::<16>().unwrap();
    let dbname = format!("v_{}", hex(&cell));
    let role = Role::Superuser;
    server
        .psql(
            "postgres",
            &format!("CREATE DATABASE {dbname} OWNER {}", role.name()),
        )
        .unwrap_or_else(|e| panic!("{e}"));
    let tls = ClientTls::new(certs::CA_PEM, role.client_cert_pem(), role.client_key_pem()).unwrap();
    let cfg = Config::new(
        server.host().to_owned(),
        server.port(),
        role.name(),
        Password::new(server.password(role)).unwrap(),
        dbname,
        tls,
    )
    .unwrap()
    .connect_timeout(Some(Duration::from_secs(20)));
    let mut db =
        block_on(Client::connect(rt(), &cfg)).unwrap_or_else(|e| panic!("connect failed: {e}"));
    block_on(store::migrate(&mut db)).unwrap();
    (db, cell)
}

fn place(db: &mut Pg, cell: &[u8; 16], kind: i16) -> Result<u64, fstp_pgwire::Error> {
    let cell = cell.to_vec();
    let cluster = vec![0x5a_u8; 16];
    block_on(db.execute(
        "INSERT INTO fstp_meta.placement (cell_id, cluster_id, kind) VALUES ($1, $2, $3)",
        &[&cell, &cluster, &kind],
    ))
}

/// I-83, design sections 4.1 and 9.2: a migrated vault database takes
/// one placement row of kind 2 for its own cell, and the start check
/// reads that marker back. A second row is refused.
#[test]
fn i83_vault_database_takes_one_vault_placement_row() {
    let (mut db, cell) = vault_db();
    place(&mut db, &cell, 2).unwrap();
    assert_eq!(block_on(placement_marker(&mut db)), Ok(VAULT_MARKER));
    assert!(place(&mut db, &cell, 2).is_err(), "a second placement row");
}

/// I-83, design section 4.1: the vault placement refuses the application
/// marker, so a vault database never claims an application cluster.
#[test]
fn i83_vault_placement_refuses_the_application_marker() {
    let (mut db, cell) = vault_db();
    assert!(place(&mut db, &cell, 1).is_err(), "kind 1 was accepted");
    assert!(
        block_on(placement_marker(&mut db)).is_err(),
        "an empty placement table read as a marker"
    );
}

/// I-82, I-83, ADR-011: the placement row names the database's own cell,
/// so a vault database never holds another cell's placement.
#[test]
fn i83_vault_placement_refuses_another_cell() {
    let (mut db, cell) = vault_db();
    let mut other = cell;
    other[0] ^= 1;
    assert!(place(&mut db, &other, 2).is_err(), "another cell's row");
}

/// ADR-007 "Database link trigger": the placement row is never changed or
/// removed, by any role.
#[test]
fn i83_vault_placement_row_is_immutable() {
    let (mut db, cell) = vault_db();
    place(&mut db, &cell, 2).unwrap();
    assert!(block_on(db.execute("UPDATE fstp_meta.placement SET kind = 2", &[])).is_err());
    assert!(block_on(db.execute("DELETE FROM fstp_meta.placement", &[])).is_err());
    assert!(block_on(db.execute("TRUNCATE fstp_meta.placement", &[])).is_err());
}

/// I-82, design section 4.1: the vault set defines
/// `fstp_meta.apply_grant`, and PUBLIC holds no EXECUTE on it.
#[test]
fn i82_vault_apply_grant_exists_and_public_cannot_call_it() {
    let (mut db, _) = vault_db();
    let rows = block_on(db.query(
        "SELECT p.proacl IS NOT NULL AND NOT EXISTS (\
           SELECT 1 FROM aclexplode(p.proacl) a WHERE a.grantee = 0) \
         FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace \
         WHERE n.nspname = 'fstp_meta' AND p.proname = 'apply_grant'",
        &[],
    ))
    .unwrap();
    assert_eq!(rows.len(), 1, "fstp_meta.apply_grant is not defined once");
    let revoked: bool = rows[0].get(0).unwrap();
    assert!(revoked, "PUBLIC holds EXECUTE on fstp_meta.apply_grant");
}
