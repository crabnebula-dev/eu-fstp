//! Review reproducers for lane int4 (security and fidelity lens).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code asserts on known-good values"
)]

use std::collections::BTreeSet;
use std::sync::OnceLock;
use std::time::Duration;

use fstp_pgtest::{PgServer, Role, tls as certs};
use fstp_pgwire::{Client, ClientTls, Config, Password};
use fstp_rt::tokio::TokioRuntime;
use fstp_vault::{CATALOGUE, store};

fn rt() -> &'static TokioRuntime {
    static RT: OnceLock<TokioRuntime> = OnceLock::new();
    RT.get_or_init(|| TokioRuntime::new_multi_thread(2).unwrap())
}

fn block_on<F: Future>(f: F) -> F::Output {
    rt().block_on(f)
}

/// R-NF-08, design sections 4.5 and 4.6: after `store::migrate`, every
/// table of the vault database is in `fstp_vault::CATALOGUE`, in every
/// schema, not only the four the existing test lists. The runner creates
/// `fstp_migrate.schema_migrations`, which the application catalogue
/// lists and the vault catalogue does not.
#[test]
fn review_vault_catalogue_misses_the_migration_ledger() {
    let server = PgServer::shared().unwrap_or_else(|e| panic!("{e}"));
    let role = Role::Superuser;
    let db = server
        .fresh_database_as(role)
        .unwrap_or_else(|e| panic!("{e}"));
    let tls = ClientTls::new(certs::CA_PEM, role.client_cert_pem(), role.client_key_pem()).unwrap();
    let cfg = Config::new(
        db.host.clone(),
        db.port,
        role.name(),
        Password::new(server.password(role)).unwrap(),
        db.dbname.clone(),
        tls,
    )
    .unwrap()
    .connect_timeout(Some(Duration::from_secs(20)));
    let mut pg: Client<TokioRuntime> =
        block_on(Client::connect(rt(), &cfg)).unwrap_or_else(|e| panic!("connect failed: {e}"));
    block_on(store::migrate(&mut pg)).unwrap();
    let rows = block_on(pg.query(
        "SELECT table_schema::text, table_name::text FROM information_schema.tables \
         WHERE table_schema NOT IN ('pg_catalog', 'information_schema') ORDER BY 1, 2",
        &[],
    ))
    .unwrap();
    let tables: BTreeSet<(String, String)> = rows
        .iter()
        .map(|r| (r.get(0).unwrap(), r.get(1).unwrap()))
        .collect();
    let catalogued: BTreeSet<(String, String)> = CATALOGUE
        .iter()
        .map(|t| (t.schema.to_owned(), t.name.to_owned()))
        .collect();
    let outside: Vec<_> = tables.difference(&catalogued).collect();
    assert!(
        outside.is_empty(),
        "R-NF-08: vault tables outside fstp_vault::CATALOGUE: {outside:?}"
    );
}
