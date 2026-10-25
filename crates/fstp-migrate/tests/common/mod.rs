//! Shared helpers for the integration tests: one tokio runtime and one
//! PostgreSQL server per test binary, a fresh database per test, and the
//! [`Pg`] client type.
//!
//! Every connection is mutually authenticated (D2, R-NF-09). It presents
//! the client certificate of its role, whose CN is the role name.

#![allow(dead_code, unreachable_pub)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::sync::OnceLock;
use std::time::Duration;

use fstp_pgtest::{ConnParams, PgServer, Role, tls as certs};
use fstp_pgwire::{Client, ClientTls, Config, Password};
use fstp_rt::tokio::TokioRuntime;

/// A test connection. `fstp_pgwire::Client` implements [`Database`]
/// in `fstp-migrate` itself.
pub type Pg = Client<TokioRuntime>;

pub fn rt() -> &'static TokioRuntime {
    static RT: OnceLock<TokioRuntime> = OnceLock::new();
    RT.get_or_init(|| TokioRuntime::new_multi_thread(4).unwrap())
}

pub fn server() -> &'static PgServer {
    PgServer::shared().unwrap_or_else(|e| panic!("{e}"))
}

pub fn block_on<F: Future>(f: F) -> F::Output {
    rt().block_on(f)
}

/// The TLS settings for `role`: the test CA as trust root, and the role's
/// client certificate and key.
pub fn tls(role: Role) -> ClientTls {
    ClientTls::new(certs::CA_PEM, role.client_cert_pem(), role.client_key_pem()).unwrap()
}

/// Configuration for a fresh database on the shared server, as the
/// superuser that owns it.
pub fn fresh() -> Config {
    fresh_as(Role::Superuser)
}

/// Configuration for a fresh database on the shared server, owned by
/// `role` and logging in as `role`.
pub fn fresh_as(role: Role) -> Config {
    let db = server()
        .fresh_database_as(role)
        .unwrap_or_else(|e| panic!("{e}"));
    config(&db, role)
}

/// Configuration for the database of `db`, logging in as `role`.
pub fn config(db: &ConnParams, role: Role) -> Config {
    Config::new(
        db.host.clone(),
        db.port,
        role.name(),
        Password::new(server().password(role)).unwrap(),
        db.dbname.clone(),
        tls(role),
    )
    .unwrap()
    .connect_timeout(Some(Duration::from_secs(20)))
}

pub fn connect(cfg: &Config) -> Pg {
    block_on(Client::connect(rt(), cfg)).unwrap_or_else(|e| panic!("connect failed: {e}"))
}

/// Runs a query that returns one `int8` and returns it.
pub fn scalar_i64(db: &mut Pg, sql: &'static str) -> i64 {
    block_on(db.query_one(sql, &[]))
        .unwrap_or_else(|e| panic!("{sql}: {e}"))
        .get(0)
        .unwrap()
}

/// Runs a query that returns one `text` and returns it.
pub fn scalar_text(db: &mut Pg, sql: &'static str) -> String {
    block_on(db.query_one(sql, &[]))
        .unwrap_or_else(|e| panic!("{sql}: {e}"))
        .get(0)
        .unwrap()
}

/// True when a relation with this name exists.
pub fn relation_exists(db: &mut Pg, name: &str) -> bool {
    block_on(db.query_one("SELECT to_regclass($1::text) IS NOT NULL", &[&name]))
        .unwrap()
        .get(0)
        .unwrap()
}
