//! Shared helpers for the integration tests: one tokio runtime and one
//! PostgreSQL server per test binary, a fresh database per test, and the
//! [`Pg`] client type.

#![allow(dead_code, unreachable_pub)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::sync::OnceLock;
use std::time::Duration;

use fstp_pgtest::{PgServer, tls as certs};
use fstp_pgwire::{Client, Config, Password};
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

/// The TLS client configuration that trusts the test CA.
pub fn tls() -> fstp_tls::ClientConfig {
    fstp_tls::ClientConfig::new(certs::CA_PEM).unwrap()
}

/// Configuration for a fresh database on the shared server.
pub fn fresh() -> Config {
    let db = server().fresh_database().unwrap_or_else(|e| panic!("{e}"));
    Config::new(
        db.host.clone(),
        db.port,
        db.user.clone(),
        Password::new(db.password.clone()).unwrap(),
        db.dbname.clone(),
        tls(),
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
