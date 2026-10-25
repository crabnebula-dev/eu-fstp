//! Shared helpers for the integration tests: one tokio runtime and one
//! PostgreSQL server per test binary, and a fresh database per test.

#![allow(dead_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::sync::OnceLock;
use std::time::Duration;

use fstp_pgtest::{ConnParams, PgServer, ServerOptions, ServerTls, tls as certs};
use fstp_pgwire::{Client, Config, Password};
use fstp_rt::tokio::TokioRuntime;

pub(crate) type PgClient = Client<TokioRuntime>;

pub(crate) fn rt() -> &'static TokioRuntime {
    static RT: OnceLock<TokioRuntime> = OnceLock::new();
    RT.get_or_init(|| TokioRuntime::new_multi_thread(4).unwrap())
}

pub(crate) fn server() -> &'static PgServer {
    PgServer::shared().unwrap_or_else(|e| panic!("{e}"))
}

pub(crate) fn server_with(tls: ServerTls) -> &'static PgServer {
    PgServer::shared_with(ServerOptions { tls }).unwrap_or_else(|e| panic!("{e}"))
}

pub(crate) fn tls() -> fstp_tls::ClientConfig {
    fstp_tls::ClientConfig::new(certs::CA_PEM).unwrap()
}

pub(crate) fn mutual_tls() -> fstp_tls::ClientConfig {
    fstp_tls::ClientConfig::mutual(certs::CA_PEM, certs::CLIENT_CERT_PEM, certs::CLIENT_KEY_PEM)
        .unwrap()
}

pub(crate) fn config_for(db: &ConnParams, tls: fstp_tls::ClientConfig) -> Config {
    Config::new(
        db.host.clone(),
        db.port,
        db.user.clone(),
        Password::new(db.password.clone()).unwrap(),
        db.dbname.clone(),
        tls,
    )
    .unwrap()
    .connect_timeout(Some(Duration::from_secs(20)))
}

/// A fresh database on the shared server and its configuration.
pub(crate) fn fresh() -> (ConnParams, Config) {
    let db = server().fresh_database().unwrap_or_else(|e| panic!("{e}"));
    let cfg = config_for(&db, tls());
    (db, cfg)
}

pub(crate) fn block_on<F: std::future::Future>(f: F) -> F::Output {
    rt().block_on(f)
}

pub(crate) fn connect(cfg: &Config) -> PgClient {
    block_on(Client::connect(rt(), cfg)).unwrap_or_else(|e| panic!("connect failed: {e}"))
}
