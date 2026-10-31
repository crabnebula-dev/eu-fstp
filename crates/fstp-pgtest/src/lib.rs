//! Test harness that runs a fresh, real PostgreSQL server per test run.
//!
//! This is the harness of the "Database" layer in
//! `SPEC/07-test-plan/test-plan.md`: real PostgreSQL per test run, used for
//! migrations, constraint enforcement and wire protocol conformance.
//!
//! # What a server looks like
//!
//! - A new data directory under a fresh temporary directory, created by
//!   `initdb` with `--auth=scram-sha-256` and a random superuser password read
//!   from `/dev/urandom`.
//! - TCP on `127.0.0.1` only, on a free port. Unix sockets live only inside
//!   the temporary directory.
//! - `ssl = on` with the fstp-tls test server certificate and key, written
//!   into the temporary directory with mode 0600. TLS 1.3 is the minimum.
//!   Client certificates are verified against the fstp-tls test CA.
//! - `password_encryption = scram-sha-256`, and `pg_hba.conf` allows only
//!   `hostssl` lines with `scram-sha-256` and `clientcert=verify-full`.
//!   Every login therefore needs TLS, the role's password and a client
//!   certificate whose CN equals the role name (D2, R-NF-09).
//! - Two login roles with fixed names, listed in [`Role`]: the superuser
//!   and a role without special rights. Each has a random password and a
//!   committed client certificate from `crates/fstp-tls/testdata/`.
//! - `fsync = off`, because the data is thrown away.
//!
//! [`ServerTls::Optional`] and [`ServerTls::Off`] are explicitly separate
//! configurations that also accept unencrypted `host` connections. They
//! exist so that a client's refusal to talk without TLS can be tested.
//! The `hostssl` lines of [`ServerTls::Optional`] still require client
//! certificates.
//!
//! # Lifetime
//!
//! No server outlives the test process. Each server has a watchdog: a small
//! bash process whose standard input is a pipe from the test process. The
//! kernel closes that pipe on every kind of exit, including a panic, an
//! abort and `SIGKILL`. The watchdog then stops the server and deletes the
//! temporary directory. It runs in its own process group and ignores
//! terminal signals, so a Ctrl-C or a signal to the test's process group
//! does not stop it before it has cleaned up.
//!
//! # Running as root
//!
//! PostgreSQL refuses to run as root. When the test process is root,
//! `initdb` and the server run as the `postgres` user through `runuser`,
//! and the temporary directory is owned by that user.
//!
//! # Usage
//!
//! [`PgServer::shared`] starts one server per test binary on first use.
//! [`PgServer::fresh_database`] gives each test its own database.
//! [`ConnParams`] carries the role's client certificate and key.
//!
//! ```no_run
//! let server = fstp_pgtest::PgServer::shared().unwrap();
//! let db = server.fresh_database().unwrap();
//! assert_eq!(db.host, "127.0.0.1");
//! assert_eq!(db.client_cert_pem, fstp_pgtest::Role::Superuser.client_cert_pem());
//! ```
//!
//! # Named servers (M3)
//!
//! [`PgServer::shared_named`] starts several servers per test binary, one
//! per name, each with its own cluster CA ([`certs::ClusterCa`]).
//! [`PgServer::create_login_role`] creates a role of any name in the
//! harness grammar and mints its client certificate at runtime.
//! [`PgServer::create_database_for`] writes one `pg_hba` line per database
//! and role. [`PgServer::create_replication_role`] adds a replication
//! role and its `hostssl replication` line. [`RoleLogin::conn_params`]
//! gives a minted role's [`ConnParams`], whose
//! [`ConnParams::server_ca_pem`] is the cluster CA.
//! [`PgServer::dump_data`] gives the logical view of a database for at-rest
//! scans. The CA mints certificates through `fstp-pki` and the
//! `fstp-crypto` signing module. Until lanes W1i and W1h land them, a named
//! server refuses to start and names what it waits for.
//!
//! # Locating PostgreSQL
//!
//! The server binaries come from `FSTP_PG_BIN` if set, then from
//! `pg_config --bindir`, then from the newest `/usr/lib/postgresql/*/bin`.
//!
//! This crate contains no parser of untrusted input, so it has no fuzz
//! target. It reads only its own child processes' output.

pub mod certs;
mod named;
mod server;
pub mod tls;

pub use crate::named::RoleLogin;
pub use crate::server::{
    ConnParams, DUMP_LOCK_WAIT, Error, PgServer, Role, ServerOptions, ServerTls,
};
