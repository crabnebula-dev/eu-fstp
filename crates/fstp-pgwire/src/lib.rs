//! In-house PostgreSQL wire protocol client. Extended query protocol only; no string-built SQL.
//!
//! This is the PostgreSQL component of the build approach in
//! `SPEC/03-architecture/overview.md`. It speaks protocol 3.0 to PostgreSQL 16
//! and later.
//!
//! # Security properties
//!
//! - **Mutual TLS is required.** [`Client::connect`] sends an SSLRequest and
//!   runs an fstp-tls handshake with full verification of chain and name. A
//!   server that declines TLS is refused, and so are unencrypted bytes that
//!   arrive between the server's `S` and the handshake. Every connection
//!   presents the role's client certificate from its [`ClientTls`], which
//!   cannot be built without one (D2, R-NF-09). The server checks it with
//!   `clientcert=verify-full`, so its CN must equal the role.
//! - **SCRAM only by default.** SCRAM-SHA-256-PLUS with
//!   `tls-server-end-point` channel binding is used when the server offers
//!   it, otherwise SCRAM-SHA-256. The server signature is always verified.
//!   Cleartext passwords and unauthenticated logins need an explicit
//!   [`RequireAuth`]; MD5, Kerberos, GSSAPI and SSPI are never supported.
//!   Passwords are printable ASCII, where SASLprep is the identity mapping
//!   (see [`Password`]). Nonces come from fstp-crypto.
//! - **No string-built SQL.** Every statement uses the extended query
//!   protocol, and SQL text is `&'static str`. Values travel as typed,
//!   binary parameters. There is no simple query protocol anywhere, so a
//!   string with several statements fails to prepare. SQL kept in files
//!   can be embedded with `include_str!`, which also yields
//!   `&'static str`. `Box::leak` could turn a runtime string into one;
//!   review must reject that, since the type is the only guard.
//! - **Strict typing.** Parameter and column types come from the server's
//!   ParameterDescription and RowDescription and must match the Rust type
//!   exactly (see [`types`]). A mismatch is an error, never a conversion.
//! - **Strict decoding.** The sans-IO codec in [`proto`] checks every
//!   length, enforces [`Limits`], and treats unsupported messages such as
//!   COPY as protocol errors that break the connection.
//! - **No data in logs.** The crate logs nothing. A [`DbError`] displays
//!   its severity, its SQLSTATE and the SQLSTATE's standard condition name
//!   (see [`sqlstate`]), plus table, column and constraint names when the
//!   server supplies them. The primary message, detail, hint and
//!   context can quote data values, so they stay behind accessors
//!   (R-NF-02). SQL text never appears in Display or Debug output. Notices
//!   are discarded unread. `Debug` output of rows and messages shows no
//!   values.
//!
//! # Example
//!
//! ```no_run
//! use fstp_pgwire::{Client, ClientTls, Config, Password};
//! use fstp_rt::tokio::TokioRuntime;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let rt = TokioRuntime::new_multi_thread(2)?;
//! let tls = ClientTls::new(
//!     &std::fs::read("ca.pem")?,
//!     &std::fs::read("app.pem")?,     // CN = app, the database role
//!     &std::fs::read("app-key.pem")?,
//! )?;
//! let config = Config::new("db.example", 5432, "app", Password::new("s3cret")?, "cell", tls)?;
//! rt.block_on(async {
//!     let mut client = Client::connect(&rt, &config).await?;
//!     client
//!         .execute("INSERT INTO notes (id, body) VALUES ($1, $2)", &[&1i64, &"hello"])
//!         .await?;
//!     let row = client
//!         .query_one("SELECT body FROM notes WHERE id = $1", &[&1i64])
//!         .await?;
//!     let body: String = row.get(0)?;
//!     assert_eq!(body, "hello");
//!     Ok::<_, fstp_pgwire::Error>(())
//! })?;
//! # Ok(())
//! # }
//! ```
//!
//! # Connections
//!
//! A [`Client`] runs one request at a time. Prepared statements are cached
//! per connection. Transactions take isolation levels and roll back when
//! dropped. A [`CancelToken`] cancels a running statement over a new TLS
//! connection. Connect and statement timeouts run on the [`fstp_rt`]
//! runtime.
//!
//! There is no connection pool in M1. Under ADR-005 pooling is per cell, so
//! it belongs to the cell runtime in M3.
//!
//! [`Session`] is the runtime-free state machine under the client. It runs
//! over any transport and is what the fuzz targets drive.
//!
//! # Fuzzing
//!
//! The fuzz project in `fuzz/` covers backend message framing and decoding,
//! SCRAM server messages, value decoding and a hostile server driving the
//! whole client state machine (TH-26, H-05).

pub mod base64;
mod client;
mod config;
mod error;
pub mod proto;
mod row;
pub mod scram;
mod session;
pub mod sqlstate;
mod tls;
pub mod types;
pub mod x509;

pub use crate::client::{
    CancelToken, Client, IsolationLevel, RowStream, Transaction, TransactionOptions,
};
pub use crate::config::{
    AuthMethod, ClientTls, Config, DEFAULT_MIN_SCRAM_ITERATIONS, Limits, MAX_NAME_LEN,
    MAX_PASSWORD_LEN, Password, RequireAuth,
};
pub use crate::error::{DbError, Error, ErrorKind};
pub use crate::proto::backend::TransactionStatus;
pub use crate::row::{Column, ColumnIndex, Row, Statement};
pub use crate::session::{BackendKey, Session, SessionRowStream};
pub use crate::tls::tls_handshake;
pub use crate::types::{
    Date, DecodeError, EncodeError, FromSql, IsNull, Numeric, Timestamptz, ToSql, ToSqlType, Type,
    Uuid,
};
