//! The cell runtime: the async engine, routes, and background tasks such
//! as the anchorer, the erasure runner and the licence and update checks
//! (M3 design sections 2.3, 5 and 8.7).
//!
//! `fstp-cell` is the one composer of `fstp-cell-core` and `fstp-pgstore`
//! (layering rule 3). It reaches `fstp-release` for the licence and update
//! checks only (I-39, layering rule 6).
//!
//! Lane W3a: agent one owns `routes` and `http`, agent two owns the
//! engine, the tasks, the witness client, `main.rs` and this file.
//!
//! # What a route handler uses
//!
//! - [`engine::CellEngine::execute`] runs an `Admitted` command. It is the
//!   only way a command reaches `DriverCore` (design section 5.4).
//! - [`engine::CellEngine::state`] gives the state after the last commit,
//!   for the gate and for reads. Reads never wait for the writer, so a
//!   cell serves reads while its witness is unreachable (risk R8).
//! - [`engine::EngineError`] tells a refusal from a cell that is shutting
//!   down.
//! - [`engine::serve::serve_until_terminated`] runs a cell until a
//!   termination signal drains it.
//! - [`tasks::erasure::ErasureHandle`], on a started cell, stores and
//!   opens texts. The erasure task behind it owns the keys.
//! - A commit the store refused because its step-up went stale after
//!   admission is [`engine::stepup_refusal`], a refusal naming I-78.
//!
//! # The serving cell (lane int5)
//!
//! - [`process::start`] starts a cell over its PostgreSQL database: the
//!   writer and app pools, [`engine::pg::PgCellStore`] with the witness
//!   link [`witness::link::TlsWitnessLink`], the first start's key chain,
//!   [`engine::startup::start_pg`], and the tunnel, health and internal
//!   listeners. A world starts its cells this way.
//! - [`routes::pg::PgBackend`] is the route backend over the engine and
//!   the operational rows of the application database.
//! - [`vault::HttpVaultClient`] is the vault client over the vault's
//!   internal mutual TLS listener.
//!
//! # What is not built here yet
//!
//! - [`run`], the binary's entry, does not start a cell yet: the
//!   configuration names no database logins, custody backend, keys,
//!   certificates or witness endpoint (design section 9.5 fixes no
//!   grammar). [`process::start`] takes them as parts.

pub mod config;
pub mod control;
pub mod egress;
pub mod engine;
pub mod http;
pub mod mail;
pub mod process;
pub mod routes;
pub mod shell;
pub mod tasks;
pub mod vault;
pub mod witness;

pub use config::CellConfig;
pub use egress::Destination;

/// Why a cell runtime operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CellError {
    /// The operation waits for a part another lane builds. It names the
    /// part.
    NotImplemented(&'static str),
    /// The configuration did not decode or was refused.
    Config(config::ConfigError),
    /// The outbound connector refused the destination.
    Egress(egress::EgressRefusal),
    /// Custody failed or refused.
    Custody(fstp_custody::CustodyError),
    /// The store failed.
    Store(fstp_ledger::StoreError),
    /// The stored ledger does not fold (I-23).
    Fold(fstp_cell_core::FoldError),
    /// The chain did not verify against the witness (I-24).
    ChainTamper,
    /// The witness failed or refused.
    Witness(fstp_audit::anchorer::WitnessFault),
    /// A key operation failed. It names the step.
    Keys(&'static str),
    /// Termination signals could not be set up.
    Signal,
    /// A listener or runtime failed.
    Io(std::io::ErrorKind),
    /// A request body was refused. It names the rule the body broke and
    /// never quotes the body (TH-26, R-NF-02).
    Request(http::BodyRefusal),
}

impl std::fmt::Display for CellError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CellError::NotImplemented(op) => write!(f, "{op} is not implemented yet"),
            CellError::Config(e) => write!(f, "configuration refused: {e:?}"),
            CellError::Egress(e) => write!(f, "outbound connection refused: {e:?}"),
            CellError::Custody(e) => write!(f, "custody failed: {e}"),
            CellError::Store(e) => write!(f, "store failed: {e}"),
            CellError::Fold(e) => write!(f, "the ledger does not fold: {e:?}"),
            CellError::ChainTamper => f.write_str("the chain did not verify against the witness"),
            CellError::Witness(e) => write!(f, "the witness failed: {e:?}"),
            CellError::Keys(step) => write!(f, "key operation failed: {step}"),
            CellError::Signal => f.write_str("termination signals could not be set up"),
            CellError::Io(kind) => write!(f, "i/o failed: {kind:?}"),
            CellError::Request(r) => write!(f, "request body refused: {r}"),
        }
    }
}

impl std::error::Error for CellError {}

/// Reads the configuration file at `path`, at most
/// [`config::MAX_CONFIG_LEN`] bytes. A longer file, or a path such as
/// `/dev/zero`, is refused after one byte past the limit, so it is never
/// read into memory whole.
///
/// # Errors
///
/// [`CellError::Io`] when the file cannot be read, and
/// [`CellError::Config`] when it is longer than the limit.
pub fn read_config(path: &std::path::Path) -> Result<Vec<u8>, CellError> {
    use std::io::Read as _;
    let file = std::fs::File::open(path).map_err(|e| CellError::Io(e.kind()))?;
    let limit = u64::try_from(config::MAX_CONFIG_LEN)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut bytes = Vec::new();
    file.take(limit)
        .read_to_end(&mut bytes)
        .map_err(|e| CellError::Io(e.kind()))?;
    if bytes.len() > config::MAX_CONFIG_LEN {
        return Err(CellError::Config(config::ConfigError::Invalid("length")));
    }
    Ok(bytes)
}

/// Runs the cell named by the configuration file in `FSTP_CELL_CONFIG`
/// until a termination signal drains it.
///
/// # Errors
///
/// [`CellError::Config`] for a missing or refused configuration. Then
/// [`CellError::NotImplemented`]: the configuration names none of the
/// parts of [`process::start`] yet. It never serves over an in-memory
/// ledger.
pub fn run() -> Result<(), CellError> {
    let path = std::env::var_os("FSTP_CELL_CONFIG")
        .ok_or(CellError::Config(config::ConfigError::Missing))?;
    let bytes = read_config(std::path::Path::new(&path))?;
    let cfg = config::decode(&bytes).map_err(CellError::Config)?;
    let _ = cfg;
    Err(CellError::NotImplemented(
        "fstp_cell::run: the configuration names no database logins, custody, keys, certificates or witness endpoint for fstp_cell::process::start (design section 9.5)",
    ))
}
