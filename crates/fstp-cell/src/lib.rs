//! The cell runtime: the async engine, routes, and background tasks such
//! as the anchorer, the erasure runner and the licence and update checks
//! (M3 design sections 2.3, 5 and 8.7).
//!
//! `fstp-cell` is the one composer of `fstp-cell-core` and `fstp-pgstore`
//! (layering rule 3). It reaches `fstp-release` for the licence and update
//! checks only (I-39, layering rule 6).
//!
//! Status: W0 stub. Lane W3a fills the crate: agent one owns `routes` and
//! `http`, agent two owns the engine, the tasks, the witness client,
//! `main.rs` and this file. Every operation refuses with
//! [`CellError::NotImplemented`].

pub mod config;
pub mod egress;
pub mod http;
pub mod routes;

pub use config::CellConfig;
pub use egress::Destination;

/// Why a cell runtime operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CellError {
    /// The operation is a W0 stub. It names the operation.
    NotImplemented(&'static str),
}

impl std::fmt::Display for CellError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CellError::NotImplemented(op) => write!(f, "{op} is not implemented yet"),
        }
    }
}

impl std::error::Error for CellError {}

/// Runs the cell until shutdown.
pub fn run() -> Result<(), CellError> {
    Err(CellError::NotImplemented("fstp_cell::run"))
}
