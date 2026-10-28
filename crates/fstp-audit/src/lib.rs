//! The audit chain: row format, link function, verifier, anchors and
//! receipts (I-24, M3 design section 7, ADR-010). Pure.
//!
//! Status: W0 stub. Lane W2g fills the crate. Every operation refuses with
//! [`AuditError::NotImplemented`]. The designed `genesis` and `link` are
//! infallible; they return a `Result` until the link function lands.
//!
//! Seam: composite anchor signatures need `fstp_crypto::composite`, which
//! lane W1h builds with moduletto (`docs/handoff/m3-base.md`).

pub mod anchor;
pub mod chain;
pub mod verify;

pub use anchor::{Anchor, Receipt};
pub use chain::{ChainId, ChainRow, ChainWriter, Link, RowKind};
pub use verify::{Tamper, Verified};

/// A cell identifier, 16 random bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CellId(pub [u8; 16]);

/// Why an audit operation failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuditError {
    /// The verifier found a change to the chain.
    Tamper(Tamper),
    /// The operation is a W0 stub. It names the operation.
    NotImplemented(&'static str),
}
