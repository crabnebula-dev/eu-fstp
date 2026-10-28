//! The closed set of outbound destinations of a cell (B4, I-16, I-38,
//! ADR-009 "Outbound destinations").
//!
//! The cell's connector opens connections only to a [`Destination`], and
//! the host firewall holds the same list. No variant reaches a payment
//! service or names a platform account (I-16).
//! `i16_cell_egress_has_no_payment_destination` enumerates the enum. A new
//! variant needs an amendment of ADR-009.
//!
//! Status: W0 stub. Lane W3a writes the connector. [`connect`] refuses
//! with [`CellError::NotImplemented`] until then.

use fstp_release::egress::CnCall;

use crate::CellError;

/// Where a cell may open a connection. Closed and exhaustive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Destination {
    /// `c_<cell>` on its application cluster, one pool per role.
    AppDatabase,
    /// Its own vault, over internal mTLS.
    Vault,
    /// Its own App and CellBackup custody entries.
    Custody,
    /// SaaS only: the control plane, through `CellToCp`. A self-hosted
    /// cell never builds it.
    ControlPlane,
    /// The witness, for the App chain's prepares, aborts and receipts.
    Witness,
    /// Self-hosted only: a CrabNebula host. The request is built only by
    /// `fstp_release::egress` (I-38). A SaaS cell never builds it.
    CrabNebula(CnCall),
    /// The `<cell>/keystore/` object storage prefix only. Proposed by
    /// ADR-012 and pending Daniel, so no connector builds it yet.
    KeystoreSnapshots,
}

/// Opens a connection to `to`.
pub fn connect(to: &Destination) -> Result<(), CellError> {
    let _ = to;
    Err(CellError::NotImplemented("fstp_cell::egress::connect"))
}
