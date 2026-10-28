//! The control plane: registry, placement, provisioning, routing, operator
//! tickets, metering, the isolation auditor and the cell role plan (M3
//! design section 9, ADR-011).
//!
//! The control plane cannot decode tenant data (I-19, I-20). It reaches no
//! crate that defines tenant records, account types or vault data
//! (layering rule 4).
//!
//! Status: W0 stub. Lane W2h fills the crate. [`CATALOGUE`] holds the `cp`
//! column map of design section 4.4, reviewed in W0. Every operation
//! refuses with [`ControlError::NotImplemented`].

pub mod api;
pub mod catalogue;
pub mod install;
pub mod isolation_audit;
pub mod pg;
pub mod pgagent;
pub mod placement;

pub use catalogue::CATALOGUE;

/// The configuration of the control plane service.
///
/// W0 stub. Lane W2h adds the fields it needs. No field may hold a
/// payment account type or a debtor account (I-16, design section 14.4
/// `i16_config_types_hold_no_debtor_account`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ControlConfig {
    /// The registered database clusters.
    pub clusters: Vec<placement::Cluster>,
}

/// Why a control plane operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlError {
    /// The operation is a W0 stub. It names the operation.
    NotImplemented(&'static str),
}

impl std::fmt::Display for ControlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ControlError::NotImplemented(op) => write!(f, "{op} is not implemented yet"),
        }
    }
}

impl std::error::Error for ControlError {}
