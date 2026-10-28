//! The configuration of a cell (design sections 1.2 and 14.4).
//!
//! W0 stub. Lane W3a adds the fields it needs. No field may hold a payment
//! account type or a debtor account (I-16,
//! `i16_config_types_hold_no_debtor_account`).

use fstp_cp_proto::CellId;

/// How a cell is deployed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// A SaaS cell, which reaches the control plane and never CrabNebula.
    Saas,
    /// A self-hosted cell, which has no control plane and reaches
    /// CrabNebula only through `fstp_release::egress` (B12).
    SelfHosted,
}

/// The configuration of one cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CellConfig {
    /// The cell.
    pub cell: CellId,
    /// The deployment mode.
    pub mode: Mode,
}
