//! Tenant onboarding (M4 design section 3.5).
//!
//! The crate holds the onboarding steps, the tenant-level settings (P-20,
//! P-69 to P-72, P-74) as ledger records, the tenant defaults that prefill
//! the programme fields for P-18, P-21 and P-45, the tenant admin set
//! (Q31) and the inference configuration record. P-73 and P-78 are not
//! settable in M4.
//!
//! Status: W0 stub. Lane W2d (L-TENANT) owns this crate. Every operation
//! refuses with [`TenantError::NotImplemented`].

#![deny(
    clippy::float_arithmetic,
    clippy::float_cmp,
    clippy::cast_precision_loss,
    clippy::arithmetic_side_effects
)]

/// Why an operation of this crate failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TenantError {
    /// The W0 stub of the named operation refuses.
    NotImplemented(&'static str),
}

impl std::fmt::Display for TenantError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TenantError::NotImplemented(op) => write!(f, "{op} is not implemented yet"),
        }
    }
}

impl std::error::Error for TenantError {}

/// A tenant command.
///
/// W0 placeholder with no fields. The owning lane writes the designed type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TenantCommand {
    _w0: (),
}

/// Decodes a tenant command from its JSON text. Fuzzed (`tenant_command_decode`).
pub fn decode_command(bytes: &[u8]) -> Result<TenantCommand, TenantError> {
    let _ = bytes;
    Err(TenantError::NotImplemented("fstp_tenant::decode_command"))
}

/// A tenant ledger record.
///
/// W0 placeholder with no fields. The owning lane writes the designed type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TenantRecord {
    _w0: (),
}

/// Decodes a stored tenant record. Fuzzed (`tenant_record_decode`).
pub fn decode_record(bytes: &[u8]) -> Result<TenantRecord, TenantError> {
    let _ = bytes;
    Err(TenantError::NotImplemented("fstp_tenant::decode_record"))
}
