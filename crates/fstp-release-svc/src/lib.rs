//! The CrabNebula licence and update services (M3 design section 10).
//!
//! Status: W0 stub. Lane W2j fills the crate. Every operation refuses with
//! [`ServiceError::NotImplemented`].

use fstp_migrate::catalogue::TableSpec;

/// The tables of the licence database. Lane W2j lists them next to its
/// migrations.
pub const CATALOGUE: &[TableSpec] = &[];

/// Why a service operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceError {
    /// The operation is a W0 stub. It names the operation.
    NotImplemented(&'static str),
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceError::NotImplemented(op) => write!(f, "{op} is not implemented yet"),
        }
    }
}

impl std::error::Error for ServiceError {}

/// A decoded licence refresh request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefreshRequest {
    /// The licence id.
    pub licence: [u8; 16],
    /// The running version.
    pub version: (u16, u16, u16),
}

/// A decoded update query.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateQuery {
    /// The channel, as a closed code.
    pub channel: u8,
    /// The running version.
    pub version: (u16, u16, u16),
}

/// Decodes a refresh request; only the permitted grammar passes. Fuzzed
/// (`refresh_request_decode`).
pub fn decode_refresh_request(bytes: &[u8]) -> Result<RefreshRequest, ServiceError> {
    let _ = bytes;
    Err(ServiceError::NotImplemented(
        "fstp_release_svc::decode_refresh_request",
    ))
}

/// Decodes an update query; only the permitted grammar passes. Fuzzed
/// (`update_query_decode`).
pub fn decode_update_query(bytes: &[u8]) -> Result<UpdateQuery, ServiceError> {
    let _ = bytes;
    Err(ServiceError::NotImplemented(
        "fstp_release_svc::decode_update_query",
    ))
}

/// Runs the licence service until shutdown.
pub fn run_licence_service() -> Result<(), ServiceError> {
    Err(ServiceError::NotImplemented(
        "fstp_release_svc::run_licence_service",
    ))
}

/// Runs the update service until shutdown.
pub fn run_update_service() -> Result<(), ServiceError> {
    Err(ServiceError::NotImplemented(
        "fstp_release_svc::run_update_service",
    ))
}
