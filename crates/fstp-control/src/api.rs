//! The control plane's private API.

use crate::ControlError;

/// A decoded control plane API request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CpApiRequest {
    /// The operation, as a closed code.
    pub op: u16,
}

/// Decodes an API request. Fuzzed (`cp_api_decode`).
pub fn decode_cp_api(bytes: &[u8]) -> Result<CpApiRequest, ControlError> {
    let _ = bytes;
    Err(ControlError::NotImplemented(
        "fstp_control::api::decode_cp_api",
    ))
}
