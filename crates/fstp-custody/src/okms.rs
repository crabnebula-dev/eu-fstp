//! The OVHcloud KMS client (ADR-004 part 2, Q11).

use crate::CustodyError;

/// A custody client for OVHcloud KMS.
#[derive(Debug)]
pub struct OkmsCustody {
    endpoint: String,
}

impl OkmsCustody {
    /// A client for the KMS at `endpoint`.
    pub fn new(endpoint: &str) -> Result<OkmsCustody, CustodyError> {
        let _ = endpoint;
        Err(CustodyError::NotImplemented(
            "fstp_custody::OkmsCustody::new",
        ))
    }

    /// The KMS endpoint.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
}

crate::refusing_custody!(OkmsCustody, "fstp_custody::OkmsCustody");

/// A decoded KMS response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OkmsResponse {
    /// The response body, decoded.
    pub body: fstp_json::Value,
}

/// Decodes a KMS response body. Fuzzed (`okms_response_decode`).
/// Unknown members are refused, and key bytes never reach an error display.
pub fn decode_response(bytes: &[u8]) -> Result<OkmsResponse, CustodyError> {
    let _ = bytes;
    Err(CustodyError::NotImplemented(
        "fstp_custody::okms::decode_response",
    ))
}
