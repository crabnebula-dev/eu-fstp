//! The only code that builds requests to CrabNebula hosts (I-38, design
//! section 10.1).

use crate::ReleaseError;
use crate::licence::LicenceId;

/// A product version, `major.minor.patch`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProductVersion(pub u16, pub u16, pub u16);

/// An update channel. Closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Channel {
    /// The stable channel.
    Stable,
}

/// An update check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UpdateCheck {
    /// The running version.
    pub version: ProductVersion,
    /// The channel.
    pub channel: Channel,
}

/// A licence refresh.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LicenceRefresh {
    /// The licence.
    pub licence: LicenceId,
    /// The running version.
    pub version: ProductVersion,
}

/// A call to a CrabNebula host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CnCall {
    /// `GET /v1/updates/{channel}/{version}`, Host only.
    Update(UpdateCheck),
    /// `POST /v1/licences/{licence}/refresh`, body `{"version":"x.y.z"}`.
    Licence(LicenceRefresh),
}

/// The request bytes of a call.
pub fn encode(call: &CnCall) -> Result<Vec<u8>, ReleaseError> {
    let _ = call;
    Err(ReleaseError::NotImplemented("fstp_release::egress::encode"))
}

/// A decoded response from a CrabNebula host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EgressResponse {
    /// The HTTP status.
    pub status: u16,
    /// The body.
    pub body: Vec<u8>,
}

/// Decodes a response. Fuzzed (`egress_response_decode`).
pub fn decode_response(bytes: &[u8]) -> Result<EgressResponse, ReleaseError> {
    let _ = bytes;
    Err(ReleaseError::NotImplemented(
        "fstp_release::egress::decode_response",
    ))
}
