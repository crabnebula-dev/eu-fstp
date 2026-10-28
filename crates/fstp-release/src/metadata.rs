//! Release metadata and `may_apply` (design section 10.3).

use crate::ReleaseError;

/// Signed metadata of one release.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseMetadata {
    /// The version, `major.minor.patch`.
    pub version: (u16, u16, u16),
    /// SHA-256 of the artifact.
    pub artifact_sha256: [u8; 32],
}

/// Decodes release metadata, signature first. Fuzzed
/// (`release_metadata_decode`).
pub fn decode_release_metadata(bytes: &[u8]) -> Result<ReleaseMetadata, ReleaseError> {
    let _ = bytes;
    Err(ReleaseError::NotImplemented(
        "fstp_release::metadata::decode_release_metadata",
    ))
}

/// Whether the release may be applied. Update installation is out of M3.
pub fn may_apply(meta: &ReleaseMetadata) -> Result<bool, ReleaseError> {
    let _ = meta;
    Err(ReleaseError::NotImplemented(
        "fstp_release::metadata::may_apply",
    ))
}
