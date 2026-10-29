//! The compiled frontend (ADR-014).
//!
//! The crate loads the compiled frontend from a directory, verifies it
//! against a SHA-256 manifest at start and serves it with fixed headers.
//! Assets are served at `/app/assets/{sha256}.js` and are immutable.
//!
//! Status: W0 stub. Lane W4e (L-WEB) owns this crate. Every operation
//! refuses with [`AssetError::NotImplemented`].

/// Why an operation of this crate failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssetError {
    /// The W0 stub of the named operation refuses.
    NotImplemented(&'static str),
}

impl std::fmt::Display for AssetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AssetError::NotImplemented(op) => write!(f, "{op} is not implemented yet"),
        }
    }
}

impl std::error::Error for AssetError {}

/// A decoded asset manifest.
///
/// W0 placeholder with no fields. The owning lane writes the designed type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetManifest {
    _w0: (),
}

/// Decodes the asset manifest. Fuzzed (`asset_manifest_decode`).
pub fn decode_manifest(bytes: &[u8]) -> Result<AssetManifest, AssetError> {
    let _ = bytes;
    Err(AssetError::NotImplemented(
        "fstp_web_assets::decode_manifest",
    ))
}

/// A resolved asset path.
///
/// W0 placeholder with no fields. The owning lane writes the designed type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetPath {
    _w0: (),
}

/// Resolves a request path to one manifest asset. Fuzzed (`static_path_resolve`).
pub fn resolve_static_path(bytes: &[u8]) -> Result<AssetPath, AssetError> {
    let _ = bytes;
    Err(AssetError::NotImplemented(
        "fstp_web_assets::resolve_static_path",
    ))
}
