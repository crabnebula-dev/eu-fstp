//! The content-addressed request path of an asset (ADR-014).

use std::fmt;

use crate::{AssetError, hash_from_hex, hex};

/// The URL prefix of every asset.
pub const ASSET_PREFIX: &str = "/app/assets/";

/// The kind of an asset, from its manifest path's extension.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AssetKind {
    /// A JavaScript module, `.js`.
    Script,
    /// A stylesheet, `.css`. Interim, pending Daniel: ADR-014 names `.js`
    /// assets only.
    Style,
}

impl AssetKind {
    /// The extension with its dot.
    #[must_use]
    pub const fn extension(self) -> &'static str {
        match self {
            AssetKind::Script => ".js",
            AssetKind::Style => ".css",
        }
    }

    /// The fixed `Content-Type` value.
    #[must_use]
    pub const fn content_type(self) -> &'static str {
        match self {
            AssetKind::Script => "text/javascript; charset=utf-8",
            AssetKind::Style => "text/css; charset=utf-8",
        }
    }

    /// The kind whose extension ends `name`, if any.
    pub(crate) fn of_name(name: &[u8]) -> Option<AssetKind> {
        if name.ends_with(b".js") {
            Some(AssetKind::Script)
        } else if name.ends_with(b".css") {
            Some(AssetKind::Style)
        } else {
            None
        }
    }
}

/// A resolved asset path: a SHA-256 and a kind.
///
/// Two values are equal exactly when their hash and kind are.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AssetPath {
    hash: [u8; 32],
    kind: AssetKind,
}

impl AssetPath {
    /// The path of the asset with SHA-256 `hash` and kind `kind`.
    #[must_use]
    pub const fn new(hash: [u8; 32], kind: AssetKind) -> AssetPath {
        AssetPath { hash, kind }
    }

    /// The SHA-256 of the asset.
    #[must_use]
    pub const fn hash(&self) -> &[u8; 32] {
        &self.hash
    }

    /// The kind of the asset.
    #[must_use]
    pub const fn kind(&self) -> AssetKind {
        self.kind
    }

    /// The request path: the prefix, the hash and the extension.
    #[must_use]
    pub fn url(&self) -> String {
        format!("{ASSET_PREFIX}{}{}", hex(&self.hash), self.kind.extension())
    }
}

impl fmt::Debug for AssetPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AssetPath({})", self.url())
    }
}

impl fmt::Display for AssetPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.url())
    }
}

/// Resolves a request path to an asset path. Fuzzed (`static_path_resolve`).
///
/// The path is the prefix [`ASSET_PREFIX`], 64 lowercase hexadecimal
/// digits, then `.js` or `.css`, and nothing else. No decoding happens, so
/// a percent-encoded or otherwise respelled path is refused.
///
/// # Errors
///
/// [`AssetError::Path`] for every other byte string.
pub fn resolve_static_path(bytes: &[u8]) -> Result<AssetPath, AssetError> {
    let rest = bytes
        .strip_prefix(ASSET_PREFIX.as_bytes())
        .ok_or(AssetError::Path)?;
    let (digits, ext) = rest.split_at_checked(64).ok_or(AssetError::Path)?;
    let hash = hash_from_hex(digits).ok_or(AssetError::Path)?;
    let kind = match ext {
        b".js" => AssetKind::Script,
        b".css" => AssetKind::Style,
        _ => return Err(AssetError::Path),
    };
    Ok(AssetPath { hash, kind })
}
