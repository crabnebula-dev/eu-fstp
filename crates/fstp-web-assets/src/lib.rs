//! The compiled frontend (ADR-014).
//!
//! The crate loads the compiled frontend from a directory, verifies it
//! against a SHA-256 manifest at start and serves it with fixed headers.
//! Assets are served at `/app/assets/{sha256}.js` and are immutable.
//!
//! # Interim readings, pending Daniel
//!
//! ADR-014 fixes the rules but not the manifest grammar, the file layout
//! or the header values. This crate reads them as follows. Each reading is
//! marked "Interim, pending Daniel" (M4 design section 15.0).
//!
//! - The directory holds the manifest [`MANIFEST_FILE`] and each asset at
//!   its manifest path, as `tsc` writes `web/dist/`.
//! - The manifest is one JSON object with exactly three members:
//!   `schema`, equal to [`SCHEMA`]; `entry`, the path of the module the
//!   shell loads; and `assets`, an object from each path to the SHA-256 of
//!   the file as 64 lowercase hexadecimal digits.
//! - A path is ASCII, 1 to 200 bytes, with 1 to 16 segments separated by
//!   `/`. Each segment is made of letters, digits, `_`, `-` and `.`. No
//!   segment starts or ends with `.`, and no path holds `..`. The last
//!   segment ends in `.js` or `.css`. The entry is a listed `.js` path.
//! - The manifest text is ASCII and holds no backslash and no `..`, so no
//!   JSON escape gives a path a second spelling.
//! - Two paths may share one hash, since `tsc` writes `export {};` for
//!   every module with types only.
//! - `.css` assets are an addition to ADR-014, which names `.js` assets
//!   only. The CSP's `style-src 'self'` needs a same-origin stylesheet.
//! - An asset is served at `/app/assets/{sha256}.js` or
//!   `/app/assets/{sha256}.css` with the fixed headers of
//!   [`AssetSet::response`]. Every other request path is refused before
//!   any lookup, so no request can name a file outside the manifest.
//! - Loading verifies every listed file against its hash at start. A
//!   missing file, a directory, a symbolic link, an oversized file or a
//!   mismatch refuses the whole set.

mod manifest;
mod path;
mod set;

pub use manifest::{AssetManifest, MANIFEST_FILE, ManifestPath, SCHEMA, decode_manifest};
pub use path::{ASSET_PREFIX, AssetKind, AssetPath, resolve_static_path};
pub use set::{ASSET_CACHE_CONTROL, AssetSet, load_dir};

/// The largest manifest text, in bytes.
pub const MAX_MANIFEST_BYTES: usize = 1024 * 1024;

/// The most assets one manifest may list.
pub const MAX_ASSETS: usize = 4096;

/// The largest single asset, in bytes.
pub const MAX_ASSET_BYTES: u64 = 8 * 1024 * 1024;

/// The largest total of every listed asset, in bytes.
pub const MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;

/// Why an operation of this crate failed.
///
/// No variant quotes file content. A path is a manifest path, which the
/// grammar limits to ASCII letters, digits, `_`, `-`, `.` and `/`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AssetError {
    /// Reserved for an operation that waits for another lane. No
    /// operation of this crate returns it now.
    NotImplemented(&'static str),
    /// The manifest breaks its grammar, for the fixed reason given.
    Manifest(&'static str),
    /// A request path outside the asset path grammar.
    Path,
    /// Reading a file or its metadata failed.
    Io {
        /// The manifest path, or [`MANIFEST_FILE`].
        file: String,
        /// The kind of the I/O error.
        kind: std::io::ErrorKind,
    },
    /// A listed path is not a regular file, or passes through a symbolic
    /// link.
    NotAFile(String),
    /// A listed file, or the total of every listed file, is over its limit.
    TooLarge(String),
    /// A listed file's SHA-256 differs from its manifest hash.
    Mismatch(String),
}

impl std::fmt::Display for AssetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AssetError::NotImplemented(op) => write!(f, "{op} is not implemented yet"),
            AssetError::Manifest(why) => write!(f, "invalid asset manifest: {why}"),
            AssetError::Path => f.write_str("the path names no asset"),
            AssetError::Io { file, kind } => write!(f, "cannot read {file}: {kind}"),
            AssetError::NotAFile(file) => write!(f, "{file} is not a regular file"),
            AssetError::TooLarge(file) => write!(f, "{file} is over the size limit"),
            AssetError::Mismatch(file) => {
                write!(f, "{file} does not match its manifest hash")
            }
        }
    }
}

impl std::error::Error for AssetError {}

/// Lowercase hexadecimal of `bytes`.
pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        for nibble in [b >> 4, b & 0x0f] {
            if let Some(d) = DIGITS.get(usize::from(nibble)) {
                s.push(char::from(*d));
            }
        }
    }
    s
}

/// The 32 bytes of 64 lowercase hexadecimal digits, or `None` for any
/// other text.
pub(crate) fn hash_from_hex(text: &[u8]) -> Option<[u8; 32]> {
    if text.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (slot, pair) in out.iter_mut().zip(text.chunks_exact(2)) {
        let [hi, lo] = pair else {
            return None;
        };
        *slot = (nibble(*hi)? << 4) | nibble(*lo)?;
    }
    Some(out)
}

/// The value of one lowercase hexadecimal digit.
fn nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => b.checked_sub(b'0'),
        b'a'..=b'f' => b.checked_sub(b'a').and_then(|v| v.checked_add(10)),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::panic, reason = "a test fails by panicking")]
mod tests {
    use super::*;

    /// ADR-014: hexadecimal round trip and the refused spellings.
    #[test]
    fn adr014_hash_hex_round_trip() {
        let h = [0xa5u8; 32];
        assert_eq!(hash_from_hex(hex(&h).as_bytes()), Some(h));
        assert_eq!(hash_from_hex(hex(&h).to_ascii_uppercase().as_bytes()), None);
        assert_eq!(hash_from_hex(&[b'0'; 63]), None);
        assert_eq!(hash_from_hex(&[b'g'; 64]), None);
    }
}
