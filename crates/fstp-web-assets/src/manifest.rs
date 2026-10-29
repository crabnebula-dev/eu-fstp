//! The asset manifest and its strict decoder (ADR-014, TH-26, H-05).

use std::collections::BTreeMap;
use std::fmt;

use crate::path::AssetKind;
use crate::{AssetError, MAX_ASSETS, MAX_MANIFEST_BYTES, hash_from_hex, hex};

/// The manifest's file name inside the asset directory.
pub const MANIFEST_FILE: &str = "asset-manifest.json";

/// The manifest schema name.
pub const SCHEMA: &str = "fstp.web-assets/1";

/// The longest manifest path, in bytes.
const MAX_PATH_BYTES: usize = 200;

/// The most segments of a manifest path.
const MAX_SEGMENTS: usize = 16;

/// A manifest path that passed the grammar of the crate documentation.
///
/// It is relative, has no empty, `.` or `..` segment, and holds only
/// ASCII letters, digits, `_`, `-`, `.` and `/`. So joining it to a
/// directory never leaves that directory by name.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ManifestPath(String);

impl ManifestPath {
    /// Checks `text` against the path grammar.
    ///
    /// # Errors
    ///
    /// [`AssetError::Manifest`] when `text` breaks it.
    pub fn new(text: &str) -> Result<ManifestPath, AssetError> {
        let bytes = text.as_bytes();
        if bytes.is_empty() || bytes.len() > MAX_PATH_BYTES {
            return Err(AssetError::Manifest("a path is empty or too long"));
        }
        let segments: Vec<&[u8]> = bytes.split(|b| *b == b'/').collect();
        if segments.len() > MAX_SEGMENTS {
            return Err(AssetError::Manifest("a path has too many segments"));
        }
        for seg in &segments {
            let (Some(first), Some(last)) = (seg.first(), seg.last()) else {
                return Err(AssetError::Manifest("a path has an empty segment"));
            };
            if *first == b'.' || *last == b'.' {
                return Err(AssetError::Manifest(
                    "a path segment starts or ends with a dot",
                ));
            }
            if !seg
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
            {
                return Err(AssetError::Manifest("a path holds a forbidden byte"));
            }
            if seg.windows(2).any(|w| w == b"..") {
                return Err(AssetError::Manifest("a path holds two dots"));
            }
        }
        if AssetKind::of_name(bytes).is_none() {
            return Err(AssetError::Manifest("a path ends in neither .js nor .css"));
        }
        Ok(ManifestPath(text.to_owned()))
    }

    /// The path text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The kind its extension names.
    #[must_use]
    pub fn kind(&self) -> AssetKind {
        AssetKind::of_name(self.0.as_bytes()).unwrap_or(AssetKind::Script)
    }

    /// The path's segments, in order.
    pub fn segments(&self) -> impl Iterator<Item = &str> {
        self.0.split('/')
    }
}

impl fmt::Debug for ManifestPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ManifestPath({:?})", self.0)
    }
}

/// A decoded asset manifest.
///
/// Equality ignores the member order of the text it came from.
#[derive(Clone, PartialEq, Eq)]
pub struct AssetManifest {
    entry: ManifestPath,
    assets: BTreeMap<ManifestPath, [u8; 32]>,
}

impl AssetManifest {
    /// The path of the module the shell loads.
    #[must_use]
    pub fn entry(&self) -> &ManifestPath {
        &self.entry
    }

    /// The SHA-256 the manifest lists for the entry.
    #[must_use]
    pub fn entry_hash(&self) -> Option<&[u8; 32]> {
        self.assets.get(&self.entry)
    }

    /// Every listed path with its SHA-256, in path order.
    pub fn assets(&self) -> impl Iterator<Item = (&ManifestPath, &[u8; 32])> {
        self.assets.iter()
    }

    /// The number of listed paths.
    #[must_use]
    pub fn len(&self) -> usize {
        self.assets.len()
    }

    /// Always false: a decoded manifest lists at least its entry.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.assets.is_empty()
    }

    /// The manifest text for `entry` and `assets`, compact. It decodes to
    /// the same manifest when every path passes the grammar.
    pub(crate) fn text(entry: &str, assets: &[(&str, [u8; 32])]) -> String {
        let members: Vec<String> = assets
            .iter()
            .map(|(p, h)| format!("\"{p}\":\"{}\"", hex(h)))
            .collect();
        format!(
            "{{\"assets\":{{{}}},\"entry\":\"{entry}\",\"schema\":\"{SCHEMA}\"}}",
            members.join(",")
        )
    }
}

impl fmt::Debug for AssetManifest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AssetManifest")
            .field("entry", &self.entry)
            .field("assets", &self.assets.len())
            .finish()
    }
}

/// Decodes the asset manifest. Fuzzed (`asset_manifest_decode`).
///
/// The text must be ASCII, at most [`MAX_MANIFEST_BYTES`] long, with no
/// backslash and no `..`, and be one JSON object with exactly the members
/// `schema`, `entry` and `assets`. Every path passes the grammar of
/// [`ManifestPath::new`], every hash is 64 lowercase hexadecimal digits,
/// and the entry is a listed `.js` path.
///
/// # Errors
///
/// [`AssetError::Manifest`] with the first rule the text breaks.
pub fn decode_manifest(bytes: &[u8]) -> Result<AssetManifest, AssetError> {
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(AssetError::Manifest("the manifest is too large"));
    }
    if !bytes.is_ascii() {
        return Err(AssetError::Manifest("the manifest is not ASCII"));
    }
    if bytes.contains(&b'\\') {
        return Err(AssetError::Manifest("the manifest holds a backslash"));
    }
    if bytes.windows(2).any(|w| w == b"..") {
        return Err(AssetError::Manifest("the manifest holds two dots"));
    }
    let value = fstp_json::parse(bytes).map_err(|_| AssetError::Manifest("not JSON"))?;
    let top = value
        .as_object()
        .ok_or(AssetError::Manifest("not a JSON object"))?;
    if top.len() != 3 {
        return Err(AssetError::Manifest(
            "the manifest needs exactly three members",
        ));
    }
    let schema = top
        .get("schema")
        .and_then(fstp_json::Value::as_str)
        .ok_or(AssetError::Manifest("no schema string"))?;
    if schema != SCHEMA {
        return Err(AssetError::Manifest("another schema"));
    }
    let entry = top
        .get("entry")
        .and_then(fstp_json::Value::as_str)
        .ok_or(AssetError::Manifest("no entry string"))?;
    let entry = ManifestPath::new(entry)?;
    if entry.kind() != AssetKind::Script {
        return Err(AssetError::Manifest("the entry is not a .js path"));
    }
    let listed = top
        .get("assets")
        .and_then(fstp_json::Value::as_object)
        .ok_or(AssetError::Manifest("no assets object"))?;
    if listed.is_empty() {
        return Err(AssetError::Manifest("no assets"));
    }
    if listed.len() > MAX_ASSETS {
        return Err(AssetError::Manifest("too many assets"));
    }
    let mut assets = BTreeMap::new();
    for (path, hash) in listed.iter() {
        let path = ManifestPath::new(path)?;
        let hash = hash
            .as_str()
            .and_then(|h| hash_from_hex(h.as_bytes()))
            .ok_or(AssetError::Manifest(
                "a hash is not 64 lowercase hexadecimal digits",
            ))?;
        if assets.insert(path, hash).is_some() {
            return Err(AssetError::Manifest("a duplicated path"));
        }
    }
    if !assets.contains_key(&entry) {
        return Err(AssetError::Manifest("the entry is not listed"));
    }
    Ok(AssetManifest { entry, assets })
}

#[cfg(test)]
#[allow(clippy::panic, reason = "a test fails by panicking")]
mod tests {
    use super::*;

    /// ADR-014: the text writer and the decoder agree.
    #[test]
    fn adr014_manifest_text_decodes() {
        let text = AssetManifest::text("main.js", &[("main.js", [1; 32]), ("a/b.css", [2; 32])]);
        let m = decode_manifest(text.as_bytes()).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(m.entry().as_str(), "main.js");
        assert_eq!(m.len(), 2);
        assert_eq!(m.entry_hash(), Some(&[1; 32]));
    }

    /// ADR-014: a segment that ends with a dot is refused.
    #[test]
    fn adr014_manifest_path_refuses_a_trailing_dot() {
        assert!(ManifestPath::new("a./b.js").is_err());
        assert!(ManifestPath::new("a/b.js").is_ok());
    }
}
