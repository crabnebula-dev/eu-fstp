//! A verified asset set and its responses (ADR-014).

use std::collections::BTreeMap;
use std::fmt;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use fstp_http::{Response, StatusCode};

use crate::manifest::{AssetManifest, MANIFEST_FILE, decode_manifest};
use crate::path::{AssetKind, AssetPath, resolve_static_path};
use crate::{AssetError, MAX_ASSET_BYTES, MAX_MANIFEST_BYTES, MAX_TOTAL_BYTES};

/// The fixed `Cache-Control` value of an asset response.
pub const ASSET_CACHE_CONTROL: &str = "public, max-age=31536000, immutable";

/// The compiled frontend after verification: every listed file, keyed by
/// its content-addressed path.
#[derive(Clone)]
pub struct AssetSet {
    entry: AssetPath,
    styles: Vec<AssetPath>,
    files: BTreeMap<AssetPath, Arc<[u8]>>,
}

impl fmt::Debug for AssetSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AssetSet")
            .field("entry", &self.entry)
            .field("styles", &self.styles.len())
            .field("files", &self.files.len())
            .finish()
    }
}

/// Loads and verifies the asset directory `dir`.
///
/// It reads [`MANIFEST_FILE`] and every listed file and checks each
/// file's SHA-256 against the manifest. Any failure refuses the whole set,
/// so a cell never starts with a changed or missing asset. Files the
/// manifest does not list are never read.
///
/// # Errors
///
/// An [`AssetError`] naming the manifest rule or the file that failed.
pub fn load_dir(dir: &Path) -> Result<AssetSet, AssetError> {
    let manifest_path = dir.join(MANIFEST_FILE);
    let text = read_regular(&manifest_path, MANIFEST_FILE, len_u64(MAX_MANIFEST_BYTES))?;
    let manifest = decode_manifest(&text)?;
    let mut total: u64 = 0;
    assemble(&manifest, |path| {
        let mut full = PathBuf::from(dir);
        let mut segments = path.segments().peekable();
        while let Some(seg) = segments.next() {
            full.push(seg);
            if segments.peek().is_some() {
                directory_not_link(&full, path.as_str())?;
            }
        }
        let bytes = read_regular(&full, path.as_str(), MAX_ASSET_BYTES)?;
        total = total.saturating_add(len_u64(bytes.len()));
        if total > MAX_TOTAL_BYTES {
            return Err(AssetError::TooLarge(path.as_str().to_owned()));
        }
        Ok(bytes)
    })
}

/// `n` as `u64`, saturating on a platform where it does not fit.
fn len_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// Fails unless `full` is a directory reached without a symbolic link.
fn directory_not_link(full: &Path, label: &str) -> Result<(), AssetError> {
    let meta = std::fs::symlink_metadata(full).map_err(|e| AssetError::Io {
        file: label.to_owned(),
        kind: e.kind(),
    })?;
    if meta.file_type().is_dir() {
        Ok(())
    } else {
        Err(AssetError::NotAFile(label.to_owned()))
    }
}

/// Reads `full`, which must be a regular file and no symbolic link, of at
/// most `limit` bytes.
///
/// The path is checked without following a link, then opened once. The
/// opened handle must be the same regular file that was checked, so a
/// file swapped for a link between the two steps is refused. The read
/// stops after `limit + 1` bytes, so a file that grows in that window
/// never allocates more than the limit allows.
fn read_regular(full: &Path, label: &str, limit: u64) -> Result<Vec<u8>, AssetError> {
    let io = |e: std::io::Error| AssetError::Io {
        file: label.to_owned(),
        kind: e.kind(),
    };
    let checked = std::fs::symlink_metadata(full).map_err(io)?;
    if !checked.file_type().is_file() {
        return Err(AssetError::NotAFile(label.to_owned()));
    }
    if checked.len() > limit {
        return Err(AssetError::TooLarge(label.to_owned()));
    }
    let file = std::fs::File::open(full).map_err(io)?;
    let opened = file.metadata().map_err(io)?;
    if !opened.file_type().is_file() || !same_file(&checked, &opened) {
        return Err(AssetError::NotAFile(label.to_owned()));
    }
    if opened.len() > limit {
        return Err(AssetError::TooLarge(label.to_owned()));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(opened.len()).unwrap_or(0));
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(io)?;
    if len_u64(bytes.len()) > limit {
        return Err(AssetError::TooLarge(label.to_owned()));
    }
    Ok(bytes)
}

/// Whether two metadata values describe one file: the same device and
/// inode.
#[cfg(unix)]
fn same_file(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    a.dev() == b.dev() && a.ino() == b.ino()
}

/// Whether two metadata values describe one file. Without inode numbers,
/// only the length is compared, and the bounded read still holds.
#[cfg(not(unix))]
fn same_file(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    a.len() == b.len()
}

/// Builds a set from `manifest`, reading each listed path with `read` and
/// verifying its SHA-256.
fn assemble(
    manifest: &AssetManifest,
    mut read: impl FnMut(&crate::ManifestPath) -> Result<Vec<u8>, AssetError>,
) -> Result<AssetSet, AssetError> {
    let mut files: BTreeMap<AssetPath, Arc<[u8]>> = BTreeMap::new();
    let mut styles = Vec::new();
    for (path, hash) in manifest.assets() {
        let bytes = read(path)?;
        if fstp_crypto::sha256(&bytes) != *hash {
            return Err(AssetError::Mismatch(path.as_str().to_owned()));
        }
        let key = AssetPath::new(*hash, path.kind());
        if key.kind() == AssetKind::Style && !styles.contains(&key) {
            styles.push(key);
        }
        files.entry(key).or_insert_with(|| Arc::from(bytes));
    }
    let entry_hash = manifest
        .entry_hash()
        .ok_or(AssetError::Manifest("the entry is not listed"))?;
    Ok(AssetSet {
        entry: AssetPath::new(*entry_hash, AssetKind::Script),
        styles,
        files,
    })
}

impl AssetSet {
    /// A verified set from files held in memory, for tests and for the
    /// stub configuration of `fstp-web`. `files` pairs each manifest path
    /// with its content, and `entry` names the module the shell loads.
    ///
    /// It writes the manifest text for these files and runs the same
    /// decoder and verification as [`load_dir`].
    ///
    /// # Errors
    ///
    /// An [`AssetError`] when a path breaks the grammar, a path repeats or
    /// the entry is not a listed `.js` path.
    pub fn from_files(entry: &str, files: &[(&str, &[u8])]) -> Result<AssetSet, AssetError> {
        let hashed: Vec<(&str, [u8; 32])> = files
            .iter()
            .map(|(p, c)| (*p, fstp_crypto::sha256(c)))
            .collect();
        let text = AssetManifest::text(entry, &hashed);
        let manifest = decode_manifest(text.as_bytes())?;
        if manifest.len() != files.len() {
            return Err(AssetError::Manifest("a duplicated path"));
        }
        assemble(&manifest, |path| {
            files
                .iter()
                .find(|(p, _)| *p == path.as_str())
                .map(|(_, c)| c.to_vec())
                .ok_or(AssetError::Manifest("the entry is not listed"))
        })
    }

    /// The content-addressed path of the entry module.
    #[must_use]
    pub fn entry(&self) -> AssetPath {
        self.entry
    }

    /// The request path of the entry module, such as
    /// `/app/assets/{sha256}.js`.
    #[must_use]
    pub fn entry_path(&self) -> String {
        self.entry.url()
    }

    /// The request path of every distinct stylesheet, in manifest path
    /// order. Interim, pending Daniel: the shell links each of them.
    #[must_use]
    pub fn style_paths(&self) -> Vec<String> {
        self.styles.iter().map(AssetPath::url).collect()
    }

    /// The number of distinct served assets.
    #[must_use]
    pub fn len(&self) -> usize {
        self.files.len()
    }

    /// True when the set serves nothing. A loaded set always serves its
    /// entry.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// The 200 response for `path`, or `None` when no listed asset has
    /// that hash and kind.
    ///
    /// The response carries exactly one each of `Content-Type` for its
    /// kind, `Cache-Control: public, max-age=31536000, immutable`,
    /// `X-Content-Type-Options: nosniff` and
    /// `Cross-Origin-Resource-Policy: same-origin`, and sets no cookie.
    #[must_use]
    pub fn response(&self, path: &AssetPath) -> Option<Response> {
        let body = self.files.get(path)?;
        let mut resp =
            Response::with_body(StatusCode::OK, path.kind().content_type(), body.to_vec());
        // Each name and value is a valid constant, so no insert fails.
        for (name, value) in [
            ("cache-control", ASSET_CACHE_CONTROL),
            ("x-content-type-options", "nosniff"),
            ("cross-origin-resource-policy", "same-origin"),
        ] {
            let _ = resp.headers.try_insert(name, value);
        }
        Some(resp)
    }

    /// The response for the raw request path `request_path`: `None` when
    /// it breaks the asset path grammar or names no listed asset.
    #[must_use]
    pub fn response_for(&self, request_path: &[u8]) -> Option<Response> {
        let path = resolve_static_path(request_path).ok()?;
        self.response(&path)
    }
}

#[cfg(test)]
#[allow(clippy::panic, reason = "a test fails by panicking")]
mod tests {
    use super::*;

    /// ADR-014: an in-memory set serves its entry and refuses a repeat.
    #[test]
    fn adr014_from_files_serves_the_entry() {
        let set = AssetSet::from_files("main.js", &[("main.js", b"export {};\n")])
            .unwrap_or_else(|e| panic!("{e}"));
        let resp = set
            .response_for(set.entry_path().as_bytes())
            .unwrap_or_else(|| panic!("the entry is not served"));
        assert_eq!(resp.body, b"export {};\n");
        assert!(AssetSet::from_files("main.js", &[("main.js", b"a"), ("main.js", b"b")]).is_err());
    }
}
