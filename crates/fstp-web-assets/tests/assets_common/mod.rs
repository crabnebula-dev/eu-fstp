//! Shared helpers of the `fstp-web-assets` tests (lane W4e, test author).
//!
//! The tests were written before the asset server exists. They reach
//! production only through the seams in this module. A seam either calls
//! the W0 stub, which refuses with `AssetError::NotImplemented`, or
//! refuses with a [`Red::Seam`] that names the production API it waits
//! for. So every test that needs one is red for that reason only. The
//! production agent of lane W4e replaces each seam body with one call into
//! `fstp_web_assets`, and the tests then run unchanged.
//!
//! # Readings the asset tests share
//!
//! ADR-014 and M4 design sections 1.1 and 3.9 fix the rules but not the
//! manifest grammar, the file layout or the header values. These tests
//! read them as follows. Each is an interim reading, pending Daniel. If
//! production picks another grammar, only [`manifest_json`] and the
//! constants here change.
//!
//! - The directory holds the manifest [`MANIFEST_FILE`] and each asset at
//!   its manifest path, as `tsc` writes `web/dist/`.
//! - The manifest is one JSON object with exactly three members:
//!   `schema`, equal to [`SCHEMA`]; `entry`, the path of the module the
//!   shell loads; and `assets`, an object from each path to the SHA-256 of
//!   the file as 64 lowercase hexadecimal digits.
//! - A path is ASCII, 1 to 200 bytes, with 1 to 16 segments separated by
//!   `/`. Each segment is made of letters, digits, `_`, `-` and `.`. No
//!   segment starts with `.`, and no path holds `..`. The last segment
//!   ends in `.js` or `.css`. The entry is a listed `.js` path.
//! - The manifest text holds no backslash, so no JSON escape gives a path
//!   a second spelling. Insignificant white space and member order are
//!   free.
//! - Two paths may share one hash: `tsc` writes `export {};` for every
//!   module with types only.
//! - `.css` assets are an interim addition. ADR-014 names `.js` assets;
//!   the CSP's `style-src 'self'` needs a same-origin stylesheet too.
//! - An asset is served at `/app/assets/{sha256}.js` or
//!   `/app/assets/{sha256}.css`, with status 200 and the fixed headers of
//!   [`ASSET_HEADERS_JS`] or [`ASSET_HEADERS_CSS`], each exactly once.
//! - Loading verifies every listed file against its hash at start. Any
//!   missing file or mismatch refuses the whole set. A file the manifest
//!   does not list is never served.

#![allow(dead_code, reason = "each test binary uses a different part")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test fixtures assert on known-good values"
)]

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fstp_http::Response;
use fstp_web_assets::AssetError;

// ---------------------------------------------------------------------------
// Readings.

/// The manifest's file name inside the asset directory.
pub(crate) const MANIFEST_FILE: &str = "asset-manifest.json";

/// The manifest schema name.
pub(crate) const SCHEMA: &str = "fstp.web-assets/1";

/// The URL prefix of every asset.
pub(crate) const ASSET_PREFIX: &str = "/app/assets/";

/// The fixed headers of a served `.js` asset.
pub(crate) const ASSET_HEADERS_JS: [(&str, &str); 4] = [
    ("content-type", "text/javascript; charset=utf-8"),
    ("cache-control", "public, max-age=31536000, immutable"),
    ("x-content-type-options", "nosniff"),
    ("cross-origin-resource-policy", "same-origin"),
];

/// The fixed headers of a served `.css` asset.
pub(crate) const ASSET_HEADERS_CSS: [(&str, &str); 4] = [
    ("content-type", "text/css; charset=utf-8"),
    ("cache-control", "public, max-age=31536000, immutable"),
    ("x-content-type-options", "nosniff"),
    ("cross-origin-resource-policy", "same-origin"),
];

// ---------------------------------------------------------------------------
// Seams.

/// Why a test could not reach production yet, or why production refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Red {
    /// The W0 stub refused with `NotImplemented`.
    Stub(&'static str),
    /// A seam waits for the named production API.
    Seam(&'static str),
    /// Production refused with a typed error other than `NotImplemented`.
    Refused(String),
}

impl fmt::Display for Red {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Red::Stub(op) => write!(f, "stub (lane W4e, NotImplemented): {op}"),
            Red::Seam(api) => write!(f, "seam (lane W4e, NotImplemented): {api}"),
            Red::Refused(e) => write!(f, "refused: {e}"),
        }
    }
}

/// Maps an asset error to [`Red`], keeping the stub refusal apart.
fn red(e: AssetError) -> Red {
    match e {
        AssetError::NotImplemented(op) => Red::Stub(op),
        #[allow(unreachable_patterns, reason = "production adds refusal variants")]
        other => Red::Refused(format!("{other:?}")),
    }
}

/// Decodes a manifest. `Ok` holds the decoded value for equality checks.
pub(crate) fn decode(bytes: &[u8]) -> Result<fstp_web_assets::AssetManifest, Red> {
    fstp_web_assets::decode_manifest(bytes).map_err(red)
}

/// Resolves a request path to an asset path.
pub(crate) fn resolve(path: &[u8]) -> Result<fstp_web_assets::AssetPath, Red> {
    fstp_web_assets::resolve_static_path(path).map_err(red)
}

/// A verified asset set, loaded from a directory.
#[derive(Debug)]
pub(crate) struct Loaded {
    set: fstp_web_assets::AssetSet,
}

/// Loads and verifies the asset directory `dir`.
pub(crate) fn load(dir: &Path) -> Result<Loaded, Red> {
    fstp_web_assets::load_dir(dir)
        .map(|set| Loaded { set })
        .map_err(red)
}

/// The response for one request path: `Ok(None)` when no listed asset
/// answers it.
pub(crate) fn serve(set: &Loaded, path: &str) -> Result<Option<Response>, Red> {
    Ok(set.set.response_for(path.as_bytes()))
}

/// The URL path of the entry module.
pub(crate) fn entry_path(set: &Loaded) -> Result<String, Red> {
    Ok(set.set.entry_path())
}

// ---------------------------------------------------------------------------
// Predicates.

/// `Ok` when `r` is a typed refusal that is not the W0 stub.
pub(crate) fn refused<T: fmt::Debug>(r: Result<T, Red>) -> Result<(), String> {
    match r {
        Err(Red::Refused(_)) => Ok(()),
        Err(other) => Err(format!("not a typed refusal: {other}")),
        Ok(v) => Err(format!("accepted: {v:?}")),
    }
}

/// Every value of the response field `name`, as text.
pub(crate) fn header_values(resp: &Response, name: &str) -> Vec<String> {
    resp.headers
        .get_all(name)
        .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
        .collect()
}

/// `Ok` when `resp` is the 200 answer for `body` with exactly the fixed
/// asset headers `fixed`, and sets no cookie.
pub(crate) fn served_as(
    resp: &Response,
    body: &[u8],
    fixed: &[(&str, &str)],
) -> Result<(), String> {
    if resp.status.as_u16() != 200 {
        return Err(format!("status {}", resp.status.as_u16()));
    }
    if resp.body != body {
        return Err("the body differs from the file".to_owned());
    }
    for (name, want) in fixed {
        let got = header_values(resp, name);
        if got != [*want] {
            return Err(format!("{name}: {got:?}, want exactly [{want:?}]"));
        }
    }
    if resp.headers.contains("set-cookie") {
        return Err("an asset response sets a cookie".to_owned());
    }
    Ok(())
}

/// The grammar of a request path that names an asset: the prefix, 64
/// lowercase hexadecimal digits, then `.js` or `.css`, and nothing else.
pub(crate) fn path_grammar(path: &[u8]) -> bool {
    let Some(rest) = path.strip_prefix(ASSET_PREFIX.as_bytes()) else {
        return false;
    };
    if rest.len() < 64 {
        return false;
    }
    let (hash, ext) = rest.split_at(64);
    hash.iter()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
        && (ext == b".js" || ext == b".css")
}

// ---------------------------------------------------------------------------
// Fixtures.

/// Lowercase hexadecimal of `bytes`.
pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from(DIGITS[usize::from(b >> 4)]));
        s.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    s
}

/// The SHA-256 of `content` as 64 lowercase hexadecimal digits.
pub(crate) fn sha_hex(content: &[u8]) -> String {
    hex(&fstp_crypto::sha256(content))
}

/// The manifest text for `entry` and `assets`, in the given member order,
/// with no white space. `assets` pairs a path with its hash text.
pub(crate) fn manifest_json(entry: &str, assets: &[(&str, &str)]) -> String {
    let members: Vec<String> = assets
        .iter()
        .map(|(p, h)| format!("\"{p}\":\"{h}\""))
        .collect();
    format!(
        "{{\"assets\":{{{}}},\"entry\":\"{entry}\",\"schema\":\"{SCHEMA}\"}}",
        members.join(",")
    )
}

/// Three synthetic modules and a stylesheet. `types.js` and `empty.js`
/// share their content, as type-only modules do.
pub(crate) fn sample_files() -> Vec<(String, Vec<u8>)> {
    vec![
        (
            "main.js".to_owned(),
            b"import \"./core/dom.js\";\nexport const started = 1;\n".to_vec(),
        ),
        (
            "core/dom.js".to_owned(),
            b"export function h() { return 0; }\n".to_vec(),
        ),
        ("core/types.js".to_owned(), b"export {};\n".to_vec()),
        ("gen/empty.js".to_owned(), b"export {};\n".to_vec()),
        (
            "styles/app.css".to_owned(),
            b"body { margin: 0; }\n".to_vec(),
        ),
    ]
}

/// The manifest of `files` with entry `main.js`.
pub(crate) fn manifest_for(files: &[(String, Vec<u8>)]) -> String {
    let hashes: Vec<(String, String)> =
        files.iter().map(|(p, c)| (p.clone(), sha_hex(c))).collect();
    let pairs: Vec<(&str, &str)> = hashes
        .iter()
        .map(|(p, h)| (p.as_str(), h.as_str()))
        .collect();
    manifest_json("main.js", &pairs)
}

/// A fresh, empty directory under the integration test scratch directory.
/// It is removed when the value drops.
pub(crate) struct ScratchDir {
    path: PathBuf,
}

impl ScratchDir {
    /// A new directory whose name starts with `label`.
    pub(crate) fn new(label: &str) -> ScratchDir {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join("fstp-web-assets")
            .join(format!("{label}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        ScratchDir { path }
    }

    /// The directory.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Writes `content` at the relative path `rel`, creating parents.
    pub(crate) fn write(&self, rel: &str, content: &[u8]) {
        let p = self.path.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(p, content).unwrap();
    }

    /// Writes every file and the manifest text `manifest`.
    pub(crate) fn write_all(&self, files: &[(String, Vec<u8>)], manifest: &str) {
        for (p, c) in files {
            self.write(p, c);
        }
        self.write(MANIFEST_FILE, manifest.as_bytes());
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
