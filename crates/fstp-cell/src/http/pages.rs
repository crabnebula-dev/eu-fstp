//! The compiled auth pages of the cell origin (design section 11.2,
//! ADR-003).
//!
//! The pages are the in-house TypeScript of `web/src/auth`, compiled by
//! the pinned `tsc` into `web/dist/auth` (`tools/devstack/run.sh` runs it).
//! [`Pages::load`] reads them once at start into memory, so a request
//! never touches the file system:
//!
//! - the shell `shell.html` of the source directory, served on each page
//!   path of [`PAGE_PATHS`];
//! - each `.js` file of the compiled directory and of its `pages`
//!   directory, served at `/assets/auth/<name>` and
//!   `/assets/auth/pages/<name>`;
//! - each `.css` file of the source directory, served at
//!   `/assets/auth/<name>`.
//!
//! The front sets the cell CSP of design section 11.2 on every reply,
//! which allows exactly these same-origin scripts and styles. The pages
//! hold no inline script or style, and no third-party asset exists.
//!
//! Every page path and asset route is a row of
//! `crate::routes::page_table`, with its risk class (I-78), and runs the
//! shared checks of every route. Those rows are not rows of
//! `crate::routes::table`, the transcription of design section 8.7,
//! which lists `GET /auth/magic` as its only page. So the production
//! front serves none of them: only `Front::with_pages`, behind the test
//! and dev-stack feature `dev-pages`, does. `GET /auth/magic` keeps its
//! table route, whose handler serves the shell when pages are loaded.
//! Adding the page rows to section 8.7 is a question for Daniel, raised
//! by lane int4.
//!
//! [`Pages::load`] refuses a directory that lacks the shell, `main.js`
//! or a stylesheet, a symbolic link, a file name outside a closed
//! grammar, a file over [`MAX_ASSET`] bytes or more than [`MAX_ASSETS`]
//! files. So a cell never serves part of a build, or a file planted
//! beside it under an unexpected name.

use std::collections::BTreeMap;
use std::path::Path;

/// The page paths that serve the shell (`web/src/auth/layout.ts`
/// `PATHS`). `/auth/magic` is served by its table route.
pub const PAGE_PATHS: [&str; 5] = [
    "/auth/login",
    "/auth/signup",
    "/auth/invite",
    "/auth/recovery",
    "/auth/account",
];

/// The confirm page of design section 8.7, served by its table route
/// with the shell when pages are loaded.
pub const MAGIC_PATH: &str = "/auth/magic";

/// The asset route templates: the compiled modules and stylesheets, and
/// the page modules one directory down.
pub const ASSET_ROUTES: [&str; 2] = ["/assets/auth/{file}", "/assets/auth/pages/{file}"];

/// The largest asset or shell the cell loads.
pub const MAX_ASSET: u64 = 1 << 20;

/// The most assets the cell loads.
pub const MAX_ASSETS: usize = 128;

/// The longest asset file name.
const MAX_NAME: usize = 64;

/// The media type of the shell.
pub const HTML: &str = "text/html; charset=utf-8";
/// The media type of a module.
pub const JAVASCRIPT: &str = "text/javascript; charset=utf-8";
/// The media type of a stylesheet.
pub const CSS: &str = "text/css; charset=utf-8";

/// Why the pages did not load. It names a part, never file content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PagesError {
    /// A directory or file could not be read. It names the path.
    Read(String),
    /// A required file is missing: the shell, `main.js` or a stylesheet.
    Missing(&'static str),
    /// A file is a symbolic link, or not a regular file. It names it.
    NotAFile(String),
    /// A file name is outside the asset grammar. It names it.
    Name(String),
    /// A file is over [`MAX_ASSET`] bytes. It names it.
    TooLarge(String),
    /// The directories hold more than [`MAX_ASSETS`] assets.
    TooMany,
}

impl std::fmt::Display for PagesError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PagesError::Read(p) => write!(f, "cannot read {p}"),
            PagesError::Missing(what) => write!(f, "the pages lack {what}"),
            PagesError::NotAFile(p) => write!(f, "{p} is not a regular file"),
            PagesError::Name(n) => write!(f, "{n} is not an asset name"),
            PagesError::TooLarge(p) => write!(f, "{p} is over {MAX_ASSET} bytes"),
            PagesError::TooMany => write!(f, "the pages hold over {MAX_ASSETS} assets"),
        }
    }
}

impl std::error::Error for PagesError {}

/// One served asset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Asset {
    /// Its media type.
    pub content_type: &'static str,
    /// Its bytes.
    pub body: Vec<u8>,
}

/// The loaded pages: the shell and the assets by their path under
/// `/assets/auth/`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pages {
    shell: Vec<u8>,
    assets: BTreeMap<String, Asset>,
}

/// Whether `name` is an asset file name: lowercase letters, digits,
/// `.`, `_` and `-`, starting with a letter or digit, ending in `.js` or
/// `.css`, at most [`MAX_NAME`] bytes.
fn asset_name(name: &str) -> Option<&'static str> {
    let b = name.as_bytes();
    let ok = !b.is_empty()
        && b.len() <= MAX_NAME
        && b.first().is_some_and(u8::is_ascii_alphanumeric)
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"._-".contains(c));
    if !ok {
        None
    } else if name.ends_with(".js") {
        Some(JAVASCRIPT)
    } else if name.ends_with(".css") {
        Some(CSS)
    } else {
        None
    }
}

/// Reads the regular file `path`, at most [`MAX_ASSET`] bytes.
fn read_file(path: &Path) -> Result<Vec<u8>, PagesError> {
    let shown = || path.display().to_string();
    let meta = std::fs::symlink_metadata(path).map_err(|_| PagesError::Read(shown()))?;
    if !meta.is_file() {
        return Err(PagesError::NotAFile(shown()));
    }
    if meta.len() > MAX_ASSET {
        return Err(PagesError::TooLarge(shown()));
    }
    std::fs::read(path).map_err(|_| PagesError::Read(shown()))
}

/// The assets of `dir` whose media type is `want`, keyed by `prefix` and
/// the file name. Directories are skipped, and every other entry must be
/// an asset of an allowed name.
fn load_dir(
    dir: &Path,
    prefix: &str,
    want: &'static str,
    out: &mut BTreeMap<String, Asset>,
) -> Result<(), PagesError> {
    let shown = || dir.display().to_string();
    let entries = std::fs::read_dir(dir).map_err(|_| PagesError::Read(shown()))?;
    let mut paths = Vec::new();
    for e in entries {
        let e = e.map_err(|_| PagesError::Read(shown()))?;
        paths.push(e.path());
    }
    paths.sort();
    for path in paths {
        let meta = std::fs::symlink_metadata(&path)
            .map_err(|_| PagesError::Read(path.display().to_string()))?;
        if meta.is_dir() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            return Err(PagesError::Name(path.display().to_string()));
        };
        match asset_name(name) {
            Some(kind) if kind == want => {}
            // A source directory also holds the TypeScript and the shell,
            // and a compiled one holds only modules: other files of an
            // allowed form are not this directory's assets.
            _ if want == CSS => continue,
            _ => return Err(PagesError::Name(name.to_owned())),
        }
        if out.len() >= MAX_ASSETS {
            return Err(PagesError::TooMany);
        }
        let body = read_file(&path)?;
        out.insert(
            format!("{prefix}{name}"),
            Asset {
                content_type: want,
                body,
            },
        );
    }
    Ok(())
}

impl Pages {
    /// Loads the pages from `compiled`, the `tsc` output of `web/src/auth`
    /// (`web/dist/auth`), and `sources`, the directory `web/src/auth` that
    /// holds the shell and the stylesheets (module documentation).
    ///
    /// # Errors
    ///
    /// A [`PagesError`] for a missing directory or required file, a
    /// symbolic link, a name outside the grammar, a file over
    /// [`MAX_ASSET`] bytes, or more than [`MAX_ASSETS`] assets.
    pub fn load(compiled: &Path, sources: &Path) -> Result<Pages, PagesError> {
        let shell = read_file(&sources.join("shell.html"))?;
        let mut assets = BTreeMap::new();
        load_dir(compiled, "", JAVASCRIPT, &mut assets)?;
        let pages = compiled.join("pages");
        if std::fs::symlink_metadata(&pages).is_ok_and(|m| m.is_dir()) {
            load_dir(&pages, "pages/", JAVASCRIPT, &mut assets)?;
        }
        load_dir(sources, "", CSS, &mut assets)?;
        if !assets.contains_key("main.js") {
            return Err(PagesError::Missing("main.js"));
        }
        if !assets.values().any(|a| a.content_type == CSS) {
            return Err(PagesError::Missing("a stylesheet"));
        }
        Ok(Pages { shell, assets })
    }

    /// The shell every page path serves.
    pub fn shell(&self) -> &[u8] {
        &self.shell
    }

    /// The asset at `/assets/auth/<rel>`, where `rel` is a file name or
    /// `pages/<file name>`.
    pub fn asset(&self, rel: &str) -> Option<&Asset> {
        self.assets.get(rel)
    }

    /// The asset paths under `/assets/auth/`, in order.
    pub fn asset_paths(&self) -> impl Iterator<Item = &str> {
        self.assets.keys().map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Design section 11.2: only `.js` and `.css` files of the closed
    /// grammar are assets, so no source map, declaration, TypeScript or
    /// hidden file is ever served.
    #[test]
    fn adr003_page_asset_names_are_closed() {
        assert_eq!(asset_name("main.js"), Some(JAVASCRIPT));
        assert_eq!(asset_name("auth.css"), Some(CSS));
        assert_eq!(asset_name("messages.en.js"), Some(JAVASCRIPT));
        for bad in [
            "",
            ".hidden.js",
            "main.js.map",
            "main.d.ts",
            "main.ts",
            "shell.html",
            "Main.js",
            "a/b.js",
            "a%2fb.js",
            "-x.js",
        ] {
            assert_eq!(asset_name(bad), None, "{bad}");
        }
    }
}
