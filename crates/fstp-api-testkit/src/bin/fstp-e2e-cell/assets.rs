//! The M3 page shell and its assets (`web/src/auth/main.ts` "Delivery").
//!
//! The M3 cell serves one shell, `web/src/auth/shell.html`, on each page
//! path of the auth pages, and `/assets/` serves the tsc output of
//! `web/dist/auth` and `web/src/auth/auth.css` at the same relative paths.
//! The e2e cell reads them once at start, so a request never names a
//! file outside the loaded set.

use std::collections::BTreeMap;
use std::path::Path;

use fstp_http::{Method, Request, Response, StatusCode};

/// The CSP of the M3 pages (M3 design section 11.2), with the Trusted
/// Types rule of the auth pages' DOM module.
pub(crate) const AUTH_CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; \
     object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; \
     require-trusted-types-for 'script'; trusted-types fstp-dom";

/// The largest file the set loads, in bytes.
const MAX_FILE: u64 = 4 * 1024 * 1024;

/// The M3 page shell and the files below `/assets/auth/`.
#[derive(Debug, Default)]
pub(crate) struct AuthAssets {
    shell: Option<Vec<u8>>,
    files: BTreeMap<String, (&'static str, Vec<u8>)>,
}

/// Reads a regular file of at most [`MAX_FILE`] bytes.
fn read(path: &Path) -> Result<Vec<u8>, String> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !meta.file_type().is_file() || meta.len() > MAX_FILE {
        return Err(format!("{} is not a small regular file", path.display()));
    }
    std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))
}

impl AuthAssets {
    /// No shell and no file: every page and asset is 404.
    pub(crate) fn empty() -> AuthAssets {
        AuthAssets::default()
    }

    /// The shell and assets below the repository's `web` directory. The
    /// demo modules are loaded only when `demo_signin` is on
    /// (`--demo-signin`); without it the cell serves none of them.
    pub(crate) fn load(web: &Path, demo_signin: bool) -> Result<AuthAssets, String> {
        let shell = read(&web.join("src").join("auth").join("shell.html"))?;
        let mut files = BTreeMap::new();
        // Every stylesheet of `web/src/auth`: the token sheet of lane
        // m4/site (`tokens.css`) and the page rules (`auth.css`).
        let styles = web.join("src").join("auth");
        let mut sheets: Vec<String> = std::fs::read_dir(&styles)
            .map_err(|e| format!("{}: {e}", styles.display()))?
            .filter_map(|e| e.ok().and_then(|e| e.file_name().into_string().ok()))
            .filter(|n| {
                n.ends_with(".css")
                    && !n.starts_with('.')
                    && n.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
            })
            .collect();
        sheets.sort();
        for name in sheets {
            files.insert(
                format!("auth/{name}"),
                ("text/css; charset=utf-8", read(&styles.join(&name))?),
            );
        }
        // The auth pages, and the demo modules of lane m4/site
        // (`web/src/demo`), which only this cell serves, and only with
        // `--demo-signin`: the demo sign-in page and the notice of a demo
        // session (`crate::demo_signin`).
        let mut stack = vec![(web.join("dist").join("auth"), String::from("auth"))];
        let demo = web.join("dist").join("demo");
        if demo_signin && demo.is_dir() {
            stack.push((demo, String::from("demo")));
        }
        while let Some((dir, rel)) = stack.pop() {
            let entries = std::fs::read_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
            for entry in entries {
                let entry = entry.map_err(|e| e.to_string())?;
                let name = entry
                    .file_name()
                    .into_string()
                    .map_err(|_| "a file name is not UTF-8")?;
                if !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
                    || name.starts_with('.')
                {
                    return Err(format!("{rel}/{name}: a name outside the asset grammar"));
                }
                let kind = entry.file_type().map_err(|e| e.to_string())?;
                let child = format!("{rel}/{name}");
                if kind.is_dir() {
                    stack.push((entry.path(), child));
                } else if kind.is_file() && name.ends_with(".js") {
                    files.insert(
                        child,
                        ("text/javascript; charset=utf-8", read(&entry.path())?),
                    );
                }
            }
        }
        Ok(AuthAssets {
            shell: Some(shell),
            files,
        })
    }

    /// The shell of an M3 page, with the M3 CSP. 404 when none is loaded.
    pub(crate) fn page(&self) -> Response {
        let Some(shell) = &self.shell else {
            return Response::new(StatusCode::NOT_FOUND);
        };
        self.page_with(shell)
    }

    /// One loaded file by its path below `/assets/`, such as
    /// `auth/tokens.css`, with its media type.
    pub(crate) fn file(&self, rel: &str) -> Option<(&'static str, &[u8])> {
        self.files.get(rel).map(|(k, b)| (*k, b.as_slice()))
    }

    /// The page `html` with the M3 CSP and headers of every M3 page.
    pub(crate) fn page_with(&self, html: &[u8]) -> Response {
        let mut r = Response::with_body(StatusCode::OK, "text/html; charset=utf-8", html.to_vec());
        let _ = r.headers.try_insert("content-security-policy", AUTH_CSP);
        let _ = r.headers.try_insert("cache-control", "no-store");
        let _ = r.headers.try_insert("x-content-type-options", "nosniff");
        let _ = r.headers.try_insert("referrer-policy", "no-referrer");
        r
    }

    /// `GET /assets/<path>`: one loaded file, or 404.
    pub(crate) fn asset(&self, req: &Request) -> Response {
        if req.method != Method::GET && req.method != Method::HEAD {
            return Response::new(StatusCode::METHOD_NOT_ALLOWED);
        }
        let rel = req.target.path().trim_start_matches("/assets/");
        match self.files.get(rel) {
            Some((kind, bytes)) => {
                let mut r = Response::with_body(StatusCode::OK, kind, bytes.clone());
                let _ = r.headers.try_insert("cache-control", "no-store");
                let _ = r.headers.try_insert("x-content-type-options", "nosniff");
                r
            }
            None => Response::new(StatusCode::NOT_FOUND),
        }
    }
}
