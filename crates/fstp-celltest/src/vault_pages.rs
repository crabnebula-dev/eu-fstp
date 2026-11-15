//! The loader pages of a world cell's vault origin (ADR-009 "Vault
//! origin" and "Delivery", M3 design section 11.2, lane
//! m3/devstack-scenarios). Test only.
//!
//! ADR-009 gives the vault origin three route groups: `POST /w`,
//! `POST /r`, and the static pages and scripts of those two. The shipped
//! vault serves the first two (`fstp_vault::origin::Vault::origin`), and
//! no part serves the third yet. A world whose cells serve the compiled
//! auth pages (`crate::world::World::start_with_pages`) serves these
//! pages on its vault origin, as the cells' dev pages do
//! (`fstp_cell::http::Front::with_pages`). Claims built on a browser that
//! opens `/w` or `/r` say so. The release document itself is the shipped
//! vault's reply to `POST /r`.
//!
//! [`VaultPages::load`] reads once, at start:
//!
//! - the shell `web/src/vault/shell.html`, served on `GET /w` and
//!   `GET /r`;
//! - each `.js` file of the `tsc` output `web/dist/vault`, served at
//!   `/assets/vault/<name>`;
//! - the auth modules the vault pages import, `dom.js`, `encoding.js` and
//!   `i18n.js` of `web/dist/auth`, at `/assets/auth/<name>`;
//! - the stylesheets `tokens.css` and `auth.css` of `web/src/auth`, at
//!   `/assets/auth/<name>`.
//!
//! Each reply carries [`LOADER_CSP`], the policy `web/src/vault/main.ts`
//! proposes: same-origin scripts, styles and form posts only, and no
//! frame ancestor. A symbolic link, a name outside `[a-z0-9._-]`, a file
//! over [`MAX_FILE`] bytes or a missing file refuses the load.

use std::collections::BTreeMap;
use std::path::Path;

use crate::world::WorldError;

/// The policy of every loader reply (`web/src/vault/main.ts`).
pub const LOADER_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";

/// The paths that serve the shell.
pub const SHELL_PATHS: [&str; 2] = ["/w", "/r"];

/// The auth modules the vault pages import.
const AUTH_MODULES: [&str; 3] = ["dom.js", "encoding.js", "i18n.js"];

/// The stylesheets the shell links.
const STYLESHEETS: [&str; 2] = ["tokens.css", "auth.css"];

/// The largest file loaded.
pub const MAX_FILE: u64 = 1 << 20;

/// The most vault modules loaded.
const MAX_MODULES: usize = 32;

const HTML: &str = "text/html; charset=utf-8";
const JAVASCRIPT: &str = "text/javascript; charset=utf-8";
const CSS: &str = "text/css; charset=utf-8";

/// One reply of the loader pages: status, header fields and body.
pub type PageReply = (u16, Vec<(&'static str, String)>, Vec<u8>);

/// The loader pages of a vault origin (module documentation).
#[derive(Clone, Debug, Default)]
pub struct VaultPages {
    shell: Vec<u8>,
    assets: BTreeMap<String, (&'static str, Vec<u8>)>,
}

fn refused(what: &str, path: &Path) -> WorldError {
    WorldError::Store(format!("the vault loader pages: {what} {}", path.display()))
}

fn read(path: &Path) -> Result<Vec<u8>, WorldError> {
    let meta = std::fs::symlink_metadata(path).map_err(|_| refused("cannot read", path))?;
    if !meta.file_type().is_file() {
        return Err(refused("is not a plain file", path));
    }
    if meta.len() > MAX_FILE {
        return Err(refused("is too large", path));
    }
    std::fs::read(path).map_err(|_| refused("cannot read", path))
}

fn plain_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
}

impl VaultPages {
    /// Loads the pages from the workspace's `web` directory: `None` when
    /// `web/dist/vault` does not exist, since `cargo test` never runs
    /// Node (design section 11.2).
    ///
    /// # Errors
    ///
    /// A compiled directory that exists but does not load.
    pub fn load(web: &Path) -> Result<Option<VaultPages>, WorldError> {
        let compiled = web.join("dist").join("vault");
        if !compiled.is_dir() {
            return Ok(None);
        }
        let shell = read(&web.join("src").join("vault").join("shell.html"))?;
        let mut assets = BTreeMap::new();
        let entries =
            std::fs::read_dir(&compiled).map_err(|_| refused("cannot list", &compiled))?;
        for entry in entries {
            let entry = entry.map_err(|_| refused("cannot list", &compiled))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.ends_with(".js") {
                continue;
            }
            if !plain_name(&name) {
                return Err(refused("holds an unexpected name in", &compiled));
            }
            if assets.len() >= MAX_MODULES {
                return Err(refused("holds too many modules:", &compiled));
            }
            assets.insert(
                format!("/assets/vault/{name}"),
                (JAVASCRIPT, read(&entry.path())?),
            );
        }
        if !assets.contains_key("/assets/vault/main.js") {
            return Err(refused("lacks main.js in", &compiled));
        }
        for name in AUTH_MODULES {
            let path = web.join("dist").join("auth").join(name);
            assets.insert(format!("/assets/auth/{name}"), (JAVASCRIPT, read(&path)?));
        }
        for name in STYLESHEETS {
            let path = web.join("src").join("auth").join(name);
            assets.insert(format!("/assets/auth/{name}"), (CSS, read(&path)?));
        }
        Ok(Some(VaultPages { shell, assets }))
    }

    /// The reply to `method` on `path`, or `None` when the path is no
    /// loader page or asset, so the vault answers it.
    pub fn serve(&self, method: &str, path: &str) -> Option<PageReply> {
        if method != "GET" {
            return None;
        }
        let (content_type, body) = if SHELL_PATHS.contains(&path) {
            (HTML, self.shell.clone())
        } else {
            let (t, b) = self.assets.get(path)?;
            (*t, b.clone())
        };
        Some((
            200,
            vec![
                ("content-type", content_type.to_owned()),
                ("content-security-policy", LOADER_CSP.to_owned()),
                ("cache-control", "no-store".to_owned()),
                ("x-content-type-options", "nosniff".to_owned()),
                ("referrer-policy", "no-referrer".to_owned()),
                ("cross-origin-resource-policy", "same-origin".to_owned()),
            ],
            body,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ADR-009 "Vault origin": the loader serves only `GET` of its shell
    /// paths and loaded assets, each under the loader policy, which runs
    /// same-origin scripts only and allows no framing (I-17).
    #[test]
    fn i17_loader_serves_its_pages_only_under_the_loader_policy() {
        let mut p = VaultPages {
            shell: b"<!doctype html>".to_vec(),
            ..VaultPages::default()
        };
        p.assets.insert(
            "/assets/vault/main.js".to_owned(),
            (JAVASCRIPT, b"1".to_vec()),
        );
        for path in ["/w", "/r", "/assets/vault/main.js"] {
            let (status, headers, _) = p.serve("GET", path).unwrap();
            assert_eq!(status, 200);
            assert!(headers.contains(&("content-security-policy", LOADER_CSP.to_owned())));
        }
        assert!(LOADER_CSP.contains("frame-ancestors 'none'"));
        assert!(LOADER_CSP.contains("script-src 'self'"));
        assert!(!LOADER_CSP.contains("unsafe"));
        for (m, path) in [
            ("POST", "/r"),
            ("POST", "/w"),
            ("GET", "/x"),
            ("GET", "/assets/vault/other.js"),
        ] {
            assert!(p.serve(m, path).is_none(), "{m} {path}");
        }
    }

    #[test]
    fn i17_loader_names_are_plain() {
        assert!(plain_name("main.js"));
        assert!(plain_name("messages.en.js"));
        for bad in ["", ".hidden.js", "Main.js", "a/b.js", "a b.js"] {
            assert!(!plain_name(bad), "{bad}");
        }
    }
}
