//! The static pages of the vault origin (ADR-009 "Vault origin" and
//! "Delivery", third route group; served by the shipped vault on Daniel's
//! decision of 2026-11-21, ADR-004 record of lane L13b, row "Static
//! pages").
//!
//! ADR-009 gives the vault origin three route groups: `POST /w`,
//! `POST /r`, and the static pages and scripts of those two. The vault
//! loads the third once, at start, and serves it from memory:
//!
//! - the shell `shell.html`, on `GET /w` and `GET /r`;
//! - each `.js` module of the compiled vault pages, at
//!   `/assets/vault/<name>`;
//! - the auth modules the vault pages import, `dom.js`, `encoding.js` and
//!   `i18n.js`, at `/assets/auth/<name>`;
//! - the stylesheets `tokens.css` and `auth.css`, at `/assets/auth/<name>`.
//!
//! [`VaultPages::load_installed`] reads an installed directory (the
//! configuration member `assets_dir`): `vault/` with the modules and
//! `shell.html`, and `auth/` with the auth modules and the stylesheets.
//! [`VaultPages::load`] reads the repository tree, as the test world
//! does. Each reply carries [`LOADER_CSP`], the policy
//! `web/src/vault/main.ts` proposes: same-origin scripts, styles and form
//! posts only, and no frame ancestor. A symbolic link, a name outside
//! `[a-z0-9._-]`, a file over [`MAX_FILE`] bytes or a missing file refuses
//! the load.

use std::collections::BTreeMap;
use std::path::Path;

use crate::VaultError;

/// The policy of every page reply.
pub const LOADER_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";

/// The paths that serve the shell.
pub const SHELL_PATHS: [&str; 2] = ["/w", "/r"];

const AUTH_MODULES: [&str; 3] = ["dom.js", "encoding.js", "i18n.js"];

const STYLESHEETS: [&str; 2] = ["tokens.css", "auth.css"];

/// The largest file the loader takes, in bytes.
pub const MAX_FILE: u64 = 1 << 20;

const MAX_MODULES: usize = 32;

const HTML: &str = "text/html; charset=utf-8";
const JAVASCRIPT: &str = "text/javascript; charset=utf-8";
const CSS: &str = "text/css; charset=utf-8";

/// A page reply: status, headers and body.
pub type PageReply = (u16, Vec<(&'static str, String)>, Vec<u8>);

/// The loaded pages.
#[derive(Clone, Debug, Default)]
pub struct VaultPages {
    shell: Vec<u8>,
    assets: BTreeMap<String, (&'static str, Vec<u8>)>,
}

fn refused() -> VaultError {
    VaultError::Config("assets_dir")
}

fn read(path: &Path) -> Result<Vec<u8>, VaultError> {
    let meta = std::fs::symlink_metadata(path).map_err(|_| refused())?;
    if !meta.file_type().is_file() || meta.len() > MAX_FILE {
        return Err(refused());
    }
    std::fs::read(path).map_err(|_| refused())
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
    /// The pages of the repository tree `web`: `src/vault/shell.html`,
    /// `dist/vault/*.js`, `dist/auth/` and `src/auth/`. `None` when the
    /// vault pages are not compiled.
    ///
    /// # Errors
    ///
    /// [`VaultError::Config`] when a file is missing or refused.
    pub fn load(web: &Path) -> Result<Option<VaultPages>, VaultError> {
        let compiled = web.join("dist").join("vault");
        if !compiled.is_dir() {
            return Ok(None);
        }
        Self::from_parts(
            &web.join("src").join("vault").join("shell.html"),
            &compiled,
            &web.join("dist").join("auth"),
            &web.join("src").join("auth"),
        )
        .map(Some)
    }

    /// The pages of the installed directory `dir`: `vault/shell.html`,
    /// `vault/*.js`, and `auth/` with the auth modules and stylesheets.
    ///
    /// # Errors
    ///
    /// [`VaultError::Config`] when a file is missing or refused.
    pub fn load_installed(dir: &Path) -> Result<VaultPages, VaultError> {
        let vault = dir.join("vault");
        let auth = dir.join("auth");
        Self::from_parts(&vault.join("shell.html"), &vault, &auth, &auth)
    }

    fn from_parts(
        shell: &Path,
        modules: &Path,
        auth_modules: &Path,
        stylesheets: &Path,
    ) -> Result<VaultPages, VaultError> {
        let shell = read(shell)?;
        let mut assets = BTreeMap::new();
        let entries = std::fs::read_dir(modules).map_err(|_| refused())?;
        for entry in entries {
            let entry = entry.map_err(|_| refused())?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.ends_with(".js") {
                continue;
            }
            if !plain_name(&name) || assets.len() >= MAX_MODULES {
                return Err(refused());
            }
            assets.insert(
                format!("/assets/vault/{name}"),
                (JAVASCRIPT, read(&entry.path())?),
            );
        }
        if !assets.contains_key("/assets/vault/main.js") {
            return Err(refused());
        }
        for name in AUTH_MODULES {
            assets.insert(
                format!("/assets/auth/{name}"),
                (JAVASCRIPT, read(&auth_modules.join(name))?),
            );
        }
        for name in STYLESHEETS {
            assets.insert(
                format!("/assets/auth/{name}"),
                (CSS, read(&stylesheets.join(name))?),
            );
        }
        Ok(VaultPages { shell, assets })
    }

    /// The reply to `method` on `path`, or `None` for anything but a `GET`
    /// of a loaded page.
    #[must_use]
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
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    /// I-17, ADR-009: the loader serves its pages only under the loader
    /// policy, and only on `GET` of a loaded path.
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

    /// The loader takes plain file names only.
    #[test]
    fn i17_loader_names_are_plain() {
        assert!(plain_name("main.js"));
        assert!(plain_name("messages.en.js"));
        for bad in ["", ".hidden.js", "Main.js", "a/b.js", "a b.js"] {
            assert!(!plain_name(bad), "{bad}");
        }
    }

    /// ADR-004 record of lane L13b, row "Static pages": an installed
    /// directory loads with its vault modules, shell, auth modules and
    /// stylesheets, and a missing part refuses the whole load.
    #[test]
    fn adr009_installed_pages_load_whole_or_not_at_all() {
        let dir = std::env::temp_dir().join(format!(
            "fstp-vault-pages-{}-{}",
            std::process::id(),
            fstp_crypto::random_array::<4>()
                .map(u32::from_be_bytes)
                .unwrap()
        ));
        let vault = dir.join("vault");
        let auth = dir.join("auth");
        std::fs::create_dir_all(&vault).unwrap();
        std::fs::create_dir_all(&auth).unwrap();
        std::fs::write(vault.join("shell.html"), b"<!doctype html>").unwrap();
        std::fs::write(vault.join("main.js"), b"export {};").unwrap();
        for name in AUTH_MODULES.iter().chain(STYLESHEETS.iter()) {
            std::fs::write(auth.join(name), b"x").unwrap();
        }
        let p = VaultPages::load_installed(&dir).unwrap();
        assert!(p.serve("GET", "/w").is_some());
        assert!(p.serve("GET", "/assets/auth/tokens.css").is_some());
        std::fs::remove_file(auth.join("i18n.js")).unwrap();
        assert!(VaultPages::load_installed(&dir).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
