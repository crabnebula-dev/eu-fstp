//! The compiled auth pages on the cell origin (design section 11.2,
//! ADR-003). Lane int4.
//!
//! Each test builds a page directory pair in Cargo's test scratch
//! directory: a compiled directory as `tsc` writes it and a source
//! directory with the shell and a stylesheet. `cargo test` never runs
//! Node (design section 11.2), so the compiled files here are fixtures.
//! One test reads the real `web/src/auth/shell.html` and checks that each
//! asset it loads is one the cell serves.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use fstp_auth::{EnabledMethods, Method as LoginMethod};
use fstp_cell::http::front::CELL_CSP;
use fstp_cell::http::pages::{
    ASSET_ROUTES, CSS, HTML, JAVASCRIPT, MAX_ASSET, PAGE_PATHS, Pages, PagesError,
};
use fstp_cell::http::{Front, FrontConfig, MemoryLog};
use fstp_cell::routes::memory::MemoryBackend;
use fstp_http::{Method, Request, RequestTarget, Response};

const CELL: [u8; 16] = [0xC5; 16];
const HOST: &str = "tenant-p.fstp.test";
const SHELL: &[u8] = b"<!doctype html><html><head><script type=\"module\" src=\"/assets/auth/main.js\"></script></head><body><main id=\"main\"></main></body></html>";

/// A fresh, empty directory under Cargo's test scratch directory.
fn scratch(name: &str) -> PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("http_pages_{}_{n}_{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// `(compiled, sources)` with `main.js`, `pages/login.js`, the shell, a
/// stylesheet and a TypeScript file the loader must leave out.
fn fixture() -> (PathBuf, PathBuf) {
    let root = scratch("fixture");
    let compiled = root.join("dist");
    let sources = root.join("src");
    std::fs::create_dir_all(compiled.join("pages")).unwrap();
    std::fs::create_dir_all(sources.join("pages")).unwrap();
    std::fs::write(compiled.join("main.js"), b"import './pages/login.js';\n").unwrap();
    std::fs::write(compiled.join("pages").join("login.js"), b"export {};\n").unwrap();
    std::fs::write(sources.join("shell.html"), SHELL).unwrap();
    std::fs::write(sources.join("auth.css"), b"main { margin: 0; }\n").unwrap();
    std::fs::write(sources.join("main.ts"), b"secret source\n").unwrap();
    std::fs::write(sources.join("pages").join("login.ts"), b"secret\n").unwrap();
    (compiled, sources)
}

fn front(pages: Option<Pages>) -> Front<MemoryBackend, MemoryLog> {
    let cfg = FrontConfig {
        cell: CELL,
        host: HOST.to_owned(),
        enabled: EnabledMethods {
            methods: vec![LoginMethod::Passkey],
        },
    };
    let backend = Arc::new(MemoryBackend::new());
    let log = Arc::new(MemoryLog::default());
    match pages {
        Some(p) => Front::with_pages(cfg, p, backend, log).unwrap(),
        None => Front::new(cfg, backend, log).unwrap(),
    }
}

fn get(f: &Front<MemoryBackend, MemoryLog>, path: &str) -> Response {
    let req = Request::new(Method::GET, RequestTarget::origin(path).unwrap())
        .try_with_header("host", HOST)
        .unwrap();
    fstp_rt::future::block_on(f.serve(req))
}

fn header<'a>(r: &'a Response, name: &str) -> Option<&'a [u8]> {
    r.headers.get(name).map(|v| v.as_bytes())
}

fn loaded() -> Pages {
    let (compiled, sources) = fixture();
    Pages::load(&compiled, &sources).unwrap()
}

/// Design section 11.2: every page path, and `GET /auth/magic`, serves the
/// shell as HTML under the cell CSP.
#[test]
fn adr003_every_page_path_serves_the_shell_under_the_cell_csp() {
    let f = front(Some(loaded()));
    for path in PAGE_PATHS.iter().chain(["/auth/magic"].iter()) {
        let r = get(&f, path);
        assert_eq!(r.status.as_u16(), 200, "{path}");
        assert_eq!(r.body, SHELL, "{path}");
        assert_eq!(header(&r, "content-type"), Some(HTML.as_bytes()), "{path}");
        assert_eq!(
            header(&r, "content-security-policy"),
            Some(CELL_CSP.as_bytes()),
            "{path}"
        );
        assert_eq!(header(&r, "x-content-type-options"), Some(&b"nosniff"[..]));
    }
}

/// Design section 11.2: the compiled modules and the stylesheet are served
/// under `/assets/auth/` with their media types and the cell CSP. A
/// TypeScript source, the shell, an unknown file and a traversal are not.
#[test]
fn adr003_assets_are_served_by_name_only() {
    let f = front(Some(loaded()));
    for (path, kind) in [
        ("/assets/auth/main.js", JAVASCRIPT),
        ("/assets/auth/pages/login.js", JAVASCRIPT),
        ("/assets/auth/auth.css", CSS),
    ] {
        let r = get(&f, path);
        assert_eq!(r.status.as_u16(), 200, "{path}");
        assert_eq!(header(&r, "content-type"), Some(kind.as_bytes()), "{path}");
        assert_eq!(
            header(&r, "content-security-policy"),
            Some(CELL_CSP.as_bytes()),
            "{path}"
        );
    }
    for path in [
        "/assets/auth/main.ts",
        "/assets/auth/shell.html",
        "/assets/auth/pages/login.ts",
        "/assets/auth/other.js",
        "/assets/auth/pages",
    ] {
        assert_eq!(get(&f, path).status.as_u16(), 404, "{path}");
    }
    for path in ["/assets/auth/..%2fmain.js", "/assets/auth/%2e%2e"] {
        let s = get(&f, path).status.as_u16();
        assert!(s == 400 || s == 404, "{path}: {s}");
    }
}

/// Design section 8.7: a front without pages serves no page path and no
/// asset, and `GET /auth/magic` keeps its fixed confirm page.
#[test]
fn adr003_a_front_without_pages_serves_none() {
    let f = front(None);
    for path in PAGE_PATHS {
        // A path with a POST route, such as `/auth/signup`, answers 405.
        let s = get(&f, path).status.as_u16();
        assert!(matches!(s, 404 | 405), "{path}: {s}");
    }
    assert_eq!(get(&f, "/assets/auth/main.js").status.as_u16(), 404);
    let magic = get(&f, "/auth/magic");
    assert_eq!(magic.status.as_u16(), 200);
    assert!(
        String::from_utf8_lossy(&magic.body).contains("fstp-magic"),
        "the fixed confirm page changed"
    );
}

/// ADR-003, design section 11.2: a page directory pair that lacks the
/// shell, `main.js` or a stylesheet does not load, so a cell never serves
/// part of a build.
#[test]
fn adr003_pages_without_a_required_file_do_not_load() {
    for missing in ["shell", "main", "css"] {
        let (compiled, sources) = fixture();
        match missing {
            "shell" => std::fs::remove_file(sources.join("shell.html")).unwrap(),
            "main" => std::fs::remove_file(compiled.join("main.js")).unwrap(),
            _ => std::fs::remove_file(sources.join("auth.css")).unwrap(),
        }
        assert!(
            Pages::load(&compiled, &sources).is_err(),
            "pages without {missing} loaded"
        );
    }
}

/// ADR-003: a compiled file outside the asset grammar, a symbolic link
/// and a file over the size limit are refused, so nothing planted beside
/// a build is served.
#[test]
fn adr003_pages_refuse_planted_files() {
    let (compiled, sources) = fixture();
    std::fs::write(compiled.join("main.js.map"), b"{}").unwrap();
    assert!(matches!(
        Pages::load(&compiled, &sources),
        Err(PagesError::Name(_))
    ));

    let (compiled, sources) = fixture();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(sources.join("main.ts"), compiled.join("link.js")).unwrap();
        assert!(matches!(
            Pages::load(&compiled, &sources),
            Err(PagesError::NotAFile(_))
        ));
    }

    let (compiled, sources) = fixture();
    let big = vec![b' '; usize::try_from(MAX_ASSET).unwrap() + 1];
    std::fs::write(compiled.join("big.js"), big).unwrap();
    assert!(matches!(
        Pages::load(&compiled, &sources),
        Err(PagesError::TooLarge(_))
    ));
}

/// Design section 11.2: every script and stylesheet the real shell
/// `web/src/auth/shell.html` loads is a same-origin path under the asset
/// routes, and the shell holds no inline script or style, which the cell
/// CSP would block.
#[test]
fn adr003_the_real_shell_loads_only_served_assets() {
    let shell = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../web/src/auth/shell.html"),
    )
    .unwrap();
    let mut refs = Vec::new();
    for attr in ["src=\"", "href=\""] {
        let mut rest = shell.as_str();
        while let Some((_, after)) = rest.split_once(attr) {
            let (value, tail) = after.split_once('"').unwrap();
            refs.push(value.to_owned());
            rest = tail;
        }
    }
    assert!(!refs.is_empty(), "the shell loads nothing");
    let prefix = ASSET_ROUTES[0].trim_end_matches("{file}");
    for r in &refs {
        let file = r
            .strip_prefix(prefix)
            .unwrap_or_else(|| panic!("{r} is not under {prefix}"));
        assert!(
            !file.contains('/') || file.starts_with("pages/"),
            "{r} is outside the asset routes"
        );
    }
    assert!(refs.iter().any(|r| r == "/assets/auth/main.js"), "{refs:?}");
    let lower = shell.to_ascii_lowercase();
    assert!(!lower.contains("<style"), "the shell holds an inline style");
    assert_eq!(
        lower.matches("<script").count(),
        lower.matches("<script type=\"module\" src=").count(),
        "the shell holds an inline script"
    );
    let css = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../web/src/auth/auth.css");
    assert!(css.is_file(), "the shell's stylesheet is missing");
}
