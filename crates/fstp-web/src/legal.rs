//! `GET /legal/{text}`: the legal pages behind the footer, and
//! `GET /legal/details`: the tenant's legal details as JSON (ADR-037).
//!
//! Both read no cookie and need no session, so the pages work signed out
//! (Daniel, 2026-11-22, `legal/README.md` Q6). A page links the platform
//! stylesheets first, as every public page does, and holds no script; the
//! surface carries the public CSP (`script-src 'none'`). Every answer is
//! sent with `no-store` by `headers::finish`.

use fstp_api_core::legal::{DETAILS_PATH, details_json, page_html};
use fstp_http::{Method, Request, Response, StatusCode};
use fstp_web_assets::AssetSet;

use crate::api::Backend;
use crate::{reply, shell};

/// The answer to a request under `/legal`.
pub(crate) fn answer(backend: &Backend, assets: &AssetSet, req: &Request) -> Response {
    if req.method != Method::GET && req.method != Method::HEAD {
        return reply::get_only();
    }
    let path = req.target.path();
    let core = match backend {
        Backend::Core(c) => Some(c.as_ref()),
        Backend::Refusing => None,
    };
    if path == DETAILS_PATH {
        let body = core.map_or_else(|| details_json(None), fstp_api_core::ApiCore::legal_details);
        return Response::with_body(
            StatusCode::OK,
            "application/json",
            fstp_json::to_compact(&body).into_bytes(),
        );
    }
    let html = match core {
        Some(c) => c.legal_page(path),
        None => page_html(path, None, None),
    };
    match html {
        Some(h) => Response::with_body(
            StatusCode::OK,
            "text/html; charset=utf-8",
            shell::public_page(&h, assets),
        ),
        None => reply::not_found(),
    }
}

#[cfg(test)]
#[allow(clippy::panic, reason = "a test fails by panicking")]
mod tests {
    use super::*;
    use fstp_http::RequestTarget;

    /// The five legal pages (ADR-037 section 2).
    const LEGAL_PATHS: [&str; 5] = [
        "/legal/privacy",
        "/legal/accessibility",
        "/legal/imprint",
        "/legal/terms",
        "/legal/data-act",
    ];

    fn req(method: Method, path: &str) -> Request {
        let Ok(t) = RequestTarget::origin(path) else {
            panic!("target");
        };
        Request::new(method, t)
    }

    fn assets() -> AssetSet {
        let Ok(a) = AssetSet::from_files(
            "main.js",
            &[
                ("main.js", b"export {};" as &[u8]),
                ("site/ui.css", b"body{margin:0}" as &[u8]),
            ],
        ) else {
            panic!("assets");
        };
        a
    }

    /// ADR-037, R-PB-04: each legal page answers HTML with the platform
    /// sheets and the draft banner, signed out; the details answer JSON;
    /// any other path is not found and any other method refused.
    #[test]
    fn adr037_legal_surface_answers() {
        let a = assets();
        for p in LEGAL_PATHS {
            let r = answer(&Backend::Refusing, &a, &req(Method::GET, p));
            assert_eq!(r.status, StatusCode::OK, "{p}");
            let html = String::from_utf8(r.body).unwrap_or_default();
            assert!(html.contains("Draft, not yet approved"), "{p}");
            assert!(html.contains("/app/assets/"), "{p}: platform sheets");
            assert!(!html.to_ascii_lowercase().contains("<script"), "{p}");
        }
        let r = answer(&Backend::Refusing, &a, &req(Method::GET, DETAILS_PATH));
        assert_eq!(r.status, StatusCode::OK);
        assert_eq!(r.body, b"{}".to_vec());
        for p in ["/legal/", "/legal/nope", "/legal/privacy/x"] {
            let r = answer(&Backend::Refusing, &a, &req(Method::GET, p));
            assert_eq!(r.status, StatusCode::NOT_FOUND, "{p}");
        }
        let r = answer(&Backend::Refusing, &a, &req(Method::POST, "/legal/privacy"));
        assert_eq!(r.status, StatusCode::METHOD_NOT_ALLOWED);
    }
}
