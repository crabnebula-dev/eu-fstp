//! `GET /brand/{digest}.css`: the tenant's brand stylesheet (M9 design
//! section 2.2, lane B2; I-68). `GET /brand/{digest}.png` and `.webp`:
//! a current logo (ADR-030). `GET /brand/logo/light` and `/dark`: the
//! tenant's current logo for the static sign-in pages, not cached.
//! `GET /brand/eu-emblem.png`: the platform's EU emblem slot.
//!
//! The body is `fstp_brand::css` of the typed tokens, so no free text
//! reaches it. It is immutable by digest: the path names the digest of
//! the token set, and any other digest, including a stale one, is not
//! found.

use fstp_api_core::Brand;
use fstp_api_core::brand::{EU_EMBLEM_PNG, LogoFormat, logo_path_digest};
use fstp_http::{Method, Request, Response, StatusCode};

use crate::reply;

/// The `Cache-Control` of a served brand stylesheet.
pub(crate) const IMMUTABLE: &str = "public, max-age=31536000, immutable";

/// The digest a brand stylesheet path names: 64 lower-case hex digits
/// between `/brand/` and `.css`.
pub(crate) fn digest_in(path: &str) -> Option<&str> {
    let d = path.strip_prefix("/brand/")?.strip_suffix(".css")?;
    (d.len() == 64 && d.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))).then_some(d)
}

/// The stable paths of the tenant's current logo, light and dark.
pub(crate) const LOGO_LIGHT: &str = "/brand/logo/light";
/// The dark one, which falls back to light (ADR-030 section 2).
pub(crate) const LOGO_DARK: &str = "/brand/logo/dark";
/// The platform's EU emblem slot (ADR-030 section 2).
pub(crate) const EMBLEM: &str = "/brand/eu-emblem.png";

/// Whether `path` names a logo by digest, so its answer is immutable.
pub(crate) fn logo_digest_in(path: &str) -> bool {
    logo_path_digest(path).is_some()
}

/// A logo answer: the bytes with the fixed content type of the checked
/// format, never one the request or the bytes suggest (I-68).
fn image(format: LogoFormat, bytes: Vec<u8>, immutable: bool) -> Response {
    let mut r = Response::with_body(StatusCode::OK, format.media_type(), bytes);
    if immutable {
        // A valid constant, so the insert never fails.
        let _ = r.headers.try_insert("cache-control", IMMUTABLE);
    }
    r
}

/// The answer to a `/brand` request for a logo or the emblem (ADR-030),
/// or `None` when `req` names the stylesheet or nothing of these.
pub(crate) async fn logo_answer(
    core: Option<&fstp_api_core::ApiCore>,
    req: &Request,
) -> Option<Response> {
    let path = req.target.path();
    if path == EMBLEM {
        return Some(match EU_EMBLEM_PNG {
            Some(b) => image(LogoFormat::Png, b.to_vec(), false),
            None => reply::not_found(),
        });
    }
    let stable = path == LOGO_LIGHT || path == LOGO_DARK;
    if !stable && !logo_digest_in(path) {
        return None;
    }
    if req.method != Method::GET && req.method != Method::HEAD {
        return Some(reply::get_only());
    }
    let Some(core) = core else {
        return Some(reply::not_found());
    };
    let target = if stable {
        let paths = core.tenant_logos();
        let p = if path == LOGO_LIGHT {
            paths.light
        } else {
            paths.dark
        };
        match p {
            Some(p) => p,
            None => return Some(reply::not_found()),
        }
    } else {
        path.to_owned()
    };
    Some(match core.brand_asset(&target).await {
        Some(a) => image(a.format, a.bytes, !stable),
        None => reply::not_found(),
    })
}

/// The answer to `req` for the current `brand`.
pub(crate) fn answer(brand: Option<Brand>, req: &Request) -> Response {
    if req.method != Method::GET && req.method != Method::HEAD {
        return reply::get_only();
    }
    let Some(digest) = digest_in(req.target.path()) else {
        return reply::not_found();
    };
    match brand {
        Some(b) if b.digest == digest => {
            let mut r = Response::with_body(StatusCode::OK, "text/css", b.css.into_bytes());
            // A valid constant, so the insert never fails.
            let _ = r.headers.try_insert("cache-control", IMMUTABLE);
            r
        }
        _ => reply::not_found(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fstp_http::RequestTarget;

    fn get(path: &str) -> Request {
        let Ok(t) = RequestTarget::origin(path) else {
            panic!("target");
        };
        Request::new(Method::GET, t)
    }

    fn brand() -> Brand {
        Brand {
            digest: "ab".repeat(32),
            css: ":root{--color-brand:#000000;}".to_owned(),
        }
    }

    /// I-68: the stylesheet is served for its own digest only, as CSS,
    /// immutable.
    #[test]
    fn i68_brand_css_is_served_by_digest_only() {
        let path = format!("/brand/{}.css", "ab".repeat(32));
        let r = answer(Some(brand()), &get(&path));
        assert_eq!(r.status, StatusCode::OK);
        assert_eq!(r.body, brand().css.into_bytes());
        assert!(
            r.headers
                .get_all("cache-control")
                .all(|v| v.as_bytes() == IMMUTABLE.as_bytes())
        );
        let stale = format!("/brand/{}.css", "cd".repeat(32));
        assert_eq!(
            answer(Some(brand()), &get(&stale)).status,
            StatusCode::NOT_FOUND
        );
        assert_eq!(answer(None, &get(&path)).status, StatusCode::NOT_FOUND);
    }

    /// I-68, ADR-030: a logo answer carries the fixed content type of its
    /// checked format, never one the bytes suggest, and caches only by
    /// digest. The emblem slot is empty until Daniel supplies the file.
    #[test]
    fn i68_logo_answer_has_a_fixed_type() {
        let r = image(LogoFormat::Webp, b"<svg/>".to_vec(), true);
        assert!(
            r.headers
                .get_all("content-type")
                .all(|v| v.as_bytes() == b"image/webp")
        );
        assert!(
            r.headers
                .get_all("cache-control")
                .all(|v| v.as_bytes() == IMMUTABLE.as_bytes())
        );
        let r = image(LogoFormat::Png, Vec::new(), false);
        assert!(
            r.headers
                .get_all("content-type")
                .all(|v| v.as_bytes() == b"image/png")
        );
        assert_eq!(r.headers.get_all("cache-control").count(), 0);
        let emblem = fstp_rt::future::block_on(logo_answer(None, &get(EMBLEM)));
        assert_eq!(emblem.map(|r| r.status), Some(StatusCode::NOT_FOUND));
        let css = format!("/brand/{}.css", "ab".repeat(32));
        assert!(fstp_rt::future::block_on(logo_answer(None, &get(&css))).is_none());
        for p in [LOGO_LIGHT, LOGO_DARK] {
            let r = fstp_rt::future::block_on(logo_answer(None, &get(p)));
            assert_eq!(r.map(|r| r.status), Some(StatusCode::NOT_FOUND));
        }
    }

    /// I-68: only a 64-digit lower-case hex digest names a sheet.
    #[test]
    fn i68_brand_path_grammar_is_closed() {
        let ok = format!("/brand/{}.css", "0f".repeat(32));
        assert!(digest_in(&ok).is_some());
        for bad in [
            "/brand/.css".to_owned(),
            format!("/brand/{}.css", "AB".repeat(32)),
            format!("/brand/{}.css", "ab".repeat(31)),
            format!("/brand/{}.css/", "ab".repeat(32)),
            format!("/brand/x/{}.css", "ab".repeat(32)),
            format!("/brand/{}.js", "ab".repeat(32)),
        ] {
            assert!(digest_in(&bad).is_none(), "{bad}");
        }
    }
}
