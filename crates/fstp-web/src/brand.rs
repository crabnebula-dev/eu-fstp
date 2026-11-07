//! `GET /brand/{digest}.css`: the tenant's brand stylesheet (M9 design
//! section 2.2, lane B2; I-68).
//!
//! The body is `fstp_brand::css` of the typed tokens, so no free text
//! reaches it. It is immutable by digest: the path names the digest of
//! the token set, and any other digest, including a stale one, is not
//! found.

use fstp_api_core::Brand;
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
