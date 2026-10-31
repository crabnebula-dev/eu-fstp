//! Surfaces and the security headers of every response (ADR-014, M4
//! design sections 3.9 and 3.10).

use fstp_http::{Response, StatusCode};

/// The CSP of every `/app` response, verbatim from design section 3.9 and
/// ADR-014.
pub const APP_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; \
     img-src 'self'; font-src 'self'; connect-src 'self'; form-action 'self'; \
     frame-ancestors 'none'; base-uri 'none'; require-trusted-types-for 'script'; \
     trusted-types fstp-dom";

/// The CSP of every `/p` response, verbatim from design section 3.10.
pub const PUBLIC_CSP: &str = "default-src 'none'; script-src 'none'; style-src 'self'; \
     img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

/// The CSP of every other response: the API, the refusals and 404s.
/// Interim, pending Daniel: none of them is a document, so nothing loads.
pub const OTHER_CSP: &str =
    "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

/// The HSTS value. Interim, pending Daniel: one year, no subdomains.
pub const HSTS: &str = "max-age=31536000";

/// The surface a request path belongs to, read from the raw path before
/// any decoding. Only [`Surface::Api`] reaches `ApiCore::dispatch`, and
/// only after the CSRF rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Surface {
    /// `/app` and below: the shell and the assets.
    App,
    /// `/api/v1` and below.
    Api,
    /// `/p` and below: public pages.
    Public,
    /// `/mcp`, `/oauth` and the OAuth `/.well-known` documents, which wait
    /// for ADR-013.
    Adr013,
    /// Any other path.
    Other,
}

/// Whether `path` is `root` or lies below it.
fn under(path: &str, root: &str) -> bool {
    path.strip_prefix(root)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

impl Surface {
    /// The surface of the raw request path `path`.
    pub(crate) fn of(path: &str) -> Surface {
        if under(path, "/app") {
            Surface::App
        } else if under(path, "/api/v1") {
            Surface::Api
        } else if under(path, "/p") {
            Surface::Public
        } else if under(path, "/mcp")
            || under(path, "/oauth")
            || under(path, "/.well-known/oauth-protected-resource")
            || under(path, "/.well-known/oauth-authorization-server")
        {
            Surface::Adr013
        } else {
            Surface::Other
        }
    }

    /// The one CSP of the surface.
    pub(crate) fn csp(self) -> &'static str {
        match self {
            Surface::App => APP_CSP,
            Surface::Public => PUBLIC_CSP,
            Surface::Api | Surface::Adr013 | Surface::Other => OTHER_CSP,
        }
    }
}

/// Whether the asset server's own `Cache-Control` stays: a 200 answer to
/// a path under `/app/assets/`.
fn keeps_cache_control(surface: Surface, path: &str, status: StatusCode) -> bool {
    surface == Surface::App && path.starts_with("/app/assets/") && status == StatusCode::OK
}

/// Sets the security headers of `resp`, the answer to a request for the
/// raw path `path`.
///
/// - Every response carries `X-Content-Type-Options: nosniff`,
///   `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy:
///   same-origin`, `Cross-Origin-Resource-Policy: same-origin`, HSTS and
///   exactly one CSP for its surface.
/// - Every response except a served asset carries `Cache-Control:
///   no-store`, so a cached shell never names a stale asset.
/// - No response sets a cookie or an `Access-Control-*` field. Session
///   cookies are M3's.
pub(crate) fn finish(resp: &mut Response, path: &str) {
    let surface = Surface::of(path);
    resp.headers.remove("set-cookie");
    let cors: Vec<String> = resp
        .headers
        .iter()
        .map(|(n, _)| n.as_str())
        .filter(|n| n.starts_with("access-control-"))
        .map(str::to_owned)
        .collect();
    for name in cors {
        resp.headers.remove(&name);
    }
    if !keeps_cache_control(surface, path, resp.status) {
        set(resp, "cache-control", "no-store");
    }
    set(resp, "content-security-policy", surface.csp());
    set(resp, "x-content-type-options", "nosniff");
    set(resp, "referrer-policy", "no-referrer");
    set(resp, "cross-origin-opener-policy", "same-origin");
    set(resp, "cross-origin-resource-policy", "same-origin");
    set(resp, "strict-transport-security", HSTS);
}

/// Replaces every field `name` of `resp` with one field `value`. Each
/// name and value here is a valid constant, so the insert never fails.
fn set(resp: &mut Response, name: &str, value: &str) {
    let _ = resp.headers.try_insert(name, value);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ADR-014: the surface follows the raw path segment by segment.
    #[test]
    fn adr014_surface_of_paths() {
        assert_eq!(Surface::of("/app"), Surface::App);
        assert_eq!(Surface::of("/app/x"), Surface::App);
        assert_eq!(Surface::of("/apple"), Surface::Other);
        assert_eq!(Surface::of("/api/v1/x"), Surface::Api);
        assert_eq!(Surface::of("/api/v10"), Surface::Other);
        assert_eq!(Surface::of("/p/x/"), Surface::Public);
        assert_eq!(Surface::of("/mcp/public"), Surface::Adr013);
        assert_eq!(Surface::of("/.well-known/other"), Surface::Other);
        assert_eq!(Surface::of("*"), Surface::Other);
    }

    /// A response carrying every field `fields`, in order.
    fn response_with(status: StatusCode, fields: &[(&str, &str)]) -> Response {
        let mut r = Response::new(status);
        for (n, v) in fields {
            assert!(r.headers.try_append(n, *v).is_ok(), "{n}");
        }
        r
    }

    /// ADR-014, TH-37: `finish` strips every `Set-Cookie` and every
    /// `Access-Control-*` field a handler set, on every surface, and keeps
    /// unrelated fields.
    #[test]
    fn adr014_finish_strips_cookies_and_cors_fields() {
        let fields = [
            ("set-cookie", "__Host-fstp=a; Secure; HttpOnly; Path=/"),
            ("set-cookie", "track=1"),
            ("access-control-allow-origin", "*"),
            ("access-control-allow-credentials", "true"),
            ("access-control-expose-headers", "x-a"),
            ("access-control-max-age", "600"),
            ("content-type", "application/json"),
            ("x-access-control", "kept"),
        ];
        for path in ["/api/v1/x", "/app/", "/p/x", "/mcp", "/other"] {
            let mut r = response_with(StatusCode::OK, &fields);
            finish(&mut r, path);
            assert_eq!(r.headers.count("set-cookie"), 0, "{path}");
            let cors = r
                .headers
                .iter()
                .filter(|(n, _)| n.as_str().starts_with("access-control-"))
                .count();
            assert_eq!(cors, 0, "{path}");
            assert_eq!(r.headers.count("content-type"), 1, "{path}");
            assert_eq!(r.headers.count("x-access-control"), 1, "{path}");
            assert_eq!(r.headers.count("content-security-policy"), 1, "{path}");
        }
    }

    /// ADR-014: `finish` replaces a handler's own security fields with one
    /// field each, and keeps an asset's `Cache-Control` only on a 200
    /// under `/app/assets/`.
    #[test]
    fn adr014_finish_sets_one_value_per_security_field() {
        let fields = [
            ("content-security-policy", "default-src *"),
            ("content-security-policy", "script-src *"),
            ("x-content-type-options", "sniff"),
            ("cache-control", "public, max-age=31536000, immutable"),
        ];
        let mut asset = response_with(StatusCode::OK, &fields);
        finish(&mut asset, "/app/assets/x.js");
        let csp: Vec<&[u8]> = asset
            .headers
            .get_all("content-security-policy")
            .map(|v| v.as_bytes())
            .collect();
        assert_eq!(csp, [APP_CSP.as_bytes()]);
        let nosniff: Vec<&[u8]> = asset
            .headers
            .get_all("x-content-type-options")
            .map(|v| v.as_bytes())
            .collect();
        assert_eq!(nosniff, [b"nosniff".as_slice()]);
        assert_eq!(asset.headers.count("cache-control"), 1);
        assert!(
            asset
                .headers
                .get_all("cache-control")
                .all(|v| v.as_bytes() == b"public, max-age=31536000, immutable")
        );
        let mut missing = response_with(StatusCode::NOT_FOUND, &fields);
        finish(&mut missing, "/app/assets/x.js");
        assert!(
            missing
                .headers
                .get_all("cache-control")
                .all(|v| v.as_bytes() == b"no-store")
        );
        assert_eq!(missing.headers.count("cache-control"), 1);
    }
}
