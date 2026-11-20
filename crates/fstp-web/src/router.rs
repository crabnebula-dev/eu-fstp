//! The web router: surfaces, gates and the sub-routers over
//! `fstp_http::Router` (M4 design sections 1.1 and 3.9).

use std::future::Future;
use std::sync::Arc;

use fstp_api_core::decode::decode_public_page;
use fstp_api_core::{ApiCore, Credential, OpResult, PageAdmission, RequestHead};
use fstp_http::{Handler, Limits, Method, Request, Response, Router, StatusCode, handler_fn};
use fstp_json::ToJson;
use fstp_web_assets::AssetSet;

use crate::api::{self, Backend};
use crate::headers::{self, Surface};
use crate::{Origin, WebError, reply, shell};

/// The largest request body, in bytes: the `fstp-http` default of 1 MiB.
pub const BODY_LIMIT: usize = 1024 * 1024;

/// The parser limits the server that mounts the router uses, so a longer
/// body gets 413 before any handler runs.
#[must_use]
pub fn limits() -> Limits {
    Limits {
        max_body_bytes: u64::try_from(BODY_LIMIT).unwrap_or(u64::MAX),
        ..Limits::default()
    }
}

/// What the router serves besides the API core.
#[derive(Clone, Debug)]
pub struct WebConfig {
    tenant_origin: Origin,
    assets: AssetSet,
    /// The hosts the OAuth metadata may name over plain `http`, besides
    /// loopback, when a caller set a rule. Only the test kit's e2e cell
    /// sets one. A shipped cell sets none.
    local_http: Option<fn(&str) -> bool>,
    /// The issuer, resource and lifetimes of the cell's own authorisation
    /// server, when the cell runs one (ADR-026, lane L1), so the metadata
    /// documents name exactly what that server issues.
    oauth: Option<fstp_oauth::Config>,
}

impl WebConfig {
    /// A configuration for the tenant origin `tenant_origin`, which every
    /// state-changing API request must name, and the verified frontend
    /// `assets`.
    #[must_use]
    pub fn new(tenant_origin: Origin, assets: AssetSet) -> WebConfig {
        WebConfig {
            tenant_origin,
            assets,
            local_http: None,
            oauth: None,
        }
    }

    /// The same configuration, whose OAuth metadata documents describe
    /// `oauth`, the configuration of the cell's own authorisation server
    /// (ADR-026, ADR-013 amendment of 2026-11-20). Without it the documents
    /// describe a server on the tenant origin with the default lifetimes.
    #[must_use]
    pub fn with_oauth(mut self, oauth: fstp_oauth::Config) -> WebConfig {
        self.oauth = Some(oauth);
        self
    }

    /// The configuration of a cell on a plain `http` origin whose host
    /// `local_http` admits, such as the e2e cell's `.localhost` origin: its
    /// OAuth metadata documents name that origin as the issuer (lane W3c).
    /// The caller supplies the rule, and no shipped code holds one. It
    /// replaces the former test-only feature `test-cell` (lane L2).
    #[must_use]
    pub fn with_local_http(mut self, local_http: fn(&str) -> bool) -> WebConfig {
        self.local_http = Some(local_http);
        self
    }

    /// The tenant origin.
    #[must_use]
    pub fn tenant_origin(&self) -> &Origin {
        &self.tenant_origin
    }
}

/// The state every handler shares.
struct Shared {
    backend: Backend,
    /// The MCP endpoints and OAuth metadata, over the core only.
    mcp: Option<crate::mcp::Mcp>,
    origin: Origin,
    assets: AssetSet,
    shell: Vec<u8>,
}

/// The routes of the web adapter. It implements [`Handler`], so a
/// `fstp_http::Server` serves it directly.
///
/// - `/app` redirects to `/app/`. `/app/assets/{sha256}.js` and `.css`
///   serve verified assets, immutable. Every other `/app/` path passes the
///   page gate of SA-09: the shell when the page's read admits the viewer,
///   so the client router handles deep links; 303 to sign in; or, for a
///   closed or unknown page, 303 to home `/app/` (SA-09 amendment).
/// - A browser page request for a path no surface serves goes home too:
///   303 to `/app/`, or to `/p/{slug}/` under an existing programme.
/// - `/api/v1/**` passes the body limit, the CSRF rule and the media type
///   check, then reaches `ApiCore::dispatch` and nothing else.
/// - `/p/**` serves the public pages and the feed through the API core,
///   with no credential (design section 3.10).
/// - `/mcp` and `/mcp/public` serve the MCP server, and the OAuth
///   `/.well-known` documents the metadata, over the core (design section
///   3.8). `/oauth/**` and the stub dispatch answer the typed ADR-013
///   refusal.
/// - Every response carries the headers of design section 3.9.
pub struct WebRouter {
    shared: Arc<Shared>,
    app: Router,
    api: Router,
}

impl std::fmt::Debug for WebRouter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebRouter")
            .field("origin", &self.shared.origin)
            .field("assets", &self.shared.assets)
            .finish_non_exhaustive()
    }
}

/// The web router over the cell's API core. `fstp-cell` mounts it on the
/// tenant listener with [`limits`].
///
/// # Errors
///
/// [`WebError::Route`] if a route pattern is refused, which a test pins.
pub fn router(core: Arc<ApiCore>, config: WebConfig) -> Result<WebRouter, WebError> {
    build(Backend::Core(core), config)
}

/// The router over `backend`.
pub(crate) fn build(backend: Backend, config: WebConfig) -> Result<WebRouter, WebError> {
    let shell = shell::render(&config.assets, None);
    let mcp = match &backend {
        Backend::Core(core) => Some(crate::mcp::Mcp::new(
            Arc::clone(core),
            &config.tenant_origin,
            config.local_http,
            config.oauth.clone(),
        )?),
        Backend::Refusing => None,
    };
    let shared = Arc::new(Shared {
        backend,
        mcp,
        origin: config.tenant_origin,
        assets: config.assets,
        shell,
    });
    let route = |e: fstp_http::RouteError| WebError::Route(e.description());

    let to_assets = Arc::clone(&shared);
    let to_shell = Arc::clone(&shared);
    let app = Router::new()
        .get(
            "/app",
            handler_fn(|_req: Request| async {
                let mut r = Response::new(StatusCode::PERMANENT_REDIRECT);
                // A valid constant, so the insert never fails.
                let _ = r.headers.try_insert("location", "/app/");
                r
            }),
        )
        .map_err(route)?
        .get(
            "/app/assets/{file}",
            handler_fn(move |req: Request| {
                let s = Arc::clone(&to_assets);
                async move {
                    s.assets
                        .response_for(req.target.path().as_bytes())
                        .unwrap_or_else(reply::not_found)
                }
            }),
        )
        .map_err(route)?
        .fallback(handler_fn(move |req: Request| {
            let s = Arc::clone(&to_shell);
            async move { app_fallback(&s, &req).await }
        }));

    let to_api = Arc::clone(&shared);
    let api = Router::new().fallback(handler_fn(move |req: Request| {
        let s = Arc::clone(&to_api);
        async move { api::answer(&s.backend, req).await }
    }));

    Ok(WebRouter { shared, app, api })
}

/// Every `/app` path the routes do not match: 404 under `/app/assets`,
/// 405 for a method other than `GET` and `HEAD`, and otherwise the page
/// gate of SA-09 before the shell ([`page`]).
async fn app_fallback(s: &Shared, req: &Request) -> Response {
    let path = req.target.path();
    if path == "/app/assets" || path.starts_with("/app/assets/") {
        return reply::not_found();
    }
    if req.method != Method::GET && req.method != Method::HEAD {
        return reply::get_only();
    }
    let admission = match &s.backend {
        Backend::Core(core) => match api::credential(&req.headers) {
            Ok(cred) => core.page(cred, &api::head(req), path).await,
            // A tossed cookie or a bearer field opens no page. The
            // visitor signs in again, as with no session.
            Err(_) => match fstp_api_core::page_without_session(path) {
                PageAdmission::Open => PageAdmission::Open,
                PageAdmission::NotFound => PageAdmission::NotFound,
                _ => PageAdmission::SignIn,
            },
        },
        Backend::Refusing => fstp_api_core::page_without_session(path),
    };
    page(s, path, admission)
}

/// The answer to an `/app/` page request under the page gate of SA-09:
///
/// - admitted: the shell, 200;
/// - no session: 303 to the login page, which returns to the page after
///   sign-in, where the gate runs again;
/// - a session too weak for the page's read (I-77): 303 to the login
///   page with `method=passkey`, then the gate again;
/// - any other refusal, and a path no page has: the same 303 to home,
///   `/app/`, whatever the request (SA-09 amendment, Daniel 2026-11-15).
///   The answer is the same bytes in every case, so it never says that a
///   page exists or why it is closed. The shell's link check asks with
///   `redirect: "manual"` and reads a redirect as closed.
fn page(s: &Shared, path: &str, admission: PageAdmission) -> Response {
    match admission {
        PageAdmission::Open => Response::with_body(
            StatusCode::OK,
            "text/html; charset=utf-8",
            shell_now(s, None),
        ),
        PageAdmission::SignIn => see_other(&login_path(path, false)),
        PageAdmission::PasskeySignIn => see_other(&login_path(path, true)),
        // Home itself is open to every session, so it never answers
        // NotFound. Were it to, a redirect to itself would loop, so it
        // answers the not-found page instead.
        PageAdmission::NotFound if path == HOME => not_found_page(s),
        PageAdmission::NotFound => see_other(HOME),
        PageAdmission::Unavailable => reply::json(
            StatusCode::SERVICE_UNAVAILABLE,
            br#"{"code":"unavailable"}"#,
        ),
    }
}

/// The "Page not found" answer: 404 with the shell marked
/// [`shell::NOT_FOUND`], whose client renders the not-found page. Since
/// the SA-09 amendment only home would answer it, which never happens
/// ([`page`]).
fn not_found_page(s: &Shared) -> Response {
    Response::with_body(
        StatusCode::NOT_FOUND,
        "text/html; charset=utf-8",
        shell_now(s, Some(shell::NOT_FOUND)),
    )
}

/// The shell with the tenant's brand sheet, if it set one (M9 lane B2),
/// and the page marker `marker`, if any.
fn shell_now(s: &Shared, marker: Option<&str>) -> Vec<u8> {
    match (s.backend.brand(), marker) {
        (None, None) => s.shell.clone(),
        (b, m) => shell::render_marked(&s.assets, b.as_ref().map(|b| b.digest.as_str()), m),
    }
}

/// The home page, where an unknown or closed page sends the browser
/// (SA-09 amendment).
const HOME: &str = "/app/";

/// A 303 to `location`, a constant path and a query this module encodes.
fn see_other(location: &str) -> Response {
    let mut r = Response::new(StatusCode::SEE_OTHER);
    let _ = r.headers.try_insert("location", location);
    r
}

/// The login page that returns to `path` after sign-in, as
/// `web/src/auth/next.ts` `loginPathFor` writes it: `/auth/login` for
/// the home page, else `/auth/login?next=<path>` with the path encoded
/// as `encodeURIComponent` encodes it. With `passkey`, the query also
/// asks for a passkey sign-in (`method=passkey`, I-77).
pub(crate) fn login_path(path: &str, passkey: bool) -> String {
    let mut q = Vec::new();
    if passkey {
        q.push("method=passkey".to_owned());
    }
    if path != "/app/" {
        q.push(format!("next={}", encode_component(path)));
    }
    if q.is_empty() {
        "/auth/login".to_owned()
    } else {
        format!("/auth/login?{}", q.join("&"))
    }
}

/// `encodeURIComponent` of ECMAScript: every byte outside
/// `A-Z a-z 0-9 - _ . ! ~ * ' ( )` as `%XX`, upper case.
fn encode_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// The public pages (design section 3.10, R-PB-04, TH-37). Only `GET` and
/// `HEAD` are served. The path goes through the public route decoder of
/// `fstp-api-core`, then `ApiCore::dispatch` with no credential, so the
/// session cookie is never read and changes nothing. A page answers as
/// HTML and the feed as JSON. A refusal answers its status with the
/// stable JSON body of every API refusal, except the setup gate's refusal
/// of a page: before activation a page answers the plain HTML page of
/// [`shell::not_published`] with the refusal's status (ADR-021 decision
/// 3, Daniel, 2026-11-15). The headers of the public
/// surface are set by [`WebRouter::serve`], so no answer sets a cookie.
async fn public(backend: &Backend, assets: &AssetSet, req: &Request) -> Response {
    if req.method != Method::GET && req.method != Method::HEAD {
        return reply::get_only();
    }
    let core = match backend {
        Backend::Core(core) => core,
        Backend::Refusing => return public_stub(req),
    };
    let op = match decode_public_page(req.target.path()) {
        Ok(op) => op,
        Err(e) => return api::api_error(e),
    };
    // ADR-021 decision 3: the feed is data, so only a page answers the
    // setup gate's refusal in words.
    let page = op.name() != "public.feed";
    match core.dispatch(Credential::None, &api::head(req), op).await {
        Ok(OpResult::Done { body, .. }) => match body.public_page() {
            Some(html) => Response::with_body(
                StatusCode::OK,
                "text/html; charset=utf-8",
                shell::public_page(html, assets),
            ),
            None => Response::with_body(
                StatusCode::OK,
                "application/json",
                body.to_json().to_compact().into_bytes(),
            ),
        },
        Ok(_) => reply::not_found(),
        Err(e) if page && e.is_setup_refusal() => {
            let status =
                StatusCode::from_u16(e.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            Response::with_body(
                status,
                "text/html; charset=utf-8",
                shell::not_published(assets),
            )
        }
        Err(e) => api::api_error(e),
    }
}

/// The public pages of the stub dispatch of `handle_op_request`: `GET`
/// answers 501 with a constant JSON body. It reads no cookie, so a
/// session cookie changes nothing (R-PB-04, TH-37).
fn public_stub(req: &Request) -> Response {
    if req.method != Method::GET && req.method != Method::HEAD {
        return reply::get_only();
    }
    reply::json(StatusCode::NOT_IMPLEMENTED, br#"{"code":"not_available"}"#)
}

impl WebRouter {
    /// Answers one request and sets the headers of its surface.
    pub async fn serve(&self, req: Request) -> Response {
        let path = req.target.path().to_owned();
        let mut resp = self.route(req).await;
        headers::finish(&mut resp, &path);
        resp
    }

    /// Answers one request by its surface. A browser page request
    /// ([`fstp_http::is_page_navigation`]) for a path no surface serves
    /// goes home instead ([`WebRouter::unknown_page`]).
    async fn route(&self, req: Request) -> Response {
        let surface = Surface::of(req.target.path());
        let page = surface.serves_pages() && fstp_http::is_page_navigation(&req);
        let path = req.target.path().to_owned();
        let head = api::head(&req);
        let resp = self.by_surface(surface, req).await;
        if page && matches!(resp.status.as_u16(), 400 | 404) {
            return self.unknown_page(surface, &path, &head).await;
        }
        resp
    }

    /// The answer to a browser page request for a path that does not
    /// exist (SA-09 amendment, Daniel 2026-11-15): 303 to home, `/app/`,
    /// whose gate sends a visitor with no session to sign in. A path
    /// under `/p/{slug}/` goes to that programme's public home
    /// `/p/{slug}/` when it exists. The API and the machine routes never
    /// get here, so they keep their JSON answers.
    async fn unknown_page(&self, surface: Surface, path: &str, head: &RequestHead) -> Response {
        if surface == Surface::Public
            && let Some(home) = self.public_home(path, head).await
        {
            return see_other(&home);
        }
        see_other(HOME)
    }

    /// The public home `/p/{slug}/` of the programme `path` names, when
    /// the cell serves it: its page answers, or the setup gate of ADR-021
    /// answers its "not published yet" page.
    async fn public_home(&self, path: &str, head: &RequestHead) -> Option<String> {
        let Backend::Core(core) = &self.shared.backend else {
            return None;
        };
        let slug = path.strip_prefix("/p/")?.split('/').next()?;
        let home = format!("/p/{slug}/");
        if home == path {
            return None;
        }
        let op = decode_public_page(&home).ok()?;
        match core.dispatch(Credential::None, head, op).await {
            Ok(OpResult::Done { .. }) => Some(home),
            Err(e) if e.is_setup_refusal() => Some(home),
            _ => None,
        }
    }

    /// Answers one request by the surface of its path.
    async fn by_surface(&self, surface: Surface, req: Request) -> Response {
        if req.body.len() > BODY_LIMIT {
            return reply::too_large();
        }
        match surface {
            Surface::App => self.app.handle(req).await,
            Surface::Api => {
                if api::changes_state(&req.method)
                    && !api::csrf_passes(&req.headers, &self.shared.origin)
                {
                    return reply::csrf_refused();
                }
                if !api::json_body(&req.headers, &req.body) {
                    return reply::unsupported_media_type();
                }
                self.api.handle(req).await
            }
            Surface::Public => public(&self.shared.backend, &self.shared.assets, &req).await,
            Surface::Brand => crate::brand::answer(self.shared.backend.brand(), &req),
            Surface::Adr013 => match &self.shared.mcp {
                Some(m) => m.answer(req).await,
                None => reply::adr013(),
            },
            Surface::Other => reply::not_found(),
        }
    }
}

impl Handler for WebRouter {
    fn handle(&self, req: Request) -> impl Future<Output = Response> + Send {
        self.serve(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SA-09 rules 2 and 4: the login page returns to the page asked for,
    /// encoded as `web/src/auth/next.ts` `loginPathFor` encodes it, and
    /// asks for a passkey when the session is too weak (I-77).
    #[test]
    fn sa09_login_path_returns_to_the_page() {
        assert_eq!(login_path("/app/", false), "/auth/login");
        assert_eq!(
            login_path("/app/grants", false),
            "/auth/login?next=%2Fapp%2Fgrants"
        );
        assert_eq!(
            login_path("/app/admin/onboarding/domains_and_email", true),
            "/auth/login?method=passkey&next=%2Fapp%2Fadmin%2Fonboarding%2Fdomains_and_email"
        );
        assert_eq!(login_path("/app/", true), "/auth/login?method=passkey");
        assert_eq!(encode_component("a-b_c.d!~*'()é"), "a-b_c.d!~*'()%C3%A9");
    }
}
