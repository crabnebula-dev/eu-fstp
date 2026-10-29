//! The web router: surfaces, gates and the sub-routers over
//! `fstp_http::Router` (M4 design sections 1.1 and 3.9).

use std::future::Future;
use std::sync::Arc;

use fstp_api_core::ApiCore;
use fstp_http::{Handler, Limits, Method, Request, Response, Router, StatusCode, handler_fn};
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
        }
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
    origin: Origin,
    assets: AssetSet,
    shell: Vec<u8>,
}

/// The routes of the web adapter. It implements [`Handler`], so a
/// `fstp_http::Server` serves it directly.
///
/// - `/app` redirects to `/app/`. `/app/assets/{sha256}.js` and `.css`
///   serve verified assets, immutable. Every other `/app/` path serves the
///   shell, so the client router handles deep links.
/// - `/api/v1/**` passes the body limit, the CSRF rule and the media type
///   check, then reaches `ApiCore::dispatch` and nothing else.
/// - `/p/**` is a stub: `fstp-public` is not on the demo path.
/// - `/mcp`, `/mcp/public`, `/oauth/**` and the OAuth `/.well-known`
///   documents answer the typed ADR-013 refusal.
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
    let shell = shell::render(&config.assets);
    let shared = Arc::new(Shared {
        backend,
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
            async move { app_fallback(&s, &req) }
        }));

    let to_api = Arc::clone(&shared);
    let api = Router::new().fallback(handler_fn(move |req: Request| {
        let s = Arc::clone(&to_api);
        async move { api::answer(&s.backend, req).await }
    }));

    Ok(WebRouter { shared, app, api })
}

/// Every `/app` path the routes do not match: 404 under `/app/assets`,
/// the shell for `GET` and `HEAD` elsewhere, and 405 otherwise.
fn app_fallback(s: &Shared, req: &Request) -> Response {
    let path = req.target.path();
    if path == "/app/assets" || path.starts_with("/app/assets/") {
        return reply::not_found();
    }
    if req.method != Method::GET && req.method != Method::HEAD {
        return reply::get_only();
    }
    Response::with_body(StatusCode::OK, "text/html; charset=utf-8", s.shell.clone())
}

/// The stub of the public pages. Interim, pending Daniel: `fstp-public`
/// is not on the demo path, so `GET` answers 501 with a constant JSON
/// body. It reads no cookie, so a session cookie changes nothing
/// (R-PB-04, TH-37).
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

    /// Answers one request by its surface.
    async fn route(&self, req: Request) -> Response {
        if req.body.len() > BODY_LIMIT {
            return reply::too_large();
        }
        match Surface::of(req.target.path()) {
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
            Surface::Public => public_stub(&req),
            Surface::Adr013 => reply::adr013(),
            Surface::Other => reply::not_found(),
        }
    }
}

impl Handler for WebRouter {
    fn handle(&self, req: Request) -> impl Future<Output = Response> + Send {
        self.serve(req)
    }
}
