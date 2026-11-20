//! The front of the cell's two listeners (design sections 2.3, 8.7, 11.1
//! and 11.2, ADR-008, ADR-009, R-NF-02, H-01).
//!
//! # Tunnel listener
//!
//! [`Front::serve`] answers one request that came through the edge
//! tunnel, in this order:
//!
//! 1. The target is in origin form and the `Host` field names the cell
//!    host, exactly once (400, or 421 for another host).
//! 2. `fstp_http::Router` matches the route table: 404 for an unlisted
//!    path, 405 for a listed path with another method, and 400 for a path
//!    the router refuses. `GET /healthz` is not on this listener.
//! 3. The matched route runs the shared checks and its handler
//!    (`crate::routes`): `Origin`, `Content-Type`, the body limit, the
//!    session, the body, the gate.
//! 4. A browser page request (`fstp_http::is_page_navigation`) outside
//!    `/api/` that would answer 404 gets 303 to home, `/app/`, instead
//!    (SA-09 amendment, Daniel 2026-11-15). `/app/` itself answers the
//!    styled "Page not found" page with 404, since this front serves no
//!    shell there yet. A path under `/p/` that no route matches answers
//!    as the web adapter answers it (`crate::routes::unrouted`).
//!
//! A front built with `Front::with_pages` or `Front::with_web` also
//! routes the compiled auth pages (ADR-026 "Auth pages", decided by
//! Daniel on 2026-11-20, `crate::http::pages`): the rows of `crate::routes::page_table`. Each
//! row names its risk class and runs the shared checks, like every other
//! route. `GET` of each page path serves the shell, and `GET` under the
//! asset routes serves a loaded module or stylesheet by name.
//!
//! Every response then carries the cell CSP of design section 11.2, or
//! for a path under `/p/` the public CSP of M4 design section 3.10,
//! `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`,
//! `Strict-Transport-Security`, `Cross-Origin-Opener-Policy`,
//! `Cross-Origin-Resource-Policy` (L17) and
//! `Cache-Control: no-store`. No response carries an
//! `Access-Control-Allow-*` field, so no other origin may read one.
//!
//! # Logs (R-NF-02, B10)
//!
//! Each request writes one [`LogEvent`]: `Refused` with its rule for a
//! refusal under a rule, and `Request` otherwise. The route field is the
//! template that matched, or [`fstp_obs::UNROUTED`]. No path parameter,
//! query, header, cookie or body byte reaches an event, since
//! `LogEvent` holds none.
//!
//! # Health listener
//!
//! [`Front::serve_health`] serves `GET /healthz` with a fixed body on
//! the loopback listener, and 404 for every other path (ADR-009).

use std::sync::{Arc, Mutex};
use std::time::Instant;

use fstp_auth::EnabledMethods;
use fstp_http::{
    Handler, HeaderName, HeaderValue, Method, Request, Response, Router, StatusCode, TargetForm,
};
use fstp_obs::{LogEvent, UNROUTED};
use fstp_webauthn::RelyingParty;

use crate::http::pages::Pages;
use crate::routes::{
    Access, Backend, CellCfg, Ctx, Outcome, Route, Rule, page_table, public_table, serve_route,
    site_table, table,
};

/// The CSP of the cell origin, verbatim from design section 11.2.
pub const CELL_CSP: &str = "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'";

/// The CSP of every `/p` response, verbatim from M4 design section 3.10:
/// a public page loads no script and submits no form (R-PB-04).
pub const PUBLIC_CSP: &str = "default-src 'none'; script-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

/// The fixed body of `GET /healthz`.
pub const HEALTH_BODY: &[u8] = b"ok\n";

/// The response field a route handler sets so the front knows the route
/// logged its own event. The front removes it from every response.
const LOGGED: &str = "x-fstp-internal-logged";

/// The response field the web adapter's answers carry inside the front,
/// so the front keeps the adapter's own security fields. The front removes
/// it from every response.
const WEB: &str = "x-fstp-internal-web";

/// Whether `path` belongs to a surface of the web adapter that the cell
/// table does not serve (ADR-026 "Composition"): the journey UI under
/// `/app`, the API core's `/api/` routes, `/mcp`, `/oauth` and the
/// two OAuth metadata documents. `/p/` stays the cell's own.
fn web_path(path: &str) -> bool {
    path == "/app"
        || path.starts_with("/app/")
        || path.starts_with("/api/")
        || path == "/mcp"
        || path.starts_with("/mcp/")
        || path.starts_with("/oauth/")
        || path.starts_with("/.well-known/")
}

/// The web adapter mounted behind the cell table (ADR-026).
type Web = Option<Arc<fstp_web::WebRouter>>;

/// Serves `req` through the web adapter, marked as its answer.
async fn serve_web(web: &fstp_web::WebRouter, req: Request) -> Response {
    let mut resp = web.serve(req).await;
    if let (Ok(name), Ok(value)) = (HeaderName::new(WEB), HeaderValue::new("1")) {
        resp.headers.insert(name, value);
    }
    resp
}

/// Where the front writes its events.
pub trait LogSink: Send + Sync + 'static {
    /// Writes one event.
    fn log(&self, event: LogEvent);
}

/// The production sink: one line per event on standard error, through
/// `fstp_obs::log_to_stderr`, the one writer of that stream.
#[derive(Clone, Copy, Debug, Default)]
pub struct StderrLog;

impl LogSink for StderrLog {
    fn log(&self, event: LogEvent) {
        // A failed write loses the line only. The request is served.
        let _ = fstp_obs::log_to_stderr(&event);
    }
}

/// A sink that keeps every event in memory, for tests.
#[derive(Debug, Default)]
pub struct MemoryLog {
    events: Mutex<Vec<LogEvent>>,
}

impl MemoryLog {
    /// Every event written so far, in order.
    pub fn events(&self) -> Vec<LogEvent> {
        self.events.lock().map(|e| e.clone()).unwrap_or_default()
    }
}

impl LogSink for MemoryLog {
    fn log(&self, event: LogEvent) {
        if let Ok(mut e) = self.events.lock() {
            e.push(event);
        }
    }
}

/// The configuration of a cell's front.
#[derive(Clone, Debug)]
pub struct FrontConfig {
    /// The cell id.
    pub cell: [u8; 16],
    /// The cell host: the relying party id and the origin host.
    pub host: String,
    /// The login methods the tenant enables (P-70). Passkeys are always
    /// enabled.
    pub enabled: EnabledMethods,
    /// The rate limits of the public auth routes and of `PutText`
    /// (ADR-024). The default holds the interim values.
    pub limits: crate::routes::AuthLimits,
    /// The organisation port of ADR-021, for a ledger with no tenant part
    /// (`crate::public::OrganisationPort`). The default fails closed.
    pub organisation: crate::public::OrganisationPort,
}

/// Why a front could not be built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrontError {
    /// The host is not a relying party host (`RelyingParty::new`).
    Host,
    /// The router refused a route of the table.
    Route,
}

impl std::fmt::Display for FrontError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            FrontError::Host => "the cell host is not a relying party host",
            FrontError::Route => "the router refused a route of the table",
        })
    }
}

impl std::error::Error for FrontError {}

/// The front of one cell: its tunnel and health listeners.
pub struct Front<B, L> {
    inner: Arc<Inner<B, L>>,
}

impl<B, L> Clone for Front<B, L> {
    fn clone(&self) -> Self {
        Front {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<B, L> std::fmt::Debug for Front<B, L> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Front").finish_non_exhaustive()
    }
}

struct Inner<B, L> {
    router: Router,
    host: String,
    log: Arc<L>,
    /// Lane L2 hook: the OAuth endpoints of the cell (`crate::oauth`).
    oauth: std::sync::OnceLock<Arc<dyn crate::oauth::Mount>>,
    _backend: std::marker::PhantomData<B>,
}

/// The handler of one table route.
struct RouteHandler<B, L> {
    ctx: Arc<Ctx<B>>,
    route: &'static Route,
    log: Arc<L>,
}

impl<B: Backend, L: LogSink> Handler for RouteHandler<B, L> {
    async fn handle(&self, req: Request) -> Response {
        let started = Instant::now();
        let method = obs_method(&req.method);
        let (mut resp, outcome) = serve_route(&self.ctx, self.route, req).await;
        let (_, template, _) = self.route.parts();
        self.log
            .log(event(method, template, &resp, outcome, started));
        if let (Ok(name), Ok(value)) = (HeaderName::new(LOGGED), HeaderValue::new("1")) {
            resp.headers.insert(name, value);
        }
        resp
    }
}

/// The handler of a path no route matches (`crate::routes::unrouted`).
/// It logs its event under [`UNROUTED`], with the rule of a refusal, such
/// as a rate limit (ADR-024).
struct Unrouted<B, L> {
    ctx: Arc<Ctx<B>>,
    log: Arc<L>,
    web: Web,
}

impl<B: Backend, L: LogSink> Handler for Unrouted<B, L> {
    async fn handle(&self, req: Request) -> Response {
        let started = Instant::now();
        let method = obs_method(&req.method);
        // ADR-026: a path of the web adapter's surfaces that the cell
        // table did not match goes to the adapter. The front logs it.
        if let Some(web) = &self.web
            && web_path(req.target.path())
        {
            return serve_web(web, req).await;
        }
        let (mut resp, outcome) = crate::routes::unrouted(&self.ctx, &req).await;
        self.log
            .log(event(method, UNROUTED, &resp, outcome, started));
        if let (Ok(name), Ok(value)) = (HeaderName::new(LOGGED), HeaderValue::new("1")) {
            resp.headers.insert(name, value);
        }
        resp
    }
}

/// The site stylesheet route with the web adapter mounted: a platform
/// stylesheet of the public pages is the cell's, and any other file under
/// `/app/assets/` is the adapter's journey UI asset (ADR-026).
struct SiteOrWeb<B, L> {
    cell: RouteHandler<B, L>,
    web: Arc<fstp_web::WebRouter>,
}

impl<B: Backend, L: LogSink> Handler for SiteOrWeb<B, L> {
    async fn handle(&self, req: Request) -> Response {
        if crate::http::site::sheet(req.target.path()).is_some() {
            self.cell.handle(req).await
        } else {
            serve_web(&self.web, req).await
        }
    }
}

/// The log event of a response.
fn event(
    method: fstp_obs::Method,
    route: &'static str,
    resp: &Response,
    outcome: Outcome,
    started: Instant,
) -> LogEvent {
    let status = resp.status.as_u16();
    match outcome.rule {
        Some(rule) => LogEvent::Refused {
            method,
            route,
            rule: rule.as_str(),
            status,
        },
        None => LogEvent::Request {
            method,
            route,
            status,
            elapsed: started.elapsed(),
        },
    }
}

/// The closed `fstp-obs` method of `m`. No method text is logged.
fn obs_method(m: &Method) -> fstp_obs::Method {
    use fstp_obs::Method as M;
    match m.as_str() {
        "GET" => M::Get,
        "HEAD" => M::Head,
        "POST" => M::Post,
        "PUT" => M::Put,
        "PATCH" => M::Patch,
        "DELETE" => M::Delete,
        "OPTIONS" => M::Options,
        "CONNECT" => M::Connect,
        "TRACE" => M::Trace,
        _ => M::Other,
    }
}

/// The `fstp-http` method of a table method.
fn http_method(m: &str) -> Result<Method, FrontError> {
    Method::from_bytes(m.as_bytes()).map_err(|_| FrontError::Route)
}

impl<B: Backend, L: LogSink> Front<B, L> {
    /// The front of the cell `cfg` names, over `backend`, writing to
    /// `log`.
    ///
    /// # Errors
    ///
    /// [`FrontError::Host`] for a host that is not a relying party host,
    /// and [`FrontError::Route`] if the router refuses a table route.
    pub fn new(cfg: FrontConfig, backend: Arc<B>, log: Arc<L>) -> Result<Front<B, L>, FrontError> {
        Front::build(cfg, None, backend, log, None)
    }

    /// The production front of ADR-026 (decided by Daniel on 2026-11-20):
    /// the cell table, the public and site rows, the auth page rows when
    /// `pages` are loaded, and the web adapter `web` behind them for the
    /// `/app`, `/api`, `/mcp`, `/oauth` and `/.well-known` paths the
    /// cell table does not match.
    ///
    /// # Errors
    ///
    /// As [`Front::new`].
    pub fn with_web(
        cfg: FrontConfig,
        pages: Option<Pages>,
        web: fstp_web::WebRouter,
        backend: Arc<B>,
        log: Arc<L>,
    ) -> Result<Front<B, L>, FrontError> {
        Front::build(cfg, pages.map(Arc::new), backend, log, Some(Arc::new(web)))
    }

    /// [`Front::new`] that also serves the compiled auth pages `pages` on
    /// the cell origin (design section 11.2, `crate::http::pages`): the
    /// rows of `crate::routes::page_table`, each with its risk class and
    /// through the shared checks of every route. `GET /auth/magic` then
    /// serves the shell too. Every reply carries the cell CSP.
    ///
    /// Daniel decided on 2026-11-20 (D2, ADR-026 "Auth pages") that the
    /// page rows join the served table, so a shipped build serves them.
    ///
    /// # Errors
    ///
    /// As [`Front::new`], and [`FrontError::Route`] if the router refuses
    /// a page route.
    pub fn with_pages(
        cfg: FrontConfig,
        pages: Pages,
        backend: Arc<B>,
        log: Arc<L>,
    ) -> Result<Front<B, L>, FrontError> {
        Front::build(cfg, Some(Arc::new(pages)), backend, log, None)
    }

    fn build(
        cfg: FrontConfig,
        pages: Option<Arc<Pages>>,
        backend: Arc<B>,
        log: Arc<L>,
        web: Web,
    ) -> Result<Front<B, L>, FrontError> {
        let rp = RelyingParty::new(&cfg.host).map_err(|_| FrontError::Host)?;
        let serve_pages = pages.is_some();
        let ctx = Arc::new(Ctx {
            backend,
            cfg: CellCfg {
                cell: cfg.cell,
                origin: format!("https://{}", cfg.host),
                rp,
                enabled: cfg.enabled,
                pages,
                organisation: cfg.organisation,
            },
            limits: crate::routes::limits::Limits::new(cfg.limits),
        });
        // The page rows are served only when pages are loaded, so a front
        // without them serves exactly the section 8.7 table.
        let pages_rows: &'static [Route] = if serve_pages { page_table() } else { &[] };
        let mut router = Router::new().fallback(Unrouted {
            ctx: Arc::clone(&ctx),
            log: Arc::clone(&log),
            web: web.clone(),
        });
        for route in table()
            .iter()
            .chain(public_table())
            .chain(site_table())
            .chain(pages_rows)
        {
            if route.access() == Access::Loopback || route.access() == Access::Unserved {
                continue;
            }
            let (m, path, _) = route.parts();
            let handler = RouteHandler {
                ctx: Arc::clone(&ctx),
                route,
                log: Arc::clone(&log),
            };
            router = match (&web, path == crate::http::site::SHEET_ROUTE) {
                (Some(w), true) => router.route(
                    http_method(m)?,
                    path,
                    SiteOrWeb {
                        cell: handler,
                        web: Arc::clone(w),
                    },
                ),
                _ => router.route(http_method(m)?, path, handler),
            }
            .map_err(|_| FrontError::Route)?;
        }
        Ok(Front {
            inner: Arc::new(Inner {
                router,
                host: cfg.host,
                log,
                oauth: std::sync::OnceLock::new(),
                _backend: std::marker::PhantomData,
            }),
        })
    }

    /// Lane L2 hook (ADR-013 amendment of 2026-11-20): mounts the OAuth
    /// endpoints of the cell, which then serve every path below `/oauth`
    /// after the host check. `false` when a mount is set already.
    pub fn mount_oauth(&self, mount: Arc<dyn crate::oauth::Mount>) -> bool {
        self.inner.oauth.set(mount).is_ok()
    }

    /// Serves one request on the tunnel listener (module documentation).
    pub async fn serve(&self, req: Request) -> Response {
        let started = Instant::now();
        let method = obs_method(&req.method);
        let home = goes_home(&req);
        let public = is_public_path(req.target.path());
        let (mut resp, rule) = match self.precheck(&req) {
            Some(refused) => refused,
            None => match self.inner.oauth.get() {
                // Lane L2 hook: `/oauth/**` goes to the authorisation server.
                Some(o) if crate::oauth::is_route(req.target.path()) => (o.serve(req).await, None),
                _ => (self.inner.router.handle(req).await, None),
            },
        };
        let logged = resp.headers.remove(LOGGED) > 0;
        let from_web = resp.headers.remove(WEB) > 0;
        if home && resp.status == StatusCode::NOT_FOUND && !from_web {
            resp = see_home();
        }
        if !logged {
            let outcome = Outcome { rule };
            self.inner
                .log
                .log(event(method, UNROUTED, &resp, outcome, started));
        }
        if from_web {
            // The adapter set the fields of its surface (ADR-014). The
            // front still removes every CORS grant.
            strip_cors(&mut resp);
        } else {
            secure(&mut resp, public);
        }
        resp
    }

    /// The checks before routing: origin form and the cell `Host`.
    fn precheck(&self, req: &Request) -> Option<(Response, Option<Rule>)> {
        if req.target.form() != TargetForm::Origin {
            return Some((Response::new(StatusCode::BAD_REQUEST), Some(Rule::Th26)));
        }
        let mut hosts = req.headers.get_all("host");
        let ok = match (hosts.next(), hosts.next()) {
            (Some(h), None) => h
                .to_str()
                .is_some_and(|h| h.eq_ignore_ascii_case(&self.inner.host)),
            _ => false,
        };
        if ok {
            None
        } else {
            // 421 Misdirected Request (RFC 9110 section 15.5.20).
            let status = StatusCode::from_u16(421).unwrap_or(StatusCode::BAD_REQUEST);
            Some((Response::new(status), Some(Rule::I19)))
        }
    }

    /// Serves one request on the loopback health listener: `GET /healthz`
    /// with a fixed body, whatever the query, cookies or host. A HEAD gets
    /// the same status. Every other path gets 404, and another method on
    /// `/healthz` gets 405.
    pub async fn serve_health(&self, req: Request) -> Response {
        let mut resp = if req.target.path() != "/healthz" {
            Response::new(StatusCode::NOT_FOUND)
        } else if req.method == Method::GET || req.method == Method::HEAD {
            Response::with_body(
                StatusCode::OK,
                "text/plain; charset=utf-8",
                HEALTH_BODY.to_vec(),
            )
        } else {
            Response::new(StatusCode::METHOD_NOT_ALLOWED)
        };
        let _ = resp.headers.try_insert("cache-control", "no-store");
        resp
    }

    /// The tunnel listener as an `fstp-http` handler.
    pub fn tunnel_handler(&self) -> impl Handler + use<B, L> {
        TunnelHandler(self.clone())
    }

    /// The health listener as an `fstp-http` handler.
    pub fn health_handler(&self) -> impl Handler + use<B, L> {
        HealthHandler(self.clone())
    }
}

struct TunnelHandler<B, L>(Front<B, L>);

impl<B: Backend, L: LogSink> Handler for TunnelHandler<B, L> {
    async fn handle(&self, req: Request) -> Response {
        self.0.serve(req).await
    }
}

struct HealthHandler<B, L>(Front<B, L>);

impl<B: Backend, L: LogSink> Handler for HealthHandler<B, L> {
    async fn handle(&self, req: Request) -> Response {
        self.0.serve_health(req).await
    }
}

/// Where a browser goes for a page that does not exist (SA-09 amendment).
const HOME: &str = "/app/";

/// Whether a 404 answer to `req` becomes 303 to home (SA-09 amendment,
/// Daniel 2026-11-15): a browser page request
/// ([`fstp_http::is_page_navigation`]) outside `/api/`. Home itself keeps
/// its 404, since this front does not serve `/app/` and a redirect to
/// itself would loop.
fn goes_home(req: &Request) -> bool {
    let path = req.target.path();
    let api = path == "/api" || path.starts_with("/api/");
    !api && path != HOME && fstp_http::is_page_navigation(req)
}

/// The 303 to home. [`Front::serve`] adds the fields of every response.
fn see_home() -> Response {
    let mut r = Response::new(StatusCode::SEE_OTHER);
    let _ = r.headers.try_insert("location", HOME);
    r
}

/// Sets the response fields every tunnel response carries, replacing any
/// a handler set, and removes every CORS grant.
/// Whether `path` lies under `/p/`, the public surface (M4 design
/// section 3.10, lane m4/cellpub).
fn is_public_path(path: &str) -> bool {
    path.starts_with("/p/")
}

/// The HSTS value of `fstp_web::HSTS`. Interim, pending Daniel: one year,
/// no subdomains.
const HSTS: &str = "max-age=31536000";

fn secure(resp: &mut Response, public: bool) {
    // R-PB-04, TH-37: a public answer never sets a cookie.
    if public {
        resp.headers.remove("set-cookie");
    }
    let csp = if public { PUBLIC_CSP } else { CELL_CSP };
    for (name, value) in [
        ("content-security-policy", csp),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        ("cache-control", "no-store"),
        // L17, ADR-014, as `fstp-web` sends them.
        ("strict-transport-security", HSTS),
        ("cross-origin-opener-policy", "same-origin"),
        ("cross-origin-resource-policy", "same-origin"),
    ] {
        let _ = resp.headers.try_insert(name, value);
    }
    strip_cors(resp);
}

/// Removes every `Access-Control-*` field, so no other origin may read
/// a response.
fn strip_cors(resp: &mut Response) {
    let cors: Vec<String> = resp
        .headers
        .iter()
        .map(|(n, _)| n.as_str().to_ascii_lowercase())
        .filter(|n| n.starts_with("access-control-"))
        .collect();
    for n in cors {
        resp.headers.remove(&n);
    }
}
