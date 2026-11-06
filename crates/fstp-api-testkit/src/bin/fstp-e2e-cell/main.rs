//! `fstp-e2e-cell`, the M4 end-to-end test cell (design sections 1.2,
//! 8.2 and 8.7). Test only (layering rule A9). Lane W5 (L-E2E) owns this
//! binary. In the demo path, lane m4int-b writes it.
//!
//! The binary starts two cells, `a` and `b`, as the stack manifest of
//! `e2e/playwright.config.ts` names them. Each cell has two loopback
//! listeners:
//!
//! - the **cell origin** `http://<x>.fstp.localhost:<port>`. It serves the
//!   `fstp-web` routes (`/app`, `/api/v1`) over an `ApiCore` built from
//!   the fake ports of `fstp_api_testkit::fake`. It also serves the M3
//!   pages and ceremony routes under `/auth` and `/assets/auth`, which
//!   [`auth`] emulates over the same fake sessions and step-up port;
//! - the **control base** `http://127.0.0.1:<port>`, which answers the
//!   test-control routes of [`control`]: reset, mailbox, account lookup,
//!   the clock, the synthetic vault and the scenario seeds. No cell origin
//!   ever answers them.
//!
//! With `--manifest-out <file>`, the binary writes the stack manifest
//! once every listener accepts connections, so a test runner reads the
//! origins from it.
//!
//! With `--demo-signin` (lane m4/site, Daniel 2026-11-04: "for the demo
//! it makes NO SENSE to have to use and generate passkeys"), the demo
//! page gives each person a one-click sign-in, and a step-up of such a
//! session confirms with a plain button ([`demo_signin`]). Without the
//! flag, which is how the e2e suite runs the cell, nothing of it exists:
//! the route answers 404 and passkeys work as before. The flag, its route
//! and its bypass live in this test-only binary only (layering rule A9).
//!
//! Interim readings, pending Daniel:
//!
//! - The cells are plain HTTP on loopback. A host under `.localhost` is a
//!   secure context in Chromium (RFC 6761), so WebAuthn and the `__Host-`
//!   cookie work without TLS. The manifest therefore names `http:`
//!   origins and no SPKI pin.
//! - The vault origin `id.<cell host>` is listed in the manifest but not
//!   served. No M4 journey reaches it.
//! - The M3 ceremonies of [`auth`] check the ceremony type, the challenge,
//!   the origin, the RP id hash, user presence and user verification, the
//!   credential id and the sign count. They also verify each assertion's
//!   signature under the attested key, through `fstp-crypto`. They do not
//!   call `fstp_webauthn::verify_assertion`, which fixes the RP origin to
//!   `https://<host>` with no port, which no loopback listener can be.
//!   The real ceremonies are M3's, in `fstp-cell`.

mod assets;
mod auth;
mod control;
mod demo;
mod demo_signin;
mod onboarding;
mod people;
mod precheck;
mod scenario;
mod wire;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use fstp_api_core::port::api_core;
use fstp_api_testkit::fake::fixture::World;
use fstp_api_testkit::fake::{FakePorts, port_seams};
use fstp_http::{
    Handler, Method, Request, Response, Server, ServerConfig, ServerHandle, StatusCode,
};
use fstp_rt::tokio::TokioRuntime;
use fstp_rt::{Listener, Runtime};
use fstp_web::{WebConfig, WebRouter, parse_origin_header};
use fstp_web_assets::AssetSet;

use crate::assets::AuthAssets;
use crate::auth::AuthState;

/// The parent domain of every cell host. Chromium resolves any name under
/// `localhost` to loopback and treats it as a secure context.
const PARENT: &str = "fstp.localhost";

/// The names of the two cells of the manifest.
const CELLS: [&str; 2] = ["a", "b"];

/// What the binary listens on and serves.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Config {
    /// The first port: cell `a` on it, its control on the next, then cell
    /// `b` and its control. Port 0 picks four free ports.
    port: u16,
    /// The `web/` directory of the repository, holding `dist/app` (the
    /// packed `/app` assets), `dist/auth` and `src/auth`. Without it, the
    /// cells serve a one-module stub set and no M3 page.
    web: Option<PathBuf>,
    /// Where to write the stack manifest, if anywhere.
    manifest_out: Option<PathBuf>,
    /// Whether the demo sign-in of [`demo_signin`] is on (`--demo-signin`).
    demo_signin: bool,
}

impl Config {
    /// Free ports, no frontend, no manifest.
    fn loopback() -> Config {
        Config {
            port: 0,
            web: None,
            manifest_out: None,
            demo_signin: false,
        }
    }

    /// The configuration from the arguments: `--port <n>`, `--web <dir>`,
    /// `--manifest-out <file>` and `--demo-signin`, each optional. Any
    /// other argument is refused, and so is a port range that does not fit.
    fn from_args(args: impl IntoIterator<Item = String>) -> Result<Config, String> {
        let mut cfg = Config::loopback();
        let mut args = args.into_iter();
        while let Some(a) = args.next() {
            match a.as_str() {
                "--port" => {
                    let v = args.next().ok_or("--port needs a number")?;
                    let p: u16 = v.parse().map_err(|_| format!("bad port {v}"))?;
                    if p != 0 && p > u16::MAX - 3 {
                        return Err(format!("port {p} leaves no room for four listeners"));
                    }
                    cfg.port = p;
                }
                "--web" => {
                    cfg.web = Some(PathBuf::from(args.next().ok_or("--web needs a directory")?));
                }
                "--manifest-out" => {
                    cfg.manifest_out = Some(PathBuf::from(
                        args.next().ok_or("--manifest-out needs a file")?,
                    ));
                }
                "--demo-signin" => cfg.demo_signin = true,
                other => return Err(format!("unknown argument {other}")),
            }
        }
        Ok(cfg)
    }

    /// The loopback address of listener `i` (0 to 3).
    fn addr(&self, i: u16) -> SocketAddr {
        let port = if self.port == 0 {
            0
        } else {
            self.port.saturating_add(i)
        };
        SocketAddr::from(([127, 0, 0, 1], port))
    }
}

/// Locks `m`, taking the data of a poisoned lock.
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// One state of a cell: the fake ports, the routes over them and the M3
/// emulation. A reset or a scenario replaces it whole.
pub(crate) struct Inner {
    /// The fake ports.
    pub(crate) ports: FakePorts,
    /// The `fstp-web` routes over an `ApiCore` of [`Inner::ports`].
    pub(crate) web: WebRouter,
    /// Accounts, invitations, passkeys and the mailbox.
    pub(crate) auth: Mutex<AuthState>,
    /// The API core the routes call, for the scenario seeds.
    pub(crate) core: Arc<fstp_api_core::ApiCore>,
    /// The name of the scene this state holds, for the demo page.
    scene: Mutex<String>,
}

impl Inner {
    /// The state over `world`, with the M3 records `auth`. The tenant's
    /// inference record names `model`, the P-21 primary model that a
    /// publication pins (design section 3.5).
    pub(crate) fn new(
        site: &SiteInfo,
        world: &World,
        auth: AuthState,
        model: &str,
    ) -> Result<Inner, String> {
        let mut seams = port_seams().map_err(|e| e.to_string())?;
        let mut settings = (*seams.settings).clone();
        if let Some(r) = settings.inference.as_mut() {
            r.model = fstp_domain::policy::ModelRef(model.to_owned());
        }
        seams.settings = Arc::new(settings);
        let ports = FakePorts::new(world, seams).map_err(|e| e.to_string())?;
        // R-GA-01: the scenarios create their SuperSAFE programme through
        // core commands, with no complete creator draft, so its Guide reads the
        // artefacts of the SuperSAFE fixture.
        let fixture = fstp_programme::supersafe_fixture().map_err(|e| format!("{e:?}"))?;
        ports.engine.set_guide_spec(fixture.spec);
        let core = Arc::new(api_core(ports.clone()));
        let origin = parse_origin_header(site.origin.as_bytes()).map_err(|e| e.to_string())?;
        let web = fstp_web::router(
            Arc::clone(&core),
            // The cell origin is plain `http` under `.localhost`, so its
            // OAuth metadata names it as a test cell (lane W3c).
            WebConfig::new(origin, site.assets.clone()).test_cell(),
        )
        .map_err(|e| e.to_string())?;
        Ok(Inner {
            ports,
            web,
            auth: Mutex::new(auth),
            core,
            scene: Mutex::new("Reset".to_owned()),
        })
    }

    /// Names the scene this state holds, such as `stage1` or `STAGE2`.
    pub(crate) fn set_scene(&self, name: &str) {
        name.clone_into(&mut lock(&self.scene));
    }

    /// The name of the scene this state holds.
    pub(crate) fn scene(&self) -> String {
        lock(&self.scene).clone()
    }
}

/// What a cell is, apart from its state.
pub(crate) struct SiteInfo {
    /// The cell's name in the manifest, `a` or `b`.
    pub(crate) name: &'static str,
    /// The cell host, `<name>.fstp.localhost`.
    pub(crate) host: String,
    /// The cell origin.
    pub(crate) origin: String,
    /// The control base.
    pub(crate) control: String,
    /// The packed `/app` assets.
    pub(crate) assets: AssetSet,
    /// The M3 pages.
    pub(crate) auth_assets: Arc<AuthAssets>,
    /// Whether the demo sign-in is on (`--demo-signin`).
    pub(crate) demo_signin: bool,
}

/// One cell: what it is and its current state.
pub(crate) struct Site {
    pub(crate) info: SiteInfo,
    inner: RwLock<Arc<Inner>>,
}

impl Site {
    /// The current state.
    pub(crate) fn inner(&self) -> Arc<Inner> {
        Arc::clone(&self.inner.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// Replaces the state.
    pub(crate) fn replace(&self, next: Inner) {
        *self.inner.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(next);
    }
}

/// The handler of a cell origin listener.
struct CellOrigin(Arc<Site>);

impl Handler for CellOrigin {
    fn handle(&self, req: Request) -> impl Future<Output = Response> + Send {
        let site = Arc::clone(&self.0);
        async move {
            let path = req.target.path().to_owned();
            if path == "/" && req.method == Method::GET {
                let mut r = Response::new(StatusCode::SEE_OTHER);
                let _ = r.headers.try_insert("location", "/auth/login");
                return r;
            }
            if path == "/assets" || path.starts_with("/assets/") {
                return site.info.auth_assets.asset(&req);
            }
            let inner = site.inner();
            if site.info.demo_signin && path == demo_signin::ROUTE {
                return demo_signin::handle(&site.info, &inner, req).await;
            }
            // The `/app/` shell and the M3 account page of a demo sign-in
            // session carry the demo notice; no other reply changes
            // (`demo_signin`).
            let demo = if site.info.demo_signin && req.method == Method::GET {
                match demo_signin::module_for(&path) {
                    Some(m) if demo_signin::is_demo_session(&inner, &req).await => Some(m),
                    _ => None,
                }
            } else {
                None
            };
            if path == "/auth" || path.starts_with("/auth/") {
                let r = auth::handle(&site.info, &inner, req).await;
                return match demo {
                    Some(m) => demo_signin::mark_shell(r, m),
                    None => r,
                };
            }
            if path == onboarding::INVITE_ROUTE && req.method == Method::POST {
                return onboarding::invite_admin(&inner, req).await;
            }
            let r = people::serve(&inner, req).await;
            match demo {
                Some(m) => demo_signin::mark_shell(r, m),
                None => r,
            }
        }
    }
}

/// The handler of a control listener.
struct ControlBase(Arc<Site>);

impl Handler for ControlBase {
    fn handle(&self, req: Request) -> impl Future<Output = Response> + Send {
        let site = Arc::clone(&self.0);
        async move { control::handle(&site, req).await }
    }
}

/// The running cells. They serve until dropped.
struct Running {
    sites: Vec<Arc<Site>>,
    _servers: Vec<ServerHandle<TokioRuntime>>,
    _rt: TokioRuntime,
}

impl std::fmt::Debug for Running {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Running")
            .field("cells", &self.sites.len())
            .finish_non_exhaustive()
    }
}

/// The one module of the stub asset set.
const STUB_MODULE: &[u8] = b"// fstp-e2e-cell stub asset set\nexport {};\n";

/// The packed `/app` assets of `cfg`, or the stub set.
fn app_assets(cfg: &Config) -> Result<AssetSet, String> {
    match &cfg.web {
        Some(dir) => fstp_web_assets::load_dir(&dir.join("dist").join("app"))
            .map_err(|e| format!("the packed assets: {e}")),
        None => {
            AssetSet::from_files("main.js", &[("main.js", STUB_MODULE)]).map_err(|e| e.to_string())
        }
    }
}

/// Starts both cells. It returns once every listener accepts connections.
fn start(cfg: &Config) -> Result<Running, String> {
    let assets = app_assets(cfg)?;
    let auth_assets = Arc::new(match &cfg.web {
        Some(dir) => AuthAssets::load(dir, cfg.demo_signin)?,
        None => AuthAssets::empty(),
    });
    let rt = TokioRuntime::new_multi_thread(2).map_err(|e| e.to_string())?;
    let server_cfg = || ServerConfig {
        limits: fstp_web::limits(),
        ..ServerConfig::default()
    };
    let mut sites = Vec::new();
    let mut servers = Vec::new();
    for (i, name) in (0u16..).zip(CELLS) {
        let cell_listener = rt
            .block_on(rt.bind_tcp(cfg.addr(i.saturating_mul(2))))
            .map_err(|e| e.to_string())?;
        let control_listener = rt
            .block_on(rt.bind_tcp(cfg.addr(i.saturating_mul(2).saturating_add(1))))
            .map_err(|e| e.to_string())?;
        let cell_addr = cell_listener.local_addr().map_err(|e| e.to_string())?;
        let control_addr = control_listener.local_addr().map_err(|e| e.to_string())?;
        let host = format!("{name}.{PARENT}");
        let info = SiteInfo {
            name,
            origin: format!("http://{host}:{}", cell_addr.port()),
            control: format!("http://{control_addr}"),
            host,
            assets: assets.clone(),
            auth_assets: Arc::clone(&auth_assets),
            demo_signin: cfg.demo_signin,
        };
        let first = control::fresh(&info)?;
        let site = Arc::new(Site {
            inner: RwLock::new(Arc::new(first.inner)),
            info,
        });
        servers.push(
            Server::new(rt.clone(), server_cfg(), CellOrigin(Arc::clone(&site)))
                .serve(cell_listener)
                .map_err(|e| e.to_string())?,
        );
        servers.push(
            Server::new(rt.clone(), server_cfg(), ControlBase(Arc::clone(&site)))
                .serve(control_listener)
                .map_err(|e| e.to_string())?,
        );
        sites.push(site);
    }
    let running = Running {
        sites,
        _servers: servers,
        _rt: rt,
    };
    if let Some(path) = &cfg.manifest_out {
        std::fs::write(path, manifest(&running).to_compact())
            .map_err(|e| format!("write {}: {e}", path.display()))?;
    }
    Ok(running)
}

/// The stack manifest of `e2e/playwright.config.ts` for the running cells.
fn manifest(r: &Running) -> fstp_json::Value {
    let mut cells = fstp_json::Object::new();
    for s in &r.sites {
        let port = s.info.origin.rsplit(':').next().unwrap_or("0");
        let _ = cells.insert(
            s.info.name,
            wire::obj(vec![
                ("origin", s.info.origin.as_str().into()),
                (
                    "vault_origin",
                    format!("http://id.{}:{port}", s.info.host).into(),
                ),
                ("control", s.info.control.as_str().into()),
            ]),
        );
    }
    wire::obj(vec![
        ("version", wire::int(1)),
        ("cells", fstp_json::Value::Object(cells)),
        ("resolver_rules", format!("MAP *.{PARENT} 127.0.0.1").into()),
        (
            "spki_pins",
            fstp_json::Value::Array(fstp_json::Array::new()),
        ),
    ])
}

fn main() -> ExitCode {
    let Ok(cfg) = Config::from_args(std::env::args().skip(1)) else {
        return ExitCode::from(64);
    };
    match start(&cfg) {
        Ok(running) => {
            let _keep = running;
            loop {
                std::thread::park();
            }
        }
        Err(_) => ExitCode::from(2),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;

    /// One HTTP/1.1 exchange with `addr`, returning the reply text.
    fn exchange(addr: &str, request: &str) -> String {
        let mut s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        s.write_all(request.as_bytes()).unwrap();
        let mut reply = Vec::new();
        s.read_to_end(&mut reply).unwrap();
        String::from_utf8_lossy(&reply).into_owned()
    }

    fn addr_of(base: &str) -> String {
        base.trim_start_matches("http://").to_owned()
    }

    fn cell_addr(site: &Site) -> String {
        let port = site.info.origin.rsplit(':').next().unwrap();
        format!("127.0.0.1:{port}")
    }

    /// R-PB-01, design sections 1.2 and 8.7: the e2e cell starts on
    /// loopback and answers one read. `GET /api/v1/calls` lists the open
    /// calls, public data that needs no session, as JSON.
    #[test]
    fn r_pb_01_e2e_cell_starts_and_answers_one_read() {
        let running = start(&Config::loopback()).unwrap_or_else(|e| panic!("{e}"));
        let site = &running.sites[0];
        let text = exchange(
            &cell_addr(site),
            "GET /api/v1/calls HTTP/1.1\r\nHost: a.fstp.localhost\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
        );
        assert!(text.starts_with("HTTP/1.1 200"), "the reply: {text}");
        let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
        assert!(
            head.to_ascii_lowercase()
                .contains("content-type: application/json"),
            "the reply head: {head}"
        );
        assert!(
            fstp_json::parse_str(body.trim()).is_ok()
                || head.to_ascii_lowercase().contains("chunked"),
            "the body is not JSON: {body}"
        );
    }

    /// Design section 8.7, layering rule A9: the control routes answer on
    /// the control base only. The cell origin refuses `/test/reset`.
    #[test]
    fn a9_control_routes_answer_on_the_control_base_only() {
        let running = start(&Config::loopback()).unwrap_or_else(|e| panic!("{e}"));
        let site = &running.sites[0];
        let on_cell = exchange(
            &cell_addr(site),
            "POST /test/reset HTTP/1.1\r\nHost: a.fstp.localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
        assert!(on_cell.starts_with("HTTP/1.1 404"), "the reply: {on_cell}");
        let on_control = exchange(
            &addr_of(&site.info.control),
            "POST /test/reset HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
        assert!(
            on_control.starts_with("HTTP/1.1 200"),
            "the reply: {on_control}"
        );
        assert!(
            on_control.contains("first_admin"),
            "the reply: {on_control}"
        );
    }

    /// The arguments: a port, the web directory and the manifest file.
    #[test]
    fn e2e_cell_arguments() {
        let ok = Config::from_args(["--port".to_owned(), "8640".to_owned()]).unwrap();
        assert_eq!(ok.addr(1).port(), 8641);
        assert!(ok.addr(3).ip().is_loopback());
        assert!(Config::from_args(["--port".to_owned(), "65534".to_owned()]).is_err());
        assert!(Config::from_args(["--other".to_owned()]).is_err());
        assert!(
            Config::from_args(["--demo-signin".to_owned()])
                .unwrap()
                .demo_signin
        );
        assert!(!Config::from_args(Vec::new()).unwrap().demo_signin);
        assert_eq!(Config::from_args(Vec::new()).unwrap(), Config::loopback());
    }
}
