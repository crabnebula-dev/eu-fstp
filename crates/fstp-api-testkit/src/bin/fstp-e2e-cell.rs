//! `fstp-e2e-cell`, the M4 end-to-end test cell (design section 1.2). Test
//! only. Lane W5 (L-E2E) owns this file. In the demo path, lane W3b writes
//! it.
//!
//! The cell serves the `fstp-web` routes on one loopback listener, over an
//! `ApiCore` built from the fake ports of `fstp_api_testkit::fake`: the
//! I-85 world from genesis, a controllable clock, the synthetic vault and
//! the recording fakes. Playwright (`e2e/`) drives it.
//!
//! Beside the `fstp-web` routes, the cell answers four control routes
//! under `/__e2e/`, which no production cell has:
//!
//! - `POST /__e2e/login` with `{"account", "method"}` logs an account in
//!   and sets the `__Host-fstp` session cookie;
//! - `POST /__e2e/clock` with `{"advance"}` or `{"set"}` moves the clock,
//!   in microseconds as decimal strings;
//! - `POST /__e2e/step-up` with `{"session", "action"}` completes a
//!   step-up for a session and an action digest, as a virtual
//!   authenticator would;
//! - `GET /__e2e/world` lists the synthetic accounts, programmes and
//!   calls of the world.
//!
//! Interim readings, pending Daniel: the cell is plain HTTP on loopback,
//! and its tenant origin is `http://` plus the listen address, or
//! `--origin`. The frontend comes from `--assets <dir>`, a directory with
//! the asset manifest, or a one-module stub set without it. The cell
//! holds the synthetic legal-wording profile only once lane W2c lands the
//! profile source.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use fstp_api_core::ActionDigest;
use fstp_api_core::port::{LoginMethod, SessionId, api_core};
use fstp_api_testkit::fake::fixture::{
    self, ADMIN, ADMIN_2, CALL_ALLOWED, CALL_EDIT, CALL_OPEN, CALL_PUBLISH, LEAD, OTHER, OWNER,
    P1, P2, PX,
};
use fstp_api_testkit::fake::{FakePorts, port_seams};
use fstp_domain::id::AccountId;
use fstp_domain::time::Timestamp;
use fstp_http::{Handler, Method, Request, Response, Server, ServerConfig, ServerHandle, StatusCode};
use fstp_json::{Object, Value};
use fstp_rt::tokio::TokioRuntime;
use fstp_rt::{Listener, Runtime};
use fstp_web::{WebConfig, WebRouter, parse_origin_header};
use fstp_web_assets::AssetSet;

/// What the e2e cell listens on and serves.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Config {
    /// The loopback address of the one listener. Port 0 picks a free port.
    listen: SocketAddr,
    /// The directory of the compiled frontend, if any.
    assets: Option<PathBuf>,
    /// The tenant origin, if not `http://` plus the listen address.
    origin: Option<String>,
}

impl Config {
    /// A loopback listener on a free port.
    fn loopback() -> Config {
        Config {
            listen: SocketAddr::from(([127, 0, 0, 1], 0)),
            assets: None,
            origin: None,
        }
    }

    /// The configuration from the arguments: `--listen <address>`,
    /// `--assets <dir>` and `--origin <origin>`, each optional. Any other
    /// argument is refused, and so is a listen address off loopback.
    fn from_args(args: impl IntoIterator<Item = String>) -> Result<Config, String> {
        let mut cfg = Config::loopback();
        let mut args = args.into_iter();
        while let Some(a) = args.next() {
            match a.as_str() {
                "--listen" => {
                    let v = args.next().ok_or("--listen needs an address")?;
                    let addr: SocketAddr = v.parse().map_err(|_| format!("bad address {v}"))?;
                    if !addr.ip().is_loopback() {
                        return Err(format!("{addr} is not a loopback address"));
                    }
                    cfg.listen = addr;
                }
                "--assets" => {
                    let v = args.next().ok_or("--assets needs a directory")?;
                    cfg.assets = Some(PathBuf::from(v));
                }
                "--origin" => {
                    cfg.origin = Some(args.next().ok_or("--origin needs an origin")?);
                }
                other => return Err(format!("unknown argument {other}")),
            }
        }
        Ok(cfg)
    }
}

/// A running e2e cell. It serves until dropped.
struct Running {
    /// The address it listens on.
    addr: SocketAddr,
    /// The server.
    _server: ServerHandle<TokioRuntime>,
    /// The runtime the server runs on.
    _rt: TokioRuntime,
}

impl std::fmt::Debug for Running {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Running")
            .field("addr", &self.addr)
            .finish_non_exhaustive()
    }
}

/// The one module of the stub asset set.
const STUB_MODULE: &[u8] = b"// fstp-e2e-cell stub asset set\nexport {};\n";

/// The routes of the cell: the control routes, then `fstp-web`.
struct Cell {
    web: WebRouter,
    ports: FakePorts,
}

/// A JSON response.
fn json(status: StatusCode, v: &Value) -> Response {
    Response::with_body(status, "application/json", v.to_compact().into_bytes())
}

/// A refusal of a control request.
fn bad(why: &str) -> Response {
    let mut o = Object::new();
    let _ = o.insert("code", Value::from("bad_request"));
    let _ = o.insert("rule", Value::from(why));
    json(StatusCode::BAD_REQUEST, &Value::Object(o))
}

/// A decimal string.
fn dec(x: impl std::fmt::Display) -> Value {
    Value::String(x.to_string())
}

/// The decimal member `name` of `o`.
fn dec_member(o: &Object, name: &str) -> Option<i128> {
    o.get(name)?.as_str()?.parse().ok()
}

impl Cell {
    /// Answers a control request under `/__e2e/`.
    fn control(&self, req: &Request) -> Response {
        let body = if req.body.is_empty() {
            Object::new()
        } else {
            match fstp_json::parse(&req.body) {
                Ok(Value::Object(o)) => o,
                _ => return bad("body"),
            }
        };
        match (req.method == Method::GET, req.target.path()) {
            (false, "/__e2e/login") => self.login(&body),
            (false, "/__e2e/clock") => self.clock(&body),
            (false, "/__e2e/step-up") => self.step_up(&body),
            (true, "/__e2e/world") => world(),
            _ => Response::new(StatusCode::NOT_FOUND),
        }
    }

    fn login(&self, body: &Object) -> Response {
        let Some(account) = dec_member(body, "account").and_then(|a| u128::try_from(a).ok())
        else {
            return bad("account");
        };
        let method = match body.get("method").and_then(Value::as_str) {
            None | Some("passkey") => LoginMethod::Passkey,
            Some("magic_link") => LoginMethod::MagicLink,
            Some("opaque") => LoginMethod::Opaque,
            Some("eudi_wallet") => LoginMethod::EudiWallet,
            Some(_) => return bad("method"),
        };
        let login = self
            .ports
            .sessions
            .login(AccountId::from_raw(account), method);
        let mut o = Object::new();
        let _ = o.insert("session", dec(login.session.raw()));
        let mut r = json(StatusCode::OK, &Value::Object(o));
        let cookie = format!(
            "__Host-fstp={}; Path=/; Secure; HttpOnly; SameSite=Strict",
            String::from_utf8_lossy(&login.cookie)
        );
        let _ = r.headers.try_insert("set-cookie", cookie.as_str());
        r
    }

    fn clock(&self, body: &Object) -> Response {
        if let Some(n) = dec_member(body, "advance").and_then(|n| i64::try_from(n).ok()) {
            self.ports.clock.advance(n);
        } else if let Some(n) = dec_member(body, "set").and_then(|n| i64::try_from(n).ok()) {
            self.ports.clock.set(Timestamp::from_micros(n));
        } else {
            return bad("clock");
        }
        let mut o = Object::new();
        let _ = o.insert("now", dec(self.ports.clock.read().micros()));
        json(StatusCode::OK, &Value::Object(o))
    }

    fn step_up(&self, body: &Object) -> Response {
        let session = dec_member(body, "session").and_then(|s| u128::try_from(s).ok());
        let action = body
            .get("action")
            .and_then(Value::as_str)
            .and_then(ActionDigest::from_hex);
        let (Some(session), Some(action)) = (session, action) else {
            return bad("step-up");
        };
        match self
            .ports
            .step_up
            .approve(SessionId::from_raw(session), action)
        {
            Ok(r) => {
                let mut o = Object::new();
                let _ = o.insert("step_up", dec(r.0));
                json(StatusCode::OK, &Value::Object(o))
            }
            Err(_) => bad("step-up"),
        }
    }
}

/// The synthetic world, so a journey names its accounts by role.
fn world() -> Response {
    let mut accounts = Object::new();
    for (name, a) in [
        ("programme_manager", OWNER),
        ("call_drafter", OTHER),
        ("tenant_admin", ADMIN),
        ("tenant_admin_2", ADMIN_2),
        ("lead", LEAD),
    ] {
        let _ = accounts.insert(name, dec(a.raw()));
    }
    let mut calls = Object::new();
    for (name, c) in [
        ("to_publish", CALL_PUBLISH),
        ("to_edit", CALL_EDIT),
        ("open", CALL_OPEN),
        ("allowed", CALL_ALLOWED),
    ] {
        let _ = calls.insert(name, dec(c.raw()));
    }
    let mut o = Object::new();
    let _ = o.insert("accounts", Value::Object(accounts));
    let _ = o.insert("calls", Value::Object(calls));
    let _ = o.insert("draft_only_programme", dec(P1.raw()));
    let _ = o.insert("allowed_programme", dec(P2.raw()));
    let _ = o.insert("draft_proposal", dec(PX.raw()));
    json(StatusCode::OK, &Value::Object(o))
}

impl Handler for Cell {
    fn handle(&self, req: Request) -> impl Future<Output = Response> + Send {
        async move {
            if req.target.path().starts_with("/__e2e/") {
                self.control(&req)
            } else {
                self.web.serve(req).await
            }
        }
    }
}

/// Starts the e2e cell on `cfg.listen`, serving the `fstp-web` routes over
/// the I-85 world on the fake ports. It returns once the listener accepts
/// connections.
fn start(cfg: &Config) -> Result<Running, String> {
    let world = fixture::pending_world()?;
    let seams = port_seams().map_err(|e| e.to_string())?;
    let ports = FakePorts::new(&world, seams).map_err(|e| e.to_string())?;
    let core = Arc::new(api_core(ports.clone()));
    let rt = TokioRuntime::new_multi_thread(2).map_err(|e| e.to_string())?;
    // Bind first, so the tenant origin names the port a port 0 listen
    // address picked.
    let listener = rt
        .block_on(rt.bind_tcp(cfg.listen))
        .map_err(|e| e.to_string())?;
    let addr = listener.local_addr().map_err(|e| e.to_string())?;
    let origin_text = cfg
        .origin
        .clone()
        .unwrap_or_else(|| format!("http://{addr}"));
    let origin = parse_origin_header(origin_text.as_bytes()).map_err(|e| e.to_string())?;
    let assets = match &cfg.assets {
        Some(dir) => fstp_web_assets::load_dir(dir).map_err(|e| e.to_string())?,
        None => AssetSet::from_files("main.js", &[("main.js", STUB_MODULE)])
            .map_err(|e| e.to_string())?,
    };
    let web = fstp_web::router(core, WebConfig::new(origin, assets)).map_err(|e| e.to_string())?;
    let server_cfg = ServerConfig {
        limits: fstp_web::limits(),
        ..ServerConfig::default()
    };
    let cell = Cell { web, ports };
    let server = Server::new(rt.clone(), server_cfg, cell)
        .serve(listener)
        .map_err(|e| e.to_string())?;
    Ok(Running {
        addr: server.local_addr(),
        _server: server,
        _rt: rt,
    })
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

    /// R-PB-01, design sections 1.2 and 8.7: the e2e cell starts on a
    /// loopback port and answers one read. `GET /api/v1/calls` lists the
    /// open calls, public data that needs no session, as JSON.
    #[test]
    fn r_pb_01_e2e_cell_starts_and_answers_one_read() {
        let running = start(&Config::loopback()).unwrap_or_else(|e| panic!("{e}"));
        assert!(running.addr.ip().is_loopback());
        let mut s = TcpStream::connect(running.addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        s.write_all(
            b"GET /api/v1/calls HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
        let mut reply = Vec::new();
        s.read_to_end(&mut reply).unwrap();
        let text = String::from_utf8_lossy(&reply);
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

    /// The arguments: only a loopback `--listen` address is taken.
    #[test]
    fn e2e_cell_takes_only_a_loopback_listen_address() {
        let ok = Config::from_args(["--listen".to_owned(), "127.0.0.1:8443".to_owned()]).unwrap();
        assert_eq!(ok.listen.port(), 8443);
        assert!(Config::from_args(["--listen".to_owned(), "0.0.0.0:1".to_owned()]).is_err());
        assert!(Config::from_args(["--other".to_owned()]).is_err());
        assert_eq!(Config::from_args(Vec::new()).unwrap(), Config::loopback());
    }
}
