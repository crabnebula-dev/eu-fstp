//! `fstp-devstack e2e`: the stack of the M3 browser specs (M3 design
//! section 14.7, the root specs of `e2e/`). Local development and tests
//! only.
//!
//! It starts one SaaS-mode world of two cells, `a` and `b`, with the
//! fixed sibling hosts `a.fstp.localhost` and `b.fstp.localhost`
//! ([`fstp_celltest::world::DevCell`]). It writes the stack manifest of
//! `e2e/playwright.config.ts`, and serves each cell's control routes on a
//! loopback HTTP listener of its own. No cell origin ever answers them.
//!
//! # Origins without port 443
//!
//! The relying party origin carries no port (I-20), so the manifest names
//! the origins `https://<host>` and `https://id.<host>`. Its resolver
//! rule `MAP *.fstp.localhost 127.0.0.1:<edge port>` makes Chromium
//! connect to the world's edge for them, while the page origin keeps no
//! port. So no forwarder and no root are needed.
//!
//! TLS stays real. The world's dev cells serve the origin CA after each
//! origin leaf, and the manifest pins the CA's key
//! ([`World::origin_ca_spki_digest`]). The pin survives a world start,
//! which a leaf pin would not.
//!
//! # Control routes
//!
//! - `POST /test/reset` answers `{first_admin: {url, email}}`. A cell
//!   whose first-admin link no reset handed out since the world started
//!   is fresh, and its link is handed out. Otherwise the stack starts the
//!   whole world again, both cells, with the same hosts. Each spec resets
//!   the cells it uses before it uses them, so a spec that uses both cells
//!   resets both first. The M3 cell has no email for its first admin, so
//!   `email` is empty.
//! - `GET /test/mailbox?to=` lists the proof mails the cell handed to the
//!   world's mail capture ([`fstp_celltest::world_mail`]). A
//!   self-registration proof is kind `signup` with the link
//!   `<origin>/auth/signup#<token>`. A magic link is kind `magic` with
//!   `<origin>/auth/magic#<token>`. A recovery email proof and enrolment
//!   token are kind `recovery`, with `<origin>/auth/recovery#e.<case>.<token>`
//!   and `<origin>/auth/recovery#c.<case>.<token>` (lane m3/login-m2http).
//! - `POST /test/clock/advance {micros}` moves the cell's test clock.
//! - `GET /test/account`, `POST /test/commands/{kind}`,
//!   `POST /test/scenario/negotiation` and `POST /test/vault-tickets/write`
//!   answer 501 with the seam they wait on. No production part offers
//!   them yet, and this stack invents none.
//!
//! The cell clock starts at the wall clock at each world start and then
//! moves only through `/test/clock/advance`.

#![allow(
    clippy::disallowed_macros,
    reason = "R-NF-02 print ban: test-only code that never ships, so it may print"
)]

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, Mutex, PoisonError};

use fstp_cell::http::pages::Pages;
use fstp_celltest::world::{DevCell, EDGE_PORT_ENV, World, WorldError, WorldSpec};
use fstp_http::{Handler, Method, Request, Response, Server, ServerConfig, StatusCode};
use fstp_json::{Object, Value};
use fstp_rt::Runtime as _;
use fstp_rt::signal::{Signals as _, TerminationListener as _};
use fstp_rt::tokio::TokioRuntime;

use crate::{ENROL_PAGE, SPEC, check_enrol_page, hex};

/// The parent domain of both cell hosts.
const PARENT: &str = "fstp.localhost";

/// The cells of the manifest, in world order.
const CELLS: [&str; 2] = ["a", "b"];

/// The first control port when `--control-port` is not given.
const CONTROL_PORT: u16 = 8831;

/// The two-cell world of the specs.
const E2E_SPEC: WorldSpec = WorldSpec { cells: 2, ..SPEC };

/// The usage line of the subcommand.
const USAGE: &str = "usage: fstp-devstack e2e --manifest-out <file> [--control-port <port>] (cell a's control on <port>, cell b's on the next; FSTP_EDGE_PORT names the edge port)";

/// The arguments of `fstp-devstack e2e`.
struct Args {
    manifest: PathBuf,
    control_port: u16,
}

fn args(raw: &[String]) -> Option<Args> {
    let mut manifest = None;
    let mut control_port = CONTROL_PORT;
    let mut it = raw.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--manifest-out" => manifest = Some(PathBuf::from(it.next()?)),
            "--control-port" => control_port = it.next()?.parse().ok()?,
            _ => return None,
        }
    }
    control_port.checked_add(1)?;
    Some(Args {
        manifest: manifest?,
        control_port,
    })
}

/// The fixed host of cell `name`.
fn host(name: &str) -> String {
    format!("{name}.{PARENT}")
}

/// The wall clock in UTC microseconds.
fn wall_micros() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_micros()).ok())
        .unwrap_or(0)
}

/// Starts the two-cell world with the fixed hosts.
fn start_world(pages: &Pages) -> Result<World, WorldError> {
    let now = wall_micros();
    let dev: Vec<DevCell> = CELLS
        .iter()
        .map(|n| DevCell {
            host: host(n),
            clock_start: now,
        })
        .collect();
    let world = World::start_with_dev_cells(E2E_SPEC, Some(pages.clone()), &dev)?;
    for (i, name) in (0u8..).zip(CELLS) {
        let cell = world
            .cell(i)
            .ok_or_else(|| WorldError::Store(format!("the world holds no cell {name}")))?;
        check_enrol_page(cell, &format!("https://{}", host(name)))?;
    }
    Ok(world)
}

/// The running world and which first-admin links a reset handed out.
struct Stack {
    pages: Pages,
    world: Option<World>,
    handed: [bool; 2],
}

type Shared = Arc<Mutex<Stack>>;

fn lock(s: &Shared) -> std::sync::MutexGuard<'_, Stack> {
    s.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Standard base64 with padding.
fn base64(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let sextet = |n: u32, shift: u32| {
        let idx = usize::try_from(n.checked_shr(shift).unwrap_or(0) & 63).unwrap_or(0);
        char::from(A.get(idx).copied().unwrap_or(b'A'))
    };
    let mut s = String::new();
    for chunk in bytes.chunks(3) {
        let b = |i: usize| u32::from(chunk.get(i).copied().unwrap_or(0));
        let n = (b(0) << 16) | (b(1) << 8) | b(2);
        for (k, shift) in [18u32, 12, 6, 0].into_iter().enumerate() {
            s.push(if k <= chunk.len() {
                sextet(n, shift)
            } else {
                '='
            });
        }
    }
    s
}

fn obj(members: Vec<(&str, Value)>) -> Value {
    let mut o = Object::new();
    for (k, v) in members {
        let _ = o.insert(k, v);
    }
    Value::Object(o)
}

/// The stack manifest of `e2e/playwright.config.ts`.
fn manifest(world: &World, control_port: u16) -> Result<String, WorldError> {
    let edge = world.edge_addr()?;
    let mut cells = Object::new();
    for (i, name) in (0u16..).zip(CELLS) {
        let h = host(name);
        let control = SocketAddr::from((Ipv4Addr::LOCALHOST, control_port.saturating_add(i)));
        let _ = cells.insert(
            name,
            obj(vec![
                ("origin", Value::from(format!("https://{h}"))),
                ("vault_origin", Value::from(format!("https://id.{h}"))),
                ("control", Value::from(format!("http://{control}"))),
            ]),
        );
    }
    Ok(fstp_json::to_compact(&obj(vec![
        ("version", Value::from(1u8)),
        ("cells", Value::Object(cells)),
        (
            "resolver_rules",
            Value::from(format!("MAP *.{PARENT} {edge}")),
        ),
        (
            "spki_pins",
            Value::from(vec![Value::from(base64(&world.origin_ca_spki_digest()?))]),
        ),
    ])))
}

fn json(status: StatusCode, v: &Value) -> Response {
    let mut r = Response::with_body(
        status,
        "application/json",
        fstp_json::to_compact(v).into_bytes(),
    );
    let _ = r.headers.try_insert("cache-control", "no-store");
    r
}

fn refuse(status: StatusCode, code: &str, detail: &str) -> Response {
    json(
        status,
        &obj(vec![
            ("code", Value::from(code)),
            ("detail", Value::from(detail)),
        ]),
    )
}

/// `POST /test/reset` of cell `i` (module documentation).
fn reset(stack: &Shared, i: usize) -> Response {
    let mut s = lock(stack);
    let fresh = s.world.is_some() && !s.handed.get(i).copied().unwrap_or(true);
    if !fresh {
        // The old world's cells stop before the new ones take the hosts.
        s.world = None;
        s.handed = [false; 2];
        match start_world(&s.pages) {
            Ok(w) => s.world = Some(w),
            Err(e) => {
                eprintln!("fstp-devstack e2e: the world did not start again: {e}");
                return refuse(StatusCode::INTERNAL_SERVER_ERROR, "world", &e.to_string());
            }
        }
    }
    let Stack { world, handed, .. } = &mut *s;
    let Some(world) = world.as_ref() else {
        return refuse(StatusCode::INTERNAL_SERVER_ERROR, "world", "no world");
    };
    let Some(cell) = u8::try_from(i).ok().and_then(|i| world.cell(i)) else {
        return refuse(StatusCode::INTERNAL_SERVER_ERROR, "world", "no such cell");
    };
    let invitation = match cell.first_admin_invitation() {
        Ok(inv) => inv,
        Err(e) => return refuse(StatusCode::INTERNAL_SERVER_ERROR, "world", &e.to_string()),
    };
    if let Some(h) = handed.get_mut(i) {
        *h = true;
    }
    let url = format!(
        "https://{}{ENROL_PAGE}#{}{}",
        cell.host(),
        hex(&invitation.first),
        hex(&invitation.second)
    );
    json(
        StatusCode::OK,
        &obj(vec![(
            "first_admin",
            obj(vec![("url", Value::from(url)), ("email", Value::from(""))]),
        )]),
    )
}

/// `s` as `application/x-www-form-urlencoded` writes it, as
/// `URLSearchParams` does for Playwright's `params`.
fn form_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'*' | b'-' | b'.' | b'_' => {
                out.push(char::from(b));
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Whether the query of `req` holds the pair `name=<value encoded>`. The
/// stack compares encoded forms, so it decodes nothing.
fn has_param(req: &Request, name: &str, value: &str) -> bool {
    let want = format!("{name}={}", form_encode(value));
    req.target
        .query()
        .is_some_and(|q| q.split('&').any(|kv| kv == want))
}

/// Whether the query of `req` names `name` at all.
fn names_param(req: &Request, name: &str) -> bool {
    let prefix = format!("{name}=");
    req.target
        .query()
        .is_some_and(|q| q.split('&').any(|kv| kv.starts_with(&prefix)))
}

/// `GET /test/mailbox?to=` of cell `i` (module documentation).
fn mailbox(stack: &Shared, i: usize, req: &Request) -> Response {
    if !names_param(req, "to") {
        return refuse(StatusCode::BAD_REQUEST, "bad_request", "to");
    }
    let s = lock(stack);
    let Some(cell) = s
        .world
        .as_ref()
        .and_then(|w| u8::try_from(i).ok().and_then(|i| w.cell(i)))
    else {
        return refuse(StatusCode::INTERNAL_SERVER_ERROR, "world", "no such cell");
    };
    let messages: Vec<Value> = cell
        .mail()
        .captured()
        .into_iter()
        .filter(|m| has_param(req, "to", &m.to))
        .map(|m| {
            let token = hex(&m.token);
            let (kind, page, fragment) = match m.kind {
                fstp_cell::mail::ProofKind::Signup => ("signup", "/auth/signup", token),
                fstp_cell::mail::ProofKind::MagicLink => ("magic", "/auth/magic", token),
                fstp_cell::mail::ProofKind::Recovery { case } => (
                    "recovery",
                    "/auth/recovery",
                    format!("e.{}.{token}", hex(&case)),
                ),
                fstp_cell::mail::ProofKind::RecoveryEnrolment { case } => (
                    "recovery",
                    "/auth/recovery",
                    format!("c.{}.{token}", hex(&case)),
                ),
            };
            obj(vec![
                ("kind", Value::from(kind)),
                (
                    "link",
                    Value::from(format!("https://{}{page}#{fragment}", cell.host())),
                ),
            ])
        })
        .collect();
    json(
        StatusCode::OK,
        &obj(vec![("messages", Value::from(messages))]),
    )
}

/// `POST /test/clock/advance {micros}` of cell `i`.
fn advance(stack: &Shared, i: usize, req: &Request) -> Response {
    let micros = fstp_json::parse(&req.body)
        .ok()
        .and_then(|v| {
            v.as_object()
                .and_then(|o| o.get("micros"))
                .and_then(Value::as_str)
                .and_then(|m| m.parse::<i64>().ok())
        })
        .filter(|m| *m >= 0);
    let Some(micros) = micros else {
        return refuse(StatusCode::BAD_REQUEST, "bad_request", "micros");
    };
    let s = lock(stack);
    let Some(cell) = s
        .world
        .as_ref()
        .and_then(|w| u8::try_from(i).ok().and_then(|i| w.cell(i)))
    else {
        return refuse(StatusCode::INTERNAL_SERVER_ERROR, "world", "no such cell");
    };
    cell.clock().advance(micros);
    json(
        StatusCode::OK,
        &obj(vec![("now", Value::from(cell.clock().now().to_string()))]),
    )
}

/// The seam each unserved control route waits on.
fn seam(path: &str) -> Option<&'static str> {
    if path == "/test/account" {
        return Some(
            "the M3 cell has no login email index to look an account up by (lane m3/login-m2http)",
        );
    }
    if path.starts_with("/test/commands/") {
        return Some(
            "no command builder of the devstack: CreateProgramme, GrantRole and SetLoginPolicy in the cell's wire form",
        );
    }
    if path == "/test/scenario/negotiation" {
        return Some(
            "no negotiation seed: a proposal in NEGOTIATION with vault facts and Operations and Judging invitations",
        );
    }
    if path == "/test/vault-tickets/write" {
        return Some("no route that issues a vault write ticket for a test account");
    }
    None
}

/// The control routes of cell `i`.
fn control(stack: &Shared, i: usize, req: &Request) -> Response {
    let path = req.target.path();
    match (req.method == Method::GET, path) {
        (false, "/test/reset") => reset(stack, i),
        (true, "/test/mailbox") => mailbox(stack, i, req),
        (false, "/test/clock/advance") => advance(stack, i, req),
        _ => match seam(path) {
            Some(why) => refuse(StatusCode::NOT_IMPLEMENTED, "not_implemented", why),
            None => Response::new(StatusCode::NOT_FOUND),
        },
    }
}

/// The handler of cell `i`'s control listener. The world blocks on its
/// own runtime, so each request runs on a blocking thread.
struct ControlBase {
    rt: TokioRuntime,
    stack: Shared,
    index: usize,
}

impl Handler for ControlBase {
    fn handle(&self, req: Request) -> impl Future<Output = Response> + Send {
        let stack = Arc::clone(&self.stack);
        let index = self.index;
        let job = self.rt.spawn_blocking(move || control(&stack, index, &req));
        async move {
            job.await.unwrap_or_else(|_| {
                refuse(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "world",
                    "the control route panicked",
                )
            })
        }
    }
}

/// Runs `fstp-devstack e2e`.
pub(crate) fn run(raw: &[String], pages: Pages) -> ExitCode {
    let Some(a) = args(raw) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let rt = match TokioRuntime::new_multi_thread(2) {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("fstp-devstack e2e: no runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut term = match rt.listen_termination() {
        Ok(term) => term,
        Err(e) => {
            eprintln!("fstp-devstack e2e: {e}");
            return ExitCode::FAILURE;
        }
    };
    let world = match start_world(&pages) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("fstp-devstack e2e: the world did not start: {e}");
            return ExitCode::FAILURE;
        }
    };
    let text = match manifest(&world, a.control_port) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("fstp-devstack e2e: no manifest: {e}");
            return ExitCode::FAILURE;
        }
    };
    let stack: Shared = Arc::new(Mutex::new(Stack {
        pages,
        world: Some(world),
        handed: [false; 2],
    }));
    let mut servers = Vec::new();
    for (i, port) in (0u16..).zip([a.control_port, a.control_port.saturating_add(1)]) {
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let listener = match rt.block_on(rt.bind_tcp(addr)) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("fstp-devstack e2e: cannot bind {addr}: {e}");
                return ExitCode::FAILURE;
            }
        };
        let handler = ControlBase {
            rt: rt.clone(),
            stack: Arc::clone(&stack),
            index: usize::from(i),
        };
        match Server::new(rt.clone(), ServerConfig::default(), handler).serve(listener) {
            Ok(h) => servers.push(h),
            Err(e) => {
                eprintln!("fstp-devstack e2e: cannot serve {addr}: {e}");
                return ExitCode::FAILURE;
            }
        }
    }
    // Written last, so a manifest names listeners that accept.
    if let Err(e) = std::fs::write(&a.manifest, text) {
        eprintln!(
            "fstp-devstack e2e: cannot write {}: {e}",
            a.manifest.display()
        );
        return ExitCode::FAILURE;
    }
    println!("manifest {}", a.manifest.display());
    println!("ready");
    eprintln!(
        "fstp-devstack e2e: edge on {} ({EDGE_PORT_ENV}), control from 127.0.0.1:{}",
        lock(&stack)
            .world
            .as_ref()
            .and_then(|w| w.edge_addr().ok())
            .map_or_else(String::new, |e| e.to_string()),
        a.control_port
    );
    let which = rt.block_on(term.recv());
    eprintln!("fstp-devstack e2e: {which:?} received, stopping");
    drop(servers);
    lock(&stack).world = None;
    ExitCode::SUCCESS
}
