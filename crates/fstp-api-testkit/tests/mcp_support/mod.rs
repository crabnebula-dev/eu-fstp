//! Shared helpers of the MCP tests of lane W3c (I-84 to I-87, TH-60,
//! TH-63; M4 design section 3.8). This directory is no test target. Each
//! MCP test file includes it with `mod mcp_support;`.
//!
//! # The cell
//!
//! [`McpCell`] is the I-85 world of `fake::fixture` behind one `ApiCore`
//! of fake ports, as `FakeCell` builds it, with an `fstp_mcp::McpServer`
//! over that core. [`McpCell::submitted`] builds the same world with the
//! lead's proposal PX submitted. Every account and text is synthetic.
//!
//! # Readings of a `tools/call` result (interim, pending Daniel)
//!
//! Design section 3.8 fixes the result of a completed read. These
//! readings are the test author's, and the implementer keeps them:
//!
//! - A completed call: `isError` false, and `structuredContent` holds
//!   exactly `classification`, `data` and `untrusted`.
//! - A prepared action: the same, with `data` the pending receipt
//!   `{"status":"awaiting_confirmation","confirm_path","expires"}`.
//! - A refusal: `isError` true, and `structuredContent` is
//!   `{"code":<ErrorCode::as_str>,"rule":<rule text>}`, the body of an
//!   HTTP refusal. A step-up answer would be `{"code":"step_up_required"}`
//!   and never arises through MCP.
//! - `content` is exactly one text block, a fixed sentence.

#![allow(dead_code, unreachable_pub)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::sync::Arc;

use fstp_api_core::port::{AgentClientId, LoginMethod, api_core};
use fstp_api_core::{ApiCore, Credential};
use fstp_api_testkit::fake::fixture::{self, World};
use fstp_api_testkit::fake::{FakePorts, WebLogin, port_seams};
use fstp_api_testkit::matrix::{ChannelFault, Observed};
use fstp_domain_testkit::r#gen::review::{attest_adult_leads, review_truth};
use fstp_domain_testkit::r#gen::roster::T0;
use fstp_engine::Engine;
use fstp_json::{Object, Value};
use fstp_ledger::MemStore;
use fstp_mcp::{McpConfig, McpServer, RpcError, Surface};
use fstp_rt::future::block_on;

/// The tenant origin of every MCP test cell.
pub const ORIGIN: &str = "https://tenant.fstp.test";
/// The tenant's verified domain.
pub const DOMAIN: &str = "tenant.fstp.test";
/// The protected resource metadata URL every 401 names (RFC 9728).
pub const RESOURCE_METADATA: &str = "https://tenant.fstp.test/.well-known/oauth-protected-resource";
/// The MCP revision the lane scope serves first: the ADR-013 floor.
pub const FLOOR: &str = "2025-06-18";

/// The MCP configuration of the test cell.
pub fn config() -> McpConfig {
    McpConfig {
        tenant_origins: vec![ORIGIN.to_owned()],
        verified_domain: DOMAIN.to_owned(),
        resource_metadata_url: RESOURCE_METADATA.to_owned(),
    }
}

/// The I-85 world, with PX submitted when `submit` holds.
pub fn world(submit: bool) -> World {
    let mut s = fixture::setup();
    for d in &mut s.drafts {
        d.submit = submit;
    }
    let mut steps = s.steps().unwrap_or_else(|e| panic!("the world steps: {e}"));
    for step in &mut steps {
        if let fstp_domain::Command::CreateProgramme { policy } = &mut step.cmd
            && policy.programme == fixture::P2
        {
            policy.frozen.p77 = fstp_domain::policy::McpBindingActions::Allowed;
        }
    }
    let mut truth = review_truth(s.accounts());
    attest_adult_leads(&mut truth, s.drafts.iter().map(|d| (d.lead, d.minor)));
    let vault = fstp_api_testkit::fake::FakeVault::new(truth.clone());
    let mut engine =
        Engine::open(MemStore::new(), vault.oracle()).unwrap_or_else(|e| panic!("{e:?}"));
    for (i, step) in steps.into_iter().enumerate() {
        let mut b = *b"mcp:w3c:world:\0\0";
        let n = u16::try_from(i).unwrap_or(u16::MAX).to_be_bytes();
        b[14] = n[0];
        b[15] = n[1];
        let ctx = step.ctx(T0, fstp_domain::id::CommandId::from_bytes(b));
        fstp_domain_testkit::activation::run_core(&mut engine, &step.cmd, ctx)
            .unwrap_or_else(|e| panic!("world step {i} {:?}: {e}", step.cmd.kind()));
    }
    let (store, _, _) = engine.into_parts();
    World {
        store,
        truth,
        start: fixture::START,
        admins: [fixture::ADMIN, fixture::ADMIN_2].into_iter().collect(),
    }
}

/// One cell of fake ports with its `ApiCore` and the MCP server over it.
pub struct McpCell {
    /// The ports, shared with the core.
    pub ports: FakePorts,
    /// The core the server dispatches through.
    pub core: Arc<ApiCore>,
}

impl McpCell {
    /// The cell over the I-85 world.
    pub fn new() -> McpCell {
        McpCell::over(&world(false))
    }

    /// The cell over the I-85 world with PX submitted.
    pub fn submitted() -> McpCell {
        McpCell::over(&world(true))
    }

    /// The cell over `w`.
    pub fn over(w: &World) -> McpCell {
        let seams = port_seams().unwrap_or_else(|e| panic!("{e}"));
        let ports = FakePorts::new(w, seams).unwrap_or_else(|e| panic!("{e}"));
        McpCell {
            core: Arc::new(api_core(ports.clone())),
            ports,
        }
    }

    /// The MCP server over this cell. It panics with the stub's refusal,
    /// so a test fails for that reason.
    pub fn server(&self) -> McpServer {
        McpServer::new(Arc::clone(&self.core), config())
            .unwrap_or_else(|e| panic!("fstp_mcp::McpServer::new: {e}"))
    }

    /// A token of `account` for `client` with `scopes`, consented in a
    /// passkey session.
    pub fn token(
        &self,
        account: fstp_domain::id::AccountId,
        client: AgentClientId,
        scopes: impl IntoIterator<Item = fstp_api_core::meta::Scope>,
    ) -> Vec<u8> {
        self.ports
            .tokens
            .issue(account, client, scopes, LoginMethod::Passkey)
    }

    /// A passkey web login of `account`.
    pub fn login(&self, account: fstp_domain::id::AccountId) -> WebLogin {
        self.ports.sessions.login(account, LoginMethod::Passkey)
    }

    /// Dispatches `op` through the web session of `login`.
    pub fn web(
        &self,
        login: &WebLogin,
        op: Result<fstp_api_core::Op, fstp_api_core::ApiError>,
    ) -> Result<fstp_api_core::OpResult, fstp_api_core::ApiError> {
        let op = op?;
        block_on(self.core.dispatch(
            Credential::SessionCookie(login.cookie.clone()),
            &fstp_api_core::RequestHead::new(),
            op,
        ))
    }
}

/// `tools/call` of `name` with `args` through `server`.
pub fn call(
    server: &McpServer,
    surface: Surface,
    cred: Credential,
    name: &str,
    args: &Value,
) -> Result<Value, RpcError> {
    block_on(server.call_tool(surface, cred, name, args.to_compact().as_bytes()))
}

/// `tools/list` through `server`.
pub fn list(server: &McpServer, surface: Surface, cred: Credential) -> Result<Value, RpcError> {
    block_on(server.list_tools(surface, cred))
}

/// The tool names of a `ListToolsResult`, in order.
pub fn listed_names(v: &Value) -> Vec<String> {
    v.as_object()
        .and_then(|o| o.get("tools"))
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|t| t.as_object()?.get("name")?.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// The `structuredContent` object of a `CallToolResult`.
pub fn structured(v: &Value) -> Option<&Object> {
    v.as_object()?.get("structuredContent")?.as_object()
}

/// Whether a `CallToolResult` says `isError`.
pub fn is_error(v: &Value) -> bool {
    v.as_object()
        .and_then(|o| o.get("isError"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

/// The string member `k` of `o`.
pub fn text<'a>(o: &'a Object, k: &str) -> Option<&'a str> {
    o.get(k)?.as_str()
}

/// What a `tools/call` result says about its operation, as the matrix
/// classes it (module documentation).
pub fn observed(r: &Result<Value, RpcError>) -> Result<Observed, ChannelFault> {
    let v = match r {
        Ok(v) => v,
        Err(e) => {
            return Err(ChannelFault::NotImplemented(format!(
                "JSON-RPC error {}: {}",
                e.code, e.message
            )));
        }
    };
    let Some(sc) = structured(v) else {
        return Err(ChannelFault::Setup(format!(
            "a result without structuredContent: {}",
            v.to_compact()
        )));
    };
    if is_error(v) {
        let Some(code) = text(sc, "code") else {
            return Err(ChannelFault::Setup(format!(
                "an error result without a code: {}",
                v.to_compact()
            )));
        };
        return match code {
            "step_up_required" => Ok(Observed::StepUpRequired),
            "strong_method_required" => Ok(Observed::StrongMethodRequired),
            other => fstp_api_testkit::harness::observed_of(other, text(sc, "rule")),
        };
    }
    let pending = sc
        .get("data")
        .and_then(Value::as_object)
        .and_then(|d| text(d, "status"))
        == Some("awaiting_confirmation");
    Ok(if pending {
        Observed::Pending
    } else {
        Observed::Completed
    })
}

/// Every string leaf of `v` with its RFC 6901 pointer, member names
/// included as leaves of their own under the pointer of their object.
pub fn string_leaves(v: &Value) -> Vec<(String, String)> {
    let mut out = Vec::new();
    walk(v, String::new(), &mut out);
    out
}

fn escape(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
}

fn walk(v: &Value, at: String, out: &mut Vec<(String, String)>) {
    match v {
        Value::String(s) => out.push((at, s.clone())),
        Value::Array(a) => {
            for (i, x) in a.iter().enumerate() {
                walk(x, format!("{at}/{i}"), out);
            }
        }
        Value::Object(o) => {
            for (k, x) in o.iter() {
                out.push((at.clone(), k.to_owned()));
                walk(x, format!("{at}/{}", escape(k)), out);
            }
        }
        _ => {}
    }
}

/// Whether `pointer` equals `under` or lies below it.
pub fn under(pointer: &str, under: &str) -> bool {
    pointer == under
        || pointer
            .strip_prefix(under)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// The `untrusted` pointers of a `structuredContent`.
pub fn untrusted(sc: &Object) -> Vec<String> {
    sc.get("untrusted")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|p| p.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// The text of the one `content` block of a `CallToolResult`.
pub fn content_text(v: &Value) -> Result<String, String> {
    let blocks = v
        .as_object()
        .and_then(|o| o.get("content"))
        .and_then(Value::as_array)
        .ok_or_else(|| format!("no content array: {}", v.to_compact()))?;
    if blocks.len() != 1 {
        return Err(format!("{} content blocks, not one", blocks.len()));
    }
    let b = blocks[0]
        .as_object()
        .ok_or_else(|| "a content block that is no object".to_owned())?;
    if text(b, "type") != Some("text") {
        return Err(format!("a content block of type {:?}", text(b, "type")));
    }
    text(b, "text")
        .map(str::to_owned)
        .ok_or_else(|| "a text block without text".to_owned())
}

/// A JSON object of `members`.
pub fn obj(members: Vec<(&str, Value)>) -> Value {
    let mut o = Object::new();
    for (k, v) in members {
        let _ = o.insert(k, v);
    }
    Value::Object(o)
}

/// A decimal id string.
pub fn dec(x: u128) -> Value {
    Value::String(x.to_string())
}

/// The registry entry of tool `name`.
pub fn op_of_tool(name: &str) -> Option<&'static fstp_access::OpSpec> {
    fstp_access::OPS
        .iter()
        .find(|o| o.tool.is_some_and(|t| t.name == name))
}

/// The arguments of tool `name` aimed at the I-85 world: each path
/// parameter of its input schema names a world target, and a tool with a
/// request object carries `body`'s members too.
pub fn args_for(name: &str, body: &Object) -> Value {
    let mut o = Object::new();
    if let Some(t) = op_of_tool(name).and_then(|op| op.tool) {
        for p in t.input.params {
            let v = match *p {
                "call" => dec(fixture::CALL_OPEN.raw()),
                "proposal" => dec(fixture::PX.raw()),
                "programme" => dec(fixture::P1.raw()),
                "slug" => Value::String(fixture::P1.raw().to_string()),
                _ => dec(1),
            };
            let _ = o.insert(*p, v);
        }
        if t.input.body {
            for (k, v) in body.iter() {
                let _ = o.insert(k, v.clone());
            }
        }
    }
    Value::Object(o)
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

/// A request to `surface` with `method`, `headers` and `body`.
pub fn http(
    surface: Surface,
    method: fstp_http::Method,
    headers: &[(&str, &str)],
    body: &[u8],
) -> fstp_http::Request {
    let target = fstp_http::RequestTarget::origin(surface.path()).unwrap();
    let mut r = fstp_http::Request::new(method, target);
    r = r.try_with_header("host", DOMAIN).unwrap();
    for (k, v) in headers {
        r = r.try_with_header(k, v.as_bytes().to_vec()).unwrap();
    }
    if !body.is_empty() {
        r = r
            .try_with_header("content-type", "application/json")
            .unwrap();
        r = r
            .try_with_header("accept", "application/json, text/event-stream")
            .unwrap();
    }
    r.body = body.to_vec();
    r
}

/// Serves `req` on `surface`.
pub fn serve(server: &McpServer, surface: Surface, req: fstp_http::Request) -> fstp_http::Response {
    block_on(server.serve(surface, req))
}

/// The one value of header `name` of `resp`, as text.
pub fn header(resp: &fstp_http::Response, name: &str) -> Option<String> {
    resp.headers
        .get(name)
        .and_then(|v| v.to_str())
        .map(str::to_owned)
}

/// The JSON body of `resp`.
pub fn body_json(resp: &fstp_http::Response) -> Option<Value> {
    fstp_json::parse(&resp.body).ok()
}

/// An `initialize` request of the floor revision with id `id`.
pub fn initialize(id: u32) -> Vec<u8> {
    format!(
        r#"{{"jsonrpc":"2.0","id":{id},"method":"initialize","params":{{"protocolVersion":"{FLOOR}","capabilities":{{}},"clientInfo":{{"name":"synthetic-client","version":"0.0.1"}}}}}}"#
    )
    .into_bytes()
}

/// The `result` member of a JSON-RPC response body.
pub fn result_of(resp: &fstp_http::Response) -> Option<Object> {
    body_json(resp)?
        .as_object()?
        .get("result")?
        .as_object()
        .cloned()
}

/// The `error.code` of a JSON-RPC response body.
pub fn error_code(resp: &fstp_http::Response) -> Option<i64> {
    let v = body_json(resp)?;
    let e = v.as_object()?.get("error")?.as_object()?;
    e.get("code")?.as_i64()
}

/// Opens a session on `surface` with `extra` headers: the session id, or
/// the response that refused it.
pub fn open_session(
    server: &McpServer,
    surface: Surface,
    extra: &[(&str, &str)],
) -> Result<String, fstp_http::Response> {
    let r = serve(
        server,
        surface,
        http(surface, fstp_http::Method::POST, extra, &initialize(1)),
    );
    match (r.status.as_u16(), header(&r, "mcp-session-id")) {
        (200, Some(id)) => {
            let mut h: Vec<(&str, &str)> = extra.to_vec();
            h.push(("mcp-session-id", id.as_str()));
            h.push(("mcp-protocol-version", FLOOR));
            let done = serve(
                server,
                surface,
                http(
                    surface,
                    fstp_http::Method::POST,
                    &h,
                    br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
                ),
            );
            if done.status.as_u16() == 202 {
                Ok(id)
            } else {
                Err(done)
            }
        }
        _ => Err(r),
    }
}
