//! The MCP server over one tenant's `ApiCore`: the Streamable HTTP rules,
//! the lifecycle, sessions and the two tool methods (design section 3.8,
//! ADR-013 "Transport" and "Tools").
//!
//! Interim readings, pending Daniel:
//!
//! - The server speaks the ADR-013 floor revision, 2025-06-18, as design
//!   section 3.8 lists its methods. `initialize` for any other revision
//!   answers the floor.
//! - Order of checks on a request: `GET` answers 405 first. Then the
//!   `Origin` rule (403 foreign, 400 duplicated or unparsable). Then, on
//!   `/mcp`, the bearer token: none gets 401 with the RFC 9728 challenge,
//!   a malformed one 400. Then the media types (415, 406), the JSON-RPC
//!   body (400) and the session.
//! - Every request but `initialize` names a session this server minted on
//!   the same surface (400 without one, 404 for an unknown or ended one)
//!   and carries `MCP-Protocol-Version` equal to the negotiated revision
//!   (400 otherwise). The tool methods wait for
//!   `notifications/initialized`.
//! - A session carries no right. Each `/mcp` request is judged by its own
//!   bearer token, so a refreshed token keeps its session. The table
//!   holds at most [`MAX_SESSIONS`] sessions and evicts the oldest.
//! - On `/mcp`, `initialize` and `tools/list` judge the token through
//!   `ApiCore::tool_rights`, and a tool call inside `ApiCore::dispatch`.
//!   Roles are evaluated again on every request. A token that resolves to
//!   no grant gets 401 `invalid_token`. `ping` and `DELETE` judge no
//!   token, since they reach no data.
//! - `tools/list` on `/mcp/public` lists the public tools. On `/mcp` it
//!   lists, in registry order, the public tools and those whose scope the
//!   token holds and whose operation one of the account's roles may
//!   perform (TH-63). Dispatch still judges every call.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

use fstp_api_core::meta::{self, ToolDef};
use fstp_api_core::{ApiCore, ApiError, Credential, ErrorCode, OpResult, RequestHead, ToolRights};
use fstp_http::{Headers, Method, Request, Response, StatusCode};
use fstp_json::{Object, ToJson, Value};

use crate::jsonrpc::{self, JsonRpcId, RpcError};
use crate::origin::{self, OriginRefusal, OriginSeen};
use crate::result::{self, McpResponse};
use crate::{McpError, McpHeaders, McpMessage, Surface};

/// The MCP revision the server speaks: the ADR-013 floor.
pub const FLOOR_REVISION: &str = "2025-06-18";

/// The most sessions the table holds.
pub(crate) const MAX_SESSIONS: usize = 4096;

/// The configuration of one tenant's MCP server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct McpConfig {
    /// The tenant's own serialised origins.
    pub tenant_origins: Vec<String>,
    /// The tenant's verified domain, such as `tenant.fstp.test`.
    pub verified_domain: String,
    /// The URL of the protected resource metadata (RFC 9728), which every
    /// 401 challenge names.
    pub resource_metadata_url: String,
}

/// One open session.
#[derive(Clone, Copy, Debug)]
struct Session {
    surface: Surface,
    initialized: bool,
    opened: u64,
}

/// The sessions, keyed by the labelled digest of their id, so the table
/// never holds an id (design section 3.8).
#[derive(Debug, Default)]
struct Sessions {
    by_digest: BTreeMap<[u8; 32], Session>,
    next: u64,
}

impl Sessions {
    fn open(&mut self, digest: [u8; 32], surface: Surface) {
        if self.by_digest.len() >= MAX_SESSIONS
            && let Some(oldest) = self
                .by_digest
                .iter()
                .min_by_key(|(_, s)| s.opened)
                .map(|(k, _)| *k)
        {
            let _ = self.by_digest.remove(&oldest);
        }
        self.next = self.next.saturating_add(1);
        let _ = self.by_digest.insert(
            digest,
            Session {
                surface,
                initialized: false,
                opened: self.next,
            },
        );
    }
}

/// One tenant's MCP server over its `ApiCore`.
pub struct McpServer {
    core: Option<Arc<ApiCore>>,
    config: McpConfig,
    name: String,
    sessions: Mutex<Sessions>,
}

impl std::fmt::Debug for McpServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpServer")
            .field("config", &self.config)
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// Whether `s` can sit inside a quoted challenge parameter: visible ASCII
/// without `"` or `\`.
fn quotable(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| (0x21..=0x7e).contains(&b) && b != b'"' && b != b'\\')
}

/// The result of one tool call below the transport.
struct Called {
    result: Result<Value, RpcError>,
    /// The token resolved to no grant.
    unauthenticated: bool,
}

/// What the transport made of a request: a final answer, or a tool call
/// to dispatch.
enum Step {
    Reply(Response),
    /// `initialize` on `/mcp`, once its token is judged.
    Initialize {
        id: JsonRpcId,
        version: String,
        cred: Credential,
    },
    /// `tools/list` on `/mcp`, filtered by the token's rights.
    List {
        id: JsonRpcId,
        cred: Credential,
    },
    Call {
        id: JsonRpcId,
        cred: Credential,
        name: String,
        arguments: String,
    },
}

impl McpServer {
    /// A server over `core` with `config`. The configuration is refused
    /// when a tenant origin is not one serialised origin, or the metadata
    /// URL cannot sit in a challenge.
    pub fn new(core: Arc<ApiCore>, config: McpConfig) -> Result<McpServer, McpError> {
        McpServer::build(Some(core), config)
    }

    /// A server with no dispatch, for the fuzz target of
    /// [`crate::handle_http_post`].
    pub(crate) fn stub(config: McpConfig) -> Result<McpServer, McpError> {
        McpServer::build(None, config)
    }

    fn build(core: Option<Arc<ApiCore>>, config: McpConfig) -> Result<McpServer, McpError> {
        let origins_ok = !config.tenant_origins.is_empty()
            && config.tenant_origins.iter().all(|o| {
                origin::check_origin(&[o.as_bytes()], std::slice::from_ref(o))
                    == Ok(OriginSeen::Tenant)
            });
        if !origins_ok {
            return Err(McpError::Invalid("a tenant origin is not one origin"));
        }
        if !quotable(&config.resource_metadata_url) {
            return Err(McpError::Invalid("the resource metadata URL is unusable"));
        }
        let name = origin::server_name(&config.verified_domain);
        Ok(McpServer {
            core,
            config,
            name,
            sessions: Mutex::new(Sessions::default()),
        })
    }

    fn sessions(&self) -> std::sync::MutexGuard<'_, Sessions> {
        self.sessions.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Serves one HTTP request to the endpoint of `surface`.
    pub async fn serve(&self, surface: Surface, req: Request) -> Response {
        match self.step(surface, &req) {
            Step::Reply(r) => r,
            Step::Initialize { id, version, cred } => match self.rights(cred).await {
                Ok(_) => self.initialize(surface, &id, &version),
                Err(e) => self.refused_token(e, &id),
            },
            Step::List { id, cred } => match self.rights(cred).await {
                Ok(rights) => rpc_reply(&id, Ok(list_result(Some(&rights)))),
                Err(e) => self.refused_token(e, &id),
            },
            Step::Call {
                id,
                cred,
                name,
                arguments,
            } => {
                let called = self.call(surface, cred, &name, arguments.as_bytes()).await;
                if called.unauthenticated && surface == Surface::Mcp {
                    return self.challenge(StatusCode::UNAUTHORIZED, Some("invalid_token"));
                }
                rpc_reply(&id, called.result)
            }
        }
    }

    /// The transport alone: every rule, with a tool call answered -32603.
    pub(crate) fn transport_only(&self, surface: Surface, req: &Request) -> Response {
        match self.step(surface, req) {
            Step::Reply(r) => r,
            Step::Initialize { id, .. } | Step::List { id, .. } | Step::Call { id, .. } => {
                rpc_reply(&id, Err(RpcError::INTERNAL))
            }
        }
    }

    /// `tools/list` on `surface` with `cred`: the `ListToolsResult` object
    /// (TH-63). Every tool is the registry's `const` data, in registry
    /// order. `/mcp/public` lists the public tools. `/mcp` lists the tools
    /// the token's rights admit, and refuses a token with no grant.
    pub async fn list_tools(&self, surface: Surface, cred: Credential) -> Result<Value, RpcError> {
        match surface {
            Surface::Public => Ok(list_result(None)),
            Surface::Mcp => match self.rights(cred).await {
                Ok(rights) => Ok(list_result(Some(&rights))),
                Err(Some(_)) => Err(RpcError::INVALID_TOKEN),
                Err(None) => Err(RpcError::INTERNAL),
            },
        }
    }

    /// The rights of `cred` (`ApiCore::tool_rights`). `Err(Some(e))` names
    /// a token with no grant, and `Err(None)` a core that could not
    /// answer, or no core.
    async fn rights(&self, cred: Credential) -> Result<ToolRights, Option<ApiError>> {
        let Some(core) = &self.core else {
            return Err(None);
        };
        match core.tool_rights(cred).await {
            Ok(r) => Ok(r),
            Err(
                e @ ApiError::Refused {
                    code: ErrorCode::Unauthenticated,
                    ..
                },
            ) => Err(Some(e)),
            Err(_) => Err(None),
        }
    }

    /// The answer to a request on `/mcp` whose token [`McpServer::rights`]
    /// refused: 401 `invalid_token`, or 503 when the core failed.
    fn refused_token(&self, e: Option<ApiError>, id: &JsonRpcId) -> Response {
        match e {
            Some(_) => self.challenge(StatusCode::UNAUTHORIZED, Some("invalid_token")),
            None => status_rpc(
                StatusCode::SERVICE_UNAVAILABLE,
                Some(id),
                RpcError::INTERNAL,
            ),
        }
    }

    /// `tools/call` of `name` with the JSON object `arguments` on
    /// `surface` with `cred`: the `CallToolResult` object. A name outside
    /// the tools of the surface is a JSON-RPC error and reaches no
    /// operation. Every other call goes through `ApiCore::dispatch` on the
    /// MCP channel (I-84), with no credential on `/mcp/public` (I-87).
    pub async fn call_tool(
        &self,
        surface: Surface,
        cred: Credential,
        name: &str,
        arguments: &[u8],
    ) -> Result<Value, RpcError> {
        self.call(surface, cred, name, arguments).await.result
    }

    async fn call(&self, surface: Surface, cred: Credential, name: &str, args: &[u8]) -> Called {
        let rpc = |e: RpcError| Called {
            result: Err(e),
            unauthenticated: false,
        };
        let Some(tool) = meta::tool(name) else {
            return rpc(RpcError::UNKNOWN_TOOL);
        };
        if surface == Surface::Public && !meta::is_public(tool) {
            return rpc(RpcError::UNKNOWN_TOOL);
        }
        let cred = match surface {
            Surface::Public => Credential::None,
            Surface::Mcp => cred,
        };
        let op = match fstp_api_core::decode::decode_tool(tool.name, args) {
            Ok(op) => op,
            Err(e) => {
                return Called {
                    result: Ok(result::refused_result(e.to_json())),
                    unauthenticated: false,
                };
            }
        };
        let Some(core) = &self.core else {
            return rpc(RpcError::INTERNAL);
        };
        let class = meta::classification(tool);
        let built = match core.dispatch(cred, &RequestHead::new(), op).await {
            Ok(OpResult::Done { body, .. }) => McpResponse::new(class, &body).call_result(),
            Ok(OpResult::Pending(r)) => {
                McpResponse::new(class, &fstp_api_core::pending::PendingAnswer(r)).call_result()
            }
            Ok(OpResult::StepUpRequired(_)) => {
                Ok(result::refused_result(code_only("step_up_required")))
            }
            Ok(OpResult::StrongMethodRequired) => {
                Ok(result::refused_result(code_only("strong_method_required")))
            }
            Err(e) => {
                let unauthenticated = matches!(
                    e,
                    ApiError::Refused {
                        code: ErrorCode::Unauthenticated,
                        ..
                    }
                );
                return Called {
                    result: Ok(result::refused_result(e.to_json())),
                    unauthenticated,
                };
            }
        };
        match built {
            Ok(v) => Called {
                result: Ok(v),
                unauthenticated: false,
            },
            Err(_) => rpc(RpcError::INTERNAL),
        }
    }

    /// The challenge of `status` naming the resource metadata, with the
    /// OAuth `error` code if any (RFC 6750 section 3, RFC 9728 section
    /// 5.1).
    fn challenge(&self, status: StatusCode, error: Option<&str>) -> Response {
        let url = &self.config.resource_metadata_url;
        let (value, body) = match error {
            Some(e) => (
                format!("Bearer error=\"{e}\", resource_metadata=\"{url}\""),
                format!("{{\"error\":\"{e}\"}}").into_bytes(),
            ),
            None => (format!("Bearer resource_metadata=\"{url}\""), Vec::new()),
        };
        let mut r = if body.is_empty() {
            Response::new(status)
        } else {
            Response::with_body(status, "application/json", body)
        };
        // `quotable` checked the URL at construction, so the value is valid.
        let _ = r.headers.try_insert("www-authenticate", value);
        r
    }

    /// Runs every transport rule on `req`.
    fn step(&self, surface: Surface, req: &Request) -> Step {
        let reply = Step::Reply;
        if req.method == Method::GET {
            return reply(not_allowed());
        }
        let h = match read_headers(&req.headers, &self.config.tenant_origins) {
            Ok(h) => h,
            Err(_) => {
                return reply(status_rpc(
                    StatusCode::BAD_REQUEST,
                    None,
                    RpcError::INVALID_REQUEST,
                ));
            }
        };
        if let Err(o) = h.origin {
            let status = match o {
                OriginRefusal::Foreign => StatusCode::FORBIDDEN,
                OriginRefusal::Duplicated | OriginRefusal::Unparsable => StatusCode::BAD_REQUEST,
            };
            return reply(status_rpc(status, None, RpcError::FORBIDDEN_ORIGIN));
        }
        let cred = match surface {
            Surface::Public => Credential::None,
            Surface::Mcp => match self.bearer(&req.headers) {
                Ok(c) => c,
                Err(r) => return reply(r),
            },
        };
        if req.method == Method::DELETE {
            return reply(self.delete(surface, &h));
        }
        if req.method != Method::POST {
            return reply(not_allowed());
        }
        if !json_content(&req.headers) {
            return reply(Response::new(StatusCode::UNSUPPORTED_MEDIA_TYPE));
        }
        if !accepts_json(&req.headers) {
            return reply(Response::new(
                StatusCode::from_u16(406).unwrap_or(StatusCode::BAD_REQUEST),
            ));
        }
        let message = match jsonrpc::decode_jsonrpc(&req.body) {
            Ok(m) => m,
            Err(e) => {
                return reply(status_rpc(
                    StatusCode::BAD_REQUEST,
                    None,
                    jsonrpc::refusal_of(e),
                ));
            }
        };
        let request_id = match &message {
            crate::JsonRpcMessage::Request { id, .. } => Some(id.clone()),
            crate::JsonRpcMessage::Notification { .. } => None,
        };
        let msg = match crate::mcp_message(message) {
            Ok(m) => m,
            Err(b) => {
                return reply(status_rpc(
                    StatusCode::OK,
                    Some(&b.id),
                    RpcError::INVALID_PARAMS,
                ));
            }
        };
        if let McpMessage::Initialize { id, version } = msg {
            if h.session.is_some() {
                return reply(status_rpc(
                    StatusCode::BAD_REQUEST,
                    Some(&id),
                    RpcError::INVALID_REQUEST,
                ));
            }
            return match surface {
                Surface::Public => reply(self.initialize(surface, &id, &version)),
                Surface::Mcp => Step::Initialize { id, version, cred },
            };
        }
        // Every other message belongs to an open session of this surface.
        let rid = request_id.as_ref();
        let Some(digest) = h.session.map(|s| meta::session_digest(&s)) else {
            return reply(status_rpc(
                StatusCode::BAD_REQUEST,
                rid,
                RpcError::NO_SESSION,
            ));
        };
        if h.version.as_deref() != Some(FLOOR_REVISION) {
            return reply(status_rpc(
                StatusCode::BAD_REQUEST,
                rid,
                RpcError::BAD_VERSION,
            ));
        }
        let initialized = {
            let mut table = self.sessions();
            match table.by_digest.get_mut(&digest) {
                Some(s) if s.surface == surface => {
                    if msg == McpMessage::Initialized {
                        s.initialized = true;
                    }
                    s.initialized
                }
                _ => {
                    return reply(status_rpc(StatusCode::NOT_FOUND, rid, RpcError::NO_SESSION));
                }
            }
        };
        match msg {
            McpMessage::Initialized | McpMessage::OtherNotification => {
                reply(Response::new(StatusCode::ACCEPTED))
            }
            McpMessage::Ping { id } => reply(rpc_reply(&id, Ok(Value::Object(Object::new())))),
            McpMessage::Unknown { id } => reply(rpc_reply(&id, Err(RpcError::METHOD_NOT_FOUND))),
            McpMessage::ToolsList { id } | McpMessage::ToolsCall { id, .. } if !initialized => {
                reply(rpc_reply(&id, Err(RpcError::NOT_INITIALIZED)))
            }
            McpMessage::ToolsList { id } => match surface {
                Surface::Public => reply(rpc_reply(&id, Ok(list_result(None)))),
                Surface::Mcp => Step::List { id, cred },
            },
            McpMessage::ToolsCall {
                id,
                name,
                arguments,
            } => Step::Call {
                id,
                cred,
                name,
                arguments,
            },
            McpMessage::Initialize { id, .. } => {
                reply(rpc_reply(&id, Err(RpcError::INVALID_REQUEST)))
            }
        }
    }

    /// The bearer credential of a `/mcp` request, or its challenge.
    fn bearer(&self, headers: &Headers) -> Result<Credential, Response> {
        let mut values = headers.get_all("authorization");
        let Some(v) = values.next() else {
            return Err(self.challenge(StatusCode::UNAUTHORIZED, None));
        };
        if values.next().is_some() {
            return Err(self.challenge(StatusCode::BAD_REQUEST, Some("invalid_request")));
        }
        match fstp_oauth::parse_bearer_header(v.as_bytes()) {
            Ok(t) => Ok(Credential::Bearer(t.as_str().as_bytes().to_vec())),
            Err(_) => Err(self.challenge(StatusCode::BAD_REQUEST, Some("invalid_request"))),
        }
    }

    /// `initialize`: a new session, the negotiated revision, the tools
    /// capability and the white-labelled `serverInfo` (TH-63, Q43).
    fn initialize(&self, surface: Surface, id: &JsonRpcId, requested: &str) -> Response {
        let Some(raw) = meta::draw_session_id() else {
            return status_rpc(
                StatusCode::SERVICE_UNAVAILABLE,
                Some(id),
                RpcError::INTERNAL,
            );
        };
        self.sessions().open(meta::session_digest(&raw), surface);
        let version = if requested == FLOOR_REVISION {
            requested
        } else {
            FLOOR_REVISION
        };
        let mut tools = Object::new();
        let _ = tools.insert("listChanged", Value::from(false));
        let mut caps = Object::new();
        let _ = caps.insert("tools", Value::Object(tools));
        let mut info = Object::new();
        let _ = info.insert("name", Value::from(self.name.as_str()));
        let _ = info.insert("version", Value::from(env!("CARGO_PKG_VERSION")));
        let mut res = Object::new();
        let _ = res.insert("protocolVersion", Value::from(version));
        let _ = res.insert("capabilities", Value::Object(caps));
        let _ = res.insert("serverInfo", Value::Object(info));
        let mut r = rpc_reply(id, Ok(Value::Object(res)));
        // Hex digits are a valid field value.
        let _ = r.headers.try_insert("mcp-session-id", hex(&raw));
        r
    }

    /// `DELETE`: ends the named session of this surface.
    fn delete(&self, surface: Surface, h: &McpHeaders) -> Response {
        let Some(raw) = h.session else {
            return status_rpc(StatusCode::BAD_REQUEST, None, RpcError::NO_SESSION);
        };
        if h.version.as_deref().is_some_and(|v| v != FLOOR_REVISION) {
            return status_rpc(StatusCode::BAD_REQUEST, None, RpcError::BAD_VERSION);
        }
        let digest = meta::session_digest(&raw);
        let mut table = self.sessions();
        match table.by_digest.get(&digest) {
            Some(s) if s.surface == surface => {
                let _ = table.by_digest.remove(&digest);
                Response::new(StatusCode::NO_CONTENT)
            }
            _ => status_rpc(StatusCode::NOT_FOUND, None, RpcError::NO_SESSION),
        }
    }
}

/// `{"code": c}`, the body of a refusal that names no rule.
fn code_only(c: &str) -> Value {
    let mut o = Object::new();
    let _ = o.insert("code", Value::from(c));
    Value::Object(o)
}

/// The JSON form of one tool (TH-63): its name, its fixed description and
/// an object schema with one required string property per path
/// parameter. A tool with no request object takes no other member.
fn tool_json(t: &ToolDef) -> Value {
    let mut props = Object::new();
    for p in t.input.params {
        let mut s = Object::new();
        let _ = s.insert("type", Value::from("string"));
        let _ = props.insert(*p, Value::Object(s));
    }
    let required: Vec<Value> = t.input.params.iter().map(|p| Value::from(*p)).collect();
    let mut schema = Object::new();
    let _ = schema.insert("type", Value::from("object"));
    let _ = schema.insert("properties", Value::Object(props));
    let _ = schema.insert("required", Value::from(required));
    if !t.input.body {
        let _ = schema.insert("additionalProperties", Value::from(false));
    }
    let mut o = Object::new();
    let _ = o.insert("name", Value::from(t.name));
    let _ = o.insert("description", Value::from(t.description));
    let _ = o.insert("inputSchema", Value::Object(schema));
    Value::Object(o)
}

/// The `ListToolsResult` of the tools `rights` admit, or of the public
/// tools with no rights (module documentation).
fn list_result(rights: Option<&ToolRights>) -> Value {
    let tools: Vec<Value> = meta::tools()
        .filter(|t| match rights {
            Some(r) => r.admits(t),
            None => meta::is_public(t),
        })
        .map(tool_json)
        .collect();
    let mut o = Object::new();
    let _ = o.insert("tools", Value::from(tools));
    Value::Object(o)
}

/// 405 with `Allow: POST, DELETE`.
fn not_allowed() -> Response {
    let mut r = Response::new(StatusCode::METHOD_NOT_ALLOWED);
    let _ = r.headers.try_insert("allow", "POST, DELETE");
    r
}

/// A 200 JSON-RPC response to `id`.
fn rpc_reply(id: &JsonRpcId, r: Result<Value, RpcError>) -> Response {
    let body = match r {
        Ok(v) => jsonrpc::response(id, v),
        Err(e) => jsonrpc::error_response(Some(id), e),
    };
    Response::with_body(
        StatusCode::OK,
        "application/json",
        body.to_compact().into_bytes(),
    )
}

/// A JSON-RPC error response with `status`.
fn status_rpc(status: StatusCode, id: Option<&JsonRpcId>, e: RpcError) -> Response {
    Response::with_body(
        status,
        "application/json",
        jsonrpc::error_response(id, e).to_compact().into_bytes(),
    )
}

/// The media type of a field value: the part before `;`, trimmed and
/// lowercase.
fn media_type(v: &[u8]) -> String {
    let end = v.iter().position(|b| *b == b';').unwrap_or(v.len());
    String::from_utf8_lossy(v.get(..end).unwrap_or_default())
        .trim()
        .to_ascii_lowercase()
}

/// Whether the request has exactly one `Content-Type` of
/// `application/json`.
fn json_content(h: &Headers) -> bool {
    let mut all = h.get_all("content-type");
    match (all.next(), all.next()) {
        (Some(v), None) => media_type(v.as_bytes()) == "application/json",
        _ => false,
    }
}

/// Whether the client accepts `application/json`: no `Accept` field, or
/// one media range that admits it.
fn accepts_json(h: &Headers) -> bool {
    let mut seen = false;
    for v in h.get_all("accept") {
        seen = true;
        if v.as_bytes().split(|b| *b == b',').any(|r| {
            matches!(
                media_type(r).as_str(),
                "application/json" | "application/*" | "*/*"
            )
        }) {
            return true;
        }
    }
    !seen
}

/// Lowercase hexadecimal.
fn hex(b: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len().saturating_mul(2));
    for x in b {
        for n in [x >> 4, x & 0x0f] {
            if let Some(d) = DIGITS.get(usize::from(n)) {
                s.push(char::from(*d));
            }
        }
    }
    s
}

/// The 16 bytes of 32 hexadecimal digits, lowercase or uppercase.
fn unhex16(v: &[u8]) -> Option<[u8; 16]> {
    if v.len() != 32 {
        return None;
    }
    let digit = |c: u8| {
        char::from(c)
            .to_digit(16)
            .and_then(|d| u8::try_from(d).ok())
    };
    let mut out = [0u8; 16];
    for (slot, pair) in out.iter_mut().zip(v.chunks_exact(2)) {
        let (hi, lo) = match pair {
            [a, b] => (digit(*a)?, digit(*b)?),
            _ => return None,
        };
        *slot = (hi << 4) | lo;
    }
    Some(out)
}

/// Reads the transport fields of `h` against `tenant_origins`. A
/// duplicated or malformed `Mcp-Session-Id` or `MCP-Protocol-Version` is
/// refused.
pub(crate) fn read_headers(h: &Headers, tenant_origins: &[String]) -> Result<McpHeaders, McpError> {
    let origins: Vec<&[u8]> = h.get_all("origin").map(|v| v.as_bytes()).collect();
    let origin = origin::check_origin(&origins, tenant_origins);
    let one = |name: &'static str| -> Result<Option<&[u8]>, McpError> {
        let mut all = h.get_all(name);
        match (all.next(), all.next()) {
            (None, _) => Ok(None),
            (Some(v), None) => Ok(Some(v.as_bytes())),
            (Some(_), Some(_)) => Err(McpError::Invalid("a transport field is duplicated")),
        }
    };
    let session = match one("mcp-session-id")? {
        None => None,
        Some(v) => Some(unhex16(v).ok_or(McpError::Invalid("the session id is malformed"))?),
    };
    let version = match one("mcp-protocol-version")? {
        None => None,
        Some(v) => Some(
            std::str::from_utf8(v)
                .ok()
                .filter(|s| s.len() <= 32 && s.bytes().all(|b| b.is_ascii_graphic()))
                .ok_or(McpError::Invalid("the protocol version is malformed"))?
                .to_owned(),
        ),
    };
    Ok(McpHeaders {
        origin,
        session,
        version,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    /// Design section 3.8: a session id round-trips through its 32
    /// hexadecimal digits, and other lengths or digits are refused.
    #[test]
    fn adr013_session_id_hex_round_trips() {
        let b: [u8; 16] = *b"\x00\x01\x7f\x80\xff0123456789a";
        assert_eq!(unhex16(hex(&b).as_bytes()), Some(b));
        assert_eq!(unhex16(b"00"), None);
        assert_eq!(unhex16(b"0000000000000000000000000000000g"), None);
    }

    /// H-23: the media type rules.
    #[test]
    fn adr013_media_types() {
        let mut h = Headers::new();
        assert!(accepts_json(&h) && !json_content(&h));
        h.try_append("content-type", "Application/JSON; charset=utf-8")
            .unwrap();
        h.try_append("accept", "text/event-stream, application/json")
            .unwrap();
        assert!(accepts_json(&h) && json_content(&h));
        let mut g = Headers::new();
        g.try_append("accept", "text/html").unwrap();
        assert!(!accepts_json(&g));
    }
}
