//! The sans-IO MCP server core (I-84, I-86, M4 design section 3.8).
//!
//! The crate holds JSON-RPC 2.0, the MCP lifecycle, the Streamable HTTP
//! rules, the Origin check, serving the tool table from
//! `fstp_api_core::meta::tools()` and response classification. It defines
//! no tool of its own (TH-63). MCP output is built only from read models
//! that implement `fstp_api_core::McpSafe` (I-86).
//!
//! It may depend directly on `fstp-api-core`, `fstp-oauth`, `fstp-http` and
//! `fstp-json` only (layering rule A1), and never names a port, the
//! principal or the execution metadata (rule A2b). Its profile is recorded
//! in ADR-013.
//!
//! # Surface (lane W3c test author, interim, pending Daniel)
//!
//! The test author of lane W3c wrote this surface ahead of the code, so
//! the tests of `fstp-api-testkit` compile and fail for the right reason.
//! Every operation still refuses with [`McpError::NotImplemented`], or
//! answers 501. The implementer fills the bodies and may add members, but
//! keeps each name and signature the tests use.
//!
//! - [`McpServer::serve`] takes one HTTP request to `/mcp` or
//!   `/mcp/public` ([`Surface`]) and returns its response. The adapters
//!   (`fstp-web`, the e2e cell) mount it.
//! - [`McpServer::list_tools`] and [`McpServer::call_tool`] are the
//!   `tools/list` and `tools/call` methods below the transport, with the
//!   credential the transport resolved. Every tool call goes through
//!   `ApiCore::dispatch` on the MCP channel (I-84).
//! - [`decode_jsonrpc`] decodes one JSON-RPC 2.0 message and refuses a
//!   batch. [`check_origin`] is the DNS rebinding rule. [`server_name`]
//!   is the white-labelled `serverInfo.name`. [`McpResponse`] builds every
//!   tool result (TH-60).
//!
//! Open point for Daniel and the lead: ADR-013 pins MCP revision
//! 2026-07-28, which removes the `initialize` handshake, `ping` and
//! protocol sessions that design section 3.8 lists. The lane scope builds
//! the design's methods. See the lane report.

use std::sync::Arc;

use fstp_api_core::{ApiCore, Credential, McpSafe};
use fstp_json::{Object, Value};

pub use fstp_api_core::meta::Classification;

/// Why an operation of this crate failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum McpError {
    /// The stub of the named operation refuses.
    NotImplemented(&'static str),
    /// The body is a JSON-RPC batch. Batches are refused (design section
    /// 3.8).
    Batch,
    /// The bytes are not one JSON value within the limits.
    NotJson,
    /// The JSON value is not a JSON-RPC 2.0 request or notification. The
    /// text names the broken rule and never holds input.
    Invalid(&'static str),
    /// The input is longer than its limit.
    TooLong,
}

impl std::fmt::Display for McpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            McpError::NotImplemented(op) => write!(f, "{op} is not implemented yet"),
            McpError::Batch => f.write_str("a JSON-RPC batch is refused"),
            McpError::NotJson => f.write_str("the body is not one JSON value"),
            McpError::Invalid(why) => write!(f, "not a JSON-RPC 2.0 message: {why}"),
            McpError::TooLong => f.write_str("the input is too long"),
        }
    }
}

impl std::error::Error for McpError {}

// ---------------------------------------------------------------------------
// JSON-RPC 2.0
// ---------------------------------------------------------------------------

/// The id of a JSON-RPC request: an integer or a string. A null id and a
/// fractional number are refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JsonRpcId {
    /// An integer id.
    Number(i64),
    /// A string id.
    String(String),
}

/// One decoded JSON-RPC 2.0 message from a client.
#[derive(Clone, Debug, PartialEq)]
pub enum JsonRpcMessage {
    /// A request, which gets one response.
    Request {
        /// The id the response echoes.
        id: JsonRpcId,
        /// The method name.
        method: String,
        /// The params object, if any.
        params: Option<Object>,
    },
    /// A notification, which gets no response.
    Notification {
        /// The method name.
        method: String,
        /// The params object, if any.
        params: Option<Object>,
    },
}

/// Decodes one JSON-RPC 2.0 message. Batches are refused. Fuzzed (`jsonrpc_decode`).
pub fn decode_jsonrpc(bytes: &[u8]) -> Result<JsonRpcMessage, McpError> {
    let _ = bytes;
    Err(McpError::NotImplemented("fstp_mcp::decode_jsonrpc"))
}

/// A JSON-RPC error of a method: its code and a fixed message that never
/// holds input or user text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RpcError {
    /// The JSON-RPC error code, such as -32601 for an unknown method.
    pub code: i64,
    /// The fixed message.
    pub message: &'static str,
}

// ---------------------------------------------------------------------------
// Origin, white-labelling
// ---------------------------------------------------------------------------

/// What an accepted `Origin` check saw.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OriginSeen {
    /// No `Origin` field: a native client.
    Absent,
    /// One `Origin` field equal to a tenant origin.
    Tenant,
}

/// Why the `Origin` check refused a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OriginRefusal {
    /// The one `Origin` is not a tenant origin (403).
    Foreign,
    /// More than one `Origin` field.
    Duplicated,
    /// The value is not one serialised origin.
    Unparsable,
}

/// The DNS rebinding rule (design section 3.8). `values` are the raw
/// values of every `Origin` field of the request, and `tenant_origins` the
/// tenant's own serialised origins, such as `https://tenant.fstp.test`.
/// Fuzzed (`mcp_headers_decode`).
pub fn check_origin(
    values: &[&[u8]],
    tenant_origins: &[String],
) -> Result<OriginSeen, OriginRefusal> {
    let _ = (values, tenant_origins);
    Err(OriginRefusal::Unparsable)
}

/// The white-labelled `serverInfo.name`: the first label of the tenant's
/// verified domain when it matches `^[a-z0-9][a-z0-9-]{0,30}$` (TH-63,
/// Q43). It never carries free text.
pub fn server_name(verified_domain: &str) -> String {
    let _ = verified_domain;
    String::new()
}

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

/// An RFC 6901 JSON pointer into `structuredContent.data`, such as
/// `/items/0/title`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct JsonPointer(String);

impl JsonPointer {
    /// The pointer text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One tool result (TH-60): the read model in `structuredContent.data`,
/// its classification, and the pointers to user-supplied text.
#[derive(Clone, Debug, PartialEq)]
pub struct McpResponse {
    classification: Classification,
    data: Value,
    untrusted: Vec<JsonPointer>,
}

impl McpResponse {
    /// The result of `v`, classified as `c`. Only an [`McpSafe`] read model
    /// can become one (I-86).
    pub fn new<T: McpSafe>(c: Classification, v: &T) -> McpResponse {
        let _ = v;
        McpResponse {
            classification: c,
            data: Value::Null,
            untrusted: Vec::new(),
        }
    }

    /// The `CallToolResult` object: `content` with the one fixed sentence
    /// naming the classification, and `structuredContent` with exactly
    /// `classification`, `data` and `untrusted`.
    pub fn call_result(&self) -> Result<Value, McpError> {
        let _ = (&self.classification, &self.data, &self.untrusted);
        Err(McpError::NotImplemented(
            "fstp_mcp::McpResponse::call_result",
        ))
    }
}

// ---------------------------------------------------------------------------
// The server
// ---------------------------------------------------------------------------

/// The two MCP endpoints of a tenant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Surface {
    /// `/mcp`, with a bearer token.
    Mcp,
    /// `/mcp/public`, with no credential: the public tools only (I-87).
    Public,
}

impl Surface {
    /// The path of the endpoint.
    pub const fn path(self) -> &'static str {
        match self {
            Surface::Mcp => "/mcp",
            Surface::Public => "/mcp/public",
        }
    }
}

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

/// One tenant's MCP server over its `ApiCore`.
pub struct McpServer {
    core: Arc<ApiCore>,
    config: McpConfig,
}

impl std::fmt::Debug for McpServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpServer")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// The JSON-RPC code of the stub's refusals: implementation-defined.
const STUB_CODE: i64 = -32000;

impl McpServer {
    /// A server over `core` with `config`.
    pub fn new(core: Arc<ApiCore>, config: McpConfig) -> Result<McpServer, McpError> {
        let _ = (core, config);
        Err(McpError::NotImplemented("fstp_mcp::McpServer::new"))
    }

    /// Serves one HTTP request to the endpoint of `surface`.
    pub async fn serve(&self, surface: Surface, req: fstp_http::Request) -> fstp_http::Response {
        let _ = (&self.core, surface, req);
        fstp_http::Response::with_body(
            fstp_http::StatusCode::NOT_IMPLEMENTED,
            "application/json",
            br#"{"code":"not_implemented"}"#.to_vec(),
        )
    }

    /// `tools/list` on `surface` with `cred`: the `ListToolsResult` object.
    pub async fn list_tools(&self, surface: Surface, cred: Credential) -> Result<Value, RpcError> {
        let _ = (surface, cred);
        Err(RpcError {
            code: STUB_CODE,
            message: "fstp_mcp::McpServer::list_tools is not implemented yet",
        })
    }

    /// `tools/call` of `name` with the JSON object `arguments` on
    /// `surface` with `cred`: the `CallToolResult` object.
    pub async fn call_tool(
        &self,
        surface: Surface,
        cred: Credential,
        name: &str,
        arguments: &[u8],
    ) -> Result<Value, RpcError> {
        let _ = (surface, cred, name, arguments);
        Err(RpcError {
            code: STUB_CODE,
            message: "fstp_mcp::McpServer::call_tool is not implemented yet",
        })
    }
}

// ---------------------------------------------------------------------------
// W0 decoder stubs kept for their fuzz targets
// ---------------------------------------------------------------------------

/// One decoded MCP method call.
///
/// W0 placeholder with no fields. The owning lane writes the designed type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct McpMessage {
    _w0: (),
}

/// Decodes the params of one MCP method. Fuzzed (`mcp_message_decode`).
pub fn decode_message(bytes: &[u8]) -> Result<McpMessage, McpError> {
    let _ = bytes;
    Err(McpError::NotImplemented("fstp_mcp::decode_message"))
}

/// Decoded tool arguments.
///
/// W0 placeholder with no fields. The owning lane writes the designed type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolArgs {
    _w0: (),
}

/// Decodes the arguments of one tool against its input schema. Fuzzed (`tool_args_decode`).
pub fn decode_tool_args(bytes: &[u8]) -> Result<ToolArgs, McpError> {
    let _ = bytes;
    Err(McpError::NotImplemented("fstp_mcp::decode_tool_args"))
}

/// Decoded MCP transport headers.
///
/// W0 placeholder with no fields. The owning lane writes the designed type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct McpHeaders {
    _w0: (),
}

/// Decodes the transport headers of one request. Fuzzed (`mcp_headers_decode`).
pub fn decode_headers(bytes: &[u8]) -> Result<McpHeaders, McpError> {
    let _ = bytes;
    Err(McpError::NotImplemented("fstp_mcp::decode_headers"))
}

/// The reply to one MCP POST.
///
/// W0 placeholder with no fields. The owning lane writes the designed type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct McpReply {
    _w0: (),
}

/// Handles one raw HTTP POST to `/mcp` over a stub dispatch. Fuzzed (`mcp_http_post`).
pub fn handle_http_post(bytes: &[u8]) -> Result<McpReply, McpError> {
    let _ = bytes;
    Err(McpError::NotImplemented("fstp_mcp::handle_http_post"))
}
