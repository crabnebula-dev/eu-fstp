//! The sans-IO MCP server core (I-84 to I-87, M4 design section 3.8).
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
//! - [`McpServer::serve`] takes one HTTP request to `/mcp` or
//!   `/mcp/public` ([`Surface`]) and returns its response. `fstp-web`
//!   mounts it, and the e2e cell through `fstp-web`.
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
//! the design's methods at the ADR-013 floor, revision 2025-06-18.

mod jsonrpc;
mod origin;
mod result;
mod server;

use std::sync::OnceLock;

pub use fstp_api_core::meta::Classification;
pub use jsonrpc::{JsonRpcId, JsonRpcMessage, MAX_MESSAGE_BYTES, RpcError, decode_jsonrpc};
pub use origin::{OriginRefusal, OriginSeen, check_origin, server_name};
pub use result::{JsonPointer, McpResponse};
pub use server::{FLOOR_REVISION, McpConfig, McpServer};

/// Why an operation of this crate failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum McpError {
    /// The named operation is not built.
    NotImplemented(&'static str),
    /// The body is a JSON-RPC batch. Batches are refused (design section
    /// 3.8).
    Batch,
    /// The bytes are not one JSON value within the limits.
    NotJson,
    /// The JSON value is not a JSON-RPC 2.0 request or notification, or
    /// the input breaks another rule. The text names the broken rule and
    /// never holds input.
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
            McpError::Invalid(why) => write!(f, "refused: {why}"),
            McpError::TooLong => f.write_str("the input is too long"),
        }
    }
}

impl std::error::Error for McpError {}

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

    /// The surface whose path is exactly `path`.
    pub fn of_path(path: &str) -> Option<Surface> {
        match path {
            "/mcp" => Some(Surface::Mcp),
            "/mcp/public" => Some(Surface::Public),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Decoders with fuzz targets
// ---------------------------------------------------------------------------

/// One MCP method call, decoded from its JSON-RPC message (design section
/// 3.8). Only the methods of M4 are named. Any other request is
/// [`McpMessage::Unknown`] and gets -32601, and any other notification
/// is [`McpMessage::OtherNotification`] and is accepted with no effect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum McpMessage {
    /// `initialize`, with the revision the client asked for.
    Initialize {
        /// The request id.
        id: JsonRpcId,
        /// `params.protocolVersion`.
        version: String,
    },
    /// `notifications/initialized`.
    Initialized,
    /// `ping`.
    Ping {
        /// The request id.
        id: JsonRpcId,
    },
    /// `tools/list`.
    ToolsList {
        /// The request id.
        id: JsonRpcId,
    },
    /// `tools/call`.
    ToolsCall {
        /// The request id.
        id: JsonRpcId,
        /// `params.name`.
        name: String,
        /// `params.arguments` as compact JSON, `{}` when absent.
        arguments: String,
    },
    /// Another request: the method is not offered.
    Unknown {
        /// The request id.
        id: JsonRpcId,
    },
    /// Another notification.
    OtherNotification,
}

/// The params of a request that do not decode, with the request id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BadParams {
    /// The request id.
    pub id: JsonRpcId,
}

/// Reads one decoded JSON-RPC message as an MCP method call.
pub(crate) fn mcp_message(m: JsonRpcMessage) -> Result<McpMessage, BadParams> {
    let (id, method, params) = match m {
        JsonRpcMessage::Notification { method, .. } => {
            return Ok(if method == "notifications/initialized" {
                McpMessage::Initialized
            } else {
                McpMessage::OtherNotification
            });
        }
        JsonRpcMessage::Request { id, method, params } => (id, method, params),
    };
    let bad = |id: &JsonRpcId| BadParams { id: id.clone() };
    match method.as_str() {
        "initialize" => {
            let version = params
                .as_ref()
                .and_then(|p| p.get("protocolVersion"))
                .and_then(fstp_json::Value::as_str)
                .ok_or_else(|| bad(&id))?
                .to_owned();
            Ok(McpMessage::Initialize { id, version })
        }
        "ping" => Ok(McpMessage::Ping { id }),
        "tools/list" => Ok(McpMessage::ToolsList { id }),
        "tools/call" => {
            let p = params.ok_or_else(|| bad(&id))?;
            let mut name = None;
            let mut arguments = String::from("{}");
            for (k, v) in p.iter() {
                match (k, v) {
                    ("name", fstp_json::Value::String(s)) => name = Some(s.clone()),
                    ("arguments", fstp_json::Value::Object(_)) => arguments = v.to_compact(),
                    ("_meta", fstp_json::Value::Object(_)) => {}
                    _ => return Err(bad(&id)),
                }
            }
            let name = name.ok_or_else(|| bad(&id))?;
            Ok(McpMessage::ToolsCall {
                id,
                name,
                arguments,
            })
        }
        _ => Ok(McpMessage::Unknown { id }),
    }
}

/// Decodes one JSON-RPC message and the params of its MCP method. Fuzzed
/// (`mcp_message_decode`).
pub fn decode_message(bytes: &[u8]) -> Result<McpMessage, McpError> {
    let m = decode_jsonrpc(bytes)?;
    mcp_message(m).map_err(|_| McpError::Invalid("the params of the method do not decode"))
}

/// A tool call decoded against its tool's input schema.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolArgs {
    op: &'static str,
}

impl ToolArgs {
    /// The registry operation the call performs.
    pub fn op_name(&self) -> &'static str {
        self.op
    }
}

/// Decodes `name`, a zero byte, then the arguments of one tool call,
/// through the strict decoder of `fstp-api-core` (design section 3.8).
/// A name outside the registry is refused. Fuzzed (`tool_args_decode`).
pub fn decode_tool_args(bytes: &[u8]) -> Result<ToolArgs, McpError> {
    let at = bytes
        .iter()
        .position(|b| *b == 0)
        .ok_or(McpError::Invalid("no zero byte ends the tool name"))?;
    let name = bytes
        .get(..at)
        .and_then(|n| std::str::from_utf8(n).ok())
        .ok_or(McpError::Invalid("the tool name is not UTF-8"))?;
    let args = bytes.get(at.saturating_add(1)..).unwrap_or_default();
    let tool = fstp_api_core::meta::tool(name).ok_or(McpError::Invalid("no such tool"))?;
    fstp_api_core::decode::decode_tool(tool.name, args)
        .map(|op| ToolArgs { op: op.name() })
        .map_err(|_| McpError::Invalid("the arguments do not decode"))
}

/// The transport fields of one request (design section 3.8).
#[derive(Clone, PartialEq, Eq)]
pub struct McpHeaders {
    origin: Result<OriginSeen, OriginRefusal>,
    session: Option<[u8; 16]>,
    version: Option<String>,
}

impl std::fmt::Debug for McpHeaders {
    /// Never shows the session id, which names a live session.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpHeaders")
            .field("origin", &self.origin)
            .field("session", &self.session.is_some())
            .field("version", &self.version)
            .finish()
    }
}

impl McpHeaders {
    /// What the `Origin` rule makes of the fields.
    pub fn origin(&self) -> Result<OriginSeen, OriginRefusal> {
        self.origin
    }

    /// The `MCP-Protocol-Version` value.
    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }

    /// Whether one well-formed `Mcp-Session-Id` is present.
    pub fn has_session(&self) -> bool {
        self.session.is_some()
    }
}

/// The tenant origin the stand-alone decoders judge against.
const STUB_ORIGIN: &str = "https://tenant.fstp.test";

/// Decodes a header block of `name: value` lines, split at line feeds,
/// into the transport fields: the `Origin` rule against the tenant
/// origin `https://tenant.fstp.test`, `Mcp-Session-Id` and
/// `MCP-Protocol-Version`. A refused field gives an error. Fuzzed
/// (`mcp_headers_decode`).
pub fn decode_headers(bytes: &[u8]) -> Result<McpHeaders, McpError> {
    let mut h = fstp_http::Headers::new();
    for line in bytes.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
        let at = line
            .iter()
            .position(|b| *b == b':')
            .ok_or(McpError::Invalid("a header line has no colon"))?;
        let name = line
            .get(..at)
            .and_then(|n| std::str::from_utf8(n).ok())
            .ok_or(McpError::Invalid("a header name is not UTF-8"))?;
        let value = line.get(at.saturating_add(1)..).unwrap_or_default();
        let value = value.strip_prefix(b" ").unwrap_or(value);
        h.try_append(name, value.to_vec())
            .map_err(|_| McpError::Invalid("a header field is malformed"))?;
    }
    server::read_headers(&h, &[STUB_ORIGIN.to_owned()])
}

/// The reply to one MCP request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct McpReply {
    response: fstp_http::Response,
}

impl McpReply {
    /// The response.
    pub fn response(&self) -> &fstp_http::Response {
        &self.response
    }
}

/// The server of [`handle_http_post`], built once.
fn stub_server() -> Result<&'static McpServer, McpError> {
    static STUB: OnceLock<Result<McpServer, McpError>> = OnceLock::new();
    STUB.get_or_init(|| {
        McpServer::stub(McpConfig {
            tenant_origins: vec![STUB_ORIGIN.to_owned()],
            verified_domain: "tenant.fstp.test".to_owned(),
            resource_metadata_url: format!("{STUB_ORIGIN}{}", fstp_oauth::RESOURCE_METADATA_PATH),
        })
    })
    .as_ref()
    .map_err(|e| *e)
}

/// Handles one raw HTTP request to `/mcp` or `/mcp/public` through the
/// transport of a server with no dispatch: every rule but the tool call
/// itself, which answers -32603. Fuzzed (`mcp_http_post`).
pub fn handle_http_post(bytes: &[u8]) -> Result<McpReply, McpError> {
    let limits = fstp_http::Limits::default();
    let req = match fstp_http::parse_request(bytes, &limits) {
        Ok(fstp_http::Parsed::Complete { message, consumed }) if consumed == bytes.len() => message,
        Ok(fstp_http::Parsed::Complete { .. }) => {
            return Err(McpError::Invalid("bytes follow the request"));
        }
        Ok(fstp_http::Parsed::Incomplete) => {
            return Err(McpError::Invalid("the input ends inside the request"));
        }
        Err(_) => return Err(McpError::Invalid("the request does not parse")),
    };
    let surface =
        Surface::of_path(req.target.path()).ok_or(McpError::Invalid("not an MCP path"))?;
    let response = stub_server()?.transport_only(surface, &req);
    Ok(McpReply { response })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    /// R-NF-02, TH-26: the crash inputs of fuzz targets `jsonrpc_decode`
    /// and `mcp_message_decode` in CI run 42359742731. Each is refused as
    /// `NotJson` and never panics. Its text is the fixed `NotJson` text,
    /// which holds the input only by coincidence.
    #[test]
    fn r_nf_02_th26_fuzz_crash_inputs_are_refused_as_not_json() {
        for input in [&b"s not one JSON value"[..], &b"ot one JSON value"[..]] {
            assert_eq!(decode_jsonrpc(input), Err(McpError::NotJson));
            let e = decode_message(input).unwrap_err();
            assert_eq!(e, McpError::NotJson);
            assert_eq!(e.to_string(), "the body is not one JSON value");
        }
    }
}
