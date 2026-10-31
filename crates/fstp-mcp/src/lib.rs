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
//! in ADR-013, a draft pending Q8 and Q25.
//!
//! Status: W0 stub. Lane W3c (L-MCP) owns this crate, and waits for
//! ADR-013. Every operation refuses with [`McpError::NotImplemented`].

/// Why an operation of this crate failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum McpError {
    /// The W0 stub of the named operation refuses.
    NotImplemented(&'static str),
}

impl std::fmt::Display for McpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            McpError::NotImplemented(op) => write!(f, "{op} is not implemented yet"),
        }
    }
}

impl std::error::Error for McpError {}

/// One decoded JSON-RPC 2.0 message.
///
/// W0 placeholder with no fields. The owning lane writes the designed type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JsonRpcMessage {
    _w0: (),
}

/// Decodes one JSON-RPC 2.0 message. Batches are refused. Fuzzed (`jsonrpc_decode`).
pub fn decode_jsonrpc(bytes: &[u8]) -> Result<JsonRpcMessage, McpError> {
    let _ = bytes;
    Err(McpError::NotImplemented("fstp_mcp::decode_jsonrpc"))
}

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
