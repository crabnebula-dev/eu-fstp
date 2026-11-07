//! JSON-RPC 2.0, one message per body (design section 3.8, TH-26).
//!
//! Interim readings, pending Daniel (written by the lane W3c test author
//! and kept here):
//!
//! - A batch, a JSON array at the top, is refused whatever it holds.
//! - A request has `"jsonrpc":"2.0"`, an integer or string `id`, a string
//!   `method` and an optional object `params`. A notification has no `id`.
//! - A `result` or `error` member is refused, since the server sends no
//!   request and so expects no response. Any other member is refused too.
//! - A refusal names the broken rule in fixed text and never holds input
//!   (R-NF-02).

use fstp_json::{Number, Object, Value};

use crate::McpError;

/// The largest message, in bytes: the body limit of `fstp-web`.
pub const MAX_MESSAGE_BYTES: usize = 1024 * 1024;

/// The id of a JSON-RPC request: an integer or a string. A null id and a
/// fractional number are refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JsonRpcId {
    /// An integer id.
    Number(i64),
    /// A string id.
    String(String),
}

impl JsonRpcId {
    /// The id as JSON.
    pub fn to_value(&self) -> Value {
        match self {
            JsonRpcId::Number(n) => Value::Number(Number::from(*n)),
            JsonRpcId::String(s) => Value::String(s.clone()),
        }
    }
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

impl JsonRpcMessage {
    /// The method name.
    pub fn method(&self) -> &str {
        match self {
            JsonRpcMessage::Request { method, .. }
            | JsonRpcMessage::Notification { method, .. } => method,
        }
    }

    /// The params object, if any.
    pub fn params(&self) -> Option<&Object> {
        match self {
            JsonRpcMessage::Request { params, .. }
            | JsonRpcMessage::Notification { params, .. } => params.as_ref(),
        }
    }
}

/// The id of `v`, an integer or a string.
fn decode_id(v: &Value) -> Result<JsonRpcId, McpError> {
    match v {
        Value::Number(n) if n.is_integer() => n
            .as_i64()
            .map(JsonRpcId::Number)
            .ok_or(McpError::Invalid("the id is out of range")),
        Value::String(s) => Ok(JsonRpcId::String(s.clone())),
        _ => Err(McpError::Invalid("the id is not an integer or a string")),
    }
}

/// Decodes one JSON-RPC 2.0 message. Batches are refused. Fuzzed
/// (`jsonrpc_decode`).
pub fn decode_jsonrpc(bytes: &[u8]) -> Result<JsonRpcMessage, McpError> {
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(McpError::TooLong);
    }
    let v = fstp_json::parse(bytes).map_err(|_| McpError::NotJson)?;
    let o = match v {
        Value::Object(o) => o,
        Value::Array(_) => return Err(McpError::Batch),
        _ => return Err(McpError::Invalid("the message is not a JSON object")),
    };
    let mut version = false;
    let mut id = None;
    let mut method = None;
    let mut params = None;
    for (k, val) in o.iter() {
        match k {
            "jsonrpc" => {
                if val.as_str() != Some("2.0") {
                    return Err(McpError::Invalid("the jsonrpc member is not 2.0"));
                }
                version = true;
            }
            "id" => id = Some(decode_id(val)?),
            "method" => {
                let m = val
                    .as_str()
                    .ok_or(McpError::Invalid("the method is not a string"))?;
                method = Some(m.to_owned());
            }
            "params" => match val {
                Value::Object(p) => params = Some(p.clone()),
                _ => return Err(McpError::Invalid("the params member is not an object")),
            },
            "result" | "error" => {
                return Err(McpError::Invalid("the server expects no response"));
            }
            _ => return Err(McpError::Invalid("the message has an unknown member")),
        }
    }
    if !version {
        return Err(McpError::Invalid("the jsonrpc member is missing"));
    }
    let method = method.ok_or(McpError::Invalid("the method is missing"))?;
    Ok(match id {
        Some(id) => JsonRpcMessage::Request { id, method, params },
        None => JsonRpcMessage::Notification { method, params },
    })
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

impl RpcError {
    /// -32700: the body is not JSON.
    pub const PARSE: RpcError = RpcError {
        code: -32700,
        message: "the body is not one JSON value",
    };
    /// -32600: not one JSON-RPC 2.0 message.
    pub const INVALID_REQUEST: RpcError = RpcError {
        code: -32600,
        message: "the body is not one JSON-RPC 2.0 message",
    };
    /// -32600: a batch.
    pub const BATCH: RpcError = RpcError {
        code: -32600,
        message: "a JSON-RPC batch is refused",
    };
    /// -32601: a method the server does not offer.
    pub const METHOD_NOT_FOUND: RpcError = RpcError {
        code: -32601,
        message: "the method is not offered",
    };
    /// -32602: params that do not decode.
    pub const INVALID_PARAMS: RpcError = RpcError {
        code: -32602,
        message: "the params do not decode",
    };
    /// -32602: a tool outside the table of this endpoint.
    pub const UNKNOWN_TOOL: RpcError = RpcError {
        code: -32602,
        message: "no such tool on this endpoint",
    };
    /// -32600: no session of this endpoint is named, or it ended.
    pub const NO_SESSION: RpcError = RpcError {
        code: -32600,
        message: "the request names no open session of this endpoint",
    };
    /// -32600: `MCP-Protocol-Version` is missing or not the negotiated
    /// revision.
    pub const BAD_VERSION: RpcError = RpcError {
        code: -32600,
        message: "the MCP-Protocol-Version is missing or not supported",
    };
    /// -32600: a tool method before `notifications/initialized`.
    pub const NOT_INITIALIZED: RpcError = RpcError {
        code: -32600,
        message: "the session is not initialised",
    };
    /// -32600: the `Origin` rule refused the request.
    pub const FORBIDDEN_ORIGIN: RpcError = RpcError {
        code: -32600,
        message: "the Origin is refused",
    };
    /// -32600: the bearer token resolves to no grant. Over HTTP the
    /// transport answers 401 `invalid_token` instead.
    pub const INVALID_TOKEN: RpcError = RpcError {
        code: -32600,
        message: "the bearer token is not valid",
    };
    /// -32603: the server failed closed.
    pub const INTERNAL: RpcError = RpcError {
        code: -32603,
        message: "the server could not answer",
    };

    /// The JSON-RPC error object.
    pub fn to_value(self) -> Value {
        let mut o = Object::new();
        let _ = o.insert("code", Value::from(self.code));
        let _ = o.insert("message", Value::from(self.message));
        Value::Object(o)
    }
}

/// The JSON-RPC error of a refused body.
pub(crate) fn refusal_of(e: McpError) -> RpcError {
    match e {
        McpError::Batch => RpcError::BATCH,
        McpError::NotJson => RpcError::PARSE,
        McpError::Invalid(_) | McpError::TooLong | McpError::NotImplemented(_) => {
            RpcError::INVALID_REQUEST
        }
    }
}

/// The response to the request `id` with `result`.
pub(crate) fn response(id: &JsonRpcId, result: Value) -> Value {
    let mut o = Object::new();
    let _ = o.insert("jsonrpc", Value::from("2.0"));
    let _ = o.insert("id", id.to_value());
    let _ = o.insert("result", result);
    Value::Object(o)
}

/// The error response to the request `id`, or to a message with no
/// readable id.
pub(crate) fn error_response(id: Option<&JsonRpcId>, e: RpcError) -> Value {
    let mut o = Object::new();
    let _ = o.insert("jsonrpc", Value::from("2.0"));
    let _ = o.insert("id", id.map_or(Value::Null, JsonRpcId::to_value));
    let _ = o.insert("error", e.to_value());
    Value::Object(o)
}
