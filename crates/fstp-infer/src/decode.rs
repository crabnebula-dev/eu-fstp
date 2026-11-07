//! The strict response decoder (M7 design section 3.4, ADR-019).

use core::fmt;

use fstp_findings::UntrustedText;
use fstp_json::{Object, ParseLimits, Value};

/// The largest response body, in bytes.
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// The largest reply content, in bytes.
pub const MAX_CONTENT_BYTES: usize = 64 * 1024;

/// Why a reply ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FinishReason {
    /// The model finished.
    Stop,
}

/// Token counts the server reported. Zero when it sent none.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    /// Tokens of the request.
    pub prompt_tokens: u64,
    /// Tokens of the reply.
    pub completion_tokens: u64,
}

/// A decoded reply. The content is untrusted: it is a model's output after
/// reading submission content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelReply {
    /// The reply content, unchanged.
    pub content: UntrustedText,
    /// Why the reply ended.
    pub finish: FinishReason,
    /// Token counts.
    pub usage: Usage,
}

/// Why a reply was refused. No variant carries input content (R-NF-02).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The body is larger than [`MAX_RESPONSE_BYTES`].
    TooLarge,
    /// The body is not I-JSON.
    Json,
    /// An object holds a member outside the closed set.
    UnknownMember,
    /// A member is missing or has the wrong type or value.
    Shape(&'static str),
    /// The model stopped at the token limit.
    Truncated,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::TooLarge => f.write_str("response too large"),
            DecodeError::Json => f.write_str("response is not JSON"),
            DecodeError::UnknownMember => f.write_str("unknown member"),
            DecodeError::Shape(what) => write!(f, "bad shape: {what}"),
            DecodeError::Truncated => f.write_str("reply truncated"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Decodes one chat-completions response body.
///
/// # Errors
///
/// Returns a [`DecodeError`] for anything outside the closed shape.
/// The members a response object may hold (ADR-019).
const TOP: [&str; 8] = [
    "id",
    "object",
    "created",
    "model",
    "choices",
    "usage",
    "system_fingerprint",
    "service_tier",
];
/// The members a choice may hold.
const CHOICE: [&str; 4] = ["index", "message", "finish_reason", "logprobs"];
/// The members a message may hold.
const MESSAGE: [&str; 4] = ["role", "content", "refusal", "tool_calls"];
/// The members a usage object may hold.
const USAGE: [&str; 3] = ["prompt_tokens", "completion_tokens", "total_tokens"];

fn limits() -> ParseLimits {
    ParseLimits {
        max_input_bytes: MAX_RESPONSE_BYTES,
        max_depth: 16,
        max_string_bytes: MAX_RESPONSE_BYTES,
        max_container_len: 64,
        max_nodes: 1024,
        ..ParseLimits::default()
    }
}

/// Refuses any member of `o` outside `allowed`.
fn closed(o: &Object, allowed: &[&str]) -> Result<(), DecodeError> {
    if o.keys().all(|k| allowed.contains(&k)) {
        Ok(())
    } else {
        Err(DecodeError::UnknownMember)
    }
}

fn object<'a>(v: Option<&'a Value>, what: &'static str) -> Result<&'a Object, DecodeError> {
    v.and_then(Value::as_object).ok_or(DecodeError::Shape(what))
}

fn string<'a>(v: Option<&'a Value>, what: &'static str) -> Result<&'a str, DecodeError> {
    v.and_then(Value::as_str).ok_or(DecodeError::Shape(what))
}

/// An optional member that must be a string or null when present.
fn opt_string(o: &Object, key: &'static str) -> Result<(), DecodeError> {
    match o.get(key) {
        None | Some(Value::Null | Value::String(_)) => Ok(()),
        Some(_) => Err(DecodeError::Shape(key)),
    }
}

/// An optional member that must be a non-negative integer when present.
fn opt_count(o: &Object, key: &'static str) -> Result<u64, DecodeError> {
    match o.get(key) {
        None => Ok(0),
        Some(v) => v.as_u64().ok_or(DecodeError::Shape(key)),
    }
}

/// Decodes one chat-completions response body.
///
/// The closed member sets are those of ADR-019. Exactly one choice, from
/// the assistant, that finished with `stop`, with string content of at
/// most [`MAX_CONTENT_BYTES`]. Tool calls must be absent or empty, and
/// `logprobs` and `refusal` absent or null.
///
/// # Errors
///
/// Returns a [`DecodeError`] for anything outside the closed shape.
pub fn decode_response(body: &[u8]) -> Result<ModelReply, DecodeError> {
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(DecodeError::TooLarge);
    }
    let v = fstp_json::parse_with(body, &limits()).map_err(|_| DecodeError::Json)?;
    let top = object(Some(&v), "response")?;
    closed(top, &TOP)?;
    if string(top.get("object"), "object")? != "chat.completion" {
        return Err(DecodeError::Shape("object"));
    }
    opt_string(top, "id")?;
    opt_string(top, "model")?;
    opt_string(top, "system_fingerprint")?;
    opt_string(top, "service_tier")?;
    let _created = opt_count(top, "created")?;

    let usage = match top.get("usage") {
        None | Some(Value::Null) => Usage::default(),
        Some(u) => {
            let u = object(Some(u), "usage")?;
            closed(u, &USAGE)?;
            let _total = opt_count(u, "total_tokens")?;
            Usage {
                prompt_tokens: opt_count(u, "prompt_tokens")?,
                completion_tokens: opt_count(u, "completion_tokens")?,
            }
        }
    };

    let choices = top
        .get("choices")
        .and_then(Value::as_array)
        .ok_or(DecodeError::Shape("choices"))?;
    let [choice] = choices.as_slice() else {
        return Err(DecodeError::Shape("choices"));
    };
    let choice = object(Some(choice), "choice")?;
    closed(choice, &CHOICE)?;
    if opt_count(choice, "index")? != 0 {
        return Err(DecodeError::Shape("index"));
    }
    if !matches!(choice.get("logprobs"), None | Some(Value::Null)) {
        return Err(DecodeError::Shape("logprobs"));
    }
    let message = object(choice.get("message"), "message")?;
    closed(message, &MESSAGE)?;
    let finish = match string(choice.get("finish_reason"), "finish_reason")? {
        "stop" => FinishReason::Stop,
        "length" => return Err(DecodeError::Truncated),
        _ => return Err(DecodeError::Shape("finish_reason")),
    };

    if string(message.get("role"), "role")? != "assistant" {
        return Err(DecodeError::Shape("role"));
    }
    if !matches!(message.get("refusal"), None | Some(Value::Null)) {
        return Err(DecodeError::Shape("refusal"));
    }
    match message.get("tool_calls") {
        None | Some(Value::Null) => {}
        Some(Value::Array(a)) if a.is_empty() => {}
        Some(_) => return Err(DecodeError::Shape("tool_calls")),
    }
    let content = string(message.get("content"), "content")?;
    if content.len() > MAX_CONTENT_BYTES {
        return Err(DecodeError::TooLarge);
    }
    Ok(ModelReply {
        content: UntrustedText::new(content.to_owned()),
        finish,
        usage,
    })
}
