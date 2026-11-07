//! The strict decoder of Anthropic Messages responses (ADR-019).
//!
//! The member sets follow the `Message` object of
//! <https://platform.claude.com/docs/en/api/messages/create>, read on
//! 2026-11-07. Only the members a request of this crate can bring back
//! are accepted. A container, diagnostics, citations, tool calls and
//! server tool results are refused, because no request asks for them.

use fstp_findings::UntrustedText;
use fstp_json::{Object, Value};

use crate::decode::{
    DecodeError, FinishReason, MAX_CONTENT_BYTES, MAX_RESPONSE_BYTES, ModelReply, StopReason,
    Usage, closed, limits, object, opt_count, opt_string, string,
};

/// The members a `Message` may hold.
pub(crate) const TOP: [&str; 11] = [
    "id",
    "type",
    "role",
    "content",
    "model",
    "stop_reason",
    "stop_sequence",
    "stop_details",
    "usage",
    "container",
    "diagnostics",
];
/// The members a `text` block may hold.
pub(crate) const TEXT: [&str; 3] = ["type", "text", "citations"];
/// The members a `thinking` block may hold. Its text is dropped.
pub(crate) const THINKING: [&str; 3] = ["type", "thinking", "signature"];
/// The members a `redacted_thinking` block may hold. It is dropped.
pub(crate) const REDACTED: [&str; 2] = ["type", "data"];
/// The members of `stop_details`.
pub(crate) const STOP_DETAILS: [&str; 3] = ["type", "category", "explanation"];
/// The members a `usage` object may hold. Beyond the two counts, these
/// are the documented harmless extras: cache, geography, tier, speed and
/// tool counters. None of them carries model text.
pub(crate) const USAGE: [&str; 10] = [
    "input_tokens",
    "output_tokens",
    "cache_creation_input_tokens",
    "cache_read_input_tokens",
    "cache_creation",
    "inference_geo",
    "output_tokens_details",
    "server_tool_use",
    "service_tier",
    "speed",
];
/// The members of `usage.cache_creation`.
pub(crate) const CACHE_CREATION: [&str; 2] =
    ["ephemeral_1h_input_tokens", "ephemeral_5m_input_tokens"];
/// The members of `usage.output_tokens_details`.
pub(crate) const OUTPUT_DETAILS: [&str; 1] = ["thinking_tokens"];
/// The members of `usage.server_tool_use`.
pub(crate) const SERVER_TOOL_USE: [&str; 2] = ["web_fetch_requests", "web_search_requests"];

/// A member that must be absent or null.
fn absent(o: &Object, key: &'static str) -> Result<(), DecodeError> {
    match o.get(key) {
        None | Some(Value::Null) => Ok(()),
        Some(_) => Err(DecodeError::Shape(key)),
    }
}

/// A count that may be absent or null, read as zero.
fn nullable_count(o: &Object, key: &'static str) -> Result<u64, DecodeError> {
    match o.get(key) {
        None | Some(Value::Null) => Ok(0),
        Some(v) => v.as_u64().ok_or(DecodeError::Shape(key)),
    }
}

/// An object of counts that may be absent or null.
fn nullable_counts(
    o: &Object,
    key: &'static str,
    members: &'static [&'static str],
) -> Result<(), DecodeError> {
    match o.get(key) {
        None | Some(Value::Null) => Ok(()),
        Some(v) => {
            let inner = object(Some(v), key)?;
            closed(inner, members)?;
            for m in members {
                nullable_count(inner, m)?;
            }
            Ok(())
        }
    }
}

fn usage(top: &Object) -> Result<Usage, DecodeError> {
    let Some(v) = top.get("usage") else {
        return Ok(Usage::default());
    };
    let u = object(Some(v), "usage")?;
    closed(u, &USAGE)?;
    nullable_counts(u, "cache_creation", &CACHE_CREATION)?;
    nullable_counts(u, "output_tokens_details", &OUTPUT_DETAILS)?;
    nullable_counts(u, "server_tool_use", &SERVER_TOOL_USE)?;
    opt_string(u, "inference_geo")?;
    opt_string(u, "service_tier")?;
    opt_string(u, "speed")?;
    // The documented total input is the sum of the three input counts.
    let input = opt_count(u, "input_tokens")?
        .saturating_add(nullable_count(u, "cache_creation_input_tokens")?)
        .saturating_add(nullable_count(u, "cache_read_input_tokens")?);
    Ok(Usage {
        prompt_tokens: input,
        completion_tokens: opt_count(u, "output_tokens")?,
    })
}

/// Checks `stop_details`, and returns whether it is a refusal.
fn stop_details(top: &Object) -> Result<bool, DecodeError> {
    match top.get("stop_details") {
        None | Some(Value::Null) => Ok(false),
        Some(v) => {
            let d = object(Some(v), "stop_details")?;
            closed(d, &STOP_DETAILS)?;
            if string(d.get("type"), "stop_details")? != "refusal" {
                return Err(DecodeError::Shape("stop_details"));
            }
            opt_string(d, "category")?;
            opt_string(d, "explanation")?;
            Ok(true)
        }
    }
}

/// The one text of `content`. Thinking blocks are checked and dropped.
fn content(top: &Object) -> Result<&str, DecodeError> {
    let blocks = top
        .get("content")
        .and_then(Value::as_array)
        .ok_or(DecodeError::Shape("content"))?;
    let mut text = None;
    for b in blocks {
        let b = object(Some(b), "content block")?;
        match string(b.get("type"), "content block")? {
            "text" => {
                closed(b, &TEXT)?;
                match b.get("citations") {
                    None | Some(Value::Null) => {}
                    Some(Value::Array(a)) if a.is_empty() => {}
                    Some(_) => return Err(DecodeError::Shape("citations")),
                }
                let t = string(b.get("text"), "text")?;
                if text.replace(t).is_some() {
                    return Err(DecodeError::Shape("content"));
                }
            }
            "thinking" => {
                closed(b, &THINKING)?;
                string(b.get("thinking"), "thinking")?;
                string(b.get("signature"), "signature")?;
            }
            "redacted_thinking" => {
                closed(b, &REDACTED)?;
                string(b.get("data"), "data")?;
            }
            _ => return Err(DecodeError::Shape("content block")),
        }
    }
    text.ok_or(DecodeError::Shape("content"))
}

/// Decodes one Anthropic Messages response body (ADR-019).
///
/// The closed member sets are those of ADR-019. The type is `message`,
/// the role `assistant`, and the content exactly one `text` block of at
/// most [`MAX_CONTENT_BYTES`], beside optional thinking blocks. Only
/// `end_turn` gives a reply. `max_tokens` and
/// `model_context_window_exceeded` are [`DecodeError::Truncated`],
/// `refusal` is [`DecodeError::Refused`], and the rest are
/// [`DecodeError::Unexpected`].
///
/// # Errors
///
/// Returns a [`DecodeError`] for anything outside the closed shape.
pub fn decode_anthropic_response(body: &[u8]) -> Result<ModelReply, DecodeError> {
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(DecodeError::TooLarge);
    }
    let v = fstp_json::parse_with(body, &limits()).map_err(|_| DecodeError::Json)?;
    let top = object(Some(&v), "response")?;
    closed(top, &TOP)?;
    if string(top.get("type"), "type")? != "message" {
        return Err(DecodeError::Shape("type"));
    }
    if string(top.get("role"), "role")? != "assistant" {
        return Err(DecodeError::Shape("role"));
    }
    opt_string(top, "id")?;
    opt_string(top, "model")?;
    absent(top, "container")?;
    absent(top, "diagnostics")?;
    absent(top, "stop_sequence")?;
    let usage = usage(top)?;
    let refusal = stop_details(top)?;
    let stop = StopReason::parse(string(top.get("stop_reason"), "stop_reason")?)
        .ok_or(DecodeError::Shape("stop_reason"))?;
    // The reference documents `stop_details` as null for every stop
    // reason except `refusal`.
    if refusal && stop != StopReason::Refusal {
        return Err(DecodeError::Shape("stop_details"));
    }
    match stop {
        StopReason::EndTurn => {}
        StopReason::MaxTokens | StopReason::ModelContextWindowExceeded => {
            return Err(DecodeError::Truncated);
        }
        StopReason::Refusal => return Err(DecodeError::Refused),
        other => return Err(DecodeError::Unexpected(other)),
    }
    let text = content(top)?;
    if text.len() > MAX_CONTENT_BYTES {
        return Err(DecodeError::TooLarge);
    }
    Ok(ModelReply {
        content: UntrustedText::new(text.to_owned()),
        finish: FinishReason::Stop,
        usage,
    })
}
