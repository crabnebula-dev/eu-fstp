//! Fuzz target `anthropic_response_decode` (ADR-019, TH-01, TH-26).
//!
//! The strict Anthropic decoder never panics, and every reply it accepts
//! holds only the closed member sets of ADR-019. The oracle walks the
//! parsed value independently, so a decoder that let an unknown member
//! or a tool block through, such as `score` or `tool_use`, fails here.

#![no_main]

use fstp_json::Value;
use libfuzzer_sys::fuzz_target;

const TOP: [&str; 11] = [
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
const USAGE: [&str; 10] = [
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

fn only(v: Option<&Value>, allowed: &[&str]) {
    if let Some(o) = v.and_then(Value::as_object) {
        for k in o.keys() {
            assert!(allowed.contains(&k), "accepted an unknown member");
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(reply) = fstp_infer::decode_anthropic_response(data) else {
        return;
    };
    assert!(reply.content.as_data().len() <= fstp_infer::MAX_CONTENT_BYTES);
    let v = fstp_json::parse(data).expect("an accepted reply is JSON");
    only(Some(&v), &TOP);
    only(v.get("usage"), &USAGE);
    assert_eq!(v.get("type").and_then(Value::as_str), Some("message"));
    assert_eq!(v.get("role").and_then(Value::as_str), Some("assistant"));
    assert_eq!(
        v.get("stop_reason").and_then(Value::as_str),
        Some("end_turn")
    );
    let blocks = v.get("content").and_then(Value::as_array).expect("content");
    let mut texts = Vec::new();
    for b in blocks {
        match b.get("type").and_then(Value::as_str) {
            Some("text") => {
                only(Some(b), &["type", "text", "citations"]);
                texts.push(b.get("text").and_then(Value::as_str).expect("text"));
            }
            Some("thinking") => only(Some(b), &["type", "thinking", "signature"]),
            Some("redacted_thinking") => only(Some(b), &["type", "data"]),
            _ => panic!("accepted another block type"),
        }
    }
    assert_eq!(
        texts,
        [reply.content.as_data()],
        "one text, kept byte for byte"
    );
});
