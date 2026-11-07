//! Fuzz target `infer_response_decode` (M7 design section 8, TH-01, TH-26).
//!
//! The strict decoder never panics, and every reply it accepts holds only
//! the closed member sets of ADR-019. The oracle walks the parsed value
//! independently, so a decoder that let an unknown member through, such
//! as `score` or `decision`, fails here.

#![no_main]

use fstp_json::Value;
use libfuzzer_sys::fuzz_target;

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
const CHOICE: [&str; 4] = ["index", "message", "finish_reason", "logprobs"];
const MESSAGE: [&str; 4] = ["role", "content", "refusal", "tool_calls"];
const USAGE: [&str; 3] = ["prompt_tokens", "completion_tokens", "total_tokens"];

fn only(v: Option<&Value>, allowed: &[&str]) {
    if let Some(o) = v.and_then(Value::as_object) {
        for k in o.keys() {
            assert!(allowed.contains(&k), "accepted an unknown member");
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(reply) = fstp_infer::decode_response(data) else {
        return;
    };
    assert!(reply.content.as_data().len() <= fstp_infer::MAX_CONTENT_BYTES);
    let v = fstp_json::parse(data).expect("an accepted reply is JSON");
    only(Some(&v), &TOP);
    only(v.get("usage"), &USAGE);
    let choices = v.get("choices").and_then(Value::as_array).expect("choices");
    assert_eq!(choices.len(), 1);
    let choice = choices.first();
    only(choice, &CHOICE);
    let message = choice.and_then(|c| c.get("message"));
    only(message, &MESSAGE);
    assert_eq!(
        message.and_then(|m| m.get("content")).and_then(Value::as_str),
        Some(reply.content.as_data()),
        "the content is kept byte for byte"
    );
});
