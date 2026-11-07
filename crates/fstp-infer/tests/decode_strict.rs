//! The strict response decoder (M7 design sections 3.3 and 3.4, R-LA-04).
//!
//! It accepts the closed chat-completions member set of the inference ADR
//! and nothing else, so a model or server cannot add a member such as
//! `score` or `decision` (I-10, TH-01).

use fstp_infer::{DecodeError, FinishReason, MAX_CONTENT_BYTES, decode_response};

fn reply(content: &str) -> String {
    let content = fstp_json::to_compact(&fstp_json::Value::String(content.to_owned()));
    format!(
        r#"{{"id":"r-1","object":"chat.completion","created":0,"model":"m","choices":[{{"index":0,"message":{{"role":"assistant","content":{content}}},"finish_reason":"stop"}}],"usage":{{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}}}"#
    )
}

/// R-LA-04: a minimal chat-completions reply decodes, and its content is
/// kept byte for byte as untrusted data.
#[test]
fn r_la_04_decode_accepts_minimal_reply() {
    let text = "{\"findings\":[]} \u{202e} \"quoted\"";
    let r = decode_response(reply(text).as_bytes()).unwrap();
    assert_eq!(r.content.as_data(), text);
    assert_eq!(r.finish, FinishReason::Stop);
    assert_eq!((r.usage.prompt_tokens, r.usage.completion_tokens), (3, 2));
}

/// TH-01, I-10: an unknown member at any level fails the whole reply.
#[test]
fn th01_decoder_rejects_unknown_members() {
    let base = reply("{}");
    let cases = [
        base.replacen("\"id\":\"r-1\"", "\"id\":\"r-1\",\"score\":5", 1),
        base.replacen("\"index\":0", "\"index\":0,\"decision\":\"fund\"", 1),
        base.replacen(
            "\"role\":\"assistant\"",
            "\"role\":\"assistant\",\"state\":\"GRANTED\"",
            1,
        ),
        base.replacen("\"total_tokens\":5", "\"total_tokens\":5,\"weight\":1", 1),
    ];
    for c in cases {
        assert!(c != base, "the case changed the reply");
        assert!(
            matches!(
                decode_response(c.as_bytes()),
                Err(DecodeError::UnknownMember)
            ),
            "accepted {c}"
        );
    }
}

/// R-LA-04: every other deviation from the closed shape is refused.
#[test]
fn r_la_04_decoder_refuses_other_shapes() {
    let base = reply("{}");
    let two = base.replacen(
        "\"finish_reason\":\"stop\"}]",
        "\"finish_reason\":\"stop\"},{\"index\":1,\"message\":{\"role\":\"assistant\",\"content\":\"x\"},\"finish_reason\":\"stop\"}]",
        1,
    );
    let refused = [
        two,
        base.replacen("\"stop\"", "\"length\"", 1),
        base.replacen("\"assistant\"", "\"user\"", 1),
        base.replacen("\"chat.completion\"", "\"chat.completion.chunk\"", 1),
        base.replacen("\"id\":\"r-1\"", "\"id\":\"r-1\",\"id\":\"r-2\"", 1),
        base.replacen(
            "\"role\":\"assistant\"",
            "\"role\":\"assistant\",\"tool_calls\":[{\"id\":\"t\"}]",
            1,
        ),
        base.replacen(
            "\"index\":0",
            "\"index\":0,\"logprobs\":{\"content\":[]}",
            1,
        ),
        base.replacen("\"prompt_tokens\":3", "\"prompt_tokens\":-3", 1),
        base.replacen("\"prompt_tokens\":3", "\"prompt_tokens\":3.5", 1),
        "[]".to_owned(),
        String::new(),
        reply(&"x".repeat(MAX_CONTENT_BYTES + 1)),
    ];
    for c in refused {
        assert!(
            decode_response(c.as_bytes()).is_err(),
            "accepted a refused shape"
        );
    }
    // The allowed optional members with their null forms still decode.
    let optional = base
        .replacen("\"index\":0", "\"index\":0,\"logprobs\":null", 1)
        .replacen(
            "\"role\":\"assistant\"",
            "\"role\":\"assistant\",\"refusal\":null,\"tool_calls\":[]",
            1,
        )
        .replacen(
            "\"model\":\"m\"",
            "\"model\":\"m\",\"system_fingerprint\":null",
            1,
        );
    assert!(decode_response(optional.as_bytes()).is_ok());
}
