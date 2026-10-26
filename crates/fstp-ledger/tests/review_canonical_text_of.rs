//! Review reproducers for the W1b ledger lane, second pass (I-23, ADR-007).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_json::{FromJson, Value, parse};
use fstp_ledger::{Entry, MAX_AT, Seq};

/// I-23 and ADR-007: `canonical_text_of` exists so that a store outside the
/// crate gets its stored bytes from the crate codec. An append-only ledger
/// can never drop an entry. So every text it returns must decode again, or
/// the call must fail. Here it returns text for seq 0, schema 0 and a time
/// past `MAX_AT`, and the crate's own decoder refuses each one.
#[test]
fn review_i23_canonical_text_of_only_returns_decodable_bytes() {
    let record = Value::Null;
    let command = [0u8; 16];
    // 2^53 is an exact double, so RFC 8785 writes it without loss.
    let past_max = MAX_AT + 1;
    let cases = [
        ("seq 0", Seq::ZERO, 0, 1u16),
        ("schema 0", Seq::from_raw(1), 0, 0u16),
        ("at past MAX_AT", Seq::from_raw(1), past_max, 1u16),
        ("at below -MAX_AT", Seq::from_raw(1), -past_max, 1u16),
    ];
    let mut bad = Vec::new();
    for (name, seq, at, schema) in cases {
        let Ok(text) = Entry::<Value>::canonical_text_of(seq, at, &command, schema, &record) else {
            continue;
        };
        let decoded = parse(text.as_bytes())
            .ok()
            .and_then(|v| Entry::<Value>::from_json(&v).ok());
        if decoded.is_none() {
            bad.push(format!("{name}: {text}"));
        }
    }
    assert!(
        bad.is_empty(),
        "canonical_text_of returned stored bytes that never decode: {bad:?}"
    );
}
