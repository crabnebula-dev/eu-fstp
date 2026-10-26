//! Fuzz target for the ledger entry codec (TH-26, H-05, I-23, ADR-007).
//!
//! Checks, for any input that parses as JSON:
//! - decoding an entry never panics, and a refusal formats without panicking;
//! - an accepted input is an object with exactly the members `seq`, `at`,
//!   `command`, `schema` and `record`;
//! - `seq` is a decimal string without leading zeros, from 1 to `u64::MAX`;
//! - `command` is 32 lowercase hex digits;
//! - decode, encode, decode gives the same entry, and encoding is
//!   deterministic;
//! - an entry whose record has canonical bytes has canonical bytes itself;
//! - when the input has canonical bytes, the encoding has the same ones, so
//!   the decoder accepts one spelling per entry;
//! - the canonical bytes decode to the same entry and encode to the same
//!   bytes again.
//!
//! The record type is `fstp_json::Value`, so this target covers the entry
//! envelope only. Record bodies are covered by the `fstp-domain`,
//! `fstp-findings` and `fstp-engine` targets. The target reads entries only
//! through the codec, never through their fields.

#![no_main]

use fstp_json::{FromJson, ToJson, Value, parse, to_canonical};
use fstp_ledger::Entry;
use libfuzzer_sys::fuzz_target;

const MEMBERS: [&str; 5] = ["at", "command", "record", "schema", "seq"];

fn sorted_keys(v: &Value) -> Vec<String> {
    let mut keys: Vec<String> = v
        .as_object()
        .map(|o| o.keys().map(str::to_owned).collect())
        .unwrap_or_default();
    keys.sort();
    keys
}

fuzz_target!(|data: &[u8]| {
    let Ok(input) = parse(data) else {
        return;
    };
    let entry = match Entry::<Value>::from_json(&input) {
        Ok(entry) => entry,
        Err(e) => {
            let _ = e.to_string();
            return;
        }
    };

    // Exactly the five members, no unknown and none missing.
    assert_eq!(sorted_keys(&input), MEMBERS, "accepted members");

    let encoded = entry.to_json();
    assert_eq!(sorted_keys(&encoded), MEMBERS, "encoded members");

    // `seq` is a canonical decimal string from 1.
    let seq = encoded
        .get("seq")
        .and_then(Value::as_str)
        .expect("seq is a string");
    let n: u64 = seq.parse().expect("seq is a decimal u64");
    assert!(n >= 1, "seq 0 decoded");
    assert_eq!(n.to_string(), seq, "seq has one spelling");

    // `command` is 32 lowercase hex digits.
    let command = encoded
        .get("command")
        .and_then(Value::as_str)
        .expect("command is a string");
    assert_eq!(command.len(), 32, "command length");
    assert!(
        command
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "command is lowercase hex"
    );

    // Round trip and deterministic encoding.
    let again = Entry::<Value>::from_json(&encoded).expect("an encoded entry decodes");
    assert_eq!(again, entry, "decode, encode, decode changed the entry");
    assert!(
        again.to_json().identical(&encoded),
        "encoding is not deterministic"
    );

    // Canonical bytes exist whenever the record has them.
    let record = encoded.get("record").expect("record member");
    let canonical = match to_canonical(&encoded) {
        Ok(c) => c,
        Err(_) => {
            assert!(
                to_canonical(record).is_err(),
                "the envelope has no canonical form"
            );
            return;
        }
    };

    // One spelling per entry: the input's canonical bytes are the encoding's.
    if let Ok(input_canonical) = to_canonical(&input) {
        assert_eq!(
            input_canonical, canonical,
            "the decoder accepted a second spelling of an entry"
        );
    }

    // The canonical bytes decode to the same entry and are stable. RFC 8785
    // respells record numbers, and `Value` compares number lexemes, so the
    // record is compared by its canonical bytes and the envelope exactly.
    let reparsed = parse(canonical.as_bytes()).expect("canonical text parses");
    let third = Entry::<Value>::from_json(&reparsed).expect("canonical text decodes");
    let third_json = third.to_json();
    for member in ["at", "command", "schema", "seq"] {
        assert!(
            matches!(
                (third_json.get(member), encoded.get(member)),
                (Some(a), Some(b)) if a.identical(b)
            ),
            "canonical bytes decode to another {member}"
        );
    }
    assert_eq!(
        third_json.get("record").map(to_canonical),
        Some(to_canonical(record)),
        "canonical bytes decode to another record"
    );
    assert_eq!(
        to_canonical(&third.to_json()).ok().as_deref(),
        Some(canonical.as_str()),
        "canonical bytes are not stable"
    );
});
