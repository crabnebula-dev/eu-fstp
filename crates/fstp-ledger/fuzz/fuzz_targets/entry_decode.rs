//! Fuzz target for the ledger entry codec (TH-26, H-05, I-23).
//!
//! Checks, for any input that parses as JSON:
//! - decoding an entry never panics;
//! - decode, encode, decode gives the same entry;
//! - the canonical bytes of an encoded entry are stable.
//!
//! The record type is `fstp_json::Value`, so this target covers the entry
//! envelope only. Record bodies are covered by the `fstp-domain`,
//! `fstp-findings` and `fstp-engine` targets.

#![no_main]

use fstp_json::{FromJson, ToJson, Value, parse, to_canonical};
use fstp_ledger::Entry;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(v) = parse(data) else {
        return;
    };
    match Entry::<Value>::from_json(&v) {
        Ok(entry) => {
            let encoded = entry.to_json();
            let again = Entry::<Value>::from_json(&encoded).expect("an encoded entry decodes");
            assert_eq!(again, entry, "decode, encode, decode changed the entry");
            assert_eq!(
                to_canonical(&again.to_json()),
                to_canonical(&encoded),
                "canonical bytes are not stable"
            );
        }
        Err(e) => {
            let _ = e.to_string();
        }
    }
});
