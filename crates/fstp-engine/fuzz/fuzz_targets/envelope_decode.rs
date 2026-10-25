//! Fuzz target for the engine envelope decoder (TH-26, H-05).
//!
//! W0 stub: the `Command` and `Record` envelopes do not exist yet, so the
//! target decodes a ledger entry with a generic JSON record, the closest
//! existing stub. The record type is replaced with the envelope when it
//! lands. The harness lane (W2) owns
//! `crates/fstp-engine/fuzz/**` after W0. The final target checks the round trip.

#![no_main]

use fstp_engine as _;
use fstp_json::{FromJson, ToJson, Value, parse};
use fstp_ledger::Entry;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(v) = parse(data) else {
        return;
    };
    if let Ok(entry) = Entry::<Value>::from_json(&v) {
        let again = Entry::<Value>::from_json(&entry.to_json()).expect("an encoded entry decodes");
        assert_eq!(again, entry, "round trip changed the entry");
    }
});
