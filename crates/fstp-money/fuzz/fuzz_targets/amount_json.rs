//! Fuzz target for amounts in JSON (TH-26, H-05, ADR-006).
//!
//! Checks, for any input that parses as JSON:
//! - `amount_from_json` never panics;
//! - JSON numbers are always rejected, and only JSON strings are accepted;
//! - an accepted amount writes back as the same string, so `to_canonical`
//!   keeps it unchanged.

#![no_main]

use fstp_json::{ToJson, Value, parse, to_canonical};
use fstp_money::{Currency, amount_from_json};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(v) = parse(data) else {
        return;
    };
    match amount_from_json(&v, Currency::Eur) {
        Ok(a) => {
            assert!(
                matches!(v, Value::String(_)),
                "accepted a value that is not a JSON string"
            );
            let back = a.to_json();
            assert!(back.identical(&v), "the string changed on the way back");
            assert_eq!(to_canonical(&back), to_canonical(&v));
        }
        Err(e) => {
            let _ = e.to_string();
        }
    }
});
