//! Fuzz target for amounts in JSON (TH-26, H-05, ADR-006).
//!
//! Checks, for any input that parses as JSON:
//! - `amount_from_json` never panics;
//! - JSON numbers are always rejected, and only JSON strings are accepted;
//! - a JSON string is accepted exactly when `Amount::parse` accepts its
//!   content, with the same value;
//! - an accepted amount writes back as the same string, so `to_canonical`
//!   keeps it unchanged.

#![no_main]

use fstp_json::{ToJson, Value, parse, to_canonical};
use fstp_money::{Amount, Currency, amount_from_json};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(v) = parse(data) else {
        return;
    };
    let decoded = amount_from_json(&v, Currency::Eur);
    match &v {
        Value::String(s) => {
            let parsed = Amount::parse(s, Currency::Eur);
            assert_eq!(
                decoded.as_ref().ok(),
                parsed.as_ref().ok(),
                "JSON decoding and text parsing disagree"
            );
        }
        _ => assert!(
            decoded.is_err(),
            "accepted a value that is not a JSON string"
        ),
    }
    match decoded {
        Ok(a) => {
            let back = a.to_json();
            assert!(back.identical(&v), "the string changed on the way back");
            // A canonical ADR-006 amount holds only ASCII digits and a full
            // stop, so its canonical JSON form is the original string in
            // quotes, with no escaping. The check above already rejects an
            // accepted value that is not a string.
            if let Value::String(s) = &v {
                assert_eq!(
                    to_canonical(&back).ok(),
                    Some(format!("\"{s}\"")),
                    "to_canonical rewrote an accepted amount"
                );
            }
        }
        Err(e) => {
            let _ = e.to_string();
        }
    }
});
