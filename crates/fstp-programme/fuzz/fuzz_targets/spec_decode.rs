//! Fuzz target `spec_decode` of `fstp-programme` (TH-26, H-05, ADR-006,
//! M4 design section 9).
//!
//! Checks, for any input:
//! - `decode_spec` never panics, and a refusal formats;
//! - an accepted input is JSON, and `encode_spec` writes canonical RFC 8785
//!   text that decodes to the same spec and encodes to the same text;
//! - unknown members are rejected: the accepted text with an extra member
//!   at the top level or in any step object is refused;
//! - amounts travel only as ADR-006 strings: the accepted text with any
//!   amount-shaped string written as a JSON number is refused.

#![no_main]

use fstp_json::{Number, Value, parse, to_canonical, to_compact};
use fstp_programme::{decode_spec, encode_spec};
use libfuzzer_sys::fuzz_target;

/// Whether `s` is spelled as an ADR-006 EUR amount.
fn is_amount_text(s: &str) -> bool {
    let Some((int, frac)) = s.split_once('.') else {
        return false;
    };
    let digits = |t: &str| !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit());
    digits(int) && digits(frac) && frac.len() == 2 && (int == "0" || !int.starts_with('0'))
}

/// Replaces the first amount-shaped string after skipping `skip` of them
/// with a JSON number of the same digits. Returns false when there is none.
fn swap_amount(v: &mut Value, mut skip: usize) -> bool {
    let mut stack: Vec<&mut Value> = vec![v];
    while let Some(v) = stack.pop() {
        match v {
            Value::String(s) if is_amount_text(s) => {
                if skip == 0 {
                    match Number::from_lexeme(s) {
                        Ok(n) => {
                            *v = Value::Number(n);
                            return true;
                        }
                        Err(_) => return false,
                    }
                }
                skip -= 1;
            }
            Value::Array(a) => stack.extend(a.iter_mut()),
            Value::Object(o) => stack.extend(o.iter_mut().map(|(_, x)| x)),
            _ => {}
        }
    }
    false
}

fuzz_target!(|data: &[u8]| {
    let spec = match decode_spec(data) {
        Ok(s) => s,
        Err(e) => {
            assert!(!format!("{e:?}").is_empty());
            return;
        }
    };
    let Ok(input) = parse(data) else {
        panic!("decode_spec accepted an input that is not JSON");
    };

    let text = encode_spec(&spec);
    let Ok(written) = parse(text.as_bytes()) else {
        panic!("encode_spec wrote text that is not JSON");
    };
    assert_eq!(
        to_canonical(&written).ok().as_deref(),
        Some(text.as_str()),
        "encode_spec wrote text that is not canonical"
    );
    match decode_spec(text.as_bytes()) {
        Ok(again) => {
            assert_eq!(again, spec, "the spec changed through encode_spec");
            assert_eq!(encode_spec(&again), text, "encode_spec is not stable");
        }
        Err(e) => panic!("decode_spec refused what encode_spec wrote: {e:?}"),
    }

    // Unknown members, at the top level and in each step object.
    let Some(top) = input.as_object() else {
        panic!("decode_spec accepted a spec that is not an object");
    };
    let mut keys: Vec<Option<String>> = vec![None];
    keys.extend(
        top.iter()
            .filter(|(_, v)| v.as_object().is_some())
            .map(|(k, _)| Some(k.to_owned())),
    );
    for key in keys {
        let mut v = input.clone();
        let target = match (&key, v.as_object_mut()) {
            (None, Some(o)) => Some(o),
            (Some(k), Some(o)) => o.get_mut(k).and_then(Value::as_object_mut),
            _ => None,
        };
        if let Some(o) = target {
            if o.contains_key("zz_unknown_member") {
                continue;
            }
            o.insert("zz_unknown_member", Value::Null);
            assert!(
                decode_spec(to_compact(&v).as_bytes()).is_err(),
                "an unknown member in {key:?} was accepted"
            );
        }
    }

    // Amounts only as ADR-006 strings.
    for skip in 0..64 {
        let mut v = input.clone();
        if !swap_amount(&mut v, skip) {
            break;
        }
        assert!(
            decode_spec(to_compact(&v).as_bytes()).is_err(),
            "an amount was accepted as a JSON number"
        );
    }
});
