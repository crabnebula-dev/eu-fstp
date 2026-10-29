//! Fuzz target `field_value_decode` of `fstp-programme` (TH-26, H-05,
//! ADR-006, M4 design section 9).
//!
//! The first input byte selects a row of `FIELDS`, and the rest is the
//! value text. Checks, for strict per-field decoding:
//! - `decode_field_value` never panics, and a refusal formats;
//! - an accepted value is JSON and names the field it was decoded for;
//! - `encode_field_value` writes canonical RFC 8785 text that decodes to
//!   the same value and encodes to the same text;
//! - amounts travel only as ADR-006 strings: the accepted text with any
//!   amount-shaped string written as a JSON number is refused.

#![no_main]

use fstp_json::{Number, Value, parse, to_canonical, to_compact};
use fstp_programme::{FIELDS, decode_field_value, encode_field_value};
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
    let Some((&select, text)) = data.split_first() else {
        return;
    };
    if FIELDS.is_empty() {
        return;
    }
    let Some(field) = FIELDS.get(usize::from(select) % FIELDS.len()) else {
        return;
    };
    let value = match decode_field_value(field.id, text) {
        Ok(v) => v,
        Err(e) => {
            assert!(!format!("{e:?}").is_empty());
            return;
        }
    };
    let Ok(input) = parse(text) else {
        panic!("decode_field_value accepted an input that is not JSON");
    };
    assert_eq!(value.field(), field.id, "the value names another field");

    let written = encode_field_value(&value);
    let Ok(parsed) = parse(written.as_bytes()) else {
        panic!("encode_field_value wrote text that is not JSON");
    };
    assert_eq!(
        to_canonical(&parsed).ok().as_deref(),
        Some(written.as_str()),
        "encode_field_value wrote text that is not canonical"
    );
    match decode_field_value(field.id, written.as_bytes()) {
        Ok(again) => {
            assert_eq!(again, value, "the value changed through encode_field_value");
            assert_eq!(
                encode_field_value(&again),
                written,
                "encoding is not stable"
            );
        }
        Err(e) => panic!("decode_field_value refused what encode_field_value wrote: {e:?}"),
    }

    for skip in 0..64 {
        let mut v = input.clone();
        if !swap_amount(&mut v, skip) {
            break;
        }
        assert!(
            decode_field_value(field.id, to_compact(&v).as_bytes()).is_err(),
            "an amount was accepted as a JSON number"
        );
    }
});
