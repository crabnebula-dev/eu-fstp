//! Fuzz target for the JSON parser and serializers (TH-26, H-05).
//!
//! Checks, for any input:
//! - parsing never panics, and error positions stay inside the input;
//! - only valid UTF-8 is ever accepted;
//! - on success, compact, pretty and HTML-safe output parse back to an
//!   identical tree, and compact output is byte-stable;
//! - on success, canonical output parses back to the same structure with
//!   numerically equal numbers, and is a fixed point;
//! - tighter limits never accept an input that the defaults reject;
//! - on success, the parser charges exactly the memory estimate that
//!   `ParseLimits::max_memory_bytes` documents: the parse succeeds with the
//!   estimate as the limit and fails with one byte less.

#![no_main]

use fstp_json::{
    CanonicalErrorKind, CanonicalOptions, Limit, ParseErrorKind, ParseLimits, Value, WriteOptions,
    parse, parse_str, parse_with, to_canonical_with, to_compact, to_pretty, to_string_with,
};
use libfuzzer_sys::fuzz_target;

/// Same structure, strings and names; numbers compared by `same_number`.
fn same_shape(a: &Value, b: &Value, same_number: &dyn Fn(&Value, &Value) -> bool) -> bool {
    let mut stack = vec![(a, b)];
    while let Some(pair) = stack.pop() {
        match pair {
            (Value::Null, Value::Null) => {}
            (Value::Bool(x), Value::Bool(y)) if x == y => {}
            (Value::String(x), Value::String(y)) if x == y => {}
            (x @ Value::Number(_), y @ Value::Number(_)) if same_number(x, y) => {}
            (Value::Array(x), Value::Array(y)) if x.len() == y.len() => {
                stack.extend(x.iter().zip(y.iter()));
            }
            (Value::Object(x), Value::Object(y)) if x.len() == y.len() => {
                for (k, v) in x.iter() {
                    match y.get(k) {
                        Some(w) => stack.push((v, w)),
                        None => return false,
                    }
                }
            }
            _ => return false,
        }
    }
    true
}

/// The memory estimate that `ParseLimits::max_memory_bytes` documents.
fn documented_estimate(v: &Value) -> usize {
    let mut total = 0usize;
    let mut stack = vec![v];
    while let Some(v) = stack.pop() {
        total += 64;
        match v {
            Value::String(s) => total += s.len(),
            Value::Number(n) => total += n.as_str().len(),
            Value::Array(a) => stack.extend(a.iter()),
            Value::Object(o) => {
                if o.len() > 8 {
                    total += 128 + 80 * o.len();
                }
                for (k, v) in o.iter() {
                    total += 64 + k.len();
                    stack.push(v);
                }
            }
            Value::Null | Value::Bool(_) => {}
        }
    }
    total
}

fn exact(a: &Value, b: &Value) -> bool {
    let d = |v: &Value| v.as_number().map(|n| n.as_decimal());
    matches!((d(a), d(b)), (Some(Ok(x)), Some(Ok(y))) if x == y)
}

fn same_double(a: &Value, b: &Value) -> bool {
    let f = |v: &Value| v.as_number().map(|n| n.as_f64_lossy());
    match (f(a), f(b)) {
        (Some(x), Some(y)) => x == y,
        _ => false,
    }
}

fuzz_target!(|data: &[u8]| {
    let parsed = parse(data);
    let tight = ParseLimits {
        max_input_bytes: 512,
        max_depth: 8,
        max_string_bytes: 32,
        max_number_len: 24,
        max_container_len: 8,
        max_nodes: 64,
        max_memory_bytes: 4096,
    };
    if let Ok(t) = parse_with(data, &tight) {
        let v = parsed
            .as_ref()
            .expect("tight limits accepted what defaults reject");
        assert!(t.identical(v));
    }

    let v = match parsed {
        Ok(v) => v,
        Err(e) => {
            assert!(e.offset() <= data.len());
            assert!(e.line() >= 1 && e.column() >= 1);
            let _ = e.to_string();
            return;
        }
    };
    assert!(std::str::from_utf8(data).is_ok(), "accepted invalid UTF-8");

    let cost = documented_estimate(&v);
    let budget = |n: usize| ParseLimits::default().with_max_memory_bytes(n);
    let at_cost = parse_with(data, &budget(cost)).expect("parses within its own estimate");
    assert!(at_cost.identical(&v));
    let below = parse_with(data, &budget(cost - 1)).expect_err("parsed below its estimate");
    assert_eq!(
        below.kind(),
        ParseErrorKind::LimitExceeded(Limit::MemoryBytes)
    );

    let compact = to_compact(&v);
    let back = parse_str(&compact).expect("compact output parses");
    assert!(back.identical(&v), "compact round trip");
    assert_eq!(to_compact(&back), compact, "compact output is not stable");
    assert!(compact.bytes().all(|b| b >= 0x20), "raw control character");

    for options in [WriteOptions::pretty(), WriteOptions::compact().html_safe()] {
        let text = to_string_with(&v, options);
        assert!(parse_str(&text).expect("output parses").identical(&v));
    }
    assert_eq!(to_pretty(&v), to_string_with(&v, WriteOptions::pretty()));

    let copy = v.clone();
    assert!(copy.identical(&v) && copy == v);

    let lossy = CanonicalOptions {
        allow_lossy_numbers: true,
    };
    for (options, same_number) in [
        (
            CanonicalOptions::default(),
            &exact as &dyn Fn(&Value, &Value) -> bool,
        ),
        (lossy, &same_double),
    ] {
        match to_canonical_with(&v, options) {
            Ok(text) => {
                let w = parse_str(&text).expect("canonical output parses");
                assert!(same_shape(&v, &w, same_number), "canonical changed a value");
                assert_eq!(to_canonical_with(&w, options).as_deref(), Ok(text.as_str()));
            }
            Err(e) => {
                if options.allow_lossy_numbers {
                    assert_eq!(e.kind(), CanonicalErrorKind::NumberOutOfRange);
                }
            }
        }
    }
});
