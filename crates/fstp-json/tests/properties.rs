//! Property tests with the in-house harness (fstp-prop).
//!
//! Round trips through every serializer, canonical idempotence and member
//! order independence, exact integers, every string, duplicate names, and
//! parser robustness on mutated documents (TH-26).

#![allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use std::collections::BTreeMap;

use common::documented_estimate;
use fstp_json::{
    Array, CanonicalErrorKind, CanonicalOptions, Decimal, FromJson, Limit, NdjsonReader,
    NdjsonWriter, Number, Object, ParseErrorKind, ParseLimits, ToJson, Value, WriteOptions,
    json_struct, parse, parse_str, parse_with, to_canonical, to_canonical_with, to_compact,
    to_pretty, to_string_with,
};
use fstp_prop::{Config, Gen, check_with, prop_assert, prop_assert_eq};

/// Cases per property. `FSTP_PROP_CASES` still overrides it.
const CASES: u32 = 1000;

#[track_caller]
fn check<F: Fn(&mut Gen) -> Result<(), String>>(name: &str, prop: F) {
    check_with(name, Config::default().with_cases(CASES), prop);
}

const LOSSY: CanonicalOptions = CanonicalOptions {
    allow_lossy_numbers: true,
};

const KEYS: &[&str] = &[
    "",
    "a",
    "b",
    "A",
    "id",
    "\u{e9}",
    "e\u{301}",
    "\u{80}",
    "\u{20ac}",
    "\u{1F600}",
    "\u{fb33}",
    "\u{FFFF}",
    "\u{10000}",
    "\r",
    "\u{0}",
    "\"",
    "\\",
    "</script>",
    "\u{2028}",
];

fn gen_string(g: &mut Gen) -> String {
    if g.weighted(&[3, 1]) == 0 {
        g.string(0..=12)
    } else {
        g.vec(0..=8, |g| {
            *g.pick(&[
                '\u{0}',
                '\u{1f}',
                '"',
                '\\',
                '\u{7f}',
                '\u{2028}',
                '\u{FFFF}',
                '\u{10000}',
                '\u{10FFFF}',
                '\u{D7FF}',
                '\u{E000}',
            ])
        })
        .into_iter()
        .collect()
    }
}

fn gen_key(g: &mut Gen) -> String {
    if g.bool() {
        (*g.pick(KEYS)).to_owned()
    } else {
        gen_string(g)
    }
}

fn digits(g: &mut Gen, out: &mut String, len: std::ops::RangeInclusive<usize>) {
    for d in g.vec(len, |g| g.u8_in(0..=9)) {
        out.push(char::from(b'0' + d));
    }
}

/// Any valid number lexeme.
fn gen_lexeme(g: &mut Gen) -> String {
    let mut s = String::new();
    if g.bool() {
        s.push('-');
    }
    if g.bool() {
        s.push('0');
    } else {
        s.push(char::from(b'0' + g.u8_in(1..=9)));
        digits(g, &mut s, 0..=22);
    }
    if g.bool() {
        s.push('.');
        digits(g, &mut s, 1..=22);
    }
    if g.bool() {
        s.push(*g.pick(&['e', 'E']));
        if let Some(sign) = g.option(|g| *g.pick(&['+', '-'])) {
            s.push(sign);
        }
        digits(g, &mut s, 1..=3);
    }
    s
}

fn finite_double(g: &mut Gen) -> f64 {
    let x = f64::from_bits(g.u64());
    if x.is_finite() { x } else { 0.5 }
}

fn gen_number(g: &mut Gen) -> Number {
    match g.weighted(&[2, 2, 2, 3]) {
        0 => Number::from(g.i64()),
        1 => Number::from(g.u64()),
        2 => Number::from_f64(finite_double(g)).unwrap_or_else(|| Number::from(0)),
        _ => Number::from_lexeme(&gen_lexeme(g)).unwrap_or_else(|e| panic!("generator bug: {e}")),
    }
}

/// A number already in RFC 8785 form, so canonical output keeps its lexeme.
fn gen_canonical_number(g: &mut Gen) -> Number {
    if g.bool() {
        Number::from(g.i64_in(-(1 << 53)..=(1 << 53)))
    } else {
        Number::from_f64(finite_double(g)).unwrap_or_else(|| Number::from(0))
    }
}

fn gen_tree(g: &mut Gen, depth: u32, number: fn(&mut Gen) -> Number) -> Value {
    let weights: &[u32] = if depth == 0 {
        &[1, 2, 3, 3, 0, 0]
    } else {
        &[1, 1, 2, 2, 4, 4]
    };
    match g.weighted(weights) {
        0 => Value::Null,
        1 => Value::Bool(g.bool()),
        2 => Value::Number(number(g)),
        3 => Value::String(gen_string(g)),
        4 => Value::Array(
            g.vec(0..=8, |g| gen_tree(g, depth - 1, number))
                .into_iter()
                .collect::<Array>(),
        ),
        _ => {
            let mut o = Object::new();
            for (k, v) in g.vec(0..=12, |g| (gen_key(g), gen_tree(g, depth - 1, number))) {
                o.insert(k, v);
            }
            Value::Object(o)
        }
    }
}

fn gen_value(g: &mut Gen) -> Value {
    let v = gen_tree(g, 4, gen_number);
    g.note("value", &v);
    v
}

fn gen_canonical_value(g: &mut Gen) -> Value {
    let v = gen_tree(g, 4, gen_canonical_number);
    g.note("value", &v);
    v
}

/// Rebuilds `v` with every object's members in a generated order.
fn shuffle_members(g: &mut Gen, v: &Value) -> Value {
    match v {
        Value::Array(a) => Value::Array(a.iter().map(|x| shuffle_members(g, x)).collect()),
        Value::Object(o) => {
            let mut members: Vec<(String, Value)> = o
                .iter()
                .map(|(k, x)| (k.to_owned(), shuffle_members(g, x)))
                .collect();
            g.shuffle(&mut members);
            Value::Object(members.into_iter().collect())
        }
        other => other.clone(),
    }
}

/// Writes `s` as a JSON string with every UTF-16 code unit as a `\u` escape,
/// in random letter case.
fn fully_escaped(g: &mut Gen, s: &str) -> String {
    let mut out = String::from("\"");
    for unit in s.encode_utf16() {
        if g.bool() {
            out.push_str(&format!("\\u{unit:04x}"));
        } else {
            out.push_str(&format!("\\u{unit:04X}"));
        }
    }
    out.push('"');
    out
}

fn reparse(text: &str) -> Result<Value, String> {
    parse_str(text).map_err(|e| format!("{e} in {text:?}"))
}

/// TH-26: compact output parses back to an identical tree, byte-stably.
#[test]
fn th26_compact_round_trip() {
    check("compact_round_trip", |g| {
        let v = gen_value(g);
        let text = to_compact(&v);
        let back = reparse(&text)?;
        prop_assert!(back.identical(&v), "{text}");
        prop_assert_eq!(to_compact(&back), text);
        Ok(())
    });
}

#[test]
fn pretty_and_html_safe_round_trip() {
    check("pretty_and_html_safe_round_trip", |g| {
        let v = gen_value(g);
        for options in [
            WriteOptions::pretty(),
            WriteOptions::compact().html_safe(),
            WriteOptions::pretty().html_safe(),
            WriteOptions {
                indent: Some(g.u8_in(0..=8)),
                escape_html: g.bool(),
            },
        ] {
            let text = to_string_with(&v, options);
            prop_assert!(reparse(&text)?.identical(&v), "{text}");
            if options.escape_html {
                prop_assert!(
                    !text.contains(['<', '>', '&', '\u{2028}', '\u{2029}']),
                    "{text}"
                );
            }
        }
        prop_assert_eq!(to_pretty(&v), to_string_with(&v, WriteOptions::pretty()));
        Ok(())
    });
}

/// Canonical output parses back to an equal value when the numbers are
/// already canonical, and canonicalizing again changes nothing.
#[test]
fn canonical_round_trip() {
    check("canonical_round_trip", |g| {
        let v = gen_canonical_value(g);
        let text = to_canonical(&v).map_err(|e| e.to_string())?;
        let back = reparse(&text)?;
        prop_assert_eq!(back, v);
        prop_assert_eq!(to_canonical(&back).map_err(|e| e.to_string())?, text);
        prop_assert!(text.bytes().all(|b| b >= 0x20), "raw control character");
        Ok(())
    });
}

/// For any value, canonical output is a fixed point, also under strict mode,
/// and strict mode agrees with lossy mode whenever it succeeds.
#[test]
fn canonical_is_idempotent() {
    check("canonical_is_idempotent", |g| {
        let v = gen_value(g);
        let strict = to_canonical(&v);
        match to_canonical_with(&v, LOSSY) {
            Ok(text) => {
                let back = reparse(&text)?;
                prop_assert_eq!(to_canonical_with(&back, LOSSY).ok(), Some(text.clone()));
                prop_assert_eq!(to_canonical(&back).ok(), Some(text.clone()));
                if let Ok(s) = &strict {
                    prop_assert_eq!(s, &text);
                }
            }
            Err(e) => {
                prop_assert_eq!(e.kind(), CanonicalErrorKind::NumberOutOfRange);
                prop_assert!(strict.is_err());
            }
        }
        Ok(())
    });
}

#[test]
fn canonical_is_independent_of_member_order() {
    check("canonical_is_independent_of_member_order", |g| {
        let v = gen_value(g);
        let shuffled = shuffle_members(g, &v);
        prop_assert!(shuffled == v);
        prop_assert_eq!(
            to_canonical_with(&v, LOSSY),
            to_canonical_with(&shuffled, LOSSY)
        );
        Ok(())
    });
}

#[test]
fn i64_round_trips_exactly() {
    check("i64_round_trips_exactly", |g| {
        let i = g.i64();
        let v = Value::from(i);
        let back = reparse(&to_compact(&v))?;
        prop_assert_eq!(back.as_i64(), Some(i));
        prop_assert_eq!(i64::from_json(&back), Ok(i));
        prop_assert_eq!(i128::from_json(&back), Ok(i128::from(i)));
        match to_canonical(&v) {
            Ok(text) => prop_assert_eq!(reparse(&text)?.as_i64(), Some(i)),
            Err(e) => {
                prop_assert_eq!(e.kind(), CanonicalErrorKind::LossyNumber);
                prop_assert!(i.unsigned_abs() > 1 << 53, "{i} should be exact");
            }
        }
        Ok(())
    });
}

#[test]
fn u64_round_trips_exactly() {
    check("u64_round_trips_exactly", |g| {
        let u = g.u64();
        let v = u.to_json();
        let back = reparse(&to_compact(&v))?;
        prop_assert_eq!(back.as_u64(), Some(u));
        prop_assert_eq!(u64::from_json(&back), Ok(u));
        prop_assert_eq!(back.as_i64(), i64::try_from(u).ok());
        match to_canonical(&v) {
            Ok(text) => prop_assert_eq!(reparse(&text)?.as_u64(), Some(u)),
            Err(e) => {
                prop_assert_eq!(e.kind(), CanonicalErrorKind::LossyNumber);
                prop_assert!(u > 1 << 53, "{u} should be exact");
            }
        }
        Ok(())
    });
}

/// Every string, including control characters and characters outside the
/// BMP (surrogate pairs when escaped), survives every serializer and the
/// fully escaped form, as a value and as a member name.
#[test]
fn every_string_round_trips() {
    check("every_string_round_trips", |g| {
        let s = gen_string(g);
        let v = Value::String(s.clone());
        let texts = [
            to_compact(&v),
            to_pretty(&v),
            to_string_with(&v, WriteOptions::compact().html_safe()),
            to_canonical(&v).map_err(|e| e.to_string())?,
            fully_escaped(g, &s),
        ];
        for text in texts {
            let back = reparse(&text)?;
            prop_assert_eq!(back.as_str(), Some(s.as_str()), "{text}");
        }
        let mut o = Object::new();
        o.insert(s.clone(), Value::Null);
        let o = Value::Object(o);
        for text in [to_compact(&o), to_canonical(&o).map_err(|e| e.to_string())?] {
            let back = reparse(&text)?;
            let keys: Vec<&str> = back
                .as_object()
                .map(|o| o.keys().collect())
                .unwrap_or_default();
            prop_assert_eq!(keys, vec![s.as_str()]);
        }
        Ok(())
    });
}

/// RFC 7493: the parser never accepts a repeated member name, however it is
/// spelled and wherever it sits.
#[test]
fn duplicate_names_are_never_accepted() {
    check("duplicate_names_are_never_accepted", |g| {
        let mut members: Vec<(String, Value)> = Vec::new();
        for (k, v) in g.vec(1..=12, |g| (gen_key(g), gen_tree(g, 1, gen_number))) {
            if !members.iter().any(|(m, _)| *m == k) {
                members.push((k, v));
            }
        }
        let original = g.usize_in(0..=members.len() - 1);
        let key = members[original].0.clone();
        let at = g.usize_in(0..=members.len());
        let value = gen_tree(g, 1, gen_number);
        members.insert(at, (key, value));
        let mut text = String::from("{");
        for (i, (k, v)) in members.iter().enumerate() {
            if i > 0 {
                text.push(',');
            }
            let name = if g.bool() {
                to_compact(&Value::String(k.clone()))
            } else {
                fully_escaped(g, k)
            };
            text.push_str(&name);
            text.push(':');
            text.push_str(&to_compact(v));
        }
        text.push('}');
        let text = match g.u8_in(0..=2) {
            0 => text,
            1 => format!("[1,{text}]"),
            _ => format!("{{\"wrap\":{{\"x\":{text}}}}}"),
        };
        g.note("text", &text);
        match parse_str(&text) {
            Ok(v) => Err(format!("accepted {v}")),
            Err(e) => {
                prop_assert_eq!(e.kind(), ParseErrorKind::DuplicateKey);
                Ok(())
            }
        }
    });
}

/// TH-26: the parser charges exactly the memory estimate that
/// `ParseLimits::max_memory_bytes` documents. A parse succeeds with the
/// estimate as the limit and fails with one byte less.
#[test]
fn th26_memory_estimate_is_exact() {
    check("memory_estimate_is_exact", |g| {
        let v = gen_value(g);
        let text = if g.bool() {
            to_compact(&v)
        } else {
            to_pretty(&v)
        };
        let cost = documented_estimate(&v);
        let at = |n: usize| ParseLimits::default().with_max_memory_bytes(n);
        let back = parse_with(text.as_bytes(), &at(cost))
            .map_err(|e| format!("{e} with limit {cost} in {text:?}"))?;
        prop_assert!(back.identical(&v), "{text}");
        match parse_with(text.as_bytes(), &at(cost - 1)) {
            Err(e) => prop_assert_eq!(e.kind(), ParseErrorKind::LimitExceeded(Limit::MemoryBytes)),
            Ok(_) => return Err(format!("accepted with limit {} in {text:?}", cost - 1)),
        }
        Ok(())
    });
}

/// TH-26: random edits of valid documents never panic; anything accepted
/// still round-trips; error positions stay inside the input.
#[test]
fn th26_mutated_documents_never_panic() {
    const BYTES: &[u8] = b"{}[],:\"\\0-19eE.+tfnu \t\n\r/*\x0c\x7f\xff\xc3\xa9\xed";
    check("mutated_documents_never_panic", |g| {
        let v = gen_value(g);
        let mut bytes = to_compact(&v).into_bytes();
        for _ in 0..g.usize_in(1..=4) {
            let byte = if g.bool() { *g.pick(BYTES) } else { g.u8() };
            let len = bytes.len();
            match g.u8_in(0..=2) {
                0 if len > 0 => {
                    let i = g.usize_in(0..=len - 1);
                    bytes[i] = byte;
                }
                1 => {
                    let i = g.usize_in(0..=len);
                    bytes.insert(i, byte);
                }
                _ if len > 0 => {
                    let i = g.usize_in(0..=len - 1);
                    bytes.remove(i);
                }
                _ => bytes.push(byte),
            }
        }
        g.note("bytes", &String::from_utf8_lossy(&bytes));
        match parse(&bytes) {
            Ok(w) => {
                let text = to_compact(&w);
                prop_assert!(reparse(&text)?.identical(&w));
                prop_assert!(std::str::from_utf8(&bytes).is_ok());
            }
            Err(e) => {
                prop_assert!(e.offset() <= bytes.len());
                prop_assert!(e.line() >= 1 && e.column() >= 1);
            }
        }
        Ok(())
    });
}

#[test]
fn ndjson_round_trip() {
    check("ndjson_round_trip", |g| {
        let values = g.vec(0..=6, gen_value);
        let mut w = NdjsonWriter::new(Vec::new());
        for v in &values {
            w.write_value(v).map_err(|e| e.to_string())?;
        }
        let mut out = w.into_inner();
        if g.bool() {
            let mut crlf = Vec::with_capacity(out.len());
            for b in out {
                if b == b'\n' {
                    crlf.push(b'\r');
                }
                crlf.push(b);
            }
            out = crlf;
        }
        if g.bool() && out.last() == Some(&b'\n') {
            out.pop();
            if out.last() == Some(&b'\r') {
                out.pop();
            }
        }
        let back: Vec<Value> = NdjsonReader::new(&out[..])
            .collect::<Result<_, _>>()
            .map_err(|e| e.to_string())?;
        prop_assert_eq!(back.len(), values.len());
        for (a, b) in back.iter().zip(&values) {
            prop_assert!(a.identical(b));
        }
        Ok(())
    });
}

#[derive(Debug, PartialEq, Clone)]
struct Record {
    id: u64,
    name: String,
    tags: Vec<String>,
    amount: Option<Decimal>,
    meta: BTreeMap<String, i32>,
    flag: Option<bool>,
    nested: Vec<Option<i8>>,
}
json_struct!(Record {
    required id,
    required name = "display name",
    required tags,
    optional amount,
    required meta,
    optional flag,
    required nested,
});

#[test]
fn typed_records_round_trip() {
    check("typed_records_round_trip", |g| {
        let r = Record {
            id: g.u64(),
            name: gen_string(g),
            tags: g.vec(0..=4, gen_string),
            amount: g.option(|g| Decimal::from_scaled_i128(i128::from(g.i64()), g.u32_in(0..=8))),
            meta: g
                .vec(0..=4, |g| (gen_key(g), g.i32()))
                .into_iter()
                .collect(),
            flag: g.option(Gen::bool),
            nested: g.vec(0..=4, |g| g.option(Gen::i8)),
        };
        g.note("record", &r);
        let text = to_compact(&r.to_json());
        let back = Record::from_json(&reparse(&text)?).map_err(|e| e.to_string())?;
        prop_assert_eq!(back, r);
        Ok(())
    });
}

#[test]
fn decimal_scaling_round_trips() {
    check("decimal_scaling_round_trips", |g| {
        let value = if g.bool() {
            i128::from(g.i64())
        } else {
            g.i64() as i128 * i128::from(g.i64())
        };
        let scale = g.u32_in(0..=20);
        let d = Decimal::from_scaled_i128(value, scale);
        prop_assert_eq!(d.to_scaled_i128(scale), Ok(value));
        let n = Number::from_decimal(&d);
        prop_assert_eq!(n.as_decimal(), Ok(d.clone()));
        prop_assert_eq!(Decimal::parse(&d.to_string()), Ok(d.clone()));
        let back = reparse(&to_compact(&d.to_json()))?;
        prop_assert_eq!(Decimal::from_json(&back), Ok(d));
        Ok(())
    });
}

#[test]
fn decimal_order_matches_exact_arithmetic() {
    check("decimal_order_matches_exact_arithmetic", |g| {
        let (a, sa) = (g.i64(), g.u32_in(0..=6));
        let (b, sb) = (g.i64(), g.u32_in(0..=6));
        let da = Decimal::from_scaled_i128(i128::from(a), sa);
        let db = Decimal::from_scaled_i128(i128::from(b), sb);
        // a / 10^sa against b / 10^sb, cross-multiplied in i128.
        let lhs = i128::from(a) * 10i128.pow(sb);
        let rhs = i128::from(b) * 10i128.pow(sa);
        prop_assert_eq!(da.cmp(&db), lhs.cmp(&rhs));
        prop_assert_eq!(da == db, lhs == rhs);
        Ok(())
    });
}

#[test]
fn from_f64_round_trips_through_the_lossy_accessor() {
    check("from_f64_round_trips", |g| {
        let x = f64::from_bits(g.u64());
        let Some(n) = Number::from_f64(x) else {
            prop_assert!(!x.is_finite());
            return Ok(());
        };
        let back = n.as_f64_lossy();
        if x == 0.0 {
            prop_assert_eq!(n.as_str(), "0");
        } else {
            prop_assert_eq!(back.to_bits(), x.to_bits(), "{}", n.as_str());
        }
        let v = Value::Number(n.clone());
        prop_assert_eq!(to_canonical(&v).ok(), Some(n.as_str().to_owned()));
        Ok(())
    });
}

/// The object index agrees with a plain list model under random edits that
/// cross the linear-scan threshold.
#[test]
fn object_matches_a_list_model() {
    check("object_matches_a_list_model", |g| {
        let mut object = Object::new();
        let mut model: Vec<(String, Value)> = Vec::new();
        for _ in 0..g.usize_in(0..=60) {
            let key = format!("k{}", g.u8_in(0..=24));
            if g.weighted(&[3, 1]) == 0 {
                let value = Value::from(g.u32());
                let old = object.insert(key.clone(), value.clone());
                let model_old = match model.iter_mut().find(|(k, _)| *k == key) {
                    Some(slot) => Some(std::mem::replace(&mut slot.1, value)),
                    None => {
                        model.push((key, value));
                        None
                    }
                };
                prop_assert_eq!(old, model_old);
            } else {
                let removed = object.remove(&key);
                let model_removed = model
                    .iter()
                    .position(|(k, _)| *k == key)
                    .map(|i| model.remove(i).1);
                prop_assert_eq!(removed, model_removed);
            }
        }
        let keys: Vec<&str> = object.keys().collect();
        let model_keys: Vec<&str> = model.iter().map(|(k, _)| k.as_str()).collect();
        prop_assert_eq!(keys, model_keys);
        for i in 0..=24 {
            let key = format!("k{i}");
            let expected = model.iter().find(|(k, _)| *k == key).map(|(_, v)| v);
            prop_assert_eq!(object.get(&key), expected);
        }
        Ok(())
    });
}
