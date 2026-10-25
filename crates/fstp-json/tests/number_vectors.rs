//! RFC 8785 number formatting against node's `JSON.stringify`.
//!
//! `testdata/number-vectors.txt` comes from `testdata/gen-number-vectors.mjs`.
//! Each line pairs the bits of a double with node's output for it.

#![allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use fstp_json::{
    CanonicalErrorKind, CanonicalOptions, Decimal, Number, Value, to_canonical, to_canonical_with,
};

const VECTORS: &str = include_str!("../testdata/number-vectors.txt");

fn vectors() -> impl Iterator<Item = (u64, f64, &'static str)> {
    VECTORS.lines().map(|line| {
        let (hex, text) = line
            .split_once(' ')
            .unwrap_or_else(|| panic!("bad line {line:?}"));
        let bits = u64::from_str_radix(hex, 16).unwrap_or_else(|_| panic!("bad bits {hex}"));
        (bits, f64::from_bits(bits), text)
    })
}

#[test]
fn vector_file_is_large_and_well_formed() {
    let count = vectors().count();
    assert!(count > 15_000, "only {count} vectors");
    for (_, x, text) in vectors() {
        assert!(x.is_finite());
        assert!(
            Number::from_lexeme(text).is_ok(),
            "{text} is not a JSON number"
        );
    }
}

/// `Number::from_f64` writes exactly what ECMAScript writes.
#[test]
fn from_f64_matches_node() {
    let mut failures = Vec::new();
    for (bits, x, text) in vectors() {
        let ours = Number::from_f64(x).map(|n| n.as_str().to_owned());
        if ours.as_deref() != Some(text) {
            failures.push(format!("{bits:016x}: node {text}, ours {ours:?}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{} mismatches:\n{}",
        failures.len(),
        failures[..failures.len().min(20)].join("\n")
    );
}

/// Node's text reads back as the same double (negative zero aside).
#[test]
fn node_text_round_trips_through_the_lossy_accessor() {
    for (bits, x, text) in vectors() {
        let n = Number::from_lexeme(text).unwrap();
        let back = n.as_f64_lossy();
        if x == 0.0 {
            assert_eq!(back, 0.0);
        } else {
            assert_eq!(back.to_bits(), bits, "{text}");
        }
    }
}

/// The canonical serializer gives node's text for node's own text and for
/// other exact spellings of the same shortest decimal, in strict mode.
#[test]
fn canonical_serializer_matches_node_from_any_spelling() {
    for (_, x, text) in vectors() {
        let spellings = [
            text.to_owned(),
            format!("{x:e}"),
            format!("{x:E}"),
            format!("{x}"),
        ];
        for lexeme in spellings {
            let Ok(n) = Number::from_lexeme(&lexeme) else {
                continue;
            };
            let v = Value::Number(n);
            // Strict mode succeeds exactly when the spelling denotes the
            // same decimal as node's text. Rust's own spelling of an exact
            // tie picks the other candidate, which strict mode must reject.
            let strict = to_canonical(&v);
            if Decimal::parse(&lexeme) == Decimal::parse(text) {
                assert_eq!(strict.as_deref(), Ok(text), "from {lexeme}");
            } else {
                let kind = strict.map_err(|e| e.kind());
                assert_eq!(kind, Err(CanonicalErrorKind::LossyNumber), "from {lexeme}");
            }
            let lossy = to_canonical_with(
                &v,
                CanonicalOptions {
                    allow_lossy_numbers: true,
                },
            );
            assert_eq!(lossy.as_deref(), Ok(text), "lossy from {lexeme}");
        }
    }
}
