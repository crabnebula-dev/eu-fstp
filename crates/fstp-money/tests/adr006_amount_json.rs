//! Amounts in JSON: always ADR-006 decimal strings, never JSON numbers
//! (ADR-006, `SPEC/schemas/README.md`, R-NF-02).

#![allow(
    clippy::arithmetic_side_effects,
    reason = "test references compute in wide integers"
)]

mod common;

use common::{
    Reference, amount_reference, canonical_amount_text, eur, format_two_decimals, in_range_minor,
    near_amount_text,
};
use fstp_json::{Array, Number, Object, ToJson, Value, parse, to_canonical};
use fstp_money::{Amount, Currency, amount_from_json};
use fstp_prop::{Config, Gen, check_with, prop_assert, prop_assert_eq};

/// Cases per property. `FSTP_PROP_CASES` still overrides it.
const CASES: u32 = 2_000;

#[track_caller]
fn check<F: Fn(&mut Gen) -> Result<(), String>>(name: &str, prop: F) {
    check_with(name, Config::default().with_cases(CASES), prop);
}

/// ADR-006: a JSON number is always refused, whatever its lexeme. The same
/// text as a JSON string is accepted exactly when it is canonical, so a
/// decoder that refuses everything fails this property.
#[test]
fn adr006_json_numbers_are_always_rejected() {
    check("adr006_json_numbers_are_always_rejected", |g| {
        let near = near_amount_text(g);
        let (canonical_text, _) = canonical_amount_text(g);
        // A text that is not a JSON number lexeme falls back to a canonical
        // amount text, which always is one.
        let (text, number) = match Number::from_lexeme(&near) {
            Ok(n) => (near, n),
            Err(_) => {
                let n = Number::from_lexeme(&canonical_text)
                    .map_err(|e| format!("{canonical_text:?} is not a lexeme: {e}"))?;
                (canonical_text, n)
            }
        };
        g.note("lexeme", &text);
        let as_number = amount_from_json(&Value::Number(number), Currency::Eur);
        prop_assert!(as_number.is_err(), "accepted the JSON number {text}");
        let as_string = amount_from_json(&Value::String(text.clone()), Currency::Eur);
        let canonical = matches!(amount_reference(&text), Reference::Accept(_));
        prop_assert_eq!(as_string.is_ok(), canonical);
        Ok(())
    });
}

/// ADR-006 names the JSON number `1234.50` as a rejected spelling. The JSON
/// string `"1234.50"` is the accepted form of the same amount.
#[test]
fn adr006_json_number_1234_50_is_rejected() {
    let number = parse(b"1234.50").expect("1234.50 is valid JSON");
    assert!(matches!(number, Value::Number(_)));
    let refused = amount_from_json(&number, Currency::Eur);
    assert!(
        refused.is_err(),
        "accepted the JSON number 1234.50: {refused:?}"
    );
    let string = parse(b"\"1234.50\"").expect("\"1234.50\" is valid JSON");
    let accepted = amount_from_json(&string, Currency::Eur).expect("the string form is accepted");
    assert_eq!(accepted.minor(), 123_450);
    assert_eq!(accepted.currency(), Currency::Eur);
}

/// ADR-006: `amount_from_json` on a JSON string agrees with `Amount::parse`
/// on its content and with the reference grammar, in both directions.
#[test]
fn adr006_amount_from_json_string_matches_the_grammar() {
    check("adr006_amount_from_json_string_matches_the_grammar", |g| {
        let text = near_amount_text(g);
        g.note("text", &text);
        let decoded = amount_from_json(&Value::String(text.clone()), Currency::Eur);
        match (decoded, amount_reference(&text)) {
            (Ok(a), Reference::Accept(v)) => {
                prop_assert_eq!(i128::from(a.minor()), v);
                prop_assert_eq!(Amount::parse(&text, Currency::Eur), Ok(a));
            }
            (Ok(a), other) => return Err(format!("accepted {a:?}; reference {other:?}")),
            (Err(e), Reference::Accept(v)) => {
                return Err(format!("refused a canonical text of value {v}: {e}"));
            }
            (Err(_), _) => {}
        }
        Ok(())
    });
}

/// ADR-006: only a JSON string can hold an amount. Null, booleans, arrays and
/// objects are refused, even when they wrap a canonical string.
#[test]
fn adr006_non_string_values_are_rejected() {
    let control = amount_from_json(&Value::String("1.00".to_owned()), Currency::Eur);
    assert!(
        control.is_ok(),
        "the control \"1.00\" was refused: {control:?}"
    );
    let array = Array::from(vec![Value::String("1.00".to_owned())]);
    let object = Object::from_members(vec![(
        "amount".to_owned(),
        Value::String("1.00".to_owned()),
    )])
    .expect("one member");
    let values = [
        Value::Null,
        Value::Bool(true),
        Value::Bool(false),
        Value::Number(Number::from(100u64)),
        Value::Number(Number::from_lexeme("1.00").expect("a valid lexeme")),
        Value::Array(array),
        Value::Object(object),
    ];
    for v in &values {
        let r = amount_from_json(v, Currency::Eur);
        assert!(r.is_err(), "accepted {}: {r:?}", v.type_name());
    }
}

/// ADR-006: `ToJson` always emits a JSON string, for every amount. For a
/// non-negative amount the string is the reference spelling, canonical JSON
/// keeps it unchanged, and `amount_from_json` decodes it back.
#[test]
fn adr006_to_json_always_emits_a_string() {
    check("adr006_to_json_always_emits_a_string", |g| {
        let minor = in_range_minor(g);
        g.note("minor", &minor);
        let a = eur(minor)?;
        let v = a.to_json();
        let Value::String(s) = &v else {
            return Err(format!("emitted a {}", v.type_name()));
        };
        if minor >= 0 {
            prop_assert_eq!(s, &format_two_decimals(minor.unsigned_abs()));
            let canonical = to_canonical(&v).map_err(|e| format!("canonical: {e:?}"))?;
            prop_assert_eq!(canonical, format!("\"{s}\""));
            prop_assert_eq!(amount_from_json(&v, Currency::Eur), Ok(a));
        }
        Ok(())
    });
}

/// R-NF-02: a refused JSON amount yields an error whose text holds no part
/// of the refused string.
#[test]
fn r_nf_02_amount_json_errors_hold_no_input_content() {
    let control = amount_from_json(&Value::String("12.34".to_owned()), Currency::Eur);
    assert!(
        control.is_ok(),
        "the control \"12.34\" was refused: {control:?}"
    );
    for text in ["98765.4", "1234.567", "secret 12.00", "-55555.55"] {
        let e = amount_from_json(&Value::String(text.to_owned()), Currency::Eur)
            .expect_err("a non-canonical text is refused");
        for shown in [e.to_string(), format!("{e:?}")] {
            let chars: Vec<char> = text.chars().collect();
            let leaked = chars
                .windows(4)
                .any(|w| shown.contains(&w.iter().collect::<String>()));
            assert!(!leaked, "{text:?}: error text {shown:?} leaks input");
        }
    }
}
