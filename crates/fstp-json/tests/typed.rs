//! `ToJson`, `FromJson`, `json!` and `json_struct!`.

#![allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::BTreeMap;

use fstp_json::{
    Decimal, FromJson, FromJsonError, FromJsonErrorKind as K, Number, Object, ToJson, Value, json,
    json_struct, parse_str,
};

fn p(s: &str) -> Value {
    parse_str(s).unwrap_or_else(|e| panic!("{s:?}: {e}"))
}

fn kind<T: FromJson + std::fmt::Debug>(v: &Value) -> K {
    match T::from_json(v) {
        Ok(t) => panic!("{v} mapped to {t:?}"),
        Err(e) => e.kind().clone(),
    }
}

#[derive(Debug, PartialEq, Clone)]
struct Call {
    id: u64,
    title: String,
    deadline: Option<String>,
    budget: Option<Decimal>,
    note: Option<String>,
}
json_struct!(Call {
    required id,
    required title = "name",
    optional deadline,
    optional budget,
    required note,
});

#[derive(Debug, PartialEq)]
struct Programme {
    calls: Vec<Call>,
    tags: BTreeMap<String, u8>,
}
json_struct!(Programme { required calls, required tags });

#[derive(Debug, PartialEq)]
struct Lenient {
    id: u64,
}
json_struct!(Lenient allow_unknown { required id });

fn call(id: u64) -> Value {
    json!({"id": id, "name": format!("Call {id}"), "note": null})
}

#[test]
fn booleans_and_strings() {
    assert_eq!(bool::from_json(&json!(true)), Ok(true));
    assert_eq!(String::from_json(&json!("x")), Ok("x".to_owned()));
    assert_eq!(
        kind::<bool>(&json!(1)),
        K::WrongType {
            expected: "a boolean",
            found: "number"
        }
    );
    assert_eq!(
        kind::<String>(&json!(null)),
        K::WrongType {
            expected: "a string",
            found: "null"
        }
    );
    assert_eq!("x".to_json(), json!("x"));
    assert_eq!(true.to_json(), Value::Bool(true));
}

#[test]
fn integers_are_exact_and_range_checked() {
    assert_eq!(u8::from_json(&json!(255)), Ok(255));
    assert_eq!(kind::<u8>(&json!(256)), K::OutOfRange { target: "u8" });
    assert_eq!(kind::<u8>(&json!(-1)), K::OutOfRange { target: "u8" });
    assert_eq!(i8::from_json(&json!(-128)), Ok(-128));
    assert_eq!(kind::<i8>(&json!(128)), K::OutOfRange { target: "i8" });
    assert_eq!(i64::from_json(&p("-9223372036854775808")), Ok(i64::MIN));
    assert_eq!(
        kind::<i64>(&p("9223372036854775808")),
        K::OutOfRange { target: "i64" }
    );
    assert_eq!(u64::from_json(&p("18446744073709551615")), Ok(u64::MAX));
    assert_eq!(
        kind::<u64>(&p("18446744073709551616")),
        K::OutOfRange { target: "u64" }
    );
    assert_eq!(
        u128::from_json(&p("340282366920938463463374607431768211455")),
        Ok(u128::MAX)
    );
    assert_eq!(
        i128::from_json(&p("-170141183460469231731687303715884105728")),
        Ok(i128::MIN)
    );
    assert_eq!(
        kind::<u128>(&p("340282366920938463463374607431768211456")),
        K::OutOfRange { target: "u128" }
    );
    assert_eq!(u32::from_json(&p("-0")), Ok(0));
    assert_eq!(kind::<u32>(&p("1.0")), K::NotAnInteger);
    assert_eq!(kind::<u32>(&p("1e2")), K::NotAnInteger);
    assert_eq!(
        kind::<u32>(&json!("1")),
        K::WrongType {
            expected: "an integer",
            found: "string"
        }
    );
    assert_eq!(u64::MAX.to_json().to_compact(), "18446744073709551615");
    assert_eq!(
        i128::MIN.to_json().to_compact(),
        "-170141183460469231731687303715884105728"
    );
    assert_eq!(usize::from_json(&json!(7usize)), Ok(7));
}

#[test]
fn collections_and_options() {
    assert_eq!(Vec::<u8>::from_json(&json!([1, 2, 3])), Ok(vec![1, 2, 3]));
    assert_eq!(Option::<u8>::from_json(&json!(null)), Ok(None));
    assert_eq!(Option::<u8>::from_json(&json!(4)), Ok(Some(4)));
    assert_eq!(None::<u8>.to_json(), Value::Null);
    let mut map = BTreeMap::new();
    map.insert("b".to_owned(), vec![true]);
    map.insert("a".to_owned(), vec![]);
    let v = map.to_json();
    assert_eq!(v.to_compact(), "{\"a\":[],\"b\":[true]}");
    assert_eq!(BTreeMap::<String, Vec<bool>>::from_json(&v), Ok(map));
    assert_eq!([1u8, 2].to_json(), json!([1, 2]));
    assert_eq!(Box::new(5u8).to_json(), json!(5));
    assert_eq!(Box::<u8>::from_json(&json!(5)), Ok(Box::new(5)));
    assert_eq!(Value::from_json(&json!({"a": 1})), Ok(json!({"a": 1})));
    assert_eq!(Object::from_json(&json!({"a": 1})).map(|o| o.len()), Ok(1));
}

#[test]
fn numbers_and_decimals_map_exactly() {
    let n = Number::from_json(&p("12.50")).unwrap();
    assert_eq!(n.as_str(), "12.50");
    let d = Decimal::from_json(&p("12.50")).unwrap();
    assert_eq!(d.to_scaled_i128(2), Ok(1250));
    assert_eq!(d.to_json().to_compact(), "12.5");
    assert_eq!(
        Decimal::from_json(&p("1e99999999999999999999"))
            .unwrap_err()
            .kind(),
        &K::Invalid("decimal exponent out of range")
    );
}

#[test]
fn errors_report_the_path() {
    let v = json!({"calls": [call(1), call(2), {"id": 3, "name": "x", "note": null, "deadline": 9}], "tags": {}});
    let e = Programme::from_json(&v).unwrap_err();
    assert_eq!(e.path().full(), "$.calls[2].deadline");
    assert_eq!(
        e.to_string(),
        "$.calls[2].deadline: expected a string, found number"
    );

    let v = json!({"calls": [call(1), {"id": 2, "note": null}], "tags": {}});
    let e = Programme::from_json(&v).unwrap_err();
    assert_eq!(e.kind(), &K::MissingField);
    assert_eq!(e.to_string(), "$.calls[1].name: missing required member");

    let v = json!({"calls": [], "tags": {"private name": 300}});
    let e = Programme::from_json(&v).unwrap_err();
    assert_eq!(e.kind(), &K::OutOfRange { target: "u8" });
    assert_eq!(e.path().full(), "$.tags[\"private name\"]");
    // Input-derived names are masked in Display and Debug (R-NF-02).
    assert_eq!(e.to_string(), "$.tags[*]: integer out of range for u8");
    assert!(!format!("{e:?}").contains("private"));
}

#[test]
fn unknown_members_are_rejected_by_default() {
    let v = json!({"calls": [], "tags": {}, "secret extra": 1});
    let e = Programme::from_json(&v).unwrap_err();
    assert_eq!(e.kind(), &K::UnknownField);
    assert_eq!(e.path().full(), "$[\"secret extra\"]");
    assert_eq!(e.to_string(), "$[*]: unknown member");

    let v =
        json!({"calls": [{"id": 1, "name": "a", "note": null, "title": "wrong name"}], "tags": {}});
    let e = Programme::from_json(&v).unwrap_err();
    assert_eq!(e.path().full(), "$.calls[0].title");

    assert_eq!(
        Lenient::from_json(&json!({"id": 1, "x": 2})),
        Ok(Lenient { id: 1 })
    );
    assert_eq!(Lenient { id: 1 }.to_json(), json!({"id": 1}));
}

#[test]
fn required_option_needs_presence_and_optional_allows_absence() {
    // `note` is required but may be null.
    let e = Call::from_json(&json!({"id": 1, "name": "a"})).unwrap_err();
    assert_eq!(e.path().full(), "$.note");
    let c =
        Call::from_json(&json!({"id": 1, "name": "a", "note": null, "deadline": null})).unwrap();
    assert_eq!(c.deadline, None);
    assert_eq!(c.note, None);
    // Optional `None` is omitted; required `None` is written as null.
    assert_eq!(
        c.to_json().to_compact(),
        "{\"id\":1,\"name\":\"a\",\"note\":null}"
    );
    let c = Call {
        id: 2,
        title: "b".to_owned(),
        deadline: Some("2026-12-01".to_owned()),
        budget: Some(Decimal::from_scaled_i128(15_000_050, 2)),
        note: Some("n".to_owned()),
    };
    let v = c.to_json();
    assert_eq!(
        v.to_compact(),
        "{\"id\":2,\"name\":\"b\",\"deadline\":\"2026-12-01\",\"budget\":150000.5,\"note\":\"n\"}"
    );
    assert_eq!(Call::from_json(&v), Ok(c));
}

#[test]
fn non_objects_are_wrong_type() {
    assert_eq!(
        kind::<Call>(&json!([1])),
        K::WrongType {
            expected: "an object",
            found: "array"
        }
    );
}

#[test]
fn json_macro_builds_every_shape() {
    let name = "dyn";
    let v = json!({
        "null": null,
        "t": true,
        "f": false,
        "n": -5,
        "s": "str",
        "arr": [null, true, false, 1, "x", [], {}, [[1]], {"k": [2]}],
        (name): name.len(),
        ("a".to_owned() + "b"): [(1 + 1), -3],
        "nested": {"deep": {"deeper": {}}},
    });
    assert_eq!(
        v.to_compact(),
        "{\"null\":null,\"t\":true,\"f\":false,\"n\":-5,\"s\":\"str\",\"arr\":[null,true,false,1,\"x\",[],{},[[1]],{\"k\":[2]}],\"dyn\":3,\"ab\":[2,-3],\"nested\":{\"deep\":{\"deeper\":{}}}}"
    );
    assert_eq!(json!(null), Value::Null);
    assert_eq!(json!([]), p("[]"));
    assert_eq!(json!({}), p("{}"));
    assert_eq!(json!([1, 2,]), p("[1,2]"));
    assert_eq!(json!({"a": 1,}), p("{\"a\":1}"));
    // A repeated name keeps its first position and takes the last value.
    assert_eq!(
        json!({"a": 1, "b": 2, "a": 3}).to_compact(),
        "{\"a\":3,\"b\":2}"
    );
    let inner = json!([1]);
    assert_eq!(json!({"x": inner}), p("{\"x\":[1]}"));
    let opt: Option<u8> = None;
    assert_eq!(json!([opt, Some(1u8)]), p("[null,1]"));
}

#[test]
fn custom_from_json_errors_compose() {
    #[derive(Debug)]
    struct Even(u8);
    impl FromJson for Even {
        fn from_json(v: &Value) -> Result<Even, FromJsonError> {
            let n = u8::from_json(v)?;
            if n % 2 == 0 {
                Ok(Even(n))
            } else {
                Err(FromJsonError::invalid("expected an even number"))
            }
        }
    }
    let e = Vec::<Even>::from_json(&json!([2, 4, 5])).unwrap_err();
    assert_eq!(e.to_string(), "$[2]: expected an even number");
    assert_eq!(Vec::<Even>::from_json(&json!([2])).map(|v| v[0].0), Ok(2));
}

/// Review finding json-struct-raw-ident: a field written as a raw identifier
/// maps to the member name without its `r#` prefix. Every Matrix event has a
/// `type` member, so `r#type` must read and write `"type"`. An explicit
/// `= "name"` stays verbatim.
#[test]
fn review_json_struct_raw_ident() {
    #[derive(Debug, PartialEq)]
    struct Event {
        r#type: String,
        r#ref: Option<String>,
        verbatim: u8,
    }
    json_struct!(Event {
        required r#type,
        optional r#ref,
        required verbatim = "r#x",
    });

    let event = Event {
        r#type: "m.room.message".to_owned(),
        r#ref: Some("a".to_owned()),
        verbatim: 1,
    };
    let text = r#"{"type":"m.room.message","ref":"a","r#x":1}"#;
    assert_eq!(event.to_json().to_compact(), text);
    assert_eq!(Event::from_json(&p(text)), Ok(event));

    // The stringified identifier itself is not a member name.
    assert_eq!(
        kind::<Event>(&p(r#"{"r#type":"x","r#x":1}"#)),
        K::UnknownField
    );
    let missing = Event::from_json(&p(r#"{"r#x":1}"#)).unwrap_err();
    assert_eq!(missing.kind(), &K::MissingField);
    assert_eq!(missing.path().to_string(), "$.type");
}
