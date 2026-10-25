//! Compact, pretty, HTML-safe and RFC 8785 canonical serialization.

#![allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use fstp_json::{
    CanonicalErrorKind, CanonicalOptions, Number, Value, WriteOptions, json, parse_str,
    to_canonical, to_canonical_with, to_compact, to_pretty, to_string_with,
};

const LOSSY: CanonicalOptions = CanonicalOptions {
    allow_lossy_numbers: true,
};

fn p(s: &str) -> Value {
    parse_str(s).unwrap_or_else(|e| panic!("{s:?}: {e}"))
}

#[test]
fn compact_preserves_lexemes_order_and_bytes() {
    let doc = "{\"z\":[1.50,1E3,-0,0e-0,12345678901234567890123],\"a\":\"x\",\"m\":{}}";
    let v = p(doc);
    assert_eq!(to_compact(&v), doc);
    assert_eq!(to_compact(&p(&to_compact(&v))), doc);
    let spaced = "{ \"z\" : [ 1.50 , 1E3 , -0 , 0e-0 , 12345678901234567890123 ] , \"a\" : \"x\" , \"m\" : { } }";
    assert_eq!(to_compact(&p(spaced)), doc);
    assert_eq!(v.to_string(), doc);
    assert_eq!(format!("{v:?}"), doc);
}

#[test]
fn compact_never_emits_raw_control_characters() {
    let all: String = (0u32..0x20).filter_map(char::from_u32).collect();
    let out = to_compact(&Value::String(all.clone()));
    assert!(out.bytes().all(|b| b >= 0x20), "{out}");
    assert_eq!(
        out,
        "\"\\u0000\\u0001\\u0002\\u0003\\u0004\\u0005\\u0006\\u0007\\b\\t\\n\\u000b\\f\\r\\u000e\\u000f\\u0010\\u0011\\u0012\\u0013\\u0014\\u0015\\u0016\\u0017\\u0018\\u0019\\u001a\\u001b\\u001c\\u001d\\u001e\\u001f\""
    );
    assert_eq!(p(&out).as_str(), Some(all.as_str()));
}

#[test]
fn pretty_output_layout() {
    let v = p("{\"a\":1,\"b\":[1,{\"c\":[]}],\"d\":{},\"e\":\"x\"}");
    assert_eq!(
        to_pretty(&v),
        "{\n  \"a\": 1,\n  \"b\": [\n    1,\n    {\n      \"c\": []\n    }\n  ],\n  \"d\": {},\n  \"e\": \"x\"\n}"
    );
    let four = WriteOptions {
        indent: Some(4),
        escape_html: false,
    };
    assert_eq!(
        to_string_with(&p("[1,[2]]"), four),
        "[\n    1,\n    [\n        2\n    ]\n]"
    );
    let zero = WriteOptions {
        indent: Some(0),
        escape_html: false,
    };
    assert_eq!(
        to_string_with(&p("[1,{\"a\":2}]"), zero),
        "[\n1,\n{\n\"a\": 2\n}\n]"
    );
    assert_eq!(to_pretty(&p("[]")), "[]");
    assert_eq!(to_pretty(&p("7")), "7");
    assert_eq!(p(&to_pretty(&v)), v);
}

#[test]
fn html_safe_escaping_round_trips() {
    let v = json!({"x": "</script><!--&\u{2028}\u{2029}>"});
    let out = to_string_with(&v, WriteOptions::compact().html_safe());
    assert_eq!(
        out,
        "{\"x\":\"\\u003c/script\\u003e\\u003c!--\\u0026\\u2028\\u2029\\u003e\"}"
    );
    assert!(!out.contains('<') && !out.contains('>') && !out.contains('&'));
    assert!(!out.contains('\u{2028}') && !out.contains('\u{2029}'));
    assert_eq!(p(&out), v);
    let pretty = to_string_with(&v, WriteOptions::pretty().html_safe());
    assert!(!pretty.contains('<'));
    assert_eq!(p(&pretty), v);
    // Without the option these characters stay as they are.
    assert_eq!(
        to_compact(&v),
        "{\"x\":\"</script><!--&\u{2028}\u{2029}>\"}"
    );
}

/// RFC 8785 section 3.2.2 example. Its first number has more precision than
/// a double, so it needs lossy mode; strict mode reports its path.
#[test]
fn rfc8785_serialization_example() {
    let input = "{\n  \"numbers\": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],\n  \"string\": \"\\u20ac$\\u000F\\u000aA'\\u0042\\u0022\\u005c\\\\\\\"\\/\",\n  \"literals\": [null, true, false]\n}";
    let expected = "{\"literals\":[null,true,false],\"numbers\":[333333333.3333333,1e+30,4.5,0.002,1e-27],\"string\":\"\u{20ac}$\\u000f\\nA'B\\\"\\\\\\\\\\\"/\"}";
    let v = p(input);
    assert_eq!(to_canonical_with(&v, LOSSY).unwrap(), expected);
    let e = to_canonical(&v).unwrap_err();
    assert_eq!(e.kind(), CanonicalErrorKind::LossyNumber);
    assert_eq!(e.path().full(), "$.numbers[0]");
    assert_eq!(
        e.to_string(),
        "$[*][0]: number would change value in canonical form"
    );
}

/// RFC 8785 section 3.2.3 example: names sort by UTF-16 code units.
#[test]
fn rfc8785_sorting_example() {
    let input = "{\n  \"\\u20ac\": \"Euro Sign\",\n  \"\\r\": \"Carriage Return\",\n  \"\\ufb33\": \"Hebrew Letter Dalet With Dagesh\",\n  \"1\": \"One\",\n  \"\\ud83d\\ude00\": \"Emoji: Grinning Face\",\n  \"\\u0080\": \"Control\",\n  \"\\u00f6\": \"Latin Small Letter O With Diaeresis\"\n}";
    let expected = "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u{80}\":\"Control\",\"\u{f6}\":\"Latin Small Letter O With Diaeresis\",\"\u{20ac}\":\"Euro Sign\",\"\u{1F600}\":\"Emoji: Grinning Face\",\"\u{fb33}\":\"Hebrew Letter Dalet With Dagesh\"}";
    let out = to_canonical(&p(input)).unwrap();
    assert_eq!(out, expected);
    let keys: Vec<String> = p(&out)
        .as_object()
        .unwrap()
        .keys()
        .map(str::to_owned)
        .collect();
    assert_eq!(
        keys,
        [
            "\r",
            "1",
            "\u{80}",
            "\u{f6}",
            "\u{20ac}",
            "\u{1F600}",
            "\u{fb33}"
        ]
    );
}

#[test]
fn canonical_numbers() {
    let c = |lexeme: &str| to_canonical(&Value::Number(Number::from_lexeme(lexeme).unwrap()));
    for (input, output) in [
        ("0", "0"),
        ("-0", "0"),
        ("-0.0e5", "0"),
        ("1.0", "1"),
        ("100E-2", "1"),
        ("1.50", "1.5"),
        ("1E3", "1000"),
        ("1e21", "1e+21"),
        ("123e18", "123000000000000000000"),
        ("0.000001", "0.000001"),
        ("0.0000001", "1e-7"),
        ("-12.5e-10", "-1.25e-9"),
        ("9007199254740992", "9007199254740992"),
        ("1152921504606846976e3", "1.152921504606847e+21"),
    ] {
        let got = c(input);
        if input.starts_with("1152921504606846976") {
            assert_eq!(
                got.map_err(|e| e.kind()),
                Err(CanonicalErrorKind::LossyNumber)
            );
        } else {
            assert_eq!(got.as_deref(), Ok(output), "{input}");
        }
        let lossy = to_canonical_with(&Value::Number(Number::from_lexeme(input).unwrap()), LOSSY);
        assert_eq!(lossy.as_deref(), Ok(output), "lossy {input}");
    }
    // Integers beyond 2^53 change value unless exactly representable and
    // printed in full.
    for lossy in [
        "9007199254740993",
        "12345678901234567890",
        "0.30000000000000001",
        "1e-400",
    ] {
        assert_eq!(
            c(lossy).map_err(|e| e.kind()),
            Err(CanonicalErrorKind::LossyNumber),
            "{lossy}"
        );
    }
    for huge in ["1e400", "-1e400", "1e99999999999999999999"] {
        assert_eq!(
            c(huge).map_err(|e| e.kind()),
            Err(CanonicalErrorKind::NumberOutOfRange),
            "{huge}"
        );
        let v = Value::Number(Number::from_lexeme(huge).unwrap());
        assert_eq!(
            to_canonical_with(&v, LOSSY).map_err(|e| e.kind()),
            Err(CanonicalErrorKind::NumberOutOfRange)
        );
    }
    let tiny = Value::Number(Number::from_lexeme("1e-400").unwrap());
    assert_eq!(to_canonical_with(&tiny, LOSSY).as_deref(), Ok("0"));
}

#[test]
fn canonical_error_path_masks_input_names() {
    let v = p("{\"secret\":[1,{\"name\":1e999}]}");
    let e = to_canonical(&v).unwrap_err();
    assert_eq!(e.path().full(), "$.secret[1].name");
    assert_eq!(e.path().redacted(), "$[*][1][*]");
    assert!(!format!("{e} {e:?}").contains("secret"));
}

#[test]
fn canonical_output_is_independent_of_member_order_and_whitespace() {
    let a = p("{\"b\":{\"y\":1,\"x\":[true,{\"q\":null,\"p\":\"s\"}]},\"a\":[]}");
    let b = p(
        "{ \"a\" : [ ] , \"b\" : { \"x\" : [ true , { \"p\" : \"s\" , \"q\" : null } ] , \"y\" : 1.0 } }",
    );
    let expected = "{\"a\":[],\"b\":{\"x\":[true,{\"p\":\"s\",\"q\":null}],\"y\":1}}";
    assert_eq!(to_canonical(&a).unwrap(), expected);
    assert_eq!(to_canonical(&b).unwrap(), expected);
    assert_eq!(to_canonical(&p(expected)).unwrap(), expected);
}

#[test]
fn canonical_strings_use_jcs_escaping() {
    let v = Value::String(
        "\u{0}\u{8}\t\n\u{b}\u{c}\r\u{1f}\"\\/\u{7f}\u{80}\u{2028}<>&\u{10FFFF}".to_owned(),
    );
    assert_eq!(
        to_canonical(&v).unwrap(),
        "\"\\u0000\\b\\t\\n\\u000b\\f\\r\\u001f\\\"\\\\/\u{7f}\u{80}\u{2028}<>&\u{10FFFF}\""
    );
}

#[test]
fn display_and_methods_agree_with_functions() {
    let v = json!({"b": [1, "x"], "a": null});
    assert_eq!(v.to_compact(), to_compact(&v));
    assert_eq!(v.to_pretty(), to_pretty(&v));
    assert_eq!(v.to_canonical().unwrap(), "{\"a\":null,\"b\":[1,\"x\"]}");
}
