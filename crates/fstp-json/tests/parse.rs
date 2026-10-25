//! Grammar conformance of the parser (RFC 8259 with RFC 7493 restrictions).
//!
//! Each case was derived from the ABNF of RFC 8259 and the I-JSON rules of
//! RFC 7493, not from the behaviour of other libraries. Parser robustness is
//! threat TH-26.

#![allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use common::documented_estimate;
use fstp_json::{Limit, ParseErrorKind as K, ParseLimits, Value, parse, parse_with};

fn ok(input: &[u8]) -> Value {
    match parse(input) {
        Ok(v) => v,
        Err(e) => panic!("{:?} rejected: {e}", String::from_utf8_lossy(input)),
    }
}

fn err(input: &[u8]) -> (K, usize) {
    match parse(input) {
        Ok(v) => panic!("{:?} accepted as {v}", String::from_utf8_lossy(input)),
        Err(e) => (e.kind(), e.offset()),
    }
}

fn s(v: &Value) -> &str {
    v.as_str().unwrap_or_else(|| panic!("not a string: {v}"))
}

#[test]
fn any_value_may_be_top_level() {
    assert_eq!(ok(b"null"), Value::Null);
    assert_eq!(ok(b"true"), Value::Bool(true));
    assert_eq!(ok(b"false"), Value::Bool(false));
    assert_eq!(ok(b"-0").as_number().unwrap().as_str(), "-0");
    assert_eq!(s(&ok(b"\"\"")), "");
    assert!(ok(b"[]").as_array().unwrap().is_empty());
    assert!(ok(b"{}").as_object().unwrap().is_empty());
}

#[test]
fn only_four_whitespace_characters_are_allowed() {
    assert_eq!(ok(b" \t\n\r1\r\n\t "), Value::from(1));
    assert_eq!(ok(b"[ 1 , { \"a\" : 2 } ]").to_compact(), "[1,{\"a\":2}]");
    assert_eq!(err(b"\x0c1"), (K::InvalidWhitespace, 0));
    assert_eq!(err(b"1\x0b"), (K::InvalidWhitespace, 1));
    assert_eq!(err("\u{a0}1".as_bytes()), (K::InvalidWhitespace, 0));
    assert_eq!(err("[\u{feff}1]".as_bytes()), (K::InvalidWhitespace, 1));
    assert_eq!(err("[1,\u{2028}2]".as_bytes()), (K::InvalidWhitespace, 3));
    assert_eq!(err("[1\u{3000}]".as_bytes()), (K::InvalidWhitespace, 2));
    assert_eq!(err(b"\x001"), (K::UnexpectedCharacter, 0));
}

#[test]
fn byte_order_mark_is_rejected() {
    assert_eq!(err(b"\xEF\xBB\xBF1"), (K::ByteOrderMark, 0));
    assert_eq!(err(b"\xEF\xBB\xBF"), (K::ByteOrderMark, 0));
}

#[test]
fn empty_input_is_unexpected_end() {
    assert_eq!(err(b""), (K::UnexpectedEnd, 0));
    assert_eq!(err(b"   "), (K::UnexpectedEnd, 3));
    assert_eq!(err(b"["), (K::UnexpectedEnd, 1));
    assert_eq!(err(b"[1"), (K::UnexpectedEnd, 2));
    assert_eq!(err(b"[1,"), (K::UnexpectedEnd, 3));
    assert_eq!(err(b"{"), (K::UnexpectedEnd, 1));
    assert_eq!(err(b"{\"a\""), (K::UnexpectedEnd, 4));
    assert_eq!(err(b"{\"a\":"), (K::UnexpectedEnd, 5));
    assert_eq!(err(b"{\"a\":1"), (K::UnexpectedEnd, 6));
    assert_eq!(err(b"\"abc"), (K::UnexpectedEnd, 4));
    assert_eq!(err(b"\"\\"), (K::UnexpectedEnd, 2));
    assert_eq!(err(b"\"\\u12"), (K::UnexpectedEnd, 5));
}

#[test]
fn trailing_commas_are_rejected() {
    assert_eq!(err(b"[1,]"), (K::TrailingComma, 3));
    assert_eq!(err(b"[1, ]"), (K::TrailingComma, 4));
    assert_eq!(err(b"{\"a\":1,}"), (K::TrailingComma, 7));
    assert_eq!(err(b"[,1]"), (K::UnexpectedCharacter, 1));
    assert_eq!(err(b"[1,,2]"), (K::UnexpectedCharacter, 3));
    assert_eq!(err(b"{,}"), (K::ExpectedKey, 1));
}

#[test]
fn comments_are_rejected() {
    assert_eq!(err(b"// c\n1"), (K::Comment, 0));
    assert_eq!(err(b"1 /* c */"), (K::Comment, 2));
    assert_eq!(err(b"[1]//"), (K::Comment, 3));
    assert_eq!(err(b"[1, /* c */ 2]"), (K::Comment, 4));
    assert_eq!(err(b"{\"a\" /* c */ : 1}"), (K::Comment, 5));
    assert_eq!(err(b"# c\n1"), (K::UnexpectedCharacter, 0));
}

#[test]
fn only_true_false_and_null_are_literals() {
    for word in [
        "NaN",
        "Infinity",
        "nul",
        "True",
        "FALSE",
        "undefined",
        "tru",
    ] {
        assert_eq!(err(word.as_bytes()), (K::InvalidLiteral, 0), "{word}");
    }
    assert_eq!(err(b"-Infinity"), (K::InvalidLiteral, 1));
    assert_eq!(err(b"-NaN"), (K::InvalidLiteral, 1));
    assert_eq!(err(b"truee"), (K::TrailingCharacters, 4));
    assert_eq!(err(b"[nulll]"), (K::UnexpectedCharacter, 5));
}

#[test]
fn numbers_follow_the_grammar_exactly() {
    for good in [
        "0",
        "-0",
        "1",
        "-1",
        "123",
        "0.0",
        "0.5",
        "-0.5",
        "1e5",
        "1E5",
        "1e+5",
        "1e-5",
        "0e0",
        "1.5E-0010",
        "1e999999",
        "-1.0e-999999",
    ] {
        assert_eq!(ok(good.as_bytes()).as_number().unwrap().as_str(), good);
    }
    assert_eq!(err(b"01"), (K::LeadingZero, 1));
    assert_eq!(err(b"-01"), (K::LeadingZero, 2));
    assert_eq!(err(b"00"), (K::LeadingZero, 1));
    assert_eq!(err(b"[00]"), (K::LeadingZero, 2));
    assert_eq!(err(b"1."), (K::InvalidNumber, 2));
    assert_eq!(err(b"1.e5"), (K::InvalidNumber, 2));
    assert_eq!(err(b"1e"), (K::InvalidNumber, 2));
    assert_eq!(err(b"1e+"), (K::InvalidNumber, 3));
    assert_eq!(err(b"-"), (K::InvalidNumber, 1));
    assert_eq!(err(b"- 1"), (K::InvalidNumber, 1));
    assert_eq!(err(b".5"), (K::UnexpectedCharacter, 0));
    assert_eq!(err(b"+1"), (K::UnexpectedCharacter, 0));
    assert_eq!(err(b"0x1"), (K::TrailingCharacters, 1));
    assert_eq!(err(b"1.5.2"), (K::TrailingCharacters, 3));
    assert_eq!(err(b"1_000"), (K::TrailingCharacters, 1));
    assert_eq!(err(b"[1 2]"), (K::UnexpectedCharacter, 3));
}

#[test]
fn string_escapes_decode() {
    assert_eq!(
        s(&ok(b"\"\\\"\\\\\\/\\b\\f\\n\\r\\t\"")),
        "\"\\/\u{8}\u{c}\n\r\t"
    );
    assert_eq!(s(&ok(b"\"\\u0041\\u00e9\\u00E9\"")), "A\u{e9}\u{e9}");
    assert_eq!(s(&ok(b"\"\\ud83d\\ude00\"")), "\u{1F600}");
    assert_eq!(s(&ok(b"\"\\uD83D\\uDE00\"")), "\u{1F600}");
    assert_eq!(s(&ok(b"\"\\udbff\\udfff\"")), "\u{10FFFF}");
    assert_eq!(s(&ok(b"\"\\u0000\"")), "\u{0}");
    assert_eq!(s(&ok(b"\"\\uffff\"")), "\u{FFFF}");
    assert_eq!(
        s(&ok("\"\u{e9}\u{1F600}\u{7f}\u{2028}\"".as_bytes())),
        "\u{e9}\u{1F600}\u{7f}\u{2028}"
    );
}

#[test]
fn raw_control_characters_in_strings_are_rejected() {
    assert_eq!(err(b"\"a\nb\""), (K::ControlCharacter, 2));
    assert_eq!(err(b"\"\t\""), (K::ControlCharacter, 1));
    assert_eq!(err(b"\"\x00\""), (K::ControlCharacter, 1));
    assert_eq!(err(b"\"\x1f\""), (K::ControlCharacter, 1));
}

#[test]
fn invalid_escapes_are_rejected() {
    assert_eq!(err(b"\"\\x41\""), (K::InvalidEscape, 1));
    assert_eq!(err(b"\"\\'\""), (K::InvalidEscape, 1));
    assert_eq!(err(b"\"\\U0041\""), (K::InvalidEscape, 1));
    assert_eq!(err(b"\"\\u12\""), (K::InvalidEscape, 5));
    assert_eq!(err(b"\"\\uZZZZ\""), (K::InvalidEscape, 3));
    assert_eq!(err(b"\"\\u+123\""), (K::InvalidEscape, 3));
}

/// RFC 7493 section 2.1: no escapes of lone surrogates.
#[test]
fn lone_surrogate_escapes_are_rejected() {
    for input in [
        "\"\\ud800\"",
        "\"\\udc00\"",
        "\"\\udfff\"",
        "\"\\ud800\\u0041\"",
        "\"\\ud800\\ud800\"",
        "\"\\ude00\\ud83d\"",
        "\"\\ud800x\"",
        "\"\\ud800\\n\"",
        "\"\\ud800\\\"",
    ] {
        assert_eq!(err(input.as_bytes()), (K::LoneSurrogate, 1), "{input}");
    }
    assert_eq!(err(b"\"ab\\ud800\""), (K::LoneSurrogate, 3));
}

/// RFC 7493 section 2.1: the input must be valid UTF-8.
#[test]
fn invalid_utf8_is_rejected() {
    assert_eq!(err(b"\"\xff\""), (K::InvalidUtf8, 1));
    assert_eq!(err(b"\"\xc3\""), (K::InvalidUtf8, 1));
    assert_eq!(err(b"\"\xc3"), (K::InvalidUtf8, 1));
    assert_eq!(err(b"\"\xed\xa0\x80\""), (K::InvalidUtf8, 1));
    assert_eq!(err(b"\"\xc0\xaf\""), (K::InvalidUtf8, 1));
    assert_eq!(err(b"\"a\xf4\x90\x80\x80\""), (K::InvalidUtf8, 2));
    assert_eq!(err(b"\"\x80\""), (K::InvalidUtf8, 1));
    assert_eq!(err(b"\xff"), (K::UnexpectedCharacter, 0));
    assert_eq!(err("\u{e9}".as_bytes()), (K::UnexpectedCharacter, 0));
}

/// RFC 7493 section 2.3: member names must be unique.
#[test]
fn duplicate_member_names_are_rejected() {
    assert_eq!(err(b"{\"a\":1,\"a\":2}"), (K::DuplicateKey, 7));
    assert_eq!(err(b"{\"a\":1,\"b\":2,\"a\":3}"), (K::DuplicateKey, 13));
    assert_eq!(err(b"{\"a\":1,\"\\u0061\":2}"), (K::DuplicateKey, 7));
    assert_eq!(err(b"{\"\":1,\"\":2}"), (K::DuplicateKey, 6));
    assert_eq!(
        err(b"[{},{\"x\":{\"y\":1,\"y\":1}}]"),
        (K::DuplicateKey, 16)
    );
    // The same name in different objects is fine.
    assert_eq!(
        ok(b"{\"a\":{\"a\":1},\"b\":{\"a\":2}}").to_compact(),
        "{\"a\":{\"a\":1},\"b\":{\"a\":2}}"
    );
    // Names that differ only in case or normalization are distinct.
    assert!(parse("{\"a\":1,\"A\":2,\"\u{e9}\":3,\"e\u{301}\":4}".as_bytes()).is_ok());
}

#[test]
fn duplicate_detection_holds_in_large_objects() {
    let mut doc = String::from("{");
    for i in 0..5000 {
        doc.push_str(&format!("\"k{i}\":{i},"));
    }
    doc.push_str("\"k4321\":0}");
    let (kind, offset) = err(doc.as_bytes());
    assert_eq!(kind, K::DuplicateKey);
    assert_eq!(&doc[offset..offset + 7], "\"k4321\"");
}

#[test]
fn object_members_need_string_names_and_colons() {
    assert_eq!(err(b"{a:1}"), (K::ExpectedKey, 1));
    assert_eq!(err(b"{'a':1}"), (K::ExpectedKey, 1));
    assert_eq!(err(b"{1:1}"), (K::ExpectedKey, 1));
    assert_eq!(err(b"{\"a\" 1}"), (K::ExpectedColon, 5));
    assert_eq!(err(b"{\"a\"=1}"), (K::ExpectedColon, 4));
    assert_eq!(err(b"{\"a\":1 \"b\":2}"), (K::UnexpectedCharacter, 7));
    assert_eq!(err(b"['a']"), (K::UnexpectedCharacter, 1));
}

#[test]
fn trailing_data_is_rejected() {
    assert_eq!(err(b"1 2"), (K::TrailingCharacters, 2));
    assert_eq!(err(b"{}}"), (K::TrailingCharacters, 2));
    assert_eq!(err(b"[]]"), (K::TrailingCharacters, 2));
    assert_eq!(err(b"[1]x"), (K::TrailingCharacters, 3));
    assert_eq!(err(b"\"a\"\"b\""), (K::TrailingCharacters, 3));
    assert_eq!(err(b"1\n\x0c"), (K::InvalidWhitespace, 2));
}

#[test]
fn errors_report_line_and_column() {
    let e = parse(b"{\n  \"a\": 1,\n  \"a\": 2\n}").unwrap_err();
    assert_eq!(
        (e.kind(), e.line(), e.column(), e.offset()),
        (K::DuplicateKey, 3, 3, 14)
    );
    let e = parse(b"[\n1,\n]").unwrap_err();
    assert_eq!((e.kind(), e.line(), e.column()), (K::TrailingComma, 3, 1));
    // Columns count code points, not bytes.
    let e = parse("[\"\u{e9}\", x]".as_bytes()).unwrap_err();
    assert_eq!((e.offset(), e.line(), e.column()), (7, 1, 7));
    // A carriage return alone does not start a line.
    let e = parse(b"[1,\r2,\r\n,]").unwrap_err();
    assert_eq!((e.line(), e.column()), (2, 1));
    let shown = e.to_string();
    assert_eq!(shown, "unexpected character at line 2, column 1 (byte 8)");
}

#[test]
fn error_messages_never_echo_input() {
    for input in [
        &b"{\"secret-name\":1,\"secret-name\":2}"[..],
        b"\"secret\\q\"",
        b"[secret]",
        b"{\"secret\" secret}",
    ] {
        let e = parse(input).unwrap_err();
        let shown = format!("{e} {e:?}");
        assert!(!shown.contains("secret"), "R-NF-02: {shown}");
    }
}

#[test]
fn depth_limit_is_enforced() {
    let limits = ParseLimits::default().with_max_depth(3);
    assert!(parse_with(b"[[[1]]]", &limits).is_ok());
    assert!(parse_with(b"[[[]]]", &limits).is_ok());
    let e = parse_with(b"[[[[1]]]]", &limits).unwrap_err();
    assert_eq!((e.kind(), e.offset()), (K::LimitExceeded(Limit::Depth), 3));
    let e = parse_with(b"{\"a\":{\"b\":{\"c\":{}}}}", &limits).unwrap_err();
    assert_eq!((e.kind(), e.offset()), (K::LimitExceeded(Limit::Depth), 15));
    let zero = ParseLimits::default().with_max_depth(0);
    assert!(parse_with(b"1", &zero).is_ok());
    assert_eq!(
        parse_with(b"[]", &zero).unwrap_err().kind(),
        K::LimitExceeded(Limit::Depth)
    );
}

#[test]
fn default_depth_limit_is_128() {
    let at = |depth: usize| format!("{}{}", "[".repeat(depth), "]".repeat(depth));
    assert!(parse(at(128).as_bytes()).is_ok());
    let e = parse(at(129).as_bytes()).unwrap_err();
    assert_eq!(
        (e.kind(), e.offset()),
        (K::LimitExceeded(Limit::Depth), 128)
    );
    assert_eq!(ParseLimits::default().max_depth, 128);
}

#[test]
fn input_size_limit_is_enforced() {
    let limits = ParseLimits::default().with_max_input_bytes(5);
    assert!(parse_with(b"12345", &limits).is_ok());
    let e = parse_with(b"123456", &limits).unwrap_err();
    assert_eq!(
        (e.kind(), e.offset()),
        (K::LimitExceeded(Limit::InputBytes), 5)
    );
}

#[test]
fn string_length_limit_counts_decoded_bytes() {
    let limits = ParseLimits::default().with_max_string_bytes(3);
    assert!(parse_with(b"\"abc\"", &limits).is_ok());
    assert!(parse_with(b"\"\\u00e9a\"", &limits).is_ok());
    let e = parse_with(b"\"abcd\"", &limits).unwrap_err();
    assert_eq!(
        (e.kind(), e.offset()),
        (K::LimitExceeded(Limit::StringBytes), 0)
    );
    let e = parse_with(b"\"\\u00e9\\u00e9\"", &limits).unwrap_err();
    assert_eq!(e.kind(), K::LimitExceeded(Limit::StringBytes));
    let e = parse_with(b"{\"abcd\":1}", &limits).unwrap_err();
    assert_eq!(
        (e.kind(), e.offset()),
        (K::LimitExceeded(Limit::StringBytes), 1)
    );
}

#[test]
fn number_length_limit_is_enforced() {
    let limits = ParseLimits::default().with_max_number_len(3);
    assert!(parse_with(b"123", &limits).is_ok());
    assert!(parse_with(b"-12", &limits).is_ok());
    let e = parse_with(b"[1,-123]", &limits).unwrap_err();
    assert_eq!(
        (e.kind(), e.offset()),
        (K::LimitExceeded(Limit::NumberLength), 3)
    );
    assert!(parse_with(b"1.5e1", &limits).is_err());
}

#[test]
fn container_length_limit_is_enforced() {
    let limits = ParseLimits::default().with_max_container_len(2);
    assert!(parse_with(b"[1,2]", &limits).is_ok());
    assert!(parse_with(b"[[1,2],[3,4]]", &limits).is_ok());
    let e = parse_with(b"[1,2,3]", &limits).unwrap_err();
    assert_eq!(
        (e.kind(), e.offset()),
        (K::LimitExceeded(Limit::ContainerLength), 5)
    );
    let e = parse_with(b"{\"a\":1,\"b\":2,\"c\":3}", &limits).unwrap_err();
    assert_eq!(
        (e.kind(), e.offset()),
        (K::LimitExceeded(Limit::ContainerLength), 13)
    );
}

#[test]
fn node_limit_is_enforced() {
    let limits = ParseLimits::default().with_max_nodes(3);
    assert!(parse_with(b"[1,2]", &limits).is_ok());
    assert!(parse_with(b"{\"a\":[]}", &limits).is_ok());
    let e = parse_with(b"[1,2,3]", &limits).unwrap_err();
    assert_eq!((e.kind(), e.offset()), (K::LimitExceeded(Limit::Nodes), 5));
}

#[test]
fn memory_limit_is_enforced() {
    // `[0]`: two values at 64 bytes each and a one-byte lexeme.
    let at = |n: usize| ParseLimits::default().with_max_memory_bytes(n);
    assert!(parse_with(b"[0]", &at(129)).is_ok());
    let e = parse_with(b"[0]", &at(128)).unwrap_err();
    assert_eq!(
        (e.kind(), e.offset()),
        (K::LimitExceeded(Limit::MemoryBytes), 1)
    );
    // An object, a member name, its two bytes, a value and its three bytes.
    let doc = b"{\"ab\":\"xyz\"}";
    assert!(parse_with(doc, &at(197)).is_ok());
    let e = parse_with(doc, &at(196)).unwrap_err();
    assert_eq!(
        (e.kind(), e.offset()),
        (K::LimitExceeded(Limit::MemoryBytes), 6)
    );
    // The name is charged before the member is complete.
    let e = parse_with(doc, &at(129)).unwrap_err();
    assert_eq!(
        (e.kind(), e.offset()),
        (K::LimitExceeded(Limit::MemoryBytes), 1)
    );
    // A long string fails before it is fully decoded.
    let long = format!("\"{}\"", "x".repeat(1000));
    let e = parse_with(long.as_bytes(), &at(500)).unwrap_err();
    assert_eq!(
        (e.kind(), e.offset()),
        (K::LimitExceeded(Limit::MemoryBytes), 0)
    );
    // The ninth member builds the hash index: 128 bytes plus 80 per member.
    let nine = ok(b"{\"a\":0,\"b\":0,\"c\":0,\"d\":0,\"e\":0,\"f\":0,\"g\":0,\"h\":0,\"i\":0}");
    let cost = 64 + 9 * (64 + 1 + 64 + 1) + 128 + 9 * 80;
    assert_eq!(documented_estimate(&nine), cost);
    let text = nine.to_compact();
    assert!(parse_with(text.as_bytes(), &at(cost)).is_ok());
    assert!(parse_with(text.as_bytes(), &at(cost - 1)).is_err());
    assert_eq!(ParseLimits::default().max_memory_bytes, 32 << 20);
}

/// `total` copies of `item` in sub-arrays of at most 99 000, which keeps
/// every container inside the default length limit.
fn chunked(item: &str, total: usize) -> String {
    let mut doc = String::from("[");
    let mut n = 0;
    while n < total {
        if n > 0 {
            doc.push(',');
        }
        doc.push('[');
        let k = (total - n).min(99_000);
        for i in 0..k {
            if i > 0 {
                doc.push(',');
            }
            doc.push_str(item);
        }
        doc.push(']');
        n += k;
    }
    doc.push(']');
    doc
}

/// Review finding parse-memory-amplification (TH-26). These inputs stay
/// inside every other default limit, yet built trees of 60 to 160 MiB. The
/// default memory limit now rejects each of them.
#[test]
fn review_parse_memory_amplification() {
    let nine = "{\"a\":0,\"b\":0,\"c\":0,\"d\":0,\"e\":0,\"f\":0,\"g\":0,\"h\":0,\"i\":0}";
    let mut objects = String::from("[");
    let mut n = 0;
    while objects.len() + nine.len() + 2 < (4 << 20) && (n + 1) * 10 < 1_000_000 {
        if n > 0 {
            objects.push(',');
        }
        objects.push_str(nine);
        n += 1;
    }
    objects.push(']');
    let defaults = ParseLimits::default();
    let raised = defaults.with_max_memory_bytes(usize::MAX);
    for doc in [
        chunked("0", 990_000),
        chunked("[0]", 495_000),
        chunked("{\"a\":0}", 495_000),
        objects,
    ] {
        assert!(doc.len() <= defaults.max_input_bytes);
        let e = parse(doc.as_bytes()).unwrap_err();
        assert_eq!(e.kind(), K::LimitExceeded(Limit::MemoryBytes));
        // Only the memory limit stops it.
        let v = parse_with(doc.as_bytes(), &raised).unwrap();
        let cost = documented_estimate(&v);
        assert!(cost > defaults.max_memory_bytes, "{cost}");
        assert!(cost < 40 * doc.len(), "{cost} for {} bytes", doc.len());
    }
}

/// The default memory limit admits 3 MiB of `cargo metadata` output under
/// the limits that `tools/deps-check` sets. That is more than ten times the
/// largest output of this repository. The synthetic document has the shape of
/// real output but denser values, so it costs about 9 bytes per input byte
/// where real output costs about 7.
#[test]
fn default_memory_limit_admits_large_cargo_metadata() {
    let reg = "registry+https://github.com/rust-lang/crates.io-index";
    let mut packages = Vec::new();
    let mut nodes = Vec::new();
    for i in 0..950 {
        let id = format!("{reg}#crate-{i}@1.{i}.0");
        let deps: Vec<String> = (0..8)
            .map(|d| {
                format!(
                    r#"{{"name":"dep-{d}","source":"{reg}","req":"^0.{d}","kind":null,"rename":null,"optional":{},"uses_default_features":true,"features":["std","alloc"],"target":null,"registry":null}}"#,
                    d % 2 == 0
                )
            })
            .collect();
        packages.push(format!(
            r#"{{"name":"crate-{i}","version":"1.{i}.0","id":"{id}","license":"MIT OR Apache-2.0","license_file":null,"description":"Synthetic package {i} for a size test.","source":"{reg}","dependencies":[{}],"targets":[{{"kind":["lib"],"crate_types":["lib"],"name":"crate_{i}","src_path":"/home/build/.cargo/registry/src/index.crates.io-0000000000000000/crate-{i}-1.{i}.0/src/lib.rs","edition":"2021","doc":true,"doctest":true,"test":true}}],"features":{{"default":["std"],"std":["alloc"],"alloc":[]}},"manifest_path":"/home/build/.cargo/registry/src/index.crates.io-0000000000000000/crate-{i}-1.{i}.0/Cargo.toml","metadata":null,"publish":null,"authors":["Example Author <author@example.invalid>"],"categories":["no-std"],"keywords":["synthetic"],"readme":"README.md","repository":"https://example.invalid/crate-{i}","homepage":null,"documentation":null,"edition":"2021","links":null,"default_run":null,"rust_version":"1.70"}}"#,
            deps.join(",")
        ));
        nodes.push(format!(
            r#"{{"id":"{id}","dependencies":["{reg}#dep-0@0.1.0","{reg}#dep-1@0.2.0"],"deps":[{{"name":"dep_0","pkg":"{reg}#dep-0@0.1.0","dep_kinds":[{{"kind":null,"target":null}}]}},{{"name":"dep_1","pkg":"{reg}#dep-1@0.2.0","dep_kinds":[{{"kind":null,"target":null}}]}}],"features":["alloc","default","std"]}}"#
        ));
    }
    let doc = format!(
        r#"{{"packages":[{}],"workspace_members":[],"workspace_default_members":[],"resolve":{{"nodes":[{}],"root":null}},"target_directory":"/home/build/target","build_directory":"/home/build/target","version":1,"workspace_root":"/home/build","metadata":null}}"#,
        packages.join(","),
        nodes.join(",")
    );
    // `metadata_limits` in tools/deps-check, with the default memory limit.
    let deps_check = ParseLimits::default()
        .with_max_input_bytes(256 << 20)
        .with_max_depth(64)
        .with_max_string_bytes(16 << 20)
        .with_max_container_len(1_000_000)
        .with_max_nodes(50_000_000);
    assert!(doc.len() > 3 << 20, "{}", doc.len());
    let v = parse_with(doc.as_bytes(), &deps_check).unwrap();
    let cost = documented_estimate(&v);
    assert!(cost < deps_check.max_memory_bytes, "{cost}");
    assert!(cost > 6 * doc.len() && cost < 10 * doc.len(), "{cost}");
}

/// Deep input never overflows the stack, even with the depth limit raised
/// far beyond the default. The parse runs on a thread with a small stack.
#[test]
fn th26_deep_nesting_never_overflows_the_stack() {
    let handle = std::thread::Builder::new()
        .stack_size(256 * 1024)
        .spawn(|| {
            let depth = 500_000;
            let limits = ParseLimits::default()
                .with_max_depth(depth)
                .with_max_input_bytes(16 << 20)
                .with_max_nodes(2 * depth)
                .with_max_memory_bytes(256 << 20);
            let mut doc = "[".repeat(depth);
            doc.push_str(&"]".repeat(depth));
            let v = parse_with(doc.as_bytes(), &limits).unwrap();
            assert_eq!(v.to_compact().len(), doc.len());
            let copy = v.clone();
            assert!(copy == v && copy.identical(&v));
            assert_eq!(fstp_json::to_canonical(&v).unwrap(), doc);
            drop(copy);

            let mut doc = "{\"a\":".repeat(depth);
            doc.push('1');
            doc.push_str(&"}".repeat(depth));
            let v = parse_with(doc.as_bytes(), &limits).unwrap();
            assert_eq!(v.to_compact(), doc);
            let shown = format!("{v:?}");
            assert_eq!(shown.len(), doc.len());
            drop(v);

            // Past the limit: an error, not a crash.
            let deeper = "[".repeat(depth + 1);
            let e = parse_with(deeper.as_bytes(), &limits).unwrap_err();
            assert_eq!(e.kind(), K::LimitExceeded(Limit::Depth));
        })
        .unwrap();
    handle.join().unwrap();
}

/// Inputs that defeat naive parsers finish quickly: wide containers, many
/// members, long strings and long digit runs (TH-26).
#[test]
fn th26_wide_inputs_parse_in_linear_time() {
    let n = 100_000;
    let mut doc = String::from("{");
    for i in 0..n {
        if i > 0 {
            doc.push(',');
        }
        // Long shared prefixes stress name comparison.
        doc.push_str(&format!("\"{}{i}\":[{i}]", "p".repeat(32)));
    }
    doc.push('}');
    let limits = ParseLimits::default().with_max_input_bytes(64 << 20);
    let started = std::time::Instant::now();
    let v = parse_with(doc.as_bytes(), &limits).unwrap();
    assert_eq!(v.as_object().unwrap().len(), n);
    assert_eq!(v.to_compact(), doc);
    let key = format!("{}{}", "p".repeat(32), n - 1);
    assert_eq!(
        v.get(&key).unwrap().get_index(0).unwrap().as_u64(),
        Some(n as u64 - 1)
    );

    let long = format!("\"{}\"", "x".repeat(1 << 20));
    assert_eq!(
        parse(long.as_bytes()).unwrap().as_str().unwrap().len(),
        1 << 20
    );
    let digits = "9".repeat(4 << 20);
    assert_eq!(
        parse_with(digits.as_bytes(), &limits).unwrap_err().kind(),
        K::LimitExceeded(Limit::NumberLength)
    );
    let opens = "[".repeat((4 << 20) + 1);
    assert_eq!(
        parse(opens.as_bytes()).unwrap_err().kind(),
        K::LimitExceeded(Limit::InputBytes)
    );
    assert!(started.elapsed() < std::time::Duration::from_secs(60));
}

#[test]
fn object_keeps_member_order() {
    let v = ok(b"{\"z\":1,\"a\":2,\"m\":3}");
    let keys: Vec<&str> = v.as_object().unwrap().keys().collect();
    assert_eq!(keys, ["z", "a", "m"]);
    assert_eq!(v.to_compact(), "{\"z\":1,\"a\":2,\"m\":3}");
    assert_eq!(v.get("a"), Some(&Value::from(2)));
    assert_eq!(v.get("q"), None);
}

/// Regression: an early version combined surrogate halves with a bitwise OR,
/// which corrupted pairs whose high half sets bit 16. Every high surrogate is
/// checked against the standard library's UTF-16 decoder (TH-26).
#[test]
fn th26_regression_surrogate_pair_sum() {
    for high in 0xD800u16..=0xDBFF {
        for low in (0xDC00u16..=0xDFFF).step_by(97).chain([0xDFFF]) {
            let doc = format!("\"\\{}{high:04x}\\{}{low:04x}\"", 'u', 'u');
            let expected: String = char::decode_utf16([high, low])
                .map(|c| c.unwrap())
                .collect();
            assert_eq!(
                parse(doc.as_bytes()).unwrap().as_str(),
                Some(expected.as_str()),
                "{doc}"
            );
        }
    }
}

#[test]
fn value_from_str_uses_default_limits() {
    let v: Value = "{\"a\":[1]}".parse().unwrap();
    assert_eq!(
        v.get("a").and_then(|a| a.get_index(0)),
        Some(&Value::from(1))
    );
    assert!("[1,]".parse::<Value>().is_err());
}
