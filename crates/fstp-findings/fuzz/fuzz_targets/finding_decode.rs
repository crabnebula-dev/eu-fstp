//! Fuzz target for the finding decoder (TH-26, H-05, TH-01, I-11).
//!
//! Checks, for any input that parses as JSON, both as a `Finding` and as a
//! `FindingRecord`:
//! - decoding never panics, and a refusal formats without panicking;
//! - decode, encode, decode gives the same value, and encoding is
//!   deterministic;
//! - the encoding has RFC 8785 bytes, they decode to the same value, and
//!   they are stable under a second round trip;
//! - an accepted finding's statement is exactly the input's `statement`
//!   string, byte for byte, and the encoding holds the same bytes;
//! - every statement inside an accepted record keeps its bytes through the
//!   round trip.
//!
//! The target reads findings only through the codec and the public fields
//! of design section 2.13. It never interprets a statement.

#![no_main]

use fstp_findings::{Finding, FindingRecord};
use fstp_json::{FromJson, ToJson, Value, parse, to_canonical};
use libfuzzer_sys::fuzz_target;

/// The statement bytes of every finding a record carries.
fn statements(record: &FindingRecord) -> Vec<Vec<u8>> {
    match record {
        FindingRecord::Recorded(f) => vec![f.statement.as_data().as_bytes().to_vec()],
        FindingRecord::Marked { .. } => Vec::new(),
        FindingRecord::Regenerated { findings, .. } => findings
            .iter()
            .map(|f| f.statement.as_data().as_bytes().to_vec())
            .collect(),
    }
}

/// Decode, encode and decode again through RFC 8785 text. Returns the value
/// decoded from the canonical bytes.
fn round_trip<T>(value: &T, what: &str) -> T
where
    T: FromJson + ToJson + PartialEq + core::fmt::Debug,
{
    let encoded = value.to_json();
    assert!(
        encoded.identical(&value.to_json()),
        "{what}: encoding is not deterministic"
    );
    let again = T::from_json(&encoded).expect("an encoded value decodes");
    assert_eq!(&again, value, "{what}: decode, encode, decode changed it");

    let text = to_canonical(&encoded).expect("an encoded value has canonical bytes");
    let reparsed = parse(text.as_bytes()).expect("canonical bytes parse");
    let third = T::from_json(&reparsed).expect("canonical bytes decode");
    assert_eq!(
        &third, value,
        "{what}: canonical bytes decode to another value"
    );
    let text2 = to_canonical(&third.to_json()).expect("canonical bytes again");
    assert_eq!(text2, text, "{what}: canonical bytes are not stable");
    third
}

fuzz_target!(|data: &[u8]| {
    let Ok(input) = parse(data) else {
        return;
    };

    match Finding::from_json(&input) {
        Ok(finding) => {
            // The statement is the input string, byte for byte.
            let given = input
                .get("statement")
                .and_then(Value::as_str)
                .expect("an accepted finding has a string statement");
            assert_eq!(
                finding.statement.as_data().as_bytes(),
                given.as_bytes(),
                "the decoder changed the statement"
            );
            let encoded = finding.to_json();
            let written = encoded
                .get("statement")
                .and_then(Value::as_str)
                .expect("an encoded finding has a string statement");
            assert_eq!(
                written.as_bytes(),
                given.as_bytes(),
                "the encoder changed the statement"
            );
            let back = round_trip(&finding, "finding");
            assert_eq!(
                back.statement.as_data().as_bytes(),
                given.as_bytes(),
                "the round trip changed the statement"
            );
            assert_eq!(back.config, finding.config, "I-11: config_id changed");
        }
        Err(e) => {
            let _ = e.to_string();
        }
    }

    match FindingRecord::from_json(&input) {
        Ok(record) => {
            let back = round_trip(&record, "record");
            assert_eq!(
                statements(&back),
                statements(&record),
                "the round trip changed a statement"
            );
        }
        Err(e) => {
            let _ = e.to_string();
        }
    }
});
