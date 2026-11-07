//! Fuzz target `assess_output_decode` (M7 design section 8, I-10, TH-26).
//!
//! The validator never panics. Every result it accepts holds only the v1
//! schema members, no number anywhere, and no score-like statement. The
//! oracle walks the parsed value independently of the decoder.

#![no_main]

use fstp_assess::{RUBRIC_V1, Stage, decode_output, score_like};
use fstp_domain::id::CriterionId;
use fstp_json::Value;
use libfuzzer_sys::fuzz_target;

const FINDING: [&str; 6] = [
    "kind",
    "criterion",
    "element",
    "severity",
    "statement",
    "evidence",
];

fn no_numbers(v: &Value) {
    match v {
        Value::Number(_) => panic!("accepted a number"),
        Value::Array(a) => a.iter().for_each(no_numbers),
        Value::Object(o) => o.values().for_each(no_numbers),
        _ => {}
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    let Ok(text) = core::str::from_utf8(rest) else {
        return;
    };
    let stage = match sel % 5 {
        0 => Stage::Completeness,
        1 => Stage::Quality,
        2 => Stage::Claims,
        3 => Stage::Verify,
        _ => Stage::Integrity,
    };
    let criteria = [CriterionId::from_raw(0x11), CriterionId::from_raw(0x22)];
    let Ok(found) = decode_output(text, stage, &criteria, &RUBRIC_V1) else {
        return;
    };
    let v = fstp_json::parse_str(text).expect("accepted output parses");
    no_numbers(&v);
    let o = v.as_object().expect("object");
    assert!(
        o.keys().all(|k| k == "findings"),
        "accepted an unknown member"
    );
    for f in v
        .get("findings")
        .and_then(Value::as_array)
        .expect("findings")
        .iter()
    {
        let fo = f.as_object().expect("finding object");
        assert!(
            fo.keys().all(|k| FINDING.contains(&k)),
            "accepted an unknown member"
        );
    }
    for f in &found {
        assert!(!score_like(f.statement.as_data()));
        assert!(f.statement.as_data().len() <= 1000);
        if let Some(c) = f.criterion {
            assert!(criteria.contains(&c));
        }
        if let Some(e) = f.element {
            assert!(RUBRIC_V1.contains(e));
        }
    }
});
