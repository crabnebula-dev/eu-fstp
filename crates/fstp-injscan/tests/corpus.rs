//! The injection corpus of ADR-035 (`corpus/injection-v1`) and the
//! proposals of the synthetic corpus v1 (TH-01, T-LLM-INJ).
//!
//! Every injection sample is flagged with at least the reasons it names.
//! Every benign control, and every v1 proposal that is neither a direct
//! nor a hidden injection, is not flagged at all. So the scan keeps its
//! false positives low (ADR-035, "False positives").

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::path::PathBuf;

use fstp_injscan::{Reason, scan};
use fstp_json::Value;

fn corpus() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../corpus")
}

fn read(p: PathBuf) -> Value {
    let bytes = std::fs::read(&p).unwrap();
    fstp_json::parse(&bytes).unwrap()
}

fn samples() -> Vec<(String, Vec<Reason>, String)> {
    let v = read(corpus().join("injection-v1/samples.json"));
    assert_eq!(v.get("synthetic").and_then(Value::as_bool), Some(true));
    v.get("samples")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .map(|s| {
            let id = s.get("id").and_then(Value::as_str).unwrap().to_owned();
            let expect = s
                .get("expect")
                .and_then(Value::as_array)
                .unwrap()
                .iter()
                .map(|r| {
                    let code = r.as_str().unwrap();
                    Reason::parse(code).unwrap_or_else(|| panic!("{id}: unknown reason {code}"))
                })
                .collect();
            let text = s.get("text").and_then(Value::as_str).unwrap().to_owned();
            (id, expect, text)
        })
        .collect()
}

/// TH-01, T-LLM-INJ: every injection sample is flagged with every reason
/// it names, and each detection lies on character boundaries of the text.
#[test]
fn th01_every_injection_sample_is_flagged_with_its_reasons() {
    let mut covered = std::collections::BTreeSet::new();
    for (id, expect, text) in samples() {
        if expect.is_empty() {
            continue;
        }
        let s = scan(&text);
        let found = s.reasons();
        for r in &expect {
            assert!(found.contains(r), "{id}: {r:?} missing, found {found:?}");
            covered.insert(*r);
        }
        for d in s.detections() {
            assert!(d.start <= d.end && d.end <= text.len(), "{id}");
            assert!(text.is_char_boundary(d.start) && text.is_char_boundary(d.end));
        }
    }
    for r in Reason::ALL {
        if r != Reason::Truncated {
            assert!(covered.contains(&r), "no sample covers {r:?}");
        }
    }
}

/// TH-01, ADR-035 "False positives": no benign control is flagged.
#[test]
fn th01_benign_controls_are_not_flagged() {
    for (id, expect, text) in samples() {
        if !expect.is_empty() {
            continue;
        }
        let s = scan(&text);
        assert!(s.detections().is_empty(), "{id}: {:?}", s.reasons());
    }
}

/// TH-01, T-LLM-INJ, ADR-035: over the synthetic corpus v1, every direct
/// and every hidden injection is flagged, and no other proposal is. The
/// indirect injections sit in fixture web pages, not in the proposal.
#[test]
fn th01_v1_corpus_flags_exactly_the_injected_proposals() {
    let dir = corpus().join("v1/items");
    let mut n = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_str().unwrap().to_owned();
        let v = read(path);
        let p = v.get("proposal").unwrap();
        let mut parts = vec![
            p.get("title").and_then(Value::as_str).unwrap().to_owned(),
            p.get("summary").and_then(Value::as_str).unwrap().to_owned(),
        ];
        // The narrative as the platform receives it: the sections under
        // their headings, with the contact block.
        parts.push(
            p.get("narrative")
                .and_then(Value::as_str)
                .unwrap()
                .to_owned(),
        );
        let flagged = parts.iter().any(|t| !scan(t).detections().is_empty());
        let injected = name.contains("-direct") || name.contains("-hidden");
        assert_eq!(flagged, injected, "{name}");
        n += 1;
    }
    assert!(n > 100, "the v1 corpus holds {n} items");
}
