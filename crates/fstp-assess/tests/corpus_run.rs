//! R-LA-01, R-LA-02: the pipeline runs end to end over corpus/v1 with the
//! synthetic transport (M7 design sections 3.2 and 7). Every item gets
//! findings, and every finding is well formed: evidence pointers that
//! name the item's own texts, a criterion of P-01 and an element of the
//! pinned rubric.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use common::{block_on, criteria, items, manifest, mask_for, pipeline};
use fstp_assess::RUBRIC_V1;
use fstp_findings::{EvidenceRef, FindingKind};
use fstp_infer::{ElementTag, SyntheticModel};

/// R-LA-01, R-LA-02: findings for every item of corpus/v1.
#[test]
fn r_la_01_synthetic_run_over_corpus_v1_gives_findings_for_every_item() {
    let all = items();
    assert!(all.len() >= 200);
    let p01 = criteria();
    for item in &all {
        let mask = mask_for(item);
        let a = block_on(pipeline(&SyntheticModel, &mask).assess(&item.job))
            .unwrap_or_else(|e| panic!("{}: {e:?}", item.id));
        assert!(!a.findings.is_empty(), "{}: no findings", item.id);
        let refs: Vec<_> = item.job.parts.iter().map(|p| p.text_ref).collect();
        for f in &a.findings {
            assert!(!f.evidence.is_empty(), "{}: R-LA-02", item.id);
            for e in &f.evidence {
                assert!(e.is_well_formed());
                match e {
                    EvidenceRef::Submission { text, end, .. } => {
                        let i = refs.iter().position(|r| r == text).expect("own text");
                        assert!(*end as usize <= item.job.parts[i].text.as_data().len());
                    }
                    EvidenceRef::Retrieved { .. } => panic!("no retrieval in M7 pipeline runs"),
                }
            }
            if let Some(c) = f.criterion {
                assert!(p01.contains(&c));
            }
            if let Some(e) = f.element {
                assert!(RUBRIC_V1.contains(e));
            }
        }
        // One quality finding per P-01 criterion from the synthetic model.
        let quality = a
            .findings
            .iter()
            .filter(|f| f.kind == FindingKind::Quality)
            .count();
        assert_eq!(quality, p01.len(), "{}", item.id);
        // Stage 1 marks become integrity findings deterministically.
        if item.variant == "hidden_injection" || item.variant == "direct_injection" {
            assert!(
                a.findings.iter().any(|f| f.kind == FindingKind::Integrity),
                "{}: no integrity finding",
                item.id
            );
        }
        if item.variant == "clean" {
            assert!(
                !a.findings.iter().any(|f| f.kind == FindingKind::Integrity),
                "{}: integrity finding on a clean item",
                item.id
            );
        }
        // Recall on omission items is T-LLM-COMPLETE, measured by the
        // evaluation harness, not asserted on the synthetic model here.
        if let Some(omitted) = &item.omitted {
            assert!(ElementTag::parse(omitted).is_some_and(|t| RUBRIC_V1.contains(t)));
        }
    }
}

/// The pinned rubric v1 lists the element tags of the corpus manifest.
#[test]
fn rubric_v1_matches_the_corpus_manifest() {
    let m = manifest();
    let tags: Vec<&str> = m
        .get("rubric_elements")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    let ours: Vec<&str> = RUBRIC_V1.required().iter().map(|t| t.as_str()).collect();
    assert_eq!(tags, ours);
    assert_eq!(RUBRIC_V1.version(), "v1");
}
