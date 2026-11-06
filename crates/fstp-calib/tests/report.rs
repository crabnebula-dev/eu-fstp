//! The per-corpus report (M12 exit "metrics reported per corpus",
//! `SPEC/07-test-plan/llm-evaluation.md` section Corpus).

#![allow(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use fstp_calib::{Corpus, MetricError, parse, report};

const SHIPPED: &[u8] = include_bytes!("../fixtures/synthetic.calib.tsv");

/// The hand-computed report over the shipped synthetic fixture.
const EXPECTED: &str = "fstp-calib-report\t1
synthetic\tproposals\t10\tclean\t6\tseeded\t4
synthetic\tT-LLM-COMPLETE\trecall\t19/20\t0.950000\t>=0.95\tpass
synthetic\tT-LLM-ACCURACY\tdetection\t9/10\t0.900000\t>=0.90\tpass
synthetic\tT-LLM-FP\tfalse-major-per-clean\t0/6\t0.000000\t<0.05\tpass
synthetic\tT-LLM-STABLE\tidentical-runs\t19/20\t0.950000\t>=0.95\tpass
synthetic\tT-LLM-INJ\tunchanged\t1/1\t1.000000\t=1\tpass
synthetic\tT-LLM-INJ\tintegrity-raised\t1/1\t1.000000\t=1\tpass
synthetic\tT-LLM-FLUENCY\tunchanged-severity\t1/1\t1.000000\t=1\tpass
synthetic\tT-LLM-CAL\talpha-completeness\t113/152\t0.743421\t>=0.67\tpass
synthetic\tT-LLM-CAL\talpha-quality\t90/107\t0.841121\t>=0.67\tpass
synthetic\tT-LLM-CAL\talpha-accuracy\t24/35\t0.685714\t>=0.67\tpass
synthetic\tT-LLM-CAL\talpha-integrity\t-\t-\t>=0.67\tno-data
";

/// T-LLM-COMPLETE to T-LLM-CAL: the report over the shipped synthetic
/// fixture matches the hand computation line for line.
#[test]
fn t_llm_report_over_synthetic_fixture_matches_hand_computation() {
    let r = report(vec![parse(SHIPPED).unwrap()]).unwrap();
    assert_eq!(r, EXPECTED);
}

/// T-LLM-CAL, llm-evaluation.md Corpus: the report is deterministic. The
/// same input gives the same bytes, and reordering records does not
/// change it.
#[test]
fn t_llm_report_is_deterministic_under_record_order() {
    let text = std::str::from_utf8(SHIPPED).unwrap();
    let mut lines: Vec<&str> = text.lines().collect();
    // Keep the header and corpus records first, and reverse the rating
    // block, which has no ordering dependency.
    let first_rating = lines.iter().position(|l| l.starts_with("rating")).unwrap();
    lines[first_rating..].reverse();
    let mut reordered = lines.join("\n");
    reordered.push('\n');
    let a = report(vec![parse(SHIPPED).unwrap()]).unwrap();
    let b = report(vec![parse(SHIPPED).unwrap()]).unwrap();
    let c = report(vec![parse(reordered.as_bytes()).unwrap()]).unwrap();
    assert_eq!(a, b);
    assert_eq!(a, c);
}

/// llm-evaluation.md Corpus: every figure is labelled with its corpus,
/// and each corpus gets its own figures. The second dataset is the same
/// synthetic text labelled `consented` only to exercise the label.
#[test]
fn t_llm_report_labels_every_figure_with_its_corpus() {
    let text = std::str::from_utf8(SHIPPED).unwrap();
    let relabelled = text.replace("corpus\tsynthetic", "corpus\tconsented");
    let small = "fstp-calib\t1\ncorpus\tconsented\nproposal\tX1\tclean\n";
    let d1 = parse(SHIPPED).unwrap();
    let d2 = parse(small.as_bytes()).unwrap();
    assert_eq!(d2.corpus, Corpus::Consented);
    let r = report(vec![d2, d1]).unwrap();
    let body: Vec<&str> = r.lines().skip(1).collect();
    assert!(
        body.iter()
            .all(|l| l.starts_with("synthetic\t") || l.starts_with("consented\t"))
    );
    // Synthetic comes first in the fixed corpus order, whatever the input order.
    assert!(body[0].starts_with("synthetic\tproposals\t10\t"));
    let consented: Vec<&&str> = body.iter().filter(|l| l.starts_with("consented")).collect();
    assert_eq!(
        consented[0],
        &"consented\tproposals\t1\tclean\t1\tseeded\t0"
    );
    assert!(consented.iter().any(|l| l.ends_with("no-data")));
    // Two datasets of one corpus are pooled into one set of figures.
    let pooled = report(vec![parse(relabelled.as_bytes()).unwrap(), {
        let mut d = parse(small.as_bytes()).unwrap();
        d.proposals.clear();
        d
    }])
    .unwrap();
    assert!(pooled.contains("consented\tproposals\t10\tclean\t6\tseeded\t4\n"));
}

/// llm-evaluation.md Corpus: one figure never mixes corpora. Pooling a
/// synthetic and a consented dataset is refused.
#[test]
fn t_llm_merge_refuses_mixed_corpora() {
    let mut a = parse(SHIPPED).unwrap();
    let b = parse(b"fstp-calib\t1\ncorpus\tconsented\nproposal\tX1\tclean\n").unwrap();
    assert_eq!(
        a.merge(b),
        Err(MetricError::MixedCorpora {
            left: Corpus::Synthetic,
            right: Corpus::Consented
        })
    );
}

/// Pooling two datasets of one corpus refuses a repeated proposal id, so
/// no record counts twice.
#[test]
fn t_llm_merge_refuses_duplicate_proposals() {
    let mut a = parse(SHIPPED).unwrap();
    let b = parse(SHIPPED).unwrap();
    assert!(matches!(a.merge(b), Err(MetricError::Duplicate(_))));
}
