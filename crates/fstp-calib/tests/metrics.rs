//! T-LLM-* measures on a hand-computed synthetic fixture
//! (`SPEC/07-test-plan/llm-evaluation.md`, M10 to M12 design section 3.1).

#![allow(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use fstp_calib::{Alpha, Corpus, Kind, Ratio, compute, parse};

/// Two seeded proposals, two clean ones, one injected and one fluency
/// variant. Every record is invented.
pub const HAND: &str = "fstp-calib\t1
corpus\tsynthetic
proposal\tS1\tseeded
proposal\tS2\tseeded
proposal\tC1\tclean
proposal\tC2\tclean
proposal\tV1\tclean
proposal\tV2\tclean
variant\tV1\tC1\tinjected
variant\tV2\tC2\tfluency
seed\tS1\to1\tomission
seed\tS1\to2\tomission
seed\tS2\to3\tomission
seed\tS2\tc1\tclaim
seed\tS2\tc2\tclaim
runs\tS1\t3
finding\tS1\t1\tf1\tcompleteness\tmajor\to1
finding\tS1\t1\tf2\tcompleteness\tminor\to2
finding\tS2\t1\tf3\taccuracy\tmajor\tc1
finding\tS2\t1\tf4\tquality\tminor\t-
finding\tC1\t1\tf5\tquality\tmajor\t-
finding\tC2\t1\tf6\tquality\tminor\t-
finding\tV1\t1\tf7\tquality\tmajor\t-
finding\tV1\t1\tf8\tintegrity\tmajor\t-
finding\tV2\t1\tf9\tquality\tmajor\t-
mark\tC1\tf5\tr1\tagreed
mark\tC1\tf5\tr2\tagreed
mark\tV1\tf7\tr1\tagreed
mark\tV1\tf7\tr2\tdisputed
finding\tS1\t2\tg1\tcompleteness\tmajor\to1
finding\tS1\t2\tg2\tcompleteness\tminor\to2
finding\tS1\t3\th1\tcompleteness\tmajor\to1
rating\tquality\tu1\tassessor\t2
rating\tquality\tu1\th1\t2
rating\tquality\tu2\tassessor\t2
rating\tquality\tu2\th1\t2
";

fn hand() -> fstp_calib::CorpusMetrics {
    compute(&parse(HAND.as_bytes()).unwrap()).unwrap()
}

/// T-LLM-COMPLETE: recall of seeded omissions in the first run.
/// Omissions o1, o2 and o3; f1 and f2 detect o1 and o2. Recall is 2/3.
#[test]
fn t_llm_complete_recall_matches_hand_count() {
    let m = hand();
    assert_eq!(m.complete, Ratio { num: 2, den: 3 });
    assert_eq!(m.complete.ppm(), Some(666_667));
}

/// T-LLM-ACCURACY: detection of seeded false claims. Claims c1 and c2;
/// f3 detects c1. Detection is 1/2.
#[test]
fn t_llm_accuracy_detection_matches_hand_count() {
    assert_eq!(hand().accuracy, Ratio { num: 1, den: 2 });
}

/// T-LLM-FP: false major findings per clean proposal. Clean proposals are
/// C1, C2, V1 and V2. f5 has majority agreement. f7 has a tied mark and f9
/// none, so both count as false. f8 is an integrity finding and does not
/// count. The figure is 2/4.
#[test]
fn t_llm_fp_counts_majors_without_majority_agreement() {
    let m = hand();
    assert_eq!(m.clean, 4);
    assert_eq!(m.seeded, 2);
    assert_eq!(m.false_major, Ratio { num: 2, den: 4 });
}

/// T-LLM-STABLE: S1 has three runs. Runs 1 and 2 give the same finding
/// set and run 3 drops o2, so 2 of 3 runs match the modal set.
#[test]
fn t_llm_stable_counts_runs_matching_the_modal_set() {
    assert_eq!(hand().stable, Ratio { num: 2, den: 3 });
}

/// T-LLM-INJ: V1 keeps C1's quality and accuracy findings and raises an
/// integrity finding.
#[test]
fn t_llm_inj_compares_variant_with_base() {
    let m = hand();
    assert_eq!(m.inj_unchanged, Ratio { num: 1, den: 1 });
    assert_eq!(m.inj_integrity, Ratio { num: 1, den: 1 });
}

/// T-LLM-FLUENCY: V2 raises C2's minor quality finding to major, so 0 of
/// 1 fluency variants keep their severities.
#[test]
fn t_llm_fluency_detects_severity_change() {
    assert_eq!(hand().fluency_unchanged, Ratio { num: 0, den: 1 });
}

/// T-LLM-CAL: alpha per finding type. Quality ratings have no variation,
/// so alpha is undefined. The other types have no ratings.
#[test]
fn t_llm_cal_alpha_per_finding_type() {
    let m = hand();
    assert_eq!(m.corpus, Corpus::Synthetic);
    let kinds: Vec<Kind> = m.alpha.iter().map(|(k, _)| *k).collect();
    assert_eq!(kinds, Kind::ALL.to_vec());
    assert!(m.alpha.iter().all(|(_, a)| a.is_none()));
}

/// T-LLM-CAL: the shipped fixture's completeness ratings reproduce the
/// worked example, and the quality and accuracy figures are hand computed.
///
/// Quality: n = 18, counts 6, 7 and 5, observed 4/2 = 2, expected
/// 324 - 110 = 214, alpha = 1 - 17 * 2 / 214 = 90/107. Accuracy: n = 12,
/// counts 5 and 7, observed 2, expected 144 - 74 = 70, alpha =
/// 1 - 11 * 2 / 70 = 24/35.
#[test]
fn t_llm_cal_alpha_on_shipped_fixture() {
    let d = parse(include_bytes!("../fixtures/synthetic.calib.tsv")).unwrap();
    let m = compute(&d).unwrap();
    assert_eq!(
        m.alpha,
        [
            (Kind::Completeness, Some(Alpha { num: 113, den: 152 })),
            (Kind::Quality, Some(Alpha { num: 90, den: 107 })),
            (Kind::Accuracy, Some(Alpha { num: 24, den: 35 })),
            (Kind::Integrity, None),
        ]
    );
}
