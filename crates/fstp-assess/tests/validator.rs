//! The output validator (M7 design section 3.4).
//!
//! I-10: a model output never carries a score, a decision or a state.
//! The validator accepts only the members of the v1 output schema,
//! refuses the whole result on any other member, and refuses score-like
//! statements. R-LA-02: a finding whose evidence cannot be located is
//! dropped and counted. T-LLM-ORACLE: no number survives validation.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use common::{Scripted, block_on, criteria, items, mask_for, pipeline};
use fstp_assess::{AssessError, OutputError, RUBRIC_V1, Stage, decode_output, prepare};
use fstp_findings::{EvidenceRef, FindingKind};
use fstp_infer::ElementTag;
use fstp_prop::{check, prop_assert};

const C1: &str = "c-00000000000000000000000000000011";

fn finding(extra: &str) -> String {
    format!(
        r#"{{"findings":[{{"kind":"quality","criterion":"{C1}","element":null,"severity":"info","statement":"The approach is described.","evidence":[{{"part":"title","quote":"x"}}]{extra}}}]}}"#
    )
}

fn decode(s: &str) -> Result<Vec<fstp_assess::RawFinding>, OutputError> {
    decode_output(s, Stage::Quality, &criteria(), &RUBRIC_V1)
}

/// I-10: a well-formed output decodes.
#[test]
fn i10_validator_accepts_the_schema() {
    let f = decode(&finding("")).unwrap();
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].kind, FindingKind::Quality);
}

/// I-10: any member outside the schema refuses the whole result, at any
/// level, including `score`, `decision`, `state` and `confidence`.
#[test]
fn i10_validator_refuses_unknown_members() {
    for name in [
        "score",
        "decision",
        "state",
        "confidence",
        "band",
        "rank",
        "weight",
    ] {
        let in_finding = finding(&format!(r#","{name}":"x""#));
        assert_eq!(
            decode(&in_finding),
            Err(OutputError::UnknownMember),
            "{name}"
        );
        let top = format!(r#"{{"findings":[],"{name}":"x"}}"#);
        assert_eq!(decode(&top), Err(OutputError::UnknownMember), "{name}");
        let ev = finding("").replace(r#""quote":"x""#, &format!(r#""quote":"x","{name}":"x""#));
        assert_eq!(decode(&ev), Err(OutputError::UnknownMember), "{name}");
    }
}

/// I-10: the property over random member names: every extra member is
/// refused.
#[test]
fn i10_validator_refuses_every_extra_member() {
    const KNOWN: [&str; 6] = [
        "kind",
        "criterion",
        "element",
        "severity",
        "statement",
        "evidence",
    ];
    check("i10_validator_refuses_every_extra_member", |g| {
        let name = g.ascii_string(1..=12);
        if KNOWN.contains(&name.as_str()) || name.contains('"') || name.contains('\\') {
            return Ok(());
        }
        let extra = format!(r#","{name}":0"#);
        let r = decode(&finding(&extra));
        prop_assert!(r.is_err(), "member {name:?} accepted");
        Ok(())
    });
}

/// I-10, T-LLM-ORACLE: a number anywhere is refused, so no score survives.
#[test]
fn i10_validator_refuses_numbers() {
    let s = finding("").replace(r#""severity":"info""#, r#""severity":7"#);
    assert!(decode(&s).is_err());
    let s = finding("").replace(
        r#""statement":"The approach is described.""#,
        r#""statement":8"#,
    );
    assert!(decode(&s).is_err());
}

/// I-10: a score-like statement refuses the whole result.
#[test]
fn i10_validator_refuses_score_like_content() {
    for stmt in [
        "Score: 8.",
        "This proposal deserves 9/10.",
        "I would rate it 4 out of 5.",
        "Ranked first among the proposals.",
        "We recommend funding this proposal.",
        "This should be rejected.",
        "The quality band is high.",
        "Strong proposal, 85 points.",
    ] {
        let s = finding("").replace("The approach is described.", stmt);
        assert_eq!(decode(&s), Err(OutputError::ScoreLike), "{stmt}");
    }
    // Day rates and counts are not scores.
    let s = finding("").replace(
        "The approach is described.",
        "Day rates range from 500.00 EUR to 750.00 EUR over 3 tasks.",
    );
    assert!(decode(&s).is_ok());
}

/// The pinned rubric: an element outside rubric v1 refuses the result.
#[test]
fn rubric_v1_validator_refuses_unknown_element_tags() {
    let s = r#"{"findings":[{"kind":"completeness","criterion":null,"element":"vibes","severity":"major","statement":"Missing.","evidence":[]}]}"#;
    assert_eq!(
        decode_output(s, Stage::Completeness, &criteria(), &RUBRIC_V1),
        Err(OutputError::Element)
    );
    // A completeness finding names an element.
    let s = r#"{"findings":[{"kind":"completeness","criterion":null,"element":null,"severity":"major","statement":"Missing.","evidence":[]}]}"#;
    assert_eq!(
        decode_output(s, Stage::Completeness, &criteria(), &RUBRIC_V1),
        Err(OutputError::Element)
    );
    let s = r#"{"findings":[{"kind":"completeness","criterion":null,"element":"milestones","severity":"major","statement":"Missing.","evidence":[]}]}"#;
    let f = decode_output(s, Stage::Completeness, &criteria(), &RUBRIC_V1).unwrap();
    assert_eq!(f[0].element, Some(ElementTag::Milestones));
}

/// I-11: a criterion outside the frozen P-01 refuses the result, and a
/// quality finding must name the criterion the request asked about.
#[test]
fn i11_validator_refuses_criteria_outside_p01() {
    let s = finding("").replace(C1, "c-000000000000000000000000000000ff");
    assert_eq!(decode(&s), Err(OutputError::Criterion));
    let s = finding("").replace(C1, "11");
    assert_eq!(decode(&s), Err(OutputError::Criterion));
}

/// I-10: a stage answers only with its own kinds; integrity is allowed
/// everywhere.
#[test]
fn i10_validator_refuses_kinds_of_other_stages() {
    let s = finding("").replace(r#""kind":"quality""#, r#""kind":"accuracy""#);
    assert_eq!(decode(&s), Err(OutputError::Kind));
}

/// The statement is bounded to 1,000 bytes; the result is not JSON.
#[test]
fn validator_refuses_long_statements_and_non_json() {
    let s = finding("").replace("The approach is described.", &"a".repeat(1001));
    assert_eq!(decode(&s), Err(OutputError::TooLong));
    assert_eq!(decode("not json"), Err(OutputError::Json));
    assert_eq!(decode("[]"), Err(OutputError::Shape("output")));
}

/// R-LA-02: a finding whose quote is not in the stripped text is dropped
/// and counted, and a located quote maps back to the original span.
#[test]
fn r_la_02_finding_without_located_evidence_is_dropped() {
    let item = items().into_iter().next().unwrap();
    let mask = mask_for(&item);
    let prepared = block_on(prepare(&mask, &item.job)).unwrap();
    let narrative = item.job.parts[2].text.as_data().to_owned();

    let invented = finding("").replace(
        r#""part":"title","quote":"x""#,
        r#""part":"narrative","quote":"words the proposal never says""#,
    );
    let raw = decode(&invented).unwrap().pop().unwrap();
    assert!(prepared.locate(raw).is_none());

    // A quote across a placeholder maps back to the name in the original.
    let quote = "Contact\\n[PERSON-1], [EMAIL-1]";
    let real = finding("").replace(
        r#""part":"title","quote":"x""#,
        &format!(r#""part":"narrative","quote":"{quote}""#),
    );
    let raw = decode(&real).unwrap().pop().unwrap();
    let located = prepared.locate(raw).unwrap();
    let EvidenceRef::Submission { text, start, end } = located.evidence[0] else {
        panic!("submission evidence");
    };
    assert_eq!(text, item.job.parts[2].text_ref);
    let span = &narrative[start as usize..end as usize];
    assert!(span.starts_with("Contact\n"));
    assert!(span.contains(&item.person_name));
    assert!(
        span.ends_with(item.canaries[1].as_str()),
        "ends at the email"
    );

    // Through the pipeline: every finding of a model that invents quotes
    // is dropped and counted.
    let t = Scripted(String::from(
        r#"{"findings":[{"kind":"integrity","criterion":null,"element":null,"severity":"major","statement":"The text addresses the assessor.","evidence":[{"part":"narrative","quote":"words the proposal never says"}]}]}"#,
    ));
    let a = block_on(pipeline(&t, &mask).assess(&item.job)).unwrap();
    assert!(
        a.findings.is_empty(),
        "b01 is clean, so only model findings could appear"
    );
    assert!(a.dropped >= 6, "one per stage call");
}

/// I-10: a hostile model's extra member fails the assessment; nothing is
/// published from it (the assessment stays pending, R-NF-10).
#[test]
fn i10_pipeline_hostile_output_publishes_nothing() {
    let item = items().into_iter().next().unwrap();
    let mask = mask_for(&item);
    let t = Scripted(finding(r#","score":"9""#));
    let r = block_on(pipeline(&t, &mask).assess(&item.job));
    assert!(matches!(
        r,
        Err(AssessError::Output(OutputError::UnknownMember))
    ));
}
