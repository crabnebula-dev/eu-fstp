//! Issue 6 M3 (H-03) and L19: a refused reply cannot keep an assessment
//! pending or hide integrity findings, and evidence is found in any part
//! that carries the label. I-10 stays: a refused reply publishes nothing.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use common::{Scripted, block_on, pipeline};
use fstp_assess::{
    AssessError, Job, MaskUnavailable, NameMask, NameSpan, OutputError, RawFinding, SubmissionPart,
};
use fstp_domain::id::{ContentDigest, ProposalId, TextId, TextRef};
use fstp_findings::{FindingKind, Severity, UntrustedText};
use fstp_infer::DataLabel;

struct NoNames;
impl NameMask for NoNames {
    async fn names(&self, _p: ProposalId, _t: &str) -> Result<Vec<NameSpan>, MaskUnavailable> {
        Ok(Vec::new())
    }
}

fn part(n: u128, label: DataLabel, text: &str) -> SubmissionPart {
    SubmissionPart {
        label,
        text_ref: TextRef::new(TextId::from_raw(n), ContentDigest::from_bytes([0; 32])),
        text: UntrustedText::new(text.to_owned()),
    }
}

fn job(parts: Vec<SubmissionPart>) -> Job {
    Job {
        proposal: ProposalId::from_raw(1),
        parts,
        handles: Vec::new(),
    }
}

/// H-03, I-10: every reply carries a score-like statement, so each is
/// refused whole. `assess` keeps its strict outcome. `assess_partial`
/// reaches a result with the stage 7 integrity finding of the hidden
/// character and the refusals listed, and no refused content in it.
#[test]
fn issue6_m3_h03_refused_replies_keep_integrity_findings() {
    let reply = r#"{"findings":[{"kind":"integrity","criterion":null,"element":null,"severity":"info","statement":"The score is high.","evidence":[]}]}"#;
    let t = Scripted(reply.to_owned());
    let j = job(vec![part(
        1,
        DataLabel::Narrative,
        "We build a tool.\u{200b} More text.",
    )]);
    let p = pipeline(&t, &NoNames);
    assert_eq!(
        block_on(p.assess(&j)).unwrap_err(),
        AssessError::Output(OutputError::ScoreLike)
    );
    let r = block_on(p.assess_partial(&j));
    assert!(r.error.is_none());
    assert!(r.refused.len() > 1, "later stages still ran");
    assert!(r.refused.iter().all(|(_, e)| *e == OutputError::ScoreLike));
    assert!(r.assessment.replies.is_empty(), "a refused reply was kept");
    assert!(
        r.assessment
            .findings
            .iter()
            .any(|f| f.kind == FindingKind::Integrity),
        "the integrity finding was lost"
    );
    assert!(
        r.assessment
            .findings
            .iter()
            .all(|f| !f.statement.as_data().contains("score")),
        "a score-like statement was published"
    );
}

/// L19: a quote that sits only in a second part with the same label is
/// located.
#[test]
fn issue6_l19_evidence_is_searched_in_every_part_with_the_label() {
    let j = job(vec![
        part(1, DataLabel::Narrative, "First narrative part."),
        part(
            2,
            DataLabel::Narrative,
            "Second narrative part has the quote.",
        ),
    ]);
    let p = block_on(fstp_assess::prepare(&NoNames, &j)).unwrap();
    let raw = RawFinding {
        kind: FindingKind::Quality,
        criterion: None,
        element: None,
        severity: Severity::Info,
        statement: UntrustedText::new("An observation.".to_owned()),
        evidence: vec![(
            DataLabel::Narrative,
            UntrustedText::new("has the quote".to_owned()),
        )],
    };
    let f = p.locate(raw).expect("the quote is in the second part");
    assert_eq!(f.evidence.len(), 1);
}
