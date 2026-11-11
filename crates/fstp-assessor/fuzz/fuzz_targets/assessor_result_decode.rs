//! TH-26, I-10: the cell's result intake (M7 design section 3.1) against
//! arbitrary result lines.
//!
//! Properties checked beyond "no panic":
//!
//! - an accepted `done` result has findings with at least one evidence
//!   pointer each, every pointer inside a text of the job (R-LA-02);
//! - an accepted finding names only a criterion of the job.

#![no_main]

use fstp_assess::SubmissionPart;
use fstp_assessor::{Intake, JobConfig, JobLine, decode_result};
use fstp_domain::id::{ContentDigest, CriterionId, ProposalId, TextId, TextRef};
use fstp_findings::{EvidenceRef, UntrustedText};
use fstp_infer::{DataLabel, Decoding, ModelName, Protocol};
use libfuzzer_sys::fuzz_target;

fn job() -> JobLine {
    let body = "The problem is weak signing. We will build a verifier.";
    JobLine {
        job: 7,
        proposal: ProposalId::from_raw(1),
        config: JobConfig {
            protocol: Protocol::Anthropic,
            model: ModelName::new("synthetic").expect("a valid model name"),
            decoding: Decoding {
                max_tokens: 1024,
                temperature_milli: 0,
                seed: 1,
            },
            criteria: vec![CriterionId::from_raw(1)],
        },
        parts: vec![SubmissionPart {
            label: DataLabel::Narrative,
            text_ref: TextRef::new(TextId::from_raw(3), ContentDigest::from_bytes([0; 32])),
            text: UntrustedText::new(body.to_owned()),
        }],
        sources: Vec::new(),
        own: Vec::new(),
    }
}

fuzz_target!(|data: &[u8]| {
    let j = job();
    if let Ok(Intake::Done { findings, .. }) = decode_result(data, &j) {
        for f in &findings {
            assert!(!f.evidence.is_empty(), "a finding without evidence");
            if let Some(c) = f.criterion {
                assert!(j.config.criteria.contains(&c), "criterion outside the job");
            }
            for e in &f.evidence {
                match e {
                    EvidenceRef::Submission { text, end, .. } => {
                        let p = j.parts.iter().find(|p| p.text_ref == *text);
                        let p = p.expect("evidence outside the job");
                        assert!((*end as usize) <= p.text.as_data().len());
                    }
                    EvidenceRef::Retrieved { .. } => panic!("no sources in this job"),
                }
            }
        }
    }
});
