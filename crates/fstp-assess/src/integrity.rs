//! Stage 7, deterministic part: the injection scan of `fstp_injscan`
//! turned into integrity findings (ADR-035, TH-01, T-LLM-INJ).
//!
//! One finding per part and reason. Its statement is fixed platform text
//! that names the kind and the part in plain words and never quotes the
//! scanned text. Its evidence points at the detected spans of the
//! original text, at most `MAX_EVIDENCE` of them (R-LA-02).
//!
//! The same function serves the pre-check, the cell assessor and the
//! intake scan at submission, so the applicant and the reviewers read the
//! same words for the same text.

use fstp_findings::{EvidenceRef, FindingKind, Severity, UntrustedText};
use fstp_infer::DataLabel;
use fstp_injscan::Reason;

use crate::pipeline::{AssessedFinding, SubmissionPart};
use crate::validate::MAX_EVIDENCE;

/// The part name in plain words.
fn part_name(label: DataLabel) -> &'static str {
    match label {
        DataLabel::Title => "title",
        DataLabel::Summary => "summary",
        DataLabel::Narrative => "narrative",
        DataLabel::Plan => "plan",
        DataLabel::Claim => "claim",
        DataLabel::SourceApplicant | DataLabel::SourceIndependent => "source",
    }
}

/// The statement of an integrity finding on `reason` in the part
/// `label`: fixed platform text (ADR-035 "Integrity finding").
pub fn integrity_statement(label: DataLabel, reason: Reason) -> String {
    let tail = if reason.is_hidden() {
        "They were removed before any AI system read it."
    } else if reason == Reason::Truncated {
        "That part was not scanned."
    } else {
        "AI systems receive it marked as data, never as an instruction."
    };
    let head = format!("The {} holds {}.", part_name(label), reason.words());
    format!("{head} {tail}")
}

/// The severity of an integrity finding on `reason`.
pub fn integrity_severity(reason: Reason) -> Severity {
    match reason {
        Reason::Truncated => Severity::Info,
        Reason::Confusable | Reason::EncodedBlob | Reason::ExfilLink | Reason::SchemaPayload => {
            Severity::Minor
        }
        _ => Severity::Major,
    }
}

/// The integrity findings of the scan of `parts`. Retrieved sources are
/// not scanned here: they reach only stage 6.
pub fn scan_findings(parts: &[SubmissionPart]) -> Vec<AssessedFinding> {
    let mut out = Vec::new();
    for part in parts.iter().filter(|p| {
        !matches!(
            p.label,
            DataLabel::SourceApplicant | DataLabel::SourceIndependent
        )
    }) {
        let scan = fstp_injscan::scan(part.text.as_data());
        for reason in scan.reasons() {
            let evidence: Vec<EvidenceRef> = scan
                .detections()
                .iter()
                .filter(|d| d.reason == reason)
                .take(MAX_EVIDENCE)
                .filter_map(|d| {
                    Some(EvidenceRef::Submission {
                        text: part.text_ref,
                        start: u32::try_from(d.start).ok()?,
                        end: u32::try_from(d.end).ok()?,
                    })
                })
                .collect();
            if evidence.is_empty() {
                continue;
            }
            out.push(AssessedFinding {
                kind: FindingKind::Integrity,
                criterion: None,
                element: None,
                severity: integrity_severity(reason),
                statement: UntrustedText::new(integrity_statement(part.label, reason)),
                evidence,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ADR-035, R-NF-02: the statement is platform text that never quotes
    /// the scanned text.
    #[test]
    fn adr035_statement_is_platform_text() {
        for r in Reason::ALL {
            let s = integrity_statement(DataLabel::Narrative, r);
            assert!(s.starts_with("The narrative holds "));
            assert!(s.len() < 200);
        }
    }
}
