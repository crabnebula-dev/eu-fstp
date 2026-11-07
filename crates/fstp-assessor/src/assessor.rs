//! One job: retrieval, stages 3 to 7 through `fstp_assess`, and the
//! result line (M7 design sections 3.1 and 3.2).
//!
//! A result line is one canonical JSON object with `status`:
//!
//! - `done`: `job`, `findings`, `dropped`, `replies` (the raw reply
//!   contents for the sealed trace, R-LA-07) and `retrievals` (the
//!   retrieval log). A finding has `kind`, `criterion` (decimal id or
//!   null), `element` (rubric tag or null), `severity`, `statement` and
//!   `evidence`, in the evidence codec of `fstp-findings`. A submission
//!   span is in offsets of the text the job sent. The cell maps it back
//!   to the original text, which never left the cell;
//! - `pending`: `job` and `error` (`mask`, `infer`, `output` or
//!   `protocol`). No finding is made up (R-NF-10);
//! - `refused`: `line` and `error`, the [`QueueError`] code, for a line
//!   that did not decode.
//!
//! The cell validates every result line before anything is stored. The
//! assessor has no other output and no write access (I-10).

use fstp_assess::{AssessError, AssessedFinding, Job, MaskUnavailable, NameMask, NameSpan};
use fstp_assess::{Pipeline, RUBRIC_V1, SubmissionPart};
use fstp_domain::id::{ContentDigest, ProposalId, TextRef};
use fstp_infer::{DataLabel, Protocol, Transport};
use fstp_json::{Array, Number, Object, ToJson, Value};
use fstp_retrieve::{ApplicantSources, Outcome, Refusal, SourceClass};

use crate::queue::{JobLine, QueueError, decode_job, id_json};
use crate::retrieval::Retrieval;

/// The name mask of the assessor. Legal names were masked in the cell
/// before the job was written, so no name is left to find here.
#[derive(Clone, Copy, Debug, Default)]
pub struct Premasked;

impl NameMask for Premasked {
    async fn names(
        &self,
        _proposal: ProposalId,
        _text: &str,
    ) -> Result<Vec<NameSpan>, MaskUnavailable> {
        Ok(Vec::new())
    }
}

/// The assessor of one process.
#[derive(Debug)]
pub struct Assessor<T, Q> {
    /// The inference transport.
    pub inference: T,
    /// The retrieval client.
    pub retrieval: Q,
    /// The protocol an HTTP endpoint speaks, which every job must use.
    /// `None` follows the job.
    pub protocol: Option<Protocol>,
}

fn status(s: &str) -> Value {
    Value::String(s.to_owned())
}

/// The result line of a line that did not decode.
pub fn refused(line: u64, e: QueueError) -> Value {
    let mut o = Object::new();
    o.insert("status", status("refused"));
    o.insert("line", Value::Number(Number::from(line)));
    o.insert("error", Value::String(e.code().to_owned()));
    Value::Object(o)
}

fn pending(job: u128, error: &str) -> Value {
    let mut o = Object::new();
    o.insert("status", status("pending"));
    o.insert("job", id_json(job));
    o.insert("error", Value::String(error.to_owned()));
    Value::Object(o)
}

fn finding_json(f: &AssessedFinding) -> Value {
    let mut o = Object::new();
    o.insert("kind", Value::String(kind_name(f.kind).to_owned()));
    o.insert(
        "criterion",
        f.criterion.map_or(Value::Null, |c| id_json(c.raw())),
    );
    o.insert(
        "element",
        f.element
            .map_or(Value::Null, |e| Value::String(e.as_str().to_owned())),
    );
    o.insert(
        "severity",
        Value::String(severity_name(f.severity).to_owned()),
    );
    o.insert("statement", Value::String(f.statement.as_data().to_owned()));
    o.insert(
        "evidence",
        Value::Array(f.evidence.iter().map(ToJson::to_json).collect()),
    );
    Value::Object(o)
}

const fn kind_name(k: fstp_findings::FindingKind) -> &'static str {
    match k {
        fstp_findings::FindingKind::Completeness => "completeness",
        fstp_findings::FindingKind::Quality => "quality",
        fstp_findings::FindingKind::Accuracy => "accuracy",
        fstp_findings::FindingKind::Integrity => "integrity",
    }
}

const fn severity_name(s: fstp_findings::Severity) -> &'static str {
    match s {
        fstp_findings::Severity::Info => "info",
        fstp_findings::Severity::Minor => "minor",
        fstp_findings::Severity::Major => "major",
    }
}

impl<T: Transport, Q: Retrieval> Assessor<T, Q> {
    /// Decodes one queue line and runs it. `line` is the line number,
    /// starting at 1, for a refusal.
    pub async fn handle_line(&self, line: u64, bytes: &[u8]) -> Value {
        match decode_job(bytes) {
            Ok(job) => self.run(&job).await,
            Err(e) => refused(line, e),
        }
    }

    /// Runs one decoded job and returns its result line.
    pub async fn run(&self, job: &JobLine) -> Value {
        if self.protocol.is_some_and(|p| p != job.config.protocol) {
            return pending(job.job, "protocol");
        }
        let mut own = ApplicantSources::new();
        for u in &job.own {
            own.add(u);
        }
        let mut parts: Vec<SubmissionPart> = job.parts.clone();
        let mut log = Array::new();
        for s in &job.sources {
            let mut entry = Object::new();
            entry.insert("url", Value::String(s.url.as_str().to_owned()));
            match self.retrieval.retrieve(&s.url).await {
                Outcome::Retrieved(r) => {
                    let class = r.class(&own);
                    let (label, name) = match class {
                        SourceClass::ApplicantControlled => {
                            (DataLabel::SourceApplicant, "applicant_controlled")
                        }
                        SourceClass::Independent => (DataLabel::SourceIndependent, "independent"),
                    };
                    entry.insert("class", Value::String(name.to_owned()));
                    entry.insert(
                        "chain",
                        Value::Array(
                            r.chain
                                .iter()
                                .map(|u| Value::String(u.as_str().to_owned()))
                                .collect(),
                        ),
                    );
                    entry.insert("truncated", Value::Bool(r.truncated));
                    let digest =
                        ContentDigest::from_bytes(fstp_crypto::sha256(r.text.as_data().as_bytes()));
                    entry.insert(
                        "text",
                        crate::queue::text_ref_json(TextRef::new(s.text, digest)),
                    );
                    parts.push(SubmissionPart {
                        label,
                        text_ref: TextRef::new(s.text, digest),
                        text: r.text,
                    });
                }
                Outcome::Refused(f) => {
                    entry.insert("refusal", Value::String(f.code().to_owned()));
                    if let Refusal::HttpStatus(code) = f {
                        entry.insert("status", Value::Number(Number::from(code)));
                    }
                }
            }
            log.push(Value::Object(entry));
        }
        let pipeline = Pipeline {
            transport: &self.inference,
            mask: &Premasked,
            protocol: job.config.protocol,
            model: job.config.model.clone(),
            decoding: job.config.decoding,
            criteria: job.config.criteria.clone(),
            rubric: &RUBRIC_V1,
        };
        let assess_job = Job {
            proposal: job.proposal,
            parts,
            handles: Vec::new(),
        };
        let a = match pipeline.assess(&assess_job).await {
            Ok(a) => a,
            Err(AssessError::Mask) => return pending(job.job, "mask"),
            Err(AssessError::Infer(_)) => return pending(job.job, "infer"),
            Err(AssessError::Output(_)) => return pending(job.job, "output"),
        };
        let mut o = Object::new();
        o.insert("status", status("done"));
        o.insert("job", id_json(job.job));
        o.insert(
            "findings",
            Value::Array(a.findings.iter().map(finding_json).collect()),
        );
        o.insert("dropped", Value::Number(Number::from(a.dropped)));
        o.insert(
            "replies",
            Value::Array(
                a.replies
                    .iter()
                    .map(|r| Value::String(r.as_data().to_owned()))
                    .collect(),
            ),
        );
        o.insert("retrievals", Value::Array(log));
        Value::Object(o)
    }
}

/// A result line as bytes, without the line feed. Canonical JSON never
/// holds a raw line feed, so each result is exactly one line.
pub fn result_bytes(v: &Value) -> Vec<u8> {
    match fstp_json::to_canonical(v) {
        Ok(s) => s.into_bytes(),
        Err(_) => b"{\"error\":\"encode\",\"status\":\"refused\"}".to_vec(),
    }
}
