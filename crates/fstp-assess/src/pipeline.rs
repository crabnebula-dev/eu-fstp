//! Stage orchestration (M7 design section 3.2).
//!
//! Stages 1 and 2 run in the cell: [`prepare`] extracts and strips every
//! part, and the placeholder map stays in the [`Prepared`] value. Stages 3
//! to 7 are model calls through `fstp_infer`, with the stripped text only
//! in data parts. Stage 7 also runs a deterministic scanner over the
//! stage 1 marks and over text addressed to an assessor. Stage 8 validates
//! each reply and locates its evidence. Any failed call fails the whole
//! assessment, which then stays pending (R-NF-10).

use core::fmt;

use fstp_domain::id::{CriterionId, ProposalId, TextRef};
use fstp_findings::{EvidenceRef, FindingKind, Severity, UntrustedText};
use fstp_infer::{
    DataLabel, DataPart, Decoding, ElementTag, InferError, InferRequest, Instruction, ModelName,
    OutputSchema, Protocol, Transport,
};

use crate::extract::{Mark, extract_text};
use crate::rubric::Rubric;
use crate::span::SpanMap;
use crate::strip::{NameMask, Placeholders, apply, detect, name_hits};
use crate::validate::{MAX_EVIDENCE, OutputError, RawFinding, Stage, decode_output};

/// One text of a submission, or one retrieved source, as the cell holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubmissionPart {
    /// What the text is. `SourceApplicant` and `SourceIndependent` parts
    /// are retrieved sources and reach only stage 6.
    pub label: DataLabel,
    /// The cell's reference to the text, for evidence pointers.
    pub text_ref: TextRef,
    /// The original text, untrusted.
    pub text: UntrustedText,
}

/// One assessment job: a proposal's texts and the team's handles.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Job {
    /// The proposal, which scopes the name-mask query.
    pub proposal: ProposalId,
    /// The texts.
    pub parts: Vec<SubmissionPart>,
    /// The team's display handles, which the cell knows.
    pub handles: Vec<String>,
}

/// Why an assessment did not complete. It stays pending; no finding is
/// made up (R-NF-10).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AssessError {
    /// The name-mask port was down or answered out of range. Nothing was
    /// sent (T-PRIV-CANARY).
    Mask,
    /// An inference call failed.
    Infer(InferError),
    /// A reply failed validation, so the whole result is refused (I-10).
    Output(OutputError),
}

impl fmt::Display for AssessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AssessError::Mask => f.write_str("name mask unavailable"),
            AssessError::Infer(e) => write!(f, "inference: {e}"),
            AssessError::Output(e) => write!(f, "output: {e}"),
        }
    }
}

impl std::error::Error for AssessError {}

/// One part after stages 1 and 2.
#[derive(Clone, Debug)]
pub struct PreparedPart {
    label: DataLabel,
    text_ref: TextRef,
    original_len: usize,
    marks: Vec<Mark>,
    stripped: UntrustedText,
    /// Stripped to pattern-stripped, pattern-stripped to cleaned, cleaned
    /// to original.
    maps: [SpanMap; 3],
}

impl PreparedPart {
    /// The label.
    pub fn label(&self) -> DataLabel {
        self.label
    }

    /// The cell's reference to the original text.
    pub fn text_ref(&self) -> TextRef {
        self.text_ref
    }

    /// The stripped text: the only text that leaves the cell.
    pub fn stripped(&self) -> &UntrustedText {
        &self.stripped
    }

    /// The hidden characters stage 1 removed, in original offsets.
    pub fn marks(&self) -> &[Mark] {
        &self.marks
    }

    /// The original span of the stripped span `a..b`.
    pub fn original_span(&self, a: usize, b: usize) -> Option<(usize, usize)> {
        let [names, patterns, extract] = &self.maps;
        let (a, b) = names.span(a, b)?;
        let (a, b) = patterns.span(a, b)?;
        extract.span(a, b)
    }

    fn is_source(&self) -> bool {
        matches!(
            self.label,
            DataLabel::SourceApplicant | DataLabel::SourceIndependent
        )
    }

    fn pointer(&self, start: usize, end: usize) -> Option<EvidenceRef> {
        if self.is_source() {
            return Some(EvidenceRef::Retrieved {
                source: self.text_ref,
            });
        }
        Some(EvidenceRef::Submission {
            text: self.text_ref,
            start: u32::try_from(start).ok()?,
            end: u32::try_from(end).ok()?,
        })
    }
}

/// A finding after validation, with located evidence (R-LA-02). The cell
/// adds its id, call, config, confidence and trace when it records it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssessedFinding {
    /// The kind.
    pub kind: FindingKind,
    /// The P-01 criterion, where one applies.
    pub criterion: Option<CriterionId>,
    /// The rubric element, where one applies.
    pub element: Option<ElementTag>,
    /// The severity.
    pub severity: Severity,
    /// The statement. Placeholders stay placeholders.
    pub statement: UntrustedText,
    /// At least one well-formed pointer.
    pub evidence: Vec<EvidenceRef>,
}

/// A job after stages 1 and 2. The placeholder map stays here.
#[derive(Clone, Debug)]
pub struct Prepared {
    parts: Vec<PreparedPart>,
    placeholders: Placeholders,
}

impl Prepared {
    /// The prepared parts, in job order.
    pub fn parts(&self) -> &[PreparedPart] {
        &self.parts
    }

    /// How many distinct values stage 2 replaced.
    pub fn replaced(&self) -> usize {
        self.placeholders.len()
    }

    fn data(&self, sources: bool) -> Vec<DataPart> {
        self.parts
            .iter()
            .filter(|p| sources || !p.is_source())
            .map(|p| DataPart::new(p.label, p.stripped.clone()))
            .collect()
    }

    /// Locates the evidence of `raw` in the stripped texts and maps it to
    /// original spans (R-LA-02). Quotes that are not found are dropped. A
    /// finding with no located quote is dropped, except a completeness
    /// finding without quotes, which points at the end of the narrative,
    /// where the element is missing.
    pub fn locate(&self, raw: RawFinding) -> Option<AssessedFinding> {
        let mut evidence = Vec::new();
        for (label, quote) in &raw.evidence {
            let q = quote.as_data();
            if q.is_empty() {
                continue;
            }
            let Some(part) = self.parts.iter().find(|p| p.label == *label) else {
                continue;
            };
            let Some(a) = part.stripped.as_data().find(q) else {
                continue;
            };
            let located = part
                .original_span(a, a.saturating_add(q.len()))
                .and_then(|(s, e)| part.pointer(s, e));
            if let Some(p) = located
                && !evidence.contains(&p)
            {
                evidence.push(p);
            }
        }
        if evidence.is_empty() && raw.evidence.is_empty() && raw.kind == FindingKind::Completeness {
            let part = self
                .parts
                .iter()
                .find(|p| p.label == DataLabel::Narrative)
                .or_else(|| self.parts.iter().find(|p| !p.is_source()))?;
            evidence.push(part.pointer(part.original_len, part.original_len)?);
        }
        if evidence.is_empty() {
            return None;
        }
        Some(AssessedFinding {
            kind: raw.kind,
            criterion: raw.criterion,
            element: raw.element,
            severity: raw.severity,
            statement: raw.statement,
            evidence,
        })
    }

    /// Stage 7, deterministic part: hidden characters and text addressed
    /// to an assessor become integrity findings (TH-01, T-LLM-INJ).
    pub fn integrity_scan(&self) -> Vec<AssessedFinding> {
        let mut out = Vec::new();
        for p in self.parts.iter().filter(|p| !p.is_source()) {
            let marks: Vec<EvidenceRef> = p
                .marks
                .iter()
                .take(MAX_EVIDENCE)
                .filter_map(|m| p.pointer(m.start, m.end))
                .collect();
            if !marks.is_empty() {
                out.push(integrity(
                    "The text holds hidden or control characters. They were removed before assessment.",
                    marks,
                ));
            }
            let text = p.stripped.as_data();
            let lower = text.to_ascii_lowercase();
            let hit = ADDRESSED
                .iter()
                .filter_map(|ph| lower.find(ph).map(|at| (at, ph.len())))
                .min();
            if let Some(ev) = hit
                .and_then(|(at, len)| p.original_span(at, at.saturating_add(len)))
                .and_then(|(s, e)| p.pointer(s, e))
            {
                out.push(integrity(
                    "The text addresses an assessor or a model. It is treated as data.",
                    vec![ev],
                ));
            }
        }
        out
    }
}

/// Phrases that address an assessor or a model, lowercase ASCII.
const ADDRESSED: [&str; 11] = [
    "ignore previous",
    "ignore all previous",
    "disregard previous",
    "system prompt",
    "language model",
    "as an ai",
    "assessor",
    "assessment system",
    "ai system",
    "ai reviewer",
    "previous instructions",
];

fn integrity(statement: &str, evidence: Vec<EvidenceRef>) -> AssessedFinding {
    AssessedFinding {
        kind: FindingKind::Integrity,
        criterion: None,
        element: None,
        severity: Severity::Major,
        statement: UntrustedText::new(statement.to_owned()),
        evidence,
    }
}

/// Stages 1 and 2 over every part of `job`.
///
/// # Errors
///
/// Returns [`AssessError::Mask`] when the name-mask port is down or gives
/// spans outside the text. Nothing leaves the cell then.
pub async fn prepare<M: NameMask>(mask: &M, job: &Job) -> Result<Prepared, AssessError> {
    let mut placeholders = Placeholders::default();
    let mut parts = Vec::with_capacity(job.parts.len());
    for part in &job.parts {
        let original = part.text.as_data();
        let x = extract_text(original);
        let hits = detect(x.text(), &job.handles);
        let (patterned, pattern_map) = apply(x.text(), &hits, &mut placeholders);
        let spans = mask
            .names(job.proposal, &patterned)
            .await
            .map_err(|_| AssessError::Mask)?;
        let names = name_hits(&patterned, &spans).ok_or(AssessError::Mask)?;
        let (stripped, name_map) = apply(&patterned, &names, &mut placeholders);
        parts.push(PreparedPart {
            label: part.label,
            text_ref: part.text_ref,
            original_len: original.len(),
            marks: x.marks().to_vec(),
            stripped: UntrustedText::new(stripped),
            maps: [name_map, pattern_map, x.map().clone()],
        });
    }
    Ok(Prepared {
        parts,
        placeholders,
    })
}

/// The result of one assessment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Assessment {
    /// The validated findings with located evidence.
    pub findings: Vec<AssessedFinding>,
    /// Findings dropped for lack of located evidence (R-LA-02), for the
    /// trace.
    pub dropped: u32,
    /// The raw reply contents, in call order, for the sealed trace
    /// (R-LA-07).
    pub replies: Vec<UntrustedText>,
}

/// The pipeline of one call's configuration.
#[derive(Debug)]
pub struct Pipeline<'a, T, M> {
    /// The transport to the model.
    pub transport: &'a T,
    /// The name-mask port.
    pub mask: &'a M,
    /// The wire protocol of the pinned configuration (ADR-019). The
    /// configuration chooses it; [`Protocol::default`] is Anthropic.
    pub protocol: Protocol,
    /// The model of the pinned configuration.
    pub model: ModelName,
    /// The decoding parameters of the pinned configuration.
    pub decoding: Decoding,
    /// The criterion ids of the call's frozen P-01, in order.
    pub criteria: Vec<CriterionId>,
    /// The pinned rubric.
    pub rubric: &'a Rubric,
}

impl<T: Transport, M: NameMask> Pipeline<'_, T, M> {
    async fn call(
        &self,
        stage: Stage,
        instruction: Instruction,
        data: Vec<DataPart>,
        prepared: &Prepared,
        out: &mut Assessment,
    ) -> Result<(), AssessError> {
        let req = InferRequest {
            protocol: self.protocol,
            model: self.model.clone(),
            decoding: self.decoding,
            instruction,
            data,
            schema: Some(OutputSchema::FindingsV1),
        };
        let reply = fstp_infer::infer(self.transport, &req)
            .await
            .map_err(AssessError::Infer)?;
        let raw = decode_output(reply.content.as_data(), stage, &self.criteria, self.rubric)
            .map_err(AssessError::Output)?;
        out.replies.push(reply.content);
        for r in raw {
            match prepared.locate(r) {
                Some(f) => out.findings.push(f),
                None => out.dropped = out.dropped.saturating_add(1),
            }
        }
        Ok(())
    }

    /// Runs stages 1 to 8 over `job`.
    ///
    /// # Errors
    ///
    /// Returns an [`AssessError`] for the first stage that failed. The
    /// assessment then stays pending and nothing is published.
    pub async fn assess(&self, job: &Job) -> Result<Assessment, AssessError> {
        let prepared = prepare(self.mask, job).await?;
        let mut out = Assessment {
            findings: Vec::new(),
            dropped: 0,
            replies: Vec::new(),
        };
        let data = prepared.data(false);
        let elements = self.rubric.required();

        let i = Instruction::new(Stage::Completeness.prompt()).elements(elements);
        self.call(Stage::Completeness, i, data.clone(), &prepared, &mut out)
            .await?;
        for c in &self.criteria {
            let i = Instruction::new(Stage::Quality.prompt()).criterion(*c);
            self.call(Stage::Quality, i, data.clone(), &prepared, &mut out)
                .await?;
        }
        let i = Instruction::new(Stage::Claims.prompt());
        self.call(Stage::Claims, i, data.clone(), &prepared, &mut out)
            .await?;
        if prepared.parts.iter().any(PreparedPart::is_source) {
            let i = Instruction::new(Stage::Verify.prompt());
            self.call(Stage::Verify, i, prepared.data(true), &prepared, &mut out)
                .await?;
        }
        let i = Instruction::new(Stage::Integrity.prompt());
        self.call(Stage::Integrity, i, data, &prepared, &mut out)
            .await?;
        out.findings.extend(prepared.integrity_scan());
        Ok(out)
    }
}
