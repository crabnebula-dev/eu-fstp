//! Stage 8: the output validator (M7 design section 3.4, I-10).
//!
//! The decoder accepts only the members of the v1 output schema. Any
//! other member, at any level, refuses the whole result, so a model cannot
//! add `score`, `decision` or `state`. No member holds a number. A
//! statement that reads like a score, a rank or a funding recommendation
//! refuses the whole result as well. Criteria must be in the frozen P-01
//! and elements in the pinned rubric. Fuzz target `assess_output_decode`.

use core::fmt;

use fstp_domain::id::CriterionId;
use fstp_findings::{FindingKind, Severity, UntrustedText};
use fstp_infer::{DataLabel, ElementTag, MAX_CONTENT_BYTES, Prompt};
use fstp_json::{Object, ParseLimits, Value};

use crate::rubric::Rubric;

/// The largest statement, in bytes.
pub const MAX_STATEMENT_BYTES: usize = 1000;
/// The most findings in one result.
pub const MAX_FINDINGS: usize = 64;
/// The most evidence entries of one finding.
pub const MAX_EVIDENCE: usize = 8;

/// The stage whose output is validated. Each stage answers only with its
/// own kinds of finding, and integrity findings come from any stage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Stage {
    /// Stage 3.
    Completeness,
    /// Stage 4.
    Quality,
    /// Stage 5.
    Claims,
    /// Stage 6.
    Verify,
    /// Stage 7.
    Integrity,
}

impl Stage {
    /// The pinned prompt of the stage.
    pub const fn prompt(self) -> Prompt {
        match self {
            Stage::Completeness => Prompt::Completeness,
            Stage::Quality => Prompt::Quality,
            Stage::Claims => Prompt::Claims,
            Stage::Verify => Prompt::Verify,
            Stage::Integrity => Prompt::Integrity,
        }
    }

    fn allows(self, kind: FindingKind) -> bool {
        kind == FindingKind::Integrity
            || matches!(
                (self, kind),
                (Stage::Completeness, FindingKind::Completeness)
                    | (Stage::Quality, FindingKind::Quality)
                    | (Stage::Claims | Stage::Verify, FindingKind::Accuracy)
            )
    }
}

/// Why a model output was refused. No variant carries output content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputError {
    /// The output is not I-JSON within the limits.
    Json,
    /// An object holds a member outside the schema.
    UnknownMember,
    /// A member is missing or has the wrong type or value.
    Shape(&'static str),
    /// A statement reads like a score, a rank or a recommendation.
    ScoreLike,
    /// A criterion outside the frozen P-01, or missing on quality.
    Criterion,
    /// An element outside the pinned rubric, or missing on completeness.
    Element,
    /// A finding kind the stage does not produce.
    Kind,
    /// A statement or quote is too long, or there are too many entries.
    TooLong,
}

impl fmt::Display for OutputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OutputError::Json => f.write_str("output is not JSON"),
            OutputError::UnknownMember => f.write_str("unknown member"),
            OutputError::Shape(w) => write!(f, "bad shape: {w}"),
            OutputError::ScoreLike => f.write_str("score-like statement"),
            OutputError::Criterion => f.write_str("criterion outside P-01"),
            OutputError::Element => f.write_str("element outside the rubric"),
            OutputError::Kind => f.write_str("finding kind outside the stage"),
            OutputError::TooLong => f.write_str("output too long"),
        }
    }
}

impl std::error::Error for OutputError {}

/// One decoded finding, before its evidence is located.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawFinding {
    /// The kind.
    pub kind: FindingKind,
    /// The P-01 criterion, where one applies.
    pub criterion: Option<CriterionId>,
    /// The rubric element, where one applies.
    pub element: Option<ElementTag>,
    /// The severity.
    pub severity: Severity,
    /// The statement, as data.
    pub statement: UntrustedText,
    /// Quotes, each with the label of its data part.
    pub evidence: Vec<(DataLabel, UntrustedText)>,
}

const TOP: [&str; 1] = ["findings"];
const FINDING: [&str; 6] = [
    "kind",
    "criterion",
    "element",
    "severity",
    "statement",
    "evidence",
];
const EVIDENCE: [&str; 2] = ["part", "quote"];

fn limits() -> ParseLimits {
    ParseLimits {
        max_input_bytes: MAX_CONTENT_BYTES,
        max_depth: 8,
        max_string_bytes: MAX_CONTENT_BYTES,
        max_number_len: 32,
        max_container_len: 128,
        max_nodes: 4096,
        max_memory_bytes: 4 << 20,
    }
}

fn closed(v: &Value, allowed: &[&str], what: &'static str) -> Result<(), OutputError> {
    let o: &Object = v.as_object().ok_or(OutputError::Shape(what))?;
    if o.keys().all(|k| allowed.contains(&k)) {
        Ok(())
    } else {
        Err(OutputError::UnknownMember)
    }
}

fn string<'a>(v: &'a Value, key: &'static str) -> Result<&'a str, OutputError> {
    v.get(key)
        .and_then(Value::as_str)
        .ok_or(OutputError::Shape(key))
}

/// A string or null member.
fn opt_string<'a>(v: &'a Value, key: &'static str) -> Result<Option<&'a str>, OutputError> {
    match v.get(key) {
        Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        _ => Err(OutputError::Shape(key)),
    }
}

/// `c-<32 lowercase hex digits>`, as `fstp_infer` spells a criterion.
fn parse_criterion(s: &str) -> Option<CriterionId> {
    let hex = s.strip_prefix("c-")?;
    if hex.len() != 32 || !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    u128::from_str_radix(hex, 16)
        .ok()
        .map(CriterionId::from_raw)
}

fn kind(s: &str) -> Option<FindingKind> {
    match s {
        "completeness" => Some(FindingKind::Completeness),
        "quality" => Some(FindingKind::Quality),
        "accuracy" => Some(FindingKind::Accuracy),
        "integrity" => Some(FindingKind::Integrity),
        _ => None,
    }
}

fn severity(s: &str) -> Option<Severity> {
    match s {
        "info" => Some(Severity::Info),
        "minor" => Some(Severity::Minor),
        "major" => Some(Severity::Major),
        _ => None,
    }
}

/// Words that make a statement read like a score, a band, a rank, a
/// weight or a funding recommendation (I-10, T-LLM-ORACLE).
const SCORE_WORDS: [&str; 26] = [
    "score",
    "scores",
    "scored",
    "scoring",
    "rating",
    "ratings",
    "rated",
    "grade",
    "graded",
    "band",
    "bands",
    "rank",
    "ranked",
    "ranking",
    "points",
    "weight",
    "weighted",
    "recommend",
    "recommends",
    "recommended",
    "recommendation",
    "reject",
    "rejected",
    "rejection",
    "fundable",
    "unfundable",
];
/// Phrases of the same kind, matched on whole words.
const SCORE_PHRASES: [&str; 5] = [
    " out of ",
    " rate it ",
    " rate this ",
    " be funded ",
    " not fund ",
];

/// Whether `s` reads like a score.
pub fn score_like(s: &str) -> bool {
    let lower = s.to_lowercase();
    let words: Vec<&str> = lower
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .collect();
    if words.iter().any(|w| SCORE_WORDS.contains(w)) {
        return true;
    }
    let joined = format!(" {} ", words.join(" "));
    if SCORE_PHRASES.iter().any(|p| joined.contains(p)) {
        return true;
    }
    // A fraction such as `9/10` or `4 / 5`.
    let b = lower.as_bytes();
    b.iter().enumerate().any(|(i, c)| {
        if *c != b'/' {
            return false;
        }
        let before = b
            .get(..i)
            .and_then(|r| r.iter().rev().find(|x| **x != b' '));
        let after = b
            .get(i.saturating_add(1)..)
            .and_then(|r| r.iter().find(|x| **x != b' '));
        before.is_some_and(u8::is_ascii_digit) && after.is_some_and(u8::is_ascii_digit)
    })
}

fn label(s: &str) -> Option<DataLabel> {
    DataLabel::ALL.into_iter().find(|l| l.as_str() == s)
}

fn finding(
    v: &Value,
    stage: Stage,
    criteria: &[CriterionId],
    rubric: &Rubric,
) -> Result<RawFinding, OutputError> {
    closed(v, &FINDING, "finding")?;
    let kind = kind(string(v, "kind")?).ok_or(OutputError::Shape("kind"))?;
    let criterion = match opt_string(v, "criterion")? {
        None => None,
        Some(s) => {
            let c = parse_criterion(s).ok_or(OutputError::Criterion)?;
            if !criteria.contains(&c) {
                return Err(OutputError::Criterion);
            }
            Some(c)
        }
    };
    let element = match opt_string(v, "element")? {
        None => None,
        Some(s) => {
            let e = ElementTag::parse(s).ok_or(OutputError::Element)?;
            if !rubric.contains(e) {
                return Err(OutputError::Element);
            }
            Some(e)
        }
    };
    let severity = severity(string(v, "severity")?).ok_or(OutputError::Shape("severity"))?;
    let statement = string(v, "statement")?;
    if statement.len() > MAX_STATEMENT_BYTES {
        return Err(OutputError::TooLong);
    }
    if score_like(statement) {
        return Err(OutputError::ScoreLike);
    }
    let evidence = v
        .get("evidence")
        .and_then(Value::as_array)
        .ok_or(OutputError::Shape("evidence"))?;
    if evidence.len() > MAX_EVIDENCE {
        return Err(OutputError::TooLong);
    }
    let mut ev = Vec::new();
    for e in evidence.iter() {
        closed(e, &EVIDENCE, "evidence")?;
        let part = label(string(e, "part")?).ok_or(OutputError::Shape("part"))?;
        let quote = string(e, "quote")?;
        if quote.len() > MAX_STATEMENT_BYTES {
            return Err(OutputError::TooLong);
        }
        ev.push((part, UntrustedText::new(quote.to_owned())));
    }
    if !stage.allows(kind) {
        return Err(OutputError::Kind);
    }
    if kind == FindingKind::Quality && criterion.is_none() {
        return Err(OutputError::Criterion);
    }
    if kind == FindingKind::Completeness && element.is_none() {
        return Err(OutputError::Element);
    }
    Ok(RawFinding {
        kind,
        criterion,
        element,
        severity,
        statement: UntrustedText::new(statement.to_owned()),
        evidence: ev,
    })
}

/// Decodes one model reply of `stage` against the frozen P-01 `criteria`
/// and the pinned `rubric`.
///
/// # Errors
///
/// Returns an [`OutputError`] for anything outside the v1 schema. One bad
/// finding refuses the whole result.
pub fn decode_output(
    content: &str,
    stage: Stage,
    criteria: &[CriterionId],
    rubric: &Rubric,
) -> Result<Vec<RawFinding>, OutputError> {
    if content.len() > MAX_CONTENT_BYTES {
        return Err(OutputError::TooLong);
    }
    let v = fstp_json::parse_with(content.as_bytes(), &limits()).map_err(|_| OutputError::Json)?;
    closed(&v, &TOP, "output")?;
    let list = v
        .get("findings")
        .and_then(Value::as_array)
        .ok_or(OutputError::Shape("findings"))?;
    if list.len() > MAX_FINDINGS {
        return Err(OutputError::TooLong);
    }
    list.iter()
        .map(|f| finding(f, stage, criteria, rubric))
        .collect()
}
