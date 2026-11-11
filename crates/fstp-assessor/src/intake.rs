//! The cell side of the queue (M7 design section 3.1, the L-CELL slice
//! that lane L-DEMO built for the demo path).
//!
//! - [`CellJob::prepare`] runs stages 1 and 2 in the cell and writes the
//!   job line with stripped bodies only. The placeholder map and the span
//!   maps stay in the [`CellJob`]; they never reach the assessor.
//! - [`decode_result`] reads one result line against the job it answers.
//!   It accepts only the closed result shape: a member such as `score` or
//!   `decision` fails the whole line (I-10). Every finding names a P-01
//!   criterion of the job, a rubric element of v1, a bounded statement
//!   and at least one evidence pointer into a text of the job (R-LA-02).
//!   It is the fuzz target `assessor_result_decode` (TH-26).
//! - [`CellJob::intake`] decodes a result and maps each submission span
//!   back to the original text, which never left the cell.
//! - [`Link`] reaches the assessor: the `fstp-assessor` child process over
//!   one Unix socket as its stdin, or the synthetic model in process for
//!   tests that run without the binary.
//!
//! Nothing here records a finding. The caller turns a validated finding
//! into `FindingCommand::Record` under a system actor, which is the only
//! path from the assessor to domain state (I-10).

use std::io::{self, Write};
use std::net::Shutdown;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use fstp_assess::{
    Job, MAX_EVIDENCE, MAX_STATEMENT_BYTES, NameMask, Prepared, RUBRIC_V1, SubmissionPart, prepare,
    score_like,
};
use fstp_domain::id::{CriterionId, ProposalId};
use fstp_findings::{EvidenceRef, FindingKind, Severity, UntrustedText};
use fstp_infer::{ElementTag, SyntheticModel};
use fstp_json::{FromJson, Object, ParseLimits, Value};

use crate::assessor::{Assessor, result_bytes};
use crate::queue::{JobConfig, JobLine, Line, LineReader, parse_id};
use crate::retrieval::NoRetrieval;

/// The longest result line the cell reads, in bytes. A result carries
/// the raw replies for the sealed trace, so it is longer than a job.
pub const MAX_RESULT_BYTES: usize = 8 << 20;
/// The most findings one result may carry.
pub const MAX_RESULT_FINDINGS: usize = 512;
/// The most raw replies one result may carry.
pub const MAX_REPLIES: usize = 64;
/// The most retrieval log entries one result may carry.
pub const MAX_RETRIEVALS: usize = 64;

/// Why a result line was refused. No variant carries result content
/// (R-NF-02).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntakeError {
    /// The line is longer than [`MAX_RESULT_BYTES`].
    TooLong,
    /// The line is not one JSON text within the limits.
    Json,
    /// An object holds a member outside the result shape, such as
    /// `score` or `decision` (I-10).
    UnknownMember,
    /// A member is missing or has the wrong type or value.
    Shape(&'static str),
    /// The result names another job.
    OtherJob,
    /// A criterion outside the job's frozen P-01.
    Criterion,
    /// An element outside the pinned rubric.
    Element,
    /// A statement over the bound, or one that reads like a score (I-10).
    Statement,
    /// An evidence pointer outside the job's texts, or none at all
    /// (R-LA-02).
    Evidence,
    /// A list over its limit.
    TooMany(&'static str),
}

/// Why a job stayed pending in the assessor. No finding is made up
/// (R-NF-10).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingCause {
    /// The name mask was down.
    Mask,
    /// An inference call failed.
    Infer,
    /// A model reply failed validation.
    Output,
    /// The job asked for a protocol the endpoint does not speak.
    Protocol,
}

impl PendingCause {
    /// The wire spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            PendingCause::Mask => "mask",
            PendingCause::Infer => "infer",
            PendingCause::Output => "output",
            PendingCause::Protocol => "protocol",
        }
    }
}

/// One validated finding of a result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntakeFinding {
    /// The kind.
    pub kind: FindingKind,
    /// The P-01 criterion, one of the job's.
    pub criterion: Option<CriterionId>,
    /// The rubric element, one of v1's.
    pub element: Option<ElementTag>,
    /// The severity.
    pub severity: Severity,
    /// The statement, as data.
    pub statement: UntrustedText,
    /// At least one pointer into a text of the job.
    pub evidence: Vec<EvidenceRef>,
}

/// One validated result line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Intake {
    /// The job ran.
    Done {
        /// The findings.
        findings: Vec<IntakeFinding>,
        /// Findings the assessor dropped for lack of located evidence.
        dropped: u32,
        /// The raw replies, for the sealed trace (R-LA-07).
        replies: Vec<UntrustedText>,
        /// The retrieval log, kept as data for the trace.
        retrievals: Vec<Value>,
    },
    /// The job stayed pending (R-NF-10).
    Pending(PendingCause),
    /// The assessor could not decode the job line the cell wrote.
    Refused,
}

fn limits() -> ParseLimits {
    ParseLimits {
        max_input_bytes: MAX_RESULT_BYTES,
        max_depth: 8,
        max_string_bytes: MAX_RESULT_BYTES,
        max_number_len: 20,
        max_container_len: MAX_RESULT_FINDINGS,
        max_nodes: 1 << 16,
        max_memory_bytes: 32 << 20,
    }
}

fn object<'a>(v: &'a Value, fields: &[&str]) -> Result<&'a Object, IntakeError> {
    let o = v.as_object().ok_or(IntakeError::Shape("object"))?;
    if o.keys().all(|k| fields.contains(&k)) {
        Ok(o)
    } else {
        Err(IntakeError::UnknownMember)
    }
}

fn get<'a>(o: &'a Object, key: &'static str) -> Result<&'a Value, IntakeError> {
    o.get(key).ok_or(IntakeError::Shape(key))
}

fn str_of<'a>(o: &'a Object, key: &'static str) -> Result<&'a str, IntakeError> {
    get(o, key)?.as_str().ok_or(IntakeError::Shape(key))
}

fn list<'a>(
    o: &'a Object,
    key: &'static str,
    max: usize,
) -> Result<&'a fstp_json::Array, IntakeError> {
    let a = get(o, key)?.as_array().ok_or(IntakeError::Shape(key))?;
    if a.len() > max {
        return Err(IntakeError::TooMany(key));
    }
    Ok(a)
}

const DONE: [&str; 6] = [
    "status",
    "job",
    "findings",
    "dropped",
    "replies",
    "retrievals",
];
const PENDING: [&str; 3] = ["status", "job", "error"];
const REFUSED: [&str; 3] = ["status", "line", "error"];
const FINDING: [&str; 6] = [
    "kind",
    "criterion",
    "element",
    "severity",
    "statement",
    "evidence",
];

/// Decodes one result line against `job`, the job it answers. Spans
/// stay in offsets of the job's bodies.
///
/// # Errors
///
/// An [`IntakeError`] for anything outside the closed result shape. The
/// whole line is refused then, and nothing of it is stored (I-10).
pub fn decode_result(line: &[u8], job: &JobLine) -> Result<Intake, IntakeError> {
    if line.len() > MAX_RESULT_BYTES {
        return Err(IntakeError::TooLong);
    }
    let v = fstp_json::parse_with(line, &limits()).map_err(|_| IntakeError::Json)?;
    let top = v.as_object().ok_or(IntakeError::Shape("object"))?;
    match top.get("status").and_then(Value::as_str) {
        Some("refused") => {
            let o = object(&v, &REFUSED)?;
            get(o, "line")?.as_u64().ok_or(IntakeError::Shape("line"))?;
            str_of(o, "error")?;
            Ok(Intake::Refused)
        }
        Some("pending") => {
            let o = object(&v, &PENDING)?;
            if parse_id(str_of(o, "job")?) != Some(job.job) {
                return Err(IntakeError::OtherJob);
            }
            let cause = match str_of(o, "error")? {
                "mask" => PendingCause::Mask,
                "infer" => PendingCause::Infer,
                "output" => PendingCause::Output,
                "protocol" => PendingCause::Protocol,
                _ => return Err(IntakeError::Shape("error")),
            };
            Ok(Intake::Pending(cause))
        }
        Some("done") => {
            let o = object(&v, &DONE)?;
            if parse_id(str_of(o, "job")?) != Some(job.job) {
                return Err(IntakeError::OtherJob);
            }
            let dropped = get(o, "dropped")?
                .as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .ok_or(IntakeError::Shape("dropped"))?;
            let findings = list(o, "findings", MAX_RESULT_FINDINGS)?
                .iter()
                .map(|f| finding(f, job))
                .collect::<Result<Vec<_>, _>>()?;
            let replies = list(o, "replies", MAX_REPLIES)?
                .iter()
                .map(|r| {
                    r.as_str()
                        .map(|s| UntrustedText::new(s.to_owned()))
                        .ok_or(IntakeError::Shape("replies"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            let retrievals = list(o, "retrievals", MAX_RETRIEVALS)?
                .iter()
                .map(|r| {
                    r.as_object()
                        .map(|_| r.clone())
                        .ok_or(IntakeError::Shape("retrievals"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Intake::Done {
                findings,
                dropped,
                replies,
                retrievals,
            })
        }
        _ => Err(IntakeError::Shape("status")),
    }
}

fn finding(v: &Value, job: &JobLine) -> Result<IntakeFinding, IntakeError> {
    let o = object(v, &FINDING)?;
    let kind = match str_of(o, "kind")? {
        "completeness" => FindingKind::Completeness,
        "quality" => FindingKind::Quality,
        "accuracy" => FindingKind::Accuracy,
        "integrity" => FindingKind::Integrity,
        _ => return Err(IntakeError::Shape("kind")),
    };
    let severity = match str_of(o, "severity")? {
        "info" => Severity::Info,
        "minor" => Severity::Minor,
        "major" => Severity::Major,
        _ => return Err(IntakeError::Shape("severity")),
    };
    let criterion = match get(o, "criterion")? {
        Value::Null => None,
        Value::String(s) => {
            let c = parse_id(s)
                .map(CriterionId::from_raw)
                .ok_or(IntakeError::Shape("criterion"))?;
            if !job.config.criteria.contains(&c) {
                return Err(IntakeError::Criterion);
            }
            Some(c)
        }
        _ => return Err(IntakeError::Shape("criterion")),
    };
    let element = match get(o, "element")? {
        Value::Null => None,
        Value::String(s) => {
            let e = ElementTag::parse(s).ok_or(IntakeError::Element)?;
            if !RUBRIC_V1.contains(e) {
                return Err(IntakeError::Element);
            }
            Some(e)
        }
        _ => return Err(IntakeError::Shape("element")),
    };
    let statement = str_of(o, "statement")?;
    if statement.is_empty() || statement.len() > MAX_STATEMENT_BYTES || score_like(statement) {
        return Err(IntakeError::Statement);
    }
    let raw = list(o, "evidence", MAX_EVIDENCE)?;
    if raw.is_empty() {
        return Err(IntakeError::Evidence);
    }
    let evidence = raw
        .iter()
        .map(|e| evidence(e, job))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(IntakeFinding {
        kind,
        criterion,
        element,
        severity,
        statement: UntrustedText::new(statement.to_owned()),
        evidence,
    })
}

fn evidence(v: &Value, job: &JobLine) -> Result<EvidenceRef, IntakeError> {
    let e = EvidenceRef::from_json(v).map_err(|_| IntakeError::Evidence)?;
    match e {
        EvidenceRef::Submission { text, start, end } => {
            let part = job
                .parts
                .iter()
                .find(|p| p.text_ref == text)
                .ok_or(IntakeError::Evidence)?;
            let body = part.text.as_data();
            let (a, b) = (start as usize, end as usize);
            if a > b || b > body.len() || !body.is_char_boundary(a) || !body.is_char_boundary(b) {
                return Err(IntakeError::Evidence);
            }
        }
        EvidenceRef::Retrieved { source } => {
            if !job.sources.iter().any(|s| s.text == source.id()) {
                return Err(IntakeError::Evidence);
            }
        }
    }
    Ok(e)
}

/// A job as the cell holds it: the line it writes and the stage 1 and 2
/// maps back to the original texts, which never leave the cell.
#[derive(Clone, Debug)]
pub struct CellJob {
    line: JobLine,
    prepared: Prepared,
}

impl CellJob {
    /// Runs stages 1 and 2 over `parts` and builds the job line with the
    /// stripped bodies (TH-01, T-PRIV-CANARY). `handles` are the team's
    /// display handles; `mask` finds legal names.
    ///
    /// # Errors
    ///
    /// [`IntakeError::Shape`] when the name mask is down. Nothing is
    /// written then, and the assessment stays pending (R-NF-10).
    pub async fn prepare<M: NameMask>(
        job: u128,
        proposal: ProposalId,
        config: JobConfig,
        parts: Vec<SubmissionPart>,
        handles: Vec<String>,
        mask: &M,
    ) -> Result<CellJob, IntakeError> {
        let j = Job {
            proposal,
            parts,
            handles,
        };
        let prepared = prepare(mask, &j)
            .await
            .map_err(|_| IntakeError::Shape("mask"))?;
        let parts = prepared
            .parts()
            .iter()
            .map(|p| SubmissionPart {
                label: p.label(),
                text_ref: p.text_ref(),
                text: p.stripped().clone(),
            })
            .collect();
        Ok(CellJob {
            line: JobLine {
                job,
                proposal,
                config,
                parts,
                sources: Vec::new(),
                own: Vec::new(),
            },
            prepared,
        })
    }

    /// The job line the cell writes.
    pub fn line(&self) -> &JobLine {
        &self.line
    }

    /// Decodes `result` against this job and maps every submission span
    /// to the original text. A span that does not map fails the result
    /// (R-LA-02).
    ///
    /// # Errors
    ///
    /// As [`decode_result`], and [`IntakeError::Evidence`] for a span
    /// with no original.
    pub fn intake(&self, result: &[u8]) -> Result<Intake, IntakeError> {
        let mut out = decode_result(result, &self.line)?;
        if let Intake::Done { findings, .. } = &mut out {
            for f in findings.iter_mut() {
                for e in &mut f.evidence {
                    *e = self.original(*e).ok_or(IntakeError::Evidence)?;
                }
            }
        }
        Ok(out)
    }

    fn original(&self, e: EvidenceRef) -> Option<EvidenceRef> {
        match e {
            EvidenceRef::Submission { text, start, end } => {
                let part = self
                    .prepared
                    .parts()
                    .iter()
                    .find(|p| p.text_ref() == text)?;
                let (a, b) = part.original_span(start as usize, end as usize)?;
                Some(EvidenceRef::Submission {
                    text,
                    start: u32::try_from(a).ok()?,
                    end: u32::try_from(b).ok()?,
                })
            }
            EvidenceRef::Retrieved { .. } => Some(e),
        }
    }
}

/// Why the link to the assessor failed. The job stays pending (R-NF-10).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkError {
    /// The child could not start, for example when the binary is missing.
    Spawn,
    /// The queue socket failed or timed out.
    Io,
    /// The child answered no line.
    NoResult,
}

/// How the cell reaches the assessor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Link {
    /// The synthetic model in this process, through the same queue line
    /// handling as the binary. For tests and cells without the binary.
    InProcess,
    /// The `fstp-assessor` binary at `exe`, started with `args`, one child
    /// per batch (M7 design section 3.1).
    Child {
        /// The binary.
        exe: PathBuf,
        /// Its arguments, such as `--inference synthetic`.
        args: Vec<String>,
        /// How long the cell waits for a result line.
        timeout: Duration,
    },
}

impl Link {
    /// Runs `jobs` and returns one result line per job, in order.
    ///
    /// # Errors
    ///
    /// A [`LinkError`] when the assessor cannot be reached or answers
    /// fewer lines than it got jobs.
    pub async fn run(&self, jobs: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, LinkError> {
        match self {
            Link::InProcess => {
                let a = Assessor {
                    inference: SyntheticModel,
                    retrieval: NoRetrieval,
                    protocol: None,
                };
                let mut out = Vec::with_capacity(jobs.len());
                for (n, j) in (1_u64..).zip(jobs) {
                    out.push(result_bytes(&a.handle_line(n, j).await));
                }
                Ok(out)
            }
            Link::Child { exe, args, timeout } => run_child(exe, args, *timeout, jobs),
        }
    }
}

fn run_child(
    exe: &PathBuf,
    args: &[String],
    timeout: Duration,
    jobs: &[Vec<u8>],
) -> Result<Vec<Vec<u8>>, LinkError> {
    let (ours, theirs) = UnixStream::pair().map_err(|_| LinkError::Io)?;
    let mut child = Command::new(exe)
        .args(args)
        .env_clear()
        .stdin(Stdio::from(OwnedFd::from(theirs)))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| LinkError::Spawn)?;
    let result = (|| {
        ours.set_read_timeout(Some(timeout))
            .map_err(|_| LinkError::Io)?;
        let mut writer = ours.try_clone().map_err(|_| LinkError::Io)?;
        let input: Vec<u8> = jobs
            .iter()
            .flat_map(|j| j.iter().copied().chain(std::iter::once(b'\n')))
            .collect();
        let feed = std::thread::spawn(move || -> io::Result<()> {
            writer.write_all(&input)?;
            writer.shutdown(Shutdown::Write)
        });
        let mut reader = LineReader::new(io::BufReader::new(&ours), MAX_RESULT_BYTES);
        let mut out = Vec::with_capacity(jobs.len());
        while out.len() < jobs.len() {
            match reader.next_line() {
                Ok(Line::Line(l)) => out.push(l),
                Ok(Line::TooLong) => out.push(Vec::new()),
                Ok(Line::Eof) => break,
                Err(_) => return Err(LinkError::Io),
            }
        }
        if feed.join().map_or(true, |r| r.is_err()) {
            return Err(LinkError::Io);
        }
        if out.len() < jobs.len() {
            return Err(LinkError::NoResult);
        }
        Ok(out)
    })();
    let _ = ours.shutdown(Shutdown::Both);
    if result.is_err() {
        let _ = child.kill();
    }
    let _ = child.wait();
    result
}
