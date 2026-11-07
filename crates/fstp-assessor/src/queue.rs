//! The job queue: one canonical JSON object per line on stdin (M7 design
//! section 3.1). The decoder accepts only the closed job shape and is the
//! fuzz target `assessor_queue_ndjson` (TH-26).
//!
//! A job line has the members:
//!
//! - `job`: the cell's job id, a canonical decimal string, echoed in the
//!   result;
//! - `proposal`: the proposal id, a canonical decimal string;
//! - `config`: `protocol` (`anthropic` or `chat_completions`), `model`,
//!   `max_tokens`, `temperature_milli`, `seed` and `criteria`, the frozen
//!   P-01 criterion ids as decimal strings;
//! - `parts`: the stripped submission texts, each with `label` (`title`,
//!   `summary`, `narrative`, `plan` or `claim`, each at most once), `text`
//!   (`{"id", "digest"}`, the cell's reference to the original) and
//!   `body` (the text after stages 1 and 2 in the cell);
//! - `sources`: URLs to retrieve for stage 6, each with `url` and `text`,
//!   the text id the cell gives the retrieved source;
//! - `own`: the URLs the proposal names as its own (TH-12 classing).
//!
//! Every text stays [`UntrustedText`]. Errors never carry input content
//! (R-NF-02).

use std::io::{self, BufRead};

use fstp_assess::SubmissionPart;
use fstp_domain::id::{ContentDigest, CriterionId, ProposalId, TextId, TextRef};
use fstp_findings::UntrustedText;
use fstp_infer::{DataLabel, Decoding, ModelName, Protocol};
use fstp_json::{Array, Number, Object, ParseLimits, Value};
use fstp_retrieve::SourceUrl;

/// The longest job line, in bytes, without its line ending.
pub const MAX_LINE_BYTES: usize = 2 << 20;
/// The most submission parts of one job.
pub const MAX_PARTS: usize = 5;
/// The most sources one job retrieves.
pub const MAX_SOURCES: usize = 8;
/// The most URLs a job names as the applicant's own.
pub const MAX_OWN: usize = 16;
/// The most P-01 criteria of one job.
pub const MAX_CRITERIA: usize = 32;

/// Why a job line was refused. No variant carries input content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueueError {
    /// The line is longer than [`MAX_LINE_BYTES`].
    TooLong,
    /// The line is not one JSON text within the limits.
    Json,
    /// An object holds a member outside the job shape.
    UnknownMember,
    /// A member is missing or has the wrong type or value.
    Shape(&'static str),
    /// A list is empty where it may not be, or longer than its limit.
    TooMany(&'static str),
}

impl QueueError {
    /// The stable code of the refusal line.
    pub const fn code(self) -> &'static str {
        match self {
            QueueError::TooLong => "line_too_long",
            QueueError::Json => "json",
            QueueError::UnknownMember => "unknown_member",
            QueueError::Shape(_) => "shape",
            QueueError::TooMany(_) => "too_many",
        }
    }
}

/// The inference configuration of the job's call, pinned at publication
/// (I-11). The cell derives the `config_id` from it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobConfig {
    /// The wire protocol (ADR-019).
    pub protocol: Protocol,
    /// The pinned model (P-21).
    pub model: ModelName,
    /// The decoding parameters.
    pub decoding: Decoding,
    /// The frozen P-01 criterion ids, in order.
    pub criteria: Vec<CriterionId>,
}

/// One source to retrieve for claim verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceLine {
    /// The URL.
    pub url: SourceUrl,
    /// The text id the cell gives the retrieved text.
    pub text: TextId,
}

/// One decoded job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobLine {
    /// The cell's job id.
    pub job: u128,
    /// The proposal.
    pub proposal: ProposalId,
    /// The pinned configuration.
    pub config: JobConfig,
    /// The stripped submission texts.
    pub parts: Vec<SubmissionPart>,
    /// The sources to retrieve.
    pub sources: Vec<SourceLine>,
    /// The URLs the proposal names as its own.
    pub own: Vec<SourceUrl>,
}

const TOP: [&str; 6] = ["job", "proposal", "config", "parts", "sources", "own"];
const CONFIG: [&str; 6] = [
    "protocol",
    "model",
    "max_tokens",
    "temperature_milli",
    "seed",
    "criteria",
];
const PART: [&str; 3] = ["label", "text", "body"];
const TEXT: [&str; 2] = ["id", "digest"];
const SOURCE: [&str; 2] = ["url", "text"];

/// The labels a job part may carry. Source labels come only from the
/// assessor's own classing.
const PART_LABELS: [DataLabel; 5] = [
    DataLabel::Title,
    DataLabel::Summary,
    DataLabel::Narrative,
    DataLabel::Plan,
    DataLabel::Claim,
];

fn limits() -> ParseLimits {
    ParseLimits {
        max_input_bytes: MAX_LINE_BYTES,
        max_depth: 6,
        max_string_bytes: MAX_LINE_BYTES,
        max_number_len: 20,
        max_container_len: 64,
        max_nodes: 1024,
        max_memory_bytes: 8 << 20,
    }
}

/// Decodes one job line.
///
/// # Errors
///
/// A [`QueueError`] for anything outside the closed job shape.
pub fn decode_job(line: &[u8]) -> Result<JobLine, QueueError> {
    if line.len() > MAX_LINE_BYTES {
        return Err(QueueError::TooLong);
    }
    let v = fstp_json::parse_with(line, &limits()).map_err(|_| QueueError::Json)?;
    let o = object(&v, &TOP)?;
    let job = id(get(o, "job")?, "job")?;
    let proposal = ProposalId::from_raw(id(get(o, "proposal")?, "proposal")?);
    let config = config(get(o, "config")?)?;
    let parts = list(get(o, "parts")?, "parts", 1, MAX_PARTS)?
        .iter()
        .map(part)
        .collect::<Result<Vec<_>, _>>()?;
    for (i, p) in parts.iter().enumerate() {
        if parts
            .iter()
            .skip(i.saturating_add(1))
            .any(|q| q.label == p.label)
        {
            return Err(QueueError::Shape("parts"));
        }
    }
    let sources = list(get(o, "sources")?, "sources", 0, MAX_SOURCES)?
        .iter()
        .map(source)
        .collect::<Result<Vec<_>, _>>()?;
    let own = list(get(o, "own")?, "own", 0, MAX_OWN)?
        .iter()
        .map(|u| url(u, "own"))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(JobLine {
        job,
        proposal,
        config,
        parts,
        sources,
        own,
    })
}

fn object<'a>(v: &'a Value, fields: &[&str]) -> Result<&'a Object, QueueError> {
    let o = v.as_object().ok_or(QueueError::Shape("object"))?;
    if o.keys().all(|k| fields.contains(&k)) {
        Ok(o)
    } else {
        Err(QueueError::UnknownMember)
    }
}

fn get<'a>(o: &'a Object, key: &'static str) -> Result<&'a Value, QueueError> {
    o.get(key).ok_or(QueueError::Shape(key))
}

fn list<'a>(
    v: &'a Value,
    what: &'static str,
    min: usize,
    max: usize,
) -> Result<&'a Array, QueueError> {
    let a = v.as_array().ok_or(QueueError::Shape(what))?;
    if a.len() < min || a.len() > max {
        return Err(QueueError::TooMany(what));
    }
    Ok(a)
}

/// A `u128` id as a canonical decimal string.
fn id(v: &Value, what: &'static str) -> Result<u128, QueueError> {
    let s = v.as_str().ok_or(QueueError::Shape(what))?;
    let canonical = !s.is_empty()
        && s.len() <= 39
        && s.bytes().all(|b| b.is_ascii_digit())
        && (s == "0" || !s.starts_with('0'));
    if !canonical {
        return Err(QueueError::Shape(what));
    }
    s.parse::<u128>().map_err(|_| QueueError::Shape(what))
}

fn uint(v: &Value, what: &'static str, max: u64) -> Result<u64, QueueError> {
    v.as_u64()
        .filter(|n| *n <= max)
        .ok_or(QueueError::Shape(what))
}

fn config(v: &Value) -> Result<JobConfig, QueueError> {
    let o = object(v, &CONFIG)?;
    let protocol = match get(o, "protocol")?.as_str() {
        Some("anthropic") => Protocol::Anthropic,
        Some("chat_completions") => Protocol::ChatCompletions,
        _ => return Err(QueueError::Shape("protocol")),
    };
    let model = get(o, "model")?
        .as_str()
        .and_then(|m| ModelName::new(m).ok())
        .ok_or(QueueError::Shape("model"))?;
    let max_tokens = uint(get(o, "max_tokens")?, "max_tokens", u64::from(u32::MAX))?;
    let temperature_milli = uint(get(o, "temperature_milli")?, "temperature_milli", 2000)?;
    let seed = uint(get(o, "seed")?, "seed", u64::from(u32::MAX))?;
    let criteria = list(get(o, "criteria")?, "criteria", 1, MAX_CRITERIA)?
        .iter()
        .map(|c| id(c, "criteria").map(CriterionId::from_raw))
        .collect::<Result<Vec<_>, _>>()?;
    for (i, c) in criteria.iter().enumerate() {
        if criteria.iter().skip(i.saturating_add(1)).any(|d| d == c) {
            return Err(QueueError::Shape("criteria"));
        }
    }
    Ok(JobConfig {
        protocol,
        model,
        decoding: Decoding {
            max_tokens: u32::try_from(max_tokens).map_err(|_| QueueError::Shape("max_tokens"))?,
            temperature_milli: u16::try_from(temperature_milli)
                .map_err(|_| QueueError::Shape("temperature_milli"))?,
            seed: u32::try_from(seed).map_err(|_| QueueError::Shape("seed"))?,
        },
        criteria,
    })
}

fn label(v: &Value) -> Result<DataLabel, QueueError> {
    let s = v.as_str().ok_or(QueueError::Shape("label"))?;
    PART_LABELS
        .into_iter()
        .find(|l| l.as_str() == s)
        .ok_or(QueueError::Shape("label"))
}

fn digest(v: &Value) -> Result<ContentDigest, QueueError> {
    let s = v.as_str().ok_or(QueueError::Shape("digest"))?;
    let b = s.as_bytes();
    if b.len() != 64 {
        return Err(QueueError::Shape("digest"));
    }
    let nibble = |c: u8| match c {
        b'0'..=b'9' => Some(c.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(c.wrapping_sub(b'a').wrapping_add(10)),
        _ => None,
    };
    let mut out = [0_u8; 32];
    for (dst, pair) in out.iter_mut().zip(b.chunks_exact(2)) {
        let (Some(&hi), Some(&lo)) = (pair.first(), pair.get(1)) else {
            return Err(QueueError::Shape("digest"));
        };
        let (Some(hi), Some(lo)) = (nibble(hi), nibble(lo)) else {
            return Err(QueueError::Shape("digest"));
        };
        *dst = hi.wrapping_shl(4) | lo;
    }
    Ok(ContentDigest::from_bytes(out))
}

fn part(v: &Value) -> Result<SubmissionPart, QueueError> {
    let o = object(v, &PART)?;
    let label = label(get(o, "label")?)?;
    let t = object(get(o, "text")?, &TEXT)?;
    let text_ref = TextRef::new(
        TextId::from_raw(id(get(t, "id")?, "text")?),
        digest(get(t, "digest")?)?,
    );
    let body = get(o, "body")?
        .as_str()
        .ok_or(QueueError::Shape("body"))?
        .to_owned();
    Ok(SubmissionPart {
        label,
        text_ref,
        text: UntrustedText::new(body),
    })
}

fn url(v: &Value, what: &'static str) -> Result<SourceUrl, QueueError> {
    v.as_str()
        .and_then(|s| SourceUrl::parse(s).ok())
        .ok_or(QueueError::Shape(what))
}

fn source(v: &Value) -> Result<SourceLine, QueueError> {
    let o = object(v, &SOURCE)?;
    Ok(SourceLine {
        url: url(get(o, "url")?, "url")?,
        text: TextId::from_raw(id(get(o, "text")?, "text")?),
    })
}

pub(crate) fn id_json(raw: u128) -> Value {
    Value::String(raw.to_string())
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        for n in [b >> 4, b & 0x0f] {
            if let Some(d) = DIGITS.get(usize::from(n)) {
                s.push(char::from(*d));
            }
        }
    }
    s
}

pub(crate) fn text_ref_json(t: TextRef) -> Value {
    let mut o = Object::with_capacity(2);
    o.insert("id", id_json(t.id().raw()));
    o.insert("digest", Value::String(hex(&t.digest().bytes())));
    Value::Object(o)
}

impl JobLine {
    /// The job as one canonical JSON line, without the line feed. The
    /// cell writes jobs with it; [`decode_job`] reads them back.
    pub fn to_json(&self) -> Value {
        let mut c = Object::new();
        c.insert(
            "protocol",
            Value::String(self.config.protocol.as_str().to_owned()),
        );
        c.insert(
            "model",
            Value::String(self.config.model.as_str().to_owned()),
        );
        c.insert(
            "max_tokens",
            Value::Number(Number::from(self.config.decoding.max_tokens)),
        );
        c.insert(
            "temperature_milli",
            Value::Number(Number::from(self.config.decoding.temperature_milli)),
        );
        c.insert(
            "seed",
            Value::Number(Number::from(self.config.decoding.seed)),
        );
        c.insert(
            "criteria",
            Value::Array(
                self.config
                    .criteria
                    .iter()
                    .map(|c| id_json(c.raw()))
                    .collect(),
            ),
        );
        let parts = self
            .parts
            .iter()
            .map(|p| {
                let mut o = Object::new();
                o.insert("label", Value::String(p.label.as_str().to_owned()));
                o.insert("text", text_ref_json(p.text_ref));
                o.insert("body", Value::String(p.text.as_data().to_owned()));
                Value::Object(o)
            })
            .collect();
        let sources = self
            .sources
            .iter()
            .map(|s| {
                let mut o = Object::new();
                o.insert("url", Value::String(s.url.as_str().to_owned()));
                o.insert("text", id_json(s.text.raw()));
                Value::Object(o)
            })
            .collect();
        let own = self
            .own
            .iter()
            .map(|u| Value::String(u.as_str().to_owned()))
            .collect();
        let mut o = Object::new();
        o.insert("job", id_json(self.job));
        o.insert("proposal", id_json(self.proposal.raw()));
        o.insert("config", Value::Object(c));
        o.insert("parts", Value::Array(parts));
        o.insert("sources", Value::Array(sources));
        o.insert("own", Value::Array(own));
        Value::Object(o)
    }

    /// [`JobLine::to_json`] as compact bytes.
    pub fn to_line(&self) -> Vec<u8> {
        fstp_json::to_compact(&self.to_json()).into_bytes()
    }
}

/// One read from a [`LineReader`].
#[derive(Debug, PartialEq, Eq)]
pub enum Line {
    /// A line, without its LF or CRLF ending.
    Line(Vec<u8>),
    /// A line over the limit. It was skipped up to its line feed.
    TooLong,
    /// The input ended.
    Eof,
}

/// Reads lines of at most a fixed length. It never buffers more than the
/// limit plus one byte of a line.
#[derive(Debug)]
pub struct LineReader<R> {
    inner: R,
    max: usize,
}

impl<R: BufRead> LineReader<R> {
    /// A reader of lines of at most `max` bytes.
    pub fn new(inner: R, max: usize) -> LineReader<R> {
        LineReader { inner, max }
    }

    /// The next line.
    ///
    /// # Errors
    ///
    /// The error of the inner reader.
    pub fn next_line(&mut self) -> io::Result<Line> {
        let mut line = Vec::new();
        let mut too_long = false;
        let mut any = false;
        loop {
            let buf = match self.inner.fill_buf() {
                Ok(b) => b,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            if buf.is_empty() {
                break;
            }
            any = true;
            let (chunk, used, end) = match buf.iter().position(|b| *b == b'\n') {
                Some(at) => (
                    buf.get(..at).unwrap_or_default(),
                    at.saturating_add(1),
                    true,
                ),
                None => (buf, buf.len(), false),
            };
            if !too_long {
                // One byte over is kept, so a CR before the LF still fits.
                let room = self.max.saturating_add(1).saturating_sub(line.len());
                if chunk.len() > room {
                    too_long = true;
                    line.clear();
                } else {
                    line.extend_from_slice(chunk);
                }
            }
            self.inner.consume(used);
            if end {
                break;
            }
        }
        if !any {
            return Ok(Line::Eof);
        }
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        if too_long || line.len() > self.max {
            return Ok(Line::TooLong);
        }
        Ok(Line::Line(line))
    }
}
