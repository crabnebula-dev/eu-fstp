//! The synthetic model (M7 design section 7).
//!
//! Deterministic code that reads a request body in the wire format and
//! answers in it, in memory. It finds missing rubric elements by keyword,
//! flags hidden characters and text addressed to an assessor, and gives
//! one info quality finding per criterion. It is never reported as an LLM
//! result: its `config_id` names provider `synthetic`.

use fstp_json::{Array, Object, Value};

use crate::encode::EncodedRequest;
use crate::instruction::ElementTag;
use crate::transport::{Transport, TransportError};

/// A deterministic, in-memory model that speaks the wire format.
#[derive(Clone, Copy, Debug, Default)]
pub struct SyntheticModel;

/// Keywords whose presence counts as addressing an element.
fn keywords(e: ElementTag) -> &'static [&'static str] {
    match e {
        ElementTag::Problem => &["problem"],
        ElementTag::Approach => &["approach", "method", "we will"],
        ElementTag::OisRelevance => &["open internet", "internet"],
        ElementTag::TeamExperience => &["team", "experience"],
        ElementTag::DeliverablesLicence => &["licence", "license"],
        ElementTag::Milestones => &["milestone"],
        ElementTag::BudgetJustification => &["budget"],
    }
}

/// Phrases that address an assessor or a model, lowercase ASCII.
const ADDRESSED: [&str; 7] = [
    "ignore previous",
    "ignore all previous",
    "disregard previous",
    "system prompt",
    "language model",
    "as an ai",
    "assessor",
];

/// Zero-width, bidi-control and tag characters.
fn hidden(c: char) -> bool {
    matches!(
        c,
        '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{2069}'
            | '\u{feff}'
            | '\u{e0000}'..='\u{e007f}'
    )
}

/// The parameters of the instruction's last parameter block.
struct Params {
    prompt: String,
    criterion: Option<String>,
    elements: Vec<ElementTag>,
}

fn params(instruction: &str) -> Params {
    let block = instruction
        .rsplit_once("\nParameters:\n")
        .map_or("", |(_, b)| b);
    let mut p = Params {
        prompt: String::new(),
        criterion: None,
        elements: Vec::new(),
    };
    for line in block.lines() {
        if let Some(v) = line.strip_prefix("prompt: ") {
            v.clone_into(&mut p.prompt);
        } else if let Some(v) = line.strip_prefix("criterion: ") {
            p.criterion = Some(v.to_owned());
        } else if let Some(t) = line.strip_prefix("element: ").and_then(ElementTag::parse) {
            p.elements.push(t);
        }
    }
    p
}

fn finding(
    kind: &str,
    criterion: Option<&str>,
    element: Option<ElementTag>,
    severity: &str,
    statement: &str,
    evidence: Vec<(String, String)>,
) -> Value {
    let mut o = Object::new();
    o.insert("kind", Value::from(kind));
    o.insert("criterion", criterion.map_or(Value::Null, Value::from));
    o.insert(
        "element",
        element.map_or(Value::Null, |e| Value::from(e.as_str())),
    );
    o.insert("severity", Value::from(severity));
    o.insert("statement", Value::from(statement));
    let ev: Array = evidence
        .into_iter()
        .map(|(part, quote)| {
            let mut e = Object::new();
            e.insert("part", Value::String(part));
            e.insert("quote", Value::String(quote));
            Value::Object(e)
        })
        .collect();
    o.insert("evidence", Value::Array(ev));
    Value::Object(o)
}

fn findings(p: &Params, parts: &[(String, String)]) -> Vec<Value> {
    let mut out = Vec::new();
    match p.prompt.as_str() {
        "completeness" => {
            let all: String = parts
                .iter()
                .map(|(_, t)| t.to_lowercase())
                .collect::<Vec<_>>()
                .join("\n");
            for e in &p.elements {
                if !keywords(*e).iter().any(|k| all.contains(k)) {
                    out.push(finding(
                        "completeness",
                        None,
                        Some(*e),
                        "major",
                        "Synthetic assessor (demo): the proposal does not address this element.",
                        Vec::new(),
                    ));
                }
            }
        }
        "quality" => {
            if let Some(c) = &p.criterion {
                // Every finding carries evidence (R-LA-02): the opening of
                // the first non-empty part, cut at a character boundary.
                let evidence = parts
                    .iter()
                    .find(|(_, t)| !t.is_empty())
                    .map(|(label, text)| {
                        let mut end = text.len().min(120);
                        while !text.is_char_boundary(end) {
                            end = end.saturating_sub(1);
                        }
                        (label.clone(), text.get(..end).unwrap_or("").to_owned())
                    })
                    .filter(|(_, q)| !q.is_empty())
                    .into_iter()
                    .collect();
                out.push(finding(
                    "quality",
                    Some(c),
                    None,
                    "info",
                    "Synthetic assessor (demo): no quality judgement is made.",
                    evidence,
                ));
            }
        }
        "integrity" => {
            for (label, text) in parts {
                if let Some(c) = text.chars().find(|c| hidden(*c)) {
                    out.push(finding(
                        "integrity",
                        None,
                        None,
                        "major",
                        "Synthetic assessor (demo): the text holds hidden or control characters.",
                        vec![(label.clone(), c.to_string())],
                    ));
                }
                // ASCII lowercasing keeps byte offsets, so a match maps back
                // to an exact quote of the original text.
                let lower = text.to_ascii_lowercase();
                for phrase in ADDRESSED {
                    if let Some(at) = lower.find(phrase) {
                        let quote = at
                            .checked_add(phrase.len())
                            .and_then(|end| text.get(at..end))
                            .unwrap_or(phrase);
                        out.push(finding(
                            "integrity",
                            None,
                            None,
                            "major",
                            "Synthetic assessor (demo): the text addresses the assessor.",
                            vec![(label.clone(), quote.to_owned())],
                        ));
                        break;
                    }
                }
            }
        }
        _ => {}
    }
    out
}

impl SyntheticModel {
    /// Answers one request body with a chat-completions response body.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Refused`] for a body it cannot read.
    pub fn answer(&self, body: &[u8]) -> Result<Vec<u8>, TransportError> {
        let req = fstp_json::parse(body).map_err(|_| TransportError::Refused)?;
        let model = req
            .get("model")
            .and_then(Value::as_str)
            .ok_or(TransportError::Refused)?;
        let messages = req
            .get("messages")
            .and_then(Value::as_array)
            .ok_or(TransportError::Refused)?;
        let content = |i: usize, role: &str| {
            messages
                .get(i)
                .filter(|m| m.get("role").and_then(Value::as_str) == Some(role))
                .and_then(|m| m.get("content"))
                .and_then(Value::as_str)
                .ok_or(TransportError::Refused)
        };
        let instruction = content(0, "system")?;
        let data =
            fstp_json::parse_str(content(1, "user")?).map_err(|_| TransportError::Refused)?;
        let parts: Vec<(String, String)> = data
            .get("parts")
            .and_then(Value::as_array)
            .ok_or(TransportError::Refused)?
            .iter()
            .filter_map(|p| {
                Some((
                    p.get("label")?.as_str()?.to_owned(),
                    p.get("text")?.as_str()?.to_owned(),
                ))
            })
            .collect();

        let mut out = Object::new();
        out.insert(
            "findings",
            Value::Array(findings(&params(instruction), &parts).into_iter().collect()),
        );
        let reply =
            fstp_json::to_canonical(&Value::Object(out)).map_err(|_| TransportError::Refused)?;

        let mut message = Object::new();
        message.insert("role", Value::from("assistant"));
        message.insert("content", Value::String(reply.clone()));
        let mut choice = Object::new();
        choice.insert("index", Value::from(count(0)));
        choice.insert("message", Value::Object(message));
        choice.insert("finish_reason", Value::from("stop"));
        let prompt_tokens = body.len() / 4;
        let completion_tokens = reply.len() / 4;
        let mut usage = Object::new();
        usage.insert("prompt_tokens", Value::from(count(prompt_tokens)));
        usage.insert("completion_tokens", Value::from(count(completion_tokens)));
        usage.insert(
            "total_tokens",
            Value::from(count(prompt_tokens.saturating_add(completion_tokens))),
        );
        let digest = crate::encode::hex(&fstp_crypto::sha256(body));
        let mut top = Object::new();
        top.insert(
            "id",
            Value::String(format!("synthetic-{}", digest.get(..16).unwrap_or(""))),
        );
        top.insert("object", Value::from("chat.completion"));
        top.insert("created", Value::from(count(0)));
        top.insert("model", Value::from(model));
        top.insert("choices", Value::Array(vec![Value::Object(choice)].into()));
        top.insert("usage", Value::Object(usage));
        fstp_json::to_canonical(&Value::Object(top))
            .map(String::into_bytes)
            .map_err(|_| TransportError::Refused)
    }
}

/// A count as a JSON number.
fn count(n: usize) -> fstp_json::Number {
    fstp_json::Number::from(u64::try_from(n).unwrap_or(u64::MAX))
}

impl Transport for SyntheticModel {
    async fn exchange(&self, req: &EncodedRequest) -> Result<Vec<u8>, TransportError> {
        self.answer(req.body())
    }
}
