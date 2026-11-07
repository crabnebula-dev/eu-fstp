//! Shared test helpers: corpus/v1 loading, a capturing transport and a
//! scripted transport. Synthetic data only.

#![allow(
    dead_code,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::path::PathBuf;
use std::sync::Mutex;

use fstp_assess::{Job, Pipeline, SubmissionPart, SyntheticNameMask};
use fstp_domain::id::{ContentDigest, CriterionId, ProposalId, TextId, TextRef};
use fstp_findings::UntrustedText;
use fstp_infer::{DataLabel, Decoding, EncodedRequest, ModelName, Transport, TransportError};
use fstp_json::{Object, Value};

/// One corpus item, as the pipeline tests read it.
pub struct Item {
    pub id: String,
    pub variant: String,
    pub person_name: String,
    pub handle: String,
    /// Every canary of the item: the five PII classes and the handle.
    pub canaries: Vec<String>,
    pub omitted: Option<String>,
    pub job: Job,
}

pub fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../corpus/v1")
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("member {k} missing"))
}

fn text_ref(n: u128, text: &str) -> TextRef {
    TextRef::new(
        TextId::from_raw(n),
        ContentDigest::from_bytes(fstp_crypto::sha256(text.as_bytes())),
    )
}

/// The plan as text, the way the cell renders it for the data channel.
pub fn plan_text(plan: &Value) -> String {
    let mut out = String::new();
    for t in plan.get("tasks").unwrap().as_array().unwrap().iter() {
        out.push_str(&format!(
            "Task {} {}: {} days at {} EUR a day.\n",
            s(t, "id"),
            s(t, "title"),
            t.get("effort_days").unwrap().as_u64().unwrap(),
            s(t, "rate_eur"),
        ));
        for m in t.get("milestones").unwrap().as_array().unwrap().iter() {
            out.push_str(&format!(
                "Milestone {} {}: months {} to {}, {} EUR.\n",
                s(m, "id"),
                s(m, "title"),
                m.get("start_month").unwrap().as_u64().unwrap(),
                m.get("due_month").unwrap().as_u64().unwrap(),
                s(m, "amount_eur"),
            ));
        }
    }
    out.push_str(&format!("Total: {} EUR.\n", s(plan, "total_eur")));
    out
}

pub fn manifest() -> Value {
    fstp_json::parse(&std::fs::read(corpus_dir().join("manifest.json")).unwrap()).unwrap()
}

/// Every item of the manifest, evaluation and e2e alike.
pub fn items() -> Vec<Item> {
    let m = manifest();
    let mut out = Vec::new();
    for (n, entry) in m
        .get("items")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        let file = corpus_dir().join(s(entry, "file"));
        let item = fstp_json::parse(&std::fs::read(&file).unwrap()).unwrap();
        let applicant = item.get("applicant").unwrap();
        let proposal = item.get("proposal").unwrap();
        let mut canaries: Vec<String> = entry
            .get("canaries")
            .unwrap()
            .as_object()
            .unwrap()
            .values()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect();
        let handle = s(applicant, "handle").to_owned();
        canaries.push(handle.clone());
        let base = (n as u128) * 16;
        let texts = [
            (DataLabel::Title, s(proposal, "title").to_owned()),
            (DataLabel::Summary, s(proposal, "summary").to_owned()),
            (DataLabel::Narrative, s(proposal, "narrative").to_owned()),
            (DataLabel::Plan, plan_text(proposal.get("plan").unwrap())),
        ];
        let parts = texts
            .into_iter()
            .enumerate()
            .map(|(i, (label, text))| SubmissionPart {
                label,
                text_ref: text_ref(base + i as u128, &text),
                text: UntrustedText::new(text),
            })
            .collect();
        out.push(Item {
            id: s(entry, "id").to_owned(),
            variant: s(entry, "variant").to_owned(),
            person_name: s(applicant, "person_name").to_owned(),
            handle: handle.clone(),
            canaries,
            omitted: entry
                .get("omitted_element")
                .and_then(Value::as_str)
                .map(str::to_owned),
            job: Job {
                proposal: ProposalId::from_raw(n as u128 + 1),
                parts,
                handles: vec![handle],
            },
        });
    }
    out
}

/// The vault's view of an item's team, through the synthetic port.
pub fn mask_for(item: &Item) -> SyntheticNameMask {
    SyntheticNameMask::new(vec![item.person_name.clone()])
}

/// A P-01 of three criteria.
pub fn criteria() -> Vec<CriterionId> {
    vec![
        CriterionId::from_raw(0x11),
        CriterionId::from_raw(0x22),
        CriterionId::from_raw(0x33),
    ]
}

pub fn pipeline<'a, T: Transport, M: fstp_assess::NameMask>(
    transport: &'a T,
    mask: &'a M,
) -> Pipeline<'a, T, M> {
    Pipeline {
        transport,
        mask,
        model: ModelName::new("synthetic").unwrap(),
        decoding: Decoding {
            max_tokens: 2048,
            temperature_milli: 0,
            seed: 7,
        },
        criteria: criteria(),
        rubric: &fstp_assess::RUBRIC_V1,
    }
}

/// Records every request body, then defers to the inner transport.
pub struct Capture<T> {
    pub inner: T,
    pub bodies: Mutex<Vec<Vec<u8>>>,
}

impl<T> Capture<T> {
    pub fn new(inner: T) -> Capture<T> {
        Capture {
            inner,
            bodies: Mutex::new(Vec::new()),
        }
    }

    pub fn bodies(&self) -> Vec<Vec<u8>> {
        self.bodies.lock().unwrap().clone()
    }
}

impl<T: Transport> Transport for Capture<T> {
    async fn exchange(&self, req: &EncodedRequest) -> Result<Vec<u8>, TransportError> {
        self.bodies.lock().unwrap().push(req.body().to_vec());
        self.inner.exchange(req).await
    }
}

/// Answers every request with the same reply content.
pub struct Scripted(pub String);

/// A chat-completions response body carrying `content`.
pub fn envelope(content: &str) -> Vec<u8> {
    let mut message = Object::new();
    message.insert("role", Value::from("assistant"));
    message.insert("content", Value::from(content));
    let mut choice = Object::new();
    choice.insert("index", Value::Number(fstp_json::Number::from(0_u64)));
    choice.insert("message", Value::Object(message));
    choice.insert("finish_reason", Value::from("stop"));
    let mut top = Object::new();
    top.insert("object", Value::from("chat.completion"));
    top.insert("choices", Value::Array(vec![Value::Object(choice)].into()));
    fstp_json::to_canonical(&Value::Object(top))
        .unwrap()
        .into_bytes()
}

impl Transport for Scripted {
    async fn exchange(&self, _req: &EncodedRequest) -> Result<Vec<u8>, TransportError> {
        Ok(envelope(&self.0))
    }
}

/// The instruction (first) message of an encoded request body.
pub fn instruction_of(body: &[u8]) -> String {
    let v = fstp_json::parse(body).unwrap();
    let msgs = v.get("messages").unwrap().as_array().unwrap();
    let first = msgs.iter().next().unwrap();
    assert_eq!(first.get("role").and_then(Value::as_str), Some("system"));
    first.get("content").unwrap().as_str().unwrap().to_owned()
}

pub fn block_on<F: std::future::Future>(f: F) -> F::Output {
    fstp_rt::future::block_on(f)
}
