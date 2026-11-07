//! Shared test helpers: a synthetic job, a capturing transport and a
//! scripted retrieval. Synthetic data only.

#![allow(
    dead_code,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::sync::Mutex;

use fstp_assess::SubmissionPart;
use fstp_assessor::{JobConfig, JobLine, Retrieval, SourceLine};
use fstp_domain::id::{ContentDigest, CriterionId, ProposalId, TextId, TextRef};
use fstp_findings::UntrustedText;
use fstp_infer::{
    DataLabel, Decoding, EncodedRequest, ModelName, Protocol, Transport, TransportError,
};
use fstp_json::Value;
use fstp_retrieve::{Outcome, Refusal, Retrieved, SourceUrl};

pub fn text_ref(n: u128, text: &str) -> TextRef {
    TextRef::new(
        TextId::from_raw(n),
        ContentDigest::from_bytes(fstp_crypto::sha256(text.as_bytes())),
    )
}

pub fn part(n: u128, label: DataLabel, text: &str) -> SubmissionPart {
    SubmissionPart {
        label,
        text_ref: text_ref(n, text),
        text: UntrustedText::new(text.to_owned()),
    }
}

pub const NARRATIVE: &str = "The problem is weak package signing. Our approach: we will build a \
    verifier for the open internet stack. The team has ten years of experience. Deliverables \
    ship under an EUPL licence. Each milestone is listed in the plan, and the budget follows \
    the tasks. We maintain https://repo.test/acme/tool.";

/// A job of four parts and two sources, the cell having stripped PII.
pub fn job(protocol: Protocol, narrative: &str) -> JobLine {
    JobLine {
        job: 4242,
        proposal: ProposalId::from_raw(7),
        config: JobConfig {
            protocol,
            model: ModelName::new("synthetic-model-1").unwrap(),
            decoding: Decoding {
                max_tokens: 2048,
                temperature_milli: 0,
                seed: 7,
            },
            criteria: vec![CriterionId::from_raw(0x11), CriterionId::from_raw(0x22)],
        },
        parts: vec![
            part(1, DataLabel::Title, "Signed packages for everyone"),
            part(2, DataLabel::Summary, "A verifier for package signatures."),
            part(3, DataLabel::Narrative, narrative),
            part(
                4,
                DataLabel::Plan,
                "Task T1 Verifier: 40 days at 500 EUR a day.\nTotal: 20000 EUR.\n",
            ),
        ],
        sources: vec![
            SourceLine {
                url: SourceUrl::parse("https://repo.test/acme/tool").unwrap(),
                text: TextId::from_raw(100),
            },
            SourceLine {
                url: SourceUrl::parse("https://registry.test/pkg/tool").unwrap(),
                text: TextId::from_raw(101),
            },
        ],
        own: vec![SourceUrl::parse("https://repo.test/acme/tool").unwrap()],
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

/// Answers every retrieval in memory: each URL with `text`, except
/// `blocked.test`, which the proxy refuses.
pub struct ScriptedRetrieval {
    pub text: String,
    pub asked: Mutex<Vec<String>>,
}

impl ScriptedRetrieval {
    pub fn new(text: &str) -> ScriptedRetrieval {
        ScriptedRetrieval {
            text: text.to_owned(),
            asked: Mutex::new(Vec::new()),
        }
    }
}

impl Retrieval for ScriptedRetrieval {
    async fn retrieve(&self, url: &SourceUrl) -> Outcome {
        self.asked.lock().unwrap().push(url.as_str().to_owned());
        if url.host() == "blocked.test" {
            return Outcome::Refused(Refusal::HostNotAllowed);
        }
        Outcome::Retrieved(Retrieved {
            chain: vec![url.clone()],
            text: UntrustedText::new(format!("{} ({})", self.text, url.as_str())),
            truncated: false,
        })
    }
}

/// The instruction of an encoded request body: the Anthropic `system`
/// member, or the first (system) message of a chat-completions body.
pub fn instruction_of(body: &[u8]) -> String {
    let v = fstp_json::parse(body).unwrap();
    if let Some(system) = v.get("system").and_then(Value::as_str) {
        return system.to_owned();
    }
    let msgs = v.get("messages").unwrap().as_array().unwrap();
    let first = msgs.iter().next().unwrap();
    assert_eq!(first.get("role").and_then(Value::as_str), Some("system"));
    first.get("content").unwrap().as_str().unwrap().to_owned()
}

/// The data text of an encoded request body: the one user message.
pub fn data_of(body: &[u8]) -> String {
    let v = fstp_json::parse(body).unwrap();
    let msgs = v.get("messages").unwrap().as_array().unwrap();
    let user = msgs
        .iter()
        .find(|m| m.get("role").and_then(Value::as_str) == Some("user"))
        .unwrap();
    match user.get("content").unwrap() {
        Value::String(s) => s.clone(),
        Value::Array(blocks) => blocks
            .iter()
            .filter_map(|b| b.get("text").and_then(Value::as_str))
            .collect::<Vec<_>>()
            .join(""),
        other => panic!("unexpected content {other:?}"),
    }
}

pub fn block_on<F: std::future::Future>(f: F) -> F::Output {
    fstp_rt::future::block_on(f)
}
