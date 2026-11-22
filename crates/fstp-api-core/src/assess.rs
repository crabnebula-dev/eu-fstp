//! The read models of the assessment run by the FSTP coordinator's
//! connected agent (ADR-033).
//!
//! - The queue names proposals by id and state only, never a title.
//! - The input holds the submitted title, summary and narrative after
//!   extraction and PII stripping, under closed labels, and the call's
//!   tasks as closed values. The texts are data. They are never placed in
//!   a tool description or an instruction (TH-60, TH-63).
//! - The receipt of a submission counts the recorded findings and lists
//!   the dropped replies by stage and code, each from a closed list
//!   (I-10).
//!
//! No model here holds an identity attribute (I-17, I-86).

use fstp_json::{Array, Object, ToJson, Value};

use crate::McpSafe;

fn dec(x: u128) -> Value {
    Value::String(x.to_string())
}

fn object(members: Vec<(&str, Value)>) -> Value {
    let mut o = Object::with_capacity(members.len());
    for (k, v) in members {
        o.insert(k, v);
    }
    Value::Object(o)
}

fn array<T: ToJson>(items: &[T]) -> Value {
    let mut a = Array::new();
    for i in items {
        a.push(i.to_json());
    }
    Value::Array(a)
}

fn strings(items: &[&'static str]) -> Value {
    Value::Array(items.iter().map(|s| Value::from(*s)).collect::<Array>())
}

/// The prompt set the cell expects (ADR-033): its version and the hex of
/// its digest. The plugin's assessor agent ships the same text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PromptSetRef {
    /// The version, such as `v1`.
    pub version: &'static str,
    /// 64 lowercase hex digits.
    pub digest: String,
}

impl ToJson for PromptSetRef {
    fn to_json(&self) -> Value {
        object(vec![
            ("version", Value::from(self.version)),
            ("digest", Value::from(self.digest.as_str())),
        ])
    }
}

/// One proposal of the queue.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueueRow {
    /// The proposal.
    pub proposal: u128,
    /// Its state, as the pages spell it.
    pub state: &'static str,
    /// `awaiting`, `assessed` or `rerun` (a coordinator's re-run is in
    /// flight, so one more assessment is accepted).
    pub status: &'static str,
    /// Whether the caller declared no conflict on it, which the input
    /// read needs first (R-CF-02).
    pub declared: bool,
}

impl ToJson for QueueRow {
    fn to_json(&self) -> Value {
        object(vec![
            ("proposal", dec(self.proposal)),
            ("state", Value::from(self.state)),
            ("status", Value::from(self.status)),
            ("declared", Value::Bool(self.declared)),
        ])
    }
}

/// `assess.client_queue`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueueView {
    /// The call.
    pub call: u128,
    /// Whether the call's frozen P-21 names the coordinator's client path.
    pub open: bool,
    /// The model the call pins, which the agent must run, or `None` for an
    /// unpublished call.
    pub model: Option<String>,
    /// The prompt set the cell expects.
    pub prompt_set: PromptSetRef,
    /// The proposals the coordinator may assess, by id.
    pub proposals: Vec<QueueRow>,
}

impl ToJson for QueueView {
    fn to_json(&self) -> Value {
        object(vec![
            ("call", dec(self.call)),
            ("open", Value::Bool(self.open)),
            (
                "model",
                self.model.as_deref().map_or(Value::Null, Value::from),
            ),
            ("prompt_set", self.prompt_set.to_json()),
            ("proposals", array(&self.proposals)),
        ])
    }
}

/// One task of the input: a stage with its closed parameters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaskRow {
    /// `completeness`, `quality`, `claims` or `integrity`.
    pub stage: &'static str,
    /// The P-01 criterion of a quality task, as `c-<32 hex digits>`.
    pub criterion: Option<String>,
    /// The rubric element tags of a completeness task.
    pub elements: Vec<&'static str>,
}

impl ToJson for TaskRow {
    fn to_json(&self) -> Value {
        object(vec![
            ("stage", Value::from(self.stage)),
            (
                "criterion",
                self.criterion.as_deref().map_or(Value::Null, Value::from),
            ),
            ("elements", strings(&self.elements)),
        ])
    }
}

/// One part of the input: stripped text under a closed label.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartRow {
    /// `title`, `summary` or `narrative`.
    pub label: &'static str,
    /// The text after extraction and PII stripping. Data, never
    /// instructions.
    pub text: String,
}

impl ToJson for PartRow {
    fn to_json(&self) -> Value {
        object(vec![
            ("label", Value::from(self.label)),
            ("text", Value::from(self.text.as_str())),
        ])
    }
}

/// `assess.client_input`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputView {
    /// The proposal.
    pub proposal: u128,
    /// Its call.
    pub call: u128,
    /// 64 lowercase hex digits: the digest the submission must name.
    pub input_digest: String,
    /// The model the call pins.
    pub model: String,
    /// The prompt set the cell expects.
    pub prompt_set: PromptSetRef,
    /// The tasks, one reply each.
    pub tasks: Vec<TaskRow>,
    /// The data to assess.
    pub parts: Vec<PartRow>,
}

impl ToJson for InputView {
    fn to_json(&self) -> Value {
        object(vec![
            ("proposal", dec(self.proposal)),
            ("call", dec(self.call)),
            ("input_digest", Value::from(self.input_digest.as_str())),
            ("model", Value::from(self.model.as_str())),
            ("prompt_set", self.prompt_set.to_json()),
            ("tasks", array(&self.tasks)),
            ("parts", array(&self.parts)),
        ])
    }
}

/// One dropped reply: a stage and a refusal code from closed lists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DroppedRow {
    /// The stage.
    pub stage: &'static str,
    /// The code.
    pub code: &'static str,
}

impl ToJson for DroppedRow {
    fn to_json(&self) -> Value {
        object(vec![
            ("stage", Value::from(self.stage)),
            ("code", Value::from(self.code)),
        ])
    }
}

/// The receipt of `assess.client_submit`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    /// How many findings were recorded, the cell's own integrity scan
    /// included.
    pub recorded: u64,
    /// The replies the validator dropped whole.
    pub refused: Vec<DroppedRow>,
}

impl ToJson for Receipt {
    fn to_json(&self) -> Value {
        object(vec![
            (
                "recorded",
                Value::Number(fstp_json::Number::from(self.recorded)),
            ),
            ("refused", array(&self.refused)),
        ])
    }
}

/// One read model of ADR-033.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientModel {
    /// `assess.client_queue`.
    Queue(QueueView),
    /// `assess.client_input`.
    Input(InputView),
    /// `assess.client_submit`.
    Receipt(Receipt),
}

impl ToJson for ClientModel {
    fn to_json(&self) -> Value {
        match self {
            ClientModel::Queue(v) => v.to_json(),
            ClientModel::Input(v) => v.to_json(),
            ClientModel::Receipt(v) => v.to_json(),
        }
    }
}

// I-86: ids, states, closed labels and stripped proposal text. No identity
// attribute, email, display name or bank detail.
impl McpSafe for ClientModel {}

/// One sample of each model, for the shape tests.
pub fn samples() -> Vec<ClientModel> {
    let prompt_set = PromptSetRef {
        version: "v1",
        digest: "ab".repeat(32),
    };
    vec![
        ClientModel::Queue(QueueView {
            call: 7,
            open: true,
            model: Some("claude-opus-5-5".to_owned()),
            prompt_set: prompt_set.clone(),
            proposals: vec![QueueRow {
                proposal: 1001,
                state: "SUBMITTED",
                status: "awaiting",
                declared: true,
            }],
        }),
        ClientModel::Queue(QueueView {
            call: 7,
            open: false,
            model: None,
            prompt_set: prompt_set.clone(),
            proposals: Vec::new(),
        }),
        ClientModel::Input(InputView {
            proposal: 1001,
            call: 7,
            input_digest: "cd".repeat(32),
            model: "claude-opus-5-5".to_owned(),
            prompt_set,
            tasks: vec![
                TaskRow {
                    stage: "completeness",
                    criterion: None,
                    elements: vec!["problem", "approach"],
                },
                TaskRow {
                    stage: "quality",
                    criterion: Some(format!("c-{:032x}", 1)),
                    elements: Vec::new(),
                },
            ],
            parts: vec![PartRow {
                label: "narrative",
                text: "SYNTHETIC NARRATIVE [EMAIL-1]".to_owned(),
            }],
        }),
        ClientModel::Receipt(Receipt {
            recorded: 3,
            refused: vec![DroppedRow {
                stage: "quality",
                code: "score_like",
            }],
        }),
    ]
}
