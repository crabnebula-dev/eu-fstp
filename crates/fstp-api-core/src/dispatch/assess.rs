//! The assessment run by the FSTP coordinator's connected agent
//! (ADR-033).
//!
//! - `assess.client_queue` lists the proposals of a call the coordinator
//!   may assess, by id and state.
//! - `assess.client_input` serves one proposal's submitted title, summary
//!   and narrative after stages 1 and 2 of the pipeline, and the call's
//!   tasks. The engine's `ReadAssessmentInput` judges the caller and asks
//!   the vault (I-03), then appends the read with the input digest
//!   (R-AU-01).
//! - `assess.client_submit` validates each reply with the pipeline's own
//!   stage 8 (`fstp_assess::decode_output` and `Prepared::locate`), adds
//!   the cell's deterministic integrity scan, and runs one
//!   `RecordClientAssessment` as the caller. A reply the validator refuses
//!   drops whole and is listed by stage and code (I-10).
//!
//! Submission text reaches the agent only as data in the read model
//! (TH-60). The instructions are the pinned prompt set, which the plugin
//! ships and whose digest every submission names (ADR-033).
//!
//! Interim readings, pending Daniel (ADR-033 "Known gaps"):
//!
//! - The cell strips emails, phone numbers and IBAN-shaped strings, then
//!   the vault masks the team's verified names and dates of birth (M7 Q4,
//!   ADR-033 record of lane L31).
//! - The evidence text references are derived from the proposal, the
//!   section and the section's digest, as the e2e cell derives them.
//! - The model reports no confidence, so each finding carries 0 permille,
//!   as the e2e cell's intake records it.

use fstp_access::{ReadKind, ReadOp, ReadTarget};
use fstp_assess::{
    AssessedFinding, Job, MaskUnavailable, NameMask, NameSpan, Prepared, RUBRIC_V1, Stage,
    SubmissionPart, decode_output,
};
use fstp_domain::StateTag;
use fstp_domain::id::{
    AccountId, CallId, CommandId, ContentDigest, CriterionId, LlmConfigId, ProposalId, TextId,
    TextRef,
};
use fstp_domain::policy::{ModelRef, ReadAccess};
use fstp_engine::{Command, FindingCommand};
use fstp_findings::{
    AssessStage, ClientRun, Confidence, Finding, FindingId, RefusalCode, RefusedStage, TraceRef,
    UntrustedText,
};
use fstp_infer::DataLabel;
use fstp_json::{Array, Object, ToJson, Value};

use super::{
    Call, Seams, call_of, call_param, dry_run, exec_failed, proposal_param, proposals_of_call,
    read_denied, state_name, submitted_of,
};
use crate::assess::{
    ClientModel, DroppedRow, InputView, PartRow, PromptSetRef, QueueRow, QueueView, Receipt,
    TaskRow,
};
use crate::port::{AsyncEngine, ExecMeta, OpName, TextClass, TextOwner, TextStore as _};
use crate::{ApiError, ErrorCode, Op, OpResult, ReadModel};

/// The most replies one submission may carry: completeness, one quality
/// reply per P-01 criterion (at most 16), claims and integrity, with room.
pub(crate) const MAX_REPLIES: usize = 24;

/// The stages a client may answer (ADR-033). Verification needs the
/// retrieval proxy, which the client does not reach.
const CLIENT_STAGES: [Stage; 4] = [
    Stage::Completeness,
    Stage::Quality,
    Stage::Claims,
    Stage::Integrity,
];

/// The name mask of the client path: the vault's (M7 Q4, ADR-033 record of
/// lane L31), over the proposal's team from the cell's own bindings. A
/// vault that cannot mask stops the input, so no text leaves the cell.
struct VaultMask<'a, P: Seams> {
    ports: &'a P,
    team: Vec<AccountId>,
}

impl<P: Seams> NameMask for VaultMask<'_, P> {
    async fn names(&self, _: ProposalId, text: &str) -> Result<Vec<NameSpan>, MaskUnavailable> {
        let spans = super::mask_spans(self.ports, &self.team, &[text.to_owned()])
            .await
            .map_err(|()| MaskUnavailable)?;
        let spans = spans.into_iter().next().ok_or(MaskUnavailable)?;
        Ok(spans
            .into_iter()
            .map(|s| NameSpan {
                start: s.start as usize,
                end: s.end as usize,
                person: s.person,
                class: if s.birth_date {
                    fstp_assess::PiiClass::BirthDate
                } else {
                    fstp_assess::PiiClass::Person
                },
            })
            .collect())
    }
}

/// Lowercase hex of `bytes`.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The 32 bytes of 64 lowercase hex digits, or `None`.
fn unhex32(s: &str) -> Option<[u8; 32]> {
    let raw = s.as_bytes();
    if raw.len() != 64 {
        return None;
    }
    let digit = |b: u8| {
        char::from(b)
            .to_digit(16)
            .and_then(|d| u8::try_from(d).ok())
    };
    if raw.iter().any(|b| b.is_ascii_uppercase()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (o, pair) in out.iter_mut().zip(raw.chunks_exact(2)) {
        let [h, l] = pair else { return None };
        *o = digit(*h)?.wrapping_shl(4) | digit(*l)?;
    }
    Some(out)
}

/// The prompt set the cell expects.
fn prompt_set() -> PromptSetRef {
    PromptSetRef {
        version: fstp_infer::PROMPT_SET_VERSION,
        digest: hex(&fstp_infer::prompt_set_digest()),
    }
}

/// `c-<32 hex digits>`, as the output schema spells a criterion.
fn criterion_name(c: CriterionId) -> String {
    format!("c-{:032x}", c.raw())
}

/// The model a run of `c` must report: the frozen P-21 primary, or the
/// fallback at the call's current position (I-11).
fn pinned_model<P: Seams>(call: &Call<'_, P>, c: CallId) -> Option<ModelRef> {
    let frozen = call.state.core.calls().get(c)?.frozen()?;
    let p21 = &frozen.values().p21;
    match call.state.findings.fallback_of(c) {
        None => Some(p21.primary.clone()),
        Some(k) => usize::try_from(k)
            .ok()
            .and_then(|k| p21.fallbacks.get(k))
            .cloned(),
    }
}

/// Whether the frozen P-21 of `c` names the client path (ADR-033).
fn client_path<P: Seams>(call: &Call<'_, P>, c: CallId) -> bool {
    call.state
        .core
        .calls()
        .get(c)
        .and_then(|v| v.frozen())
        .is_some_and(|f| fstp_findings::client_run(&f.values().p21))
}

/// The text reference of section `k` of `p`'s submitted text `text`.
pub(super) fn part_ref(p: ProposalId, k: u8, text: &str) -> TextRef {
    let mut h = fstp_crypto::Sha256::new();
    h.update(b"fstp-api-core/client-assessment/part\0");
    h.update(&p.raw().to_be_bytes());
    h.update(&[k]);
    let d = h.finish();
    let mut first = [0u8; 16];
    for (o, s) in first.iter_mut().zip(d.iter()) {
        *o = *s;
    }
    TextRef::new(
        TextId::from_raw(u128::from_be_bytes(first)),
        ContentDigest::from_bytes(fstp_crypto::sha256(text.as_bytes())),
    )
}

/// The served input of one proposal.
struct Input {
    call: CallId,
    config: LlmConfigId,
    criteria: Vec<CriterionId>,
    model: ModelRef,
    prepared: Prepared,
    tasks: Vec<TaskRow>,
    parts: Vec<PartRow>,
    digest: ContentDigest,
}

/// The tasks of a call with criteria `criteria`.
fn tasks(criteria: &[CriterionId]) -> Vec<TaskRow> {
    let mut out = vec![TaskRow {
        stage: Stage::Completeness.as_str(),
        criterion: None,
        elements: RUBRIC_V1.required().iter().map(|t| t.as_str()).collect(),
    }];
    for c in criteria {
        out.push(TaskRow {
            stage: Stage::Quality.as_str(),
            criterion: Some(criterion_name(*c)),
            elements: Vec::new(),
        });
    }
    for s in [Stage::Claims, Stage::Integrity] {
        out.push(TaskRow {
            stage: s.as_str(),
            criterion: None,
            elements: Vec::new(),
        });
    }
    out
}

/// The digest of an input (ADR-033): SHA-256 over the labelled canonical
/// JSON of the call, the proposal, the prompt set, the tasks and the
/// parts. A change of any of them changes it.
fn input_digest(
    c: CallId,
    p: ProposalId,
    tasks: &[TaskRow],
    parts: &[PartRow],
) -> Option<ContentDigest> {
    let mut o = Object::new();
    o.insert("v", Value::from("fstp-api-core/client-assessment-input/v1"));
    o.insert("call", Value::String(c.raw().to_string()));
    o.insert("proposal", Value::String(p.raw().to_string()));
    o.insert("prompt_set", prompt_set().to_json());
    o.insert(
        "tasks",
        Value::Array(tasks.iter().map(ToJson::to_json).collect::<Array>()),
    );
    o.insert(
        "parts",
        Value::Array(parts.iter().map(ToJson::to_json).collect::<Array>()),
    );
    let text = fstp_json::to_canonical(&Value::Object(o)).ok()?;
    let mut h = fstp_crypto::Sha256::new();
    h.update(b"fstp-api-core/client-assessment-input\0");
    h.update(text.as_bytes());
    Some(ContentDigest::from_bytes(h.finish()))
}

/// The input of `p` for the caller: its call on the client path, the
/// submitted content, stages 1 and 2, the tasks and the digest.
async fn input_of<P: Seams>(
    call: &Call<'_, P>,
    p: ProposalId,
    clearance: &fstp_access::ReadClearance,
) -> Result<Input, ApiError> {
    let c = call_of(&call.state, p)
        .ok_or_else(|| call.refuse(ApiError::refused(ErrorCode::NotFound, "Input")))?;
    let view = call.state.core.calls().get(c);
    let (Some(frozen), Some(config)) = (
        view.and_then(|v| v.frozen()),
        view.and_then(|v| v.llm_config()),
    ) else {
        return Err(call.refuse(ApiError::refused(ErrorCode::Refused, "I-11")));
    };
    if !fstp_findings::client_run(&frozen.values().p21) {
        return Err(call.refuse(ApiError::refused(ErrorCode::Refused, "P-21")));
    }
    let criteria: Vec<CriterionId> = frozen.values().p01.items().iter().map(|x| x.id).collect();
    let model = pinned_model(call, c)
        .ok_or_else(|| call.refuse(ApiError::refused(ErrorCode::Refused, "I-11")))?;
    let w = submitted_of(call, p, clearance)
        .await
        .map_err(|e| call.refuse(e))?;
    let team = super::team_of(&call.state, p);
    let handles = super::team_handles(call, &team)
        .await
        .map_err(|e| call.refuse(e))?;
    let sections = [
        (DataLabel::Title, 0u8, w.title),
        (DataLabel::Summary, 1, w.summary),
        (DataLabel::Narrative, 2, w.narrative),
    ];
    let job = Job {
        proposal: p,
        parts: sections
            .into_iter()
            .map(|(label, k, text)| SubmissionPart {
                label,
                text_ref: part_ref(p, k, &text),
                text: UntrustedText::new(text),
            })
            .collect(),
        // M10 F-006 (ADR-033): the names the cell holds for the team are
        // handles of the pattern stage, so an unverified team is masked.
        handles: handles.into_iter().flatten().collect(),
    };
    let mask = VaultMask {
        ports: call.ports,
        team,
    };
    let prepared = fstp_assess::prepare(&mask, &job)
        .await
        .map_err(|_| call.refuse(ApiError::refused(ErrorCode::Unavailable, "content")))?;
    let parts: Vec<PartRow> = prepared
        .parts()
        .iter()
        .map(|part| {
            let text = part.stripped().as_data().to_owned();
            PartRow {
                label: part.label().as_str(),
                flags: super::integrity::flags(&text),
                text,
            }
        })
        .collect();
    let tasks = tasks(&criteria);
    let digest = input_digest(c, p, &tasks, &parts)
        .ok_or_else(|| call.refuse(ApiError::refused(ErrorCode::Unavailable, "content")))?;
    Ok(Input {
        call: c,
        config,
        criteria,
        model,
        prepared,
        tasks,
        parts,
        digest,
    })
}

/// The clearance of the input read of `p` for the caller, which the
/// submission needs too.
fn clearance_of<P: Seams>(
    call: &Call<'_, P>,
    p: ProposalId,
) -> Result<fstp_access::ReadClearance, ApiError> {
    let rop = ReadOp {
        kind: ReadKind::GetAssessmentInput,
        target: ReadTarget::Proposal(p),
    };
    fstp_access::authorize_read(&rop, &call.caller.p, &call.state, call.now)
        .map_err(|d| call.refuse(read_denied(d.rule())))
}

/// The metadata of an engine command by the caller.
fn meta<P: Seams>(call: &Call<'_, P>) -> ExecMeta {
    ExecMeta {
        via: call.caller.via(),
        session: call.caller.session,
        agent: call.caller.agent,
        op: OpName(call.spec.name),
        request: call.digest,
        step_up: None,
        pending: None,
        second_tenant_admin: None,
    }
}

/// The dry run of `ReadAssessmentInput` by the caller on `p`: the engine
/// judges the actor, then the P-21 path, the state, the declaration, the
/// assignments and the vault (ADR-033, I-03). Nothing is opened or
/// recorded before it passes. Returns the call and the context the read
/// then runs under.
async fn judge_reader<P: Seams>(
    call: &Call<'_, P>,
    account: AccountId,
    p: ProposalId,
) -> Result<(CallId, fstp_domain::command::Ctx), ApiError> {
    let c = call_of(&call.state, p)
        .ok_or_else(|| call.refuse(ApiError::refused(ErrorCode::NotFound, "Input")))?;
    let cmd = Command::Finding(FindingCommand::ReadAssessmentInput {
        call: c,
        proposal: p,
        input: ContentDigest::from_bytes([0; 32]),
    });
    let command_id = CommandId::from_bytes(call.draw().map_err(|e| call.refuse(e))?.to_be_bytes());
    let ctx = call.ctx(account, &cmd, call.caller.via(), command_id);
    dry_run(call, account, &cmd, ctx)
        .await
        .map_err(|e| call.refuse(e))?;
    Ok((c, ctx))
}

/// `assess.client_queue` (ADR-033): the proposals of the call in a state
/// where the coordinator reads content, by id and state, with whether a
/// client assessment is awaited.
pub(super) fn queue<P: Seams>(
    call: &Call<'_, P>,
    op: &Op,
    account: AccountId,
) -> Result<ReadModel, ApiError> {
    let c = call_param(call, op)?;
    let view = call
        .state
        .core
        .calls()
        .get(c)
        .ok_or_else(|| call.refuse(ApiError::refused(ErrorCode::NotFound, "Input")))?;
    let staged_open = view
        .frozen()
        .is_some_and(|f| f.values().p10 == ReadAccess::OperatorStaffOnly);
    let open = client_path(call, c);
    let store = &call.state.findings;
    let review = call.state.core.review();
    let proposals = if open {
        proposals_of_call(&call.state, c)
            .into_iter()
            .filter_map(|p| {
                let tag = fstp_domain::view::proposal_state(&call.state.core, p)?;
                let readable = match tag {
                    StateTag::Submitted => true,
                    StateTag::Stage1 | StateTag::Stage2 => staged_open,
                    _ => false,
                };
                if !readable {
                    return None;
                }
                // ADR-035: a held proposal waits for the coordinator's
                // release before any AI assessment.
                let status = if store.held(p) {
                    "held"
                } else if store.rerun_in_flight(p).is_some() {
                    "rerun"
                } else if store.client_runs_of(p) > 0 {
                    "assessed"
                } else {
                    "awaiting"
                };
                Some(QueueRow {
                    proposal: p.raw(),
                    state: state_name(&call.state, p),
                    status,
                    declared: review.cleared(account, p) && !review.conflict_fact(account, p),
                })
            })
            .collect()
    } else {
        Vec::new()
    };
    Ok(ReadModel::ClientAssessment(ClientModel::Queue(QueueView {
        call: c.raw(),
        open,
        model: if open {
            pinned_model(call, c).map(|m| m.0)
        } else {
            None
        },
        prompt_set: prompt_set(),
        proposals,
    })))
}

/// `assess.client_input` (ADR-033): the input of one proposal, after the
/// engine appended the read (R-AU-01, I-03).
pub(super) async fn input<P: Seams>(
    call: &Call<'_, P>,
    op: &Op,
    clearance: &fstp_access::ReadClearance,
) -> Result<OpResult, ApiError> {
    let Some(account) = call.account() else {
        return Err(call.refuse(ApiError::refused(ErrorCode::Unauthenticated, "actor")));
    };
    let p = proposal_param(call, op)?;
    // The engine judges the caller before any content is opened.
    let (c, ctx) = judge_reader(call, account, p).await?;
    let input = input_of(call, p, clearance).await?;
    let cmd = Command::Finding(FindingCommand::ReadAssessmentInput {
        call: c,
        proposal: p,
        input: input.digest,
    });
    let seq = call
        .ports
        .engine()
        .execute(cmd, ctx, meta(call))
        .await
        .map_err(|e| call.refuse(exec_failed(e)))?;
    Ok(OpResult::Done {
        body: ReadModel::ClientAssessment(ClientModel::Input(InputView {
            proposal: p.raw(),
            call: input.call.raw(),
            input_digest: hex(&input.digest.bytes()),
            model: input.model.0,
            prompt_set: prompt_set(),
            tasks: input.tasks,
            parts: input.parts,
        })),
        seq: Some(seq),
    })
}

/// One decoded reply of a submission.
struct Reply {
    stage: Stage,
    output: String,
}

/// The raw trace of a submission (R-LA-07): the replies as the client
/// sent them, each written back as canonical JSON, with the model, the
/// prompt set digest and the input digest. Canonical JSON throughout.
fn raw_trace(body: &Submission) -> String {
    let replies: Array = body
        .replies
        .iter()
        .map(|r| {
            let mut o = Object::new();
            o.insert("stage", Value::from(r.stage.as_str()));
            o.insert("output", Value::from(r.output.as_str()));
            Value::Object(o)
        })
        .collect();
    let mut o = Object::new();
    o.insert("v", Value::from("fstp-api-core/client-trace/v1"));
    o.insert("model", Value::from(body.model.as_str()));
    o.insert("prompt_set", Value::from(hex(&body.prompt_set).as_str()));
    o.insert("input", Value::from(hex(&body.input.bytes()).as_str()));
    o.insert("replies", Value::Array(replies));
    fstp_json::to_canonical(&Value::Object(o)).unwrap_or_default()
}

/// The decoded body of a submission.
struct Submission {
    input: ContentDigest,
    prompt_set: [u8; 32],
    model: String,
    replies: Vec<Reply>,
}

/// Decodes the body of `assess.client_submit`. Each reply's `output` is
/// written back as canonical JSON text for the stage 8 validator, which
/// owns its members (I-10).
fn submission(r: &Object) -> Option<Submission> {
    let input = unhex32(r.get("input_digest")?.as_str()?)?;
    let prompt_set = unhex32(r.get("prompt_set")?.as_str()?)?;
    let model = r.get("model")?.as_str()?;
    if !fstp_findings::codec::model_name_ok(model) {
        return None;
    }
    let list = r.get("replies")?.as_array()?;
    if list.len() > MAX_REPLIES {
        return None;
    }
    let mut replies = Vec::with_capacity(list.len());
    for v in list.iter() {
        let o = v.as_object()?;
        if o.keys().any(|k| k != "stage" && k != "output") {
            return None;
        }
        let name = o.get("stage")?.as_str()?;
        let stage = CLIENT_STAGES.into_iter().find(|s| s.as_str() == name)?;
        let output = fstp_json::to_canonical(o.get("output")?).ok()?;
        replies.push(Reply { stage, output });
    }
    Some(Submission {
        input: ContentDigest::from_bytes(input),
        prompt_set,
        model: model.to_owned(),
        replies,
    })
}

/// `assess.client_submit` (ADR-033): the checks of the cell, then one
/// `RecordClientAssessment` as the caller. The engine judges the caller,
/// the pin, the model, the input binding and the one-run rule.
pub(super) async fn submit<P: Seams>(call: &Call<'_, P>, op: &Op) -> Result<OpResult, ApiError> {
    let Some(account) = call.account() else {
        return Err(call.refuse(ApiError::refused(ErrorCode::Unauthenticated, "actor")));
    };
    let p = proposal_param(call, op)?;
    // The engine judges the caller and the path first, as for the input
    // read, so a caller who may not assess learns nothing more.
    judge_reader(call, account, p).await?;
    let clearance = clearance_of(call, p)?;
    let bad = || call.refuse(ApiError::bad_request(crate::forms::REQUEST_RULE));
    let body = submission(&op.request).ok_or_else(bad)?;
    if body.prompt_set != fstp_infer::prompt_set_digest() {
        // The plugin's prompt set is not the cell's (ADR-033).
        return Err(call.refuse(ApiError::refused(ErrorCode::Refused, "I-11")));
    }
    let input = input_of(call, p, &clearance).await?;
    if body.input != input.digest {
        // The submission names another input than the cell serves now.
        return Err(call.refuse(ApiError::refused(ErrorCode::Refused, "R-AU-01")));
    }
    if body.model != input.model.0 {
        // The client runs another model than the call pins.
        return Err(call.refuse(ApiError::refused(ErrorCode::Refused, "I-11")));
    }
    let mut found: Vec<AssessedFinding> = Vec::new();
    let mut refused: Vec<RefusedStage> = Vec::new();
    let mut dropped: Vec<DroppedRow> = Vec::new();
    for r in &body.replies {
        match decode_output(&r.output, r.stage, &input.criteria, &RUBRIC_V1) {
            Ok(raws) => found.extend(raws.into_iter().filter_map(|x| input.prepared.locate(x))),
            Err(e) => {
                let stage = AssessStage::parse(r.stage.as_str());
                let code = RefusalCode::parse(e.code());
                if let (Some(stage), Some(code)) = (stage, code) {
                    refused.push(RefusedStage { stage, code });
                    dropped.push(DroppedRow {
                        stage: stage.as_str(),
                        code: code.as_str(),
                    });
                }
            }
        }
    }
    // Stage 7, deterministic part: the cell's own scan, whatever the
    // client sent (TH-01). A proposal the scan flagged at submission holds
    // these findings already (ADR-035), so they are not recorded twice.
    if call.state.findings.integrity_of(p).is_none() {
        found.extend(input.prepared.integrity_scan());
    }
    if found.len() > fstp_findings::MAX_CLIENT_FINDINGS {
        return Err(bad());
    }
    let trace = TraceRef::from_raw(call.draw().map_err(|e| call.refuse(e))?);
    let mut findings = Vec::with_capacity(found.len());
    for f in found {
        findings.push(Finding {
            id: FindingId::from_raw(call.draw().map_err(|e| call.refuse(e))?),
            call: input.call,
            proposal: p,
            config: input.config,
            kind: f.kind,
            criterion: f.criterion,
            severity: f.severity,
            confidence: Confidence::from_permille(0).unwrap_or(Confidence::FULL),
            statement: f.statement,
            evidence: f.evidence,
            trace,
        });
    }
    let recorded = u64::try_from(findings.len()).unwrap_or(u64::MAX);
    let trace_text = raw_trace(&body);
    let mut run = ClientRun {
        model: ModelRef(body.model),
        prompt_set: ContentDigest::from_bytes(body.prompt_set),
        input: body.input,
        trace,
        raw: None,
    };
    let command = |run: ClientRun, findings: Vec<Finding>, refused: Vec<RefusedStage>| {
        Command::Finding(FindingCommand::RecordClientAssessment {
            call: input.call,
            proposal: p,
            run,
            findings,
            refused,
        })
    };
    let cmd = command(run.clone(), findings.clone(), refused.clone());
    let command_id = CommandId::from_bytes(call.draw().map_err(|e| call.refuse(e))?.to_be_bytes());
    let ctx = call.ctx(account, &cmd, call.caller.via(), command_id);
    dry_run(call, account, &cmd, ctx)
        .await
        .map_err(|e| call.refuse(e))?;
    // R-LA-07, P-22 (ADR-033 record of lane L31): the raw replies, sealed
    // at rest as a confidential text of the proposal, erased with its
    // texts. No read serves it, and nothing remembers it in this process.
    let stored = call
        .ports
        .texts()
        .put(
            TextClass::Confidential,
            TextOwner::Proposal(p),
            trace_text.as_bytes(),
        )
        .await
        .map_err(|e| call.refuse(super::port_failed(e, "text")))?;
    run.raw = Some(crate::forms::text_ref(stored.0, &trace_text));
    let cmd = command(run, findings, refused);
    let seq = call
        .ports
        .engine()
        .execute(cmd, ctx, meta(call))
        .await
        .map_err(|e| call.refuse(exec_failed(e)))?;
    Ok(OpResult::Done {
        body: ReadModel::ClientAssessment(ClientModel::Receipt(Receipt {
            recorded,
            refused: dropped,
        })),
        seq: Some(seq),
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    /// ADR-033: the input digest binds every served byte, so a submission
    /// cannot name content the cell did not serve.
    #[test]
    fn adr033_input_digest_binds_tasks_and_parts() {
        let c = CallId::from_raw(7);
        let p = ProposalId::from_raw(9);
        let t = tasks(&[CriterionId::from_raw(1)]);
        let parts = vec![PartRow {
            label: "narrative",
            text: "SYNTHETIC".to_owned(),
            flags: Vec::new(),
        }];
        let d = input_digest(c, p, &t, &parts).unwrap();
        assert_eq!(input_digest(c, p, &t, &parts), Some(d));
        let other = vec![PartRow {
            label: "narrative",
            text: "SYNTHETIC.".to_owned(),
            flags: Vec::new(),
        }];
        assert_ne!(input_digest(c, p, &t, &other), Some(d));
        assert_ne!(
            input_digest(c, ProposalId::from_raw(10), &t, &parts),
            Some(d)
        );
        assert_ne!(
            input_digest(c, p, &tasks(&[CriterionId::from_raw(2)]), &parts),
            Some(d)
        );
    }

    /// ADR-033, TH-01: a submission body is closed. A reply names one of
    /// the four client stages and an output, and nothing else. Verify is
    /// not a client stage.
    #[test]
    fn adr033_th01_submission_body_is_closed() {
        let good = |reply: &str| {
            format!(
                r#"{{"input_digest":"{}","prompt_set":"{}","model":"claude-opus-5-5","replies":[{reply}]}}"#,
                "a".repeat(64),
                "b".repeat(64)
            )
        };
        let parse = |s: String| {
            let v = fstp_json::parse(s.as_bytes()).unwrap();
            submission(v.as_object().unwrap()).is_some()
        };
        assert!(parse(good(
            r#"{"stage":"quality","output":{"findings":[]}}"#
        )));
        for bad in [
            r#"{"stage":"verify","output":{"findings":[]}}"#,
            r#"{"stage":"score","output":{"findings":[]}}"#,
            r#"{"stage":"quality","output":{"findings":[]},"tool":"fstp_prepare_role_grant"}"#,
            r#"{"stage":"quality"}"#,
        ] {
            assert!(!parse(good(bad)), "{bad}");
        }
        assert!(!parse(good("").replace("claude-opus-5-5", "bad model")));
    }
}
