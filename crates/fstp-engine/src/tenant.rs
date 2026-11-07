//! The tenant side of the envelope (M4 design sections 3.5 and 4.2, lane
//! m4tenant).
//!
//! A tenant record is stored under the envelope member `onboarding`. M3's
//! cell envelope (`fstp-cell-core`) stores its own tenant records under
//! `tenant`, so the engine's tenant side takes a member no cell family
//! uses, and one cell ledger can hold both. Its inner value is one of two
//! forms:
//!
//! - the codec form of an `fstp_tenant::TenantRecord`, decoded and encoded
//!   by `fstp-tenant`'s own codec, so each record has one spelling alone
//!   and inside the envelope (ADR-007);
//! - the provisioning record [`Provisioning`], the genesis of the tenant
//!   part. It names the first tenant admin and the kind of cell (Q31 A:
//!   "M3 provisioning the first admin"), and for a SaaS cell the
//!   agreement versions the control plane recorded as accepted (Q22).
//!
//! The fold is structural. A tenant record before the provisioning record,
//! or a second provisioning record, does not fold. Every other tenant
//! record folds through `TenantState::apply`, which checks again every rule
//! a record alone can show.
//!
//! A tenant command arrives as a [`TenantRequest`]: the command and the
//! [`TenantFacts`] the shell gathered in the same request, which are the
//! prober outcomes (Q5: an absent outcome fails closed). A save of the
//! Inference step also carries the configuration id the shell drew for
//! its inference record (see below). The engine answers the other
//! questions itself: the vault's `IsVerified` for each tenant admin, the
//! agreement versions of the provisioning record, and whether an account
//! holds a Receiving binding, from the core roster.
//!
//! # Interim readings, pending Daniel and the lead
//!
//! - The design names no record for the genesis of the tenant part. The
//!   provisioning record is this lane's reading. The control plane, or the
//!   enrolment token of a self-hosted cell, appends it at first start, so
//!   no command builds it.
//! - The control plane's answer to `TenantQuery::Agreements` is the
//!   versions of the provisioning record, which the control plane knows at
//!   provisioning (design 2.2 J0: sign-up and agreement acceptance come
//!   first). No later re-acceptance exists in M4.
//! - `TenantQuery::AdminVerified` is the vault's `IsVerified`. The vault
//!   has no `AdminIdentity` purpose query yet (design 6.1 item 13).
//! - Design 3.5: "The Inference step also records an
//!   `InferenceConfigRecorded` entry". A save of the Inference step that
//!   validates also records it, in the same entry, with the step's primary
//!   and fallbacks under the `LlmConfigId` the request carries. The shell
//!   draws that id from its id port. A validating Inference save without
//!   one is refused as facts incomplete. A command other than an Inference
//!   save that carries one is refused as inconsistent.

use std::collections::BTreeMap;
use std::hash::{Hash, Hasher};

use fstp_domain::command::{Actor, Ctx};
use fstp_domain::engine::FoldError;
use fstp_domain::id::{AccountId, LlmConfigId};
use fstp_domain::oracle::{Answers, Query};
use fstp_domain::refusal::{Refusal, RefusalReason, RuleRef};
use fstp_domain::roles::Group;
use fstp_domain::rules::ParamId;
use fstp_domain::state::State;
use fstp_json::{FromJsonError, Object, Value};
use fstp_tenant::{
    AgreementVersions, CellKind, DomainName, OnboardingStep, ProbeKind, ProbeOutcome, StepValues,
    TenantAnswers, TenantCommand, TenantCtx, TenantError, TenantQuery, TenantRecord, TenantRefusal,
    TenantState,
};

use crate::{EngineState, Record};

/// The `kind` of the provisioning record in its stored form.
pub const PROVISIONED_KIND: &str = "TenantProvisioned";

/// What the control plane provisioned: the genesis of the tenant part.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Provisioning {
    /// The first tenant admin, enrolled through the one-time link of the
    /// control plane or the enrolment token of a self-hosted cell.
    pub first_admin: AccountId,
    /// The kind of cell.
    pub cell: CellKind,
    /// The agreement versions the control plane recorded as accepted
    /// (Q22). Always `None` in a self-hosted cell, which has no control
    /// plane.
    pub agreements: Option<AgreementVersions>,
}

/// One record of the tenant side.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TenantEntry {
    /// The genesis of the tenant part.
    Provisioned(Provisioning),
    /// A record of `fstp-tenant`.
    Record(TenantRecord),
}

/// Hashes the canonical encoding, which is a function of the value, so
/// equal entries hash equally.
impl Hash for TenantEntry {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            TenantEntry::Provisioned(p) => {
                0u8.hash(state);
                p.hash(state);
            }
            TenantEntry::Record(r) => {
                1u8.hash(state);
                fstp_tenant::encode_record(r).ok().hash(state);
            }
        }
    }
}

/// The facts of one tenant command that only the shell can give: the
/// outcome of each prober check it ran in the same request.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TenantFacts {
    probes: BTreeMap<ProbeKind, ProbeOutcome>,
}

impl TenantFacts {
    /// No facts: every prober check reads as absent (Q5).
    pub fn new() -> TenantFacts {
        TenantFacts::default()
    }

    /// Records the outcome of the prober check `kind`.
    pub fn probe(&mut self, kind: ProbeKind, outcome: ProbeOutcome) {
        self.probes.insert(kind, outcome);
    }

    /// The recorded outcome of `kind`, if any.
    pub fn probe_outcome(&self, kind: &ProbeKind) -> Option<ProbeOutcome> {
        self.probes.get(kind).copied()
    }
}

/// A tenant command and the shell's facts for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TenantRequest {
    /// The command.
    pub command: TenantCommand,
    /// The facts the shell gathered in the same request.
    pub facts: TenantFacts,
    /// The configuration id the shell drew for the inference record of an
    /// Inference step save (design 3.5, module documentation). `None` for
    /// every other command.
    pub inference_config: Option<LlmConfigId>,
}

impl TenantRequest {
    /// `command` with no facts and no configuration id.
    pub fn new(command: TenantCommand) -> TenantRequest {
        TenantRequest {
            command,
            facts: TenantFacts::new(),
            inference_config: None,
        }
    }
}

/// The provisioned tenant: its genesis and its fold.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Provisioned {
    provisioning: Provisioning,
    state: TenantState,
}

/// The tenant part of [`EngineState`]. It is empty until the provisioning
/// record folds.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TenantPart {
    inner: Option<Provisioned>,
}

/// Hashes the provisioning, the revision and the admin set. Equal parts
/// hold equal values of each, so this agrees with `Eq`.
impl Hash for TenantPart {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match &self.inner {
            None => 0u8.hash(state),
            Some(p) => {
                1u8.hash(state);
                p.provisioning.hash(state);
                p.state.revision().hash(state);
                p.state.admins().hash(state);
            }
        }
    }
}

impl TenantPart {
    /// The tenant state, once provisioned.
    pub fn state(&self) -> Option<&TenantState> {
        self.inner.as_ref().map(|p| &p.state)
    }

    /// The provisioning record, once folded.
    pub fn provisioning(&self) -> Option<Provisioning> {
        self.inner.as_ref().map(|p| p.provisioning)
    }

    /// The agreement versions the control plane recorded (Q22), if any.
    pub fn agreements(&self) -> Option<AgreementVersions> {
        self.provisioning().and_then(|p| p.agreements)
    }
}

// ---------------------------------------------------------------------------
// Fold
// ---------------------------------------------------------------------------

/// The engine fold error of a tenant fold refusal.
fn fold_error(e: fstp_tenant::FoldError) -> FoldError {
    match e.0 {
        TenantRefusal::InvitationNotOpen | TenantRefusal::ApprovalNotOpen => {
            FoldError::UnknownEntity
        }
        TenantRefusal::InvitationTaken
        | TenantRefusal::ApprovalTaken
        | TenantRefusal::ConfigTaken => FoldError::DuplicateId,
        _ => FoldError::Inconsistent,
    }
}

/// Folds one tenant entry. On an error the part may be partly changed;
/// the engine folds into a copy.
pub(crate) fn apply_tenant(part: &mut TenantPart, entry: &TenantEntry) -> Result<(), FoldError> {
    match entry {
        TenantEntry::Provisioned(p) => {
            if part.inner.is_some() {
                return Err(FoldError::DuplicateId);
            }
            if p.cell == CellKind::SelfHosted && p.agreements.is_some() {
                return Err(FoldError::Inconsistent);
            }
            part.inner = Some(Provisioned {
                provisioning: *p,
                state: TenantState::genesis(p.first_admin, p.cell),
            });
            Ok(())
        }
        TenantEntry::Record(r) => {
            let Some(p) = part.inner.as_mut() else {
                return Err(FoldError::UnknownEntity);
            };
            p.state.apply(r).map_err(fold_error)
        }
    }
}

// ---------------------------------------------------------------------------
// Decide
// ---------------------------------------------------------------------------

/// The refusal of a tenant command in an unprovisioned engine.
const fn unprovisioned() -> Refusal {
    Refusal::new(RuleRef::Input, RefusalReason::UnknownEntity)
}

/// The domain refusal of a tenant refusal. The engine's error channel is
/// the domain `Refusal`, so a tenant rule is named by the nearest rule
/// reference. The API core names the tenant rule itself
/// ([`precheck_tenant`] gives it).
pub fn tenant_refusal(r: TenantRefusal) -> Refusal {
    use RefusalReason as Why;
    let (rule, why) = match r {
        TenantRefusal::HighRiskViaMcp | TenantRefusal::WebOnlyViaMcp => {
            (RuleRef::I85, Why::NotThroughMcp)
        }
        TenantRefusal::NotTenantAdmin => (RuleRef::Rac01, Why::WrongActor),
        TenantRefusal::InvalidSetting(p) => (RuleRef::Param(p.param_id()), Why::InvalidValue),
        TenantRefusal::InvalidModels | TenantRefusal::NotDefaultModels => {
            (RuleRef::Param(ParamId::P21), Why::InvalidValue)
        }
        TenantRefusal::HoldsReceiving => (RuleRef::Sod03, Why::GuardFailed),
        TenantRefusal::AdminNotVerified => (RuleRef::Sod07, Why::VaultRefused),
        TenantRefusal::TooFewAdmins
        | TenantRefusal::SelfApproval
        | TenantRefusal::GranteeNotAdmin
        | TenantRefusal::ApprovalExpired
        | TenantRefusal::ApprovalNotOpen => (RuleRef::Sod07, Why::GuardFailed),
        TenantRefusal::AnswerMissing => (RuleRef::FactsIncomplete, Why::AnswerMissing),
        TenantRefusal::InvitationTaken
        | TenantRefusal::ApprovalTaken
        | TenantRefusal::ConfigTaken => (RuleRef::Input, Why::IdReused),
        TenantRefusal::InvitationNotOpen => (RuleRef::Input, Why::UnknownEntity),
        TenantRefusal::InvitationMismatch => (RuleRef::Input, Why::WrongActor),
        TenantRefusal::InvalidInstant => (RuleRef::Ledger, Why::InvalidValue),
        TenantRefusal::Inconsistent => (RuleRef::Ledger, Why::GuardFailed),
        // R-GA-01 has no domain rule reference, so the API core names it.
        TenantRefusal::InvalidAddress => (RuleRef::Input, Why::InvalidValue),
        TenantRefusal::StaleRevision
        | TenantRefusal::StepLocked
        | TenantRefusal::StepSkipped
        | TenantRefusal::AlreadyAdmin
        | TenantRefusal::AlreadyCompleted
        | TenantRefusal::StepsNotValidated => (RuleRef::Input, Why::WrongState),
        // SoD-14 to SoD-18 have no domain rule reference. Their nearest
        // ones are named here, and the API core names the SoD rule.
        TenantRefusal::SignatorySelfGrant => (RuleRef::Sod07, Why::GuardFailed),
        TenantRefusal::SignatoryHeld
        | TenantRefusal::LastSignatory
        | TenantRefusal::NoFinancialSignatory
        | TenantRefusal::NoLegalSignatory => (RuleRef::Input, Why::GuardFailed),
        TenantRefusal::SignatoryNotHeld => (RuleRef::Input, Why::UnknownEntity),
        TenantRefusal::ActivationPending
        | TenantRefusal::AlreadyActive
        | TenantRefusal::ActivationNotOpen => (RuleRef::Input, Why::WrongState),
        // SoD-18 holds by analogy with I-67.
        TenantRefusal::SelfActivationApproval => (RuleRef::I67, Why::GuardFailed),
        // I-70 has no domain rule reference. The API core names I-70.
        TenantRefusal::BrandingContrast(_) => (RuleRef::Input, Why::InvalidValue),
        TenantRefusal::TerminologyInvalid => (RuleRef::Input, Why::InvalidValue),
        // ADR-018 and I-38 have no domain rule reference. The API core
        // names I-38.
        TenantRefusal::InvalidMailRelay => (RuleRef::Input, Why::InvalidValue),
    };
    Refusal::new(rule, why)
}

/// The account of a tenant command's actor. A system actor issues no
/// tenant command.
fn actor_of(ctx: &Ctx) -> Result<AccountId, Refusal> {
    match ctx.actor {
        Actor::Account(a) => Ok(a),
        Actor::System(_) => Err(Refusal::new(RuleRef::Actor, RefusalReason::WrongActor)),
    }
}

/// The tenant state of a provisioned engine.
fn provisioned(state: &EngineState) -> Result<&TenantState, Refusal> {
    state.tenant.state().ok_or(unprovisioned())
}

/// Whether `a` holds a Receiving binding in any programme of the cell, as
/// SoD-03 counts it: a held binding of the Receiving group.
fn holds_receiving(core: &State, a: AccountId) -> bool {
    core.roster()
        .bindings()
        .any(|(_, b)| b.account == a && b.group() == Group::Receiving && b.held())
}

/// The vault questions of a tenant command: `IsVerified` for each
/// `AdminVerified` question of `fstp_tenant::queries`.
pub(crate) fn tenant_queries(
    state: &EngineState,
    req: &TenantRequest,
    ctx: &Ctx,
) -> Result<Vec<Query>, Refusal> {
    actor_of(ctx)?;
    let ts = provisioned(state)?;
    Ok(fstp_tenant::queries(ts, &req.command)
        .into_iter()
        .filter_map(|q| match q {
            TenantQuery::AdminVerified(account) => Some(Query::IsVerified { account }),
            _ => None,
        })
        .collect())
}

/// The answers of `fstp_tenant::queries`: the vault's from `verified`,
/// the prober's from the request's facts, the control plane's from the
/// provisioning record, and the Receiving check from the core roster.
fn tenant_answers(
    state: &EngineState,
    ts: &TenantState,
    req: &TenantRequest,
    verified: &dyn Fn(AccountId) -> Option<bool>,
) -> TenantAnswers {
    let mut answers = TenantAnswers::new();
    for q in fstp_tenant::queries(ts, &req.command) {
        match q {
            TenantQuery::AdminVerified(a) => {
                if let Some(holds) = verified(a) {
                    answers.verified(a, holds);
                }
            }
            TenantQuery::Probe(kind) => {
                if let Some(outcome) = req.facts.probe_outcome(&kind) {
                    answers.probe(kind, outcome);
                }
            }
            TenantQuery::Agreements => {
                if let Some(v) = state.tenant.agreements() {
                    answers.agreements(v);
                }
            }
            TenantQuery::HoldsReceiving(a) => {
                answers.holds_receiving(a, holds_receiving(&state.core, a));
            }
        }
    }
    answers
}

/// The tenant context of `ctx`.
fn tenant_ctx(actor: AccountId, ctx: &Ctx) -> TenantCtx {
    TenantCtx {
        actor,
        via: ctx.via,
        at: ctx.now,
    }
}

/// Decides a tenant command with the vault answers the driver obtained.
/// Every record it returns encodes, so the ledger can store it.
pub(crate) fn decide_tenant(
    state: &EngineState,
    req: &TenantRequest,
    ctx: &Ctx,
    vault: &Answers,
) -> Result<Vec<Record>, Refusal> {
    let actor = actor_of(ctx)?;
    let ts = provisioned(state)?;
    let verified = |account: AccountId| vault.get(&Query::IsVerified { account }).map(|a| a.holds);
    let answers = tenant_answers(state, ts, req, &verified);
    let records =
        decide_request(ts, &tenant_ctx(actor, ctx), req, &answers).map_err(tenant_refusal)?;
    if records
        .iter()
        .any(|r| fstp_tenant::encode_record(r).is_err())
    {
        return Err(Refusal::new(RuleRef::Ledger, RefusalReason::InvalidValue));
    }
    Ok(records
        .into_iter()
        .map(|r| Record::Tenant(TenantEntry::Record(r)))
        .collect())
}

/// Decides `req` in `state` without the vault, reading every tenant admin
/// as verified, and returns the tenant refusal itself. The API core runs
/// it before the dry run, so a refusal names its tenant rule. The dry run
/// and the execution still decide with the vault's answers.
pub fn precheck_tenant(
    state: &EngineState,
    req: &TenantRequest,
    actor: AccountId,
    ctx: &Ctx,
) -> Result<Vec<TenantRecord>, PrecheckError> {
    let ts = state.tenant.state().ok_or(PrecheckError::Unprovisioned)?;
    let answers = tenant_answers(state, ts, req, &|_| Some(true));
    decide_request(ts, &tenant_ctx(actor, ctx), req, &answers).map_err(PrecheckError::Refused)
}

/// The records of `req` in `ts`: those of `fstp_tenant::decide`, and for
/// an Inference step save that validates, the `InferenceConfigRecorded`
/// record of its models under the request's configuration id (design
/// 3.5, module documentation). That record is decided against the state
/// the save's records leave, so the entry folds in the order it is
/// stored.
fn decide_request(
    ts: &TenantState,
    ctx: &TenantCtx,
    req: &TenantRequest,
    answers: &TenantAnswers,
) -> Result<Vec<TenantRecord>, TenantRefusal> {
    let inference = match &req.command {
        TenantCommand::SaveStep {
            values: StepValues::Inference(d),
            ..
        } => Some(d),
        _ => None,
    };
    if inference.is_none() && req.inference_config.is_some() {
        return Err(TenantRefusal::Inconsistent);
    }
    let mut records = fstp_tenant::decide(ts, ctx, &req.command, answers)?;
    let validated = records.iter().any(|r| {
        matches!(
            r,
            TenantRecord::StepValidated {
                step: OnboardingStep::Inference,
                ..
            }
        )
    });
    let Some(d) = inference.filter(|_| validated) else {
        return Ok(records);
    };
    let config = req.inference_config.ok_or(TenantRefusal::AnswerMissing)?;
    let mut after = ts.clone();
    after.apply_all(&records).map_err(|e| e.0)?;
    let record = TenantCommand::RecordInferenceConfig {
        config,
        primary: d.primary.clone(),
        fallbacks: d.fallbacks.clone(),
    };
    records.extend(fstp_tenant::decide(&after, ctx, &record, answers)?);
    Ok(records)
}

/// Why [`precheck_tenant`] refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PrecheckError {
    /// The tenant part holds no provisioning record yet.
    Unprovisioned,
    /// `fstp_tenant::decide` refused.
    Refused(TenantRefusal),
}

// ---------------------------------------------------------------------------
// Codec
// ---------------------------------------------------------------------------

fn dec(x: impl std::fmt::Display) -> Value {
    Value::String(x.to_string())
}

const fn cell_name(c: CellKind) -> &'static str {
    match c {
        CellKind::Saas => "saas",
        CellKind::SelfHosted => "self_hosted",
    }
}

/// The stored inner value of a tenant entry.
pub(crate) fn entry_to_json(e: &TenantEntry) -> Value {
    match e {
        TenantEntry::Provisioned(p) => {
            let mut o = Object::new();
            if let Some(a) = p.agreements {
                let mut v = Object::new();
                v.insert("dpa", dec(a.dpa));
                v.insert("saas_terms", dec(a.saas_terms));
                v.insert("sub_processors", dec(a.sub_processors));
                o.insert("agreements", Value::Object(v));
            }
            o.insert("cell", Value::from(cell_name(p.cell)));
            o.insert("first_admin", dec(p.first_admin.raw()));
            o.insert("kind", Value::from(PROVISIONED_KIND));
            Value::Object(o)
        }
        // A record that `decide_tenant` returned always encodes. A value
        // with no encoding becomes `null`, which no decoder takes, so it
        // never folds.
        TenantEntry::Record(r) => fstp_tenant::encode_record(r)
            .ok()
            .and_then(|b| fstp_json::parse(&b).ok())
            .unwrap_or(Value::Null),
    }
}

/// The JSON form of a tenant request: the command in the tenant codec's
/// form, each prober outcome it carries in the order of its kinds, and
/// the configuration id when it carries one. A cell envelope of commands
/// encodes it with this, and [`request_from_json`] reads it back.
pub fn request_json(r: &TenantRequest) -> Value {
    let command = fstp_tenant::encode_command(&r.command)
        .ok()
        .and_then(|b| fstp_json::parse(&b).ok())
        .unwrap_or(Value::Null);
    let probes: fstp_json::Array = r
        .facts
        .probes
        .iter()
        .map(|(kind, outcome)| {
            let mut o = Object::new();
            match kind {
                ProbeKind::SendingDomain(d) => {
                    o.insert("check", Value::from("sending_domain"));
                    o.insert("domain", Value::from(d.as_str()));
                }
                ProbeKind::Channels => {
                    o.insert("check", Value::from("channels"));
                }
            }
            let outcome = match outcome {
                ProbeOutcome::Passed => "passed",
                ProbeOutcome::Failed => "failed",
                ProbeOutcome::Absent => "absent",
            };
            o.insert("outcome", Value::from(outcome));
            Value::Object(o)
        })
        .collect();
    let mut o = Object::new();
    o.insert("command", command);
    if let Some(c) = r.inference_config {
        o.insert("inference_config", dec(c.raw()));
    }
    o.insert("probes", Value::Array(probes));
    Value::Object(o)
}

/// The prober check and outcome of one member of `probes`.
fn probe_from_json(v: &Value) -> Result<(ProbeKind, ProbeOutcome), FromJsonError> {
    let o = v
        .as_object()
        .ok_or_else(|| FromJsonError::invalid("expected an object"))?;
    let str_of = |k: &str| {
        o.get(k)
            .and_then(Value::as_str)
            .ok_or_else(|| FromJsonError::invalid("a probe member is missing"))
    };
    let (kind, members) = match str_of("check")? {
        "sending_domain" => {
            let d = DomainName::new(str_of("domain")?)
                .ok_or_else(|| FromJsonError::invalid("not a domain name"))?;
            (ProbeKind::SendingDomain(d), 3)
        }
        "channels" => (ProbeKind::Channels, 2),
        _ => return Err(FromJsonError::invalid("unknown prober check")),
    };
    if o.len() != members {
        return Err(FromJsonError::invalid(
            "probe members do not match the schema",
        ));
    }
    let outcome = match str_of("outcome")? {
        "passed" => ProbeOutcome::Passed,
        "failed" => ProbeOutcome::Failed,
        "absent" => ProbeOutcome::Absent,
        _ => return Err(FromJsonError::invalid("unknown probe outcome")),
    };
    Ok((kind, outcome))
}

/// Decodes the JSON form of a tenant request strictly: exactly `command`
/// and `probes`, with `inference_config` when the request carries one.
/// The command goes to the tenant codec through its canonical text, so
/// the codec's limits and checks apply. The probes must be in the order
/// of their kinds, each kind once, and the whole value must be the one
/// [`request_json`] writes, so each request has one spelling (I-78: the
/// step-up digest is taken over it).
pub fn request_from_json(v: &Value) -> Result<TenantRequest, FromJsonError> {
    let o = v
        .as_object()
        .ok_or_else(|| FromJsonError::invalid("expected an object"))?;
    let want = if o.contains_key("inference_config") {
        3
    } else {
        2
    };
    if o.len() != want || !o.contains_key("command") || !o.contains_key("probes") {
        return Err(FromJsonError::invalid(
            "request members do not match the schema",
        ));
    }
    let command = o
        .get("command")
        .ok_or_else(|| FromJsonError::invalid("missing command"))?;
    let text = fstp_json::to_canonical(command)
        .map_err(|_| FromJsonError::invalid("value has no canonical text"))?;
    let command = fstp_tenant::decode_command(text.as_bytes()).map_err(codec_error)?;
    let mut req = TenantRequest::new(command);
    let probes = o
        .get("probes")
        .and_then(Value::as_array)
        .ok_or_else(|| FromJsonError::invalid("expected an array of probes"))?;
    for p in probes.iter() {
        let (kind, outcome) = probe_from_json(p)?;
        if req
            .facts
            .probes
            .keys()
            .next_back()
            .is_some_and(|k| *k >= kind)
        {
            return Err(FromJsonError::invalid("probes out of order"));
        }
        req.facts.probe(kind, outcome);
    }
    req.inference_config = match o.get("inference_config") {
        None => None,
        Some(c) => Some(
            canonical_digits(c)?
                .parse::<u128>()
                .map(LlmConfigId::from_raw)
                .map_err(|_| FromJsonError::invalid("decimal out of range"))?,
        ),
    };
    if !request_json(&req).identical(v) {
        return Err(FromJsonError::invalid(
            "not the one spelling of the request",
        ));
    }
    Ok(req)
}

/// The digits of a canonical unsigned decimal string.
fn canonical_digits(v: &Value) -> Result<&str, FromJsonError> {
    let s = v
        .as_str()
        .ok_or_else(|| FromJsonError::invalid("expected a decimal string"))?;
    let ok =
        !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) && (s == "0" || !s.starts_with('0'));
    if ok {
        Ok(s)
    } else {
        Err(FromJsonError::invalid("not a canonical decimal string"))
    }
}

fn take_u32(v: &Value) -> Result<u32, FromJsonError> {
    canonical_digits(v)?
        .parse::<u32>()
        .map_err(|_| FromJsonError::invalid("decimal out of range"))
}

/// Decodes the provisioning record strictly: exactly `cell`,
/// `first_admin` and `kind`, with `agreements` in a SaaS cell when the
/// control plane recorded them. An absent `agreements` is the only
/// spelling of none.
fn provisioning_from_json(o: &Object) -> Result<Provisioning, FromJsonError> {
    let has_agreements = o.contains_key("agreements");
    let want = if has_agreements { 4 } else { 3 };
    let named = ["cell", "first_admin", "kind"]
        .iter()
        .all(|m| o.contains_key(m));
    if o.len() != want || !named {
        return Err(FromJsonError::invalid(
            "provisioning members do not match the schema",
        ));
    }
    let cell = match o.get("cell").and_then(Value::as_str) {
        Some("saas") => CellKind::Saas,
        Some("self_hosted") => CellKind::SelfHosted,
        _ => return Err(FromJsonError::invalid("unknown cell kind")),
    };
    let first_admin = o
        .get("first_admin")
        .ok_or_else(|| FromJsonError::invalid("missing first admin"))
        .and_then(canonical_digits)?
        .parse::<u128>()
        .map(AccountId::from_raw)
        .map_err(|_| FromJsonError::invalid("decimal out of range"))?;
    let agreements = match o.get("agreements") {
        None => None,
        Some(_) if cell == CellKind::SelfHosted => {
            return Err(FromJsonError::invalid(
                "a self-hosted cell records no agreements",
            ));
        }
        Some(v) => {
            let a = v
                .as_object()
                .ok_or_else(|| FromJsonError::invalid("expected an object"))?;
            let members = ["dpa", "saas_terms", "sub_processors"];
            if a.len() != members.len() || !members.iter().all(|m| a.contains_key(m)) {
                return Err(FromJsonError::invalid(
                    "agreement members do not match the schema",
                ));
            }
            let get = |k: &str| {
                a.get(k)
                    .ok_or_else(|| FromJsonError::invalid("missing member"))
                    .and_then(take_u32)
            };
            Some(AgreementVersions {
                saas_terms: get("saas_terms")?,
                dpa: get("dpa")?,
                sub_processors: get("sub_processors")?,
            })
        }
    };
    Ok(Provisioning {
        first_admin,
        cell,
        agreements,
    })
}

/// The decode error of a tenant codec error. It holds a fixed message
/// only (R-NF-02).
fn codec_error(e: TenantError) -> FromJsonError {
    match e {
        TenantError::Decode(d) => FromJsonError::invalid(d.message()),
        _ => FromJsonError::invalid("tenant record does not decode"),
    }
}

/// Decodes the stored inner value of a tenant entry. A record goes to the
/// tenant codec through its canonical text, so the codec's limits and
/// checks apply.
pub(crate) fn entry_from_json(v: &Value) -> Result<TenantEntry, FromJsonError> {
    let o = v
        .as_object()
        .ok_or_else(|| FromJsonError::invalid("expected an object"))?;
    if o.get("kind").and_then(Value::as_str) == Some(PROVISIONED_KIND) {
        return provisioning_from_json(o).map(TenantEntry::Provisioned);
    }
    let text = fstp_json::to_canonical(v)
        .map_err(|_| FromJsonError::invalid("value has no canonical text"))?;
    fstp_tenant::decode_record_at(fstp_tenant::CURRENT_SCHEMA, text.as_bytes())
        .map(TenantEntry::Record)
        .map_err(codec_error)
}
