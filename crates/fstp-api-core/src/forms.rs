//! The request form of each operation (design section 3.7 step 1).
//!
//! A request is one JSON object: the route's path parameters, each a
//! decimal string, and the body members. A tool call carries the same
//! object as its arguments. [`check`] is the strict decoder: it refuses
//! unknown members, missing members and values of the wrong JSON type.
//! [`build`] turns a checked request into the engine command, with the
//! values only the server supplies: drawn ids, text references from the
//! text store, members derived from the state, and attested records.
//!
//! Interim readings, pending Daniel (design section 15.0):
//!
//! - Request members follow the command codec of `fstp-domain`: ids,
//!   instants and amounts as decimal strings (ADR-006), a `currency`
//!   member beside amounts, and small integers as JSON numbers.
//! - Free text is a plain JSON string, at most [`TEXT_LIMIT`] bytes. The
//!   server stores it and puts the `TextRef` in its place.
//! - Ids the server draws (bindings, decisions, calls, proposals, plans,
//!   assignments, handles) and values from attested records (the P-21
//!   configuration of a publication) are never request members.
//! - A cut-off round is named by the round id the server drew when it
//!   opened (change D5). The ballot, the delegation and the record carry
//!   no other member of the round.
//! - A page form plan records a stage 2 revision while its proposal is in
//!   STAGE2, and the plan of the submission otherwise (R-EV-05).
//! - `PUT /assignments/{assignment}/scores/{score}` names the score by
//!   the plan version it scored, with the stage in the body.
//! - `EndRole` takes an optional `at`. Without it the binding ends at the
//!   call's instant.
//! - `CreateDraft` starts minor-flagged. The flag never comes from a
//!   request, and the domain derives it from the vault (I-18, NOTE 14).

use std::collections::BTreeMap;

use fstp_access::{OpKind, OpSpec, PendingKind};
use fstp_domain::command::{Command as Core, CommandKind, DeclarationSubject};
use fstp_domain::id::{
    AccountId, AssignmentId, CallId, ContentDigest, LlmConfigId, ProgrammeId, ProposalId, TextId,
    TextRef,
};
use fstp_domain::policy::{ModelRef, ReviewerAnonymity};
use fstp_domain::roles::BindingScope;
use fstp_domain::time::Timestamp;
use fstp_engine::{Command, EngineState};
use fstp_json::{Object, ToJson, Value};

use crate::ApiError;

/// The largest free text member, in bytes (interim, pending Daniel).
pub(crate) const TEXT_LIMIT: usize = 64 * 1024;

/// The rule text a malformed request names.
pub(crate) const REQUEST_RULE: &str = "request";

/// How a path parameter is spelled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ParamKind {
    /// A canonical decimal id.
    Id,
    /// A lowercase token: `[a-z0-9_-]{1,64}`.
    Token,
    /// The secret token of a link, `[0-9a-f]{32,128}` (lane m4reg). It is
    /// the capability of a read that admits a caller with no account, so
    /// it is never a guessable id (SoD-09).
    LinkToken,
    /// A field key of the programme spec, `<step>.<member>`: two tokens
    /// of `[a-z0-9_]` joined by one dot (lane m4wire). The creator codec
    /// judges whether it names a field.
    FieldKey,
    /// One of the previews of journey J1 (`creator::PREVIEWS`).
    Preview,
}

/// The spelling of the path parameter `name`.
pub(crate) fn param_kind(name: &str) -> ParamKind {
    match name {
        "slug" | "step" => ParamKind::Token,
        // Lane m4wire: the narrative acceptance names its field by key,
        // and a preview by its kind.
        "field" => ParamKind::FieldKey,
        "preview" => ParamKind::Preview,
        // Lane m4reg: the invitation landing, its acceptance and its
        // verification take the token of the link (SoD-09).
        "invitation_token" => ParamKind::LinkToken,
        _ => ParamKind::Id,
    }
}

/// Whether `s` is a valid value of the path parameter `name`.
pub(crate) fn param_str_ok(name: &str, s: &str) -> bool {
    match param_kind(name) {
        ParamKind::Id => canonical_id(s).is_some(),
        ParamKind::Token => token(s),
        ParamKind::LinkToken => link_token(s),
        ParamKind::FieldKey => field_key(s),
        ParamKind::Preview => crate::creator::PREVIEWS.contains(&s),
    }
}

/// Whether `s` is shaped as a field key: `<step>.<member>`, each part 1
/// to 64 characters of `[a-z0-9_]`.
pub(crate) fn field_key(s: &str) -> bool {
    let part = |p: &str| {
        (1..=64).contains(&p.len())
            && p.bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
    };
    s.split_once('.').is_some_and(|(a, b)| part(a) && part(b))
}

/// Whether `s` is a canonical decimal `u128`: digits only, no leading
/// zero, and in range.
pub(crate) fn canonical_id(s: &str) -> Option<u128> {
    let b = s.as_bytes();
    let canonical = !b.is_empty()
        && b.iter().all(u8::is_ascii_digit)
        && (b.len() == 1 || b.first() != Some(&b'0'));
    if !canonical {
        return None;
    }
    s.parse::<u128>().ok()
}

/// Whether `s` is a path token.
pub(crate) fn token(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'_')
}

/// Whether `s` is a link token: 32 to 128 lowercase hexadecimal digits.
pub(crate) fn link_token(s: &str) -> bool {
    (32..=128).contains(&s.len())
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// Whether `v` is a valid value of the path parameter `name`.
pub(crate) fn param_ok(name: &str, v: &Value) -> bool {
    let Some(s) = v.as_str() else {
        return false;
    };
    param_str_ok(name, s)
}

/// What a command takes from the state or the cell beside the request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Derive {
    /// Nothing.
    None,
    /// `proposal` is the proposal of the `assignment` parameter.
    ProposalOfAssignment,
    /// `subject` is the proposal parameter.
    SubjectProposal,
    /// `subject` is the assignment parameter, from `param`.
    SubjectAssignment(&'static str),
    /// `config` and `config_model` come from the tenant's inference
    /// record (design section 3.5).
    Inference,
    /// `minor` is `true` (I-18).
    Minor,
    /// `key` is `{assignment, stage, plan}`: the assignment parameter,
    /// the body's `stage` and the plan, from the body or from `{score}`.
    ScoreKey,
    /// `second_admin` is the approver of the body's optional `approval`
    /// (SoD-07). Dispatch resolves it, so the form only removes it.
    SecondAdmin,
    /// `at` defaults to the call's instant.
    EndAt,
    /// `handle` is drawn under P-11 anonymous and `null` under named.
    Handle,
    /// A plan from the page form (`pageforms.rs`): the content digest of
    /// its description, the origin, the currency of the proposal's
    /// programme and drawn milestone ids. The superseded plan is the one
    /// [`name_plans`] named before the digest. A codec form passes
    /// unchanged.
    PlanForm,
    /// A submission names the plan that [`name_plans`] put in the request
    /// before the digest. Without one it is refused, and nothing is
    /// derived here, so a confirmation never picks a later plan (I-85).
    LatestPlan,
}

/// The form of one command kind.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CmdForm {
    /// The command kind.
    pub(crate) kind: CommandKind,
    /// Path parameters and the command member each fills. `None` checks
    /// the parameter against the target only.
    pub(crate) params: &'static [(&'static str, Option<&'static str>)],
    /// Body members the client must send.
    pub(crate) required: &'static [&'static str],
    /// Body members the client may send. A missing one is `null`.
    pub(crate) optional: &'static [&'static str],
    /// Members the server draws as fresh ids.
    pub(crate) drawn: &'static [&'static str],
    /// Text members, as dotted paths into the request.
    pub(crate) texts: &'static [&'static str],
    /// What the server derives.
    pub(crate) derive: Derive,
}

const fn form(kind: CommandKind) -> CmdForm {
    CmdForm {
        kind,
        params: &[],
        required: &[],
        optional: &[],
        drawn: &[],
        texts: &[],
        derive: Derive::None,
    }
}

/// The form of a routed command kind, or `None` for a kind no route
/// reaches.
pub(crate) fn command_form(kind: CommandKind) -> Option<CmdForm> {
    use CommandKind as K;
    const PROPOSAL: &[(&str, Option<&str>)] = &[("proposal", Some("proposal"))];
    const CALL: &[(&str, Option<&str>)] = &[("call", Some("call"))];
    const ASSIGNMENT: &[(&str, Option<&str>)] = &[("assignment", Some("assignment"))];
    let f = match kind {
        K::GrantRole => CmdForm {
            params: &[("programme", Some("programme"))],
            required: &["account", "role", "start"],
            optional: &["end", "organisation", "confidentiality", "approval"],
            drawn: &["binding"],
            texts: &["confidentiality"],
            derive: Derive::SecondAdmin,
            ..form(kind)
        },
        K::EndRole => CmdForm {
            params: &[("programme", None), ("binding", Some("binding"))],
            optional: &["at"],
            derive: Derive::EndAt,
            ..form(kind)
        },
        K::ReinstateBinding => CmdForm {
            params: &[("programme", None), ("binding", Some("binding"))],
            required: &["reason"],
            texts: &["reason"],
            ..form(kind)
        },
        K::DraftCall => CmdForm {
            params: &[("programme", Some("programme"))],
            required: &[
                "opens",
                "deadline",
                "deadline_zone",
                "currency",
                "budget",
                "text",
            ],
            drawn: &["call"],
            texts: &["text"],
            ..form(kind)
        },
        K::EditCall => CmdForm {
            params: CALL,
            required: &[
                "opens",
                "deadline",
                "deadline_zone",
                "currency",
                "budget",
                "text",
            ],
            texts: &["text"],
            ..form(kind)
        },
        K::ApproveCallPublication => CmdForm {
            params: CALL,
            drawn: &["decision"],
            ..form(kind)
        },
        K::PublishCall => CmdForm {
            params: CALL,
            derive: Derive::Inference,
            ..form(kind)
        },
        K::CreateDraft => CmdForm {
            params: CALL,
            drawn: &["proposal", "binding"],
            derive: Derive::Minor,
            ..form(kind)
        },
        K::AddTeamMember | K::AddGuardian => CmdForm {
            params: PROPOSAL,
            required: &["account"],
            drawn: &["binding"],
            ..form(kind)
        },
        // The page form sends `description` and `tasks` (`pageforms.rs`);
        // the codec form, as a tool sends it, `origin`, `content` and
        // `currency` beside them.
        K::RecordPlanVersion => CmdForm {
            params: PROPOSAL,
            required: &["tasks"],
            optional: &["origin", "content", "currency", "supersedes", "description"],
            drawn: &["plan"],
            texts: &["description"],
            derive: Derive::PlanForm,
            ..form(kind)
        },
        // Without a `plan`, the submission names the proposal's latest
        // recorded plan (the page form, `pageforms.rs`).
        K::Submit => CmdForm {
            params: PROPOSAL,
            required: &["ethics", "notice"],
            optional: &["plan"],
            texts: &["ethics.text"],
            derive: Derive::LatestPlan,
            ..form(kind)
        },
        K::AnswerQuestions => CmdForm {
            params: PROPOSAL,
            required: &["text"],
            texts: &["text"],
            ..form(kind)
        },
        K::SubmitRevision => CmdForm {
            params: PROPOSAL,
            required: &["plan"],
            ..form(kind)
        },
        K::Withdraw
        | K::AdmitToStage1
        | K::CloseStage1
        | K::DeclineAfterConcern
        | K::DeclineNegotiation => CmdForm {
            params: PROPOSAL,
            drawn: if matches!(kind, K::AdmitToStage1) {
                &["decision"]
            } else {
                &[]
            },
            ..form(kind)
        },
        K::RecordKnockOut => CmdForm {
            params: PROPOSAL,
            required: &["outcomes"],
            optional: &["reason"],
            drawn: &["decision"],
            texts: &["reason"],
            ..form(kind)
        },
        K::Assign => CmdForm {
            params: PROPOSAL,
            required: &["reviewer", "kind"],
            drawn: &["assignment"],
            derive: Derive::Handle,
            ..form(kind)
        },
        K::Unassign => CmdForm {
            params: ASSIGNMENT,
            ..form(kind)
        },
        K::RecordScore => CmdForm {
            params: &[("assignment", None)],
            required: &["stage", "plan", "values"],
            derive: Derive::ScoreKey,
            ..form(kind)
        },
        K::CorrectScore => CmdForm {
            params: &[("assignment", None), ("score", None)],
            required: &["stage", "values", "reason"],
            texts: &["reason"],
            derive: Derive::ScoreKey,
            ..form(kind)
        },
        K::RecordRankingSummary => CmdForm {
            params: ASSIGNMENT,
            required: &["title", "neutral_summary", "rationale"],
            texts: &["title", "neutral_summary", "rationale"],
            derive: Derive::ProposalOfAssignment,
            ..form(kind)
        },
        K::AskQuestion => CmdForm {
            params: ASSIGNMENT,
            required: &["text"],
            texts: &["text"],
            derive: Derive::ProposalOfAssignment,
            ..form(kind)
        },
        K::RecordNoQuestions => CmdForm {
            params: ASSIGNMENT,
            derive: Derive::ProposalOfAssignment,
            ..form(kind)
        },
        K::RankAfterStage2 => CmdForm {
            params: &[("assignment", None)],
            derive: Derive::ProposalOfAssignment,
            ..form(kind)
        },
        // Change D5: the record names its round only. The order, the
        // position, the rationale and the ballots are the round's own
        // (R-EV-08, R-EV-09).
        K::RecordCutOff => CmdForm {
            params: &[("round", Some("round"))],
            ..form(kind)
        },
        // Lane m4reg, change D5: the server draws the round id, and the
        // ballot and the delegation name no voter (R-EV-08, R-EV-09).
        K::OpenCutOffRound => CmdForm {
            params: CALL,
            required: &["order", "nominated", "rationale"],
            optional: &["tie_breaks"],
            drawn: &["round"],
            texts: &["rationale", "tie_breaks"],
            ..form(kind)
        },
        K::CastBallot => CmdForm {
            params: &[("round", Some("round"))],
            required: &["vote"],
            ..form(kind)
        },
        K::DelegateVote => CmdForm {
            params: &[("round", Some("round"))],
            required: &["to"],
            ..form(kind)
        },
        K::RecordIrcReview => CmdForm {
            params: &[("irc_assignment", Some("assignment"))],
            required: &["verdict"],
            // A concern's text is sent to the applicant (R-IR-02), so
            // the server stores it like every other free text.
            texts: &["verdict.concern"],
            ..form(kind)
        },
        K::DeclareConflict => CmdForm {
            required: &["conflicted", "notifiable"],
            ..form(kind)
        },
        _ => return None,
    };
    Some(f)
}

/// The form of a command operation, with the declaration subject set
/// from the route the operation is on.
pub(crate) fn op_form(spec: &OpSpec) -> Option<CmdForm> {
    let OpKind::Command(kind) = spec.kind else {
        return None;
    };
    let f = command_form(kind)?;
    if kind != CommandKind::DeclareConflict {
        return Some(f);
    }
    let params = route_param_names(spec);
    let derive = match params.first().copied() {
        Some("proposal") => Derive::SubjectProposal,
        Some("assignment") => Derive::SubjectAssignment("assignment"),
        Some("irc_assignment") => Derive::SubjectAssignment("irc_assignment"),
        _ => return None,
    };
    let params: &'static [(&'static str, Option<&'static str>)] = match derive {
        Derive::SubjectProposal => &[("proposal", None)],
        Derive::SubjectAssignment("irc_assignment") => &[("irc_assignment", None)],
        _ => &[("assignment", None)],
    };
    Some(CmdForm {
        params,
        derive,
        ..f
    })
}

/// The path parameter names of an operation's route, in order.
pub(crate) fn route_param_names(spec: &OpSpec) -> Vec<&'static str> {
    spec.route
        .map(|(_, path)| fstp_access::route_params(path).collect())
        .unwrap_or_default()
}

/// The body rule of an operation that is not a command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BodyRule {
    /// No body member.
    Empty,
    /// Exactly these members.
    Exactly(&'static [&'static str]),
    /// Any object. The operation waits for another lane and never runs,
    /// so its members are not judged here.
    Unjudged,
}

/// The body rule of a non-command operation.
fn body_rule(spec: &OpSpec) -> BodyRule {
    use fstp_access::{AgentKind, PortKind};
    match spec.kind {
        OpKind::Read(_) | OpKind::Public(_) => BodyRule::Empty,
        OpKind::Pending(PendingKind::Confirm) => BodyRule::Exactly(&["shown"]),
        OpKind::Pending(PendingKind::Discard) | OpKind::Agent(AgentKind::Revoke) => BodyRule::Empty,
        OpKind::M3Port(PortKind::ApproveBreakGlass) => BodyRule::Exactly(&["approve"]),
        OpKind::M3Port(PortKind::SaveWorkspace) => {
            BodyRule::Exactly(&["narrative", "summary", "title"])
        }
        OpKind::M3Port(PortKind::StateCountry) => BodyRule::Exactly(&["country"]),
        OpKind::M3Port(PortKind::AcknowledgeNegotiationNotice) => {
            BodyRule::Exactly(&["notice_version"])
        }
        OpKind::M3Port(
            PortKind::ApproveRecovery | PortKind::EndSession | PortKind::BeginVerification,
        ) => BodyRule::Empty,
        _ => BodyRule::Unjudged,
    }
}

/// The value at the dotted `path` of `o`.
fn at<'a>(o: &'a Object, path: &str) -> Option<&'a Value> {
    let mut parts = path.split('.');
    let mut v = o.get(parts.next()?)?;
    for p in parts {
        v = v.as_object()?.get(p)?;
    }
    Some(v)
}

/// A mutable reference to the value at the dotted `path` of `o`.
fn at_mut<'a>(o: &'a mut Object, path: &str) -> Option<&'a mut Value> {
    let mut parts = path.split('.');
    let mut v = o.get_mut(parts.next()?)?;
    for p in parts {
        v = v.as_object_mut()?.get_mut(p)?;
    }
    Some(v)
}

/// Checks a request object: the path parameters, then the body members.
/// The strict decoder of every operation (design section 3.7 step 1).
pub(crate) fn check(spec: &OpSpec, request: &Object) -> Result<(), ApiError> {
    let params = route_param_names(spec);
    for p in &params {
        match request.get(p) {
            Some(v) if param_ok(p, v) => {}
            _ => return Err(ApiError::bad_request(REQUEST_RULE)),
        }
    }
    let body = request.keys().filter(|k| !params.contains(k));
    if let Some(f) = op_form(spec) {
        return check_command(&f, request, body.collect());
    }
    if matches!(spec.kind, OpKind::Command(_)) {
        // A command kind with no form never runs, and is not judged.
        return Ok(());
    }
    if matches!(
        spec.kind,
        OpKind::Creator(_) | OpKind::Bridge(_) | OpKind::Import(_)
    ) {
        return crate::creator::check(spec, request, &params);
    }
    let members: Vec<&str> = body.collect();
    match body_rule(spec) {
        BodyRule::Empty if members.is_empty() => Ok(()),
        BodyRule::Exactly(want)
            if members.len() == want.len() && want.iter().all(|w| members.contains(w)) =>
        {
            check_plain_values(spec, request)
        }
        BodyRule::Unjudged => Ok(()),
        _ => Err(ApiError::bad_request(REQUEST_RULE)),
    }
}

/// The value checks of the non-command bodies.
fn check_plain_values(spec: &OpSpec, request: &Object) -> Result<(), ApiError> {
    let ok = match spec.kind {
        OpKind::Pending(PendingKind::Confirm) => request
            .get("shown")
            .and_then(Value::as_str)
            .and_then(crate::ActionDigest::from_hex)
            .is_some(),
        OpKind::M3Port(fstp_access::PortKind::ApproveBreakGlass) => {
            request.get("approve").and_then(Value::as_bool).is_some()
        }
        _ => true,
    };
    if ok {
        Ok(())
    } else {
        Err(ApiError::bad_request(REQUEST_RULE))
    }
}

/// Checks the body members of a command request.
fn check_command(f: &CmdForm, request: &Object, members: Vec<&str>) -> Result<(), ApiError> {
    let bad = || ApiError::bad_request(REQUEST_RULE);
    for m in &members {
        if !f.required.contains(m) && !f.optional.contains(m) {
            return Err(bad());
        }
    }
    if f.required.iter().any(|r| !members.contains(r)) {
        return Err(bad());
    }
    for path in f.texts {
        match at(request, path) {
            Some(Value::String(s)) if s.len() <= TEXT_LIMIT => {}
            Some(Value::Null) | None if is_optional(f, path) => {}
            None if in_other_variant(request, path) => {}
            _ => return Err(bad()),
        }
    }
    if let Some(v) = request.get("approval")
        && !v.is_null()
        && !param_ok("approval", v)
    {
        return Err(bad());
    }
    // A trial build judges the shape of every member through the command
    // codec: types, enum spellings and ADR-006 amount strings.
    let state = EngineState::genesis();
    let cx = BuildCtx {
        state: &state,
        now: Timestamp::from_micros(0),
        inference: None,
        second_admin: None,
        trial: true,
        plan_unknown: false,
    };
    let refs = texts(f, request)
        .into_iter()
        .map(|(p, s)| (p, text_ref(1, s)))
        .collect();
    build(f, request, &refs, &cx, &mut || Ok(1)).map(|_| ())
}

/// Whether the text at `path` is absent because its parent is a tagged
/// value of another variant, such as the `Validate` verdict of an IRC
/// review, which has no `concern`. The trial build then judges the
/// variant through the command codec.
fn in_other_variant(request: &Object, path: &str) -> bool {
    let Some((parent, _)) = path.rsplit_once('.') else {
        return false;
    };
    at(request, parent)
        .and_then(Value::as_object)
        .is_some_and(|o| o.get("type").and_then(Value::as_str).is_some())
}

/// Whether the text at `path` may be absent or `null`.
fn is_optional(f: &CmdForm, path: &str) -> bool {
    let first = path.split('.').next().unwrap_or(path);
    f.optional.contains(&first)
}

/// The free texts of a command request, by dotted path. Absent and
/// `null` optional texts are left out.
pub(crate) fn texts<'a>(f: &CmdForm, request: &'a Object) -> Vec<(&'static str, &'a str)> {
    f.texts
        .iter()
        .filter_map(|p| at(request, p).and_then(Value::as_str).map(|s| (*p, s)))
        .collect()
}

/// The content digest of a free text: SHA-256 of its UTF-8 bytes
/// (interim, pending Daniel).
pub(crate) fn text_digest(s: &str) -> ContentDigest {
    ContentDigest::from_bytes(fstp_crypto::sha256(s.as_bytes()))
}

/// A text reference with id `id` for `s`.
pub(crate) fn text_ref(id: u128, s: &str) -> TextRef {
    TextRef::new(TextId::from_raw(id), text_digest(s))
}

/// What [`build`] reads besides the request.
pub(crate) struct BuildCtx<'a> {
    /// The current snapshot.
    pub(crate) state: &'a EngineState,
    /// The call's instant.
    pub(crate) now: Timestamp,
    /// The tenant's inference record: configuration and model.
    pub(crate) inference: Option<(LlmConfigId, ModelRef)>,
    /// The approver of a recorded second-admin approval, if the request
    /// names one (SoD-07).
    pub(crate) second_admin: Option<AccountId>,
    /// A trial build at decode time: members the state or the cell
    /// supply get placeholder values, so only the request's shape is
    /// judged.
    pub(crate) trial: bool,
    /// Whether the API core's journal does not hold the plan history of
    /// the request's proposal (`journal.rs`), so a plan member it would
    /// have named is missing for that reason.
    pub(crate) plan_unknown: bool,
}

/// What the journal knows of a proposal's latest plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LatestPlan {
    /// The latest plan, or `None` when none was recorded.
    Known(Option<fstp_domain::id::PlanVersionId>),
    /// The journal does not hold the proposal's history.
    Unknown,
}

/// The refusal of a plan member the journal cannot name.
fn plan_unknown() -> ApiError {
    ApiError::NotImplemented(
        "the latest plan of a proposal recorded outside this API core: a domain read accessor (lane W1b)",
    )
}

/// Names the plan members the server supplies, in `request`, before the
/// action digest and any pending request are made (I-85, design section
/// 3.7 step 6). The digest, the pending view and a later confirmation
/// then all carry the same plan.
///
/// - A submission without `plan` names the latest plan.
/// - A page form plan (`description` and no `content`) without
///   `supersedes` names the latest plan, or `null` when none was
///   recorded.
///
/// A member the request names stays. An unknown history names nothing,
/// and [`build`] refuses the request.
pub(crate) fn name_plans(form: &CmdForm, request: &mut Object, latest: LatestPlan) {
    let LatestPlan::Known(latest) = latest else {
        return;
    };
    match form.derive {
        Derive::LatestPlan => {
            if let Some(p) = latest
                && request.get("plan").is_none_or(Value::is_null)
            {
                let _ = request.insert("plan", dec(p.raw()));
            }
        }
        Derive::PlanForm => {
            let page_form = request.contains_key("description") && !request.contains_key("content");
            if page_form && !request.contains_key("supersedes") {
                let v = latest.map_or(Value::Null, |p| dec(p.raw()));
                let _ = request.insert("supersedes", v);
            }
        }
        _ => {}
    }
}

/// A decimal string.
fn dec(x: u128) -> Value {
    Value::String(x.to_string())
}

/// The id at the request parameter `name`.
pub(crate) fn id_param(request: &Object, name: &str) -> Option<u128> {
    request
        .get(name)
        .and_then(Value::as_str)
        .and_then(canonical_id)
}

/// The proposal of assignment `a`.
pub(crate) fn proposal_of_assignment(state: &EngineState, a: AssignmentId) -> Option<ProposalId> {
    state.core.review().get(a).map(|x| x.proposal)
}

/// The call of proposal `p`: the call of its latest Receiving binding.
/// Interim: the domain has no public accessor for a proposal's current
/// call yet.
pub(crate) fn call_of_proposal(state: &EngineState, p: ProposalId) -> Option<CallId> {
    state
        .core
        .roster()
        .bindings()
        .filter_map(|(id, b)| match b.scope {
            BindingScope::Proposal { proposal, call } if proposal == p => Some((id, call)),
            _ => None,
        })
        .max_by_key(|(id, _)| *id)
        .map(|(_, call)| call)
}

/// The programme of the call `c`.
pub(crate) fn programme_of_call(state: &EngineState, c: CallId) -> Option<ProgrammeId> {
    state.core.calls().get(c).map(|v| v.programme())
}

/// The JSON of member `name` of a command, used to spell values whose
/// codec form is not a plain string.
fn member_json(cmd: &Core, name: &str) -> Option<Value> {
    cmd.to_json().as_object()?.get(name).cloned()
}

/// Builds the engine command of a checked request. `texts` holds the
/// text reference of each free text path. `draw` draws a fresh id.
pub(crate) fn build(
    f: &CmdForm,
    request: &Object,
    texts: &BTreeMap<&'static str, TextRef>,
    cx: &BuildCtx<'_>,
    draw: &mut dyn FnMut() -> Result<u128, ApiError>,
) -> Result<Command, ApiError> {
    let bad = || ApiError::bad_request(REQUEST_RULE);
    let not_found = || ApiError::refused(crate::ErrorCode::NotFound, "Input");
    let mut o = Object::new();
    let _ = o.insert("type", Value::from(kind_name(f.kind)));
    for (param, member) in f.params {
        if let Some(m) = member {
            let v = request.get(param).cloned().ok_or_else(bad)?;
            let _ = o.insert(*m, v);
        }
    }
    let params: Vec<&str> = f.params.iter().map(|(p, _)| *p).collect();
    for (k, v) in request.iter() {
        if params.contains(&k) || k == "approval" {
            continue;
        }
        let _ = o.insert(k, v.clone());
    }
    for m in f.optional {
        if *m != "approval" && !o.contains_key(m) {
            let _ = o.insert(*m, Value::Null);
        }
    }
    for (path, r) in texts {
        let slot = at_mut(&mut o, path).ok_or_else(bad)?;
        *slot = r.to_json_value();
    }
    for m in f.drawn {
        let _ = o.insert(*m, dec(draw()?));
    }
    match f.derive {
        Derive::None => {}
        Derive::ProposalOfAssignment => {
            let a = id_param(request, "assignment").ok_or_else(bad)?;
            let p = if cx.trial {
                ProposalId::from_raw(1)
            } else {
                proposal_of_assignment(cx.state, AssignmentId::from_raw(a)).ok_or_else(not_found)?
            };
            let _ = o.insert("proposal", dec(p.raw()));
        }
        Derive::SubjectProposal | Derive::SubjectAssignment(_) => {
            let subject = match f.derive {
                Derive::SubjectAssignment(param) => DeclarationSubject::Assignment(
                    AssignmentId::from_raw(id_param(request, param).ok_or_else(bad)?),
                ),
                _ => DeclarationSubject::Proposal(ProposalId::from_raw(
                    id_param(request, "proposal").ok_or_else(bad)?,
                )),
            };
            let dummy = Core::DeclareConflict {
                subject,
                conflicted: false,
                notifiable: false,
            };
            let _ = o.insert("subject", member_json(&dummy, "subject").ok_or_else(bad)?);
        }
        Derive::Inference => {
            let trial = (LlmConfigId::from_raw(1), ModelRef("trial".to_owned()));
            let (config, model) = match cx.inference.clone() {
                Some(i) => i,
                None if cx.trial => trial,
                None => return Err(ApiError::refused(crate::ErrorCode::Refused, "R-LA-05")),
            };
            let dummy = Core::PublishCall {
                call: CallId::from_raw(0),
                config,
                config_model: model,
            };
            let _ = o.insert("config", member_json(&dummy, "config").ok_or_else(bad)?);
            let _ = o.insert(
                "config_model",
                member_json(&dummy, "config_model").ok_or_else(bad)?,
            );
        }
        Derive::Minor => {
            let _ = o.insert("minor", Value::Bool(true));
        }
        Derive::ScoreKey => {
            let a = id_param(request, "assignment").ok_or_else(bad)?;
            let plan = match id_param(request, "score") {
                Some(p) => dec(p),
                None => o.remove("plan").ok_or_else(bad)?,
            };
            let stage = o.remove("stage").ok_or_else(bad)?;
            let mut key = Object::new();
            let _ = key.insert("assignment", dec(a));
            let _ = key.insert("stage", stage);
            let _ = key.insert("plan", plan);
            let _ = o.insert("key", Value::Object(key));
        }
        Derive::SecondAdmin => {
            let v = cx.second_admin.map_or(Value::Null, |a| dec(a.raw()));
            let _ = o.insert("second_admin", v);
        }
        Derive::EndAt => {
            if o.get("at").is_none_or(Value::is_null) {
                let _ = o.insert("at", Value::String(cx.now.micros().to_string()));
            }
        }
        Derive::Handle => {
            let p = id_param(request, "proposal").ok_or_else(bad)?;
            let anonymous = !cx.trial
                && call_of_proposal(cx.state, ProposalId::from_raw(p))
                    .and_then(|c| fstp_domain::policy::frozen_policy(&cx.state.core, c))
                    .is_some_and(|fp| fp.values().p11 == ReviewerAnonymity::Anonymous);
            let handle = if anonymous {
                let a = draw()?.to_be_bytes();
                Value::String(crate::action::hex(&a))
            } else {
                Value::Null
            };
            let _ = o.insert("handle", handle);
        }
        Derive::PlanForm => plan_form(&mut o, request, cx, draw)?,
        Derive::LatestPlan => {
            if o.get("plan").is_none_or(Value::is_null) {
                // Dispatch named the latest plan before the digest
                // (`name_plans`). Nothing is derived here.
                if !cx.trial {
                    if cx.plan_unknown {
                        return Err(plan_unknown());
                    }
                    // No plan was recorded, so there is nothing to submit.
                    return Err(ApiError::refused(crate::ErrorCode::Refused, "R-SB-01"));
                }
                let _ = o.insert("plan", dec(1));
            }
        }
    }
    let cmd = fstp_domain::codec::command_from_json(&Value::Object(o)).map_err(|_| bad())?;
    if cmd.kind() != f.kind {
        return Err(bad());
    }
    Ok(Command::Core(cmd))
}

/// The members of a `RecordPlanVersion` from its page form
/// (`pageforms.rs`), or a check of its codec form.
///
/// In the page form, `description` holds the stored text's reference, so
/// the plan's content digest is that text's digest. The origin is the
/// stage 2 revision in STAGE2 and the submission's otherwise. The
/// currency is the programme's, the plan supersedes the one dispatch
/// named ([`name_plans`]), and every milestone gets a drawn id, no
/// activity and no deliverable (activity types arrive with the
/// negotiated plan).
fn plan_form(
    o: &mut Object,
    request: &Object,
    cx: &BuildCtx<'_>,
    draw: &mut dyn FnMut() -> Result<u128, ApiError>,
) -> Result<(), ApiError> {
    let bad = || ApiError::bad_request(REQUEST_RULE);
    let description = o.remove("description");
    let Some(Value::Object(text)) = description else {
        // The codec form names every member itself.
        for m in ["origin", "content", "currency"] {
            if o.get(m).is_none_or(Value::is_null) {
                return Err(bad());
            }
        }
        return Ok(());
    };
    let digest = text.get("digest").cloned().ok_or_else(bad)?;
    let _ = o.insert("content", digest);
    // A plan of a proposal in STAGE2 is its stage 2 revision (R-EV-05).
    // Every other page plan is the plan of the submission, which the
    // domain admits in DRAFT only.
    let in_stage2 = !cx.trial
        && id_param(request, "proposal").is_some_and(|p| {
            fstp_domain::view::proposal_state(&cx.state.core, ProposalId::from_raw(p))
                == Some(fstp_domain::StateTag::Stage2)
        });
    let origin = if in_stage2 {
        "Stage2Revision"
    } else {
        "Submitted"
    };
    let _ = o.insert("origin", Value::from(origin));
    // Dispatch named the superseded plan before the digest
    // (`name_plans`). Nothing is derived here.
    if !o.contains_key("supersedes") {
        if !cx.trial && cx.plan_unknown {
            return Err(plan_unknown());
        }
        let _ = o.insert("supersedes", Value::Null);
    }
    let currency = if cx.trial {
        fstp_money::Currency::Eur
    } else {
        let p = id_param(request, "proposal").ok_or_else(bad)?;
        call_of_proposal(cx.state, ProposalId::from_raw(p))
            .and_then(|c| programme_of_call(cx.state, c))
            .and_then(|g| cx.state.core.policy().head(g))
            .map(|v| v.currency)
            .ok_or_else(|| ApiError::refused(crate::ErrorCode::NotFound, "Input"))?
    };
    let _ = o.insert("currency", Value::from(currency.code()));
    let tasks = o
        .get_mut("tasks")
        .and_then(Value::as_array_mut)
        .ok_or_else(bad)?;
    for t in tasks.iter_mut() {
        let milestones = t
            .as_object_mut()
            .and_then(|x| x.get_mut("milestones"))
            .and_then(Value::as_array_mut)
            .ok_or_else(bad)?;
        for m in milestones.iter_mut() {
            let m = m.as_object_mut().ok_or_else(bad)?;
            if !m.contains_key("id") {
                let _ = m.insert("id", dec(draw()?));
            }
            if !m.contains_key("activity") {
                let _ = m.insert("activity", Value::Null);
            }
            if !m.contains_key("deliverables") {
                let _ = m.insert("deliverables", Value::Array(fstp_json::Array::new()));
            }
        }
    }
    Ok(())
}

/// The JSON form of a text reference, as the command codec spells it.
trait TextRefJson {
    fn to_json_value(&self) -> Value;
}

impl TextRefJson for TextRef {
    fn to_json_value(&self) -> Value {
        let dummy = Core::AnswerQuestions {
            proposal: ProposalId::from_raw(0),
            text: *self,
        };
        member_json(&dummy, "text").unwrap_or(Value::Null)
    }
}

/// The codec name of a command kind: its variant name.
fn kind_name(kind: CommandKind) -> String {
    format!("{kind:?}")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    /// I-84: every routed command operation of the registry has a request
    /// form, so no routed command is undecodable.
    #[test]
    fn i84_every_routed_command_op_has_a_form() {
        for spec in fstp_access::OPS {
            if let OpKind::Command(kind) = spec.kind {
                assert!(op_form(spec).is_some(), "{} ({kind:?})", spec.name);
            }
        }
    }

    /// I-84: every form parameter is a parameter of its route.
    #[test]
    fn i84_form_parameters_are_route_parameters() {
        for spec in fstp_access::OPS {
            let Some(f) = op_form(spec) else {
                continue;
            };
            let route = route_param_names(spec);
            for (p, _) in f.params {
                assert!(route.contains(p), "{}: {p}", spec.name);
            }
            assert_eq!(f.params.len(), route.len(), "{}", spec.name);
        }
    }

    /// Design section 3.7 step 1, a support test: ids are canonical decimal
    /// strings.
    #[test]
    fn request_ids_are_canonical_decimals() {
        assert_eq!(canonical_id("0"), Some(0));
        assert_eq!(canonical_id("12"), Some(12));
        assert_eq!(canonical_id("012"), None);
        assert_eq!(canonical_id("-1"), None);
        assert_eq!(canonical_id(""), None);
        assert_eq!(canonical_id("1e3"), None);
        assert!(token("supersafe-2026"));
        assert!(!token("Upper"));
    }

    /// I-85, design section 3.7 step 6: a submission without a plan gets
    /// the latest plan before its digest, a named plan stays, and an
    /// unknown history names nothing, so the build refuses it.
    #[test]
    fn i85_name_plans_names_the_plan_before_the_digest() {
        let form = command_form(CommandKind::Submit).unwrap();
        let latest = LatestPlan::Known(Some(fstp_domain::id::PlanVersionId::from_raw(7)));
        let mut bare = Object::new();
        name_plans(&form, &mut bare, latest);
        assert_eq!(bare.get("plan"), Some(&Value::from("7")));
        let mut named = Object::new();
        let _ = named.insert("plan", Value::from("5"));
        name_plans(&form, &mut named, latest);
        assert_eq!(named.get("plan"), Some(&Value::from("5")));
        let mut unknown = Object::new();
        name_plans(&form, &mut unknown, LatestPlan::Unknown);
        assert_eq!(unknown.get("plan"), None);
    }

    /// R-EV-08, R-EV-09, change D5: the record of a cut-off names its
    /// round only, as the ballot and the delegation do. The order, the
    /// position, the rationale and the ballots are the round's own, so a
    /// request carrying any of them is refused.
    #[test]
    fn r_ev_08_record_cutoff_names_its_round_only() {
        let spec = fstp_access::op("committee.record_cutoff").unwrap();
        let mut request = Object::new();
        let _ = request.insert("round", Value::from("9"));
        assert_eq!(check(spec, &request), Ok(()));
        let form = op_form(spec).unwrap();
        let state = EngineState::genesis();
        let cx = BuildCtx {
            state: &state,
            now: Timestamp::from_micros(0),
            inference: None,
            second_admin: None,
            trial: false,
            plan_unknown: false,
        };
        let cmd = build(&form, &request, &BTreeMap::new(), &cx, &mut || Ok(1)).unwrap();
        assert_eq!(
            cmd,
            Command::Core(Core::RecordCutOff {
                round: fstp_domain::id::DecisionId::from_raw(9),
            })
        );
        let _ = request.insert("nominated", Value::Number(fstp_json::Number::from(1u32)));
        assert!(check(spec, &request).is_err());
    }
}
