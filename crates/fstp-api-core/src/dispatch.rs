//! The one dispatch (design section 3.7, I-84, I-85).
//!
//! [`run`] takes every call through the steps of design section 3.7, in
//! order:
//!
//! 0. **Principal.** A session cookie resolves through the M3 `Sessions`
//!    port and a bearer token through the token seam. A missing or
//!    invalid credential gives an anonymous principal, on the channel the
//!    call arrived through.
//! 1. **Decode.** The adapter decoded the request with the operation's
//!    strict form (`decode`). Free text is stored only once the call is
//!    about to execute, so a refused call stores no text.
//! 2. **Session strength** (I-77).
//! 3. **Channel.** `channel_policy`, with the governing P-77 read from the
//!    domain's own rule.
//! 4. **Rate limits** per session, account, token and client.
//! 5. **Dry run** with web semantics. Every vault answer it obtains is
//!    recorded through `VaultAudit` as a query digest and the answer bit,
//!    and the call fails closed if recording fails (`overview.md` NOTE 5).
//!    Dry runs that ask the vault have their own limit per account (H-07).
//! 6. **Prepare** a pending action for `ChannelVerdict::Prepare`.
//! 7. **Step-up** for high-risk operations through the web: a proof for
//!    this digest, younger than P-71, consumed.
//! 8. **Execute.** The domain re-runs every guard, and refuses `Via::Mcp`
//!    for high-risk and draft-only binding commands as a second line.
//! 9. **Audit.** One entry per call. An appended command's entry commits
//!    with the append, inside the engine port. Every other call's entry is
//!    recorded here, on both channels alike (I-84). A refusal before the
//!    caller resolves is recorded with no actor. A failed write of an
//!    accepted entry refuses the call, and that refusal is recorded.
//!
//! # Seams the lead closes in `port.rs`
//!
//! [`Seams`] names what dispatch needs and the W0 ports do not offer yet.
//! `port.rs` implements it for every `CellPorts` and calls [`run`] from
//! its `Core<P>`, with a [`State`] beside the ports. Until then `Core<P>`
//! refuses every call, so nothing here is reachable. The seams:
//!
//! - a token port: bearer token to grant facts, and revocation (ADR-013 is
//!   a draft, so the port is interim);
//! - a dry run that returns the vault answers it obtained;
//! - the tenant settings: P-74, the inference record and the tenant id;
//! - an audit entry outside an engine transaction;
//! - the ids of the calls in the state, until the domain's `CallState`
//!   offers an iterator.
//!
//! Interim readings, pending Daniel (design section 15.0):
//!
//! - The governing P-77 of a binding command through MCP is the one the
//!   domain applies: its `Via::Mcp` check refuses with P-77 exactly when
//!   the governing value is "draft only".
//! - A call with no account is refused with `Unauthenticated` before any
//!   dry run.
//! - An M3 port operation acting as tenant admin needs the attested admin
//!   set.
//! - A confirmation checks the account, the status and expiry, the shown
//!   digest, the session strength of the stored operation and a fresh dry
//!   run, in that order, before it consumes a step-up proof. It claims the
//!   action before its first await.
//! - A bearer token that resolves to no grant is anonymous and keeps no
//!   rate counter of its own. The public rate-limit key of Q19 will limit
//!   such calls once it exists.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::sync::{Mutex, MutexGuard, PoisonError};

use fstp_access::{
    AgentKind, ChannelDenial, ChannelVerdict, DenyRule, GrantFacts, McpSettings, OpKind, OpSpec,
    PendingKind, PortKind, Principal, ReadKind, ReadOp, ReadTarget, RoleOrApplicant, SessionFacts,
};
use fstp_domain::command::{Actor, Ctx, Via};
use fstp_domain::id::{
    AccountId, AssignmentId, CallId, CommandId, LlmConfigId, ProgrammeId, ProposalId, TextRef,
};
use fstp_domain::oracle::Answer;
use fstp_domain::policy::{McpBindingActions, ModelRef};
use fstp_domain::refusal::{Refusal, RuleRef};
use fstp_domain::roles::{BindingScope, Role};
use fstp_domain::time::Timestamp;
use fstp_engine::{Command, EngineState};
use fstp_json::{Object, Value};

use crate::decode::{decode_pending_request, pending_request_text};
use crate::forms::{self, BuildCtx, CmdForm};
use crate::model::{AssignmentSummary, CallSummary, ProposalSummary, SessionSummary};
use crate::pending::{
    InsertError, PENDING_LIFETIME_MICROS, PendingAction, PendingReceipt, PendingStatus,
    PendingStore, confirm_path,
};
use crate::port::{
    AgentClientId, AsyncEngine, AuditEntry, BreakGlass, BreakGlassId, CellPorts, Clock, ExecError,
    ExecMeta, Ids, LoginMethod, OpName, Outcome, PendingId, PortError, QueryDigest, Recovery,
    RecoveryId, SessionId, Sessions, SessionsAdmin, StepUp, StepUpRef, TenantConfig, TextClass,
    TextOwner, TextStore, Vault, VaultAudit, VerificationPurpose,
};
use crate::rate::{self, Key, Rates};
use crate::{ActionDigest, ApiError, Credential, ErrorCode, Op, OpResult, ReadModel, RequestHead};

/// What dispatch needs beside the W0 ports. `port.rs` implements it for
/// every `CellPorts` once the lead closes the seams (module
/// documentation).
#[allow(
    dead_code,
    reason = "port.rs implements and calls it once the lead closes the seams"
)]
pub(crate) trait Seams: CellPorts {
    /// The grant of a valid bearer token at `now`: the account, the agent
    /// client, the scopes and the consenting session's method.
    fn grant(
        &self,
        token: &[u8],
        now: Timestamp,
    ) -> impl Future<Output = Result<GrantFacts, PortError>> + Send;
    /// Revokes every token of `client` for `account` at once (R-MC-03).
    fn revoke_agent(
        &self,
        account: AccountId,
        client: AgentClientId,
    ) -> impl Future<Output = Result<(), PortError>> + Send;
    /// A dry run that returns its result and every vault answer it
    /// obtained, in order, whether it was refused or not.
    fn dry_run_answers(
        &self,
        cmd: &Command,
        ctx: Ctx,
    ) -> impl Future<Output = (Result<(), Refusal>, Vec<Answer>)> + Send;
    /// The tenant's MCP settings (P-74).
    fn mcp_settings(&self) -> McpSettings;
    /// The tenant's inference record: configuration and model (design
    /// section 3.5). `None` before onboarding records one.
    fn inference(&self) -> Option<(LlmConfigId, ModelRef)>;
    /// The tenant id, bound into every action digest.
    fn tenant_id(&self) -> Option<u128>;
    /// Records one audit entry of a call that appends nothing (I-24).
    fn record_audit(&self, e: AuditEntry) -> Result<(), PortError>;
    /// The ids of every call in `state`.
    fn call_ids(&self, state: &EngineState) -> Vec<CallId>;
}

/// The state of one API core beside its ports: the pending actions and
/// the rate-limit counters, in memory only.
#[derive(Debug, Default)]
#[allow(
    dead_code,
    reason = "port.rs holds it beside the ports once the lead closes the seams"
)]
pub(crate) struct State {
    pending: Mutex<PendingStore>,
    rates: Mutex<Rates>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The caller of one call.
struct Caller {
    /// The principal.
    p: Principal,
    /// The M3 session, for a web caller.
    session: Option<SessionId>,
    /// The agent client, for an MCP caller.
    agent: Option<AgentClientId>,
    /// The SHA-256 of a bearer token that resolved to a grant, for the
    /// per-token limit.
    token: Option<[u8; 32]>,
}

impl Caller {
    fn via(&self) -> Via {
        self.p.via()
    }
}

/// The rule text of a domain refusal. Non-spec rules get a fixed name.
pub(crate) fn rule_text(r: RuleRef) -> &'static str {
    match r.spec_id() {
        Some(id) => id,
        None => match r {
            RuleRef::Actor => "actor",
            RuleRef::Input => "Input",
            RuleRef::OracleDown => "oracle",
            RuleRef::StaleFacts => "stale_facts",
            RuleRef::Ledger => "ledger",
            RuleRef::FactsIncomplete => "facts_incomplete",
            RuleRef::Row => "row",
            _ => "refused",
        },
    }
}

/// The API error of a domain refusal.
fn refusal(r: Refusal) -> ApiError {
    match r.rule {
        RuleRef::OracleDown => ApiError::refused(ErrorCode::Unavailable, "oracle"),
        RuleRef::Actor => ApiError::refused(ErrorCode::Unauthenticated, "actor"),
        rule => ApiError::refused(ErrorCode::Refused, rule_text(rule)),
    }
}

/// The API error of a port failure.
fn port_failed(e: PortError, rule: &'static str) -> ApiError {
    match e {
        PortError::Unavailable => ApiError::refused(ErrorCode::Unavailable, rule),
        PortError::Refused => ApiError::refused(ErrorCode::Refused, rule),
    }
}

/// The access crate's login method of an M3 method.
const fn access_method(m: LoginMethod) -> fstp_access::LoginMethod {
    match m {
        LoginMethod::Passkey => fstp_access::LoginMethod::Passkey,
        LoginMethod::MagicLink => fstp_access::LoginMethod::MagicLink,
        LoginMethod::Opaque => fstp_access::LoginMethod::Opaque,
        LoginMethod::EudiWallet => fstp_access::LoginMethod::EudiWallet,
    }
}

/// The attested tenant admin set, as far as it concerns `account`.
fn admins_of<P: CellPorts>(ports: &P, account: AccountId) -> BTreeSet<AccountId> {
    let mut set = BTreeSet::new();
    if ports.tenant().is_tenant_admin(account) {
        set.insert(account);
    }
    set
}

/// Step 0: the principal of the credential.
async fn resolve<P: Seams>(
    ports: &P,
    cred: &Credential,
    head: &RequestHead,
    op: &Op,
    state: &EngineState,
    now: Timestamp,
) -> Result<Caller, ApiError> {
    let anonymous = |tool: bool| Caller {
        p: if tool {
            Principal::anonymous_mcp()
        } else {
            Principal::anonymous()
        },
        session: None,
        agent: None,
        token: None,
    };
    match cred {
        Credential::None => Ok(anonymous(op.from_tool)),
        Credential::SessionCookie(_) => {
            if op.from_tool {
                // A tool call carries a bearer token, never a cookie.
                return Err(ApiError::bad_request("ADR-014"));
            }
            match ports.sessions().principal(head, cred, now).await {
                Ok(s) => {
                    let facts = SessionFacts {
                        account: s.account,
                        session: fstp_access::SessionId::from_raw(s.session.raw()),
                        method: access_method(s.method),
                    };
                    let p = Principal::web(&facts, &admins_of(ports, s.account), state, now);
                    Ok(Caller {
                        p,
                        session: Some(s.session),
                        agent: None,
                        token: None,
                    })
                }
                Err(PortError::Unavailable) => {
                    Err(ApiError::refused(ErrorCode::Unavailable, "session"))
                }
                Err(PortError::Refused) => Ok(anonymous(false)),
            }
        }
        // A token with no grant is anonymous and keeps no counter of its
        // own, so fresh random tokens allocate nothing (design section 3.7
        // step 4). Its calls are limited as anonymous calls are.
        Credential::Bearer(token) => match ports.grant(token, now).await {
            Ok(g) => match Principal::mcp(&g, &admins_of(ports, g.account), state, now) {
                Ok(p) => Ok(Caller {
                    p,
                    session: None,
                    agent: Some(AgentClientId::from_raw(g.agent.raw())),
                    token: Some(fstp_crypto::sha256(token)),
                }),
                Err(_) => Ok(anonymous(true)),
            },
            Err(PortError::Unavailable) => Err(ApiError::refused(ErrorCode::Unavailable, "token")),
            Err(PortError::Refused) => Ok(anonymous(true)),
        },
    }
}

/// The target object of a request: its path parameters.
fn target(spec: &OpSpec, request: &Object) -> Object {
    let mut t = Object::new();
    for p in forms::route_param_names(spec) {
        if let Some(v) = request.get(p) {
            let _ = t.insert(p, v.clone());
        }
    }
    t
}

/// One call in flight: the ports, the state, the caller and the digest.
struct Call<'a, P: Seams> {
    ports: &'a P,
    st: &'a State,
    caller: Caller,
    spec: &'static OpSpec,
    digest: ActionDigest,
    now: Timestamp,
    state: std::sync::Arc<EngineState>,
}

impl<P: Seams> Call<'_, P> {
    fn account(&self) -> Option<AccountId> {
        self.caller.p.account()
    }

    /// Records the audit entry of a call that appends nothing.
    fn audit(&self, outcome: Outcome, step_up: Option<StepUpRef>) -> Result<(), PortError> {
        self.ports.record_audit(AuditEntry {
            actor: self.account(),
            via: self.caller.via(),
            agent: self.caller.agent,
            op: OpName(self.spec.name),
            outcome,
            request: self.digest,
            step_up,
        })
    }

    /// Audits a refusal and returns it. A failed audit write does not
    /// change the refusal.
    fn refuse(&self, e: ApiError) -> ApiError {
        let _ = self.audit(Outcome::Refused(refused_rule(&e)), None);
        e
    }

    /// Audits an accepted call that appended nothing, failing closed. A
    /// failed write is refused, and the refusal is audited in its place.
    fn accept(&self, body: ReadModel) -> Result<OpResult, ApiError> {
        self.accepted(None)?;
        Ok(OpResult::Done { body, seq: None })
    }

    /// Writes the accepted entry of a call that appended nothing. A
    /// failed write becomes an audited I-24 refusal.
    fn accepted(&self, step_up: Option<StepUpRef>) -> Result<(), ApiError> {
        self.audit(Outcome::Accepted, step_up)
            .map_err(|e| self.refuse(port_failed(e, "I-24")))
    }

    /// Draws a fresh id.
    fn draw(&self) -> Result<u128, ApiError> {
        self.ports.ids().fresh().map_err(|e| port_failed(e, "ids"))
    }

    /// The context of a command by the caller through `via`.
    fn ctx(&self, account: AccountId, cmd: &Command, via: Via, command: CommandId) -> Ctx {
        Ctx {
            now: self.now,
            actor: Actor::Account(account),
            command,
            via,
            tenant_admin: self.caller.p.tenant_admin(),
            second_tenant_admin: None,
            binds_tenant_admin: binds_admin(self.ports, account, cmd),
        }
    }
}

/// The rule an audit entry names for a refusal.
fn refused_rule(e: &ApiError) -> &'static str {
    match e {
        ApiError::Refused { rule, .. } => rule,
        ApiError::NotImplemented(_) => "not_implemented",
    }
}

/// The request digest of a call whose request has no canonical form,
/// which a decoded request always has. It names no request content.
fn uncanonical_digest() -> ActionDigest {
    ActionDigest(fstp_crypto::sha256(
        b"fstp-api-core: a request with no canonical form",
    ))
}

/// Audits a refusal raised before the call has its caller and digest
/// (design section 3.7 step 9: one entry per call, accepted or refused).
/// A failed audit write does not change the refusal.
fn refuse_early<P: Seams>(
    ports: &P,
    spec: &OpSpec,
    via: Via,
    caller: Option<&Caller>,
    request: ActionDigest,
    e: ApiError,
) -> ApiError {
    let _ = ports.record_audit(AuditEntry {
        actor: caller.and_then(|c| c.p.account()),
        via,
        agent: caller.and_then(|c| c.agent),
        op: OpName(spec.name),
        outcome: Outcome::Refused(refused_rule(&e)),
        request,
        step_up: None,
    });
    e
}

/// Whether the account `cmd` binds is a tenant admin (design section
/// 3.7: from the attested admin set only).
fn binds_admin<P: CellPorts>(ports: &P, actor: AccountId, cmd: &Command) -> bool {
    use fstp_domain::command::Command as Core;
    let bound = match cmd {
        Command::Core(
            Core::GrantRole { account, .. }
            | Core::AddTeamMember { account, .. }
            | Core::AddGuardian { account, .. },
        ) => *account,
        Command::Core(Core::CreateDraft { .. }) => actor,
        _ => return false,
    };
    ports.tenant().is_tenant_admin(bound)
}

/// Runs one call through every step of design section 3.7.
#[allow(dead_code, reason = "port.rs calls it once the lead closes the seams")]
pub(crate) async fn run<P: Seams>(
    ports: &P,
    st: &State,
    cred: Credential,
    head: &RequestHead,
    op: Op,
) -> Result<OpResult, ApiError> {
    let now = ports.clock().now();
    let state = ports.engine().snapshot();
    let spec = op.spec;
    let digest_for = |account: Option<AccountId>| {
        crate::action::digest(
            spec.name,
            &op.request,
            &target(spec, &op.request),
            ports.tenant_id(),
            account,
        )
    };
    // Step 0. A refusal here is audited with no actor, on the channel the
    // call arrived through.
    let caller = match resolve(ports, &cred, head, &op, &state, now).await {
        Ok(c) => c,
        Err(e) => {
            let via = if op.from_tool { Via::Mcp } else { Via::Web };
            let request = digest_for(None).unwrap_or_else(uncanonical_digest);
            return Err(refuse_early(ports, spec, via, None, request, e));
        }
    };
    let Some(digest) = digest_for(caller.p.account()) else {
        let e = ApiError::bad_request(forms::REQUEST_RULE);
        let request = uncanonical_digest();
        return Err(refuse_early(
            ports,
            spec,
            caller.via(),
            Some(&caller),
            request,
            e,
        ));
    };
    let call = Call {
        ports,
        st,
        caller,
        spec,
        digest,
        now,
        state,
    };
    // Step 2.
    if !fstp_access::session_admits(spec, &call.caller.p) {
        return Err(call.refuse(ApiError::refused(ErrorCode::LoginStrength, "I-77")));
    }
    // Step 3, with the strictest P-77 first: only `Prepare` depends on it.
    let settings = ports.mcp_settings();
    let verdict = fstp_access::channel_policy(
        spec,
        &call.caller.p,
        McpBindingActions::DraftOnly,
        &settings,
    );
    let verdict = match verdict {
        ChannelVerdict::Deny(d) => return Err(call.refuse(denial(d))),
        ChannelVerdict::Prepare if needs_p77(spec) => {
            let p77 = governing_p77(&call, &op).map_err(|e| call.refuse(e))?;
            fstp_access::channel_policy(spec, &call.caller.p, p77, &settings)
        }
        v => v,
    };
    let verdict = match verdict {
        ChannelVerdict::Deny(d) => return Err(call.refuse(denial(d))),
        // Only a command is prepared (step 6). Any other kind answered
        // with `Prepare` is refused here, so no later arm can run it
        // directly through MCP (I-85).
        ChannelVerdict::Prepare if !matches!(spec.kind, OpKind::Command(_)) => {
            return Err(call.refuse(ApiError::NotImplemented(
                "a prepared operation that is not a command (I-85)",
            )));
        }
        v => v,
    };
    // Step 4.
    rate_limits(&call)?;
    match spec.kind {
        OpKind::Command(_) => command(&call, &op, verdict).await,
        OpKind::Read(kind) => read(&call, &op, kind).await,
        OpKind::Pending(PendingKind::Confirm) => confirm(&call, &op).await,
        OpKind::Pending(PendingKind::Discard) => discard(&call, &op),
        OpKind::Agent(kind) => agent(&call, &op, kind).await,
        OpKind::M3Port(kind) => m3_port(&call, &op, kind).await,
        OpKind::Creator(_) => Err(call.refuse(ApiError::NotImplemented(
            "creator operations: the engine's creator envelope (lanes W2a, W2e)",
        ))),
        OpKind::Bridge(_) | OpKind::Import(_) => Err(call.refuse(ApiError::NotImplemented(
            "import operations: the engine bridge (lane W2b)",
        ))),
        OpKind::Tenant(_) => Err(call.refuse(ApiError::NotImplemented(
            "tenant operations: the engine's tenant envelope (lanes W2d, W2e)",
        ))),
        OpKind::Finding(_) => Err(call.refuse(ApiError::NotImplemented(
            "finding marks: the finding request form (lane W3b, after M4 W5)",
        ))),
        OpKind::Public(_) => Err(call.refuse(ApiError::NotImplemented(
            "public tools: fstp-public (lane W2c)",
        ))),
    }
}

/// The refusal of a channel denial.
fn denial(d: ChannelDenial) -> ApiError {
    let code = match d {
        ChannelDenial::NotExposed => ErrorCode::NotExposed,
        ChannelDenial::Scope => ErrorCode::Scope,
        ChannelDenial::P74 => ErrorCode::P74,
    };
    ApiError::refused(code, d.spec_id())
}

/// Whether a `Prepare` verdict may depend on P-77: a binding command that
/// is not high-risk and has no prepare-only tool.
fn needs_p77(spec: &OpSpec) -> bool {
    spec.binding
        && !spec.high_risk
        && !spec.tool.is_some_and(|t| t.prepare_only)
        && matches!(spec.kind, OpKind::Command(_))
}

/// The governing P-77 of a binding command: "draft only" exactly when the
/// domain's own `Via::Mcp` check refuses it with P-77 (R-MC-05).
fn governing_p77<P: Seams>(call: &Call<'_, P>, op: &Op) -> Result<McpBindingActions, ApiError> {
    let (Some(form), Some(account)) = (forms::op_form(call.spec), call.account()) else {
        return Ok(McpBindingActions::DraftOnly);
    };
    let cmd = build(call, &form, op, &BTreeMap::new(), &mut Vec::new())?;
    let Command::Core(core) = &cmd else {
        return Ok(McpBindingActions::DraftOnly);
    };
    let ctx = call.ctx(account, &cmd, Via::Mcp, CommandId::from_bytes([0; 16]));
    match fstp_domain::queries(&call.state.core, core, &ctx) {
        Err(r) if r.rule == RuleRef::Param(fstp_domain::rules::ParamId::P77) => {
            Ok(McpBindingActions::DraftOnly)
        }
        _ => Ok(McpBindingActions::Allowed),
    }
}

/// Step 4: the limits per session, account, token and client.
fn rate_limits<P: Seams>(call: &Call<'_, P>) -> Result<(), ApiError> {
    let mut keys = Vec::new();
    if let Some(a) = call.account() {
        keys.push((Key::Account(a), rate::PER_ACCOUNT));
    }
    if let Some(s) = call.caller.session {
        keys.push((Key::Session(s), rate::PER_SESSION));
    }
    if let Some(t) = call.caller.token {
        keys.push((Key::Token(t), rate::PER_TOKEN));
    }
    if let Some(c) = call.caller.agent {
        keys.push((Key::Client(c), rate::PER_CLIENT));
    }
    if lock(&call.st.rates).take_all(&keys, call.now) {
        Ok(())
    } else {
        Err(call.refuse(ApiError::refused(ErrorCode::RateLimited, "rate")))
    }
}

/// The context of a build.
fn build_ctx<'a, P: Seams>(call: &'a Call<'_, P>, second_admin: Option<AccountId>) -> BuildCtx<'a> {
    BuildCtx {
        state: &call.state,
        now: call.now,
        inference: call.ports.inference(),
        second_admin,
        trial: false,
    }
}

/// Builds the command of `op`. `texts` holds stored text references; a
/// text missing from it gets a placeholder reference with id 0 and the
/// text's digest, which no guard reads. `ids` replays the ids an earlier
/// build drew, and records each new draw.
fn build<P: Seams>(
    call: &Call<'_, P>,
    form: &CmdForm,
    op: &Op,
    texts: &BTreeMap<&'static str, TextRef>,
    ids: &mut Vec<u128>,
) -> Result<Command, ApiError> {
    let mut refs = texts.clone();
    for (path, s) in forms::texts(form, &op.request) {
        refs.entry(path).or_insert_with(|| forms::text_ref(0, s));
    }
    let mut next = 0usize;
    let mut draw = || -> Result<u128, ApiError> {
        let id = match ids.get(next) {
            Some(id) => *id,
            None => {
                let id = call.draw()?;
                ids.push(id);
                id
            }
        };
        next = next.saturating_add(1);
        Ok(id)
    };
    let cx = build_ctx(call, None);
    forms::build(form, &op.request, &refs, &cx, &mut draw)
}

/// Stores the free texts of `op` and returns their references.
async fn store_texts<P: Seams>(
    call: &Call<'_, P>,
    form: &CmdForm,
    op: &Op,
) -> Result<BTreeMap<&'static str, TextRef>, ApiError> {
    let mut out = BTreeMap::new();
    let texts = forms::texts(form, &op.request);
    if texts.is_empty() {
        return Ok(out);
    }
    let owner = text_owner(&call.state, &op.request)
        .ok_or(ApiError::refused(ErrorCode::NotFound, "Input"))?;
    let class = match form.kind {
        fstp_domain::command::CommandKind::DraftCall
        | fstp_domain::command::CommandKind::EditCall => TextClass::Public,
        _ => TextClass::Confidential,
    };
    for (path, s) in texts {
        let r = call
            .ports
            .texts()
            .put(class, owner, s.as_bytes())
            .await
            .map_err(|e| port_failed(e, "text"))?;
        out.insert(path, forms::text_ref(r.0, s));
    }
    Ok(out)
}

/// The owner of a request's texts: its proposal, or the programme of its
/// call or binding.
fn text_owner(state: &EngineState, request: &Object) -> Option<TextOwner> {
    if let Some(p) = forms::id_param(request, "proposal") {
        return Some(TextOwner::Proposal(ProposalId::from_raw(p)));
    }
    for name in ["assignment", "irc_assignment"] {
        if let Some(a) = forms::id_param(request, name) {
            return forms::proposal_of_assignment(state, AssignmentId::from_raw(a))
                .map(TextOwner::Proposal);
        }
    }
    if let Some(p) = forms::id_param(request, "programme") {
        return Some(TextOwner::Programme(ProgrammeId::from_raw(p)));
    }
    for name in ["call", "round"] {
        if let Some(c) = forms::id_param(request, name) {
            return forms::programme_of_call(state, CallId::from_raw(c)).map(TextOwner::Programme);
        }
    }
    None
}

/// Checks the path parameters that fill no command member against the
/// target: a binding's programme must be the route's programme.
fn check_target(state: &EngineState, request: &Object) -> bool {
    match (
        forms::id_param(request, "programme"),
        forms::id_param(request, "binding"),
    ) {
        (Some(p), Some(b)) => state
            .core
            .roster()
            .held_or_ended(fstp_domain::id::BindingId::from_raw(b))
            .is_some_and(|x| x.programme.raw() == p),
        _ => true,
    }
}

/// The second tenant admin of the request's recorded approval, if any
/// (SoD-07).
async fn second_admin<P: Seams>(
    call: &Call<'_, P>,
    request: &Object,
) -> Result<Option<AccountId>, ApiError> {
    let Some(id) = forms::id_param(request, "approval") else {
        return Ok(None);
    };
    let a = call
        .ports
        .tenant()
        .approval(crate::port::ApprovalId::from_raw(id))
        .await
        .map_err(|e| port_failed(e, "SoD-07"))?;
    if !call.ports.tenant().is_tenant_admin(a.approver) {
        return Err(ApiError::refused(ErrorCode::Refused, "SoD-07"));
    }
    Ok(Some(a.approver))
}

/// Step 5: the dry run with web semantics, its vault answers recorded.
async fn dry_run<P: Seams>(
    call: &Call<'_, P>,
    account: AccountId,
    cmd: &Command,
    ctx: Ctx,
) -> Result<(), ApiError> {
    let limit = rate::DRY_RUN_VAULT_PER_ACCOUNT;
    let web = Ctx {
        via: Via::Web,
        ..ctx
    };
    // H-07 limits the dry runs that ask the vault. A core command whose
    // questions are known to be none is not limited. Any other command,
    // and one whose questions are refused, is checked: fail closed.
    let asks_vault = match cmd {
        Command::Core(core) => !matches!(
            fstp_domain::queries(&call.state.core, core, &web),
            Ok(q) if q.is_empty()
        ),
        _ => true,
    };
    if asks_vault && !lock(&call.st.rates).admits(&Key::VaultDryRun(account), limit, call.now) {
        return Err(ApiError::refused(ErrorCode::RateLimited, "H-07"));
    }
    let (result, answers) = call.ports.dry_run_answers(cmd, web).await;
    if !answers.is_empty() {
        lock(&call.st.rates).hit(Key::VaultDryRun(account), limit, call.now);
    }
    for a in &answers {
        call.ports
            .vault_audit()
            .record(QueryDigest(a.digest.bytes()), a.holds, a.epoch)
            .await
            .map_err(|e| port_failed(e, "NOTE 5"))?;
    }
    result.map_err(refusal)
}

/// Step 7: a fresh proof for this digest in this session, consumed. Its
/// absence asks for a step-up bound to the digest.
async fn step_up<P: Seams>(
    call: &Call<'_, P>,
    digest: ActionDigest,
) -> Result<Result<StepUpRef, OpResult>, ApiError> {
    let Some(session) = call.caller.session else {
        return Err(ApiError::refused(ErrorCode::LoginStrength, "I-78"));
    };
    match call.ports.step_up().take(session, digest, call.now).await {
        Ok(proof) if proof.action == digest => Ok(Ok(proof.step_up)),
        Ok(_) => Err(ApiError::refused(ErrorCode::Refused, "I-78")),
        Err(_) => match call.ports.step_up().begin(session, digest).await {
            Ok(ch) => Ok(Err(OpResult::StepUpRequired(ch))),
            Err(PortError::Refused) => Ok(Err(OpResult::StrongMethodRequired)),
            Err(e) => Err(port_failed(e, "I-78")),
        },
    }
}

/// The API error of an execution failure.
fn exec_failed(e: ExecError) -> ApiError {
    match e {
        ExecError::Refused(r) => refusal(r),
        ExecError::Port(PortError::Unavailable) => {
            ApiError::refused(ErrorCode::Unavailable, "ledger")
        }
        ExecError::Port(PortError::Refused) => ApiError::refused(ErrorCode::Refused, "ledger"),
    }
}

/// A command operation: steps 5 to 9.
async fn command<P: Seams>(
    call: &Call<'_, P>,
    op: &Op,
    verdict: ChannelVerdict,
) -> Result<OpResult, ApiError> {
    let Some(account) = call.account() else {
        return Err(call.refuse(ApiError::refused(ErrorCode::Unauthenticated, "actor")));
    };
    let Some(form) = forms::op_form(call.spec) else {
        return Err(call.refuse(ApiError::NotImplemented(
            "a command operation with no request form",
        )));
    };
    if !check_target(&call.state, &op.request) {
        return Err(call.refuse(ApiError::refused(ErrorCode::NotFound, "Input")));
    }
    let second = second_admin(call, &op.request)
        .await
        .map_err(|e| call.refuse(e))?;
    let mut ids = Vec::new();
    let cmd = build(call, &form, op, &BTreeMap::new(), &mut ids).map_err(|e| call.refuse(e))?;
    let command_id = CommandId::from_bytes(call.draw().map_err(|e| call.refuse(e))?.to_be_bytes());
    let ctx = Ctx {
        second_tenant_admin: second,
        ..call.ctx(account, &cmd, call.caller.via(), command_id)
    };
    // Step 5.
    dry_run(call, account, &cmd, ctx)
        .await
        .map_err(|e| call.refuse(e))?;
    // Step 6.
    if verdict == ChannelVerdict::Prepare {
        return prepare(call, op, account);
    }
    // Step 7.
    let proof = if call.spec.high_risk && call.caller.via() == Via::Web {
        match step_up(call, call.digest)
            .await
            .map_err(|e| call.refuse(e))?
        {
            Ok(p) => Some(p),
            Err(ask) => {
                let _ = call.audit(Outcome::Refused("I-78"), None);
                return Ok(ask);
            }
        }
    } else {
        None
    };
    // Step 8.
    let texts = store_texts(call, &form, op)
        .await
        .map_err(|e| call.refuse(e))?;
    let cmd = build(call, &form, op, &texts, &mut ids).map_err(|e| call.refuse(e))?;
    let meta = ExecMeta {
        via: call.caller.via(),
        session: call.caller.session,
        agent: call.caller.agent,
        op: OpName(call.spec.name),
        request: call.digest,
        step_up: proof,
        pending: None,
        second_tenant_admin: second,
    };
    match call.ports.engine().execute(cmd, ctx, meta).await {
        Ok(seq) => Ok(OpResult::Done {
            body: ReadModel::Accepted,
            seq: Some(seq),
        }),
        Err(e) => Err(call.refuse(exec_failed(e))),
    }
}

/// Step 6: stores a pending action for a web confirmation (I-85).
fn prepare<P: Seams>(
    call: &Call<'_, P>,
    op: &Op,
    account: AccountId,
) -> Result<OpResult, ApiError> {
    let Some(agent) = call.caller.agent else {
        return Err(call.refuse(ApiError::refused(ErrorCode::NotExposed, "I-85")));
    };
    let (Some(request), Ok(shown)) = (
        pending_request_text(op),
        fstp_json::to_canonical(&Value::Object(op.request.clone())),
    ) else {
        return Err(call.refuse(ApiError::bad_request(forms::REQUEST_RULE)));
    };
    let id = PendingId::from_raw(call.draw().map_err(|e| call.refuse(e))?);
    let expires = Timestamp::from_micros(call.now.micros().saturating_add(PENDING_LIFETIME_MICROS));
    let action = PendingAction {
        id,
        account,
        agent,
        op: call.spec.name,
        request,
        shown,
        digest: call.digest,
        created: call.now,
        expires,
        status: PendingStatus::Open,
        closed: None,
    };
    match lock(&call.st.pending).insert(action, call.now) {
        Ok(()) => {}
        Err(InsertError::Taken) => {
            return Err(call.refuse(ApiError::refused(ErrorCode::Unavailable, "ids")));
        }
        Err(InsertError::Full) => {
            return Err(call.refuse(ApiError::refused(ErrorCode::RateLimited, "I-85")));
        }
    }
    // The action is confirmable only with its audit entry: a failed write
    // removes it again.
    if let Err(e) = call.accepted(None) {
        lock(&call.st.pending).remove(id);
        return Err(e);
    }
    Ok(OpResult::Pending(PendingReceipt {
        id,
        confirm_path: confirm_path(id),
        expires,
    }))
}

/// The pending action a confirmation or discard names.
fn pending_of<P: Seams>(
    call: &Call<'_, P>,
    op: &Op,
) -> Result<(AccountId, PendingAction), ApiError> {
    let Some(account) = call.account() else {
        return Err(ApiError::refused(ErrorCode::Unauthenticated, "actor"));
    };
    let id = forms::id_param(&op.request, "pending")
        .ok_or(ApiError::bad_request(forms::REQUEST_RULE))?;
    let found = lock(&call.st.pending)
        .get(PendingId::from_raw(id), account)
        .cloned();
    let a = found.ok_or(ApiError::refused(ErrorCode::NotFound, "I-85"))?;
    match a.status_at(call.now) {
        PendingStatus::Open => Ok((account, a)),
        PendingStatus::Expired => {
            lock(&call.st.pending).close(a.id, PendingStatus::Expired, call.now);
            Err(ApiError::refused(ErrorCode::Expired, "I-85"))
        }
        PendingStatus::Confirmed | PendingStatus::Discarded => {
            Err(ApiError::refused(ErrorCode::Refused, "I-85"))
        }
    }
}

/// A confirmation's claim on its pending action. Dropping it releases
/// the claim, which is a no-op once the action is confirmed.
struct Claim<'a> {
    store: &'a Mutex<PendingStore>,
    id: PendingId,
}

impl<'a> Claim<'a> {
    /// Claims the open action `id` of `account`, or `None`.
    fn take(
        store: &'a Mutex<PendingStore>,
        id: PendingId,
        account: AccountId,
        now: Timestamp,
    ) -> Option<Claim<'a>> {
        lock(store)
            .claim(id, account, now)
            .then_some(Claim { store, id })
    }
}

impl Drop for Claim<'_> {
    fn drop(&mut self) {
        lock(self.store).release(self.id);
    }
}

/// `pending.confirm` (I-85, design section 3.7): web only, by the same
/// account, open and unexpired, the shown digest equal to the stored one,
/// a fresh dry run, and for a high-risk kind a fresh step-up proof for the
/// stored digest. It executes the stored request with `Via::Web`.
async fn confirm<P: Seams>(call: &Call<'_, P>, op: &Op) -> Result<OpResult, ApiError> {
    if call.caller.via() != Via::Web {
        return Err(call.refuse(ApiError::refused(ErrorCode::NotExposed, "I-85")));
    }
    let (account, a) = pending_of(call, op).map_err(|e| call.refuse(e))?;
    let shown = op
        .request
        .get("shown")
        .and_then(Value::as_str)
        .and_then(ActionDigest::from_hex)
        .ok_or_else(|| call.refuse(ApiError::bad_request(forms::REQUEST_RULE)))?;
    if !fstp_crypto::constant_time_eq(&shown.0, &a.digest.0) {
        return Err(call.refuse(ApiError::refused(ErrorCode::DigestMismatch, "I-85")));
    }
    let stored = decode_pending_request(a.request.as_bytes())
        .map_err(|e| call.refuse(e))?
        .into_op();
    let (Some(form), OpKind::Command(_)) = (forms::op_form(stored.spec), stored.spec.kind) else {
        return Err(call.refuse(ApiError::NotImplemented(
            "a pending action of an operation that is not a command",
        )));
    };
    // The confirming session must be strong enough for the stored
    // operation, as on its direct web path (I-77).
    if !fstp_access::session_admits(stored.spec, &call.caller.p) {
        return Err(call.refuse(ApiError::refused(ErrorCode::LoginStrength, "I-77")));
    }
    // Claimed before the first await: a discard, an expiry mark or a
    // second confirmation meanwhile is refused. Dropping the claim
    // releases it unless the execution confirmed the action.
    let _claim = Claim::take(&call.st.pending, a.id, account, call.now)
        .ok_or_else(|| call.refuse(ApiError::refused(ErrorCode::Refused, "I-85")))?;
    let mut ids = Vec::new();
    let cmd =
        build(call, &form, &stored, &BTreeMap::new(), &mut ids).map_err(|e| call.refuse(e))?;
    let command_id = CommandId::from_bytes(call.draw().map_err(|e| call.refuse(e))?.to_be_bytes());
    let ctx = call.ctx(account, &cmd, Via::Web, command_id);
    dry_run(call, account, &cmd, ctx)
        .await
        .map_err(|e| call.refuse(e))?;
    let proof = if stored.spec.high_risk {
        match step_up(call, a.digest).await.map_err(|e| call.refuse(e))? {
            Ok(p) => Some(p),
            Err(ask) => {
                let _ = call.audit(Outcome::Refused("I-78"), None);
                return Ok(ask);
            }
        }
    } else {
        None
    };
    let texts = store_texts(call, &form, &stored)
        .await
        .map_err(|e| call.refuse(e))?;
    let cmd = build(call, &form, &stored, &texts, &mut ids).map_err(|e| call.refuse(e))?;
    let meta = ExecMeta {
        via: Via::Web,
        session: call.caller.session,
        agent: Some(a.agent),
        op: OpName(stored.spec.name),
        request: a.digest,
        step_up: proof,
        pending: Some(a.id),
        second_tenant_admin: None,
    };
    match call.ports.engine().execute(cmd, ctx, meta).await {
        Ok(seq) => {
            let _ = lock(&call.st.pending).confirm(a.id, call.now);
            Ok(OpResult::Done {
                body: ReadModel::Accepted,
                seq: Some(seq),
            })
        }
        Err(e) => Err(call.refuse(exec_failed(e))),
    }
}

/// `pending.discard`: the user discards an open action of their own.
fn discard<P: Seams>(call: &Call<'_, P>, op: &Op) -> Result<OpResult, ApiError> {
    if call.caller.via() != Via::Web {
        return Err(call.refuse(ApiError::refused(ErrorCode::NotExposed, "I-85")));
    }
    let (_, a) = pending_of(call, op).map_err(|e| call.refuse(e))?;
    if !lock(&call.st.pending).close(a.id, PendingStatus::Discarded, call.now) {
        return Err(call.refuse(ApiError::refused(ErrorCode::Refused, "I-85")));
    }
    call.accept(ReadModel::Accepted)
}

/// The read target of a request (design section 3.6).
fn read_target(op: &Op) -> ReadTarget {
    let r = &op.request;
    if let Some(p) = forms::id_param(r, "proposal") {
        return ReadTarget::Proposal(ProposalId::from_raw(p));
    }
    for name in ["assignment", "irc_assignment"] {
        if let Some(a) = forms::id_param(r, name) {
            return ReadTarget::Assignment(AssignmentId::from_raw(a));
        }
    }
    for name in ["call", "round"] {
        if let Some(c) = forms::id_param(r, name) {
            return ReadTarget::Call(CallId::from_raw(c));
        }
    }
    if let Some(p) = forms::id_param(r, "programme") {
        return ReadTarget::Programme(ProgrammeId::from_raw(p));
    }
    ReadTarget::None
}

/// The API error of a denied read.
fn read_denied(rule: DenyRule) -> ApiError {
    match rule {
        DenyRule::Actor => ApiError::refused(ErrorCode::Unauthenticated, "actor"),
        DenyRule::Input => ApiError::refused(ErrorCode::NotFound, "Input"),
        other => ApiError::refused(ErrorCode::Refused, other.spec_id()),
    }
}

/// A read: `authorize_read`, then the read model.
async fn read<P: Seams>(call: &Call<'_, P>, op: &Op, kind: ReadKind) -> Result<OpResult, ApiError> {
    let rop = ReadOp {
        kind,
        target: read_target(op),
    };
    if let Err(d) = fstp_access::authorize_read(&rop, &call.caller.p, &call.state, call.now) {
        return Err(call.refuse(read_denied(d.rule())));
    }
    let account = call.account();
    let body = match kind {
        ReadKind::ListOpenCalls => {
            let core = &call.state.core;
            let calls = call
                .ports
                .call_ids(&call.state)
                .into_iter()
                .filter_map(|c| core.calls().get(c))
                .filter(|v| v.is_open_at(call.now))
                .map(|v| CallSummary::of(v, call.now))
                .collect();
            ReadModel::OpenCalls(calls)
        }
        ReadKind::GetPublicCall => {
            let id = forms::id_param(&op.request, "call").map(CallId::from_raw);
            let view = id
                .and_then(|c| call.state.core.calls().get(c))
                .filter(|v| v.status() == fstp_domain::programme::CallStatus::Published);
            match view {
                Some(v) => ReadModel::Call(CallSummary::of(v, call.now)),
                None => return Err(call.refuse(ApiError::refused(ErrorCode::NotFound, "Input"))),
            }
        }
        ReadKind::ListMyPendingActions => {
            let Some(a) = account else {
                return Err(call.refuse(ApiError::refused(ErrorCode::Unauthenticated, "actor")));
            };
            ReadModel::PendingActions(lock(&call.st.pending).list(a, call.now))
        }
        ReadKind::ListMySessions => {
            let Some(a) = account else {
                return Err(call.refuse(ApiError::refused(ErrorCode::Unauthenticated, "actor")));
            };
            let list = call
                .ports
                .sessions_admin()
                .list(a)
                .await
                .map_err(|e| call.refuse(port_failed(e, "R-LG-04")))?;
            ReadModel::Sessions(list.into_iter().map(SessionSummary::from).collect())
        }
        ReadKind::ListOwnProposals => {
            let Some(a) = account else {
                return Err(call.refuse(ApiError::refused(ErrorCode::Unauthenticated, "actor")));
            };
            ReadModel::OwnProposals(own_proposals(&call.state, a, call.now))
        }
        ReadKind::ListMyAssignments => {
            let Some(a) = account else {
                return Err(call.refuse(ApiError::refused(ErrorCode::Unauthenticated, "actor")));
            };
            ReadModel::Assignments(own_assignments(&call.state, a))
        }
        _ => {
            return Err(call.refuse(ApiError::NotImplemented(
                "this read model: the domain or lane it reads from (see the W3b report)",
            )));
        }
    };
    call.accept(body)
}

/// The caller's proposals: one per Receiving binding active at `now`.
fn own_proposals(state: &EngineState, account: AccountId, now: Timestamp) -> Vec<ProposalSummary> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for (_, b) in state.core.roster().bindings() {
        let BindingScope::Proposal { proposal, call } = b.scope else {
            continue;
        };
        if b.account != account || !b.active_at(now) || !seen.insert(proposal) {
            continue;
        }
        let role = match b.role {
            Role::Applicant => "lead",
            Role::Guardian => "guardian",
            _ => "member",
        };
        let tag = fstp_domain::view::proposal_state(&state.core, proposal);
        out.push(ProposalSummary {
            proposal,
            call,
            state: tag.map_or("UNKNOWN", |t| t.spec_name()).to_owned(),
            role,
        });
    }
    out
}

/// The caller's assignments, without released ones.
fn own_assignments(state: &EngineState, account: AccountId) -> Vec<AssignmentSummary> {
    use fstp_domain::assignment::{AssignmentKind, AssignmentStatus};
    state
        .core
        .review()
        .assignments()
        .filter(|(_, a)| a.reviewer == account && a.unreleased())
        .map(|(id, a)| AssignmentSummary {
            assignment: id,
            proposal: a.proposal,
            call: a.call,
            kind: match a.kind {
                AssignmentKind::Reviewer => "reviewer",
                AssignmentKind::Irc => "irc",
                AssignmentKind::Amendment(_) => "amendment",
            },
            awaiting_declaration: matches!(a.status, AssignmentStatus::AwaitingDeclaration),
            active: a.active(),
        })
        .collect()
}

/// An agent operation (R-MC-03).
async fn agent<P: Seams>(
    call: &Call<'_, P>,
    op: &Op,
    kind: AgentKind,
) -> Result<OpResult, ApiError> {
    let Some(account) = call.account() else {
        return Err(call.refuse(ApiError::refused(ErrorCode::Unauthenticated, "actor")));
    };
    match kind {
        AgentKind::Revoke => {
            let client = forms::id_param(&op.request, "client")
                .map(AgentClientId::from_raw)
                .ok_or_else(|| call.refuse(ApiError::bad_request(forms::REQUEST_RULE)))?;
            match call.ports.revoke_agent(account, client).await {
                Ok(()) => call.accept(ReadModel::Accepted),
                Err(PortError::Refused) => {
                    Err(call.refuse(ApiError::refused(ErrorCode::NotFound, "R-MC-03")))
                }
                Err(e) => Err(call.refuse(port_failed(e, "R-MC-03"))),
            }
        }
        AgentKind::Consent => Err(call.refuse(ApiError::NotImplemented(
            "agent consent: the OAuth profile of ADR-013, a draft",
        ))),
    }
}

/// Whether the operation acts as tenant admin only.
fn admin_only(spec: &OpSpec) -> bool {
    spec.acting == [RoleOrApplicant::Role(Role::TenantAdmin)]
}

/// A supported M3 port operation with its decoded arguments.
enum PortCall {
    /// A guardian approves an account recovery (I-79).
    ApproveRecovery(RecoveryId),
    /// A tenant admin decides a break-glass request (SoD-08).
    ApproveBreakGlass(BreakGlassId, bool),
    /// The user ends one of their sessions (R-LG-04).
    EndSession(SessionId),
    /// The user begins an identity verification.
    BeginVerification,
}

/// An operation an M3 port serves.
async fn m3_port<P: Seams>(
    call: &Call<'_, P>,
    op: &Op,
    kind: PortKind,
) -> Result<OpResult, ApiError> {
    let Some(account) = call.account() else {
        return Err(call.refuse(ApiError::refused(ErrorCode::Unauthenticated, "actor")));
    };
    if admin_only(call.spec) && !call.caller.p.tenant_admin() {
        return Err(call.refuse(ApiError::refused(ErrorCode::Refused, "R-AC-01")));
    }
    let id = |name: &str| {
        forms::id_param(&op.request, name)
            .ok_or_else(|| call.refuse(ApiError::bad_request(forms::REQUEST_RULE)))
    };
    // The supported operations and their arguments come first, so no
    // step-up proof is spent on a call that cannot run.
    let port_call = match kind {
        PortKind::ApproveRecovery if call.spec.high_risk => {
            PortCall::ApproveRecovery(RecoveryId::from_raw(id("recovery")?))
        }
        PortKind::ApproveBreakGlass if call.spec.high_risk => {
            let b = BreakGlassId::from_raw(id("break_glass")?);
            let approve = op
                .request
                .get("approve")
                .and_then(Value::as_bool)
                .ok_or_else(|| call.refuse(ApiError::bad_request(forms::REQUEST_RULE)))?;
            PortCall::ApproveBreakGlass(b, approve)
        }
        PortKind::EndSession => PortCall::EndSession(SessionId::from_raw(id("session")?)),
        PortKind::BeginVerification => PortCall::BeginVerification,
        _ => {
            return Err(call.refuse(ApiError::NotImplemented(
                "this M3 port operation: its port or request form (see the W3b report)",
            )));
        }
    };
    let proof = if call.spec.high_risk {
        if call.caller.via() != Via::Web {
            return Err(call.refuse(ApiError::refused(ErrorCode::NotExposed, "I-85")));
        }
        match step_up(call, call.digest)
            .await
            .map_err(|e| call.refuse(e))?
        {
            Ok(p) => Some(p),
            Err(ask) => {
                let _ = call.audit(Outcome::Refused("I-78"), None);
                return Ok(ask);
            }
        }
    } else {
        None
    };
    let proof_of = |p: Option<StepUpRef>| crate::port::StepUpProof {
        step_up: p.unwrap_or(StepUpRef(0)),
        action: call.digest,
    };
    let done = |r: Result<(), PortError>, rule: &'static str| match r {
        Ok(()) => {
            call.accepted(proof)?;
            Ok(OpResult::Done {
                body: ReadModel::Accepted,
                seq: None,
            })
        }
        Err(e) => Err(call.refuse(port_failed(e, rule))),
    };
    match port_call {
        PortCall::ApproveRecovery(r) => done(
            call.ports
                .recovery()
                .approve(account, r, proof_of(proof))
                .await,
            "I-79",
        ),
        PortCall::ApproveBreakGlass(b, approve) => done(
            call.ports
                .break_glass()
                .decide(account, b, approve, proof_of(proof))
                .await,
            "SoD-08",
        ),
        PortCall::EndSession(s) => {
            done(call.ports.sessions_admin().end(account, s).await, "R-LG-04")
        }
        PortCall::BeginVerification => {
            let purpose = if call.caller.p.tenant_admin() {
                VerificationPurpose::AdminIdentity
            } else {
                VerificationPurpose::Applicant
            };
            match call
                .ports
                .vault()
                .begin_verification(purpose, account)
                .await
            {
                Ok(to) => call.accept(ReadModel::Redirect(to.0)),
                Err(_) => Err(call.refuse(ApiError::refused(ErrorCode::Unavailable, "oracle"))),
            }
        }
    }
}
