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
//!    about to execute, so a refused call stores no text. Before the
//!    request digest is made, dispatch names the plan members the server
//!    supplies (`forms::name_plans`). A pending action and its
//!    confirmation then carry the same plan (I-85).
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
//!
//! Interim readings of lane m4disp, pending Daniel:
//!
//! - A read that shows other people's vault answers, such as the SoD-11
//!   check of the assignment view or the recusals of a round, asks the
//!   vault at read time. Each answer is recorded as a dry run's answers
//!   are, and such reads share the H-07 limit per account.
//! - A cut-off round is read from the journal of the rounds this core
//!   opened (`journal.rs`). Any other round fails closed.
//! - The caller's own list of proposals keeps a proposal that reached a
//!   terminal state, since the domain ends the team's Receiving bindings
//!   there. `proposal.view` keeps the `Team` rule of the access crate.
//! - `stage2.revise` with a plan page form records the plan and submits
//!   it in one entry, as the engine's composed `Stage2Revision` (R-EV-05,
//!   lane mapp). With a `plan` member it is the domain's `SubmitRevision`
//!   of a plan the lead recorded first through `proposal.record_plan`.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::sync::{Mutex, MutexGuard, PoisonError};

use fstp_access::{
    AgentKind, ChannelDenial, ChannelVerdict, DenyRule, GrantFacts, McpSettings, OpKind, OpSpec,
    PendingKind, PortKind, Principal, ReadKind, ReadOp, ReadTarget, RoleOrApplicant, SessionFacts,
};
use fstp_domain::command::{Actor, Ctx, Via};
use fstp_domain::id::{
    AccountId, AssignmentId, CallId, CommandId, DecisionId, LlmConfigId, OrganisationId,
    ProgrammeId, ProposalId, TextRef,
};
use fstp_domain::oracle::{Answer, Query};
use fstp_domain::policy::{McpBindingActions, ModelRef};
use fstp_domain::refusal::{Refusal, RuleRef};
use fstp_domain::roles::{Binding, BindingScope, BindingStatus, Role};
use fstp_domain::time::Timestamp;
use fstp_engine::{Command, EngineState};
use fstp_json::{Object, Value};

use crate::content::{ContentStore, SaveError, Workspace};
use crate::decode::{decode_pending_request, pending_request_text};
use crate::forms::{self, BuildCtx, CmdForm};
use crate::journal::{Journal, RoundStatus, ThreadEntry, Unknown};
use crate::model::{AssignmentSummary, CallSummary, ProposalSummary, SessionSummary};
use crate::pending::{
    InsertError, PENDING_LIFETIME_MICROS, PendingAction, PendingReceipt, PendingStatus,
    PendingStore, confirm_path,
};
use crate::port::{
    Accounts, AgentClientId, AsyncEngine, AsyncIdentityOracle, AuditEntry, BreakGlass,
    BreakGlassId, CellPorts, Clock, ExecError, ExecMeta, Ids, LoginMethod, OpName, Outcome,
    PendingId, PortError, QueryDigest, Recovery, RecoveryId, SessionId, Sessions, SessionsAdmin,
    StepUp, StepUpRef, TenantConfig, TextClass, TextOwner, TextStore, Vault, VaultAudit,
    VerificationPurpose,
};
use crate::rate::{self, Key, Rates};
use crate::{ActionDigest, ApiError, Credential, ErrorCode, Op, OpResult, ReadModel, RequestHead};

mod creator_ops;
/// `proposal.journey` and `proposal.diary` (lane j2, ADR-015), and
/// `proposal.route_map` (lane j4).
pub(crate) mod journey;
/// `me.roles`, the caller's own roles (design section 15.0, 2026-10-31).
pub(crate) mod me_roles;
/// The people operations of journey J2 (lane inv). The file sits beside
/// `creator.rs`, as the lane's file plan names it.
#[path = "people.rs"]
pub(crate) mod people;
/// The public pages, the feed and the public tools (lane W2c).
mod public;
/// The tenant operations (lane m4tenant).
mod tenant;

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

/// The state of one API core beside its ports: the pending actions, the
/// rate-limit counters, the content and journal projections, and the
/// accounts that began an identity verification, in memory only.
#[derive(Debug, Default)]
#[allow(
    dead_code,
    reason = "port.rs holds it beside the ports once the lead closes the seams"
)]
pub(crate) struct State {
    pending: Mutex<PendingStore>,
    rates: Mutex<Rates>,
    content: Mutex<ContentStore>,
    journal: Mutex<Journal>,
    /// The verifications begun through this core, so their state reads
    /// "pending" for a bounded time while the vault has not confirmed
    /// them (I-86).
    begun: Mutex<Begun>,
    /// The tenant templates and uploads this core took (lane m4wire,
    /// `creator.rs`).
    creator: Mutex<crate::creator::CreatorMemory>,
}

/// The most accounts [`Begun`] holds. Past it, a new account's state
/// reads as the vault answers it, without "pending".
const MAX_BEGUN: usize = 1_000_000;

/// How long a begun verification reads "pending": one hour.
///
/// Interim, pending a vault query for a verification in flight (a port
/// seam the lead owns): the vault port answers `IsVerified` only, so a
/// verification it rejects or the person abandons cannot be seen here.
/// The bound keeps such a verification from reading "pending" for
/// longer than one hour. A verification the vault confirms reads
/// "verified" at once, whatever the bound.
pub(crate) const VERIFICATION_PENDING_MICROS: i64 = 3_600_000_000;

/// The instant each account last began a verification through this core,
/// in memory only (I-86). Bounded by [`MAX_BEGUN`].
#[derive(Debug, Default)]
pub(crate) struct Begun {
    at: BTreeMap<AccountId, Timestamp>,
}

impl Begun {
    /// Records that `account` began a verification at `now`. A full map
    /// first drops every entry no longer pending, and records nothing if
    /// it is still full.
    fn begin(&mut self, account: AccountId, now: Timestamp) {
        if self.at.len() >= MAX_BEGUN && !self.at.contains_key(&account) {
            self.at.retain(|_, t| still_pending(*t, now));
        }
        if self.at.len() < MAX_BEGUN || self.at.contains_key(&account) {
            let _ = self.at.insert(account, now);
        }
    }

    /// Whether a verification `account` began reads "pending" at `now`:
    /// it began less than [`VERIFICATION_PENDING_MICROS`] ago.
    fn pending(&self, account: AccountId, now: Timestamp) -> bool {
        self.at
            .get(&account)
            .is_some_and(|t| still_pending(*t, now))
    }
}

/// Whether a verification begun at `began` still reads "pending" at `now`.
fn still_pending(began: Timestamp, now: Timestamp) -> bool {
    now.micros() < began.micros().saturating_add(VERIFICATION_PENDING_MICROS)
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What the journal knows of the latest plan of `p` (`journal.rs`).
fn latest_plan(st: &State, p: ProposalId) -> forms::LatestPlan {
    match lock(&st.journal).latest_plan(p) {
        Ok(x) => forms::LatestPlan::Known(x),
        Err(Unknown) => forms::LatestPlan::Unknown,
    }
}

/// The refusal of a read model whose proposal history the journal does
/// not hold (`journal.rs`, fail closed).
fn history_unknown() -> ApiError {
    ApiError::NotImplemented(
        "the history of a proposal recorded outside this API core: domain read accessors (lane W1b)",
    )
}

/// The refusal of a read of content this core does not hold
/// (`content.rs`, fail closed).
fn content_unknown() -> ApiError {
    ApiError::NotImplemented(
        "the content of a proposal saved outside this API core: the sealed workspace store (lane W6)",
    )
}

/// The refusal of a read of a text this core did not store
/// (`content.rs`, fail closed).
fn text_unknown() -> ApiError {
    ApiError::NotImplemented(
        "a text stored outside this API core: a read clearance of the text store (port.rs, the lead)",
    )
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
        // A seam of a parallel lane refused, such as the creator's compile
        // seam (lane m4wire). It names no rule, so it stays a stub answer.
        RuleRef::NotImplemented => ApiError::NotImplemented(
            "the engine refused at a seam of a parallel lane (RuleRef::NotImplemented)",
        ),
        RuleRef::OracleDown => ApiError::refused(ErrorCode::Unavailable, "oracle"),
        RuleRef::Actor => ApiError::refused(ErrorCode::Unauthenticated, "actor"),
        rule => match r.detail {
            // I-50 at save names both values (Daniel's answer of
            // 2026-10-31, M4 design section 15.0).
            Some(d) => ApiError::refused_naming(ErrorCode::Refused, rule_text(rule), d),
            None => ApiError::refused(ErrorCode::Refused, rule_text(rule)),
        },
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

/// The tenant admin set, as far as it concerns `account`: the ledger's
/// once it holds the tenant part (Q31 A, `tenant::is_admin`).
fn admins_of<P: CellPorts>(
    ports: &P,
    state: &EngineState,
    account: AccountId,
) -> BTreeSet<AccountId> {
    let mut set = BTreeSet::new();
    if tenant::is_admin(ports, state, account) {
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
                    let p = Principal::web(&facts, &admins_of(ports, state, s.account), state, now);
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
            Ok(g) => match Principal::mcp(&g, &admins_of(ports, state, g.account), state, now) {
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

/// The rights of a bearer token now, with no operation (TH-63, lane
/// W3c): the MCP principal of its grant, with roles evaluated at the
/// instant as step 0 evaluates them. Unlike step 0, a credential that is
/// no bearer token, or a token with no grant, is refused with
/// `Unauthenticated` rather than made anonymous. Nothing is recorded.
pub(crate) async fn tool_rights<P: Seams>(
    ports: &P,
    cred: &Credential,
) -> Result<crate::ToolRights, ApiError> {
    let unknown = || ApiError::refused(ErrorCode::Unauthenticated, "actor");
    let Credential::Bearer(token) = cred else {
        return Err(unknown());
    };
    let now = ports.clock().now();
    let g = match ports.grant(token, now).await {
        Ok(g) => g,
        Err(PortError::Unavailable) => {
            return Err(ApiError::refused(ErrorCode::Unavailable, "token"));
        }
        Err(PortError::Refused) => return Err(unknown()),
    };
    let state = ports.engine().snapshot();
    let principal = Principal::mcp(&g, &admins_of(ports, &state, g.account), &state, now)
        .map_err(|_| unknown())?;
    Ok(crate::ToolRights { principal })
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
            binds_tenant_admin: binds_admin(self.ports, &self.state, account, cmd),
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

/// Whether the account `cmd` binds holds a tenant-wide Operations role:
/// tenant admin (design section 3.7: from the attested admin set, which
/// the ledger owns under Q31 A), or Financial or Legal signatory from the
/// ledger's signatory bindings (NOTE 5). The core reads it for SoD-03.
fn binds_admin<P: CellPorts>(
    ports: &P,
    state: &EngineState,
    actor: AccountId,
    cmd: &Command,
) -> bool {
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
    tenant::holds_tenant_operations(ports, state, bound)
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
    let mut op = op;
    let spec = op.spec;
    // The plan members the server supplies are named before the digest,
    // so the digest, a pending action and its confirmation carry the
    // same plan (I-85, design section 3.7 step 6).
    if let (Some(form), Some(p)) = (
        forms::request_form(spec, &op.request),
        forms::id_param(&op.request, "proposal"),
    ) {
        let latest = latest_plan(st, ProposalId::from_raw(p));
        forms::name_plans(&form, &mut op.request, latest);
    }
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
    let settings = tenant::mcp_settings(ports, &call.state);
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
        OpKind::Creator(_) | OpKind::Bridge(_) | OpKind::Import(_) => {
            creator_ops::command(&call, &op).await
        }
        OpKind::Tenant(kind) => tenant::command(&call, &op, kind).await,
        OpKind::Finding(fstp_access::FindingKind::Mark) => finding_mark(&call, &op).await,
        // `Record` and `Regenerate` are the assessor's, through no route.
        OpKind::Finding(_) => Err(call.refuse(ApiError::NotImplemented(
            "a finding command that only the assessor issues",
        ))),
        OpKind::Public(kind) => public::read(&call, &op, kind).await,
    }
}

/// `review.mark_finding`: the acting reviewer's mark on a finding, run
/// as `FindingCommand::Mark` (I-03, I-10). The engine judges who may
/// mark. It is web only, so it is never prepared.
async fn finding_mark<P: Seams>(call: &Call<'_, P>, op: &Op) -> Result<OpResult, ApiError> {
    let Some(account) = call.account() else {
        return Err(call.refuse(ApiError::refused(ErrorCode::Unauthenticated, "actor")));
    };
    let bad = || call.refuse(ApiError::bad_request(forms::REQUEST_RULE));
    let finding = forms::id_param(&op.request, "finding").ok_or_else(bad)?;
    let mark = op
        .request
        .get("mark")
        .and_then(Value::as_str)
        .and_then(forms::finding_mark)
        .ok_or_else(bad)?;
    let cmd = Command::Finding(fstp_engine::FindingCommand::Mark {
        finding: fstp_engine::FindingId::from_raw(finding),
        mark,
    });
    let command_id = CommandId::from_bytes(call.draw().map_err(|e| call.refuse(e))?.to_be_bytes());
    let ctx = call.ctx(account, &cmd, call.caller.via(), command_id);
    // Step 5.
    dry_run(call, account, &cmd, ctx)
        .await
        .map_err(|e| call.refuse(e))?;
    let meta = ExecMeta {
        via: call.caller.via(),
        session: call.caller.session,
        agent: call.caller.agent,
        op: OpName(call.spec.name),
        request: call.digest,
        step_up: None,
        pending: None,
        second_tenant_admin: None,
    };
    match call.ports.engine().execute(cmd, ctx, meta).await {
        Ok(seq) => Ok(OpResult::Done {
            body: ReadModel::Accepted,
            seq: Some(seq),
        }),
        Err(e) => Err(call.refuse(exec_failed(e))),
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
    let (Some(form), Some(account)) = (forms::request_form(call.spec, &op.request), call.account())
    else {
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
        inference: tenant::inference(call.ports, &call.state),
        second_admin,
        trial: false,
        plan_unknown: false,
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
    let mut cx = build_ctx(call, None);
    // Nothing is derived from the journal here: `run` named the plan
    // members before the digest. The build only learns whether a missing
    // member is missing because the journal does not hold the history.
    cx.plan_unknown = forms::id_param(&op.request, "proposal").is_some_and(|p| {
        latest_plan(call.st, ProposalId::from_raw(p)) == forms::LatestPlan::Unknown
    });
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
        let r = forms::text_ref(r.0, s);
        lock(&call.st.content).remember(r, s);
        out.insert(path, r);
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
    // A round id is never read as a call id. No round command has a text.
    if let Some(c) = forms::id_param(request, "call") {
        return forms::programme_of_call(state, CallId::from_raw(c)).map(TextOwner::Programme);
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
    if !tenant::is_admin(call.ports, &call.state, a.approver) {
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
    let Some(form) = forms::request_form(call.spec, &op.request) else {
        return Err(call.refuse(ApiError::NotImplemented(
            "a command operation with no request form",
        )));
    };
    if !check_target(&call.state, &op.request) {
        return Err(call.refuse(ApiError::refused(ErrorCode::NotFound, "Input")));
    }
    // Lane inv, J2: a grant by invitation stands for the grant of the
    // accepting account in the invited role, with the accepted terms as
    // its confidentiality text (`people`). The digest stays the one of the
    // request the admin sent.
    let composed = people::grant_request(&call.state, op, call.now).map_err(|e| call.refuse(e))?;
    let (op, mut preset) = match &composed {
        Some((rewritten, texts)) => (rewritten, texts.clone()),
        None => (op, BTreeMap::new()),
    };
    let second = second_admin(call, &op.request)
        .await
        .map_err(|e| call.refuse(e))?;
    let mut ids = Vec::new();
    let cmd = build(call, &form, op, &preset, &mut ids).map_err(|e| call.refuse(e))?;
    // J2: a Drafting or Judging grant is composed only from accepted terms,
    // and binds exactly them.
    if let Some(terms) = people::grant_terms(&call.state, op, &cmd).map_err(|e| call.refuse(e))? {
        preset.insert("confidentiality", terms);
    }
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
    let mut texts = store_texts(call, &form, op)
        .await
        .map_err(|e| call.refuse(e))?;
    texts.extend(preset);
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
    let appended = cmd.clone();
    match call.ports.engine().execute(cmd, ctx, meta).await {
        Ok(seq) => Ok(OpResult::Done {
            body: {
                executed(call, account, &appended);
                plan_saved(&appended).unwrap_or_else(|| accepted(&form, &ids))
            },
            seq: Some(seq),
        }),
        Err(e) => Err(call.refuse(exec_failed(e))),
    }
}

/// Folds a command that `actor` appended into the projections of this
/// core: the journal of its read models and rounds, and the content
/// frozen at submission.
fn executed<P: Seams>(call: &Call<'_, P>, actor: AccountId, cmd: &Command) {
    use fstp_domain::command::Command as Core;
    {
        let mut journal = lock(&call.st.journal);
        journal.fold(cmd, &call.state, call.now);
        journal.fold_round(cmd, actor);
    }
    match cmd {
        Command::Core(Core::CreateDraft { proposal, .. }) => {
            lock(&call.st.content).created(*proposal);
        }
        Command::Core(Core::Submit { proposal, .. }) => {
            lock(&call.st.content).freeze(*proposal);
        }
        _ => {}
    }
}

/// The body of an executed command: `{"accepted": true}`, and for a
/// command that creates an object the client opens next, the drawn id
/// that names it. Interim, pending Daniel: only `CreateDraft` names its
/// new proposal (`proposal.create`, design section 2.2 J4), and
/// `DraftCall` its new call (`call.draft`, lane mcreator). Other drawn
/// ids, such as bindings and decisions, stay with the server.
///
/// `OpenCutOffRound` answers `{"round": id}` with the drawn round alone,
/// since the ballot, the delegation and the round read address it
/// (change D5, `committee.open_round` in `fstp_access::REPLIES`). A
/// recorded plan answers through [`plan_saved`] instead, with its drawn
/// plan id, which a stage 2 revision names (R-EV-05).
fn accepted(form: &CmdForm, ids: &[u128]) -> ReadModel {
    if form.kind == fstp_domain::CommandKind::OpenCutOffRound {
        let round = form
            .drawn
            .iter()
            .zip(ids.iter())
            .find(|(member, _)| **member == "round")
            .map(|(_, id)| *id);
        if let Some(round) = round {
            return ReadModel::RoundOpened(crate::model::RoundOpened {
                round: fstp_domain::id::DecisionId::from_raw(round),
            });
        }
    }
    // Lane mcreator: a drafted call names its id, which the Studio opens.
    const NAMED: &[(fstp_domain::CommandKind, &str)] = &[
        (fstp_domain::CommandKind::CreateDraft, "proposal"),
        (fstp_domain::CommandKind::DraftCall, "call"),
    ];
    let Some((_, name)) = NAMED.iter().find(|(k, _)| *k == form.kind) else {
        return ReadModel::Accepted;
    };
    let created: Vec<(&'static str, u128)> = form
        .drawn
        .iter()
        .copied()
        .zip(ids.iter().copied())
        .filter(|(member, _)| member == name)
        .collect();
    if created.is_empty() {
        ReadModel::Accepted
    } else {
        ReadModel::Created(created)
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
    let (Some(form), OpKind::Command(_)) = (
        forms::request_form(stored.spec, &stored.request),
        stored.spec.kind,
    ) else {
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
    // J2 (lane inv): a confirmed grant needs accepted terms too, and binds
    // exactly them.
    let preset = people::grant_terms(&call.state, &stored, &cmd).map_err(|e| call.refuse(e))?;
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
    let mut texts = store_texts(call, &form, &stored)
        .await
        .map_err(|e| call.refuse(e))?;
    if let Some(terms) = preset {
        texts.insert("confidentiality", terms);
    }
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
    let appended = cmd.clone();
    match call.ports.engine().execute(cmd, ctx, meta).await {
        Ok(seq) => {
            executed(call, account, &appended);
            let _ = lock(&call.st.pending).confirm(a.id, call.now);
            Ok(OpResult::Done {
                body: accepted(&form, &ids),
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
    // A round is judged through its call, which `read` resolves from the
    // journal (change D5). Its own id is never read as a call id.
    if let Some(c) = forms::id_param(r, "call") {
        return ReadTarget::Call(CallId::from_raw(c));
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
    let target = match kind {
        ReadKind::GetCutOffRound => round_target(call, op)?,
        _ => read_target(op),
    };
    let rop = ReadOp { kind, target };
    let clearance = match fstp_access::authorize_read(&rop, &call.caller.p, &call.state, call.now) {
        Ok(c) => c,
        Err(d) => return Err(call.refuse(read_denied(d.rule()))),
    };
    let account = call.account();
    let body = match kind {
        ReadKind::ListOpenCalls => {
            let core = &call.state.core;
            let views: Vec<_> = call
                .ports
                .call_ids(&call.state)
                .into_iter()
                .filter_map(|c| core.calls().get(c))
                .filter(|v| v.is_open_at(call.now))
                .collect();
            let mut calls = Vec::new();
            for v in views {
                calls.push(call_summary(call, v).await);
            }
            ReadModel::OpenCalls(calls)
        }
        ReadKind::GetPublicCall => {
            let id = forms::id_param(&op.request, "call").map(CallId::from_raw);
            let view = id
                .and_then(|c| call.state.core.calls().get(c))
                .filter(|v| v.status() == fstp_domain::programme::CallStatus::Published);
            match view {
                Some(v) => ReadModel::Call(call_summary(call, v).await),
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
            let mut own = own_proposals(&call.state, a, call.now, Ended::Final);
            let content = lock(&call.st.content);
            for p in &mut own {
                // An unknown proposal shows no title, never an empty one.
                p.title = content.title_of(p.proposal);
            }
            ReadModel::OwnProposals(own)
        }
        ReadKind::ListMyAssignments => {
            let Some(a) = account else {
                return Err(call.refuse(ApiError::refused(ErrorCode::Unauthenticated, "actor")));
            };
            ReadModel::Assignments(own_assignments(&call.state, a))
        }
        ReadKind::GetOwnProposal => {
            let Some(a) = account else {
                return Err(call.refuse(ApiError::refused(ErrorCode::Unauthenticated, "actor")));
            };
            let p = proposal_param(call, op)?;
            // The read rule admitted the caller, the former team included
            // in a terminal state (Daniel, 2026-11-06).
            let Some(mut mine) = own_proposals(&call.state, a, call.now, Ended::Final)
                .into_iter()
                .find(|x| x.proposal == p)
            else {
                return Err(call.refuse(ApiError::refused(ErrorCode::NotFound, "Input")));
            };
            mine.title = lock(&call.st.content).title_of(p);
            // R-AU-01, I-84: the team's read of its own proposal appends a
            // `ContentRead` through every channel (design section 3.8).
            let seq = append_content_read(call, p).await?;
            return Ok(OpResult::Done {
                body: ReadModel::OwnProposal(mine),
                seq: Some(seq),
            });
        }
        ReadKind::GetOwnStage2Thread => {
            let p = proposal_param(call, op)?;
            ReadModel::Stage2Questions(own_questions(call, p)?)
        }
        ReadKind::GetOwnNotices => {
            let Some(a) = account else {
                return Err(call.refuse(ApiError::refused(ErrorCode::Unauthenticated, "actor")));
            };
            ReadModel::Notices(notices(call, a)?)
        }
        ReadKind::GetNegotiationLanding => {
            let Some(a) = account else {
                return Err(call.refuse(ApiError::refused(ErrorCode::Unauthenticated, "actor")));
            };
            let p = proposal_param(call, op)?;
            ReadModel::Negotiation {
                acknowledged: lock(&call.st.content).acknowledged(a, p),
            }
        }
        ReadKind::ListMyIrcCases => {
            let Some(a) = account else {
                return Err(call.refuse(ApiError::refused(ErrorCode::Unauthenticated, "actor")));
            };
            let mut mine = own_assignments(&call.state, a);
            mine.retain(|s| s.kind == "irc");
            ReadModel::Assignments(mine)
        }
        ReadKind::GetOwnWorkspace => {
            let p = proposal_param(call, op)?;
            let w = lock(&call.st.content)
                .workspace(p)
                .ok_or_else(|| call.refuse(content_unknown()))?;
            ReadModel::Workspace(crate::views::WorkspaceView {
                title: w.title,
                summary: w.summary,
                narrative: w.narrative,
            })
        }
        ReadKind::GetDeclarationView => {
            let p = proposal_param(call, op)?;
            let c = submitted_content(call, p)?;
            ReadModel::DeclarationView(crate::views::DeclarationView {
                title: c.title,
                neutral_summary: c.summary,
            })
        }
        ReadKind::GetContent => {
            let p = proposal_param(call, op)?;
            return content_read(call, p, None).await;
        }
        ReadKind::GetIrcCase => {
            let a = assignment_param(call, op, "irc_assignment")?;
            let p = call
                .state
                .core
                .review()
                .get(a)
                .map(|x| x.proposal)
                .ok_or_else(|| call.refuse(ApiError::refused(ErrorCode::NotFound, "Input")))?;
            return content_read(call, p, Some("nominated")).await;
        }
        ReadKind::GetIntakeQueue => {
            let c = call_param(call, op)?;
            let knock_out = knock_out_criteria(call, c).await?;
            // The intake holds the proposals awaiting their knock-out, and those
            // its knock-out made INELIGIBLE (R-EV-01).
            let proposals = proposal_rows(call, c, |s| {
                matches!(
                    s,
                    fstp_domain::StateTag::Submitted | fstp_domain::StateTag::Ineligible
                )
            })?;
            ReadModel::IntakeQueue(crate::views::IntakeQueue {
                knock_out,
                proposals,
            })
        }
        ReadKind::GetCallBoard => {
            let c = call_param(call, op)?;
            ReadModel::Board(proposal_rows(call, c, |s| {
                !matches!(s, fstp_domain::StateTag::Draft)
            })?)
        }
        ReadKind::ListNotifiableConflicts => {
            let c = call_param(call, op)?;
            // Every submitted proposal of the call, each known to the
            // journal: an unknown one fails the read closed.
            let journal = lock(&call.st.journal);
            let mut notifiable = Vec::new();
            for p in proposals_of_call(&call.state, c) {
                if fstp_domain::view::proposal_state(&call.state.core, p)
                    .is_none_or(|t| t == fstp_domain::StateTag::Draft)
                {
                    continue;
                }
                if journal
                    .notifiable(p)
                    .map_err(|Unknown| call.refuse(history_unknown()))?
                {
                    notifiable.push(p);
                }
            }
            drop(journal);
            ReadModel::Notifiable(notifiable)
        }
        ReadKind::GetScoreSheet => {
            let a = assignment_param(call, op, "assignment")?;
            ReadModel::ScoreSheet(score_sheet(call, a)?)
        }
        ReadKind::GetFindings => {
            let Some(viewer) = account else {
                return Err(call.refuse(ApiError::refused(ErrorCode::Unauthenticated, "actor")));
            };
            let a = assignment_param(call, op, "assignment")?;
            ReadModel::Findings(findings(call, a, viewer)?)
        }
        ReadKind::GetStage2Thread => {
            let a = assignment_param(call, op, "assignment")?;
            ReadModel::Stage2Thread(stage2_thread(call, a)?)
        }
        ReadKind::GetRankingView => {
            let Some(viewer) = account else {
                return Err(call.refuse(ApiError::refused(ErrorCode::Unauthenticated, "actor")));
            };
            let c = call_param(call, op)?;
            ReadModel::Ranking(ranking(call, c, viewer)?)
        }
        ReadKind::GetCutOffRound => {
            let Some(viewer) = account else {
                return Err(call.refuse(ApiError::refused(ErrorCode::Unauthenticated, "actor")));
            };
            let r = round_param(call, op)?;
            ReadModel::Round(round_view(call, r, viewer).await?)
        }
        ReadKind::ListProposalAssignments => {
            let p = proposal_param(call, op)?;
            ReadModel::AssignmentView(assignment_view(call, p).await?)
        }
        ReadKind::GetMyVerification => {
            let Some(a) = account else {
                return Err(call.refuse(ApiError::refused(ErrorCode::Unauthenticated, "actor")));
            };
            ReadModel::Verification(own_verification(call, a).await?)
        }
        ReadKind::GetOnboarding
        | ReadKind::GetTenantSettings
        | ReadKind::ListTenantAdmins
        | ReadKind::ListSignatories
        | ReadKind::GetActivation => tenant::read(call, op, kind).await?,
        // Lane m4wire: the creator pages and the approval inbox.
        ReadKind::GetDraft
        | ReadKind::GetReport
        | ReadKind::GetPreview
        | ReadKind::GetImpact
        | ReadKind::ListInvitations
        | ReadKind::ListImportProposals
        | ReadKind::ListProgrammes
        | ReadKind::ListTemplates
        | ReadKind::ListApprovals => ReadModel::Creator(creator_ops::read(call, op, kind).await?),
        // The interim home page of design section 15.0 (2026-10-31), I-86.
        ReadKind::ListMyRoles => {
            let Some(a) = account else {
                return Err(call.refuse(ApiError::refused(ErrorCode::Unauthenticated, "actor")));
            };
            ReadModel::MyRoles(me_roles::read(call, a).await)
        }
        // Lane j2, `SPEC/12-journey-ui.md` section 10 (I-92, I-93, I-97).
        ReadKind::GetJourney => {
            let p = proposal_param(call, op)?;
            ReadModel::Journey(journey::journey(call, p, clearance.rule())?)
        }
        ReadKind::GetDiary => {
            let p = proposal_param(call, op)?;
            ReadModel::Diary(journey::diary(call, p, clearance.rule())?)
        }
        // Lane inv, J2: the invitation landing, by its link token only.
        ReadKind::GetInvitation => ReadModel::Invitation(people::landing(call, op).await?),
        // Lane j4, ADR-015 amendment of 2026-11-06 (section 8.1, O-58, I-97).
        ReadKind::GetRouteMap => {
            let p = proposal_param(call, op)?;
            ReadModel::RouteMap(journey::route_map(call, p, clearance.rule())?)
        }
        // Lane mcreator: the Studio's calls of the programme (R-PC-03).
        ReadKind::ListCalls => {
            let Some(a) = account else {
                return Err(call.refuse(ApiError::refused(ErrorCode::Unauthenticated, "actor")));
            };
            let p = forms::id_param(&op.request, "programme")
                .map(ProgrammeId::from_raw)
                .ok_or_else(|| call.refuse(ApiError::bad_request(forms::REQUEST_RULE)))?;
            ReadModel::Calls(staff_calls(&call.state.core, p, a, call.now))
        }
        // R-GA-01, I-53: the stored Guide, never one bound per request.
        ReadKind::GetGuide => ReadModel::Guide(
            public::calls_guide(call, op)
                .await
                .map_err(|e| call.refuse(e))?,
        ),
        _ => {
            return Err(call.refuse(ApiError::NotImplemented(
                "this read model: the domain or lane it reads from (see the W3b report)",
            )));
        }
    };
    // I-86: a model that carries an email is served to the web only. The
    // creator read refuses it earlier. This is the backstop.
    if body.carries_email() && call.caller.via() != Via::Web {
        return Err(call.refuse(ApiError::refused(ErrorCode::NotExposed, "I-86")));
    }
    call.accept(body)
}

/// Whether a read of the caller's proposals also lists those whose
/// Receiving bindings ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ended {
    /// Active bindings only, as every act and the `Team` read rule need.
    Excluded,
    /// Also each proposal in a terminal state on which the caller held a
    /// Receiving binding until the domain ended it there.
    Final,
}

/// Whether an ended Receiving binding gives its holder the final-state
/// read of [`Ended::Final`]: only one that was active when it ended. A
/// suspended binding is inactive for every action (`roles-and-sod.md`),
/// even where it still counts as held, and a voided one never counts.
fn gives_final_read(b: &Binding) -> bool {
    matches!(b.status, BindingStatus::Active)
}

/// The roles through which a former lead or team member reads the route
/// of `proposal` in a terminal state (Daniel, 2026-11-06): each ended
/// Receiving binding of lead or team member that gives the final-state
/// read. It is empty while the proposal is under way. The read rule
/// `ReadRule::FormerTeam` admits the same callers, and no binding is
/// revived, so every command stays refused.
fn former_team_roles(state: &EngineState, account: AccountId, proposal: ProposalId) -> Vec<Role> {
    let terminal = fstp_domain::view::proposal_state(&state.core, proposal)
        .is_some_and(fstp_domain::StateTag::is_terminal);
    if !terminal {
        return Vec::new();
    }
    state
        .core
        .roster()
        .ended()
        .map(|(_, e)| e.binding)
        .filter(|b| {
            b.account == account
                && b.proposal() == Some(proposal)
                && matches!(b.role, Role::Applicant | Role::ApplicantTeamMember)
                && gives_final_read(b)
        })
        .map(|b| b.role)
        .collect()
}

/// The caller's proposals: one per Receiving binding active at `now`,
/// and with [`Ended::Final`] one per proposal in a terminal state whose
/// Receiving binding of the caller ended.
///
/// A Receiving binding ends when its proposal reaches a terminal state
/// (`roles-and-sod.md`, Receiving bindings). The team then still reads
/// the final state of its own proposal, such as WITHDRAWN or
/// NOT_SELECTED, through this list (R-SB-03, R-EV-04). A voided or
/// suspended binding gives no such read, and neither does an ended one
/// of a proposal still under way.
fn own_proposals(
    state: &EngineState,
    account: AccountId,
    now: Timestamp,
    ended: Ended,
) -> Vec<ProposalSummary> {
    let roster = state.core.roster();
    let active = roster
        .bindings()
        .map(|(_, b)| *b)
        .filter(|b| b.active_at(now));
    let finals = roster
        .ended()
        .map(|(_, e)| e.binding)
        .filter(|b| ended == Ended::Final && gives_final_read(b))
        .filter(|b| {
            b.proposal().is_some_and(|p| {
                fstp_domain::view::proposal_state(&state.core, p)
                    .is_some_and(fstp_domain::StateTag::is_terminal)
            })
        });
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for b in active.chain(finals) {
        let BindingScope::Proposal { proposal, call } = b.scope else {
            continue;
        };
        let receiving = matches!(
            b.role,
            Role::Applicant | Role::ApplicantTeamMember | Role::Guardian
        );
        if b.account != account || !receiving || !seen.insert(proposal) {
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
            title: None,
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
            stage2: matches!(a.kind, AssignmentKind::Reviewer)
                && a.active()
                && fstp_domain::view::proposal_state(&state.core, a.proposal)
                    == Some(fstp_domain::StateTag::Stage2),
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
    /// The team saves the private workspace of a draft (I-21).
    SaveWorkspace(ProposalId, Workspace),
    /// The lead states the country, to the vault only (R-NG-01).
    StateCountry(ProposalId, [u8; 2]),
    /// The lead declares affiliations, to the vault only (R-NG-01).
    DeclareAffiliations(ProposalId, crate::port::Affiliations),
    /// The lead states a date of birth, to the vault only (Q23 B, I-86).
    StateBirthDate(ProposalId, crate::port::BirthDate),
    /// The guardian starts the consent on the vault origin (I-18).
    BeginGuardianConsent(ProposalId),
    /// A team member acknowledges the negotiation notice (R-NG-06).
    AcknowledgeNotice(ProposalId),
    /// The user adds a passkey (`authentication.md`, high-risk).
    AddPasskey,
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
        // An actor refusal: these approvals are the tenant admin's role
        // (`roles-and-sod.md` roles table). R-AC-01 governs proposal
        // reads under P-10 only.
        return Err(call.refuse(ApiError::refused(ErrorCode::Refused, "actor")));
    }
    // Lane inv, J2: the invitation acceptance and its verification name
    // the invitation by its link token (`people`).
    match kind {
        PortKind::AcceptInvitation => return people::accept(call, op, account).await,
        PortKind::BeginInvitationVerification => {
            return people::begin_verification(call, op, account).await;
        }
        _ => {}
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
        // Adding a passkey is high-risk (`authentication.md`). Its channel
        // and step-up checks run before the seam, as the cell's
        // `/auth/passkeys` route runs them before its 501.
        PortKind::AddPasskey if call.spec.high_risk => PortCall::AddPasskey,
        PortKind::EndSession => PortCall::EndSession(SessionId::from_raw(id("session")?)),
        PortKind::BeginVerification => PortCall::BeginVerification,
        PortKind::SaveWorkspace => {
            let p = ProposalId::from_raw(id("proposal")?);
            let text = |name: &str| {
                op.request
                    .get(name)
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .ok_or_else(|| call.refuse(ApiError::bad_request(forms::REQUEST_RULE)))
            };
            let w = Workspace {
                title: text("title")?,
                summary: text("summary")?,
                narrative: text("narrative")?,
            };
            if !drafting_team(&call.state, account, p, call.now) {
                return Err(call.refuse(ApiError::refused(ErrorCode::Refused, "I-21")));
            }
            PortCall::SaveWorkspace(p, w)
        }
        PortKind::StateCountry => {
            let p = ProposalId::from_raw(id("proposal")?);
            let code = op
                .request
                .get("country")
                .and_then(Value::as_str)
                .and_then(country_code)
                .ok_or_else(|| call.refuse(ApiError::bad_request(forms::REQUEST_RULE)))?;
            if !drafting_team(&call.state, account, p, call.now) {
                return Err(call.refuse(ApiError::refused(ErrorCode::Refused, "R-NG-01")));
            }
            PortCall::StateCountry(p, code)
        }
        PortKind::DeclareAffiliations => {
            let p = ProposalId::from_raw(id("proposal")?);
            let d = op
                .request
                .get("affiliations")
                .and_then(Value::as_str)
                .and_then(crate::port::Affiliations::new)
                .ok_or_else(|| call.refuse(ApiError::bad_request(forms::REQUEST_RULE)))?;
            if !drafting_team(&call.state, account, p, call.now) {
                return Err(call.refuse(ApiError::refused(ErrorCode::Refused, "R-NG-01")));
            }
            PortCall::DeclareAffiliations(p, d)
        }
        PortKind::StateBirthDate => {
            let p = ProposalId::from_raw(id("proposal")?);
            let d = op
                .request
                .get("date_of_birth")
                .and_then(Value::as_str)
                .and_then(crate::port::BirthDate::parse)
                .ok_or_else(|| call.refuse(ApiError::bad_request(forms::REQUEST_RULE)))?;
            if !drafting_team(&call.state, account, p, call.now) {
                return Err(call.refuse(ApiError::refused(ErrorCode::Refused, "R-NG-01")));
            }
            PortCall::StateBirthDate(p, d)
        }
        PortKind::BeginGuardianConsent => {
            let p = ProposalId::from_raw(id("proposal")?);
            if !consenting_guardian(&call.state, account, p, call.now) {
                return Err(call.refuse(ApiError::refused(ErrorCode::Refused, "I-18")));
            }
            PortCall::BeginGuardianConsent(p)
        }
        PortKind::AcknowledgeNegotiationNotice => {
            let p = ProposalId::from_raw(id("proposal")?);
            let negotiating = fstp_domain::view::proposal_state(&call.state.core, p)
                == Some(fstp_domain::StateTag::Negotiation);
            let team = own_proposals(&call.state, account, call.now, Ended::Excluded)
                .iter()
                .any(|x| x.proposal == p);
            if !negotiating || !team {
                return Err(call.refuse(ApiError::refused(ErrorCode::Refused, "R-NG-06")));
            }
            PortCall::AcknowledgeNotice(p)
        }
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
        PortCall::AddPasskey => Err(call.refuse(ApiError::NotImplemented(
            "adding a passkey: no port registers a credential yet, and the cell's /auth/passkeys route answers 501",
        ))),
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
        PortCall::StateCountry(p, code) => {
            let fact = crate::port::VaultBound::new(crate::port::CountryCode(code));
            match call.ports.vault().state_country(account, p, fact).await {
                Ok(_) => done(Ok(()), "R-NG-01"),
                Err(_) => Err(call.refuse(ApiError::refused(ErrorCode::Unavailable, "oracle"))),
            }
        }
        PortCall::DeclareAffiliations(p, d) => {
            let fact = crate::port::VaultBound::new(d);
            match call
                .ports
                .vault()
                .declare_affiliations(account, p, fact)
                .await
            {
                Ok(_) => done(Ok(()), "R-NG-01"),
                Err(_) => Err(call.refuse(ApiError::refused(ErrorCode::Unavailable, "oracle"))),
            }
        }
        PortCall::StateBirthDate(p, d) => {
            let fact = crate::port::VaultBound::new(d);
            match call.ports.vault().state_birth_date(account, p, fact).await {
                Ok(_) => done(Ok(()), "I-86"),
                Err(_) => Err(call.refuse(ApiError::refused(ErrorCode::Unavailable, "oracle"))),
            }
        }
        PortCall::BeginGuardianConsent(p) => {
            let purpose = VerificationPurpose::GuardianConsent(p);
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
        PortCall::AcknowledgeNotice(p) => {
            // Kept in memory only until its ledger or outbox record exists
            // (`content.rs`, lane W6).
            if !lock(&call.st.content).acknowledge(account, p) {
                return Err(call.refuse(ApiError::refused(ErrorCode::Unavailable, "R-NG-06")));
            }
            done(Ok(()), "R-NG-06")
        }
        PortCall::SaveWorkspace(p, w) => {
            let saved = lock(&call.st.content).save(p, w);
            match saved {
                Ok(()) => done(Ok(()), "I-21"),
                Err(SaveError::TooLong) => {
                    Err(call.refuse(ApiError::bad_request(forms::REQUEST_RULE)))
                }
                Err(SaveError::Full) => {
                    Err(call.refuse(ApiError::refused(ErrorCode::Unavailable, "I-21")))
                }
            }
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
                Ok(to) => {
                    lock(&call.st.begun).begin(account, call.now);
                    call.accept(ReadModel::Redirect(to.0))
                }
                Err(_) => Err(call.refuse(ApiError::refused(ErrorCode::Unavailable, "oracle"))),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The read models of the review and applicant pages (design section 3.6)
// ---------------------------------------------------------------------------

/// The call of proposal `p`: the call of its latest Receiving binding,
/// active or ended, since a proposal that leaves the review, such as one
/// NOT_SELECTED, ends its team's bindings (interim, pending a public
/// accessor of the domain).
fn call_of(state: &EngineState, p: ProposalId) -> Option<CallId> {
    let roster = state.core.roster();
    roster
        .bindings()
        .map(|(_, b)| *b)
        .chain(roster.ended().map(|(_, e)| e.binding))
        .filter_map(|b| match b.scope {
            BindingScope::Proposal { proposal, call } if proposal == p => {
                Some((b.opened, b.start, call))
            }
            _ => None,
        })
        .max()
        .map(|(_, _, call)| call)
}

/// The `proposal` path parameter of a read.
fn proposal_param<P: Seams>(call: &Call<'_, P>, op: &Op) -> Result<ProposalId, ApiError> {
    forms::id_param(&op.request, "proposal")
        .map(ProposalId::from_raw)
        .ok_or_else(|| call.refuse(ApiError::bad_request(forms::REQUEST_RULE)))
}

/// The assignment path parameter `name` of a read.
fn assignment_param<P: Seams>(
    call: &Call<'_, P>,
    op: &Op,
    name: &str,
) -> Result<AssignmentId, ApiError> {
    forms::id_param(&op.request, name)
        .map(AssignmentId::from_raw)
        .ok_or_else(|| call.refuse(ApiError::bad_request(forms::REQUEST_RULE)))
}

/// The `call` path parameter of a read.
fn call_param<P: Seams>(call: &Call<'_, P>, op: &Op) -> Result<CallId, ApiError> {
    forms::id_param(&op.request, "call")
        .map(CallId::from_raw)
        .ok_or_else(|| call.refuse(ApiError::bad_request(forms::REQUEST_RULE)))
}

/// The content `p` was submitted with. A proposal this core never saw
/// submitted has none, and the read fails closed (`content.rs`).
fn submitted_content<P: Seams>(call: &Call<'_, P>, p: ProposalId) -> Result<Workspace, ApiError> {
    lock(&call.st.content)
        .submitted(p)
        .cloned()
        .ok_or_else(|| call.refuse(content_unknown()))
}

/// Every proposal of call `c`, active or ended, in id order.
fn proposals_of_call(state: &EngineState, c: CallId) -> Vec<ProposalId> {
    let roster = state.core.roster();
    let seen: BTreeSet<ProposalId> = roster
        .bindings()
        .map(|(_, b)| b.scope)
        .chain(roster.ended().map(|(_, e)| e.binding.scope))
        .filter_map(|s| match s {
            BindingScope::Proposal { proposal, .. } => Some(proposal),
            _ => None,
        })
        .collect();
    seen.into_iter()
        .filter(|p| call_of(state, *p) == Some(c))
        .collect()
}

/// The state tag of `p` as the pages spell it.
fn state_name(state: &EngineState, p: ProposalId) -> &'static str {
    fstp_domain::view::proposal_state(&state.core, p).map_or("UNKNOWN", |t| t.spec_name())
}

/// A content read (R-AU-01, R-AC-01, I-03): the domain `ReadContent`
/// appends a `ContentRead` and re-runs every guard, then the submitted
/// content is returned. The append carries the call's one audit entry.
/// `outcome` names the outcome of an IRC case (R-IR-03).
async fn content_read<P: Seams>(
    call: &Call<'_, P>,
    p: ProposalId,
    outcome: Option<&'static str>,
) -> Result<OpResult, ApiError> {
    if call.account().is_none() {
        return Err(call.refuse(ApiError::refused(ErrorCode::Unauthenticated, "actor")));
    }
    // A draft has no submitted content. Only its team reads it (I-21), as
    // `authorize_read` and the domain's `ReadContent` both check, and the
    // team reads its latest workspace (R-AC-01).
    let draft = fstp_domain::view::proposal_state(&call.state.core, p)
        == Some(fstp_domain::StateTag::Draft);
    let content = if draft {
        lock(&call.st.content)
            .workspace(p)
            .ok_or_else(|| call.refuse(content_unknown()))?
    } else {
        submitted_content(call, p)?
    };
    let seq = append_content_read(call, p).await?;
    let view = crate::views::ContentView {
        proposal: p.raw(),
        call: call_of(&call.state, p).map_or(0, CallId::raw),
        state: state_name(&call.state, p),
        title: content.title,
        text: content.narrative,
        outcome,
    };
    Ok(OpResult::Done {
        body: ReadModel::Content(view),
        seq: Some(seq),
    })
}

/// Runs the domain `ReadContent` of `p` by the caller, through the
/// caller's channel: it re-runs every read guard and appends one
/// `ContentRead` (R-AU-01, I-03). The append carries the call's one audit
/// entry.
async fn append_content_read<P: Seams>(
    call: &Call<'_, P>,
    p: ProposalId,
) -> Result<fstp_ledger::Seq, ApiError> {
    let Some(account) = call.account() else {
        return Err(call.refuse(ApiError::refused(ErrorCode::Unauthenticated, "actor")));
    };
    let cmd = Command::Core(fstp_domain::command::Command::ReadContent { proposal: p });
    let command_id = CommandId::from_bytes(call.draw().map_err(|e| call.refuse(e))?.to_be_bytes());
    let ctx = call.ctx(account, &cmd, call.caller.via(), command_id);
    let meta = ExecMeta {
        via: call.caller.via(),
        session: call.caller.session,
        agent: call.caller.agent,
        op: OpName(call.spec.name),
        request: call.digest,
        step_up: None,
        pending: None,
        second_tenant_admin: None,
    };
    call.ports
        .engine()
        .execute(cmd, ctx, meta)
        .await
        .map_err(|e| call.refuse(exec_failed(e)))
}

/// The text behind `r`: one this core stored, else a public text of the
/// text store. A text neither holds fails the read closed.
async fn text_of<P: Seams>(call: &Call<'_, P>, r: TextRef) -> Result<String, ApiError> {
    if let Some(t) = lock(&call.st.content).text(r) {
        return Ok(t.to_owned());
    }
    let bytes = call
        .ports
        .texts()
        .get_public(crate::port::PublicTextRef(r.id().raw()))
        .await
        .map_err(|e| call.refuse(port_failed(e, "text")))?;
    String::from_utf8(bytes)
        .map_err(|_| call.refuse(ApiError::refused(ErrorCode::Unavailable, "text")))
}

/// The frozen values of the published call `c`.
fn frozen_values<'a, P: Seams>(
    call: &'a Call<'_, P>,
    c: CallId,
) -> Result<&'a fstp_domain::policy::FrozenValues, ApiError> {
    call.state
        .core
        .calls()
        .get(c)
        .and_then(|v| v.frozen())
        .map(|f| f.values())
        .ok_or_else(|| call.refuse(ApiError::refused(ErrorCode::NotFound, "Input")))
}

/// The P-09 knock-out criteria of call `c`, with their wording.
async fn knock_out_criteria<P: Seams>(
    call: &Call<'_, P>,
    c: CallId,
) -> Result<Vec<crate::views::KnockOutCriterion>, ApiError> {
    let items: Vec<(u128, TextRef)> = frozen_values(call, c)?
        .p09
        .0
        .iter()
        .map(|k| (k.id.raw(), k.text))
        .collect();
    let mut out = Vec::new();
    for (id, text) in items {
        out.push(crate::views::KnockOutCriterion {
            id,
            text: text_of(call, text).await?,
        });
    }
    Ok(out)
}

/// Every proposal of call `c` whose state `keep` admits, in id order,
/// with its submitted title. A row whose submitted content this core does
/// not hold fails the read closed (`content.rs`).
fn proposal_rows<P: Seams>(
    call: &Call<'_, P>,
    c: CallId,
    keep: impl Fn(fstp_domain::StateTag) -> bool,
) -> Result<Vec<crate::views::ProposalRow>, ApiError> {
    let content = lock(&call.st.content);
    let mut out = Vec::new();
    for p in proposals_of_call(&call.state, c) {
        let Some(tag) = fstp_domain::view::proposal_state(&call.state.core, p) else {
            continue;
        };
        if !keep(tag) {
            continue;
        }
        let title = content
            .submitted(p)
            .map(|w| w.title.clone())
            .ok_or_else(|| call.refuse(content_unknown()))?;
        out.push(crate::views::ProposalRow {
            proposal: p.raw(),
            state: tag.spec_name(),
            title,
        });
    }
    Ok(out)
}

/// The P-01 label of criterion `id`. The domain holds no criterion
/// wording, and the creator artefacts that do are not in the engine
/// state yet (lane W2e), so the label names the criterion by number.
fn criterion_label(id: u128) -> String {
    format!("Criterion {id}")
}

/// The findings on the proposal of assignment `a` from the assignment's
/// call, which keeps them (Q15), with the viewer's own marks (I-10).
fn findings<P: Seams>(
    call: &Call<'_, P>,
    a: AssignmentId,
    viewer: AccountId,
) -> Result<Vec<crate::views::FindingRow>, ApiError> {
    use fstp_engine::{FindingKind, Mark, Severity};
    let assignment = call
        .state
        .core
        .review()
        .get(a)
        .ok_or_else(|| call.refuse(ApiError::refused(ErrorCode::NotFound, "Input")))?;
    let store = &call.state.findings;
    Ok(store
        .findings_of(assignment.call)
        .into_iter()
        .filter(|f| f.proposal == assignment.proposal)
        .map(|f| crate::views::FindingRow {
            finding: f.id.raw(),
            kind: match f.kind {
                FindingKind::Completeness => "Completeness",
                FindingKind::Quality => "Quality",
                FindingKind::Accuracy => "Accuracy",
                FindingKind::Integrity => "Integrity",
            },
            severity: match f.severity {
                Severity::Info => "Info",
                Severity::Minor => "Minor",
                Severity::Major => "Major",
            },
            confidence: f.confidence.permille(),
            statement: f.statement.as_data().to_owned(),
            mark: store
                .marks_of(f.id)
                .filter(|(by, _)| *by == viewer)
                .last()
                .map(|(_, m)| match m {
                    Mark::Agreed => "Agreed",
                    Mark::Disputed => "Disputed",
                }),
        })
        .collect())
}

/// The score sheet of reviewer assignment `a`: the stage of its proposal,
/// the plan that stage scores, the P-01 scale and the current score.
fn score_sheet<P: Seams>(
    call: &Call<'_, P>,
    a: AssignmentId,
) -> Result<crate::views::ScoreSheet, ApiError> {
    use fstp_domain::scoring::{ScoreKey, Stage};
    let assignment = call
        .state
        .core
        .review()
        .get(a)
        .ok_or_else(|| call.refuse(ApiError::refused(ErrorCode::NotFound, "Input")))?;
    let p = assignment.proposal;
    let tag = fstp_domain::view::proposal_state(&call.state.core, p);
    let journal = lock(&call.st.journal);
    let unknown = |Unknown| call.refuse(history_unknown());
    let submitted = journal.submitted_plan(p).map_err(unknown)?;
    let (stage, plan) = match tag {
        Some(fstp_domain::StateTag::Stage2) => (
            Stage::Two,
            journal.last_revision(p).map_err(unknown)?.or(submitted),
        ),
        _ => (Stage::One, submitted),
    };
    // A known proposal with no submitted plan has nothing to score.
    let plan =
        plan.ok_or_else(|| call.refuse(ApiError::refused(ErrorCode::Unavailable, "content")))?;
    let current = journal
        .score(&ScoreKey {
            assignment: a,
            stage,
            plan,
        })
        .map(|v| (plan.raw(), v.to_vec()));
    drop(journal);
    let p01 = &frozen_values(call, assignment.call)?.p01;
    let max = p01.scale_max().get();
    let criteria = p01
        .items()
        .iter()
        .map(|c| crate::views::SheetCriterion {
            id: c.id.raw(),
            text: criterion_label(c.id.raw()),
            max,
        })
        .collect();
    Ok(crate::views::ScoreSheet {
        stage: match stage {
            Stage::One => "One",
            Stage::Two => "Two",
        },
        plan: plan.raw(),
        criteria,
        current,
    })
}

/// A P-11 handle as the pages show it: `R-` and its first four bytes in
/// hex. It names no account (R-AN-01).
pub(crate) fn handle_text(h: fstp_domain::id::Handle) -> String {
    let b = h.bytes();
    let head: Vec<u8> = b.iter().take(4).copied().collect();
    format!("R-{}", crate::action::hex(&head))
}

/// The UTC day of `t`, `YYYY-MM-DD` (TH-08: applicants see days only).
pub(crate) fn utc_day(t: Timestamp) -> String {
    let days = t.micros().div_euclid(86_400_000_000);
    // Howard Hinnant's civil-from-days, on integers only.
    let z = days.saturating_add(719_468);
    let era = z.div_euclid(146_097);
    let doe = z.saturating_sub(era.saturating_mul(146_097));
    let yoe = doe
        .saturating_sub(doe.div_euclid(1_460))
        .saturating_add(doe.div_euclid(36_524))
        .saturating_sub(doe.div_euclid(146_096))
        .div_euclid(365);
    let y = yoe.saturating_add(era.saturating_mul(400));
    let doy = doe.saturating_sub(
        yoe.saturating_mul(365)
            .saturating_add(yoe.div_euclid(4))
            .saturating_sub(yoe.div_euclid(100)),
    );
    let mp = doy.saturating_mul(5).saturating_add(2).div_euclid(153);
    let d = doy
        .saturating_sub(mp.saturating_mul(153).saturating_add(2).div_euclid(5))
        .saturating_add(1);
    let m = if mp < 10 {
        mp.saturating_add(3)
    } else {
        mp.saturating_sub(9)
    };
    let y = if m <= 2 { y.saturating_add(1) } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

/// The stage 2 thread of reviewer assignment `a` (R-EV-05).
fn stage2_thread<P: Seams>(
    call: &Call<'_, P>,
    a: AssignmentId,
) -> Result<crate::views::Stage2Thread, ApiError> {
    use fstp_domain::assignment::AssignmentKind;
    let review = call.state.core.review();
    let assignment = review
        .get(a)
        .ok_or_else(|| call.refuse(ApiError::refused(ErrorCode::NotFound, "Input")))?;
    let p = assignment.proposal;
    let tag = fstp_domain::view::proposal_state(&call.state.core, p);
    let journal = lock(&call.st.journal);
    // The "no questions" marks are read only for a known proposal.
    let entries: Vec<ThreadEntry> = journal
        .thread(p)
        .map_err(|Unknown| call.refuse(history_unknown()))?
        .to_vec();
    let everyone_done = review
        .assignments()
        .filter(|(_, x)| x.proposal == p && x.kind == AssignmentKind::Reviewer && x.active())
        .all(|(id, _)| journal.no_questions(id));
    let open = tag == Some(fstp_domain::StateTag::Stage2) && !everyone_done;
    let own = journal.no_questions(a);
    drop(journal);
    let content = lock(&call.st.content);
    let mut items = Vec::new();
    for e in entries {
        let item = match e {
            ThreadEntry::Question {
                assignment: by,
                text,
                at,
            } => crate::views::ThreadItem {
                kind: "question",
                author: review.get(by).and_then(|x| x.handle).map(handle_text),
                text: known_text(call, &content, text)?,
                day: utc_day(at),
            },
            ThreadEntry::Answer { text, at } => crate::views::ThreadItem {
                kind: "answer",
                author: None,
                text: known_text(call, &content, text)?,
                day: utc_day(at),
            },
        };
        items.push(item);
    }
    Ok(crate::views::Stage2Thread {
        state: tag.map_or("UNKNOWN", |t| t.spec_name()),
        open,
        own_no_questions: own,
        entries: items,
    })
}

/// The text this core stored under `r`. A text it did not store fails
/// the read closed (`content.rs`), never showing an empty text.
fn known_text<P: Seams>(
    call: &Call<'_, P>,
    content: &ContentStore,
    r: TextRef,
) -> Result<String, ApiError> {
    content
        .text(r)
        .map(str::to_owned)
        .ok_or_else(|| call.refuse(text_unknown()))
}

/// The committee ranking view of call `c` for `viewer` (R-EV-08, Q16, D9,
/// D10): a row with a conflict fact for the viewer shows "recused" only.
fn ranking<P: Seams>(
    call: &Call<'_, P>,
    c: CallId,
    viewer: AccountId,
) -> Result<Vec<crate::views::RankingRow>, ApiError> {
    let rows = fstp_domain::visibility::ranking_view(&call.state.core, c)
        .map_err(|r| call.refuse(refusal(r)))?;
    let review = call.state.core.review();
    let content = lock(&call.st.content);
    let text = |r: Option<TextRef>| -> Result<Option<String>, ApiError> {
        r.map(|r| known_text(call, &content, r)).transpose()
    };
    let overflow = || call.refuse(ApiError::refused(ErrorCode::Unavailable, "ranking"));
    let mut out = Vec::new();
    for row in rows {
        if review.conflict_fact(viewer, row.proposal) {
            out.push(crate::views::RankingRow::Recused {
                proposal: row.proposal.raw(),
            });
            continue;
        }
        let effective = fstp_domain::decision::effective_score(&call.state.core, row.proposal)
            .map(|e| e.value())
            .ok_or_else(overflow)?;
        let effective = crate::views::two_decimals(effective.num(), effective.den().get(), 100)
            .ok_or_else(overflow)?;
        let mut scores = Vec::new();
        for (criterion, r) in &row.criterion_scores {
            scores.push(crate::views::CriterionScore {
                criterion: criterion.raw(),
                weighted: crate::views::two_decimals(r.num(), r.den().get(), 1)
                    .ok_or_else(overflow)?,
            });
        }
        out.push(crate::views::RankingRow::Ranked {
            proposal: row.proposal.raw(),
            title: text(row.title)?,
            neutral_summary: text(row.neutral_summary)?,
            rationale: text(row.rationale)?,
            effective,
            criterion_scores: scores,
            requested: row.requested.amount().to_string(),
            remaining_budget: row.remaining_budget.to_string(),
        });
    }
    Ok(out)
}

/// The refusal of a read of a cut-off round this core did not see
/// opened (`journal.rs`, fail closed).
fn round_unknown() -> ApiError {
    ApiError::NotImplemented(
        "a cut-off round opened outside this API core: a domain read accessor of the rounds (lane W1b)",
    )
}

/// The `round` path parameter of a read.
fn round_param<P: Seams>(call: &Call<'_, P>, op: &Op) -> Result<DecisionId, ApiError> {
    forms::id_param(&op.request, "round")
        .map(DecisionId::from_raw)
        .ok_or_else(|| call.refuse(ApiError::bad_request(forms::REQUEST_RULE)))
}

/// The read target of a round: its call, from the journal (change D5).
///
/// A round this core did not see opened resolves to a call the state
/// does not hold. `authorize_read` judges such a target against a
/// context in which no relation holds (`reads.rs`). So a caller with no
/// account is refused as an actor, and every other caller gets the
/// COMMITTEE rule's own R-AC-01, as an outsider of a known round does.
/// The refusal then tells no caller whether such a round exists, and
/// none reaches the read model. Interim, pending a domain read of the
/// rounds (lane W1b): a member of the round's own committee is refused
/// in the same way.
fn round_target<P: Seams>(call: &Call<'_, P>, op: &Op) -> Result<ReadTarget, ApiError> {
    let r = round_param(call, op)?;
    let known = lock(&call.st.journal).round(r).map(|x| x.call);
    Ok(ReadTarget::Call(
        known.unwrap_or_else(|| absent_call(&call.state)),
    ))
}

/// A call id the state does not hold: the least such raw value. The
/// search ends within one more step than the state has calls.
fn absent_call(state: &EngineState) -> CallId {
    let calls = state.core.calls();
    (0..=u128::MAX)
        .map(CallId::from_raw)
        .find(|c| calls.get(*c).is_none())
        .unwrap_or(CallId::from_raw(u128::MAX))
}

/// The calls of programme `p` in call order, each with its state and
/// whether `viewer` may approve it at `now` (R-PC-03): a draft call, and
/// an active programme manager binding of `viewer` on `p` outside the
/// call's drafters. The domain guard decides an approval again.
fn staff_calls(
    core: &fstp_domain::State,
    p: ProgrammeId,
    viewer: AccountId,
    now: Timestamp,
) -> Vec<crate::model::StaffCallRow> {
    let manager = core.roster().bindings().any(|(_, b)| {
        b.account == viewer
            && b.programme == p
            && b.role == Role::ProgrammeManager
            && b.active_at(now)
    });
    core.calls()
        .iter()
        .filter(|(_, v)| v.programme() == p)
        .map(|(c, v)| {
            let status = v.status();
            let drafter =
                fstp_domain::programme::drafters(core, c).is_none_or(|d| d.contains(&viewer));
            crate::model::StaffCallRow {
                call: c,
                status,
                may_approve: manager
                    && !drafter
                    && status == fstp_domain::programme::CallStatus::Draft,
            }
        })
        .collect()
}

/// Admits one read that asks the vault, under the per-account limit of
/// H-07: each answer such a read shows tells the caller one bit about
/// other people. The limit is checked before the first question and
/// charged once per read.
fn vault_read_admitted<P: Seams>(call: &Call<'_, P>, account: AccountId) -> Result<(), ApiError> {
    let limit = rate::DRY_RUN_VAULT_PER_ACCOUNT;
    let admitted = {
        let mut rates = lock(&call.st.rates);
        let ok = rates.admits(&Key::VaultDryRun(account), limit, call.now);
        if ok {
            rates.hit(Key::VaultDryRun(account), limit, call.now);
        }
        ok
    };
    if admitted {
        Ok(())
    } else {
        Err(call.refuse(ApiError::refused(ErrorCode::RateLimited, "H-07")))
    }
}

/// One vault answer of a read, recorded as its query digest and answer
/// bit (`overview.md` NOTE 5). A vault that cannot answer, or a record
/// that fails, refuses the read (fail closed).
async fn ask_vault<P: Seams>(call: &Call<'_, P>, q: &Query) -> Result<Answer, ApiError> {
    let a = call
        .ports
        .vault()
        .answer(q)
        .await
        .map_err(|_| call.refuse(ApiError::refused(ErrorCode::Unavailable, "oracle")))?;
    call.ports
        .vault_audit()
        .record(QueryDigest(a.digest.bytes()), a.holds, a.epoch)
        .await
        .map_err(|e| call.refuse(port_failed(e, "NOTE 5")))?;
    Ok(a)
}

/// The label of a Judging member: the pseudonymous display handle of
/// the accounts port. Never an email (I-17, R-CF-03).
async fn label_of<P: Seams>(call: &Call<'_, P>, a: AccountId) -> Result<String, ApiError> {
    call.ports
        .accounts()
        .display_handle(a)
        .await
        .map(|h| h.0)
        .map_err(|e| call.refuse(port_failed(e, "label")))
}

/// The organisation on the active committee member binding of `account`
/// in `programme` at `now`, as SoD-10 and I-34 count it. `None` for no
/// such binding, or one with no organisation.
fn committee_organisation(
    state: &EngineState,
    account: AccountId,
    programme: ProgrammeId,
    now: Timestamp,
) -> Option<OrganisationId> {
    state
        .core
        .roster()
        .bindings()
        .map(|(_, b)| b)
        .find(|b| {
            b.account == account
                && b.role == Role::CommitteeMember
                && b.programme == programme
                && b.scope == BindingScope::Programme
                && b.active_at(now)
        })
        .and_then(|b| b.organisation)
}

/// `review.assignments`: one proposal's assignment view for the FSTP
/// coordinator (R-AC-01, R-CF-03, J5). Assignees and candidates appear
/// by label only. The checks state pass or fail, with no reason and no
/// account:
///
/// - SoD-10 and I-34: the unreleased reviewer assignees span at least
///   P-39 organisations, read from their committee bindings. An unknown
///   organisation fails the check, as the domain fails closed on it.
/// - SoD-11 and I-35: for each assignee whose organisation has a P-38
///   list, the vault answers whether a team member declares an
///   affiliation on it. The check passes when no answer holds. Each
///   answer is recorded (`overview.md` NOTE 5), and the read is limited
///   as H-07 limits dry runs.
///
/// The domain runs both guards again at every assignment and admission.
async fn assignment_view<P: Seams>(
    call: &Call<'_, P>,
    p: ProposalId,
) -> Result<crate::model::AssignmentView, ApiError> {
    use crate::model::{AssignedRow, AssignmentChecks, AssignmentView, CandidateRow};
    let Some(account) = call.account() else {
        return Err(call.refuse(ApiError::refused(ErrorCode::Unauthenticated, "actor")));
    };
    let not_found = || call.refuse(ApiError::refused(ErrorCode::NotFound, "Input"));
    let board = crate::model::assignment_board(&call.state, p, call.now).ok_or_else(not_found)?;
    let c = call_of(&call.state, p).ok_or_else(not_found)?;
    let programme = forms::programme_of_call(&call.state, c).ok_or_else(not_found)?;
    let p39 = usize::from(frozen_values(call, c)?.p39.get());
    let orgs: Option<BTreeSet<OrganisationId>> = board
        .assigned
        .iter()
        .map(|a| committee_organisation(&call.state, a.reviewer, programme, call.now))
        .collect();
    let p39_pass = orgs.is_some_and(|o| o.len() >= p39);
    let team: BTreeSet<AccountId> = call
        .state
        .core
        .roster()
        .bindings()
        .map(|(_, b)| b)
        .filter(|b| b.held() && b.proposal() == Some(p))
        .map(|b| b.account)
        .collect();
    let lists = fstp_domain::policy::live_values(&call.state.core, programme).map(|l| &l.p38.0);
    let mut queries: Vec<Query> = Vec::new();
    for a in &board.assigned {
        let list = committee_organisation(&call.state, a.reviewer, programme, call.now)
            .and_then(|org| lists.and_then(|l| l.get(&org)).copied());
        if let Some(list) = list {
            let q = Query::DeclaresAffiliationOnList {
                team: team.clone(),
                list,
            };
            if !queries.contains(&q) {
                queries.push(q);
            }
        }
    }
    if !queries.is_empty() {
        vault_read_admitted(call, account)?;
    }
    let mut proximity_pass = true;
    for q in &queries {
        if ask_vault(call, q).await?.holds {
            proximity_pass = false;
        }
    }
    let mut assigned = Vec::new();
    for a in &board.assigned {
        assigned.push(AssignedRow {
            assignment: a.assignment,
            label: label_of(call, a.reviewer).await?,
        });
    }
    let mut candidates = Vec::new();
    for m in &board.candidates {
        candidates.push(CandidateRow {
            account: *m,
            label: label_of(call, *m).await?,
        });
    }
    Ok(AssignmentView::new(
        board.state,
        assigned,
        candidates,
        AssignmentChecks {
            p39: p39_pass,
            proximity: proximity_pass,
        },
    ))
}

/// `me.get_verification`: the caller's own verification state (I-86).
/// The vault is asked `IsVerified` for the caller's account and no
/// other, and the answer is recorded (`overview.md` NOTE 5). A
/// verification the caller began through this core reads "pending"
/// until the vault confirms it, for at most
/// [`VERIFICATION_PENDING_MICROS`] (interim, see there). It then reads
/// "unverified" again.
async fn own_verification<P: Seams>(
    call: &Call<'_, P>,
    account: AccountId,
) -> Result<crate::model::VerificationState, ApiError> {
    use crate::model::{VerificationState, VerificationStatus};
    let answer = ask_vault(call, &Query::IsVerified { account }).await?;
    let begun = lock(&call.st.begun).pending(account, call.now);
    Ok(VerificationState {
        status: VerificationStatus::of(answer.holds, begun),
    })
}

/// The active committee members and chairs of `programme` at `now`: the
/// members of its cut-off votes.
fn committee_members(
    state: &EngineState,
    programme: ProgrammeId,
    now: Timestamp,
) -> BTreeSet<AccountId> {
    state
        .core
        .roster()
        .bindings()
        .map(|(_, b)| b)
        .filter(|b| {
            matches!(b.role, Role::CommitteeMember | Role::CommitteeChair)
                && b.programme == programme
                && b.scope == BindingScope::Programme
                && b.active_at(now)
        })
        .map(|b| b.account)
        .collect()
}

/// `committee.round`: one cut-off round for committee member `viewer`
/// (R-EV-08, R-EV-09, P-16 NOTE 8, change D5).
///
/// - The status is open, recorded or superseded. Only an open round takes
///   ballots, delegations and the record of its cut-off.
/// - The order lists the proposals the round was opened with, by id, with
///   their states now. It counts the ballots and names no voter.
/// - The viewer reads their own ballot or delegation only. While the
///   round is open, the vault is asked the recusal questions of the
///   viewer (Conflict declarations). A recused viewer gets no delegates.
///   On a round that is not open no recusal is judged, so it reads null.
/// - The delegates are the members the domain would accept a delegation
///   to: active members of the committee other than the viewer, who have
///   not delegated and hold no delegated vote, and are not recused. They
///   are offered only to a viewer who may still delegate.
///
/// Every vault answer is recorded (`overview.md` NOTE 5), and the read is
/// limited as H-07 limits dry runs. A round this core did not see opened
/// fails closed.
async fn round_view<P: Seams>(
    call: &Call<'_, P>,
    r: DecisionId,
    viewer: AccountId,
) -> Result<crate::model::RoundView, ApiError> {
    use crate::model::{CandidateRow, RoundRow, RoundView, RoundViewer};
    let facts = lock(&call.st.journal).round(r).cloned();
    let facts = facts.ok_or_else(|| call.refuse(round_unknown()))?;
    let core = &call.state.core;
    let programme = forms::programme_of_call(&call.state, facts.call)
        .ok_or_else(|| call.refuse(ApiError::refused(ErrorCode::NotFound, "Input")))?;
    let mut order = Vec::new();
    for p in &facts.order {
        let state = fstp_domain::view::proposal_state(core, *p)
            .ok_or_else(|| call.refuse(ApiError::refused(ErrorCode::Unavailable, "ranking")))?;
        order.push(RoundRow {
            proposal: *p,
            state,
        });
    }
    let (rationale, tie_break) = {
        let content = lock(&call.st.content);
        let rationale = known_text(call, &content, facts.rationale)?;
        let tie_break = facts
            .tie_breaks
            .map(|t| known_text(call, &content, t))
            .transpose()?;
        (rationale, tie_break)
    };
    let open = facts.status == RoundStatus::Open;
    let own_vote = facts.cast.get(&viewer).copied();
    let delegated_to = facts.delegated.get(&viewer).copied();
    let holds_vote = |m: &AccountId| facts.delegated.values().any(|t| t == m);
    let members = committee_members(&call.state, programme, call.now);
    let may_delegate = open
        && members.contains(&viewer)
        && own_vote.is_none()
        && delegated_to.is_none()
        && !holds_vote(&viewer);
    let candidates: Vec<AccountId> = if may_delegate {
        members
            .iter()
            .filter(|m| **m != viewer && !facts.delegated.contains_key(m) && !holds_vote(m))
            .copied()
            .collect()
    } else {
        Vec::new()
    };
    let asked: Vec<AccountId> = if open {
        std::iter::once(viewer)
            .chain(candidates.iter().copied())
            .collect()
    } else {
        Vec::new()
    };
    let mut queries: Vec<Query> = Vec::new();
    for m in &asked {
        for q in fstp_domain::assignment::cut_off_recusal_queries(core, *m, facts.call) {
            if !queries.contains(&q) {
                queries.push(q);
            }
        }
    }
    if !queries.is_empty() {
        vault_read_admitted(call, viewer)?;
    }
    let mut answers = fstp_domain::oracle::Answers::new();
    for q in queries {
        let a = ask_vault(call, &q).await?;
        answers.insert(q, a);
    }
    let recused = |m: AccountId| -> Result<bool, ApiError> {
        if !open {
            return Ok(false);
        }
        fstp_domain::assignment::recused_from_cut_off(core, m, facts.call, &answers)
            .map_err(|e| call.refuse(refusal(e)))
    };
    let viewer_recused = recused(viewer)?;
    let mut delegates = Vec::new();
    if !viewer_recused {
        for m in candidates {
            if !recused(m)? {
                delegates.push(CandidateRow {
                    account: m,
                    label: label_of(call, m).await?,
                });
            }
        }
    }
    Ok(RoundView {
        round: r,
        call: facts.call,
        status: match facts.status {
            RoundStatus::Open => crate::model::RoundStatus::Open,
            RoundStatus::Recorded => crate::model::RoundStatus::Recorded,
            RoundStatus::Superseded => crate::model::RoundStatus::Superseded,
        },
        order,
        nominated: facts.nominated,
        rationale,
        tie_break,
        ballots_cast: u32::try_from(facts.cast.len()).unwrap_or(u32::MAX),
        viewer: RoundViewer {
            recused: open.then_some(viewer_recused),
            own_vote,
            delegated_to,
        },
        delegates,
    })
}

/// Whether `account` holds an active Receiving binding of the lead or a
/// team member on `proposal` at `now`, and the proposal is a draft: the
/// workspace is the drafting team's alone (I-21). A guardian consents and
/// does not write the form.
fn drafting_team(
    state: &EngineState,
    account: AccountId,
    proposal: ProposalId,
    now: Timestamp,
) -> bool {
    let member = state.core.roster().bindings().any(|(_, b)| {
        b.account == account
            && b.active_at(now)
            && matches!(b.role, Role::Applicant | Role::ApplicantTeamMember)
            && matches!(b.scope, BindingScope::Proposal { proposal: x, .. } if x == proposal)
    });
    member
        && fstp_domain::view::proposal_state(&state.core, proposal)
            == Some(fstp_domain::StateTag::Draft)
}

/// Whether `account` is the guardian of `proposal` while its consent is
/// open: an active Guardian binding on it, in IRC_REVIEW or NEGOTIATION
/// (state-machine NOTE 14, R-NG-01 NOTE). The vault decides the rest.
fn consenting_guardian(
    state: &EngineState,
    account: AccountId,
    proposal: ProposalId,
    now: Timestamp,
) -> bool {
    let guardian = state.core.roster().bindings().any(|(_, b)| {
        b.account == account
            && b.active_at(now)
            && b.role == Role::Guardian
            && matches!(b.scope, BindingScope::Proposal { proposal: x, .. } if x == proposal)
    });
    guardian
        && matches!(
            fstp_domain::view::proposal_state(&state.core, proposal),
            Some(fstp_domain::StateTag::IrcReview | fstp_domain::StateTag::Negotiation)
        )
}

/// A country code of the vault intake: two upper-case ASCII letters
/// (ISO 3166-1 alpha-2 spelling; the vault judges the code itself).
fn country_code(s: &str) -> Option<[u8; 2]> {
    match s.as_bytes() {
        [a, b] if a.is_ascii_uppercase() && b.is_ascii_uppercase() => Some([*a, *b]),
        _ => None,
    }
}

/// The stage 2 questions of `p` under their P-11 handles, each with the
/// day it was asked only (TH-08). The answers stay with the team's own
/// form.
fn own_questions<P: Seams>(
    call: &Call<'_, P>,
    p: ProposalId,
) -> Result<Vec<crate::views::Question>, ApiError> {
    let review = call.state.core.review();
    let entries: Vec<ThreadEntry> = lock(&call.st.journal)
        .thread(p)
        .map_err(|Unknown| call.refuse(history_unknown()))?
        .to_vec();
    let content = lock(&call.st.content);
    let mut out = Vec::new();
    for e in entries {
        if let ThreadEntry::Question {
            assignment,
            text,
            at,
        } = e
        {
            out.push(crate::views::Question {
                handle: review
                    .get(assignment)
                    .and_then(|x| x.handle)
                    .map_or_else(|| "R".to_owned(), handle_text),
                asked: utc_day(at),
                text: known_text(call, &content, text)?,
            });
        }
    }
    Ok(out)
}

/// The caller's notices (R-EV-04, R-IR-02): the outcome of each proposal
/// of theirs that left the review as NOT_SELECTED, and each IRC concern
/// raised on one. Interim, pending the outbox port: they are derived from
/// the state and the journal, and sent within P-08 from M6. A submitted
/// proposal the journal does not know fails the read closed.
fn notices<P: Seams>(
    call: &Call<'_, P>,
    account: AccountId,
) -> Result<Vec<crate::views::Notice>, ApiError> {
    let mut mine = BTreeSet::new();
    let roster = call.state.core.roster();
    let receiving = roster
        .bindings()
        .map(|(_, b)| *b)
        .chain(roster.ended().map(|(_, e)| e.binding));
    for b in receiving {
        if let BindingScope::Proposal { proposal, .. } = b.scope
            && b.account == account
        {
            mine.insert(proposal);
        }
    }
    let journal = lock(&call.st.journal);
    let mut out = Vec::new();
    for p in mine {
        let tag = fstp_domain::view::proposal_state(&call.state.core, p);
        if tag.is_none_or(|t| t == fstp_domain::StateTag::Draft) {
            continue;
        }
        if tag == Some(fstp_domain::StateTag::NotSelected) {
            out.push(crate::views::Notice {
                kind: "ProposalOutcome",
                proposal: p.raw(),
                day: None,
            });
        }
        let concern = journal
            .concern(p)
            .map_err(|Unknown| call.refuse(history_unknown()))?;
        if let Some(at) = concern {
            out.push(crate::views::Notice {
                kind: "IrcConcern",
                proposal: p.raw(),
                day: Some(utc_day(at)),
            });
        }
    }
    Ok(out)
}

/// The body of a recorded plan: the id the server drew for it, which a
/// stage 2 revision names (R-EV-05), and its total, summed by the cell
/// (ADR-006, design section 3.9). `None` for any other command, or a
/// total that does not fit.
fn plan_saved(cmd: &Command) -> Option<ReadModel> {
    let core = match cmd {
        Command::Core(c) => c.clone(),
        // R-EV-05: a stage 2 revision answers with the plan it recorded.
        Command::Stage2Revision(r) => {
            let [plan, _] = r.commands();
            plan
        }
        _ => return None,
    };
    let fstp_domain::command::Command::RecordPlanVersion { plan, tasks, .. } = &core else {
        return None;
    };
    let mut total: Option<fstp_money::Amount> = None;
    for m in tasks.iter().flat_map(|t| t.milestones.iter()) {
        let a = m.amount.amount();
        total = Some(match total {
            None => a,
            Some(t) => t.checked_add(a).ok()?,
        });
    }
    total.map(|t| ReadModel::PlanSaved {
        plan: plan.raw(),
        total: t.to_string(),
    })
}

/// The summary of a published call: its fields, its title from the
/// published call text, and P-05 from the programme's head policy. A
/// title the text store cannot give is left out, never made up.
async fn call_summary<P: Seams>(
    call: &Call<'_, P>,
    v: &fstp_domain::programme::CallView,
) -> CallSummary {
    let mut s = CallSummary::of(v, call.now);
    s.title = text_of(call, v.text()).await.ok();
    s.recipient_max = call
        .state
        .core
        .policy()
        .head(v.programme())
        .map(|p| p.live.p05.amount().to_string());
    s
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use fstp_json::ToJson;

    /// I-50, R-PG-01 AC, M4 design section 15.0 (I-50 timing, Daniel,
    /// 2026-10-31): an engine refusal of a save with P-05 above P-58 reaches
    /// the API error with both values, in its text and in its JSON body.
    #[test]
    fn i50_api_refusal_names_both_values() {
        use fstp_money::{Amount, Currency, NonNegAmount};
        let eur = |minor: i64| {
            NonNegAmount::new(Amount::from_minor(minor, Currency::Eur).unwrap()).unwrap()
        };
        let detail = fstp_domain::RefusalDetail::CapAboveCeiling {
            p05: eur(6_000_001),
            p58: eur(6_000_000),
        };
        let r = Refusal::new(RuleRef::I50, fstp_domain::RefusalReason::InvalidValue).naming(detail);
        let e = refusal(r);
        assert_eq!(
            e,
            ApiError::Refused {
                code: ErrorCode::Refused,
                rule: "I-50",
                detail: Some(detail),
            }
        );
        let text = e.to_string();
        assert!(
            text.contains("60000.01") && text.contains("60000.00"),
            "{text}"
        );
        let mut values = fstp_json::Object::new();
        let _ = values.insert("P-05", fstp_json::Value::from("60000.01"));
        let _ = values.insert("P-58", fstp_json::Value::from("60000.00"));
        let mut want = fstp_json::Object::new();
        let _ = want.insert("code", fstp_json::Value::from("refused"));
        let _ = want.insert("rule", fstp_json::Value::from("I-50"));
        let _ = want.insert("values", fstp_json::Value::Object(values));
        assert_eq!(e.to_json(), fstp_json::Value::Object(want));
    }

    /// R-EV-08, TH-26, change D5: dispatch answers `committee.open_round`
    /// with the round it drew and nothing else, and that body fits the
    /// reply shape of `fstp_access::REPLIES`.
    #[test]
    fn r_ev_08_open_round_reply_is_the_drawn_round_and_fits_its_shape() {
        let form = forms::command_form(fstp_domain::CommandKind::OpenCutOffRound).unwrap();
        let body = accepted(&form, &[9]);
        crate::model::reply_shape_tests::assert_fits("committee.open_round", &body);
        assert_eq!(
            fstp_json::to_canonical(&body.to_json()).unwrap(),
            r#"{"round":"9"}"#
        );
    }

    /// R-SB-03, R-EV-04, `roles-and-sod.md` Receiving bindings: an ended
    /// Receiving binding gives the final-state read only when it was
    /// active as it ended. An ordinary suspension still counts as held,
    /// yet it is inactive for every action, so it gives no such read.
    /// Neither does a voided binding.
    #[test]
    fn r_sb_03_suspended_or_voided_binding_gives_no_final_state_read() {
        let base = Binding {
            account: AccountId::from_raw(7),
            programme: ProgrammeId::from_raw(1),
            role: Role::Applicant,
            scope: BindingScope::Proposal {
                proposal: ProposalId::from_raw(11),
                call: CallId::from_raw(1),
            },
            start: Timestamp::from_micros(0),
            opened: 1,
            status: BindingStatus::Active,
            suspended_beneath: None,
            granted: 0,
            organisation: None,
            scheduled_end: None,
        };
        assert!(gives_final_read(&base));
        let suspended = Binding {
            status: BindingStatus::Suspended(RuleRef::I04),
            ..base
        };
        assert!(suspended.held(), "an ordinary suspension still counts");
        assert!(!gives_final_read(&suspended));
        let voided = Binding {
            status: BindingStatus::Voided(RuleRef::I04),
            ..base
        };
        assert!(!gives_final_read(&voided));
    }

    /// I-86: a begun verification reads "pending" for less than
    /// [`VERIFICATION_PENDING_MICROS`] after its latest begin, and then
    /// no longer, so one the vault rejected does not read "pending"
    /// until a restart. Beginning again restarts the bound, and another
    /// account never reads the caller's begin.
    #[test]
    fn i86_begun_verification_stops_reading_pending_after_its_bound() {
        let a = AccountId::from_raw(7);
        let at = |m: i64| Timestamp::from_micros(m);
        let mut begun = Begun::default();
        begun.begin(a, at(1_000));
        assert!(begun.pending(a, at(1_000)));
        assert!(begun.pending(a, at(1_000 + VERIFICATION_PENDING_MICROS - 1)));
        assert!(!begun.pending(a, at(1_000 + VERIFICATION_PENDING_MICROS)));
        assert!(!begun.pending(AccountId::from_raw(8), at(1_000)));
        begun.begin(a, at(1_000 + VERIFICATION_PENDING_MICROS));
        assert!(begun.pending(a, at(1_000 + VERIFICATION_PENDING_MICROS)));
    }

    /// J4, TH-26: creating a draft still answers the drawn proposal, so
    /// the round reply leaves the other commands' bodies as they were.
    #[test]
    fn j4_create_draft_reply_still_names_the_drawn_proposal() {
        let form = forms::command_form(fstp_domain::CommandKind::CreateDraft).unwrap();
        let ids: Vec<u128> = (1..=u128::try_from(form.drawn.len()).unwrap()).collect();
        let body = accepted(&form, &ids);
        crate::model::reply_shape_tests::assert_fits("proposal.create", &body);
    }
}
