//! The channel harness of the authorisation matrix (M4 design section
//! 8.3): every cell through `ApiCore::dispatch` directly, through the
//! HTTP routes of `fstp-web` over `fstp_rt::duplex`, and every MCP cell
//! through the `tools/call` handler of `fstp_mcp::McpServer` (lane W3c).
//!
//! # Worlds
//!
//! A cell runs in a world built for its state, its policy row and its
//! principal. A world is a cell of fake ports behind one `ApiCore`, built
//! from genesis through production commands (design section 8.1):
//!
//! - the tenant part of the ledger holds the provisioning of the first
//!   tenant admin and the second admin's invitation and enrolment, as M3
//!   appends them. Every onboarding step then runs through dispatch;
//! - the programme P comes through the creator: the first admin opens the
//!   draft, the programme manager applies the SuperSAFE template, saves
//!   the policy row's P-10, P-11, P-28, P-75 and P-77 and requests the
//!   activation, and the second admin approves it with a step-up. P-74 is
//!   the tenant setting `tenant.set_mcp`;
//! - the call C and the proposal X walk the lifecycle through dispatch
//!   wherever the API core keeps a projection of the step (drafts, plans,
//!   workspaces, submissions, scores, summaries, stage 2, rounds and IRC
//!   reviews), and through the engine port's driver for the rest (grants,
//!   calls, declarations, assignments, the knock-out, admission, the
//!   stage 1 close and the commands of later milestones).
//!
//! Every principal of [`Who`] has its own account and relation to the
//! targets. The principals that exclude each other in one world get a
//! world of their own ([`Variant`]): the sole tenant admin and the lead
//! whose Receiving binding was voided.
//!
//! # Cells
//!
//! A cell runs on a world that no earlier cell changed. A cell that
//! changed anything, by appending to the ledger or by completing or
//! preparing an operation that is not a read, marks its world dirty, and
//! the next cell of that world runs on a rebuilt one. A rate-limit
//! refusal is an effect of earlier cells of the same instant, so the cell
//! runs again on a rebuilt world.
//!
//! The harness logs the principal in with the cell's method, or issues it
//! an MCP token with or without the operation's scope, consented in a
//! passkey session. A high-risk web cell with a fresh step-up answers its
//! challenge in the same session and calls again. A stale step-up answers
//! it P-71 plus one microsecond in the past. Every request is valid for
//! its target, so a refusal by a guard on unrelated data does not occur
//! where the world can hold valid data.
//!
//! The harness reads no `fstp-access` rule and no reference rule. It
//! only builds worlds and sends requests.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use fstp_api_core::decode::{Method as ApiMethod, decode_public_page, decode_route, decode_tool};
use fstp_api_core::meta::Scope;
use fstp_api_core::port::{AgentClientId, LoginMethod, PendingId, api_core};
use fstp_api_core::{ApiCore, ApiError, Credential, OpResult, RequestHead};
use fstp_domain::StateTag;
use fstp_domain::assignment::AssignmentKind;
use fstp_domain::command::{Actor, Command as Core, Ctx, DeclarationSubject, SystemCause, Via};
use fstp_domain::id::{
    AccountId, AssignmentId, BindingId, CallId, CommandId, DecisionId, ProgrammeId, ProposalId,
};
use fstp_domain::roles::Role;
use fstp_domain::time::{Timestamp, ZoneName};
use fstp_domain_testkit::vault::{GroundTruth, IdentityTag};
use fstp_engine::{Command, Record, record_from_json_at};
use fstp_json::{Array, Number, Object, ToJson, Value};
use fstp_ledger::{MemStore, RecordStore};
use fstp_rt::future::block_on;

use crate::NotImplemented;
use crate::fake::fixture::World as FakeWorld;
use crate::fake::{FakePorts, WebLogin};
use crate::matrix::{Cell, Channel, ChannelFault, Denial, Observed};
use crate::reference::authz::{
    Channel as Via2, Login, OnboardStep, P10, P74, Policy, StateProfile, StepUp, Who,
};

// ---------------------------------------------------------------------------
// The cast
// ---------------------------------------------------------------------------

/// The first tenant admin: provisioned with the tenant, opens the draft P,
/// so a builder of P (Q1).
const ADMIN_BUILDER: AccountId = AccountId::from_raw(1);
/// The second tenant admin: built nothing, approves P's activation.
const ADMIN_PLAIN: AccountId = AccountId::from_raw(2);
/// The only tenant admin of the [`Variant::Sole`] worlds.
const ADMIN_SOLE: AccountId = AccountId::from_raw(5);
/// A programme manager of P who drafted nothing.
const PM: AccountId = AccountId::from_raw(3);
/// A programme manager of P who drafted C.
const PM_DRAFTER: AccountId = AccountId::from_raw(6);
/// A programme manager of P whose binding ended.
const PM_ENDED: AccountId = AccountId::from_raw(7);
/// A programme manager of P2.
const PM_OTHER: AccountId = AccountId::from_raw(8);
/// A call drafter of P, who edited C.
const DRAFTER: AccountId = AccountId::from_raw(4);
/// The FSTP coordinators of P: declared, undeclared and conflicted on X.
const COORD: AccountId = AccountId::from_raw(201);
const COORD_UNDECLARED: AccountId = AccountId::from_raw(202);
const COORD_CONFLICTED: AccountId = AccountId::from_raw(203);
/// The committee chair of P.
const CHAIR: AccountId = AccountId::from_raw(209);
/// A committee member of P assigned to nothing.
const MEMBER: AccountId = AccountId::from_raw(210);
/// The assigned reviewers of X.
const REVIEWER: AccountId = AccountId::from_raw(211);
const REVIEWER_UNDECLARED: AccountId = AccountId::from_raw(212);
const REVIEWER_CONFLICTED: AccountId = AccountId::from_raw(213);
const REVIEWER_RELEASED: AccountId = AccountId::from_raw(214);
const REVIEWER_SUSPENDED: AccountId = AccountId::from_raw(215);
/// A committee member with a conflict on Y, so recused from C's round.
const RECUSED: AccountId = AccountId::from_raw(216);
/// A committee member who delegated the vote in the round.
const DELEGATOR: AccountId = AccountId::from_raw(217);
/// The second scoring reviewer of X and Y, for P-03.
const REVIEWER_2: AccountId = AccountId::from_raw(218);
/// The IRC members of P.
const IRC_MEMBER: AccountId = AccountId::from_raw(220);
const IRC_ASSIGNEE: AccountId = AccountId::from_raw(221);
const IRC_UNDECLARED: AccountId = AccountId::from_raw(222);
const IRC_CONFLICTED: AccountId = AccountId::from_raw(223);
const IRC_2: AccountId = AccountId::from_raw(224);
/// The team of X.
const LEAD: AccountId = AccountId::from_raw(301);
const TEAM: AccountId = AccountId::from_raw(311);
const GUARDIAN: AccountId = AccountId::from_raw(321);
/// The lead of Y.
const LEAD_Y: AccountId = AccountId::from_raw(302);
/// The Operations roles and the auditor of P.
const FINANCE: AccountId = AccountId::from_raw(401);
const RELEASER: AccountId = AccountId::from_raw(402);
const SIGNATORY: AccountId = AccountId::from_raw(403);
const AUDITOR: AccountId = AccountId::from_raw(404);
/// The holder of both signatory roles in every built world, granted before
/// the first onboarding step (SoD-14, SoD-15, NOTE 5). It holds no
/// programme binding.
const ORG_SIGNATORY: AccountId = AccountId::from_raw(405);
/// An account a signatory grant names, which holds no role.
const SIGNATORY_GRANTEE: AccountId = AccountId::from_raw(406);
/// An account with no binding.
const UNBOUND: AccountId = AccountId::from_raw(499);

/// Every account of the cast, each with its own verified identity.
const CAST: [AccountId; 37] = [
    ADMIN_BUILDER,
    ADMIN_PLAIN,
    ADMIN_SOLE,
    PM,
    PM_DRAFTER,
    PM_ENDED,
    PM_OTHER,
    DRAFTER,
    COORD,
    COORD_UNDECLARED,
    COORD_CONFLICTED,
    CHAIR,
    MEMBER,
    REVIEWER,
    REVIEWER_UNDECLARED,
    REVIEWER_CONFLICTED,
    REVIEWER_RELEASED,
    REVIEWER_SUSPENDED,
    RECUSED,
    DELEGATOR,
    REVIEWER_2,
    IRC_MEMBER,
    IRC_ASSIGNEE,
    IRC_UNDECLARED,
    IRC_CONFLICTED,
    IRC_2,
    LEAD,
    TEAM,
    GUARDIAN,
    LEAD_Y,
    FINANCE,
    RELEASER,
    SIGNATORY,
    AUDITOR,
    UNBOUND,
    AccountId::from_raw(990),
    AccountId::from_raw(991),
];

/// The account that stands for `who`, or `None` for no credential.
const fn account_of(who: Who) -> Option<AccountId> {
    Some(match who {
        Who::Anonymous => return None,
        Who::Unbound => UNBOUND,
        Who::TenantAdmin => ADMIN_PLAIN,
        Who::TenantAdminBuilder => ADMIN_BUILDER,
        Who::SoleTenantAdmin => ADMIN_SOLE,
        Who::ProgrammeManager => PM,
        Who::ProgrammeManagerDrafter => PM_DRAFTER,
        Who::EndedProgrammeManager => PM_ENDED,
        Who::OtherProgrammeManager => PM_OTHER,
        Who::CallDrafter => DRAFTER,
        Who::Coordinator => COORD,
        Who::CoordinatorUndeclared => COORD_UNDECLARED,
        Who::CoordinatorConflicted => COORD_CONFLICTED,
        Who::CommitteeMember => MEMBER,
        Who::CommitteeChair => CHAIR,
        Who::AssignedReviewer => REVIEWER,
        Who::AssignedReviewerUndeclared => REVIEWER_UNDECLARED,
        Who::AssignedReviewerConflicted => REVIEWER_CONFLICTED,
        Who::ReleasedReviewer => REVIEWER_RELEASED,
        Who::SuspendedReviewer => REVIEWER_SUSPENDED,
        Who::RecusedCommitteeMember => RECUSED,
        Who::DelegatingCommitteeMember => DELEGATOR,
        Who::IrcMember => IRC_MEMBER,
        Who::IrcAssignee => IRC_ASSIGNEE,
        Who::IrcAssigneeUndeclared => IRC_UNDECLARED,
        Who::IrcAssigneeConflicted => IRC_CONFLICTED,
        Who::Lead | Who::VoidedLead => LEAD,
        Who::TeamMember => TEAM,
        Who::Guardian => GUARDIAN,
        Who::FinanceApprover => FINANCE,
        Who::PaymentReleaser => RELEASER,
        Who::ContractSignatory => SIGNATORY,
        Who::FinancialSignatory => ORG_SIGNATORY,
        Who::Auditor => AUDITOR,
    })
}

/// The worlds whose principals exclude each other.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Variant {
    /// Two tenant admins, and every other principal.
    Main,
    /// One tenant admin only, who opened the draft P.
    Sole,
    /// X's lead had its Receiving binding voided under I-04.
    Voided,
}

impl Variant {
    /// The world variant a principal needs.
    pub const fn of(who: Who) -> Variant {
        match who {
            Who::SoleTenantAdmin => Variant::Sole,
            Who::VoidedLead => Variant::Voided,
            _ => Variant::Main,
        }
    }
}

/// The key of one world.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WorldKey {
    /// The state.
    pub state: StateProfile,
    /// The policy row.
    pub policy: Policy,
    /// The variant.
    pub variant: Variant,
}

impl WorldKey {
    /// The world of `cell`.
    pub fn of(cell: &Cell) -> WorldKey {
        WorldKey {
            state: cell.state,
            policy: cell.policy,
            variant: Variant::of(cell.who),
        }
    }
}

// ---------------------------------------------------------------------------
// Time
// ---------------------------------------------------------------------------

/// One second, in microseconds.
const SECOND: i64 = 1_000_000;
/// One day, in microseconds.
const DAY: i64 = 86_400 * SECOND;
/// The setup: tenant, programme and people.
const T_SETUP: i64 = 10 * DAY;
/// The call opens.
const OPENS: i64 = 11 * DAY;
/// The drafts.
const T_DRAFT: i64 = 12 * DAY;
/// The cell clock of a world whose call is still open.
const NOW_OPEN: i64 = 13 * DAY;
/// The call deadline.
const DEADLINE: i64 = 14 * DAY;
/// The evaluation, after the deadline.
const T_EVAL: i64 = 15 * DAY;
/// The cell clock of a world whose call is closed.
const NOW_CLOSED: i64 = 18 * DAY;
/// The first milestone start of every plan.
const MILESTONE_START: i64 = 20 * DAY;
/// The cell clock once execution started.
const NOW_EXECUTING: i64 = 21 * DAY;
/// The deadline of the future call of NOTE 7.
const FUTURE_DEADLINE: i64 = 400 * DAY;

/// The day `micros` as `YYYY-MM-DD`, for days within 1970.
fn day_of(micros: i64) -> String {
    let mut d = micros.div_euclid(DAY);
    const MONTHS: [i64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut m = 0usize;
    for (i, len) in MONTHS.iter().enumerate() {
        if d < *len {
            m = i;
            break;
        }
        d = d.saturating_sub(*len);
        m = i.saturating_add(1);
    }
    format!("1970-{:02}-{:02}", m.saturating_add(1), d.saturating_add(1))
}

// ---------------------------------------------------------------------------
// JSON helpers
// ---------------------------------------------------------------------------

/// An object of `members`.
fn obj(members: Vec<(&str, Value)>) -> Value {
    let mut o = Object::new();
    for (k, v) in members {
        let _ = o.insert(k, v);
    }
    Value::Object(o)
}

/// A decimal string.
fn dec(x: u128) -> Value {
    Value::String(x.to_string())
}

/// A JSON string.
fn s(x: &str) -> Value {
    Value::String(x.to_owned())
}

/// A small JSON number.
fn int(n: u32) -> Value {
    Value::Number(Number::from(n))
}

/// The string member `k` of `v`.
fn str_member(v: &Value, k: &str) -> Option<String> {
    v.as_object()?.get(k)?.as_str().map(str::to_owned)
}

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

/// One request of an operation: its route and body, and its tool.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// The operation name.
    pub op: &'static str,
    /// The method of the web route.
    pub method: ApiMethod,
    /// The web path, relative to `/api/v1` (or absolute for `/p/`).
    pub path: String,
    /// The body members of the web route.
    pub body: Object,
    /// The path parameters, as a tool call carries them.
    pub params: Object,
}

impl Request {
    /// The body bytes of the web route. An empty body is sent for a read.
    pub fn body_bytes(&self) -> Vec<u8> {
        if self.method == ApiMethod::Get && self.body.is_empty() {
            return Vec::new();
        }
        Value::Object(self.body.clone()).to_compact().into_bytes()
    }

    /// The arguments of the tool call: the path parameters and the body.
    pub fn tool_args(&self) -> Vec<u8> {
        let mut o = self.params.clone();
        for (k, v) in self.body.iter() {
            let _ = o.insert(k, v.clone());
        }
        Value::Object(o).to_compact().into_bytes()
    }
}

/// The objects of a world that cells act on.
#[derive(Clone, Debug, Default)]
pub struct Targets {
    programme: Option<ProgrammeId>,
    slug: String,
    call: Option<CallId>,
    proposal: Option<ProposalId>,
    plan: Option<u128>,
    assignments: BTreeMap<AccountId, AssignmentId>,
    irc: BTreeMap<AccountId, AssignmentId>,
    round: Option<DecisionId>,
    invitation: Option<String>,
    revision: Option<String>,
    binding_end: Option<BindingId>,
    narrative: Option<String>,
    /// The key of a warning of the draft report of P.
    warning: Option<String>,
    pending: BTreeMap<AccountId, (PendingId, String)>,
    /// M5 lane L-API: see `Reached`.
    contract: Option<u128>,
    accepted: Option<u128>,
    approved: Option<u128>,
    amendment: Option<u128>,
    report: Option<u128>,
    request: Option<u128>,
    line: Option<u128>,
    p71: i64,
}

/// The agent client of `account`'s MCP tokens.
fn agent_of(account: AccountId) -> AgentClientId {
    AgentClientId::from_raw(0xa6e0_0000u128.saturating_add(account.raw()))
}

/// The agent client `agents.revoke` and `agents.activity` act on: one of
/// the caller's own, with a token, so a revocation never touches the
/// client of the cell's own MCP token.
fn other_agent_of(account: AccountId) -> AgentClientId {
    AgentClientId::from_raw(0xa6f0_0000u128.saturating_add(account.raw()))
}

/// A link token that names no invitation: 32 hexadecimal digits.
const UNKNOWN_LINK: &str = "0123456789abcdef0123456789abcdef";

/// The path parameter `name` of a cell's request.
fn param(name: &str, who: Who, t: &Targets, session: Option<u128>) -> Result<String, String> {
    let id = |x: Option<u128>| x.map(|v| v.to_string()).ok_or_else(|| format!("no {name}"));
    let account = account_of(who);
    Ok(match name {
        "programme" => id(t.programme.map(|p| p.raw()))?,
        "slug" => t.slug.clone(),
        "call" => id(t.call.map(|c| c.raw()))?,
        "proposal" => id(t.proposal.map(|p| p.raw()))?,
        "assignment" => {
            let own = account.and_then(|a| t.assignments.get(&a).copied());
            let any = t
                .assignments
                .get(&REVIEWER)
                .copied()
                .or_else(|| t.assignments.values().next().copied());
            id(own.or(any).map(|a| a.raw()))?
        }
        "irc_assignment" => {
            let own = account.and_then(|a| t.irc.get(&a).copied());
            let any = t
                .irc
                .get(&IRC_ASSIGNEE)
                .copied()
                .or_else(|| t.irc.values().next().copied());
            id(own.or(any).map(|a| a.raw()))?
        }
        "round" => id(t.round.map(|r| r.raw()))?,
        "finding" => "1".to_owned(),
        "score" => id(t.plan)?,
        "step" => "organisation".to_owned(),
        "binding" => id(t.binding_end.map(|b| b.raw()))?,
        "approval" => "1".to_owned(),
        "recovery" => "1".to_owned(),
        // `tenant.end_signatory` ends a binding the world holds.
        "role" => "financial_signatory".to_owned(),
        "account" => ORG_SIGNATORY.raw().to_string(),
        "break_glass" => "1".to_owned(),
        "invitation" => t.invitation.clone().unwrap_or_else(|| "1".to_owned()),
        "invitation_token" => UNKNOWN_LINK.to_owned(),
        // M5 lane L-API: no world holds a payment request, contract,
        // amendment or report yet, and a milestone is named by an id no
        // plan holds, so its closure meets a guard.
        "milestone" | "clause" => "1".to_owned(),
        "request" => t.request.unwrap_or(1).to_string(),
        "line" => t.line.unwrap_or(1).to_string(),
        "contract" => t.contract.unwrap_or(1).to_string(),
        "amendment" => t.amendment.unwrap_or(1).to_string(),
        "report" => t.report.unwrap_or(1).to_string(),
        "field" => t
            .narrative
            .clone()
            .unwrap_or_else(|| "general.narrative".to_owned()),
        "preview" => "guide".to_owned(),
        "import_proposal" => "1".to_owned(),
        "client" => account
            .map(|a| other_agent_of(a).raw())
            .unwrap_or(1)
            .to_string(),
        "session" => session.unwrap_or(1).to_string(),
        "pending" => account
            .and_then(|a| t.pending.get(&a))
            .map(|(p, _)| p.raw())
            .unwrap_or(1)
            .to_string(),
        other => return Err(format!("no value for the path parameter {other}")),
    })
}

/// The tenant onboarding step a read or save names in `state`. Past
/// onboarding it is Agreements: a world replayed from a [`Start`] runs a
/// fresh API core, which does not hold the Organisation step's data
/// protection contact text, so that step's view fails closed there.
fn step_name(state: StateProfile) -> &'static str {
    match state {
        StateProfile::Onboarding(s) => onboard_name(s),
        _ => "agreements",
    }
}

/// The route segment of an onboarding step.
const fn onboard_name(s: OnboardStep) -> &'static str {
    match s {
        OnboardStep::Organisation => "organisation",
        OnboardStep::Agreements => "agreements",
        OnboardStep::Branding => "branding",
        OnboardStep::DomainsAndEmail => "domains_and_email",
        OnboardStep::Identity => "identity",
        OnboardStep::Inference => "inference",
        OnboardStep::Payments => "payments",
        OnboardStep::Channels => "channels",
        OnboardStep::Administrators => "administrators",
    }
}

/// The values of a valid save of onboarding step `step`.
fn step_values(step: &str, admins: &[AccountId]) -> Value {
    let text = match step {
        "organisation" => format!(
            r#"{{"data_protection_contact":"Synthetic data protection contact.","signatories":["{}"]}}"#,
            ADMIN_BUILDER.raw()
        ),
        "agreements" => r#"{"dpa":"1","saas_terms":"1","sub_processors":"1"}"#.to_owned(),
        "branding" => r#"{"package":"default"}"#.to_owned(),
        "domains_and_email" => r#"{"sending_domain":"mail.matrix.invalid"}"#.to_owned(),
        "identity" => {
            r#"{"p18":["document_upload","eudi_wallet"],"p45":"tenant_registration"}"#.to_owned()
        }
        "inference" => {
            r#"{"fallbacks":[],"primary":"placeholder-model","provider":"placeholder"}"#.to_owned()
        }
        "payments" => r#"{"bank_interface":"not_connected"}"#.to_owned(),
        "channels" => r#"{"matrix_homeserver":null,"whatsapp":false}"#.to_owned(),
        _ => {
            let list: Vec<String> = admins.iter().map(|a| format!("\"{}\"", a.raw())).collect();
            format!(r#"{{"admins":[{}]}}"#, list.join(","))
        }
    };
    fstp_json::parse(text.as_bytes()).unwrap_or(Value::Null)
}

/// One milestone of the page form, `amount` EUR.
fn plan_body(amount: &str) -> Value {
    let milestone = obj(vec![
        ("amount", s(amount)),
        ("start", s(&day_of(MILESTONE_START))),
        ("due", s(&day_of(MILESTONE_START.saturating_add(150 * DAY)))),
    ]);
    let task = obj(vec![(
        "milestones",
        Value::Array(Array::from(vec![milestone])),
    )]);
    obj(vec![
        ("description", s("SYNTHETIC WORK PLAN")),
        ("tasks", Value::Array(Array::from(vec![task]))),
    ])
}

/// The scores of one assignment: the top of the scale on every criterion.
fn score_values(n: usize, max: u32) -> Value {
    Value::Array((0..n).map(|_| int(max)).collect::<Array>())
}

/// Scores at the top of the scale, less one on the first criterion: a
/// proposal scored so ranks below one scored with [`score_values`], so a
/// round over both needs no P-17 tie-break.
fn lower_values(n: usize, max: u32) -> Value {
    Value::Array(
        (0..n)
            .map(|i| int(if i == 0 { max.saturating_sub(1) } else { max }))
            .collect::<Array>(),
    )
}

/// The body members of a valid request of `op` by `who`.
fn body_of(op: &str, who: Who, state: StateProfile, w: &Built) -> Result<Object, String> {
    let t = &w.targets;
    let v = match op {
        "me.begin_verification"
        | "tenant.complete"
        | "admin.approve_self_grant"
        | "admin.approve_recovery"
        | "creator.open_draft"
        | "creator.save_as_template"
        | "call.approve"
        | "call.publish"
        | "proposal.create"
        | "proposal.withdraw"
        | "guardian.begin_consent"
        | "review.admit"
        | "review.close_stage1"
        | "review.unassign"
        | "stage2.no_questions"
        | "review.rank"
        | "committee.record_cutoff"
        | "decision.decline_after_concern"
        | "decision.decline_negotiation"
        | "agents.revoke"
        | "me.end_session"
        | "me.add_passkey"
        | "pending.discard"
        | "people.accept_invitation"
        | "people.begin_verification"
        | "creator.withdraw_invitation" => obj(vec![]),
        "tenant.save_step" => {
            let step = step_name(state);
            obj(vec![
                ("base", s(&w.tenant_revision)),
                ("values", step_values(step, &w.admins)),
            ])
        }
        "tenant.invite_admin" => obj(vec![("email", s("new-admin@matrix.invalid"))]),
        "proposal.request_copy" => obj(vec![("email", s("copy@matrix.invalid"))]),
        "tenant.grant_signatory" => obj(vec![
            ("account", dec(SIGNATORY_GRANTEE.raw())),
            ("role", s("legal_signatory")),
        ]),
        "tenant.approve_activation" => obj(vec![("request", s("1"))]),
        "tenant.set_login_methods" => obj(vec![(
            "value",
            Value::Array(Array::from(vec![s("eudi_wallet"), s("passkey")])),
        )]),
        "tenant.set_step_up_freshness" => obj(vec![("value", s("60000000"))]),
        "tenant.set_session_lifetimes" => obj(vec![(
            "value",
            obj(vec![
                ("absolute_us", s("3600000000")),
                ("idle_us", s("600000000")),
            ]),
        )]),
        "tenant.set_mcp" => obj(vec![("value", mcp_value(P74::AllRoles))]),
        "tenant.set_payment_mode" => obj(vec![("value", s("record_only"))]),
        "tenant.set_template_licence" => obj(vec![("value", s("MIT"))]),
        "tenant.set_guide_notice" => obj(vec![
            (
                "privacy_statement_url",
                s("https://privacy.matrix.example/statement"),
            ),
            (
                "summary",
                s("Synthetic data protection summary, matrix cell."),
            ),
        ]),
        // M9 lane T1: one tenant label and the Voyage switch (I-72).
        "tenant.terminology.set" => obj(vec![
            ("labels", obj(vec![("vocab.call", s("Subgrant call"))])),
            ("voyage_on", Value::Bool(true)),
        ]),
        "tenant.set_mail_relay" => obj(vec![
            ("ca_pem", s("")),
            ("credential", s("mail-relay")),
            ("host", s("smtp.relay.example")),
        ]),
        "admin.approve_break_glass" => obj(vec![("approve", Value::Bool(true))]),
        "creator.invite" => obj(vec![
            ("email", s("invitee@matrix.invalid")),
            ("role", s("programme_manager")),
        ]),
        "creator.apply_start" => obj(vec![
            ("base", s(t.revision.as_deref().unwrap_or("1.1"))),
            ("start", crate::fake::creator_requests::supersafe_start()),
        ]),
        "creator.save_fields" => obj(vec![
            ("base", s(t.revision.as_deref().unwrap_or("1.1"))),
            (
                "fields",
                Value::Array(Array::from(vec![obj(vec![
                    ("field", s("evaluation.p28_rubric_bands")),
                    ("value", Value::Bool(false)),
                ])])),
            ),
        ]),
        "creator.accept_narrative" => {
            obj(vec![("base", s(t.revision.as_deref().unwrap_or("1.1")))])
        }
        "creator.acknowledge" => obj(vec![
            ("revision", s(t.revision.as_deref().unwrap_or("1.1"))),
            ("warning", s(t.warning.as_deref().unwrap_or("null"))),
        ]),
        "creator.request_activation" | "creator.approve_activation" => obj(vec![(
            "revision",
            s(t.revision.as_deref().unwrap_or("1.1")),
        )]),
        "import.upload" => obj(vec![
            ("media", s("text/plain")),
            (
                "text",
                s("SYNTHETIC ANNEX: the grant range is 1000 to 2000 EUR."),
            ),
        ]),
        "import.resolve" => obj(vec![
            ("base", s(t.revision.as_deref().unwrap_or("1.1"))),
            ("conflict_acknowledged", Value::Bool(false)),
            ("resolution", obj(vec![("kind", s("dismiss"))])),
            ("shown", s(&"0".repeat(64))),
        ]),
        "roles.grant" => obj(vec![
            ("account", dec(UNBOUND.raw())),
            ("role", s("Auditor")),
            ("start", dec(u128::try_from(w.now).unwrap_or(0))),
        ]),
        "roles.end" => obj(vec![]),
        "roles.reinstate" => obj(vec![("reason", s("SYNTHETIC REINSTATEMENT REASON"))]),
        "call.draft" | "call.edit" => obj(vec![
            ("opens", dec(u128::try_from(OPENS).unwrap_or(0))),
            ("deadline", dec(u128::try_from(DEADLINE).unwrap_or(0))),
            ("deadline_zone", s("Europe/Brussels")),
            ("currency", s("EUR")),
            ("budget", s("400000.00")),
            ("text", s("SYNTHETIC CALL TEXT")),
        ]),
        "proposal.save_workspace" => obj(vec![
            ("narrative", s("SYNTHETIC NARRATIVE")),
            ("summary", s("SYNTHETIC SUMMARY")),
            ("title", s("SYNTHETIC TITLE")),
        ]),
        "proposal.record_plan" => plan_body("50000.00"),
        "proposal.add_member" | "proposal.add_guardian" => {
            obj(vec![("account", dec(AccountId::from_raw(990).raw()))])
        }
        "proposal.state_country" => obj(vec![("country", s("BE"))]),
        "proposal.declare_affiliations" => obj(vec![("affiliations", s("SYNTHETIC AFFILIATIONS"))]),
        "proposal.state_birth_date" => obj(vec![("date_of_birth", s("1990-01-01"))]),
        "proposal.submit" => obj(vec![("ethics", s("none")), ("notice_version", s("1"))]),
        "stage2.answer" => obj(vec![("text", s("SYNTHETIC ANSWERS"))]),
        "stage2.revise" => obj(vec![("plan", dec(t.plan.unwrap_or(1)))]),
        "negotiation.acknowledge_notice" => obj(vec![("notice_version", s("1"))]),
        "review.declare_proposal" | "review.declare_assignment" | "irc.declare" => obj(vec![
            ("conflicted", Value::Bool(false)),
            ("notifiable", Value::Bool(false)),
        ]),
        "review.knock_out" => {
            let outcomes: Vec<Value> = w
                .knock_outs
                .iter()
                .map(|k| obj(vec![("criterion", dec(*k)), ("passed", Value::Bool(true))]))
                .collect();
            obj(vec![(
                "outcomes",
                Value::Array(outcomes.into_iter().collect()),
            )])
        }
        "review.assign" => obj(vec![
            ("reviewer", dec(MEMBER.raw())),
            ("kind", obj(vec![("type", s("Reviewer"))])),
        ]),
        "review.score" => obj(vec![
            ("plan", dec(t.plan.unwrap_or(1))),
            ("stage", s(stage_of(state))),
            ("values", score_values(w.criteria, w.scale)),
        ]),
        "review.correct_score" => obj(vec![
            ("stage", s(stage_of(state))),
            ("values", score_values(w.criteria, w.scale)),
            ("reason", s("SYNTHETIC CORRECTION")),
        ]),
        "review.ranking_summary" => obj(vec![
            ("neutral_summary", s("SYNTHETIC NEUTRAL SUMMARY")),
            ("rationale", s("SYNTHETIC RATIONALE")),
            ("title", s("SYNTHETIC TITLE")),
        ]),
        "stage2.ask" => obj(vec![("text", s("SYNTHETIC QUESTION"))]),
        "committee.open_round" => {
            let order: Vec<Value> = w.ranked.iter().map(|p| dec(p.raw())).collect();
            obj(vec![
                ("order", Value::Array(order.into_iter().collect())),
                ("nominated", int(1)),
                ("rationale", s("SYNTHETIC ROUND RATIONALE")),
            ])
        }
        "committee.cast" => obj(vec![("vote", s("For"))]),
        "review.mark_finding" => obj(vec![("mark", s("Agreed"))]),
        "committee.delegate" => obj(vec![("to", dec(MEMBER.raw()))]),
        "irc.review" => obj(vec![("verdict", obj(vec![("type", s("Validate"))]))]),
        "agents.consent" => obj(vec![]),
        "grant.determine_amount" => obj(vec![
            ("agreed", dec(t.plan.unwrap_or(1))),
            ("deductions", Value::Array(Array::new())),
            ("currency", s("EUR")),
        ]),
        "grant.accept" | "grant.approve" => obj(vec![("determination", s("1"))]),
        "grant.terminate" | "milestone.close" => obj(vec![("reason", s("SYNTHETIC REASON"))]),
        "amendment.propose" => obj(vec![("plan", dec(t.plan.unwrap_or(1)))]),
        "amendment.route" => obj(vec![("route", s("Irc"))]),
        "contract.propose_change" => obj(vec![
            ("clause", int(1)),
            ("text", s("SYNTHETIC CLAUSE CHANGE")),
        ]),
        "contract.decide_change" => obj(vec![("accept", Value::Bool(true))]),
        "contract.sign" => obj(vec![("route", s("wallet_qes"))]),
        "contract.approve_advanced" => obj(vec![
            ("party", s("lead")),
            ("reason", s("SYNTHETIC REASON")),
        ]),
        "contract.decline" | "payment.close" | "payment.request_changes" => {
            obj(vec![("reason", s("SYNTHETIC REASON"))])
        }
        "payment.review_line" => obj(vec![("approved", s("100.00")), ("currency", s("EUR"))]),
        "payment.resubmit" => obj(vec![
            ("kind", obj(vec![("type", s("Milestone"))])),
            ("currency", s("EUR")),
            ("lines", Value::Array(Array::new())),
        ]),
        "payment.submit" => obj(vec![
            ("kind", obj(vec![("type", s("Milestone"))])),
            ("currency", s("EUR")),
            ("lines", Value::Array(Array::new())),
        ]),
        "report.generate" => obj(vec![
            ("kind", s("audit_file")),
            ("call", dec(t.call.map_or(1, |c| c.raw()))),
        ]),
        "pending.confirm" => {
            let shown = account_of(who)
                .and_then(|a| t.pending.get(&a))
                .map_or_else(|| "0".repeat(64), |(_, d)| d.clone());
            obj(vec![("shown", s(&shown))])
        }
        _ => obj(vec![]),
    };
    match v {
        Value::Object(o) => Ok(o),
        _ => Err(format!("{op}: the body is not an object")),
    }
}

/// The stage of a score in `state`.
fn stage_of(state: StateProfile) -> &'static str {
    match state {
        StateProfile::Proposal(StateTag::Stage2) => "Two",
        _ => "One",
    }
}

/// The P-74 setting value of `p74`.
fn mcp_value(p74: P74) -> Value {
    let text = match p74 {
        P74::AllRoles => r#"{"enabled":true,"public_tools":true,"roles":null}"#,
        P74::Disabled => r#"{"enabled":false,"public_tools":false,"roles":null}"#,
        P74::ReceivingOnly => {
            r#"{"enabled":true,"public_tools":true,"roles":["Applicant","Applicant team member","Guardian"]}"#
        }
    };
    fstp_json::parse(text.as_bytes()).unwrap_or(Value::Null)
}

/// The request of `cell` in world `w`.
fn request_of(cell: &Cell, w: &Built, session: Option<u128>) -> Result<Request, String> {
    let spec = fstp_access::op(cell.op).ok_or_else(|| format!("no operation {}", cell.op))?;
    let (method, pattern) = spec
        .route
        .ok_or_else(|| format!("{} has no route", cell.op))?;
    let method = match method {
        fstp_access::Method::Get => ApiMethod::Get,
        fstp_access::Method::Post => ApiMethod::Post,
        fstp_access::Method::Put => ApiMethod::Put,
        fstp_access::Method::Delete => ApiMethod::Delete,
    };
    let mut params = Object::new();
    let mut path = String::new();
    for (i, seg) in pattern.split('/').enumerate() {
        if i > 0 {
            path.push('/');
        }
        match seg.strip_prefix('{').and_then(|x| x.strip_suffix('}')) {
            Some(name) => {
                let v = match (name, cell.op) {
                    // M5 lane L-API: the approval names the ACCEPTED request,
                    // the release the PAYMENT_APPROVED one.
                    ("request", "payment.approve") => w.targets.accepted.unwrap_or(1).to_string(),
                    ("request", "payment.release") => w.targets.approved.unwrap_or(1).to_string(),
                    _ => param(name, cell.who, &w.targets, session)?,
                };
                path.push_str(&v);
                let v = if name == "step" {
                    s(step_name(cell.state))
                } else {
                    s(&v)
                };
                let _ = params.insert(name, v);
            }
            None => path.push_str(seg),
        }
    }
    if let Some(v) = params.get("step").cloned() {
        // The path segment and the parameter name the same step.
        let step = v.as_str().unwrap_or("organisation").to_owned();
        path = path.replace("/organisation", &format!("/{step}"));
    }
    let path = served_path(spec, pattern, path);
    let body = body_of(cell.op, cell.who, cell.state, w)?;
    Ok(Request {
        op: cell.op,
        method,
        path,
        body,
        params,
    })
}

/// The path a web client sends for `spec`, whose registry route `pattern`
/// filled in is `path`. The `/p` router serves the programme page at
/// `/p/{slug}/` and the feed at `/p/{slug}/feed.json` (M4 design section
/// 3.10, "Routes"), where the registry names `/p/{slug}` and
/// `/p/{slug}/feed`. Every other path is sent as filled in.
fn served_path(spec: &fstp_access::OpSpec, pattern: &str, mut path: String) -> String {
    if matches!(spec.kind, fstp_access::OpKind::Public(_)) {
        match pattern {
            "/p/{slug}" => path.push('/'),
            "/p/{slug}/feed" => path.push_str(".json"),
            _ => {}
        }
    }
    path
}

/// Decodes a web request as `fstp-web`'s router does: a `GET` under `/p/`
/// through the public page decoder, any other through the API routes.
fn decode_web(method: ApiMethod, path: &str, body: &[u8]) -> Result<fstp_api_core::Op, ApiError> {
    if method == ApiMethod::Get && path.starts_with("/p/") {
        decode_public_page(path)
    } else {
        decode_route(method, path, body)
    }
}

// ---------------------------------------------------------------------------
// The ports of a world
// ---------------------------------------------------------------------------

/// The production driver of a world, over the fake ledger and vault, with
/// the cell's creator environment (as `fake::engine` drives it).
type Driver = fstp_engine::Engine<
    MemStore<Record>,
    crate::fake::CellOracle,
    fstp_engine::CreatorDecider<crate::fake::shell::CellEnvironment>,
>;

#[derive(Debug)]
struct EngineInner {
    engine: Driver,
    confirmed: BTreeSet<PendingId>,
    imports: Option<crate::fake::shell::ImportShell>,
}

/// The engine port of a world. It runs the production driver as
/// `fake::FakeEngine` does: `execute` re-runs every guard, a dry run
/// decides on a copy and reports the vault answers it obtained, and a
/// confirmed pending action is refused a second time. Unlike the fake, it
/// keeps no log of its calls, since a world serves thousands of cells, and
/// it hands out a copy of its ledger, so a world's expensive start is
/// built once.
#[derive(Clone, Debug)]
pub struct WorldEngine {
    inner: Arc<std::sync::Mutex<EngineInner>>,
}

fn lock_engine(m: &std::sync::Mutex<EngineInner>) -> std::sync::MutexGuard<'_, EngineInner> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl WorldEngine {
    /// The engine over `store`, with the creator environment and the
    /// proposer run of `base`'s fakes.
    fn open(store: MemStore<Record>, base: &FakePorts) -> Result<WorldEngine, String> {
        let env = crate::fake::shell::CellEnvironment::new(
            &base.vault,
            base.prober.clone(),
            base.tenant.admin_set(),
            base.vault_audit.clone(),
        );
        let imports = crate::fake::shell::ImportShell::new(base.blobs.clone(), base.texts.clone());
        let engine = fstp_engine::Engine::open_with(
            store,
            base.vault.oracle(),
            fstp_engine::CreatorDecider(env),
        )
        .map_err(|e| format!("open the world engine: {e:?}"))?;
        Ok(WorldEngine {
            inner: Arc::new(std::sync::Mutex::new(EngineInner {
                engine,
                confirmed: BTreeSet::new(),
                imports: Some(imports),
            })),
        })
    }

    /// Runs `cmd` with `ctx` straight on the driver: a step of the world's
    /// build.
    fn environment(
        &self,
        cmd: Command,
        ctx: Ctx,
    ) -> Result<fstp_ledger::Seq, fstp_engine::ExecError> {
        lock_engine(&self.inner).engine.execute(cmd, ctx)
    }

    /// The ledger head.
    fn head(&self) -> fstp_ledger::Seq {
        lock_engine(&self.inner).engine.head()
    }

    /// A copy of the engine state.
    fn state(&self) -> fstp_engine::EngineState {
        lock_engine(&self.inner).engine.state().clone()
    }

    /// A copy of the ledger.
    fn store_copy(&self) -> MemStore<Record> {
        let engine = lock_engine(&self.inner).engine.clone();
        let (store, _, _) = engine.into_parts();
        store
    }

    fn execute_now(
        &self,
        cmd: Command,
        ctx: Ctx,
        meta: &fstp_api_core::port::ExecMeta,
    ) -> Result<fstp_ledger::Seq, fstp_api_core::port::ExecError> {
        use fstp_api_core::port::{ExecError, PortError};
        let mut inner = lock_engine(&self.inner);
        if meta.pending.is_some_and(|p| inner.confirmed.contains(&p)) {
            return Err(ExecError::Port(PortError::Refused));
        }
        let result = inner.engine.execute(cmd.clone(), ctx).map_err(|e| match e {
            fstp_engine::ExecError::Refused(r) => ExecError::Refused(r),
            fstp_engine::ExecError::Duplicate { .. }
            | fstp_engine::ExecError::ReservedCommandId => ExecError::Port(PortError::Refused),
            _ => ExecError::Port(PortError::Unavailable),
        });
        if let (Ok(_), Some(p)) = (&result, meta.pending) {
            inner.confirmed.insert(p);
        }
        if let (Ok(_), Command::Import(fstp_import::ImportCommand::RegisterDocument(doc))) =
            (&result, &cmd)
        {
            let batch = inner
                .imports
                .as_ref()
                .and_then(|shell| shell.proposals(doc, &ctx));
            if let Some((record, system)) = batch {
                let _ = inner.engine.execute(Command::Import(record), system);
            }
        }
        result
    }

    fn dry_run_now(
        &self,
        cmd: &Command,
        ctx: Ctx,
    ) -> (
        Result<(), fstp_domain::refusal::Refusal>,
        Vec<fstp_domain::oracle::Answer>,
    ) {
        let mut copy = lock_engine(&self.inner).engine.clone();
        let oracle = copy.oracle().with_fresh_log();
        *copy.oracle_mut() = oracle;
        copy.decider_mut().0.set_dry(true);
        let result = match copy.execute(cmd.clone(), ctx) {
            Ok(_) => Ok(()),
            Err(fstp_engine::ExecError::Refused(r)) => Err(r),
            Err(_) => Err(fstp_domain::refusal::Refusal::new(
                fstp_domain::refusal::RuleRef::OracleDown,
                fstp_domain::refusal::RefusalReason::OracleUnavailable,
            )),
        };
        let answers = copy.oracle().asks().into_iter().map(|(_, a)| a).collect();
        (result, answers)
    }
}

impl fstp_api_core::port::AsyncEngine for WorldEngine {
    async fn execute(
        &self,
        cmd: Command,
        ctx: Ctx,
        meta: fstp_api_core::port::ExecMeta,
    ) -> Result<fstp_ledger::Seq, fstp_api_core::port::ExecError> {
        self.execute_now(cmd, ctx, &meta)
    }

    async fn dry_run(&self, cmd: &Command, ctx: Ctx) -> Result<(), fstp_domain::refusal::Refusal> {
        self.dry_run_now(cmd, ctx).0
    }

    async fn dry_run_answers(
        &self,
        cmd: &Command,
        ctx: Ctx,
    ) -> (
        Result<(), fstp_domain::refusal::Refusal>,
        Vec<fstp_domain::oracle::Answer>,
    ) {
        self.dry_run_now(cmd, ctx)
    }

    fn snapshot(&self) -> Arc<fstp_engine::EngineState> {
        Arc::new(self.state())
    }

    /// The world's ledger from genesis, for the journey reads (lane j2).
    /// A read failure answers `None`, so the reads fail closed.
    fn ledger(&self) -> Option<Vec<fstp_ledger::Entry<Record>>> {
        use fstp_ledger::RecordStore;
        let inner = lock_engine(&self.inner);
        let mut out = Vec::new();
        inner
            .engine
            .store()
            .read(fstp_ledger::Seq::ZERO, usize::MAX, &mut out)
            .ok()?;
        Some(out)
    }

    fn creator_inputs(
        &self,
        state: &fstp_engine::EngineState,
        cmd: &fstp_creator::CreatorCommand,
        ctx: &Ctx,
    ) -> fstp_creator::CreatorInputs {
        use fstp_engine::CreatorEnvironment;
        lock_engine(&self.inner)
            .engine
            .decider()
            .0
            .creator_inputs(state, cmd, ctx)
    }
}

/// The ports of a world: the fakes of `fake`, with [`WorldEngine`] as
/// the engine port.
#[derive(Clone, Debug)]
pub struct WorldPorts {
    base: FakePorts,
    /// The engine port.
    engine: WorldEngine,
}

impl std::ops::Deref for WorldPorts {
    type Target = FakePorts;
    fn deref(&self) -> &FakePorts {
        &self.base
    }
}

impl fstp_api_core::port::CellPorts for WorldPorts {
    type Sessions = crate::fake::FakeSessions;
    type StepUp = crate::fake::FakeStepUp;
    type Accounts = crate::fake::FakeAccounts;
    type Vault = crate::fake::FakeVault;
    type Engine = WorldEngine;
    type Audit = crate::fake::FakeAudit;
    type Texts = crate::fake::FakeTexts;
    type Blobs = crate::fake::FakeBlobs;
    type Precheck = crate::fake::FakePrecheck;
    type Sealer = crate::fake::FakeSealer;
    type VaultAudit = crate::fake::FakeVaultAudit;
    type SessionsAdmin = crate::fake::FakeSessions;
    type Recovery = crate::fake::FakeRecovery;
    type BreakGlass = crate::fake::FakeBreakGlass;
    type Tenant = crate::fake::FakeTenant;
    type Outbox = crate::fake::FakeOutbox;
    type Prober = crate::fake::FakeProber;
    type Clock = crate::fake::FakeClock;
    type Ids = crate::fake::FakeIds;
    type Tokens = crate::fake::FakeTokens;

    fn sessions(&self) -> &Self::Sessions {
        &self.base.sessions
    }
    fn step_up(&self) -> &Self::StepUp {
        &self.base.step_up
    }
    fn accounts(&self) -> &Self::Accounts {
        &self.base.accounts
    }
    fn vault(&self) -> &Self::Vault {
        &self.base.vault
    }
    fn engine(&self) -> &WorldEngine {
        &self.engine
    }
    fn audit(&self) -> &Self::Audit {
        &self.base.audit
    }
    fn texts(&self) -> &Self::Texts {
        &self.base.texts
    }
    fn blobs(&self) -> &Self::Blobs {
        &self.base.blobs
    }
    fn precheck(&self) -> Option<&Self::Precheck> {
        Some(&self.base.precheck)
    }
    fn sealer(&self) -> &Self::Sealer {
        &self.base.sealer
    }
    fn vault_audit(&self) -> &Self::VaultAudit {
        &self.base.vault_audit
    }
    fn sessions_admin(&self) -> &Self::SessionsAdmin {
        &self.base.sessions
    }
    fn recovery(&self) -> &Self::Recovery {
        &self.base.recovery
    }
    fn break_glass(&self) -> &Self::BreakGlass {
        &self.base.break_glass
    }
    fn tenant(&self) -> &Self::Tenant {
        &self.base.tenant
    }
    fn outbox(&self) -> &Self::Outbox {
        &self.base.outbox
    }
    fn prober(&self) -> &Self::Prober {
        &self.base.prober
    }
    fn clock(&self) -> &Self::Clock {
        &self.base.clock
    }
    fn ids(&self) -> &Self::Ids {
        &self.base.ids
    }
    fn tokens(&self) -> &Self::Tokens {
        &self.base.tokens
    }
}

// ---------------------------------------------------------------------------
// Building a world
// ---------------------------------------------------------------------------

/// A built world: the ports, the API core and the targets.
pub struct Built {
    ports: WorldPorts,
    core: Arc<ApiCore>,
    router: Option<fstp_web::WebRouter>,
    /// The MCP server of the MCP channel, built on first use.
    mcp: Option<fstp_mcp::McpServer>,
    targets: Targets,
    /// The cell clock.
    now: i64,
    /// The tenant revision a step save names.
    tenant_revision: String,
    /// The tenant admins.
    admins: Vec<AccountId>,
    /// P-01: the number of criteria and the top of the scale.
    criteria: usize,
    scale: u32,
    /// The P-09 criteria.
    knock_outs: Vec<u128>,
    /// The RANKED proposals of C, in the order a round names them.
    ranked: Vec<ProposalId>,
    /// The ledger head after the build.
    head: fstp_ledger::Seq,
    /// Whether a cell changed the world.
    dirty: bool,
}

impl std::fmt::Debug for Built {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Built")
            .field("targets", &self.targets)
            .finish_non_exhaustive()
    }
}

/// The seeder of one world.
struct Seeder {
    ports: WorldPorts,
    core: Arc<ApiCore>,
    now: i64,
    command: u32,
    cookies: BTreeMap<AccountId, WebLogin>,
    next_id: u128,
    admins: BTreeSet<AccountId>,
}

impl Seeder {
    /// The next instant: one second later.
    fn tick(&mut self) -> Timestamp {
        self.now = self.now.saturating_add(SECOND);
        self.ports.clock.set(Timestamp::from_micros(self.now));
        Timestamp::from_micros(self.now)
    }

    /// Moves the clock to `t`, if later.
    fn at(&mut self, t: i64) {
        if t > self.now {
            self.now = t;
            self.ports.clock.set(Timestamp::from_micros(self.now));
        }
    }

    /// A fresh id for an engine command.
    fn id(&mut self) -> u128 {
        self.next_id = self.next_id.saturating_add(1);
        self.next_id
    }

    /// The context of a command by `actor` at the next instant.
    fn ctx(&mut self, actor: Actor) -> Ctx {
        let now = self.tick();
        self.command = self.command.saturating_add(1);
        let mut b = *b"fstp:matrix:\0\0\0\0";
        for (slot, x) in b.iter_mut().skip(12).zip(self.command.to_be_bytes()) {
            *slot = x;
        }
        let admin = matches!(actor, Actor::Account(a) if self.admins.contains(&a));
        Ctx {
            now,
            actor,
            command: CommandId::from_bytes(b),
            via: Via::Web,
            tenant_admin: admin,
            second_tenant_admin: None,
            binds_tenant_admin: false,
        }
    }

    /// Runs `cmd` by `account` on the engine port's driver.
    fn by(&mut self, account: AccountId, cmd: Core) -> Result<(), String> {
        let kind = cmd.kind();
        let ctx = self.ctx(Actor::Account(account));
        self.ports
            .engine
            .environment(Command::Core(cmd), ctx)
            .map(|_| ())
            .map_err(|e| format!("{kind:?} by {}: {e}", account.raw()))
    }

    /// Runs `cmd` by the system on the engine port's driver.
    fn system(&mut self, cause: SystemCause, cmd: Core) -> Result<(), String> {
        let kind = cmd.kind();
        let ctx = self.ctx(Actor::System(cause));
        self.ports
            .engine
            .environment(Command::Core(cmd), ctx)
            .map(|_| ())
            .map_err(|e| format!("{kind:?} by the system: {e}"))
    }

    /// Records finding 1 on `x` of `call` through the assessor's system
    /// path under the call's pin (I-10, I-11). `review.mark_finding` and
    /// `review.findings` address it.
    fn finding(&mut self, call: CallId, x: ProposalId) -> Result<(), String> {
        let state = self.ports.engine.state();
        let config = state
            .core
            .calls()
            .get(call)
            .and_then(|v| v.llm_config())
            .ok_or("the call has no assessor pin")?;
        let f = fstp_domain_testkit::r#gen::findings::finding(
            1,
            call,
            x,
            config,
            fstp_engine::FindingKind::Completeness,
            "SYNTHETIC FINDING",
        );
        let ctx = self.ctx(Actor::System(SystemCause::Timeline));
        self.ports
            .engine
            .environment(
                Command::Finding(fstp_engine::FindingCommand::Record(f)),
                ctx,
            )
            .map(|_| ())
            .map_err(|e| format!("a finding by the assessor: {e}"))
    }

    /// The passkey session of `account`.
    fn login(&mut self, account: AccountId) -> WebLogin {
        if let Some(l) = self.cookies.get(&account) {
            return l.clone();
        }
        let l = self.ports.sessions.login(account, LoginMethod::Passkey);
        self.cookies.insert(account, l.clone());
        l
    }

    /// Calls the API through the web as `account` at the next instant,
    /// answering a step-up challenge once.
    fn api(
        &mut self,
        account: AccountId,
        method: ApiMethod,
        path: &str,
        body: &Value,
    ) -> Result<Value, String> {
        self.tick();
        let l = self.login(account);
        let bytes = match body {
            Value::Null => Vec::new(),
            v => v.to_compact().into_bytes(),
        };
        let call = |core: &ApiCore| -> Result<OpResult, ApiError> {
            let op = decode_route(method, path, &bytes)?;
            block_on(core.dispatch(
                Credential::SessionCookie(l.cookie.clone()),
                &RequestHead::new(),
                op,
            ))
        };
        let mut r = call(&self.core);
        if let Ok(OpResult::StepUpRequired(ch)) = &r {
            self.ports
                .step_up
                .approve(l.session, ch.action)
                .map_err(|e| format!("{path}: the step-up: {e:?}"))?;
            r = call(&self.core);
        }
        match r {
            Ok(OpResult::Done { body, .. }) => Ok(body.to_json()),
            Ok(other) => Err(format!("{path}: {}", other.to_json().to_compact())),
            Err(e) => Err(format!("{path}: {}", e.to_json().to_compact())),
        }
    }
}

/// The JSON form of the tenant record `r`, as the engine stores it.
fn tenant_record(inner: Value) -> Result<Record, String> {
    let stored = obj(vec![("onboarding", inner)]);
    record_from_json_at(1, &stored).map_err(|e| format!("a tenant record: {e:?}"))
}

/// Appends `records` at `at` as setup entry `n`.
fn append(
    store: &mut MemStore<Record>,
    at: i64,
    n: u8,
    records: Vec<Record>,
) -> Result<(), String> {
    let head = store.head();
    let mut command = [0x6d; 16];
    command[15] = n;
    store
        .append(head, at, command, records)
        .map(|_| ())
        .map_err(|e| format!("setup entry {n}: {e:?}"))
}

/// The vault of every world: each cast account with its own verified
/// identity, adult from the call's opening; X's proposal has its
/// guardian's consent.
fn truth() -> GroundTruth {
    let mut t = GroundTruth::new();
    for (i, a) in (0u64..).zip(CAST.iter()) {
        t.set_identity(*a, IdentityTag::new(10_000u64.saturating_add(i)));
        t.verify(*a);
        t.attest_adult(*a, Timestamp::from_micros(0));
    }
    t
}

/// The ledger of a fresh tenant: the provisioning of its first admin and,
/// unless `sole`, the second admin's invitation and enrolment, as the M3
/// enrolment appends them (Q31 A).
fn tenant_ledger(sole: bool) -> Result<(MemStore<Record>, BTreeSet<AccountId>), String> {
    let first = if sole { ADMIN_SOLE } else { ADMIN_BUILDER };
    let mut store = MemStore::new();
    let prov = obj(vec![
        (
            "agreements",
            obj(vec![
                ("dpa", s("1")),
                ("saas_terms", s("1")),
                ("sub_processors", s("1")),
            ]),
        ),
        ("cell", s("saas")),
        ("first_admin", dec(first.raw())),
        ("kind", s("TenantProvisioned")),
    ]);
    append(&mut store, T_SETUP, 1, vec![tenant_record(prov)?])?;
    let mut admins: BTreeSet<AccountId> = [first].into_iter().collect();
    if !sole {
        let invitation = fstp_tenant::InvitationId::from_raw(0x1a2);
        let invited = fstp_tenant::TenantRecord::AdminInvited {
            invitation,
            invitee: ADMIN_PLAIN,
            token_digest: fstp_tenant::TokenDigest::from_bytes([0xd2; 32]),
            by: first,
        };
        let added = fstp_tenant::TenantRecord::AdminAdded {
            account: ADMIN_PLAIN,
            invitation,
        };
        for (n, r) in [(2u8, invited), (3u8, added)] {
            let bytes = fstp_tenant::encode_record(&r).map_err(|e| format!("{e:?}"))?;
            let v = fstp_json::parse(&bytes).map_err(|e| format!("{e:?}"))?;
            append(&mut store, T_SETUP, n, vec![tenant_record(v)?])?;
        }
        admins.insert(ADMIN_PLAIN);
    }
    Ok((store, admins))
}

/// Walks onboarding until `stop`, the first step not validated, or to the
/// end and the completion when `stop` is `None`.
fn onboard(
    seed: &mut Seeder,
    stop: Option<OnboardStep>,
    admins: &[AccountId],
) -> Result<(), String> {
    let admin = admins.first().copied().ok_or("no admin")?;
    // SoD-14, SoD-15: the Administrators step validates only with a holder
    // of each signatory role. The grants come first, so every built state
    // holds the binding that `tenant.end_signatory` names.
    for role in ["financial_signatory", "legal_signatory"] {
        seed.api(
            admin,
            ApiMethod::Post,
            "/admin/signatories",
            &obj(vec![
                ("account", dec(ORG_SIGNATORY.raw())),
                ("role", s(role)),
            ]),
        )?;
    }
    for step in OnboardStep::ALL {
        if Some(step) == stop {
            return Ok(());
        }
        let name = onboard_name(step);
        if step == OnboardStep::Payments {
            seed.api(
                admin,
                ApiMethod::Put,
                "/admin/settings/payment-mode",
                &obj(vec![("value", s("record_only"))]),
            )?;
        }
        let view = seed.api(
            admin,
            ApiMethod::Get,
            &format!("/admin/onboarding/{name}"),
            &Value::Null,
        )?;
        let base = str_member(&view, "revision").ok_or("no revision")?;
        let saved = seed.api(
            admin,
            ApiMethod::Put,
            &format!("/admin/onboarding/{name}"),
            &obj(vec![
                ("base", s(&base)),
                ("values", step_values(name, admins)),
            ]),
        )?;
        if str_member(&saved, "outcome").as_deref() != Some("validated") {
            if step == OnboardStep::Administrators && admins.len() < 2 {
                return Ok(());
            }
            return Err(format!("onboarding step {name}: {}", saved.to_compact()));
        }
    }
    seed.api(
        admin,
        ApiMethod::Post,
        "/admin/onboarding/complete",
        &obj(vec![]),
    )?;
    Ok(())
}

/// The head revision of the draft of `p`, in the wire form
/// `"<seq>.<entry>"` that `creator.get_draft` shows. The harness reads it
/// from the engine state, since `creator.get_draft` waits for a seam of
/// lane m4creator.
fn draft_revision(seed: &mut Seeder, _reader: AccountId, p: ProgrammeId) -> Result<String, String> {
    let state = seed.ports.engine.state();
    let r = state
        .creator
        .head(p)
        .ok_or_else(|| format!("no draft of {}", p.raw()))?;
    Ok(format!("{}.{}", r.seq(), r.entry().raw()))
}

/// The template narratives of the SuperSAFE start that wait for
/// acceptance in the draft of `p` (TH-49): the fields the template sets
/// that the start left unset and nobody accepted yet. Only an artefact
/// field takes an acceptance; a policy field such as P-09 is saved with
/// its value instead.
fn pending_narratives(seed: &Seeder, p: ProgrammeId) -> Result<Vec<String>, String> {
    let template = fstp_programme::shipped_templates()
        .map_err(|e| format!("templates: {e:?}"))?
        .into_iter()
        .find(|t| t.id == fstp_programme::SUPERSAFE_TEMPLATE && t.version.get() == 1)
        .ok_or("no SuperSAFE template")?;
    let state = seed.ports.engine.state();
    let d = state
        .creator
        .draft(p)
        .ok_or_else(|| format!("no draft of {}", p.raw()))?;
    let set = d.set_fields();
    // The template values a start leaves for acceptance: narrative text,
    // and P-09 while its wording is inline (`programme-creator.md`, TH-49).
    let waits = |v: &fstp_programme::FieldValue| {
        use fstp_programme::FieldValue as V;
        match v {
            V::ActionAcronym(_)
            | V::CoordinatorName(_)
            | V::ProgrammeName(_)
            | V::ProgrammeNarrative(_)
            | V::ProgrammeScope(_)
            | V::PersonsSupported(_)
            | V::Minors(_)
            | V::AmountCriteria(_)
            | V::Faq(_)
            | V::ProgrammeContact(_)
            | V::MessageTemplates(_) => true,
            V::P09(k) => k
                .items()
                .iter()
                .any(|x| matches!(x.text, fstp_programme::Narrative::Inline(_))),
            _ => false,
        }
    };
    Ok(fstp_programme::FieldId::ALL
        .iter()
        .filter(|f| f.spec().map(|s| s.kind) == Some(fstp_programme::FieldKind::Artefact))
        .filter(|f| match template.spec.get(**f) {
            fstp_programme::Field::Set(v) => waits(&v),
            fstp_programme::Field::Unset => false,
        })
        .filter(|f| !set.contains(f) && !d.narratives().contains(f))
        .map(|f| f.key())
        .collect())
}

/// Grants `role` on `p` to `account` through the engine, by `grantor`.
fn grant(
    seed: &mut Seeder,
    grantor: AccountId,
    account: AccountId,
    p: ProgrammeId,
    role: Role,
) -> Result<BindingId, String> {
    let binding = BindingId::from_raw(seed.id());
    let start = Timestamp::from_micros(seed.now.saturating_add(SECOND));
    let confidentiality = (!matches!(
        role,
        Role::Applicant | Role::ApplicantTeamMember | Role::Guardian
    ))
    .then(|| fstp_domain_testkit::r#gen::policy::text(binding.raw().saturating_add(50_000)));
    seed.by(
        grantor,
        Core::GrantRole {
            binding,
            account,
            programme: p,
            role,
            start,
            second_admin: None,
            confidentiality,
            organisation: matches!(role, Role::CommitteeMember | Role::CommitteeChair)
                .then(|| fstp_domain::id::OrganisationId::from_raw(account.raw())),
            end: None,
        },
    )?;
    Ok(binding)
}

/// The field edits the programme manager saves after the start: every
/// value of the SuperSAFE fixture that the draft of `p` still lacks, as
/// the fixture spells it, and the policy row, which takes precedence.
fn draft_fields(seed: &Seeder, p: ProgrammeId, policy: &Policy) -> Result<Value, String> {
    let fixture = fstp_programme::supersafe_fixture().map_err(|e| format!("fixture: {e:?}"))?;
    let state = seed.ports.engine.state();
    let d = state
        .creator
        .draft(p)
        .ok_or_else(|| format!("no draft of {}", p.raw()))?;
    let set = d.set_fields();
    let row = policy_fields(policy);
    let row_keys: BTreeSet<String> = row
        .as_array()
        .map(|a| a.iter().filter_map(|e| str_member(e, "field")).collect())
        .unwrap_or_default();
    let mut out: Vec<Value> = Vec::new();
    for f in fstp_programme::FieldId::ALL.iter() {
        let key = f.key();
        if set.contains(f) || row_keys.contains(&key) {
            continue;
        }
        if let fstp_programme::Field::Set(_) = fixture.spec.get(*f) {
            let mut value = fixture_value(&key)?;
            if *f == fstp_programme::FieldId::P09 {
                value = stored_wording(seed, p, &value)?;
            }
            out.push(obj(vec![("field", s(&key)), ("value", value)]));
        }
    }
    if let Some(a) = row.as_array() {
        out.extend(a.iter().cloned());
    }
    Ok(Value::Array(Array::from(out)))
}

/// The P-09 criteria of `value` with each inline wording stored as a
/// public text of `p` first, since no ledger body holds inline text
/// (ADR-007). A stored text is `{digest, text}` (`fstp_programme`
/// `Narrative`).
fn stored_wording(seed: &Seeder, p: ProgrammeId, value: &Value) -> Result<Value, String> {
    let items = value.as_array().ok_or("P-09 is not a list")?;
    let mut out = Vec::new();
    for item in items.iter() {
        let o = item
            .as_object()
            .ok_or("a P-09 criterion is not an object")?;
        let mut o = o.clone();
        if let Some(text) = o.get("text").and_then(Value::as_str).map(str::to_owned) {
            let r = seed.ports.texts.put_now(
                fstp_api_core::port::TextClass::Public,
                fstp_api_core::port::TextOwner::Programme(p),
                text.as_bytes(),
            );
            let digest: String = fstp_crypto::sha256(text.as_bytes())
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            let _ = o.insert(
                "text",
                obj(vec![("digest", s(&digest)), ("text", dec(r.0))]),
            );
        }
        out.push(Value::Object(o));
    }
    Ok(Value::Array(Array::from(out)))
}

/// The JSON field values of a policy row, as `creator.save_fields` sends
/// them.
fn policy_fields(p: &Policy) -> Value {
    let p10 = match p.p10 {
        P10::AssignedOnly => "assigned_reviewers_only",
        P10::AllCommittee => "all_committee_members",
        P10::OperatorStaffOnly => "operator_staff_only",
    };
    let p11 = if p.p11_anonymous {
        "anonymous"
    } else {
        "named"
    };
    let p77 = if p.p77_draft_only {
        "draft_only"
    } else {
        "allowed"
    };
    let field = |k: &str, v: Value| obj(vec![("field", s(k)), ("value", v)]);
    Value::Array(Array::from(vec![
        field("evaluation.p10_read_access", s(p10)),
        field("evaluation.p11_anonymity", s(p11)),
        field("evaluation.p28_rubric_bands", Value::Bool(p.p28_on)),
        field("evaluation.p75_agent_content_reads", Value::Bool(p.p75_on)),
        field("evaluation.p77_mcp_binding_actions", s(p77)),
    ]))
}

/// The results of a report: check, severity, whether acknowledged, key.
fn report_rows(report: &Value) -> Vec<(String, String, bool, String)> {
    let mut out = Vec::new();
    let Some(rows) = report
        .as_object()
        .and_then(|o| o.get("results"))
        .and_then(Value::as_array)
    else {
        return out;
    };
    for r in rows.iter() {
        let check = str_member(r, "check").unwrap_or_default();
        let severity = str_member(r, "severity").unwrap_or_default();
        let ack = r
            .as_object()
            .and_then(|o| o.get("acknowledged"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let key = str_member(r, "key").unwrap_or_else(|| check.clone());
        out.push((check, severity, ack, key));
    }
    out
}

/// Opens the draft P as `opener`, with `pm` granted its manager.
fn open_draft(seed: &mut Seeder, opener: AccountId, pm: AccountId) -> Result<ProgrammeId, String> {
    let body = seed.api(opener, ApiMethod::Post, "/programmes", &obj(vec![]))?;
    let raw: u128 = str_member(&body, "programme")
        .and_then(|x| x.parse().ok())
        .ok_or_else(|| format!("creator.open_draft gave {}", body.to_compact()))?;
    let p = ProgrammeId::from_raw(raw);
    grant(seed, opener, pm, p, Role::ProgrammeManager)?;
    Ok(p)
}

/// Builds the draft P to a clean report, but for the `tolerated` checks,
/// with the policy row saved. Returns the key of its first warning and the
/// field of its first accepted narrative, which the `creator.acknowledge`
/// and `creator.accept_narrative` cells name.
fn build_draft(
    seed: &mut Seeder,
    p: ProgrammeId,
    policy: &Policy,
    tolerated: &[&str],
) -> Result<(Option<String>, Option<String>), String> {
    let rev = draft_revision(seed, PM, p)?;
    seed.api(
        PM,
        ApiMethod::Post,
        &format!("/programmes/{}/draft/start", p.raw()),
        &obj(vec![
            ("base", s(&rev)),
            ("start", crate::fake::creator_requests::supersafe_start()),
        ]),
    )?;
    let narratives = pending_narratives(seed, p)?;
    let narrative = narratives.first().cloned();
    for key in narratives {
        let base = draft_revision(seed, PM, p)?;
        seed.api(
            PM,
            ApiMethod::Post,
            &format!("/programmes/{}/draft/narratives/{key}/acceptance", p.raw()),
            &obj(vec![("base", s(&base))]),
        )?;
    }
    let rev = draft_revision(seed, PM, p)?;
    seed.api(
        PM,
        ApiMethod::Put,
        &format!("/programmes/{}/draft/fields", p.raw()),
        &obj(vec![
            ("base", s(&rev)),
            ("fields", draft_fields(seed, p, policy)?),
        ]),
    )?;
    let report = seed.api(
        PM,
        ApiMethod::Get,
        &format!("/programmes/{}/draft/report", p.raw()),
        &Value::Null,
    )?;
    let rows = report_rows(&report);
    let failures: Vec<&str> = rows
        .iter()
        .filter(|r| r.1 == "failure")
        .map(|r| r.0.as_str())
        .filter(|c| !tolerated.contains(c))
        .collect();
    if !failures.is_empty() {
        return Err(format!("the draft report fails: {failures:?}"));
    }
    let first = rows.iter().find(|r| r.1 == "warning").map(|r| r.3.clone());
    for (_, _, ack, key) in rows.iter().filter(|r| r.1 == "warning") {
        if *ack {
            continue;
        }
        let rev = draft_revision(seed, PM, p)?;
        seed.api(
            PM,
            ApiMethod::Post,
            &format!("/programmes/{}/draft/acknowledgements", p.raw()),
            &obj(vec![("revision", s(&rev)), ("warning", s(key))]),
        )?;
    }
    Ok((first, narrative))
}

/// Requests and approves the activation of the built draft P.
fn activate(seed: &mut Seeder, p: ProgrammeId, approver: AccountId) -> Result<(), String> {
    let rev = draft_revision(seed, PM, p)?;
    seed.api(
        PM,
        ApiMethod::Post,
        &format!("/programmes/{}/activation-request", p.raw()),
        &obj(vec![("revision", s(&rev))]),
    )?;
    let rev = draft_revision(seed, PM, p)?;
    seed.api(
        approver,
        ApiMethod::Post,
        &format!("/programmes/{}/activation", p.raw()),
        &obj(vec![("revision", s(&rev))]),
    )?;
    Ok(())
}

/// Acknowledges every warning of the draft P that has no live
/// acknowledgement, then requests its activation as its manager, so the
/// request is live at the head revision. The clock moves with each call,
/// so a binding end scheduled meanwhile can raise a fresh warning: the
/// report is read again until it shows none unacknowledged.
fn request_live(seed: &mut Seeder, p: ProgrammeId) -> Result<(), String> {
    for _ in 0..3 {
        let report = seed.api(
            PM,
            ApiMethod::Get,
            &format!("/programmes/{}/draft/report", p.raw()),
            &Value::Null,
        )?;
        let open: Vec<String> = report_rows(&report)
            .into_iter()
            .filter(|(_, severity, ack, _)| severity == "warning" && !ack)
            .map(|(_, _, _, key)| key)
            .collect();
        if open.is_empty() {
            break;
        }
        for key in open {
            let rev = draft_revision(seed, PM, p)?;
            seed.api(
                PM,
                ApiMethod::Post,
                &format!("/programmes/{}/draft/acknowledgements", p.raw()),
                &obj(vec![("revision", s(&rev)), ("warning", s(&key))]),
            )?;
        }
    }
    // A report that does not clear refuses the request with I-66, and the
    // world keeps no live request, as before this step.
    let rev = draft_revision(seed, PM, p)?;
    let _ = seed.api(
        PM,
        ApiMethod::Post,
        &format!("/programmes/{}/activation-request", p.raw()),
        &obj(vec![("revision", s(&rev))]),
    );
    Ok(())
}

/// The pending actions of the call authors of the active programme P
/// (I-85, R-MC-05): under a P-77 "draft only" row each drafts a call
/// through MCP, which waits for a web confirmation, keyed by account with
/// its digest. MCP prepares no operation of another account without a
/// step-up, so the `pending.*` cells of the others name no action. The
/// calls run at the world's instant, so no action has expired.
fn pending_actions(
    seed: &mut Seeder,
    p: ProgrammeId,
) -> Result<BTreeMap<AccountId, (PendingId, String)>, String> {
    let mut out = BTreeMap::new();
    let args = obj(vec![
        ("programme", s(&p.raw().to_string())),
        ("opens", dec(u128::try_from(OPENS).unwrap_or(0))),
        ("deadline", dec(u128::try_from(DEADLINE).unwrap_or(0))),
        ("deadline_zone", s("Europe/Brussels")),
        ("currency", s("EUR")),
        ("budget", s("400000.00")),
        ("text", s("SYNTHETIC PENDING CALL TEXT")),
    ])
    .to_compact()
    .into_bytes();
    for a in [PM, PM_DRAFTER, DRAFTER] {
        let token = seed
            .ports
            .tokens
            .issue(a, agent_of(a), Scope::ALL, LoginMethod::Passkey);
        let r = decode_tool("fstp_draft_call", &args).and_then(|op| {
            block_on(
                seed.core
                    .dispatch(Credential::Bearer(token), &RequestHead::new(), op),
            )
        });
        let Ok(OpResult::Pending(receipt)) = r else {
            continue;
        };
        let cookie = seed.login(a).cookie;
        let list = decode_route(ApiMethod::Get, "/me/pending-actions", &[])
            .and_then(|op| {
                block_on(seed.core.dispatch(
                    Credential::SessionCookie(cookie),
                    &RequestHead::new(),
                    op,
                ))
            })
            .map_err(|e| format!("pending.list: {}", e.to_json().to_compact()))?;
        let OpResult::Done { body, .. } = list else {
            return Err("pending.list did not complete".to_owned());
        };
        let id = receipt.id.raw().to_string();
        let digest = body
            .to_json()
            .as_array()
            .and_then(|rows| {
                rows.iter()
                    .find(|r| str_member(r, "id").as_deref() == Some(id.as_str()))
                    .and_then(|r| str_member(r, "digest"))
            })
            .ok_or_else(|| format!("pending.list does not show the action {id}"))?;
        out.insert(a, (receipt.id, digest));
    }
    Ok(out)
}

/// What a world's lifecycle reached, for the targets.
#[derive(Default)]
struct Reached {
    call: Option<CallId>,
    proposal: Option<ProposalId>,
    plan: Option<u128>,
    assignments: BTreeMap<AccountId, AssignmentId>,
    irc: BTreeMap<AccountId, AssignmentId>,
    round: Option<DecisionId>,
    ranked: Vec<ProposalId>,
    binding_end: Option<BindingId>,
    /// M5 lane L-API: the drafted contract, the proposed amendment and
    /// the generated report of a GRANTED world, and the payment request
    /// under review and its line of an IN_EXECUTION world.
    contract: Option<u128>,
    amendment: Option<u128>,
    report: Option<u128>,
    request: Option<u128>,
    line: Option<u128>,
    /// A request whose lines were accepted, and one approved for payment.
    accepted: Option<u128>,
    approved: Option<u128>,
}

/// The lifecycle position of a state: how far C and X go.
fn depth(state: StateProfile) -> u8 {
    match state {
        StateProfile::Onboarding(_) | StateProfile::ProgrammeDraft => 0,
        StateProfile::ProgrammeActive => 1,
        StateProfile::CallDrafted => 2,
        StateProfile::CallApproved => 3,
        StateProfile::CallOpen | StateProfile::CallClosed => 4,
        StateProfile::Proposal(_) => 5,
    }
}

/// The ports and API core of a cell over `store`, with the attested
/// tenant admin set `admins`.
fn fresh_cell(
    store: MemStore<Record>,
    admins: &BTreeSet<AccountId>,
    start: i64,
) -> Result<(WorldPorts, Arc<ApiCore>), String> {
    let world = FakeWorld {
        store: MemStore::new(),
        truth: truth(),
        start: Timestamp::from_micros(start),
        admins: admins.clone(),
    };
    let seams = crate::fake::port_seams().map_err(|e| e.to_string())?;
    let base = FakePorts::new(&world, seams).map_err(|e| e.to_string())?;
    let engine = WorldEngine::open(store, &base)?;
    let ports = WorldPorts { base, engine };
    let core = Arc::new(api_core(ports.clone()));
    Ok((ports, core))
}

/// What the expensive start of a world leaves: the tenant onboarded, the
/// programme P built through the creator, and P2 opened.
///
/// The creator decides every draft command with its full validation, so
/// building P takes long. Every world of one policy row and variant
/// shares the same start, so it is built once and replayed: a world opens
/// a fresh cell over a copy of the start's ledger and texts. The P-09
/// wording of the draft is a public text the ledger names by reference, so
/// without the texts no open call would be public. The API core's memory
/// of the start is not carried over. It holds only the data protection
/// contact of the Organisation step, which no cell of a programme state
/// reads.
#[derive(Clone)]
struct Start {
    store: MemStore<Record>,
    /// The texts stored during the start, under the references its ledger
    /// names.
    texts: crate::fake::FakeTexts,
    admins: BTreeSet<AccountId>,
    programme: ProgrammeId,
    now: i64,
    next_id: u128,
    command: u32,
    drawn: u128,
    /// The key of the draft report's first warning.
    warning: Option<String>,
    /// The field of the draft's first template narrative.
    narrative: Option<String>,
}

/// The key of a [`Start`]: the variant, whether P is activated and the
/// policy row.
type StartKey = (bool, bool, Policy);

/// One start, built once by the first thread that asks for it.
type StartSlot = Arc<std::sync::OnceLock<Result<Start, String>>>;

/// The starts by key.
type StartCache = std::sync::Mutex<BTreeMap<StartKey, StartSlot>>;

/// The cache of starts, shared by every thread.
fn starts() -> &'static StartCache {
    static CACHE: std::sync::OnceLock<StartCache> = std::sync::OnceLock::new();
    CACHE.get_or_init(|| std::sync::Mutex::new(BTreeMap::new()))
}

/// The start of `key`, built once.
fn start_of(key: StartKey) -> Result<Start, String> {
    let slot = {
        let mut cache = starts()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Arc::clone(
            cache
                .entry(key)
                .or_insert_with(|| Arc::new(std::sync::OnceLock::new())),
        )
    };
    slot.get_or_init(|| build_start(key)).clone()
}

/// The JSON value of the fixture's field `key`, `"<step>.<member>"`.
fn fixture_value(key: &str) -> Result<Value, String> {
    let v = fstp_json::parse(fstp_programme::SUPERSAFE_FIXTURE.as_bytes())
        .map_err(|e| format!("fixture: {e:?}"))?;
    let (step, member) = key.split_once('.').ok_or("field key")?;
    v.as_object()
        .and_then(|o| o.get("spec"))
        .and_then(Value::as_object)
        .and_then(|o| o.get(step))
        .and_then(Value::as_object)
        .and_then(|o| o.get(member))
        .cloned()
        .ok_or_else(|| format!("the fixture sets no {key}"))
}

/// Builds the start of `key`.
fn build_start(key: StartKey) -> Result<Start, String> {
    let (sole, activated, policy) = key;
    let (store, admins) = tenant_ledger(sole)?;
    let (ports, core) = fresh_cell(store, &admins, T_SETUP)?;
    let mut seed = Seeder {
        ports,
        core,
        now: T_SETUP,
        command: 0,
        cookies: BTreeMap::new(),
        next_id: 5_000_000,
        admins: admins.clone(),
    };
    let admin_list: Vec<AccountId> = admins.iter().copied().collect();
    seed.at(T_SETUP);
    let stop = sole.then_some(OnboardStep::Administrators);
    onboard(&mut seed, stop, &admin_list)?;
    let first_admin = if sole { ADMIN_SOLE } else { ADMIN_BUILDER };
    if policy.p74 != P74::AllRoles {
        seed.api(
            first_admin,
            ApiMethod::Put,
            "/admin/settings/mcp",
            &obj(vec![("value", mcp_value(policy.p74))]),
        )?;
    }
    let p = open_draft(&mut seed, first_admin, PM)?;
    if !sole {
        grant(&mut seed, first_admin, PM_ENDED, p, Role::ProgrammeManager)?;
    }
    // The only admin cannot have the activation approved by another
    // (I-67), so the report of a sole-admin draft keeps that failure.
    let tolerated: &[&str] = if sole { &["TooFewTenantAdmins"] } else { &[] };
    let (warning, narrative) = build_draft(&mut seed, p, &policy, tolerated)?;
    if activated {
        activate(&mut seed, p, ADMIN_PLAIN)?;
    }
    if !sole {
        other_programme(&mut seed)?;
    }
    let store = seed.ports.engine.store_copy();
    let texts = crate::fake::FakeTexts::default();
    texts.copy_from(&seed.ports.texts);
    Ok(Start {
        store,
        texts,
        admins,
        programme: p,
        now: seed.now,
        next_id: seed.next_id,
        command: seed.command,
        drawn: seed.ports.ids.drawn(),
        warning,
        narrative,
    })
}

/// Builds the world of `key`.
pub fn build(key: WorldKey) -> Result<Built, String> {
    let sole = key.variant == Variant::Sole;
    let mut reached = Reached::default();
    let mut programme = None;
    let mut revision = None;
    let mut warning = None;
    let mut narrative = None;
    let first_admin = if sole { ADMIN_SOLE } else { ADMIN_BUILDER };
    let mut seed = if let StateProfile::Onboarding(step) = key.state {
        let (store, admins) = tenant_ledger(sole)?;
        let (ports, core) = fresh_cell(store, &admins, T_SETUP)?;
        let mut seed = Seeder {
            ports,
            core,
            now: T_SETUP,
            command: 0,
            cookies: BTreeMap::new(),
            next_id: 5_000_000,
            admins: admins.clone(),
        };
        seed.at(T_SETUP);
        let admin_list: Vec<AccountId> = admins.iter().copied().collect();
        onboard(&mut seed, Some(step), &admin_list)?;
        if key.policy.p74 != P74::AllRoles {
            seed.api(
                first_admin,
                ApiMethod::Put,
                "/admin/settings/mcp",
                &obj(vec![("value", mcp_value(key.policy.p74))]),
            )?;
        }
        seed
    } else {
        let activated = !sole && depth(key.state) >= 1;
        let start = start_of((sole, activated, key.policy))?;
        let (ports, core) = fresh_cell(start.store.clone(), &start.admins, start.now)?;
        ports.texts.copy_from(&start.texts);
        for _ in 0..start.drawn {
            let _ = fstp_api_core::port::Ids::fresh(&ports.ids);
        }
        let mut seed = Seeder {
            ports,
            core,
            now: start.now,
            command: start.command,
            cookies: BTreeMap::new(),
            next_id: start.next_id,
            admins: start.admins.clone(),
        };
        seed.at(start.now);
        let p = start.programme;
        programme = Some(p);
        warning = start.warning.clone();
        narrative = start.narrative.clone();
        if activated {
            staff(&mut seed, p, &mut reached)?;
            lifecycle(&mut seed, p, key, &mut reached)?;
        }
        end_binding_of(&mut seed, p, PM_ENDED, key)?;
        // The end of a binding on the draft is an edit, so the creator
        // cells name the revision after it, and an approval cell meets a
        // live request there (design 3.7 step 5). The report of a
        // sole-admin draft fails, so no request is admitted.
        if !activated && !sole {
            request_live(&mut seed, p)?;
        }
        revision = Some(draft_revision(&mut seed, PM, p)?);
        seed
    };
    let now = match key.state {
        StateProfile::Proposal(StateTag::Draft) | StateProfile::CallOpen => NOW_OPEN,
        StateProfile::Proposal(
            StateTag::InExecution | StateTag::Completed | StateTag::Terminated,
        ) => NOW_EXECUTING,
        StateProfile::Onboarding(_)
        | StateProfile::ProgrammeDraft
        | StateProfile::ProgrammeActive
        | StateProfile::CallDrafted
        | StateProfile::CallApproved => seed.now.saturating_add(SECOND),
        _ => NOW_CLOSED,
    };
    if now < seed.now {
        return Err(format!(
            "the world of {key:?} took until {} but its cell clock is {now}",
            seed.now
        ));
    }
    seed.at(now);
    let pending = match programme {
        Some(p) if !sole && depth(key.state) >= 1 && key.policy.p77_draft_only => {
            pending_actions(&mut seed, p)?
        }
        _ => BTreeMap::new(),
    };
    let tenant_revision = {
        let v = seed.api(
            first_admin,
            ApiMethod::Get,
            &format!("/admin/onboarding/{}", step_name(key.state)),
            &Value::Null,
        )?;
        str_member(&v, "revision").unwrap_or_else(|| "0".to_owned())
    };
    let state = seed.ports.engine.state();
    let (criteria, scale, knock_outs) =
        match programme.and_then(|p| fstp_domain::policy::head(&state.core, p)) {
            Some(v) => (
                v.frozen.p01.items().len(),
                u32::from(v.frozen.p01.scale_max().get()),
                v.frozen.p09.0.iter().map(|k| k.id.raw()).collect(),
            ),
            None => (3, 5, Vec::new()),
        };
    let admin_list: Vec<AccountId> = seed.admins.iter().copied().collect();
    let targets = Targets {
        programme,
        slug: "supersafe".to_owned(),
        call: reached.call,
        proposal: reached.proposal,
        plan: reached.plan,
        assignments: reached.assignments,
        irc: reached.irc,
        round: reached.round,
        invitation: None,
        revision,
        binding_end: reached.binding_end,
        narrative,
        warning,
        pending,
        p71: seed.ports.step_up.p71(),
        contract: reached.contract,
        amendment: reached.amendment,
        report: reached.report,
        request: reached.request,
        line: reached.line,
        accepted: reached.accepted,
        approved: reached.approved,
    };
    let head = seed.ports.engine.head();
    Ok(Built {
        ports: seed.ports,
        core: seed.core,
        router: None,
        mcp: None,
        targets,
        now,
        tenant_revision,
        admins: admin_list,
        criteria,
        scale,
        knock_outs,
        ranked: reached.ranked,
        head,
        dirty: false,
    })
}

/// P2, the other programme of the tenant, with [`PM_OTHER`] its manager.
fn other_programme(seed: &mut Seeder) -> Result<(), String> {
    let p2 = open_draft(seed, ADMIN_BUILDER, PM_OTHER)?;
    let _ = p2;
    Ok(())
}

/// Ends the binding of `account` on `p`, once every step of the world
/// that needs it ran.
fn end_binding_of(
    seed: &mut Seeder,
    p: ProgrammeId,
    account: AccountId,
    key: WorldKey,
) -> Result<(), String> {
    if key.variant == Variant::Sole {
        return Ok(());
    }
    let state = seed.ports.engine.state();
    let binding = state
        .core
        .roster()
        .bindings()
        .find(|(_, b)| b.account == account && b.programme == p)
        .map(|(id, _)| id);
    let Some(binding) = binding else {
        return Err(format!("no binding of {} on P", account.raw()));
    };
    let at = Timestamp::from_micros(seed.now.saturating_add(SECOND));
    seed.by(ADMIN_PLAIN, Core::EndRole { binding, at })
}

/// The staff and Judging grants of the active programme P.
fn staff(seed: &mut Seeder, p: ProgrammeId, reached: &mut Reached) -> Result<(), String> {
    let g = ADMIN_PLAIN;
    grant(seed, g, PM_DRAFTER, p, Role::ProgrammeManager)?;
    hand_criteria_to(seed, p, PM_DRAFTER)?;
    let drafter = grant(seed, g, DRAFTER, p, Role::CallDrafter)?;
    reached.binding_end = Some(drafter);
    for a in [COORD, COORD_UNDECLARED, COORD_CONFLICTED] {
        grant(seed, g, a, p, Role::FstpCoordinator)?;
    }
    grant(seed, g, CHAIR, p, Role::CommitteeChair)?;
    for a in [
        MEMBER,
        REVIEWER,
        REVIEWER_UNDECLARED,
        REVIEWER_CONFLICTED,
        REVIEWER_RELEASED,
        REVIEWER_SUSPENDED,
        RECUSED,
        DELEGATOR,
        REVIEWER_2,
    ] {
        grant(seed, g, a, p, Role::CommitteeMember)?;
    }
    for a in [
        IRC_MEMBER,
        IRC_ASSIGNEE,
        IRC_UNDECLARED,
        IRC_CONFLICTED,
        IRC_2,
    ] {
        grant(seed, g, a, p, Role::IrcMember)?;
    }
    grant(seed, g, FINANCE, p, Role::FinanceApprover)?;
    grant(seed, g, RELEASER, p, Role::PaymentReleaser)?;
    grant(seed, g, SIGNATORY, p, Role::ContractSignatory)?;
    grant(seed, g, AUDITOR, p, Role::Auditor)?;
    Ok(())
}

/// Makes `author` the last author of P-01 and P-09 of `p` (R-PC-03 NOTE),
/// with the values unchanged: one edit that changes both, and one that
/// restores them. The programme manager who built the draft wrote them
/// first, and the matrix's [`PM`] drafts nothing, so these edits give
/// that authorship to [`PM_DRAFTER`], the drafter of C.
fn hand_criteria_to(seed: &mut Seeder, p: ProgrammeId, author: AccountId) -> Result<(), String> {
    let head = {
        let state = seed.ports.engine.state();
        fstp_domain::policy::head(&state.core, p)
            .ok_or("no policy")?
            .clone()
    };
    let scale = head.frozen.p01.scale_max().get();
    let other = if scale > 1 {
        scale.saturating_sub(1)
    } else {
        scale.saturating_add(1)
    };
    let other = std::num::NonZeroU8::new(other).ok_or("scale")?;
    let mut changed = fstp_domain_testkit::r#gen::policy::next_version(
        &head,
        fstp_domain::id::PolicyVersionId::from_raw(seed.id()),
    );
    changed.frozen.p01 =
        fstp_domain::scoring::Criteria::new(other, head.frozen.p01.items().to_vec())
            .map_err(|e| format!("P-01: {e:?}"))?;
    let mut ko = head.frozen.p09.0.clone();
    if ko.pop().is_none() {
        return Err("P-09 holds no criterion to change".to_owned());
    }
    changed.frozen.p09 = fstp_domain::policy::KnockOutCriteria(ko);
    let restored = {
        let mut v = fstp_domain_testkit::r#gen::policy::next_version(
            &changed,
            fstp_domain::id::PolicyVersionId::from_raw(seed.id()),
        );
        v.frozen.p01 = head.frozen.p01.clone();
        v.frozen.p09 = head.frozen.p09.clone();
        v
    };
    for (base, version) in [(head.id, changed.clone()), (changed.id, restored)] {
        seed.by(
            author,
            Core::EditPolicy {
                base,
                version: Box::new(version),
            },
        )?;
    }
    Ok(())
}

/// Drafts, approves and publishes the call `c` of `p` up to `depth`.
fn call_to(seed: &mut Seeder, p: ProgrammeId, upto: u8, deadline: i64) -> Result<CallId, String> {
    let zone = ZoneName::new("Europe/Brussels").ok_or("zone")?;
    let body = seed.api(
        PM_DRAFTER,
        ApiMethod::Post,
        &format!("/programmes/{}/calls", p.raw()),
        &obj(vec![
            ("opens", dec(u128::try_from(OPENS).unwrap_or(0))),
            ("deadline", dec(u128::try_from(deadline).unwrap_or(0))),
            ("deadline_zone", s(zone.as_str())),
            ("currency", s("EUR")),
            ("budget", s("400000.00")),
            ("text", s("SYNTHETIC CALL TEXT")),
        ]),
    );
    let _ = body?;
    let state = seed.ports.engine.state();
    // The server drew the call id, and drawn ids only grow.
    let c = state
        .core
        .calls()
        .iter()
        .map(|(c, _)| c)
        .max_by_key(|c| c.raw())
        .ok_or("the drafted call is not in the state")?;
    // The call drafter edits C, so it is one of C's authors.
    seed.api(
        DRAFTER,
        ApiMethod::Put,
        &format!("/calls/{}", c.raw()),
        &obj(vec![
            ("opens", dec(u128::try_from(OPENS).unwrap_or(0))),
            ("deadline", dec(u128::try_from(deadline).unwrap_or(0))),
            ("deadline_zone", s(zone.as_str())),
            ("currency", s("EUR")),
            ("budget", s("400000.00")),
            ("text", s("SYNTHETIC CALL TEXT, EDITED")),
        ]),
    )?;
    if upto >= 3 {
        seed.api(
            PM,
            ApiMethod::Post,
            &format!("/calls/{}/approval", c.raw()),
            &obj(vec![]),
        )?;
    }
    if upto >= 4 {
        seed.api(
            PM,
            ApiMethod::Post,
            &format!("/calls/{}/publication", c.raw()),
            &obj(vec![]),
        )?;
    }
    Ok(c)
}

/// The lifecycle of C and X for the state of `key`.
fn lifecycle(
    seed: &mut Seeder,
    p: ProgrammeId,
    key: WorldKey,
    reached: &mut Reached,
) -> Result<(), String> {
    let d = depth(key.state);
    if d < 2 {
        return Ok(());
    }
    seed.at(T_SETUP.saturating_add(DAY / 2));
    let c = call_to(seed, p, d.min(4), DEADLINE)?;
    reached.call = Some(c);
    let StateProfile::Proposal(target) = key.state else {
        return Ok(());
    };
    proposal_to(seed, p, c, target, key, reached)
}

/// Creates a draft proposal of `lead` in `c` through the API, with a plan
/// and a saved workspace, and returns it with its plan.
fn draft_proposal(
    seed: &mut Seeder,
    lead: AccountId,
    c: CallId,
    team: bool,
) -> Result<(ProposalId, u128), String> {
    let body = seed.api(
        lead,
        ApiMethod::Post,
        &format!("/calls/{}/proposals", c.raw()),
        &obj(vec![]),
    )?;
    let raw: u128 = str_member(&body, "proposal")
        .and_then(|x| x.parse().ok())
        .ok_or_else(|| format!("proposal.create gave {}", body.to_compact()))?;
    let x = ProposalId::from_raw(raw);
    if team {
        seed.api(
            lead,
            ApiMethod::Post,
            &format!("/proposals/{raw}/team"),
            &obj(vec![("account", dec(TEAM.raw()))]),
        )?;
        seed.api(
            lead,
            ApiMethod::Post,
            &format!("/proposals/{raw}/guardian"),
            &obj(vec![("account", dec(GUARDIAN.raw()))]),
        )?;
    }
    let plan = seed.api(
        lead,
        ApiMethod::Put,
        &format!("/proposals/{raw}/plan"),
        &plan_body("50000.00"),
    )?;
    let plan_id: u128 = str_member(&plan, "plan")
        .and_then(|x| x.parse().ok())
        .ok_or_else(|| format!("proposal.record_plan gave {}", plan.to_compact()))?;
    seed.api(
        lead,
        ApiMethod::Put,
        &format!("/proposals/{raw}/workspace"),
        &obj(vec![
            ("narrative", s("SYNTHETIC NARRATIVE")),
            ("summary", s("SYNTHETIC SUMMARY")),
            ("title", s("SYNTHETIC TITLE")),
        ]),
    )?;
    Ok((x, plan_id))
}

/// Submits `x` through the API.
fn submit(seed: &mut Seeder, lead: AccountId, x: ProposalId) -> Result<(), String> {
    seed.api(
        lead,
        ApiMethod::Post,
        &format!("/proposals/{}/submission", x.raw()),
        &obj(vec![("ethics", s("none")), ("notice_version", s("1"))]),
    )?;
    Ok(())
}

/// Whether P-11 of the programme of the published calls is anonymous: an
/// assignment then carries a fresh handle, and under P-11 named none
/// (R-AN-01).
fn anonymous(seed: &Seeder) -> bool {
    let state = seed.ports.engine.state();
    state
        .core
        .calls()
        .iter()
        .find_map(|(_, view)| fstp_domain::policy::head(&state.core, view.programme()))
        .is_some_and(|v| v.frozen.p11 == fstp_domain::policy::ReviewerAnonymity::Anonymous)
}

/// Assigns `reviewer` to `x` as `kind` through the engine.
fn assign(
    seed: &mut Seeder,
    x: ProposalId,
    reviewer: AccountId,
    kind: AssignmentKind,
) -> Result<AssignmentId, String> {
    let a = AssignmentId::from_raw(seed.id());
    let handle =
        anonymous(seed).then(|| fstp_domain::id::Handle::from_bytes(a.raw().to_be_bytes()));
    seed.by(
        COORD,
        Core::Assign {
            assignment: a,
            proposal: x,
            reviewer,
            kind,
            handle,
        },
    )?;
    Ok(a)
}

/// Declares `conflicted` on `subject` as `who`.
fn declare(
    seed: &mut Seeder,
    who: AccountId,
    subject: DeclarationSubject,
    conflicted: bool,
) -> Result<(), String> {
    seed.by(
        who,
        Core::DeclareConflict {
            subject,
            conflicted,
            notifiable: false,
        },
    )
}

/// Scores assignment `a` of `x` through the API.
fn score(
    seed: &mut Seeder,
    who: AccountId,
    a: AssignmentId,
    plan: u128,
    stage: &str,
    values: Value,
) -> Result<(), String> {
    seed.api(
        who,
        ApiMethod::Post,
        &format!("/assignments/{}/scores", a.raw()),
        &obj(vec![
            ("plan", dec(plan)),
            ("stage", s(stage)),
            ("values", values),
        ]),
    )?;
    Ok(())
}

/// The P-01 shape of `p`: criteria count and scale top, and the P-09 ids.
fn shape(seed: &Seeder, p: ProgrammeId) -> Result<(usize, u32, Vec<u128>), String> {
    let state = seed.ports.engine.state();
    let v = fstp_domain::policy::head(&state.core, p).ok_or("no policy")?;
    Ok((
        v.frozen.p01.items().len(),
        u32::from(v.frozen.p01.scale_max().get()),
        v.frozen.p09.0.iter().map(|k| k.id.raw()).collect(),
    ))
}

/// Takes the proposal X of `c` to `target`.
fn proposal_to(
    seed: &mut Seeder,
    p: ProgrammeId,
    c: CallId,
    target: StateTag,
    key: WorldKey,
    reached: &mut Reached,
) -> Result<(), String> {
    use StateTag as S;
    seed.at(T_DRAFT);
    let (x, plan) = draft_proposal(seed, LEAD, c, true)?;
    reached.proposal = Some(x);
    reached.plan = Some(plan);
    // The rounds that rank X also rank Y.
    let ranked_states = [
        S::Ranked,
        S::IrcReview,
        S::NotSelected,
        S::Deferred,
        S::Declined,
        S::Negotiation,
        S::Withdrawn,
        S::Granted,
        S::InExecution,
        S::Completed,
        S::Terminated,
    ];
    let with_y = ranked_states.contains(&target);
    let y = if with_y {
        Some(draft_proposal(seed, LEAD_Y, c, false)?)
    } else {
        None
    };
    if target == S::Draft {
        return Ok(());
    }
    if target == S::Withdrawn && false {
        return Ok(());
    }
    submit(seed, LEAD, x)?;
    if let Some((yp, _)) = y {
        submit(seed, LEAD_Y, yp)?;
    }
    seed.at(T_EVAL);
    let (n, max, kos) = shape(seed, p)?;
    // The coordinators' declarations on X.
    declare(seed, COORD, DeclarationSubject::Proposal(x), false)?;
    declare(
        seed,
        COORD_CONFLICTED,
        DeclarationSubject::Proposal(x),
        true,
    )?;
    // Under P-10 "all committee members" every committee member declares
    // per proposal (`roles-and-sod.md` Conflict declarations, R-CF-02).
    if key.policy.p10 == P10::AllCommittee {
        for m in [MEMBER, REVIEWER_RELEASED] {
            declare(seed, m, DeclarationSubject::Proposal(x), false)?;
        }
    }
    // The assessor's finding on X, which the reviewers read and mark.
    seed.finding(c, x)?;
    if target == S::Ineligible {
        let outcomes = kos
            .iter()
            .enumerate()
            .map(|(i, k)| fstp_domain::command::KnockOutResult {
                criterion: fstp_domain::id::KnockOutCriterionId::from_raw(*k),
                passed: i != 0,
            })
            .collect();
        let decision = DecisionId::from_raw(seed.id());
        seed.by(
            COORD,
            Core::RecordKnockOut {
                decision,
                proposal: x,
                outcomes,
                reason: Some(fstp_domain_testkit::r#gen::policy::text(81_000)),
            },
        )?;
        return Ok(());
    }
    // The reviewers of X.
    let mut assigned = BTreeMap::new();
    let early = matches!(target, S::Submitted | S::Stage1);
    let mut reviewers = vec![
        REVIEWER,
        REVIEWER_2,
        REVIEWER_CONFLICTED,
        REVIEWER_RELEASED,
        REVIEWER_SUSPENDED,
    ];
    if early {
        reviewers.push(REVIEWER_UNDECLARED);
    }
    for r in &reviewers {
        let a = assign(seed, x, *r, AssignmentKind::Reviewer)?;
        assigned.insert(*r, a);
    }
    for r in [REVIEWER, REVIEWER_2, REVIEWER_SUSPENDED] {
        let a = assigned.get(&r).copied().ok_or("assignment")?;
        declare(seed, r, DeclarationSubject::Assignment(a), false)?;
    }
    let a_conf = assigned
        .get(&REVIEWER_CONFLICTED)
        .copied()
        .ok_or("assignment")?;
    declare(
        seed,
        REVIEWER_CONFLICTED,
        DeclarationSubject::Assignment(a_conf),
        true,
    )?;
    let a_rel = assigned
        .get(&REVIEWER_RELEASED)
        .copied()
        .ok_or("assignment")?;
    seed.by(COORD, Core::Unassign { assignment: a_rel })?;
    reached.assignments = assigned.clone();
    if target == S::Submitted {
        suspend(seed, REVIEWER_SUSPENDED)?;
        return Ok(());
    }
    // Y's reviewers: the two scorers and the recused member.
    let y_assigned = match y {
        Some((yp, _)) => {
            declare(seed, COORD, DeclarationSubject::Proposal(yp), false)?;
            let mut m = BTreeMap::new();
            for r in [REVIEWER, REVIEWER_2, RECUSED] {
                let a = assign(seed, yp, r, AssignmentKind::Reviewer)?;
                m.insert(r, a);
            }
            for r in [REVIEWER, REVIEWER_2] {
                let a = m.get(&r).copied().ok_or("assignment")?;
                declare(seed, r, DeclarationSubject::Assignment(a), false)?;
            }
            let a = m.get(&RECUSED).copied().ok_or("assignment")?;
            declare(seed, RECUSED, DeclarationSubject::Assignment(a), true)?;
            m
        }
        None => BTreeMap::new(),
    };
    // Knock-out and admission.
    let pass = |kos: &[u128]| -> Vec<fstp_domain::command::KnockOutResult> {
        kos.iter()
            .map(|k| fstp_domain::command::KnockOutResult {
                criterion: fstp_domain::id::KnockOutCriterionId::from_raw(*k),
                passed: true,
            })
            .collect()
    };
    let mut admitted = vec![x];
    if let Some((yp, _)) = y {
        admitted.push(yp);
    }
    for q in &admitted {
        let decision = DecisionId::from_raw(seed.id());
        seed.by(
            COORD,
            Core::RecordKnockOut {
                decision,
                proposal: *q,
                outcomes: pass(&kos),
                reason: None,
            },
        )?;
        let decision = DecisionId::from_raw(seed.id());
        seed.by(
            COORD,
            Core::AdmitToStage1 {
                decision,
                proposal: *q,
            },
        )?;
    }
    if target == S::Stage1 {
        let a = assigned.get(&REVIEWER).copied().ok_or("assignment")?;
        score(seed, REVIEWER, a, plan, "One", score_values(n, max))?;
        suspend(seed, REVIEWER_SUSPENDED)?;
        return Ok(());
    }
    // Stage 1 scores and close.
    for r in [REVIEWER, REVIEWER_2, REVIEWER_SUSPENDED] {
        let a = assigned.get(&r).copied().ok_or("assignment")?;
        let top = if target == S::NotSelected {
            lower_values(n, max)
        } else {
            score_values(n, max)
        };
        score(seed, r, a, plan, "One", top)?;
    }
    seed.by(COORD, Core::CloseStage1 { proposal: x })?;
    if let Some((yp, yplan)) = y {
        for r in [REVIEWER, REVIEWER_2] {
            let a = y_assigned.get(&r).copied().ok_or("assignment")?;
            let top = if target == S::NotSelected {
                score_values(n, max)
            } else {
                lower_values(n, max)
            };
            score(seed, r, a, yplan, "One", top)?;
        }
        seed.by(COORD, Core::CloseStage1 { proposal: yp })?;
    }
    if target == S::Stage2 {
        suspend(seed, REVIEWER_SUSPENDED)?;
        return Ok(());
    }
    // Stage 2: a ranking summary and "no questions" by every reviewer.
    rank(seed, &assigned, &[REVIEWER, REVIEWER_2, REVIEWER_SUSPENDED])?;
    let Some((yp, _)) = y else {
        return Err(format!("{target:?} needs Y"));
    };
    rank(seed, &y_assigned, &[REVIEWER, REVIEWER_2])?;
    // The round: X first, unless X falls below the cut-off.
    let order = if target == S::NotSelected {
        vec![yp, x]
    } else {
        vec![x, yp]
    };
    reached.ranked = order.clone();
    let order_json: Vec<Value> = order.iter().map(|q| dec(q.raw())).collect();
    let opened = seed.api(
        MEMBER,
        ApiMethod::Post,
        &format!("/calls/{}/cut-off-rounds", c.raw()),
        &obj(vec![
            ("order", Value::Array(order_json.into_iter().collect())),
            ("nominated", int(1)),
            ("rationale", s("SYNTHETIC ROUND RATIONALE")),
        ]),
    )?;
    let round: u128 = str_member(&opened, "round")
        .and_then(|r| r.parse().ok())
        .ok_or_else(|| format!("committee.open_round gave {}", opened.to_compact()))?;
    let round = DecisionId::from_raw(round);
    reached.round = Some(round);
    seed.api(
        DELEGATOR,
        ApiMethod::Post,
        &format!("/cut-off-rounds/{}/delegation", round.raw()),
        &obj(vec![("to", dec(MEMBER.raw()))]),
    )?;
    if target == S::Ranked {
        suspend(seed, REVIEWER_SUSPENDED)?;
        return Ok(());
    }
    // REVIEWER_CONFLICTED and RECUSED are recused by their conflicts
    // (I-03), and DELEGATOR voted through MEMBER.
    for m in [
        MEMBER,
        CHAIR,
        REVIEWER,
        REVIEWER_2,
        REVIEWER_RELEASED,
        REVIEWER_SUSPENDED,
    ] {
        seed.api(
            m,
            ApiMethod::Post,
            &format!("/cut-off-rounds/{}/ballot", round.raw()),
            &obj(vec![("vote", s("For"))]),
        )?;
    }
    seed.api(
        MEMBER,
        ApiMethod::Post,
        &format!("/cut-off-rounds/{}/record", round.raw()),
        &obj(vec![]),
    )?;
    if target == S::NotSelected {
        suspend(seed, REVIEWER_SUSPENDED)?;
        return Ok(());
    }
    // IRC review of X.
    let mut ircs = vec![IRC_ASSIGNEE, IRC_2, IRC_CONFLICTED];
    if target == S::IrcReview {
        ircs.push(IRC_UNDECLARED);
    }
    for i in &ircs {
        let a = assign(seed, x, *i, AssignmentKind::Irc)?;
        reached.irc.insert(*i, a);
    }
    for i in [IRC_ASSIGNEE, IRC_2] {
        let a = reached.irc.get(&i).copied().ok_or("irc")?;
        declare(seed, i, DeclarationSubject::Assignment(a), false)?;
    }
    let a = reached.irc.get(&IRC_CONFLICTED).copied().ok_or("irc")?;
    declare(
        seed,
        IRC_CONFLICTED,
        DeclarationSubject::Assignment(a),
        true,
    )?;
    if target == S::IrcReview {
        suspend(seed, REVIEWER_SUSPENDED)?;
        return Ok(());
    }
    let review = |seed: &mut Seeder, who: AccountId, a: AssignmentId, verdict: Value| {
        seed.api(
            who,
            ApiMethod::Post,
            &format!("/irc-assignments/{}/review", a.raw()),
            &obj(vec![("verdict", verdict)]),
        )
        .map(|_| ())
    };
    let concern = obj(vec![
        ("concern", s("SYNTHETIC CONCERN")),
        ("type", s("Concern")),
    ]);
    if matches!(target, S::Deferred | S::Declined) && key.variant != Variant::Voided {
        if target == S::Deferred {
            // A future call exists (NOTE 7).
            call_to(seed, p, 4, FUTURE_DEADLINE)?;
        }
        let a = reached.irc.get(&IRC_ASSIGNEE).copied().ok_or("irc")?;
        review(seed, IRC_ASSIGNEE, a, concern)?;
        if target == S::Declined {
            seed.api(
                PM,
                ApiMethod::Post,
                &format!("/proposals/{}/decline-after-concern", x.raw()),
                &obj(vec![]),
            )?;
        }
        suspend(seed, REVIEWER_SUSPENDED)?;
        return Ok(());
    }
    for i in [IRC_ASSIGNEE, IRC_2] {
        let a = reached.irc.get(&i).copied().ok_or("irc")?;
        review(seed, i, a, obj(vec![("type", s("Validate"))]))?;
    }
    // X is in NEGOTIATION. A reviewer is assigned there and not declared.
    let a = assign(seed, x, REVIEWER_UNDECLARED, AssignmentKind::Reviewer)?;
    reached.assignments.insert(REVIEWER_UNDECLARED, a);
    if key.variant == Variant::Voided {
        void(seed, LEAD)?;
        if target == S::Declined {
            seed.api(
                PM,
                ApiMethod::Post,
                &format!("/proposals/{}/decline-negotiation", x.raw()),
                &obj(vec![]),
            )?;
        }
        return Ok(());
    }
    match target {
        S::Negotiation => {}
        S::Withdrawn => {
            seed.api(
                LEAD,
                ApiMethod::Post,
                &format!("/proposals/{}/withdrawal", x.raw()),
                &obj(vec![]),
            )?;
        }
        S::Granted | S::InExecution | S::Completed | S::Terminated => {
            grant_x(seed, x, plan)?;
            if matches!(target, S::InExecution | S::Completed) {
                seed.at(MILESTONE_START.saturating_add(SECOND));
                seed.system(SystemCause::Timeline, Core::StartExecution { proposal: x })?;
            }
            if target == S::Granted {
                m5_granted(seed, p, c, x, plan, reached)?;
            }
            if target == S::InExecution {
                m5_executing(seed, x, plan, reached)?;
            }
            if target == S::Completed {
                close_milestones(seed, x, plan)?;
                seed.system(SystemCause::Timeline, Core::Complete { proposal: x })?;
            }
            if target == S::Terminated {
                let decision = DecisionId::from_raw(seed.id());
                seed.by(
                    PM,
                    Core::Terminate {
                        decision,
                        proposal: x,
                        reason: fstp_domain_testkit::r#gen::policy::text(82_000),
                    },
                )?;
            }
        }
        _ => return Err(format!("no path to {target:?}")),
    }
    suspend(seed, REVIEWER_SUSPENDED)?;
    Ok(())
}

/// Stage 2 of a proposal: a ranking summary by the first of `rs`, then
/// "no questions" by each, which ranks it (NOTE 4).
fn rank(
    seed: &mut Seeder,
    m: &BTreeMap<AccountId, AssignmentId>,
    rs: &[AccountId],
) -> Result<(), String> {
    let first = rs.first().copied().ok_or("no reviewer")?;
    let a = m.get(&first).copied().ok_or("assignment")?;
    seed.api(
        first,
        ApiMethod::Post,
        &format!("/assignments/{}/ranking-summary", a.raw()),
        &obj(vec![
            ("neutral_summary", s("SYNTHETIC NEUTRAL SUMMARY")),
            ("rationale", s("SYNTHETIC RATIONALE")),
            ("title", s("SYNTHETIC TITLE")),
        ]),
    )?;
    for r in rs {
        let a = m.get(r).copied().ok_or("assignment")?;
        seed.api(
            *r,
            ApiMethod::Post,
            &format!("/assignments/{}/no-questions", a.raw()),
            &Value::Null,
        )?;
    }
    Ok(())
}

/// The tasks of plan `plan` of `x`, from its ledger record.
fn plan_tasks(
    seed: &Seeder,
    x: ProposalId,
    plan: u128,
) -> Result<Vec<fstp_domain::proposal::Task>, String> {
    let store = seed.ports.engine.store_copy();
    let mut entries = Vec::new();
    store
        .read(fstp_ledger::Seq::ZERO, usize::MAX, &mut entries)
        .map_err(|e| format!("read the ledger: {e:?}"))?;
    entries
        .iter()
        .find_map(|e| match &e.record {
            Record::Core(fstp_domain::record::Record::PlanVersionRecorded(r))
                if r.proposal == x && r.plan.raw() == plan =>
            {
                Some(r.tasks.clone())
            }
            _ => None,
        })
        .ok_or_else(|| format!("no plan {plan} of X"))
}

/// M5 lane L-API: a GRANTED world holds a drafted contract, a proposed
/// amendment and a generated funder report, so their operations have
/// targets (M5 design section 5).
fn m5_granted(
    seed: &mut Seeder,
    p: ProgrammeId,
    c: CallId,
    x: ProposalId,
    plan: u128,
    reached: &mut Reached,
) -> Result<(), String> {
    let v = seed.api(
        PM,
        ApiMethod::Post,
        &format!("/grants/{}/contract", x.raw()),
        &obj(vec![]),
    )?;
    reached.contract = str_member(&v, "contract").and_then(|s| s.parse().ok());
    let mut tasks = plan_tasks(seed, x, plan)?;
    for t in &mut tasks {
        for m in &mut t.milestones {
            m.id = fstp_domain::id::MilestoneId::from_raw(seed.id());
        }
    }
    let amended = fstp_domain::id::PlanVersionId::from_raw(seed.id());
    seed.by(
        LEAD,
        Core::RecordPlanVersion {
            plan: amended,
            proposal: x,
            origin: fstp_domain::proposal::PlanOrigin::Amendment,
            supersedes: Some(fstp_domain::id::PlanVersionId::from_raw(plan)),
            tasks,
            content: fstp_domain::id::ContentDigest::from_bytes([9; 32]),
        },
    )?;
    let amendment = fstp_domain::id::AmendmentId::from_raw(seed.id());
    seed.by(
        LEAD,
        Core::ProposeAmendment {
            amendment,
            grant: x,
            plan: amended,
        },
    )?;
    reached.amendment = Some(amendment.raw());
    let v = seed.api(
        PM,
        ApiMethod::Post,
        &format!("/programmes/{}/reports", p.raw()),
        &obj(vec![("kind", s("audit_file")), ("call", dec(c.raw()))]),
    )?;
    reached.report = str_member(&v, "report").and_then(|s| s.parse().ok());
    Ok(())
}

/// M5 lane L-API: an IN_EXECUTION world holds three payment requests of
/// the lead: one under review, one whose line the assigned reviewer
/// accepted, and one the finance approver approved for payment.
fn m5_executing(
    seed: &mut Seeder,
    x: ProposalId,
    plan: u128,
    reached: &mut Reached,
) -> Result<(), String> {
    let milestone = plan_tasks(seed, x, plan)?
        .first()
        .and_then(|t| t.milestones.first())
        .map(|m| m.id)
        .ok_or("the plan has no milestone")?;
    let (r, line) = m5_request(seed, x, milestone)?;
    reached.request = Some(r.raw());
    reached.line = Some(line.raw());
    for stage in 1..=2u8 {
        let (r, line) = m5_request(seed, x, milestone)?;
        m5_checks(seed, r, line, fstp_domain::payment::CheckPhase::Acceptance)?;
        seed.by(
            REVIEWER,
            Core::AcceptLine {
                request: r,
                line,
                approved: fstp_money::NonNegAmount::new(
                    fstp_money::Amount::parse("100.00", fstp_money::Currency::Eur)
                        .map_err(|e| format!("{e:?}"))?,
                )
                .map_err(|e| format!("{e:?}"))?,
                reason: None,
            },
        )?;
        if stage == 1 {
            reached.accepted = Some(r.raw());
        } else {
            seed.by(FINANCE, Core::ApprovePayment { request: r })?;
            reached.approved = Some(r.raw());
        }
    }
    // I-33: verified bank details written before the P-36 hold of 7 days,
    // so the release meets no bank guard.
    seed.ports.vault.change(|t| {
        t.write_bank(x, Timestamp::from_micros(T_SETUP));
        t.verify_bank(x);
    });
    Ok(())
}

/// A milestone claim of 100.00 EUR by the lead through the API, whose
/// submission checks passed.
fn m5_request(
    seed: &mut Seeder,
    x: ProposalId,
    milestone: fstp_domain::id::MilestoneId,
) -> Result<(fstp_domain::id::RequestId, fstp_domain::id::LineId), String> {
    let line = obj(vec![
        ("milestone", dec(milestone.raw())),
        ("amount", s("100.00")),
        (
            "evidence",
            obj(vec![
                ("location", s("https://forge.example/synthetic/repo")),
                ("release", s("v1.0.0")),
                ("licence", s("MIT")),
                ("report", s("SYNTHETIC DELIVERY REPORT")),
            ]),
        ),
    ]);
    let v = seed.api(
        LEAD,
        ApiMethod::Post,
        &format!("/grants/{}/payment-requests", x.raw()),
        &obj(vec![
            ("kind", obj(vec![("type", s("Milestone"))])),
            ("currency", s("EUR")),
            ("lines", Value::Array(Array::from(vec![line]))),
        ]),
    )?;
    let request = str_member(&v, "request")
        .and_then(|s| s.parse::<u128>().ok())
        .map(fstp_domain::id::RequestId::from_raw)
        .ok_or("no payment request")?;
    let line = seed
        .ports
        .engine
        .state()
        .core
        .payments()
        .summaries()
        .filter(|s| s.request == request)
        .flat_map(|s| s.lines.into_iter().map(|l| l.line))
        .next()
        .ok_or("the request has no line")?;
    m5_checks(
        seed,
        request,
        line,
        fstp_domain::payment::CheckPhase::Submission,
    )?;
    Ok((request, line))
}

/// A passed run of the checks of one phase over the request's one line.
fn m5_checks(
    seed: &mut Seeder,
    request: fstp_domain::id::RequestId,
    line: fstp_domain::id::LineId,
    phase: fstp_domain::payment::CheckPhase,
) -> Result<(), String> {
    seed.system(
        SystemCause::Timeline,
        Core::RecordChecks {
            request,
            phase,
            results: vec![fstp_domain::payment::CheckResult {
                line: Some(line),
                check: fstp_domain::payment::CheckKind::Evidence,
                failure: None,
            }],
            snapshot: fstp_domain::id::ContentDigest::from_bytes([7; 32]),
        },
    )
}

/// Takes X from NEGOTIATION to GRANTED with the commands of M5.
fn grant_x(seed: &mut Seeder, x: ProposalId, plan: u128) -> Result<(), String> {
    let determination = DecisionId::from_raw(seed.id());
    // An assigned reviewer determines the amount (`ACTOR_RULES`).
    seed.by(
        REVIEWER,
        Core::DetermineAmount {
            decision: determination,
            proposal: x,
            agreed: fstp_domain::id::PlanVersionId::from_raw(plan),
            deductions: Vec::new(),
        },
    )?;
    let decision = DecisionId::from_raw(seed.id());
    seed.by(
        LEAD,
        Core::AcceptGrant {
            decision,
            proposal: x,
            determination,
        },
    )?;
    let decision = DecisionId::from_raw(seed.id());
    seed.by(
        PM,
        Core::ApproveGrant {
            decision,
            proposal: x,
            determination,
        },
    )?;
    let contract = fstp_domain::id::ContractId::from_raw(seed.id());
    seed.system(
        SystemCause::ContractPort,
        Core::ContractFact {
            proposal: x,
            contract,
            event: fstp_domain::command::ContractEvent::Effective,
        },
    )
}

/// Closes every milestone of the plan version `plan` of `x` as the
/// programme manager, so IN_EXECUTION to COMPLETED holds (state machine
/// NOTE 12). The milestone ids are read from the plan's ledger record.
fn close_milestones(seed: &mut Seeder, x: ProposalId, plan: u128) -> Result<(), String> {
    let store = seed.ports.engine.store_copy();
    let mut entries = Vec::new();
    store
        .read(fstp_ledger::Seq::ZERO, usize::MAX, &mut entries)
        .map_err(|e| format!("read the ledger: {e:?}"))?;
    let milestones: Vec<fstp_domain::id::MilestoneId> = entries
        .iter()
        .filter_map(|e| match &e.record {
            Record::Core(fstp_domain::record::Record::PlanVersionRecorded(r))
                if r.proposal == x && r.plan.raw() == plan =>
            {
                Some(
                    r.tasks
                        .iter()
                        .flat_map(|t| t.milestones.iter().map(|m| m.id)),
                )
            }
            _ => None,
        })
        .flatten()
        .collect();
    if milestones.is_empty() {
        return Err(format!("the plan {plan} of X has no milestone"));
    }
    for (i, milestone) in (0u128..).zip(milestones) {
        seed.by(
            PM,
            Core::CloseMilestone {
                proposal: x,
                milestone,
                reason: fstp_domain_testkit::r#gen::policy::text(83_000u128.saturating_add(i)),
            },
        )?;
    }
    Ok(())
}

/// Excludes `account`'s identity from a P-13 class of P and processes the
/// vault change, which suspends a Judging binding and voids a Receiving
/// one (I-04).
fn exclude(seed: &mut Seeder, account: AccountId) -> Result<(), String> {
    let state = seed.ports.engine.state();
    let classes: Vec<fstp_domain::id::ClassId> = state
        .core
        .calls()
        .iter()
        .filter_map(|(c, _)| fstp_domain::policy::effective_p13(&state.core, c).ok())
        .flat_map(|p13| p13.0.into_iter())
        .collect();
    let class = classes.first().copied().ok_or("P-13 has no class")?;
    let tag = seed
        .ports
        .vault
        .truth()
        .identity_of(account)
        .ok_or("no identity")?;
    seed.ports.vault.change(|t| t.exclude(tag, class));
    vault_changed(seed, account)
}

/// Sends the `VaultChanged` of a vault change that touched `account`.
fn vault_changed(seed: &mut Seeder, account: AccountId) -> Result<(), String> {
    let epoch = seed.ports.vault.truth().epoch();
    let changed: BTreeSet<AccountId> = [account].into_iter().collect();
    let sent = seed.system(SystemCause::Vault, Core::VaultChanged { epoch, changed });
    // The driver processes a vault epoch ahead of the state's before it
    // decides any command (`fstp_engine` driver step 2), so it may have
    // reacted to the change already and refuse this copy as stale.
    let processed = seed.ports.engine.state().core.epoch();
    match sent {
        Ok(()) => Ok(()),
        Err(_) if processed == epoch => Ok(()),
        Err(e) => Err(format!(
            "{e} (vault epoch {epoch:?}, processed {processed:?})"
        )),
    }
}

/// Suspends the committee binding of `account`: the vault finds that
/// `account` shares the identity of the call drafter [`DRAFTER`], so the
/// reaction suspends the Judging binding under I-06 (identity discovery,
/// `roles-and-sod.md`). A P-13 exclusion would not suspend it, since
/// P-13 bars receiving roles only.
fn suspend(seed: &mut Seeder, account: AccountId) -> Result<(), String> {
    let tag = seed
        .ports
        .vault
        .truth()
        .identity_of(DRAFTER)
        .ok_or("no identity")?;
    seed.ports.vault.change(|t| t.set_identity(account, tag));
    vault_changed(seed, account)
}

/// Voids the Receiving binding of `account` (I-04).
fn void(seed: &mut Seeder, account: AccountId) -> Result<(), String> {
    exclude(seed, account)
}

// ---------------------------------------------------------------------------
// Running a cell
// ---------------------------------------------------------------------------

/// The login method of a cell's session.
const fn method_of(l: Login) -> LoginMethod {
    match l {
        Login::Passkey => LoginMethod::Passkey,
        Login::MagicLink => LoginMethod::MagicLink,
        Login::Opaque => LoginMethod::Opaque,
    }
}

/// The scopes of a cell's MCP token: every scope, less the operation's
/// own when the cell has no scope.
fn scopes_of(op: &str, scope: bool) -> Vec<Scope> {
    let own = fstp_access::op(op).and_then(|o| o.scope);
    Scope::ALL
        .into_iter()
        .filter(|s| scope || Some(*s) != own)
        .collect()
}

/// The observed outcome of a stable error code and rule.
pub fn observed_of(code: &str, rule: Option<&str>) -> Result<Observed, ChannelFault> {
    Ok(match code {
        "not_exposed" => Observed::ChannelDenied(Denial::NotExposed),
        "scope" => Observed::ChannelDenied(Denial::Scope),
        "p74" => Observed::ChannelDenied(Denial::P74),
        "not_found" => Observed::NotFound(rule.unwrap_or("").to_owned()),
        "not_implemented" | "not_available" => {
            return Err(ChannelFault::NotImplemented(format!(
                "{code}{}",
                rule.map(|r| format!(" ({r})")).unwrap_or_default()
            )));
        }
        _ => Observed::Refused(rule.map(str::to_owned)),
    })
}

/// The observed outcome of a dispatch result.
pub fn observed_of_result(r: &Result<OpResult, ApiError>) -> Result<Observed, ChannelFault> {
    match r {
        Ok(OpResult::Done { .. }) => Ok(Observed::Completed),
        Ok(OpResult::Pending(_)) => Ok(Observed::Pending),
        Ok(OpResult::StepUpRequired(_)) => Ok(Observed::StepUpRequired),
        Ok(OpResult::StrongMethodRequired) => Ok(Observed::StrongMethodRequired),
        Err(ApiError::Refused { code, rule, .. }) => observed_of(code.as_str(), Some(rule)),
        Err(ApiError::NotImplemented(seam)) => {
            Err(ChannelFault::NotImplemented((*seam).to_owned()))
        }
    }
}

/// How a cell reaches the API core.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Transport {
    /// `ApiCore::dispatch`, with an `Op` from the adapter-facing decoders.
    Direct,
    /// The HTTP routes of `fstp-web` over `fstp_rt::duplex`.
    Http,
    /// MCP cells through `fstp_mcp::McpServer::call_tool`, and web cells
    /// as [`Transport::Http`] sends them.
    Mcp,
}

/// The reply of one call: the dispatch result directly, an HTTP status
/// and body, or an MCP `tools/call` result.
enum Reply {
    Direct(Box<Result<OpResult, ApiError>>),
    Http(u16, Vec<u8>),
    /// The `CallToolResult`, or the JSON-RPC error, and whether the
    /// operation has a tool.
    Mcp(Result<Value, fstp_mcp::RpcError>, bool),
}

impl Reply {
    /// The step-up challenge of a reply that asks for one.
    fn challenge(&self) -> Option<fstp_api_core::ActionDigest> {
        match self {
            Reply::Direct(r) => match r.as_ref() {
                Ok(OpResult::StepUpRequired(ch)) => Some(ch.action),
                _ => None,
            },
            Reply::Http(_, body) => {
                let v = fstp_json::parse(body).ok()?;
                if str_member(&v, "code").as_deref() != Some("step_up_required") {
                    return None;
                }
                // `{"code":"step_up_required","challenge":{"digest",..}}`
                // (`fstp_api_core::OpResult` wire form).
                let challenge = v.as_object()?.get("challenge")?;
                let hex = str_member(challenge, "digest")?;
                fstp_api_core::ActionDigest::from_hex(&hex)
            }
            Reply::Mcp(..) => None,
        }
    }
}

/// The world cache of one channel.
struct Runner {
    transport: Transport,
    worlds: BTreeMap<WorldKey, Result<Built, String>>,
    /// The worlds the cache holds at most.
    capacity: usize,
}

impl Runner {
    fn new(transport: Transport) -> Runner {
        Runner {
            transport,
            worlds: BTreeMap::new(),
            capacity: 4,
        }
    }

    /// The clean world of `key`, built or rebuilt as needed.
    fn world(&mut self, key: WorldKey) -> Result<&mut Built, String> {
        let stale = match self.worlds.get(&key) {
            Some(Ok(b)) => b.dirty,
            Some(Err(_)) => false,
            None => true,
        };
        if stale {
            if self.worlds.len() >= self.capacity && !self.worlds.contains_key(&key) {
                self.worlds.clear();
            }
            self.worlds.insert(key, build(key));
        }
        match self.worlds.get_mut(&key) {
            Some(Ok(b)) => Ok(b),
            Some(Err(e)) => Err(e.clone()),
            None => Err("the world cache lost a world".to_owned()),
        }
    }

    /// Runs `cell` once on a clean world.
    fn run_once(&mut self, cell: &Cell) -> Result<Observed, ChannelFault> {
        let transport = self.transport;
        let w = self
            .world(WorldKey::of(cell))
            .map_err(|e| ChannelFault::Setup(format!("world {:?}: {e}", WorldKey::of(cell))))?;
        let result = run_on(w, cell, transport);
        let head = w.ports.engine.head();
        let changed = head != w.head
            || match &result {
                Ok(Observed::Completed | Observed::Pending) => !is_read(cell.op),
                _ => false,
            };
        if changed {
            w.dirty = true;
        }
        result
    }
}

/// Whether `op` is a read or a public page.
fn is_read(op: &str) -> bool {
    fstp_access::op(op).is_some_and(|o| {
        matches!(
            o.kind,
            fstp_access::OpKind::Read(_) | fstp_access::OpKind::Public(_)
        )
    })
}

/// Runs `cell` on the clean world `w`.
fn run_on(w: &mut Built, cell: &Cell, transport: Transport) -> Result<Observed, ChannelFault> {
    let now = Timestamp::from_micros(w.now);
    w.ports.clock.set(now);
    let account = account_of(cell.who);
    let mcp = matches!(cell.session.channel, Via2::Mcp { .. });
    // The credential.
    let (cred, login) = match (account, cell.session.login, cell.session.channel) {
        (None, _, _) | (_, None, _) => (Credential::None, None),
        (Some(a), Some(_), Via2::Mcp { scope }) => {
            let token = w.ports.tokens.issue(
                a,
                agent_of(a),
                scopes_of(cell.op, scope),
                LoginMethod::Passkey,
            );
            (Credential::Bearer(token), None)
        }
        (Some(a), Some(l), Via2::Web) => {
            let login = w.ports.sessions.login(a, method_of(l));
            (Credential::SessionCookie(login.cookie.clone()), Some(login))
        }
    };
    if let Some(a) = account {
        // The caller's other agent client holds a token, so a revocation
        // and an activity read have a client to act on.
        let _ = w
            .ports
            .tokens
            .issue(a, other_agent_of(a), Vec::new(), LoginMethod::Passkey);
    }
    let session = login.as_ref().map(|l| l.session.raw());
    let req = request_of(cell, w, session).map_err(ChannelFault::Setup)?;
    if mcp && fstp_access::op(cell.op).and_then(|o| o.tool).is_none() {
        // An operation with neither a tool nor an API route, such as a
        // public page, has no name an MCP client could send, so it is
        // not exposed through MCP (I-84).
        if let Err(ApiError::Refused { code, .. }) =
            decode_route(req.method, &req.path, &req.body_bytes())
            && code.as_str() == "not_found"
        {
            return Ok(Observed::ChannelDenied(Denial::NotExposed));
        }
    }
    let send = |w: &mut Built| -> Result<Reply, ChannelFault> {
        match (transport, mcp) {
            (Transport::Mcp, true) => mcp_call(w, cell.op, &req, &cred),
            (Transport::Mcp, false) => http_call(w, &req, &cred),
            (_, true) => {
                let tool = fstp_access::op(cell.op)
                    .and_then(|o| o.tool)
                    .map(|t| t.name);
                let op = match tool {
                    Some(name) => decode_tool(name, &req.tool_args()),
                    // No tool names an operation without one, so the MCP
                    // decoder cannot reach it. It is sent by its route
                    // with the agent's token instead, so `channel_policy`
                    // judges the MCP principal (I-84, NotExposed).
                    None => decode_route(req.method, &req.path, &req.body_bytes()),
                };
                let r = match op {
                    Ok(op) => block_on(w.core.dispatch(cred.clone(), &RequestHead::new(), op)),
                    Err(e) => Err(e),
                };
                Ok(Reply::Direct(Box::new(r)))
            }
            (Transport::Direct, false) => {
                let r = match decode_web(req.method, &req.path, &req.body_bytes()) {
                    Ok(op) => block_on(w.core.dispatch(cred.clone(), &RequestHead::new(), op)),
                    Err(e) => Err(e),
                };
                Ok(Reply::Direct(Box::new(r)))
            }
            (Transport::Http, false) => http_call(w, &req, &cred),
        }
    };
    let mut reply = send(w)?;
    if !mcp
        && cell.session.step_up != StepUp::Absent
        && let (Some(digest), Some(l)) = (reply.challenge(), login.as_ref())
    {
        match cell.session.step_up {
            StepUp::Fresh => {
                w.ports
                    .step_up
                    .approve(l.session, digest)
                    .map_err(|e| ChannelFault::Setup(format!("step-up: {e:?}")))?;
            }
            StepUp::Stale | StepUp::Absent => {
                let stale = w.now.saturating_sub(w.targets.p71).saturating_sub(1);
                w.ports.clock.set(Timestamp::from_micros(stale));
                let r = w.ports.step_up.approve(l.session, digest);
                w.ports.clock.set(now);
                r.map_err(|e| ChannelFault::Setup(format!("step-up: {e:?}")))?;
            }
        }
        reply = send(w)?;
    }
    match reply {
        Reply::Direct(r) => observed_of_result(&r),
        Reply::Http(status, body) => observed_of_http(status, &body),
        Reply::Mcp(r, tool) => observed_of_mcp(&r, tool),
    }
}

/// The observed outcome of a `tools/call` result (lane W3c). A completed
/// call carries its read model in `structuredContent.data`, and a refusal
/// is `isError` with the API refusal body `{"code","rule"}`. A name the
/// server does not list is refused before any operation: for an
/// operation with no tool, that is `NotExposed` (I-84).
pub fn observed_of_mcp(
    r: &Result<Value, fstp_mcp::RpcError>,
    tool: bool,
) -> Result<Observed, ChannelFault> {
    let v = match r {
        Ok(v) => v,
        Err(e) if !tool && *e == fstp_mcp::RpcError::UNKNOWN_TOOL => {
            return Ok(Observed::ChannelDenied(Denial::NotExposed));
        }
        Err(e) => {
            return Err(ChannelFault::NotImplemented(format!(
                "JSON-RPC error {}: {}",
                e.code, e.message
            )));
        }
    };
    let o = v.as_object();
    let sc = o
        .and_then(|o| o.get("structuredContent"))
        .ok_or_else(|| ChannelFault::Setup(format!("no structuredContent: {}", v.to_compact())))?;
    let error = o
        .and_then(|o| o.get("isError"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if error {
        let Some(code) = str_member(sc, "code") else {
            return Err(ChannelFault::Setup(format!(
                "an error result without a code: {}",
                v.to_compact()
            )));
        };
        return match code.as_str() {
            "step_up_required" => Ok(Observed::StepUpRequired),
            "strong_method_required" => Ok(Observed::StrongMethodRequired),
            other => observed_of(other, str_member(sc, "rule").as_deref()),
        };
    }
    let data = sc.as_object().and_then(|s| s.get("data"));
    if data.and_then(|d| str_member(d, "status")).as_deref() == Some("awaiting_confirmation") {
        return Ok(Observed::Pending);
    }
    Ok(Observed::Completed)
}

/// Sends the MCP cell of `op` as a `tools/call` of its tool through the
/// world's MCP server, on `/mcp` with the cell's credential. An operation
/// with no tool is called by its operation name, which the server lists
/// under no tool.
fn mcp_call(
    w: &mut Built,
    op: &str,
    req: &Request,
    cred: &Credential,
) -> Result<Reply, ChannelFault> {
    if w.mcp.is_none() {
        let server = fstp_mcp::McpServer::new(
            Arc::clone(&w.core),
            fstp_mcp::McpConfig {
                tenant_origins: vec![ORIGIN.to_owned()],
                verified_domain: "tenant.fstp.test".to_owned(),
                resource_metadata_url: format!("{ORIGIN}{}", fstp_oauth::RESOURCE_METADATA_PATH),
            },
        )
        .map_err(|e| ChannelFault::Setup(format!("MCP server: {e}")))?;
        w.mcp = Some(server);
    }
    let server = w
        .mcp
        .as_ref()
        .ok_or_else(|| ChannelFault::Setup("no MCP server".to_owned()))?;
    let tool = fstp_access::op(op).and_then(|o| o.tool).map(|t| t.name);
    let r = block_on(server.call_tool(
        fstp_mcp::Surface::Mcp,
        cred.clone(),
        tool.unwrap_or(op),
        &req.tool_args(),
    ));
    Ok(Reply::Mcp(r, tool.is_some()))
}

/// The observed outcome of an HTTP reply.
pub fn observed_of_http(status: u16, body: &[u8]) -> Result<Observed, ChannelFault> {
    let v = fstp_json::parse(body).ok();
    let member = |k: &str| v.as_ref().and_then(|v| str_member(v, k));
    if let Some(code) = member("code") {
        return match code.as_str() {
            "step_up_required" => Ok(Observed::StepUpRequired),
            "strong_method_required" => Ok(Observed::StrongMethodRequired),
            other => observed_of(other, member("rule").as_deref()),
        };
    }
    if member("status").as_deref() == Some("awaiting_confirmation") {
        return Ok(Observed::Pending);
    }
    if (200..300).contains(&status) {
        Ok(Observed::Completed)
    } else {
        Err(ChannelFault::Setup(format!(
            "an HTTP {status} reply with no code: {}",
            String::from_utf8_lossy(body)
        )))
    }
}

/// The tenant origin of the HTTP channel.
const ORIGIN: &str = "https://tenant.fstp.test";

/// Sends `req` through the HTTP routes of `fstp-web` over a duplex pair.
fn http_call(w: &mut Built, req: &Request, cred: &Credential) -> Result<Reply, ChannelFault> {
    let fault = |e: String| ChannelFault::Setup(format!("HTTP: {e}"));
    if w.router.is_none() {
        let origin = fstp_web::parse_origin_header(ORIGIN.as_bytes())
            .map_err(|e| fault(format!("origin: {e:?}")))?;
        let assets = fstp_web::AssetSet::from_files(
            "main.js",
            &[(
                "main.js",
                b"// matrix harness asset set\nexport {};\n".as_slice(),
            )],
        )
        .map_err(|e| fault(format!("assets: {e:?}")))?;
        let router = fstp_web::router(
            Arc::clone(&w.core),
            fstp_web::WebConfig::new(origin, assets),
        )
        .map_err(|e| fault(format!("router: {e:?}")))?;
        w.router = Some(router);
    }
    let path = if req.path.starts_with("/p/") {
        req.path.clone()
    } else {
        format!("/api/v1{}", req.path)
    };
    let body = req.body_bytes();
    let mut head = format!(
        "{} {path} HTTP/1.1\r\nhost: tenant.fstp.test\r\n",
        match req.method {
            ApiMethod::Get => "GET",
            ApiMethod::Post => "POST",
            ApiMethod::Put => "PUT",
            ApiMethod::Delete => "DELETE",
        }
    );
    if req.method != ApiMethod::Get {
        head.push_str(&format!("origin: {ORIGIN}\r\nx-fstp-request: 1\r\n"));
    }
    if let Credential::SessionCookie(c) = cred {
        head.push_str(&format!(
            "cookie: {}={}\r\n",
            fstp_web::SESSION_COOKIE,
            String::from_utf8_lossy(c)
        ));
    }
    if !body.is_empty() {
        head.push_str("content-type: application/json\r\n");
    }
    head.push_str(&format!("content-length: {}\r\n\r\n", body.len()));
    let mut bytes = head.into_bytes();
    bytes.extend_from_slice(&body);
    let router = w
        .router
        .as_ref()
        .ok_or_else(|| fault("no router".to_owned()))?;
    let method = match req.method {
        ApiMethod::Get => fstp_http::Method::GET,
        ApiMethod::Post => fstp_http::Method::POST,
        ApiMethod::Put => fstp_http::Method::PUT,
        ApiMethod::Delete => fstp_http::Method::DELETE,
    };
    let (status, out) = block_on(duplex_exchange(router, &method, &bytes)).map_err(fault)?;
    Ok(Reply::Http(status, out))
}

/// Writes `request` into one end of a duplex pair, serves it from the
/// other end through `router`, and reads the response back.
async fn duplex_exchange(
    router: &fstp_web::WebRouter,
    method: &fstp_http::Method,
    request: &[u8],
) -> Result<(u16, Vec<u8>), String> {
    use fstp_rt::IoExt;
    const LIMIT: usize = 1 << 22;
    let (mut client, mut server) = fstp_rt::duplex::duplex(LIMIT);
    client
        .write_all(request)
        .await
        .map_err(|e| format!("client write: {e}"))?;
    client
        .shutdown()
        .await
        .map_err(|e| format!("client shutdown: {e}"))?;
    let mut got = Vec::new();
    server
        .read_to_end(&mut got, LIMIT)
        .await
        .map_err(|e| format!("server read: {e}"))?;
    let limits = fstp_web::limits();
    let response = match fstp_http::parse_request(&got, &limits) {
        Ok(fstp_http::Parsed::Complete { message, .. }) => router.serve(message).await,
        Ok(fstp_http::Parsed::Incomplete) => return Err("an incomplete request".to_owned()),
        Err(e) => return Err(format!("the request does not parse: {e:?}")),
    };
    let mut wire = Vec::new();
    fstp_http::encode_response(&response, false, &mut wire)
        .map_err(|e| format!("encode the response: {e:?}"))?;
    server
        .write_all(&wire)
        .await
        .map_err(|e| format!("server write: {e}"))?;
    server
        .shutdown()
        .await
        .map_err(|e| format!("server shutdown: {e}"))?;
    let mut back = Vec::new();
    client
        .read_to_end(&mut back, LIMIT)
        .await
        .map_err(|e| format!("client read: {e}"))?;
    match fstp_http::parse_response(&back, method, &limits, true) {
        Ok(fstp_http::Parsed::Complete { message, .. }) => {
            Ok((message.status.as_u16(), message.body))
        }
        Ok(fstp_http::Parsed::Incomplete) => Err("an incomplete response".to_owned()),
        Err(e) => Err(format!("the response does not parse: {e:?}")),
    }
}

// ---------------------------------------------------------------------------
// Channels
// ---------------------------------------------------------------------------

/// The direct channel: every cell through `ApiCore::dispatch`.
pub struct DirectChannel {
    runner: Runner,
}

/// The HTTP channel: every web cell through the routes of `fstp-web`.
/// An MCP cell runs through dispatch, since `/mcp` waits for ADR-013.
pub struct HttpChannel {
    runner: Runner,
}

/// The MCP channel: every MCP cell through the `tools/call` handler of
/// `fstp_mcp::McpServer`, and every web cell through the routes of
/// `fstp-web`, as the HTTP channel sends it (I-84, lane W3c).
pub struct McpChannel {
    runner: Runner,
}

impl std::fmt::Debug for McpChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("McpChannel")
    }
}

impl Channel for McpChannel {
    fn name(&self) -> &'static str {
        "mcp"
    }

    fn observe(&mut self, cell: &Cell) -> Result<Observed, ChannelFault> {
        observe_with(&mut self.runner, cell)
    }
}

impl std::fmt::Debug for DirectChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DirectChannel")
    }
}

impl std::fmt::Debug for HttpChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HttpChannel")
    }
}

/// Runs `cell`, again on a rebuilt world once if a rate limit refused it.
fn observe_with(runner: &mut Runner, cell: &Cell) -> Result<Observed, ChannelFault> {
    let first = runner.run_once(cell);
    let limited = matches!(
        &first,
        Ok(Observed::Refused(Some(r))) if r == "rate" || r == "H-07"
    );
    if !limited {
        return first;
    }
    if let Some(Ok(w)) = runner.worlds.get_mut(&WorldKey::of(cell)) {
        w.dirty = true;
    }
    runner.run_once(cell)
}

impl Channel for DirectChannel {
    fn name(&self) -> &'static str {
        "direct"
    }

    fn observe(&mut self, cell: &Cell) -> Result<Observed, ChannelFault> {
        observe_with(&mut self.runner, cell)
    }
}

impl Channel for HttpChannel {
    fn name(&self) -> &'static str {
        "http"
    }

    fn observe(&mut self, cell: &Cell) -> Result<Observed, ChannelFault> {
        observe_with(&mut self.runner, cell)
    }
}

/// The channel factory of the matrix.
#[derive(Clone, Copy, Debug)]
pub struct Harness {
    _private: (),
}

impl Harness {
    /// A fresh direct channel, with its own world cache.
    pub fn direct(&self) -> DirectChannel {
        DirectChannel {
            runner: Runner::new(Transport::Direct),
        }
    }

    /// A fresh HTTP channel, with its own world cache.
    pub fn http(&self) -> HttpChannel {
        HttpChannel {
            runner: Runner::new(Transport::Http),
        }
    }

    /// A fresh MCP channel, with its own world cache.
    pub fn mcp(&self) -> McpChannel {
        McpChannel {
            runner: Runner::new(Transport::Mcp),
        }
    }
}

/// Builds the `Harness`.
pub fn harness() -> Result<Harness, NotImplemented> {
    Ok(Harness { _private: () })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    /// Design section 8.1: the days of the harness timeline spell real
    /// calendar days.
    #[test]
    fn t_authz_matrix_harness_days_are_calendar_days() {
        assert_eq!(day_of(0), "1970-01-01");
        assert_eq!(day_of(31 * DAY), "1970-02-01");
        assert_eq!(day_of(MILESTONE_START), "1970-01-21");
    }

    /// I-87, R-PB-04, M4 design section 3.10 "Routes": the web channels
    /// send a public page as the `/p` router serves it, and decode it as
    /// that router does. The page and feed operations of the reference
    /// decode to themselves. The tool-only public operations have no page.
    #[test]
    fn i87_r_pb_04_harness_sends_public_pages_as_served() {
        let fill = |pattern: &str| {
            pattern
                .replace("{slug}", "synthetic")
                .replace("{call}", "7")
        };
        let mut pages = 0usize;
        for r in crate::reference::authz::REFERENCE_OPS
            .iter()
            .filter(|r| r.public)
        {
            let spec = fstp_access::op(r.name).unwrap();
            let (_, pattern) = spec.route.unwrap();
            let path = served_path(spec, pattern, fill(pattern));
            let got = decode_web(ApiMethod::Get, &path, &[]);
            if r.page {
                pages += 1;
                assert_eq!(got.map(|op| op.name()).ok(), Some(r.name), "{path}");
            } else {
                assert!(
                    matches!(&got, Err(ApiError::Refused { code, .. }) if code.as_str() == "not_found"),
                    "{path}: {got:?}"
                );
            }
        }
        assert_eq!(pages, 6);
        let api = served_path(
            fstp_access::op("call.publish").unwrap(),
            "/x",
            "/x".to_owned(),
        );
        assert_eq!(api, "/x");
    }

    /// I-87, R-PB-04, review H-01: through the direct channel an anonymous
    /// web read of a public page reaches the system. No page is public
    /// while the programme is a draft. Once it is active its pages are
    /// served. Once the call is open its call page is served too (lane
    /// mpubfin2). The Guide page still answers not found: the Guide is an
    /// M4 seam that fails closed (`fstp-api-core` `dispatch/public.rs`,
    /// "Seams"). It is pinned here, so this test fails once the seam lands.
    #[test]
    fn i87_r_pb_04_direct_public_pages_are_served_once_active() {
        let m = crate::matrix::matrix().unwrap();
        let mut channel = harness().unwrap().direct();
        let programme = [
            "public.programme",
            "public.funded",
            "public.finished",
            "public.feed",
        ];
        let cases: Vec<(StateProfile, &str, Observed)> = programme
            .iter()
            .map(|op| {
                (
                    StateProfile::ProgrammeDraft,
                    *op,
                    Observed::NotFound("Input".to_owned()),
                )
            })
            .chain(
                programme
                    .iter()
                    .map(|op| (StateProfile::ProgrammeActive, *op, Observed::Completed)),
            )
            .chain(
                programme
                    .iter()
                    .map(|op| (StateProfile::CallOpen, *op, Observed::Completed)),
            )
            .chain(
                [
                    ("public.call", Observed::Completed),
                    ("public.guide", Observed::NotFound("Input".to_owned())),
                ]
                .into_iter()
                .map(|(op, want)| (StateProfile::CallOpen, op, want)),
            )
            .collect();
        for (state, op, want) in cases {
            let cell = m
                .cells()
                .find(|c| {
                    c.op == op
                        && c.state == state
                        && c.who == Who::Anonymous
                        && c.session.channel == Via2::Web
                })
                .unwrap_or_else(|| panic!("no anonymous web cell of {op} in {state:?}"));
            assert_eq!(
                m.reference().expected(&cell),
                Some(crate::reference::authz::Expected::Allow)
            );
            let got = channel
                .observe(&cell)
                .unwrap_or_else(|e| panic!("{op} {state:?}: {e:?}"));
            assert_eq!(got, want, "{op} in {state:?}");
        }
    }
}

/// M5 lane L-API: the grant, contract, payment and report operations run
/// end to end through `ApiCore::dispatch` on a matrix world, and no reply
/// of a new read holds an identity attribute, a bank detail or a vault
/// value (I-86).
#[cfg(test)]
mod m5_api_tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::arithmetic_side_effects,
        clippy::indexing_slicing
    )]

    use super::*;
    use crate::reference::authz::Policy;
    use fstp_domain::id::{ContentDigest, MilestoneId, RequestId};
    use fstp_domain::payment::{CheckKind, CheckPhase, CheckResult, RequestStatus};

    const POST: ApiMethod = ApiMethod::Post;
    const GET: ApiMethod = ApiMethod::Get;

    fn world(state: StateTag) -> Built {
        build(WorldKey {
            state: StateProfile::Proposal(state),
            policy: Policy::SUPERSAFE,
            variant: Variant::Main,
        })
        .unwrap_or_else(|e| panic!("world {state:?}: {e}"))
    }

    fn seeder(w: Built) -> Seeder {
        Seeder {
            ports: w.ports,
            core: w.core,
            now: w.now,
            command: 900_000,
            cookies: BTreeMap::new(),
            next_id: 90_000_000,
            admins: w.admins.iter().copied().collect(),
        }
    }

    /// I-86: an IBAN-shaped run, an email, or a member that names vault
    /// evidence or bank details.
    fn leaks(json: &str) -> bool {
        let b = json.as_bytes();
        let iban = (0..b.len()).any(|i| {
            b.get(i..i + 4).is_some_and(|h| {
                h[0].is_ascii_uppercase()
                    && h[1].is_ascii_uppercase()
                    && h[2].is_ascii_digit()
                    && h[3].is_ascii_digit()
            }) && b.get(i + 4..).is_some_and(|t| {
                t.iter()
                    .take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
                    .count()
                    >= 11
            })
        });
        iban || json.contains('@')
            || json.contains("evidence")
            || json.contains("iban")
            || json.contains("bank")
    }

    fn read(seed: &mut Seeder, who: AccountId, path: &str) -> Value {
        let v = seed
            .api(who, GET, path, &Value::Null)
            .unwrap_or_else(|e| panic!("{path}: {e}"));
        let text = v.to_compact();
        assert!(!leaks(&text), "I-86: {path} leaks: {text}");
        v
    }

    fn milestone_of(seed: &Seeder, x: ProposalId, plan: u128) -> MilestoneId {
        let store = seed.ports.engine.store_copy();
        let mut entries = Vec::new();
        store
            .read(fstp_ledger::Seq::ZERO, usize::MAX, &mut entries)
            .unwrap();
        entries
            .iter()
            .find_map(|e| match &e.record {
                Record::Core(fstp_domain::record::Record::PlanVersionRecorded(r))
                    if r.proposal == x && r.plan.raw() == plan =>
                {
                    r.tasks
                        .first()
                        .and_then(|t| t.milestones.first())
                        .map(|m| m.id)
                }
                _ => None,
            })
            .expect("a milestone")
    }

    fn checks(seed: &mut Seeder, r: RequestId, phase: CheckPhase) {
        let state = seed.ports.engine.state();
        let s = state
            .core
            .payments()
            .summaries()
            .find(|s| s.request == r)
            .expect("the request");
        let results = s
            .lines
            .iter()
            .map(|l| CheckResult {
                line: Some(l.line),
                check: CheckKind::Evidence,
                failure: None,
            })
            .collect();
        seed.system(
            SystemCause::Timeline,
            Core::RecordChecks {
                request: r,
                phase,
                results,
                snapshot: ContentDigest::from_bytes([7; 32]),
            },
        )
        .unwrap();
    }

    fn status(seed: &Seeder, r: RequestId) -> Option<RequestStatus> {
        seed.ports.engine.state().core.payments().status(r)
    }

    /// R-PR-01, I-05, I-31, I-33, I-86, M5 exit "a call cycle runs through
    /// to PAID": a milestone claim of the lead runs through the checks,
    /// line review by the assigned reviewer, approval, release after the
    /// bank hold and the paid confirmation, each through the API. Every
    /// new read is scanned for identity and bank values on the way.
    #[test]
    fn m5_i86_r_pr_01_payment_cycle_through_the_api_reaches_paid() {
        let w = world(StateTag::InExecution);
        let x = w.targets.proposal.expect("X");
        let plan = w.targets.plan.expect("plan");
        let mut seed = seeder(w);
        let milestone = milestone_of(&seed, x, plan);
        let line = obj(vec![
            ("milestone", dec(milestone.raw())),
            ("amount", s("100.00")),
            (
                "evidence",
                obj(vec![
                    ("location", s("https://forge.example/synthetic/repo")),
                    ("release", s("v1.0.0")),
                    ("licence", s("MIT")),
                    ("report", s("SYNTHETIC DELIVERY REPORT")),
                ]),
            ),
        ]);
        let body = obj(vec![
            ("kind", obj(vec![("type", s("Milestone"))])),
            ("currency", s("EUR")),
            ("lines", Value::Array(Array::from(vec![line]))),
        ]);
        let v = seed
            .api(
                LEAD,
                POST,
                &format!("/grants/{}/payment-requests", x.raw()),
                &body,
            )
            .unwrap();
        let r = RequestId::from_raw(str_member(&v, "request").unwrap().parse().unwrap());
        assert_eq!(status(&seed, r), Some(RequestStatus::Submitted));
        checks(&mut seed, r, CheckPhase::Submission);
        checks(&mut seed, r, CheckPhase::Acceptance);
        let q = read(&mut seed, REVIEWER, "/me/payment-queue");
        assert!(q.to_compact().contains("\"review\""), "{}", q.to_compact());
        let state = seed.ports.engine.state();
        let l = state
            .core
            .payments()
            .summaries()
            .find(|s| s.request == r)
            .unwrap()
            .lines[0]
            .line;
        // SoD-12: the lead cannot decide a line of its own request.
        assert!(
            seed.api(
                LEAD,
                POST,
                &format!("/payment-requests/{}/lines/{}/decision", r.raw(), l.raw()),
                &obj(vec![("approved", s("100.00")), ("currency", s("EUR"))]),
            )
            .is_err()
        );
        seed.api(
            REVIEWER,
            POST,
            &format!("/payment-requests/{}/lines/{}/decision", r.raw(), l.raw()),
            &obj(vec![("approved", s("100.00")), ("currency", s("EUR"))]),
        )
        .unwrap();
        assert_eq!(status(&seed, r), Some(RequestStatus::Accepted));
        seed.api(
            FINANCE,
            POST,
            &format!("/payment-requests/{}/approval", r.raw()),
            &obj(vec![]),
        )
        .unwrap();
        // I-33: a new bank detail write holds every release until it is
        // verified and P-36 elapsed, the world's earlier write aside.
        let fresh = Timestamp::from_micros(seed.now);
        seed.ports.vault.change(|t| t.write_bank(x, fresh));
        assert!(
            seed.api(
                RELEASER,
                POST,
                &format!("/payment-requests/{}/release", r.raw()),
                &obj(vec![])
            )
            .is_err()
        );
        let v = seed
            .api(
                LEAD,
                POST,
                &format!("/grants/{}/bank-details", x.raw()),
                &obj(vec![]),
            )
            .unwrap();
        assert!(str_member(&v, "redirect").is_some(), "{}", v.to_compact());
        let written = Timestamp::from_micros(seed.now);
        seed.ports.vault.change(|t| {
            t.write_bank(x, written);
            t.verify_bank(x);
        });
        seed.at(seed.now.saturating_add(400 * DAY));
        seed.api(
            RELEASER,
            POST,
            &format!("/payment-requests/{}/release", r.raw()),
            &obj(vec![]),
        )
        .unwrap();
        assert_eq!(status(&seed, r), Some(RequestStatus::Released));
        // Reading 6: the releaser of this request opens the payee page.
        seed.api(
            RELEASER,
            POST,
            &format!("/payment-requests/{}/payee", r.raw()),
            &obj(vec![]),
        )
        .unwrap();
        seed.api(
            FINANCE,
            POST,
            &format!("/payment-requests/{}/paid", r.raw()),
            &obj(vec![]),
        )
        .unwrap();
        assert_eq!(status(&seed, r), Some(RequestStatus::Paid));
        let o = read(&mut seed, PM, &format!("/grants/{}", x.raw()));
        assert_eq!(str_member(&o, "paid").as_deref(), Some("100.00"));
        let p = read(
            &mut seed,
            LEAD,
            &format!("/grants/{}/payment-requests", x.raw()),
        );
        assert!(p.to_compact().contains("\"PAID\""), "{}", p.to_compact());
        read(&mut seed, AUDITOR, &format!("/grants/{}/contract", x.raw()));
        // An outsider of the grant reads nothing.
        assert!(
            seed.api(MEMBER, GET, &format!("/grants/{}", x.raw()), &Value::Null)
                .is_err()
        );
    }

    /// I-30, R-CT-01, R-CT-04, R-NG-03, R-RP-03, R-RP-04, I-44: from
    /// NEGOTIATION, the amount is determined, accepted and approved; the
    /// contract is drafted, a clause change agreed, sent and signed by
    /// both parties through the fake wallet and QTSP, and the grant is
    /// GRANTED. A funder output is generated by the programme manager and
    /// approved by a Financial signatory, never by its generator.
    #[test]
    fn m5_i30_r_rp_03_contract_and_report_through_the_api() {
        let w = world(StateTag::Negotiation);
        let x = w.targets.proposal.expect("X");
        let plan = w.targets.plan.expect("plan");
        let c = w.targets.call.expect("C");
        let programme = w.targets.programme.expect("P");
        let mut seed = seeder(w);
        // X.509 validity needs a calendar instant: 2027-01-01T00:00:00Z.
        seed.at(1_798_761_600 * SECOND);
        let fake = fstp_contract::fake::FakeTrustServices::new(seed.now / SECOND).unwrap();
        let trust = fake.trusted_list();
        seed.core = Arc::new(fstp_api_core::port::api_core_with_signing(
            seed.ports.clone(),
            Box::new(fake),
            Box::new(trust),
        ));
        seed.api(
            REVIEWER,
            POST,
            &format!("/grants/{}/amount-determination", x.raw()),
            &obj(vec![
                ("agreed", dec(plan)),
                ("deductions", Value::Array(Array::new())),
                ("currency", s("EUR")),
            ]),
        )
        .unwrap();
        let o = read(&mut seed, LEAD, &format!("/grants/{}", x.raw()));
        let d = str_member(&o, "determination").unwrap();
        let det = obj(vec![("determination", s(&d))]);
        seed.api(LEAD, POST, &format!("/grants/{}/acceptance", x.raw()), &det)
            .unwrap();
        seed.api(PM, POST, &format!("/grants/{}/approval", x.raw()), &det)
            .unwrap();
        // Only the programme manager drafts.
        assert!(
            seed.api(
                LEAD,
                POST,
                &format!("/grants/{}/contract", x.raw()),
                &obj(vec![])
            )
            .is_err()
        );
        let v = seed
            .api(
                PM,
                POST,
                &format!("/grants/{}/contract", x.raw()),
                &obj(vec![]),
            )
            .unwrap();
        let k = str_member(&v, "contract").unwrap();
        seed.api(
            LEAD,
            POST,
            &format!("/contracts/{k}/changes"),
            &obj(vec![
                ("clause", int(1)),
                ("text", s("SYNTHETIC CHANGE: the report is due in English.")),
            ]),
        )
        .unwrap();
        // R-CT-04: the proposing side does not decide its own change.
        assert!(
            seed.api(
                LEAD,
                POST,
                &format!("/contracts/{k}/changes/1/decision"),
                &obj(vec![("accept", Value::Bool(true))])
            )
            .is_err()
        );
        seed.api(
            PM,
            POST,
            &format!("/contracts/{k}/changes/1/decision"),
            &obj(vec![("accept", Value::Bool(true))]),
        )
        .unwrap();
        seed.api(PM, POST, &format!("/contracts/{k}/send"), &obj(vec![]))
            .unwrap();
        // Only a party signs.
        assert!(
            seed.api(
                PM,
                POST,
                &format!("/contracts/{k}/signature"),
                &obj(vec![("route", s("wallet_qes"))])
            )
            .is_err()
        );
        seed.api(
            LEAD,
            POST,
            &format!("/contracts/{k}/signature"),
            &obj(vec![("route", s("wallet_qes"))]),
        )
        .unwrap();
        let pending = read(&mut seed, LEAD, &format!("/grants/{}/contract", x.raw()));
        if pending.to_compact().contains("\"guardian\"") {
            seed.api(
                GUARDIAN,
                POST,
                &format!("/contracts/{k}/signature"),
                &obj(vec![("route", s("wallet_qes"))]),
            )
            .unwrap();
        }
        seed.api(
            SIGNATORY,
            POST,
            &format!("/contracts/{k}/signature"),
            &obj(vec![("route", s("qtsp_remote_qes"))]),
        )
        .unwrap();
        let view = read(&mut seed, LEAD, &format!("/grants/{}/contract", x.raw()));
        assert_eq!(str_member(&view, "status").as_deref(), Some("effective"));
        let o = read(&mut seed, PM, &format!("/grants/{}", x.raw()));
        assert_eq!(str_member(&o, "state").as_deref(), Some("GRANTED"));
        // R-RP-04, R-RP-03.
        let v = seed
            .api(
                PM,
                POST,
                &format!("/programmes/{}/reports", programme.raw()),
                &obj(vec![("kind", s("audit_file")), ("call", dec(c.raw()))]),
            )
            .unwrap();
        let report = str_member(&v, "report").unwrap();
        assert!(
            seed.api(
                PM,
                POST,
                &format!("/reports/{report}/approval"),
                &obj(vec![])
            )
            .is_err()
        );
        seed.api(
            ORG_SIGNATORY,
            POST,
            &format!("/reports/{report}/approval"),
            &obj(vec![]),
        )
        .unwrap();
        let list = read(
            &mut seed,
            ORG_SIGNATORY,
            &format!("/programmes/{}/reports", programme.raw()),
        );
        assert!(
            list.to_compact().contains("\"approved\":true"),
            "{}",
            list.to_compact()
        );
    }
}

/// The M5 reads follow-up through the API (`docs/handoff/m5-ui.md`).
#[cfg(test)]
#[path = "harness_m5_reads.rs"]
mod m5_reads_tests;
/// Lane m6/mailbox: `me.mailbox` on the matrix worlds
/// (`docs/handoff/mailbox-design.md` section 7).
#[cfg(test)]
mod mailbox_tests;
