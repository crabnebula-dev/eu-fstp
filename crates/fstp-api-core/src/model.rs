//! Identity-free read models (design sections 3.6 and 3.7). No read model
//! carries an identity field (I-17): no display name, no email, no
//! identity attribute and no vault fact. Ids are the only references. The
//! [`crate::McpSafe`] marker is implemented by hand for each of them.
//!
//! One exception is web only: the creator's invitation list names each
//! pending invitee's email to the programme managers who invited them
//! ([`ReadModel::carries_email`]). The dispatch refuses it through MCP,
//! and a test checks that no tool's operation is served by it (I-86).
//!
//! Every model has a JSON encoding with decimal strings for ids, instants
//! and amounts (ADR-006), and snake_case member names (interim, pending
//! Daniel).
//!
//! Status: the models below are the ones whose data the M4 domain state
//! exposes today. Each other read answers `ApiError::NotImplemented`
//! naming the lane it waits for, so no read is answered with made-up
//! data.

use fstp_domain::id::{AssignmentId, CallId, ProgrammeId, ProposalId};
use fstp_domain::programme::{CallStatus, CallView};
use fstp_domain::time::Timestamp;
use fstp_json::{Array, Object, ToJson, Value};

use crate::McpSafe;
use crate::pending::PendingView;
use crate::port::{LoginMethod, SessionId, SessionInfo};

/// The body of a completed call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReadModel {
    /// A command completed. It returns no read model.
    Accepted,
    /// A command completed and drew new ids, each named by the command
    /// member it fills, such as `proposal` for `CreateDraft`.
    Created(Vec<(&'static str, u128)>),
    /// `pending.list`: the caller's own pending actions (I-85).
    PendingActions(Vec<PendingView>),
    /// `calls.list_open`: the calls open at the instant of the read.
    OpenCalls(Vec<CallSummary>),
    /// `calls.get`: one published call.
    Call(CallSummary),
    /// `proposal.list_own`: the caller's own proposals.
    OwnProposals(Vec<ProposalSummary>),
    /// `me.assignments`: the caller's own assignments.
    Assignments(Vec<AssignmentSummary>),
    /// `me.sessions`: the caller's own sessions (R-LG-04).
    Sessions(Vec<SessionSummary>),
    /// `me.begin_verification`: where the browser goes to verify.
    Redirect(String),
    /// `intake.queue`: the P-09 criteria and the submitted proposals.
    IntakeQueue(crate::views::IntakeQueue),
    /// `call.board`: the call's proposals in review.
    Board(Vec<crate::views::ProposalRow>),
    /// `review.declaration_view`: title and neutral summary only (Q9).
    DeclarationView(crate::views::DeclarationView),
    /// `review.read_content` and `irc.case`: the submitted proposal.
    Content(crate::views::ContentView),
    /// `review.score_sheet`: what the reviewer scores now.
    ScoreSheet(crate::views::ScoreSheet),
    /// `review.stage2_thread`: the stage 2 questions and answers.
    Stage2Thread(crate::views::Stage2Thread),
    /// `committee.ranking`: the ranked proposals of the call.
    Ranking(Vec<crate::views::RankingRow>),
    /// `review.notifiable_conflicts`: one draft per notifiable conflict.
    Notifiable(Vec<ProposalId>),
    /// `proposal.get_workspace`: the team's private draft (I-21).
    Workspace(crate::views::WorkspaceView),
    /// `proposal.record_plan`: the plan was recorded, with the id the
    /// server drew for it and its total as the cell computed it
    /// (ADR-006). The browser never computes money. A stage 2 revision
    /// names this plan when it is submitted (R-EV-05).
    PlanSaved {
        /// The recorded plan.
        plan: u128,
        /// Its total, an ADR-006 string.
        total: String,
    },
    /// `proposal.view`: one of the caller's own proposals.
    OwnProposal(ProposalSummary),
    /// `stage2.view`: the questions under their P-11 handles, by day (TH-08).
    Stage2Questions(Vec<crate::views::Question>),
    /// `me.notices`: the caller's notices.
    Notices(Vec<crate::views::Notice>),
    /// `negotiation.view`: whether the caller acknowledged the notice (R-NG-06).
    Negotiation {
        /// Whether the caller acknowledged the negotiation notice.
        acknowledged: bool,
    },
    /// `committee.open_round`: the round the server drew (change D5).
    RoundOpened(RoundOpened),
    /// `review.assignments`: one proposal's assignment view (R-AC-01,
    /// R-CF-03).
    AssignmentView(AssignmentView),
    /// `me.get_verification`: the caller's own verification state (I-86).
    Verification(VerificationState),
    /// `committee.round`: one cut-off round (R-EV-08, R-EV-09).
    Round(RoundView),
    /// The tenant reads and the reply of a step save (R-TN-01, SoD-07,
    /// R-LG-03, lane m4tenant).
    Tenant(crate::tenant::TenantView),
    /// A read model of the creator pages, or the reply of a creator
    /// command that names what it drew (lane m4wire).
    Creator(crate::creator::CreatorModel),
    /// `me.roles`: the caller's own active roles, for the interim home
    /// page of design section 15.0 (2026-10-31; I-86).
    MyRoles(crate::dispatch::me_roles::MyRoles),
    /// `proposal.journey`: a proposal's route position, its legs and the
    /// overlay (lane j2, `SPEC/12-journey-ui.md` section 10).
    Journey(crate::dispatch::journey::JourneyView),
    /// `proposal.diary`: the diary entries the caller may see (lane j2,
    /// I-93, I-97).
    Diary(crate::dispatch::journey::DiaryView),
    /// `calls.guide`: the Guide its publication stored (R-GA-01, I-53).
    Guide(StoredGuideView),
    /// A public page, the feed or a public tool answer, from
    /// `fstp-public` only (I-87, design section 3.10).
    Public(PublicReply),
}

/// The Guide of a published call as its publication stored it, with its
/// corrigenda after the page (R-GA-01, I-51, I-53). Nothing is bound
/// again per request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredGuideView {
    /// The call.
    pub call: CallId,
    /// The Guide version.
    pub version: u32,
    /// The SHA-256 of the canonical document, in lower-case hex.
    pub digest: String,
    /// The stored page with its corrigenda.
    pub html: String,
}

impl ToJson for StoredGuideView {
    fn to_json(&self) -> Value {
        let mut o = Object::new();
        let _ = o.insert("call", dec(self.call.raw()));
        let _ = o.insert("version", Value::from(self.version));
        let _ = o.insert("digest", Value::from(self.digest.as_str()));
        let _ = o.insert("html", Value::from(self.html.as_str()));
        Value::Object(o)
    }
}

/// The answer to a public operation (design section 3.10).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicReply {
    /// A public tool answer or the feed, as `fstp_public` encodes it.
    Json(Value),
    /// A server-rendered public page: the bytes of the `fstp-html`
    /// writer, with no script (R-PB-04).
    Page(String),
}

impl ReadModel {
    /// The HTML of a public page, for the `/p` routes of the web adapter.
    pub fn public_page(&self) -> Option<&str> {
        match self {
            ReadModel::Public(PublicReply::Page(html)) => Some(html),
            _ => None,
        }
    }
}

/// A decimal string.
fn dec(x: impl std::fmt::Display) -> Value {
    Value::String(x.to_string())
}

fn array<T: ToJson>(items: &[T]) -> Value {
    let mut a = Array::new();
    for i in items {
        a.push(i.to_json());
    }
    Value::Array(a)
}

impl ToJson for ReadModel {
    fn to_json(&self) -> Value {
        match self {
            ReadModel::Accepted => {
                let mut o = Object::new();
                let _ = o.insert("accepted", Value::Bool(true));
                Value::Object(o)
            }
            ReadModel::Created(ids) => {
                let mut o = Object::new();
                let _ = o.insert("accepted", Value::Bool(true));
                for (name, id) in ids {
                    let _ = o.insert(*name, dec(id));
                }
                Value::Object(o)
            }
            ReadModel::PendingActions(v) => array(v),
            ReadModel::OpenCalls(v) => array(v),
            ReadModel::Call(c) => c.to_json(),
            ReadModel::OwnProposals(v) => array(v),
            ReadModel::Assignments(v) => array(v),
            ReadModel::Sessions(v) => array(v),
            ReadModel::Redirect(to) => {
                let mut o = Object::new();
                let _ = o.insert("redirect", Value::from(to.as_str()));
                Value::Object(o)
            }
            ReadModel::IntakeQueue(q) => q.to_json(),
            ReadModel::Board(rows) => array(rows),
            ReadModel::DeclarationView(v) => v.to_json(),
            ReadModel::Content(v) => v.to_json(),
            ReadModel::ScoreSheet(v) => v.to_json(),
            ReadModel::Stage2Thread(v) => v.to_json(),
            ReadModel::Ranking(rows) => array(rows),
            ReadModel::Notifiable(ps) => Value::Array(
                ps.iter()
                    .map(|p| {
                        let mut o = Object::new();
                        let _ = o.insert("proposal", dec(p.raw()));
                        Value::Object(o)
                    })
                    .collect(),
            ),
            ReadModel::Workspace(w) => w.to_json(),
            ReadModel::OwnProposal(p) => p.to_json(),
            ReadModel::PlanSaved { plan, total } => {
                let mut o = Object::new();
                let _ = o.insert("accepted", Value::Bool(true));
                let _ = o.insert("plan", dec(plan));
                let _ = o.insert("total", Value::from(total.as_str()));
                Value::Object(o)
            }
            ReadModel::Stage2Questions(qs) => {
                let mut o = Object::new();
                let _ = o.insert("questions", array(qs));
                Value::Object(o)
            }
            ReadModel::Notices(ns) => array(ns),
            ReadModel::Negotiation { acknowledged } => {
                let mut o = Object::new();
                let _ = o.insert("acknowledged", Value::Bool(*acknowledged));
                Value::Object(o)
            }
            ReadModel::RoundOpened(r) => r.to_json(),
            ReadModel::AssignmentView(v) => v.to_json(),
            ReadModel::Verification(v) => v.to_json(),
            ReadModel::Round(v) => v.to_json(),
            ReadModel::Tenant(v) => v.to_json(),
            ReadModel::Creator(m) => m.to_json(),
            ReadModel::MyRoles(r) => r.to_json(),
            ReadModel::Journey(v) => v.to_json(),
            ReadModel::Diary(v) => v.to_json(),
            ReadModel::Guide(g) => g.to_json(),
            ReadModel::Public(PublicReply::Json(v)) => v.clone(),
            ReadModel::Public(PublicReply::Page(html)) => {
                let mut o = Object::new();
                let _ = o.insert("html", Value::from(html.as_str()));
                Value::Object(o)
            }
        }
    }
}

impl ReadModel {
    /// Whether the model carries an email. Only the creator's invitation
    /// list does, and it is web only: the dispatch refuses it through MCP
    /// before it reads anything, and no tool's operation is served by
    /// it (I-86; tested below).
    pub fn carries_email(&self) -> bool {
        match self {
            ReadModel::Creator(m) => m.carries_email(),
            _ => false,
        }
    }
}

/// I-86: every model but the web-only invitation list is identity free
/// ([`ReadModel::carries_email`]). That one never reaches an MCP
/// response, by the dispatch guard and the registry test below.
impl McpSafe for ReadModel {}

/// The status of a call as JSON spells it.
const fn call_status(s: CallStatus) -> &'static str {
    match s {
        CallStatus::Draft => "draft",
        CallStatus::Approved => "approved",
        CallStatus::Published => "published",
    }
}

/// One call, without its authors or approver (I-17).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallSummary {
    /// The call.
    pub call: CallId,
    /// Its programme.
    pub programme: ProgrammeId,
    /// `draft`, `approved` or `published`.
    pub status: &'static str,
    /// When it opens.
    pub opens: Timestamp,
    /// The deadline.
    pub deadline: Timestamp,
    /// The deadline's IANA zone.
    pub deadline_zone: String,
    /// The budget, an ADR-006 string.
    pub budget: String,
    /// The budget's currency code.
    pub currency: &'static str,
    /// Whether the call is open at the instant of the read.
    pub open: bool,
    /// The call's title: its published text (R-PB-01), when read.
    pub title: Option<String>,
    /// P-04, the grant range, as ADR-006 strings, once published.
    pub grant_range: Option<(String, String)>,
    /// P-05, the cap per recipient, as an ADR-006 string, when known.
    pub recipient_max: Option<String>,
}

impl CallSummary {
    /// The summary of `v` at `now`.
    pub(crate) fn of(v: &CallView, now: Timestamp) -> CallSummary {
        let budget = v.budget().amount();
        CallSummary {
            call: v.id(),
            programme: v.programme(),
            status: call_status(v.status()),
            opens: v.opens(),
            deadline: v.deadline(),
            deadline_zone: v.deadline_zone().as_str().to_owned(),
            budget: budget.to_string(),
            currency: budget.currency().code(),
            open: v.is_open_at(now),
            title: None,
            grant_range: v.frozen().map(|f| {
                (
                    f.values().p04.min().amount().to_string(),
                    f.values().p04.max().amount().to_string(),
                )
            }),
            recipient_max: None,
        }
    }
}

impl ToJson for CallSummary {
    fn to_json(&self) -> Value {
        let mut o = Object::new();
        let _ = o.insert("call", dec(self.call.raw()));
        let _ = o.insert("programme", dec(self.programme.raw()));
        let _ = o.insert("status", Value::from(self.status));
        let _ = o.insert("opens", dec(self.opens.micros()));
        let _ = o.insert("deadline", dec(self.deadline.micros()));
        let _ = o.insert("deadline_zone", Value::from(self.deadline_zone.as_str()));
        let _ = o.insert("budget", Value::from(self.budget.as_str()));
        let _ = o.insert("currency", Value::from(self.currency));
        let _ = o.insert("open", Value::Bool(self.open));
        if let Some(t) = &self.title {
            let _ = o.insert("title", Value::from(t.as_str()));
        }
        if let Some((min, max)) = &self.grant_range {
            let _ = o.insert("grant_min", Value::from(min.as_str()));
            let _ = o.insert("grant_max", Value::from(max.as_str()));
        }
        if let Some(r) = &self.recipient_max {
            let _ = o.insert("recipient_max", Value::from(r.as_str()));
        }
        Value::Object(o)
    }
}

impl McpSafe for CallSummary {}

/// One of the caller's proposals: "Proposal" plus its id, never a name
/// (I-17).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposalSummary {
    /// The proposal.
    pub proposal: ProposalId,
    /// Its call.
    pub call: CallId,
    /// Its state, as the state machine names it.
    pub state: String,
    /// The caller's role on it: `lead`, `member` or `guardian`.
    pub role: &'static str,
    /// Its title: the submitted one, else the team's draft title.
    pub title: Option<String>,
}

impl ToJson for ProposalSummary {
    fn to_json(&self) -> Value {
        let mut o = Object::new();
        let _ = o.insert("proposal", dec(self.proposal.raw()));
        let _ = o.insert("call", dec(self.call.raw()));
        let _ = o.insert("state", Value::from(self.state.as_str()));
        let _ = o.insert("role", Value::from(self.role));
        if let Some(t) = &self.title {
            let _ = o.insert("title", Value::from(t.as_str()));
        }
        Value::Object(o)
    }
}

impl McpSafe for ProposalSummary {}

/// One of the caller's assignments, with no applicant identity (I-17).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssignmentSummary {
    /// The assignment.
    pub assignment: AssignmentId,
    /// The proposal, as "Proposal" plus its id.
    pub proposal: ProposalId,
    /// The call it was made in.
    pub call: CallId,
    /// `reviewer`, `irc` or `amendment`.
    pub kind: &'static str,
    /// Whether the caller still has to declare (R-CF-02).
    pub awaiting_declaration: bool,
    /// Whether it is active.
    pub active: bool,
    /// Whether its stage 2 thread opens: an active reviewer assignment
    /// whose proposal is in STAGE2. The list links the stage 2 page only
    /// then (review finding U5). An IRC row is always false, so it says
    /// nothing of the proposal's state (O-58).
    pub stage2: bool,
}

impl ToJson for AssignmentSummary {
    fn to_json(&self) -> Value {
        let mut o = Object::new();
        let _ = o.insert("assignment", dec(self.assignment.raw()));
        let _ = o.insert("proposal", dec(self.proposal.raw()));
        let _ = o.insert("call", dec(self.call.raw()));
        let _ = o.insert("kind", Value::from(self.kind));
        let _ = o.insert(
            "awaiting_declaration",
            Value::Bool(self.awaiting_declaration),
        );
        let _ = o.insert("active", Value::Bool(self.active));
        let _ = o.insert("stage2", Value::Bool(self.stage2));
        Value::Object(o)
    }
}

impl McpSafe for AssignmentSummary {}

/// One of the caller's sessions (R-LG-04).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionSummary {
    /// The session.
    pub session: SessionId,
    /// How it logged in.
    pub method: LoginMethod,
    /// When it started.
    pub started: Timestamp,
}

impl From<SessionInfo> for SessionSummary {
    fn from(s: SessionInfo) -> SessionSummary {
        SessionSummary {
            session: s.session,
            method: s.method,
            started: s.started,
        }
    }
}

impl ToJson for SessionSummary {
    fn to_json(&self) -> Value {
        let method = match self.method {
            LoginMethod::Passkey => "passkey",
            LoginMethod::MagicLink => "magic_link",
            LoginMethod::Opaque => "opaque",
            LoginMethod::EudiWallet => "eudi_wallet",
        };
        let mut o = Object::new();
        let _ = o.insert("session", dec(self.session.raw()));
        let _ = o.insert("method", Value::from(method));
        let _ = o.insert("started", dec(self.started.micros()));
        Value::Object(o)
    }
}

impl McpSafe for SessionSummary {}

impl McpSafe for PendingView {}

// ---------------------------------------------------------------------------
// Lane m4reg: the read models of the reads the M4 demo pages call. Each
// encodes to the reply shape `fstp_access::REPLIES` names for its
// operation. The models hold only what their constructors are given or
// what the projection holds, so none is served with made-up data.
//
// Seam for lane m4int-b: `dispatch::read` has no branch for these reads
// yet, and `ReadModel` has no variant for them. The data behind
// `tenant.list_admins`, `me.get_verification`, `creator.list_programmes`,
// `creator.list_templates` and `people.get_invitation` comes from ports
// and from the creator state, which dispatch reads.
// ---------------------------------------------------------------------------

use std::collections::BTreeSet;
use std::num::NonZeroU32;

use fstp_domain::StateTag;
use fstp_domain::assignment::{AssignmentKind, AssignmentStatus};
use fstp_domain::id::{AccountId, DecisionId, Handle};
use fstp_domain::policy::McpBindingActions;
use fstp_domain::roles::{BindingScope, Group, Role};

use crate::port::DisplayHandle;

fn object(members: Vec<(&'static str, Value)>) -> Value {
    let mut o = Object::new();
    for (k, v) in members {
        let _ = o.insert(k, v);
    }
    Value::Object(o)
}

/// One tenant admin as the Administrators step lists it (SoD-07): the
/// account, its pseudonymous display handle, never an email, and whether
/// it verified its identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdminRow {
    /// The account.
    pub account: AccountId,
    /// The display handle from `Accounts::display_handle`.
    pub handle: DisplayHandle,
    /// Whether the vault answered `IsVerified` for the account.
    pub verified: bool,
}

/// `tenant.list_admins`: the tenant's admins, in account order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TenantAdmins {
    admins: Vec<AdminRow>,
}

impl TenantAdmins {
    /// The list of `rows`, in account order, each account once. A later
    /// row for an account already listed is dropped.
    pub fn new(rows: impl IntoIterator<Item = AdminRow>) -> TenantAdmins {
        let mut seen = BTreeSet::new();
        let mut admins: Vec<AdminRow> = rows
            .into_iter()
            .filter(|r| seen.insert(r.account))
            .collect();
        admins.sort_by_key(|r| r.account);
        TenantAdmins { admins }
    }

    /// The rows.
    pub fn admins(&self) -> &[AdminRow] {
        &self.admins
    }

    /// How many listed admins verified their identity. Onboarding
    /// finishes only with two (SoD-07, J0).
    pub fn verified_count(&self) -> usize {
        self.admins.iter().filter(|r| r.verified).count()
    }
}

impl ToJson for AdminRow {
    fn to_json(&self) -> Value {
        object(vec![
            ("account", dec(self.account.raw())),
            ("handle", Value::from(self.handle.0.as_str())),
            ("verified", Value::Bool(self.verified)),
        ])
    }
}

impl ToJson for TenantAdmins {
    fn to_json(&self) -> Value {
        object(vec![("admins", array(&self.admins))])
    }
}

/// The identity verification state of the caller (I-86). It carries the
/// state only, and no other vault fact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VerificationStatus {
    /// Not verified, and no verification is under way.
    Unverified,
    /// A verification was begun and the vault has not confirmed it.
    Pending,
    /// The vault answered `IsVerified` for the caller.
    Verified,
}

impl VerificationStatus {
    /// The status as JSON spells it.
    pub const fn as_str(self) -> &'static str {
        match self {
            VerificationStatus::Unverified => "unverified",
            VerificationStatus::Pending => "pending",
            VerificationStatus::Verified => "verified",
        }
    }

    /// The status from the vault's `IsVerified` answer for the caller and
    /// whether the caller began a verification. A verified answer wins.
    pub const fn of(verified: bool, begun: bool) -> VerificationStatus {
        match (verified, begun) {
            (true, _) => VerificationStatus::Verified,
            (false, true) => VerificationStatus::Pending,
            (false, false) => VerificationStatus::Unverified,
        }
    }
}

/// `me.get_verification`: `{status}` and nothing else (I-86).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerificationState {
    /// The state.
    pub status: VerificationStatus,
}

impl ToJson for VerificationState {
    fn to_json(&self) -> Value {
        object(vec![("status", Value::from(self.status.as_str()))])
    }
}

/// One programme of the tenant, as the clone choice lists it (R-PG-02).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProgrammeRow {
    /// The programme.
    pub programme: ProgrammeId,
    /// Its name, from creator step 2.
    pub name: String,
}

/// `creator.list_programmes`: the clone sources, in programme order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProgrammeList {
    programmes: Vec<ProgrammeRow>,
}

impl ProgrammeList {
    /// The list of `rows`, in programme order, each programme once.
    pub fn new(rows: impl IntoIterator<Item = ProgrammeRow>) -> ProgrammeList {
        let mut seen = BTreeSet::new();
        let mut programmes: Vec<ProgrammeRow> = rows
            .into_iter()
            .filter(|r| seen.insert(r.programme))
            .collect();
        programmes.sort_by_key(|r| r.programme);
        ProgrammeList { programmes }
    }

    /// The rows.
    pub fn programmes(&self) -> &[ProgrammeRow] {
        &self.programmes
    }
}

impl ToJson for ProgrammeRow {
    fn to_json(&self) -> Value {
        object(vec![
            ("id", dec(self.programme.raw())),
            ("name", Value::from(self.name.as_str())),
        ])
    }
}

impl ToJson for ProgrammeList {
    fn to_json(&self) -> Value {
        object(vec![("programmes", array(&self.programmes))])
    }
}

/// One template of the catalogue (R-PG-02, R-PG-05): a shipped template
/// or one private to the tenant. It never holds people or programme
/// history.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TemplateRow {
    /// The template id.
    pub template: fstp_creator::TemplateId,
    /// Its version, from 1.
    pub version: NonZeroU32,
    /// Its display name.
    pub name: String,
}

/// `creator.list_templates`: the catalogue, in template and version
/// order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TemplateList {
    templates: Vec<TemplateRow>,
}

impl TemplateList {
    /// The list of `rows`, in template and version order, each pair once.
    pub fn new(rows: impl IntoIterator<Item = TemplateRow>) -> TemplateList {
        let mut seen = BTreeSet::new();
        let mut templates: Vec<TemplateRow> = rows
            .into_iter()
            .filter(|r| seen.insert((r.template, r.version)))
            .collect();
        templates.sort_by_key(|r| (r.template, r.version));
        TemplateList { templates }
    }

    /// The rows.
    pub fn templates(&self) -> &[TemplateRow] {
        &self.templates
    }
}

impl ToJson for TemplateRow {
    fn to_json(&self) -> Value {
        object(vec![
            ("id", dec(self.template.raw())),
            ("version", Value::from(self.version.get())),
            ("name", Value::from(self.name.as_str())),
        ])
    }
}

impl ToJson for TemplateList {
    fn to_json(&self) -> Value {
        object(vec![("templates", array(&self.templates))])
    }
}

/// How far an invitation has come (J2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum InvitationState {
    /// Sent and not yet accepted.
    Invited,
    /// Accepted with its confidentiality terms.
    Accepted,
    /// The invitee verified identity for SoD-09.
    Verified,
    /// The role was granted.
    Granted,
}

impl InvitationState {
    /// The state as JSON spells it.
    pub const fn as_str(self) -> &'static str {
        match self {
            InvitationState::Invited => "invited",
            InvitationState::Accepted => "accepted",
            InvitationState::Verified => "verified",
            InvitationState::Granted => "granted",
        }
    }
}

/// The wire name of a role an invitation of creator step 9 names, or
/// `None` for a role no invitation names. These are the roles
/// `fstp_access::invitable` admits, the finance roles among them.
pub const fn invited_role(role: Role) -> Option<&'static str> {
    if fstp_access::invitable(role) {
        Some(fstp_access::role_wire_name(role))
    } else {
        None
    }
}

/// `people.get_invitation`: the invitation landing (SoD-09, J2). It holds
/// the invited role, the version of the confidentiality terms the
/// acceptance names, the programme's P-75 and P-77 choices for the terms
/// of a Judging role, and the state. It names no account, no inviter and
/// no contact address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvitationLanding {
    role: Role,
    terms_version: NonZeroU32,
    p75: Option<bool>,
    p77: Option<McpBindingActions>,
    state: InvitationState,
}

impl InvitationLanding {
    /// The landing of an invitation to `role`, or `None` for a role no
    /// invitation names. `p75` and `p77` are `None` while the programme
    /// has not made the choice. The page then offers no acceptance.
    ///
    /// Only the terms of a Judging role state the P-75 and P-77 choices
    /// (design section 2.2 J2). For any other role both are dropped, so
    /// the landing sends `null` for them.
    pub const fn new(
        role: Role,
        terms_version: NonZeroU32,
        p75: Option<bool>,
        p77: Option<McpBindingActions>,
        state: InvitationState,
    ) -> Option<InvitationLanding> {
        if invited_role(role).is_none() {
            return None;
        }
        let judging = matches!(role.group(), Group::Judging);
        Some(InvitationLanding {
            role,
            terms_version,
            p75: if judging { p75 } else { None },
            p77: if judging { p77 } else { None },
            state,
        })
    }

    /// The invited role.
    pub const fn role(&self) -> Role {
        self.role
    }

    /// The state.
    pub const fn state(&self) -> InvitationState {
        self.state
    }
}

impl ToJson for InvitationLanding {
    fn to_json(&self) -> Value {
        let p75 = self.p75.map_or(Value::Null, Value::Bool);
        let p77 = match self.p77 {
            Some(McpBindingActions::DraftOnly) => Value::from("draft_only"),
            Some(McpBindingActions::Allowed) => Value::from("allowed"),
            None => Value::Null,
        };
        object(vec![
            (
                "role",
                Value::from(invited_role(self.role).unwrap_or_default()),
            ),
            ("terms_version", Value::from(self.terms_version.get())),
            ("p75", p75),
            ("p77", p77),
            ("state", Value::from(self.state.as_str())),
        ])
    }
}

/// `committee.open_round`: the cut-off round the server drew (R-EV-08,
/// change D5). The ballot, the delegation and the round read address it.
/// It names no voter and no proposal. Dispatch serves it as
/// [`ReadModel::RoundOpened`], with the id the form drew.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoundOpened {
    /// The round, the decision id of its cut-off.
    pub round: DecisionId,
}

impl ToJson for RoundOpened {
    fn to_json(&self) -> Value {
        object(vec![("round", dec(self.round.raw()))])
    }
}

/// One proposal of a round's order, with its state now (NOTE 6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoundRow {
    /// The proposal, by id only (I-17).
    pub proposal: ProposalId,
    /// Its state.
    pub state: StateTag,
}

/// The status of a cut-off round (change D5). Only an open round takes
/// ballots, delegations and the record of its cut-off.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RoundStatus {
    /// Members cast and delegate, and a member may record the cut-off.
    Open,
    /// The cut-off was recorded.
    Recorded,
    /// A later round of the call replaced it. Nothing acts in it.
    Superseded,
}

impl RoundStatus {
    /// The status as JSON spells it.
    pub const fn as_str(self) -> &'static str {
        match self {
            RoundStatus::Open => "open",
            RoundStatus::Recorded => "recorded",
            RoundStatus::Superseded => "superseded",
        }
    }
}

/// The viewer's own part in a round (R-EV-09, P-16 NOTE 8). It names no
/// other member's vote.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoundViewer {
    /// Whether a conflict on a RANKED proposal of the call recuses the
    /// viewer from the vote (Conflict declarations). It is judged while
    /// the round is open only, and is `None` on any other round, since
    /// nothing acts there.
    pub recused: Option<bool>,
    /// The viewer's own ballot, if cast.
    pub own_vote: Option<fstp_domain::decision::Vote>,
    /// The member the viewer delegated to, if any.
    pub delegated_to: Option<AccountId>,
}

/// `committee.round`: one cut-off round (R-EV-08, R-EV-09, change D5).
/// It counts the ballots and names no voter. The delegates are the
/// members the viewer may delegate to, by label only, none recused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoundView {
    /// The round.
    pub round: DecisionId,
    /// Its call.
    pub call: CallId,
    /// Open, recorded or superseded.
    pub status: RoundStatus,
    /// The order it was opened with, top first.
    pub order: Vec<RoundRow>,
    /// The cut-off rank position.
    pub nominated: u32,
    /// The recorded rationale (R-EV-08).
    pub rationale: String,
    /// The recorded P-17 tie-break, if any.
    pub tie_break: Option<String>,
    /// How many ballots were cast in the round.
    pub ballots_cast: u32,
    /// The viewer's own part.
    pub viewer: RoundViewer,
    /// The members the viewer may delegate to.
    pub delegates: Vec<CandidateRow>,
}

/// A vote as the domain spells it.
const fn vote_name(v: fstp_domain::decision::Vote) -> &'static str {
    match v {
        fstp_domain::decision::Vote::For => "For",
        fstp_domain::decision::Vote::Against => "Against",
        fstp_domain::decision::Vote::Abstain => "Abstain",
    }
}

impl ToJson for RoundView {
    fn to_json(&self) -> Value {
        let order: Vec<Value> = self
            .order
            .iter()
            .map(|r| {
                object(vec![
                    ("proposal", dec(r.proposal.raw())),
                    ("state", Value::from(r.state.spec_name())),
                ])
            })
            .collect();
        let viewer = object(vec![
            (
                "recused",
                self.viewer.recused.map_or(Value::Null, Value::Bool),
            ),
            (
                "own_vote",
                self.viewer
                    .own_vote
                    .map_or(Value::Null, |v| Value::from(vote_name(v))),
            ),
            (
                "delegated_to",
                self.viewer
                    .delegated_to
                    .map_or(Value::Null, |a| dec(a.raw())),
            ),
        ]);
        object(vec![
            ("round", dec(self.round.raw())),
            ("call", dec(self.call.raw())),
            ("status", Value::from(self.status.as_str())),
            ("order", Value::Array(order.into_iter().collect())),
            ("nominated", Value::from(self.nominated)),
            ("rationale", Value::from(self.rationale.as_str())),
            (
                "tie_break",
                self.tie_break.as_deref().map_or(Value::Null, Value::from),
            ),
            ("ballots_cast", Value::from(self.ballots_cast)),
            ("viewer", viewer),
            ("delegates", array(&self.delegates)),
        ])
    }
}

/// One active or awaiting reviewer assignment of a proposal, as the
/// projection holds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BoardAssignee {
    /// The assignment.
    pub assignment: AssignmentId,
    /// The assignee, whose label the cell resolves.
    pub reviewer: AccountId,
    /// The handle under P-11 anonymous.
    pub handle: Option<Handle>,
    /// Whether the assignee still has to declare (R-CF-02).
    pub awaiting_declaration: bool,
}

/// What the projection says about one proposal's assignments, before the
/// cell resolves labels and the SoD-10 and SoD-11 checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssignmentBoard {
    /// The proposal's state.
    pub state: StateTag,
    /// Its unreleased reviewer assignments made in [`board_call`], in
    /// assignment order. Those of an earlier call stay out, as the
    /// domain's I-34 count leaves them out (NOTE 8).
    pub assigned: Vec<BoardAssignee>,
    /// The committee members of its programme the coordinator may assign,
    /// in account order. Each holds an active committee member binding at
    /// the instant. None holds an unreleased reviewer assignment of
    /// `assigned` or a recorded conflict fact on the proposal. The domain guards run again
    /// at the assignment.
    pub candidates: Vec<AccountId>,
}

/// The assignment board of `proposal` at `now` (R-AC-01, J5), or `None`
/// for a proposal the projection does not hold.
pub(crate) fn assignment_board(
    state: &fstp_engine::EngineState,
    proposal: ProposalId,
    now: Timestamp,
) -> Option<AssignmentBoard> {
    let core = &state.core;
    let tag = fstp_domain::view::proposal_state(core, proposal)?;
    let current = board_call(state, proposal);
    let mut assigned: Vec<BoardAssignee> = core
        .review()
        .assignments()
        .filter(|(_, a)| {
            a.proposal == proposal
                && Some(a.call) == current
                && a.kind == AssignmentKind::Reviewer
                && a.unreleased()
        })
        .map(|(id, a)| BoardAssignee {
            assignment: id,
            reviewer: a.reviewer,
            handle: a.handle,
            awaiting_declaration: a.status == AssignmentStatus::AwaitingDeclaration,
        })
        .collect();
    assigned.sort_by_key(|a| a.assignment);
    let taken: BTreeSet<AccountId> = assigned.iter().map(|a| a.reviewer).collect();
    let programme = crate::forms::call_of_proposal(state, proposal)
        .and_then(|c| crate::forms::programme_of_call(state, c));
    let candidates: BTreeSet<AccountId> = match programme {
        Some(programme) => core
            .roster()
            .bindings()
            .map(|(_, b)| b)
            .filter(|b| {
                b.role == Role::CommitteeMember
                    && b.programme == programme
                    && b.scope == BindingScope::Programme
                    && b.group() != Group::Receiving
                    && b.active_at(now)
            })
            .map(|b| b.account)
            .filter(|a| !taken.contains(a) && !core.review().conflict_fact(*a, proposal))
            .collect(),
        None => BTreeSet::new(),
    };
    Some(AssignmentBoard {
        state: tag,
        assigned,
        candidates: candidates.into_iter().collect(),
    })
}

/// The call whose assignments the board of `proposal` counts: the call
/// the proposal is evaluated in, as far as the public state shows it.
///
/// The domain counts I-34 over the assignments of the proposal's current
/// call only (NOTE 8). That is its creation call, or the call of its
/// latest re-entry. A re-entry rebinds no team, so the Receiving bindings
/// still name the creation call. The domain makes each assignment in the
/// current call of its time, and that call only moves forward. So the
/// latest call by sequence among the creation call and the calls of the
/// proposal's assignments is the current call once one assignment of it
/// exists.
///
/// Interim, pending a public domain read of the current call (lane W1b):
/// after a re-entry and before the first assignment in the new call, this
/// still names the earlier call. The domain runs I-34 again at every
/// assignment and admission, so the board check never admits anything.
pub(crate) fn board_call(state: &fstp_engine::EngineState, proposal: ProposalId) -> Option<CallId> {
    let calls = state.core.calls();
    let created = crate::forms::call_of_proposal(state, proposal);
    let assigned = state
        .core
        .review()
        .assignments()
        .filter(|(_, a)| a.proposal == proposal)
        .map(|(_, a)| a.call);
    created
        .into_iter()
        .chain(assigned)
        .max_by_key(|c| (calls.get(*c).and_then(|v| v.seq()), *c))
}

/// One assignee of the assignment view, by label only (I-17, R-CF-03).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssignedRow {
    /// The assignment.
    pub assignment: AssignmentId,
    /// The label the programme gives the assignee: the P-11 handle, or
    /// the pseudonymous display handle. Never an email.
    pub label: String,
}

/// One candidate of the assignment view, by label only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidateRow {
    /// The committee member's account.
    pub account: AccountId,
    /// The label the programme gives the member. Never an email.
    pub label: String,
}

/// The SoD-10 (P-39 organisations) and SoD-11 (P-38 proximity) checks
/// over the current assignees, as pass or fail only, with no reason and
/// no account (R-CF-03).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AssignmentChecks {
    /// Whether the assignees span at least P-39 organisations.
    pub p39: bool,
    /// Whether no assignee's organisation lists a team member's
    /// declared affiliation under P-38.
    pub proximity: bool,
}

/// `review.assignments`: one proposal's assignment view for the FSTP
/// coordinator (R-AC-01, J5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssignmentView {
    state: StateTag,
    assigned: Vec<AssignedRow>,
    candidates: Vec<CandidateRow>,
    checks: AssignmentChecks,
}

impl AssignmentView {
    /// The view of a proposal in `state`. Rows keep the order given.
    pub fn new(
        state: StateTag,
        assigned: Vec<AssignedRow>,
        candidates: Vec<CandidateRow>,
        checks: AssignmentChecks,
    ) -> AssignmentView {
        AssignmentView {
            state,
            assigned,
            candidates,
            checks,
        }
    }

    /// The state.
    pub const fn state(&self) -> StateTag {
        self.state
    }
}

const fn outcome(pass: bool) -> &'static str {
    if pass { "pass" } else { "fail" }
}

impl ToJson for AssignedRow {
    fn to_json(&self) -> Value {
        object(vec![
            ("assignment", dec(self.assignment.raw())),
            ("label", Value::from(self.label.as_str())),
        ])
    }
}

impl ToJson for CandidateRow {
    fn to_json(&self) -> Value {
        object(vec![
            ("account", dec(self.account.raw())),
            ("label", Value::from(self.label.as_str())),
        ])
    }
}

impl ToJson for AssignmentView {
    fn to_json(&self) -> Value {
        let checks = object(vec![
            ("p39", Value::from(outcome(self.checks.p39))),
            ("proximity", Value::from(outcome(self.checks.proximity))),
        ]);
        object(vec![
            ("state", Value::from(self.state.spec_name())),
            ("assigned", array(&self.assigned)),
            ("candidates", array(&self.candidates)),
            ("checks", checks),
        ])
    }
}

#[cfg(test)]
pub(crate) mod reply_shape_tests {
    //! Each read model encodes to the reply shape `fstp_access::REPLIES`
    //! names for its operation, so the generated `SCHEMAS` and
    //! `VALIDATORS` of `web/src/gen/api.ts` describe what the server
    //! sends (TH-26, ADR-006, ADR-014). Written by lane m4reg.

    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use fstp_access::{Shape, reply};

    use super::*;
    use crate::ActionDigest;
    use crate::pending::{PendingStatus, PendingView};
    use crate::port::{AgentClientId, PendingId};

    /// Whether `v` fits `s`, with the server's own spellings: an id is a
    /// canonical decimal string, an int a JSON integer lexeme and an
    /// amount an ADR-006 EUR string. Objects are closed.
    fn fits(s: &Shape, v: &Value) -> bool {
        match (s, v) {
            (Shape::String, Value::String(_)) | (Shape::Bool, Value::Bool(_)) => true,
            (Shape::Null, Value::Null) => true,
            (Shape::Id, Value::String(t)) => crate::forms::canonical_id(t).is_some(),
            (Shape::Amount, Value::String(t)) => {
                fstp_money::Amount::parse(t, fstp_money::Currency::Eur).is_ok()
            }
            (Shape::Int, Value::Number(n)) => {
                let t = n.as_str();
                crate::forms::canonical_id(t).is_some() && t.len() <= 15
            }
            (Shape::Enum(values), Value::String(t)) => values.contains(&t.as_str()),
            (Shape::Array(items), Value::Array(a)) => a.into_iter().all(|x| fits(items, x)),
            (Shape::Nullable(_), Value::Null) => true,
            (Shape::Nullable(inner), other) => fits(inner, other),
            (Shape::Object(members), Value::Object(o)) => {
                o.keys().all(|k| members.iter().any(|m| m.name == k))
                    && members.iter().all(|m| match o.get(m.name) {
                        Some(x) => fits(&m.shape, x),
                        None => m.optional,
                    })
            }
            _ => false,
        }
    }

    fn shape_of(op: &str) -> &'static Shape {
        reply(op).unwrap_or_else(|| panic!("REPLIES has no {op}"))
    }

    /// Asserts that `v` encodes to the reply shape of `op`.
    pub(crate) fn assert_fits(op: &str, v: &impl ToJson) {
        let json = v.to_json();
        let text = fstp_json::to_canonical(&json).unwrap_or_default();
        assert!(fits(shape_of(op), &json), "{op} does not fit: {text}");
    }

    fn call() -> CallSummary {
        CallSummary {
            call: CallId::from_raw(7),
            programme: ProgrammeId::from_raw(1),
            status: "published",
            opens: Timestamp::from_micros(1),
            deadline: Timestamp::from_micros(2),
            deadline_zone: "Europe/Brussels".to_owned(),
            budget: "400000.00".to_owned(),
            currency: "EUR",
            open: true,
            title: Some("Synthetic call".to_owned()),
            grant_range: Some(("1000.00".to_owned(), "60000.00".to_owned())),
            recipient_max: Some("60000.00".to_owned()),
        }
    }

    /// A call the text store and the policy know nothing more of: no
    /// title, no frozen P-04 and no P-05.
    fn bare_call() -> CallSummary {
        CallSummary {
            title: None,
            grant_range: None,
            recipient_max: None,
            ..call()
        }
    }

    fn pending() -> PendingView {
        PendingView {
            id: PendingId::from_raw(3),
            agent: AgentClientId::from_raw(4),
            op: "call.publish".to_owned(),
            request: "{}".to_owned(),
            digest: ActionDigest([7; 32]),
            created: Timestamp::from_micros(10),
            expires: Timestamp::from_micros(20),
            status: PendingStatus::Open,
        }
    }

    fn own(title: Option<&str>) -> ProposalSummary {
        ProposalSummary {
            proposal: ProposalId::from_raw(11),
            call: CallId::from_raw(7),
            state: "SUBMITTED".to_owned(),
            role: "lead",
            title: title.map(str::to_owned),
        }
    }

    fn assignment(kind: &'static str) -> AssignmentSummary {
        AssignmentSummary {
            assignment: AssignmentId::from_raw(5),
            proposal: ProposalId::from_raw(11),
            call: CallId::from_raw(7),
            kind,
            awaiting_declaration: true,
            active: false,
            stage2: false,
        }
    }

    fn row(state: &'static str) -> crate::views::ProposalRow {
        crate::views::ProposalRow {
            proposal: 1001,
            state,
            title: "Synthetic open sensor kit".to_owned(),
        }
    }

    fn content(outcome: Option<&'static str>) -> crate::views::ContentView {
        crate::views::ContentView {
            proposal: 1001,
            call: 1,
            state: "IRC_REVIEW",
            title: "Synthetic open sensor kit".to_owned(),
            text: "A synthetic narrative.".to_owned(),
            outcome,
        }
    }

    fn sheet(current: Option<(u128, Vec<u8>)>) -> crate::views::ScoreSheet {
        crate::views::ScoreSheet {
            stage: "One",
            plan: 3,
            criteria: vec![crate::views::SheetCriterion {
                id: 1,
                text: "Criterion 1".to_owned(),
                max: 5,
            }],
            current,
        }
    }

    fn ranked() -> crate::views::RankingRow {
        crate::views::RankingRow::Ranked {
            proposal: 1001,
            title: Some("Synthetic open sensor kit".to_owned()),
            neutral_summary: Some("A synthetic summary.".to_owned()),
            rationale: Some("A synthetic rationale.".to_owned()),
            effective: "100.00".to_owned(),
            criterion_scores: vec![crate::views::CriterionScore {
                criterion: 1,
                weighted: "4.50".to_owned(),
            }],
            requested: "1500.50".to_owned(),
            remaining_budget: "398499.50".to_owned(),
        }
    }

    /// A ranked row of an over-nominated call, whose remaining budget is
    /// spelled as dispatch writes it: `Amount`'s display, with a minus.
    fn over_nominated() -> crate::views::RankingRow {
        let budget = fstp_money::Amount::from_minor(100_000, fstp_money::Currency::Eur).unwrap();
        let committed = fstp_money::Amount::from_minor(150_000, fstp_money::Currency::Eur).unwrap();
        let remaining = budget.checked_sub(committed).unwrap();
        let mut row = ranked();
        if let crate::views::RankingRow::Ranked {
            remaining_budget, ..
        } = &mut row
        {
            *remaining_budget = remaining.to_string();
        }
        row
    }

    fn thread() -> crate::views::Stage2Thread {
        crate::views::Stage2Thread {
            state: "STAGE2",
            open: true,
            own_no_questions: false,
            entries: vec![
                crate::views::ThreadItem {
                    kind: "question",
                    author: Some("R-0a1b2c3d".to_owned()),
                    text: "Why this milestone?".to_owned(),
                    day: "2026-10-30".to_owned(),
                },
                crate::views::ThreadItem {
                    kind: "answer",
                    author: None,
                    text: "Because of the pilot.".to_owned(),
                    day: "2026-10-30".to_owned(),
                },
            ],
        }
    }

    fn assignment_view() -> AssignmentView {
        AssignmentView::new(
            StateTag::Submitted,
            vec![AssignedRow {
                assignment: AssignmentId::from_raw(5),
                label: "Committee member R1".to_owned(),
            }],
            vec![CandidateRow {
                account: AccountId::from_raw(8),
                label: "Committee member R2".to_owned(),
            }],
            AssignmentChecks {
                p39: false,
                proximity: true,
            },
        )
    }

    /// A round with `status`. An open round has the viewer's ballot
    /// still to cast, one delegate and a recusal answer. A recorded one
    /// has the viewer's vote and a tie-break. A round that is not open
    /// has no recusal answer.
    fn round_view(status: RoundStatus) -> RoundView {
        let recorded = status == RoundStatus::Recorded;
        let open = status == RoundStatus::Open;
        RoundView {
            round: DecisionId::from_raw(9),
            call: CallId::from_raw(1),
            status,
            order: vec![
                RoundRow {
                    proposal: ProposalId::from_raw(1001),
                    state: if recorded {
                        StateTag::IrcReview
                    } else {
                        StateTag::Ranked
                    },
                },
                RoundRow {
                    proposal: ProposalId::from_raw(1003),
                    state: if recorded {
                        StateTag::NotSelected
                    } else {
                        StateTag::Ranked
                    },
                },
            ],
            nominated: 1,
            rationale: "Synthetic: within the remaining budget.".to_owned(),
            tie_break: recorded.then(|| "Synthetic P-17 tie-break.".to_owned()),
            ballots_cast: if recorded { 4 } else { 0 },
            viewer: RoundViewer {
                recused: open.then_some(false),
                own_vote: recorded.then_some(fstp_domain::decision::Vote::For),
                delegated_to: None,
            },
            delegates: if !open {
                Vec::new()
            } else {
                vec![CandidateRow {
                    account: AccountId::from_raw(203),
                    label: "Committee member R2".to_owned(),
                }]
            },
        }
    }

    /// A report with a failure that names both cap values and an
    /// acknowledged warning (R-PG-01 AC, I-66).
    fn creator_report() -> crate::creator::CreatorModel {
        use fstp_creator::{CheckDetail, CheckId, CheckResult, CheckSubject, Severity};
        let p = ProgrammeId::from_raw(7);
        let cap = CheckResult {
            check: CheckId::CapAboveCeiling,
            severity: Severity::Failure,
            subject: CheckSubject::Draft,
            detail: CheckDetail::Cap {
                p05: "450000.00".to_owned(),
                p58: "400000.00".to_owned(),
            },
        };
        let roster = CheckResult {
            check: CheckId::RosterShort,
            severity: Severity::Warning,
            subject: CheckSubject::Draft,
            detail: CheckDetail::None,
        };
        let results = [(cap, false), (roster, true)]
            .iter()
            .map(|(r, ack)| crate::creator::report_row(p, r, *ack).unwrap())
            .collect();
        crate::creator::CreatorModel::Report {
            revision: fstp_creator::DraftRevision::new(4, fstp_ledger::Seq::from_raw(20)),
            results,
        }
    }

    /// An invitation row, refused by `rule` if one is given.
    fn invitation(rule: Option<&'static str>) -> crate::creator::InvitationRow {
        crate::creator::InvitationRow {
            id: fstp_creator::InvitationId::from_raw(12),
            email: "m2@e2e.invalid".to_owned(),
            role: "programme_manager",
            state: if rule.is_some() {
                "verified"
            } else {
                "invited"
            },
            sod: if rule.is_some() { "fail" } else { "unchecked" },
            rule,
        }
    }

    /// The operations whose reply the creator model `c` is.
    fn creator_served_as(c: &crate::creator::CreatorModel) -> &'static [&'static str] {
        use crate::creator::CreatorModel as C;
        match c {
            C::Opened { .. } => &["creator.open_draft"],
            C::Report { .. } => &["creator.get_report"],
            C::Invitations(_) => &["creator.invitations"],
            C::Programmes(_) => &["creator.list_programmes"],
            C::Templates(_) => &["creator.list_templates"],
            C::Approvals(_) => &["admin.approvals"],
            C::Impact(_) => &["creator.impact"],
            // Unshaped, see [`unshaped`].
            C::Draft { .. } | C::Proposals(_) | C::Preview { .. } => &[],
        }
    }

    /// The read models that carry an arbitrary JSON value, which no
    /// `fstp_access::Shape` kind states: the draft's spec and a proposed
    /// import value (lane m4wire). Their members are checked by the
    /// tests of `creator.rs` and the readers of
    /// `web/src/creator/model.ts`.
    fn unshaped(m: &ReadModel) -> bool {
        matches!(
            m,
            ReadModel::Creator(
                crate::creator::CreatorModel::Draft { .. }
                    | crate::creator::CreatorModel::Proposals(_)
                    | crate::creator::CreatorModel::Preview { .. }
            ) | ReadModel::Public(_)
        )
    }

    /// The operations whose reply `m` is, by name. The match has no
    /// wildcard, so a new read model fails to compile here until it names
    /// its operation and so its shape.
    fn served_as(m: &ReadModel) -> &'static [&'static str] {
        match m {
            // A command's `{"accepted": true}`: no data, and no entry.
            ReadModel::Accepted => &[],
            ReadModel::Created(_) => &["proposal.create"],
            ReadModel::PendingActions(_) => &["pending.list"],
            ReadModel::OpenCalls(_) => &["calls.list_open"],
            ReadModel::Call(_) => &["calls.get"],
            ReadModel::OwnProposals(_) => &["proposal.list_own"],
            ReadModel::Assignments(_) => &["me.assignments", "me.irc_cases"],
            ReadModel::Sessions(_) => &["me.sessions"],
            ReadModel::Redirect(_) => &["me.begin_verification"],
            ReadModel::IntakeQueue(_) => &["intake.queue"],
            ReadModel::Board(_) => &["call.board"],
            ReadModel::DeclarationView(_) => &["review.declaration_view"],
            ReadModel::Content(v) if v.outcome.is_some() => &["irc.case"],
            ReadModel::Content(_) => &["review.read_content"],
            ReadModel::ScoreSheet(_) => &["review.score_sheet"],
            ReadModel::Stage2Thread(_) => &["review.stage2_thread"],
            ReadModel::Ranking(_) => &["committee.ranking"],
            ReadModel::Notifiable(_) => &["review.notifiable_conflicts"],
            ReadModel::Workspace(_) => &["proposal.get_workspace"],
            ReadModel::PlanSaved { .. } => &["proposal.record_plan"],
            ReadModel::OwnProposal(_) => &["proposal.view"],
            ReadModel::Stage2Questions(_) => &["stage2.view"],
            ReadModel::Notices(_) => &["me.notices"],
            ReadModel::Negotiation { .. } => &["negotiation.view"],
            ReadModel::RoundOpened(_) => &["committee.open_round"],
            ReadModel::AssignmentView(_) => &["review.assignments"],
            ReadModel::Verification(_) => &["me.get_verification"],
            ReadModel::Round(_) => &["committee.round"],
            ReadModel::Tenant(crate::tenant::TenantView::Step(_)) => {
                &["tenant.get_step", "tenant.save_step"]
            }
            ReadModel::Tenant(crate::tenant::TenantView::Settings(_)) => &["tenant.settings"],
            ReadModel::Tenant(crate::tenant::TenantView::Admins(_)) => &["tenant.list_admins"],
            ReadModel::Tenant(crate::tenant::TenantView::Signatories(_)) => {
                &["tenant.list_signatories"]
            }
            ReadModel::Tenant(crate::tenant::TenantView::Activation(_)) => {
                &["tenant.get_activation"]
            }
            ReadModel::Creator(c) => creator_served_as(c),
            ReadModel::MyRoles(_) => &["me.roles"],
            ReadModel::Journey(_) => &["proposal.journey"],
            ReadModel::Diary(_) => &["proposal.diary"],
            // Unshaped, see [`unshaped`]: `fstp-public` pins its shapes.
            ReadModel::Guide(_) => &["calls.guide"],
            ReadModel::Public(_) => &[],
        }
    }

    /// A `proposal.journey` reply (lane j2): with two legs and the overlay
    /// when `full`, else a draft with no leg and no overlay.
    fn journey_view(full: bool) -> crate::dispatch::journey::JourneyView {
        use fstp_domain::StateTag;
        use fstp_journey::overlay::{IrcConcern, Overlay};
        use fstp_journey::projector::{LegRow, Position};
        let p = ProposalId::from_raw(1001);
        let leg = |ord: u32, from, to| LegRow {
            proposal: p,
            ord,
            from,
            to,
            at: 5,
            source_seq: 9,
        };
        crate::dispatch::journey::JourneyView {
            proposal: p,
            position: Position {
                node: if full {
                    StateTag::Stage1
                } else {
                    StateTag::Draft
                },
                since: 5,
                source_seq: 9,
            },
            legs: if full {
                vec![
                    leg(0, StateTag::Draft, StateTag::Submitted),
                    leg(1, StateTag::Submitted, StateTag::Stage1),
                ]
            } else {
                Vec::new()
            },
            strip: full,
            overlay: full.then(|| Overlay {
                policy: fstp_domain::id::PolicyVersionId::from_raw(3),
                stage2_window: fstp_domain::time::Days::new(14),
                anonymity: fstp_domain::policy::ReviewerAnonymity::Anonymous,
                irc_concern: IrcConcern::Deferred,
                agent_actions: fstp_domain::policy::McpBindingActions::DraftOnly,
                wording: [
                    fstp_domain::rules::ParamId::P08,
                    fstp_domain::rules::ParamId::P20,
                ]
                .into_iter()
                .collect(),
            }),
        }
    }

    /// A `proposal.diary` reply (lane j2): one entry with every optional
    /// member, every parameter kind and both text slots when `full`, else
    /// no entry.
    fn diary_view(full: bool) -> crate::dispatch::journey::DiaryView {
        use fstp_domain::StateTag;
        use fstp_domain::id::{ContentDigest, TextId, TextRef};
        use fstp_journey::diary::{DiaryItem, Erasure, Param, TextSlot};
        use fstp_journey::projector::Subject;
        use fstp_journey::visibility::EntryKind;
        let p = ProposalId::from_raw(1001);
        let item = DiaryItem {
            entry_id: [7; 16],
            source_seq: 12,
            subject: Subject::Proposal(p),
            kind: EntryKind::ReviewerScore,
            summary_key: 7,
            occurred_at: 5,
            deadline_zone: Some(2),
            params: vec![
                Param::State(StateTag::Granted),
                Param::Amount("1500.50".to_owned()),
                Param::Sequence(12),
                Param::Score(fstp_domain::scoring::ScoreVector(vec![3, 5])),
                Param::Outcome(true),
                Param::Time(5),
            ],
            texts: vec![
                TextSlot::Live(TextRef::new(
                    TextId::from_raw(4),
                    ContentDigest::from_bytes([1; 32]),
                )),
                TextSlot::Erased(Erasure { on: 6, cause: 2 }),
            ],
        };
        crate::dispatch::journey::DiaryView {
            proposal: p,
            entries: if full {
                vec![crate::dispatch::journey::DiaryEntry {
                    item,
                    supersedes: Some([8; 16]),
                }]
            } else {
                Vec::new()
            },
        }
    }

    /// A `me.roles` reply (design section 15.0, I-86): with every
    /// optional member set when `full`, else a caller with no role.
    fn my_roles(full: bool) -> crate::dispatch::me_roles::MyRoles {
        use crate::dispatch::me_roles::{CallItem, MyRoles, RoleItem, RoundItem};
        if !full {
            return MyRoles {
                tenant_admin: false,
                roles: Vec::new(),
                calls: Vec::new(),
                rounds: Vec::new(),
                drafts: Vec::new(),
            };
        }
        MyRoles {
            tenant_admin: true,
            roles: vec![
                RoleItem {
                    role: Role::CommitteeMember,
                    programme: ProgrammeId::from_raw(1),
                    proposal: None,
                    calls: vec![CallId::from_raw(1), CallId::from_raw(2)],
                },
                RoleItem {
                    role: Role::Guardian,
                    programme: ProgrammeId::from_raw(1),
                    proposal: Some(ProposalId::from_raw(1004)),
                    calls: vec![CallId::from_raw(1)],
                },
            ],
            calls: vec![
                CallItem {
                    call: CallId::from_raw(1),
                    title: Some("Synthetic open call".to_owned()),
                },
                CallItem {
                    call: CallId::from_raw(2),
                    title: None,
                },
            ],
            rounds: vec![RoundItem {
                round: DecisionId::from_raw(7),
                call: CallId::from_raw(1),
            }],
            drafts: vec![ProgrammeId::from_raw(1)],
        }
    }

    /// One read model of each variant, with every optional member set.
    fn one_of_each() -> Vec<ReadModel> {
        vec![
            ReadModel::Accepted,
            ReadModel::Created(vec![("proposal", 1001)]),
            ReadModel::PendingActions(vec![pending()]),
            ReadModel::OpenCalls(vec![call()]),
            ReadModel::Call(call()),
            ReadModel::OwnProposals(vec![own(Some("Synthetic proposal"))]),
            ReadModel::Assignments(vec![assignment("reviewer")]),
            ReadModel::Sessions(vec![SessionSummary {
                session: SessionId::from_raw(9),
                method: LoginMethod::MagicLink,
                started: Timestamp::from_micros(5),
            }]),
            ReadModel::Redirect("/vault/begin".to_owned()),
            ReadModel::IntakeQueue(crate::views::IntakeQueue {
                knock_out: vec![crate::views::KnockOutCriterion {
                    id: 1,
                    text: "Eligible country".to_owned(),
                }],
                proposals: vec![row("SUBMITTED")],
            }),
            ReadModel::Board(vec![row("STAGE1")]),
            ReadModel::DeclarationView(crate::views::DeclarationView {
                title: "Synthetic open sensor kit".to_owned(),
                neutral_summary: "A synthetic summary.".to_owned(),
            }),
            ReadModel::Content(content(None)),
            ReadModel::Content(content(Some("nominated"))),
            ReadModel::ScoreSheet(sheet(Some((3, vec![0, 5])))),
            ReadModel::Stage2Thread(thread()),
            ReadModel::Ranking(vec![
                ranked(),
                crate::views::RankingRow::Recused { proposal: 1003 },
            ]),
            ReadModel::Ranking(vec![over_nominated()]),
            ReadModel::Notifiable(vec![ProposalId::from_raw(1003)]),
            ReadModel::Workspace(crate::views::WorkspaceView {
                title: "Synthetic open sensor kit".to_owned(),
                summary: "A synthetic summary.".to_owned(),
                narrative: "A synthetic narrative.".to_owned(),
            }),
            ReadModel::PlanSaved {
                plan: 31,
                total: "1500.50".to_owned(),
            },
            ReadModel::OwnProposal(own(Some("Synthetic proposal"))),
            ReadModel::Stage2Questions(vec![crate::views::Question {
                handle: "R-0a1b2c3d".to_owned(),
                asked: "2026-10-30".to_owned(),
                text: "Why this milestone?".to_owned(),
            }]),
            ReadModel::Notices(vec![crate::views::Notice {
                kind: "IrcConcern",
                proposal: 1001,
                day: Some("2026-10-30".to_owned()),
            }]),
            ReadModel::Negotiation { acknowledged: true },
            ReadModel::RoundOpened(RoundOpened {
                round: DecisionId::from_raw(9),
            }),
            ReadModel::AssignmentView(assignment_view()),
            ReadModel::Verification(VerificationState {
                status: VerificationStatus::Pending,
            }),
            ReadModel::Round(round_view(RoundStatus::Open)),
            ReadModel::Round(round_view(RoundStatus::Recorded)),
            ReadModel::Round(round_view(RoundStatus::Superseded)),
            ReadModel::Tenant(crate::tenant::TenantView::Admins(TenantAdmins::new([
                AdminRow {
                    account: AccountId::from_raw(1),
                    handle: DisplayHandle("admin-1".to_owned()),
                    verified: true,
                },
            ]))),
            ReadModel::Creator(crate::creator::CreatorModel::Opened {
                programme: ProgrammeId::from_raw(7),
            }),
            ReadModel::Creator(creator_report()),
            ReadModel::Creator(crate::creator::CreatorModel::Invitations(vec![
                invitation(Some("SoD-09")),
                invitation(None),
            ])),
            ReadModel::Creator(crate::creator::CreatorModel::Programmes(vec![
                ProgrammeId::from_raw(1),
            ])),
            ReadModel::Creator(crate::creator::CreatorModel::Templates(vec![(
                1,
                1,
                "SuperSAFE".to_owned(),
            )])),
            ReadModel::Creator(crate::creator::CreatorModel::Approvals(vec![
                crate::creator::ApprovalRow {
                    programme: ProgrammeId::from_raw(7),
                    revision: fstp_creator::DraftRevision::new(4, fstp_ledger::Seq::from_raw(20)),
                    approvable: true,
                },
            ])),
            ReadModel::Creator(crate::creator::CreatorModel::Impact(vec![
                crate::creator::ImpactRow {
                    call: CallId::from_raw(1),
                },
            ])),
            ReadModel::Creator(crate::creator::CreatorModel::Draft {
                spec: Value::Object(Object::new()),
                revision: fstp_creator::DraftRevision::new(1, fstp_ledger::Seq::from_raw(3)),
                active: false,
                pending_narratives: std::collections::BTreeMap::new(),
                requested: false,
            }),
            ReadModel::Creator(crate::creator::CreatorModel::Proposals(Vec::new())),
            ReadModel::MyRoles(my_roles(true)),
            ReadModel::MyRoles(my_roles(false)),
            ReadModel::Journey(journey_view(true)),
            ReadModel::Journey(journey_view(false)),
            ReadModel::Diary(diary_view(true)),
            ReadModel::Diary(diary_view(false)),
            ReadModel::Creator(crate::creator::CreatorModel::Preview {
                kind: "public",
                blocks: vec![fstp_guide::PreviewBlock {
                    kind: fstp_guide::PreviewKind::Heading,
                    text: "SuperSAFE".to_owned(),
                }],
            }),
            ReadModel::Guide(StoredGuideView {
                call: CallId::from_raw(1),
                version: 1,
                digest: "00".repeat(32),
                html: "<!DOCTYPE html>".to_owned(),
            }),
            ReadModel::Public(PublicReply::Json(Value::Object(Object::new()))),
            ReadModel::Public(PublicReply::Page("<!DOCTYPE html>".to_owned())),
        ]
        .into_iter()
        .chain(crate::tenant::samples().into_iter().map(ReadModel::Tenant))
        .collect()
    }

    /// TH-26, ADR-006, ADR-014: every read model the API core serves fits
    /// the shape of each operation it answers, so no reply escapes the
    /// check. Every variant of [`ReadModel`] is sampled, and only the
    /// bare command acknowledgement names no operation.
    #[test]
    fn th26_served_read_models_fit_their_reply_shapes() {
        let samples = one_of_each();
        let mut named = std::collections::BTreeSet::new();
        for m in &samples {
            let ops = served_as(m);
            assert_eq!(
                ops.is_empty(),
                *m == ReadModel::Accepted || unshaped(m),
                "{m:?}"
            );
            for op in ops {
                assert_fits(op, m);
                named.insert(*op);
            }
        }
        // Every entry of REPLIES that a read model of this crate encodes
        // is reached above, or is one of the m4reg models tested below.
        let m4reg = [
            "tenant.list_admins",
            "creator.list_programmes",
            "creator.list_templates",
            "people.get_invitation",
        ];
        for (name, _) in fstp_access::REPLIES {
            assert!(
                named.contains(name) || m4reg.contains(name),
                "{name} has a shape but no read model sample"
            );
        }
    }

    /// I-86: only the web-only invitation list carries an email, and
    /// every operation it serves has no MCP tool. So no MCP response can
    /// hold an email, though `McpSafe` covers `ReadModel` as a whole.
    #[test]
    fn i86_no_tool_serves_an_email_bearing_read_model() {
        let mut bearing = 0usize;
        for m in &one_of_each() {
            let has_email = m.to_json().to_compact().contains('@');
            assert_eq!(m.carries_email(), has_email, "{m:?}");
            if !m.carries_email() {
                continue;
            }
            bearing += 1;
            let ops = served_as(m);
            assert!(!ops.is_empty(), "{m:?}");
            for op in ops {
                let spec = fstp_access::OPS
                    .iter()
                    .find(|s| s.name == *op)
                    .unwrap_or_else(|| panic!("{op} is not in the registry"));
                assert!(
                    spec.tool.is_none(),
                    "I-86: {op} serves an email and has an MCP tool"
                );
            }
        }
        assert_eq!(bearing, 1, "the invitation list is the one sample");
    }

    /// The number of [`ReadModel`] variants.
    const VARIANTS: usize = 34;

    /// The position of `m`'s variant in the declaration of [`ReadModel`].
    /// The match has no wildcard, so a new variant fails to compile here,
    /// and [`VARIANTS`] grows with it.
    fn variant(m: &ReadModel) -> usize {
        match m {
            ReadModel::Accepted => 0,
            ReadModel::Created(_) => 1,
            ReadModel::PendingActions(_) => 2,
            ReadModel::OpenCalls(_) => 3,
            ReadModel::Call(_) => 4,
            ReadModel::OwnProposals(_) => 5,
            ReadModel::Assignments(_) => 6,
            ReadModel::Sessions(_) => 7,
            ReadModel::Redirect(_) => 8,
            ReadModel::IntakeQueue(_) => 9,
            ReadModel::Board(_) => 10,
            ReadModel::DeclarationView(_) => 11,
            ReadModel::Content(_) => 12,
            ReadModel::ScoreSheet(_) => 13,
            ReadModel::Stage2Thread(_) => 14,
            ReadModel::Ranking(_) => 15,
            ReadModel::Notifiable(_) => 16,
            ReadModel::Workspace(_) => 17,
            ReadModel::PlanSaved { .. } => 18,
            ReadModel::OwnProposal(_) => 19,
            ReadModel::Stage2Questions(_) => 20,
            ReadModel::Notices(_) => 21,
            ReadModel::Negotiation { .. } => 22,
            ReadModel::RoundOpened(_) => 23,
            ReadModel::AssignmentView(_) => 24,
            ReadModel::Verification(_) => 25,
            ReadModel::Round(_) => 26,
            ReadModel::Tenant(_) => 27,
            ReadModel::Creator(_) => 28,
            ReadModel::MyRoles(_) => 29,
            ReadModel::Journey(_) => 30,
            ReadModel::Diary(_) => 31,
            ReadModel::Public(_) => 32,
            ReadModel::Guide(_) => 33,
        }
    }

    /// TH-26: the samples of [`one_of_each`] hold every variant of
    /// [`ReadModel`], so the shape check above reaches each one.
    #[test]
    fn th26_samples_cover_every_read_model_variant() {
        let seen: std::collections::BTreeSet<usize> = one_of_each().iter().map(variant).collect();
        let all: std::collections::BTreeSet<usize> = (0..VARIANTS).collect();
        assert_eq!(seen, all);
    }

    /// TH-26, ADR-006, R-PB-01: the open calls and one call fit their
    /// shape with the title, P-04 and P-05 present, and with each left
    /// out. The amounts are ADR-006 strings.
    #[test]
    fn th26_calls_fit_with_and_without_title_and_amounts() {
        for c in [call(), bare_call()] {
            assert_fits("calls.list_open", &ReadModel::OpenCalls(vec![c.clone()]));
            assert_fits("calls.get", &ReadModel::Call(c));
        }
        assert_fits("calls.list_open", &ReadModel::OpenCalls(Vec::new()));
        let text = fstp_json::to_canonical(&call().to_json()).unwrap();
        for member in [
            r#""grant_min":"1000.00""#,
            r#""grant_max":"60000.00""#,
            r#""recipient_max":"60000.00""#,
        ] {
            assert!(text.contains(member), "{member} in {text}");
        }
    }

    /// I-85, TH-26: the caller's pending actions fit their shape.
    #[test]
    fn i85_pending_actions_fit_their_shape() {
        assert_fits("pending.list", &ReadModel::PendingActions(vec![pending()]));
    }

    /// I-17, TH-26: the caller's own proposals and one of them fit their
    /// shape with and without a title, and name no person.
    #[test]
    fn i17_own_proposals_fit_with_and_without_a_title() {
        for title in [Some("Synthetic proposal"), None] {
            assert_fits(
                "proposal.list_own",
                &ReadModel::OwnProposals(vec![own(title)]),
            );
            assert_fits("proposal.view", &ReadModel::OwnProposal(own(title)));
        }
        let mut unknown = own(None);
        unknown.state = "UNKNOWN".to_owned();
        assert_fits("proposal.view", &ReadModel::OwnProposal(unknown));
    }

    /// I-17, R-IR-01, TH-26: the caller's assignments and IRC cases fit
    /// the one assignment shape, for every assignment kind.
    #[test]
    fn i17_own_assignments_and_irc_cases_fit_their_shape() {
        for kind in ["reviewer", "irc", "amendment"] {
            let m = ReadModel::Assignments(vec![assignment(kind)]);
            assert_fits("me.assignments", &m);
            assert_fits("me.irc_cases", &m);
        }
    }

    /// R-LG-04, TH-26: the caller's sessions fit their shape for every
    /// login method.
    #[test]
    fn r_lg_04_sessions_fit_for_every_method() {
        for method in [
            LoginMethod::Passkey,
            LoginMethod::MagicLink,
            LoginMethod::Opaque,
            LoginMethod::EudiWallet,
        ] {
            let s = SessionSummary {
                session: SessionId::from_raw(9),
                method,
                started: Timestamp::from_micros(5),
            };
            assert_fits("me.sessions", &ReadModel::Sessions(vec![s]));
        }
    }

    /// I-86, TH-26: the start of a verification answers its redirect only.
    #[test]
    fn i86_begin_verification_fits_its_shape() {
        assert_fits(
            "me.begin_verification",
            &ReadModel::Redirect("/vault/begin".to_owned()),
        );
    }

    /// J4, TH-26: creating a draft answers the drawn proposal id, and no
    /// other drawn id.
    #[test]
    fn th26_created_draft_fits_and_names_the_proposal_only() {
        let m = ReadModel::Created(vec![("proposal", 1001)]);
        assert_fits("proposal.create", &m);
        assert_eq!(
            fstp_json::to_canonical(&m.to_json()).unwrap(),
            r#"{"accepted":true,"proposal":"1001"}"#
        );
        let with_binding = ReadModel::Created(vec![("proposal", 1001), ("binding", 9)]);
        assert!(!fits(shape_of("proposal.create"), &with_binding.to_json()));
    }

    /// ADR-006, TH-26: a recorded plan answers the total the cell summed as
    /// an amount string, with the drawn plan id, and a plan with no
    /// milestone answers the bare acknowledgement. A total as a JSON
    /// number is refused.
    #[test]
    fn adr006_plan_saved_fits_with_and_without_a_total() {
        let saved = ReadModel::PlanSaved {
            plan: 31,
            total: "1500.50".to_owned(),
        };
        assert_fits("proposal.record_plan", &saved);
        assert_eq!(
            fstp_json::to_canonical(&saved.to_json()).unwrap(),
            r#"{"accepted":true,"plan":"31","total":"1500.50"}"#
        );
        assert_fits("proposal.record_plan", &ReadModel::Accepted);
        let mut o = Object::new();
        let _ = o.insert("accepted", Value::Bool(true));
        let _ = o.insert("total", Value::from(1500u32));
        assert!(!fits(shape_of("proposal.record_plan"), &Value::Object(o)));
        let short = ReadModel::PlanSaved {
            plan: 31,
            total: "1500.5".to_owned(),
        };
        assert!(!fits(shape_of("proposal.record_plan"), &short.to_json()));
    }

    /// I-21, TH-26: the team's workspace fits its shape.
    #[test]
    fn i21_workspace_fits_its_shape() {
        let w = ReadModel::Workspace(crate::views::WorkspaceView {
            title: String::new(),
            summary: String::new(),
            narrative: String::new(),
        });
        assert_fits("proposal.get_workspace", &w);
    }

    /// TH-08, R-AN-01: the team's stage 2 questions fit their shape, each
    /// with a handle and a day, and the empty list fits too.
    #[test]
    fn th08_stage2_questions_fit_their_shape() {
        let q = crate::views::Question {
            handle: "R".to_owned(),
            asked: "2026-10-30".to_owned(),
            text: "Why this milestone?".to_owned(),
        };
        assert_fits("stage2.view", &ReadModel::Stage2Questions(vec![q]));
        assert_fits("stage2.view", &ReadModel::Stage2Questions(Vec::new()));
    }

    /// R-EV-04, R-IR-02, TH-26: both notice kinds fit, with and without
    /// their day.
    #[test]
    fn r_ev_04_notices_fit_with_and_without_a_day() {
        let n = |kind, day: Option<&str>| crate::views::Notice {
            kind,
            proposal: 1001,
            day: day.map(str::to_owned),
        };
        let m = ReadModel::Notices(vec![
            n("ProposalOutcome", None),
            n("IrcConcern", Some("2026-10-30")),
        ]);
        assert_fits("me.notices", &m);
    }

    /// R-NG-06, TH-26: the negotiation landing fits its shape.
    #[test]
    fn r_ng_06_negotiation_landing_fits_its_shape() {
        for acknowledged in [false, true] {
            assert_fits("negotiation.view", &ReadModel::Negotiation { acknowledged });
        }
    }

    /// R-EV-01, TH-26: the intake queue and the call board fit their
    /// shapes, with SUBMITTED and INELIGIBLE rows.
    #[test]
    fn r_ev_01_intake_queue_and_board_fit_their_shapes() {
        let q = ReadModel::IntakeQueue(crate::views::IntakeQueue {
            knock_out: vec![crate::views::KnockOutCriterion {
                id: 2,
                text: "Open licence".to_owned(),
            }],
            proposals: vec![row("SUBMITTED"), row("INELIGIBLE")],
        });
        assert_fits("intake.queue", &q);
        let b = ReadModel::Board(vec![row("STAGE1"), row("NEGOTIATION")]);
        assert_fits("call.board", &b);
    }

    /// Q9, R-CF-02, TH-26: the declaration view fits a shape of exactly the
    /// title and the neutral summary.
    #[test]
    fn r_cf_02_declaration_view_fits_its_shape() {
        let v = ReadModel::DeclarationView(crate::views::DeclarationView {
            title: "t".to_owned(),
            neutral_summary: "s".to_owned(),
        });
        assert_fits("review.declaration_view", &v);
        let Some(Shape::Object(members)) = reply("review.declaration_view") else {
            panic!("review.declaration_view is not an object shape");
        };
        let names: Vec<&str> = members.iter().map(|m| m.name).collect();
        assert_eq!(names, ["title", "neutral_summary"]);
    }

    /// R-AC-01, R-IR-03, TH-26: the content read fits its shape, and the
    /// IRC case fits its own, which has no call member. Neither fits the
    /// other's shape.
    #[test]
    fn r_ir_03_content_and_irc_case_fit_their_own_shapes() {
        let read = ReadModel::Content(content(None));
        let case = ReadModel::Content(content(Some("nominated")));
        assert_fits("review.read_content", &read);
        assert_fits("irc.case", &case);
        assert!(!fits(shape_of("irc.case"), &read.to_json()));
        assert!(!fits(shape_of("review.read_content"), &case.to_json()));
    }

    /// R-CF-04, TH-26: the notifiable conflicts fit their shape.
    #[test]
    fn r_cf_04_notifiable_conflicts_fit_their_shape() {
        let m = ReadModel::Notifiable(vec![ProposalId::from_raw(1003)]);
        assert_fits("review.notifiable_conflicts", &m);
        assert_fits(
            "review.notifiable_conflicts",
            &ReadModel::Notifiable(Vec::new()),
        );
    }

    /// P-01, TH-26: the score sheet fits with and without a current score,
    /// at both stages, and its scale and values are JSON integers.
    #[test]
    fn th26_score_sheet_fits_with_and_without_a_current_score() {
        for current in [None, Some((3, vec![0, 5]))] {
            for stage in ["One", "Two"] {
                let mut s = sheet(current.clone());
                s.stage = stage;
                assert_fits("review.score_sheet", &ReadModel::ScoreSheet(s));
            }
        }
        let text = fstp_json::to_canonical(&sheet(Some((3, vec![4]))).to_json()).unwrap();
        assert!(text.contains(r#""max":5"#), "{text}");
        assert!(text.contains(r#""values":[4]"#), "{text}");
    }

    /// R-EV-05, R-AN-01, TH-26: the reviewer's stage 2 thread fits its
    /// shape, with a question under a handle and an answer with none.
    #[test]
    fn r_ev_05_stage2_thread_fits_its_shape() {
        assert_fits("review.stage2_thread", &ReadModel::Stage2Thread(thread()));
        let mut empty = thread();
        empty.entries.clear();
        empty.state = "UNKNOWN";
        assert_fits("review.stage2_thread", &ReadModel::Stage2Thread(empty));
    }

    /// R-EV-08, Q16, TH-26: ranked and recused rows fit the ranking shape.
    /// A recused row carries the proposal and `recused` only, and a ranked
    /// row carries every member, the empty texts as `null`.
    #[test]
    fn r_ev_08_ranking_rows_fit_and_a_recused_row_shows_nothing_else() {
        let recused = crate::views::RankingRow::Recused { proposal: 1003 };
        let mut untitled = ranked();
        if let crate::views::RankingRow::Ranked {
            title,
            neutral_summary,
            rationale,
            ..
        } = &mut untitled
        {
            *title = None;
            *neutral_summary = None;
            *rationale = None;
        }
        let m = ReadModel::Ranking(vec![ranked(), untitled, recused.clone()]);
        assert_fits("committee.ranking", &m);
        assert_eq!(
            fstp_json::to_canonical(&recused.to_json()).unwrap(),
            r#"{"proposal":"1003","recused":true}"#
        );
        let Some(Shape::Array(Shape::Object(members))) = reply("committee.ranking") else {
            panic!("committee.ranking is not an array of objects");
        };
        // A row within budget carries every member but `shortfall`, and
        // an over-nominated row carries every member.
        let within = ranked().to_json();
        let over = over_nominated().to_json();
        for member in *members {
            let name = member.name;
            let expected = name != "shortfall";
            assert_eq!(
                within.as_object().unwrap().get(name).is_some(),
                expected,
                "{name}"
            );
            assert!(
                over.as_object().unwrap().get(name).is_some(),
                "over-nominated row lacks {name}"
            );
        }
    }

    /// R-EV-08, ADR-006, TH-26: the remaining budget of an over-nominated
    /// call is signed, and no served amount carries a sign. The row
    /// serves a zero `remaining_budget` and a positive `shortfall`, as the
    /// domain codec spells a signed amount, and fits its shape.
    #[test]
    fn adr006_over_nominated_ranking_row_serves_a_positive_shortfall() {
        let m = ReadModel::Ranking(vec![over_nominated()]);
        assert_fits("committee.ranking", &m);
        let json = over_nominated().to_json();
        let o = json.as_object().unwrap();
        assert_eq!(o.get("remaining_budget"), Some(&Value::from("0.00")));
        assert_eq!(o.get("shortfall"), Some(&Value::from("500.00")));
        let text = fstp_json::to_canonical(&json).unwrap();
        assert!(!text.contains('-'), "{text}");
    }

    /// R-EV-08, ADR-006: a budget of exactly zero is one spelling, a zero
    /// `remaining_budget` with no `shortfall`, so a zero shortfall is
    /// never served.
    #[test]
    fn adr006_exhausted_budget_serves_no_shortfall() {
        let mut row = ranked();
        if let crate::views::RankingRow::Ranked {
            remaining_budget, ..
        } = &mut row
        {
            *remaining_budget = fstp_money::Amount::from_minor(0, fstp_money::Currency::Eur)
                .unwrap()
                .to_string();
        }
        assert_fits("committee.ranking", &ReadModel::Ranking(vec![row.clone()]));
        let json = row.to_json();
        let o = json.as_object().unwrap();
        assert_eq!(o.get("remaining_budget"), Some(&Value::from("0.00")));
        assert_eq!(o.get("shortfall"), None);
    }

    /// TH-26, ADR-006: the shape check has teeth. An extra member, a
    /// missing member, a budget sent as a JSON number and an id that is
    /// not canonical are each refused.
    #[test]
    fn th26_reply_shapes_refuse_extra_missing_and_mistyped_members() {
        let good = call().to_json();
        assert!(fits(shape_of("calls.get"), &good));
        let edit = |f: &dyn Fn(&mut Object)| {
            let mut v = good.clone();
            if let Some(o) = v.as_object_mut() {
                f(o);
            }
            v
        };
        let extra = edit(&|o| {
            let _ = o.insert("author", Value::from("1"));
        });
        let missing = edit(&|o| {
            let _ = o.remove("open");
        });
        let number = edit(&|o| {
            let _ = o.insert("budget", Value::from(400_000u32));
        });
        let id = edit(&|o| {
            let _ = o.insert("call", Value::from("07"));
        });
        for (bad, what) in [
            (extra, "extra"),
            (missing, "missing"),
            (number, "number"),
            (id, "id"),
        ] {
            assert!(!fits(shape_of("calls.get"), &bad), "{what} passed");
        }
    }

    /// SoD-07, TH-26: the admin list fits its shape, lists each account
    /// once in account order, and counts the verified admins.
    #[test]
    fn sod07_admin_list_fits_and_counts_verified_admins() {
        let row = |a: u128, verified: bool| AdminRow {
            account: AccountId::from_raw(a),
            handle: DisplayHandle(format!("admin-{a}")),
            verified,
        };
        let list = TenantAdmins::new([row(2, true), row(1, false), row(2, false)]);
        assert_fits("tenant.list_admins", &list);
        let accounts: Vec<u128> = list.admins().iter().map(|r| r.account.raw()).collect();
        assert_eq!(accounts, vec![1, 2]);
        assert_eq!(list.verified_count(), 1);
    }

    /// I-86: the verification state is `{status}` alone, and a verified
    /// answer wins over a begun verification.
    #[test]
    fn i86_verification_state_is_the_status_only() {
        for (verified, begun, want) in [
            (false, false, "unverified"),
            (false, true, "pending"),
            (true, false, "verified"),
            (true, true, "verified"),
        ] {
            let v = VerificationState {
                status: VerificationStatus::of(verified, begun),
            };
            assert_fits("me.get_verification", &v);
            let json = v.to_json();
            let o = json.as_object().unwrap();
            assert_eq!(o.len(), 1);
            assert_eq!(o.get("status").and_then(Value::as_str), Some(want));
        }
    }

    /// R-PG-02, R-PG-05, TH-26: the creator start lists fit their shapes,
    /// in id order with no repeat, and a template version is a JSON
    /// integer.
    #[test]
    fn r_pg_02_creator_start_lists_fit_their_shapes() {
        let p = |id: u128| ProgrammeRow {
            programme: ProgrammeId::from_raw(id),
            name: format!("SYNTHETIC PROGRAMME {id}"),
        };
        let programmes = ProgrammeList::new([p(3), p(1), p(3)]);
        assert_fits("creator.list_programmes", &programmes);
        assert_eq!(programmes.programmes().len(), 2);
        let t = |id: u128, version: u32| TemplateRow {
            template: fstp_creator::TemplateId::from_raw(id),
            version: NonZeroU32::new(version).unwrap(),
            name: "SuperSAFE".to_owned(),
        };
        let templates = TemplateList::new([t(2, 1), t(1, 2), t(1, 1), t(1, 1)]);
        assert_fits("creator.list_templates", &templates);
        let order: Vec<(u128, u32)> = templates
            .templates()
            .iter()
            .map(|r| (r.template.raw(), r.version.get()))
            .collect();
        assert_eq!(order, vec![(1, 1), (1, 2), (2, 1)]);
    }

    /// SoD-09, TH-26: the invitation landing fits its shape with and
    /// without the programme's P-75 and P-77 choices, names no account,
    /// and exists only for a role an invitation names.
    #[test]
    fn sod09_invitation_landing_fits_and_names_no_account() {
        let v1 = NonZeroU32::MIN;
        let open = InvitationLanding::new(
            Role::CommitteeMember,
            v1,
            None,
            None,
            InvitationState::Invited,
        )
        .unwrap();
        assert_fits("people.get_invitation", &open);
        let decided = InvitationLanding::new(
            Role::IrcMember,
            v1,
            Some(false),
            Some(McpBindingActions::DraftOnly),
            InvitationState::Accepted,
        )
        .unwrap();
        assert_fits("people.get_invitation", &decided);
        let json = decided.to_json();
        let o = json.as_object().unwrap();
        for absent in ["account", "email", "by", "invitee", "programme"] {
            assert!(o.get(absent).is_none(), "{absent}");
        }
        assert!(
            InvitationLanding::new(Role::Applicant, v1, None, None, InvitationState::Invited)
                .is_none()
        );
        assert!(
            InvitationLanding::new(Role::TenantAdmin, v1, None, None, InvitationState::Invited)
                .is_none()
        );
    }

    /// SoD-09, `programme-creator.md` step 9: every role the creator can
    /// invite has a landing that fits its shape, the finance roles among
    /// them. Only a Judging role's landing states P-75 and P-77.
    #[test]
    fn sod09_invitation_landing_exists_for_every_invitable_role() {
        let v1 = NonZeroU32::MIN;
        for role in Role::ALL {
            let landing = InvitationLanding::new(
                role,
                v1,
                Some(true),
                Some(McpBindingActions::Allowed),
                InvitationState::Invited,
            );
            assert_eq!(landing.is_some(), fstp_access::invitable(role), "{role:?}");
            let Some(landing) = landing else {
                continue;
            };
            assert_fits("people.get_invitation", &landing);
            let json = landing.to_json();
            let o = json.as_object().unwrap();
            let judging = matches!(role.group(), Group::Judging);
            assert_eq!(o.get("p75") == Some(&Value::Null), !judging, "{role:?}");
            assert_eq!(o.get("p77") == Some(&Value::Null), !judging, "{role:?}");
        }
    }

    /// R-EV-08, TH-26, change D5: the reply to opening a round carries the
    /// drawn round id as a canonical decimal string and nothing else.
    #[test]
    fn r_ev_08_round_opened_fits_and_carries_the_round_only() {
        let opened = RoundOpened {
            round: DecisionId::from_raw(9),
        };
        assert_fits("committee.open_round", &opened);
        assert_eq!(
            fstp_json::to_canonical(&opened.to_json()).unwrap(),
            r#"{"round":"9"}"#
        );
    }

    /// R-AC-01, R-CF-03, I-17: the assignment view fits its shape, states
    /// its checks as pass or fail only, and carries labels, never a name
    /// or an email member.
    #[test]
    fn r_ac_01_assignment_view_fits_and_names_no_identity() {
        let view = AssignmentView::new(
            StateTag::Stage1,
            vec![AssignedRow {
                assignment: AssignmentId::from_raw(5),
                label: "Reviewer A".to_owned(),
            }],
            vec![CandidateRow {
                account: AccountId::from_raw(8),
                label: "member-8".to_owned(),
            }],
            AssignmentChecks {
                p39: true,
                proximity: false,
            },
        );
        assert_fits("review.assignments", &view);
        let text = fstp_json::to_canonical(&view.to_json()).unwrap();
        assert!(text.contains(r#""checks":{"p39":"pass","proximity":"fail"}"#));
        for field in ["\"name\"", "\"email\"", "\"reviewer\""] {
            assert!(!text.contains(field), "{field} in {text}");
        }
    }

    /// R-EV-09, P-16 NOTE 8, TH-26: the round view fits its shape, open,
    /// recorded and superseded. It counts the ballots, names the viewer's own vote
    /// only, and has no member naming a voter or another member's vote.
    #[test]
    fn r_ev_09_round_view_fits_and_names_no_voter() {
        for status in [
            RoundStatus::Open,
            RoundStatus::Recorded,
            RoundStatus::Superseded,
        ] {
            let v = round_view(status);
            assert_fits("committee.round", &v);
            let text = fstp_json::to_canonical(&v.to_json()).unwrap();
            for field in [
                "\"voter\"",
                "\"votes\"",
                "\"ballots\"",
                "\"email\"",
                "\"name\"",
            ] {
                assert!(!text.contains(field), "{field} in {text}");
            }
        }
        let open = fstp_json::to_canonical(&round_view(RoundStatus::Open).to_json()).unwrap();
        assert!(
            open.contains(r#""viewer":{"delegated_to":null,"own_vote":null,"recused":false}"#),
            "{open}"
        );
    }

    /// R-EV-09, change D5: the round view states its status, so a page
    /// offers the ballot, the delegation and the record only on an open
    /// round. A superseded round reads as superseded, never as open. A
    /// round that is not open states no recusal, since none is judged.
    #[test]
    fn r_ev_09_round_view_states_superseded_and_no_recusal_off_open() {
        for (status, name) in [
            (RoundStatus::Open, "open"),
            (RoundStatus::Recorded, "recorded"),
            (RoundStatus::Superseded, "superseded"),
        ] {
            let text = fstp_json::to_canonical(&round_view(status).to_json()).unwrap();
            assert!(text.contains(&format!(r#""status":"{name}""#)), "{text}");
            assert!(!text.contains(r#""recorded":"#), "{text}");
            let recusal = if status == RoundStatus::Open {
                r#""recused":false"#
            } else {
                r#""recused":null"#
            };
            assert!(text.contains(recusal), "{text}");
        }
    }

    /// R-AC-01: a proposal the projection does not hold has no board.
    #[test]
    fn r_ac_01_assignment_board_of_an_unknown_proposal_is_none() {
        let state = fstp_engine::EngineState::genesis();
        let board = assignment_board(&state, ProposalId::from_raw(1), Timestamp::from_micros(0));
        assert_eq!(board, None);
    }
}
