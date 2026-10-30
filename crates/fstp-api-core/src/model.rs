//! Identity-free read models (design sections 3.6 and 3.7). No read model
//! carries an identity field (I-17): no display name, no email, no
//! identity attribute and no vault fact. Ids are the only references. The
//! [`crate::McpSafe`] marker is implemented by hand for each of them.
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
    /// `proposal.record_plan`: the plan was recorded, with its total as
    /// the cell computed it (ADR-006). The browser never computes money.
    PlanSaved(String),
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
            ReadModel::PlanSaved(total) => {
                let mut o = Object::new();
                let _ = o.insert("accepted", Value::Bool(true));
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
        }
    }
}

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
