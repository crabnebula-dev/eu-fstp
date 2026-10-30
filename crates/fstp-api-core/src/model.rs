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
}

impl ToJson for ProposalSummary {
    fn to_json(&self) -> Value {
        let mut o = Object::new();
        let _ = o.insert("proposal", dec(self.proposal.raw()));
        let _ = o.insert("call", dec(self.call.raw()));
        let _ = o.insert("state", Value::from(self.state.as_str()));
        let _ = o.insert("role", Value::from(self.role));
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
/// It names no voter and no proposal.
///
/// Seam for lane m4int-b: dispatch answers the command with
/// [`ReadModel::Accepted`] today. It must serve this reply instead, with
/// the id the form drew.
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
    /// Its unreleased reviewer assignments, in assignment order.
    pub assigned: Vec<BoardAssignee>,
    /// The committee members of its programme the coordinator may assign,
    /// in account order. Each holds an active committee member binding at
    /// the instant. None holds an unreleased reviewer assignment or a
    /// recorded conflict fact on the proposal. The domain guards run again
    /// at the assignment.
    pub candidates: Vec<AccountId>,
}

/// The assignment board of `proposal` at `now` (R-AC-01, J5), or `None`
/// for a proposal the projection does not hold.
#[allow(
    dead_code,
    reason = "dispatch::read serves it once lane m4int-b adds the branch"
)]
pub(crate) fn assignment_board(
    state: &fstp_engine::EngineState,
    proposal: ProposalId,
    now: Timestamp,
) -> Option<AssignmentBoard> {
    let core = &state.core;
    let tag = fstp_domain::view::proposal_state(core, proposal)?;
    let mut assigned: Vec<BoardAssignee> = core
        .review()
        .assignments()
        .filter(|(_, a)| {
            a.proposal == proposal && a.kind == AssignmentKind::Reviewer && a.unreleased()
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
mod reply_shape_tests {
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

    fn assert_fits(op: &str, v: &impl ToJson) {
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
        }
    }

    /// TH-26, ADR-006, ADR-014: every reply the API core serves today fits
    /// its shape, and a call's budget is an amount string.
    #[test]
    fn th26_served_read_models_fit_their_reply_shapes() {
        let pending = PendingView {
            id: PendingId::from_raw(3),
            agent: AgentClientId::from_raw(4),
            op: "call.publish".to_owned(),
            request: "{}".to_owned(),
            digest: ActionDigest([7; 32]),
            created: Timestamp::from_micros(10),
            expires: Timestamp::from_micros(20),
            status: PendingStatus::Open,
        };
        assert_fits("pending.list", &ReadModel::PendingActions(vec![pending]));
        assert_fits("calls.list_open", &ReadModel::OpenCalls(vec![call()]));
        assert_fits("calls.get", &ReadModel::Call(call()));
        let own = ProposalSummary {
            proposal: ProposalId::from_raw(11),
            call: CallId::from_raw(7),
            state: "SUBMITTED".to_owned(),
            role: "lead",
        };
        assert_fits("proposal.list_own", &ReadModel::OwnProposals(vec![own]));
        let mine = AssignmentSummary {
            assignment: AssignmentId::from_raw(5),
            proposal: ProposalId::from_raw(11),
            call: CallId::from_raw(7),
            kind: "reviewer",
            awaiting_declaration: true,
            active: false,
        };
        assert_fits("me.assignments", &ReadModel::Assignments(vec![mine]));
        let session = SessionSummary {
            session: SessionId::from_raw(9),
            method: LoginMethod::MagicLink,
            started: Timestamp::from_micros(5),
        };
        assert_fits("me.sessions", &ReadModel::Sessions(vec![session]));
        assert_fits(
            "me.begin_verification",
            &ReadModel::Redirect("/vault/begin".to_owned()),
        );
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

    /// R-AC-01: a proposal the projection does not hold has no board.
    #[test]
    fn r_ac_01_assignment_board_of_an_unknown_proposal_is_none() {
        let state = fstp_engine::EngineState::genesis();
        let board = assignment_board(&state, ProposalId::from_raw(1), Timestamp::from_micros(0));
        assert_eq!(board, None);
    }
}
