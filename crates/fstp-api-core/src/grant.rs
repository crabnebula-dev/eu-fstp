//! The read models of the M5 grant, contract, payment and report reads
//! (M5 design section 5, lane L-API).
//!
//! I-86: no model here holds a bank detail, an identity attribute or a
//! vault value. A hardship request is marked as such, and its vault
//! evidence reference never leaves the cell. Parties are named by their
//! signature field and role, never by account. Amounts are ADR-006
//! strings the cell formats.

use fstp_domain::id::{
    CallId, ContractId, LineId, MilestoneId, ProgrammeId, ProposalId, RequestId,
};
use fstp_json::{Array, Object, ToJson, Value};

use crate::McpSafe;
use crate::grant_lists::{DeterminationView, GrantRow, MilestoneRow, SignRow};

fn dec(x: u128) -> Value {
    Value::String(x.to_string())
}

fn nullable<T>(x: Option<T>, f: impl FnOnce(T) -> Value) -> Value {
    x.map_or(Value::Null, f)
}

fn array<T: ToJson>(items: &[T]) -> Value {
    let mut a = Array::new();
    for i in items {
        a.push(i.to_json());
    }
    Value::Array(a)
}

/// One M5 read model.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GrantModel {
    /// `grant.overview`.
    Overview(Box<GrantOverview>),
    /// `contract.view`.
    Contract(ContractView),
    /// `payment.status`.
    Payments(Vec<RequestRow>),
    /// `payment.queue`.
    Queue(Vec<QueueRow>),
    /// `report.list`.
    Reports(Vec<ReportRow>),
    /// `grant.list_mine` (M5 reads follow-up).
    Grants(Vec<GrantRow>),
    /// `contract.awaiting_me` (M5 reads follow-up).
    ToSign(Vec<SignRow>),
    /// `grant.determination_view` (R-NG-03).
    Determination(DeterminationView),
    /// `payment.line_review_view` (R-PR-08, lane m5/polish-access).
    LineReview(Box<crate::grant_lists::LineReviewView>),
    /// `report.programmes`: the programmes whose reports `report.list`
    /// serves the caller (lane m5/report-programmes, R-RP-03).
    ReportProgrammes(Vec<ProgrammeId>),
    /// `grant.publicity.view` (M9 lane P1, R-PB-02, I-43).
    Publicity(Box<crate::publicity::PublicityView>),
    /// `programme.funder_profile.view` (M9 finish, R-RP-01): the profile
    /// the programme pins through P-53, if it names a shipped one.
    FunderProfile(ProgrammeId, Option<FunderProfileView>),
}

impl ToJson for GrantModel {
    fn to_json(&self) -> Value {
        match self {
            GrantModel::Overview(v) => v.to_json(),
            GrantModel::Contract(v) => v.to_json(),
            GrantModel::Payments(rows) => array(rows),
            GrantModel::Queue(rows) => array(rows),
            GrantModel::Reports(rows) => array(rows),
            GrantModel::Grants(rows) => array(rows),
            GrantModel::ToSign(rows) => array(rows),
            GrantModel::Determination(v) => v.to_json(),
            GrantModel::LineReview(v) => v.to_json(),
            GrantModel::Publicity(v) => v.to_json(),
            GrantModel::FunderProfile(p, view) => {
                let mut o = Object::new();
                let _ = o.insert("programme", dec(p.raw()));
                let _ = o.insert(
                    "profile",
                    view.as_ref()
                        .map_or(Value::Null, FunderProfileView::to_json),
                );
                Value::Object(o)
            }
            GrantModel::ReportProgrammes(ps) => {
                let mut a = Array::new();
                for p in ps {
                    let mut o = Object::new();
                    let _ = o.insert("id", dec(p.raw()));
                    let _ = o.insert("name", Value::String(crate::creator::programme_name(*p)));
                    a.push(Value::Object(o));
                }
                Value::Array(a)
            }
        }
    }
}

impl McpSafe for GrantModel {}

/// A pinned funder profile, as `programme.funder_profile.view` shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FunderProfileView {
    /// The profile id, such as `horizon-europe`.
    pub id: String,
    /// The version.
    pub version: u16,
    /// The SHA-256 of the profile file, as lowercase hex.
    pub digest: String,
    /// The output kinds the profile defines, in file order.
    pub outputs: Vec<&'static str>,
    /// The visibility element keys, in file order.
    pub visibility_elements: Vec<String>,
}

impl ToJson for FunderProfileView {
    fn to_json(&self) -> Value {
        let mut o = Object::new();
        let _ = o.insert("id", Value::String(self.id.clone()));
        let _ = o.insert("version", dec(u128::from(self.version)));
        let _ = o.insert("digest", Value::String(self.digest.clone()));
        let mut outputs = Array::new();
        for k in &self.outputs {
            outputs.push(Value::String((*k).to_owned()));
        }
        let _ = o.insert("outputs", Value::Array(outputs));
        let mut keys = Array::new();
        for k in &self.visibility_elements {
            keys.push(Value::String(k.clone()));
        }
        let _ = o.insert("visibility_elements", Value::Array(keys));
        Value::Object(o)
    }
}

/// The overview of one grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantOverview {
    /// The grant, by its proposal.
    pub proposal: ProposalId,
    /// The proposal state, as the state machine names it.
    pub state: &'static str,
    /// The current amount determination (R-NG-03).
    pub determination: Option<u128>,
    /// The reserved or granted amount.
    pub amount: Option<String>,
    /// The paid total (I-64).
    pub paid: String,
    /// The effective or latest contract.
    pub contract: Option<ContractId>,
    /// The number of payment requests.
    pub requests: u32,
    /// The plan of the effective contract, else the agreed plan of the
    /// current determination (M5 reads follow-up).
    pub plan: Option<fstp_domain::id::PlanVersionId>,
    /// The plan's milestones with the cell's sums (R-PR-07, I-58).
    pub milestones: Vec<MilestoneRow>,
}

impl ToJson for GrantOverview {
    fn to_json(&self) -> Value {
        let mut o = Object::new();
        let _ = o.insert("proposal", dec(self.proposal.raw()));
        let _ = o.insert("state", Value::from(self.state));
        let _ = o.insert("determination", nullable(self.determination, dec));
        let _ = o.insert("amount", nullable(self.amount.as_deref(), Value::from));
        let _ = o.insert("paid", Value::from(self.paid.as_str()));
        let _ = o.insert("contract", nullable(self.contract, |c| dec(c.raw())));
        let _ = o.insert("requests", Value::from(self.requests));
        let _ = o.insert("plan", nullable(self.plan, |p| dec(p.raw())));
        let _ = o.insert("milestones", array(&self.milestones));
        Value::Object(o)
    }
}

/// One party of a contract version, by field and role (I-86).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartyRow {
    /// The signature field.
    pub field: String,
    /// `lead`, `team_member`, `guardian` or `signatory`.
    pub role: &'static str,
    /// Whether the party signed this version.
    pub signed: bool,
    /// Whether the caller is this party.
    pub mine: bool,
}

impl ToJson for PartyRow {
    fn to_json(&self) -> Value {
        let mut o = Object::new();
        let _ = o.insert("field", Value::from(self.field.as_str()));
        let _ = o.insert("role", Value::from(self.role));
        let _ = o.insert("signed", Value::Bool(self.signed));
        let _ = o.insert("mine", Value::Bool(self.mine));
        Value::Object(o)
    }
}

/// One version of a contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionRow {
    /// The version number.
    pub version: u32,
    /// The version state.
    pub state: &'static str,
    /// Its parties.
    pub parties: Vec<PartyRow>,
    /// The number of stored revisions (I-30).
    pub revisions: u32,
    /// The SHA-256 of the latest revision, lowercase hex.
    pub digest: Option<String>,
    /// The clause changes still proposed (R-CT-04).
    pub open_changes: Vec<u32>,
}

impl ToJson for VersionRow {
    fn to_json(&self) -> Value {
        let mut o = Object::new();
        let _ = o.insert("version", Value::from(self.version));
        let _ = o.insert("state", Value::from(self.state));
        let _ = o.insert("parties", array(&self.parties));
        let _ = o.insert("revisions", Value::from(self.revisions));
        let _ = o.insert("digest", nullable(self.digest.as_deref(), Value::from));
        let _ = o.insert(
            "open_changes",
            Value::Array(self.open_changes.iter().map(|c| Value::from(*c)).collect()),
        );
        Value::Object(o)
    }
}

/// The contract status of one grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContractView {
    /// The grant.
    pub proposal: ProposalId,
    /// The contract, once drafted.
    pub contract: Option<ContractId>,
    /// The contract status.
    pub status: Option<&'static str>,
    /// Every version, oldest first.
    pub versions: Vec<VersionRow>,
}

impl ToJson for ContractView {
    fn to_json(&self) -> Value {
        let mut o = Object::new();
        let _ = o.insert("proposal", dec(self.proposal.raw()));
        let _ = o.insert("contract", nullable(self.contract, |c| dec(c.raw())));
        let _ = o.insert("status", nullable(self.status, Value::from));
        let _ = o.insert("versions", array(&self.versions));
        Value::Object(o)
    }
}

/// One line of a payment request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LineRow {
    /// The line.
    pub line: LineId,
    /// The milestone it claims.
    pub milestone: MilestoneId,
    /// The requested amount.
    pub requested: String,
    /// The approved amount, once decided.
    pub approved: Option<String>,
}

impl ToJson for LineRow {
    fn to_json(&self) -> Value {
        let mut o = Object::new();
        let _ = o.insert("line", dec(self.line.raw()));
        let _ = o.insert("milestone", dec(self.milestone.raw()));
        let _ = o.insert("requested", Value::from(self.requested.as_str()));
        let _ = o.insert("approved", nullable(self.approved.as_deref(), Value::from));
        Value::Object(o)
    }
}

/// One payment request of a grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestRow {
    /// The request.
    pub request: RequestId,
    /// The grant.
    pub proposal: ProposalId,
    /// The status, as `payment-requests.md` names it.
    pub status: &'static str,
    /// Milestone claim or hardship contribution (R-PR-04).
    pub kind: &'static str,
    /// Whether the submission checks passed (I-32).
    pub submission_checks: bool,
    /// Whether the acceptance checks passed (I-32).
    pub acceptance_checks: bool,
    /// The lines.
    pub lines: Vec<LineRow>,
}

impl ToJson for RequestRow {
    fn to_json(&self) -> Value {
        let mut o = Object::new();
        let _ = o.insert("request", dec(self.request.raw()));
        let _ = o.insert("proposal", dec(self.proposal.raw()));
        let _ = o.insert("status", Value::from(self.status));
        let _ = o.insert("kind", Value::from(self.kind));
        let _ = o.insert("submission_checks", Value::Bool(self.submission_checks));
        let _ = o.insert("acceptance_checks", Value::Bool(self.acceptance_checks));
        let _ = o.insert("lines", array(&self.lines));
        Value::Object(o)
    }
}

/// One item of the caller's payment work queue.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueueRow {
    /// What the caller does: `review`, `approve`, `release` or `confirm`.
    pub task: &'static str,
    /// The request, with its lines.
    pub request: RequestRow,
}

impl ToJson for QueueRow {
    fn to_json(&self) -> Value {
        let mut o = Object::new();
        let _ = o.insert("task", Value::from(self.task));
        let _ = o.insert("request", self.request.to_json());
        Value::Object(o)
    }
}

/// One funder report of a programme (R-RP-01, R-RP-03).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReportRow {
    /// The report.
    pub report: u128,
    /// The output kind.
    pub kind: &'static str,
    /// The call it covers, if it covers one call.
    pub call: Option<CallId>,
    /// The programme it covers, if it covers the programme.
    pub programme: Option<ProgrammeId>,
    /// The SHA-256 of the document, lowercase hex.
    pub document: String,
    /// The template version.
    pub template: String,
    /// Whether the caller generated it, and so may not approve it.
    pub generated_by_me: bool,
    /// Whether it is approved.
    pub approved: bool,
}

impl ToJson for ReportRow {
    fn to_json(&self) -> Value {
        let mut o = Object::new();
        let _ = o.insert("report", dec(self.report));
        let _ = o.insert("kind", Value::from(self.kind));
        let _ = o.insert("call", nullable(self.call, |c| dec(c.raw())));
        let _ = o.insert("programme", nullable(self.programme, |p| dec(p.raw())));
        let _ = o.insert("document", Value::from(self.document.as_str()));
        let _ = o.insert("template", Value::from(self.template.as_str()));
        let _ = o.insert("generated_by_me", Value::Bool(self.generated_by_me));
        let _ = o.insert("approved", Value::Bool(self.approved));
        Value::Object(o)
    }
}

/// One sample of each model, filled and empty, for the reply shape tests.
#[cfg(test)]
pub(crate) fn samples() -> Vec<GrantModel> {
    let request = RequestRow {
        request: RequestId::from_raw(7),
        proposal: ProposalId::from_raw(3),
        status: "UNDER_REVIEW",
        kind: "hardship",
        submission_checks: true,
        acceptance_checks: false,
        lines: vec![LineRow {
            line: LineId::from_raw(8),
            milestone: MilestoneId::from_raw(9),
            requested: "100.00".to_owned(),
            approved: Some("90.00".to_owned()),
        }],
    };
    vec![
        GrantModel::Overview(Box::new(GrantOverview {
            proposal: ProposalId::from_raw(3),
            state: "GRANTED",
            determination: Some(4),
            amount: Some("1000.00".to_owned()),
            paid: "0.00".to_owned(),
            contract: Some(ContractId::from_raw(5)),
            requests: 1,
            plan: Some(fstp_domain::id::PlanVersionId::from_raw(6)),
            milestones: vec![MilestoneRow {
                milestone: MilestoneId::from_raw(9),
                amount: "1000.00".to_owned(),
                due: "2027-03-01".to_owned(),
                paid: "0.00".to_owned(),
                pending: "100.00".to_owned(),
                available: "900.00".to_owned(),
                closed: false,
            }],
        })),
        GrantModel::Overview(Box::new(GrantOverview {
            proposal: ProposalId::from_raw(3),
            state: "NEGOTIATION",
            determination: None,
            amount: None,
            paid: "0.00".to_owned(),
            contract: None,
            requests: 0,
            plan: None,
            milestones: Vec::new(),
        })),
        GrantModel::Contract(ContractView {
            proposal: ProposalId::from_raw(3),
            contract: Some(ContractId::from_raw(5)),
            status: Some("sent"),
            versions: vec![VersionRow {
                version: 1,
                state: "sent",
                parties: vec![PartyRow {
                    field: "lead".to_owned(),
                    role: "lead",
                    signed: false,
                    mine: true,
                }],
                revisions: 1,
                digest: Some("00".repeat(32)),
                open_changes: vec![2],
            }],
        }),
        GrantModel::Contract(ContractView {
            proposal: ProposalId::from_raw(3),
            contract: None,
            status: None,
            versions: Vec::new(),
        }),
        GrantModel::Payments(vec![request.clone()]),
        GrantModel::Queue(vec![QueueRow {
            task: "review",
            request: request.clone(),
        }]),
        GrantModel::Reports(vec![ReportRow {
            report: 11,
            kind: "audit_file",
            call: Some(CallId::from_raw(2)),
            programme: None,
            document: "00".repeat(32),
            template: "horizon-europe/audit_file/1".to_owned(),
            generated_by_me: false,
            approved: false,
        }]),
        GrantModel::Grants(vec![GrantRow {
            proposal: ProposalId::from_raw(3),
            call: Some(CallId::from_raw(2)),
            state: "IN_EXECUTION",
            amount: Some("1000.00".to_owned()),
            paid: "0.00".to_owned(),
            contract: Some(ContractId::from_raw(5)),
            via: "programme_manager",
        }]),
        GrantModel::Grants(vec![GrantRow {
            proposal: ProposalId::from_raw(3),
            call: None,
            state: "NEGOTIATION",
            amount: None,
            paid: "0.00".to_owned(),
            contract: None,
            via: "team",
        }]),
        GrantModel::Grants(Vec::new()),
        GrantModel::ReportProgrammes(vec![ProgrammeId::from_raw(1), ProgrammeId::from_raw(2)]),
        GrantModel::ReportProgrammes(Vec::new()),
        GrantModel::FunderProfile(ProgrammeId::from_raw(1), None),
        GrantModel::FunderProfile(
            ProgrammeId::from_raw(1),
            Some(FunderProfileView {
                id: "horizon-europe".to_owned(),
                version: 1,
                digest: "ab".repeat(32),
                outputs: vec!["call_publication_record", "audit_file"],
                visibility_elements: vec!["acknowledgement".to_owned()],
            }),
        ),
        GrantModel::ToSign(vec![SignRow {
            proposal: ProposalId::from_raw(3),
            contract: ContractId::from_raw(5),
            version: 1,
            field: "signatory".to_owned(),
            role: "signatory",
            state: "signed_by_grantee",
            digest: Some("00".repeat(32)),
        }]),
        GrantModel::ToSign(Vec::new()),
        GrantModel::Determination(DeterminationView {
            proposal: ProposalId::from_raw(3),
            state: "NEGOTIATION",
            determination: Some(4),
            plan: Some(fstp_domain::id::PlanVersionId::from_raw(6)),
            plan_total: Some("1000.00".to_owned()),
            granted: Some("900.00".to_owned()),
        }),
        GrantModel::Determination(DeterminationView {
            proposal: ProposalId::from_raw(3),
            state: "NEGOTIATION",
            determination: None,
            plan: None,
            plan_total: None,
            granted: None,
        }),
        GrantModel::LineReview(Box::new(crate::grant_lists::LineReviewView {
            request: request.clone(),
            texts: vec![crate::grant_lists::LineTexts {
                location: Some("https://forge.example/synthetic".to_owned()),
                release: Some("v1.0.0".to_owned()),
                licence: Some("MIT".to_owned()),
                report: None,
            }],
        })),
        GrantModel::LineReview(Box::new(crate::grant_lists::LineReviewView {
            request: request.clone(),
            texts: Vec::new(),
        })),
        GrantModel::Publicity(Box::new(crate::publicity::PublicityView {
            proposal: ProposalId::from_raw(3),
            state: "COMPLETED",
            minor: false,
            max_funded: fstp_public::Level::Full,
            max_finished: fstp_public::Level::ProjectAndGrantee,
            funded: crate::publicity::PhaseView {
                open: true,
                choice: Some(crate::publicity::ChoiceView {
                    level: fstp_public::Level::Full,
                    effective: fstp_public::Level::Full,
                    title: "Synthetic title".to_owned(),
                    summary: "Synthetic summary".to_owned(),
                    grantee: "Synthetic Grantee".to_owned(),
                    deliverables: Vec::new(),
                }),
            },
            finished: crate::publicity::PhaseView {
                open: true,
                choice: Some(crate::publicity::ChoiceView {
                    level: fstp_public::Level::Full,
                    effective: fstp_public::Level::ProjectAndGrantee,
                    title: String::new(),
                    summary: String::new(),
                    grantee: String::new(),
                    deliverables: vec![fstp_domain::id::DeliverableId::from_raw(7)],
                }),
            },
            deliverables: vec![crate::publicity::DeliverableView {
                id: fstp_domain::id::DeliverableId::from_raw(7),
                licence: "MIT".to_owned(),
                snapshot: "ab".repeat(32),
            }],
        })),
        GrantModel::Publicity(Box::new(crate::publicity::PublicityView {
            proposal: ProposalId::from_raw(3),
            state: "GRANTED",
            minor: true,
            max_funded: fstp_public::Level::Hidden,
            max_finished: fstp_public::Level::Hidden,
            funded: crate::publicity::PhaseView {
                open: true,
                choice: None,
            },
            finished: crate::publicity::PhaseView {
                open: false,
                choice: None,
            },
            deliverables: Vec::new(),
        })),
    ]
}
