//! The read models of the coordinator unmask (ADR-023, I-17 as amended
//! 2026-11-15): the parties a coordinator may unmask, and the unmask log
//! of a programme for its auditor and the tenant admins.
//!
//! Neither model carries an identity attribute. A party is named by its
//! binding or assignment id, its party kind and its role. The label is the
//! pseudonymous display handle of a reviewer or IRC assignee, which the
//! coordinator's assignment page already shows, and empty otherwise.

use fstp_domain::id::{AccountId, ProgrammeId, ProposalId};
use fstp_domain::unmask::{PartyKind, UnmaskSubject};
use fstp_json::{Array, Object, ToJson, Value};

/// One unmask read model.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnmaskModel {
    /// `identity.parties`.
    Parties(PartiesView),
    /// `audit.unmasks`.
    Log(Vec<UnmaskRow>),
}

/// The parties of one proposal and the staff of its programme.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartiesView {
    /// The programme.
    pub programme: ProgrammeId,
    /// The proposal.
    pub proposal: ProposalId,
    /// The parties, proposal parties first, then staff.
    pub parties: Vec<PartyRow>,
}

/// One party a coordinator may unmask.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartyRow {
    /// The party kind.
    pub party: PartyKind,
    /// The subject, by id.
    pub subject: UnmaskSubject,
    /// The role wire name of the binding the party rests on.
    pub role: &'static str,
    /// The display handle of a reviewer or IRC assignee, or empty.
    pub label: String,
}

/// One unmask of the log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnmaskRow {
    /// The party kind.
    pub party: PartyKind,
    /// The subject, by id.
    pub subject: UnmaskSubject,
    /// The coordinator.
    pub by: AccountId,
    /// The purpose the coordinator gave.
    pub purpose: String,
    /// The instant of the entry, in UTC microseconds.
    pub at: i64,
}

fn dec(x: u128) -> Value {
    Value::String(x.to_string())
}

fn subject_members(o: &mut Object, s: UnmaskSubject) {
    let (kind, id) = match s {
        UnmaskSubject::Binding(b) => ("binding", b.raw()),
        UnmaskSubject::Assignment(a) => ("assignment", a.raw()),
    };
    let _ = o.insert("subject_type", Value::from(kind));
    let _ = o.insert("subject", dec(id));
}

impl ToJson for PartyRow {
    fn to_json(&self) -> Value {
        let mut o = Object::new();
        let _ = o.insert("party", Value::from(self.party.wire()));
        subject_members(&mut o, self.subject);
        let _ = o.insert("role", Value::from(self.role));
        let _ = o.insert("label", Value::from(self.label.as_str()));
        Value::Object(o)
    }
}

impl ToJson for UnmaskRow {
    fn to_json(&self) -> Value {
        let mut o = Object::new();
        let _ = o.insert("party", Value::from(self.party.wire()));
        subject_members(&mut o, self.subject);
        let _ = o.insert("by", dec(self.by.raw()));
        let _ = o.insert("purpose", Value::from(self.purpose.as_str()));
        let _ = o.insert("at", Value::String(self.at.to_string()));
        Value::Object(o)
    }
}

impl ToJson for UnmaskModel {
    fn to_json(&self) -> Value {
        let mut o = Object::new();
        match self {
            UnmaskModel::Parties(v) => {
                let _ = o.insert("programme", dec(v.programme.raw()));
                let _ = o.insert("proposal", dec(v.proposal.raw()));
                let rows: Array = v.parties.iter().map(ToJson::to_json).collect();
                let _ = o.insert("parties", Value::Array(rows));
            }
            UnmaskModel::Log(rows) => {
                let rows: Array = rows.iter().map(ToJson::to_json).collect();
                let _ = o.insert("unmasks", Value::Array(rows));
            }
        }
        Value::Object(o)
    }
}

/// One sample of each model, with every member set, for the shape tests.
#[cfg(test)]
pub(crate) fn samples() -> Vec<UnmaskModel> {
    use fstp_domain::id::{AssignmentId, BindingId};
    vec![
        UnmaskModel::Parties(PartiesView {
            programme: ProgrammeId::from_raw(1),
            proposal: ProposalId::from_raw(2),
            parties: vec![
                PartyRow {
                    party: PartyKind::Applicant,
                    subject: UnmaskSubject::Binding(BindingId::from_raw(3)),
                    role: "applicant",
                    label: String::new(),
                },
                PartyRow {
                    party: PartyKind::Reviewer,
                    subject: UnmaskSubject::Assignment(AssignmentId::from_raw(4)),
                    role: "committee_member",
                    label: "Reviewer handle".to_owned(),
                },
            ],
        }),
        UnmaskModel::Log(vec![UnmaskRow {
            party: PartyKind::Guardian,
            subject: UnmaskSubject::Binding(BindingId::from_raw(5)),
            by: AccountId::from_raw(6),
            purpose: "Synthetic purpose".to_owned(),
            at: 7,
        }]),
    ]
}
