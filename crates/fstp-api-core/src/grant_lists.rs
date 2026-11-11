//! The read models of the M5 reads follow-up (`docs/handoff/m5-ui.md`):
//! the milestones of `grant.overview`, the caller's grants
//! (`grant.list_mine`) and the contract versions awaiting the caller's
//! signature (`contract.awaiting_me`).
//!
//! I-86: no row names an account, a bank detail or a vault value. A party
//! is named by its signature field and role. Amounts are ADR-006 strings
//! the cell formats, so the browser computes no money.

use fstp_domain::id::{CallId, ContractId, MilestoneId, ProposalId};
use fstp_json::{Object, ToJson, Value};

fn dec(x: u128) -> Value {
    Value::String(x.to_string())
}

fn nullable<T>(x: Option<T>, f: impl FnOnce(T) -> Value) -> Value {
    x.map_or(Value::Null, f)
}

/// One milestone of a grant's plan with its money (R-PR-07, I-58).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MilestoneRow {
    /// The milestone.
    pub milestone: MilestoneId,
    /// Its amount in the plan.
    pub amount: String,
    /// Its due day, `YYYY-MM-DD` in UTC.
    pub due: String,
    /// What released and paid requests hold on it.
    pub paid: String,
    /// What pending requests hold on it.
    pub pending: String,
    /// What a new request may still claim (I-58).
    pub available: String,
    /// Whether the programme manager closed it (NOTE 12).
    pub closed: bool,
}

impl ToJson for MilestoneRow {
    fn to_json(&self) -> Value {
        let mut o = Object::new();
        let _ = o.insert("milestone", dec(self.milestone.raw()));
        let _ = o.insert("amount", Value::from(self.amount.as_str()));
        let _ = o.insert("due", Value::from(self.due.as_str()));
        let _ = o.insert("paid", Value::from(self.paid.as_str()));
        let _ = o.insert("pending", Value::from(self.pending.as_str()));
        let _ = o.insert("available", Value::from(self.available.as_str()));
        let _ = o.insert("closed", Value::Bool(self.closed));
        Value::Object(o)
    }
}

/// One grant of the caller's list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantRow {
    /// The grant, by its proposal.
    pub proposal: ProposalId,
    /// Its call.
    pub call: Option<CallId>,
    /// The proposal state, as the state machine names it.
    pub state: &'static str,
    /// The reserved or granted amount.
    pub amount: Option<String>,
    /// The paid total (I-64).
    pub paid: String,
    /// The latest contract.
    pub contract: Option<ContractId>,
    /// The rule of `grant.overview` that admits the caller: `team`,
    /// `former_team`, a role name or `auditor`.
    pub via: &'static str,
}

impl ToJson for GrantRow {
    fn to_json(&self) -> Value {
        let mut o = Object::new();
        let _ = o.insert("proposal", dec(self.proposal.raw()));
        let _ = o.insert("call", nullable(self.call, |c| dec(c.raw())));
        let _ = o.insert("state", Value::from(self.state));
        let _ = o.insert("amount", nullable(self.amount.as_deref(), Value::from));
        let _ = o.insert("paid", Value::from(self.paid.as_str()));
        let _ = o.insert("contract", nullable(self.contract, |c| dec(c.raw())));
        let _ = o.insert("via", Value::from(self.via));
        Value::Object(o)
    }
}

/// One contract version that waits on the caller's signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignRow {
    /// The grant.
    pub proposal: ProposalId,
    /// The contract.
    pub contract: ContractId,
    /// The version to sign.
    pub version: u32,
    /// The caller's signature field.
    pub field: String,
    /// The caller's party role.
    pub role: &'static str,
    /// `sent` or `signed_by_grantee`.
    pub state: &'static str,
    /// The SHA-256 of the revision to sign, lowercase hex (I-30).
    pub digest: Option<String>,
}

impl ToJson for SignRow {
    fn to_json(&self) -> Value {
        let mut o = Object::new();
        let _ = o.insert("proposal", dec(self.proposal.raw()));
        let _ = o.insert("contract", dec(self.contract.raw()));
        let _ = o.insert("version", Value::from(self.version));
        let _ = o.insert("field", Value::from(self.field.as_str()));
        let _ = o.insert("role", Value::from(self.role));
        let _ = o.insert("state", Value::from(self.state));
        let _ = o.insert("digest", nullable(self.digest.as_deref(), Value::from));
        Value::Object(o)
    }
}

/// What an amount determination of one proposal needs, for its assigned
/// reviewer (R-NG-03). I-86: no paid sum, contract, request or account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeterminationView {
    /// The proposal.
    pub proposal: ProposalId,
    /// The proposal state, as the state machine names it.
    pub state: &'static str,
    /// The current amount determination, if any.
    pub determination: Option<u128>,
    /// The plan the determination starts from: the agreed plan of the
    /// current determination, else the effective plan (I-09).
    pub plan: Option<fstp_domain::id::PlanVersionId>,
    /// That plan's total (I-13).
    pub plan_total: Option<String>,
    /// The granted amount of the current determination.
    pub granted: Option<String>,
}

impl ToJson for DeterminationView {
    fn to_json(&self) -> Value {
        let mut o = Object::new();
        let _ = o.insert("proposal", dec(self.proposal.raw()));
        let _ = o.insert("state", Value::from(self.state));
        let _ = o.insert("determination", nullable(self.determination, dec));
        let _ = o.insert("plan", nullable(self.plan, |p| dec(p.raw())));
        let _ = o.insert(
            "plan_total",
            nullable(self.plan_total.as_deref(), Value::from),
        );
        let _ = o.insert("granted", nullable(self.granted.as_deref(), Value::from));
        Value::Object(o)
    }
}
