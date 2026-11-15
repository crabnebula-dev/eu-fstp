//! `roles.list`: the staff bindings of one programme, for the tenant
//! admin who grants, ends and reinstates them (J1, SoD-09; M4 design
//! sections 2.2 and 3.6).
//!
//! Reading, lane m4/ops-roles-agents: the list holds the bindings a
//! tenant admin manages, the Drafting, Judging and Operations ones that
//! are held or voided. `EndRole` and `ReinstateBinding` act on those
//! groups only. Receiving bindings belong to the proposal's team and
//! stay out, so the list names no applicant. An ended binding has left
//! the roster's held set, and the list leaves it out too.
//!
//! Each row names the binding, its account by id, the role, its start,
//! a scheduled end, and whether it is active, suspended or voided with
//! the rule. It holds no name, no email and no identity attribute (I-17,
//! I-86).

use fstp_domain::id::{AccountId, BindingId, ProgrammeId};
use fstp_domain::roles::{BindingStatus, Group, Role};
use fstp_domain::time::Timestamp;
use fstp_engine::EngineState;
use fstp_json::{Array, Object, ToJson, Value};

/// The state of a binding, as the list shows it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindingState {
    /// It acts from its start.
    Active,
    /// Suspended, under this rule when it is a spec rule. A tenant admin may reinstate it.
    Suspended(Option<&'static str>),
    /// Voided, under this rule when it is a spec rule. Nothing reinstates it.
    Voided(Option<&'static str>),
}

/// One staff binding of the programme.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BindingRow {
    /// The binding.
    pub binding: BindingId,
    /// The account, by id only.
    pub account: AccountId,
    /// The role.
    pub role: Role,
    /// Its start.
    pub start: Timestamp,
    /// Its scheduled end, if any.
    pub end: Option<Timestamp>,
    /// Active, suspended or voided.
    pub state: BindingState,
}

/// The `roles.list` reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProgrammeBindings(pub Vec<BindingRow>);

/// The staff bindings of `p` in `state`, by binding id.
pub(super) fn list(state: &EngineState, p: ProgrammeId) -> ProgrammeBindings {
    let rows = state
        .core
        .roster()
        .bindings()
        .filter(|(_, b)| b.programme == p && b.group() != Group::Receiving)
        .map(|(id, b)| BindingRow {
            binding: id,
            account: b.account,
            role: b.role,
            start: b.start,
            end: b.scheduled_end,
            state: match b.status {
                BindingStatus::Active => BindingState::Active,
                BindingStatus::Suspended(r) => BindingState::Suspended(r.spec_id()),
                BindingStatus::Voided(r) => BindingState::Voided(r.spec_id()),
            },
        })
        .collect();
    ProgrammeBindings(rows)
}

/// A decimal string.
fn dec(x: impl std::fmt::Display) -> Value {
    Value::String(x.to_string())
}

impl ToJson for ProgrammeBindings {
    fn to_json(&self) -> Value {
        let mut out = Array::new();
        for r in &self.0 {
            let mut o = Object::new();
            let _ = o.insert("binding", dec(r.binding.raw()));
            let _ = o.insert("account", dec(r.account.raw()));
            let _ = o.insert("role", Value::from(fstp_access::role_wire_name(r.role)));
            let _ = o.insert("start", dec(r.start.micros()));
            if let Some(e) = r.end {
                let _ = o.insert("end", dec(e.micros()));
            }
            let (state, rule) = match r.state {
                BindingState::Active => ("active", None),
                BindingState::Suspended(x) => ("suspended", x),
                BindingState::Voided(x) => ("voided", x),
            };
            let _ = o.insert("state", Value::from(state));
            if let Some(x) = rule {
                let _ = o.insert("rule", Value::from(x));
            }
            out.push(Value::Object(o));
        }
        Value::Array(out)
    }
}
